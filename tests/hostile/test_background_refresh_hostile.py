"""Hostile: a background re-verification that reports another build (Amendment 9).

The vendor answers the background capture with a different fingerprint. The refresh stages a pending pin
and writes its verify_ok row as not accepted. The new result is never committed to the adapter, never
swapped into the cache, and no send uses its key. When the TTL ends, the next call verifies inline and
refuses until a person approves the pin.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode import provider as provider_mod  # noqa: E402
from confidential_mode import receipts  # noqa: E402
from confidential_mode.pins import PinStore  # noqa: E402
from confidential_mode.verify.base import VerifyError  # noqa: E402

from ..near_world import NearWorld  # noqa: E402
from ..unit.test_background_refresh import Clock, FakeAdapter, _result  # noqa: E402

P = "attested-tinfoil"


def test_a_background_result_with_another_fingerprint_stages_a_pin_and_is_never_used(tmp_path, monkeypatch):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    events: list[dict] = []
    clock = Clock()
    cache = provider_mod.VerificationCache(clock=clock)
    cache.active = lambda: True
    monkeypatch.setattr(provider_mod.BackgroundRefresh, "start", lambda self: None)
    first, evil = _result(), _result(code="c-evil", enclave="e-evil")
    ad = FakeAdapter([first, evil])
    cache.register(P, ad, store, 300.0, on_event=events.append, refresh_lead_seconds=60.0)
    assert cache.ensure(P)[0] is True
    r = cache.entry(P).refresher
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    r.step()
    assert r.outcomes == ["staged"]
    assert [c for c, _ in ad.commits] == [first] and ad.discarded == [evil]
    assert cache.entry(P).result is first and ad.send() == "c1"
    staged = [e for e in events if e["kind"] == "pin_staged"]
    assert len(staged) == 1 and staged[0]["detail"]["code_fingerprint"] == "c-evil"
    bg = [e for e in events if e["kind"] == "verify_ok"][-1]
    assert bg["detail"]["source"] == "background" and bg["detail"]["accepted"] is False
    assert store.pending().code_fingerprint == "c-evil"
    clock.t = 260.0
    r.step()
    assert r.outcomes == ["staged"] and ad.prepares == 2      # a staged result is not retried
    clock.t = 301.0                                           # expired: inline re-verify, same build: refused
    ok, reason, _ = cache.ensure(P)
    assert ok is False and reason == provider_mod.REASON_PIN_MISMATCH
    with pytest.raises(VerifyError):
        ad.send()


def test_a_receipt_never_credits_a_send_to_an_unaccepted_background_row():
    rows = [
        {"id": 1, "kind": "verify_ok", "ts": 100.0, "host": "h", "detail": {"enclave_host": "h", "ttl_seconds": 300}},
        {"id": 2, "kind": "verify_ok", "ts": 350.0, "host": "h",
         "detail": {"enclave_host": "h", "ttl_seconds": 300, "source": "background", "accepted": False}},
        {"id": 3, "kind": "send_observed", "ts": 360.0, "host": "h", "tier": "attested",
         "detail": {"verify_before": 2, "started_ts": 360.0}},
    ]
    cov = receipts._send_coverage(rows, 300.0, "config")
    assert cov[0]["verify"] == 1 and cov[0]["covered"] is True


def _blocking_world(tmp_path):
    world = NearWorld()
    gate, entered = threading.Event(), threading.Event()
    blocking = {"on": False}

    import httpx

    def attest(request):
        if blocking["on"] and request.url.path.startswith("/v1/attestation"):
            entered.set()
            assert gate.wait(10)
        return world.handler(request)
    ad = world.adapter(tmp_path, encrypt=True)
    ad._transport_factory = lambda: httpx.MockTransport(attest)
    ad._send_transport_factory = lambda: httpx.MockTransport(lambda r: world.handler(r))
    return world, ad, gate, entered, blocking


def test_near_capture_runs_outside_the_adapter_lock_and_publishes_nothing(tmp_path):
    """Codebase review finding 19 and the S09 ordering: a NEAR re-verification capture never holds the
    lock the send path takes, and a prepared result is not visible to sends before it is committed."""
    pytest.importorskip("nacl")
    world, ad, gate, entered, blocking = _blocking_world(tmp_path)
    first = ad.verify()
    ad.release()
    key = ad.model_public_key(world.models[0])
    blocking["on"] = True
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("p", ad.prepare_verification()), daemon=True)
    t.start()
    assert entered.wait(5)
    assert ad._lock.acquire(timeout=0.5), "the capture holds the adapter lock"
    ad._lock.release()
    assert ad.last_result is first and ad.model_public_key(world.models[0]) == key
    gate.set()
    t.join(10)
    prepared = out["p"]
    assert ad.last_result is first and prepared.result is not first      # prepared, not published
    assert ad.held_reason is None
    seen = {}
    real = ad.pinned_spki

    def spy():
        seen.setdefault("held", ad.held_reason)
        seen.setdefault("accepted", ad._accepted)
        return real()
    ad.pinned_spki = spy
    ad.commit_verification(prepared, hold=True)
    assert seen["held"] is not None and seen["accepted"] is first          # held BEFORE publishing
    assert ad.last_result is prepared.result


def test_near_commit_refuses_after_close(tmp_path):
    pytest.importorskip("nacl")
    world, ad, _gate, _entered, _blocking = _blocking_world(tmp_path)
    ad.verify()
    prepared = ad.prepare_verification()
    ad.close()
    with pytest.raises(VerifyError):
        ad.commit_verification(prepared, hold=False)


def test_a_send_prepared_before_a_held_commit_is_refused_at_the_pool(tmp_path):
    """S09, atomic: a request that passed the first hold check and was built on the old verification is
    refused when a verification was committed with a hold in between (checked with the pool choice)."""
    pytest.importorskip("nacl")
    import httpx
    from ..near_world import BASE, MODEL
    world, ad, _gate, _entered, _blocking = _blocking_world(tmp_path)
    ad.verify()
    ad.release()
    req = httpx.Request("POST", f"{BASE}/chat/completions",
                        json={"model": MODEL, "messages": [{"role": "user", "content": "hi"}]})
    req.read()
    ex = ad.begin_exchange(req)
    ad.commit_verification(ad.prepare_verification(), hold=True)
    with pytest.raises(VerifyError, match="held"):
        ad._acquire(ex, check=True)
    ad.release()
    _pool, release = ad._acquire(ex, check=True)     # same key and certificate: the prepared send proceeds
    release()
    ad.close()
    with pytest.raises(VerifyError, match="closed"):
        ad.prepare_verification()


def test_the_text_receipt_marks_an_unaccepted_background_row():
    row = {"id": 2, "kind": "verify_ok", "ts": 350.0, "host": "h", "provider": "attested-tinfoil",
           "detail": {"enclave_host": "h", "source": "background", "accepted": False, "vendor": "tinfoil"}}
    text = receipts._verify_body(row)
    assert "NOT ACCEPTED (the pins did not match this build; never used for a send)" in text
    assert "source=background" in text
    ok = dict(row, detail={"enclave_host": "h", "source": "background", "accepted": True, "vendor": "tinfoil"})
    assert "NOT ACCEPTED" not in receipts._verify_body(ok) and "source=background" in receipts._verify_body(ok)


def test_a_background_commit_with_the_same_key_and_certificate_does_not_refuse_a_prepared_send(tmp_path):
    """N1: only the values an exchange was prepared with matter, not the verification object."""
    pytest.importorskip("nacl")
    import httpx
    from ..near_world import BASE, MODEL
    world, ad, _gate, _entered, _blocking = _blocking_world(tmp_path)
    ad.verify()
    ad.release()

    def prepared_exchange():
        req = httpx.Request("POST", f"{BASE}/chat/completions",
                            json={"model": MODEL, "messages": [{"role": "user", "content": "hi"}]})
        req.read()
        return ad.begin_exchange(req)
    ex = prepared_exchange()
    ad.commit_verification(ad.prepare_verification(), hold=False)     # same key, same certificate
    assert ex.accepted is not ad.last_result
    pool, release = ad._acquire(ex, check=True)
    release()
    import dataclasses
    ex = prepared_exchange()
    ad._appraisal = dataclasses.replace(ad._appraisal, model_signers={MODEL: ["ab" * 32]})   # another key
    ad._accepted = dataclasses.replace(ad._accepted)
    with pytest.raises(VerifyError, match="signing key changed"):
        ad._acquire(ex, check=True)

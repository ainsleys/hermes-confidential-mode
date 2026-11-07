"""The background re-verification (Amendment 9): a fake clock and a fake adapter, no Hermes, no network.

The refresh captures before the TTL ends, outside every lock a send takes, and swaps the new result in
only after the pin check accepted it. A failure or a staged pin changes nothing until the TTL ends; the
next call then verifies inline and refuses as it would without the refresh.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode import provider as provider_mod  # noqa: E402
from confidential_mode.pins import PinStore  # noqa: E402
from confidential_mode.verify.base import PreparedVerification, VerificationResult, VerifyError  # noqa: E402

REPO = "tinfoilsh/confidential-model-router"
P = "attested-tinfoil"
TTL, LEAD = 300.0, 60.0


def _result(code="c1", enclave="e1"):
    return VerificationResult(vendor="tinfoil", router_repo=REPO, enclave_host="r.example", code_fingerprint=code,
                              enclave_fingerprint=enclave, release_tag="v1", verifier="tinfoil/0.14.2",
                              verified_at_host_clock=0.0, evidence={"platform": "sev-snp"})


class FakeAdapter:
    """prepare_verification() returns the next queued result (or raises a queued exception); a send uses the
    committed result's fingerprint as its key."""
    vendor = "tinfoil"
    enclave_host = "r.example"
    base_url = "https://r.example/v1"

    def __init__(self, queue):
        self.queue = list(queue)
        self.prepares = 0
        self.commits: list[tuple[VerificationResult, bool]] = []
        self.discarded: list[VerificationResult] = []
        self.accepted: VerificationResult | None = None
        self.held_reason: str | None = None
        self.closed = False
        self.on_close = None
        self.capture_gate: threading.Event | None = None    # set: prepare blocks until it is set
        self.in_capture = threading.Event()
        self.lock = threading.Lock()                         # the "send lock"

    def _next(self):
        item = self.queue.pop(0) if len(self.queue) > 1 else self.queue[0]
        if isinstance(item, BaseException):
            raise item
        return item

    def verify(self):
        return self.commit_verification(self.prepare_verification(), hold=True)

    def prepare_verification(self):
        self.prepares += 1
        if self.capture_gate is not None:
            self.in_capture.set()
            assert self.capture_gate.wait(5)
        r = self._next()
        return PreparedVerification(result=r, payload=r, on_discard=lambda: self.discarded.append(r))

    def commit_verification(self, prepared, *, hold):
        with self.lock:
            if hold:
                self.held_reason = "verification not yet accepted against pins"
            self.accepted = prepared.result
            self.commits.append((prepared.result, hold))
            prepared.on_discard = None
            return prepared.result

    def hold(self, reason):
        self.held_reason = reason

    def release(self):
        self.held_reason = None

    def send(self) -> str:
        """What a send would encrypt to; raises while held. Takes only the send lock, briefly."""
        with self.lock:
            if self.held_reason is not None:
                raise VerifyError(f"held: {self.held_reason}")
            return self.accepted.code_fingerprint

    def close(self):
        self.closed = True
        if self.on_close:
            self.on_close()


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


@pytest.fixture
def world(tmp_path, monkeypatch):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    events: list[dict] = []
    clock = Clock()
    cache = provider_mod.VerificationCache(clock=clock)
    cache.active = lambda: state["locked"]
    cache.refresh_poll_seconds = 0.01
    state = {"locked": True}

    def make(queue, *, threads=False):
        ad = FakeAdapter(queue)
        cache.register(P, ad, store, TTL, on_event=events.append, refresh_lead_seconds=LEAD)
        if not threads:   # tests drive step() themselves
            monkeypatch.setattr(provider_mod.BackgroundRefresh, "start", lambda self: None)
        return ad
    return {"cache": cache, "pins": store, "events": events, "clock": clock, "state": state, "make": make}


def _rows(events, kind):
    return [e for e in events if e["kind"] == kind]


def _refresher(cache):
    r = cache.entry(P).refresher
    assert r is not None
    return r


def test_the_refresh_waits_for_the_lead_then_swaps_an_accepted_result_in(world):
    cache, clock, events = world["cache"], world["clock"], world["events"]
    first, second = _result(), _result()
    ad = world["make"]([first, second])
    assert cache.ensure(P)[0] is True and ad.prepares == 1 and ad.commits == [(first, True)]
    r = _refresher(cache)
    clock.t = 200.0
    assert 0 < r.step() <= cache.refresh_poll_seconds and ad.prepares == 1   # not yet due (due at 240)
    clock.t = 241.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    assert r.step() == 0.0 and r.outcomes == ["accepted"]
    assert ad.prepares == 2 and ad.commits[-1] == (second, False)   # committed without a hold
    e = cache.entry(P)
    assert e.result is second and e.verified_mono == 241.0
    ok = _rows(events, "verify_ok")
    assert [x["detail"]["source"] for x in ok] == ["verify", "background"]
    assert ok[-1]["detail"]["accepted"] is True and "accepted" not in ok[0]["detail"]
    clock.t = 400.0   # the first result would have expired at 300; the swapped one is fresh to 541
    assert cache.ensure(P)[0] is True and ad.prepares == 2


def test_no_send_waits_on_a_background_capture(world):
    cache, clock = world["cache"], world["clock"]
    ad = world["make"]([_result(), _result()])
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    ad.capture_gate = threading.Event()
    t = threading.Thread(target=r.step, daemon=True)
    t.start()
    assert ad.in_capture.wait(5)
    # The capture is in progress: the cache answers and the send goes out at once, on the old result.
    started = time.monotonic()
    assert cache.ensure(P)[0] is True
    assert ad.send() == "c1"
    assert cache.entry(P).lock.acquire(timeout=0.5)
    cache.entry(P).lock.release()
    assert time.monotonic() - started < 1.0
    ad.capture_gate.set()
    t.join(5)
    assert r.outcomes == ["accepted"]


def test_a_failed_background_capture_keeps_the_old_result_until_expiry_then_refuses(world):
    cache, clock, events = world["cache"], world["clock"], world["events"]
    first = _result()
    ad = world["make"]([first, VerifyError("network down")])
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    r.step()
    assert r.outcomes == ["failed"] and cache.entry(P).result is first
    fail = _rows(events, "verify_fail")
    assert len(fail) == 1 and fail[0]["detail"]["source"] == "background" and "network down" in fail[0]["detail"]["error"]
    assert cache.ensure(P)[0] is True and ad.send() == "c1"   # still vouching: nothing changed
    clock.t = 255.0
    r.step()
    assert r.outcomes == ["failed"]                            # within the failure backoff: no new attempt
    clock.t = 261.0
    r.step()
    assert r.outcomes == ["failed", "failed"] and ad.prepares == 3
    clock.t = 300.5                                            # expired: inline verification, which fails
    assert r.step() is None
    ok, reason, _ = cache.ensure(P)
    assert ok is False and "attested verification failed" in reason and "network down" in reason
    with pytest.raises(VerifyError):
        ad.send()
    assert len(_rows(events, "verify_fail")) == 3 and "source" not in _rows(events, "verify_fail")[-1]["detail"]


def test_a_lost_background_verify_row_is_a_failure(world):
    cache, clock = world["cache"], world["clock"]
    first = _result()
    ad = world["make"]([first, _result()])
    assert cache.ensure(P)[0] is True
    e = cache.entry(P)
    good = e.on_event
    e.on_event = lambda ev: (_ for _ in ()).throw(RuntimeError("disk full")) if ev["kind"] == "verify_ok" else good(ev)
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    _refresher(cache).step()
    # The row is written after the commit; a lost row holds the adapter and drops the entry (fail closed).
    assert _refresher(cache).outcomes == ["failed"] and e.result is None and len(ad.commits) == 2
    assert ad.held_reason == provider_mod.REASON_VERIFY_ROW_LOST
    with pytest.raises(VerifyError):
        ad.send()


def test_a_failed_commit_writes_no_accepted_row(world):
    cache, clock, events = world["cache"], world["clock"], world["events"]
    first = _result()
    ad = world["make"]([first, _result()])
    assert cache.ensure(P)[0] is True

    def boom(prepared, *, hold):
        raise VerifyError("closed meanwhile")
    ad.commit_verification = boom
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    _refresher(cache).step()
    assert _refresher(cache).outcomes == ["failed"] and cache.entry(P).result is first and ad.discarded
    assert [x["detail"].get("source") for x in _rows(events, "verify_ok")] == ["verify"]
    assert _rows(events, "verify_fail")[-1]["detail"]["source"] == "background"


def test_the_refresh_never_runs_while_unlocked_and_never_without_a_prepare_step(world):
    cache, state = world["cache"], world["state"]
    state["locked"] = False
    world["make"]([_result()])
    assert cache.ensure(P)[0] is True and cache.entry(P).refresher is None
    state["locked"] = True
    cache.entry(P).refresh_lead_seconds = 0.0          # 0 turns it off
    assert cache.ensure(P)[0] is True and cache.entry(P).refresher is None
    assert provider_mod.refresh_lead_from({"confidential": {"verify_refresh_lead_seconds": 0}}) == 0.0
    assert provider_mod.refresh_lead_from({"confidential": {"verify_refresh_lead_seconds": "x"}}) == LEAD
    assert provider_mod.refresh_lead_from({}) == LEAD


def test_an_adapter_without_prepare_keeps_the_inline_path(world, tmp_path):
    cache = world["cache"]

    class Old:
        vendor, enclave_host, base_url = "tinfoil", "r.example", "https://r.example/v1"

        def verify(self):
            return _result()
    cache.register(P, Old(), world["pins"], TTL, on_event=world["events"].append)
    assert cache.ensure(P)[0] is True and cache.entry(P).refresher is None


def test_the_thread_is_a_daemon_and_stops_on_unlock_close_invalidate_and_a_lost_lock(world):
    cache, state = world["cache"], world["state"]
    ad = world["make"]([_result()], threads=True)
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    assert r.thread.daemon is True and r.alive()
    cache.stop_refresh()                                   # what unlock calls
    r.thread.join(2)
    assert not r.thread.is_alive()

    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    assert r.alive()
    ad.close()                                             # adapter close stops it (on_close)
    r.thread.join(2)
    assert not r.thread.is_alive()

    ad.closed = False
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    cache.invalidate(P)                                    # an HTTP 421 or a TLS pin mismatch
    r.thread.join(2)
    assert not r.thread.is_alive()

    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    state["locked"] = False                                # unlocked from another process
    r.thread.join(2)
    assert not r.thread.is_alive()


def test_locking_unlock_stops_every_refresh(world, monkeypatch):
    from confidential_mode import locking
    cache = world["cache"]
    world["make"]([_result()], threads=True)
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    monkeypatch.setattr(provider_mod, "verification_cache", cache)
    locking._clear_verification_cache()
    r.thread.join(2)
    assert not r.thread.is_alive() and cache.entry(P).result is None


def test_an_unlock_during_the_capture_discards_the_result(world):
    cache, clock, state = world["cache"], world["clock"], world["state"]
    first = _result()
    ad = world["make"]([first, _result()])
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    ad.capture_gate = threading.Event()
    t = threading.Thread(target=r.step, daemon=True)
    t.start()
    assert ad.in_capture.wait(5)
    state["locked"] = False
    ad.capture_gate.set()
    t.join(5)
    assert r.outcomes == ["discarded"] and len(ad.commits) == 1 and ad.discarded
    assert not _rows(world["events"], "verify_ok")[1:]


def test_an_inline_verification_in_progress_makes_the_refresh_wait(world):
    cache, clock = world["cache"], world["clock"]
    world["make"]([_result(), _result()])
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    e = cache.entry(P)
    with e.verify_lock:
        r.step()
    assert r.outcomes == ["busy"]


def test_an_idle_session_is_not_refreshed(world):
    cache, clock = world["cache"], world["clock"]
    ad = world["make"]([_result(), _result(), _result()])
    assert cache.ensure(P)[0] is True
    r = _refresher(cache)
    clock.t = 250.0
    assert cache.ensure(P)[0] is True   # a recent use: the refresh is for an active session
    r.step()
    assert r.outcomes == ["accepted"] and ad.prepares == 2
    clock.t = 250.0 + 241.0          # the swapped verification is due, but no call used it recently
    assert r.step() > 0 and ad.prepares == 2
    clock.t = 250.0 + 301.0          # expired without a use: the thread ends, nothing was fetched
    assert r.step() is None and ad.prepares == 2
    clock.t = 250.0 + 241.0
    assert cache.ensure(P)[0] is True    # a call uses it and starts a refresh again
    assert _refresher(cache) is not r
    _refresher(cache).step()
    assert ad.prepares == 3

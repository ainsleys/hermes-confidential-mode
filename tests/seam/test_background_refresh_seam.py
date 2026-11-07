"""Seam: the background re-verification through the LLM gate on the plugin loaded by real discovery
(Amendment 9). NEAR is the synthetic one of tests/near_world.py; Hermes runs real turns.

A locked turn starts the refresh. In the lead window the refresh captures while a turn goes out on the
verification in use, swaps the new verification in after the pin check, and the next turn uses the new
attestation without an inline re-verification.
"""
from __future__ import annotations

import threading

import httpx
import pytest

from .test_near_seam import _approve, _sub, near  # noqa: F401  (fixture)
from .test_register import plugin  # noqa: F401  (fixture)
from ._harness import no_lazy_installs  # noqa: F401  (fixture)
from ..near_world import BASE, MODEL

P = "attested-near"


def _agent():
    import run_agent
    return run_agent.AIAgent(model=MODEL, provider=P, api_key="sk-near-seam", base_url=BASE, quiet_mode=True,
                             skip_context_files=True, skip_memory=True, max_iterations=2)


def _locked(plugin, near):
    assert plugin.slash("on attested").startswith("Not locked")
    _approve(plugin)
    out = plugin.slash("on attested")
    assert out.startswith("Locked to "), out


def test_a_turn_during_a_background_capture_is_not_delayed_and_the_next_turn_uses_the_new_verification(
        plugin, near):
    pytest.importorskip("nacl")
    _locked(plugin, near)
    provider = _sub(plugin, "provider")
    cache = provider.verification_cache
    ad = plugin.rt.near_adapter
    agent = _agent()
    assert "NEAR-FAKE-REPLY" in str(agent.run_conversation("hello").get("final_response"))
    e = cache.entry(P)
    r = e.refresher
    assert r is not None and r.thread.daemon is True, "a locked accepted turn starts the refresh"
    r.stop()
    r.thread.join(2)

    # Block the attestation endpoint; inference keeps its own pool.
    gate, entered = threading.Event(), threading.Event()

    def attest(request):
        if request.url.path.startswith("/v1/attestation"):
            entered.set()
            assert gate.wait(20)
        return near.handler(request)
    ad._transport_factory = lambda: httpx.MockTransport(attest)
    ad._attest_transport = None

    before = ad.attestation_count
    old_nonce = e.result.evidence["nonce"]
    e.verified_mono -= e.ttl_seconds - e.refresh_lead_seconds + 1    # inside the lead window
    bg = provider.BackgroundRefresh(cache, P, e)
    t = threading.Thread(target=bg.step, daemon=True)
    t.start()
    assert entered.wait(5)
    # The capture is blocked; a turn goes out on the verification in use, through the LLM gate.
    assert "NEAR-FAKE-REPLY" in str(agent.run_conversation("during").get("final_response"))
    sends = [x for x in plugin.rt.ledger.tail(0) if x.kind == "send_signed"]
    assert sends[-1].detail["attestation_nonce"] == old_nonce and sends[-1].detail["fully_attested"] is True
    gate.set()
    t.join(20)
    assert bg.outcomes == ["accepted"] and ad.attestation_count == before + 1
    new_nonce = e.result.evidence["nonce"]
    assert new_nonce != old_nonce and ad.last_result is e.result

    assert "NEAR-FAKE-REPLY" in str(agent.run_conversation("after").get("final_response"))
    assert ad.attestation_count == before + 1, "no inline re-verification"
    sends = [x for x in plugin.rt.ledger.tail(0) if x.kind == "send_signed"]
    assert sends[-1].detail["attestation_nonce"] == new_nonce
    rows = [x for x in plugin.rt.ledger.tail(0) if x.kind == "verify_ok" and x.provider == P]
    assert rows[-1].detail["source"] == "background" and rows[-1].detail["accepted"] is True


def test_unlock_stops_the_refresh_and_an_unlocked_turn_starts_none(plugin, near):
    pytest.importorskip("nacl")
    _locked(plugin, near)
    cache = _sub(plugin, "provider").verification_cache
    agent = _agent()
    agent.run_conversation("hello")
    r = cache.entry(P).refresher
    assert r is not None and r.alive()
    plugin.slash("off")
    r.thread.join(5)
    assert not r.thread.is_alive()
    assert cache.entry(P).result is None
    agent.run_conversation("unlocked")
    r2 = cache.entry(P).refresher
    assert r2 is r or r2 is None or not r2.alive()

"""Amendment 13 (S17): the full per-turn recheck runs in the llm gate as well as in pre_llm_call.

Hermes bounds pre_llm_call (30 s, hermes_cli/plugins_dispatch.py:183), abandons a hook that runs past it,
suppresses it for 60 s, skips it for agents with persistence disabled (agent/turn_context.py:858) and in
safe-worker mode, and then runs the turn with no veto. The llm_execution middleware is never skipped. These
tests skip the hook the way Hermes does (persistence disabled) and check that the gate still refuses, with the
same breach rows, and that the hook stays far from the timeout on a large config with the real preflight.
"""
from __future__ import annotations

import importlib
import socket
import time

from ._harness import Rec, no_lazy_installs  # noqa: F401  (fixture)
from .test_register import BASE_CONFIG, ON_HOST_URL, REMOTE_URL, build_agent, plugin  # noqa: F401  (fixture)


def _sub(plugin, name):
    return importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.{name}")


def _skip_hook(agent):
    agent._persist_disabled = True      # Hermes then never calls pre_llm_call (agent/turn_context.py:858)
    return agent


def test_a_skipped_hook_still_gets_the_structural_recheck_and_its_breach_row(plugin, monkeypatch):
    """The fingerprint still matches (so the gate's predicate passes the main call), the config no longer
    passes the preflight: only the structural recheck can refuse, and with the hook skipped the gate runs it."""
    locking = _sub(plugin, "locking")
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = _skip_hook(build_agent(monkeypatch, rec, ON_HOST_URL))
    assert agent.run_conversation("first")["final_response"] == "provider answered"
    assert "[confidential mode]" not in str(rec.provider_calls[0])          # no hook: no note either
    plugin.cfg.write_text(BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    monkeypatch.setattr(locking, "fingerprint_matches", lambda *a, **k: True)
    result = agent.run_conversation("second")
    assert result["final_response"].startswith("Confidential mode"), result["final_response"]
    assert len(rec.provider_calls) == 1, "the refused turn made no provider call"
    assert ("breach", "preflight_failed") in plugin.kinds()
    refused = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]
    assert refused and refused[-1].detail["reason_code"] == "preflight_failed"
    assert plugin.rt.state.is_breached(agent.session_id)


def test_a_skipped_hook_still_gets_the_config_changed_breach(plugin, monkeypatch):
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = _skip_hook(build_agent(monkeypatch, rec, ON_HOST_URL))
    plugin.cfg.write_text(BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    result = agent.run_conversation("second")
    assert "routing config changed after this profile was locked" in (result["final_response"] or "")
    assert rec.provider_calls == []
    assert ("breach", "config_changed") in plugin.kinds()


def test_a_skipped_hook_still_gets_the_live_runtime_check(plugin, monkeypatch):
    locking = _sub(plugin, "locking")
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = _skip_hook(build_agent(monkeypatch, rec, ON_HOST_URL))
    monkeypatch.setattr(locking, "live_main_runtime",
                        lambda: {"provider": "custom", "model": "x", "base_url": REMOTE_URL, "api_mode": "",
                                 "requested_provider": ""})
    result = agent.run_conversation("the merger terms are")
    assert "live model runtime is custom at llm.example.test" in (result["final_response"] or "")
    assert rec.provider_calls == []
    assert ("breach", "live_runtime_off_tier") in plugin.kinds()
    assert plugin.rt.state.is_breached(agent.session_id)


def test_a_skipped_hook_still_gets_the_unreadable_runtime_refusal(plugin, monkeypatch):
    locking = _sub(plugin, "locking")
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = _skip_hook(build_agent(monkeypatch, rec, ON_HOST_URL))

    def unreadable():
        raise locking.LiveRuntimeUnreadable("cannot import the live runtime accessor (ImportError)")
    monkeypatch.setattr(locking, "live_main_runtime", unreadable)
    result = agent.run_conversation("the merger terms are")
    assert "does not expose the live model runtime" in (result["final_response"] or "")
    assert rec.provider_calls == []
    codes = [e.detail.get("reason_code") for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]
    assert "live_runtime_unreadable" in codes


def test_the_hook_and_the_gate_share_one_check_per_turn(plugin, monkeypatch):
    locking = _sub(plugin, "locking")
    assert plugin.slash("on on-host-only").startswith("Locked")
    calls = []
    real = locking.recheck

    def counted(**kw):
        calls.append(1)
        return real(**kw)
    monkeypatch.setattr(locking, "recheck", counted)
    rec = Rec()
    agent = build_agent(monkeypatch, rec, ON_HOST_URL)          # hook not skipped
    assert agent.run_conversation("one turn")["final_response"] == "provider answered"
    assert "[confidential mode] This profile is locked" in str(rec.provider_calls[0])
    assert len(calls) == 1, calls


def _forty_route_config() -> str:
    """The main route plus 13 auxiliary tasks with two fallback entries each: 40 routes (the preflight reads
    every mapping under ``auxiliary``)."""
    tasks = "\n".join(
        f"  task{i}:\n    provider: custom\n    model: m\n    base_url: {ON_HOST_URL}\n    fallback_chain:\n"
        f"      - provider: custom\n        model: m2\n        base_url: {ON_HOST_URL}\n"
        f"      - provider: custom\n        model: m3\n        base_url: http://localhost:8080/v1"
        for i in range(13))
    return BASE_CONFIG + tasks + "\n"


def test_the_hook_is_fast_and_off_network_on_a_forty_route_config(plugin, monkeypatch):
    plugin.cfg.write_text(_forty_route_config())
    assert plugin.slash("on on-host-only").startswith("Locked"), plugin.slash("check")

    touched = _forbid_network(monkeypatch)
    hook = plugin.mod._pre_llm_call(plugin.rt)
    timings = []
    for i in range(5):
        start = time.perf_counter()
        out = hook(session_id="sess-fast", turn_id=f"turn-{i}")      # a new turn each time: never cached
        timings.append(time.perf_counter() - start)
        assert out and "context" in out, out
    assert max(timings) < 0.5, timings
    assert touched == [], touched


class _NetworkTouched(BaseException):
    """Not an Exception: no ``except Exception`` on the way can swallow it."""


def _forbid_network(monkeypatch):
    """Record and refuse every socket-level lookup or connect. The record is the assertion: a thread that
    swallowed the exception still leaves its entry."""
    touched = []

    def no_network(*a, **k):
        touched.append(a[:1])
        raise _NetworkTouched("pre_llm_call touched the network")
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    return touched


OWN = "cm-own-host.test"
OWN_CONFIG = BASE_CONFIG.replace(ON_HOST_URL, f"http://{OWN}:11434/v1")


def test_the_hook_never_resolves_the_own_host_name(plugin, monkeypatch):
    """A route naming this machine's host name needs a DNS lookup (tiers.own_hostname_is_loopback). The hook
    answers from the cache, or defers to the llm gate when nothing is cached; it never resolves."""
    tiers = _sub(plugin, "tiers")
    assert ON_HOST_URL in BASE_CONFIG
    monkeypatch.setattr(socket, "gethostname", lambda: OWN)
    monkeypatch.setattr(tiers, "_resolve_all", lambda name: ["127.0.0.1"])
    tiers._OWN_HOSTNAME_CACHE.clear()
    plugin.cfg.write_text(OWN_CONFIG)
    assert plugin.slash("on on-host-only").startswith("Locked"), plugin.slash("check")
    hook = plugin.mod._pre_llm_call(plugin.rt)
    resolved = []
    monkeypatch.setattr(tiers, "_resolve_all", lambda name: resolved.append(name) or ["127.0.0.1"])
    touched = _forbid_network(monkeypatch)
    # Cached from the lock: answered from the cache, even past the TTL.
    monkeypatch.setattr(tiers, "_OWN_HOSTNAME_TTL_SECONDS", 0.0)
    out = hook(session_id="sess-own", turn_id="turn-cached")
    assert out and "context" in out, out
    # Nothing cached (another process locked): the hook defers, caches nothing, and writes no row.
    tiers._OWN_HOSTNAME_CACHE.clear()
    before = len(plugin.rt.ledger.tail(0))
    out = hook(session_id="sess-own", turn_id="turn-uncached")
    assert out and "context" in out and "action" not in out, out
    assert len(plugin.rt.ledger.tail(0)) == before
    assert resolved == [] and touched == []
    assert not any(k[1] == "turn-uncached" for k in plugin.rt._turn_checks)
    # The gate's call for the same turn then runs the whole check, lookup included.
    tier = tiers.Tier.ON_HOST
    assert plugin.rt.turn_check("sess-own", "turn-uncached", tier) is None
    assert resolved and set(resolved) == {OWN}


def test_the_turn_check_is_single_flight(plugin, monkeypatch):
    """A second caller for the same turn waits for the check in flight (the gate after Hermes abandoned the
    hook) instead of running it again, so its rows are written once."""
    import threading
    locking, tiers = _sub(plugin, "locking"), _sub(plugin, "tiers")
    assert plugin.slash("on on-host-only").startswith("Locked")
    calls, started = [], threading.Event()
    real = locking.recheck

    def slow(**kw):
        calls.append(1)
        started.set()
        time.sleep(0.3)
        return real(**kw)
    monkeypatch.setattr(locking, "recheck", slow)
    results = []
    first = threading.Thread(target=lambda: results.append(plugin.rt.turn_check("s", "t", tiers.Tier.ON_HOST)))
    first.start()
    assert started.wait(2)
    results.append(plugin.rt.turn_check("s", "t", tiers.Tier.ON_HOST))
    first.join(2)
    assert calls == [1] and results == [None, None]
    # Another tier or another lock is another key.
    plugin.rt.turn_check("s", "t", tiers.Tier.ATTESTED)
    assert len(calls) == 2

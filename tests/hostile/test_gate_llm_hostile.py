"""Hostile tests for the W1 llm_execution gate (confidential_mode.gate_llm.build_middleware).

Written by T1 BEFORE the implementation existed. Each test drives a real
``AIAgent.run_conversation`` turn through the real PluginManager; a failure here means a leak
(a provider request that should not have been sent), a fail-open (an exception escaping the
gate so Hermes calls the provider itself, retries, or arms fallback), or a swallowed user stop.

The strongest observable is the recording provider seam: on every refusal it must have received
ZERO requests. See tests/hostile/_harness_llm.py for the seams.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import openai
import pytest

try:
    from . import _harness_llm as H
except ImportError:  # pragma: no cover - collected without package context
    import _harness_llm as H  # type: ignore

from confidential_mode.tiers import Destination, Tier, Verdict

# pytest discovers fixtures by name in the test module namespace.
_no_lazy_installs = H._no_lazy_installs
manager = H.manager

SECRET = H.SECRET
MODES = H.MODES


def _turn(agent):
    return agent.run_conversation(f"please summarise {SECRET}")


def _gate(manager, rec, *, decide=None, tier=Tier.ON_HOST, locked=True, ledger=None, attested_ok=None):
    pred = H.FakePredicate(decide or H.always(False), tier=tier)
    ledger = ledger if ledger is not None else H.FakeLedger()
    if isinstance(locked, H.Lock):
        locked.tier = tier
        lock = locked
    else:
        lock = H.Lock(locked, tier=tier)
    H.install_gate(manager, rec, predicate=pred, ledger=ledger, is_locked=lock, attested_ok=attested_ok)
    return pred, ledger, lock


def _assert_provider_answer(result, rec, n_sends=1):
    assert len(rec.provider_calls) == n_sends, rec.provider_calls
    assert result.get("completed") is True, result
    assert result["final_response"] == H.PROVIDER_TEXT


# =============================================================================================
# Baseline allow twins (so every refusal test below has a passing mutant twin)
# =============================================================================================


@pytest.mark.parametrize("api_mode", MODES)
def test_locked_in_tier_reaches_provider_exactly_once(monkeypatch, manager, api_mode):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, api_mode, rec)
    pred, ledger, _ = _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    _assert_provider_answer(result, rec)
    assert rec.fallback_calls == []
    assert "send_refused" not in H.kinds(ledger)
    H.assert_no_secret_in_ledger(ledger)


@pytest.mark.parametrize("api_mode", MODES)
def test_unlocked_passes_through_and_observes(monkeypatch, manager, api_mode):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, api_mode, rec)
    pred, ledger, _ = _gate(manager, rec, decide=H.always(False), locked=False)
    result = _turn(agent)
    _assert_provider_answer(result, rec)
    assert "send_observed" in H.kinds(ledger)
    assert "send_refused" not in H.kinds(ledger)
    H.assert_no_secret_in_ledger(ledger)


# =============================================================================================
# Off-tier refusal, every api_mode, streaming and not
# =============================================================================================


@pytest.mark.parametrize("api_mode", MODES)
def test_off_tier_locked_refuses_with_zero_provider_requests(monkeypatch, manager, api_mode):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, api_mode, rec)
    pred, ledger, _ = _gate(manager, rec, decide=H.always(False, "off-tier host"))
    result = _turn(agent)
    H.assert_refused_clean(result, rec, agent)
    assert H.kinds(ledger).count("send_refused") == 1, H.kinds(ledger)
    assert "send_observed" not in H.kinds(ledger), "a refused send must not be ledgered as observed"
    H.assert_no_secret_in_ledger(ledger)
    assert len(pred.seen) == 1


@pytest.mark.parametrize("api_mode", MODES)
def test_off_tier_streaming_refuses_with_zero_provider_requests(monkeypatch, manager, api_mode):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, api_mode, rec, streaming=True)
    from agent.turn_api_call import _should_stream
    if not _should_stream(agent):
        pytest.skip(f"{api_mode}: Hermes does not stream for this configuration")
    pred, ledger, _ = _gate(manager, rec, decide=H.always(False))
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert "send_refused" in H.kinds(ledger)


@pytest.mark.parametrize("api_mode", MODES)
def test_in_tier_streaming_provider_500_refuses_without_retry_or_fallback(monkeypatch, manager, api_mode):
    rec = H.Rec()

    def respond(n, kw, agent):
        raise H.status_error_500()

    agent = H.build_agent(monkeypatch, api_mode, rec, streaming=True, respond=respond)
    _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1, "provider called exactly once (no Hermes retry)"
    rec.provider_calls.clear()
    H.assert_refused_clean(result, rec, agent)


# =============================================================================================
# Predicate attacks
# =============================================================================================


@pytest.mark.parametrize("exc", [RuntimeError("predicate bug"), ValueError("bad url"), KeyError("extra_hosts"),
                                 AttributeError("NoneType has no attribute hostname"), RecursionError()],
                         ids=lambda e: type(e).__name__)
def test_predicate_raising_refuses_and_never_reaches_provider(monkeypatch, manager, exc):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)

    def decide(dest):
        raise exc

    _gate(manager, rec, decide=decide)
    H.assert_refused_clean(_turn(agent), rec, agent)


@dataclass(frozen=True)
class _WeirdVerdict(Verdict):
    pass


def _weird(in_tier_value):
    v = _WeirdVerdict(in_tier=False, reason="weird", host="x")
    object.__setattr__(v, "in_tier", in_tier_value)
    return v


class _Truthy:
    def __bool__(self):
        return True


@pytest.mark.parametrize("value", ["False", "no", "", MagicMock(), _Truthy(), [False], 1],
                         ids=["str-False", "str-no", "empty-str", "MagicMock", "truthy-obj", "list", "int-1"])
def test_predicate_verdict_subclass_with_non_bool_in_tier_refuses(monkeypatch, manager, value):
    """in_tier is typed bool. Anything that is not exactly True must not open the gate
    (``if verdict.in_tier:`` would open it for every truthy value here)."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    _gate(manager, rec, decide=lambda d: _weird(value))
    H.assert_refused_clean(_turn(agent), rec, agent)


class _ExplodingVerdict(Verdict):
    @property
    def in_tier(self):  # type: ignore[override]
        raise RuntimeError("in_tier exploded")


@pytest.mark.parametrize("returned", [None, {"in_tier": True}, True, "in_tier", MagicMock(),
                                      SimpleNamespace(in_tier="yes", reason="r", host="h")],
                         ids=["None", "dict", "True", "str", "MagicMock", "namespace-str"])
def test_predicate_returning_non_verdict_refuses(monkeypatch, manager, returned):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    _gate(manager, rec, decide=lambda d: returned)
    H.assert_refused_clean(_turn(agent), rec, agent)


def test_predicate_verdict_whose_in_tier_property_raises_refuses(monkeypatch, manager):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)

    def decide(dest):
        v = object.__new__(_ExplodingVerdict)
        object.__setattr__(v, "reason", "r")
        object.__setattr__(v, "host", "h")
        return v

    _gate(manager, rec, decide=decide)
    H.assert_refused_clean(_turn(agent), rec, agent)


def test_predicate_receives_destination_exactly_from_context(monkeypatch, manager):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    pred, _, _ = _gate(manager, rec, decide=H.always(False))
    _turn(agent)
    assert len(pred.seen) == 1
    d, ctx = pred.seen[0], rec.middleware_calls[0]
    assert isinstance(d, Destination)
    assert (d.provider, d.base_url, d.model, d.api_mode) == (
        ctx["provider"], ctx["base_url"], ctx["model"], ctx["api_mode"])
    assert d.purpose == "main"


# =============================================================================================
# attested_ok attacks (ATTESTED tier; the predicate says in-tier, W2's freshness check decides)
# =============================================================================================


@pytest.mark.parametrize("exc", [RuntimeError("verifier crashed"), TimeoutError("attestation timed out"),
                                 httpx.ConnectError("enclave unreachable"), OSError("cache dir")],
                         ids=lambda e: type(e).__name__)
def test_attested_ok_raising_never_reaches_provider(monkeypatch, manager, exc):
    from confidential_mode.verify.base import VerifyError  # noqa: F401  (frozen type exists)
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)

    def boom(provider):
        raise exc

    att = H.AttestedOk(boom)
    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=att)
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert att.calls, "the attested tier must consult attested_ok before next_call"


def test_attested_ok_verify_error_never_reaches_provider(monkeypatch, manager):
    from confidential_mode.verify.base import VerifyError
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)

    def boom(provider):
        raise VerifyError("measurement mismatch")

    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=H.AttestedOk(boom))
    H.assert_refused_clean(_turn(agent), rec, agent)


def test_attested_ok_off_verdict_object_is_not_truthy_permission(monkeypatch, manager):
    """A Verdict dataclass instance is truthy; ``if attested_ok(p):`` would open the gate."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    att = H.attested_verdict(False, "enclave build changed")
    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=att)
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert att.calls == [agent.provider], "attested_ok is asked about the provider Hermes is calling"


@pytest.mark.parametrize("returned", [None, MagicMock(), object(), "ok", _weird("True")],
                         ids=["None", "MagicMock", "object", "str", "verdict-str-in_tier"])
def test_attested_ok_returning_garbage_refuses(monkeypatch, manager, returned):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=H.AttestedOk(lambda p: returned))
    H.assert_refused_clean(_turn(agent), rec, agent)


def test_attested_ok_slow_never_sends_before_it_answers_and_refuses_on_stale(monkeypatch, manager):
    """attested_ok blocks (W2 refreshing attestation). Nothing may reach the provider while it
    blocks (no 'optimistic' send, no timeout-then-proceed), and a stale answer refuses."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    entered, release = threading.Event(), threading.Event()
    sends_while_blocked = []

    def slow(provider):
        entered.set()
        release.wait(10)
        sends_while_blocked.append(len(rec.provider_calls))
        return Verdict(in_tier=False, reason="verification stale", host="")

    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=H.AttestedOk(slow))
    box_holder = {}
    t = threading.Thread(target=lambda: box_holder.update(r=_turn(agent)), daemon=True)
    t.start()
    assert entered.wait(10), "attested_ok never consulted"
    threading.Event().wait(1.5)  # let any timeout-and-proceed logic fire
    assert rec.provider_calls == [], "LEAK: provider called while attested_ok was still deciding"
    release.set()
    t.join(30)
    assert not t.is_alive()
    assert sends_while_blocked == [0]
    H.assert_refused_clean(box_holder["r"], rec, agent)


def test_attested_tier_in_tier_and_fresh_is_allowed(monkeypatch, manager):
    """Allow twin for the attested_ok attacks."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    att = H.attested_verdict(True)
    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=att)
    _assert_provider_answer(_turn(agent), rec)
    assert att.calls == [agent.provider]


def test_attested_tier_off_tier_predicate_refuses_even_if_attested_ok_says_fresh(monkeypatch, manager):
    """attested_ok is about the provider name; the predicate is about the destination. A fresh
    verification for a provider must not override an off-tier predicate verdict."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    _gate(manager, rec, decide=H.always(False), tier=Tier.ATTESTED, attested_ok=H.attested_verdict(True))
    H.assert_refused_clean(_turn(agent), rec, agent)


# =============================================================================================
# Ledger attacks: logging failure can never open the gate
# =============================================================================================

_LEDGER_EXCS = [OSError("disk full"), sqlite3.OperationalError("database is locked"),
                RuntimeError("ledger closed"), TypeError("Object of type bytes is not JSON serializable")]


@pytest.mark.parametrize("exc", _LEDGER_EXCS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("api_mode", MODES)
def test_ledger_append_raising_still_refuses_off_tier(monkeypatch, manager, api_mode, exc):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, api_mode, rec)
    ledger = H.FakeLedger(fail=exc)
    _gate(manager, rec, decide=H.always(False), ledger=ledger)
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert ledger.attempts, "the gate tried to ledger the refusal"


@pytest.mark.parametrize("exc", _LEDGER_EXCS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("api_mode", MODES)
def test_ledger_append_raising_during_in_tier_429_still_refuses_without_retry(monkeypatch, manager, api_mode, exc):
    """The provider 429s; while handling it the ledger raises. If that exception escapes the
    gate after a failed next_call, Hermes retries the whole chain and arms fallback/cooldown."""
    rec = H.Rec()

    def respond(n, kw, agent):
        raise H.rate_limit_429()

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond)
    ledger = H.FakeLedger(fail=exc)
    _gate(manager, rec, decide=H.always(True), ledger=ledger)
    result = _turn(agent)
    assert len(rec.provider_calls) == 1, "provider called once; no Hermes retry"
    rec.provider_calls.clear()
    H.assert_refused_clean(result, rec, agent)


def test_ledger_append_raising_only_on_refusal_rows_still_refuses(monkeypatch, manager):
    """A ledger that accepts some kinds and fails on send_refused (e.g. a schema bug)."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    ledger = H.FakeLedger(fail=lambda ev: H.ev_field(ev, "kind") != "send_observed")
    _gate(manager, rec, decide=H.always(False), ledger=ledger)
    H.assert_refused_clean(_turn(agent), rec, agent)


@pytest.mark.parametrize("locked,decide", [(False, H.always(False)), (True, H.always(True))],
                         ids=["unlocked", "locked-in-tier"])
def test_ledger_append_raising_never_double_sends(monkeypatch, manager, locked, decide):
    """Ledger failure on an allowed send. Ruling (C2): the ledger is best effort and never changes
    a decision, so the turn passes through exactly once (a gate that retries next_call, or raises
    so Hermes re-runs the chain, would send twice; one that refuses changed the decision)."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    _gate(manager, rec, decide=decide, locked=locked, ledger=H.FakeLedger(fail=OSError("disk full")))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1, f"provider received {len(rec.provider_calls)} requests"
    assert rec.fallback_calls == []
    assert result.get("completed") is True and not result.get("failed"), result
    assert result["final_response"] == H.PROVIDER_TEXT


# =============================================================================================
# Context attacks: api_mode / provider / base_url odd or missing
# =============================================================================================


@pytest.mark.parametrize("bad_mode", ["made_up_mode", "codex_app_server", "", None, 42, "CHAT_COMPLETIONS"],
                         ids=["made-up", "codex_app_server", "empty", "None", "int", "upper"])
def test_unknown_api_mode_in_context_still_refuses_off_tier(monkeypatch, manager, bad_mode):
    """Refusal construction for an unexpected api_mode must not raise (that would escape and fail
    open); the contract says fall back to the chat_completions shape, which this agent accepts."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    H.mutate_context(monkeypatch, lambda c: c.__setitem__("api_mode", bad_mode))
    _, ledger, _ = _gate(manager, rec, decide=H.always(False))
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert ledger.attempts, "unknown api_mode should leave a ledger note / refusal row"


def test_api_mode_missing_from_context_still_refuses(monkeypatch, manager):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    H.mutate_context(monkeypatch, lambda c: c.pop("api_mode", None))
    _gate(manager, rec, decide=H.always(False))
    H.assert_refused_clean(_turn(agent), rec, agent)


@pytest.mark.parametrize("api_mode", [
    "chat_completions",
    pytest.param("codex_responses", marks=pytest.mark.xfail(strict=False, reason=(
        "CONTRACT HOLE (flagged for W1/C1): 'unknown api_mode -> chat_completions shape' is an "
        "invalid response for a non-chat agent, so Hermes runs its invalid-response cycle: the "
        "gate is re-entered 3x, the in-tier provider is re-sent the conversation 3x, and eager "
        "fallback is attempted 4x. Only reachable if the context api_mode disagrees with the "
        "agent's (e.g. a future Hermes api_mode)."))),
])
def test_unknown_api_mode_in_context_with_in_tier_500_still_refuses(monkeypatch, manager, api_mode):
    """The error-path refusal builder with a junk api_mode must not raise after a failed
    next_call (an escape there re-runs the chain: retries + fallback)."""
    rec = H.Rec()

    def respond(n, kw, agent):
        raise H.status_error_500()

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond)
    H.mutate_context(monkeypatch, lambda c: c.__setitem__("api_mode", "made_up_mode"))
    _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1
    assert rec.fallback_calls == [] and rec.backoff_calls == []
    assert getattr(agent, "_rate_limited_until", 0) in (0, None)
    if api_mode == "chat_completions":
        rec.provider_calls.clear()
        H.assert_refused_clean(result, rec, agent)


@pytest.mark.parametrize("mutation", [
    lambda c: c.pop("provider", None),
    lambda c: c.pop("base_url", None),
    lambda c: (c.pop("provider", None), c.pop("base_url", None)),
    lambda c: c.__setitem__("base_url", None),
    lambda c: c.__setitem__("provider", None),
    lambda c: c.pop("model", None),
    lambda c: c.pop("session_id", None),
    lambda c: c.__setitem__("base_url", object()),
], ids=["no-provider", "no-base_url", "neither", "base_url-None", "provider-None", "no-model", "no-session",
        "base_url-object"])
def test_missing_or_odd_context_fields_never_fail_open(monkeypatch, manager, mutation):
    """The oracle predicate is in-tier only for the agent's real host; with that host missing
    from the context, the gate must refuse (or classify '' -> off-tier), never KeyError out."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    H.mutate_context(monkeypatch, mutation)
    real_host = H.host_of(H.IN_TIER_URL)

    def decide(dest):
        if dest.provider in ("", "None") or not isinstance(dest.base_url, str):
            return Verdict(in_tier=False, reason="no provider", host="")
        return H.by_host(real_host)(dest)

    _gate(manager, rec, decide=lambda d: Verdict(False, "unknown", "") if d.base_url in ("", "None") else decide(d))
    result = _turn(agent)
    ctx = rec.middleware_calls[0]
    if "base_url" in ctx and ctx["base_url"] == H.IN_TIER_URL and ctx.get("provider"):
        # model / session_id removed: the destination is still in-tier; one send is fine.
        assert len(rec.provider_calls) <= 1
        assert rec.fallback_calls == []
    else:
        H.assert_refused_clean(result, rec, agent)


@pytest.mark.parametrize("url,allowed", [
    ("http://127.0.0.1@evil.example/v1", "127.0.0.1"),
    ("http://127.0.0.1:8080@evil.example:443/v1", "127.0.0.1"),
    ("https://evil.example/v1/127.0.0.1", "127.0.0.1"),
    ("https://evil.example/localhost/v1", "localhost"),
    ("http://localhost.evil.example/v1", "localhost"),
    ("https://evil.example/v1?host=127.0.0.1", "127.0.0.1"),
    ("https://evil.example/v1#@127.0.0.1", "127.0.0.1"),
], ids=["userinfo", "userinfo-port", "path-ip", "path-localhost", "suffix", "query", "fragment"])
def test_base_url_with_userinfo_or_trailing_path_reaches_predicate_verbatim(monkeypatch, manager, url, allowed):
    """The gate must hand the predicate base_url exactly as Hermes passed it; any 'helpful'
    normalisation (strip userinfo, take the last path segment) lets a crafted URL pass as on-host."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec, base_url=url)
    pred, ledger, _ = _gate(manager, rec, decide=H.by_host(allowed))
    result = _turn(agent)
    ctx_url = rec.middleware_calls[0]["base_url"]
    assert H.host_of(ctx_url) != allowed, f"Hermes itself rewrote the URL ({ctx_url}); test premise broken"
    assert [d.base_url for d in pred.seen] == [ctx_url], "base_url altered before classification"
    H.assert_refused_clean(result, rec, agent)


@pytest.mark.parametrize("url", ["http://127.0.0.1@evil.example/v1", "https://evil.example/v1/127.0.0.1",
                                 "http://localhost.evil.example/v1"], ids=["userinfo", "path-ip", "suffix"])
def test_unlocked_watch_view_host_is_the_real_host(monkeypatch, manager, url):
    """send_observed feeds the watch view; a naive host parse would show '127.0.0.1' for a send
    that actually went to evil.example."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec, base_url=url)
    _, ledger, _ = _gate(manager, rec, decide=H.always(False), locked=False)
    _turn(agent)
    obs = [e for e in ledger.events if H.ev_field(e, "kind") == "send_observed"]
    assert len(obs) == 1
    real = H.host_of(rec.middleware_calls[0]["base_url"])
    host = str(H.ev_field(obs[0], "host") or "").lower()
    assert host in (real, f"{real}:{httpx.URL(rec.middleware_calls[0]['base_url']).port}"), (host, real)


# =============================================================================================
# Request payload attacks (byte size must not raise; prompt text never ledgered)
# =============================================================================================


def test_unlocked_send_observed_records_byte_size_not_prompt(monkeypatch, manager):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    _, ledger, _ = _gate(manager, rec, locked=False)
    _turn(agent)
    obs = [e for e in ledger.events if H.ev_field(e, "kind") == "send_observed"]
    assert len(obs) == 1
    b = H.ev_field(obs[0], "bytes")
    assert isinstance(b, int) and not isinstance(b, bool) and b > len(SECRET), b
    H.assert_no_secret_in_ledger(ledger)


def _unserialisable(request):
    out = dict(request)
    out["extra_body"] = {"blob": b"\xff\xfe" + SECRET.encode(), "obj": object(), "set": {1, 2},
                         "cb": lambda: None}
    return out


def _circular(request):
    out = dict(request)
    loop: dict = {}
    loop["self"] = loop
    out["metadata"] = loop
    return out


@pytest.mark.parametrize("mutate", [_unserialisable, _circular], ids=["unserialisable", "circular"])
def test_non_json_request_unlocked_still_sends_exactly_once(monkeypatch, manager, mutate):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    H.install_outer_payload_mutator(manager, mutate)
    _, ledger, _ = _gate(manager, rec, locked=False)
    _assert_provider_answer(_turn(agent), rec)
    assert "send_observed" in H.kinds(ledger)
    H.assert_no_secret_in_ledger(ledger)


@pytest.mark.parametrize("mutate", [_unserialisable, _circular], ids=["unserialisable", "circular"])
def test_non_json_request_locked_in_tier_still_sends_exactly_once(monkeypatch, manager, mutate):
    """Byte-size computation raising would be converted into a refusal of a legitimate turn."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    H.install_outer_payload_mutator(manager, mutate)
    _gate(manager, rec, decide=H.always(True))
    _assert_provider_answer(_turn(agent), rec)


@pytest.mark.parametrize("mutate", [_unserialisable, _circular], ids=["unserialisable", "circular"])
def test_non_json_request_locked_off_tier_refuses_with_zero_sends(monkeypatch, manager, mutate):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    H.install_outer_payload_mutator(manager, mutate)
    _, ledger, _ = _gate(manager, rec, decide=H.always(False))
    H.assert_refused_clean(_turn(agent), rec, agent)
    H.assert_no_secret_in_ledger(ledger)


@pytest.mark.parametrize("api_mode", ["chat_completions", "anthropic_messages"])
def test_provider_error_echoing_prompt_is_not_shown_or_ledgered(monkeypatch, manager, api_mode):
    """Providers echo request fragments in 4xx/5xx bodies. The refusal is user-visible and the
    ledger never stores prompt text, so str(exc) must go to neither."""
    rec = H.Rec()

    def respond(n, kw, agent):
        raise H.status_error_500(f"invalid request: messages[0].content={SECRET!r}")

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond)
    _, ledger, _ = _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1
    assert SECRET not in (result.get("final_response") or "")
    H.assert_no_secret_in_ledger(ledger)


# =============================================================================================
# Fallback re-entry and lock flips within one turn
# =============================================================================================


def test_fallback_reentry_with_off_tier_provider_is_refused(monkeypatch, manager):
    """The in-tier provider returns an invalid response; Hermes' eager fallback switches the agent
    to openrouter mid-turn and the retry RE-ENTERS the gate with the new provider/base_url. The gate
    cannot stop the switch, but it must refuse the off-tier re-entry: zero requests to openrouter."""
    rec = H.Rec()

    def respond(n, kw, agent):
        return None  # invalid response -> eager fallback

    agent = H.build_agent(monkeypatch, "chat_completions", rec, respond=respond)
    H.configure_fallback_to_openrouter(monkeypatch, agent)
    pred, ledger, _ = _gate(manager, rec, decide=H.by_host(H.host_of(H.IN_TIER_URL)))
    result = _turn(agent)
    assert H.host_of(H.OFF_TIER_URL) in {H.host_of(d.base_url) for d in pred.seen}, \
        "premise: the retry re-entered the gate on the fallback host"
    assert rec.sends_to(H.host_of(H.OFF_TIER_URL)) == [], "LEAK: request sent to the fallback provider"
    assert all(H.host_of(c["base_url"]) == H.host_of(H.IN_TIER_URL) for c in rec.provider_calls)
    assert "send_refused" in H.kinds(ledger)
    fb = [d for d in pred.seen if H.host_of(d.base_url) == H.host_of(H.OFF_TIER_URL)]
    assert all(d.provider == "openrouter" for d in fb), [d.provider for d in fb]
    assert result.get("final_response") != H.PROVIDER_TEXT


def test_fallback_reentry_attested_tier_asks_attested_ok_for_new_provider(monkeypatch, manager):
    """Same re-entry under the attested tier, with a predicate that (wrongly, for the attack) says
    in-tier for everything: attested_ok must be asked about 'openrouter', not a cached answer for
    the original provider."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec, respond=lambda n, kw, a: None)
    H.configure_fallback_to_openrouter(monkeypatch, agent)
    original = agent.provider
    att = H.AttestedOk(lambda p: Verdict(in_tier=(p == original), reason="x", host=""))
    _gate(manager, rec, decide=H.always(True), tier=Tier.ATTESTED, attested_ok=att)
    _turn(agent)
    assert "openrouter" in att.calls, att.calls
    assert rec.sends_to(H.host_of(H.OFF_TIER_URL)) == []


def test_is_locked_flip_after_first_read_does_not_open_gate(monkeypatch, manager):
    """is_locked answers True once, then False. A gate that reads it more than once per call
    (e.g. once to decide, again inside a helper) can take the unlocked branch for a locked call."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    lock = H.Lock([True, False])
    _gate(manager, rec, decide=H.always(False), locked=lock)
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert lock.calls >= 1


def test_lock_engaged_mid_turn_refuses_the_retry(monkeypatch, manager):
    """Unlocked first call returns an invalid response; the user locks; Hermes' retry re-enters
    the gate. The lock must be read per call, not cached per gate or per turn."""
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec, respond=lambda n, kw, a: None)
    lock = H.Lock([False, True])
    _, ledger, _ = _gate(manager, rec, decide=H.always(False), locked=lock)
    result = _turn(agent)
    assert len(rec.middleware_calls) >= 2 or rec.provider_calls == [], "premise: Hermes retried through the gate"
    assert len(rec.provider_calls) <= 1, "LEAK: a call after the lock reached the provider"
    assert "send_refused" in H.kinds(ledger)
    assert result.get("final_response") != H.PROVIDER_TEXT


def test_off_tier_refusal_then_in_tier_next_turn_is_not_sticky(monkeypatch, manager):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    state = {"in": False}
    pred, ledger, _ = _gate(manager, rec, decide=lambda d: H.always(state["in"])(d))
    H.assert_refused_clean(_turn(agent), rec, agent)
    state["in"] = True
    result = agent.run_conversation("second turn")
    assert len(rec.provider_calls) == 1, "in-tier second turn must reach the provider"
    assert result["final_response"] == H.PROVIDER_TEXT
    assert len(pred.seen) == 2


def test_in_tier_turn_then_off_tier_turn_is_refused_no_cached_verdict(monkeypatch, manager):
    rec = H.Rec()
    agent = H.build_agent(monkeypatch, "chat_completions", rec)
    state = {"in": True}
    pred, _, _ = _gate(manager, rec, decide=lambda d: H.always(state["in"])(d))
    _assert_provider_answer(agent.run_conversation("first"), rec)
    state["in"] = False
    rec.middleware_calls.clear()
    rec.provider_calls.clear()
    H.assert_refused_clean(_turn(agent), rec, agent)
    assert len(pred.seen) == 2, "the predicate must be consulted on every locked call"


def test_in_tier_500_then_next_turn_still_classified_fresh(monkeypatch, manager):
    """After an error refusal, the next turn must neither be pre-refused nor pre-approved."""
    rec = H.Rec()

    def respond(n, kw, agent):
        if n == 0:
            raise H.status_error_500()
        return H.provider_ok("chat_completions")

    agent = H.build_agent(monkeypatch, "chat_completions", rec, respond=respond)
    state = {"in": True}
    pred, _, _ = _gate(manager, rec, decide=lambda d: H.always(state["in"])(d))
    r1 = _turn(agent)
    assert len(rec.provider_calls) == 1 and r1["final_response"] != H.PROVIDER_TEXT
    r2 = agent.run_conversation("again")
    assert len(rec.provider_calls) == 2 and r2["final_response"] == H.PROVIDER_TEXT
    state["in"] = False
    rec.provider_calls.clear()
    rec.middleware_calls.clear()
    H.assert_refused_clean(_turn(agent), rec, agent)


# =============================================================================================
# User stop and process-level exceptions
# =============================================================================================


def _baseline(monkeypatch, manager_factory, api_mode, exc_factory, streaming=False):
    """Same turn with a pass-through middleware instead of the gate (what Hermes does on its own)."""
    rec = H.Rec()

    def respond(n, kw, agent):
        raise exc_factory()

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond, streaming=streaming)
    mgr = manager_factory()

    def passthrough(request, next_call, **context):
        return next_call(request)

    H.PluginContext(H.PluginManifest(name="baseline"), mgr).register_middleware("llm_execution", passthrough)
    box = H.run_in_thread(lambda: _turn(agent))
    return box, rec


def _fresh_manager(monkeypatch):
    def factory():
        mgr = H.PluginManager()
        mgr._discovered = True
        monkeypatch.setattr(H.plugins_mod, "get_plugin_manager", lambda: mgr)
        return mgr
    return factory


@pytest.mark.parametrize("streaming", [False, True], ids=["nonstream", "stream"])
@pytest.mark.parametrize("api_mode", MODES)
def test_interrupted_error_from_provider_propagates_not_refused(monkeypatch, manager, api_mode, streaming):
    """InterruptedError is the user's stop/redirect. A catch-all would turn it into a refusal and
    the UI would show a completed turn instead of an interrupted one."""
    from agent.conversation_loop import INTERRUPT_WAITING_FOR_MODEL_PREFIX
    rec = H.Rec()

    def respond(n, kw, agent):
        raise InterruptedError("user pressed stop")

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond, streaming=streaming)
    _, ledger, _ = _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1
    assert result.get("interrupted") is True, result
    assert (result.get("final_response") or "").startswith(INTERRUPT_WAITING_FOR_MODEL_PREFIX), result
    assert rec.fallback_calls == [] and rec.backoff_calls == []


@pytest.mark.parametrize("api_mode", ["chat_completions", "anthropic_messages"])
def test_interrupted_error_matches_hermes_baseline(monkeypatch, manager, api_mode):
    from agent.conversation_loop import INTERRUPT_WAITING_FOR_MODEL_PREFIX
    rec = H.Rec()

    def respond(n, kw, agent):
        raise InterruptedError("stop")

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond)
    _gate(manager, rec, decide=H.always(True))
    gated = _turn(agent)
    base_box, base_rec = _baseline(monkeypatch, _fresh_manager(monkeypatch), api_mode,
                                   lambda: InterruptedError("stop"))
    base = base_box["result"]
    for key in ("interrupted", "completed", "failed", "api_calls"):
        assert gated.get(key) == base.get(key), (key, gated.get(key), base.get(key))
    assert (base["final_response"] or "").startswith(INTERRUPT_WAITING_FOR_MODEL_PREFIX)
    assert len(rec.provider_calls) == len(base_rec.provider_calls) == 1


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit, GeneratorExit],
                         ids=["KeyboardInterrupt", "SystemExit", "GeneratorExit"])
def test_base_exception_from_provider_is_not_converted_to_refusal(monkeypatch, manager, exc_type):
    """Decision: BaseExceptions that are not Exceptions (Ctrl-C, sys.exit, generator close) belong
    to the process, not the gate. Correct = the turn behaves EXACTLY as Hermes behaves with a
    pass-through middleware (Hermes' next_call does not wrap them, so a gate using ``except
    Exception`` lets them through untouched). A gate using ``except BaseException`` would turn
    Ctrl-C into a polite refusal and keep the process running."""
    rec = H.Rec()

    def respond(n, kw, agent):
        raise exc_type()

    agent = H.build_agent(monkeypatch, "chat_completions", rec, respond=respond)
    _gate(manager, rec, decide=H.always(True))
    gated = H.run_in_thread(lambda: _turn(agent))
    base, base_rec = _baseline(monkeypatch, _fresh_manager(monkeypatch), "chat_completions", exc_type)
    assert len(rec.provider_calls) == 1
    assert ("exc" in gated) == ("exc" in base), (gated, base)
    if "exc" in base:
        assert type(gated["exc"]) is type(base["exc"]), (gated, base)
    else:
        g, b = gated["result"], base["result"]
        for key in ("interrupted", "completed", "failed", "final_response"):
            assert g.get(key) == b.get(key), (key, g.get(key), b.get(key))
    assert len(rec.provider_calls) == len(base_rec.provider_calls)


# =============================================================================================
# 429 / 500 under lock: no sleep, no cooldown, no fallback
# =============================================================================================


@pytest.mark.parametrize("retry_after", ["30", "0", "86400", "garbage"])
@pytest.mark.parametrize("api_mode", MODES)
def test_locked_429_retry_after_no_sleep_no_cooldown_no_fallback(monkeypatch, manager, api_mode, retry_after):
    rec = H.Rec()

    def respond(n, kw, agent):
        raise H.rate_limit_429(retry_after)

    agent = H.build_agent(monkeypatch, api_mode, rec, respond=respond)
    agent._fallback_chain = [{"provider": "openrouter", "model": "fallback/model"}]
    _, ledger, _ = _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1
    rec.provider_calls.clear()
    H.assert_refused_clean(result, rec, agent)
    assert not hasattr(agent, "_rate_limited_until") or not agent._rate_limited_until
    H.assert_no_secret_in_ledger(ledger)


@pytest.mark.parametrize("make_exc", [
    lambda: H.status_error_500(),
    lambda: openai.APIConnectionError(request=httpx.Request("POST", H.IN_TIER_URL)),
    lambda: openai.APITimeoutError(request=httpx.Request("POST", H.IN_TIER_URL)),
    lambda: openai.AuthenticationError("bad key", response=httpx.Response(
        401, request=httpx.Request("POST", H.IN_TIER_URL)), body=None),
    lambda: openai.BadRequestError("context length exceeded", response=httpx.Response(
        400, request=httpx.Request("POST", H.IN_TIER_URL)), body=None),
    lambda: RuntimeError("SDK bug"),
    lambda: ConnectionResetError("peer reset"),
], ids=["500", "connection", "timeout", "401", "400-context", "RuntimeError", "ConnectionReset"])
def test_locked_in_tier_any_provider_error_refuses_once_without_failover(monkeypatch, manager, make_exc):
    """Every error class Hermes would recover from by retry/compress/rotate/fallback must end the
    turn instead (each of those recoveries can re-send the conversation)."""
    rec = H.Rec()

    def respond(n, kw, agent):
        raise make_exc()

    agent = H.build_agent(monkeypatch, "chat_completions", rec, respond=respond)
    agent._fallback_chain = [{"provider": "openrouter", "model": "fallback/model"}]
    _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(rec.provider_calls) == 1
    rec.provider_calls.clear()
    H.assert_refused_clean(result, rec, agent)


# =============================================================================================
# Request-scoped client path: real _interruptible_api_call, real openai.OpenAI, MockTransport
# =============================================================================================


def _wire_agent(monkeypatch, rec, respond=None):
    agent = H.build_agent(monkeypatch, "chat_completions", rec, fake_terminal=False)
    wire = H.WireRecorder(respond)
    wire.install(agent)
    return agent, wire


def test_request_scoped_client_path_off_tier_zero_wire_requests(monkeypatch, manager):
    rec = H.Rec()
    agent, wire = _wire_agent(monkeypatch, rec)
    _gate(manager, rec, decide=H.always(False))
    result = _turn(agent)
    assert wire.requests == [], "LEAK: an HTTP request reached the transport"
    H.assert_refused_clean(result, rec, agent)


def test_request_scoped_client_path_in_tier_one_wire_request(monkeypatch, manager):
    """Allow twin: proves the wire seam is live (otherwise the zero-request test proves nothing)."""
    rec = H.Rec()
    agent, wire = _wire_agent(monkeypatch, rec)
    _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(wire.requests) == 1
    assert result["final_response"] == H.PROVIDER_TEXT
    assert SECRET in wire.requests[0].content.decode()


@pytest.mark.parametrize("status,headers", [(429, {"retry-after": "30"}), (500, {}), (503, {"retry-after": "5"})])
def test_request_scoped_client_path_locked_http_error_one_wire_request(monkeypatch, manager, status, headers):
    rec = H.Rec()
    agent, wire = _wire_agent(monkeypatch, rec, respond=lambda req, n: httpx.Response(
        status, headers=headers, json={"error": {"message": f"echo {SECRET}"}}))
    agent._fallback_chain = [{"provider": "openrouter", "model": "fallback/model"}]
    _, ledger, _ = _gate(manager, rec, decide=H.always(True))
    result = _turn(agent)
    assert len(wire.requests) == 1, f"{len(wire.requests)} wire requests (SDK or Hermes retried)"
    H.assert_refused_clean(result, rec, agent)
    H.assert_no_secret_in_ledger(ledger)


# =============================================================================================
# Concurrency: two turns on two threads, one gate
# =============================================================================================


@pytest.mark.parametrize("order", ["off-classifies-while-in-is-sending", "in-classifies-while-off-is-deciding"])
def test_concurrent_turns_share_gate_without_cross_talk(monkeypatch, manager, order):
    """Two agents, one gate instance (registered once). Agent A is in-tier, agent B is off-tier.
    Interleave them so any per-gate mutable state (last destination, last verdict, a 'current
    provider' attribute) set by A is live while B is decided, and vice versa."""
    in_host, off_host = "in.example.test", "off.example.test"
    rec_a, rec_b = H.Rec(), H.Rec()
    a_sending, b_done, a_classified = threading.Event(), threading.Event(), threading.Event()
    b_classifying = threading.Event()

    def respond_a(n, kw, agent):
        a_sending.set()
        b_done.wait(5)
        return H.provider_ok("chat_completions")

    agent_a = H.build_agent(monkeypatch, "chat_completions", rec_a, respond=respond_a,
                            base_url=f"https://{in_host}/v1")
    agent_b = H.build_agent(monkeypatch, "chat_completions", rec_b, base_url=f"https://{off_host}/v1")

    def decide(dest):
        h = H.host_of(dest.base_url)
        if order == "off-classifies-while-in-is-sending" and h == off_host:
            a_sending.wait(5)
        if order == "in-classifies-while-off-is-deciding":
            if h == in_host:
                b_classifying.wait(5)
                verdict = Verdict(True, "in", h)
                a_classified.set()
                return verdict
            if h == off_host:
                b_classifying.set()
                a_classified.wait(5)
        return H.by_host(in_host)(dest)

    pred = H.FakePredicate(decide)
    ledger = H.FakeLedger()
    shared_rec = H.Rec()
    H.install_gate(manager, shared_rec, predicate=pred, ledger=ledger, is_locked=H.Lock(True))

    box_a, box_b = {}, {}
    ta = threading.Thread(target=lambda: box_a.update(r=_turn(agent_a)), daemon=True)

    def run_b():
        try:
            box_b.update(r=_turn(agent_b))
        finally:
            b_done.set()

    tb = threading.Thread(target=run_b, daemon=True)
    ta.start()
    tb.start()
    ta.join(30)
    tb.join(30)
    assert not ta.is_alive() and not tb.is_alive()
    assert rec_b.provider_calls == [], "LEAK: off-tier agent B reached its provider"
    assert len(rec_a.provider_calls) == 1, "in-tier agent A was not allowed exactly once"
    assert box_a["r"]["final_response"] == H.PROVIDER_TEXT
    assert box_b["r"]["final_response"] != H.PROVIDER_TEXT and box_b["r"].get("completed") is True
    refused = [e for e in ledger.events if H.ev_field(e, "kind") == "send_refused"]
    assert len(refused) == 1


def test_concurrent_many_turns_off_tier_never_leak(monkeypatch, manager):
    """Eight agents alternating in/off tier hammer one gate; no off-tier agent sends."""
    in_host, off_host = "in.example.test", "off.example.test"
    pairs = []
    for i in range(8):
        rec = H.Rec()
        host = in_host if i % 2 == 0 else off_host
        agent = H.build_agent(monkeypatch, "chat_completions", rec, base_url=f"https://{host}/v1")
        pairs.append((host, rec, agent))
    H.install_gate(manager, H.Rec(), predicate=H.FakePredicate(H.by_host(in_host)), ledger=H.FakeLedger(),
                   is_locked=H.Lock(True))
    start = threading.Barrier(len(pairs))
    results: dict[int, dict] = {}

    def run(i, agent):
        start.wait(10)
        results[i] = _turn(agent)

    threads = [threading.Thread(target=run, args=(i, a), daemon=True) for i, (_, _, a) in enumerate(pairs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    for i, (host, rec, agent) in enumerate(pairs):
        if host == off_host:
            assert rec.provider_calls == [], f"LEAK: off-tier agent {i} sent"
            assert results[i]["final_response"] != H.PROVIDER_TEXT
        else:
            assert len(rec.provider_calls) == 1 and results[i]["final_response"] == H.PROVIDER_TEXT

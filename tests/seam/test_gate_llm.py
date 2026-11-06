"""Seam tests for the llm_execution gate (W1).

Every turn test drives one real ``AIAgent.run_conversation`` through the real PluginManager
(see _harness.py). Each safety test is a ``check_*`` scenario plus a mutant twin: the same
scenario run against a deliberately broken gate, which must make the check fail. A twin that
passes proves the check would catch that bug.
"""
from __future__ import annotations

import pytest

from ._harness import (  # noqa: F401  (fixtures)
    MODES, PROVIDER_TEXT, Rec, arm_fallback_chain, assert_clean_refusal, build_agent, manager,
    no_lazy_installs, rate_limit_429, register, status_error_500,
)

from confidential_mode import gate_llm
from confidential_mode.gate_llm import (
    TEXT_INTERNAL_ERROR, TEXT_PIN_CHANGED, TEXT_PROVIDER_ERROR, LlmGate, build_middleware, off_tier_text,
)
from confidential_mode.ledger import Ledger
from confidential_mode.state import ConfidentialState, InMemoryState
from confidential_mode.tiers import Destination, Tier, Verdict


# ---------------------------------------------------------------------------------------------
# Fakes for W2/W3 collaborators
# ---------------------------------------------------------------------------------------------


class FakePredicate:
    def __init__(self, tier=Tier.LOCAL, *, in_tier=True, reason="", host="llm.example.test", raises=None):
        self.tier = tier
        self.in_tier, self.reason, self.host, self.raises = in_tier, reason, host, raises
        self.calls: list[Destination] = []

    def classify(self, dest: Destination) -> Verdict:
        self.calls.append(dest)
        if self.raises is not None:
            raise self.raises
        return Verdict(in_tier=self.in_tier, reason=self.reason, host=self.host)


class FakeAttested:
    def __init__(self, *, ok=True, reason="", raises=None):
        self.ok, self.reason, self.raises = ok, reason, raises
        self.calls: list[str] = []

    def __call__(self, provider: str) -> Verdict:
        self.calls.append(provider)
        if self.raises is not None:
            raise self.raises
        return Verdict(in_tier=self.ok, reason=self.reason, host="enclave.example.test")


class Env:
    def __init__(self, tmp_path, *, sealed=False, tier=Tier.LOCAL, predicate=None, attested=None,
                 pin_pending=None, builders=None, gate_cls=LlmGate):
        self.ledger = Ledger(tmp_path / "ledger.sqlite")
        self.state = ConfidentialState(InMemoryState())
        if sealed:
            self.state.seal(tier, "fp")
        self.predicate = predicate or FakePredicate(tier)
        self.attested = attested or FakeAttested()
        self.fn = build_middleware(ledger=self.ledger, is_sealed=self.state.sealed,
                                   predicate_for=lambda t: self.predicate, attested_ok=self.attested,
                                   pin_pending=pin_pending, builders=builders, gate_cls=gate_cls)

    def kinds(self):
        return [e.kind for e in self.ledger.tail(0)]


def run_turn(monkeypatch, manager, tmp_path, api_mode, *, provider_exc=None, fallback=False, **env_kw):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec, provider_exc=provider_exc)
    if fallback:
        arm_fallback_chain(monkeypatch, agent)
    env = Env(tmp_path, **env_kw)
    register(manager, env.fn)
    result = agent.run_conversation("secret question about the merger")
    return result, rec, agent, env


# ---------------------------------------------------------------------------------------------
# Mutant gates (each reintroduces one bug the real gate must not have)
# ---------------------------------------------------------------------------------------------


class MutantNoObserve(LlmGate):
    def record(self, kind, *a, **k):
        if kind != "send_observed":
            super().record(kind, *a, **k)


class MutantIgnoresVerdict(LlmGate):
    def handle(self, request, next_call, context):
        dest = self.destination(context)
        sealed, tier = self.is_sealed()
        if not sealed:
            return next_call(request)
        self.predicate_for(Tier(tier)).classify(dest)
        return self.guarded_call(request, next_call, dest, context, Tier(tier), Verdict(True, "", ""))


class MutantRefusesAll(LlmGate):
    def handle(self, request, next_call, context):
        dest = self.destination(context)
        return self.refuse(dest, context, Tier.LOCAL, Verdict(False, "no", ""), "refused", reason_code="mutant")


class MutantUncaughtProviderError(LlmGate):
    def guarded_call(self, request, next_call, *a, **k):
        return next_call(request)


class MutantSwallowsInterrupt(LlmGate):
    def guarded_call(self, request, next_call, dest, context, tier, verdict):
        try:
            return next_call(request)
        except Exception:
            return self.refuse(dest, context, tier, verdict, TEXT_PROVIDER_ERROR, reason_code="provider_error")


class MutantNoCatchAll(LlmGate):
    def __call__(self, request, next_call, **context):
        return self.handle(request, next_call, context)


class MutantSkipsAttested(LlmGate):
    def handle(self, request, next_call, context):
        dest = self.destination(context)
        sealed, tier = self.is_sealed()
        verdict = self.predicate_for(Tier(tier)).classify(dest)
        return self.guarded_call(request, next_call, dest, context, Tier(tier), verdict)


# ---------------------------------------------------------------------------------------------
# 1. Unsealed: observe and pass through
# ---------------------------------------------------------------------------------------------


def check_unsealed_observes(monkeypatch, manager, tmp_path, api_mode, gate_cls=LlmGate):
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, api_mode, sealed=False, gate_cls=gate_cls)
    assert result["final_response"] == PROVIDER_TEXT
    assert len(rec.all_provider_calls) == 1, "provider called exactly once"
    rows = env.ledger.tail(0)
    assert [r.kind for r in rows] == ["send_observed"]
    row = rows[0]
    assert row.host == {"chat_completions": "llm.example.test", "codex_responses": "chatgpt.com",
                        "anthropic_messages": "api.anthropic.com",
                        "bedrock_converse": "bedrock-runtime.us-east-1.amazonaws.com"}[api_mode]
    assert row.decision == "observed" and row.tier is None
    assert isinstance(row.bytes, int) and row.bytes > len("secret question about the merger")
    assert row.provider == agent.provider and row.model == agent.model and row.purpose == "main"
    assert env.predicate.calls == [], "unsealed never classifies"


@pytest.mark.parametrize("api_mode", MODES)
def test_unsealed_observes_and_passes_through(monkeypatch, manager, tmp_path, api_mode):
    check_unsealed_observes(monkeypatch, manager, tmp_path, api_mode)


def test_unsealed_never_stores_prompt_text(monkeypatch, manager, tmp_path):
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions")
    raw = (tmp_path / "ledger.sqlite").read_bytes()
    assert b"merger" not in raw


def test_mutant_unsealed_no_observe_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_unsealed_observes(monkeypatch, manager, tmp_path, "chat_completions", MutantNoObserve)


def test_mutant_unsealed_refusing_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_unsealed_observes(monkeypatch, manager, tmp_path, "chat_completions", MutantRefusesAll)


def test_unsealed_provider_error_propagates_to_hermes(monkeypatch, manager, tmp_path):
    """Unsealed, the gate must not change Hermes' error handling: a 500 is retried as usual."""
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions",
                                       provider_exc=status_error_500)
    assert len(rec.provider_calls) > 1, "Hermes' own retry ran"
    assert result["final_response"] != TEXT_PROVIDER_ERROR


# ---------------------------------------------------------------------------------------------
# 2. Sealed off-tier: refused in all four api_modes, zero provider calls
# ---------------------------------------------------------------------------------------------


def check_off_tier_refused(monkeypatch, manager, tmp_path, api_mode, gate_cls=LlmGate):
    pred = FakePredicate(Tier.LOCAL, in_tier=False, reason="host is not local", host="llm.example.test")
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, api_mode, sealed=True,
                                       tier=Tier.LOCAL, predicate=pred, fallback=True, gate_cls=gate_cls)
    assert_clean_refusal(result, rec, agent, off_tier_text(Tier.LOCAL, "host is not local"))
    assert len(pred.calls) == 1 and pred.calls[0].api_mode == api_mode
    rows = env.ledger.tail(0)
    assert [r.kind for r in rows] == ["send_refused"]
    assert rows[0].decision == "refused" and rows[0].tier == "local-only" and rows[0].verdict == "off_tier"
    assert rows[0].detail["reason_code"] == "off_tier"


@pytest.mark.parametrize("api_mode", MODES)
def test_sealed_off_tier_refused(monkeypatch, manager, tmp_path, api_mode):
    check_off_tier_refused(monkeypatch, manager, tmp_path, api_mode)


@pytest.mark.parametrize("api_mode", MODES)
def test_mutant_off_tier_ignored_verdict_is_caught(monkeypatch, manager, tmp_path, api_mode):
    with pytest.raises(AssertionError):
        check_off_tier_refused(monkeypatch, manager, tmp_path, api_mode, MutantIgnoresVerdict)


# ---------------------------------------------------------------------------------------------
# 3. Sealed in-tier: passes
# ---------------------------------------------------------------------------------------------


def check_in_tier_passes(monkeypatch, manager, tmp_path, api_mode, gate_cls=LlmGate):
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, api_mode, sealed=True,
                                       tier=Tier.LOCAL, gate_cls=gate_cls)
    assert result["final_response"] == PROVIDER_TEXT and result["completed"] is True
    assert len(rec.all_provider_calls) == 1
    rows = env.ledger.tail(0)
    assert [(r.kind, r.decision, r.verdict) for r in rows] == [("send_observed", "allowed", "in_tier")]
    assert env.attested.calls == [], "attested_ok is only consulted for the attested tier"


@pytest.mark.parametrize("api_mode", MODES)
def test_sealed_in_tier_passes(monkeypatch, manager, tmp_path, api_mode):
    check_in_tier_passes(monkeypatch, manager, tmp_path, api_mode)


def test_mutant_in_tier_refused_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_in_tier_passes(monkeypatch, manager, tmp_path, "chat_completions", MutantRefusesAll)


# ---------------------------------------------------------------------------------------------
# 4. Sealed in-tier, provider 500 / 429 -> refusal; fallback never armed; no cooldown
# ---------------------------------------------------------------------------------------------


def check_provider_error_refused(monkeypatch, manager, tmp_path, api_mode, err, gate_cls=LlmGate):
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, api_mode, sealed=True,
                                       tier=Tier.LOCAL, provider_exc=err, fallback=True, gate_cls=gate_cls)
    assert result["final_response"] == TEXT_PROVIDER_ERROR and result["completed"] is True
    assert len(rec.all_provider_calls) == 1, "provider called exactly once, no retry"
    assert rec.fallback_calls == [], "_try_activate_fallback never called"
    assert agent._fallback_index == 0, "fallback chain never armed"
    assert rec.backoff_calls == [] and rec.backoff_sleeps == [] and rec.error_hook_calls == []
    assert getattr(agent, "_rate_limited_until", 0) in (0, None), "_rate_limited_until never set"
    assert getattr(agent, "_rate_limit_backoff_count", 0) == 0
    rows = env.ledger.tail(0)
    assert [r.kind for r in rows] == ["send_observed", "send_refused"]
    assert rows[1].detail["reason_code"] == "provider_error"
    assert rows[1].detail["status_code"] in (500, 429)


ERRS = pytest.mark.parametrize("err", [status_error_500, rate_limit_429], ids=["500", "429"])


@ERRS
@pytest.mark.parametrize("api_mode", MODES)
def test_sealed_provider_error_becomes_refusal(monkeypatch, manager, tmp_path, api_mode, err):
    check_provider_error_refused(monkeypatch, manager, tmp_path, api_mode, err)


@ERRS
@pytest.mark.parametrize("api_mode", MODES)
def test_mutant_uncaught_provider_error_is_caught(monkeypatch, manager, tmp_path, api_mode, err):
    with pytest.raises(AssertionError):
        check_provider_error_refused(monkeypatch, manager, tmp_path, api_mode, err, MutantUncaughtProviderError)


# ---------------------------------------------------------------------------------------------
# 5. InterruptedError is re-raised (user stop / redirect), not turned into a refusal
# ---------------------------------------------------------------------------------------------


def check_interrupt_reraised(monkeypatch, manager, tmp_path, gate_cls=LlmGate):
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.LOCAL, provider_exc=InterruptedError, gate_cls=gate_cls)
    assert result.get("interrupted") is True, result
    assert result.get("final_response") != TEXT_PROVIDER_ERROR
    assert len(rec.provider_calls) == 1
    assert rec.fallback_calls == []
    assert "send_refused" not in env.kinds()


def test_interrupt_reraised(monkeypatch, manager, tmp_path):
    check_interrupt_reraised(monkeypatch, manager, tmp_path)


def test_mutant_swallowed_interrupt_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_interrupt_reraised(monkeypatch, manager, tmp_path, MutantSwallowsInterrupt)


# ---------------------------------------------------------------------------------------------
# 6. Predicate raising -> refusal, provider zero calls
# ---------------------------------------------------------------------------------------------


def check_predicate_raising_refused(monkeypatch, manager, tmp_path, api_mode, gate_cls=LlmGate):
    pred = FakePredicate(Tier.LOCAL, raises=RuntimeError("predicate crashed"))
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, api_mode, sealed=True,
                                       tier=Tier.LOCAL, predicate=pred, fallback=True, gate_cls=gate_cls)
    assert_clean_refusal(result, rec, agent, TEXT_INTERNAL_ERROR)
    rows = env.ledger.tail(0)
    assert [r.kind for r in rows] == ["send_refused"]
    assert rows[0].detail == {"reason_code": "internal_error", "error_type": "RuntimeError"}


@pytest.mark.parametrize("api_mode", MODES)
def test_predicate_raising_refused(monkeypatch, manager, tmp_path, api_mode):
    check_predicate_raising_refused(monkeypatch, manager, tmp_path, api_mode)


def test_mutant_predicate_raising_without_catch_all_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_predicate_raising_refused(monkeypatch, manager, tmp_path, "chat_completions", MutantNoCatchAll)


def check_state_raising_refused(monkeypatch, manager, tmp_path, gate_cls=LlmGate):
    """Corrupt seal state (is_sealed raising) fails closed, even though we cannot tell if sealed."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    env = Env(tmp_path, gate_cls=gate_cls)
    env.state._store.set("sealed", "yes")  # not a bool -> StateError
    env.fn = build_middleware(ledger=env.ledger, is_sealed=env.state.sealed, predicate_for=lambda t: env.predicate,
                              attested_ok=env.attested, gate_cls=gate_cls)
    register(manager, env.fn)
    assert_clean_refusal(agent.run_conversation("q"), rec, agent, TEXT_INTERNAL_ERROR)


def test_state_raising_refused(monkeypatch, manager, tmp_path):
    check_state_raising_refused(monkeypatch, manager, tmp_path)


def test_mutant_state_raising_without_catch_all_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_state_raising_refused(monkeypatch, manager, tmp_path, MutantNoCatchAll)


# ---------------------------------------------------------------------------------------------
# 7. Attested tier: attested_ok consulted before next_call
# ---------------------------------------------------------------------------------------------


def check_attested_mismatch_refused(monkeypatch, manager, tmp_path, gate_cls=LlmGate):
    att = FakeAttested(ok=False, reason="enclave fingerprint does not match pin")
    pred = FakePredicate(Tier.ATTESTED, in_tier=True)
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.ATTESTED, predicate=pred, attested=att,
                                       pin_pending=lambda: True, fallback=True, gate_cls=gate_cls)
    assert_clean_refusal(result, rec, agent, TEXT_PIN_CHANGED)
    assert att.calls == ["custom"]
    rows = env.ledger.tail(0)
    assert [r.kind for r in rows] == ["send_refused"] and rows[0].detail["reason_code"] == "pin_mismatch"


def test_attested_mismatch_refused_with_staged_pin_message(monkeypatch, manager, tmp_path):
    check_attested_mismatch_refused(monkeypatch, manager, tmp_path)


def test_mutant_attested_check_skipped_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_attested_mismatch_refused(monkeypatch, manager, tmp_path, MutantSkipsAttested)


def test_attested_not_ok_without_pending_pin_uses_reason(monkeypatch, manager, tmp_path):
    att = FakeAttested(ok=False, reason="verification is stale")
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.ATTESTED, predicate=FakePredicate(Tier.ATTESTED),
                                       attested=att, pin_pending=lambda: False)
    assert_clean_refusal(result, rec, agent, gate_llm.attested_fail_text("verification is stale"))


def check_attested_raising_refused(monkeypatch, manager, tmp_path, gate_cls=LlmGate):
    att = FakeAttested(raises=RuntimeError("verifier exploded"))
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.ATTESTED, predicate=FakePredicate(Tier.ATTESTED),
                                       attested=att, fallback=True, gate_cls=gate_cls)
    assert_clean_refusal(result, rec, agent, TEXT_INTERNAL_ERROR)
    assert att.calls == ["custom"]


def test_attested_ok_raising_refused(monkeypatch, manager, tmp_path):
    check_attested_raising_refused(monkeypatch, manager, tmp_path)


def test_mutant_attested_raising_without_catch_all_is_caught(monkeypatch, manager, tmp_path):
    with pytest.raises(AssertionError):
        check_attested_raising_refused(monkeypatch, manager, tmp_path, MutantNoCatchAll)


def test_attested_ok_passes(monkeypatch, manager, tmp_path):
    att = FakeAttested(ok=True)
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.ATTESTED, predicate=FakePredicate(Tier.ATTESTED), attested=att)
    assert result["final_response"] == PROVIDER_TEXT and len(rec.provider_calls) == 1
    assert att.calls == ["custom"]


def test_predicate_for_wrong_tier_refused(monkeypatch, manager, tmp_path):
    """A predicate whose tier differs from the sealed tier is an internal error, not a pass."""
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.ATTESTED, predicate=FakePredicate(Tier.LOCAL))
    assert_clean_refusal(result, rec, agent, TEXT_INTERNAL_ERROR)


# ---------------------------------------------------------------------------------------------
# 8. Refusal builders failing / unknown api_mode -> still a chat-shaped refusal
# ---------------------------------------------------------------------------------------------


def _raising_builder(text):
    raise RuntimeError("builder crashed")


def check_builder_failure_refused(monkeypatch, manager, tmp_path):
    """Every chat-completions builder raises (injected and module-level): the last-resort
    SimpleNamespace shape must still end the turn cleanly."""
    monkeypatch.setattr(gate_llm, "chat_completions_refusal", _raising_builder)
    pred = FakePredicate(Tier.LOCAL, in_tier=False, reason="off")
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "chat_completions", sealed=True,
                                       tier=Tier.LOCAL, predicate=pred,
                                       builders={"chat_completions": _raising_builder}, fallback=True)
    assert_clean_refusal(result, rec, agent, off_tier_text(Tier.LOCAL, "off"))
    rows = env.ledger.tail(0)
    assert rows[-1].detail["note"].startswith("refusal_builder_failed")


def test_builder_raising_still_refuses(monkeypatch, manager, tmp_path):
    check_builder_failure_refused(monkeypatch, manager, tmp_path)


def test_mutant_builder_without_fallback_is_caught(monkeypatch, manager, tmp_path):
    def naive_build_refusal(api_mode, text, builders=None):
        return (builders or gate_llm.REFUSAL_BUILDERS)[api_mode](text), None

    monkeypatch.setattr(gate_llm, "build_refusal", naive_build_refusal)
    with pytest.raises(AssertionError):
        check_builder_failure_refused(monkeypatch, manager, tmp_path)


def test_unknown_api_mode_in_real_turn_gets_chat_shape(monkeypatch, manager, tmp_path):
    """No builder for bedrock_converse -> unknown-mode path -> ChatCompletion, which bedrock
    validation accepts (C0). Ledger carries the note."""
    pred = FakePredicate(Tier.LOCAL, in_tier=False, reason="off")
    builders = {k: v for k, v in gate_llm.REFUSAL_BUILDERS.items() if k != "bedrock_converse"}
    result, rec, agent, env = run_turn(monkeypatch, manager, tmp_path, "bedrock_converse", sealed=True,
                                       tier=Tier.LOCAL, predicate=pred, builders=builders)
    assert_clean_refusal(result, rec, agent, off_tier_text(Tier.LOCAL, "off"))
    assert env.ledger.tail(0)[-1].detail["note"] == "unknown_api_mode"


def test_unknown_api_mode_direct_call_returns_chat_completion(tmp_path):
    from openai.types.chat import ChatCompletion
    env = Env(tmp_path, sealed=True, predicate=FakePredicate(Tier.LOCAL, in_tier=False, reason="off"))
    calls = []
    out = env.fn(request={"messages": []}, next_call=lambda p=None: calls.append(p),
                 api_mode="mystery_mode", provider="x", base_url="https://x.test", model="m", session_id="s1")
    assert isinstance(out, ChatCompletion)
    assert out.choices[0].finish_reason == "stop" and out.choices[0].message.content == off_tier_text(Tier.LOCAL, "off")
    assert calls == []
    row = env.ledger.session("s1")[0]
    assert row.kind == "send_refused" and row.detail["note"] == "unknown_api_mode"


@pytest.mark.parametrize("api_mode", MODES + ["mystery_mode"])
def test_refusal_shapes_are_never_forbidden(api_mode):
    obj, _ = gate_llm.build_refusal(api_mode, "t")
    if api_mode == "bedrock_converse":
        assert obj["stopReason"] == "end_turn"
        return
    assert not isinstance(obj, dict)
    if hasattr(obj, "choices"):
        assert obj.choices[0].finish_reason == "stop"
        assert getattr(obj.choices[0].message, "refusal", None) is None
    elif hasattr(obj, "status"):
        assert obj.status == "completed"
    else:
        assert obj.stop_reason == "end_turn"


def test_ledger_failure_never_changes_decision(monkeypatch, manager, tmp_path):
    class BrokenLedger:
        def append(self, event):
            raise OSError("disk full")
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    fn = build_middleware(ledger=BrokenLedger(), is_sealed=lambda: (True, Tier.LOCAL),
                          predicate_for=lambda t: FakePredicate(Tier.LOCAL, in_tier=False, reason="off"),
                          attested_ok=FakeAttested())
    register(manager, fn)
    assert_clean_refusal(agent.run_conversation("q"), rec, agent, off_tier_text(Tier.LOCAL, "off"))


def test_purpose_from_context():
    assert gate_llm.purpose_from_context({}) == "main"
    assert gate_llm.purpose_from_context({"call_role": "fallback"}) == "fallback"
    assert gate_llm.purpose_from_context({"fallback_index": 2}) == "fallback"
    assert gate_llm.purpose_from_context({"fallback_index": "junk"}) == "main"


# ---------------------------------------------------------------------------------------------
# 9. Documentation: a raising middleware fails OPEN in Hermes. This is what the catch-all defends.
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("api_mode", MODES)
def test_documentation_raising_middleware_fails_open(monkeypatch, manager, api_mode):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec)

    def naive_gate(request, next_call, **context):
        raise RuntimeError("policy check crashed")

    register(manager, naive_gate)
    result = agent.run_conversation("secret question")
    assert len(rec.all_provider_calls) == 1, "Hermes called the provider itself: FAIL-OPEN"
    assert result["final_response"] == PROVIDER_TEXT


@pytest.mark.parametrize("api_mode", MODES)
def test_documentation_twin_gate_with_same_crash_fails_closed(monkeypatch, manager, tmp_path, api_mode):
    check_predicate_raising_refused(monkeypatch, manager, tmp_path, api_mode)


@pytest.mark.parametrize("api_mode", MODES)
def test_sealed_off_tier_refused_on_streaming_turn(monkeypatch, manager, tmp_path, api_mode):
    from agent.turn_api_call import _should_stream
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec, streaming=True)
    if not _should_stream(agent):
        pytest.skip(f"{api_mode}: Hermes does not stream for this agent configuration")
    env = Env(tmp_path, sealed=True, predicate=FakePredicate(Tier.LOCAL, in_tier=False, reason="off"))
    register(manager, env.fn)
    assert_clean_refusal(agent.run_conversation("q"), rec, agent, off_tier_text(Tier.LOCAL, "off"))

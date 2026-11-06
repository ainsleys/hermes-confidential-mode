"""``llm_execution`` middleware: the sealed-mode gate on every main-loop provider call (W1).

Register with ``ctx.register_middleware("llm_execution", build_middleware(...))``.

Proven constraints (docs/C0-spikes.md, tests/spikes/test_refusal_shape.py):
- An exception escaping a middleware is FAIL-OPEN: Hermes skips the frame and calls the
  provider itself (hermes_cli/middleware.py ``_run_execution_chain``). So nothing the gate
  itself raises may escape; every internal failure becomes a refusal.
- Exceptions raised by ``next_call`` arrive wrapped in Hermes' private
  ``_DownstreamExecutionError``; the provider exception is ``.original``.
- A refusal must be the api_mode's response object (never a dict, except Bedrock's raw
  converse dict), with finish_reason "stop" / stop_reason "end_turn" / status "completed".
  content_filter, length and message.refusal re-enter Hermes' fallback or continuation paths.

Behaviour:
- unsealed: ledger ``send_observed`` (host, serialised request byte size), call through
  unchanged; downstream exceptions propagate untouched so Hermes' normal retry/fallback runs.
- sealed: classify the destination with the sealed tier's predicate. Off-tier: ledger
  ``send_refused`` and refuse without calling ``next_call``. Attested tier: ``attested_ok``
  must also pass before ``next_call``. In-tier: call through; any provider error except
  ``InterruptedError`` becomes a refusal so Hermes never retries, backs off or arms a fallback.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from .ledger import LedgerEvent
from .state import StateError
from .tiers import Destination, Tier, TierPredicate, Verdict

logger = logging.getLogger(__name__)

REFUSAL_PREFIX = "Confidential mode: "
TEXT_INTERNAL_ERROR = (REFUSAL_PREFIX + "the confidentiality check failed, so this request was not "
                       "sent to any model provider.")
TEXT_PROVIDER_ERROR = REFUSAL_PREFIX + "attested endpoint unavailable; this turn ended; resend."
TEXT_PIN_CHANGED = REFUSAL_PREFIX + "enclave build changed; run /confidential pins approve"
TEXT_STATE_UNREADABLE = (REFUSAL_PREFIX + "seal state is unreadable, so every request is refused until it "
                         "is repaired; run /confidential status or /confidential off.")
REFUSAL_MODEL = "confidential-mode"
KNOWN_API_MODES = ("chat_completions", "codex_responses", "anthropic_messages", "bedrock_converse")


def off_tier_text(tier: Tier, reason: str) -> str:
    return f"{REFUSAL_PREFIX}sealed to {Tier(tier).value}; this request was not sent. {reason}".rstrip()


def attested_fail_text(reason: str) -> str:
    return f"{REFUSAL_PREFIX}attested endpoint not verified; this request was not sent. {reason}".rstrip()


# ---------------------------------------------------------------------------------------------
# Refusal builders, one per api_mode (shapes proven in tests/spikes/test_refusal_shape.py)
# ---------------------------------------------------------------------------------------------


def chat_completions_refusal(text: str):
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice

    return ChatCompletion(
        id="confidential-refusal", object="chat.completion", created=int(time.time()), model=REFUSAL_MODEL,
        choices=[Choice(index=0, finish_reason="stop",
                        message=ChatCompletionMessage(role="assistant", content=text))],
        usage=None,
    )


def codex_responses_refusal(text: str):
    from openai.types.responses import Response, ResponseOutputMessage, ResponseOutputText

    return Response(
        id="resp_confidential_refusal", object="response", created_at=time.time(), model=REFUSAL_MODEL,
        status="completed", parallel_tool_calls=False, tool_choice="auto", tools=[],
        output=[ResponseOutputMessage(
            id="msg_confidential_refusal", type="message", role="assistant", status="completed",
            content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
        )],
    )


def anthropic_messages_refusal(text: str):
    # The attribute shape of anthropic.types.Message; the SDK is optional in Hermes' venv.
    return SimpleNamespace(
        id="msg_confidential_refusal", type="message", role="assistant", model=REFUSAL_MODEL,
        content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
        stop_sequence=None, usage=None,
    )


def bedrock_converse_refusal(text: str):
    # Raw boto3 converse() dict; agent/transports/bedrock.py accepts it (C0).
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "stopReason": "end_turn"}


def last_resort_refusal(text: str):
    """Chat-completions duck type built from SimpleNamespace only: cannot raise. Accepted by
    chat_completions and bedrock_converse validation (C0 duck-type test)."""
    return SimpleNamespace(id="confidential-refusal", model=REFUSAL_MODEL, usage=None, choices=[
        SimpleNamespace(index=0, finish_reason="stop",
                        message=SimpleNamespace(role="assistant", content=text, tool_calls=None))])


REFUSAL_BUILDERS: dict[str, Callable[[str], Any]] = {
    "chat_completions": chat_completions_refusal,
    "codex_responses": codex_responses_refusal,
    "anthropic_messages": anthropic_messages_refusal,
    "bedrock_converse": bedrock_converse_refusal,
}


def build_refusal(api_mode: str, text: str,
                  builders: Mapping[str, Callable[[str], Any]] | None = None) -> tuple[Any, str | None]:
    """Return (refusal, note). Never raises. ``note`` is set when the mode was unknown or a
    builder failed and a fallback shape was used."""
    builders = REFUSAL_BUILDERS if builders is None else builders
    note = None
    try:
        builder = builders.get(api_mode)
        if builder is None:
            note = "unknown_api_mode"
            builder = builders.get("chat_completions") or chat_completions_refusal
        return builder(text), note
    except Exception as exc:  # noqa: BLE001 - nothing may escape
        note = f"refusal_builder_failed:{type(exc).__name__}"
    try:
        return chat_completions_refusal(text), note
    except Exception:  # noqa: BLE001
        return last_resort_refusal(text), note


# ---------------------------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------------------------


def _host(base_url: str) -> str:
    try:
        return (urlparse(base_url or "").hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def request_bytes(request: Any) -> int | None:
    """Byte size of the serialised provider request. Counted, never stored."""
    try:
        return len(json.dumps(request, default=str, ensure_ascii=False).encode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def purpose_from_context(context: Mapping[str, Any]) -> str:
    """Hermes 84a0301 does not pass a fallback indicator to llm_execution middleware
    (agent/turn_api_call.py:139-145); honour one if a later Hermes adds it."""
    try:
        if str(context.get("call_role") or "") == "fallback":
            return "fallback"
        if int(context.get("fallback_index") or 0) > 0:
            return "fallback"
    except Exception:  # noqa: BLE001
        pass
    return "main"


@dataclass
class _Call:
    downstream_exc: BaseException | None = None
    next_called: bool = False


class LlmGate:
    """The middleware body. Collaborators are injected so W2/W3 can be faked:

    - ``is_sealed() -> (bool, Tier | None)``  (state.ConfidentialState.sealed)
    - ``predicate_for(tier) -> TierPredicate`` (W3 predicates)
    - ``attested_ok(provider) -> Verdict``     (W2; handles TTL and stages pending_pin)
    - ``pin_pending() -> bool``                (W2 PinStore.pending() is not None); optional
    - ``ledger`` with ``append(LedgerEvent)``
    """

    def __init__(self, *, ledger, is_sealed: Callable[[], tuple[bool, Tier | None]],
                 predicate_for: Callable[[Tier], TierPredicate],
                 attested_ok: Callable[[str], Verdict],
                 pin_pending: Callable[[], bool] | None = None,
                 builders: Mapping[str, Callable[[str], Any]] | None = None):
        self.ledger = ledger
        self.is_sealed = is_sealed
        self.predicate_for = predicate_for
        self.attested_ok = attested_ok
        self.pin_pending = pin_pending
        self.builders = REFUSAL_BUILDERS if builders is None else builders

    # -- entry point ---------------------------------------------------------
    def __call__(self, request: Any, next_call: Callable[..., Any], **context: Any) -> Any:
        call = _Call()

        def tracked_next(payload: Any = None) -> Any:
            call.next_called = True
            try:
                return next_call(request if payload is None else payload)
            except BaseException as exc:
                call.downstream_exc = exc
                raise

        try:
            return self.handle(request, tracked_next, context)
        except BaseException as exc:
            if exc is call.downstream_exc or not isinstance(exc, Exception):
                raise  # downstream failure meant to propagate, or KeyboardInterrupt/SystemExit
            return self.internal_error(context, exc)

    # -- decision ------------------------------------------------------------
    def destination(self, context: Mapping[str, Any]) -> Destination:
        return Destination(
            provider=str(context.get("provider") or ""), base_url=str(context.get("base_url") or ""),
            model=str(context.get("model") or ""), api_mode=str(context.get("api_mode") or ""),
            purpose=purpose_from_context(context))

    def handle(self, request: Any, next_call: Callable[..., Any], context: Mapping[str, Any]) -> Any:
        dest = self.destination(context)
        # Values crossing a trust boundary are compared by identity, never truthiness (Ruling 8):
        # only ``True`` permits, only ``False`` means unsealed; anything else fails closed.
        try:
            sealed, tier = self.is_sealed()
            if self.permits(sealed, "sealed"):
                tier = Tier(tier)
            elif not self.is_false(sealed):
                raise StateError(f"is_sealed returned a non-bool sealed flag ({type(sealed).__name__})")
        except Exception as exc:  # corrupt seal state: fail closed (INTERFACES Amendment 2)
            return self.internal_error(context, exc, text=TEXT_STATE_UNREADABLE,
                                       reason_code="seal_state_unreadable")
        if self.is_false(sealed):
            self.record("send_observed", dest, context, host=_host(dest.base_url),
                        nbytes=request_bytes(request), decision="observed")
            return next_call(request)

        predicate = self.predicate_for(tier)
        if not self.same_tier(Tier(predicate.tier), tier):
            raise RuntimeError(f"predicate tier {predicate.tier!r} does not match sealed tier {tier.value!r}")
        verdict = predicate.classify(dest)
        if not isinstance(verdict, Verdict):
            raise TypeError("predicate returned a non-Verdict")
        if not self.permits(verdict.in_tier, "verdict"):
            return self.refuse(dest, context, tier, verdict, off_tier_text(tier, verdict.reason),
                               reason_code="off_tier", nbytes=request_bytes(request))

        if tier is Tier.ATTESTED:
            att = self.attested_ok(dest.provider)
            if not isinstance(att, Verdict):
                raise TypeError("attested_ok returned a non-Verdict")
            if not self.permits(att.in_tier, "attested"):
                # Only selects the refusal text; both branches refuse.
                pending = self.pin_pending is not None and self.permits(self.pin_pending(), "pin_pending")
                text = TEXT_PIN_CHANGED if pending else attested_fail_text(att.reason)
                return self.refuse(dest, context, tier, att, text,
                                   reason_code="pin_mismatch" if pending else "attestation_not_ok",
                                   nbytes=request_bytes(request))

        return self.guarded_call(request, next_call, dest, context, tier, verdict)

    # Identity checks, one place so mutant tests can target each use (``what``).
    @staticmethod
    def permits(value: Any, what: str) -> bool:
        return value is True

    @staticmethod
    def is_false(value: Any) -> bool:
        return value is False

    @staticmethod
    def same_tier(a: Tier, b: Tier) -> bool:
        return a is b

    def guarded_call(self, request, next_call, dest, context, tier: Tier, verdict: Verdict) -> Any:
        nbytes = request_bytes(request)
        self.record("send_observed", dest, context, host=verdict.host or _host(dest.base_url),
                    nbytes=nbytes, tier=tier.value, verdict="in_tier", decision="allowed")
        try:
            return next_call(request)
        except Exception as exc:
            original = getattr(exc, "original", exc)
            if isinstance(original, InterruptedError):
                raise
            detail = {"reason_code": "provider_error", "error_type": type(original).__name__}
            status = getattr(original, "status_code", None)
            if isinstance(status, int):
                detail["status_code"] = status
            return self.refuse(dest, context, tier, verdict, TEXT_PROVIDER_ERROR,
                               reason_code="provider_error", nbytes=nbytes, verdict_label="in_tier",
                               detail=detail)

    # -- outcomes ------------------------------------------------------------
    def refuse(self, dest: Destination, context, tier: Tier | None, verdict: Verdict | None, text: str, *,
               reason_code: str, nbytes: int | None = None, verdict_label: str | None = None,
               detail: dict | None = None) -> Any:
        refusal, note = build_refusal(dest.api_mode, text, self.builders)
        d = {"reason_code": reason_code, **(detail or {})}
        if verdict is not None:
            d["reason"] = verdict.reason
        if note:
            d["note"] = note
        self.record("send_refused", dest, context, host=(verdict.host if verdict else "") or _host(dest.base_url),
                    nbytes=nbytes, tier=tier.value if tier else None,
                    verdict=verdict_label or ("off_tier" if verdict is not None else "error"),
                    decision="refused", detail=d)
        return refusal

    def internal_error(self, context: Mapping[str, Any], exc: BaseException, *, text: str = TEXT_INTERNAL_ERROR,
                       reason_code: str = "internal_error") -> Any:
        logger.warning("confidential-mode gate refused after internal error: %s", type(exc).__name__)
        api_mode = ""
        try:
            api_mode = str(context.get("api_mode") or "")
        except Exception:  # noqa: BLE001
            pass
        refusal, note = build_refusal(api_mode, text, self.builders)
        try:
            dest = self.destination(context)
            d = {"reason_code": reason_code, "error_type": type(exc).__name__}
            if note:
                d["note"] = note
            self.record("send_refused", dest, context, host=_host(dest.base_url), verdict="error",
                        decision="refused", detail=d)
        except Exception:  # noqa: BLE001
            pass
        return refusal

    def record(self, kind: str, dest: Destination, context: Mapping[str, Any], *, host: str = "",
               nbytes: int | None = None, tier: str | None = None, verdict: str | None = None,
               decision: str | None = None, detail: dict | None = None) -> None:
        """Best effort: a ledger failure never changes the gate's decision."""
        try:
            d = dict(detail or {})
            if dest.api_mode not in KNOWN_API_MODES:
                d.setdefault("note", "unknown_api_mode")
            self.ledger.append(LedgerEvent(
                kind=kind, session_id=str(context.get("session_id") or ""), purpose=dest.purpose,
                provider=dest.provider, host=host, model=dest.model, bytes=nbytes, tier=tier,
                verdict=verdict, decision=decision, surface=str(context.get("platform") or "") or None,
                detail=d))
        except Exception as exc:  # noqa: BLE001
            logger.warning("confidential-mode ledger append failed: %s", type(exc).__name__)

    def as_middleware(self) -> Callable[..., Any]:
        def confidential_mode_llm_execution(request=None, next_call=None, **context):
            return self(request, next_call, **context)
        confidential_mode_llm_execution.gate = self  # type: ignore[attr-defined]
        return confidential_mode_llm_execution


def build_middleware(*, ledger, is_sealed, predicate_for, attested_ok, pin_pending=None,
                     builders=None, gate_cls: type[LlmGate] = LlmGate) -> Callable[..., Any]:
    """Return the callable for ``ctx.register_middleware("llm_execution", fn)``."""
    return gate_cls(ledger=ledger, is_sealed=is_sealed, predicate_for=predicate_for,
                    attested_ok=attested_ok, pin_pending=pin_pending, builders=builders).as_middleware()

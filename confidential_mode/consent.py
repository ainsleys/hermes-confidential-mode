"""Human consent outside a turn (W4), on ``ctx.ask_choice`` only.

Why ask_choice and not ``tools.approval.request_tool_approval`` (docs/C0-spikes.md, spike 3):
request_tool_approval asks nobody from a slash command (no turn -> no gateway notifier -> it returns
``approval_required`` at once) and auto-approves under every bypass state (yolo, approvals.mode off,
remembered grants, cron/unattended approve modes). ``ctx.ask_choice`` blocks on the surface with no
turn running, never auto-picks, and returns None on no surface / timeout / cancel / prose /
out-of-range (tests/spikes/test_ask_choice.py). It fires no approval hooks, so we ledger here.

Both entry points are SYNC and refuse to run on an event loop. Reason: ask_choice waits for the
user's reply, which the gateway delivers on its event loop; waiting on that loop would deadlock it,
so Hermes' ask_choice returns None with only a warning when called from a coroutine
(hermes_cli/plugin_choices.py; tests/spikes/test_ask_choice.py::test_a). A None there would look
exactly like the user saying no. We raise ``ConsentContextError`` instead so the mistake is loud
and is never ledgered as a human denial. Register the slash-command handler as a plain ``def``;
the gateway runs it on an executor thread (tests/spikes/test_ask_choice.py::test_b_e).

Interfaces used (duck-typed, W1/W2 own the real ones):
  ledger.append(event: dict)
  store.pending() -> PendingPin | None ; store.apply(pending, *, approved_via=surface) -> PinRecord
  (approved_via is being added by W2, Amendment 2; older stores without it get apply(pending))
  allowlist.get(name) -> ToolInfo | None ; allowlist.add(name) ; allowlist.is_added(name)
"""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Optional

from .gate_tools import Route

PIN_CHOICES = [
    {"value": "approve", "label": "Approve", "description": "pin the new enclave measurement"},
    {"value": "deny", "label": "Deny", "description": "keep the current pin"},
]
TOOL_CHOICES = [
    {"value": "approve", "label": "Allow", "description": "let this tool run while sealed without asking each call"},
    {"value": "deny", "label": "Deny", "description": "keep asking (or blocking) for this tool"},
]


_APPLY_LOCK = threading.Lock()


class ConsentContextError(RuntimeError):
    """Raised when consent is requested from a coroutine (see module docstring)."""


def _refuse_on_event_loop(what: str) -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise ConsentContextError(
        f"{what} must run from a sync handler (the gateway runs those on an executor thread); "
        "called on an event loop, ask_choice would return None and look like a denial.")


def _ask(ctx: Any, question: str, choices: list) -> tuple[Optional[str], Optional[str]]:
    """(raw_pick, error). An exception from the surface counts as no answer."""
    try:
        return ctx.ask_choice(question, choices), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _short(fp: Any) -> str:
    s = str(fp or "")
    return s[:16] if s else "(none)"


def pin_question(pending: Any) -> str:
    result = _field(pending, "result", None)

    def get(name: str) -> Any:
        v = _field(pending, name, None)
        return v if v is not None or result is None else _field(result, name, None)

    return (
        "Approve confidential pin update?\n"
        f"Vendor: {get('vendor') or '?'}\n"
        f"Release: {get('release_tag') or '(untagged)'} ({get('router_repo') or '?'})\n"
        f"Old fingerprint: {_short(get('previous'))}\n"
        f"New code fingerprint: {_short(get('code_fingerprint'))}\n"
        f"New enclave fingerprint: {_short(get('enclave_fingerprint'))}"
    )


def _event(kind: str, *, session_id: str, platform: str, decision: str, detail: dict,
           purpose: str = "pin", provider: str = "") -> dict:
    return {
        "ts": time.time(), "session_id": session_id or "", "kind": kind, "purpose": purpose,
        "provider": provider, "host": "", "model": "", "bytes": None, "tier": None, "verdict": None,
        "decision": decision, "surface": platform or None, "detail": detail,
    }


def approve_pending_pin(ctx: Any, store: Any, ledger: Any, *, session_key: str, session_id: str,
                        platform: str) -> str:
    """Ask the human to approve the staged pin; apply it only on an explicit Approve and only if the
    pending pin is still the one the human saw. Returns the user-facing reply."""
    _refuse_on_event_loop("approve_pending_pin")
    pending = store.pending()
    if pending is None:
        return "No pin update is waiting for approval."
    vendor = str(_field(pending, "vendor", "") or "")
    base = {"session_key": session_key or "", "vendor": vendor,
            "code_fingerprint": str(_field(pending, "code_fingerprint", "") or ""),
            "enclave_fingerprint": str(_field(pending, "enclave_fingerprint", "") or "")}

    raw, error = _ask(ctx, pin_question(pending), PIN_CHOICES)
    detail = {**base, "raw_pick": raw}
    if error:
        detail["error"] = error
    if raw != "approve":
        ledger.append(_event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                             decision="no_answer" if raw is None else str(raw), detail=detail))
        if raw is None:
            return "No answer (timed out, cancelled, or not one of the options): pin update denied; current pin kept."
        return "Pin update denied; current pin kept."

    # Re-check and apply under one lock: two approvals racing for the same pending pin apply once
    # (the second sees pending cleared or changed). PinStore.apply is additionally idempotent (W2).
    with _APPLY_LOCK:
        try:
            current = store.pending()
        except Exception as exc:
            current, detail["recheck_error"] = None, f"{type(exc).__name__}: {exc}"[:200]
        if current is None or current != pending:
            detail["reason"] = "pending pin changed while waiting for the answer"
            ledger.append(_event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                                 decision="stale", detail=detail))
            return ("The pending pin changed while you were deciding, so nothing was applied. "
                    "Run /confidential pins approve again to review the new one.")
        try:
            record = _apply(store, pending, platform or "unknown")
        except Exception as exc:
            detail["error"] = type(exc).__name__
            ledger.append(_event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                                 decision="apply_failed", detail=detail))
            return f"The pin could not be applied ({type(exc).__name__}); the current pin is unchanged."
    detail["approved_at"] = str(_field(record, "approved_at", "") or "")
    ledger.append(_event("pin_applied", session_id=session_id, platform=platform, provider=vendor,
                         decision="approve", detail=detail))
    return (f"Pinned {vendor or 'enclave'} build "
            f"{_field(record, 'release_tag', None) or _field(pending, 'release_tag', None) or ''}".rstrip()
            + f" (code {_short(base['code_fingerprint'])}, enclave {_short(base['enclave_fingerprint'])}).")


def _apply(store: Any, pending: Any, surface: str) -> Any:
    """store.apply(pending, approved_via=surface) when the store takes it, else store.apply(pending).
    Decided by signature, not by catching TypeError, so an error inside apply is never retried."""
    import inspect
    try:
        params = inspect.signature(store.apply).parameters
        takes = "approved_via" in params or any(p.kind is p.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        takes = False
    return store.apply(pending, approved_via=surface) if takes else store.apply(pending)


def allow_tool(ctx: Any, allowlist: Any, ledger: Any, name: str, *, session_key: str = "",
               session_id: str = "", platform: str = "") -> str:
    """Ask the human to add an off-machine tool to the sealed allowlist (no per-call prompt after).
    Hard-blocked tools (cronjob_manage, delegate_task routing, MCP-by-URL) cannot be added."""
    _refuse_on_event_loop("allow_tool")
    info = allowlist.get(name)
    if info is None:
        return f"Unknown tool {name!r}; it was not registered when the session was sealed."
    if info.route is Route.LOCAL:
        return f"{name} is local and already runs without asking."
    if info.route is not Route.ASK:
        return f"{name} cannot be allowed while sealed ({info.route.value})."
    if allowlist.is_added(name):
        return f"{name} is already allowed."
    question = (f"Allow {name} while sealed?\n"
                f"It sends data off this machine (toolset {info.toolset}, origin {info.origin.value}).\n"
                "Once allowed, it runs without asking for the rest of this seal.")
    raw, error = _ask(ctx, question, TOOL_CHOICES)
    detail = {"tool": name, "raw_pick": raw, "session_key": session_key or "", "change": "allowlist_add"}
    if error:
        detail["error"] = error
    if raw != "approve":
        ledger.append(_event("tool_refused", session_id=session_id, platform=platform, purpose=f"tool:{name}",
                             decision="no_answer" if raw is None else str(raw), detail=detail))
        return f"{name} was not added; it still needs approval each call."
    allowlist.add(name)
    ledger.append(_event("tool_allowed", session_id=session_id, platform=platform, purpose=f"tool:{name}",
                         decision="allowlist_add", detail=detail))
    return f"{name} added to the allowlist for this seal."

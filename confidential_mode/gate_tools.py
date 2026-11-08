"""Tool gate for locked mode (W4): allowlist built from Hermes' live registry, a ``pre_tool_call``
hook, and a ``post_approval_response`` observer.

Hermes facts this module relies on (pinned checkout 84a0301):

* Registry enumeration: ``tools.registry.registry.get_all_entries()`` returns the merged
  ``ToolEntry`` list (name, toolset, handler, ...) for the active scope (tools/registry.py:589,
  :542-552).
* MCP origin: every MCP tool is registered under toolset ``f"mcp-{server_name}"`` with the RAW
  server name (tools/mcp_tool_registration.py:365, :384-387, for live and lazy/cached servers alike).
  ``tools.mcp_tool._mcp_tool_server_names`` maps registry tool name -> raw server name
  (tools/mcp_tool.py:561, filled at tools/mcp_tool_registration.py:110-113). A server is an HTTP
  ("from a URL") server iff ``"url" in config`` (tools/mcp_tool_health.py:25-26,
  tools/mcp_tool_transport.py:147, tools/mcp_tool_server_run.py:277-280: url wins over command).
  Config comes from ``mcp_servers`` (tools/mcp_tool_config.py:709-737) and, for connected servers,
  the live ``MCPServerTask._config`` in ``tools.mcp_tool._servers`` (tools/mcp_tool.py:459).
  A server we cannot find config for is treated as a URL server (blocked): fail closed.
* Plugin origin: ``PluginContext.register_tool`` adds the name to the plugin manager's
  ``_plugin_tool_names`` (hermes_cli/plugins.py:493); directory plugins import as
  ``hermes_plugins.<slug>`` (hermes_cli/plugins_loader.py:36, :811).
* ``pre_tool_call`` directives: ``{"action": "block", "message"}`` vetoes; ``{"action": "approve",
  "message", "rule_key"}`` routes the call through ``request_tool_approval`` with pattern key
  ``plugin_rule:<rule_key>`` (hermes_cli/plugins.py:1907-2016, tools/approval.py:1208-1230). A hook
  that raises or times out fails CLOSED with a block (hermes_cli/plugins_dispatch.py:60, :301-322).
* The approval gate auto-approves WITHOUT asking anybody under: yolo (``_yolo_active``: --yolo,
  session /yolo, ``hermes -z`` unattended turns), ``approvals.mode: off``, and cron /
  unattended-platform / single-query contexts whose mode is ``approve`` (tools/approval.py:1071-1113).
  Locked mode BLOCKS in those instead of returning the approve directive.
  A remembered once/session/always grant on OUR rule key is a human's answer to our own prompt and is
  honoured (INTERFACES.md Amendment 2): ledgered as tool_allowed, decision "remembered".

Layout: this module holds the three entry points register() wires (``build_pre_tool_call``,
``build_tool_execution``, ``build_post_approval_response``). Each tool's route is decided at lock by
gate_tools_classify.py and recorded by gate_tools_allowlist.py; each call is decided by
gate_tools_policy.py from what gate_tools_calls.py reads off the call, Hermes' approval state
(gate_tools_hermes.py) and the answers and grants in gate_tools_grants.py. Names imported below as
``X as X`` were defined here before that split and stay importable from here.
"""
from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from typing import Any

from .gate_tools_allowlist import (
    Allowlist,
    _import_modules as _import_modules,
    _printable,
    _read_added as _read_added,
    _read_json_or_yaml as _read_json_or_yaml,
    build_allowlist as build_allowlist,
    clear_persisted as clear_persisted,
    ensure_builtin_tools as ensure_builtin_tools,
    ensure_tools_for_lock as ensure_tools_for_lock,
    format_allowlist as format_allowlist,
    lock_id_for as lock_id_for,
    lock_id_from as lock_id_from,
)
from .gate_tools_calls import (
    DELEGATE_TASK_KEYS as DELEGATE_TASK_KEYS,
    DELEGATE_TOP_LEVEL_KEYS as DELEGATE_TOP_LEVEL_KEYS,
    DELEGATION_CONFIG_ROUTE_KEYS as DELEGATION_CONFIG_ROUTE_KEYS,
    DELEGATION_ROUTE_KEYS as DELEGATION_ROUTE_KEYS,
    IMAGE_SUFFIXES as IMAGE_SUFFIXES,
    SELF_APPROVAL_TOOLS as SELF_APPROVAL_TOOLS,
    STATE_FILE_TOOLS as STATE_FILE_TOOLS,
    _load_delegation_config as _load_delegation_config,
    args_bytes,
    args_kb as args_kb,
    ask_message as ask_message,
    attached_image_bytes as attached_image_bytes,
    call_bytes as call_bytes,
    default_delegation_ok,
    invokes_confidential_cli as invokes_confidential_cli,
    names_state_file as names_state_file,
    size_text as size_text,
)
from .gate_tools_classify import (
    BUILTIN_TOOL_CLASSES as BUILTIN_TOOL_CLASSES,
    CLASS_REASONS as CLASS_REASONS,
    CRON_TOOL as CRON_TOOL,
    DATA_CLASSES as DATA_CLASSES,
    DELEGATE_TOOL as DELEGATE_TOOL,
    MODE_TOOLS as MODE_TOOLS,
    OFF_HOST as OFF_HOST,
    ON_HOST as ON_HOST,
    ON_HOST_TOOLS as ON_HOST_TOOLS,
    UNKNOWN as UNKNOWN,
    UNSETTLED as UNSETTLED,
    Origin as Origin,
    Route as Route,
    ToolInfo as ToolInfo,
    _default_mcp_configs as _default_mcp_configs,
    _default_mcp_tool_servers as _default_mcp_tool_servers,
    _default_plugin_tool_names as _default_plugin_tool_names,
    classify_tool as classify_tool,
)
from .gate_tools_grants import (
    _ALLOW_CHOICES,
    _MISSING,
    ASK_EACH_CALL as ASK_EACH_CALL,
    ASK_MODES as ASK_MODES,
    ASK_ONCE_PER_LOCK as ASK_ONCE_PER_LOCK,
    DEFAULT_ASK_MODE as DEFAULT_ASK_MODE,
    DEFAULT_DECISIONS,
    KNOWN_CHOICES,
    ApprovalDecisions,
    LockGrants,
    _call_key,
    _choice_repr,
    _refusal_ledgered,
    ask_mode_from as ask_mode_from,
    grant_scope,
)
from .gate_tools_hermes import (
    APPROVAL_LABEL as APPROVAL_LABEL,
    PATTERN_KEY_PREFIX as PATTERN_KEY_PREFIX,
    PATTERN_KEY_STEM as PATTERN_KEY_STEM,
    RULE_KEY_PREFIX as RULE_KEY_PREFIX,
    RULE_KEY_STEM as RULE_KEY_STEM,
    _hermes_approval_state as _hermes_approval_state,
    bypass_active_for as bypass_active_for,
    bypass_text as bypass_text,
    cached_remote_environments as cached_remote_environments,
    hermes_bypass_active,
    hermes_bypass_is_interactive as hermes_bypass_is_interactive,
    hermes_remembered_grant,
    hermes_request_approval,
    hermes_terminal_backend as hermes_terminal_backend,
    parse_pattern_key,
    rule_key_for,
)
from .gate_tools_policy import CallDecision as CallDecision, _policy

# Set in this process's environment by the tool hooks before any tool runs (selfapproval.py): the id of the
# process that ran the tool. It reaches terminal, process_manage and execute_code children; every asker
# refuses when it names another process. An agent that unsets it, assembles the command at run time, or
# attaches through the gateway socket can still approve.
from .selfapproval import TOOL_PROCESS_ENV as TOOL_PROCESS_ENV, mark_tool_process


def _locked_flag(value: Any) -> bool:
    """is_locked() is canonically (bool, Tier | None) (Amendment 2); a bare bool is also accepted."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (tuple, list)) and len(value) == 2 and isinstance(value[0], bool):
        return value[0]
    raise TypeError(f"is_locked() returned {type(value).__name__}; expected bool or (bool, tier)")


# --------------------------------------------------------------------------------------------------
# the hooks
# --------------------------------------------------------------------------------------------------


def _event(kind: str, *, tool_name: str, session_id: str, decision: str, detail: dict,
           nbytes: int | None = None, surface: str | None = None) -> dict:
    return {
        "ts": time.time(), "session_id": session_id or "", "kind": kind, "purpose": f"tool:{tool_name}",
        "provider": "", "host": "", "model": "", "bytes": nbytes, "tier": None, "verdict": None,
        "decision": decision, "surface": surface, "detail": detail,
    }


def _block(message: str) -> dict:
    return {"action": "block", "message": message}


class LockStateError(RuntimeError):
    pass


def _lock_state(is_locked: Callable[[], Any]) -> bool:
    """True/False, or raise LockStateError (unreadable lock state blocks every tool, Amendment 3)."""
    try:
        return _locked_flag(is_locked())
    except Exception as exc:
        raise LockStateError(f"{type(exc).__name__}: {exc}") from exc


_LOCK_UNREADABLE = ("confidential mode: the lock state cannot be read, so every tool is blocked. "
                    "Run /confidential status (or /confidential off) to repair it.")


def build_pre_tool_call(is_locked: Callable[[], Any], allowlist: Allowlist | Callable[[], Allowlist],
                        ledger: Any, bypass_active: Callable[[str], bool] = hermes_bypass_active,
                        delegation_ok: Callable[[dict], bool] = default_delegation_ok,
                        remembered: Callable[[str], bool] = hermes_remembered_grant,
                        decisions: ApprovalDecisions | None = None,
                        terminal_backend: Callable[[str], str] | None = None,
                        rule_key: Callable[[str], str] = rule_key_for,
                        lock_grants: LockGrants | None = None,
                        ask_mode: Callable[[], str] | None = None) -> Callable[..., dict | None]:
    """``pre_tool_call`` callback: blocks every refuse decision (ledgered tool_refused) and, for an
    off-host tool, returns the approve directive with the "~N KB" message (ledgered tool_asked).
    The directive only ASKS: Hermes' CLI grants on any answer except the exact string "deny"
    (tools/approval.py:1006-1010), so enforcement is build_tool_execution. REGISTER BOTH, with the
    same ``decisions`` (or both defaulting to DEFAULT_DECISIONS) and build_post_approval_response.

    If the middleware already asked for this exact call (agent-loop order: tool_execution is
    outermost, agent/tool_executor.py:775-812, and pre_tool_call runs inside its next_call,
    :677-736), the hook returns None instead of asking a second time.

    ``bypass_active(tool_name)`` (zero-arg also accepted), ``delegation_ok(args)`` and
    ``remembered(tool_name)`` are injectable. ``is_locked()`` returns ``(bool, Tier | None)`` or a bool;
    anything else, or raising, blocks every tool. ``lock_grants`` and ``ask_mode`` (Amendment 13): pass the
    same LockGrants to both builders; without one every call asks (each_call)."""
    pol = _policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend, lock_grants, ask_mode)
    dec = decisions if decisions is not None else DEFAULT_DECISIONS

    def pre_tool_call(tool_name: str = "", args: dict | None = None, session_id: str = "",
                      tool_call_id: str = "", task_id: str = "", **_kw: Any) -> dict | None:
        mark_tool_process()
        try:
            locked = _lock_state(is_locked)
        except LockStateError as exc:
            _try_ledger(ledger, "tool_refused", tool_name, session_id, "lock_state_unreadable", args,
                        {"tool": str(tool_name), "tool_call_id": str(tool_call_id or ""), "error": str(exc)[:200]},
                        "gate")
            return _block(_LOCK_UNREADABLE)
        if not locked:
            return None
        try:
            a = args if isinstance(args, dict) else {}
            d = pol.decide(tool_name, a, str(task_id or ""), str(session_id or ""))
            base = {"tool": str(tool_name), "tool_call_id": str(tool_call_id or "")}
            if d.action == "refuse":
                ledger.append(_event("tool_refused", tool_name=tool_name, session_id=session_id or "",
                                     decision=d.decision, nbytes=args_bytes(a), surface="gate",
                                     detail={**base, "reason": d.decision}))
                return _block(d.message)
            if d.action == "run":
                return None
            if not tool_call_id:
                # No id => an answer recorded for this call could not be told apart from a concurrent
                # call's (Amendment 4 F3). Do not ask here; the middleware asks with a fresh approval id.
                return None
            key = _call_key(tool_name, tool_call_id)
            if dec.take_grant(key):
                return None                      # the middleware asked for this call already
            directive = {"action": "approve", "message": d.message, "rule_key": rule_key(tool_name)}
            dec.pop(key)                         # forget any stale answer for this key: only a fresh one counts
            if d.decision == "remembered":
                return directive                 # Hermes honours the grant silently; the middleware ledgers it
            ledger.append(_event("tool_asked", tool_name=tool_name, session_id=session_id or "", decision="ask",
                                 nbytes=args_bytes(a), surface="gate",
                                 detail={**base, "kb": d.kb, "message": d.message}))
            return directive
        except Exception as exc:  # never let a bug turn into "allow"
            return _block(f"confidential mode: tool gate error ({type(exc).__name__}); "
                          f"{_printable(tool_name)} blocked")

    return pre_tool_call


def _refusal_result(message: str) -> str:
    return json.dumps({"error": message})


def _try_ledger(ledger, kind, tool_name, session_id, decision, args, detail, surface) -> Any:
    """Append one row; returns its id, or None when the write failed."""
    try:
        return ledger.append(_event(kind, tool_name=tool_name, session_id=session_id or "", decision=decision,
                                    nbytes=args_bytes(args), surface=surface, detail=detail))
    except Exception:
        return None


def build_tool_execution(is_locked: Callable[[], Any], allowlist: Allowlist | Callable[[], Allowlist],
                         ledger: Any, decisions: ApprovalDecisions | None = None, *,
                         bypass_active: Callable[[str], bool] = hermes_bypass_active,
                         delegation_ok: Callable[[dict], bool] = default_delegation_ok,
                         remembered: Callable[[str], bool] = hermes_remembered_grant,
                         ask: Callable[..., dict] = hermes_request_approval,
                         terminal_backend: Callable[[str], str] | None = None,
                         rule_key: Callable[[str], str] = rule_key_for,
                         lock_grants: LockGrants | None = None,
                         ask_mode: Callable[[], str] | None = None) -> Callable[..., Any]:
    """``tool_execution`` middleware: the ENFORCEMENT line, for ctx.register_middleware("tool_execution", fn).

    Off-host tool => ``next_call`` only on an explicit once/session/always recorded by
    post_approval_response for this call, or a remembered grant under our rule key. How the answer
    is obtained depends on where Hermes put the middleware (84a0301):
      * model_tools.handle_function_call: pre_tool_call ran first (model_tools.py:954) and its approve
        directive asked; the middleware reads the recorded answer (model_tools.py:855-859);
      * agent loop: the middleware is OUTERMOST and pre_tool_call + approval run inside next_call
        (agent/tool_executor.py:775-812, :677-736), so no answer exists yet; the middleware asks
        itself on the agent thread and tells the inner hook not to ask again.
    Any other answer, including ones Hermes treats as a grant (None, "", "d", "yes"), is refused and
    ledgered tool_refused "unexpected_choice". Block routes are refused here too (second line).

    Never raises: our own errors become a refusal result; an exception from ``next_call`` (the tool
    itself) propagates unchanged, as Hermes expects.

    Under ``confidential.tools.ask: once_per_lock`` (``lock_grants`` given), an exact "once" answer also makes a
    lock grant holding the answering row's id; later calls of the tool in the same lock run with a
    ``tool_allowed`` row (decision ``lock_grant``, detail ``grant_row``), except while approvals are bypassed or
    nobody can be asked, which refuse as before (catalog rule 12)."""
    pol = _policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend, lock_grants, ask_mode)
    dec = decisions if decisions is not None else DEFAULT_DECISIONS

    def confidential_mode_tool_execution(tool_name: str = "", args: Any = None, next_call: Any = None,
                                         session_id: str = "", tool_call_id: str = "", turn_id: str = "",
                                         task_id: str = "", **_kw: Any) -> Any:
        mark_tool_process()
        downstream: dict[str, BaseException] = {}

        def run(payload: Any = None) -> Any:
            try:
                return next_call(args if payload is None else payload)
            except BaseException as exc:
                downstream["exc"] = exc
                raise

        try:
            return _handle(tool_name, args if isinstance(args, dict) else {}, run, session_id or "",
                           tool_call_id or "", turn_id or "", str(task_id or ""))
        except BaseException as exc:
            if exc is downstream.get("exc") or not isinstance(exc, Exception):
                raise
            _try_ledger(ledger, "tool_refused", tool_name, session_id, "gate_error", args,
                        {"tool": str(tool_name), "tool_call_id": str(tool_call_id or ""),
                         "error": type(exc).__name__}, "middleware")
            return _refusal_result(f"confidential mode: tool gate error ({type(exc).__name__}); "
                                   f"{_printable(tool_name)} blocked")

    def _refuse(tool_name, args, session_id, decision, message, detail, *, answered=False):
        # ``answered``: post_approval_response already wrote this decision's tool_refused row (it ledgers
        # every answer to our prompt), so a second row would count one refusal twice (ux-pass-1 item 5).
        if not answered:
            ledger.append(_event("tool_refused", tool_name=tool_name, session_id=session_id, decision=decision,
                                 nbytes=args_bytes(args), surface="middleware", detail=detail))
        return _refusal_result(message)

    def _handle(tool_name, args, run, session_id, tool_call_id, turn_id, task_id=""):
        base = {"tool": str(tool_name), "tool_call_id": tool_call_id}
        try:
            locked = _lock_state(is_locked)
        except LockStateError as exc:
            _try_ledger(ledger, "tool_refused", tool_name, session_id, "lock_state_unreadable", args,
                        {**base, "error": str(exc)[:200]}, "middleware")
            return _refusal_result(_LOCK_UNREADABLE)
        if not locked:
            return run()
        d = pol.decide(tool_name, args, task_id, session_id)
        if d.action == "refuse":
            return _refuse(tool_name, args, session_id, d.decision, d.message, {**base, "reason": d.decision})
        if d.action == "run":
            if d.decision != "on-host":
                detail = {**base, "grant_row": d.grant_row} if d.decision == "lock_grant" else base
                ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id,
                                     decision=d.decision, nbytes=args_bytes(args), surface="middleware", detail=detail))
            return run()
        key = _call_key(tool_name, tool_call_id) if tool_call_id else None
        # Never consume an answer recorded under an empty id (Amendment 4 F3).
        choice = dec.pop(key) if key is not None else _MISSING
        if choice is not _MISSING:                 # pre_tool_call asked (model_tools order)
            if type(choice) is str and choice in _ALLOW_CHOICES:
                if dec.pop_ledgered(key):  # type: ignore[arg-type]  # a choice was found, so key is set
                    row = dec.pop_row(key)  # type: ignore[arg-type]  # same: key is set when a choice was found
                else:                              # the hook's tool_allowed row could not be written
                    row = _allowed_row(tool_name, args, session_id, base, choice)
                _grant_for_lock(tool_name, choice, row, session_id)
                return run()                       # tool_allowed was ledgered by post_approval_response
            return _unexpected(tool_name, args, session_id, base, choice,
                               answered=dec.pop_ledgered(key)  # type: ignore[arg-type]  # key is set here
                               and _refusal_ledgered(choice))
        if d.decision == "remembered":
            ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id, decision="remembered",
                                 nbytes=args_bytes(args), surface="middleware", detail={**base, "kb": d.kb}))
            return run()
        # Nobody asked yet (agent-loop order, or pre_tool_call skipped): ask here.
        approval_id = f"cm-{uuid.uuid4().hex}"
        ledger.append(_event("tool_asked", tool_name=tool_name, session_id=session_id, decision="ask",
                             nbytes=args_bytes(args), surface="middleware",
                             detail={**base, "kb": d.kb, "message": d.message, "approval_id": approval_id}))
        with dec.asking(tool_name, approval_id):
            result = ask(tool_name, d.message, rule_key=rule_key(tool_name), approval_id=approval_id,
                         session_id=session_id, turn_id=turn_id)
        choice = dec.pop(_call_key(tool_name, approval_id))
        hook_wrote_row = dec.pop_ledgered(_call_key(tool_name, approval_id))
        answer_row = dec.pop_row(_call_key(tool_name, approval_id))
        approved = isinstance(result, dict) and result.get("approved") is True
        if approved and type(choice) is str and choice in _ALLOW_CHOICES:
            if not hook_wrote_row:                 # the hook's tool_allowed row could not be written
                answer_row = _allowed_row(tool_name, args, session_id, {**base, "approval_id": approval_id}, choice)
            _grant_for_lock(tool_name, choice, answer_row, session_id)
            if key is None:
                return run()                       # the inner hook never asks for an id-less call
            dec.grant(key)
            try:
                return run()
            finally:
                dec.drop_grant(key)
        if approved:
            return _unexpected(tool_name, args, session_id, {**base, "approval_id": approval_id},
                               None if choice is _MISSING else choice,
                               answered=hook_wrote_row and _refusal_ledgered(choice))
        decision = "no_surface" if (choice is _MISSING and isinstance(result, dict)
                                    and result.get("status") == "approval_required") else "denied"
        return _refuse(tool_name, args, session_id, decision,
                       str((result or {}).get("message") or f"confidential mode: {tool_name} was not approved"),
                       {**base, "choice": None if choice is _MISSING else _choice_repr(choice),
                        "approval_id": approval_id}, answered=hook_wrote_row and _refusal_ledgered(choice))

    def _allowed_row(tool_name, args, session_id, base, choice):
        return _try_ledger(ledger, "tool_allowed", tool_name, session_id, choice, args, {**base, "choice": choice},
                           "middleware")

    def _grant_for_lock(tool_name, choice, row_id, session_id):
        """An exact "once" under once_per_lock grants the tool for this lock, in this conversation only. Never
        raises: a grant that cannot be made only means the next call asks again."""
        try:
            if choice == "once" and pol.once_per_lock():
                pol.lock_grants.grant(  # type: ignore[union-attr]  # once_per_lock() needs lock_grants
                    pol.allowlist().lock_id, grant_scope(session_id), tool_name, row_id)
        except Exception:  # noqa: BLE001
            pass

    def _unexpected(tool_name, args, session_id, base, choice, *, answered=False):
        return _refuse(tool_name, args, session_id, "unexpected_choice",
                       f"confidential mode: {_printable(tool_name)} was not run: the answer to the approval prompt "
                       f"was not once/session/always ({_printable(_choice_repr(choice))}).",
                       {**base, "choice": _choice_repr(choice)}, answered=answered)

    return confidential_mode_tool_execution


def build_post_approval_response(is_locked: Callable[[], Any], ledger: Any,
                                 decisions: ApprovalDecisions | None = None) -> Callable[..., None]:
    """``post_approval_response`` observer: ledgers tool_allowed / tool_refused for OUR approve
    directives only (pattern_key ``plugin_rule:confidential-mode:tool:<name>``), and records the exact
    choice in ``decisions`` (default DEFAULT_DECISIONS) for build_tool_execution. Only the exact strings
    once/session/always are tool_allowed; every other value is tool_refused. Never raises."""
    dec = decisions if decisions is not None else DEFAULT_DECISIONS

    def post_approval_response(pattern_key: str = "", choice: str = "", session_id: str = "",
                               session_key: str = "", surface: str = "", tool_call_id: str = "",
                               **kw: Any) -> None:
        try:
            parsed = parse_pattern_key(pattern_key)
            if parsed is None:
                return None
            tool_name = parsed[0]
            # An answer with an empty id is keyed on the middleware's ask in progress, if any (Amendment 11).
            call_id = tool_call_id or dec.current_ask(tool_name)
            pick = choice if type(choice) is str else ""
            allowed = pick in _ALLOW_CHOICES
            detail = {"tool": tool_name, "choice": _choice_repr(choice), "tool_call_id": call_id or "",
                      "session_key": session_key or "", "locked": _safe(is_locked)}
            # The row first, then the choice: a row that could not be written leaves the middleware to write
            # the refusal itself, so a denial is always recorded once and always stands.
            wrote, row_id = False, None
            try:
                row_id = ledger.append(_event("tool_allowed" if allowed else "tool_refused", tool_name=tool_name,
                                     session_id=session_id or "",
                                     decision=pick if pick in KNOWN_CHOICES else "unexpected_choice",
                                     surface=surface or None, detail=detail))
                wrote = True
            except Exception as exc:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning(
                    "confidential-mode: could not ledger the answer for %s (%s); the middleware records it",
                    _printable(tool_name), type(exc).__name__)
            if call_id:                          # an id-less answer is never recorded (Amendment 4 F3)
                dec.record(_call_key(tool_name, call_id), choice, ledgered=wrote, row_id=row_id)
        except Exception:
            pass
        return None

    return post_approval_response


def _safe(fn: Callable[[], Any]) -> Any:
    try:
        return _locked_flag(fn())
    except Exception:
        return None

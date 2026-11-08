"""Tool gate, answers and grants: what a person answered and what it allows.

``ApprovalDecisions`` carries each answer from ``post_approval_response`` to the tool_execution
middleware by tool_call_id (never under an empty id, Amendment 4 F3). ``LockGrants`` holds the
once-per-lock grants (``confidential.tools.ask``, ``ask_mode_from``), scoped to one conversation
(``grant_scope``); a revoke drops them (revoke.py).
"""
from __future__ import annotations

import contextlib
import threading
from collections.abc import Mapping
from typing import Any

# post_approval_response choices that let the tool run (tools/approval.py:907-913, :928).
_ALLOW_CHOICES = frozenset({"once", "session", "always"})


# confidential.tools.ask (Amendment 13): how often an off-host tool asks while locked.
ASK_EACH_CALL, ASK_ONCE_PER_LOCK = "each_call", "once_per_lock"
ASK_MODES = (ASK_EACH_CALL, ASK_ONCE_PER_LOCK)
DEFAULT_ASK_MODE = ASK_ONCE_PER_LOCK


def ask_mode_from(config: Any) -> str:
    """``confidential.tools.ask``: once_per_lock (default, also when absent) or each_call. Any other value is
    each_call, the stricter mode (fail closed)."""
    node = config.get("confidential") if isinstance(config, Mapping) else None
    node = node.get("tools") if isinstance(node, Mapping) else None
    if not isinstance(node, Mapping) or "ask" not in node:
        return DEFAULT_ASK_MODE
    value = node.get("ask")
    return value if isinstance(value, str) and value in ASK_MODES else ASK_EACH_CALL


def grant_scope(session_id: str = "") -> tuple[str, str]:
    """The conversation a lock grant belongs to: Hermes' approval session key (the key Hermes' own "session"
    answer is stored under; a gateway chat, a CLI session) and the agent's session id (a subagent has its own).
    A grant is never wider than Hermes' session answer. Any error reading the key: an empty key, so the grant
    still needs the same session id. Both empty names no conversation: LockGrants makes no grant for that
    scope, so such a caller is asked on every call instead of sharing one grant with every other such caller."""
    try:
        from .hermes_compat import current_session_key
        key = current_session_key("")
    except Exception:  # noqa: BLE001
        key = ""
    return (str(key or ""), str(session_id or ""))


class LockGrants:
    """The plugin's own tool grants under ``confidential.tools.ask: once_per_lock`` (Amendment 13): one per
    (lock id, conversation, tool), where the conversation is ``grant_scope``: Hermes' approval session key and
    the agent's session id. A grant is made when a person answers "once" to the plugin's prompt and holds the
    id of the ledger row that recorded the answer. A grant counts only for the lock it was made in and only in
    the conversation that answered: another chat, user or subagent asks again. A grant ends at unlock; a revoke
    drops it. In memory, per process: a restart asks again. The gate never consults a grant while Hermes'
    approvals are bypassed (yolo, approvals off) or nobody can be asked (one-shot, cron, unattended
    platforms): those keep refusing. A scope with neither a session key nor a session id names no
    conversation, so it is never granted and never matches: that caller is asked on every call."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[tuple[str, tuple[str, str], str], Any] = {}

    @staticmethod
    def _scope(scope: Any) -> tuple[str, str] | None:
        """The scope as a key, or None when it names no conversation (both parts empty) or is malformed."""
        try:
            key, sid = scope
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(key, str) or not isinstance(sid, str) or not (key or sid):
            return None
        return (key, sid)

    def grant(self, lock_id: str, scope: Any, tool: str, row_id: Any) -> None:
        scope = self._scope(scope)
        if not lock_id or scope is None or not isinstance(tool, str) or not tool:
            return
        with self._lock:
            for key in [k for k in self._grants if k[0] != lock_id]:
                del self._grants[key]          # grants of an earlier lock end with that lock
            self._grants[(lock_id, scope, tool)] = row_id

    def get(self, lock_id: str, scope: Any, tool: str) -> Any:
        """The answering row id, or _MISSING when this conversation has no grant for the tool in this lock."""
        scope = self._scope(scope)
        if not lock_id or scope is None:
            return _MISSING
        with self._lock:
            return self._grants.get((lock_id, scope, tool), _MISSING)

    def drop(self, tools: set | None = None) -> list[str]:
        with self._lock:
            gone = sorted({k[2] for k in self._grants if tools is None or k[2] in tools})
            for key in [k for k in self._grants if tools is None or k[2] in tools]:
                del self._grants[key]
        return gone

    def names(self, lock_id: str) -> list[str]:
        """Every tool granted in this lock, in any conversation of this process."""
        with self._lock:
            return sorted({k[2] for k in self._grants if k[0] == lock_id})


def _refusal_ledgered(choice: Any) -> bool:
    """Whether post_approval_response already wrote a tool_refused row for this recorded answer: it writes
    one for every answer that is not exactly once/session/always (an allow answer is a tool_allowed row)."""
    return choice is not _MISSING and not (type(choice) is str and choice in _ALLOW_CHOICES)


def _call_key(tool_name: Any, tool_call_id: Any) -> str:
    return f"{tool_name}\x00{tool_call_id or ''}"


class ApprovalDecisions:
    """Shared between post_approval_response, pre_tool_call and tool_execution.

    * ``record/pop``: the human's exact answer, keyed by (tool, tool_call_id) as Hermes reports it in
      post_approval_response (the observability context carries the call's tool_call_id,
      hermes_cli/plugins.py:1996-2009, tools/approval_context.py:55-73).
    * ``grant/take_grant``: the middleware asked and got an explicit answer for this call (agent-loop
      order, where the middleware runs first), so the inner pre_tool_call must not ask again."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._choices: dict[str, Any] = {}
        self._ledgered: set[str] = set()
        self._rows: dict[str, Any] = {}
        self._grants: set[str] = set()
        self._asking = threading.local()

    def record(self, key: str, choice: Any, *, ledgered: bool = False, row_id: Any = None) -> None:
        """``ledgered``: post_approval_response wrote this answer's row (``row_id``), so the middleware writes
        none."""
        with self._lock:
            self._choices[key] = choice
            if ledgered:
                self._ledgered.add(key)
                self._rows[key] = row_id
            else:
                self._ledgered.discard(key)
                self._rows.pop(key, None)

    def pop_row(self, key: str) -> Any:
        """The ledger row id of the answer recorded under ``key`` (once), or None."""
        with self._lock:
            return self._rows.pop(key, None)

    def pop(self, key: str) -> Any:
        with self._lock:
            return self._choices.pop(key, _MISSING)

    def pop_ledgered(self, key: str) -> bool:
        with self._lock:
            if key in self._ledgered:
                self._ledgered.discard(key)
                return True
            return False

    @contextlib.contextmanager
    def asking(self, tool_name: str, approval_id: str):
        """The middleware's ask in progress on this thread. Hermes fires post_approval_response on the asking
        thread; an answer that arrives with an empty tool_call_id is keyed on this approval id, so it is
        recorded once and the middleware finds it (Amendment 11)."""
        previous = getattr(self._asking, "value", None)
        self._asking.value = (tool_name, approval_id)
        try:
            yield
        finally:
            self._asking.value = previous

    def current_ask(self, tool_name: str) -> str:
        value = getattr(self._asking, "value", None)
        return value[1] if isinstance(value, tuple) and value[0] == tool_name else ""

    def grant(self, key: str) -> None:
        with self._lock:
            self._grants.add(key)

    def take_grant(self, key: str) -> bool:
        with self._lock:
            if key in self._grants:
                self._grants.discard(key)
                return True
            return False

    def drop_grant(self, key: str) -> None:
        with self._lock:
            self._grants.discard(key)


_MISSING = object()
DEFAULT_DECISIONS = ApprovalDecisions()   # used when the builders are not handed one explicitly


#: Hermes' own approval answers (tools/approval.py). Only these are stored verbatim (review finding 20).
KNOWN_CHOICES = frozenset({"once", "session", "always", "deny", "timeout", "cancelled", "notify_failed",
                           "smart_approve", "smart_deny"})


def _choice_repr(choice: Any) -> Any:
    """A classification of an approval answer, safe to store and to show the model. A human may type a
    secret at the prompt by mistake (review finding 20), so free text is never kept: Hermes' fixed answers
    and "" stay as they are, None stays None, any other string is "other", any other value is its type."""
    if choice is None:
        return None
    if type(choice) is str:                   # exact type first: a str subclass's __eq__ is never consulted
        return choice if choice == "" or choice in KNOWN_CHOICES else "other"
    if isinstance(choice, str):
        return "other"
    return f"<{type(choice).__name__}>"

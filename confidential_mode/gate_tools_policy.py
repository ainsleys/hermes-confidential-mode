"""Tool gate, policy: the decision for one call while locked.

``_Policy.decide`` returns a ``CallDecision`` (run, refuse or ask) from the allowlist entry, the bypass
state, the self-approval guard, the delegation check and any once-per-lock grant. The hook and the
middleware in gate_tools.py both call it, so they decide the same way.
"""
from __future__ import annotations

import inspect
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .gate_tools_allowlist import _printable
from .gate_tools_calls import (
    SELF_APPROVAL_TOOLS,
    STATE_FILE_TOOLS,
    ask_message,
    call_bytes,
    invokes_confidential_cli,
    names_state_file,
)
from .gate_tools_classify import Route
from .gate_tools_grants import _MISSING, ASK_ONCE_PER_LOCK, DEFAULT_ASK_MODE, grant_scope
from .gate_tools_hermes import bypass_text, hermes_bypass_is_interactive, hermes_terminal_backend

if TYPE_CHECKING:
    from .gate_tools_allowlist import Allowlist
    from .gate_tools_classify import ToolInfo
    from .gate_tools_grants import LockGrants


@dataclass(frozen=True)
class CallDecision:
    """What the gate does with one call. ``action``: run | refuse | ask."""
    action: str
    decision: str = ""          # ledger decision code
    message: str = ""           # refusal text, or the ask prompt text
    kb: int = 0
    grant_row: Any = None       # decision "lock_grant": the id of the ledger row that answered the ask


class _Policy:
    """The classification both enforcement points share."""

    def __init__(self, allowlist, bypass_active, delegation_ok, remembered, terminal_backend=None,
                 lock_grants: LockGrants | None = None, ask_mode: Callable[[], str] | None = None):
        self._allowlist = allowlist
        self._bypass_fn = bypass_active
        self._takes_name = _accepts_positional(bypass_active)
        self.delegation_ok = delegation_ok
        self.remembered = remembered
        self.terminal_backend = terminal_backend if terminal_backend is not None else hermes_terminal_backend
        self.lock_grants = lock_grants
        self._ask_mode = ask_mode

    def once_per_lock(self) -> bool:
        """True when lock grants apply: a grant store is wired and confidential.tools.ask is once_per_lock.
        An unreadable setting is each_call."""
        if self.lock_grants is None:
            return False
        try:
            mode = self._ask_mode() if self._ask_mode is not None else DEFAULT_ASK_MODE
        except Exception:  # noqa: BLE001
            return False
        return mode == ASK_ONCE_PER_LOCK

    def allowlist(self) -> Allowlist:
        return self._allowlist() if callable(self._allowlist) else self._allowlist

    def bypass(self, tool_name: str) -> bool:
        return bool(self._bypass_fn(tool_name) if self._takes_name else self._bypass_fn())

    def on_host_decision(self, info: ToolInfo, args: dict, task_id: str = "") -> CallDecision:
        # Review finding 2 (INTERFACES Amendment 6): a terminal-backend tool is on-host only on the local
        # backend. The preflight refuses to lock otherwise; this is the second line, per call, because the
        # environment variable, the profile's terminal scope or a cached task environment can differ from
        # what the lock saw.
        from .preflight import LOCAL_BACKEND, TERMINAL_BACKEND_KEY, TERMINAL_BACKEND_TOOLS
        if info.name in SELF_APPROVAL_TOOLS:
            why = invokes_confidential_cli(args, info.name)
            if why:
                return CallDecision("refuse", "self_approval",
                                    f"confidential mode: {info.name} was blocked because its command {why}. While "
                                    "locked, no terminal, process or code tool may run the confidential command: "
                                    "pins and tool grants are approved by a person, on a terminal or chat surface "
                                    "the agent does not drive.")
        if info.name in STATE_FILE_TOOLS and names_state_file(args):
            return CallDecision("refuse", "self_approval",
                                f"confidential mode: {info.name} was blocked because it targets one of the plugin's "
                                "state files (pins.yaml, ledger.sqlite, allowlist.yaml or its state.json), which no "
                                "tool may write while locked.")
        if info.name in TERMINAL_BACKEND_TOOLS:
            try:
                backend = self.terminal_backend(task_id)
            except Exception as exc:  # noqa: BLE001 - cannot tell where the tool runs: block
                return CallDecision("refuse", "terminal_backend_unreadable",
                                    f"confidential mode: {info.name} was blocked because the plugin cannot read "
                                    f"Hermes' terminal backend ({type(exc).__name__}), so it cannot tell whether "
                                    "the tool runs on this host.")
            if backend != LOCAL_BACKEND:
                return CallDecision("refuse", "terminal_backend",
                                    f"confidential mode: {info.name} was blocked because Hermes' terminal backend "
                                    f"is {_printable(backend)}, so the tool would run there, not on this host. "
                                    f"Set {TERMINAL_BACKEND_KEY}: local (and unset TERMINAL_ENV), then run "
                                    "/confidential off and lock again.")
        # Extension point for MODE_TOOLS (terminal / execute_code three-mode rule, pending).
        return CallDecision("run", "on-host")

    def decide(self, tool_name: str, args: dict, task_id: str = "", session_id: str = "") -> CallDecision:
        al = self.allowlist()
        info = al.current(tool_name) if isinstance(tool_name, str) else None
        if info is None:
            return CallDecision("refuse", "unclassified",
                                f"confidential mode: {_printable(tool_name)} is not the tool that was registered "
                                "when this profile was locked (new, renamed, re-registered or swapped), so it is "
                                "blocked. Run /confidential off and lock again to classify it.")
        if info.route is Route.ON_HOST:
            return self.on_host_decision(info, args, task_id)
        if info.route is Route.BLOCK_CRON:
            return CallDecision("refuse", "cron", "confidential mode: scheduled jobs (cronjob_manage) are blocked "
                                                  "while locked; a job would run later outside this locked session.")
        if info.route is Route.BLOCK_MCP_URL:
            return CallDecision("refuse", "mcp_url",
                                f"confidential mode: {_printable(tool_name)} belongs to MCP server "
                                f"'{_printable(info.mcp_server)}' ({_printable(info.mcp_host or 'host unknown')}: "
                                f"{_printable(info.reason)}); blocked while locked.")
        if info.route is Route.DELEGATE:
            if self.delegation_ok(args):
                return CallDecision("run", "delegation_default")
            return CallDecision("refuse", "delegation_route",
                                "confidential mode: delegate_task is allowed only on the default delegation "
                                "backend with no profile, ACP command, provider, base_url or other route field; "
                                "this call is blocked.")
        # Route.ASK
        if al.is_added(tool_name):
            return CallDecision("run", "allowlist")
        if self.bypass(tool_name):
            name = _printable(tool_name)
            return CallDecision("refuse", "bypass_active", bypass_text(name, hermes_bypass_is_interactive()))
        nbytes = call_bytes(args)
        n = max(1, math.ceil(nbytes / 1024))
        once = self.once_per_lock()
        if once:
            row = self.lock_grants.get(  # type: ignore[union-attr]  # once_per_lock() needs lock_grants
                al.lock_id, grant_scope(session_id), tool_name)
            if row is not _MISSING:
                return CallDecision("run", "lock_grant", kb=n, grant_row=row)
        return CallDecision("ask", "remembered" if self.remembered(tool_name) else "ask",
                            ask_message(tool_name, nbytes, once_per_lock=once), kb=n)


def _policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend=None, lock_grants=None,
            ask_mode=None) -> _Policy:
    return _Policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend, lock_grants, ask_mode)


def _accepts_positional(fn: Callable[..., Any]) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL) for p in params)

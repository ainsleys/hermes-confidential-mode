"""Tool gate for sealed mode (W4): allowlist built from Hermes' live registry, a ``pre_tool_call``
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
  session /yolo, ``hermes -z`` unattended turns), ``approvals.mode: off``, a remembered
  session/always grant for the same ``plugin_rule:`` key, and cron / unattended-platform /
  single-query contexts whose mode is ``approve`` (tools/approval.py:1071-1113). Sealed mode must
  BLOCK in all of those instead of returning the approve directive (docs/C0-spikes.md, spike 3).
"""
from __future__ import annotations

import functools
import inspect
import json
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Optional

# The contract's local set (docs/INTERFACES.md, "W4 gate_tools.py, consent.py"). Exactly these.
LOCAL_TOOLS: frozenset[str] = frozenset({
    "terminal", "process_manage", "execute_code", "read_file", "write_file", "patch", "search_files",
    "skills_list", "skill_view", "skill_manage", "todo_list", "memory", "clarify", "session_search",
})
CRON_TOOL = "cronjob_manage"
DELEGATE_TOOL = "delegate_task"

# Our approve directive's rule_key. Hermes prefixes it with ``plugin_rule:`` (tools/approval.py:1226);
# the remembered-grant check MUST use the prefixed key (see hermes_bypass_active).
RULE_KEY_PREFIX = "confidential-mode:tool:"
PATTERN_KEY_PREFIX = "plugin_rule:" + RULE_KEY_PREFIX

# post_approval_response choices that let the tool run (tools/approval.py:907-913, :928).
_ALLOW_CHOICES = frozenset({"once", "session", "always"})


class Origin(str, Enum):
    BUILTIN = "builtin"
    PLUGIN = "plugin"
    MCP = "mcp"


class Route(str, Enum):
    """What the sealed gate does with a tool."""
    LOCAL = "local"                 # runs, nothing asked, nothing ledgered
    ASK = "ask"                     # off-machine: per-call human approval (block under bypass)
    DELEGATE = "delegate"           # allowed only via delegation_ok
    BLOCK_CRON = "block-cron"       # cronjob_manage: always blocked
    BLOCK_MCP_URL = "block-mcp-url"  # tool from an MCP server configured with a URL: always blocked


@dataclass(frozen=True)
class ToolInfo:
    name: str
    toolset: str
    origin: Origin
    route: Route
    mcp_server: Optional[str] = None   # raw server name for MCP tools
    mcp_transport: Optional[str] = None  # "url" | "stdio" | "unknown" for MCP tools


@dataclass
class Allowlist:
    """Classification computed at seal. ``added`` holds names a human allowed via consent.allow_tool."""
    tools: dict[str, ToolInfo]
    built_at: float = field(default_factory=time.time)
    added: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def get(self, name: str) -> Optional[ToolInfo]:
        return self.tools.get(name)

    def names(self, route: Route) -> list[str]:
        return sorted(n for n, t in self.tools.items() if t.route is route)

    @property
    def local(self) -> list[str]:
        return self.names(Route.LOCAL)

    def is_added(self, name: str) -> bool:
        with self._lock:
            return name in self.added

    def add(self, name: str) -> None:
        """Only consent.allow_tool calls this, after a human picked Allow."""
        info = self.tools.get(name)
        if info is None or info.route is not Route.ASK:
            raise ValueError(f"{name!r} cannot be added to the allowlist")
        with self._lock:
            self.added.add(name)


# --------------------------------------------------------------------------------------------------
# allowlist from the live registry
# --------------------------------------------------------------------------------------------------

def _default_mcp_configs() -> dict[str, dict]:
    """Every MCP server config Hermes knows: ``mcp_servers`` (incl. portable packages) overlaid with
    the live connection configs. Never raises."""
    configs: dict[str, dict] = {}
    try:
        from tools.mcp_tool_config import _load_mcp_config
        for name, cfg in (_load_mcp_config() or {}).items():
            if isinstance(cfg, dict):
                configs[str(name)] = dict(cfg)
    except Exception:
        pass
    try:
        from tools import mcp_tool as _core
        from tools.mcp_tool_scope import _key_name
        with _core._lock:
            live = list(_core._servers.items())
        for key, server in live:
            cfg = getattr(server, "_config", None)
            if isinstance(cfg, dict) and cfg:
                name = _key_name(key)
                # url anywhere wins (fail closed): merge rather than replace.
                configs[name] = {**configs.get(name, {}), **cfg}
    except Exception:
        pass
    return configs


def _default_mcp_tool_servers() -> dict[str, str]:
    try:
        from tools import mcp_tool as _core
        with _core._lock:
            return dict(_core._mcp_tool_server_names)
    except Exception:
        return {}


def _default_plugin_tool_names() -> set[str]:
    try:
        from hermes_cli.plugins import get_plugin_manager
        return set(getattr(get_plugin_manager(), "_plugin_tool_names", ()) or ())
    except Exception:
        return set()


def _handler_module(handler: Any) -> str:
    """Defining module of a handler through partials / bound methods / wrappers (same walk as
    ToolRegistry._callable_module, tools/registry.py:666-684, without importing Hermes)."""
    current, seen = handler, set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        globals_dict = getattr(current, "__globals__", None)
        if isinstance(current, functools.partial):
            current = current.func
        elif getattr(current, "__func__", None) is not None:
            current = current.__func__
        elif isinstance(globals_dict, dict) and globals_dict.get("__name__"):
            return str(globals_dict["__name__"])
        elif getattr(current, "__wrapped__", None) is not None:
            current = current.__wrapped__
        else:
            break
    return str(getattr(current, "__module__", "") or "")


def _mcp_transport(cfg: Optional[Mapping[str, Any]]) -> str:
    if not isinstance(cfg, Mapping):
        return "unknown"
    if "url" in cfg:          # same test Hermes uses to pick HTTP over stdio
        return "url"
    if "command" in cfg:
        return "stdio"
    return "unknown"


def classify_tool(name: str, toolset: str, *, origin: Origin, mcp_server: Optional[str] = None,
                  mcp_config: Optional[Mapping[str, Any]] = None) -> ToolInfo:
    if origin is Origin.MCP:
        transport = _mcp_transport(mcp_config)
        # A URL server, or one whose transport we cannot establish, is blocked (fail closed).
        route = Route.ASK if transport == "stdio" else Route.BLOCK_MCP_URL
        return ToolInfo(name, toolset, origin, route, mcp_server, transport)
    if name in LOCAL_TOOLS and origin is Origin.BUILTIN:
        route = Route.LOCAL
    elif name == CRON_TOOL:
        route = Route.BLOCK_CRON
    elif name == DELEGATE_TOOL:
        route = Route.DELEGATE
    else:
        route = Route.ASK
    return ToolInfo(name, toolset, origin, route)


def build_allowlist(registry: Any, *, mcp_configs: Optional[Mapping[str, Mapping[str, Any]]] = None,
                    mcp_tool_servers: Optional[Mapping[str, str]] = None,
                    plugin_tool_names: Optional[Iterable[str]] = None) -> Allowlist:
    """Classify every tool in ``registry.get_all_entries()``. The keyword arguments default to Hermes'
    live state (see the module docstring); tests pass fakes.

    A LOCAL-set name re-registered by a plugin (``override=True``) or by an MCP server is NOT local:
    locality is a property of the built-in implementation, not of the name."""
    if mcp_configs is None:
        mcp_configs = _default_mcp_configs()
    if mcp_tool_servers is None:
        mcp_tool_servers = _default_mcp_tool_servers()
    plugin_names = set(_default_plugin_tool_names() if plugin_tool_names is None else plugin_tool_names)
    tools: dict[str, ToolInfo] = {}
    for entry in registry.get_all_entries():
        name, toolset = str(entry.name), str(entry.toolset or "")
        if toolset.startswith("mcp-"):
            server = mcp_tool_servers.get(name) or toolset[len("mcp-"):]
            tools[name] = classify_tool(name, toolset, origin=Origin.MCP, mcp_server=server,
                                        mcp_config=mcp_configs.get(server))
            continue
        is_plugin = name in plugin_names or _handler_module(getattr(entry, "handler", None)).startswith(
            "hermes_plugins.")
        tools[name] = classify_tool(name, toolset, origin=Origin.PLUGIN if is_plugin else Origin.BUILTIN)
    return Allowlist(tools=tools)


_ROUTE_TITLES = (
    (Route.LOCAL, "local (runs without asking)"),
    (Route.ASK, "off-machine (asks each call; blocked under yolo/approvals off/unattended)"),
    (Route.DELEGATE, "delegation (default backend only, no profile/ACP)"),
    (Route.BLOCK_CRON, "blocked (scheduled jobs)"),
    (Route.BLOCK_MCP_URL, "blocked (MCP server reached by URL)"),
)


def format_allowlist(allowlist: Allowlist) -> str:
    """Printed on seal."""
    lines: list[str] = []
    for route, title in _ROUTE_TITLES:
        infos = [allowlist.tools[n] for n in allowlist.names(route)]
        lines.append(f"{title}: {len(infos)}")
        for info in infos:
            extra = [info.origin.value]
            if info.mcp_server is not None:
                extra.append(f"server={info.mcp_server}, transport={info.mcp_transport}")
            if info.name in allowlist.added:
                extra.append("allowed by you")
            lines.append(f"  {info.name}  [{info.toolset}; {'; '.join(extra)}]")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------------
# bypass and delegation predicates (defaults wired by register(); injectable for tests)
# --------------------------------------------------------------------------------------------------

def rule_key_for(tool_name: str) -> str:
    return f"{RULE_KEY_PREFIX}{tool_name}"


def hermes_bypass_active(tool_name: str) -> bool:
    """True when Hermes' approval gate would NOT put our approve directive in front of a human.
    Mirrors ``_run_approval_gate`` (tools/approval.py:1071-1113) in order. Any error -> True (block)."""
    try:
        from tools.approval import _presence, _yolo_active, is_approved
        from tools.approval_context import _get_approval_mode, get_current_session_key
        if _yolo_active() or _get_approval_mode() == "off":
            return True
        # The plugin_rule: prefix trap: the remembered grant is stored under the PREFIXED key;
        # is_approved(sk, rule_key) without it is always False (tests/spikes/test_approval_gate.py:384).
        if is_approved(get_current_session_key(), f"plugin_rule:{rule_key_for(tool_name)}"):
            return True
        _cb, is_cli, is_gateway, is_ask = _presence(None)
        # Nobody to ask: Hermes either blocks or (cron/unattended/single_query mode approve) auto-approves.
        # Either way no human decides, so we block ourselves.
        return not (is_cli or is_gateway or is_ask)
    except Exception:
        return True


def bypass_active_for(tool_name: str) -> Callable[[], bool]:
    return lambda: hermes_bypass_active(tool_name)


# Task/top-level keys that would move a child off the parent's route (delegate_tool.py:911,
# agent/delegation_provider.py:45-48, delegate_tool_routes.py:227-235).
DELEGATION_ROUTE_KEYS = frozenset({
    "profile", "acp_command", "acp_args", "provider", "model", "base_url", "api_key", "api_mode",
})
# delegation config keys that move a child off the parent's route under the default backend
# (plugins/delegation/default/__init__.py:32-34 returns the whole section as the route;
# delegate_tool_config.py:478-497; delegate_tool.py:435-436, :620-630).
DELEGATION_CONFIG_ROUTE_KEYS = frozenset({"profile", "command", "args", "provider", "base_url"})


def _load_delegation_config() -> dict:
    from tools.delegate_tool_config import _load_config
    cfg = _load_config()
    return cfg if isinstance(cfg, dict) else {}


def default_delegation_ok(args: Mapping[str, Any], *,
                          load_config: Callable[[], Mapping[str, Any]] = _load_delegation_config) -> bool:
    """delegate_task is allowed iff the child inherits the parent's (sealed, in-tier) route: the
    ``default`` backend, no profile / ACP command / provider / base_url in ``delegation``, and no
    route keys in the model's arguments. Any error -> False."""
    try:
        cfg = dict(load_config() or {})
        backend = cfg.get("backend")
        if isinstance(backend, str) and backend.strip() and backend.strip().lower() != "default":
            return False
        if backend is not None and not isinstance(backend, str):
            return False
        for key in DELEGATION_CONFIG_ROUTE_KEYS:
            value = cfg.get(key)
            if value not in (None, "", [], {}):
                return False
        if not isinstance(args, Mapping):
            return False
        if any(args.get(k) not in (None, "", []) for k in DELEGATION_ROUTE_KEYS):
            return False
        tasks = args.get("tasks")
        if tasks is not None:
            if not isinstance(tasks, list):
                return False
            for task in tasks:
                if not isinstance(task, Mapping):
                    return False
                if any(task.get(k) not in (None, "", []) for k in DELEGATION_ROUTE_KEYS):
                    return False
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------------------------------
# the hooks
# --------------------------------------------------------------------------------------------------

def _dumps(args: Any) -> str:
    try:
        return json.dumps(args if args is not None else {}, default=str)
    except Exception:
        return str(args)


def args_kb(args: Any) -> int:
    """~KB of conversation a call ships: ceil(len(json.dumps(args)) / 1024), minimum 1."""
    return max(1, math.ceil(len(_dumps(args)) / 1024))


def args_bytes(args: Any) -> int:
    """len(json.dumps(args)): ASCII-escaped, so characters == bytes."""
    return len(_dumps(args))


def _event(kind: str, *, tool_name: str, session_id: str, decision: str, detail: dict,
           nbytes: Optional[int] = None, surface: Optional[str] = None) -> dict:
    return {
        "ts": time.time(), "session_id": session_id or "", "kind": kind, "purpose": f"tool:{tool_name}",
        "provider": "", "host": "", "model": "", "bytes": nbytes, "tier": None, "verdict": None,
        "decision": decision, "surface": surface, "detail": detail,
    }


def _block(message: str) -> dict:
    return {"action": "block", "message": message}


def build_pre_tool_call(is_sealed: Callable[[], bool], allowlist: Allowlist | Callable[[], Allowlist],
                        ledger: Any, bypass_active: Callable[[str], bool] = hermes_bypass_active,
                        delegation_ok: Callable[[dict], bool] = default_delegation_ok) -> Callable[..., Optional[dict]]:
    """Return the ``pre_tool_call`` callback.

    ``bypass_active(tool_name) -> bool`` (the contract's zero-arg ``Callable[[], bool]`` is also
    accepted) and ``delegation_ok(args) -> bool`` are injectable. ``allowlist`` may be a zero-arg
    callable so a reseal can swap it. Every non-local decision is ledgered; a ledger failure blocks
    (the hook raising is a fail-closed block in Hermes anyway; we make the message explicit)."""

    takes_name = _accepts_positional(bypass_active)

    def _bypass(tool_name: str) -> bool:
        return bool(bypass_active(tool_name) if takes_name else bypass_active())  # type: ignore[call-arg]

    def _current() -> Allowlist:
        return allowlist() if callable(allowlist) else allowlist

    def pre_tool_call(tool_name: str = "", args: Optional[dict] = None, session_id: str = "",
                      tool_call_id: str = "", **_kw: Any) -> Optional[dict]:
        try:
            if not is_sealed():
                return None
        except Exception:
            pass  # cannot tell -> treat as sealed
        try:
            return _decide(tool_name, args if isinstance(args, dict) else {}, session_id, tool_call_id)
        except Exception as exc:  # never let a bug turn into "allow"
            return _block(f"confidential mode: tool gate error ({type(exc).__name__}); {tool_name} blocked")

    def _decide(tool_name: str, args: dict, session_id: str, tool_call_id: str) -> Optional[dict]:
        al = _current()
        info = al.get(tool_name)
        nbytes = args_bytes(args)
        base = {"tool": tool_name, "tool_call_id": tool_call_id}

        def refuse(reason: str, message: str) -> dict:
            ledger.append(_event("tool_refused", tool_name=tool_name, session_id=session_id, decision=reason,
                                 nbytes=nbytes, surface="gate", detail={**base, "reason": reason}))
            return _block(message)

        if info is None:
            return refuse("unclassified",
                          f"confidential mode: {tool_name} was registered after sealing and is not classified; "
                          "it is blocked. Unseal and seal again to classify it.")
        if info.route is Route.LOCAL:
            return None
        if info.route is Route.BLOCK_CRON:
            return refuse("cron", "confidential mode: scheduled jobs (cronjob_manage) are blocked while sealed; "
                                  "a job would run later outside this sealed session.")
        if info.route is Route.BLOCK_MCP_URL:
            return refuse("mcp_url",
                          f"confidential mode: {tool_name} belongs to MCP server '{info.mcp_server}', "
                          f"which is reached over the network (transport: {info.mcp_transport}); blocked while sealed.")
        if info.route is Route.DELEGATE:
            if delegation_ok(args):
                ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id,
                                     decision="delegation_default", nbytes=nbytes, surface="gate",
                                     detail={**base, "reason": "default backend, parent route"}))
                return None
            return refuse("delegation_route",
                          "confidential mode: delegate_task is allowed only on the default delegation backend "
                          "with no profile, ACP command, provider or base_url; this call is blocked.")
        # Route.ASK: off-machine
        if al.is_added(tool_name):
            ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id,
                                 decision="allowlist", nbytes=nbytes, surface="gate", detail=base))
            return None
        if _bypass(tool_name):
            return refuse("bypass_active",
                          f"confidential mode: {tool_name} sends data off the machine and needs your approval, "
                          "but approvals are bypassed here (yolo, approvals.mode off, a remembered "
                          "session/always answer, or no one to ask). Blocked. Answer 'once' when asked, "
                          "or add it with /confidential allow-tool.")
        n = args_kb(args)
        message = f"{tool_name} wants to send ~{n} KB of this conversation off the machine"
        ledger.append(_event("tool_asked", tool_name=tool_name, session_id=session_id, decision="ask",
                             nbytes=nbytes, surface="gate", detail={**base, "kb": n, "message": message}))
        return {"action": "approve", "message": message, "rule_key": rule_key_for(tool_name)}

    return pre_tool_call


def build_post_approval_response(is_sealed: Callable[[], bool], ledger: Any) -> Callable[..., None]:
    """``post_approval_response`` observer: ledgers tool_allowed / tool_refused for OUR approve
    directives only (pattern_key ``plugin_rule:confidential-mode:tool:<name>``). Never raises."""

    def post_approval_response(pattern_key: str = "", choice: str = "", session_id: str = "",
                               session_key: str = "", surface: str = "", tool_call_id: str = "",
                               **kw: Any) -> None:
        try:
            if not isinstance(pattern_key, str) or not pattern_key.startswith(PATTERN_KEY_PREFIX):
                return None
            tool_name = pattern_key[len(PATTERN_KEY_PREFIX):]
            pick = str(choice or "")
            allowed = pick in _ALLOW_CHOICES
            detail = {"tool": tool_name, "choice": pick, "tool_call_id": tool_call_id or "",
                      "session_key": session_key or "", "sealed": _safe(is_sealed)}
            if allowed and pick in ("session", "always"):
                detail["note"] = ("remembered grants count as a bypass while sealed: later calls of this tool "
                                  "are blocked, not auto-approved")
            ledger.append(_event("tool_allowed" if allowed else "tool_refused", tool_name=tool_name,
                                 session_id=session_id or "", decision=pick or "unknown",
                                 surface=surface or None, detail=detail))
        except Exception:
            pass
        return None

    return post_approval_response


def _accepts_positional(fn: Callable[..., Any]) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL) for p in params)


def _safe(fn: Callable[[], Any]) -> Any:
    try:
        return bool(fn())
    except Exception:
        return None

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
  session /yolo, ``hermes -z`` unattended turns), ``approvals.mode: off``, and cron /
  unattended-platform / single-query contexts whose mode is ``approve`` (tools/approval.py:1071-1113).
  Sealed mode BLOCKS in those instead of returning the approve directive (docs/C0-spikes.md, spike 3).
  A remembered once/session/always grant on OUR rule key is a human's answer to our own prompt and is
  honoured (INTERFACES.md Amendment 2): ledgered as tool_allowed, decision "remembered".
"""
from __future__ import annotations

import functools
import inspect
import json
import math
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

# The contract's local set (docs/INTERFACES.md, "W4 gate_tools.py, consent.py"). Exactly these.
LOCAL_TOOLS: frozenset[str] = frozenset({
    "terminal", "process_manage", "execute_code", "read_file", "write_file", "patch", "search_files",
    "skills_list", "skill_view", "skill_manage", "todo_list", "memory", "clarify", "session_search",
})
CRON_TOOL = "cronjob_manage"
DELEGATE_TOOL = "delegate_task"

# Our approve directive's rule_key. Hermes prefixes it with ``plugin_rule:`` (tools/approval.py:1226);
# the remembered-grant check MUST use the prefixed key (see hermes_remembered_grant).
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
    BLOCK_MCP_URL = "block-mcp-url"  # MCP server whose URL host is off-tier (or unreadable config): blocked


# Tools that will get a per-tool "mode" (pending product decision, INTERFACES.md Amendment 1:
# ask on network-looking commands / allow all / block). Today they are plain LOCAL with mode None;
# the decision hook is _local_decision() in build_pre_tool_call, so adding modes touches only
# ToolInfo.mode, build_allowlist's mode argument and that function.
MODE_TOOLS: frozenset[str] = frozenset({"terminal", "execute_code"})


@dataclass(frozen=True)
class ToolInfo:
    name: str
    toolset: str
    origin: Origin
    route: Route
    mcp_server: Optional[str] = None   # raw server name for MCP tools
    mcp_transport: Optional[str] = None  # "url" | "stdio" | "unknown" for MCP tools
    mcp_host: Optional[str] = None       # host_of(url) for URL servers
    reason: str = ""                     # why this route (verdict reason for MCP URL servers)
    mode: Optional[str] = None           # reserved for MODE_TOOLS (see above); None = plain route


@dataclass
class Allowlist:
    """Classification computed at seal. ``added`` holds names a human allowed via consent.allow_tool."""
    tools: dict[str, ToolInfo]
    built_at: float = field(default_factory=time.time)
    added: set[str] = field(default_factory=set)
    added_path: Optional[Path] = None   # allowlist.yaml; additions persist there (Amendment 3)
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
            if self.added_path is not None:
                _write_added(self.added_path, self.added)


def _read_added(path: Path) -> set[str]:
    """Names in allowlist.yaml; missing file -> empty; unreadable/corrupt -> empty (adds nothing)."""
    try:
        text = Path(path).read_text() if Path(path).exists() else ""
    except Exception:
        return set()
    try:
        data = json.loads(text) if text.strip() else None   # what we write: JSON, a YAML subset
    except ValueError:
        try:
            import hermes_yaml   # a hand-edited YAML file
            data = hermes_yaml.safe_load(text)
        except Exception:
            return set()
    names = data.get("allowed") if isinstance(data, dict) else None
    return {n for n in names if isinstance(n, str)} if isinstance(names, list) else set()


def _write_added(path: Path, names: Iterable[str]) -> None:
    # JSON is valid YAML; it needs no YAML library (Hermes ships ruamel via hermes_yaml, not PyYAML).
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"version": 1, "allowed": sorted(names)}, indent=2) + "\n")
    os.replace(tmp, path)


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


def _mcp_url_route(server: str, url: Any, predicate: Any) -> tuple[Route, str, str]:
    """(route, host, reason) for a URL MCP server. Local host (LocalPredicate, plus the active
    predicate's extra_hosts when it is a LocalPredicate) -> LOCAL; in-tier under the active
    predicate -> ASK; anything else, or any error -> BLOCK_MCP_URL."""
    from .tiers import Destination, LocalPredicate, host_of
    try:
        if not isinstance(url, str) or not url.strip():
            return Route.BLOCK_MCP_URL, "", "url is empty or not a string"
        dest = Destination(provider="", base_url=url, model="", api_mode="", purpose=f"mcp:{server}")
        local = predicate if isinstance(predicate, LocalPredicate) else LocalPredicate()
        v = local.classify(dest)
        if v.in_tier:
            return Route.LOCAL, v.host or host_of(url), v.reason
        if predicate is not None and not isinstance(predicate, LocalPredicate):
            pv = predicate.classify(dest)
            if pv.in_tier:
                return Route.ASK, pv.host or host_of(url), pv.reason
            return Route.BLOCK_MCP_URL, pv.host or v.host or host_of(url), pv.reason
        return Route.BLOCK_MCP_URL, v.host or host_of(url), v.reason
    except Exception as exc:
        return Route.BLOCK_MCP_URL, "", f"could not classify url ({type(exc).__name__})"


def classify_tool(name: str, toolset: str, *, origin: Origin, mcp_server: Optional[str] = None,
                  mcp_config: Optional[Mapping[str, Any]] = None, predicate: Any = None) -> ToolInfo:
    if origin is Origin.MCP:
        transport = _mcp_transport(mcp_config)
        if transport == "url":
            route, host, reason = _mcp_url_route(mcp_server or "", mcp_config.get("url"), predicate)
            return ToolInfo(name, toolset, origin, route, mcp_server, transport, host, reason)
        if transport == "stdio":
            # A local child process: allowed per contract (Amendment 3), disclosed as the same class of
            # gap as terminal (the command can itself be a network proxy).
            return ToolInfo(name, toolset, origin, Route.LOCAL, mcp_server, transport, None, "stdio server")
        # config unreadable / neither url nor command: fail closed
        return ToolInfo(name, toolset, origin, Route.BLOCK_MCP_URL, mcp_server, transport, None,
                        "server config not found")
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
                    plugin_tool_names: Optional[Iterable[str]] = None, predicate: Any = None,
                    added_path: Optional[Path] = None) -> Allowlist:
    """Classify every tool in ``registry.get_all_entries()``. The keyword arguments default to Hermes'
    live state (see the module docstring); tests pass fakes. ``predicate`` is the active
    TierPredicate (confidential_mode.tiers); it classifies MCP server URLs. None = LocalPredicate().

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
                                        mcp_config=mcp_configs.get(server), predicate=predicate)
            continue
        is_plugin = name in plugin_names or _handler_module(getattr(entry, "handler", None)).startswith(
            "hermes_plugins.")
        tools[name] = classify_tool(name, toolset, origin=Origin.PLUGIN if is_plugin else Origin.BUILTIN)
    added: set[str] = set()
    if added_path is not None:
        # Only names that are still on the ask route at this seal are honoured.
        added = {n for n in _read_added(added_path) if n in tools and tools[n].route is Route.ASK}
    return Allowlist(tools=tools, added=added, added_path=Path(added_path) if added_path is not None else None)


_ROUTE_TITLES = (
    (Route.LOCAL, "local (runs without asking)"),
    (Route.ASK, "off-machine (asks each call; blocked under yolo/approvals off/unattended)"),
    (Route.DELEGATE, "delegation (default backend only, no profile/ACP)"),
    (Route.BLOCK_CRON, "blocked (scheduled jobs)"),
    (Route.BLOCK_MCP_URL, "blocked (MCP server URL off-tier or unreadable)"),
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
                extra.append(f"server={info.mcp_server}, transport={info.mcp_transport}"
                             + (f", host={info.mcp_host}" if info.mcp_host else ""))
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
        from tools.approval import _presence, _yolo_active
        from tools.approval_context import _get_approval_mode
        if _yolo_active() or _get_approval_mode() == "off":
            return True
        _cb, is_cli, is_gateway, is_ask = _presence(None)
        # Nobody to ask: Hermes either blocks or (cron/unattended/single_query mode approve) auto-approves.
        # Either way no human decides, so we block ourselves.
        return not (is_cli or is_gateway or is_ask)
    except Exception:
        return True


def hermes_remembered_grant(tool_name: str) -> bool:
    """True when Hermes holds a session/always grant for our rule key in this session.
    The plugin_rule: prefix trap: the grant is stored under the PREFIXED key; is_approved(sk, rule_key)
    without it is always False (tests/spikes/test_approval_gate.py:384). Any error -> False (ask)."""
    try:
        from tools.approval import is_approved
        from tools.approval_context import get_current_session_key
        return bool(is_approved(get_current_session_key(), f"plugin_rule:{rule_key_for(tool_name)}"))
    except Exception:
        return False


def _sealed_flag(value: Any) -> bool:
    """is_sealed() is canonically (bool, Tier | None) (Amendment 2); a bare bool is also accepted."""
    if isinstance(value, bool):
        return value
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bool):
        return value[0]
    raise TypeError(f"is_sealed() returned {type(value).__name__}; expected bool or (bool, tier)")


def bypass_active_for(tool_name: str) -> Callable[[], bool]:
    return lambda: hermes_bypass_active(tool_name)


# Task/top-level keys that would move a child off the parent's route (delegate_tool.py:911,
# agent/delegation_provider.py:45-48, delegate_tool_routes.py:227-235).
DELEGATION_ROUTE_KEYS = frozenset({
    "profile", "acp_command", "acp_args", "provider", "model", "base_url", "api_key", "api_mode",
    "fallback_providers", "request_overrides", "backend", "command", "args", "reasoning_effort",
    "service_tier", "credentials_cfg",
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
            if not isinstance(tasks, list):   # incl. tasks passed as a JSON string (Amendment 3)
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


@dataclass(frozen=True)
class CallDecision:
    """What the gate does with one call. ``action``: run | refuse | ask."""
    action: str
    decision: str = ""          # ledger decision code
    message: str = ""           # refusal text, or the ask prompt text
    kb: int = 0


class SealStateError(RuntimeError):
    pass


def _seal_state(is_sealed: Callable[[], Any]) -> bool:
    """True/False, or raise SealStateError (unreadable seal state blocks every tool, Amendment 3)."""
    try:
        return _sealed_flag(is_sealed())
    except Exception as exc:
        raise SealStateError(f"{type(exc).__name__}: {exc}") from exc


_SEAL_UNREADABLE = ("confidential mode: the seal state cannot be read, so every tool is blocked. "
                    "Run /confidential status (or /confidential off) to repair it.")


class _Policy:
    """The classification both enforcement points share."""

    def __init__(self, allowlist, bypass_active, delegation_ok, remembered):
        self._allowlist = allowlist
        self._bypass_fn = bypass_active
        self._takes_name = _accepts_positional(bypass_active)
        self.delegation_ok = delegation_ok
        self.remembered = remembered

    def allowlist(self) -> Allowlist:
        return self._allowlist() if callable(self._allowlist) else self._allowlist

    def bypass(self, tool_name: str) -> bool:
        return bool(self._bypass_fn(tool_name) if self._takes_name else self._bypass_fn())  # type: ignore[call-arg]

    def local_decision(self, info: ToolInfo, args: dict) -> CallDecision:
        # Extension point for MODE_TOOLS (terminal / execute_code three-mode rule, pending).
        # mode None -> run. A future mode returns run, refuse, or ask here.
        return CallDecision("run", "local")

    def decide(self, tool_name: str, args: dict) -> CallDecision:
        al = self.allowlist()
        info = al.get(tool_name)
        if info is None:
            return CallDecision("refuse", "unclassified",
                                f"confidential mode: {tool_name} was not registered when this profile was sealed, "
                                "so it is not classified and is blocked. Run /confidential off and seal again "
                                "to classify it.")
        if info.route is Route.LOCAL:
            return self.local_decision(info, args)
        if info.route is Route.BLOCK_CRON:
            return CallDecision("refuse", "cron", "confidential mode: scheduled jobs (cronjob_manage) are blocked "
                                                  "while sealed; a job would run later outside this sealed session.")
        if info.route is Route.BLOCK_MCP_URL:
            return CallDecision("refuse", "mcp_url",
                                f"confidential mode: {tool_name} belongs to MCP server '{info.mcp_server}' "
                                f"({info.mcp_host or 'host unknown'}: {info.reason}); blocked while sealed.")
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
            return CallDecision("refuse", "bypass_active",
                                f"confidential mode: {tool_name} sends data off the machine and needs your "
                                "approval, but approvals are bypassed here (yolo, approvals.mode off, or an "
                                "unattended context with no one to ask). Blocked. Turn the bypass off, or add "
                                "the tool with /confidential allow-tool.")
        n = args_kb(args)
        if self.remembered(tool_name):
            return CallDecision("run", "remembered", kb=n)
        return CallDecision("ask", "ask", f"{tool_name} wants to send ~{n} KB of this conversation off the machine",
                            kb=n)


def _policy(allowlist, bypass_active, delegation_ok, remembered) -> _Policy:
    return _Policy(allowlist, bypass_active, delegation_ok, remembered)


def build_pre_tool_call(is_sealed: Callable[[], Any], allowlist: Allowlist | Callable[[], Allowlist],
                        ledger: Any, bypass_active: Callable[[str], bool] = hermes_bypass_active,
                        delegation_ok: Callable[[dict], bool] = default_delegation_ok,
                        remembered: Callable[[str], bool] = hermes_remembered_grant) -> Callable[..., Optional[dict]]:
    """``pre_tool_call`` callback: the FIRST line. It blocks every refuse decision (and ledgers
    tool_refused) and otherwise returns None. It never returns the approve directive: Hermes' CLI
    approve path grants on any answer except the exact string "deny" (tools/approval.py:1006-1009)
    and the hook cannot veto after the prompt, so asking and enforcement live in the
    ``tool_execution`` middleware (build_tool_execution). REGISTER BOTH: without the middleware,
    ask-route tools run unasked.

    ``bypass_active(tool_name)`` (zero-arg also accepted), ``delegation_ok(args)`` and
    ``remembered(tool_name)`` are injectable. ``is_sealed()`` may return ``(bool, Tier | None)`` or a bool."""
    pol = _policy(allowlist, bypass_active, delegation_ok, remembered)

    def pre_tool_call(tool_name: str = "", args: Optional[dict] = None, session_id: str = "",
                      tool_call_id: str = "", **_kw: Any) -> Optional[dict]:
        try:
            sealed = _seal_state(is_sealed)
        except SealStateError as exc:
            _try_ledger(ledger, "tool_refused", tool_name, session_id, "seal_state_unreadable", args,
                        {"tool": tool_name, "tool_call_id": tool_call_id, "error": str(exc)}, "gate")
            return _block(_SEAL_UNREADABLE)
        if not sealed:
            return None
        try:
            d = pol.decide(tool_name, args if isinstance(args, dict) else {})
            if d.action != "refuse":
                return None
            ledger.append(_event("tool_refused", tool_name=tool_name, session_id=session_id, decision=d.decision,
                                 nbytes=args_bytes(args), surface="gate",
                                 detail={"tool": tool_name, "tool_call_id": tool_call_id, "reason": d.decision}))
            return _block(d.message)
        except Exception as exc:  # never let a bug turn into "allow"
            return _block(f"confidential mode: tool gate error ({type(exc).__name__}); {tool_name} blocked")

    return pre_tool_call


class ApprovalDecisions:
    """Explicit answers recorded by post_approval_response, keyed by the call's approval id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, str] = {}

    def record(self, call_id: str, choice: str) -> None:
        if call_id:
            with self._lock:
                self._by_id[call_id] = choice

    def pop(self, call_id: str) -> Optional[str]:
        with self._lock:
            return self._by_id.pop(call_id, None)


def hermes_request_approval(tool_name: str, message: str, *, rule_key: str, approval_id: str,
                            session_id: str = "", turn_id: str = "") -> dict:
    """Ask through Hermes' own gate (CLI panel / gateway card), from the agent thread, with the
    observability context set so post_approval_response carries ``approval_id`` as tool_call_id
    (same mechanism as hermes_cli/plugins.py:1996-2009)."""
    from tools.approval import request_tool_approval
    from tools.approval_context import reset_current_observability_context, set_current_observability_context
    tokens = set_current_observability_context(turn_id=turn_id, tool_call_id=approval_id, session_id=session_id)
    try:
        return request_tool_approval(tool_name, message, rule_key=rule_key)
    finally:
        reset_current_observability_context(tokens)


def _refusal_result(message: str) -> str:
    return json.dumps({"error": message})


def _try_ledger(ledger, kind, tool_name, session_id, decision, args, detail, surface) -> None:
    try:
        ledger.append(_event(kind, tool_name=tool_name, session_id=session_id or "", decision=decision,
                             nbytes=args_bytes(args), surface=surface, detail=detail))
    except Exception:
        pass


def build_tool_execution(is_sealed: Callable[[], Any], allowlist: Allowlist | Callable[[], Allowlist],
                         ledger: Any, decisions: ApprovalDecisions, *,
                         bypass_active: Callable[[str], bool] = hermes_bypass_active,
                         delegation_ok: Callable[[dict], bool] = default_delegation_ok,
                         remembered: Callable[[str], bool] = hermes_remembered_grant,
                         ask: Callable[..., dict] = hermes_request_approval) -> Callable[..., Any]:
    """``tool_execution`` middleware: the ENFORCEMENT line, for ctx.register_middleware("tool_execution", fn).

    Where it sits (84a0301): on the agent loop it is OUTERMOST, wrapping pre_tool_call, the approval
    gate and the handler (agent/tool_executor.py:775-812, _dispatch_authorized_once at :677-736); on
    model_tools.handle_function_call it runs after pre_tool_call (model_tools.py:954 then :855-859).
    So it cannot wait for a prompt the hook raised: on the agent path that prompt has not happened yet.
    It therefore asks itself, on the agent thread, and calls ``next_call`` for an ask-route tool only
    when post_approval_response recorded an explicit once/session/always for THIS call (or a
    remembered grant under our rule key exists). Any other answer, including one Hermes would
    treat as a grant (None, "", "d", "yes"), is refused and ledgered tool_refused "unexpected_choice".

    Never raises: our own errors become a refusal result; an exception from ``next_call`` (the tool
    itself) propagates unchanged, as Hermes expects."""
    pol = _policy(allowlist, bypass_active, delegation_ok, remembered)

    def confidential_mode_tool_execution(tool_name: str = "", args: Any = None, next_call: Any = None,
                                         session_id: str = "", tool_call_id: str = "", turn_id: str = "",
                                         **_kw: Any) -> Any:
        downstream: dict[str, BaseException] = {}

        def run(payload: Any = None) -> Any:
            try:
                return next_call(args if payload is None else payload)
            except BaseException as exc:
                downstream["exc"] = exc
                raise

        try:
            return _handle(tool_name, args if isinstance(args, dict) else {}, run, session_id or "",
                           tool_call_id or "", turn_id or "")
        except BaseException as exc:
            if exc is downstream.get("exc") or not isinstance(exc, Exception):
                raise
            _try_ledger(ledger, "tool_refused", tool_name, session_id, "gate_error", args,
                        {"tool": tool_name, "tool_call_id": tool_call_id, "error": type(exc).__name__}, "middleware")
            return _refusal_result(f"confidential mode: tool gate error ({type(exc).__name__}); {tool_name} blocked")

    def _handle(tool_name, args, run, session_id, tool_call_id, turn_id):
        base = {"tool": tool_name, "tool_call_id": tool_call_id}
        try:
            sealed = _seal_state(is_sealed)
        except SealStateError as exc:
            _try_ledger(ledger, "tool_refused", tool_name, session_id, "seal_state_unreadable", args,
                        {**base, "error": str(exc)}, "middleware")
            return _refusal_result(_SEAL_UNREADABLE)
        if not sealed:
            return run()
        d = pol.decide(tool_name, args)
        if d.action == "refuse":
            ledger.append(_event("tool_refused", tool_name=tool_name, session_id=session_id, decision=d.decision,
                                 nbytes=args_bytes(args), surface="middleware", detail={**base, "reason": d.decision}))
            return _refusal_result(d.message)
        if d.action == "run":
            if d.decision != "local":
                ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id,
                                     decision=d.decision, nbytes=args_bytes(args), surface="middleware",
                                     detail={**base, **({"kb": d.kb} if d.kb else {})}))
            return run()
        # ask
        approval_id = f"cm-{tool_call_id or 'call'}-{uuid.uuid4().hex[:12]}"
        ledger.append(_event("tool_asked", tool_name=tool_name, session_id=session_id, decision="ask",
                             nbytes=args_bytes(args), surface="middleware",
                             detail={**base, "kb": d.kb, "message": d.message, "approval_id": approval_id}))
        result = ask(tool_name, d.message, rule_key=rule_key_for(tool_name), approval_id=approval_id,
                     session_id=session_id, turn_id=turn_id)
        choice = decisions.pop(approval_id)
        approved = isinstance(result, dict) and result.get("approved") is True
        if approved and choice in _ALLOW_CHOICES:
            return run()   # tool_allowed was ledgered by post_approval_response
        if approved:
            decision = "unexpected_choice"
        elif choice is None and isinstance(result, dict) and result.get("status") == "approval_required":
            decision = "no_surface"
        else:
            decision = "denied"
        ledger.append(_event("tool_refused", tool_name=tool_name, session_id=session_id, decision=decision,
                             nbytes=args_bytes(args), surface="middleware",
                             detail={**base, "choice": choice, "approval_id": approval_id,
                                     "hermes_approved": approved}))
        if decision == "unexpected_choice":
            return _refusal_result(f"confidential mode: {tool_name} was not run: the answer to the approval "
                                   f"prompt was not once/session/always ({choice!r}).")
        return _refusal_result(str((result or {}).get("message") or f"confidential mode: {tool_name} was not approved"))

    return confidential_mode_tool_execution


def build_post_approval_response(is_sealed: Callable[[], Any], ledger: Any,
                                 decisions: Optional[ApprovalDecisions] = None) -> Callable[..., None]:
    """``post_approval_response`` observer: ledgers tool_allowed / tool_refused for OUR approve
    directives only (pattern_key ``plugin_rule:confidential-mode:tool:<name>``). Never raises."""

    def post_approval_response(pattern_key: str = "", choice: str = "", session_id: str = "",
                               session_key: str = "", surface: str = "", tool_call_id: str = "",
                               **kw: Any) -> None:
        try:
            if not isinstance(pattern_key, str) or not pattern_key.startswith(PATTERN_KEY_PREFIX):
                return None
            tool_name = pattern_key[len(PATTERN_KEY_PREFIX):]
            if decisions is not None:
                decisions.record(str(tool_call_id or ""), choice if isinstance(choice, str) else repr(choice))
            pick = str(choice or "")
            allowed = pick in _ALLOW_CHOICES
            detail = {"tool": tool_name, "choice": pick, "tool_call_id": tool_call_id or "",
                      "session_key": session_key or "", "sealed": _safe(is_sealed)}
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
        return _sealed_flag(fn())
    except Exception:
        return None

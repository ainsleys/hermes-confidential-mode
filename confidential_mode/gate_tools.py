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
  Locked mode BLOCKS in those instead of returning the approve directive (docs/C0-spikes.md, spike 3).
  A remembered once/session/always grant on OUR rule key is a human's answer to our own prompt and is
  honoured (INTERFACES.md Amendment 2): ledgered as tool_allowed, decision "remembered".
"""
from __future__ import annotations

import contextlib
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

# The contract's on-host set (docs/INTERFACES.md, "W4 gate_tools.py, consent.py"). Exactly these.
ON_HOST_TOOLS: frozenset[str] = frozenset({
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
    """What the locked gate does with a tool."""
    ON_HOST = "on-host"                 # runs, nothing asked, nothing ledgered
    ASK = "ask"                     # off-host: per-call human approval (block under bypass)
    DELEGATE = "delegate"           # allowed only via delegation_ok
    BLOCK_CRON = "block-cron"       # cronjob_manage: always blocked
    BLOCK_MCP_URL = "block-mcp-url"  # MCP server whose URL host is off-tier (or unreadable config): blocked


# Tools that will get a per-tool "mode" (pending product decision, INTERFACES.md Amendment 1:
# ask on network-looking commands / allow all / block). Today they are plain ON_HOST with mode None;
# the decision hook is _on_host_decision() in build_pre_tool_call, so adding modes touches only
# ToolInfo.mode, build_allowlist's mode argument and that function.
MODE_TOOLS: frozenset[str] = frozenset({"terminal", "execute_code"})

_ROUTE_STRICTNESS = {"on-host": 0, "delegate": 1, "ask": 2, "block-cron": 3, "block-mcp-url": 3}


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
    """Classification computed at lock. ``added`` holds names a human allowed via consent.allow_tool."""
    tools: dict[str, ToolInfo]
    built_at: float = field(default_factory=time.time)
    added: set[str] = field(default_factory=set)
    added_path: Optional[Path] = None   # allowlist.yaml; additions persist there (Amendment 3)
    # Pinned at lock (Amendment 3 addendum): name -> (toolset, handler object). Holding the handler keeps
    # its id from being reused. A live entry whose toolset or handler differs => unclassified.
    pins: dict[str, tuple[str, Any]] = field(default_factory=dict, repr=False)
    registry: Any = field(default=None, repr=False)
    # Re-read at call time for MCP tools so a server re-pointed after lock is re-judged (fail closed).
    mcp_config_loader: Optional[Callable[[], Mapping[str, Any]]] = field(default=None, repr=False)
    predicate: Any = field(default=None, repr=False)
    lock_id: str = ""                    # identity of the lock this allowlist belongs to (F5/F6)
    # name -> (toolset, handler module, handler qualname) as persisted at lock; set on a restart rebuild
    persisted_identity: Optional[dict[str, tuple[str, str, str]]] = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def get(self, name: str) -> Optional[ToolInfo]:
        return self.tools.get(name)

    def current(self, name: str) -> Optional[ToolInfo]:
        """The lock-time classification, only if the live registry entry is still the one pinned
        (same toolset, same handler object) and, for MCP tools, re-judged on the live config with the
        stricter of the two routes. None => unclassified => block."""
        info = self.tools.get(name)
        if info is None:
            return None
        if self.registry is not None:
            pin = self.pins.get(name)
            live = _live_entry(self.registry, name)
            if pin is None or live is None:
                return None
            if str(getattr(live, "toolset", "") or "") != pin[0] or getattr(live, "handler", None) is not pin[1]:
                return None
        if info.origin is Origin.MCP and self.mcp_config_loader is not None:
            try:
                cfgs = self.mcp_config_loader() or {}
                fresh = classify_tool(name, info.toolset, origin=Origin.MCP, mcp_server=info.mcp_server,
                                      mcp_config=cfgs.get(info.mcp_server), predicate=self.predicate)
            except Exception:
                return None
            if _ROUTE_STRICTNESS[fresh.route] > _ROUTE_STRICTNESS[info.route]:
                return fresh
        return info

    def names(self, route: Route) -> list[str]:
        return sorted(n for n, t in self.tools.items() if t.route is route)

    @property
    def on_host(self) -> list[str]:
        return self.names(Route.ON_HOST)

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
            self.persist()

    # -- persistence (Amendment 4 F5/F6) ------------------------------------------------------------
    def persist(self, path: Optional[Path] = None) -> None:
        """Write the lock's tool identities (name, toolset, handler module, qualname) and the
        human-approved additions, tagged with ``lock_id``. Called at lock and after each add.
        JSON (a YAML subset): Hermes ships ruamel via hermes_yaml, not PyYAML."""
        target = Path(path) if path is not None else self.added_path
        if target is None:
            return
        with self._lock:
            added = sorted(self.added)
        tools = []
        for name, (toolset, handler) in sorted(self.pins.items()):
            if name not in self.tools:
                continue
            module, qualname = _handler_identity(handler)
            tools.append({"name": name, "toolset": toolset, "module": module, "qualname": qualname})
        data = {"version": 2, "lock_id": self.lock_id, "tools": tools, "allowed": added}
        target.parent.mkdir(parents=True, exist_ok=True)
        # Mode 0600 like pins.yaml (review finding 18): an "allowed" entry lifts the ask prompt for a tool.
        import tempfile
        fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(data, indent=2) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    @classmethod
    def load_persisted(cls, path: Optional[Path], registry: Any, *, lock_id: str, predicate: Any = None,
                       mcp_configs: Optional[Mapping[str, Mapping[str, Any]]] = None,
                       mcp_tool_servers: Optional[Mapping[str, str]] = None,
                       plugin_tool_names: Optional[Iterable[str]] = None) -> "Allowlist":
        """Rebuild the allowlist after a restart. Only tools persisted at THIS lock (matching
        ``lock_id``) whose live toolset, handler module and qualname still match are classified;
        everything else is unclassified (block/refuse) until a relock. A missing, corrupt or
        other-lock file yields an empty allowlist: every tool blocked. Additions are honoured only
        from the same lock."""
        empty = cls(tools={}, added_path=Path(path) if path is not None else None, lock_id=lock_id,
                    registry=registry, persisted_identity={})
        data = _read_json_or_yaml(path) if path is not None else None
        if not isinstance(data, dict) or data.get("version") != 2 or not lock_id or data.get("lock_id") != lock_id:
            return empty
        identity: dict[str, tuple[str, str, str]] = {}
        for t in data.get("tools") or []:
            if isinstance(t, dict) and all(isinstance(t.get(k), str) for k in ("name", "toolset", "module", "qualname")):
                identity[t["name"]] = (t["toolset"], t["module"], t["qualname"])
        fresh = build_allowlist(registry, predicate=predicate, mcp_configs=mcp_configs,
                                mcp_tool_servers=mcp_tool_servers, plugin_tool_names=plugin_tool_names,
                                added_path=path)
        keep = {}
        for name, info in fresh.tools.items():
            toolset, handler = fresh.pins.get(name, ("", None))
            if identity.get(name) == (toolset, *_handler_identity(handler)):
                keep[name] = info
        fresh.tools = keep
        fresh.lock_id = lock_id
        fresh.persisted_identity = identity
        allowed = data.get("allowed") if isinstance(data.get("allowed"), list) else []
        fresh.added = {n for n in allowed if isinstance(n, str) and n in keep and keep[n].route is Route.ASK}
        return fresh


def clear_persisted(path: Optional[Path]) -> None:
    """Unlock: drop the lock's persisted allowlist and its additions (Amendment 4 F6)."""
    if path is None:
        return
    with contextlib.suppress(FileNotFoundError):
        Path(path).unlink()


def lock_id_for(state: Any) -> str:
    """A lock's identity: when it was locked plus the config fingerprint recorded at lock."""
    try:
        since, fp = state.locked_since(), state.config_fingerprint()
    except Exception:
        return ""
    return lock_id_from(since, fp)


def lock_id_from(since: Any, fingerprint: Any) -> str:
    """``lock_id_for`` from the two values, before they are written (the lock persists the allowlist first)."""
    if since is None:
        return ""
    return f"{float(since)!r}|{None if fingerprint is None else str(fingerprint)}"


def _handler_identity(handler: Any) -> tuple[str, str]:
    current, seen = handler, set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, functools.partial):
            current = current.func
        elif getattr(current, "__func__", None) is not None:
            current = current.__func__
        elif getattr(current, "__wrapped__", None) is not None and not hasattr(current, "__qualname__"):
            current = current.__wrapped__
        else:
            break
    qual = getattr(current, "__qualname__", None) or type(current).__qualname__
    return _handler_module(handler), str(qual)


def _read_json_or_yaml(path: Path) -> Any:
    try:
        text = Path(path).read_text() if Path(path).exists() else ""
    except Exception:
        return None
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        try:
            import hermes_yaml   # a hand-edited YAML file
            return hermes_yaml.safe_load(text)
        except Exception:
            return None


def _live_entry(registry: Any, name: str) -> Any:
    get = getattr(registry, "get_entry", None)
    if callable(get):
        return get(name)
    for entry in registry.get_all_entries():
        if entry.name == name:
            return entry
    return None


def _read_added(path: Path) -> set[str]:
    """Names in allowlist.yaml; missing file -> empty; unreadable/corrupt -> empty (adds nothing)."""
    data = _read_json_or_yaml(path)
    names = data.get("allowed") if isinstance(data, dict) else None
    return {n for n in names if isinstance(n, str)} if isinstance(names, list) else set()


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
    """(route, host, reason) for a URL MCP server. On-host endpoint (OnHostPredicate, plus the active
    predicate's extra_hosts when it is an OnHostPredicate) -> ON_HOST; in-tier under the active
    predicate -> ASK; anything else, or any error -> BLOCK_MCP_URL."""
    from .tiers import Destination, OnHostPredicate, host_of
    try:
        if not isinstance(url, str) or not url.strip():
            return Route.BLOCK_MCP_URL, "", "url is empty or not a string"
        dest = Destination(provider="", base_url=url, model="", api_mode="", purpose=f"mcp:{server}")
        on_host_pred = predicate if isinstance(predicate, OnHostPredicate) else OnHostPredicate()
        v = on_host_pred.classify(dest)
        if v.in_tier:
            return Route.ON_HOST, v.host or host_of(url), v.reason
        if predicate is not None and not isinstance(predicate, OnHostPredicate):
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
            # A child process on this host: allowed per contract (Amendment 3), disclosed as the same class of
            # gap as terminal (the command can itself be a network proxy).
            return ToolInfo(name, toolset, origin, Route.ON_HOST, mcp_server, transport, None, "stdio server")
        # config unreadable / neither url nor command: fail closed
        return ToolInfo(name, toolset, origin, Route.BLOCK_MCP_URL, mcp_server, transport, None,
                        "server config not found")
    if name in ON_HOST_TOOLS and origin is Origin.BUILTIN:
        route = Route.ON_HOST
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
    TierPredicate (confidential_mode.tiers); it classifies MCP server URLs. None = OnHostPredicate().

    An on-host-set name re-registered by a plugin (``override=True``) or by an MCP server is NOT on-host:
    locality is a property of the built-in implementation, not of the name."""
    if mcp_configs is None:
        mcp_loader: Callable[[], Mapping[str, Any]] = _default_mcp_configs
    else:
        _fixed = mcp_configs
        mcp_loader = lambda: _fixed  # noqa: E731
    mcp_configs = mcp_loader()
    if mcp_tool_servers is None:
        mcp_tool_servers = _default_mcp_tool_servers()
    plugin_names = set(_default_plugin_tool_names() if plugin_tool_names is None else plugin_tool_names)
    tools: dict[str, ToolInfo] = {}
    pins: dict[str, tuple[str, Any]] = {}
    for entry in registry.get_all_entries():
        name, toolset = str(entry.name), str(entry.toolset or "")
        pins[name] = (toolset, getattr(entry, "handler", None))
        if toolset.startswith("mcp-"):
            server = mcp_tool_servers.get(name) or toolset[len("mcp-"):]
            tools[name] = classify_tool(name, toolset, origin=Origin.MCP, mcp_server=server,
                                        mcp_config=mcp_configs.get(server), predicate=predicate)
            continue
        is_plugin = name in plugin_names or _handler_module(getattr(entry, "handler", None)).startswith(
            "hermes_plugins.")
        tools[name] = classify_tool(name, toolset, origin=Origin.PLUGIN if is_plugin else Origin.BUILTIN)
    # A NEW lock starts with no additions (Amendment 4 F6): ``added_path`` is where this lock persists
    # them; only Allowlist.load_persisted (same lock, after a restart) reads them back.
    return Allowlist(tools=tools, added=set(), added_path=Path(added_path) if added_path is not None else None,
                     pins=pins, registry=registry, mcp_config_loader=mcp_loader, predicate=predicate)


_ROUTE_TITLES = (
    (Route.ON_HOST, "on-host (runs without asking)"),
    (Route.ASK, "off-host (asks each call; blocked under yolo/approvals off/unattended)"),
    (Route.DELEGATE, "delegation (default backend only, no profile/ACP)"),
    (Route.BLOCK_CRON, "blocked (scheduled jobs)"),
    (Route.BLOCK_MCP_URL, "blocked (MCP server URL off-tier or unreadable)"),
)


def _printable(value: Any) -> str:
    """Escape control/format characters (newline, ESC, NUL, zero-width, bidi) so a registered name
    cannot forge lines or terminal sequences in the printed allowlist."""
    import unicodedata
    out = []
    for ch in str(value):
        cat = unicodedata.category(ch)
        if ch == "\\" or cat[0] == "C" or cat in ("Zl", "Zp"):
            out.append(ch.encode("unicode_escape").decode("ascii") if ch != "\\" else "\\\\")
        else:
            out.append(ch)
    return "".join(out)


def format_allowlist(allowlist: Allowlist) -> str:
    """Printed on lock. Every field is escaped with _printable."""
    lines: list[str] = []
    for route, title in _ROUTE_TITLES:
        infos = [allowlist.tools[n] for n in allowlist.names(route)]
        lines.append(f"{title}: {len(infos)}")
        for info in infos:
            extra = [info.origin.value]
            if info.mcp_server is not None:
                extra.append(f"server={_printable(info.mcp_server)}, transport={info.mcp_transport}"
                             + (f", host={_printable(info.mcp_host)}" if info.mcp_host else ""))
            if info.name in allowlist.added:
                extra.append("allowed by you")
            lines.append(f"  {_printable(info.name)}  [{_printable(info.toolset)}; {'; '.join(extra)}]")
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


def hermes_terminal_backend(task_id: str = "") -> str:
    """The terminal backend a call for ``task_id`` would run on (review finding 2): a per-task ``env_type``
    override (tools/terminal_tool.py resolve_task_overrides, registered by RL/benchmark rollouts), else the
    scope-aware ``TERMINAL_ENV`` (tools/terminal_scope.py terminal_env). Raises when Hermes cannot be read;
    the caller then blocks."""
    from tools.terminal_scope import terminal_env
    from tools.terminal_tool import resolve_task_overrides
    from .preflight import normalize_backend
    override = (resolve_task_overrides(task_id or "default") or {}).get("env_type")
    return normalize_backend(override if override else terminal_env("TERMINAL_ENV", "local"))


def _locked_flag(value: Any) -> bool:
    """is_locked() is canonically (bool, Tier | None) (Amendment 2); a bare bool is also accepted."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (tuple, list)) and len(value) == 2 and isinstance(value[0], bool):
        return value[0]
    raise TypeError(f"is_locked() returned {type(value).__name__}; expected bool or (bool, tier)")


def bypass_active_for(tool_name: str) -> Callable[[], bool]:
    return lambda: hermes_bypass_active(tool_name)


# Route keys named in Hermes (tools/delegate_tool.py:911 _MODEL_HIDDEN_TASK_FIELDS acp_command/acp_args;
# agent/delegation_provider.py:45-48 RESERVED_TASK_PARAMETERS; delegate_tool_routes.py:227-235 profile /
# fallback_providers; delegate_tool.py:432-438 request_overrides / command / args / service_tier). Kept for
# documentation and the report; the ARGUMENT check below is stricter: anything outside the documented
# schema blocks, so these are all blocked a fortiori.
DELEGATION_ROUTE_KEYS = frozenset({
    "profile", "acp_command", "acp_args", "provider", "model", "base_url", "api_key", "api_mode",
    "fallback_providers", "request_overrides", "backend", "command", "args", "reasoning_effort",
    "service_tier", "credentials_cfg",
})
# The documented delegate_task argument schema at 84a0301: DELEGATE_TASK_SCHEMA (delegate_tool.py:778-857)
# plus the legacy fields the registry handler reads (delegate_tool.py:921-929). Exact-match: a key that is
# not one of these (incl. case/space variants such as "Profile" or "profile ", and backend-declared
# per-task parameters such as "persona") blocks.
DELEGATE_TOP_LEVEL_KEYS = frozenset({
    "goal", "context", "tasks", "max_iterations", "role", "background", "output_schema", "images",
    "action", "subagent_id", "message",
})
DELEGATE_TASK_KEYS = frozenset({"goal", "context", "output_schema", "images", "group", "role"})
# delegation config keys that move a child off the parent's route under the default backend
# (plugins/delegation/default/__init__.py:32-34 returns the whole section as the route;
# delegate_tool_config.py:478-497; delegate_tool.py:432-438, :620-630). Matched after strip+casefold.
DELEGATION_CONFIG_ROUTE_KEYS = frozenset({"profile", "command", "args", "provider", "base_url",
                                          "fallback_providers", "request_overrides", "acp_command", "acp_args"})


def _norm_key(key: Any) -> str:
    return key.strip().casefold() if isinstance(key, str) else ""


def _load_delegation_config() -> dict:
    from tools.delegate_tool_config import _load_config
    cfg = _load_config()
    return cfg if isinstance(cfg, dict) else {}


def _keys_ok(obj: Mapping[str, Any], allowed: frozenset[str]) -> bool:
    for key, value in obj.items():
        if not isinstance(key, str) or key not in allowed:
            return False
        if _norm_key(key) in DELEGATION_ROUTE_KEYS:   # cannot happen with the sets above; belt and braces
            return False
    return True


def default_delegation_ok(args: Mapping[str, Any], *,
                          load_config: Callable[[], Mapping[str, Any]] = _load_delegation_config) -> bool:
    """delegate_task is allowed iff the child inherits the parent's (locked, in-tier) route: the
    ``default`` backend (read per call), no route key in ``delegation`` config (strip+casefold), and
    arguments that use only the documented delegate_task schema, with ``tasks`` a list of dicts.
    Any error -> False."""
    try:
        cfg = load_config() or {}
        if not isinstance(cfg, Mapping):
            return False
        norm = {}
        for key, value in cfg.items():
            norm.setdefault(_norm_key(key), []).append(value)
        backends = norm.get("backend", [])
        for backend in backends:
            if backend is None or (isinstance(backend, str) and backend.strip().casefold() in ("", "default")):
                continue
            return False
        for key in DELEGATION_CONFIG_ROUTE_KEYS:
            if any(v not in (None, "", [], {}) for v in norm.get(key, [])):
                return False
        if not isinstance(args, Mapping) or not _keys_ok(args, DELEGATE_TOP_LEVEL_KEYS):
            return False
        tasks = args.get("tasks")
        if tasks is not None:
            if not isinstance(tasks, list):   # incl. tasks passed as a JSON string (Amendment 3)
                return False
            for task in tasks:
                if not isinstance(task, Mapping) or not _keys_ok(task, DELEGATE_TASK_KEYS):
                    return False
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------------------------------
# the hooks
# --------------------------------------------------------------------------------------------------

def _dumps(args: Any) -> str:
    """json.dumps(args); non-serialisable args fall back to repr, and to "" if even that raises."""
    try:
        return json.dumps(args if args is not None else {}, default=str)
    except Exception:
        try:
            return repr(args)
        except Exception:
            return ""


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


class _Policy:
    """The classification both enforcement points share."""

    def __init__(self, allowlist, bypass_active, delegation_ok, remembered, terminal_backend=None):
        self._allowlist = allowlist
        self._bypass_fn = bypass_active
        self._takes_name = _accepts_positional(bypass_active)
        self.delegation_ok = delegation_ok
        self.remembered = remembered
        self.terminal_backend = terminal_backend if terminal_backend is not None else hermes_terminal_backend

    def allowlist(self) -> Allowlist:
        return self._allowlist() if callable(self._allowlist) else self._allowlist

    def bypass(self, tool_name: str) -> bool:
        return bool(self._bypass_fn(tool_name) if self._takes_name else self._bypass_fn())  # type: ignore[call-arg]

    def on_host_decision(self, info: ToolInfo, args: dict, task_id: str = "") -> CallDecision:
        # Review finding 2 (INTERFACES Amendment 6): a terminal-backend tool is on-host only on the local
        # backend. The preflight refuses to lock otherwise; this is the second line, per call, because a
        # per-task override or the environment can change the backend after the lock.
        from .preflight import LOCAL_BACKEND, TERMINAL_BACKEND_KEY, TERMINAL_BACKEND_TOOLS
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

    def decide(self, tool_name: str, args: dict, task_id: str = "") -> CallDecision:
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
            return CallDecision("refuse", "bypass_active",
                                f"confidential mode: {tool_name} sends data off the machine and needs your "
                                "approval, but approvals are bypassed here (yolo, approvals.mode off, or an "
                                "unattended context with no one to ask). Blocked. Turn the bypass off, or add "
                                "the tool with /confidential allow.")
        n = args_kb(args)
        return CallDecision("ask", "remembered" if self.remembered(tool_name) else "ask",
                            f"{tool_name} wants to send ~{n} KB of this conversation off the machine", kb=n)


def _policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend=None) -> _Policy:
    return _Policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend)


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
        self._grants: set[str] = set()

    def record(self, key: str, choice: Any) -> None:
        with self._lock:
            self._choices[key] = choice

    def pop(self, key: str) -> Any:
        with self._lock:
            return self._choices.pop(key, _MISSING)

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


def build_pre_tool_call(is_locked: Callable[[], Any], allowlist: Allowlist | Callable[[], Allowlist],
                        ledger: Any, bypass_active: Callable[[str], bool] = hermes_bypass_active,
                        delegation_ok: Callable[[dict], bool] = default_delegation_ok,
                        remembered: Callable[[str], bool] = hermes_remembered_grant,
                        decisions: Optional[ApprovalDecisions] = None,
                        terminal_backend: Optional[Callable[[str], str]] = None) -> Callable[..., Optional[dict]]:
    """``pre_tool_call`` callback: blocks every refuse decision (ledgered tool_refused) and, for an
    off-host tool, returns the approve directive with the "~N KB" message (ledgered tool_asked).
    The directive only ASKS: Hermes' CLI grants on any answer except the exact string "deny"
    (tools/approval.py:1006-1009), so enforcement is build_tool_execution. REGISTER BOTH, with the
    same ``decisions`` (or both defaulting to DEFAULT_DECISIONS) and build_post_approval_response.

    If the middleware already asked for this exact call (agent-loop order: tool_execution is
    outermost, agent/tool_executor.py:775-812, and pre_tool_call runs inside its next_call,
    :677-736), the hook returns None instead of asking a second time.

    ``bypass_active(tool_name)`` (zero-arg also accepted), ``delegation_ok(args)`` and
    ``remembered(tool_name)`` are injectable. ``is_locked()`` returns ``(bool, Tier | None)`` or a bool;
    anything else, or raising, blocks every tool."""
    pol = _policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend)
    dec = decisions if decisions is not None else DEFAULT_DECISIONS

    def pre_tool_call(tool_name: str = "", args: Optional[dict] = None, session_id: str = "",
                      tool_call_id: str = "", task_id: str = "", **_kw: Any) -> Optional[dict]:
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
            d = pol.decide(tool_name, a, str(task_id or ""))
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
            directive = {"action": "approve", "message": d.message, "rule_key": rule_key_for(tool_name)}
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


def build_tool_execution(is_locked: Callable[[], Any], allowlist: Allowlist | Callable[[], Allowlist],
                         ledger: Any, decisions: Optional[ApprovalDecisions] = None, *,
                         bypass_active: Callable[[str], bool] = hermes_bypass_active,
                         delegation_ok: Callable[[dict], bool] = default_delegation_ok,
                         remembered: Callable[[str], bool] = hermes_remembered_grant,
                         ask: Callable[..., dict] = hermes_request_approval,
                         terminal_backend: Optional[Callable[[str], str]] = None) -> Callable[..., Any]:
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
    itself) propagates unchanged, as Hermes expects."""
    pol = _policy(allowlist, bypass_active, delegation_ok, remembered, terminal_backend)
    dec = decisions if decisions is not None else DEFAULT_DECISIONS

    def confidential_mode_tool_execution(tool_name: str = "", args: Any = None, next_call: Any = None,
                                         session_id: str = "", tool_call_id: str = "", turn_id: str = "",
                                         task_id: str = "", **_kw: Any) -> Any:
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

    def _refuse(tool_name, args, session_id, decision, message, detail):
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
        d = pol.decide(tool_name, args, task_id)
        if d.action == "refuse":
            return _refuse(tool_name, args, session_id, d.decision, d.message, {**base, "reason": d.decision})
        if d.action == "run":
            if d.decision != "on-host":
                ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id,
                                     decision=d.decision, nbytes=args_bytes(args), surface="middleware", detail=base))
            return run()
        key = _call_key(tool_name, tool_call_id) if tool_call_id else None
        # Never consume an answer recorded under an empty id (Amendment 4 F3).
        choice = dec.pop(key) if key is not None else _MISSING
        if choice is not _MISSING:                 # pre_tool_call asked (model_tools order)
            if type(choice) is str and choice in _ALLOW_CHOICES:
                return run()                       # tool_allowed was ledgered by post_approval_response
            return _unexpected(tool_name, args, session_id, base, choice)
        if d.decision == "remembered":
            ledger.append(_event("tool_allowed", tool_name=tool_name, session_id=session_id, decision="remembered",
                                 nbytes=args_bytes(args), surface="middleware", detail={**base, "kb": d.kb}))
            return run()
        # Nobody asked yet (agent-loop order, or pre_tool_call skipped): ask here.
        approval_id = f"cm-{uuid.uuid4().hex}"
        ledger.append(_event("tool_asked", tool_name=tool_name, session_id=session_id, decision="ask",
                             nbytes=args_bytes(args), surface="middleware",
                             detail={**base, "kb": d.kb, "message": d.message, "approval_id": approval_id}))
        result = ask(tool_name, d.message, rule_key=rule_key_for(tool_name), approval_id=approval_id,
                     session_id=session_id, turn_id=turn_id)
        choice = dec.pop(_call_key(tool_name, approval_id))
        approved = isinstance(result, dict) and result.get("approved") is True
        if approved and type(choice) is str and choice in _ALLOW_CHOICES:
            if key is None:
                return run()                       # the inner hook never asks for an id-less call
            dec.grant(key)
            try:
                return run()
            finally:
                dec.drop_grant(key)
        if approved:
            return _unexpected(tool_name, args, session_id, {**base, "approval_id": approval_id},
                               None if choice is _MISSING else choice)
        decision = "no_surface" if (choice is _MISSING and isinstance(result, dict)
                                    and result.get("status") == "approval_required") else "denied"
        return _refuse(tool_name, args, session_id, decision,
                       str((result or {}).get("message") or f"confidential mode: {tool_name} was not approved"),
                       {**base, "choice": None if choice is _MISSING else _choice_repr(choice),
                        "approval_id": approval_id})

    def _unexpected(tool_name, args, session_id, base, choice):
        return _refuse(tool_name, args, session_id, "unexpected_choice",
                       f"confidential mode: {_printable(tool_name)} was not run: the answer to the approval prompt "
                       f"was not once/session/always ({_printable(_choice_repr(choice))}).",
                       {**base, "choice": _choice_repr(choice)})

    return confidential_mode_tool_execution


#: Hermes' own approval answers (tools/approval.py). Only these are stored verbatim (review finding 20).
KNOWN_CHOICES = frozenset({"once", "session", "always", "deny", "timeout", "cancelled", "notify_failed",
                           "smart_approve", "smart_deny"})


def _choice_repr(choice: Any) -> Any:
    """A classification of an approval answer, safe to store and to show the model. A human may type a
    secret at the prompt by mistake (review finding 20), so free text is never kept: Hermes' fixed answers
    and "" stay as they are, None stays None, any other string is "other", any other value is its type."""
    if choice is None or choice == "" and isinstance(choice, str):
        return choice
    if isinstance(choice, str):
        return choice if choice in KNOWN_CHOICES else "other"
    return f"<{type(choice).__name__}>"


def build_post_approval_response(is_locked: Callable[[], Any], ledger: Any,
                                 decisions: Optional[ApprovalDecisions] = None) -> Callable[..., None]:
    """``post_approval_response`` observer: ledgers tool_allowed / tool_refused for OUR approve
    directives only (pattern_key ``plugin_rule:confidential-mode:tool:<name>``), and records the exact
    choice in ``decisions`` (default DEFAULT_DECISIONS) for build_tool_execution. Only the exact strings
    once/session/always are tool_allowed; every other value is tool_refused. Never raises."""
    dec = decisions if decisions is not None else DEFAULT_DECISIONS

    def post_approval_response(pattern_key: str = "", choice: str = "", session_id: str = "",
                               session_key: str = "", surface: str = "", tool_call_id: str = "",
                               **kw: Any) -> None:
        try:
            if not isinstance(pattern_key, str) or not pattern_key.startswith(PATTERN_KEY_PREFIX):
                return None
            tool_name = pattern_key[len(PATTERN_KEY_PREFIX):]
            if tool_call_id:                     # an id-less answer is never recorded (Amendment 4 F3)
                dec.record(_call_key(tool_name, tool_call_id), choice)
            pick = choice if type(choice) is str else ""
            allowed = pick in _ALLOW_CHOICES
            detail = {"tool": tool_name, "choice": _choice_repr(choice), "tool_call_id": tool_call_id or "",
                      "session_key": session_key or "", "locked": _safe(is_locked)}
            ledger.append(_event("tool_allowed" if allowed else "tool_refused", tool_name=tool_name,
                                 session_id=session_id or "",
                                 decision=pick if pick in KNOWN_CHOICES else "unexpected_choice",
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
        return _locked_flag(fn())
    except Exception:
        return None

"""Tool gate, classification: the route each registered tool takes while locked.

``classify_tool`` gives a tool its ``Route`` from its name, toolset and origin (built-in, plugin or MCP):
the contract's on-host set runs, ``cronjob_manage`` and MCP servers whose URL host is off-tier are
blocked, ``delegate_task`` is checked per call, and everything else asks. The ``_default_*`` readers find
MCP server configs and plugin tool names through hermes_compat.py.
"""
from __future__ import annotations

import functools
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

# The contract's on-host set (docs/INTERFACES.md, "W4 gate_tools.py, consent.py"). Exactly these.
ON_HOST_TOOLS: frozenset[str] = frozenset({
    "terminal", "process_manage", "execute_code", "read_file", "write_file", "patch", "search_files",
    "skills_list", "skill_view", "skill_manage", "todo_list", "memory", "clarify", "session_search",
})
CRON_TOOL = "cronjob_manage"
DELEGATE_TOOL = "delegate_task"


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


@dataclass(frozen=True)
class ToolInfo:
    name: str
    toolset: str
    origin: Origin
    route: Route
    mcp_server: str | None = None   # raw server name for MCP tools
    mcp_transport: str | None = None  # "url" | "stdio" | "unknown" for MCP tools
    mcp_host: str | None = None       # host_of(url) for URL servers
    reason: str = ""                     # why this route (verdict reason for MCP URL servers)
    mode: str | None = None           # reserved for MODE_TOOLS (see above); None = plain route


def _default_mcp_configs() -> dict[str, dict]:
    """Every MCP server config Hermes knows: ``mcp_servers`` (incl. portable packages) overlaid with
    the live connection configs. Never raises."""
    configs: dict[str, dict] = {}
    try:
        from . import hermes_compat
        for name, cfg in (hermes_compat.mcp_server_configs() or {}).items():
            if isinstance(cfg, dict):
                configs[str(name)] = dict(cfg)
    except Exception:
        pass
    try:
        from . import hermes_compat
        live = hermes_compat.mcp_live_servers()
        for key, server in live:
            cfg = hermes_compat.mcp_server_config(server)
            if isinstance(cfg, dict) and cfg:
                name = hermes_compat.mcp_key_name(key)
                # url anywhere wins (fail closed): merge rather than replace.
                configs[name] = {**configs.get(name, {}), **cfg}
    except Exception:
        pass
    return configs


def _default_mcp_tool_servers() -> dict[str, str]:
    try:
        from .hermes_compat import mcp_tool_server_names
        return mcp_tool_server_names()
    except Exception:
        return {}


def _default_plugin_tool_names() -> set[str]:
    try:
        from .hermes_compat import plugin_tool_names
        return plugin_tool_names()
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


def _mcp_transport(cfg: Mapping[str, Any] | None) -> str:
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


def classify_tool(name: str, toolset: str, *, origin: Origin, mcp_server: str | None = None,
                  mcp_config: Mapping[str, Any] | None = None, predicate: Any = None) -> ToolInfo:
    if origin is Origin.MCP:
        transport = _mcp_transport(mcp_config)
        if transport == "url":
            route, host, reason = _mcp_url_route(mcp_server or "",
                                                 mcp_config.get("url"),  # type: ignore[union-attr]  # "url": a config
                                                 predicate)
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

"""Tool gate, classification: the route each registered tool takes while locked.

``classify_tool`` gives a tool its ``Route`` from its name, toolset and origin (built-in, plugin or MCP):
``BUILTIN_TOOL_CLASSES`` classes every built-in by data flow (on-host, off-host, unsettled; issue #1); the on-host
rows run, ``cronjob_manage`` and MCP servers whose URL host is off-tier are blocked, ``delegate_task`` is
checked per call, and everything else (off-host, unsettled, not audited, plugin tools) asks. The
``_default_*`` readers find MCP server configs and plugin tool names through hermes_compat.py.
"""
from __future__ import annotations

import functools
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

# Data-flow classes of Hermes' built-in tools (issue #1; docs/TOOL_CLASSES.md holds the same table with the
# evidence for each row). A tool is on-host only when its own code makes no network call and launches nothing
# that does, other than installing a declared dependency from a package index; a tool whose data leaves this
# machine, or is handed to another agent, is off-host; a tool whose data flow cannot be settled from Hermes'
# source at 84a0301 is unsettled. Off-host and unsettled tools both take the ASK route; the class is kept on the
# ToolInfo so the lock reply and the receipt can name it. Shell, code execution and the file tools keep the
# on-host class of the original contract: they run what the model writes and are not inspected, and the
# preflight requires the terminal backend to be local.
ON_HOST = "on-host"
OFF_HOST = "off-host"
UNSETTLED = "unsettled"
DATA_CLASSES = (ON_HOST, OFF_HOST, UNSETTLED)
BUILTIN_TOOL_CLASSES: dict[str, str] = {
    # shell, code execution, files
    "terminal": ON_HOST, "process_manage": ON_HOST, "execute_code": ON_HOST,
    "read_file": ON_HOST, "write_file": ON_HOST, "patch": ON_HOST, "search_files": ON_HOST,
    # skills, memory, todo, clarify, session search
    "skills_list": ON_HOST, "skill_view": ON_HOST, "skill_manage": ON_HOST, "todo_list": ON_HOST,
    "memory": ON_HOST, "clarify": ON_HOST, "session_search": ON_HOST,
    # the Desktop app's panes (annotate_preview and gui_tour write into the previewed page)
    "annotate_preview": OFF_HOST, "close_terminal": ON_HOST, "desktop_preview": OFF_HOST, "drive_preview": OFF_HOST,
    "focus_pane": ON_HOST, "gui_tour": OFF_HOST, "react_to_message": ON_HOST, "read_terminal": ON_HOST,
    "read_window_below": ON_HOST, "set_theme": ON_HOST, "show_tip": ON_HOST, "desktop_project": UNSETTLED,
    "computer_use": UNSETTLED,
    # onboarding
    "setup_beat": OFF_HOST,
    # the kanban board: a write to the board hands text to the workers the gateway dispatcher spawns
    "kanban_attach": OFF_HOST, "kanban_attach_url": OFF_HOST, "kanban_attachments": ON_HOST, "kanban_block": OFF_HOST,
    "kanban_comment": OFF_HOST, "kanban_complete": OFF_HOST, "kanban_create": OFF_HOST, "kanban_heartbeat": ON_HOST,
    "kanban_link": OFF_HOST, "kanban_list": OFF_HOST, "kanban_request_changes": OFF_HOST,
    "kanban_request_review": OFF_HOST, "kanban_schedule": OFF_HOST, "kanban_show": ON_HOST, "kanban_unblock": OFF_HOST,
    # web, browser, media, messaging, connectors
    "browser_cdp": OFF_HOST, "browser_dialog": OFF_HOST, "browser_exec": OFF_HOST, "browser_vault": OFF_HOST,
    "web_search": OFF_HOST, "web_extract": OFF_HOST, "x_search": OFF_HOST,
    "image_generate": OFF_HOST, "vision_analyze": OFF_HOST, "video_analyze": OFF_HOST, "video_generate": OFF_HOST,
    "xai_video_edit": OFF_HOST, "xai_video_extend": OFF_HOST, "text_to_speech": UNSETTLED,
    "discord": OFF_HOST, "discord_admin": OFF_HOST,
    "feishu_doc_read": OFF_HOST, "feishu_drive_add_comment": OFF_HOST, "feishu_drive_list_comment_replies": OFF_HOST,
    "feishu_drive_list_comments": OFF_HOST, "feishu_drive_reply_comment": OFF_HOST,
    "yb_query_group_info": OFF_HOST, "yb_query_group_members": OFF_HOST, "yb_search_sticker": ON_HOST,
    "yb_send_dm": OFF_HOST, "yb_send_sticker": OFF_HOST,
    "manage_catalog": UNSETTLED, "manage_connections": OFF_HOST,
    # scheduled jobs and delegation: their own routes (BLOCK_CRON, DELEGATE); the class is for the record
    "cronjob_manage": OFF_HOST, "delegate_task": OFF_HOST,
}
#: The built-in tools that run without a prompt while locked: the on-host rows of the table.
ON_HOST_TOOLS: frozenset[str] = frozenset(n for n, c in BUILTIN_TOOL_CLASSES.items() if c == ON_HOST)
UNKNOWN = "unknown"   # a built-in tool the table does not name
CLASS_REASONS = {
    OFF_HOST: "off-host: the tool's data leaves this machine (docs/TOOL_CLASSES.md)",
    UNSETTLED: "unsettled: the tool's data flow cannot be settled from Hermes' source (docs/TOOL_CLASSES.md)",
    UNKNOWN: "not audited: the table for Hermes 84a0301 has no row for this tool",
}
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
    data_class: str = ""              # built-in tools: on-host | off-host | ask | unknown (issue #1)


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
    data_class = BUILTIN_TOOL_CLASSES.get(name, UNKNOWN) if origin is Origin.BUILTIN else ""
    if name in ON_HOST_TOOLS and origin is Origin.BUILTIN:
        route = Route.ON_HOST
    elif name == CRON_TOOL:
        route = Route.BLOCK_CRON
    elif name == DELEGATE_TOOL:
        route = Route.DELEGATE
    else:
        route = Route.ASK
    reason = CLASS_REASONS.get(data_class, "") if origin is Origin.BUILTIN else ""
    return ToolInfo(name, toolset, origin, route, reason=reason, data_class=data_class)

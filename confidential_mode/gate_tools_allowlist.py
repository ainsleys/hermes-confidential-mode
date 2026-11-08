"""Tool gate, allowlist: the tools classified at lock, persisted, and checked again at each call.

``build_allowlist`` classifies every tool in Hermes' live registry; ``Allowlist`` records each entry's
route and handler identity, persists the set beside the lock (allowlist.yaml) and treats a tool whose
handler or toolset changed since lock as unclassified. ``ensure_tools_for_lock`` loads the tool modules
first, ``format_allowlist`` prints the lists, and ``lock_id_for`` names the lock a grant belongs to.
"""
from __future__ import annotations

import contextlib
import functools
import json
import os
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .gate_tools_classify import (
    Origin,
    Route,
    _default_mcp_configs,
    _default_mcp_tool_servers,
    _default_plugin_tool_names,
    _handler_module,
    classify_tool,
)

if TYPE_CHECKING:
    from .gate_tools_classify import ToolInfo


_ROUTE_STRICTNESS = {"on-host": 0, "delegate": 1, "ask": 2, "block-cron": 3, "block-mcp-url": 3}


@dataclass
class Allowlist:
    """Classification computed at lock. ``added`` holds names a human allowed via consent.allow_tool."""
    tools: dict[str, ToolInfo]
    built_at: float = field(default_factory=time.time)
    added: set[str] = field(default_factory=set)
    added_path: Path | None = None   # allowlist.yaml; additions persist there (Amendment 3)
    # Pinned at lock (Amendment 3 addendum): name -> (toolset, handler object). Holding the handler keeps
    # its id from being reused. A live entry whose toolset or handler differs => unclassified.
    pins: dict[str, tuple[str, Any]] = field(default_factory=dict, repr=False)
    registry: Any = field(default=None, repr=False)
    # Re-read at call time for MCP tools so a server re-pointed after lock is re-judged (fail closed).
    mcp_config_loader: Callable[[], Mapping[str, Any]] | None = field(default=None, repr=False)
    predicate: Any = field(default=None, repr=False)
    lock_id: str = ""                    # identity of the lock this allowlist belongs to (F5/F6)
    # name -> (toolset, handler module, handler qualname) as persisted at lock; set on a restart rebuild
    persisted_identity: dict[str, tuple[str, str, str]] | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def get(self, name: str) -> ToolInfo | None:
        return self.tools.get(name)

    def current(self, name: str) -> ToolInfo | None:
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
                                      mcp_config=cfgs.get(info.mcp_server),  # type: ignore[arg-type]  # MCP tools name a server
                                      predicate=self.predicate)
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
        if self.added_path is None:
            with self._lock:
                self.added.add(name)
            return
        # Amendment 10: under the file lock, start from the names on disk for this lock, so a name another
        # process revoked while this process waited for the human is not written back. FI-2: the file is
        # written first and the grant is taken in memory only after the write succeeded, so a failed write
        # (which raises) grants nothing.
        from .revoke import allowed_on_disk, file_lock
        with file_lock(self.added_path):
            on_disk = allowed_on_disk(self.added_path, self.lock_id)
            with self._lock:
                if on_disk is not None:
                    base = {n for n in on_disk if getattr(self.tools.get(n), "route", None) is Route.ASK}
                else:
                    base = set(self.added)
            new = base | {name}
            self.persist(added=new)
            with self._lock:
                self.added = new

    # -- persistence (Amendment 4 F5/F6) ------------------------------------------------------------
    def persist(self, path: Path | None = None, *, added: Iterable[str] | None = None) -> None:
        """Write the lock's tool identities (name, toolset, handler module, qualname) and the
        human-approved additions (``added``, default the in-memory set), tagged with ``lock_id``. Called at
        lock and after each add. JSON (a YAML subset): Hermes ships ruamel via hermes_yaml, not PyYAML."""
        target = Path(path) if path is not None else self.added_path
        if target is None:
            return
        if added is not None:
            added = sorted(added)
        else:
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
    def load_persisted(cls, path: Path | None, registry: Any, *, lock_id: str, predicate: Any = None,
                       mcp_configs: Mapping[str, Mapping[str, Any]] | None = None,
                       mcp_tool_servers: Mapping[str, str] | None = None,
                       plugin_tool_names: Iterable[str] | None = None) -> Allowlist:
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
            if isinstance(t, dict) and all(isinstance(t.get(k), str)
                                           for k in ("name", "toolset", "module", "qualname")):
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
        allowed = cast(list, data.get("allowed")) if isinstance(data.get("allowed"), list) else []
        fresh.added = {n for n in allowed if isinstance(n, str) and n in keep and keep[n].route is Route.ASK}
        return fresh


def clear_persisted(path: Path | None, *, lock_id: str = "") -> None:
    """Unlock: drop the lock's persisted allowlist and its additions (Amendment 4 F6). With ``lock_id``, only
    a file written for that lock (or an unreadable one) is removed: a file another process wrote for a newer
    lock is kept. Without it (unreadable lock state), the file is removed."""
    if path is None:
        return
    if lock_id:
        data = _read_json_or_yaml(Path(path))
        if isinstance(data, dict) and isinstance(data.get("lock_id"), str) and data["lock_id"] != lock_id:
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
            from . import hermes_compat  # a hand-edited YAML file
            return hermes_compat.hermes_yaml().safe_load(text)
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
# loading every tool before the lock classifies the live registry
# --------------------------------------------------------------------------------------------------

def ensure_builtin_tools(progress: Any = None) -> None:
    """Import every Hermes built-in tool module so the lock can classify them all. Built-in tools register
    themselves on import, and a `hermes confidential` CLI process never builds an agent. Side effects
    (INTERFACES Amendment 11): Hermes may rewrite its tool-discovery cache when the cache is stale, and the
    imported modules register their exit handlers (Hermes' browser module registers one that, at exit, closes the
    browsers this process opened and stops browser processes whose owning Hermes process is gone; a running
    gateway's browsers have a live owner and are left alone). Idempotent; never raises. ``progress``: a
    progress.Progress for the "discovering tools" line."""
    try:
        from tools.registry import discover_builtin_tools, registry
        if progress is None or not getattr(progress, "enabled", False):
            discover_builtin_tools()
        else:
            with progress.phase("discovering tools") as box:
                discover_builtin_tools()
                box["result"] = f"{len(registry.get_all_entries())} found"
    except Exception:
        pass


def ensure_tools_for_lock(path: Path | None, progress: Any = None) -> None:
    """Import only the built-in tool modules the lock recorded (allowlist.yaml's ``module`` fields), for a
    rebuild in a process that has not imported them (`hermes confidential allow`, `status --verbose`). Unlike
    ensure_builtin_tools this never touches Hermes' tool-discovery cache. Never raises."""
    import sys
    data = _read_json_or_yaml(Path(path)) if path is not None else None
    tools = data.get("tools") if isinstance(data, dict) else None
    # MCP tools are gateway-registered: their handlers live in tools.mcp_tool_handlers and only a connected
    # MCP server registers them, so importing anything for them registers nothing (Amendment 11).
    tools = [t for t in tools if isinstance(t, dict) and not str(t.get("toolset", "")).startswith("mcp-")] \
        if isinstance(tools, list) else []
    names = sorted({t["module"] for t in tools if isinstance(t.get("module"), str)
                    and t["module"].startswith("tools.")})
    missing = [n for n in names if n not in sys.modules]
    if missing:
        _import_modules(missing, progress)
    # A handler defined outside the module that registers it: fall back to the full import for those tools.
    try:
        from tools.registry import registry
        wanted = [t["name"] for t in tools if isinstance(t.get("name"), str)
                  and str(t.get("module", "")).startswith("tools.")]
        if any(registry.get_entry(n) is None for n in wanted):
            ensure_builtin_tools(progress)
    except Exception:
        pass


def _import_modules(missing: list, progress: Any = None) -> None:
    from .hermes_compat import import_tool_module
    try:
        if progress is not None and getattr(progress, "enabled", False):
            with progress.phase("loading the locked tools") as box:
                for name in missing:
                    with contextlib.suppress(Exception):
                        import_tool_module(name)
                box["result"] = f"{len(missing)} modules"
        else:
            for name in missing:
                with contextlib.suppress(Exception):
                    import_tool_module(name)
    except Exception:
        pass


def build_allowlist(registry: Any, *, mcp_configs: Mapping[str, Mapping[str, Any]] | None = None,
                    mcp_tool_servers: Mapping[str, str] | None = None,
                    plugin_tool_names: Iterable[str] | None = None, predicate: Any = None,
                    added_path: Path | None = None) -> Allowlist:
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
    (Route.ASK, "off-host (asks the first time per lock in each conversation, each call with "
                "confidential.tools.ask: each_call; blocked under yolo/approvals off/unattended)"),
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

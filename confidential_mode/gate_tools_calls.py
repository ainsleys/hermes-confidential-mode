"""Tool gate, call inspection: what one tool call carries.

The self-approval guard (``invokes_confidential_cli``, ``names_state_file``: a locked call that runs the
plugin's own CLI or writes its state files is refused), the delegate_task route check
(``default_delegation_ok``), and the size of what a call would send (``call_bytes``, with attached
images) and the ask text built from it (``ask_message``).
"""
from __future__ import annotations

import json
import math
import os
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

# Self-approval guard (INTERFACES Amendment 7, step 0). These on-host tools run a command or code on this
# host. While the profile is locked, a call whose command or code invokes the plugin's own CLI is refused,
# because under a pseudo-terminal the agent could answer the pin or allow prompt itself.
SELF_APPROVAL_TOOLS: frozenset[str] = frozenset({"terminal", "process_manage", "execute_code"})
# File-writing on-host tools: while locked, a call that names one of the plugin's state files is refused.
STATE_FILE_TOOLS: frozenset[str] = frozenset({"write_file", "patch"})


def _strings(value: Any, depth: int = 0) -> Iterable[str]:
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from _strings(k, depth + 1)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, depth + 1)


def invokes_confidential_cli(args: Any, tool: str | None = None) -> str | None:
    """Why the call would run the plugin's own CLI, import its package or write its state files, or None
    (selfscan.py has the forms, Amendment 9). terminal strings are read as shell, execute_code strings as
    Python, and process_manage input (a shell or a Python prompt may be reading it) as both; with no tool
    named, every string is read both ways. Text that only mentions the word, the package name or a path is
    not refused. Not detectable: a command assembled at run time, a script that imports the package
    indirectly, and a command split across several process_manage writes. selfapproval.py is the second
    line."""
    from . import selfscan
    as_shell = tool in (None, "terminal", "process_manage")
    as_python = tool in (None, "execute_code", "process_manage")
    for raw in _strings(args):
        if as_shell:
            why = selfscan.shell_reason(raw)
            if why:
                return why
        if as_python:
            why = selfscan.python_reason(raw)
            if why:
                return why
    return None


def names_state_file(args: Any) -> bool:
    """A write_file or patch call whose target path (or a V4A patch's file) is one of the plugin's state
    files where the plugin keeps them (selfscan.is_state_path)."""
    from . import selfscan
    return selfscan.file_tool_reason(args) is not None


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
    from .hermes_compat import delegation_config
    cfg = delegation_config()
    return cfg if isinstance(cfg, dict) else {}


def _keys_ok(obj: Mapping[str, Any], allowed: frozenset[str]) -> bool:
    for key in obj:
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
        norm: dict = {}
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
# what a call would send
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


IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".heif"})


def attached_image_bytes(args: Any) -> int:
    """Bytes of the local image files a call names (vision_analyze takes a path, then reads and sends the
    file). Each distinct existing regular file with an image suffix counts once, by its size; nothing is read.
    A data: URL is already counted by args_bytes. Never raises."""
    total, seen = 0, set()
    for raw in _strings(args):
        try:
            text = raw.strip()
            if text.startswith("file://"):
                text = text[len("file://"):]
            if not text or len(text) > 4096 or "\n" in text or Path(text).suffix.lower() not in IMAGE_SUFFIXES:
                continue
            path = Path(os.path.expanduser(text))
            key = str(path)
            if key in seen or not path.is_file():
                continue
            seen.add(key)
            total += path.stat().st_size
        except Exception:
            continue
    return total


def call_bytes(args: Any) -> int:
    """What a call sends off the machine, as far as the gate can see: the arguments plus attached images."""
    return args_bytes(args) + attached_image_bytes(args)


def size_text(nbytes: int) -> str:
    """"~N KB" (rounded up, at least 1) up to 1 MB, then "~X.Y MB"."""
    if nbytes > 1024 * 1024:
        return f"~{nbytes / (1024 * 1024):.1f} MB"
    return f"~{max(1, math.ceil(nbytes / 1024))} KB"


def ask_message(tool_name: str, nbytes: int, once_per_lock: bool = False) -> str:
    """The plugin's own line in the approval prompt; it leads with what is happening. Under once_per_lock it
    says what an allow covers."""
    text = f"Confidential mode: {tool_name} wants to send {size_text(nbytes)} of this conversation off the machine"
    if once_per_lock:
        text += f"; allowing once covers {tool_name} in this conversation until this profile is unlocked"
    return text

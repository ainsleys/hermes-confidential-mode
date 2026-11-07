"""Self-approval guard, second line (INTERFACES Amendment 7): may this process ask a person for a pin or
tool approval?

The tool hooks (gate_tools) call ``mark_tool_process()`` before any tool runs. It sets the tool marker,
``XDG_CONFIDENTIAL_MODE_TOOL_PROCESS``, to this process's id, once. The ``XDG_`` prefix is what lets the
marker through Hermes' execute_code environment allowlist (tools/code_execution_env.py, _SAFE_ENV_PREFIXES),
so terminal, process_manage and execute_code children all inherit it. Every approval prompt calls
``self_approval_reason()`` and refuses when the process carries a marker that names another process.

What this does not stop (docs/LIMITATIONS.md section 15): an agent that unsets the marker, assembles the
command at run time, or attaches a client through the gateway socket, where the gateway (the marking
process itself) runs the client's slash command.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

TOOL_PROCESS_ENV = "XDG_CONFIDENTIAL_MODE_TOOL_PROCESS"


def mark_tool_process() -> None:
    """Set the tool marker to this process's id unless an ancestor already set it. Never raises."""
    try:
        os.environ.setdefault(TOOL_PROCESS_ENV, str(os.getpid()))
    except Exception:
        pass


def self_approval_reason(environ: Optional[Mapping] = None, pid: Optional[int] = None) -> Optional[str]:
    """Why this process must not ask for an approval, or None."""
    environ = os.environ if environ is None else environ
    pid = os.getpid() if pid is None else int(pid)
    marker = environ.get(TOOL_PROCESS_ENV)
    if marker and marker != str(pid):
        return (f"this process carries the tool marker {TOOL_PROCESS_ENV} of process {marker}: a Hermes tool "
                "started it, so the agent may be driving this prompt")
    return None

"""Self-approval guard, second line (INTERFACES Amendment 7): may this process ask a person for a pin or
tool approval right now?

The tool hooks (gate_tools) call ``mark_tool_process()`` before any tool runs. It sets
``CONFIDENTIAL_MODE_TOOL_PROCESS`` to this process's id, once, so every tool subprocess inherits the id of
the process that ran the tool. Every asker path then calls ``self_approval_reason()``:

* the marker is set and names another process: this process descends from a Hermes tool (for example
  ``hermes confidential pins approve``, or a nested ``hermes`` chat that answers its own slash command, run
  by the agent under a pseudo-terminal). Refused.
* the marker names this process: this process runs tools, and in Hermes 84a0301 it is also the gateway
  that executes the slash commands of every attached chat client, including a nested ``hermes`` chat that a
  tool started. The asker cannot tell which client answers, so it refuses while any live descendant of
  this process carries this process's marker (a tool subprocess that is still running). A descendant whose
  environment the operating system does not let us read (macOS system binaries such as /bin/bash) is not
  counted; the Hermes client under it is a Python process and is.
* no marker: no tool has run in this process or its ancestors. Allowed.

What still gets through: a tool subprocess that unsets the marker before it starts the nested Hermes,
together with leaving this process's tree (a double fork); docs/LIMITATIONS.md section 15.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Iterable, Mapping, Optional

TOOL_PROCESS_ENV = "CONFIDENTIAL_MODE_TOOL_PROCESS"


def mark_tool_process() -> None:
    """Set TOOL_PROCESS_ENV to this process's id unless an ancestor already set it. Never raises."""
    try:
        os.environ.setdefault(TOOL_PROCESS_ENV, str(os.getpid()))
    except Exception:
        pass


def _default_descendants(pid: int) -> list[tuple[int, Optional[Mapping]]]:
    """(pid, environment or None when unreadable) for every live descendant of ``pid``."""
    import psutil
    out = []
    for child in psutil.Process(pid).children(recursive=True):
        try:
            if child.status() == psutil.STATUS_ZOMBIE:
                continue
            env = child.environ()
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
            env = None
        except psutil.NoSuchProcess:
            continue
        out.append((child.pid, env or None))
    return out


Descendants = Callable[[int], Iterable[tuple[int, Optional[Mapping]]]]


def live_tool_descendants(pid: int, descendants: Optional[Descendants] = None) -> list[int]:
    """Ids of live descendants of ``pid`` whose environment carries ``pid`` as the marker."""
    mine = str(pid)
    return sorted(p for p, env in (descendants or _default_descendants)(pid)
                  if isinstance(env, Mapping) and env.get(TOOL_PROCESS_ENV) == mine)


def self_approval_reason(environ: Optional[Mapping] = None, pid: Optional[int] = None,
                         descendants: Optional[Descendants] = None) -> Optional[str]:
    """Why this process must not ask for an approval now, or None. Fails closed: an error while looking
    for live tool processes is a reason."""
    environ = os.environ if environ is None else environ
    pid = os.getpid() if pid is None else int(pid)
    marker = environ.get(TOOL_PROCESS_ENV)
    if not marker:
        return None
    if marker != str(pid):
        return (f"this process descends from a Hermes tool (its environment carries {TOOL_PROCESS_ENV}, set by "
                f"process {marker}), so the agent may be driving this prompt")
    try:
        live = live_tool_descendants(pid, descendants)
    except Exception as exc:  # noqa: BLE001 - cannot tell: refuse
        return f"the plugin could not check for running tool processes ({type(exc).__name__})"
    if live:
        shown = ", ".join(str(p) for p in live[:8]) + (" ..." if len(live) > 8 else "")
        return (f"{len(live)} {'process' if len(live) == 1 else 'processes'} started by Hermes tools "
                f"{'is' if len(live) == 1 else 'are'} still running (pid {shown}); one of them could be a Hermes "
                "client answering this prompt. Stop them (process_manage kill) first")
    return None


def refusal(reason: str) -> Any:
    from .consent import SelfApprovalRefused
    return SelfApprovalRefused(reason)

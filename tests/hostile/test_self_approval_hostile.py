"""Hostile tests for the self-approval guard (INTERFACES Amendment 7, step 0).

The attack: while a profile is locked and a pin is pending, the agent runs
`hermes confidential pins approve` from its own terminal tool under a pseudo-terminal and answers the
prompt itself. Two lines stop it:
  1. the tool gate refuses any terminal, process_manage or execute_code call whose text reaches the
     confidential CLI or its files, with a tool_refused ledger row (decision "self_approval");
  2. TerminalAsker refuses in a process that carries the tool-process marker, which the tool hooks set in
     the agent process before any tool runs, so every tool subprocess inherits it. The test runs a real
     pty: a child process holds the slave end as its terminal and the parent types "1" into the master.
"""
from __future__ import annotations

import io
import json
import os
import pty
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from confidential_mode import commands, consent, gate_tools
from confidential_mode.gate_tools import Allowlist, Origin, Route, ToolInfo

PLUGIN_ROOT = Path(__file__).resolve().parents[2]


class _Ledger:
    def __init__(self):
        self.events = []

    def append(self, ev):
        self.events.append(ev)


def _allowlist():
    tools = {n: ToolInfo(n, n, Origin.BUILTIN, Route.ON_HOST)
             for n in ("terminal", "process_manage", "execute_code", "read_file")}
    return Allowlist(tools=tools)


def _hooks(locked=True):
    ledger = _Ledger()
    dec = gate_tools.ApprovalDecisions()
    kw = dict(bypass_active=lambda name: False, remembered=lambda name: False,
              terminal_backend=lambda task_id="": "local")
    pre = gate_tools.build_pre_tool_call(lambda: (locked, None), _allowlist(), ledger, decisions=dec, **kw)
    mw = gate_tools.build_tool_execution(lambda: (locked, None), _allowlist(), ledger, dec, **kw)
    return pre, mw, ledger


ATTACKS = [
    ("terminal", {"command": "hermes confidential pins approve", "pty": True}),
    ("terminal", {"command": "hermes -p work confidential pins approve --reviewed-by me", "pty": True}),
    ("terminal", {"command": "python -m hermes_cli.main confidential pins approve", "pty": True}),
    ("terminal", {"command": "'her'\"mes\" conf\\idential allow web_search", "pty": True}),
    ("terminal", {"command": "h confidential pins approve", "pty": True}),
    ("process_manage", {"action": "submit", "session_id": "p1", "data": "hermes confidential pins approve"}),
    ("execute_code", {"code": "import subprocess\nsubprocess.run(['hermes', 'confidential', 'pins', 'approve'])"}),
    ("execute_code", {"code": "from confidential_mode.pins import PinStore"}),
    ("terminal", {"command": "sqlite3 ~/.hermes/plugin-data/x/ledger.sqlite .dump"}),
    ("terminal", {"command": "sed -i s/a/b/ ~/.hermes/plugin-data/x/pins.yaml"}),
]


@pytest.mark.parametrize("tool,args", ATTACKS)
def test_gate_refuses_the_confidential_cli_from_a_tool_while_locked(tool, args):
    pre, mw, ledger = _hooks()
    directive = pre(tool_name=tool, args=args, session_id="s", tool_call_id="c1")
    assert directive and directive["action"] == "block" and "confidential" in directive["message"]
    ran = []
    out = mw(tool_name=tool, args=args, next_call=lambda a: ran.append(a) or "ran", session_id="s",
             tool_call_id="c1")
    assert ran == [] and "blocked" in json.loads(out)["error"]
    rows = [e for e in ledger.events if e["kind"] == "tool_refused"]
    assert len(rows) == 2 and {r["decision"] for r in rows} == {"self_approval"}


@pytest.mark.parametrize("cmd", ["ls -la", "grep -r confidential docs/", "git log --oneline", "printf '1\\n'"])
def test_gate_lets_ordinary_commands_run(cmd):
    pre, mw, ledger = _hooks()
    assert pre(tool_name="terminal", args={"command": cmd}, session_id="s", tool_call_id="c1") is None
    assert mw(tool_name="terminal", args={"command": cmd}, next_call=lambda a: "ran", session_id="s",
              tool_call_id="c1") == "ran"
    assert not [e for e in ledger.events if e["kind"] == "tool_refused"]


def test_unlocked_profile_is_not_refused_but_still_marks_the_process():
    pre, mw, ledger = _hooks(locked=False)
    assert os.environ.get(gate_tools.TOOL_PROCESS_ENV) is None
    assert pre(tool_name="terminal", args={"command": "hermes confidential pins"}, session_id="s",
               tool_call_id="c1") is None
    assert os.environ.get(gate_tools.TOOL_PROCESS_ENV) == "1"


def test_read_file_is_not_a_self_approval_tool():
    pre, _, _ = _hooks()
    assert pre(tool_name="read_file", args={"path": "pins.yaml"}, session_id="s", tool_call_id="c1") is None


_CHILD = textwrap.dedent("""
    import sys
    sys.path.insert(0, {root!r})
    from confidential_mode.commands import TerminalAsker
    from confidential_mode.consent import SelfApprovalRefused
    try:
        pick = TerminalAsker().ask_choice("Approve?", [{{"value": "approve"}}, {{"value": "deny"}}])
        print("PICK=" + repr(pick), file=sys.stderr)
    except SelfApprovalRefused as exc:
        print("REFUSED", file=sys.stderr)
""")


def _run_under_pty(env_extra: dict) -> str:
    """Run TerminalAsker in a child whose stdin and stdout are a real pty; type "1" into the master."""
    master, slave = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k != gate_tools.TOOL_PROCESS_ENV}
    env.update(env_extra)
    proc = subprocess.Popen([sys.executable, "-c", _CHILD.format(root=str(PLUGIN_ROOT))], stdin=slave,
                            stdout=slave, stderr=subprocess.PIPE, env=env, cwd=str(PLUGIN_ROOT))
    os.close(slave)
    try:
        os.write(master, b"1\n")
        _, err = proc.communicate(timeout=60)
    finally:
        os.close(master)
    return err.decode()


def test_pty_approve_from_a_tool_subprocess_is_refused():
    """The marker the hooks set reaches the child; under a real pty the asker refuses and reads nothing."""
    pre, _, _ = _hooks()
    pre(tool_name="terminal", args={"command": "bash"}, session_id="s", tool_call_id="c1")   # marks
    err = _run_under_pty({gate_tools.TOOL_PROCESS_ENV: os.environ[gate_tools.TOOL_PROCESS_ENV]})
    assert "REFUSED" in err and "PICK=" not in err, err


def test_pty_control_without_the_marker_reads_the_answer():
    err = _run_under_pty({})
    assert "PICK='approve'" in err, err


def test_cli_approve_inside_a_tool_process_is_refused_and_ledgered(tmp_path):
    """The full consent path with the marker set: no apply, a pin_denied row with decision self_approval."""
    class Store:
        applied = []

        def pending(self):
            return {"vendor": "tinfoil", "code_fingerprint": "c" * 64, "enclave_fingerprint": "e" * 64}

        def apply(self, p, **kw):
            self.applied.append(p)

    class TTY(io.StringIO):
        def isatty(self):
            return True

    ledger, store = _Ledger(), Store()
    asker = commands.TerminalAsker(stdin=TTY("1\n"), stdout=io.StringIO(),
                                   environ={gate_tools.TOOL_PROCESS_ENV: "1"})
    out = consent.approve_pending_pin(asker, store, ledger, session_key="cli", session_id="", platform="cli")
    assert out.startswith("Refused:") and store.applied == []
    assert [e["decision"] for e in ledger.events] == ["self_approval"]

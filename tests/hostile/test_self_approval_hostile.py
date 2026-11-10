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
import shutil
import subprocess
import sys
import tempfile
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
             for n in ("terminal", "process_manage", "execute_code", "read_file", "write_file", "patch")}
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
    # Issue #63: revoke through the short alias (selfscan.CLI_VERBS had no revoke).
    ("terminal", {"command": "h confidential revoke web_search", "pty": True}),
    ("terminal", {"command": "h confidential revoke --all", "pty": True}),
    ("process_manage", {"action": "submit", "session_id": "p1", "data": "hermes confidential pins approve"}),
    ("execute_code", {"code": "import subprocess\nsubprocess.run(['hermes', 'confidential', 'pins', 'approve'])"}),
    ("execute_code", {"code": "from confidential_mode.pins import PinStore"}),
    ("terminal", {"command": "sqlite3 ~/.hermes/plugin-data/x/ledger.sqlite .dump"}),
    ("terminal", {"command": "sed -i s/a/b/ ~/.hermes/plugin-data/x/pins.yaml"}),
    ("terminal", {"command": "hermes $'\\x63onfidential' pins approve", "pty": True}),          # ANSI-C quoting
    ("execute_code", {"code": "import importlib; importlib.import_module('confidential_mode.provider')"}),
    ("write_file", {"path": "/Users/x/.hermes/plugin-data/p/pins.yaml", "content": "version: 3"}),
    ("patch", {"path": "ledger.sqlite", "old_string": "a", "new_string": "b"}),
    # Amendment 9: more real forms the narrowed scan still refuses
    ("terminal", {"command": "bash -c 'hermes confidential pins approve'"}),
    ("terminal", {"command": "echo \"$(hermes confidential pins)\""}),
    ("terminal", {"command": "echo `hermes confidential off`"}),
    ("terminal", {"command": "sudo -E hermes confidential off"}),
    ("terminal", {"command": "env A=1 ~/.local/bin/hermes confidential pins approve"}),
    ("terminal", {"command": "/opt/hermes/bin/hermes --profile work confidential allow web_search"}),
    ("terminal", {"command": "uv run hermes confidential pins approve"}),
    ("terminal", {"command": "ls; hermes confidential off"}),
    ("terminal", {"command": "ls\nhermes confidential off"}),
    ("terminal", {"command": "true && python3 -m hermes_cli.main confidential pins approve"}),
    ("terminal", {"command": "hermes chat -q '/confidential pins approve'"}),
    ("terminal", {"command": "hermes $'conf\\x69dential' off"}),
    ("terminal", {"command": "echo hermes confidential pins approve | sh"}),
    ("terminal", {"command": "cat <<EOF | bash\nhermes confidential pins approve\nEOF"}),
    ("terminal", {"command": "find . -maxdepth 0 -exec sh -c 'hermes confidential off' \\;"}),
    ("terminal", {"command": "python3 -c 'import confidential_mode.pins'"}),
    ("terminal", {"command": "python -c \"from plugin.confidential_mode import consent\""}),
    ("terminal", {"command": "python -m confidential_mode.commands"}),
    ("terminal", {"command": "python - <<'EOF'\nfrom confidential_mode.pins import PinStore\nEOF"}),
    ("terminal", {"command": "python3 <<< 'import confidential_mode'"}),
    ("terminal", {"command": "echo 'import confidential_mode' | python3"}),
    ("terminal", {"command": "echo x > ~/.hermes/plugin-data/confidential-mode/pins.yaml"}),
    ("terminal", {"command": "printf '{}' >> ~/.hermes/plugin-data/confidential-mode/state.json"}),
    ("terminal", {"command": "cp /tmp/p ~/.hermes/plugin-data/confidential-mode/allowlist.yaml"}),
    ("terminal", {"command": "cat /tmp/rows | tee ~/.hermes/plugin-data/c/ledger.sqlite"}),
    ("terminal", {"command": "cd ~/.hermes/plugin-data/confidential-mode && rm ledger.sqlite"}),
    ("terminal", {"command": "sed -i.bak s/a/b/ pins.yaml"}),
    ("process_manage", {"action": "submit", "session_id": "p1", "data": "/confidential pins approve"}),
    ("process_manage", {"action": "submit", "session_id": "p1", "data": "import confidential_mode.pins"}),
    ("execute_code", {"code": "import os\nos.system('hermes confidential pins approve')"}),
    ("execute_code", {"code": "import subprocess\nsubprocess.run('python -m hermes_cli.main confidential off', shell=True)"}),
    ("execute_code", {"code": "from hermes_cli.main import main\nmain(['confidential', 'pins', 'approve'])"}),
    ("execute_code", {"code": "__import__('confidential_mode.consent')"}),
    ("execute_code", {"code": "import sqlite3\nsqlite3.connect('/h/.hermes/plugin-data/c/ledger.sqlite')"}),
    ("write_file", {"path": "~/.hermes/plugin-data/confidential-mode/state.json", "content": "{}"}),
    ("write_file", {"path": "allowlist.yaml", "content": "tools: []"}),
    ("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Update File: /h/.hermes/plugin-data/c/pins.yaml\n"
                                          "@@\n-a\n+b\n*** End Patch"}),
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


@pytest.mark.parametrize("cmd", [
    "ls -la", "grep -r confidential docs/", "git log --oneline", "printf '1\\n'",
    # Amendment 9: text and paths that only mention the word, the package or a state file
    'grep "confidential off" docs/README.md',
    "grep -rn 'hermes confidential pins approve' docs",
    "rg 'hermes confidential' README.md",
    "echo 'mark confidential on purpose'",
    "echo confidential off",
    "echo hermes confidential pins approve",
    "cat confidential_mode/gate_tools.py",
    "sed -n 1,40p ~/hermes-confidential-mode/confidential_mode/gate_tools.py",
    "sed -i s/a/b/ ~/hermes-confidential-mode/confidential_mode/gate_tools.py",
    "git diff confidential_mode/ docs/LIMITATIONS.md",
    "git commit -m 'hermes confidential: narrow the tool gate'",
    "ls ~/.hermes/plugins/confidential-mode/confidential_mode",
    "cat ~/.hermes/plugin-data/confidential-mode/pins.yaml",
    "grep -c verify_ok ~/.hermes/plugin-data/confidential-mode/ledger.sqlite",
    "head -5 docs/config.example.yaml",
    "grep -rn confidential_mode .",
    "cd ~/hermes-agent && uv run pytest ~/hermes-confidential-mode/tests -q",
    "python -m pytest tests/unit -q -k confidential",
    "python3 -c 'print(1)'",
    "cp ~/hermes-confidential-mode/docs/config.example.yaml /tmp/x.yaml",
])
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
    assert os.environ.get(gate_tools.TOOL_PROCESS_ENV) == str(os.getpid()), "the marker names the marking process"


@pytest.mark.parametrize("tool,args", [
    ("execute_code", {"code": "print(open('docs/README.md').read().count('confidential off'))"}),
    ("execute_code", {"code": "import re\nprint(re.findall('hermes confidential', open('README.md').read()))"}),
    ("write_file", {"path": "/Users/x/hermes-confidential-mode/confidential_mode/gate_tools.py",
                    "content": "# hermes confidential pins approve; pins.yaml; import confidential_mode\n"}),
    ("patch", {"path": "/Users/x/hermes-confidential-mode/confidential_mode/selfscan.py",
               "old_string": "pins.yaml", "new_string": "ledger.sqlite"}),
    ("write_file", {"path": "/Users/x/hermes-confidential-mode/docs/README.md",
                    "content": "Run `hermes confidential off` to unlock.\n"}),
    ("write_file", {"path": "/tmp/pins.yaml", "content": "a: 1"}),
    ("read_file", {"path": "/Users/x/hermes-confidential-mode/docs/LIMITATIONS.md"}),
    ("process_manage", {"action": "submit", "session_id": "p1", "data": "grep 'confidential off' docs/README.md"}),
])
def test_gate_lets_tools_that_only_mention_the_plugin_run(tool, args):
    pre, mw, ledger = _hooks()
    assert pre(tool_name=tool, args=args, session_id="s", tool_call_id="c1") is None, (tool, args)
    assert mw(tool_name=tool, args=args, next_call=lambda a: "ran", session_id="s", tool_call_id="c1") == "ran"
    assert not [e for e in ledger.events if e["kind"] == "tool_refused"]


def test_a_python_script_that_imports_the_package_is_refused_and_one_that_does_not_runs(tmp_path):
    bad, good = tmp_path / "bad.py", tmp_path / "good.py"
    bad.write_text("import sys\nfrom confidential_mode import consent\n")
    good.write_text("print('confidential off')\n")
    pre, _, _ = _hooks()
    d = pre(tool_name="terminal", args={"command": f"python3 {bad}"}, session_id="s", tool_call_id="c1")
    assert d and d["action"] == "block"
    assert pre(tool_name="terminal", args={"command": f"python3 {good}"}, session_id="s", tool_call_id="c2") is None


def test_read_file_is_not_a_self_approval_tool():
    pre, _, _ = _hooks()
    assert pre(tool_name="read_file", args={"path": "pins.yaml"}, session_id="s", tool_call_id="c1") is None


def test_state_file_refusal_names_the_revoke_state_file():
    # Issue #63: the refusal text names every file the state-file scan matches, grants_revoked.json included.
    pre, _, _ = _hooks()
    d = pre(tool_name="write_file", args={"path": "~/.hermes/plugin-data/c/grants_revoked.json", "content": "{}"},
            session_id="s", tool_call_id="c1")
    assert d and d["action"] == "block" and "grants_revoked.json" in d["message"], d


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


# ── every asker path, and a real nested hermes process ─────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self.applied = []

    def pending(self):
        return {"vendor": "tinfoil", "code_fingerprint": "c" * 64, "enclave_fingerprint": "e" * 64}

    def apply(self, p, **kw):
        self.applied.append(p)


class _ChatAsker:
    """A chat surface's ctx (Hermes' clarify panel): it answers whatever it is asked."""

    def __init__(self):
        self.asked = []

    def ask_choice(self, q, choices):
        self.asked.append(q)
        return "approve"


def test_chat_surface_asker_in_a_tool_subprocess_is_refused(monkeypatch):
    """A nested hermes chat answers through ctx, not TerminalAsker: the marker of another process refuses."""
    monkeypatch.setenv(gate_tools.TOOL_PROCESS_ENV, str(os.getpid() + 100000))
    store, ledger, ctx = _Store(), _Ledger(), _ChatAsker()
    out = consent.approve_pending_pin(ctx, store, ledger, session_key="k", session_id="s", platform="cli")
    assert out.startswith("Refused:") and ctx.asked == [] and store.applied == []
    assert [e["decision"] for e in ledger.events] == ["self_approval"]
    allow = gate_tools.Allowlist(tools={"web_search": ToolInfo("web_search", "web", Origin.BUILTIN, Route.ASK)})
    out = consent.allow_tool(ctx, allow, ledger, "web_search", session_key="k")
    assert out.startswith("Refused:") and ctx.asked == [] and not allow.is_added("web_search")
    assert ledger.events[-1]["kind"] == "tool_refused" and ledger.events[-1]["decision"] == "self_approval"


def test_the_marking_process_itself_still_asks():
    """The person's own surface in the process that ran the tools (the marker names this process) is asked."""
    gate_tools.mark_tool_process()
    assert os.environ[gate_tools.TOOL_PROCESS_ENV] == str(os.getpid())
    ctx = _ChatAsker()
    consent.approve_pending_pin(ctx, _Store(), _Ledger(), session_key="k", session_id="s", platform="telegram")
    assert len(ctx.asked) == 1


def test_execute_code_children_carry_the_marker():
    """Hermes builds execute_code's environment from an allowlist (tools/code_execution_env.py), for the
    per-call runs and the persistent kernel alike; the marker's XDG_ prefix is on it."""
    from tools.code_execution_env import _build_child_env
    gate_tools.mark_tool_process()
    env = _build_child_env(rpc_endpoint="x", rpc_token="t", tmpdir=tempfile.mkdtemp(), child_python=sys.executable)
    assert env.get(gate_tools.TOOL_PROCESS_ENV) == str(os.getpid())
    out = subprocess.run([sys.executable, "-c", _CHILD.format(root=str(PLUGIN_ROOT))], env=env,
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd=str(PLUGIN_ROOT), timeout=60)
    assert "REFUSED" in out.stderr, out.stderr


def test_terminal_children_carry_the_marker():
    from tools.environments.local import _make_run_env
    gate_tools.mark_tool_process()
    assert _make_run_env({}).get(gate_tools.TOOL_PROCESS_ENV) == str(os.getpid())


def _nested_home(tmp_root: Path) -> Path:
    home = tmp_root
    (home / "plugins").mkdir(parents=True)
    os.symlink(str(PLUGIN_ROOT), home / "plugins" / "confidential-mode")
    (home / "config.yaml").write_text("_config_version: 52\nplugins:\n  enabled: [confidential-mode]\n"
                                      "telemetry:\n  shared_metrics: {enabled: false, send: false, offer_version: 2}\n")
    return home


def _hermes_checkout() -> Path:
    """The Hermes checkout the nested ``hermes`` runs from: the one this process imported ``hermes_cli``
    from, else ``$HERMES_AGENT_ROOT``. Skips the test when neither is a Hermes checkout."""
    candidates = []
    try:
        import hermes_cli
        candidates.append(Path(hermes_cli.__file__).resolve().parents[1])
    except Exception:  # noqa: BLE001
        pass
    if os.environ.get("HERMES_AGENT_ROOT"):
        candidates.append(Path(os.environ["HERMES_AGENT_ROOT"]))
    for root in candidates:
        if (root / "hermes_cli" / "main.py").is_file():
            return root
    pytest.skip("no Hermes checkout: hermes_cli is not importable and HERMES_AGENT_ROOT is unset or not a checkout")


def _run_nested_hermes(home: Path, env: dict, argv: list, answer: bytes = b"1\n") -> str:
    """Run a real ``hermes`` (python -m hermes_cli.main) under a pty and answer its terminal prompt."""
    import select
    import time
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, "-m", "hermes_cli.main", *argv], stdin=slave, stdout=slave,
                            stderr=slave, env={**env, "HERMES_HOME": str(home)}, cwd=str(_hermes_checkout()),
                            start_new_session=True)
    os.close(slave)
    buf, answered, end = b"", False, time.time() + 120
    try:
        while time.time() < end and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.3)
            if ready:
                try:
                    buf += os.read(master, 65536)
                except OSError:
                    break
            if b"Choice:" in buf and not answered:
                os.write(master, answer)
                answered = True
        if proc.poll() is None:
            proc.kill()
    finally:
        os.close(master)
    return buf.decode(errors="replace")


def _stage_tinfoil_pin(home: Path) -> Path:
    from confidential_mode.pins import PinStore
    from confidential_mode.verify.base import VerificationResult
    data = next((home / "plugin-data").glob("agent-plugin-confidential-mode-*"))
    store = PinStore(data / "pins.yaml")
    store.stage(VerificationResult("tinfoil", "tinfoilsh/confidential-model-router", "router.test", "c1" * 32,
                                   "e1" * 48, "v9.9.9", "test", 0.0, {}))
    return data / "pins.yaml"


def test_real_nested_hermes_under_a_pty_from_a_tool_subprocess_is_refused(tmp_path):
    """The agent's route: a tool subprocess (environment built by Hermes' own local backend, so the marker is
    inherited, not passed by hand) runs `hermes confidential pins approve` under a pty and types "1"."""
    from tools.environments.local import _make_run_env
    home = _nested_home(Path(tempfile.mkdtemp(prefix="h", dir="/tmp")))
    try:
        _run_nested_hermes(home, {k: v for k, v in os.environ.items() if k != gate_tools.TOOL_PROCESS_ENV},
                           ["confidential", "status"])   # creates the plugin's data directory
        pins = _stage_tinfoil_pin(home)
        before = pins.read_bytes()
        pre, _, _ = _hooks()
        pre(tool_name="terminal", args={"command": "bash"}, session_id="s", tool_call_id="c1")   # marks this process
        env = _make_run_env({})
        assert env.get(gate_tools.TOOL_PROCESS_ENV) == str(os.getpid())
        out = _run_nested_hermes(home, env, ["confidential", "pins", "approve"])
        assert "Refused:" in out and "Choice:" not in out, out[-2000:]
        assert pins.read_bytes() == before, "nothing was applied"
        import sqlite3
        db = next(home.glob("plugin-data/confidential-mode/ledger.sqlite"))
        rows = sqlite3.connect(db).execute("select kind, decision from events where kind='pin_denied'").fetchall()
        assert ("pin_denied", "self_approval") in rows
        # control: the same command from a terminal no tool started asks, reads "1" and pins
        os.environ.pop(gate_tools.TOOL_PROCESS_ENV, None)
        clean = {k: v for k, v in _make_run_env({}).items() if k != gate_tools.TOOL_PROCESS_ENV}
        out = _run_nested_hermes(home, clean, ["confidential", "pins", "approve"])
        assert "Choice:" in out and "Pinned tinfoil build v9.9.9" in out, out[-2000:]
    finally:
        shutil.rmtree(home, ignore_errors=True)


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

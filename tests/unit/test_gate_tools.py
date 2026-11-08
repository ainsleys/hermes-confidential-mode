"""Unit tests for confidential_mode.gate_tools over a fake registry. No Hermes import: every Hermes
default (MCP configs, plugin names, bypass detection, delegation config) is injected."""
from __future__ import annotations

import functools
import json
from types import SimpleNamespace

import pytest

from confidential_mode.gate_tools import (
    ON_HOST_TOOLS,
    PATTERN_KEY_PREFIX,
    Allowlist,
    Origin,
    Route,
    args_kb,
    build_allowlist,
    build_post_approval_response,
    build_pre_tool_call,
    default_delegation_ok,
    format_allowlist,
    rule_key_for,
)


def _builtin_handler(args, **kw):
    return "{}"


def _plugin_handler_factory():
    ns = {"__name__": "hermes_plugins.someplugin.tools"}
    exec("def handler(args, **kw):\n    return '{}'\n", ns)
    return ns["handler"]


class FakeRegistry:
    def __init__(self, entries):
        self._entries = [SimpleNamespace(name=n, toolset=ts, handler=h) for n, ts, h in entries]

    def get_all_entries(self):
        return list(self._entries)


class FakeLedger:
    def __init__(self, fail=False):
        self.events, self.fail = [], fail

    def append(self, event):
        if self.fail:
            raise OSError("disk full")
        self.events.append(event)

    def kinds(self):
        return [e["kind"] for e in self.events]


ENTRIES = [(n, "core", _builtin_handler) for n in sorted(ON_HOST_TOOLS)] + [
    ("cronjob_manage", "cronjob", _builtin_handler),
    ("delegate_task", "delegation", _builtin_handler),
    ("web_search", "web", _builtin_handler),
    ("vision_analyze", "vision", functools.partial(_builtin_handler)),
    ("remote_query", "mcp-remote", _builtin_handler),
    ("on_host_query", "mcp-localsrv", _builtin_handler),
    ("ghost_query", "mcp-ghost", _builtin_handler),          # no config anywhere
    ("both_query", "mcp-both", _builtin_handler),            # url AND command: url wins
    ("lh_query", "mcp-lh", _builtin_handler),                # http://localhost URL: on-host
    ("lan_query", "mcp-lan", _builtin_handler),              # RFC1918 URL: off-tier unless listed (Amendment 10)
    ("obf_query", "mcp-obf", _builtin_handler),              # obfuscated loopback: off-tier
    ("plug_tool", "someplugin", _plugin_handler_factory()),
    ("named_plug", "other", _builtin_handler),               # plugin by manager name list
]
MCP_CONFIGS = {
    "remote": {"url": "https://mcp.example.com/mcp"},
    "localsrv": {"command": "npx", "args": ["some-server"]},
    "both": {"url": "https://x.example/mcp", "command": "x"},
    "lh": {"url": "http://localhost:8765/mcp"},
    "lan": {"url": "http://10.0.0.5:9000/mcp"},
    "obf": {"url": "http://0x7f000001/mcp"},
}


def allowlist(**kw):
    return build_allowlist(FakeRegistry(kw.pop("entries", ENTRIES)), mcp_configs=kw.pop("mcp_configs", MCP_CONFIGS),
                           mcp_tool_servers=kw.pop("mcp_tool_servers", {}),
                           plugin_tool_names=kw.pop("plugin_tool_names", {"named_plug"}))


# --------------------------------------------------------------------------------------------------
# allowlist
# --------------------------------------------------------------------------------------------------

def test_on_host_set_is_exactly_the_contract():
    """The on-host set is the on-host class of docs/TOOL_CLASSES.md (issue #1): the original contract's tools
    except skill_view, plus the Desktop pane, kanban and other tools whose data stays on this machine."""
    assert ON_HOST_TOOLS == {
        "terminal", "process_manage", "execute_code", "read_file", "write_file", "patch", "search_files",
        "skills_list", "skill_manage", "todo_list", "memory", "clarify", "session_search",
        "annotate_preview", "close_terminal", "focus_pane", "gui_tour", "react_to_message", "read_terminal",
        "read_window_below", "set_theme", "show_tip", "desktop_project",
        "kanban_attach", "kanban_attachments", "kanban_block", "kanban_comment", "kanban_create", "kanban_heartbeat",
        "kanban_link", "kanban_list", "kanban_request_changes", "kanban_schedule", "kanban_show", "kanban_unblock",
        "yb_search_sticker"}
    al = allowlist()
    assert set(al.on_host) - {"lh_query", "on_host_query"} == ON_HOST_TOOLS


def test_registry_driven_classification():
    al = allowlist()
    r = {n: al.get(n).route for n in al.tools}
    assert r["cronjob_manage"] is Route.BLOCK_CRON
    assert r["delegate_task"] is Route.DELEGATE
    assert r["web_search"] is Route.ASK and r["vision_analyze"] is Route.ASK
    assert r["remote_query"] is Route.BLOCK_MCP_URL
    assert r["both_query"] is Route.BLOCK_MCP_URL
    assert r["ghost_query"] is Route.BLOCK_MCP_URL          # unknown transport: fail closed
    assert r["on_host_query"] is Route.ON_HOST                  # stdio MCP: allowed per Amendment 3
    assert al.get("remote_query").origin is Origin.MCP
    assert (al.get("remote_query").mcp_server, al.get("remote_query").mcp_transport) == ("remote", "url")
    assert al.get("on_host_query").mcp_transport == "stdio"
    assert al.get("ghost_query").mcp_transport == "unknown"
    assert r["lh_query"] is Route.ON_HOST and al.get("lh_query").mcp_host == "localhost"
    assert r["lan_query"] is Route.BLOCK_MCP_URL
    assert r["obf_query"] is Route.BLOCK_MCP_URL
    assert al.get("plug_tool").origin is Origin.PLUGIN      # hermes_plugins.* handler module
    assert al.get("named_plug").origin is Origin.PLUGIN     # plugin manager's tool-name list
    assert al.get("web_search").origin is Origin.BUILTIN
    assert al.get("vision_analyze").origin is Origin.BUILTIN  # partial unwrapped to this module


def test_mcp_server_name_comes_from_hermes_map_when_present():
    # Hermes' raw-name map wins over the toolset suffix (tools/mcp_tool.py:561).
    al = allowlist(entries=[("q", "mcp-remote", _builtin_handler)], mcp_tool_servers={"q": "localsrv"})
    assert al.get("q").mcp_server == "localsrv" and al.get("q").route is Route.ON_HOST


def test_on_host_name_overridden_by_plugin_is_not_on_host():
    al = allowlist(entries=[("read_file", "evil", _plugin_handler_factory())])
    assert al.get("read_file").origin is Origin.PLUGIN and al.get("read_file").route is Route.ASK


def test_format_allowlist_lists_every_bucket():
    al = allowlist()
    text = format_allowlist(al)
    assert "on-host (runs without asking): 38" in text     # 36 on-host built-ins, a stdio and a loopback MCP server
    assert "blocked (MCP server URL off-tier or unreadable): 5" in text
    assert "blocked (scheduled jobs): 1" in text
    assert "remote_query  [mcp-remote; mcp; server=remote, transport=url, host=mcp.example.com]" in text
    for name in al.tools:
        assert f"  {name}  [" in text


def test_allowlist_add_only_for_ask_route():
    al = allowlist()
    al.add("web_search")
    assert al.is_added("web_search")
    for name in ("cronjob_manage", "delegate_task", "remote_query", "read_file", "nope"):
        with pytest.raises(ValueError):
            al.add(name)


# --------------------------------------------------------------------------------------------------
# pre_tool_call (first line: blocks refusals, never asks) and tool_execution (enforcement, asks)
# --------------------------------------------------------------------------------------------------

class Rig:
    """Both enforcement points over one fake world. ``answer`` is the recorded post_approval_response
    choice (None = no hook fired); ``hermes_approved`` is what Hermes' gate returned."""

    def __init__(self, locked=True, bypass=False, delegation=True, remembered=False, answer="once",
                 hermes_approved=True, al=None, ledger=None, status=None, terminal_backend=None):
        from confidential_mode.gate_tools import ApprovalDecisions, build_tool_execution
        self.ledger = ledger if ledger is not None else FakeLedger()
        self.al = al or allowlist()
        self.calls = {"bypass": [], "delegation": [], "ask": [], "ran": []}
        self.decisions = ApprovalDecisions()
        self.post = build_post_approval_response(lambda: locked, self.ledger, self.decisions)

        def bypass_active(name):
            self.calls["bypass"].append(name)
            return bypass

        def delegation_ok(args):
            self.calls["delegation"].append(args)
            return delegation

        def ask(tool_name, message, *, rule_key, approval_id, session_id="", turn_id=""):
            self.calls["ask"].append((tool_name, message, rule_key))
            if answer is not None:
                self.post(pattern_key="plugin_rule:" + rule_key, choice=answer, session_id=session_id,
                          tool_call_id=approval_id, surface="cli")
            res = {"approved": hermes_approved, "message": None if hermes_approved else "BLOCKED: denied"}
            if status:
                res["status"] = status
            return res

        locked_fn = locked if callable(locked) else (lambda: locked)
        self.hook = build_pre_tool_call(locked_fn, self.al, self.ledger, bypass_active, delegation_ok,
                                        lambda n: remembered, decisions=self.decisions,
                                        terminal_backend=terminal_backend)
        self.mw = build_tool_execution(locked_fn, self.al, self.ledger, self.decisions, bypass_active=bypass_active,
                                       delegation_ok=delegation_ok, remembered=lambda n: remembered, ask=ask,
                                       terminal_backend=terminal_backend)

    def run(self, name, args=None, **kw):
        args = {} if args is None else args

        def next_call(a):
            self.calls["ran"].append((name, a))
            return '{"ok": true}'
        return self.mw(tool_name=name, args=args, next_call=next_call, session_id="s", tool_call_id="c1", **kw)

    def ran(self):
        return [n for n, _ in self.calls["ran"]]


def refused(out):
    return isinstance(out, str) and "error" in json.loads(out)


def test_unlocked_passes_everything_and_ledgers_nothing():
    for locked in (False, (False, None)):
        r = Rig(locked=locked)
        for name in ("web_search", "cronjob_manage", "remote_query", "delegate_task", "never_registered"):
            assert r.hook(tool_name=name, args={"q": "x"}, session_id="s") is None
            assert r.run(name, {"q": "x"}) == '{"ok": true}'
        assert r.ledger.events == [] and r.calls["ask"] == [] and r.calls["bypass"] == []


def test_locked_on_host_tools_run_silently_even_under_bypass():
    r = Rig(bypass=True)
    for name in sorted(ON_HOST_TOOLS) + ["lh_query", "on_host_query"]:
        assert r.hook(tool_name=name, args={}, session_id="s") is None
        r.run(name)
    assert len(r.ran()) == len(ON_HOST_TOOLS) + 2 and r.ledger.events == [] and r.calls["bypass"] == []


@pytest.mark.parametrize("backend", ["ssh", "modal", "docker", "daytona", "vercel_sandbox", "my_plugin_backend"])
def test_terminal_backend_tools_are_blocked_on_a_non_local_backend(backend):
    """Review finding 2: terminal, execute_code and the file tools run on the terminal backend; on any
    backend but local both lines refuse them, naming the backend and the key. Other on-host tools run."""
    from confidential_mode.preflight import TERMINAL_BACKEND_TOOLS
    seen = []

    def where(task_id):
        seen.append(task_id)
        return backend
    r = Rig(terminal_backend=where)
    for name in sorted(TERMINAL_BACKEND_TOOLS):
        d = r.hook(tool_name=name, args={}, session_id="s", task_id="t1")
        assert d["action"] == "block" and f"terminal backend is {backend}" in d["message"]
        assert "terminal.backend: local" in d["message"]
        assert refused(r.run(name, task_id="t1"))
    assert r.ran() == [] and set(seen) == {"t1"}
    assert {e["decision"] for e in r.ledger.events} == {"terminal_backend"}
    for name in sorted(ON_HOST_TOOLS - TERMINAL_BACKEND_TOOLS):
        assert r.hook(tool_name=name, args={}, session_id="s") is None
        r.run(name)
    assert len(r.ran()) == len(ON_HOST_TOOLS - TERMINAL_BACKEND_TOOLS)


def test_terminal_backend_local_runs_and_unreadable_blocks():
    r = Rig(terminal_backend=lambda t: "local")
    assert r.hook(tool_name="write_file", args={}, session_id="s") is None
    r.run("write_file")
    assert r.ran() == ["write_file"]

    def broken(task_id):
        raise ImportError("tools.terminal_scope moved")
    r = Rig(terminal_backend=broken)
    d = r.hook(tool_name="terminal", args={}, session_id="s")
    assert d["action"] == "block" and "cannot read Hermes' terminal backend" in d["message"]
    assert refused(r.run("terminal")) and r.ran() == []


def test_hermes_terminal_backend_reads_hermes_resolution_then_the_cached_environment(monkeypatch):
    """Second review, items 4 and 5: the check reads the backend the way Hermes' tools do, then the environment
    Hermes cached for the task, which the tools reuse without re-reading the backend."""
    from types import SimpleNamespace

    from tools import terminal_tool

    from confidential_mode.gate_tools import cached_remote_environments, hermes_terminal_backend
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    assert hermes_terminal_backend("t-none") == "local" and cached_remote_environments() == []
    monkeypatch.setenv("TERMINAL_ENV", "SSH ")
    assert hermes_terminal_backend("t-none") == "ssh"
    monkeypatch.setenv("TERMINAL_ENV", "local")
    # An ssh environment created before the lock, still cached for task t1.
    monkeypatch.setattr(terminal_tool, "_active_environments", {"t1": SimpleNamespace(env_type="ssh"),
                                                                 "t2": SimpleNamespace(env_type="local"),
                                                                 "t3": SimpleNamespace()})
    assert hermes_terminal_backend("t1") == "ssh" and hermes_terminal_backend("t2") == "local"
    assert hermes_terminal_backend("t3").startswith("unknown") and hermes_terminal_backend("none") == "local"
    assert sorted(cached_remote_environments()) == [("t1", "ssh"), ("t3", "unknown")]


@pytest.mark.parametrize("name,decision", [("cronjob_manage", "cron"), ("remote_query", "mcp_url"),
                                           ("ghost_query", "mcp_url"), ("registered_after_lock", "unclassified")])
def test_block_routes_refused_by_both_lines(name, decision):
    r = Rig(bypass=False, delegation=True, answer="once")
    d = r.hook(tool_name=name, args={"x": 1}, session_id="s", tool_call_id="c1")
    assert d["action"] == "block" and r.ledger.events[-1]["decision"] == decision
    out = r.run(name, {"x": 1})
    assert refused(out) and r.ran() == [] and r.calls["ask"] == []
    assert r.ledger.kinds() == ["tool_refused", "tool_refused"]
    assert r.ledger.events[1]["surface"] == "middleware" and r.ledger.events[1]["decision"] == decision
    if decision == "unclassified":
        assert "lock again" in d["message"]


def test_delegate_task_only_via_delegation_ok():
    r = Rig(delegation=True)
    args = {"tasks": [{"goal": "g"}]}
    assert r.hook(tool_name="delegate_task", args=args, session_id="s") is None
    r.run("delegate_task", args)
    assert r.ran() == ["delegate_task"] and r.ledger.kinds() == ["tool_allowed"]
    assert r.ledger.events[0]["decision"] == "delegation_default"
    r = Rig(delegation=False)
    assert r.hook(tool_name="delegate_task", args=args, session_id="s")["action"] == "block"
    assert refused(r.run("delegate_task", args)) and r.ran() == []
    assert [e["decision"] for e in r.ledger.events] == ["delegation_route", "delegation_route"]


def test_hook_returns_approve_directive_unless_the_middleware_already_asked():
    from confidential_mode.gate_tools import _call_key
    r = Rig()
    d = r.hook(tool_name="web_search", args={"q": "x"}, session_id="s", tool_call_id="c1")
    assert d["action"] == "approve" and d["rule_key"] == rule_key_for("web_search")
    assert r.ledger.kinds() == ["tool_asked"] and r.calls["ask"] == []
    # agent-loop order: the middleware asked and granted this exact call -> the inner hook does not re-ask
    r.decisions.grant(_call_key("web_search", "c1"))
    assert r.hook(tool_name="web_search", args={"q": "x"}, session_id="s", tool_call_id="c1") is None
    # ...once only, and not for another call id
    assert r.hook(tool_name="web_search", args={}, session_id="s", tool_call_id="c1")["action"] == "approve"


def test_model_order_hook_asks_then_middleware_enforces_recorded_answer():
    from confidential_mode.gate_tools import PATTERN_KEY_PREFIX as P
    for answer, runs in (("once", True), ("always", True), ("", False), ("d", False), (None, False)):
        r = Rig(answer=None)
        assert r.hook(tool_name="web_search", args={}, session_id="s", tool_call_id="c1")["action"] == "approve"
        r.post(pattern_key=P + "web_search", choice=answer, tool_call_id="c1", session_id="s")   # Hermes' prompt
        out = r.run("web_search")
        assert (r.ran() == ["web_search"]) is runs, answer
        assert r.calls["ask"] == []                       # the middleware did not ask a second time
        if not runs:
            assert refused(out) and r.ledger.events[-1]["decision"] == "unexpected_choice"


def test_stale_answer_is_forgotten_when_the_hook_asks_again():
    from confidential_mode.gate_tools import PATTERN_KEY_PREFIX as P
    r = Rig(answer=None, hermes_approved=False)
    r.post(pattern_key=P + "web_search", choice="once", tool_call_id="c1")   # left over, never consumed
    r.hook(tool_name="web_search", args={}, session_id="s", tool_call_id="c1")
    assert refused(r.run("web_search")) and r.ran() == []      # nobody answered THIS ask


def test_off_host_tool_asks_with_kb_message_and_runs_on_explicit_answer():
    for answer in ("once", "session", "always"):
        r = Rig(answer=answer)
        args = {"query": "x" * 3000}
        out = r.run("web_search", args)
        n = -(-len(json.dumps(args)) // 1024)
        assert n == 3 and out == '{"ok": true}' and r.ran() == ["web_search"]
        assert r.calls["ask"] == [("web_search", f"Confidential mode: web_search wants to send ~{n} KB of this conversation off the machine",
                                   rule_key_for("web_search"))]
        assert r.ledger.kinds() == ["tool_asked", "tool_allowed"]
        assert r.ledger.events[0]["bytes"] == len(json.dumps(args)) and r.ledger.events[0]["detail"]["kb"] == 3
        assert r.ledger.events[1]["decision"] == answer


@pytest.mark.parametrize("answer", [None, "", "d", "yes", "Deny", "ONCE", "approve"])
def test_hermes_grant_on_an_unexpected_answer_is_refused(answer):
    # tools/approval.py:1006-1009: anything but the exact "deny" is a grant on the CLI.
    r = Rig(answer=answer, hermes_approved=True)
    out = r.run("web_search", {"q": "x"})
    assert refused(out) and r.ran() == []
    assert r.ledger.kinds()[-1] == "tool_refused" and r.ledger.events[-1]["decision"] == "unexpected_choice"
    # Review finding 20: free text is classified, never stored (a typed secret must not reach the ledger).
    assert r.ledger.events[-1]["detail"]["choice"] == (answer if answer in (None, "") else "other")


def test_a_secret_typed_at_the_approval_prompt_never_reaches_the_ledger_or_the_model():
    secret = "hunter2-correct-horse"
    r = Rig(answer=secret, hermes_approved=True)
    out = r.run("web_search", {"q": "x"})
    assert refused(out) and secret not in out
    assert secret not in json.dumps(r.ledger.events)
    ledger = FakeLedger()
    post = build_post_approval_response(lambda: True, ledger)
    post(pattern_key=PATTERN_KEY_PREFIX + "web_search", choice=secret, session_id="s", tool_call_id="c")
    assert ledger.events[0]["decision"] == "unexpected_choice" and secret not in json.dumps(ledger.events)


def test_denied_and_no_surface_are_refused():
    r = Rig(answer="deny", hermes_approved=False)
    assert refused(r.run("web_search")) and r.ran() == []
    # ux-pass-1 item 5: one refusal row per decision. post_approval_response ledgers the human's "deny";
    # the middleware's enforcement adds no second row.
    assert r.ledger.kinds() == ["tool_asked", "tool_refused"] and r.ledger.events[-1]["decision"] == "deny"
    r = Rig(answer=None, hermes_approved=False, status="approval_required")
    assert refused(r.run("web_search")) and r.ledger.events[-1]["decision"] == "no_surface"
    # an explicit answer recorded but Hermes said no (e.g. a race): still refused
    r = Rig(answer="once", hermes_approved=False)
    assert refused(r.run("web_search")) and r.ran() == []
    assert r.ledger.kinds()[-1] == "tool_refused" and r.ledger.events[-1]["decision"] == "denied"


class FlakyLedger(FakeLedger):
    """Fails the hook's write of the human's answer (a busy SQLite file), and nothing else."""

    def append(self, event):
        if event["kind"] == "tool_refused" and event.get("surface") == "cli":
            raise OSError("database is locked")
        super().append(event)


def test_a_refusal_the_hook_could_not_write_is_written_by_the_middleware(caplog):
    """Amendment 11: the hook writes the row before recording the choice; when the write fails, the denial
    stands, a warning is logged, and the middleware writes the one refusal row."""
    r = Rig(answer="deny", hermes_approved=False, ledger=FlakyLedger())
    with caplog.at_level("WARNING"):
        assert refused(r.run("web_search")) and r.ran() == []
    assert r.ledger.kinds() == ["tool_asked", "tool_refused"] and r.ledger.events[-1]["surface"] == "middleware"
    assert "could not ledger the answer for web_search" in caplog.text


class FlakyAllowLedger(FakeLedger):
    def append(self, event):
        if event["kind"] == "tool_allowed" and event.get("surface") == "cli":
            raise OSError("database is locked")
        super().append(event)


def test_an_allow_the_hook_could_not_write_is_written_by_the_middleware():
    r = Rig(answer="once", hermes_approved=True, ledger=FlakyAllowLedger())
    assert r.run("web_search") == '{"ok": true}' and r.ran() == ["web_search"]
    assert r.ledger.kinds() == ["tool_asked", "tool_allowed"]
    assert r.ledger.events[-1]["surface"] == "middleware" and r.ledger.events[-1]["decision"] == "once"
    r = Rig(answer="once", hermes_approved=True)                 # the hook wrote it: no second row
    r.run("web_search")
    assert r.ledger.kinds() == ["tool_asked", "tool_allowed"] and r.ledger.events[-1]["surface"] == "cli"


def test_an_answer_with_an_empty_id_is_recorded_once():
    """Hermes can fire post_approval_response without the observability context (an empty tool_call_id). The
    answer is keyed on the middleware's ask in progress, so exactly one row is written."""
    r = Rig(answer=None, hermes_approved=False)

    def ask(tool_name, message, *, rule_key, approval_id, session_id="", turn_id=""):
        r.post(pattern_key="plugin_rule:" + rule_key, choice="deny", session_id=session_id, tool_call_id="",
               surface="cli")
        return {"approved": False, "message": "BLOCKED: denied"}
    from confidential_mode.gate_tools import build_tool_execution
    mw = build_tool_execution(lambda: True, r.al, r.ledger, r.decisions, bypass_active=lambda n: False,
                              delegation_ok=lambda a: True, remembered=lambda n: False, ask=ask)
    out = mw(tool_name="web_search", args={}, next_call=lambda a: "{}", session_id="s", tool_call_id="c1")
    assert refused(out)
    assert r.ledger.kinds() == ["tool_asked", "tool_refused"] and r.ledger.events[-1]["decision"] == "deny"


def test_bypass_text_names_the_cause():
    from confidential_mode.gate_tools import bypass_text
    assert bypass_text("web_search", True) == (
        "confidential mode: web_search was blocked because approvals are bypassed (yolo or approvals off); turn "
        "the bypass off to be asked, or run: hermes confidential allow web_search (in chat: /confidential allow "
        "web_search)")
    assert "in an unattended run; to allow it, run: hermes confidential allow web_search, or run interactively" \
        in bypass_text("web_search", False)


def test_answer_for_another_call_does_not_count():
    r = Rig(answer=None, hermes_approved=True)
    r.decisions.record("some-other-call", "once")
    assert refused(r.run("web_search")) and r.ran() == []


@pytest.mark.parametrize("size,kb", [(0, 1), (1, 1), (1024, 1), (1025, 2), (2048, 2), (2049, 3), (10 * 1024 + 1, 11)])
def test_kb_rounding_is_ceiling_of_json_length(size, kb):
    # json.dumps({"q": s}) adds 9 chars of framing: {"q": ""}
    s = "a" * max(0, size - 9)
    args = {"q": s}
    if size >= 9:
        assert len(json.dumps(args)) == size
    assert args_kb(args) == max(1, -(-len(json.dumps(args)) // 1024))
    if size >= 9:
        assert args_kb(args) == kb


def test_kb_uses_json_dumps_default_escaping():
    args = {"q": "é" * 600}   # json.dumps escapes to \u00e9: 6 chars each -> 3609 chars
    assert len(json.dumps(args)) == 3609 and args_kb(args) == 4


def test_bypass_blocks_in_both_lines_and_never_asks():
    r = Rig(bypass=True, answer="once")
    d = r.hook(tool_name="web_search", args={"q": "x"}, session_id="s")
    # No Hermes surface in a unit test: the unattended wording, naming the command (Amendment 11).
    assert d["action"] == "block" and "unattended run" in d["message"]
    assert "hermes confidential allow web_search" in d["message"]
    assert refused(r.run("web_search", {"q": "x"})) and r.ran() == [] and r.calls["ask"] == []
    assert [e["decision"] for e in r.ledger.events] == ["bypass_active", "bypass_active"]


def test_zero_arg_bypass_callable_from_the_contract_is_accepted():
    ledger = FakeLedger()
    fn = build_pre_tool_call(lambda: True, allowlist(), ledger, lambda: True, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    fn = build_pre_tool_call(lambda: True, allowlist(), ledger, lambda: False, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s", tool_call_id="c")["action"] == "approve"


def test_user_added_tool_runs_without_asking_and_is_ledgered():
    r = Rig(bypass=True)
    r.al.add("web_search")
    assert r.hook(tool_name="web_search", args={}, session_id="s") is None
    r.run("web_search")
    assert r.ran() == ["web_search"] and r.calls["ask"] == []
    assert r.ledger.kinds() == ["tool_allowed"] and r.ledger.events[0]["decision"] == "allowlist"


def test_remembered_grant_is_honoured_and_ledgered():
    r = Rig(remembered=True, answer=None)
    r.run("web_search", {"q": "x"})
    assert r.ran() == ["web_search"] and r.calls["ask"] == []
    assert r.ledger.kinds() == ["tool_allowed"] and r.ledger.events[0]["decision"] == "remembered"
    r = Rig(remembered=False, answer=None, hermes_approved=True)   # mutant twin: no grant -> asked
    assert refused(r.run("web_search")) and len(r.calls["ask"]) == 1


def test_bypass_still_blocks_with_a_remembered_grant():
    r = Rig(bypass=True, remembered=True)
    assert refused(r.run("web_search")) and r.ran() == []
    assert r.ledger.events[0]["decision"] == "bypass_active"


@pytest.mark.parametrize("locked", [None, "yes", 1, (True,), ("x", None), (1, None), [True, None, 3]])
def test_unexpected_lock_shape_blocks_everything_including_on_host(locked):
    r = Rig(locked=locked)
    assert r.hook(tool_name="read_file", args={}, session_id="s")["action"] == "block"
    out = r.run("read_file")
    assert refused(out) and "/confidential status" in json.loads(out)["error"] and r.ran() == []


def test_unreadable_lock_state_blocks_everything_including_on_host():
    def boom():
        raise RuntimeError("state corrupt")
    r = Rig(locked=boom)
    d = r.hook(tool_name="read_file", args={}, session_id="s")
    assert d["action"] == "block" and "/confidential status" in d["message"]
    assert refused(r.run("read_file")) and r.ran() == []
    assert [e["decision"] for e in r.ledger.events] == ["lock_state_unreadable"] * 2


def test_is_locked_tuple_shape():
    from confidential_mode.tiers import Tier
    r = Rig(locked=(True, Tier.ON_HOST))
    assert r.hook(tool_name="cronjob_manage", args={}, session_id="s")["action"] == "block"
    assert refused(r.run("cronjob_manage"))
    r = Rig(locked=(False, None))
    assert r.hook(tool_name="cronjob_manage", args={}, session_id="s") is None
    r.run("cronjob_manage")
    assert r.ran() == ["cronjob_manage"]


def test_errors_fail_closed():
    def boom(name):
        raise RuntimeError("x")
    r = Rig()
    hook = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(), boom, lambda a: True)
    assert hook(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    # ledger raising -> hook blocks; middleware refuses (never runs the tool)
    hook = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(fail=True), lambda n: True, lambda a: True)
    assert hook(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    r = Rig(ledger=FakeLedger(fail=True))
    assert refused(r.run("web_search")) and r.ran() == []
    # on-host still runs with a broken ledger (nothing to ledger)
    r = Rig(ledger=FakeLedger(fail=True))
    r.run("read_file")
    assert r.ran() == ["read_file"]


def test_middleware_propagates_the_tools_own_exception_untouched():
    from confidential_mode.gate_tools import ApprovalDecisions, build_tool_execution
    mw = build_tool_execution(lambda: True, allowlist(), FakeLedger(), ApprovalDecisions(),
                              bypass_active=lambda n: False, remembered=lambda n: False)

    class ToolBoom(Exception):
        pass

    def next_call(a):
        raise ToolBoom("handler failed")
    with pytest.raises(ToolBoom):
        mw(tool_name="read_file", args={}, next_call=next_call)
    with pytest.raises(KeyboardInterrupt):
        mw(tool_name="read_file", args={}, next_call=lambda a: (_ for _ in ()).throw(KeyboardInterrupt()))


def test_allowlist_may_be_a_callable_for_relock():
    box = {"al": allowlist()}
    fn = build_pre_tool_call(lambda: True, lambda: box["al"], FakeLedger(), lambda n: False, lambda a: True)
    assert fn(tool_name="new_tool", args={}, session_id="s")["action"] == "block"
    box["al"] = allowlist(entries=ENTRIES + [("new_tool", "x", _builtin_handler)])
    assert fn(tool_name="new_tool", args={}, session_id="s", tool_call_id="c")["action"] == "approve"


def _build(reg, path=None):
    return build_allowlist(reg, mcp_configs=MCP_CONFIGS, mcp_tool_servers={}, plugin_tool_names=set(),
                           added_path=path)


def _load(reg, path, lock_id="S1"):
    return Allowlist.load_persisted(path, reg, lock_id=lock_id, mcp_configs=MCP_CONFIGS, mcp_tool_servers={},
                                    plugin_tool_names=set())


def test_persisted_allowlist_is_mode_0600_and_leaves_no_temp_file(tmp_path):
    """Review finding 18: allowlist.yaml lifts ask prompts, so it is written 0600 like pins.yaml."""
    import stat
    path = tmp_path / "allowlist.yaml"
    al = _build(MutableRegistry(ENTRIES), path)
    al.lock_id = "S1"
    al.persist()
    al.add("web_search")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # allowlist.yaml.lock is the advisory lock file (Amendment 10), empty and kept, as pins.yaml.lock is.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["allowlist.yaml", "allowlist.yaml.lock"]


def test_persist_and_reload_same_lock_keeps_classification_and_additions(tmp_path):
    path = tmp_path / "allowlist.yaml"
    reg = MutableRegistry(ENTRIES)
    al = _build(reg, path)
    al.lock_id = "S1"
    al.persist()
    al.add("web_search")
    data = json.loads(path.read_text())
    assert data["version"] == 2 and data["lock_id"] == "S1" and data["allowed"] == ["web_search"]
    row = next(t for t in data["tools"] if t["name"] == "read_file")
    assert row == {"name": "read_file", "toolset": "core", "module": __name__, "qualname": "_builtin_handler"}
    al2 = _load(reg, path)
    assert set(al2.tools) == set(al.tools) and al2.is_added("web_search")
    # a persisted addition that is now a hard block is not honoured
    data["allowed"] = ["web_search", "cronjob_manage", "remote_query", "nope"]
    path.write_text(json.dumps(data))
    assert _load(reg, path).added == {"web_search"}


def test_restart_rebuild_blocks_tools_registered_or_changed_after_lock(tmp_path):
    """Amendment 4 F5."""
    path = tmp_path / "allowlist.yaml"
    reg = MutableRegistry(ENTRIES)
    al = _build(reg, path)
    al.lock_id = "S1"
    al.persist()
    reg._entries.append(SimpleNamespace(name="crm_push", toolset="crm", handler=_builtin_handler))   # after lock
    reg.get_entry("web_search").toolset = "evil"                                                     # changed
    reg.get_entry("terminal").handler = _plugin_handler_factory()                                    # other module
    al2 = _load(reg, path)
    for name in ("crm_push", "web_search", "terminal"):
        assert al2.current(name) is None, name
    assert al2.current("read_file") is not None
    r = Rig(al=al2)
    assert r.hook(tool_name="crm_push", args={}, session_id="s", tool_call_id="c")["action"] == "block"
    assert refused(r.run("crm_push"))


@pytest.mark.parametrize("content", [None, "", ": not yaml [", '{"version": 1, "allowed": ["web_search"]}',
                                     "OTHER_LOCK"])
def test_restart_rebuild_without_this_locks_file_blocks_everything(tmp_path, content):
    path = tmp_path / "allowlist.yaml"
    reg = MutableRegistry(ENTRIES)
    if content == "OTHER_LOCK":
        al = _build(reg, path)
        al.lock_id = "S0"
        al.persist()
    elif content is not None:
        path.write_text(content)
    al2 = _load(reg, path, lock_id="S1")
    assert al2.tools == {} and al2.added == set()
    assert Rig(al=al2).hook(tool_name="read_file", args={}, session_id="s")["action"] == "block"


def test_new_lock_starts_without_previous_additions(tmp_path):
    """Amendment 4 F6: build_allowlist (a new lock) never reads old additions."""
    from confidential_mode.gate_tools import clear_persisted, lock_id_for
    path = tmp_path / "allowlist.yaml"
    reg = MutableRegistry(ENTRIES)
    al = _build(reg, path)
    al.lock_id = "S1"
    al.persist()
    al.add("web_search")
    assert not _build(reg, path).is_added("web_search")
    clear_persisted(path)
    assert not path.exists()
    clear_persisted(path)            # idempotent
    st = SimpleNamespace(locked_since=lambda: 12.5, config_fingerprint=lambda: "fp")
    assert lock_id_for(st) == "12.5|fp"
    assert lock_id_for(SimpleNamespace(locked_since=lambda: None, config_fingerprint=lambda: "fp")) == ""


def test_empty_tool_call_id_hook_never_asks_middleware_asks_with_fresh_id():
    """Amendment 4 F3."""
    from confidential_mode.gate_tools import PATTERN_KEY_PREFIX as P
    r = Rig(answer=None, hermes_approved=True)
    assert r.hook(tool_name="web_search", args={}, session_id="s", tool_call_id="") is None
    r.post(pattern_key=P + "web_search", choice="once", tool_call_id="")     # an id-less answer
    from confidential_mode.gate_tools import _MISSING
    assert r.decisions.pop("web_search\x00") is _MISSING                     # never recorded
    r2 = Rig(answer="once")
    r2.post(pattern_key=P + "web_search", choice="once", tool_call_id="")    # must never be consumed
    out = r2.mw(tool_name="web_search", args={}, next_call=lambda a: r2.calls["ran"].append(("web_search", a)) or "{}",
                session_id="s", tool_call_id="")
    assert len(r2.calls["ask"]) == 1                                         # asked itself
    assert r2.ran() == ["web_search"]
    r3 = Rig(answer="")
    r3.post(pattern_key=P + "web_search", choice="once", tool_call_id="")
    out = r3.mw(tool_name="web_search", args={}, next_call=lambda a: r3.calls["ran"].append(("web_search", a)) or "{}",
                session_id="s", tool_call_id="")
    assert refused(out) and r3.ran() == []                                   # the stray "once" did not count


# --------------------------------------------------------------------------------------------------
# post_approval_response
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("choice,kind", [
    ("once", "tool_allowed"), ("session", "tool_allowed"), ("always", "tool_allowed"),
    ("deny", "tool_refused"), ("timeout", "tool_refused"), ("cancelled", "tool_refused"),
    ("notify_failed", "tool_refused"), ("", "tool_refused"),
])
def test_post_approval_response_ledgers_choice(choice, kind):
    ledger = FakeLedger()
    post = build_post_approval_response(lambda: True, ledger)
    post(command="<web_search> (plugin approval rule)", description="m", pattern_key=PATTERN_KEY_PREFIX + "web_search",
         pattern_keys=[], session_key="sk", surface="cli", choice=choice, session_id="s", tool_call_id="c")
    assert ledger.kinds() == [kind]
    e = ledger.events[0]
    assert e["purpose"] == "tool:web_search" and e["detail"]["choice"] == choice and e["surface"] == "cli"


def test_post_approval_response_ignores_other_rules_and_never_raises():
    ledger = FakeLedger()
    post = build_post_approval_response(lambda: True, ledger)
    post(pattern_key="plugin_rule:web_search", choice="once")              # someone else's (default rule_key)
    post(pattern_key="rm -rf", choice="once")                               # a dangerous-command key
    post(choice="once")
    assert ledger.events == []
    post = build_post_approval_response(lambda: True, FakeLedger(fail=True))
    assert post(pattern_key=PATTERN_KEY_PREFIX + "x", choice="once") is None


# --------------------------------------------------------------------------------------------------
# default delegation predicate
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cfg,args,ok", [
    ({}, {"tasks": [{"goal": "g"}]}, True),
    ({"backend": "default", "model": "m", "max_iterations": 5}, {"goal": "g"}, True),
    ({"backend": "Default"}, {"tasks": [{"goal": "g", "context": "c"}]}, True),
    ({"backend": "other"}, {"tasks": [{"goal": "g"}]}, False),
    ({"backend": 3}, {"tasks": [{"goal": "g"}]}, False),
    ({"profile": "work"}, {"tasks": [{"goal": "g"}]}, False),
    ({"command": "claude"}, {"tasks": [{"goal": "g"}]}, False),
    ({"args": ["--acp"]}, {"tasks": [{"goal": "g"}]}, False),
    ({"provider": "openrouter"}, {"tasks": [{"goal": "g"}]}, False),
    ({"base_url": "https://api.example.com/v1"}, {"tasks": [{"goal": "g"}]}, False),
    ({}, {"tasks": [{"goal": "g", "acp_command": "claude"}]}, False),
    ({}, {"tasks": [{"goal": "g", "acp_args": ["x"]}]}, False),
    ({}, {"tasks": [{"goal": "g", "profile": "work"}]}, False),
    ({}, {"tasks": [{"goal": "g", "provider": "openrouter"}]}, False),
    ({}, {"goal": "g", "profile": "work"}, False),
    ({}, {"tasks": "not a list"}, False),
    ({}, {"tasks": ["not a dict"]}, False),
    ({}, {"tasks": json.dumps([{"goal": "g"}])}, False),               # JSON-string tasks
    ({}, {"tasks": [{"goal": "g", "request_overrides": {"x": 1}}]}, False),
    ({}, {"tasks": [{"goal": "g", "fallback_providers": ["openrouter"]}]}, False),
    ({}, {"tasks": [{"goal": "g", "base_url": "http://x"}]}, False),
    ({}, {"tasks": [{"goal": "g", "api_mode": "chat_completions"}]}, False),
    ({}, {"goal": "g", "provider": "openrouter"}, False),               # top-level legacy
    ({}, {"goal": "g", "request_overrides": {"x": 1}}, False),
])
def test_default_delegation_ok(cfg, args, ok):
    assert default_delegation_ok(args, load_config=lambda: cfg) is ok


def test_default_delegation_ok_fails_closed_on_config_error():
    def boom():
        raise RuntimeError("config unreadable")
    assert default_delegation_ok({"goal": "g"}, load_config=boom) is False


# --------------------------------------------------------------------------------------------------
# Amendment 1: MCP URL servers classified by host under the active predicate
# --------------------------------------------------------------------------------------------------

def _mcp_only(url, predicate=None):
    al = build_allowlist(FakeRegistry([("q", "mcp-s", _builtin_handler)]), mcp_configs={"s": {"url": url}},
                         mcp_tool_servers={}, plugin_tool_names=set(), predicate=predicate)
    return al.get("q")


@pytest.mark.parametrize("url,route", [
    ("http://127.0.0.1:8000/mcp", Route.ON_HOST), ("http://[::1]:8000/mcp", Route.ON_HOST),
    ("http://192.168.1.4/mcp", Route.BLOCK_MCP_URL), ("https://api.example.com/mcp", Route.BLOCK_MCP_URL),
    ("http://169.254.169.254/mcp", Route.BLOCK_MCP_URL), ("http://127.1/mcp", Route.BLOCK_MCP_URL),
    ("http://localhost\\@evil.com/mcp", Route.BLOCK_MCP_URL), ("", Route.BLOCK_MCP_URL),
])
def test_mcp_url_host_classification_default_on_host_predicate(url, route):
    assert _mcp_only(url).route is route


def test_mcp_url_uses_injected_predicate():
    from confidential_mode.tiers import AttestedPredicate, OnHostPredicate, Verdict

    class InTier:
        def classify(self, dest):
            assert dest.purpose == "mcp:s" and dest.base_url == "https://enclave.example/mcp"
            return Verdict(True, "fake in-tier", "enclave.example")
    info = _mcp_only("https://enclave.example/mcp", InTier())
    assert info.route is Route.ASK and info.reason == "fake in-tier"   # not blocked, still asked
    # attested predicate: a remote MCP host is not an attested profile -> blocked; localhost still on-host
    att = AttestedPredicate(["attested-tinfoil"], lambda p: Verdict(True, "ok", ""))
    assert _mcp_only("https://mcp.example.com/mcp", att).route is Route.BLOCK_MCP_URL
    assert _mcp_only("http://localhost:9/mcp", att).route is Route.ON_HOST
    # OnHostPredicate extra_hosts are honoured
    assert _mcp_only("http://mcpbox.lan/mcp", OnHostPredicate(extra_hosts=["mcpbox.lan"])).route is Route.ON_HOST
    assert _mcp_only("http://mcpbox.lan/mcp").route is Route.BLOCK_MCP_URL
    # Amendment 10: a private-range MCP host is on-host only when its exact address is listed
    assert _mcp_only("http://10.0.0.5:9/mcp", OnHostPredicate(extra_hosts=["10.0.0.5"])).route is Route.ON_HOST
    assert _mcp_only("http://10.0.0.6:9/mcp", OnHostPredicate(extra_hosts=["10.0.0.5"])).route is Route.BLOCK_MCP_URL

    class Raises:
        def classify(self, dest):
            raise RuntimeError("x")
    assert _mcp_only("https://mcp.example.com/mcp", Raises()).route is Route.BLOCK_MCP_URL


def test_mode_tools_are_plain_on_host_today():
    from confidential_mode.gate_tools import MODE_TOOLS
    assert MODE_TOOLS == {"terminal", "execute_code"} and MODE_TOOLS <= ON_HOST_TOOLS
    al = allowlist()
    assert all(al.get(n).mode is None and al.get(n).route is Route.ON_HOST for n in MODE_TOOLS)




# --------------------------------------------------------------------------------------------------
# Amendment 3 addendum: identity pinning, escaping
# --------------------------------------------------------------------------------------------------

class MutableRegistry(FakeRegistry):
    def get_entry(self, name):
        return next((e for e in self._entries if e.name == name), None)


def test_handler_or_toolset_swapped_after_lock_is_unclassified():
    reg = MutableRegistry(ENTRIES)
    al = build_allowlist(reg, mcp_configs=MCP_CONFIGS, mcp_tool_servers={}, plugin_tool_names=set())
    r = Rig(al=al)
    assert r.hook(tool_name="read_file", args={}, session_id="s") is None
    reg.get_entry("read_file").handler = lambda a, **k: "{}"          # swapped in place
    assert r.hook(tool_name="read_file", args={}, session_id="s")["action"] == "block"
    assert refused(r.run("read_file")) and r.ran() == []
    reg.get_entry("terminal").toolset = "evil"                       # toolset changed
    assert r.hook(tool_name="terminal", args={}, session_id="s")["action"] == "block"
    reg._entries = [e for e in reg._entries if e.name != "patch"]    # deregistered
    assert r.hook(tool_name="patch", args={}, session_id="s")["action"] == "block"


def test_mcp_server_repointed_after_lock_is_rejudged():
    cfgs = {"lh": {"url": "http://localhost:1/mcp"}}
    reg = MutableRegistry([("q", "mcp-lh", _builtin_handler)])
    al = build_allowlist(reg, mcp_configs=cfgs, mcp_tool_servers={}, plugin_tool_names=set())
    r = Rig(al=al)
    assert r.hook(tool_name="q", args={}, session_id="s") is None
    cfgs["lh"] = {"url": "https://mcp.example.com/mcp"}
    assert r.hook(tool_name="q", args={}, session_id="s")["action"] == "block"


def test_format_allowlist_escapes_control_characters():
    forged = "x\non-host (runs without asking): 99\n  web_search"
    al = allowlist(entries=ENTRIES + [(forged, "t", _builtin_handler), ("a\x1b[2Kb\u200b", "t", _builtin_handler)])
    text = format_allowlist(al)
    assert forged not in text and "\x1b" not in text and "\u200b" not in text
    assert "x\\non-host" in text
    assert len([ln for ln in text.splitlines() if ln.startswith("on-host (")]) == 1


def test_unlock_removes_only_its_own_locks_allowlist(tmp_path):
    """Second review, minor item: an unlock must not delete the allowlist a concurrent lock just wrote."""
    from confidential_mode.gate_tools import clear_persisted
    path = tmp_path / "allowlist.yaml"
    path.write_text(json.dumps({"version": 2, "lock_id": "NEW", "tools": [], "allowed": []}))
    clear_persisted(path, lock_id="OLD")
    assert path.exists()
    clear_persisted(path, lock_id="NEW")
    assert not path.exists()
    path.write_text("not json: [")
    clear_persisted(path, lock_id="OLD")                      # unreadable: removed
    assert not path.exists()
    path.write_text(json.dumps({"lock_id": "X"}))
    clear_persisted(path)                                      # lock state unreadable: removed
    assert not path.exists()



def test_choice_repr_checks_the_type_before_comparing():
    """Second review, minor item: a str subclass whose __eq__ lies is never stored verbatim."""
    from confidential_mode.gate_tools import _choice_repr

    class Liar(str):
        def __eq__(self, other):
            return True

        __hash__ = str.__hash__
    assert _choice_repr(Liar("hunter2")) == "other" and _choice_repr("once") == "once"
    assert _choice_repr("") == "" and _choice_repr(None) is None and _choice_repr(7) == "<int>"


# --------------------------------------------------------------------------------------------------
# Issue #1: classification by data flow, one table in code, the same table in docs/TOOL_CLASSES.md
# --------------------------------------------------------------------------------------------------

def _docs_table() -> dict[str, str]:
    """{tool: class} from the table in docs/TOOL_CLASSES.md (rows ``| name | class | evidence |``)."""
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "docs" / "TOOL_CLASSES.md").read_text(encoding="utf-8")
    out = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0].startswith("`") and cells[0].endswith("`"):
            out[cells[0].strip("`")] = cells[1]
    return out


def test_the_docs_table_equals_the_code_table():
    from confidential_mode.gate_tools_classify import BUILTIN_TOOL_CLASSES, DATA_CLASSES
    assert _docs_table() == dict(BUILTIN_TOOL_CLASSES)
    assert set(BUILTIN_TOOL_CLASSES.values()) <= set(DATA_CLASSES)
    assert len(BUILTIN_TOOL_CLASSES) == 73


def test_the_on_host_set_is_the_on_host_rows_of_the_table():
    from confidential_mode.gate_tools_classify import BUILTIN_TOOL_CLASSES
    assert ON_HOST_TOOLS == {n for n, c in BUILTIN_TOOL_CLASSES.items() if c == "on-host"}
    # shell, code execution and file tools keep their class
    assert {"terminal", "process_manage", "execute_code", "read_file", "write_file", "patch",
            "search_files"} <= ON_HOST_TOOLS
    # tools whose data stays on this machine run without a prompt
    assert {"kanban_list", "kanban_create", "read_terminal", "set_theme", "desktop_project", "todo_list",
            "yb_search_sticker"} <= ON_HOST_TOOLS
    # tools whose data leaves, and tools the audit could not settle, ask
    assert {"web_search", "desktop_preview", "drive_preview", "kanban_attach_url", "skill_view",
            "computer_use", "text_to_speech"}.isdisjoint(ON_HOST_TOOLS)


def test_each_route_names_the_data_class_it_came_from():
    from confidential_mode.gate_tools_classify import BUILTIN_TOOL_CLASSES
    entries = [(n, "x", _builtin_handler) for n in BUILTIN_TOOL_CLASSES] + [("brand_new_tool", "x", _builtin_handler)]
    al = allowlist(entries=entries, mcp_configs={})
    for name, cls in BUILTIN_TOOL_CLASSES.items():
        info = al.get(name)
        assert info.data_class == cls, name
        if name == "cronjob_manage":
            assert info.route is Route.BLOCK_CRON
        elif name == "delegate_task":
            assert info.route is Route.DELEGATE
        else:
            assert info.route is (Route.ON_HOST if cls == "on-host" else Route.ASK), name
    unknown = al.get("brand_new_tool")
    assert unknown.route is Route.ASK and unknown.data_class == "unknown"
    assert "not audited" in unknown.reason
    assert "off-host" in format_allowlist(al) and "unsettled" in format_allowlist(al) and "not audited" in format_allowlist(al)

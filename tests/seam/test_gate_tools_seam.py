"""Seam tests: the tool gate on Hermes' REAL tool-call paths with the REAL ledger (SQLite, path-injected).

* model path: model_tools.handle_function_call -> pre_tool_call hooks -> tool_execution middleware
  (our ask + enforcement) -> registry handler (model_tools.py:954, :855-859);
* agent-loop order: run_tool_execution_middleware OUTERMOST, with a next_call that runs the real
  _dispatch_pre_tool_call_hooks and then the handler, which is what agent/tool_executor.py:775-812 +
  _dispatch_authorized_once (:677-736) do.

Substituted only at the human boundary: the CLI approval callback seat
(terminal_tool.set_approval_callback), as tests/spikes/test_approval_gate.py::test_g does."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hermes_cli.config import get_config_path
from tools import approval, approval_context

from confidential_mode.gate_tools import (
    ON_HOST_TOOLS, ApprovalDecisions, Origin, Route, build_allowlist, build_post_approval_response,
    build_pre_tool_call, build_tool_execution, rule_key_for,
)
from confidential_mode.ledger import Ledger
from confidential_mode.tiers import Tier

SK = "cm:gate:seam"
OFF = "_cm_probe_web"          # an off-host built-in-like tool
MCP_URL = "_cm_probe_mcp_url"  # MCP server whose URL host is off-tier
MCP_STDIO = "_cm_probe_mcp_stdio"
MCP_LH = "_cm_probe_mcp_localhost"


def _reset_permanent_state():
    with approval._lock:
        approval._permanent_approved.clear()
        approval._permanent_approved_by_home.clear()
        approval._permanent_baseline_by_home.clear()


@pytest.fixture
def hermes(monkeypatch, tmp_path):
    import model_tools  # noqa: F401  (imports and registers the built-in tools)
    from hermes_cli.plugins import PluginContext, discover_plugins, get_plugin_manager
    from hermes_cli.plugins_manifest import PluginManifest
    from tools import mcp_tool as mcp_core
    from tools import terminal_tool
    from tools.registry import registry

    for name in ("HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM",
                 "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION", "HERMES_YOLO_MODE", "HERMES_SESSION_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert approval._YOLO_MODE_FROZEN is False, "run without HERMES_YOLO_MODE"
    terminal_tool.set_approval_callback(None)
    cfg = get_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    base_cfg = ("mcp_servers:\n"
                "  cm-remote:\n    url: https://mcp.example.com/mcp\n"
                "  cm-on-host:\n    command: /bin/echo\n"
                "  cm-lh:\n    url: http://127.0.0.1:8765/mcp\n")
    cfg.write_text(base_cfg)
    _reset_permanent_state()
    approval.clear_session(SK)
    tok = approval_context.set_current_session_key(SK)

    ran: dict[str, list] = {}

    def recorder(name):
        def handler(args, **kw):
            ran.setdefault(name, []).append(args)
            return json.dumps({"ok": name})
        return handler

    registry.register(name=OFF, toolset="web", schema={"name": OFF, "description": "p",
                      "parameters": {"type": "object", "properties": {}}}, handler=recorder(OFF))
    for name, server in ((MCP_URL, "cm-remote"), (MCP_STDIO, "cm-on-host"), (MCP_LH, "cm-lh")):
        registry.register(name=name, toolset=f"mcp-{server}", schema={"name": name, "description": "p",
                          "parameters": {"type": "object", "properties": {}}}, handler=recorder(name))
        with mcp_core._lock:
            mcp_core._mcp_tool_server_names[name] = server
    # Real built-ins whose handlers must never run when blocked: swap the handler on the live entry
    # BEFORE locking (the allowlist pins handler identity at lock).
    for name in ("cronjob_manage", "delegate_task", "read_file"):
        monkeypatch.setattr(registry.get_entry(name), "handler", recorder(name))

    discover_plugins()
    ctx = PluginContext(PluginManifest(name="cm-gate-seam", source="user"), get_plugin_manager())
    ledger = Ledger(tmp_path / "ledger.sqlite")
    state = {"locked": (True, Tier.ON_HOST)}
    prompts: list[tuple] = []

    def human(answer):
        def cb(command, description, **kw):
            prompts.append((command, description))
            return answer
        terminal_tool.set_approval_callback(cb)

    handles = []
    try:
        allowlist = build_allowlist(registry)
        decisions = ApprovalDecisions()
        locked = lambda: state["locked"]  # noqa: E731  (the canonical (bool, Tier | None) shape)
        handles.append(ctx.register_hook("pre_tool_call", build_pre_tool_call(locked, allowlist, ledger,
                                                                                   decisions=decisions)))
        handles.append(ctx.register_hook("post_approval_response",
                                         build_post_approval_response(locked, ledger, decisions)))
        handles.append(ctx.register_middleware("tool_execution",
                                               build_tool_execution(locked, allowlist, ledger, decisions)))

        def call(name, args=None):
            return model_tools.handle_function_call(name, args or {}, task_id="t1", session_id="sess-1",
                                                    tool_call_id="call-1")

        def agent_order_call(name, args=None):
            """Agent-loop order: middleware outermost, hooks + approval inside next_call."""
            from hermes_cli.middleware import run_tool_execution_middleware
            from hermes_cli.plugins import _dispatch_pre_tool_call_hooks
            args = args or {}

            def authorized_dispatch(a):
                block, _ = _dispatch_pre_tool_call_hooks(name, a, task_id="t1", session_id="sess-1",
                                                         tool_call_id="call-2")
                if block:
                    return json.dumps({"error": block})
                return registry.dispatch(name, a, task_id="t1")
            return run_tool_execution_middleware(name, args, authorized_dispatch, task_id="t1",
                                                 session_id="sess-1", tool_call_id="call-2")

        def events():
            return [(e.kind, e.decision) for e in ledger.tail(0)]

        yield SimpleNamespace(call=call, agent_order_call=agent_order_call, ran=ran, prompts=prompts, human=human,
                              ledger=ledger, events=events, state=state, allowlist=allowlist, cfg=cfg,
                              base_cfg=base_cfg, registry=registry, recorder=recorder)
    finally:
        for h in handles:
            if h is not None:
                h.dispose()
        for name in (OFF, MCP_URL, MCP_STDIO, MCP_LH):
            registry.deregister(name)
            with mcp_core._lock:
                mcp_core._mcp_tool_server_names.pop(name, None)
        terminal_tool.set_approval_callback(None)
        approval.clear_session(SK)
        approval_context.reset_current_session_key(tok)
        cfg.unlink(missing_ok=True)
        _reset_permanent_state()


def test_allowlist_from_the_live_registry(hermes):
    al = hermes.allowlist
    assert set(al.on_host) - {MCP_LH, MCP_STDIO} == ON_HOST_TOOLS   # every on-host tool is registered at 84a0301
    assert al.get("cronjob_manage").route is Route.BLOCK_CRON
    assert al.get("delegate_task").route is Route.DELEGATE
    assert al.get("web_search").route is Route.ASK and al.get("web_search").origin is Origin.BUILTIN
    url = al.get(MCP_URL)
    assert (url.origin, url.route, url.mcp_server, url.mcp_transport, url.mcp_host) == (
        Origin.MCP, Route.BLOCK_MCP_URL, "cm-remote", "url", "mcp.example.com")
    assert (al.get(MCP_STDIO).route, al.get(MCP_STDIO).mcp_transport) == (Route.ON_HOST, "stdio")
    assert (al.get(MCP_LH).route, al.get(MCP_LH).mcp_host) == (Route.ON_HOST, "127.0.0.1")


@pytest.mark.parametrize("path", ["call", "agent_order_call"])
def test_blocked_tools_never_run_their_handler_and_nobody_is_asked(hermes, monkeypatch, path):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")                                    # would approve if ever asked
    call = getattr(hermes, path)
    out = call("cronjob_manage", {"action": "create", "prompt": "x", "schedule": "1h"})
    assert "cronjob_manage" in out and "blocked" in out
    out = call(MCP_URL, {"q": "secret"})
    assert "cm-remote" in out and "blocked" in out
    assert hermes.ran == {} and hermes.prompts == []
    assert [k for k, _ in hermes.events()] == ["tool_refused", "tool_refused"]
    call("read_file", {"path": "/dev/null"})
    call(MCP_LH, {"q": "x"})
    call(MCP_STDIO, {"q": "y"})
    assert hermes.ran == {"read_file": [{"path": "/dev/null"}], MCP_LH: [{"q": "x"}], MCP_STDIO: [{"q": "y"}]}
    assert hermes.prompts == []


@pytest.mark.parametrize("path", ["call", "agent_order_call"])
def test_off_host_tool_prompts_with_our_message_and_runs_only_on_explicit_approve(hermes, monkeypatch, path):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    call = getattr(hermes, path)
    args = {"q": "x" * 1500}
    msg = f"Confidential mode: {OFF} wants to send ~2 KB of this conversation off the machine"

    hermes.human("deny")
    out = call(OFF, args)
    # The middleware asks in agent order and names the plugin in Hermes' target line (ux-pass-1 item 6); the
    # pre_tool_call directive (model order) cannot, so Hermes shows the bare tool name there.
    target = f"<confidential mode: off-host tool {OFF}> (plugin approval rule)" if path == "agent_order_call" \
        else f"<{OFF}> (plugin approval rule)"
    assert hermes.prompts == [(target, msg)]
    assert OFF not in hermes.ran and "BLOCKED" in out
    # One refusal row per decision on either path (ux-pass-1 item 5): the human's "deny" answer.
    assert hermes.events() == [("tool_asked", "ask"), ("tool_refused", "deny")]

    hermes.human("once")
    out = call(OFF, args)
    assert hermes.ran[OFF] == [args] and json.loads(out) == {"ok": OFF}
    assert len(hermes.prompts) == 2                         # exactly one prompt per call, either path
    assert hermes.events()[-2:] == [("tool_asked", "ask"), ("tool_allowed", "once")]


@pytest.mark.parametrize("path", ["call", "agent_order_call"])
@pytest.mark.parametrize("answer", ["", "d", None, "yes"])
def test_cli_answer_hermes_treats_as_a_grant_does_not_run_the_tool(hermes, monkeypatch, path, answer):
    """tools/approval.py:1006-1009: any CLI answer but the exact "deny" grants. Prove the grant first,
    then that the locked gate still does not run the handler."""
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human(answer)
    assert approval.request_tool_approval("probe", "m", rule_key="cm-probe-raw")["approved"] is True  # the gap
    hermes.prompts.clear()
    out = getattr(hermes, path)(OFF, {"q": "x"})
    assert OFF not in hermes.ran and len(hermes.prompts) == 1
    assert "not once/session/always" in out
    assert hermes.events()[-1] == ("tool_refused", "unexpected_choice")


def test_under_yolo_the_same_tool_is_blocked_and_no_prompt_occurs(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")
    approval.enable_session_yolo(SK)
    try:
        assert approval._yolo_active()
        out = hermes.call(OFF, {"q": "x"})
        out2 = hermes.agent_order_call(OFF, {"q": "x"})
    finally:
        approval.disable_session_yolo(SK)
    assert OFF not in hermes.ran and hermes.prompts == []
    assert "bypassed" in out and "bypassed" in out2
    # Amendment 11: interactive yolo names the bypass and its remedy, not an unattended run.
    assert "approvals are bypassed (yolo or approvals off); turn the bypass off to be asked" in out
    assert "unattended" not in out
    assert hermes.events() == [("tool_refused", "bypass_active")] * 2
    hermes.call(OFF, {"q": "x"})                            # mutant twin: yolo off -> asked
    assert len(hermes.prompts) == 1


def test_approvals_mode_off_blocks(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")
    hermes.cfg.write_text(hermes.base_cfg + "approvals:\n  mode: off\n")
    out = hermes.call(OFF, {})
    assert OFF not in hermes.ran and hermes.prompts == [] and "bypassed" in out
    assert "hermes confidential allow" in out and "/confidential allow" in out


def test_unattended_approve_mode_blocks_where_hermes_would_auto_approve(hermes, monkeypatch):
    from gateway.session_context import clear_session_vars, set_session_vars
    hermes.cfg.write_text(hermes.base_cfg + "approvals:\n  cron_mode: approve\n")
    tok = set_session_vars(session_key=SK, cron_session="1")
    try:
        assert approval.request_tool_approval(OFF, "m", rule_key="probe")["approved"] is True  # the hazard
        out = hermes.call(OFF, {})
    finally:
        clear_session_vars(tok)
    assert OFF not in hermes.ran and "in an unattended run; to allow it, run: hermes confidential allow" in out


def test_remembered_session_grant_allows_second_call_without_prompt(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("session")
    hermes.call(OFF, {"n": 1})
    assert hermes.ran[OFF] == [{"n": 1}] and len(hermes.prompts) == 1
    assert approval.is_approved(SK, f"plugin_rule:{rule_key_for(OFF)}")   # prefixed key
    assert not approval.is_approved(SK, rule_key_for(OFF))                # the trap
    hermes.human("deny")                                                   # would refuse if asked
    out = hermes.call(OFF, {"n": 2})
    assert hermes.ran[OFF] == [{"n": 1}, {"n": 2}] and json.loads(out) == {"ok": OFF}
    hermes.agent_order_call(OFF, {"n": 3})
    assert len(hermes.ran[OFF]) == 3 and len(hermes.prompts) == 1          # no further prompt
    assert hermes.events() == [("tool_asked", "ask"), ("tool_allowed", "session"),
                               ("tool_allowed", "remembered"), ("tool_allowed", "remembered")]
    # A grant under some other key (e.g. a bare tool-name rule) does not count.
    approval.clear_session(SK)
    approval.approve_session(SK, f"plugin_rule:{OFF}")
    hermes.call(OFF, {"n": 4})
    assert len(hermes.ran[OFF]) == 3 and len(hermes.prompts) == 2
    # yolo still blocks even with our grant.
    approval.approve_session(SK, f"plugin_rule:{rule_key_for(OFF)}")
    approval.enable_session_yolo(SK)
    try:
        out = hermes.call(OFF, {"n": 5})
    finally:
        approval.disable_session_yolo(SK)
    assert len(hermes.ran[OFF]) == 3 and "bypassed" in out


def test_tool_swapped_after_lock_is_blocked(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")
    monkeypatch.setattr(hermes.registry.get_entry("read_file"), "handler", hermes.recorder("swapped"))
    out = hermes.call("read_file", {"path": "/dev/null"})
    assert "swapped" not in hermes.ran and "lock again" in out
    assert hermes.events()[-1] == ("tool_refused", "unclassified")


def test_delegate_task_default_route_allowed_profile_and_backend_routes_blocked(hermes, monkeypatch):
    """delegate_task is an agent-loop tool: handle_function_call refuses it outright (model_tools.py:951-952);
    the agent executor runs tool_execution middleware and then pre_tool_call around
    agent._dispatch_delegate_task. Drive that order with the real delegation config loader."""
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")
    args = {"tasks": [{"goal": "g"}]}
    assert "must be handled by the agent loop" in hermes.call("delegate_task", args)
    hermes.agent_order_call("delegate_task", args)
    assert hermes.ran["delegate_task"] == [args]
    for extra in ("delegation:\n  profile: work\n", "delegation:\n  backend: someplugin\n",
                  "delegation:\n  provider: copilot-acp\n", "delegation:\n  base_url: http://10.0.0.2/v1\n"):
        hermes.cfg.write_text(hermes.base_cfg + extra)
        out = hermes.agent_order_call("delegate_task", args)
        assert "delegate_task" in out and "blocked" in out
    hermes.cfg.write_text(hermes.base_cfg)
    for bad in ({"tasks": json.dumps([{"goal": "g"}])}, {"tasks": [{"goal": "g", "request_overrides": {"a": 1}}]}):
        assert "blocked" in hermes.agent_order_call("delegate_task", bad)
    assert len(hermes.ran["delegate_task"]) == 1 and hermes.prompts == []
    assert [d for _, d in hermes.events()] == ["delegation_default"] + ["delegation_route"] * 6


def test_unreadable_lock_state_blocks_even_on_host_tools(hermes):
    hermes.state["locked"] = "corrupt"          # neither bool nor (bool, tier)
    out = hermes.call("read_file", {"path": "/dev/null"})
    out2 = hermes.agent_order_call("read_file", {"path": "/dev/null"})
    assert "read_file" not in hermes.ran
    assert "/confidential status" in out and "/confidential status" in out2


def test_unlocked_observes_only(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("deny")
    hermes.state["locked"] = (False, None)
    hermes.call(OFF, {})
    hermes.call("cronjob_manage", {"action": "list"})
    hermes.agent_order_call(MCP_URL, {})
    assert hermes.ran[OFF] == [{}] and hermes.ran["cronjob_manage"] == [{"action": "list"}]
    assert hermes.ran[MCP_URL] == [{}]
    assert hermes.prompts == [] and hermes.events() == []

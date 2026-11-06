"""Seam tests: the tool gate on Hermes' REAL model-tool-call path (model_tools.handle_function_call ->
pre_tool_call hooks -> request_tool_approval -> handler), the real registry, real MCP config loading
and the real bypass state. Substituted only at the human boundary: the CLI approval callback seat
(terminal_tool.set_approval_callback), as tests/spikes/test_approval_gate.py::test_g does."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hermes_cli.config import get_config_path
from tools import approval, approval_context

from confidential_mode.gate_tools import (
    LOCAL_TOOLS, Origin, Route, build_allowlist, build_post_approval_response, build_pre_tool_call, rule_key_for,
)

SK = "cm:gate:seam"
OFF = "_cm_probe_web"          # an off-machine built-in-like tool
MCP_URL = "_cm_probe_mcp_url"  # from an MCP server configured with url:
MCP_STDIO = "_cm_probe_mcp_stdio"
MCP_LH = "_cm_probe_mcp_localhost"


class Ledger:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)

    def kinds(self):
        return [e["kind"] for e in self.events]


def _reset_permanent_state():
    with approval._lock:
        approval._permanent_approved.clear()
        approval._permanent_approved_by_home.clear()
        approval._permanent_baseline_by_home.clear()


@pytest.fixture
def hermes(monkeypatch):
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
                "  cm-local:\n    command: /bin/echo\n"
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
    for name, server in ((MCP_URL, "cm-remote"), (MCP_STDIO, "cm-local"), (MCP_LH, "cm-lh")):
        registry.register(name=name, toolset=f"mcp-{server}", schema={"name": name, "description": "p",
                          "parameters": {"type": "object", "properties": {}}}, handler=recorder(name))
        with mcp_core._lock:
            mcp_core._mcp_tool_server_names[name] = server
    # Real built-ins whose handlers must never run when blocked: swap the handler on the live entry.
    for name in ("cronjob_manage", "delegate_task", "read_file"):
        monkeypatch.setattr(registry.get_entry(name), "handler", recorder(name))

    discover_plugins()
    ctx = PluginContext(PluginManifest(name="cm-gate-seam", source="user"), get_plugin_manager())
    ledger = Ledger()
    state = {"sealed": True}
    prompts: list[tuple] = []

    def human(answer):
        def cb(command, description, **kw):
            prompts.append((command, description))
            return answer
        terminal_tool.set_approval_callback(cb)

    handles = []
    try:
        allowlist = build_allowlist(registry)
        handles.append(ctx.register_hook("pre_tool_call", build_pre_tool_call(lambda: state["sealed"], allowlist, ledger)))
        handles.append(ctx.register_hook("post_approval_response", build_post_approval_response(lambda: state["sealed"],
                                                                                            ledger)))

        def call(name, args=None):
            return model_tools.handle_function_call(name, args or {}, task_id="t1", session_id="sess-1",
                                                    tool_call_id="call-1")
        yield SimpleNamespace(call=call, ran=ran, prompts=prompts, human=human, ledger=ledger, state=state,
                              allowlist=allowlist, cfg=cfg, base_cfg=base_cfg, registry=registry)
    finally:
        for h in handles:
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
    assert set(al.local) - {MCP_LH} == LOCAL_TOOLS          # every local tool is registered at 84a0301
    assert al.get("cronjob_manage").route is Route.BLOCK_CRON
    assert al.get("delegate_task").route is Route.DELEGATE
    assert al.get("web_search").route is Route.ASK and al.get("web_search").origin is Origin.BUILTIN
    # MCP identification through the real toolset naming + real mcp_servers config loading.
    url = al.get(MCP_URL)
    assert (url.origin, url.route, url.mcp_server, url.mcp_transport) == (Origin.MCP, Route.BLOCK_MCP_URL,
                                                                          "cm-remote", "url")
    stdio = al.get(MCP_STDIO)
    assert (stdio.route, stdio.mcp_transport) == (Route.ASK, "stdio")
    lh = al.get(MCP_LH)
    assert (lh.route, lh.mcp_host) == (Route.LOCAL, "127.0.0.1")


def test_blocked_tools_never_run_their_handler_and_nobody_is_asked(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")                                    # would approve if ever asked
    out = hermes.call("cronjob_manage", {"action": "create", "prompt": "x", "schedule": "1h"})
    assert "cronjob_manage" in out and "blocked" in out
    out = hermes.call(MCP_URL, {"q": "secret"})
    assert "cm-remote" in out and "blocked" in out
    assert hermes.ran == {} and hermes.prompts == []
    assert hermes.ledger.kinds() == ["tool_refused", "tool_refused"]
    # Local tool runs untouched.
    hermes.call("read_file", {"path": "/dev/null"})
    assert hermes.ran == {"read_file": [{"path": "/dev/null"}]} and hermes.prompts == []
    # localhost-URL MCP server counts as local (Amendment 1).
    hermes.call(MCP_LH, {"q": "x"})
    assert hermes.ran[MCP_LH] == [{"q": "x"}] and hermes.prompts == []


def test_off_machine_tool_prompts_with_our_message_and_runs_only_on_approve(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    args = {"q": "x" * 1500}
    msg = f"{OFF} wants to send ~2 KB of this conversation off the machine"

    hermes.human("deny")
    out = hermes.call(OFF, args)
    assert hermes.prompts == [(f"<{OFF}> (plugin approval rule)", msg)]
    assert OFF not in hermes.ran and "BLOCKED" in out
    assert hermes.ledger.kinds() == ["tool_asked", "tool_refused"]
    assert hermes.ledger.events[1]["decision"] == "deny"

    hermes.human("once")
    out = hermes.call(OFF, args)
    assert hermes.ran[OFF] == [args] and json.loads(out) == {"ok": OFF}
    assert hermes.prompts[-1] == (f"<{OFF}> (plugin approval rule)", msg)
    assert hermes.ledger.kinds()[-2:] == ["tool_asked", "tool_allowed"]
    # A stdio MCP tool takes the same ask path.
    out = hermes.call(MCP_STDIO, {})
    assert hermes.ran[MCP_STDIO] == [{}] and len(hermes.prompts) == 3


def test_under_yolo_the_same_tool_is_blocked_and_no_prompt_occurs(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("deny")
    approval.enable_session_yolo(SK)
    try:
        assert approval._yolo_active()
        out = hermes.call(OFF, {"q": "x"})
    finally:
        approval.disable_session_yolo(SK)
    assert OFF not in hermes.ran and hermes.prompts == []
    assert "bypassed" in out
    assert hermes.ledger.kinds() == ["tool_refused"] and hermes.ledger.events[0]["decision"] == "bypass_active"
    # Mutant twin: yolo off -> the human is asked.
    hermes.call(OFF, {"q": "x"})
    assert len(hermes.prompts) == 1


def test_approvals_mode_off_blocks(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")
    hermes.cfg.write_text(hermes.base_cfg + "approvals:\n  mode: off\n")
    out = hermes.call(OFF, {})
    assert OFF not in hermes.ran and hermes.prompts == [] and "bypassed" in out


def test_unattended_approve_mode_blocks_where_hermes_would_auto_approve(hermes, monkeypatch):
    # No CLI/gateway, cron context with cron_mode approve: Hermes would run the tool unasked.
    from gateway.session_context import clear_session_vars, set_session_vars
    hermes.cfg.write_text(hermes.base_cfg + "approvals:\n  cron_mode: approve\n")
    tok = set_session_vars(session_key=SK, cron_session="1")
    try:
        assert approval.request_tool_approval(OFF, "m", rule_key="probe")["approved"] is True  # the hazard
        out = hermes.call(OFF, {})
    finally:
        clear_session_vars(tok)
    assert OFF not in hermes.ran and "bypassed" in out


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
    assert len(hermes.prompts) == 1                                        # no second prompt
    assert hermes.ledger.kinds() == ["tool_asked", "tool_allowed", "tool_allowed"]
    assert [e["decision"] for e in hermes.ledger.events] == ["ask", "session", "remembered"]
    # yolo still blocks even with the grant.
    approval.enable_session_yolo(SK)
    try:
        out = hermes.call(OFF, {"n": 3})
    finally:
        approval.disable_session_yolo(SK)
    assert len(hermes.ran[OFF]) == 2 and "bypassed" in out


def test_delegate_task_default_route_allowed_profile_and_backend_routes_blocked(hermes, monkeypatch):
    """delegate_task is an agent-loop tool: handle_function_call refuses it outright (model_tools.py:951-952)
    and the agent executor fires pre_tool_call through _dispatch_pre_tool_call_hooks
    (agent/tool_executor.py:661-675), then runs agent._dispatch_delegate_task only when the block
    message is None. Drive that same function, with the real delegation config loader."""
    from hermes_cli.plugins import _dispatch_pre_tool_call_hooks
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("once")
    args = {"tasks": [{"goal": "g"}]}
    assert "must be handled by the agent loop" in hermes.call("delegate_task", args)
    hermes.ledger.events.clear()

    def gate():
        return _dispatch_pre_tool_call_hooks("delegate_task", args, task_id="t1", session_id="sess-1",
                                             tool_call_id="call-1")

    assert gate() == (None, None)                                  # default backend, inherit route
    hermes.cfg.write_text(hermes.base_cfg + "delegation:\n  profile: work\n")
    block, _ = gate()
    assert block and "delegate_task" in block and "blocked" in block
    hermes.cfg.write_text(hermes.base_cfg + "delegation:\n  backend: someplugin\n")
    assert gate()[0]
    hermes.cfg.write_text(hermes.base_cfg + "delegation:\n  provider: copilot-acp\n")
    assert gate()[0]
    hermes.cfg.write_text(hermes.base_cfg)
    assert gate()[0] is None
    assert hermes.prompts == []
    assert hermes.ledger.kinds() == ["tool_allowed", "tool_refused", "tool_refused", "tool_refused", "tool_allowed"]


def test_unsealed_observes_only(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    hermes.human("deny")
    hermes.state["sealed"] = False
    hermes.call(OFF, {})
    hermes.call("cronjob_manage", {"action": "list"})
    assert hermes.ran[OFF] == [{}] and hermes.ran["cronjob_manage"] == [{"action": "list"}]
    assert hermes.prompts == [] and hermes.ledger.events == []

"""Amendment 13: confidential.tools.ask (once_per_lock by default, each_call on request) through the REAL tool
gate on Hermes' real approval paths, on every surface: the interactive CLI, gateway chat (a pending approval
answered from another thread, as /approve does), a one-shot run, yolo, approvals off, an unattended platform
and cron. A lock grant is the plugin's own, holds the id of the answering row, ends with the lock and never
applies where Hermes would not ask a person (catalog rule 12)."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from hermes_cli.config import get_config_path
from tools import approval, approval_context

from confidential_mode.gate_tools import (
    ASK_EACH_CALL, ASK_ONCE_PER_LOCK, ApprovalDecisions, LockGrants, ask_mode_from, build_allowlist,
    build_post_approval_response, build_pre_tool_call, build_tool_execution,
)
from confidential_mode.ledger import Ledger
from confidential_mode.tiers import Tier

SK = "cm:ask:scope"
OFF = "_cm_probe_ask_scope"
SURFACE_ENV = ("HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM",
               "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION", "HERMES_YOLO_MODE", "HERMES_SESSION_KEY")


@pytest.fixture
def gate(monkeypatch, tmp_path):
    import model_tools  # noqa: F401
    from hermes_cli.plugins import PluginContext, discover_plugins, get_plugin_manager
    from hermes_cli.plugins_manifest import PluginManifest
    from tools import terminal_tool
    from tools.registry import registry

    for name in SURFACE_ENV:
        monkeypatch.delenv(name, raising=False)
    assert approval._YOLO_MODE_FROZEN is False, "run without HERMES_YOLO_MODE"
    terminal_tool.set_approval_callback(None)
    cfg = get_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("model:\n  provider: custom\n")
    approval.clear_session(SK)
    tok = approval_context.set_current_session_key(SK)
    ran: list = []
    registry.register(name=OFF, toolset="web", schema={"name": OFF, "description": "p",
                      "parameters": {"type": "object", "properties": {}}},
                      handler=lambda args, **kw: ran.append(args) or json.dumps({"ok": 1}))
    discover_plugins()
    ctx = PluginContext(PluginManifest(name="cm-ask-scope", source="user"), get_plugin_manager())
    ledger = Ledger(tmp_path / "ledger.sqlite")
    mode = {"value": ASK_ONCE_PER_LOCK}
    grants = LockGrants()
    allowlist = build_allowlist(registry)
    allowlist.lock_id = "lock-1"
    decisions = ApprovalDecisions()
    locked = lambda: (True, Tier.ON_HOST)  # noqa: E731
    prompts: list = []
    kw = dict(lock_grants=grants, ask_mode=lambda: mode["value"])
    handles = [
        ctx.register_hook("pre_tool_call", build_pre_tool_call(locked, allowlist, ledger, decisions=decisions, **kw)),
        ctx.register_hook("post_approval_response", build_post_approval_response(locked, ledger, decisions)),
        ctx.register_middleware("tool_execution", build_tool_execution(locked, allowlist, ledger, decisions, **kw)),
    ]

    def cli(answer):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")

        def cb(command, description, **_):
            prompts.append(description)
            return answer
        terminal_tool.set_approval_callback(cb)

    def gateway(answer):
        """A gateway chat: Hermes parks a pending approval and notifies; the person answers with /approve."""
        monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")

        def notify(data):
            prompts.append(data.get("description") or data)
            threading.Timer(0.05, lambda: approval.resolve_gateway_approval(SK, answer)).start()
        approval.register_gateway_notify(SK, notify)

    calls = {"n": 0}

    def call(name=OFF, session_id="s"):
        calls["n"] += 1
        return model_tools.handle_function_call(name, {"q": calls["n"]}, task_id="t", session_id=session_id,
                                                tool_call_id=f"c{calls['n']}")

    def rows(kind=None):
        return [e for e in ledger.tail(0) if kind is None or e.kind == kind]

    try:
        yield SimpleNamespace(call=call, ran=ran, prompts=prompts, cli=cli, gateway=gateway, rows=rows, mode=mode,
                              grants=grants, allowlist=allowlist, cfg=cfg, monkeypatch=monkeypatch)
    finally:
        for h in handles:
            if h is not None:
                h.dispose()
        registry.deregister(OFF)
        approval.unregister_gateway_notify(SK)
        terminal_tool.set_approval_callback(None)
        approval.clear_session(SK)
        approval_context.reset_current_session_key(tok)
        cfg.unlink(missing_ok=True)


def _granted_once_on_cli(gate):
    gate.cli("once")
    gate.call()
    gate.call()
    assert len(gate.ran) == 2 and len(gate.prompts) == 1


def test_the_default_mode_and_a_bad_value():
    assert ask_mode_from({}) == ASK_ONCE_PER_LOCK
    assert ask_mode_from({"confidential": {"tools": {"ask": "each_call"}}}) == ASK_EACH_CALL
    assert ask_mode_from({"confidential": {"tools": {"ask": "sometimes"}}}) == ASK_EACH_CALL   # fail closed
    assert ask_mode_from({"confidential": {"tools": {"ask": None}}}) == ASK_EACH_CALL


def test_interactive_cli_asks_once_per_tool_per_lock_and_records_the_answering_row(gate):
    _granted_once_on_cli(gate)
    assert "allowing once covers _cm_probe_ask_scope in this conversation until this profile is unlocked" in gate.prompts[0]
    answer = [e for e in gate.rows("tool_allowed") if e.decision == "once"]
    granted = [e for e in gate.rows("tool_allowed") if e.decision == "lock_grant"]
    assert len(answer) == 1 and len(granted) == 1
    assert granted[0].detail["grant_row"] == answer[0].id


def test_gateway_chat_asks_once_per_tool_per_lock(gate):
    gate.gateway("once")
    gate.call()
    gate.call()
    assert len(gate.ran) == 2 and len(gate.prompts) == 1
    assert [e.decision for e in gate.rows("tool_allowed")] == ["once", "lock_grant"]


def test_a_grant_covers_only_the_conversation_that_answered(gate):
    """Another chat or user (another Hermes approval session key) and a subagent (another session id) in the
    same process and lock each ask again; the conversation that answered does not."""
    _granted_once_on_cli(gate)
    other = approval_context.set_current_session_key("cm:ask:scope:other-chat")
    try:
        gate.call()
    finally:
        approval_context.reset_current_session_key(other)
    assert len(gate.prompts) == 2, "a grant from one chat covered another chat"
    gate.call(session_id="s-subagent")
    assert len(gate.prompts) == 3, "a grant from the parent covered a subagent"
    gate.call()
    assert len(gate.prompts) == 3 and len(gate.ran) == 5
    granted = [e for e in gate.rows("tool_allowed") if e.decision == "lock_grant"]
    assert len(granted) == 2 and len({e.detail["grant_row"] for e in granted}) == 1


def test_the_grant_ends_with_the_lock(gate):
    _granted_once_on_cli(gate)
    gate.allowlist.lock_id = "lock-2"          # unlock, then lock again: a new lock identity
    gate.call()
    assert len(gate.prompts) == 2 and len(gate.ran) == 3
    assert gate.grants.names("lock-1") == []    # the earlier lock's grant is gone


def test_a_revoke_drops_the_grant(gate):
    _granted_once_on_cli(gate)
    assert gate.grants.drop({OFF}) == [OFF]
    gate.call()
    assert len(gate.prompts) == 2


def test_a_denial_grants_nothing(gate):
    gate.cli("deny")
    gate.call()
    gate.call()
    assert gate.ran == [] and len(gate.prompts) == 2 and gate.grants.names("lock-1") == []


def test_each_call_keeps_the_old_behaviour(gate):
    gate.mode["value"] = ASK_EACH_CALL
    gate.cli("once")
    gate.call()
    gate.call()
    assert len(gate.ran) == 2 and len(gate.prompts) == 2
    assert "allowing once covers" not in gate.prompts[0]
    assert gate.grants.names("lock-1") == []


def test_session_and_always_keep_hermes_meaning(gate):
    gate.cli("session")
    gate.call()
    gate.call()
    assert len(gate.prompts) == 1 and gate.grants.names("lock-1") == []      # Hermes remembers, not the plugin
    assert [e.decision for e in gate.rows("tool_allowed")] == ["session", "remembered"]


def _yolo(gate):
    approval.enable_session_yolo(SK)


def _approvals_off(gate):
    gate.cfg.write_text("model:\n  provider: custom\napprovals:\n  mode: off\n")


def _one_shot(gate):
    gate.monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")


def _cron(gate):
    """Hermes' cron runner binds the session context (gateway.session_context), which wins over the
    environment once any session context has been bound in the process."""
    from gateway.session_context import set_session_vars
    gate.session_tokens = set_session_vars(session_key=SK, cron_session="1")


def _unattended_platform(gate):
    from gateway.session_context import set_session_vars
    gate.monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    gate.monkeypatch.setenv("HERMES_EXEC_ASK", "1")
    gate.session_tokens = set_session_vars(session_key=SK, platform="webhook")


@pytest.mark.parametrize("bypass", [_yolo, _approvals_off, _one_shot, _cron, _unattended_platform],
                         ids=["yolo", "approvals_off", "one_shot", "cron", "unattended_platform"])
def test_a_lock_grant_never_applies_where_nobody_is_asked(gate, bypass):
    _granted_once_on_cli(gate)
    gate.session_tokens = None
    bypass(gate)
    try:
        out = gate.call()
    finally:
        approval.disable_session_yolo(SK)
        if gate.session_tokens is not None:
            from gateway.session_context import clear_session_vars
            clear_session_vars(gate.session_tokens)
    assert len(gate.ran) == 2, "the granted tool did not run under the bypass"
    assert "blocked" in out and len(gate.prompts) == 1
    assert gate.rows("tool_refused")[-1].decision == "bypass_active"

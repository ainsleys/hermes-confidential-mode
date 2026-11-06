"""C0 follow-up spike: ``ctx.ask_choice`` as the consent primitive for a slash-command-initiated
pin update (``/confidential pins approve``), since ``request_tool_approval`` returns
``approval_required`` when no agent turn is running (see test_approval_gate.py::test_c / test_h).

Real Hermes code at 84a0301 throughout. Substituted only at the human boundary:
  * gateway: a text-only platform adapter whose ``send`` records what the user would see, and the
    user's reply injected through the adapter's real ``handle_message`` (the same harness as Hermes'
    tests/gateway/test_plugin_command_choice.py);
  * CLI: the clarify panel callback (``cli._clarify_callback``), as in Hermes'
    tests/hermes_cli/test_plugin_ask_choice.py.
"""
from __future__ import annotations

import asyncio
import inspect
import threading
import time
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from hermes_cli.config import get_config_path
from tools import approval, approval_context

QUESTION = (
    "Approve confidential pin update?\n"
    "Vendor: tinfoil\n"
    "Release: v0.4.2 (tinfoilsh/confidential-model-router)\n"
    "Old fingerprint: ab12cd34ef56\n"
    "New fingerprint: ffee99887766"
)
CHOICES = [
    {"value": "approve", "label": "Approve", "description": "pin the new enclave measurement"},
    {"value": "deny", "label": "Deny", "description": "keep the current pin"},
]
SHOWN = ["Approve — pin the new enclave measurement", "Deny — keep the current pin"]


# --------------------------------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------------------------------

@pytest.fixture
def hermes(monkeypatch):
    from hermes_cli.plugins import PluginContext, discover_plugins, get_plugin_manager
    from hermes_cli.plugins_manifest import PluginManifest

    for name in ("HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM",
                 "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION", "HERMES_SESSION_KEY"):
        monkeypatch.delenv(name, raising=False)
    cfg = get_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.unlink(missing_ok=True)
    discover_plugins()
    mgr = get_plugin_manager()
    ctx = PluginContext(PluginManifest(name="spike-askchoice", source="user"), mgr)
    approval_events = []
    handles = [ctx.register_hook(h, (lambda h: lambda **kw: approval_events.append(h))(h))
               for h in ("pre_approval_request", "post_approval_response")]
    try:
        yield SimpleNamespace(ctx=ctx, cfg=cfg, approval_events=approval_events,
                              write_cfg=lambda text: cfg.write_text(text))
    finally:
        for h in handles:
            h.dispose()
        cfg.unlink(missing_ok=True)


async def wait_until(pred, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met in time")


def _text_adapter_cls():
    from gateway.config import Platform, PlatformConfig
    from gateway.platforms.base import BasePlatformAdapter, SendResult

    class TextAdapter(BasePlatformAdapter):
        """A chat with no native card: the base ``send_clarify`` numbered list is what the user sees."""

        def __init__(self):
            super().__init__(PlatformConfig(enabled=True, token="t"), Platform.TELEGRAM)
            self.sent = []

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        async def send(self, chat_id, content, reply_to=None, metadata=None):
            self.sent.append(content)
            return SendResult(success=True, message_id=str(len(self.sent)))

        async def get_chat_info(self, chat_id):
            return {"id": chat_id, "type": "private"}

    return TextAdapter


def _source():
    from gateway.config import Platform
    from gateway.session import SessionSource
    return SessionSource(platform=Platform.TELEGRAM, chat_id="c1", chat_type="dm", user_id="u1")


def _runner(adapter):
    """A GatewayRunner with only its state stubbed (same shape as Hermes' own gateway test)."""
    from gateway.config import GatewayConfig, Platform, PlatformConfig
    from gateway.run import GatewayRunner
    from gateway.session import SessionEntry, build_session_key
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(platforms={Platform.TELEGRAM: PlatformConfig(enabled=True, token="t")})
    runner.adapters = {Platform.TELEGRAM: adapter}
    runner._voice_mode = {}
    runner.hooks = SimpleNamespace(emit=AsyncMock(), emit_collect=AsyncMock(return_value=[]), loaded_hooks=False)
    entry = SessionEntry(session_key=build_session_key(_source()), session_id="sess-1", created_at=datetime.now(),
                         updated_at=datetime.now(), platform=Platform.TELEGRAM, chat_type="dm")
    runner.session_store = MagicMock()
    runner.session_store.get_or_create_session.return_value = entry
    runner.session_store.load_transcript.return_value = []
    runner.session_store.has_any_sessions.return_value = True
    runner._running_agents, runner._pending_messages, runner._pending_approvals = {}, {}, {}
    runner._session_db = None
    runner._is_user_authorized = lambda _source: True
    runner._set_session_env = lambda _context: None
    runner._emit_gateway_run_progress = AsyncMock()
    return runner


def _event(text):
    from gateway.platforms.event import MessageEvent, MessageType
    return MessageEvent(text=text, message_type=MessageType.TEXT, source=_source(), message_id=text)


# --------------------------------------------------------------------------------------------------
# (a) signature and return contract
# --------------------------------------------------------------------------------------------------

def test_a_signature_and_return_contract(hermes):
    from hermes_cli.plugin_choices import ask_choice, bind_asker
    from hermes_cli.plugins import PluginContext
    from tools.clarify_gateway import get_clarify_timeout, resolve_clarify_timeout

    assert str(inspect.signature(PluginContext.ask_choice)) == \
        "(self, question: 'str', choices: 'list') -> 'Optional[str]'"

    asked = []

    def asker(answer):
        def ask(question, labels):
            asked.append((question, labels))
            return answer
        return ask

    # A pick returns the choice's VALUE; the asker sees the question verbatim (multi-line kept) and
    # "label — description" for dict choices (plugin_choices.py:59-71, 80-95).
    with bind_asker(asker("Approve — pin the new enclave measurement")):
        assert hermes.ctx.ask_choice(QUESTION, CHOICES) == "approve"
    assert asked[-1] == (QUESTION, SHOWN)
    # Typed label or value, any case, also counts.
    for typed, want in (("deny", "deny"), ("APPROVE", "approve"), ("Deny", "deny")):
        with bind_asker(asker(typed)):
            assert ask_choice(QUESTION, CHOICES) == want
    # Anything else -> None: free prose, the 'skip' sentinel, empty, asker None (cancel / timeout /
    # undeliverable all reach ask_choice as None or a non-matching sentinel).
    for answer in ("yes", "approve it", "\x00skipped", "\x00cancelled", "", None,
                   "[user did not respond within 60m]", "[clarify prompt could not be delivered]"):
        with bind_asker(asker(answer)):
            assert ask_choice(QUESTION, CHOICES) is None, answer
    # No asker bound (hook, cron, plain call) -> None, no raise; no choices -> None without asking.
    assert ask_choice(QUESTION, CHOICES) is None
    n = len(asked)
    with bind_asker(asker("Approve")):
        assert ask_choice(QUESTION, []) is None
    assert len(asked) == n
    # Called on an event loop (an async handler) -> None with a warning, asker never called.
    async def on_loop():
        with bind_asker(asker("Approve")):
            return ask_choice(QUESTION, CHOICES)
    assert asyncio.run(on_loop()) is None and len(asked) == n
    # An asker that raises propagates (ask_choice does not catch).
    def boom(q, l):
        raise RuntimeError("surface died")
    with bind_asker(boom), pytest.raises(RuntimeError):
        ask_choice(QUESTION, CHOICES)

    # The wait is the clarify timeout: default 3600 s, agent.clarify_timeout / legacy clarify.timeout,
    # <= 0 means unlimited (tools/clarify_gateway.py:283-306).
    assert get_clarify_timeout() == 3600
    assert resolve_clarify_timeout({"agent": {"clarify_timeout": 120}}) == 120
    assert resolve_clarify_timeout({"clarify": {"timeout": 0}, "agent": {"clarify_timeout": 5}}) == 0


# --------------------------------------------------------------------------------------------------
# (b) + (e) gateway path, no agent turn running: asker bound, handler blocks, answer is routed
# --------------------------------------------------------------------------------------------------

def _run_gateway_scenario(hermes, replies, *, clarify_timeout=None):
    """Send /spike-pin through the real GatewayRunner._handle_message; the plugin handler calls
    ctx.ask_choice. ``replies`` are typed by the user after the prompt appears."""
    from tools import clarify_gateway

    if clarify_timeout is not None:
        hermes.write_cfg(f"agent:\n  clarify_timeout: {clarify_timeout}\n")
    state = {"handler_thread": None, "returned": threading.Event(), "turn_running": None, "notifier": None}

    def handler(raw_args, session_key=None):
        state["handler_thread"] = threading.current_thread().name
        state["turn_running"] = approval.has_blocking_approval(session_key or "")
        state["notifier"] = approval._gateway_notify_cb(session_key or "")
        choice = hermes.ctx.ask_choice(QUESTION, CHOICES)
        state["returned"].set()
        return f"PIN={choice}"

    reg = hermes.ctx.register_command("spike-pin", handler, description="spike")

    async def scenario():
        adapter = _text_adapter_cls()()
        runner = _runner(adapter)
        adapter.set_message_handler(runner._handle_message)
        await adapter.handle_message(_event("/spike-pin"))
        await wait_until(lambda: any("Old fingerprint" in s for s in adapter.sent))
        prompt = next(s for s in adapter.sent if "Old fingerprint" in s)
        await asyncio.sleep(0.5)
        blocked = not state["returned"].is_set() and not any(s.startswith("PIN=") for s in adapter.sent)
        pending = clarify_gateway.has_pending(build_key())
        state["session_active_while_blocked"] = build_key() in adapter._active_sessions
        for text in replies:
            await adapter.handle_message(_event(text))
            await asyncio.sleep(0.2)
        await wait_until(lambda: any(s.startswith("PIN=") for s in adapter.sent), timeout=15)
        return adapter.sent, prompt, blocked, pending

    try:
        sent, prompt, blocked, pending = asyncio.run(scenario())
    finally:
        reg.dispose()
    return SimpleNamespace(sent=sent, prompt=prompt, blocked=blocked, pending=pending, **state)


def build_key():
    from gateway.session import build_session_key
    return build_session_key(_source())


def test_b_e_gateway_no_turn_blocks_until_user_picks(hermes):
    r = _run_gateway_scenario(hermes, ["1"])
    # No agent turn: no approval notifier exists, so request_tool_approval would NOT have worked here.
    assert r.notifier is None
    # The handler ran off the event loop (gateway executor thread) and was blocked in ask_choice
    # while the prompt sat in the chat; the clarify entry was registered for this session.
    assert r.handler_thread != threading.main_thread().name
    assert r.blocked is True and r.pending is True
    # The chat is held by the running command (adapter busy guard), so the answer must take the
    # busy-session clarify bypass (gateway/platforms/base.py:4021-4039) -- and it does.
    assert r.session_active_while_blocked is True
    # What the user sees on a text adapter (base send_clarify, gateway/platforms/base.py:2830-2857):
    assert r.prompt == (
        "❓ " + QUESTION + "\n\n"
        "  1. Approve — pin the new enclave measurement\n"
        "  2. Deny — keep the current pin\n\n"
        "Reply with the number, the option text, or your own answer."
    )
    # The typed "1" was routed to the clarify text-intercept although the command still held the chat.
    assert [s for s in r.sent if s.startswith("PIN=")] == ["PIN=approve"]
    assert hermes.approval_events == []        # (d) no approval hooks


def test_b_e_gateway_typed_label_prose_and_timeout(hermes):
    assert [s for s in _run_gateway_scenario(hermes, ["deny"]).sent if s.startswith("PIN=")] == ["PIN=deny"]
    # Free prose is accepted as "your own answer" by the text prompt, and ask_choice maps it to None.
    assert [s for s in _run_gateway_scenario(hermes, ["sure, go ahead"]).sent if s.startswith("PIN=")] \
        == ["PIN=None"]
    # An out-of-range number: on the text prompt (awaiting_text) it is also free text -> None.
    assert [s for s in _run_gateway_scenario(hermes, ["7"]).sent if s.startswith("PIN=")] == ["PIN=None"]
    # Silence past the clarify timeout -> None (deny), with no reply typed.
    t0 = time.monotonic()
    r = _run_gateway_scenario(hermes, [], clarify_timeout=1)
    assert [s for s in r.sent if s.startswith("PIN=")] == ["PIN=None"]
    assert time.monotonic() - t0 < 10


def test_b_no_asker_returns_none_not_raise(hermes):
    from hermes_cli.plugin_command_dispatch import invoke_plugin_command
    from hermes_cli.plugins import invoke_hook

    seen = []
    reg = hermes.ctx.register_command("spike-pin2", lambda raw: f"PIN={hermes.ctx.ask_choice(QUESTION, CHOICES)}")
    try:
        from hermes_cli.plugins import get_plugin_command_handler
        assert invoke_plugin_command(get_plugin_command_handler("spike-pin2"), "") == "PIN=None"
    finally:
        reg.dispose()
    # Inside a hook callback (no surface binds an asker there): None.
    h = hermes.ctx.register_hook("pre_tool_call", lambda **kw: seen.append(hermes.ctx.ask_choice(QUESTION, CHOICES)))
    try:
        invoke_hook("pre_tool_call", tool_name="x", args={})
    finally:
        h.dispose()
    assert seen == [None]


# --------------------------------------------------------------------------------------------------
# (c) CLI path (in-process classic CLI; the clarify panel is the human boundary)
# --------------------------------------------------------------------------------------------------

def test_c_cli_in_process_uses_clarify_panel(hermes, monkeypatch, capsys):
    from cli import HermesCLI

    shown = []

    def panel(answer_index, outcome="submitted"):
        def cb(questions):
            shown.append(questions)
            if answer_index is None:
                return {"answers": {}, "outcome": outcome}
            return {"answers": {questions[0]["qid"]: questions[0]["choices"][answer_index]}, "outcome": outcome}
        return cb

    reg = hermes.ctx.register_command("spike-pin", lambda raw: f"PIN={hermes.ctx.ask_choice(QUESTION, CHOICES)}")
    monkeypatch.setattr("hermes_cli.gateway_side.connection_for", lambda _cli: None)  # off-gateway dispatch
    try:
        cli = HermesCLI.__new__(HermesCLI)
        cli.session_id = "s1"
        cli._clarify_callback = panel(0)
        cli._run_plugin_slash_command("/spike-pin", "")
        assert "PIN=approve" in capsys.readouterr().out
        assert shown[-1] == [{"qid": "q0", "question": QUESTION, "choices": SHOWN, "multi_select": False}]
        cli._clarify_callback = panel(1)
        cli._run_plugin_slash_command("/spike-pin", "")
        assert "PIN=deny" in capsys.readouterr().out
        # Panel timed out / cancelled with nothing locked -> None.
        for outcome in ("timed_out", "cancelled"):
            cli._clarify_callback = panel(None, outcome)
            cli._run_plugin_slash_command("/spike-pin", "")
            assert "PIN=None" in capsys.readouterr().out
        # CAVEAT: clarify_asker ignores ``outcome`` (plugin_choices.py:47-55). A panel that returns a
        # locked answer with outcome 'timed_out' (cli_modal_mixin.py:1025-1028) still counts as a pick.
        cli._clarify_callback = panel(0, "timed_out")
        cli._run_plugin_slash_command("/spike-pin", "")
        assert "PIN=approve" in capsys.readouterr().out
    finally:
        reg.dispose()
    assert hermes.approval_events == []


# --------------------------------------------------------------------------------------------------
# (d) bypass states never auto-pick; no approval hooks
# --------------------------------------------------------------------------------------------------

def test_d_no_bypass_no_auto_pick_no_approval_hooks(hermes, monkeypatch):
    from gateway.session_context import clear_session_vars, set_session_vars
    from gateway.session_finite import finite_turn_scope
    from hermes_cli.plugin_choices import bind_asker

    asked = []

    def human(question, labels):
        asked.append(question)
        return "Deny"

    sk = "spike:askchoice"
    hermes.write_cfg("approvals:\n  mode: off\n  cron_mode: approve\n  unattended_mode: approve\n"
                     "  single_query_mode: approve\n")
    approval.enable_session_yolo(sk)
    tok = approval_context.set_current_session_key(sk)
    vars_tok = set_session_vars(session_key=sk, cron_session="1", platform="webhook")
    monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
    try:
        assert approval._yolo_active() and approval_context._get_approval_mode() == "off"
        assert approval_context._is_cron_approval_context()
        with finite_turn_scope(True, unattended=True), bind_asker(human):
            assert hermes.ctx.ask_choice(QUESTION, CHOICES) == "deny"   # the human was still asked
        # With nobody to ask, every bypass state still yields None -- never an automatic "approve".
        with finite_turn_scope(True, unattended=True):
            assert hermes.ctx.ask_choice(QUESTION, CHOICES) is None
    finally:
        clear_session_vars(vars_tok)
        approval_context.reset_current_session_key(tok)
        approval.clear_session(sk)
    assert asked == [QUESTION]
    assert hermes.approval_events == []
    # Source-level: plugin_choices never touches the approval module.
    import hermes_cli.plugin_choices as pc
    src = inspect.getsource(pc)
    assert "approval" not in src.replace("approval prompt", "")

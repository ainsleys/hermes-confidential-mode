"""Seam tests for confidential_mode.consent on the REAL gateway ask_choice path: a plugin slash
command sent through GatewayRunner._handle_message with no agent turn running, the prompt rendered
by the base adapter's send_clarify, the user's reply injected through the adapter's real
handle_message (same harness as tests/spikes/test_ask_choice.py). Fakes: the PinStore and the
ledger (W2/W1 own the real ones) and the text platform adapter's transport."""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from hermes_cli.config import get_config_path

from confidential_mode.consent import ConsentContextError, allow_tool, approve_pending_pin
from confidential_mode.gate_tools import build_allowlist


@dataclass(frozen=True)
class PendingPin:
    vendor: str
    router_repo: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None
    previous: str | None


PIN = PendingPin("tinfoil", "tinfoilsh/confidential-model-router", "c0de" * 8, "e1c1" * 8, "v0.4.2", "ab12cd34ef56")
PIN_B = replace(PIN, code_fingerprint="bad0" * 8, release_tag="v0.4.3")


class FakeStore:
    def __init__(self, pending):
        self._pending, self.applied, self._lock = pending, [], threading.Lock()

    def pending(self):
        with self._lock:
            return self._pending

    def swap(self, pending):
        with self._lock:
            self._pending = pending

    def apply(self, pending):
        with self._lock:
            self.applied.append(pending)
            self._pending = None
        return SimpleNamespace(release_tag=pending.release_tag, approved_at="2026-11-06T00:00:00Z")


class Ledger:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)

    def kinds(self):
        return [e["kind"] for e in self.events]


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
    ctx = PluginContext(PluginManifest(name="cm-consent-seam", source="user"), get_plugin_manager())
    approval_events = []
    handles = [ctx.register_hook(h, (lambda h: lambda **kw: approval_events.append(h))(h))
               for h in ("pre_approval_request", "post_approval_response")]
    try:
        yield SimpleNamespace(ctx=ctx, cfg=cfg, approval_events=approval_events)
    finally:
        for h in handles:
            h.dispose()
        cfg.unlink(missing_ok=True)


# ---- the gateway harness (tests/spikes/test_ask_choice.py) --------------------------------------

def _text_adapter_cls():
    from gateway.config import Platform, PlatformConfig
    from gateway.platforms.base import BasePlatformAdapter, SendResult

    class TextAdapter(BasePlatformAdapter):
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


async def _wait_until(pred, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met in time")


def run_command(hermes, command, body, prompt_marker, replies, *, during_wait=None, clarify_timeout=None):
    """Send /<command>; ``body(session_key, platform)`` runs inside the registered sync handler and
    returns the reply. ``during_wait`` runs after the prompt is shown and before any reply."""
    if clarify_timeout is not None:
        hermes.cfg.write_text(f"agent:\n  clarify_timeout: {clarify_timeout}\n")
    done = threading.Event()
    seen = {}

    def handler(raw_args, session_key=None, platform=None):
        seen.update(session_key=session_key, platform=platform, thread=threading.current_thread().name)
        try:
            return body(session_key, platform)
        finally:
            done.set()

    reg = hermes.ctx.register_command(command, handler, description="cm test")

    async def scenario():
        adapter = _text_adapter_cls()()
        adapter.set_message_handler(_runner(adapter)._handle_message)
        await adapter.handle_message(_event(f"/{command}"))
        await _wait_until(lambda: any(prompt_marker in s for s in adapter.sent))
        prompt = next(s for s in adapter.sent if prompt_marker in s)
        await asyncio.sleep(0.3)
        blocked = not done.is_set()
        if during_wait is not None:
            during_wait()
        for text in replies:
            await adapter.handle_message(_event(text))
            await asyncio.sleep(0.2)
        await _wait_until(lambda: done.is_set() and len(adapter.sent) >= 2, timeout=15)
        await asyncio.sleep(0.1)
        return adapter.sent, prompt, blocked

    try:
        sent, prompt, blocked = asyncio.run(scenario())
    finally:
        reg.dispose()
    replies_out = [s for s in sent if prompt_marker not in s]
    return SimpleNamespace(sent=sent, prompt=prompt, blocked=blocked, reply=replies_out[-1], **seen)


def pin_cmd(hermes, store, ledger, replies, **kw):
    return run_command(
        hermes, "cm-pin",
        lambda sk, platform: approve_pending_pin(hermes.ctx, store, ledger, session_key=sk or "",
                                                 session_id="sess-1", platform=platform or ""),
        "New code fingerprint", replies, **kw)


# ---- approve_pending_pin ------------------------------------------------------------------------

@pytest.mark.parametrize("answer", ["1", "approve", "Approve"])
def test_pin_applied_on_explicit_approve(hermes, answer):
    store, ledger = FakeStore(PIN), Ledger()
    r = pin_cmd(hermes, store, ledger, [answer])
    assert r.blocked is True and r.thread != threading.main_thread().name
    assert r.prompt == (
        "❓ Approve confidential pin update?\n"
        "Vendor: tinfoil\n"
        "Release: v0.4.2 (tinfoilsh/confidential-model-router)\n"
        "Old fingerprint: ab12cd34ef56\n"
        f"New code fingerprint: {'c0de' * 4}\n"
        f"New enclave fingerprint: {'e1c1' * 4}\n\n"
        "  1. Approve — pin the new enclave measurement\n"
        "  2. Deny — keep the current pin\n\n"
        "Reply with the number, the option text, or your own answer."
    )
    assert store.applied == [PIN]
    assert ledger.kinds() == ["pin_applied"]
    e = ledger.events[0]
    assert e["detail"]["raw_pick"] == "approve" and e["surface"] == "telegram" and e["session_id"] == "sess-1"
    assert e["detail"]["session_key"] == r.session_key and r.session_key
    assert r.reply.startswith("Pinned tinfoil build v0.4.2")
    assert hermes.approval_events == []        # ask_choice fires no approval hooks


@pytest.mark.parametrize("answer,raw", [("2", "deny"), ("deny", "deny"), ("sure, go ahead", None), ("7", None)])
def test_pin_denied_on_deny_prose_and_out_of_range(hermes, answer, raw):
    store, ledger = FakeStore(PIN), Ledger()
    r = pin_cmd(hermes, store, ledger, [answer])
    assert store.applied == [] and store.pending() == PIN
    assert ledger.kinds() == ["pin_denied"] and ledger.events[0]["detail"]["raw_pick"] == raw
    assert "denied" in r.reply and "current pin kept" in r.reply


def test_pin_denied_on_timeout(hermes):
    store, ledger = FakeStore(PIN), Ledger()
    t0 = time.monotonic()
    r = pin_cmd(hermes, store, ledger, [], clarify_timeout=1)
    assert time.monotonic() - t0 < 12
    assert store.applied == [] and ledger.kinds() == ["pin_denied"]
    assert ledger.events[0]["detail"]["raw_pick"] is None and ledger.events[0]["decision"] == "no_answer"
    assert r.reply.startswith("No answer")


def test_pin_not_applied_when_pending_changed_during_the_wait(hermes):
    store, ledger = FakeStore(PIN), Ledger()
    r = pin_cmd(hermes, store, ledger, ["1"], during_wait=lambda: store.swap(PIN_B))
    assert store.applied == [] and store.pending() == PIN_B
    assert ledger.kinds() == ["pin_denied"]
    assert ledger.events[0]["decision"] == "stale" and ledger.events[0]["detail"]["raw_pick"] == "approve"
    assert "changed while you were deciding" in r.reply
    # Cleared during the wait: also not applied.
    store, ledger = FakeStore(PIN), Ledger()
    pin_cmd(hermes, store, ledger, ["1"], during_wait=lambda: store.swap(None))
    assert store.applied == [] and ledger.events[0]["decision"] == "stale"


def test_no_pending_pin_asks_nobody(hermes):
    from hermes_cli.plugin_choices import bind_asker
    asked = []
    with bind_asker(lambda q, labels: asked.append(q) or "Approve"):
        out = approve_pending_pin(hermes.ctx, FakeStore(None), Ledger(), session_key="k", session_id="s", platform="cli")
    assert asked == [] and out == "No pin update is waiting for approval."


def test_surface_raising_or_absent_is_a_denial(hermes):
    from hermes_cli.plugin_choices import bind_asker

    def boom(q, labels):
        raise RuntimeError("surface died")
    store, ledger = FakeStore(PIN), Ledger()
    with bind_asker(boom):
        approve_pending_pin(hermes.ctx, store, ledger, session_key="k", session_id="s", platform="cli")
    assert store.applied == [] and ledger.kinds() == ["pin_denied"]
    assert "surface died" in ledger.events[0]["detail"]["error"]
    # No asker bound at all (hook, cron, plain call): None -> deny.
    store, ledger = FakeStore(PIN), Ledger()
    approve_pending_pin(hermes.ctx, store, ledger, session_key="k", session_id="s", platform="cli")
    assert store.applied == [] and ledger.kinds() == ["pin_denied"]


def test_bypass_states_do_not_auto_approve(hermes, monkeypatch):
    from gateway.session_context import clear_session_vars, set_session_vars
    from gateway.session_finite import finite_turn_scope
    from tools import approval, approval_context

    sk = "cm:consent:bypass"
    hermes.cfg.write_text("approvals:\n  mode: off\n  cron_mode: approve\n  unattended_mode: approve\n")
    approval.enable_session_yolo(sk)
    tok = approval_context.set_current_session_key(sk)
    vtok = set_session_vars(session_key=sk, cron_session="1", platform="webhook")
    store, ledger = FakeStore(PIN), Ledger()
    try:
        with finite_turn_scope(True, unattended=True):
            approve_pending_pin(hermes.ctx, store, ledger, session_key=sk, session_id="s", platform="webhook")
    finally:
        clear_session_vars(vtok)
        approval_context.reset_current_session_key(tok)
        approval.clear_session(sk)
    assert store.applied == [] and ledger.kinds() == ["pin_denied"]


def test_refuses_to_run_on_an_event_loop(hermes):
    from hermes_cli.plugin_choices import bind_asker
    store, ledger = FakeStore(PIN), Ledger()

    async def handler():
        with bind_asker(lambda q, labels: "Approve"):
            return approve_pending_pin(hermes.ctx, store, ledger, session_key="k", session_id="s", platform="x")
    with pytest.raises(ConsentContextError):
        asyncio.run(handler())
    assert store.applied == [] and ledger.events == []

    async def handler2():
        return allow_tool(hermes.ctx, None, ledger, "web_search")
    with pytest.raises(ConsentContextError):
        asyncio.run(handler2())


# ---- allow_tool -----------------------------------------------------------------------------------

def _allowlist():
    from tools.registry import registry
    import model_tools  # noqa: F401
    return build_allowlist(registry, mcp_configs={}, mcp_tool_servers={})


def tool_cmd(hermes, al, ledger, name, replies, **kw):
    return run_command(
        hermes, "cm-allow",
        lambda sk, platform: allow_tool(hermes.ctx, al, ledger, name, session_key=sk or "", session_id="sess-1",
                                        platform=platform or ""),
        f"Allow {name} while sealed?", replies, **kw)


def test_allow_tool_adds_on_allow_only(hermes):
    al, ledger = _allowlist(), Ledger()
    r = tool_cmd(hermes, al, ledger, "web_search", ["2"])
    assert not al.is_added("web_search") and ledger.kinds() == ["tool_refused"]
    assert "  1. Allow — " in r.prompt and "  2. Deny — " in r.prompt
    r = tool_cmd(hermes, al, ledger, "web_search", ["1"])
    assert al.is_added("web_search") and ledger.kinds() == ["tool_refused", "tool_allowed"]
    assert ledger.events[-1]["detail"]["raw_pick"] == "approve" and r.reply.endswith("added to the allowlist for this seal.")


def test_allow_tool_refuses_hard_blocked_and_local_without_asking(hermes):
    from hermes_cli.plugin_choices import bind_asker
    al, ledger, asked = _allowlist(), Ledger(), []
    with bind_asker(lambda q, labels: asked.append(q) or "Allow"):
        assert "cannot be allowed" in allow_tool(hermes.ctx, al, ledger, "cronjob_manage")
        assert "cannot be allowed" in allow_tool(hermes.ctx, al, ledger, "delegate_task")
        assert "already runs without asking" in allow_tool(hermes.ctx, al, ledger, "read_file")
        assert "Unknown tool" in allow_tool(hermes.ctx, al, ledger, "nope")
    assert asked == [] and ledger.events == []

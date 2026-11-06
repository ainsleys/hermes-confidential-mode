"""C0 spike: can the confidential-mode plugin raise a human approval for a pin update
by calling ``tools.approval.request_tool_approval`` directly?

Every test drives the REAL Hermes functions at the pinned checkout (84a0301). Only the
human-input boundary is substituted:
  * CLI: the ``approval_callback`` argument / ``builtins.input`` (the prompt_toolkit panel's seat);
  * gateway: a notify callback registered through the real ``register_gateway_notify`` plus
    the real ``resolve_gateway_approval`` that ``/approve`` and ``/deny`` call
    (gateway/slash_commands.py:1206-1245) -- the same pattern Hermes' own
    tests/tools/test_request_tool_approval.py::test_api_server_exec_ask_uses_approval_bridge uses.
Policy is set through a real ``config.yaml`` in the temp HERMES_HOME, session/cron identity
through the real context setters, hooks through a real ``PluginContext.register_hook``.

One test per sub-question (a)-(h); the report lives in the spike hand-off, not here.
"""
from __future__ import annotations

import builtins
import contextvars
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli.config import get_config_path
from tools import approval, approval_context

SK = "spike:approval:session"
PIN_TOOL = "confidential_pin_update"
PIN_REASON = "Pin new Tinfoil enclave build for vendor tinfoil (fingerprint ab12cd34)"
K1 = "confidential_pin:tinfoil:ab12cd34"
K2 = "confidential_pin:tinfoil:ffee9988"

_ENV_MARKERS = (
    "HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM",
    "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION", "HERMES_YOLO_MODE", "HERMES_SESSION_KEY",
)


# --------------------------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------------------------

def _reset_permanent_state():
    with approval._lock:
        approval._permanent_approved.clear()
        approval._permanent_approved_by_home.clear()
        approval._permanent_baseline_by_home.clear()


@pytest.fixture
def hermes(monkeypatch):
    """Clean approval state, a bound session key, a writable config.yaml, a hook recorder."""
    from hermes_cli.plugins import PluginContext, discover_plugins, get_plugin_manager
    from hermes_cli.plugins_manifest import PluginManifest

    for name in _ENV_MARKERS:
        monkeypatch.delenv(name, raising=False)
    # No terminal-thread CLI callback leaks in from another test.
    from tools import terminal_tool
    terminal_tool.set_approval_callback(None)
    assert approval._YOLO_MODE_FROZEN is False, "run without HERMES_YOLO_MODE"

    cfg_path = get_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.unlink(missing_ok=True)

    def write_cfg(text: str) -> None:
        cfg_path.write_text(text)

    _reset_permanent_state()
    approval.clear_session(SK)
    token = approval_context.set_current_session_key(SK)

    # Real hook registration on the real manager (discover first so lazy discovery cannot reset it).
    discover_plugins()
    mgr = get_plugin_manager()
    ctx = PluginContext(PluginManifest(name="spike-approval", source="user"), mgr)
    events: list[tuple[str, dict]] = []
    handles = [
        ctx.register_hook("pre_approval_request", lambda **kw: events.append(("pre_approval_request", kw))),
        ctx.register_hook("post_approval_response", lambda **kw: events.append(("post_approval_response", kw))),
    ]
    try:
        yield SimpleNamespace(write_cfg=write_cfg, cfg_path=cfg_path, events=events, ctx=ctx, mgr=mgr)
    finally:
        for h in handles:
            h.dispose()
        approval.unregister_gateway_notify(SK)
        approval.clear_session(SK)
        approval_context.reset_current_session_key(token)
        terminal_tool.set_approval_callback(None)
        cfg_path.unlink(missing_ok=True)
        _reset_permanent_state()


def hook_names(events):
    return [name for name, _ in events]


def run_in_thread_with_context(fn, *args, **kwargs):
    """Start *fn* on a thread that carries the caller's contextvars (as the gateway executor does,
    gateway/run.py:4007-4011). Returns (thread, result_box)."""
    box: dict = {}
    ctx = contextvars.copy_context()

    def _target():
        try:
            box["value"] = ctx.run(fn, *args, **kwargs)
        except BaseException as exc:  # pragma: no cover - surfaced by the assert
            box["error"] = exc

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return t, box


def bind_gateway_session(platform: str = "telegram"):
    """Bind session vars exactly as GatewayRunner._session_env_scope does for a plugin command."""
    from gateway.session_context import set_session_vars
    return set_session_vars(platform=platform, session_key=SK, session_id="sess-1", chat_id="c1")


# --------------------------------------------------------------------------------------------------
# (a) signature, return shape, meaning of the arguments, the prompt text the human sees
# --------------------------------------------------------------------------------------------------

def test_a_signature_return_shape_and_prompt_text(hermes, monkeypatch):
    import inspect

    sig = inspect.signature(approval.request_tool_approval)
    assert str(sig) == "(tool_name: str, reason: str, *, rule_key: str = '', approval_callback=None) -> dict"

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    seen = []

    def human(command, description, **kw):
        seen.append((command, description, kw))
        return "once"

    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=human)
    # Approved by a human via the action gate: exactly _approved() (approval.py:555-556) -- no
    # user_approved marker because _ACTION_GATE.user_approved is False (approval.py:832-846).
    assert res == {"approved": True, "message": None}
    # What the human-facing callback receives: the synthetic target label + the reason verbatim.
    assert seen == [(f"<{PIN_TOOL}> (plugin approval rule)", PIN_REASON, {"allow_permanent": True})]

    # Deny shape (the keys a plugin must read).
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                         approval_callback=lambda *a, **k: "deny")
    assert res["approved"] is False
    assert res["outcome"] == "denied" and res["user_consent"] is False
    assert res["pattern_key"] == f"plugin_rule:{K1}"   # rule_key is namespaced (approval.py:1226)
    assert res["description"] == PIN_REASON
    assert res["message"].startswith("BLOCKED: User denied this potentially dangerous action (matched "
                                     f"'{PIN_REASON}')")
    assert set(res) == {"approved", "message", "pattern_key", "description", "outcome", "user_consent",
                        "user_summary"}

    # Empty rule_key -> tool_name + sha256(reason)[:12]; empty reason -> generic description.
    res = approval.request_tool_approval(PIN_TOOL, "", approval_callback=lambda *a, **k: "deny")
    assert res["description"] == f"Plugin requires approval for {PIN_TOOL}"
    assert res["pattern_key"].startswith(f"plugin_rule:{PIN_TOOL}:")

    # The plain-terminal prompt (no prompt_toolkit callback): capture what is printed.
    printed = []
    monkeypatch.setattr(builtins, "print", lambda *a, **k: printed.append(" ".join(map(str, a))))
    monkeypatch.setattr(builtins, "input", lambda prompt="": printed.append(prompt) or "d")
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1)
    assert res["approved"] is False
    text = "\n".join(printed)
    assert f"DANGEROUS COMMAND: {PIN_REASON}" in text           # reason renders (locales/en.yaml:2)
    assert f"<{PIN_TOOL}> (plugin approval rule)" in text      # tool_name renders as the "command"
    assert "[o]nce  |  [s]ession  |  [a]lways  |  [d]eny" in text
    assert "Choice [o/s/a/D]:" in text


# --------------------------------------------------------------------------------------------------
# (b) CLI surface: once / session / always / deny / timeout
# --------------------------------------------------------------------------------------------------

def test_b_cli_once_session_always_deny_and_timeout_is_deny(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    pk = f"plugin_rule:{K1}"

    def answer(choice):
        calls = []

        def cb(command, description, **kw):
            calls.append(choice)
            return choice
        return cb, calls

    # once: approved, nothing remembered -> next call prompts again.
    cb, calls = answer("once")
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=cb)["approved"]
    assert not approval.is_approved(SK, pk)
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=cb)["approved"]
    assert calls == ["once", "once"]

    # deny: blocked, nothing remembered.
    cb, calls = answer("deny")
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=cb)
    assert res["approved"] is False and res["outcome"] == "denied"
    assert not approval.is_approved(SK, pk)

    # session: approved, remembered for THIS session only (not persisted to config).
    cb, calls = answer("session")
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=cb)["approved"]
    assert approval.is_approved(SK, pk)
    assert not approval.is_approved("some-other-session", pk)
    assert "command_allowlist" not in (hermes.cfg_path.read_text() if hermes.cfg_path.exists() else "")
    approval.clear_session(SK)
    assert not approval.is_approved(SK, pk)

    # always: approved, persisted to config.yaml command_allowlist and honoured by every session.
    cb, calls = answer("always")
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=cb)["approved"]
    assert pk in hermes.cfg_path.read_text()
    assert approval.is_approved("some-other-session", pk)

    # timeout: plain-terminal input() never answers within approvals.timeout -> 'timeout' -> BLOCKED.
    _reset_permanent_state()
    hermes.cfg_path.unlink()
    approval.clear_session(SK)
    hermes.write_cfg("approvals:\n  timeout: 1\n")
    never = threading.Event()
    monkeypatch.setattr(builtins, "input", lambda prompt="": never.wait(30) and "o")
    t0 = time.monotonic()
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1)
    elapsed = time.monotonic() - t0
    never.set()
    assert 0.9 <= elapsed < 5
    assert res["approved"] is False
    assert res["outcome"] == "timeout"
    assert res["message"].startswith("BLOCKED: Action timed out without user response.")
    assert "Silence is not consent." in res["message"]
    assert not approval.is_approved(SK, pk)
    # The CLI fires the hooks around the prompt (approval.py:993-996), choice reported as 'timeout'.
    assert hook_names(hermes.events)[-2:] == ["pre_approval_request", "post_approval_response"]
    assert hermes.events[-1][1]["choice"] == "timeout"

    # A raising callback (prompt never reached a human) is also fail-closed ("cancelled").
    def boom(*a, **k):
        raise RuntimeError("panel gone")
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=boom)
    assert res["approved"] is False and res["outcome"] == "cancelled"


# --------------------------------------------------------------------------------------------------
# (c) gateway surface: blocks until /approve or /deny; default timeout 300; silence and notify
#     failure are deny
# --------------------------------------------------------------------------------------------------

def test_c_gateway_blocks_until_approve_or_deny_silence_and_notify_failure_deny(hermes):
    from gateway.session_context import clear_session_vars

    assert approval_context._get_approval_timeout() == 300        # default (approval_context.py:305-326)
    tokens = bind_gateway_session("telegram")
    try:
        assert approval_context._is_gateway_approval_context() is True
        cards = []
        approval.register_gateway_notify(SK, lambda data: cards.append(data))

        # Blocks: the call does not return until /approve resolves it.
        t, box = run_in_thread_with_context(approval.request_tool_approval, PIN_TOOL, PIN_REASON, rule_key=K1)
        deadline = time.monotonic() + 5
        while not cards and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.5)
        assert t.is_alive(), "request_tool_approval must block while the card is pending"
        assert approval.has_blocking_approval(SK)     # what /approve checks (slash_commands.py:1193-1199)
        card = cards[0]
        assert card["description"] == PIN_REASON
        assert card["command"] == f"<{PIN_TOOL}> (plugin approval rule)"
        assert card["pattern_key"] == f"plugin_rule:{K1}"
        assert card["allow_permanent"] is True and card["allow_session"] is True
        assert card["timeout_s"] == 300
        assert approval.resolve_gateway_approval(SK, "once") == 1   # what /approve calls
        t.join(5)
        assert box["value"] == {"approved": True, "message": None}
        # Gateway path fires hooks inside _await_gateway_decision (approval_gateway_wait.py:271, 108-113).
        assert hook_names(hermes.events) == ["pre_approval_request", "post_approval_response"]
        assert hermes.events[0][1]["surface"] == "gateway"
        assert hermes.events[1][1]["choice"] == "once"

        # /deny <reason>
        cards.clear()
        t, box = run_in_thread_with_context(approval.request_tool_approval, PIN_TOOL, PIN_REASON, rule_key=K1)
        while not cards and t.is_alive():
            time.sleep(0.02)
        assert approval.resolve_gateway_approval(SK, "deny", reason="not my build") == 1
        t.join(5)
        res = box["value"]
        assert res["approved"] is False and res["outcome"] == "denied"
        assert res["deny_reason"] == "not my build"
        assert 'Reason given by the user: "not my build"' in res["message"]

        # Silence: nobody answers within approvals.timeout -> BLOCKED 'timeout'.
        hermes.write_cfg("approvals:\n  timeout: 1\n")
        t0 = time.monotonic()
        res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1)
        assert 0.9 <= time.monotonic() - t0 < 5
        assert res["approved"] is False and res["outcome"] == "timeout"
        assert "Silence is not consent." in res["message"]
        assert not approval.has_blocking_approval(SK)

        # Notify failure -> deny, immediately.
        def broken(data):
            raise ConnectionError("telegram down")
        approval.register_gateway_notify(SK, broken)
        res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1)
        assert res["approved"] is False and res["outcome"] == "notify_failed"
        assert res["message"] == "BLOCKED: Failed to send approval request to user. Do NOT retry."
        assert hermes.events[-1][1]["choice"] == "notify_failed"

        # SURPRISE: gateway context with NO notifier registered (i.e. no agent turn is running for the
        # session -- only gateway/run_turn_runner.py:984 registers one) returns IMMEDIATELY with an
        # 'approval_required' pending result. Nobody is asked, nothing blocks, no hook fires, and
        # /approve cannot resolve it later (has_blocking_approval is False).
        approval.unregister_gateway_notify(SK)
        n_events = len(hermes.events)
        t0 = time.monotonic()
        res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1)
        assert time.monotonic() - t0 < 0.5
        assert res["approved"] is False
        assert res["status"] == "approval_required"
        assert "Asking the user for approval" in res["message"]
        assert "outcome" not in res
        assert len(hermes.events) == n_events
        assert not approval.has_blocking_approval(SK)
    finally:
        clear_session_vars(tokens)


# --------------------------------------------------------------------------------------------------
# (d) bypass states approve WITHOUT any hook firing, and how a plugin detects them
# --------------------------------------------------------------------------------------------------

def _detect_bypass(session_key: str, rule_key: str) -> dict:
    """The exact pre-flight a plugin can run (mirrors _run_approval_gate's own order)."""
    from tools.approval import _yolo_active, is_approval_bypass_active_for_session, is_approved
    from tools.approval_context import _get_approval_mode
    return {
        "yolo": _yolo_active(),                       # --yolo (frozen), /yolo, hermes -z
        "mode_off": _get_approval_mode() == "off",
        "remembered": is_approved(session_key, f"plugin_rule:{rule_key}"),  # NOTE the prefix
        "canonical_bypass": is_approval_bypass_active_for_session(session_key),
    }


def test_d_bypass_states_skip_human_and_hooks_and_are_detectable(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    def must_not_prompt(*a, **k):
        raise AssertionError("bypass state must not prompt")

    assert _detect_bypass(SK, K1) == {"yolo": False, "mode_off": False, "remembered": False,
                                      "canonical_bypass": False}

    # 1. session /yolo (what the --yolo launch policy seeds per session, tools/approval_yolo.py)
    approval.enable_session_yolo(SK)
    assert _detect_bypass(SK, K1)["yolo"] is True
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                          approval_callback=must_not_prompt) == {"approved": True, "message": None}
    approval.disable_session_yolo(SK)

    # 2. approvals.mode: off (YAML bare `off` parses to False -> normalized to 'off')
    hermes.write_cfg("approvals:\n  mode: off\n")
    assert _detect_bypass(SK, K1)["mode_off"] is True
    assert _detect_bypass(SK, K1)["canonical_bypass"] is True
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                          approval_callback=must_not_prompt) == {"approved": True, "message": None}
    hermes.cfg_path.unlink()

    # 3. remembered session answer for the same rule_key
    approval.approve_session(SK, f"plugin_rule:{K1}")
    assert _detect_bypass(SK, K1)["remembered"] is True
    assert approval.is_approved(SK, K1) is False   # the un-prefixed key does NOT detect it
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                          approval_callback=must_not_prompt) == {"approved": True, "message": None}
    approval.clear_session(SK)

    # 4. remembered 'always' answer (config.yaml command_allowlist, any session, survives restart)
    hermes.write_cfg(f"command_allowlist:\n- 'plugin_rule:{K1}'\n")
    approval.load_permanent_allowlist()
    assert _detect_bypass("fresh-session", K1)["remembered"] is True
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                          approval_callback=must_not_prompt) == {"approved": True, "message": None}
    hermes.cfg_path.unlink()
    _reset_permanent_state()

    # 5. `hermes -z` unattended turn: _yolo_active() is True (approval.py:350-356, session_finite.py:27-30)
    from gateway.session_finite import finite_turn_scope
    with finite_turn_scope(True, unattended=True):
        assert _detect_bypass(SK, K1)["yolo"] is True
        assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                              approval_callback=must_not_prompt)["approved"] is True

    # 6. cron_mode / unattended_mode / single_query_mode: approve ALSO auto-approve (break at
    #    approval.py:1103 skips the fail-closed else-branch), and they are NOT covered by the
    #    canonical bypass predicate -- a plugin must check them separately.
    from gateway.session_context import clear_session_vars, set_session_vars
    hermes.write_cfg("approvals:\n  cron_mode: approve\n  unattended_mode: approve\n  single_query_mode: approve\n")
    tok = set_session_vars(session_key=SK, cron_session="1")
    try:
        assert approval_context._is_cron_approval_context() is True
        assert approval_context._get_cron_approval_mode() == "approve"
        assert _detect_bypass(SK, K1)["canonical_bypass"] is False
        assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                              approval_callback=must_not_prompt) == {"approved": True, "message": None}
    finally:
        clear_session_vars(tok)
    tok = set_session_vars(platform="webhook", session_key=SK)
    try:
        monkeypatch.delenv("HERMES_INTERACTIVE")
        assert approval_context._is_unattended_platform_approval_context() is True
        assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                              approval_callback=must_not_prompt) == {"approved": True, "message": None}
    finally:
        clear_session_vars(tok)
    monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1,
                                          approval_callback=must_not_prompt) == {"approved": True, "message": None}
    monkeypatch.delenv("HERMES_SINGLE_QUERY_SESSION")

    # None of the bypassed calls fired a hook.
    assert hermes.events == []


def test_d_process_yolo_flag_frozen_at_import_bypasses(tmp_path):
    """`hermes --yolo` sets HERMES_YOLO_MODE=1 before import (hermes_cli/main.py:2854-2860); the flag is
    frozen into approval._YOLO_MODE_FROZEN (approval.py:48). Run in a fresh interpreter to observe it."""
    hermes_root = Path(approval.__file__).resolve().parents[1]
    code = (
        "import json, os\n"
        "from tools import approval\n"
        "os.environ['HERMES_YOLO_MODE'] = '0'  # flipping it after import changes nothing\n"
        "def cb(*a, **k): raise AssertionError('prompted')\n"
        "r = approval.request_tool_approval('t', 'r', rule_key='k', approval_callback=cb)\n"
        "print(json.dumps({'frozen': approval._YOLO_MODE_FROZEN, 'yolo': approval._yolo_active(), 'r': r}))\n"
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "HERMES_HOME": str(tmp_path),
           "HERMES_YOLO_MODE": "1", "HERMES_INTERACTIVE": "1"}
    out = subprocess.run([sys.executable, "-c", code], cwd=hermes_root, env=env, capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data == {"frozen": True, "yolo": True, "r": {"approved": True, "message": None}}


# --------------------------------------------------------------------------------------------------
# (e) unattended contexts: cron deny by default, fail-closed BLOCKED when nobody can answer
# --------------------------------------------------------------------------------------------------

def test_e_cron_denies_immediately_and_no_human_is_blocked(hermes, monkeypatch):
    from gateway.session_context import clear_session_vars, set_session_vars

    def must_not_prompt(*a, **k):
        raise AssertionError("unattended context must not prompt")

    # Cron (contextvar, as cron/scheduler.py binds it) -- even if HERMES_INTERACTIVE leaked in.
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    tok = set_session_vars(session_key=SK, cron_session="1", platform="telegram")
    try:
        assert approval_context._get_cron_approval_mode() == "deny"     # default
        t0 = time.monotonic()
        res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=must_not_prompt)
        assert time.monotonic() - t0 < 0.5
        assert res["approved"] is False
        assert res["message"].startswith(f"BLOCKED: Tool '{PIN_TOOL}' requires approval ({PIN_REASON}) but cron jobs "
                                         "run without a user present to approve it.")
        assert "approvals.cron_mode: approve" in res["message"]
        assert "outcome" not in res and "user_consent" not in res   # _blocked() shape (approval.py:584-586)
    finally:
        clear_session_vars(tok)

    # Legacy env marker too (approval_context.py:167-169 falls back to os.environ when unbound).
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    from gateway.session_context import reset_session_vars
    ctx = contextvars.copy_context()
    res = ctx.run(lambda: (reset_session_vars(), approval.request_tool_approval(
        PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=must_not_prompt))[1])
    assert res["approved"] is False and "cron jobs run without a user" in res["message"]
    monkeypatch.delenv("HERMES_CRON_SESSION")
    monkeypatch.delenv("HERMES_INTERACTIVE")

    # Nobody reachable (no CLI, no gateway, not cron/-q/unattended): fail_closed_when_no_human=True.
    assert not approval_context._is_interactive_cli()
    assert not approval_context._is_gateway_approval_context()
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=must_not_prompt)
    assert res == {
        "approved": False,
        "message": (f"BLOCKED: Tool '{PIN_TOOL}' requires approval ({PIN_REASON}) but no interactive user or "
                    "gateway is present to approve it. A plugin flagged this action for human confirmation."),
        "pattern_key": f"plugin_rule:{K1}", "description": PIN_REASON,
    }
    # -q single query, default deny.
    monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=must_not_prompt)
    assert res["approved"] is False and "single-query mode (-q)" in res["message"]
    assert hermes.events == []


# --------------------------------------------------------------------------------------------------
# (f) rule_key isolation and namespace collisions
# --------------------------------------------------------------------------------------------------

def test_f_rule_key_isolation_and_collisions(hermes, monkeypatch):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    prompts = []

    def human(choice):
        def cb(command, description, **kw):
            prompts.append(choice)
            return choice
        return cb

    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=human("always"))["approved"]
    assert f"plugin_rule:{K1}" in hermes.cfg_path.read_text()
    # K1 again: no prompt.
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1, approval_callback=human("deny"))["approved"]
    assert prompts == ["always"]
    # K2 (different fingerprint) still prompts, and the human's deny holds.
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K2, approval_callback=human("deny"))
    assert res["approved"] is False and prompts == ["always", "deny"]
    # The persisted 'always' survives a process restart: reload from disk into a clean state.
    _reset_permanent_state()
    approval.clear_session(SK)
    approval.load_permanent_allowlist()
    assert approval.is_approved("new-session", f"plugin_rule:{K1}")
    assert not approval.is_approved("new-session", f"plugin_rule:{K2}")

    # Collision with built-in pattern keys is impossible from request_tool_approval: every key is
    # prefixed "plugin_rule:" and built-in keys are bare descriptions with alias sets
    # (approval_detection.py:737-755). Pick a real built-in key and prove no cross-over either way.
    from tools.approval_detection import DANGEROUS_PATTERNS, _approval_key_aliases
    builtin_key = DANGEROUS_PATTERNS[0][1]
    approval.approve_session(SK, builtin_key)
    res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=builtin_key, approval_callback=human("deny"))
    assert res["approved"] is False and res["pattern_key"] == f"plugin_rule:{builtin_key}"
    assert _approval_key_aliases(f"plugin_rule:{K1}") == {f"plugin_rule:{K1}"}

    # BUT the plugin_rule namespace is shared by every plugin and by Hermes' own pre_tool_call
    # 'approve' directive, whose rule_key defaults to the TOOL NAME (plugins.py:2003). An 'always'
    # granted for some model-tool approval with rule_key == our key pre-approves our pin update.
    approval.approve_session(SK, "plugin_rule:confidential_pin_update")
    assert approval.request_tool_approval(PIN_TOOL, "anything", rule_key="confidential_pin_update",
                                          approval_callback=human("deny"))["approved"] is True
    # ...and any in-process code can mint the grant directly (no authentication on the store).
    approval.approve_permanent(f"plugin_rule:{K2}")
    assert approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K2,
                                          approval_callback=human("deny"))["approved"] is True


# --------------------------------------------------------------------------------------------------
# (g) ctx.dispatch_tool skips pre_tool_call and the approval gate; the model path does not
# --------------------------------------------------------------------------------------------------

def test_g_dispatch_tool_bypasses_pre_tool_call_model_path_does_not(hermes, monkeypatch):
    import model_tools
    from tools import terminal_tool
    from tools.registry import registry

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    tool = "_spike_pin_probe"
    ran = []
    registry.register(
        name=tool, toolset="debugging",
        schema={"name": tool, "description": "probe", "parameters": {"type": "object", "properties": {}}},
        handler=lambda args, **kw: ran.append(args) or '{"ok": true}',
    )
    pre_calls = []
    prompts = []
    handle = hermes.ctx.register_hook(
        "pre_tool_call",
        lambda tool_name, **kw: (pre_calls.append(tool_name),
                                 {"action": "approve", "message": "pin probe", "rule_key": "probe"}
                                 if tool_name == tool else None)[1])
    # The CLI's prompt_toolkit callback seat (thread-local, cli.py:959).
    terminal_tool.set_approval_callback(lambda c, d, **k: prompts.append(d) or "deny")
    try:
        out = hermes.ctx.dispatch_tool(tool, {"via": "ctx"})
        assert json.loads(out) == {"ok": True}
        assert ran == [{"via": "ctx"}]
        assert tool not in pre_calls and prompts == [] and hermes.events == []

        out = model_tools.handle_function_call(tool, {"via": "model"}, task_id="t1", session_id="s1")
        assert tool in pre_calls
        assert prompts == ["pin probe"]          # the gate ran and the human denied
        assert ran == [{"via": "ctx"}]           # handler did NOT run on the model path
        assert "BLOCKED" in out and "denied" in out.lower()
        assert hook_names(hermes.events) == ["pre_approval_request", "post_approval_response"]
    finally:
        handle.dispose()
        registry.deregister(tool)


# --------------------------------------------------------------------------------------------------
# (h) calling from hooks / middleware / a gateway slash-command handler
# --------------------------------------------------------------------------------------------------

def test_h_hook_and_slash_command_call_sites(hermes, monkeypatch):
    from gateway.session_context import clear_session_vars
    from hermes_cli.plugin_command_dispatch import invoke_plugin_command
    from hermes_cli.plugins import get_plugin_command_handler, invoke_hook

    # --- 1. From inside a pre_tool_call hook callback, gateway surface, human answers quickly: no deadlock.
    tokens = bind_gateway_session("telegram")
    try:
        approval.register_gateway_notify(
            SK, lambda data: threading.Timer(0.2, approval.resolve_gateway_approval, (SK, "once")).start())
        results = []

        def hook(tool_name, **kw):
            if tool_name == "spike_hook_probe":
                results.append(approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1))
        h = hermes.ctx.register_hook("pre_tool_call", hook)
        try:
            invoke_hook("pre_tool_call", tool_name="spike_hook_probe", args={}, session_id="s1")
        finally:
            h.dispose()
        assert results == [{"approved": True, "message": None}]

        # --- 2. ...but the hook worker is capped by plugins.hook_callback_timeout (default 30 s), far
        # below approvals.timeout (300 s). A human slower than the cap -> pre_tool_call is abandoned
        # and FAILS CLOSED with a block directive (plugins_dispatch.py:62-64, 296-302), while the
        # orphaned approval card stays pending until the human answers or 300 s pass.
        hermes.write_cfg("plugins:\n  hook_callback_timeout: 1\n")
        approval.register_gateway_notify(SK, lambda data: None)   # card delivered, nobody answers yet
        h = hermes.ctx.register_hook("pre_tool_call", hook)
        try:
            t0 = time.monotonic()
            directives = invoke_hook("pre_tool_call", tool_name="spike_hook_probe", args={}, session_id="s1")
            assert 0.9 <= time.monotonic() - t0 < 5
        finally:
            h.dispose()
        assert {"action": "block", "message": "pre_tool_call plugin callback timed out or is still running"} \
            in directives
        assert approval.has_blocking_approval(SK)                 # the orphan card is still pending
        approval.resolve_gateway_approval(SK, "deny", resolve_all=True)
        approval.unregister_gateway_notify(SK)                    # the "agent turn" ends
        hermes.cfg_path.unlink()
    finally:
        clear_session_vars(tokens)

    # --- 3. From a slash-command handler registered with ctx.register_command, invoked the way the
    # gateway does (_hm_run_plugin_handler: session env scope + executor thread with copied context +
    # invoke_plugin_command, gateway/run_inbound_hooks.py:262-301).
    seen = []

    def pin_command(raw_args, session_key=None, platform=None):
        seen.append((session_key, platform, approval_context.get_current_session_key()))
        return json.dumps(approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1))

    reg = hermes.ctx.register_command("spike-pin", pin_command, description="spike")
    try:
        handler = get_plugin_command_handler("spike-pin")
        assert handler is pin_command

        def gateway_dispatch():
            toks = bind_gateway_session("telegram")
            try:
                t, box = run_in_thread_with_context(invoke_plugin_command, handler, "", source=None,
                                                    session_id="sess-1", session_key=SK, platform="telegram")
                return t, box
            finally:
                clear_session_vars(toks)

        # 3a. No agent turn running for the session -> no notifier -> immediate non-approval.
        approval_context._approval_session_key.set("")   # the gateway does NOT bind the approval key here
        t, box = contextvars.copy_context().run(gateway_dispatch)
        t.join(5)
        assert "error" not in box, repr(box.get("error"))
        res = json.loads(box["value"])
        assert seen[-1] == (SK, "telegram", SK)       # session key resolves via HERMES_SESSION_KEY var
        assert res["approved"] is False and res["status"] == "approval_required"

        # 3b. Agent turn running concurrently (notifier registered): the handler thread blocks until
        # /approve, without blocking the caller (the event loop in the real gateway).
        cards = []
        approval.register_gateway_notify(SK, cards.append)
        t, box = contextvars.copy_context().run(gateway_dispatch)
        while not cards and t.is_alive():
            time.sleep(0.02)
        time.sleep(0.3)
        assert t.is_alive()
        approval.resolve_gateway_approval(SK, "once")
        t.join(5)
        assert json.loads(box["value"]) == {"approved": True, "message": None}
    finally:
        if reg is not None:
            reg.dispose()
        approval.unregister_gateway_notify(SK)

    # --- 4. From inside an llm_execution middleware callback (runs synchronously on the agent thread,
    # no timeout: hermes_cli/middleware.py:162-213). No deadlock with a live notifier...
    from hermes_cli.middleware import run_llm_execution_middleware
    from tools.interrupt import set_interrupt

    def mw(request, next_call, **kw):
        res = approval.request_tool_approval(PIN_TOOL, PIN_REASON, rule_key=K1)
        return next_call(request) if res["approved"] else {"refused": res.get("outcome")}

    reg = hermes.ctx.register_middleware("llm_execution", mw)
    try:
        def agent_thread_call():
            toks = bind_gateway_session("telegram")
            try:
                return run_llm_execution_middleware({"model": "m"}, lambda req: {"provider_called": True})
            finally:
                clear_session_vars(toks)

        cards = []
        approval.register_gateway_notify(SK, cards.append)
        t, box = run_in_thread_with_context(agent_thread_call)
        while not cards and t.is_alive():
            time.sleep(0.02)
        approval.resolve_gateway_approval(SK, "once")
        t.join(5)
        assert box["value"] == {"provider_called": True}

        # ...but an interrupt of the agent thread while it waits (what AIAgent.redirect() does when a
        # user message lands while _model_request_active is set, agent/interrupt_control.py:362-381)
        # withdraws the approval: 'cancelled', fail-closed, not attributed to the user.
        cards.clear()
        t, box = run_in_thread_with_context(agent_thread_call)
        while not cards and t.is_alive():
            time.sleep(0.02)
        set_interrupt(True, t.ident, reason="user redirect")
        t.join(5)
        set_interrupt(False, t.ident)
        assert box["value"] == {"refused": "cancelled"}
    finally:
        reg.dispose()

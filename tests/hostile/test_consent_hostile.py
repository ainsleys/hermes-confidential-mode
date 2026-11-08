"""T4 hostile tests for W4 consent (confidential_mode.consent.approve_pending_pin / allow_tool).

Written BEFORE the implementation, against docs/INTERFACES.md ("W4") and docs/dev/C0-spikes.md spike 3:
ctx.ask_choice is the consent primitive, sync only, None -> deny, pending re-checked before apply,
ledger pin_applied / pin_denied with raw_pick.

Two kinds of ctx:
  * the REAL PluginContext.ask_choice, driven either through the real gateway
    (GatewayRunner._handle_message + a text adapter, the spike's harness) or with
    hermes_cli.plugin_choices.bind_asker (the seat every surface binds). Real ask_choice already
    strips/casefolds typed text and RAISES AttributeError when an asker returns a non-str
    (plugin_choices.py:94) -- consent must survive that;
  * a FAKE ctx whose ask_choice returns values the real one never would ("Approve" label,
    "approve " with whitespace, 1, True). The contract says "exactly as in docs/dev/C0-spikes.md", whose
    primitive returns a choice VALUE or None; anything else must be treated as deny, never as a pick.

PinStore (W2) and Ledger (W1) are not merged: FakeStore / FakeLedger stand in. FakeStore.pending()
returns a FRESH equal copy each call, as a store that re-reads pins.yaml would, so an identity-only
(`is`) re-check fails the positive control.
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

_PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from hermes_cli.config import get_config_path  # noqa: E402

from confidential_mode import consent  # noqa: E402  ImportError until W4 merges is expected
from confidential_mode.verify.base import VerificationResult  # noqa: E402

SK = "t4:hostile:consent"
AFFIRMATIVE_HINTS = ("approve", "allow", "yes", "pin", "accept", "trust")


# --------------------------------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------------------------------

def _kind(event) -> str:
    if isinstance(event, dict):
        return str(event.get("kind", ""))
    return str(getattr(event, "kind", ""))


def _text(event) -> str:
    try:
        if isinstance(event, dict):
            return json.dumps(event, default=repr)
        return json.dumps(getattr(event, "__dict__", {}) or {"repr": repr(event)}, default=repr)
    except Exception:
        return repr(event)


class FakeLedger:
    def __init__(self):
        self.events: list = []
        self._lock = threading.Lock()

    def append(self, event=None, **kw):
        with self._lock:
            self.events.append(event if event is not None else kw)
        return len(self.events)

    def tail(self, since_id=0):
        return list(self.events[since_id:])

    def session(self, session_id):
        return list(self.events)

    def kinds(self):
        return [_kind(e) for e in self.events]


def _result(code="ffee99887766aabb", enclave="1122334455667788", tag="v0.4.2"):
    return VerificationResult(vendor="tinfoil", router_repo="tinfoilsh/confidential-model-router",
                              enclave_host="router.inf.tinfoil.sh", code_fingerprint=code,
                              enclave_fingerprint=enclave, release_tag=tag, verifier="tinfoil-0.14.2",
                              verified_at_host_clock=1_700_000_000.0, evidence={"t4": True})


@dataclass(frozen=True)
class FakePending:
    vendor: str
    router_repo: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None
    previous: str | None
    result: VerificationResult
    models_seen: tuple = ()
    staged_at: str = "2026-11-06T00:00:00Z"
    extra: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def fingerprint(self):
        return self.code_fingerprint

    @property
    def new(self):
        return self.result


def make_pending(code="ffee99887766aabb", enclave="1122334455667788", tag="v0.4.2"):
    r = _result(code, enclave, tag)
    return FakePending(vendor=r.vendor, router_repo=r.router_repo, code_fingerprint=r.code_fingerprint,
                       enclave_fingerprint=r.enclave_fingerprint, release_tag=r.release_tag,
                       previous="ab12cd34ef56", result=r)


class FakeStore:
    """pending() returns a fresh equal copy (like re-reading pins.yaml). apply() optionally sleeps
    (to widen race windows) or raises after a partial write."""

    def __init__(self, pending):
        self._pending = pending
        self.applied: list = []
        self.apply_delay = 0.0
        self.apply_boom: BaseException | None = None
        self.partial_writes: list = []
        self.approved_via: list = []

    def pending(self):
        return copy.copy(self._pending) if self._pending is not None else None

    def match(self, result):
        return False

    def stage(self, result):
        self._pending = make_pending(result.code_fingerprint, result.enclave_fingerprint, result.release_tag)
        return self.pending()

    def apply(self, pending, *, approved_via=None):
        self.approved_via.append(approved_via)
        if self.apply_delay:
            time.sleep(self.apply_delay)
        if self.apply_boom is not None:
            self.partial_writes.append(pending)
            raise self.apply_boom
        self.applied.append(pending)
        self._pending = None
        return SimpleNamespace(vendor=pending.vendor, code_fingerprint=pending.code_fingerprint,
                               enclave_fingerprint=pending.enclave_fingerprint, release_tag=pending.release_tag,
                               approved_by="human", approved_at="2026-11-06T00:00:00Z", approved_via="t4",
                               approval_rule_key="t4", previous=pending.previous,
                               models_seen=list(pending.models_seen))


def _options(choices):
    out = []
    for c in choices:
        if isinstance(c, dict):
            value = str(c.get("value"))
            out.append((value, str(c.get("label") or value), c.get("description") or ""))
        else:
            out.append((str(c), str(c), ""))
    return out


def affirmative(choices):
    for value, label, _desc in _options(choices):
        if any(h in value.casefold() or h in label.casefold() for h in AFFIRMATIVE_HINTS) \
                and not any(n in value.casefold() for n in ("deny", "reject", "no", "keep", "cancel")):
            return value, label
    pytest.fail(f"hostile harness: no affirmative choice recognisable in {choices!r}")


class FakeCtx:
    """ask_choice(question, choices) -> answer_fn(question, choices). Records every ask."""

    def __init__(self, answer_fn):
        self.answer_fn = answer_fn
        self.asked: list = []
        self.state = _DictState()

    def ask_choice(self, question, choices):
        self.asked.append((question, choices))
        return self.answer_fn(question, choices)


class _DictState(dict):
    def set(self, k, v):
        self[k] = v

    def delete(self, k):
        self.pop(k, None)


def approve_pin(ctx, store, ledger, **kw):
    kw.setdefault("session_key", SK)
    kw.setdefault("session_id", "sess-1")
    kw.setdefault("platform", "cli")
    return consent.approve_pending_pin(ctx, store, ledger, **kw)


def assert_denied(store, ledger, why=""):
    assert store.applied == [], f"pin applied {why}"
    kinds = ledger.kinds()
    assert "pin_applied" not in kinds, f"ledger says applied {why}: {kinds}"
    assert "pin_denied" in kinds, f"a refused/failed consent must ledger pin_denied {why}: {kinds}"


# --------------------------------------------------------------------------------------------------
# controls
# --------------------------------------------------------------------------------------------------

def test_control_exact_value_applies_once_with_the_shown_pending():
    p = make_pending()
    store, ledger = FakeStore(p), FakeLedger()
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])
    reply = approve_pin(ctx, store, ledger)
    assert isinstance(reply, str), "Amendment 3: approve_pending_pin returns a string"
    assert store.applied == [p], "positive control: the exact affirmative value must apply (fresh equal copy)"
    assert ledger.kinds().count("pin_applied") == 1
    assert "raw_pick" in _text(next(e for e in ledger.events if _kind(e) == "pin_applied"))
    assert store.approved_via and isinstance(store.approved_via[-1], str) and store.approved_via[-1], \
        "Amendment 2: consent passes apply(pending, approved_via=<surface>)"
    question = ctx.asked[0][0]
    assert p.code_fingerprint[:8] in question or p.enclave_fingerprint[:8] in question, \
        "the human must see what they are pinning (spike 3 question shows the fingerprints)"


def test_no_pending_asks_nobody_and_applies_nothing():
    store, ledger = FakeStore(None), FakeLedger()
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])
    approve_pin(ctx, store, ledger)
    assert ctx.asked == [] and store.applied == []
    assert "pin_applied" not in ledger.kinds()


# --------------------------------------------------------------------------------------------------
# non-canonical answers from ctx.ask_choice
# --------------------------------------------------------------------------------------------------

def _label_variant(value, label):
    if label != value:
        return label
    for cand in (value.capitalize(), value.upper(), value + "!"):
        if cand != value:
            return cand


ANSWER_VARIANTS = {
    "label": _label_variant,
    "trailing_space": lambda v, label: v + " ",
    "leading_space": lambda v, label: " " + v,
    "upper": lambda v, label: v.upper(),
    "shown_text": lambda v, label: f"{label} — pin the new enclave measurement",
    "int_1": lambda v, label: 1,
    "true": lambda v, label: True,
    "float_1": lambda v, label: 1.0,
    "list": lambda v, label: [v],
    "dict": lambda v, label: {"value": v},
    "bytes": lambda v, label: v.encode(),
    "str_subclass": lambda v, label: type("S", (str,), {"__eq__": lambda s, o: True, "__hash__": str.__hash__})("x"),
    "none": lambda v, label: None,
    "empty": lambda v, label: "",
    "sentinel_skip": lambda v, label: "\x00skipped",
}


@pytest.mark.parametrize("variant", sorted(ANSWER_VARIANTS))
def test_non_canonical_answer_is_deny(variant):
    """Only the exact affirmative VALUE counts. A str subclass whose __eq__ is always True is the
    sharpest case: `pick == "approve"` is True for it; `pick is` / type checks are not fooled."""
    store, ledger = FakeStore(make_pending()), FakeLedger()

    def answer(q, choices):
        value, label = affirmative(choices)
        return ANSWER_VARIANTS[variant](value, label)

    ctx = FakeCtx(answer)
    with contextlib.suppress(Exception):     # raising is acceptable; applying is not
        approve_pin(ctx, store, ledger)
    assert store.applied == [], f"{variant} answer applied the pin"
    assert "pin_applied" not in ledger.kinds()
    if variant != "str_subclass":
        assert "pin_denied" in ledger.kinds(), f"{variant}: denial must be ledgered"


def test_raw_pick_that_is_not_json_serialisable_does_not_crash_the_denial():
    store, ledger = FakeStore(make_pending()), FakeLedger()
    ctx = FakeCtx(lambda q, c: object())
    approve_pin(ctx, store, ledger)
    assert_denied(store, ledger, "object() pick")


@pytest.mark.parametrize("exc", [RuntimeError("surface died"), KeyboardInterrupt(), TimeoutError()],
                         ids=["runtime", "keyboard_interrupt", "timeout"])
def test_asker_raising_never_applies(exc):
    store, ledger = FakeStore(make_pending()), FakeLedger()

    def boom(q, c):
        raise exc

    ctx = FakeCtx(boom)
    with contextlib.suppress(BaseException):
        approve_pin(ctx, store, ledger)
    assert store.applied == []
    assert "pin_applied" not in ledger.kinds()


# --------------------------------------------------------------------------------------------------
# real PluginContext.ask_choice with a bound asker
# --------------------------------------------------------------------------------------------------

@pytest.fixture
def real_ctx(monkeypatch):
    from hermes_cli.plugins import PluginContext, discover_plugins, get_plugin_manager
    from hermes_cli.plugins_manifest import PluginManifest
    for name in ("HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM",
                 "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION", "HERMES_SESSION_KEY"):
        monkeypatch.delenv(name, raising=False)
    cfg = get_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.unlink(missing_ok=True)
    discover_plugins()
    ctx = PluginContext(PluginManifest(name="confidential-mode-t4c", source="user"), get_plugin_manager())
    try:
        yield SimpleNamespace(ctx=ctx, cfg=cfg, write_cfg=lambda t: cfg.write_text(t))
    finally:
        cfg.unlink(missing_ok=True)


def _shown_affirmative(labels):
    for s in labels:
        if any(h in s.casefold() for h in AFFIRMATIVE_HINTS) and "deny" not in s.casefold():
            return s
    pytest.fail(f"no affirmative option shown: {labels!r}")


def test_real_ask_choice_affirmative_applies_control(real_ctx):
    from hermes_cli.plugin_choices import bind_asker
    store, ledger = FakeStore(make_pending()), FakeLedger()
    with bind_asker(lambda q, labels: _shown_affirmative(labels)):
        approve_pin(real_ctx.ctx, store, ledger)
    assert len(store.applied) == 1


@pytest.mark.parametrize("raw", [1, True, b"approve", ["1"]], ids=["int", "bool", "bytes", "list"])
def test_real_ask_choice_raises_on_non_str_asker_and_consent_does_not_apply(real_ctx, raw):
    """plugin_choices.ask_choice does `(picked or "").strip()`: a surface returning 1/True raises
    AttributeError out of ctx.ask_choice. Consent must not apply, and should ledger the denial."""
    from hermes_cli.plugin_choices import bind_asker
    store, ledger = FakeStore(make_pending()), FakeLedger()
    with bind_asker(lambda q, labels: raw), contextlib.suppress(Exception):
        approve_pin(real_ctx.ctx, store, ledger)
    assert store.applied == []
    assert "pin_applied" not in ledger.kinds()


def test_real_ask_choice_asker_raising(real_ctx):
    from hermes_cli.plugin_choices import bind_asker
    store, ledger = FakeStore(make_pending()), FakeLedger()

    def boom(q, labels):
        raise ConnectionError("telegram down")

    with bind_asker(boom), contextlib.suppress(Exception):
        approve_pin(real_ctx.ctx, store, ledger)
    assert store.applied == [] and "pin_applied" not in ledger.kinds()


def test_real_ask_choice_with_no_surface_is_deny(real_ctx):
    store, ledger = FakeStore(make_pending()), FakeLedger()
    approve_pin(real_ctx.ctx, store, ledger)              # no asker bound (cron, hook, plain call)
    assert_denied(store, ledger, "no surface")


# --------------------------------------------------------------------------------------------------
# async handlers
# --------------------------------------------------------------------------------------------------

def test_called_from_async_handler_with_real_ctx_refuses(real_ctx):
    """Real ask_choice returns None on a running loop (plugin_choices.py:89-92) -> must deny."""
    from hermes_cli.plugin_choices import bind_asker
    store, ledger = FakeStore(make_pending()), FakeLedger()

    async def handler():
        with bind_asker(lambda q, labels: _shown_affirmative(labels)):
            with contextlib.suppress(Exception):
                return approve_pin(real_ctx.ctx, store, ledger)

    asyncio.run(handler())
    assert store.applied == []
    assert "pin_applied" not in ledger.kinds()


def test_called_from_async_handler_refuses_even_if_ctx_would_answer():
    """Contract: 'sync only'. A ctx that answers on a loop (a future Hermes, a wrapper, a test double)
    must not turn an async handler into a working consent path that blocks the event loop."""
    store, ledger = FakeStore(make_pending()), FakeLedger()
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])

    async def handler():
        with pytest.raises(consent.ConsentContextError):
            approve_pin(ctx, store, ledger)

    asyncio.run(handler())
    assert store.applied == [], "approve_pending_pin applied from inside a running event loop"
    assert ctx.asked == [], "asked the human from an event loop"


# --------------------------------------------------------------------------------------------------
# pending swapped / apply failing / concurrency
# --------------------------------------------------------------------------------------------------

SWAPS = {
    "different_code_fp": lambda: make_pending(code="0000deadbeef0000"),
    "different_enclave_fp": lambda: make_pending(enclave="9999aaaabbbbcccc"),
    "cleared": lambda: None,
    "restaged_same_fp_new_tag": lambda: make_pending(tag="v0.4.3"),
}


@pytest.mark.parametrize("swap", sorted(SWAPS))
def test_pending_swapped_between_ask_and_apply_is_not_applied(swap):
    store, ledger = FakeStore(make_pending()), FakeLedger()

    def answer(q, choices):
        store._pending = SWAPS[swap]()        # an attacker (or the verifier) re-stages while the human reads
        return affirmative(choices)[0]

    approve_pin(FakeCtx(answer), store, ledger)
    assert store.applied == [], f"applied after swap {swap}"
    assert "pin_applied" not in ledger.kinds()


def test_pending_swapped_apply_never_receives_the_new_pending():
    shown, attacker = make_pending(), make_pending(code="0000deadbeef0000")
    store, ledger = FakeStore(shown), FakeLedger()

    def answer(q, choices):
        store._pending = attacker
        return affirmative(choices)[0]

    approve_pin(FakeCtx(answer), store, ledger)
    assert attacker not in store.applied, "the human approved fingerprint A; B was applied"


@pytest.mark.parametrize("exc", [OSError(28, "No space left on device"), RuntimeError("yaml write"),
                                 PermissionError("ro")])
def test_apply_raising_midway_ledgers_denied_not_applied(exc):
    store, ledger = FakeStore(make_pending()), FakeLedger()
    store.apply_boom = exc
    with contextlib.suppress(Exception):
        approve_pin(FakeCtx(lambda q, c: affirmative(c)[0]), store, ledger)
    assert store.partial_writes, "apply was reached (harness sanity)"
    kinds = ledger.kinds()
    assert "pin_applied" not in kinds, f"apply raised but the ledger says applied: {kinds}"
    assert "pin_denied" in kinds or any("fail" in k for k in kinds), f"failure not ledgered: {kinds}"


def test_two_concurrent_approvals_for_same_pending_apply_once():
    store, ledger = FakeStore(make_pending()), FakeLedger()
    store.apply_delay = 0.3                   # both threads pass the re-check before either clears pending
    barrier = threading.Barrier(2, timeout=10)

    def answer(q, choices):
        barrier.wait()
        return affirmative(choices)[0]

    errors = []

    def run():
        try:
            approve_pin(FakeCtx(answer), store, ledger)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert len(store.applied) == 1, f"one pending applied {len(store.applied)} times"
    assert ledger.kinds().count("pin_applied") == 1, ledger.kinds()


# --------------------------------------------------------------------------------------------------
# real gateway path (spike harness): /confidential-style command -> ask_choice -> typed reply
# --------------------------------------------------------------------------------------------------

async def _wait_until(pred, timeout=10.0):
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
    return MessageEvent(text=text, message_type=MessageType.TEXT, source=_source(), message_id=f"{text}-{time.time()}")


def _affirmative_number(prompt: str) -> str:
    for line in prompt.splitlines():
        s = line.strip()
        if s[:1].isdigit() and "." in s:
            num, _, rest = s.partition(".")
            if any(h in rest.casefold() for h in AFFIRMATIVE_HINTS) and "deny" not in rest.casefold():
                return num
    pytest.fail(f"no affirmative numbered option in prompt:\n{prompt}")


def _gateway(real_ctx, store, ledger, replies, *, before_reply=None):
    """replies: list of str or callables(prompt) -> str, typed after the prompt appears."""
    def handler(raw_args, session_key=None):
        with contextlib.suppress(Exception):
            approve_pin(real_ctx.ctx, store, ledger, session_key=session_key or SK, session_id="sess-1",
                        platform="telegram")
        return "PIN=done"

    if not real_ctx.cfg.exists():             # bound every scenario: an unrouted reply must not hang 3600 s
        real_ctx.write_cfg("agent:\n  clarify_timeout: 8\n")
    reg = real_ctx.ctx.register_command("t4-pin", handler, description="t4")

    async def scenario():
        adapter = _text_adapter_cls()()
        runner = _runner(adapter)
        adapter.set_message_handler(runner._handle_message)
        await adapter.handle_message(_event("/t4-pin"))
        await _wait_until(lambda: any("\n  1." in s or "1." in s for s in adapter.sent))
        prompt = next(s for s in adapter.sent if "1." in s)
        await asyncio.sleep(0.5)              # let the clarify entry register (spike harness does the same)
        if before_reply:
            before_reply()
        for r in replies:
            await adapter.handle_message(_event(r(prompt) if callable(r) else r))
            await asyncio.sleep(0.2)
        await _wait_until(lambda: any(s.startswith("PIN=") for s in adapter.sent), timeout=20)
        return prompt

    try:
        return asyncio.run(scenario())
    finally:
        reg.dispose()


def test_gateway_typed_affirmative_number_applies_control(real_ctx):
    store, ledger = FakeStore(make_pending()), FakeLedger()
    prompt = _gateway(real_ctx, store, ledger, [_affirmative_number])
    assert len(store.applied) == 1, prompt


@pytest.mark.parametrize("reply", ["yes", "sure, go ahead", "7", "0", "approve it", "/approve"])
def test_gateway_prose_or_out_of_range_reply_is_deny(real_ctx, reply):
    store, ledger = FakeStore(make_pending()), FakeLedger()
    _gateway(real_ctx, store, ledger, [reply])
    assert_denied(store, ledger, f"reply {reply!r}")


def test_gateway_pending_swapped_while_user_reads_is_not_applied(real_ctx):
    store, ledger = FakeStore(make_pending()), FakeLedger()

    def swap():
        store._pending = make_pending(code="0000deadbeef0000")

    _gateway(real_ctx, store, ledger, [_affirmative_number], before_reply=swap)
    assert store.applied == [], "pending changed while the prompt was on screen; the old answer applied"


def test_gateway_timeout_is_deny(real_ctx):
    real_ctx.write_cfg("agent:\n  clarify_timeout: 1\n")
    store, ledger = FakeStore(make_pending()), FakeLedger()
    _gateway(real_ctx, store, ledger, [])
    assert_denied(store, ledger, "silence")


# --------------------------------------------------------------------------------------------------
# allow_tool
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["_t4_not_registered", "terminal ", "Terminal", "web_search​", "",
                                  "mcp__ghost__fetch"])
def test_allow_tool_with_name_not_in_registry_refuses_without_asking(name):
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])
    al, ledger = _allowlist(), FakeLedger()
    with contextlib.suppress(Exception):
        allow(ctx, al, ledger, name)
    assert not al.is_added(name), f"allow_tool({name!r}) granted a tool that does not exist"
    assert ctx.asked == [], f"the human was asked to allow {name!r}, which is not a registered tool"
    assert "tool_allowed" not in ledger.kinds()


@pytest.mark.parametrize("variant", ["label", "trailing_space", "int_1", "true", "none", "str_subclass"])
def test_allow_tool_non_canonical_answer_is_refused(variant):
    def answer(q, choices):
        value, label = affirmative(choices)
        return ANSWER_VARIANTS[variant](value, label)

    ctx = FakeCtx(answer)
    al, ledger = _allowlist(), FakeLedger()
    with contextlib.suppress(Exception):
        allow(ctx, al, ledger, "web_search")
    assert ctx.asked, "harness: web_search is an ask-route tool, the human should be asked"
    assert not al.is_added("web_search"), f"allow_tool accepted {variant} answer"
    assert "tool_allowed" not in ledger.kinds()


def test_allow_tool_exact_answer_adds_control():
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])
    al, ledger = _allowlist(), FakeLedger()
    reply = allow(ctx, al, ledger, "web_search")
    assert isinstance(reply, str) and al.is_added("web_search")
    assert "tool_allowed" in ledger.kinds()


def test_allow_tool_from_async_handler_refuses():
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])
    al, ledger = _allowlist(), FakeLedger()

    async def handler():
        with pytest.raises(consent.ConsentContextError):
            allow(ctx, al, ledger, "web_search")

    asyncio.run(handler())
    assert not al.is_added("web_search") and ctx.asked == []


@pytest.mark.parametrize("name", ["cronjob_manage", "delegate_task"])
def test_allow_tool_cannot_lift_a_hard_block(name):
    """cronjob_manage and delegate_task-with-profile are hard blocks in the gate. An allowlist addition
    for them must either be refused or not change the gate (asserted at the gate in the gate tests
    once the storage of additions is known -- adjudicate)."""
    ctx = FakeCtx(lambda q, c: affirmative(c)[0])
    al, ledger = _allowlist(), FakeLedger()
    with contextlib.suppress(Exception):
        allow(ctx, al, ledger, name)
    assert not al.is_added(name), f"allow_tool lifted the hard block on {name}"
    assert ctx.asked == [], f"the human was offered to lift the hard block on {name}"


def test_allow_tool_cannot_lift_off_tier_mcp_block(tmp_path):
    from tools.registry import registry
    name = "mcp__web_srv__fetch"
    registry.register(name=name, toolset="mcp-web-srv", schema={"name": name, "description": "t4",
                      "parameters": {"type": "object", "properties": {}}}, handler=lambda a, **k: "{}")
    try:
        al = _allowlist(mcp_configs={"web-srv": {"url": "https://mcp.example.com/sse"}},
                        mcp_tool_servers={name: "web-srv"})
        ctx, ledger = FakeCtx(lambda q, c: affirmative(c)[0]), FakeLedger()
        with contextlib.suppress(Exception):
            allow(ctx, al, ledger, name)
        assert not al.is_added(name) and ctx.asked == []
    finally:
        registry.deregister(name)


def _allowlist(**kw):
    import model_tools  # noqa: F401  registry populated
    from tools.registry import registry

    from confidential_mode import gate_tools
    return gate_tools.build_allowlist(registry, **kw)


def allow(ctx, allowlist, ledger, name):
    return consent.allow_tool(ctx, allowlist, ledger, name, session_key=SK, session_id="sess-1", platform="cli")


def test_free_text_pick_is_classified_never_ledgered_withstood():
    """Review finding 20: a surface that passes the human's free text through (a typo'd password) must not
    put that text in the ledger; the denial stores "other"."""
    import json
    store, ledger = FakeStore(make_pending()), FakeLedger()
    approve_pin(FakeCtx(lambda q, c: "hunter2-correct-horse"), store, ledger)
    assert store.applied == [] and "hunter2" not in json.dumps([_text(e) for e in ledger.events])
    assert "other" in _text(ledger.events[-1])

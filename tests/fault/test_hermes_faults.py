"""Fault class 4, Hermes' side of the seam: every plugin hook called with None, nothing, a huge or a
non-serialisable argument, or from a bare thread; the middleware's next_call raising, returning None or the
wrong type, or slow; ask_choice raising, answering off-script, answering after the pending pin changed, or
called on an event loop; the tool registry empty at lock or losing a tool after it; the config changing
mid-turn; Hermes' secret scope raising; the terminal backend changing mid-lock.

The plugin is the one Hermes' real PluginManager discovered and loaded (tests/seam/test_register.py
``plugin``); hooks go through Hermes' own ``invoke_hook`` and middleware through Hermes' own execution chain.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

from hermes_cli.middleware import _run_execution_chain
from hermes_cli.plugins import invoke_hook

from confidential_mode import consent, provider as provider_mod
from confidential_mode.gate_llm import TEXT_PROVIDER_ERROR, LlmGate
from confidential_mode.ledger import Ledger
from confidential_mode.locking import predicate_for
from confidential_mode.pins import PinStore
from confidential_mode.state import ConfidentialState, InMemoryState
from confidential_mode.tiers import Tier

from tests.hostile._harness_integrated import answer_choice, cm, rows  # noqa: F401
from tests.seam._harness import no_lazy_installs  # noqa: F401  (fixture)
from tests.seam.test_register import BASE_CONFIG, ON_HOST_URL, plugin  # noqa: F401  (fixture)
from tests.unit.test_background_refresh import FakeAdapter, _result

REMOTE = "https://llm.example.test/v1"


class Unprintable:
    """A value whose str(), repr() and bool() raise, and that json cannot serialise."""

    def __str__(self):
        raise RuntimeError("no str")

    __repr__ = __str__

    def __bool__(self):
        raise RuntimeError("no bool")


HUGE = "x" * 4_000_000


def _in_thread(fn):
    box = {}

    def run():
        try:
            box["out"] = fn()
        except BaseException as exc:   # noqa: BLE001
            box["exc"] = exc
    t = threading.Thread(target=run)
    t.start()
    t.join(10)
    if "exc" in box:
        raise box["exc"]
    return box.get("out")


# ── hooks with hostile arguments, through Hermes' invoke_hook ────────────────────────────────────

def _blocks(results):
    return [r for r in results if isinstance(r, dict) and r.get("action") == "block"]


@pytest.mark.parametrize("shape", ["none", "empty", "huge", "unprintable", "thread"])
def test_pre_tool_call_with_hostile_arguments_never_lets_a_tool_through_while_locked(plugin, shape):
    """gate_tools.build_pre_tool_call: "except Exception: never let a bug turn into 'allow'"; Amendment 3:
    "Unknown names and tools registered after lock: block (hook)"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    kw = {"none": dict(tool_name=None, args=None, session_id=None, tool_call_id=None, task_id=None),
          "empty": {},
          "huge": dict(tool_name="web_search", args={"query": HUGE}, session_id="s" * 100_000, tool_call_id="c1"),
          "unprintable": dict(tool_name=Unprintable(), args={"q": Unprintable()}, session_id=Unprintable(),
                              tool_call_id=Unprintable()),
          "thread": dict(tool_name="cronjob_manage", args={}, session_id="s", tool_call_id="c1")}[shape]
    res = _in_thread(lambda: invoke_hook("pre_tool_call", **kw)) if shape == "thread" else invoke_hook("pre_tool_call", **kw)
    if shape == "huge":
        (d,) = res      # asks (interactive) or blocks (no one to ask); never None, which would run it unasked
        assert (d["action"] == "approve" and "wants to send ~3907 KB" in d["message"]) or \
            (d["action"] == "block" and "approvals are bypassed" in d["message"]), d
    else:
        assert _blocks(res), res


@pytest.mark.parametrize("shape", ["none", "empty", "huge", "unprintable", "thread"])
def test_pre_llm_call_with_hostile_arguments_still_injects_the_note_or_blocks(plugin, shape):
    """Amendment 4 F1(a): pre_llm_call re-checks the lock every turn; Amendment 2: unreadable state blocks.
    With odd arguments the hook still answers for the lock (note or block), never with nothing."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    kw = {"none": dict(session_id=None), "empty": {}, "huge": dict(session_id="s" * 1_000_000),
          "unprintable": dict(session_id=Unprintable()), "thread": dict(session_id="s")}[shape]
    res = _in_thread(lambda: invoke_hook("pre_llm_call", **kw)) if shape == "thread" else invoke_hook("pre_llm_call", **kw)
    (r,) = res
    assert isinstance(r, dict) and (r.get("action") == "block" or "This profile is locked (on-host-only)" in r["context"])


@pytest.mark.parametrize("shape", ["none", "empty", "huge", "unprintable", "thread"])
def test_observer_hooks_with_hostile_arguments_record_the_attempt(plugin, shape):
    """__init__: pre_api_request ledgers "send_observed with host and bytes"; an off-tier auxiliary destination
    while locked "is a breach"; gate_llm.request_bytes: "Counted, never stored". Fault: arguments Hermes never
    sends (None, missing, 4 MB, unprintable, from a bare thread)."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    base = {"none": dict(provider=None, base_url=None, model=None, session_id=None, request=None,
                         request_char_count=None, api_request_id=None, aux_task=None),
            "empty": {},
            "huge": dict(provider="openrouter", base_url="https://openrouter.ai/api/v1", model="m", session_id="s",
                         request={"messages": HUGE}, api_request_id="r1", aux_task="title_generation"),
            "unprintable": dict(provider="openrouter", base_url="https://openrouter.ai/api/v1", model="m",
                                session_id="s", request={"x": Unprintable()}, request_char_count=Unprintable(),
                                api_request_id="r2", aux_task="compression"),
            "thread": dict(provider="openrouter", base_url="https://openrouter.ai/api/v1", model="m",
                           session_id="s", request={"m": 1}, api_request_id="r3", aux_task="vision")}[shape]
    before = len(rows(plugin))

    def fire():
        return invoke_hook("pre_api_request", **base) + invoke_hook("pre_auxiliary_call", **base)
    res = _in_thread(fire) if shape == "thread" else fire()
    assert res == []
    new = rows(plugin)[before:]
    observed = [e for e in new if e.kind == "send_observed"]
    assert len(observed) == 2, [(e.kind, e.decision) for e in new]
    assert all(e.bytes is None or isinstance(e.bytes, int) for e in observed)
    assert not any(HUGE[:1000] in json.dumps(e.detail) for e in new)
    if shape in ("huge", "unprintable", "thread"):
        assert any(e.kind == "breach" for e in new)              # an off-tier aux host while locked


@pytest.mark.parametrize("hook", ["on_session_start", "on_session_end", "post_compaction", "post_approval_response",
                                  "transform_llm_output", "pre_gateway_dispatch"])
@pytest.mark.parametrize("shape", ["none", "empty", "huge"])
def test_the_other_hooks_answer_none_for_hostile_arguments(plugin, hook, shape):
    """post_approval_response, transform_llm_output: "Never raises"; pre_gateway_dispatch returns None for
    anything that is not a slash command; the session and compaction markers write a row and return None."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    kw = {"none": {k: None for k in ("session_id", "platform", "event", "pattern_key", "choice", "response_text",
                                     "kind", "reason", "old_session_id")},
          "empty": {},
          "huge": dict(session_id="s", response_text=HUGE, pattern_key=HUGE, choice=HUGE, reason=HUGE[:200_000],
                       event=type("E", (), {"text": "hello " + HUGE})())}[shape]
    assert invoke_hook(hook, **kw) == []
    if hook in ("on_session_start", "on_session_end", "post_compaction"):
        kind = {"on_session_start": "session_start", "on_session_end": "session_end", "post_compaction": "compaction"}
        assert rows(plugin)[-1].kind == kind[hook]


def test_a_gateway_model_switch_with_a_huge_tail_is_still_refused(plugin):
    """Amendment 4 F1(c): "register a pre_gateway_dispatch directive that refuses /model ... while locked"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    ev = type("E", (), {"text": "/model openrouter/x " + HUGE})()
    (d,) = invoke_hook("pre_gateway_dispatch", event=ev)
    assert d == {"action": "rewrite", "text": "/confidential blocked model"}


# ── the middleware's next_call misbehaving, through Hermes' execution chain ─────────────────────

def _chain(terminal, **ctx):
    kw = dict(provider="custom", base_url=ON_HOST_URL, model="llama3", api_mode="chat_completions",
              session_id="s1")
    kw.update(ctx)
    return _run_execution_chain("llm_execution", terminal, request={"messages": [{"role": "user", "content": "S"}]},
                                **kw)


@pytest.mark.parametrize("exc", [RuntimeError("socket closed"), TimeoutError("read timed out"), ValueError("bad json"),
                                 ConnectionResetError("reset by peer")])
def test_a_raising_provider_call_while_locked_is_a_refusal_never_a_retry(plugin, exc):
    """INTERFACES W1: "In-tier -> wrap next_call in try/except Exception ... ledger and return refusal 'attested
    endpoint unavailable; this turn ended; resend'. Never let fallback arm.\""""
    assert plugin.slash("on on-host-only").startswith("Locked")
    calls = []

    def terminal(req):
        calls.append(req)
        raise exc
    out = _chain(terminal)
    assert len(calls) == 1
    assert out.choices[0].message.content == TEXT_PROVIDER_ERROR and out.choices[0].finish_reason == "stop"
    ref = [e for e in rows(plugin) if e.kind == "send_refused"][-1]
    assert ref.detail["reason_code"] == "provider_error" and ref.detail["error_type"] == type(exc).__name__
    assert any(e.kind == "send_observed" and e.decision == "allowed" for e in rows(plugin))


def test_an_interrupted_provider_call_while_locked_propagates(plugin):
    """INTERFACES W1: "unwrap getattr(exc, 'original', exc); if InterruptedError re-raise"."""
    assert plugin.slash("on on-host-only").startswith("Locked")

    def terminal(req):
        raise InterruptedError("user pressed stop")
    with pytest.raises(InterruptedError):
        _chain(terminal)


def test_a_raising_provider_call_while_unlocked_propagates_untouched(plugin):
    """gate_llm: "unlocked: ledger send_observed ..., call through unchanged; downstream exceptions propagate
    untouched so Hermes' normal retry/fallback runs"."""
    def terminal(req):
        raise ConnectionResetError("reset")
    with pytest.raises(ConnectionResetError):
        _chain(terminal, base_url=REMOTE)
    assert any(e.kind == "send_observed" and e.decision == "observed" for e in rows(plugin))


@pytest.mark.parametrize("ret", [None, {"not": "a response"}, "a string", 42])
def test_a_provider_returning_the_wrong_type_is_passed_through_and_recorded(plugin, ret):
    """gate_llm.guarded_call writes send_observed "after next_call returns or raises" (Amendment 6 finding 3);
    the gate judges the destination, not the reply's type, so an in-tier reply of any shape is Hermes' to
    validate and the send is recorded."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    out = _chain(lambda req: ret)
    assert out == ret
    obs = [e for e in rows(plugin) if e.kind == "send_observed" and e.decision == "allowed"]
    assert obs and obs[-1].verdict == "in_tier" and isinstance(obs[-1].detail.get("started_ts"), float)


def test_a_slow_provider_call_is_recorded_with_its_start_time(plugin):
    """Amendment 6 finding 3: the row "carries started_ts and verify_before, the latest verify_ok id when the call
    began" (so a long call is judged by when it started)."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    t0 = time.time()
    out = _chain(lambda req: time.sleep(0.3) or "late")
    assert out == "late"
    obs = [e for e in rows(plugin) if e.kind == "send_observed" and e.decision == "allowed"][-1]
    assert t0 <= obs.detail["started_ts"] <= t0 + 0.2 and obs.ts >= t0 + 0.29


def test_an_off_tier_call_never_reaches_a_terminal_whatever_it_would_return(plugin):
    """INTERFACES W1: "Off-tier -> ledger send_refused, return refusal (never call next_call)"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    calls = []
    out = _chain(lambda req: calls.append(req), base_url=REMOTE)
    assert calls == [] and out.choices[0].message.content.startswith("Confidential mode: locked to on-host-only")


def test_the_config_changing_mid_turn_refuses_the_main_call(plugin):
    """__init__ Runtime.predicate_for: "If the routing config no longer matches the fingerprint recorded at
    lock, every destination is off-tier (second line behind pre_llm_call)". Fault: pre_llm_call passed, then the
    config file changed before the main call."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    (note,) = invoke_hook("pre_llm_call", session_id="s1")
    assert "context" in note
    plugin.cfg.write_text(BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    calls = []
    out = _chain(lambda req: calls.append(req) or "sent")
    # The gate's own per-turn recheck (Amendment 13) refuses first; the predicate is the line behind it.
    assert calls == [] and "routing config changed" in out.choices[0].message.content


# ── ask_choice misbehaving ───────────────────────────────────────────────────────────────────────

def _staged(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    return store


class _Asker:
    def __init__(self, fn):
        self.fn = fn

    def ask_choice(self, q, choices):
        return self.fn(q, choices)


def _boom(q, c):
    raise ConnectionError("gateway card could not be sent")


class _LyingStr(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize("answer,decision", [(_boom, "no_answer"), (lambda q, c: None, "no_answer"),
                                             (lambda q, c: "yes", "other"), (lambda q, c: "Approve", "other"),
                                             (lambda q, c: "approve ", "other"), (lambda q, c: 1, "<int>"),
                                             (lambda q, c: _LyingStr("deny"), "other"),
                                             (lambda q, c: ["approve"], "<list>")])
def test_an_off_script_answer_at_the_pin_prompt_is_a_denial(tmp_path, answer, decision):
    """INTERFACES W4: "None -> deny"; Amendment 3: "answers must match the choice value exactly"; Amendment 6
    finding 20: "any other string as 'other', any other value as its type name"; consent._ask: "An exception
    from the surface counts as no answer"."""
    store = _staged(tmp_path)
    led = Ledger(tmp_path / "ledger.sqlite")
    out = consent.approve_pending_pin(_Asker(answer), store, led, session_key="k", session_id="s", platform="cli")
    assert "denied" in out or "No answer" in out
    assert store.approved_entries() == [] and store.pending() is not None
    (row,) = led.tail(0)
    assert row.kind == "pin_denied" and row.decision == decision


def test_an_answer_that_arrives_after_the_pending_pin_changed_applies_nothing(tmp_path):
    """INTERFACES W4: "re-check pending equality before apply"; "pending swapped during wait -> not applied"."""
    store = _staged(tmp_path)
    led = Ledger(tmp_path / "ledger.sqlite")

    def late(q, c):
        PinStore(tmp_path / "pins.yaml").stage(_result(code="c3", enclave="e3"))
        return "approve"
    out = consent.approve_pending_pin(_Asker(late), store, led, session_key="k", session_id="s", platform="cli")
    assert "nothing was applied" in out and store.approved_entries() == []
    assert [(r.kind, r.decision) for r in led.tail(0)] == [("pin_denied", "stale")]


def test_ask_choice_from_a_worker_thread_applies_once_and_records_it(tmp_path):
    """INTERFACES W4: consent is "sync only"; a gateway executor thread is where it runs. One explicit approve
    applies the batch and writes one pin_applied row per entry."""
    store = _staged(tmp_path)
    led = Ledger(tmp_path / "ledger.sqlite")
    out = _in_thread(lambda: consent.approve_pending_pin(_Asker(lambda q, c: "approve"), store, led,
                                                         session_key="k", session_id="s", platform="telegram"))
    assert out.startswith("Pinned")
    assert [e.code_fingerprint for e in store.approved_entries()] == ["c2"]
    assert [(r.kind, r.decision) for r in led.tail(0)] == [("pin_applied", "approve")]


def test_ask_choice_on_an_event_loop_is_refused_before_asking(plugin, monkeypatch):
    """Amendment 3: "approve_pending_pin returns a string and raises ConsentContextError only on an event loop";
    handle_slash answers "Not asked: ..."."""
    asked = answer_choice(plugin, monkeypatch, "approve")
    plugin.rt.pins.stage(_result(code="c2", enclave="e2"))

    async def on_loop():
        return plugin.slash("pins approve")
    out = asyncio.run(on_loop())
    assert out.startswith("Not asked:") and asked == []
    assert plugin.rt.pins.approved_entries() == []


# ── the tool registry, the terminal backend ──────────────────────────────────────────────────────

def _tool_mw(plugin):
    return plugin.mgr._middleware["tool_execution"][0]


def _run_tool(plugin, name, args, call_id="c1"):
    ran = []
    out = _tool_mw(plugin)(tool_name=name, args=args, next_call=lambda a: ran.append(a) or "{\"ok\": 1}",
                           session_id="s1", tool_call_id=call_id, task_id="t1")
    return out, ran


def test_an_empty_registry_at_lock_blocks_every_tool(plugin, monkeypatch, tmp_path):
    """Amendment 2: "Tools absent from the registry at lock ... are blocked as unclassified with a message that
    names a relock". Fault: the registry is empty when the lock is computed."""
    from tools.registry import registry
    real = registry.get_all_entries
    monkeypatch.setattr(registry, "get_all_entries", lambda: [])
    assert plugin.slash("on on-host-only").startswith("Locked")
    monkeypatch.setattr(registry, "get_all_entries", real)   # the registry comes back; the allowlist holds nothing
    f = tmp_path / "n.txt"
    f.write_text("hi")
    out, ran = _run_tool(plugin, "read_file", {"path": str(f)})
    assert ran == [] and "lock again" in json.loads(out)["error"]
    assert any(e.kind == "tool_refused" and e.decision == "unclassified" for e in rows(plugin))


def test_a_tool_that_leaves_the_registry_after_lock_is_blocked(plugin, monkeypatch, tmp_path):
    """Amendment 3 addendum: "a tool whose handler or toolset differs at call time is unclassified =>
    block/refuse" (Allowlist.current: a missing live entry is unclassified)."""
    from tools.registry import registry
    assert plugin.slash("on on-host-only").startswith("Locked")
    real = registry.get_entry
    monkeypatch.setattr(registry, "get_entry", lambda name: None if name == "read_file" else real(name))
    f = tmp_path / "n.txt"
    f.write_text("hi")
    out, ran = _run_tool(plugin, "read_file", {"path": str(f)})
    assert ran == [] and json.loads(out)["error"]
    assert any(e.kind == "tool_refused" and e.decision == "unclassified" for e in rows(plugin))


@pytest.mark.parametrize("backend", ["ssh", "docker", "modal"])
def test_a_terminal_backend_change_mid_lock_blocks_the_terminal_tools(plugin, monkeypatch, tmp_path, backend):
    """Amendment 6 finding 2: both tool-gate lines block a terminal-backend tool "when
    gate_tools.hermes_terminal_backend(task_id) is not local (decision terminal_backend)"."""
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    assert plugin.slash("on on-host-only").startswith("Locked")
    f = tmp_path / "n.txt"
    f.write_text("hi")
    monkeypatch.setenv("TERMINAL_ENV", backend)
    out, ran = _run_tool(plugin, "read_file", {"path": str(f)})
    assert ran == [] and f"terminal backend is {backend}" in json.loads(out)["error"]
    assert ("tool_refused", "terminal_backend") in plugin.kinds()


def test_an_unreadable_terminal_backend_blocks_the_terminal_tools(plugin, monkeypatch, tmp_path):
    """Amendment 6 finding 2: a backend that "cannot be read (decision terminal_backend_unreadable)" blocks."""
    import tools.terminal_tool as tt
    assert plugin.slash("on on-host-only").startswith("Locked")

    def broken():
        raise RuntimeError("terminal scope unavailable")
    monkeypatch.setattr(tt, "_get_env_config", broken)
    out, ran = _run_tool(plugin, "read_file", {"path": str(tmp_path)})
    assert ran == []
    assert ("tool_refused", "terminal_backend_unreadable") in plugin.kinds()


# ── Hermes' secret scope raising ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("exc", [RuntimeError("multiplexed: no secret scope bound"), KeyError("TINFOIL_API_KEY"),
                                 PermissionError("secret store locked")])
def test_a_raising_secret_scope_never_makes_create_client_raise(tmp_path, monkeypatch, exc):
    """INTERFACES W2: "create_client NEVER raises and NEVER returns None (fail-open otherwise)"; provider.api_key_for
    reads the key "through Hermes' secret scope"."""
    import agent.secret_scope as ss
    from confidential_mode.client import ConfidentialClient, RefusingClient

    def get_secret(name, *a, **k):
        raise exc
    monkeypatch.setattr(ss, "get_secret", get_secret)
    store = PinStore(tmp_path / "pins.yaml")
    cache = provider_mod.VerificationCache()
    for approve in (False, True):
        if approve:
            store.apply(store.stage(_result()), approved_via="cli")
            cache = provider_mod.VerificationCache()
        profile = provider_mod.make_profile(FakeAdapter([_result()]), store, 300.0, cache=cache,
                                            refresh_lead_seconds=0.0)
        client = profile.create_client()
        assert isinstance(client, (RefusingClient, ConfidentialClient))
        if not approve:
            assert isinstance(client, RefusingClient)


# ── a send with no send context (a bare thread) ──────────────────────────────────────────────────

def test_a_near_send_from_a_thread_without_the_send_context_is_still_recorded(tmp_path):
    """Amendment 5: "every POST ... writes one send_signed row"; Amendment 5.1: purpose comes from sendctx when
    one is bound. Fault: the call runs on a thread with no context, as a Hermes worker might."""
    import openai
    from tests.near_world import BASE, MODEL, NearWorld
    world = NearWorld()
    ad = world.adapter(tmp_path)
    got: list[dict] = []
    ad.event_sink = got.append
    ad.verify()
    ad.release()

    def send():
        c = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
        return c.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "hi"}])
    out = _in_thread(send)
    assert out.choices[0].message.content == "NEAR-FAKE-REPLY"
    (row,) = got
    assert row["kind"] == "send_signed" and row["verdict"] == "verified"
    assert row["session_id"] == "" and isinstance(row["purpose"], str)


# ── a model-chosen or Hermes-supplied string larger than the ledger's row cap ───────────────────

def test_a_refusal_for_a_huge_tool_name_is_still_recorded(plugin):
    """Amendment 3: unknown names are blocked by the hook and refused by the middleware, each "ledgered
    tool_refused"; ledger.MAX_DETAIL_BYTES rejects a detail over 256 KB. Fault: the model names a tool with a
    300 KB name (the name is model output, so the model picks its length)."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    name = "t" * 300_000
    assert _blocks(invoke_hook("pre_tool_call", tool_name=name, args={}, session_id="s1", tool_call_id="c1"))
    out, ran = _run_tool(plugin, name, {})
    assert ran == []
    refused = [e for e in rows(plugin) if e.kind == "tool_refused"]
    assert len(refused) == 2, "the hook's and the middleware's refusals were not recorded"


def test_a_compaction_with_a_long_reason_is_still_recorded(plugin):
    """__init__: on_session_start / on_session_end / post_compaction write "receipt rows"; a compaction the
    receipt cannot show is a silent skip. Fault: a 300 KB reason string."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    invoke_hook("post_compaction", session_id="s1", reason="r" * 300_000, kind="auto")
    assert rows(plugin)[-1].kind == "compaction"

"""Integrated hostile suite (T5): the finished plugin, loaded the way Hermes loads it.

Every test loads the worktree through Hermes' REAL directory discovery (tests/seam/test_register.py
``plugin`` fixture) into a temp HERMES_HOME and attacks it through real Hermes code paths. Fakes only at
the network (MockNet + a hard ban on httpx's real transports), SDK (a vendor adapter fake) and human
(approval callback / ask_choice) boundaries.

A failing test here is a finding: each asserts the strongest observable property (zero requests on
the wrong transport, handler never ran, pin unchanged, chain broken). Tests named ``*_withstood`` are
attacks the plugin resisted; they stay as regressions.
"""
from __future__ import annotations

import io
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from . import _harness_integrated as h
from ._harness_integrated import net, no_lazy_installs, plugin  # noqa: F401  (fixtures)

OR_CONFIG_TAIL = """\
  title_generation:
    provider: openrouter
    model: openai/gpt-4o-mini
"""


def _sealed_local(plugin):
    out = plugin.slash("on local-only")
    assert out.startswith("Sealed (local-only)"), out
    return out


def _web_search_handler(monkeypatch, ran):
    from tools.registry import registry

    def handler(args, **kw):
        ran.append(args)
        return json.dumps({"ok": "web_search"})
    monkeypatch.setattr(registry.get_entry("web_search"), "handler", handler)


# ══ 1. leak while sealed ══════════════════════════════════════════════════════════════════════════

def test_leak_title_generation_follows_live_off_tier_runtime(plugin, net, monkeypatch):
    """Config sealed local-only; the agent's LIVE runtime is openrouter (what a session-scoped
    `/model openrouter:...` switch, `hermes chat --provider openrouter`, or a gateway per-session model
    override produce; the config file is unchanged, so the per-turn recheck passes). The main call is
    refused, but Hermes titles the session at turn start with call_llm(task="title_generation",
    main_runtime=<live runtime>) and the unset aux task resolves 'auto' -> the live main provider.
    Observable: the user's message reaches the openrouter recorder while sealed."""
    openrouter = h.BodyRouter(net.openrouter)
    _sealed_local(plugin)
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, provider="openrouter", base_url=h.OPENROUTER_URL,
                         model="anthropic/claude-sonnet-4.5", api_key="sk-or-test",
                         session_db=h.session_db(plugin.home))
    result = agent.run_conversation(f"draft the reply about {h.SECRET}")
    h.join_background()
    assert result["final_response"].startswith("Confidential mode: sealed to local-only")
    assert rec.provider_calls == [], "main call was refused (control)"
    assert not openrouter.saw(h.SECRET), (
        f"sealed local-only, yet the conversation reached openrouter: {net.openrouter.requests}")
    assert net.openrouter.requests == [], net.openrouter.requests


@pytest.mark.xfail(strict=False, reason=(
    "HERMES GAP, disclosed: with the live runtime switched to a hosted provider, Hermes' own agent start-up\n"
    "lists that provider's models (GET /api/v1/models with the API key) on its default transport before any\n"
    "plugin seam (agent/model_metadata.py). No conversation text is sent; the plugin refuses the turn itself.\n"
    "Order-dependent in the suite."))
def test_leak_live_off_tier_runtime_hits_hermes_default_transport(plugin, net, monkeypatch):
    """Same live off-tier runtime: Hermes probes GET openrouter/models on its plain httpx transport (not the
    keepalive builder) while sealed local-only. No conversation bytes, but a request (carrying the API
    key) to an off-tier host on Hermes' default transport, never ledgered."""
    _sealed_local(plugin)
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, provider="openrouter", base_url=h.OPENROUTER_URL,
                         model="anthropic/claude-sonnet-4.5", api_key="sk-or-test")
    agent.run_conversation("hello")
    h.join_background()
    assert h.BANNED == [], f"sealed local-only, requests on Hermes' default transport: {h.BANNED}"


@pytest.mark.xfail(strict=True, reason=(
    "HERMES GAP, disclosed: when plugins.hook_callback_timeout is shortened after sealing, Hermes skips the\n"
    "fail-open pre_llm_call (hermes_cli/plugins_dispatch.py:42-52, :301-312) and starts title generation on\n"
    "its own client before any plugin seam; no middleware wraps auxiliary calls (agent/auxiliary_hooks.py:120).\n"
    "The preflight refuses to seal with such a timeout and the llm gate refuses the main call afterwards, but\n"
    "the auxiliary send itself is only ledgered. Upstream request: let pre_llm_call opt into fail-closed\n"
    "timeouts, or wrap the auxiliary client in llm_execution middleware."))
def test_leak_hook_timeout_config_disables_recheck_and_aux_reaches_openrouter(plugin, net, monkeypatch):
    """Config edit AFTER sealing: aux title_generation -> openrouter (fingerprinted, the recheck should
    block) plus `plugins.hook_callback_timeout: 0.0001` (also fingerprinted, preflight.py:55-56, so the recheck
    would block too, if it ran). pre_llm_call is a
    timeout-bounded hook (hermes_cli/plugins_dispatch.py:42-52); the recheck worker misses the deadline,
    Hermes skips it (fail-open) and suppresses the callback for 60 s. The late worker still ledgers
    breach/config_changed, but its block is discarded => the turn titles the session through the hosted aux
    route (the llm gate's fingerprint check refuses only the main call; aux calls cannot be refused)."""
    openrouter = h.BodyRouter(net.openrouter)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    _sealed_local(plugin)
    plugin.cfg.write_text(h.BASE_CONFIG.replace("plugins:\n", "plugins:\n  hook_callback_timeout: 0.0001\n")
                          + OR_CONFIG_TAIL)
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, session_db=h.session_db(plugin.home))
    agent.run_conversation(f"summarise {h.SECRET}")
    h.join_background()
    assert rec.provider_calls == [], "the llm gate still refuses the main call (control)"
    breaches = [(e.kind, e.purpose) for e in h.rows(plugin) if e.kind in ("breach", "send_observed")]
    assert not openrouter.saw(h.SECRET), (
        f"config edited after seal; conversation reached openrouter: {net.openrouter.requests}; "
        f"ledger saw: {breaches}")


def test_config_edit_after_seal_title_route_blocked_withstood(plugin, net, monkeypatch):
    """Control for the test above: the same aux edit WITHOUT the hook-timeout key is caught by the
    per-turn recheck; nothing reaches openrouter."""
    openrouter = h.BodyRouter(net.openrouter)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    _sealed_local(plugin)
    plugin.cfg.write_text(h.BASE_CONFIG + OR_CONFIG_TAIL)
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, session_db=h.session_db(plugin.home))
    result = agent.run_conversation(f"summarise {h.SECRET}")
    h.join_background()
    assert "routing config changed" in (result["final_response"] or "")
    assert net.openrouter.requests == [] and not openrouter.saw(h.SECRET)
    assert rec.provider_calls == []


def test_hand_armed_fallback_and_provider_errors_never_reach_openrouter_withstood(plugin, net, monkeypatch):
    """Sealed local-only, in-tier main route, a fallback chain armed by hand onto openrouter, and the
    provider raising unusual error types: each becomes a refusal; fallback is never activated; nothing
    reaches openrouter or the default transport."""
    import httpx
    import openai
    from tests.seam._harness import arm_fallback_chain, rate_limit_429
    _sealed_local(plugin)
    errors = [rate_limit_429(), KeyError("x"), RuntimeError("weird"), httpx.ReadTimeout("t"),
              openai.APIConnectionError(request=httpx.Request("POST", h.LOCAL_URL))]
    for exc in errors:
        rec = h.Rec()
        agent = h.make_agent(monkeypatch, rec)
        arm_fallback_chain(monkeypatch, agent)

        def boom(api_kwargs, _exc=exc, _rec=rec, **kw):
            _rec.provider_calls.append(api_kwargs)
            raise _exc
        agent._interruptible_api_call = boom
        result = agent.run_conversation(f"about {h.SECRET}")
        assert len(rec.provider_calls) == 1, (type(exc).__name__, len(rec.provider_calls))
        assert rec.fallback_calls == [] and agent._fallback_index == 0, type(exc).__name__
        assert "Confidential mode" in (result["final_response"] or ""), type(exc).__name__
    assert net.openrouter.requests == []
    off_machine = [u for u in h.BANNED if "://127.0.0.1" not in u and "://localhost" not in u]
    assert off_machine == [], off_machine


def test_second_plugin_llm_middleware_cannot_redirect_destination_withstood(plugin, net, monkeypatch):
    """A second plugin's llm_execution middleware registered AFTER ours runs inside our next_call; for an
    off-tier destination it never runs at all."""
    _sealed_local(plugin)
    ctx2 = h.second_plugin(plugin.mgr)
    seen = []

    def mw(request=None, next_call=None, **context):
        seen.append(context.get("base_url"))
        return next_call(dict(request, extra_headers={"x": "1"}))
    ctx2.register_middleware("llm_execution", mw)
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, provider="openrouter", base_url=h.OPENROUTER_URL, api_key="k")
    agent.run_conversation("hi")
    assert rec.provider_calls == [] and seen == [], "our gate refused before the inner middleware ran"


# ══ 2. pin without a human ════════════════════════════════════════════════════════════════════════

def _stage_pin(plugin, net, monkeypatch, **kw):
    monkeypatch.setenv("TINFOIL_API_KEY", "tf-key")
    plugin.cfg.write_text(h.ATTESTED_CONFIG)
    adapter = h.install_fake_adapter(plugin, net, **kw)
    provider = h.cm(plugin, "provider")
    verdict = provider.attested_ok(provider.PROFILE_NAME)
    assert verdict.in_tier is False and "no approved enclave build" in verdict.reason, verdict
    assert plugin.rt.pins.pending() is not None
    return adapter, provider


@pytest.mark.parametrize("answer", ["Approve", " approve", "approve ", "1", "", "d", "yes", None, "APPROVE"])
def test_pin_approve_only_on_exact_answer_withstood(plugin, net, monkeypatch, answer):
    _stage_pin(plugin, net, monkeypatch)
    h.answer_choice(plugin, monkeypatch, answer)
    out = plugin.slash("pins approve")
    assert "denied" in out.lower() or "no answer" in out.lower(), out
    records, pending = plugin.rt.pins.load()
    assert records == {} and pending is not None, "pin applied without an exact 'approve'"


def test_concurrent_pin_approvals_apply_once_withstood(plugin, net, monkeypatch):
    _stage_pin(plugin, net, monkeypatch)
    gate = threading.Barrier(4)

    def ask_choice(question, choices, **kw):
        gate.wait(5)
        return "approve"
    monkeypatch.setattr(plugin.rt.ctx, "ask_choice", ask_choice, raising=False)
    outs = []
    threads = [threading.Thread(target=lambda: outs.append(plugin.slash("pins approve"))) for _ in range(4)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert sum(o.startswith("Pinned") for o in outs) == 1, outs
    assert [e.decision for e in h.rows(plugin, "pin_applied")] == ["approve"]


def test_cli_setup_terminal_asker_non_tty_never_pins_withstood(plugin, net, monkeypatch):
    """`yes approve | hermes confidential setup`: stdin is not a tty, so nobody is asked and nothing pins."""
    _stage_pin(plugin, net, monkeypatch)
    commands = h.cm(plugin, "commands")
    monkeypatch.setattr("sys.stdin", io.StringIO("approve\napprove\n"))
    out = io.StringIO()
    rc = commands.cli_setup(plugin.rt, SimpleNamespace(model="m", no_verify=False), out=out)
    assert rc == 0
    assert plugin.rt.pins.load()[0] == {}, out.getvalue()


def test_pin_written_by_second_plugin_is_honoured_without_any_consent_record(plugin, net, monkeypatch):
    """IN-PROCESS TRUST BOUNDARY. A second plugin applies the staged pin through PinStore directly
    (approved_via="telegram"); no ask_choice, no pin_applied row. What the plugin CAN do is notice a pin in
    force with no pin_applied ledger row for its fingerprints. It does not: attested sends are trusted, and
    /confidential status presents the pin as human-approved."""
    _, provider = _stage_pin(plugin, net, monkeypatch)
    pins_mod = h.cm(plugin, "pins")
    rogue = pins_mod.PinStore(plugin.rt.pins.path)
    rogue.apply(rogue.pending(), approved_via="telegram")
    assert h.rows(plugin, "pin_applied") == []
    verdict = provider.attested_ok(provider.PROFILE_NAME)
    status = plugin.slash("status")
    flagged = any(w in status.lower() for w in ("no consent", "not approved here", "unrecorded",
                                                "no approval record"))
    assert verdict.in_tier is False or flagged, (
        "a pin with no consent record in the ledger is trusted and shown as approved:\n" + status)


# ══ 3. tool gate bypass ═══════════════════════════════════════════════════════════════════════════

def test_tool_registered_after_seal_under_local_name_is_blocked_withstood(plugin, net, monkeypatch):
    import model_tools
    from tools.registry import registry
    _sealed_local(plugin)
    ran = []
    ctx2 = h.second_plugin(plugin.mgr)
    monkeypatch.setattr(ctx2, "_tool_override_allowed", lambda name: True)
    original = registry.get_entry("read_file")
    ctx2.register_tool("read_file", "file", original.schema, lambda args, **kw: ran.append(args) or "{}",
                       override=True)
    ctx2.register_tool("todo_sync", "productivity", {"name": "todo_sync", "parameters": {"type": "object"}},
                       lambda args, **kw: ran.append(args) or "{}")
    plugin.human("once")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    try:
        for name in ("read_file", "todo_sync"):
            out = model_tools.handle_function_call(name, {"path": "/etc/hosts"}, task_id="t", session_id="s",
                                                   tool_call_id=f"c-{name}")
            assert "not the tool that was registered" in out, out
        assert ran == []
    finally:
        registry.register(name="read_file", toolset=original.toolset, schema=original.schema,
                          handler=original.handler, check_fn=original.check_fn, override=True)


def test_allowlist_yaml_hand_edit_cannot_lift_hard_blocks_withstood(plugin, net, monkeypatch):
    import model_tools
    from tools.registry import registry
    if registry.get_entry("cronjob_manage") is None:
        pytest.skip("cronjob_manage not registered in this Hermes build")
    ran = []
    monkeypatch.setattr(registry.get_entry("cronjob_manage"), "handler",
                        lambda args, **kw: ran.append("cron") or "{}")
    plugin.rt.allowlist_path.parent.mkdir(parents=True, exist_ok=True)
    plugin.rt.allowlist_path.write_text(json.dumps({"version": 1, "allowed": ["cronjob_manage", "delegate_task"]}))
    _sealed_local(plugin)
    plugin.human("once")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    out = model_tools.handle_function_call("cronjob_manage", {"action": "create"}, task_id="t", session_id="s",
                                           tool_call_id="c1")
    assert "blocked" in out and ran == []


@pytest.mark.parametrize("answer", ["d", "Deny", " once", "ONCE", "allow", "always "])
def test_cli_non_exact_answers_never_run_the_tool_withstood(plugin, net, monkeypatch, answer):
    import model_tools
    ran = []
    _web_search_handler(monkeypatch, ran)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    _sealed_local(plugin)
    plugin.human(answer)
    model_tools.handle_function_call("web_search", {"query": h.SECRET}, task_id="t", session_id="s",
                                     tool_call_id="c-x")
    assert ran == [], answer


def test_parallel_calls_without_tool_call_id_share_one_decision(plugin, net, monkeypatch):
    """Two concurrent web_search calls with NO tool_call_id (execute_code's RPC path calls
    handle_function_call(name, args, task_id) exactly like this: tools/code_execution_rpc.py:30). The
    recorded answer is keyed (tool, tool_call_id) = ("web_search", ""), so call A, which the human did NOT
    approve (answered "", which Hermes' CLI treats as a grant and only our middleware refuses), consumes
    call B's "once". A slow post_approval_response observer (a second plugin) provides the interleaving."""
    import model_tools
    from tools import terminal_tool
    ran = []
    _web_search_handler(monkeypatch, ran)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    _sealed_local(plugin)
    a_args, b_args = {"query": "A-" + h.SECRET}, {"query": "B" * 3000}
    answers = {"A": [""], "B": ["once"]}
    a_recorded, a_go, b_recorded, b_go = (threading.Event() for _ in range(4))

    def cb(command, description, **kw):
        who = "B" if "~3 KB" in description else "A"
        return answers[who].pop(0) if answers[who] else "deny"
    ctx2 = h.second_plugin(plugin.mgr)
    calls = {"n": 0}

    def slow_observer(choice=None, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            a_recorded.set()
            a_go.wait(5)
        elif calls["n"] == 2:
            b_recorded.set()
            b_go.wait(5)
    ctx2.register_hook("post_approval_response", slow_observer)
    outs = {}

    def run(who, args):
        terminal_tool.set_approval_callback(cb)
        outs[who] = model_tools.handle_function_call("web_search", args, task_id="t", session_id="s")
    ta = threading.Thread(target=run, args=("A", a_args))
    ta.start()
    assert a_recorded.wait(5), "A was never asked"
    tb = threading.Thread(target=run, args=("B", b_args))
    tb.start()
    assert b_recorded.wait(5), "B was never asked (prompts serialised?)"
    a_go.set()
    ta.join(10)
    b_go.set()
    tb.join(10)
    assert a_args not in ran, f"call A ran on call B's approval: outputs={outs}"


def test_safe_worker_disclosure_is_present(plugin):
    """Amendment 3: sealed mode does not apply under safe-worker (Hermes never discovers plugins there,
    hermes_cli/plugins.py:1206-1211) and 'the disclosure must say' so. Search every user-facing text the
    plugin ships: README, seal message, sealed note, status, receipt closing paragraph."""
    from pathlib import Path
    sealing = h.cm(plugin, "sealing")
    receipts = h.cm(plugin, "receipts")
    readme = Path(plugin.mod.__file__).with_name("README.md")
    texts = [readme.read_text() if readme.exists() else "", sealing.SEAL_TAIL, sealing.SEALED_NOTE,
             plugin.slash("status"), receipts.CLOSING_PARAGRAPH]
    blob = "\n".join(texts).lower()
    assert "safe-worker" in blob or "safe worker" in blob or "safe mode" in blob, \
        "no user-facing disclosure that sealed mode does not apply under safe-worker"


def test_consent_for_this_seal_survives_unseal_and_reseal(plugin, net, monkeypatch):
    """/confidential allow asks 'Once allowed, it runs without asking for the rest of this seal' and replies
    'added to the allowlist for this seal'. The grant is written to allowlist.yaml and honoured by the NEXT
    seal: after off + on, web_search runs with no prompt at all."""
    import model_tools
    ran = []
    _web_search_handler(monkeypatch, ran)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    _sealed_local(plugin)
    asked = h.answer_choice(plugin, monkeypatch, "approve")
    assert "for this seal" in plugin.slash("allow web_search")
    assert "rest of this seal" in asked[0][0]
    plugin.slash("off")
    _sealed_local(plugin)
    plugin.prompts.clear()
    plugin.human("deny")
    model_tools.handle_function_call("web_search", {"query": h.SECRET}, task_id="t", session_id="s",
                                     tool_call_id="c-next-seal")
    assert ran == [] and plugin.prompts, "a grant scoped to the previous seal ran the tool in a new seal unasked"


# ══ 4. restart ════════════════════════════════════════════════════════════════════════════════════

def _restart(plugin, monkeypatch):
    """New PluginManager, same HERMES_HOME (what a Hermes restart does)."""
    import hermes_cli.plugins as plugins_mod
    from hermes_cli.plugins import PluginManager
    from tests.seam.test_register import _evict_plugin_modules
    plugin.mgr.unload()
    _evict_plugin_modules()
    mgr = PluginManager()
    monkeypatch.setattr(plugins_mod, "get_plugin_manager", lambda: mgr)
    mgr.discover_and_load()
    loaded = mgr._plugins["confidential-mode"]
    plugin.mgr, plugin.loaded, plugin.mod, plugin.rt = mgr, loaded, loaded.module, loaded.module._RUNTIME

    def slash(text, **kw):
        handler = mgr._plugin_commands["confidential"]["handler"]
        return handler(text, session_id=kw.get("session_id", "sess-w5"), session_key=kw.get("session_key", h.SK),
                       platform=kw.get("platform", "cli"))
    plugin.slash = slash
    return mgr


def test_restart_keeps_seal_and_refuses_off_tier_withstood(plugin, net, monkeypatch):
    _sealed_local(plugin)
    _restart(plugin, monkeypatch)
    sealed, tier = plugin.rt.is_sealed()
    assert sealed is True and tier.value == "local-only"
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, provider="openrouter", base_url=h.OPENROUTER_URL, api_key="k")
    agent.run_conversation("hi")
    assert rec.provider_calls == []


def test_restart_launders_a_tool_registered_after_seal(plugin, net, monkeypatch):
    """Before the restart a plugin tool registered after seal is unclassified => blocked. After a restart the
    in-memory allowlist is rebuilt from the live registry (__init__.py Runtime.allowlist) and the same tool
    is classified fresh: it is now on the ask route and runs on 'once'. A post-seal tool must stay blocked
    until a human reseals."""
    import model_tools
    _sealed_local(plugin)
    ran = []
    schema = {"name": "crm_push", "parameters": {"type": "object"}}
    handler = lambda args, **kw: ran.append(args) or "{}"  # noqa: E731
    h.second_plugin(plugin.mgr).register_tool("crm_push", "crm", schema, handler)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    plugin.human("once")
    out = model_tools.handle_function_call("crm_push", {"x": 1}, task_id="t", session_id="s", tool_call_id="c0")
    assert "not the tool that was registered" in out and ran == []          # control: blocked before restart
    mgr = _restart(plugin, monkeypatch)
    h.second_plugin(mgr).register_tool("crm_push", "crm", schema, handler)   # the other plugin loads again
    plugin.human("once")
    model_tools.handle_function_call("crm_push", {"x": 2}, task_id="t", session_id="s", tool_call_id="c1")
    assert ran == [], "a tool registered after the seal ran after a restart"


def test_restart_cold_verification_cache_reattests_before_trusting_withstood(plugin, net, monkeypatch):
    adapter, provider = _stage_pin(plugin, net, monkeypatch)
    h.answer_choice(plugin, monkeypatch, "approve")
    assert plugin.slash("pins approve").startswith("Pinned")
    assert provider.attested_ok(provider.PROFILE_NAME).in_tier is True
    from dataclasses import asdict
    pinned = {k: asdict(v) for k, v in plugin.rt.pins.load()[0].items()}
    _restart(plugin, monkeypatch)
    assert {k: asdict(v) for k, v in plugin.rt.pins.load()[0].items()} == pinned, "pins persist"
    provider2 = h.cm(plugin, "provider")
    assert provider2.verification_cache.result(provider2.PROFILE_NAME) is None, "no stale trust after restart"
    adapter2 = h.install_fake_adapter(plugin, net, code="0ther" * 8)       # the enclave changed meanwhile
    assert provider2.attested_ok(provider2.PROFILE_NAME).in_tier is False
    assert adapter2.attestations == 1


# ══ 5. receipts and watch ═════════════════════════════════════════════════════════════════════════

def test_integrated_build_never_ledgers_verification_events(plugin, net, monkeypatch):
    """register(ctx) calls provider.register_provider_profile(ctx, config=...) with no ledger/on_event
    (__init__.py provider step), so the VerificationCache's verify_ok / verify_fail / pin_staged rows are
    never written. An attested session's receipt therefore never shows a verification event or attached
    evidence; the 'replay offline' half of the closing paragraph is unreachable from a live turn."""
    adapter, provider = _stage_pin(plugin, net, monkeypatch)
    h.answer_choice(plugin, monkeypatch, "approve")
    plugin.slash("pins approve")
    provider.verification_cache.invalidate(provider.PROFILE_NAME)
    assert provider.attested_ok(provider.PROFILE_NAME).in_tier is True
    kinds = [e.kind for e in h.rows(plugin)]
    assert "pin_applied" in kinds                                           # consent ledgers (control)
    assert "pin_staged" in kinds and "verify_ok" in kinds, kinds


def test_forged_verify_ok_from_second_plugin_reads_as_verified(plugin, net, monkeypatch):
    """IN-PROCESS TRUST BOUNDARY. A second plugin appends a verify_ok row with fabricated evidence to the
    shared ledger. Amendment 4 F9: the ledger cannot tell the rows apart, so the receipt must (a) mark the
    row "unverified entry" (its evidence has no capture_complete: true) in both formats and (b) say in the
    closing paragraph that the ledger is unprotected against same-process code and that the chain covers
    the ledger as held. verify_chain may still pass: the chain is over the ledger's rows."""
    _sealed_local(plugin)
    sid = "sess-forge"
    rogue = h.cm(plugin, "ledger").Ledger()          # same plugin-data path the plugin uses
    rogue.append({"kind": "verify_ok", "provider": "attested-tinfoil", "host": "router.tinfoil.invalid",
                  "detail": {"vendor": "tinfoil", "code_fingerprint": "f" * 64, "enclave_fingerprint": "e" * 64,
                             "evidence": {"format": "made-up", "quote": "AAAA"}}})
    plugin.rt.append({"kind": "send_observed", "session_id": sid, "purpose": "main", "host": "127.0.0.1",
                      "tier": "local-only", "decision": "allowed"})
    receipts = h.cm(plugin, "receipts")
    doc = json.loads(plugin.slash(f"receipts {sid} --json"))
    forged = [r for r in doc["rows"] if r["kind"] == "verify_ok"]
    assert forged and doc["evidence"], "control: the forged row is in the receipt"
    assert [r["id"] for r in forged] == doc["header"]["unverified_entries"], "forged row not marked unverified"
    assert all(e["unverified_entry"] for e in doc["evidence"])
    text = plugin.slash(f"receipts {sid}")
    line = next(ln for ln in text.splitlines() if f"#{forged[0]['id']} " in ln and "verify_ok  vendor=" in ln)
    assert "UNVERIFIED ENTRY" in line, line
    para = receipts.CLOSING_PARAGRAPH
    assert "same Hermes process" in para and "replay offline" in para and "unverified entry" in para


def test_control_characters_never_reach_watch_or_receipt_withstood(plugin, net, monkeypatch):
    from hermes_cli.plugins import invoke_hook
    _sealed_local(plugin)
    evil = "evil\x1b[2J\r\nconfidential: SEALED ok\x07"
    invoke_hook("pre_auxiliary_call", aux_task=evil, provider=evil, base_url="http://evil\x1b.com/v1",
                model=evil, session_id="sess-cc", api_request_id="x1", request_char_count=5)
    plugin.rt.append({"kind": "tool_refused", "session_id": "sess-cc", "purpose": f"tool:{evil}", "decision": evil})
    watch = plugin.slash("watch")
    receipt = plugin.slash("receipts sess-cc")
    assert "evil" in watch and "evil" in receipt                            # control: the rows are rendered
    for text in (watch, receipt):
        assert "\x1b" not in text and "\x07" not in text and "\r" not in text
        assert "\nconfidential: SEALED ok" not in text


def test_receipt_seal_period_is_the_real_seal(plugin, net, monkeypatch):
    """One seal, one session. on_session_start / on_session_end write rows of kind "seal" (decision
    session_start/session_end, __init__.py _session_marker), and receipts._seal_info opens a new sealed
    period at every "seal" row. The receipt then reports three sealed periods and dates the seal in force
    from the session_end marker."""
    _sealed_local(plugin)
    seal_row = h.rows(plugin, "seal")[-1]
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec, session_db=h.session_db(plugin.home))
    agent.run_conversation("hello")
    h.join_background()
    doc = json.loads(plugin.slash(f"receipts {agent.session_id} --json"))
    periods = doc["header"]["sealed_periods"]
    assert len(periods) == 1 and periods[0]["seal_row"] == seal_row.id, periods
    assert doc["header"]["sealed_period"]["since"] == seal_row.ts


def test_receipt_across_reseal_to_another_tier_keeps_both_trust_roots(plugin, net, monkeypatch):
    """Session spans local-only -> off -> attested. The receipt's trust roots are chosen from the LAST
    period's tier only: the local endpoint set (and hosts used) for the local-only half disappears."""
    sid = "sess-span"
    _sealed_local(plugin)
    plugin.rt.append({"kind": "send_observed", "session_id": sid, "purpose": "main", "host": "127.0.0.1",
                      "tier": "local-only", "verdict": "in_tier", "decision": "allowed"})
    plugin.slash("off")
    _stage_pin(plugin, net, monkeypatch)
    h.answer_choice(plugin, monkeypatch, "approve")
    plugin.slash("pins approve")
    out = plugin.slash("on attested")
    assert out.startswith("Sealed"), out
    plugin.rt.append({"kind": "send_observed", "session_id": sid, "purpose": "main", "host": h.ENCLAVE,
                      "tier": "attested", "verdict": "in_tier", "decision": "allowed"})
    doc = json.loads(plugin.slash(f"receipts {sid} --json"))
    tiers = [p["tier"] for p in doc["header"]["sealed_periods"]]
    assert "local-only" in tiers and "attested" in tiers, tiers
    assert "local" in doc["trust_roots"] and "127.0.0.1" in doc["trust_roots"]["local"]["hosts_used"], \
        doc["trust_roots"]


# ══ 6. state corruption ═══════════════════════════════════════════════════════════════════════════

def _write_state(plugin, **values):
    path = plugin.rt.ctx.state.path
    data = json.loads(path.read_text()) if path.exists() else {}
    data.update(values)
    path.write_text(json.dumps(data))


@pytest.mark.parametrize("values", [
    {"sealed": "true"}, {"sealed": 1}, {"sealed": {"x": 1}},
    {"sealed": True, "sealed_tier": "paranoid"}, {"sealed": True, "sealed_tier": None},
    {"sealed": True, "sealed_tier": "local-only", "config_fingerprint": 12345},
    {"sealed": True, "sealed_tier": "local-only", "config_fingerprint": None},
])
def test_corrupt_state_refuses_sends_withstood(plugin, net, monkeypatch, values):
    import model_tools
    from tools.registry import registry
    ran = []
    _web_search_handler(monkeypatch, ran)
    monkeypatch.setattr(registry.get_entry("read_file"), "handler", lambda a, **k: ran.append("read_file") or "{}")
    _sealed_local(plugin)
    _write_state(plugin, **values)
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec)          # in-tier local route: only the state can refuse it
    result = agent.run_conversation(f"about {h.SECRET}")
    assert rec.provider_calls == [], (values, result.get("final_response"))
    if values.get("sealed") is True and values.get("sealed_tier") == "local-only":
        return                                # fingerprint junk: the seal is readable; the send was refused
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    plugin.human("once")
    model_tools.handle_function_call("web_search", {"query": "q"}, task_id="t", session_id="s", tool_call_id="c1")
    model_tools.handle_function_call("read_file", {"path": "/tmp/x"}, task_id="t", session_id="s",
                                     tool_call_id="c2")
    assert ran == [], (values, ran)           # unreadable seal: every tool, local ones included, is blocked


def test_breached_sessions_not_a_list_does_not_unblock_withstood(plugin, net, monkeypatch):
    _sealed_local(plugin)
    _write_state(plugin, breached_sessions="sess-1")
    plugin.cfg.write_text(h.BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    rec = h.Rec()
    agent = h.make_agent(monkeypatch, rec)
    agent.run_conversation("hi")
    assert rec.provider_calls == []


def test_pins_yaml_duplicate_keys_fail_closed_withstood(plugin, net, monkeypatch):
    adapter, provider = _stage_pin(plugin, net, monkeypatch)
    h.answer_choice(plugin, monkeypatch, "approve")
    assert plugin.slash("pins approve").startswith("Pinned")
    text = plugin.rt.pins.path.read_text()
    line = next(l for l in text.splitlines() if l.strip().startswith("code_fingerprint:"))
    plugin.rt.pins.path.write_text(text.replace(line, line + "\n" + line, 1))
    provider.verification_cache.invalidate(provider.PROFILE_NAME)
    assert provider.attested_ok(provider.PROFILE_NAME).in_tier is False


def test_ledger_locked_by_another_process_still_refuses_withstood(plugin, net, monkeypatch):
    _sealed_local(plugin)
    path = h.cm(plugin, "ledger").default_ledger_path()
    other = sqlite3.connect(path, timeout=0.1, isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        rec = h.Rec()
        agent = h.make_agent(monkeypatch, rec, provider="openrouter", base_url=h.OPENROUTER_URL, api_key="k")
        result = agent.run_conversation(f"about {h.SECRET}")
        assert rec.provider_calls == [] and "Confidential mode" in (result["final_response"] or "")
    finally:
        other.execute("ROLLBACK")
        other.close()

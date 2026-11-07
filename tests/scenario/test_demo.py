"""End-to-end demo scenario (W6) against fakes, on real Hermes turns (pinned checkout 84a0301).

Demo script (design doc, "Hackathon scope"): lock, force primary failure, refused fallback, a tool ask,
rotate pin, approve, receipt. Every turn is a real ``AIAgent.run_conversation`` through a real
PluginManager; the provider is reached over real openai/httpx code whose transport is an
httpx.MockTransport (tests/scenario/_fakes.py). The tool step uses the real model-tool path
(model_tools.handle_function_call -> pre_tool_call -> tool_execution middleware -> handler) with the
human replaced at the CLI approval-callback seat, as in tests/seam/test_gate_tools_seam.py. Pin consent
goes through consent.approve_pending_pin with ask_choice scripted.

The /confidential commands are not used (W5 is writing them): ``_fakes.Plugin`` is the glue.
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from tests.seam._harness import manager, no_lazy_installs  # noqa: F401  (fixtures)

from confidential_mode import provider as provider_mod
from confidential_mode.consent import approve_pending_pin
from confidential_mode.gate_llm import TEXT_PROVIDER_ERROR
from confidential_mode.receipts import CLOSING_PARAGRAPH, render, verify_chain
from confidential_mode.tiers import Tier

from ._fakes import (
    ATTESTED_MODEL, ENCLAVE, ENCLAVE_URL, HPKE_KEY, ON_HOST_ADDR, ON_HOST_MODEL, ON_HOST_URL, OPENROUTER_URL, PROFILE,
    REPLY, REPO, TLS_FP,
    FakeCtx, MockNet, Plugin, attested_config, on_host_config, patch_hermes_http,
)

SID = "demo-session-1"
SK = "cm:demo"
PROMPT = "summarise the confidential merger memo"   # must never reach the ledger or the receipt
_SCRUB_ENV = (
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "NOUS_API_KEY",
    "DEEPINFRA_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY", "HERMES_INFERENCE_PROVIDER",
    "HERMES_MODEL", "HERMES_PLUGIN_HOST_PROCESS", "TINFOIL_USER_CACHE_SECRET", "HERMES_INTERACTIVE",
    "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM", "HERMES_CRON_SESSION",
    "HERMES_SINGLE_QUERY_SESSION", "HERMES_YOLO_MODE", "HERMES_SESSION_KEY",
)


def _reset_permanent_state(approval):
    with approval._lock:
        approval._permanent_approved.clear()
        approval._permanent_approved_by_home.clear()
        approval._permanent_baseline_by_home.clear()


@pytest.fixture
def world(tmp_path, monkeypatch, manager):  # noqa: F811
    import providers as _providers
    import hermes_cli.auth as _auth
    from agent import auxiliary_client as _aux
    import model_tools  # noqa: F401  (registers the built-in tools)
    from tools import approval, approval_context, terminal_tool
    from tools.registry import registry

    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HOME", str(tmp_path / "userhome"))
    for var in _SCRUB_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TINFOIL_API_KEY", "tf-key")
    _providers._discover_providers()
    monkeypatch.setattr(_providers, "_REGISTRY", dict(_providers._REGISTRY))
    monkeypatch.setattr(_providers, "_ALIASES", dict(_providers._ALIASES))
    monkeypatch.setattr(_providers, "_SOURCES", dict(_providers._SOURCES))
    monkeypatch.setattr(_providers, "_PROVIDER_LIST_CACHE", None)
    monkeypatch.setattr(_auth, "PROVIDER_REGISTRY", dict(_auth.PROVIDER_REGISTRY))
    _aux._client_cache.clear()
    monkeypatch.setattr(provider_mod, "verification_cache", provider_mod.VerificationCache())

    # retries and backoff: instant, and observable
    sleeps = []
    monkeypatch.setattr("agent.retry_utils.jittered_backoff", lambda *a, **k: 0.0)
    monkeypatch.setattr("agent.turn_recovery.interruptible_backoff_sleep", lambda *a, **k: sleeps.append(a))
    monkeypatch.setattr("agent.turn_api_error.interruptible_backoff_sleep", lambda *a, **k: sleeps.append(a))
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("model_tools.check_toolset_requirements", dict)

    net = MockNet()
    patch_hermes_http(monkeypatch, net)

    # the human at the CLI approval seat, and web_search's handler swapped before the lock
    assert approval._YOLO_MODE_FROZEN is False, "run without HERMES_YOLO_MODE"
    _reset_permanent_state(approval)
    approval.clear_session(SK)
    tok = approval_context.set_current_session_key(SK)
    prompts, ran = [], []

    def human(answer):
        def cb(command, description, **kw):
            prompts.append((command, description))
            return answer
        terminal_tool.set_approval_callback(cb)

    def web_search_handler(args, **kw):
        ran.append(args)
        return json.dumps({"results": ["fake"]})
    monkeypatch.setattr(registry.get_entry("web_search"), "handler", web_search_handler)

    plugin = Plugin(tmp_path, manager, net)
    plugin.register()
    try:
        yield SimpleNamespace(plugin=plugin, net=net, human=human, prompts=prompts, ran=ran, sleeps=sleeps,
                              monkeypatch=monkeypatch, tmp=tmp_path)
    finally:
        plugin.close()
        terminal_tool.set_approval_callback(None)
        approval.clear_session(SK)
        approval_context.reset_current_session_key(tok)
        _reset_permanent_state(approval)
        _aux._client_cache.clear()


# ── agents ──────────────────────────────────────────────────────────────────────────────────────

_AGENT_KW = dict(quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=4, session_id=SID)


def _finish(agent, rec):
    agent._cleanup_task_resources = lambda task_id: None
    agent._persist_session = lambda messages, history=None: None
    agent._save_trajectory = lambda messages, user_message, completed: None
    agent._disable_streaming = True
    real_fallback = agent._try_activate_fallback

    def spy(*a, **k):
        rec["fallback_calls"].append((a, k))
        return real_fallback(*a, **k)
    agent._try_activate_fallback = spy
    return agent


def on_host_agent(w):
    from run_agent import AIAgent
    rec = {"fallback_calls": []}
    agent = AIAgent(model=ON_HOST_MODEL, provider="custom", api_mode="chat_completions", base_url=ON_HOST_URL,
                    api_key="on-host-key", **_AGENT_KW)
    return _finish(agent, rec), rec


def attested_agent(w):
    from run_agent import AIAgent
    rec = {"fallback_calls": []}
    agent = AIAgent(model=ATTESTED_MODEL, provider=PROFILE, api_key="tf-key", base_url=ENCLAVE_URL, **_AGENT_KW)
    return _finish(agent, rec), rec


def arm_openrouter_fallback(w, agent):
    """A live fallback chain to openrouter whose client really sends into the MockNet, so arming and
    using it would show up as requests on the openrouter recorder."""
    import openai
    agent._fallback_chain = [{"provider": "openrouter", "model": "anthropic/claude-sonnet-4.5"}]
    agent._fallback_index = 0
    client = openai.OpenAI(api_key="or-key", base_url=OPENROUTER_URL, http_client=w.net.sync_client(), max_retries=0)
    w.monkeypatch.setattr("agent.auxiliary_client.resolve_provider_client",
                          lambda *a, **k: (client, "anthropic/claude-sonnet-4.5"))


# ── control: the fakes are wired (unlocked, Hermes' own fallback reaches the openrouter recorder) ──

def test_control_unlocked_5xx_falls_back_to_openrouter(world):
    w = world
    agent, rec = on_host_agent(w)
    arm_openrouter_fallback(w, agent)
    w.net.on_host.fail_status = 500
    agent.run_conversation(PROMPT)
    assert w.net.on_host.requests, "the on-host router was asked"
    assert rec["fallback_calls"], "unlocked, Hermes arms the fallback on a 5xx"
    assert w.net.openrouter.requests, "and the fallback's requests reach the openrouter recorder"
    assert [k for k, _ in w.plugin.events()] and {k for k, _ in w.plugin.events()} == {"send_observed"}


# ── the demo ────────────────────────────────────────────────────────────────────────────────────

def test_demo(world, monkeypatch):
    w, plugin, net = world, world.plugin, world.net

    # (1) lock to on-host-only with a leftover fallback_providers entry: preflight refuses, names the key
    ok, report = plugin.lock(Tier.ON_HOST, on_host_config(leftover_fallback=True), session_id=SID)
    assert ok is False
    assert "FAIL (1 item(s))" in report
    failing = [line for line in report.splitlines() if "off_tier" in line]
    assert len(failing) == 1 and failing[0].startswith("fallback_providers[0]")
    assert "remove fallback_providers entries while locked" in failing[0]
    assert plugin.state.locked() == (False, None)
    assert plugin.events() == [("preflight_fail", None)]

    # (2) remove it: lock succeeds and the allowlist is printed
    ok, out = plugin.lock(Tier.ON_HOST, on_host_config(leftover_fallback=False), session_id=SID)
    assert ok is True, out
    assert "tier=on-host-only PASS" in out
    for name in ("read_file", "terminal", "web_search", "cronjob_manage"):
        assert name in out.split("\n\n", 1)[1]
    assert plugin.state.locked() == (True, Tier.ON_HOST)
    assert plugin.events()[-1] == ("lock", "locked")

    # (3) a locked turn with the in-tier provider passes; send_observed with the host
    agent, rec = on_host_agent(w)
    mark = len(plugin.ledger.tail(0))
    result = agent.run_conversation(PROMPT)
    assert REPLY in str(result["final_response"])
    assert [r[1] for r in net.on_host.requests] == [ON_HOST_ADDR]
    rows = plugin.ledger.tail(mark)
    assert [(r.kind, r.host, r.tier, r.decision) for r in rows] == [
        ("send_observed", ON_HOST_ADDR, "on-host-only", "allowed")]
    assert rows[0].bytes and rows[0].bytes > len(PROMPT) and rows[0].session_id == SID

    # (4) force a 5xx: the turn ends with the refusal, zero requests on openrouter, fallback never armed
    arm_openrouter_fallback(w, agent)
    net.on_host.fail_status = 500
    before = len(net.on_host.requests)
    mark = len(plugin.ledger.tail(0))
    result = agent.run_conversation(PROMPT)
    assert result["final_response"] == TEXT_PROVIDER_ERROR
    assert len(net.on_host.requests) > before, "the in-tier provider was asked and failed"
    assert net.openrouter.requests == [], "zero requests reached openrouter"
    assert rec["fallback_calls"] == [] and agent._fallback_index == 0, "fallback never armed"
    assert w.sleeps == []
    rows = plugin.ledger.tail(mark)
    assert [r.kind for r in rows] == ["send_observed", "send_refused"]
    assert rows[1].detail["reason_code"] == "provider_error" and rows[1].detail["status_code"] == 500
    net.on_host.fail_status = None

    # (5) web_search: the ask prompt; "once" runs it, "" does not (real model-tool path)
    import model_tools
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    w.human("once")
    out = model_tools.handle_function_call("web_search", {"query": "acme merger"}, task_id="t1",
                                           session_id=SID, tool_call_id="call-ws-1")
    assert w.prompts == [("<web_search> (plugin approval rule)",
                          "Confidential mode: web_search wants to send ~1 KB of this conversation off the machine")]
    assert w.ran == [{"query": "acme merger"}] and json.loads(out) == {"results": ["fake"]}
    assert plugin.events()[-2:] == [("tool_asked", "ask"), ("tool_allowed", "once")]
    w.human("")
    out = model_tools.handle_function_call("web_search", {"query": "acme merger 2"}, task_id="t1",
                                           session_id=SID, tool_call_id="call-ws-2")
    assert len(w.prompts) == 2 and w.ran == [{"query": "acme merger"}], "'' must not run the tool"
    assert "not once/session/always" in out
    assert plugin.events()[-1] == ("tool_refused", "unexpected_choice")
    monkeypatch.delenv("HERMES_INTERACTIVE")

    # (6) attested tier. Unlock, register the attested profile, first pin by explicit consent, lock.
    plugin.unlock(session_id=SID)
    plugin.register_attested_profile()
    assert plugin.attested_ok(PROFILE).reason == provider_mod.REASON_NO_PIN  # no trust on first use
    first = plugin.pins.pending()
    assert first is not None and first.previous is None
    reply = approve_pending_pin(FakeCtx("approve"), plugin.pins, plugin.ledger, session_key=SK, session_id=SID,
                                platform="telegram")
    assert reply.startswith("Pinned tinfoil build v1.0.0")
    ok, out = plugin.lock(Tier.ATTESTED, attested_config(), session_id=SID)
    assert ok is True, out
    att_agent, att_rec = attested_agent(w)
    result = att_agent.run_conversation(PROMPT)
    assert "ATTESTED-" + REPLY in str(result["final_response"])
    assert [r[1] for r in net.enclave.requests] == [ENCLAVE]
    last_send = [r for r in plugin.ledger.tail(0) if r.kind == "send_observed"][-1]
    assert (last_send.host, last_send.tier, last_send.provider) == (ENCLAVE, "attested", PROFILE)

    # stage a pin mismatch by hand: the enclave now presents a different build; verification expires
    plugin.adapter.code = "c0de2" * 8
    plugin.adapter.release = "v1.1.0"
    provider_mod.verification_cache.invalidate(PROFILE)
    sent = len(net.enclave.requests)
    mark = len(plugin.ledger.tail(0))
    result = att_agent.run_conversation(PROMPT)
    assert provider_mod.REASON_PIN_MISMATCH in result["final_response"]   # "enclave build changed; run ..."
    assert result["final_response"].startswith("Confidential mode: ")
    assert len(net.enclave.requests) == sent, "nothing sent to the changed enclave"
    assert net.openrouter.requests == [] and att_rec["fallback_calls"] == []
    pending = plugin.pins.pending()
    assert pending is not None and pending.code_fingerprint == "c0de2" * 8 and pending.previous == "c0de1" * 8
    kinds = [r.kind for r in plugin.ledger.tail(mark)]
    assert "pin_staged" in kinds and kinds[-1] == "send_refused"

    # consent: ask_choice scripted "approve" applies the pin; the next turn passes
    ctx = FakeCtx("approve")
    reply = approve_pending_pin(ctx, plugin.pins, plugin.ledger, session_key=SK, session_id=SID, platform="telegram")
    assert len(ctx.questions) == 1 and "Code fingerprint new: " + "c0de2" * 8 in ctx.questions[0][0]
    assert reply.startswith("Pinned tinfoil build v1.1.0")
    assert plugin.pins.pending() is None
    assert plugin.pins.get("tinfoil", pending.router_repo).code_fingerprint == "c0de2" * 8
    assert plugin.events()[-1] == ("pin_applied", "approve")
    result = att_agent.run_conversation(PROMPT)
    assert "ATTESTED-" + REPLY in str(result["final_response"])
    assert len(net.enclave.requests) == sent + 1
    assert plugin.adapter.attestation_count == 2, "one attestation per build, cached across create_client calls"
    assert net.unknown == []

    # (7) the receipt, both formats
    text = render(plugin.ledger, SID, pins=plugin.pins)
    doc_json = render(plugin.ledger, SID, pins=plugin.pins, fmt="json")
    doc = json.loads(doc_json)
    assert PROMPT not in text and PROMPT not in doc_json and "acme merger" not in doc_json
    assert text.endswith("\n\n" + CLOSING_PARAGRAPH + "\n") and doc["closing"] == CLOSING_PARAGRAPH
    closing_in_text = text[-(len(CLOSING_PARAGRAPH) + 1):-1]
    assert closing_in_text.encode("utf-8") == CLOSING_PARAGRAPH.encode("utf-8")
    kinds = {r["kind"] for r in doc["rows"]}
    assert {"preflight_fail", "lock", "unlock", "send_observed", "send_refused", "tool_asked", "tool_allowed",
            "tool_refused", "verify_ok", "pin_staged", "pin_applied"} <= kinds
    assert doc["header"]["locked_tier"] == "attested"
    assert {e["host"] for e in doc["header"]["enclave_hosts"]} == {ENCLAVE}
    assert len(doc["evidence"]) == 2 and {e["evidence"]["claims"]["code_fingerprint"] for e in doc["evidence"]} == {
        "c0de1" * 8, "c0de2" * 8}
    assert doc["header"]["unverified_entries"] == []
    # header: chain head first, with the instruction to record it elsewhere; a self-report; plugin + SDK
    lines = text.splitlines()
    assert lines[1] == f"CHAIN HEAD: {doc['header']['chain_head']}" and "somewhere other than this machine" in lines[2]
    assert "self-report" in lines[3]
    assert lines[4].startswith("Plugin: ") and "verifier SDK: 0.14.2" in lines[4]
    # per verification row: repo, platform, host and the committed keys
    vlines = [ln for ln in lines if "verify_ok  vendor=" in ln]
    assert len(vlines) == 2
    for ln in vlines:
        assert f"repo={REPO}" in ln and "platform=sev-snp" in ln and f"enclave={ENCLAVE}" in ln
        assert f"tls_key_fp={TLS_FP}" in ln and f"hpke_key={HPKE_KEY}" in ln
        assert f"enclave={ENCLAVE} (asserted by capturer)" in ln
        assert "evidence replays under: vendor SDK 0.14.2 [pass]; restated policy check (" in ln
        assert "sends were gated by the vendor SDK only" in ln
    assert "verified by" not in text.lower()
    from confidential_mode.receipts import policy_checker_id
    assert doc["header"]["policy_checker"] == policy_checker_id()
    assert [st["vendor_sdk"]["result"] for st in doc["sections"]["replay_status"]] == ["pass", "pass"]
    # every attested send names the verify row and TTL window that covered it
    cov = doc["sections"]["send_coverage"]
    verify_ids = [r["id"] for r in doc["rows"] if r["kind"] == "verify_ok"]
    assert [c["verify"] for c in cov] == verify_ids and all(c["covered"] for c in cov)
    assert {c["ttl_seconds"] for c in cov} == {300.0}
    for c in cov:
        assert f"covered by verify #{c['verify']}, TTL 300 s" in text
    assert "c0de2c0de2" in text and "approved by human" in text and "via telegram" in text
    assert "reason: provider_error; HTTP 500" in text
    assert "reason: off_tier; enclave build changed; run /confidential pins approve" in text
    periods = [line for line in text.splitlines() if line.startswith("Locked period:")]
    assert len(periods) == 2 and periods[0].startswith("Locked period: on-host-only from ")
    assert " (host clock) to 20" in periods[0]                       # closed by the unlock row
    assert periods[1].startswith("Locked period: attested from ") and "still locked at the last row" in periods[1]
    assert "allowed (once)" in text and "refused (unexpected_choice)" in text
    assert "reason: fallback_providers[0] off_tier" in text
    assert f"host={ON_HOST_ADDR}" in text and f"host={ENCLAVE}" in text

    assert verify_chain(doc_json) is True
    tampered = json.loads(doc_json)
    victim = next(r for r in tampered["rows"] if r["kind"] == "send_refused")
    victim["detail"]["reason_code"] = "nothing to see"
    assert verify_chain(tampered) is False
    tampered = json.loads(doc_json)
    next(r for r in tampered["rows"] if r["kind"] == "send_observed")["host"] = "openrouter.ai"
    assert verify_chain(json.dumps(tampered)) is False

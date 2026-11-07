"""Seam tests for the 'attested-near' profile on the plugin loaded by real discovery (fixture from
test_register.py): registration, the attested-tier lock through the real preflight and pins, consent on a
changed measurement through Hermes' real ask_choice, a real Hermes turn through the NEAR client, the
send_signed ledger row, the receipt, and `hermes confidential replay`.

Fakes only at the network boundary: the registered NearAdapter's transports serve the synthetic NEAR of
tests/near_world.py (real ed25519 and RSA signatures; a stand-in TDX quote and its verifier).
"""
from __future__ import annotations

import argparse
import importlib
import json
import time

import pytest

from hermes_cli.plugin_choices import bind_asker

from .test_register import plugin  # noqa: F401  (fixture)
from ._harness import no_lazy_installs  # noqa: F401  (fixture)
from ..near_world import BASE, HOST, MODEL, NOW, NearWorld, fake_quote_verifier

NEAR_CONFIG = f"""\
plugins:
  enabled: [confidential-mode]
model:
  provider: attested-near
  default: {MODEL}
auxiliary:
  vision:
    provider: attested-near
    model: {MODEL}
confidential:
  near:
    models: [{MODEL}]
"""


def _sub(plugin, name):
    return importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.{name}")


@pytest.fixture
def near(plugin, monkeypatch):
    """The registered NEAR adapter wired to a synthetic NEAR; the plugin copy's real-hardware verifier
    and Intel roots replaced by the world's (so the offline replay uses them too)."""
    import httpx
    world = NearWorld()
    ad = plugin.rt.near_adapter
    ad.models = [MODEL]
    ad._transport_factory = lambda: httpx.MockTransport(lambda r: world.handler(r))
    ad._async_transport_factory = lambda: httpx.MockTransport(lambda r: world.handler(r))
    ad._send_transport_factory = lambda: httpx.MockTransport(lambda r: world.handler(r))
    ad._sync_transport = ad._attest_transport = None
    ad._quote_verifier, ad._ita_roots = fake_quote_verifier, world.ita.roots
    ad.signature_wait_seconds = 0.0
    ad._sleep = lambda s: None
    ad._clock = lambda: NOW                 # the world's Intel tokens are issued at NOW
    nc = _sub(plugin, "verify.near_checks")
    monkeypatch.setattr(nc, "default_quote_verifier", fake_quote_verifier)
    monkeypatch.setattr(nc, "ITA_ROOT_SHA256", world.ita.roots)
    monkeypatch.setenv("NEAR_AI_API_KEY", "sk-near-seam")
    plugin.cfg.write_text(NEAR_CONFIG)
    return world


def _approve(plugin):
    from tests.near_world import cache_inner_composes
    cache_inner_composes(plugin.rt.pins.composes_dir)    # as `pins review` would: the service map is then pinned
    with bind_asker(lambda question, labels: "Approve"):
        return plugin.slash("pins approve")


def test_attested_near_profile_is_registered_without_network(plugin):
    import providers
    profile = providers.get_provider_profile("attested-near")
    assert profile is plugin.rt.near_profile and "attested-near" in plugin.rt.registered["providers"]
    assert profile.base_url == BASE and profile.env_vars == ("NEAR_AI_API_KEY",)
    assert profile.supports_streaming is False            # unstreamed main calls: model-signed responses
    ad = plugin.rt.near_adapter
    assert type(ad).__name__ == "NearAdapter" and ad.attestation_count == 0 and ad.require_provider_tee is True
    assert plugin.rt.errors == []


def test_lock_needs_a_human_approved_pin_then_a_turn_is_signed_and_ledgered(plugin, near):
    out = plugin.slash("on attested")
    assert out.startswith("Not locked") and "no approved enclave build pinned" in out
    pending = plugin.rt.pins.pending()
    assert pending.vendor == "near" and pending.router_repo == f"{HOST}#{MODEL}"
    assert pending.components and pending.components[0].startswith("gateway compose sha256:")
    asked = []
    from tests.near_world import cache_inner_composes
    with bind_asker(lambda q, labels: asked.append(q) or "Approve"):
        assert plugin.slash("pins approve").startswith("Not asked: the service map"), "fail closed until fetched"
        assert asked == []
        cache_inner_composes(plugin.rt.pins.composes_dir)
        assert plugin.slash("pins approve").startswith("Pinned 2 NEAR entries")   # gateway and model (Amendment 7)
    consent = _sub(plugin, "consent")
    assert "Identity: cloud-api.near.ai#" in asked[0] and consent.PINNED_HEADING in asked[0]
    head, _, tail = asked[0].partition(consent.REPORTED_HEADING)
    assert "(recorded in RTMR3; pinned; the instance id is shown only)" in head
    # Amendment 7: each model entry pins the compose-manager image the log reports; the services stay
    # shown for review only until their socket tags can be shown
    assert "compose-manager image reported by the log" in head and "services: pinned, the whole map" in head
    assert "  `  prod/test.yaml::proxy-test v0.0.2 commit " + "c2" * 20 in tail and "(the two differ)" in tail
    assert consent.REPORTED_NOT_PINNED in tail and "reported: " not in asked[0]
    out = plugin.slash("on attested")
    assert out.startswith(f"Locked. Model: attested-near/{MODEL} at {HOST}"), out

    import run_agent
    agent = run_agent.AIAgent(model=MODEL, provider="attested-near", api_key="sk-near-seam", base_url=BASE,
                              quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=2)
    assert type(agent.client).__name__ == "ConfidentialClient"
    result = agent.run_conversation("hello")
    assert "NEAR-FAKE-REPLY" in str(result.get("final_response"))
    assert near.chat_posts() >= 1 and all(b'"stream": true' not in b and b'"stream":true' not in b
                                          for b in near.chat_bodies)
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_signed"]
    assert rows, plugin.kinds()
    row = rows[-1]
    assert row.session_id == agent.session_id and row.purpose == "main" and row.provider == "attested-near"
    assert row.verdict == "verified" and row.decision == "provider_tee" and row.detail["fully_attested"] is True
    assert row.tier == "attested"

    receipt = json.loads(plugin.slash(f"receipts {agent.session_id} --json"))
    assert receipt["header"]["near"]["fully_attested"] is True, receipt["sections"].get("near_sends")
    send = receipt["sections"]["near_sends"][-1]
    assert send["signature_kind"] == "provider_tee" and send["replay_verdict"] == "pass"
    text = plugin.slash(f"receipts {agent.session_id}")
    assert "Signed responses (NEAR AI Cloud" in text and "Session fully attested" in text
    # Amendment 5.2: the verify_ok row keeps blob ids; the blobs sit in the plugin's data directory and the
    # JSON receipt carries them again.
    verify_rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "verify_ok" and e.provider == "attested-near"]
    ev = verify_rows[-1].detail["evidence"]
    assert "blobs" not in ev and ev["blob_refs"] and all(plugin.rt.ledger.blob(b) for b in ev["blob_refs"])
    items = [i for i in receipt["evidence"] if i["evidence"].get("vendor") == "near"]
    assert items and all(sorted(i["blobs"]) == i["evidence"]["blob_refs"] for i in items)


def test_changed_measurement_refuses_until_a_human_approves_it(plugin, near):
    plugin.slash("on attested")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked")
    provider = _sub(plugin, "provider")
    import tests.near_world as w
    old = w.MODEL_COMPOSE
    w.MODEL_COMPOSE = old.replace("vllm", "vllm-next")
    try:
        provider.verification_cache.invalidate("attested-near")
        v = provider.attested_ok("attested-near")
        assert v.in_tier is False and "enclave build changed" in v.reason
        pending = plugin.rt.pins.pending()
        assert pending.code_changed is True and pending.previous is not None
        with bind_asker(lambda q, labels: "Deny"):
            assert "denied" in plugin.slash("pins approve")
        assert provider.attested_ok("attested-near").in_tier is False
        assert _approve(plugin).startswith("Pinned 1 NEAR entry")    # only the changed model CVM (Amendment 7)
        assert provider.attested_ok("attested-near").in_tier is True
    finally:
        w.MODEL_COMPOSE = old


def test_preflight_treats_attested_near_as_in_tier_and_other_providers_as_off_tier(plugin, near):
    plugin.slash("on attested")
    _approve(plugin)
    check = plugin.slash("check attested")
    assert "provider_profile[attested-near]" in check
    locking = _sub(plugin, "locking")
    report = locking.run_tier_preflight("attested", config=plugin.rt.load_config(),
                                        predicate=locking.structural_predicate("attested", config=plugin.rt.load_config()))
    assert report.ok, [(i.key, i.verdict) for i in report.failures()]
    bad = NEAR_CONFIG.replace("vision:\n    provider: attested-near", "vision:\n    provider: openrouter")
    plugin.cfg.write_text(bad)
    report = locking.run_tier_preflight("attested", config=plugin.rt.load_config(),
                                        predicate=locking.structural_predicate("attested", config=plugin.rt.load_config()))
    assert not report.ok and any("vision" in i.key for i in report.failures())


def test_cli_replay_checks_evidence_and_every_signed_response(plugin, near, tmp_path, capsys):
    plugin.slash("on attested")
    _approve(plugin)
    plugin.slash("on attested")
    profile = plugin.rt.near_profile
    client = profile.create_client(api_key="sk-near-seam", base_url=BASE)
    sendctx = _sub(plugin, "sendctx")
    with sendctx.send_context(session_id="sess-near", purpose="main", tier="attested"):
        client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "hi"}])
        near.sig_mode = "tamper_response"
        with pytest.raises(Exception) as ei:   # D5: the encrypted reply is withheld; the row is still written
            client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "again"}])
        assert "withheld" in repr(ei.value) + repr(ei.value.__cause__)
    path = tmp_path / "receipt.json"
    path.write_text(plugin.slash("receipts sess-near --json"))
    parser = argparse.ArgumentParser()
    plugin.mgr._cli_commands["confidential"]["setup_fn"](parser)
    code = plugin.mgr._cli_commands["confidential"]["handler_fn"](parser.parse_args(["replay", str(path)]))
    out = capsys.readouterr().out
    assert code == 1                                   # the tampered signature fails the replay
    assert "Signed responses (NEAR AI Cloud):" in out and ": OK  provider_tee" in out and ": FAIL" in out
    assert "Session fully attested: NO" in out
    replay_near = _sub(plugin, "verify.replay_near")
    for line in replay_near.NOT_ESTABLISHED:
        assert f"  - {line}\n" in out
    assert "evidence row(s) replayed OK" in out and "1/2 signed response(s) replayed OK" in out


def test_status_shows_the_near_verification(plugin, near):
    plugin.slash("on attested")
    out = plugin.slash("status")
    assert "NEAR verification:" in out and f"{HOST}#{MODEL}" in out


# ── request encryption (W11) ─────────────────────────────────────────────────────────────────────

def test_a_locked_turn_leaves_encrypted_and_the_receipt_separates_self_report_from_signature(plugin, near):
    plugin.slash("on attested")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked")
    import run_agent
    agent = run_agent.AIAgent(model=MODEL, provider="attested-near", api_key="sk-near-seam", base_url=BASE,
                              quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=2)
    result = agent.run_conversation("SEAM-SECRET-PROMPT")
    assert "NEAR-FAKE-REPLY" in str(result.get("final_response"))
    assert near.chat_bodies and all(b"SEAM-SECRET-PROMPT" not in b for b in near.chat_bodies)
    assert any("SEAM-SECRET-PROMPT" in json.dumps(r) for r in near.decrypted_requests)
    row = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_signed"][-1]
    assert row.detail["near_e2ee"] is True and "messages[].content" in row.detail["e2ee_fields"]
    text = plugin.slash(f"receipts {agent.session_id}")
    assert "request body sent as ciphertext for fields messages[].content" in text
    assert "(plugin self-report)" in text and "signature verified over the ciphertext digests (third-party checkable)" in text
    doc = json.loads(plugin.slash(f"receipts {agent.session_id} --json"))
    send = doc["sections"]["near_sends"][-1]
    assert send["near_e2ee"] is True and send["model_pub"] == plugin.rt.near_adapter.model_public_key(MODEL)


@pytest.mark.parametrize("extra,key", [
    ("    encrypt: false\n", "confidential.near.encrypt"),
    ("", "model.api_mode"),
])
def test_lock_refuses_encryption_off_or_a_non_chat_api_mode(plugin, near, extra, key):
    cfg = NEAR_CONFIG + extra
    if key == "model.api_mode":
        cfg = cfg.replace(f"  default: {MODEL}\n", f"  default: {MODEL}\n  api_mode: codex_responses\n")
    plugin.cfg.write_text(cfg)
    out = plugin.slash("on attested")
    assert out.startswith("Not locked") and key in out, out


def test_lock_refuses_when_the_encryption_library_is_missing(plugin, near, monkeypatch):
    e2 = _sub(plugin, "verify.near_e2ee")
    monkeypatch.setattr(e2, "available", lambda: (False, "pynacl unavailable (ImportError): install pynacl==1.6.*"))
    out = plugin.slash("on attested")
    assert out.startswith("Not locked") and "confidential.near.encryption_library" in out and "pynacl" in out


def test_create_client_for_attested_near_never_returns_an_unviewed_client(plugin, near):
    """Review finding 9: Hermes builds a plain client only when create_client returns None or raises;
    the profile returns a ConfidentialClient on the adapter's views, or a RefusingClient."""
    profile = plugin.rt.near_profile
    refused = profile.create_client(api_key="sk-near-seam", base_url=BASE)   # no pin yet
    assert type(refused).__name__ == "RefusingClient"
    plugin.slash("on attested")
    _approve(plugin)
    client = profile.create_client(api_key="sk-near-seam", base_url=BASE)
    assert type(client).__name__ == "ConfidentialClient"
    assert type(client._view._transport).__name__ == "_SyncView"
    assert type(client._sync._client._transport).__name__ == "_SyncView"
    import asyncio

    async def go():
        return type(client._async_client()._client._transport).__name__
    assert asyncio.run(go()) == "_AsyncView"
    import providers
    providers_profile = providers.get_provider_profile("attested-near")
    broken = providers_profile.create_client(api_key="sk-near-seam", base_url=BASE, timeout=object())
    assert type(broken).__name__ in ("ConfidentialClient", "RefusingClient")


def test_a_withheld_reply_is_not_resent_by_hermes_retry_loop(plugin, near):
    """Review finding 4: a refusal from the transport is an openai.OpenAIError (the SDK does not retry it)
    and the profile's classify_api_error marks it non-retryable, so Hermes' own loop sends once."""
    plugin.slash("on attested")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked")
    near.sig_mode = "404"                       # no signature: the reply is withheld
    import run_agent
    agent = run_agent.AIAgent(model=MODEL, provider="attested-near", api_key="sk-near-seam", base_url=BASE,
                              quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=2)
    try:
        result = agent.run_conversation("hello")
    except Exception as exc:                    # either surface is acceptable; the count is the test
        result = {"error": repr(exc)}
    assert "NEAR-FAKE-REPLY" not in json.dumps(result, default=str)
    assert near.chat_posts() == 1, near.chat_posts()
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_signed"]
    assert len(rows) == 1 and rows[0].detail["reply_released"] is False
    # One refusal row for the withheld reply: the llm gate's (the NEAR transport writes none inside it).
    refused = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]
    assert len(refused) == 1 and refused[0].purpose == "main", [(e.purpose, e.detail) for e in refused]
    assert refused[0].detail["reason_code"] == "provider_error"
    from agent.error_classifier import classify_api_error
    from confidential_mode.verify.near import NearRefusal
    c = classify_api_error(NearRefusal("NEAR response withheld"), provider="attested-near", model=MODEL)
    assert c.retryable is False and c.should_fallback is False


@pytest.mark.parametrize("cfg,key", [
    (NEAR_CONFIG + "    require_tls_binding: false\n", "confidential.near.require_tls_binding"),
    (NEAR_CONFIG + "    encrypt: \"no\"\n", "confidential.near.encrypt"),
    (NEAR_CONFIG.replace("auxiliary:\n", "auxiliary:\n  compression:\n    provider: attested-near\n    model: "
                         f"{MODEL}\n    fallback_chain:\n      - provider: attested-near\n        model: {MODEL}\n"
                         "        api_mode: codex_responses\n"),
     "auxiliary.compression.fallback_chain[0].api_mode"),
])
def test_lock_refuses_tls_binding_off_odd_values_and_fallback_chain_api_modes(plugin, near, cfg, key):
    plugin.cfg.write_text(cfg)
    out = plugin.slash("on attested")
    assert out.startswith("Not locked") and key in out, out



@pytest.mark.parametrize("status,body,reason,retryable,compress", [
    (429, {"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}}, "rate_limit", True, False),
    (503, {"error": {"message": "upstream unavailable", "type": "server_error"}}, "overloaded", True, False),
    (500, {"error": {"message": "boom", "type": "server_error"}}, "server_error", True, False),
    (400, {"error": {"message": "This model's maximum context length is 65536 tokens", "type": "invalid_request_error",
                     "code": "context_length_exceeded"}}, "context_overflow", True, True),
    (400, {"error": {"message": "bad request", "type": "invalid_request_error"}}, "provider_policy_blocked", False, False),
    (421, {"error": {"message": "The encryption key is no longer valid.", "type": "provider_error"}},
     "provider_policy_blocked", False, False),
    (201, {"choices": []}, "provider_policy_blocked", False, False),
])
def test_gateway_errors_keep_hermes_recovery_and_refusals_stay_fatal(plugin, near, status, body, reason, retryable,
                                                                    compress):
    """N1: the status rides on NearRefusal and Hermes' classifier (through the profile hook) maps it.
    Nothing here changes what is released: none of these reaches Hermes as a reply."""
    import httpx
    plugin.slash("on attested")
    _approve(plugin)
    client = plugin.rt.near_profile.create_client(api_key="sk-near-seam", base_url=BASE)
    orig = near.handler
    near.handler = lambda r: httpx.Response(status, json=body) if r.url.path == "/v1/chat/completions" else orig(r)
    with pytest.raises(Exception) as ei:
        client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "hi"}])
    assert type(ei.value).__name__ == "NearRefusal" and ei.value.status_code == status
    from agent.error_classifier import classify_api_error
    c = classify_api_error(ei.value, provider="attested-near", model=MODEL)
    assert (c.reason.value, c.retryable, c.should_compress, c.should_fallback) == (reason, retryable, compress, False)


def test_a_withheld_reply_stays_non_retryable_through_the_classifier(plugin, near):
    plugin.slash("on attested")
    _approve(plugin)
    client = plugin.rt.near_profile.create_client(api_key="sk-near-seam", base_url=BASE)
    near.sig_mode = "gateway"
    with pytest.raises(Exception) as ei:
        client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "hi"}])
    from agent.error_classifier import classify_api_error
    c = classify_api_error(ei.value, provider="attested-near", model=MODEL)
    assert ei.value.status_code is None and c.retryable is False and c.should_fallback is False


# ── auxiliary calls: structured settings and refusal rows (live finding 2026-11-07) ─────────────

def _aux_title_call(plugin, reasoning):
    """A title_generation call through Hermes' real auxiliary client path (call_llm, the relay funnel and
    pre/post_auxiliary_call), with ``reasoning`` riding in extra_body as Hermes sends it."""
    from agent import auxiliary_client
    return auxiliary_client.call_llm(task="title_generation", provider="attested-near", model=MODEL,
                                     base_url=BASE, api_key="sk-near-seam",
                                     messages=[{"role": "user", "content": "AUX-SECRET name this chat"}],
                                     max_tokens=32, extra_body={"reasoning": reasoning})


def test_an_aux_title_call_with_a_structured_reasoning_setting_leaves_encrypted(plugin, near):
    plugin.slash("on attested")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked")
    resp = _aux_title_call(plugin, {"effort": "low", "summary": "auto"})
    assert "NEAR-FAKE-REPLY" in str(resp.choices[0].message.content)
    assert near.chat_bodies and all(b"AUX-SECRET" not in b for b in near.chat_bodies)
    assert json.loads(near.chat_bodies[-1])["reasoning"] == {"effort": "low", "summary": "auto"}
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_signed"]
    assert rows and rows[-1].purpose == "aux:title_generation", [(e.kind, e.purpose) for e in rows]
    assert "reasoning" in rows[-1].detail["plaintext_keys"] and rows[-1].detail["fully_attested"] is True
    assert not [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]


def test_an_aux_title_call_with_free_text_in_reasoning_is_refused_and_ledgered(plugin, near):
    plugin.slash("on attested")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked")
    posts = near.chat_posts()
    with pytest.raises(Exception) as ei:
        _aux_title_call(plugin, {"effort": "low", "note": "free text"})
    assert "refused before sending" in repr(ei.value) + repr(ei.value.__cause__)
    assert near.chat_posts() == posts                       # nothing left this host
    refused = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]
    assert len(refused) == 1, [(e.kind, e.purpose) for e in plugin.rt.ledger.tail(0)]
    row = refused[0]
    assert row.purpose == "aux:title_generation" and row.host == HOST and row.provider == "attested-near"
    assert row.detail["stage"] == "before_send" and "'reasoning'" in row.detail["reason"]
    assert isinstance(row.bytes, int) and row.bytes > 0 and row.tier == "attested"
    if row.session_id:
        text = plugin.slash(f"receipts {row.session_id}")
    else:
        receipts = _sub(plugin, "receipts")
        text = receipts.render(plugin.rt.ledger, "", fmt="text")
    refusals = text.split("\nRefusals\n", 1)[1].split("\n\n", 1)[0]
    assert "send_refused  aux:title_generation" in refusals and f"host={HOST}" in refusals, refusals
    assert "near_refused_before_send" in refusals


IMAGE_PART = {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}


def test_an_image_to_near_while_locked_is_disclosed_once_per_lock_and_the_reply_gets_one_line(plugin, near):
    """Amendment 9: image_parts disclose. The first plaintext image part of a lock writes one notice row and
    transform_llm_output appends one line to that session's reply; later images and other replies do not."""
    import providers
    from hermes_cli.plugins import invoke_hook
    assert plugin.slash("on attested").startswith("Not locked")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked.")
    client = providers.get_provider_profile("attested-near").create_client(api_key="sk-near-seam", base_url=BASE)
    sendctx = _sub(plugin, "sendctx")
    msg = [{"role": "user", "content": [{"type": "text", "text": "Describe this"}, IMAGE_PART]}]
    for _ in range(2):
        with sendctx.send_context(session_id="sess-img", purpose="aux:vision", tier="attested"):
            assert client.chat.completions.create(model=MODEL, messages=msg).choices[0].message.content
    rows = plugin.rt.ledger.tail(0)
    notices = [e for e in rows if e.kind == "notice"]
    assert len(notices) == 1 and notices[0].decision == "image_plaintext" and notices[0].session_id == "sess-img"
    assert notices[0].detail["note"] == "1 image part(s) left this host in plaintext to NEAR's gateway"
    signed = [e for e in rows if e.kind == "send_signed"][-2:]
    assert all(e.detail["plaintext_parts"]["count"] == 1 and e.verdict == "verified" for e in signed)
    line = plugin.mod.image_notice_line({"count": 1, "types": {"image_url": 1}})
    assert line == ("Confidential mode: an image part (image_url) in this turn went to NEAR's gateway in "
                    "plaintext; the text around it was encrypted.")
    other = invoke_hook("transform_llm_output", response_text="hi", session_id="another", model=MODEL, platform="cli")
    assert not [r for r in other if r]
    out = [r for r in invoke_hook("transform_llm_output", response_text="A cat.", session_id="sess-img",
                                  model=MODEL, platform="cli") if r]
    assert out == [f"A cat.\n\n{line}"]
    again = invoke_hook("transform_llm_output", response_text="A dog.", session_id="sess-img", model=MODEL,
                        platform="cli")
    assert not [r for r in again if r], "one line per lock"
    # The receipt's per-send line says it too.
    text = plugin.slash("receipts sess-img")
    assert "1 image part(s) left this host in plaintext to NEAR's gateway" in text
    # A new lock notices again.
    plugin.slash("off")
    assert plugin.slash("on attested").startswith("Locked.")
    with sendctx.send_context(session_id="sess-img", purpose="aux:vision", tier="attested"):
        client = providers.get_provider_profile("attested-near").create_client(api_key="sk-near-seam", base_url=BASE)
        client.chat.completions.create(model=MODEL, messages=msg)
    assert len([e for e in plugin.rt.ledger.tail(0) if e.kind == "notice"]) == 2


def test_image_parts_refuse_is_in_tier_and_shown_and_refuses_images(plugin, near):
    import providers
    plugin.cfg.write_text(plugin.cfg.read_text() + "    image_parts: refuse\n")
    plugin.rt.near_adapter.image_parts = "refuse"
    preflight, locking = _sub(plugin, "preflight"), _sub(plugin, "locking")
    cfg = preflight.load_core_config()
    report = locking.run_tier_preflight("attested", config=cfg, predicate=locking.structural_predicate("attested", config=cfg),
                                        provider_lookup=providers.get_provider_profile)
    item = next(i for i in report.items if i.key == "confidential.near.image_parts")
    assert item.verdict == "in_tier" and item.value_redacted == "refuse"
    assert plugin.slash("on attested").startswith("Not locked")
    _approve(plugin)
    assert plugin.slash("on attested").startswith("Locked.")
    client = providers.get_provider_profile("attested-near").create_client(api_key="sk-near-seam", base_url=BASE)
    with pytest.raises(Exception):
        client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": [IMAGE_PART]}])
    assert near.chat_posts() == 0 and not [e for e in plugin.rt.ledger.tail(0) if e.kind == "notice"]


def test_an_aux_call_refused_by_the_provider_gate_writes_one_send_refused_row(plugin, near):
    """Review item 7: a NEAR client refused before any transport (no pin yet) is ledgered too."""
    import providers
    client = providers.get_provider_profile("attested-near").create_client(api_key="sk-near-seam", base_url=BASE)
    assert type(client).__name__ == "RefusingClient"
    sendctx = _sub(plugin, "sendctx")
    with sendctx.send_context(session_id="sess-aux", purpose="aux:title_generation", tier="attested"):
        with pytest.raises(Exception):
            client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "x"}])
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]
    assert len(rows) == 1 and rows[0].purpose == "aux:title_generation" and rows[0].session_id == "sess-aux"
    assert rows[0].detail["stage"] == "provider_gate" and "pinned" in rows[0].detail["reason"]
    with sendctx.send_context(session_id="s", purpose="main", refusals_ledgered_by="llm_gate"):
        with pytest.raises(Exception):
            client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "x"}])
    assert len([e for e in plugin.rt.ledger.tail(0) if e.kind == "send_refused"]) == 1   # the gate writes its own

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
    with bind_asker(lambda q, labels: asked.append(q) or "Approve"):
        assert plugin.slash("pins approve").startswith("Pinned near build")
    assert "Identity: cloud-api.near.ai#" in asked[0] and "Measured configuration" in asked[0]
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
        assert _approve(plugin).startswith("Pinned near build")
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
        client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "again"}])
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

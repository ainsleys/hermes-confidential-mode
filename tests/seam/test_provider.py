"""Seam tests: the real 'attested-tinfoil' profile inside the pinned Hermes checkout (84a0301).

Reuses the C0 harness (tests/spikes/test_create_client*.py): fresh HERMES_HOME, provider/auth/plugin/aux
registries snapshotted, and Hermes' own keepalive httpx builder patched to a recording transport
labelled "hermes-default-*" so any request that lost the attested transport is visible. Fakes only
at the SDK boundary: SecureClient.verify and the SDK http-client builders are recorders (no network).
"""
from __future__ import annotations

import asyncio
import json
import struct
import sys
import time
import zlib
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

tinfoil_client = pytest.importorskip("tinfoil.client")

_REAL_GET_ROUTER_ADDRESS = tinfoil_client.get_router_address  # captured before any fixture stubs it

from confidential_mode import provider as provider_mod  # noqa: E402
from confidential_mode.client import ConfidentialClient, ConfidentialRefused, RefusingClient  # noqa: E402
from confidential_mode.pins import PinStore  # noqa: E402
from confidential_mode.verify.tinfoil import TinfoilAdapter  # noqa: E402

PROFILE = "attested-tinfoil"
ENCLAVE = "router.tinfoil.invalid"
BASE_URL = f"https://{ENCLAVE}/v1"
REPO = "tinfoilsh/confidential-model-router"
MSG = [{"role": "user", "content": "hi"}]

_SCRUB_ENV = (
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "NOUS_API_KEY",
    "DEEPINFRA_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY", "HERMES_INFERENCE_PROVIDER",
    "HERMES_MODEL", "HERMES_PLUGIN_HOST_PROCESS", "TINFOIL_USER_CACHE_SECRET",
)


# ── recording transports (same shape as the C0 follow-up spike) ───────────────────────────────

def _completion(model):
    return {"id": "s-1", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "ATTESTED-FAKE-REPLY"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _sse(model):
    base = {"id": "s-1", "object": "chat.completion.chunk", "created": int(time.time()), "model": model}
    chunks = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": "ATTESTED-FAKE-REPLY"},
                                   "finish_reason": None}]),
              dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])]
    return b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"


class Recorder:
    def __init__(self):
        self.requests = []  # (label, host, path, stream)

    def handler(self, label):
        def handle(request):
            try:
                body = json.loads(request.content or b"{}")
            except Exception:
                body = {}
            self.requests.append((label, request.url.host, request.url.path, bool(body.get("stream"))))
            model = body.get("model") or "m"
            if body.get("stream"):
                return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=_sse(model))
            return httpx.Response(200, json=_completion(model))
        return handle

    def labels(self, since=0):
        return [r[0] for r in self.requests[since:]]


def _png(path: Path) -> Path:
    rows = (b"\x00" + b"\xff\x00\x00" * 4) * 4

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
    return path


# ── SDK-boundary stubs ────────────────────────────────────────────────────────────────────────

def _stub_sdk(monkeypatch, rec: Recorder, sdk_state: dict):
    def fake_verify(self):
        sdk_state["verify_calls"] += 1
        if sdk_state.get("fail"):
            raise RuntimeError(sdk_state["fail"])
        doc = tinfoil_client.VerificationDocument(config_repo=self.repo, enclave_host=self.enclave,
                                                  selected_router_endpoint=self.enclave)
        doc.code_fingerprint, doc.enclave_fingerprint = sdk_state["code"], sdk_state["enclave"]
        doc.release_tag, doc.release_digest, doc.security_verified = "v1.0.0", "d" * 64, True
        doc.verified_at = "2026-11-06T00:00:00Z"
        for step in doc.steps.values():
            step.status = "success"
        self._verification_document = doc
        return tinfoil_client.GroundTruth(public_key="ab" * 32, digest="d" * 64, measurement="m")

    def fake_sync(self):
        self.verify()  # the real builder attests on every build
        return httpx.Client(transport=httpx.MockTransport(rec.handler("secure-sync")), follow_redirects=False)

    def fake_async(self):
        self.verify()
        return httpx.AsyncClient(transport=httpx.MockTransport(rec.handler("secure-async")),
                                 follow_redirects=False)

    def no_router():
        raise AssertionError("router discovery must not run: the enclave is configured")
    monkeypatch.setattr(tinfoil_client.SecureClient, "verify", fake_verify)
    monkeypatch.setattr(tinfoil_client.SecureClient, "make_secure_http_client", fake_sync)
    monkeypatch.setattr(tinfoil_client.SecureClient, "make_secure_async_http_client", fake_async)
    monkeypatch.setattr(tinfoil_client, "get_router_address", no_router)


@pytest.fixture
def env(tmp_path, monkeypatch):
    import hermes_yaml as yaml
    import providers as _providers
    import hermes_cli.auth as _auth
    import hermes_cli.plugins as _plugins
    from agent import auxiliary_client as _aux
    import agent.process_bootstrap as _bootstrap

    home = tmp_path / ".hermes"
    (home / "plugins").mkdir(parents=True)
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
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()
    monkeypatch.setattr(provider_mod, "verification_cache", provider_mod.VerificationCache())

    cfg = {"model": {"provider": PROFILE, "default": "tf-main-model", "base_url": BASE_URL},
           "confidential": {"tinfoil": {"enclave": ENCLAVE, "tls_probe": False}, "verify_ttl_seconds": 300},
           "auxiliary": {"compression": {"provider": PROFILE, "model": "tf-aux-model"},
                         "title_generation": {"provider": PROFILE, "model": "tf-aux-model"},
                         "vision": {"provider": PROFILE, "model": "tf-vision-model"}}}
    (home / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")

    rec = Recorder()

    def fake_keepalive(base_url="", *, async_mode=False, verify=True):
        transport = httpx.MockTransport(rec.handler("hermes-default-" + ("async" if async_mode else "sync")))
        return (httpx.AsyncClient if async_mode else httpx.Client)(transport=transport)
    monkeypatch.setattr(_bootstrap, "build_keepalive_http_client", fake_keepalive)

    sdk_state = {"code": "c1", "enclave": "e1", "fail": None, "verify_calls": 0}
    _stub_sdk(monkeypatch, rec, sdk_state)

    data_dir = tmp_path / "plugin-data"
    pins = PinStore(data_dir / "pins.yaml")

    def approve_current():
        from confidential_mode.verify.base import VerificationResult
        r = VerificationResult(vendor="tinfoil", router_repo=REPO, enclave_host=ENCLAVE,
                               code_fingerprint=sdk_state["code"], enclave_fingerprint=sdk_state["enclave"],
                               release_tag="v1.0.0", verifier="tinfoil/0.14.2", verified_at_local=0.0)
        pins.apply(pins.stage(r), approved_via="test", approval_rule_key="confidential-mode:pin:tinfoil")

    approve_current()

    def register(**kw):
        profile = provider_mod.register_provider_profile(None, config=cfg, data_dir=data_dir, **kw)
        assert _providers.get_provider_profile(PROFILE) is profile
        return profile

    yield {"home": home, "tmp": tmp_path, "rec": rec, "sdk": sdk_state, "pins": pins, "register": register,
           "approve_current": approve_current, "cfg": cfg}
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()


def _agent():
    from run_agent import AIAgent
    return AIAgent(model="tf-main-model", provider=PROFILE, api_key="tf-key", base_url=BASE_URL,
                   quiet_mode=True, skip_context_files=True, skip_memory=True)


def _count_create_client(monkeypatch, profile):
    built = []
    real = type(profile).create_client

    def counting(self, **kw):
        client = real(self, **kw)
        built.append(type(client).__name__)
        return client
    monkeypatch.setattr(type(profile), "create_client", counting)
    return built


# ── tests ─────────────────────────────────────────────────────────────────────────────────────


def test_profile_shape(env):
    profile = env["register"]()
    assert profile.name == PROFILE and profile.base_url == BASE_URL
    assert profile.env_vars == ("TINFOIL_API_KEY",) and profile.auth_type == "api_key"
    from hermes_cli.auth import PROVIDER_REGISTRY
    assert PROVIDER_REGISTRY[PROFILE].auth_type == "api_key"
    ad = profile._confidential_adapter
    assert isinstance(ad, TinfoilAdapter) and ad.enclave_source == "config"
    assert ad.attestation_count == 0  # registration itself does not attest


def test_main_client_is_confidential_and_turn_uses_secure_transport_with_one_sync_attestation(env, monkeypatch):
    profile = env["register"]()
    built = _count_create_client(monkeypatch, profile)
    agent = _agent()
    assert isinstance(agent.client, ConfidentialClient)
    result = agent.run_conversation("hello")
    assert "ATTESTED-FAKE-REPLY" in str(result.get("final_response"))
    # Rebuild + request-scoped client + another turn, as in the C0 follow-up.
    assert agent._replace_primary_openai_client(reason="seam_rebuild")
    req = agent._create_request_openai_client(reason="seam_request")
    assert isinstance(agent.client, ConfidentialClient) and isinstance(req, ConfidentialClient)
    agent._close_request_openai_client(req, reason="seam_request")
    agent.run_conversation("again")

    assert len(built) >= 4 and set(built) == {"ConfidentialClient"}, built
    rec = env["rec"]
    assert rec.labels() and set(rec.labels()) == {"secure-sync"}, rec.requests
    assert {r[1] for r in rec.requests} == {ENCLAVE}
    ad = profile._confidential_adapter
    assert ad.sync_attestation_count == 1 and ad.attestation_count == 1, ad.attestation_count
    assert env["sdk"]["verify_calls"] == 1


def test_attestation_count_is_one_across_four_create_client_calls(env):
    profile = env["register"]()
    clients = [profile.create_client(api_key="tf-key", base_url=BASE_URL) for _ in range(4)]
    assert all(isinstance(c, ConfidentialClient) for c in clients)
    for c in clients:
        c.chat.completions.create(model="m", messages=MSG)
        c.close()  # Hermes closes request-scoped clients; the pool must survive
    assert profile._confidential_adapter.sync_attestation_count == 1
    assert env["rec"].labels() == ["secure-sync"] * 4


def test_explicit_aux_text_and_vision_clients_are_confidential(env):
    env["register"]()
    from agent import auxiliary_client as aux
    for task in ("compression", "title_generation"):
        client, model = aux.get_text_auxiliary_client(task)
        assert isinstance(client, ConfidentialClient), task
        assert model == "tf-aux-model"
    resp = aux.call_llm(task="compression", messages=MSG)
    assert resp.choices[0].message.content == "ATTESTED-FAKE-REPLY"

    provider, client, model = aux.resolve_vision_provider_client()
    assert provider == PROFILE and isinstance(client, ConfidentialClient) and model == "tf-vision-model"
    aux._client_cache.clear()
    provider, aclient, _ = aux.resolve_vision_provider_client(async_mode=True)
    assert isinstance(aclient, ConfidentialClient)  # HERMES_SKIP_ASYNC_WRAP honoured, not rebuilt
    assert set(env["rec"].labels()) == {"secure-sync"}


def test_vision_analyze_uses_secure_async_transport(env):
    profile = env["register"]()
    from agent import auxiliary_client as aux
    from tools.vision_tools import vision_analyze_tool
    aux._client_cache.clear()
    result = asyncio.run(vision_analyze_tool(str(_png(env["tmp"] / "img.png")), "describe"))
    assert "ATTESTED-FAKE-REPLY" in str(result)
    labels = env["rec"].labels()
    assert labels and set(labels) == {"secure-async"}, env["rec"].requests
    assert profile._confidential_adapter.async_attestation_count == 1


def test_one_async_attestation_per_event_loop(env):
    profile = env["register"]()
    from agent import auxiliary_client as aux
    ad = profile._confidential_adapter

    async def two_calls():
        await aux.async_call_llm(task="compression", messages=MSG)
        await aux.async_call_llm(task="compression", messages=MSG)
    asyncio.run(two_calls())
    assert ad.async_attestation_count == 1
    aux._client_cache.clear()
    asyncio.run(two_calls())
    assert ad.async_attestation_count == 2
    asyncio.run(two_calls())
    assert ad.async_attestation_count == 3
    assert ad.async_pool_count() == 1  # pools of closed loops pruned
    assert ad.sync_attestation_count == 1
    labels = env["rec"].labels()
    assert labels.count("secure-async") == 6 and not any(lbl.startswith("hermes-default") for lbl in labels)


def test_failing_verifier_yields_refusing_client_and_no_request_anywhere(env, monkeypatch):
    env["sdk"]["fail"] = "attestation report signature invalid (simulated)"
    profile = env["register"]()
    from openai import OpenAI
    import agent.retry_utils as retry_utils
    monkeypatch.setattr(retry_utils, "jittered_backoff", lambda *a, **k: 0.0)  # keep Hermes' retries fast
    provider_mod.verification_cache.entry(PROFILE).failure_backoff_seconds = 3600  # timing-independent
    built = _count_create_client(monkeypatch, profile)

    direct = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(direct, RefusingClient) and "attested verification failed" in direct.reason

    agent = _agent()
    assert isinstance(agent.client, RefusingClient) and not isinstance(agent.client, OpenAI)
    try:
        result = agent.run_conversation("hello")
        outcome = str(result.get("final_response")) + " " + str(result.get("error", ""))
    except ConfidentialRefused as exc:
        outcome = f"raised {exc.reason}"
    assert "ATTESTED-FAKE-REPLY" not in outcome
    assert set(built) == {"RefusingClient"}, built
    # Without W1's middleware Hermes retries the refusal like a provider error (3 attempts, each a
    # fresh request-scoped client from create_client); W1 must catch-and-refuse so fallback never arms.
    assert len(built) >= 3, built
    assert env["rec"].requests == [], env["rec"].requests  # neither Hermes' transport nor the enclave
    # Failure backoff: the ~4 create_client calls did not each re-run attestation.
    assert env["sdk"]["verify_calls"] == 1

    from agent import auxiliary_client as aux
    client, _ = aux.get_text_auxiliary_client("compression")
    assert isinstance(client, RefusingClient)
    with pytest.raises(ConfidentialRefused):
        aux.call_llm(task="compression", messages=MSG)
    assert env["rec"].requests == []
    print("FAILING_VERIFIER_TURN_OUTCOME", outcome[:300])


def test_pin_mismatch_refuses_stages_pending_and_recovers_after_apply(env):
    profile = env["register"]()
    env["sdk"]["code"] = "c-new-build"
    client = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(client, RefusingClient) and client.reason == provider_mod.REASON_PIN_MISMATCH
    pending = env["pins"].pending()
    assert pending.code_fingerprint == "c-new-build" and pending.previous == "c1"
    verdict = provider_mod.attested_ok(PROFILE)
    assert verdict.in_tier is False and verdict.reason == provider_mod.REASON_PIN_MISMATCH
    assert verdict.host == ENCLAVE
    # Pool is held at the transport level too.
    with pytest.raises(Exception):
        profile._confidential_adapter.sync_http_view().post(f"{BASE_URL}/chat/completions", json={})
    assert env["rec"].requests == []

    env["pins"].apply(pending, approved_via="test", approval_rule_key="k")
    assert provider_mod.attested_ok(PROFILE).in_tier is True
    client = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(client, ConfidentialClient)
    client.chat.completions.create(model="m", messages=MSG)
    assert env["rec"].labels() == ["secure-sync"]
    assert env["sdk"]["verify_calls"] == 1  # mismatch did not trigger repeated attestation


def test_ttl_expiry_refreshes_once_and_cached_clients_refuse_when_refresh_fails(env):
    profile = env["register"]()
    cache = provider_mod.verification_cache
    client = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(client, ConfidentialClient) and cache.fresh(PROFILE)
    entry = cache.entry(PROFILE)

    entry.verified_mono -= 301  # TTL elapsed
    assert not cache.fresh(PROFILE)
    client.chat.completions.create(model="m", messages=MSG)  # gate refreshes once, then sends
    assert env["sdk"]["verify_calls"] == 2 and cache.fresh(PROFILE)

    entry.verified_mono -= 301
    env["sdk"]["fail"] = "network down"
    before = len(env["rec"].requests)
    with pytest.raises(ConfidentialRefused):
        client.chat.completions.create(model="m", messages=MSG)  # e.g. a client held in Hermes' aux cache
    with pytest.raises(Exception):
        client.with_options(timeout=3).chat.completions.create(model="m", messages=MSG)  # bypasses the gate
    assert len(env["rec"].requests) == before
    assert provider_mod.attested_ok(PROFILE).in_tier is False


def test_create_client_never_raises_or_returns_none(env, monkeypatch):
    profile = env["register"]()

    def explode(*a, **k):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(provider_mod.VerificationCache, "ensure", explode)
    client = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(client, RefusingClient)


def test_attested_ok_for_unknown_provider_is_off_tier(env):
    v = provider_mod.attested_ok("openrouter")
    assert v.in_tier is False and v.reason == provider_mod.REASON_NOT_REGISTERED


def _block_network(monkeypatch):
    import socket
    attempts = []

    def blocked(*a, **k):
        attempts.append(a[:1])
        raise OSError("NETWORK BLOCKED (test)")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", lambda self, *a, **k: blocked(*a))
    return attempts


def test_register_without_network_or_configured_enclave_then_lazy_router_discovery(env, monkeypatch):
    import providers

    attempts = _block_network(monkeypatch)
    monkeypatch.setattr(tinfoil_client, "get_router_address", _REAL_GET_ROUTER_ADDRESS)  # the real SDK call
    cfg = {k: v for k, v in env["cfg"].items() if k != "confidential"}  # no confidential.tinfoil.enclave
    cfg["confidential"] = {"tinfoil": {"tls_probe": False}}

    # Fresh import + register: no network, no attestation, placeholder endpoint.
    for name in [m for m in sys.modules if m.startswith("confidential_mode")]:
        monkeypatch.delitem(sys.modules, name)
    import confidential_mode.provider as fresh_provider
    import confidential_mode.verify.tinfoil as tinfoil_mod
    from confidential_mode.preflight import profile_base_url
    from confidential_mode.tiers import AttestedPredicate, Destination
    monkeypatch.setattr(fresh_provider, "verification_cache", fresh_provider.VerificationCache())
    profile = fresh_provider.register_provider_profile(None, config=cfg, data_dir=env["tmp"] / "pd2")
    assert providers.get_provider_profile(PROFILE) is profile
    ad = profile._confidential_adapter
    assert profile.base_url == tinfoil_mod.PLACEHOLDER_BASE_URL and ad.enclave_host == ""
    assert ad.enclave_resolved is False and ad.attestation_count == 0
    assert attempts == [] and env["sdk"]["verify_calls"] == 0
    assert not (env["tmp"] / "pd2").exists()  # not even the cache secret is written at register time

    # First create_client with no network: refuses (router discovery failed), never raises.
    client = profile.create_client(api_key="tf-key", base_url=profile.base_url)
    assert type(client).__name__ == "RefusingClient" and "router discovery failed" in client.reason
    assert attempts, "the real get_router_address should have tried (and been blocked)"
    assert env["sdk"]["verify_calls"] == 0 and env["rec"].requests == []
    verdict = fresh_provider.attested_ok(PROFILE)
    assert verdict.in_tier is False and verdict.host == ""
    predicate = AttestedPredicate([PROFILE], fresh_provider.attested_ok, profile_base_url)
    assert predicate.classify(Destination(PROFILE, "https://router.tinfoil.invalid/v1", "m", "chat_completions",
                                          "main")).in_tier is False  # placeholder host never matches

    # Network back: discovery resolves once, base_url follows, the predicate compares the resolved host.
    monkeypatch.setattr(tinfoil_client, "get_router_address", lambda platform=None: "r9.tinfoil.invalid")
    fresh_provider.verification_cache.entry(PROFILE).failure_backoff_seconds = 0
    first = profile.create_client(api_key="tf-key", base_url=profile.base_url)
    assert first.reason == fresh_provider.REASON_NO_PIN  # no trust on first use, even once reachable
    assert profile.base_url == "https://r9.tinfoil.invalid/v1"  # resolved by that attempt
    store = profile._confidential_pins
    store.apply(store.pending(), approved_via="test")
    client = profile.create_client(api_key="tf-key", base_url=profile.base_url)
    assert type(client).__name__ == "ConfidentialClient", getattr(client, "reason", None)
    assert ad.enclave_host == "r9.tinfoil.invalid" and ad.enclave_source == "router_discovery"
    assert profile.base_url == "https://r9.tinfoil.invalid/v1" and str(client.base_url).startswith(profile.base_url)
    assert fresh_provider.attested_ok(PROFILE).host == "r9.tinfoil.invalid"
    ok = predicate.classify(Destination(PROFILE, "https://r9.tinfoil.invalid/v1", "m", "chat_completions", "main"))
    assert ok.in_tier is True and ok.host == "r9.tinfoil.invalid"
    other = predicate.classify(Destination(PROFILE, BASE_URL, "m", "chat_completions", "main"))
    assert other.in_tier is False
    client.chat.completions.create(model="m", messages=MSG)
    assert [r[:2] for r in env["rec"].requests] == [("secure-sync", "r9.tinfoil.invalid")]


# ── ledger events (verify_ok / verify_fail / pin_staged) ─────────────────────────────────────

def test_verify_ok_is_emitted_once_with_evidence_and_lands_in_the_ledger(env, tmp_path):
    from confidential_mode.ledger import Ledger
    led = Ledger(tmp_path / "ledger.sqlite")
    events = []

    def sink(ev):
        events.append(ev)
        led.append(ev)
    profile = env["register"](on_event=sink)
    for _ in range(4):
        assert isinstance(profile.create_client(api_key="tf-key", base_url=BASE_URL), ConfidentialClient)
    assert [e["kind"] for e in events] == ["verify_ok"]
    ev = events[0]
    assert ev["provider"] == PROFILE and ev["host"] == ENCLAVE
    d = ev["detail"]
    assert (d["code_fingerprint"], d["enclave_fingerprint"], d["release_tag"], d["enclave_host"]) == (
        "c1", "e1", "v1.0.0", ENCLAVE)
    assert d["ttl_seconds"] == 300.0
    assert d["verifier"] == "tinfoil/0.14.2" and d["evidence"]["schema"] == "confidential-mode/tinfoil-evidence/v1"
    json.dumps(d)
    (row,) = led.tail()
    assert row.kind == "verify_ok" and row.host == ENCLAVE


def test_verify_fail_is_emitted_once_per_attempt(env):
    env["sdk"]["fail"] = "quote signature invalid (simulated)"
    events = []
    profile = env["register"](on_event=events.append)
    for _ in range(4):  # failure backoff: one attempt
        assert isinstance(profile.create_client(api_key="tf-key", base_url=BASE_URL), RefusingClient)
    assert [e["kind"] for e in events] == ["verify_fail"]
    d = events[0]["detail"]
    assert d["error_type"] == "VerifyError" and "quote signature invalid" in d["error"]
    assert d["enclave_host"] == ENCLAVE and events[0]["host"] == ENCLAVE and len(d["error"]) <= 300


def test_pin_staged_is_emitted_once_per_new_pending(env):
    events = []
    profile = env["register"](on_event=events.append)
    env["sdk"]["code"] = "c-new"
    for _ in range(3):
        profile.create_client(api_key="tf-key", base_url=BASE_URL)
        provider_mod.attested_ok(PROFILE)
    kinds = [e["kind"] for e in events]
    assert kinds == ["verify_ok", "pin_staged"], kinds
    d = events[1]["detail"]
    assert d["code_fingerprint"] == "c-new" and d["previous"] == "c1" and d["enclave_fingerprint"] == "e1"
    assert d["reason"] == provider_mod.REASON_PIN_MISMATCH


@pytest.mark.parametrize("fail", [None, "boom"])
def test_a_raising_on_event_never_changes_the_decision(env, fail):
    env["sdk"]["fail"] = fail

    def broken(ev):
        raise RuntimeError("ledger disk full")
    profile = env["register"](on_event=broken)
    client = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(client, RefusingClient if fail else ConfidentialClient)
    assert provider_mod.attested_ok(PROFILE).in_tier is (not fail)


def test_ledger_kwarg_is_a_shortcut_for_on_event(env, tmp_path):
    from confidential_mode.ledger import Ledger
    led = Ledger(tmp_path / "l.sqlite")
    profile = env["register"](ledger=led)
    profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert [r.kind for r in led.tail()] == ["verify_ok"]


# ── F8: a pin in force needs a consent record ─────────────────────────────────────────────────

def _consent_row(led, code="c1", enclave="e1", decision="approve"):
    led.append({"kind": "pin_applied", "provider": "tinfoil", "decision": decision,
                "detail": {"vendor": "tinfoil", "code_fingerprint": code, "enclave_fingerprint": enclave}})


def test_pin_without_consent_record_refuses_and_stages_nothing(env, tmp_path):
    from confidential_mode.ledger import Ledger
    led = Ledger(tmp_path / "ledger.sqlite")
    profile = env["register"](ledger=led)  # the fixture pinned c1/e1 straight through PinStore.apply
    client = profile.create_client(api_key="tf-key", base_url=BASE_URL)
    assert isinstance(client, RefusingClient) and client.reason == "pin has no consent record"
    v = provider_mod.attested_ok(PROFILE)
    assert v.in_tier is False and v.reason == "pin has no consent record"
    assert env["pins"].pending() is None and env["rec"].requests == []
    _consent_row(led, decision="deny")
    _consent_row(led, code="other")
    assert provider_mod.attested_ok(PROFILE).in_tier is False  # neither row vouches for c1/e1
    _consent_row(led)
    assert provider_mod.attested_ok(PROFILE).in_tier is True
    assert isinstance(profile.create_client(api_key="tf-key", base_url=BASE_URL), ConfidentialClient)


def test_unreadable_consent_ledger_refuses(env):
    class Broken:
        def append(self, ev):
            pass

        def tail(self, *a, **k):
            raise RuntimeError("sqlite locked")
    profile = env["register"](ledger=Broken())
    assert profile.create_client(api_key="tf-key", base_url=BASE_URL).reason == "pin has no consent record"


def test_register_with_ctx_defaults_to_the_plugin_ledger(env, monkeypatch, tmp_path):
    import confidential_mode.ledger as ledger_mod
    from confidential_mode.ledger import Ledger
    monkeypatch.setattr(ledger_mod, "default_ledger_path", lambda: tmp_path / "default.sqlite")
    made = []
    real_init = Ledger.__init__

    def init(self, path=None, **kw):
        made.append(path)
        real_init(self, path if path is not None else tmp_path / "default.sqlite", **kw)
    monkeypatch.setattr(Ledger, "__init__", init)
    profile = provider_mod.register_provider_profile(object(), config=env["cfg"], data_dir=tmp_path / "pd")
    assert made == [None]  # Ledger() with its default path, like the plugin's own
    assert provider_mod.verification_cache.entry(PROFILE).consent_ledger is not None


# ── catalog rule 11: the API key comes from Hermes' secret scope ──────────────────────────────

def test_api_key_comes_from_secret_scope_not_the_environment(env, monkeypatch):
    import agent.secret_scope as secret_scope
    monkeypatch.setenv("TINFOIL_API_KEY", "ENV-KEY-MUST-NOT-BE-READ-DIRECTLY")
    monkeypatch.setattr(secret_scope, "get_secret", lambda name, default=None: "scoped-key"
                        if name == "TINFOIL_API_KEY" else default)
    profile = env["register"]()
    assert profile.create_client(base_url=BASE_URL).api_key == "scoped-key"
    monkeypatch.setattr(secret_scope, "get_secret", lambda name, default=None: None)
    assert provider_mod.tinfoil_api_key() == ""  # no direct os.environ fallback
    import inspect
    assert "os.environ" not in inspect.getsource(provider_mod).replace("never os.environ directly", "")


def test_verify_rows_carry_source_and_key_first_seen_and_silent_reattest_reaches_the_ledger(env):
    events = []
    profile = env["register"](on_event=events.append)
    profile.create_client(api_key="tf-key", base_url=BASE_URL)
    (ok,) = events
    assert ok["detail"]["source"] == "verify" and ok["detail"]["key_first_seen"]["new"] is True
    assert set(ok["detail"]) >= {"log_index", "integrated_time", "policy_check", "ttl_seconds"}
    ad = provider_mod.adapter_for(PROFILE)
    assert ad is profile._confidential_adapter
    ad._sc.verify()  # an SDK-internal re-attestation (key rotation path)
    assert [e["detail"]["source"] for e in events] == ["verify", "silent_reattest"]
    assert events[1]["provider"] == PROFILE and events[1]["detail"]["key_first_seen"]["new"] is False

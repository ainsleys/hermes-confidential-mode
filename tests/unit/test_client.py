"""ConfidentialClient / RefusingClient and the Tinfoil adapter's pool model, with no Hermes and no network.

The SDK is never allowed to reach the network: SecureClient.verify and the http-client builders are
replaced by recorders, exactly as the C0 spikes did.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx
import openai
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode.client import ConfidentialClient, ConfidentialRefused, RefusingClient  # noqa: E402
from confidential_mode.verify.base import VerifyError  # noqa: E402

MSG = [{"role": "user", "content": "hi"}]


def _completion(model):
    return {"id": "x", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


class Recorder:
    def __init__(self):
        self.requests = []  # (label, path)

    def handler(self, label):
        def handle(request):
            self.requests.append((label, request.url.path))
            body = json.loads(request.content or b"{}")
            return httpx.Response(200, json=_completion(body.get("model") or "m"))
        return handle

    def labels(self):
        return [r[0] for r in self.requests]


class _NoClose(httpx.BaseTransport):
    def __init__(self, inner):
        self.inner = inner

    def handle_request(self, request):
        return self.inner.handle_request(request)

    def close(self):
        pass


class FakeAdapter:
    """Stands in for TinfoilAdapter: one shared sync pool, one async pool per loop."""
    vendor = "fake"

    def __init__(self, rec: Recorder):
        self.rec = rec
        self.shared_sync = httpx.MockTransport(rec.handler("secure-sync"))
        self.async_builds = []

    def sync_http_view(self):
        return httpx.Client(transport=_NoClose(self.shared_sync))

    def async_http_for_loop(self):
        self.async_builds.append(asyncio.get_running_loop())
        return httpx.AsyncClient(transport=httpx.MockTransport(self.rec.handler("secure-async")))


@pytest.fixture
def rec():
    return Recorder()


@pytest.fixture
def client(rec):
    return ConfidentialClient(FakeAdapter(rec), api_key="k", base_url="https://enclave.invalid/v1")


# ── ConfidentialClient ─────────────────────────────────────────────────────────────────────────


def test_declares_hermes_skip_flags_and_exposes_api_key_and_base_url(client):
    assert client.HERMES_SKIP_TRANSPORT_WRAP is True and client.HERMES_SKIP_ASYNC_WRAP is True
    assert client.api_key == "k"
    assert str(client.base_url).startswith("https://enclave.invalid/v1")


def test_sync_caller_gets_sync_result_on_secure_sync_transport(client, rec):
    resp = client.chat.completions.create(model="m", messages=MSG)
    assert resp.choices[0].message.content == "OK"
    assert rec.labels() == ["secure-sync"]


def test_async_caller_gets_awaitable_on_secure_async_transport(client, rec):
    async def caller():
        return await client.chat.completions.create(model="m", messages=MSG)
    resp = asyncio.run(caller())
    assert resp.choices[0].message.content == "OK"
    assert rec.labels() == ["secure-async"]


def test_sync_call_from_a_function_running_on_a_loop_thread_stays_sync(client, rec):
    def sync_helper():
        return client.chat.completions.create(model="m", messages=MSG)

    async def caller():
        return sync_helper()  # sync frame calls create, even though a loop is running
    resp = asyncio.run(caller())
    assert resp.choices[0].message.content == "OK" and rec.labels() == ["secure-sync"]


def test_one_async_client_per_event_loop(client, rec):
    adapter = client._adapter

    async def twice():
        await client.chat.completions.create(model="m", messages=MSG)
        await client.chat.completions.create(model="m", messages=MSG)
    asyncio.run(twice())
    asyncio.run(twice())
    assert len(adapter.async_builds) == 2  # one per loop, reused within a loop
    assert rec.labels() == ["secure-async"] * 4
    assert all(lp.is_closed() for lp in adapter.async_builds)
    asyncio.run(twice())
    assert len(client._async_by_loop) == 1  # closed loops pruned


def test_getattr_delegates_to_sync_openai(client, rec):
    assert client.with_options(timeout=5).chat.completions.create(model="m", messages=MSG)
    assert rec.labels() == ["secure-sync"]
    assert client.is_closed() is False
    assert isinstance(client._client, httpx.Client)
    assert client.models is client._sync.models
    with pytest.raises(AttributeError):
        client.consume_reference_usage  # MoA probe must read as absent
    assert client.chat.completions.with_raw_response is not None  # delegated to sync completions


def test_close_closes_only_the_view_not_the_shared_pool(rec):
    adapter = FakeAdapter(rec)
    a = ConfidentialClient(adapter, api_key="k", base_url="https://enclave.invalid/v1")
    b = ConfidentialClient(adapter, api_key="k", base_url="https://enclave.invalid/v1")
    a.close()
    assert a.is_closed() is True
    b.chat.completions.create(model="m", messages=MSG)  # the shared pool survived
    c = ConfidentialClient(adapter, api_key="k", base_url="https://enclave.invalid/v1")
    c.chat.completions.create(model="m", messages=MSG)
    assert rec.labels() == ["secure-sync", "secure-sync"]


def test_gate_refusal_blocks_both_modes_before_any_request(rec):
    def gate():
        raise ConfidentialRefused("stale")
    c = ConfidentialClient(FakeAdapter(rec), api_key="k", base_url="https://enclave.invalid/v1", gate=gate)
    with pytest.raises(ConfidentialRefused):
        c.chat.completions.create(model="m", messages=MSG)

    async def caller():
        return await c.chat.completions.create(model="m", messages=MSG)
    with pytest.raises(ConfidentialRefused):
        asyncio.run(caller())
    assert rec.requests == []


# ── RefusingClient ─────────────────────────────────────────────────────────────────────────────


def test_refusing_client_raises_in_sync_and_async_modes():
    r = RefusingClient("attestation failed", api_key="k", base_url="https://enclave.invalid/v1")
    assert r.HERMES_SKIP_TRANSPORT_WRAP is True and r.HERMES_SKIP_ASYNC_WRAP is True
    assert r.api_key == "k" and r.base_url == "https://enclave.invalid/v1"
    with pytest.raises(ConfidentialRefused) as exc:
        r.chat.completions.create(model="m", messages=MSG)
    assert exc.value.reason == "attestation failed"

    async def caller():
        return await r.chat.completions.create(model="m", messages=MSG)
    with pytest.raises(ConfidentialRefused):
        asyncio.run(caller())
    for call in (lambda: r.with_options(timeout=1).chat.completions.create(model="m"),
                 lambda: r.models.list(), lambda: r.embeddings.create(input="x"),
                 lambda: r.responses.create(model="m"), lambda: r._client.get("https://x.invalid/")):
        with pytest.raises(ConfidentialRefused):
            call()
    with pytest.raises(AttributeError):
        r.consume_reference_usage
    assert r.is_closed() is False
    r.close()
    assert r.is_closed() is True


# ── TinfoilAdapter against a stubbed SDK ───────────────────────────────────────────────────────


tinfoil_client = pytest.importorskip("tinfoil.client")


def _stub_sdk(monkeypatch, rec: Recorder, *, code="c1", enclave="e1", fail=None):
    calls = []
    state = {"code": code, "enclave": enclave, "fail": fail}

    def fake_verify(self):
        calls.append(self.enclave)
        if state["fail"]:
            raise RuntimeError(state["fail"])
        doc = tinfoil_client.VerificationDocument(config_repo=self.repo, enclave_host=self.enclave,
                                                  selected_router_endpoint=self.enclave)
        doc.code_fingerprint, doc.enclave_fingerprint = state["code"], state["enclave"]
        doc.release_tag, doc.release_digest, doc.security_verified = "v9", "d" * 64, True
        doc.verified_at = "2026-11-06T00:00:00Z"
        for step in doc.steps.values():
            step.status = "success"
        self._verification_document = doc
        return tinfoil_client.GroundTruth(public_key="ab" * 32, digest="d" * 64, measurement="m")

    def fake_sync(self):
        self.verify()
        return httpx.Client(transport=httpx.MockTransport(rec.handler("secure-sync")), follow_redirects=False)

    def fake_async(self):
        self.verify()
        return httpx.AsyncClient(transport=httpx.MockTransport(rec.handler("secure-async")),
                                 follow_redirects=False)
    monkeypatch.setattr(tinfoil_client.SecureClient, "verify", fake_verify)
    monkeypatch.setattr(tinfoil_client.SecureClient, "make_secure_http_client", fake_sync)
    monkeypatch.setattr(tinfoil_client.SecureClient, "make_secure_async_http_client", fake_async)

    def no_router():
        raise AssertionError("router discovery must not run when an enclave is configured")
    monkeypatch.setattr(tinfoil_client, "get_router_address", no_router)
    return calls, state


def _adapter(tmp_path, **kw):
    from confidential_mode.verify.tinfoil import TinfoilAdapter
    kw.setdefault("enclave", "router.example")
    return TinfoilAdapter(data_dir=tmp_path / "data", **kw)


def test_adapter_verify_maps_document_and_counts_one_attestation(tmp_path, monkeypatch, rec):
    calls, _ = _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path)
    res = ad.verify()
    assert (res.vendor, res.router_repo, res.enclave_host) == ("tinfoil", "tinfoilsh/confidential-model-router",
                                                                 "router.example")
    assert (res.code_fingerprint, res.enclave_fingerprint, res.release_tag) == ("c1", "e1", "v9")
    assert res.verifier == "tinfoil/0.14.2"
    assert abs(res.verified_at_local - time.time()) < 5
    assert res.evidence["schema"] == "confidential-mode/tinfoil-evidence/v1"
    assert res.evidence["claims"]["code_fingerprint"] == "c1"
    assert res.evidence["verification_document"]["securityVerified"] is True
    # The stubbed verify fetched nothing, so the capture is (honestly) incomplete.
    assert res.evidence["capture_complete"] is False and "attestation" in res.evidence["capture_missing"]
    json.dumps(res.evidence)  # JSON-serialisable
    assert ad.enclave_source == "config"
    assert calls == ["router.example"] and ad.attestation_count == 1 and ad.sync_attestation_count == 1
    assert ad.base_url == "https://router.example/v1"


def test_adapter_user_cache_secret_lives_in_data_dir_never_home(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("TINFOIL_USER_CACHE_SECRET", raising=False)
    ad = _adapter(tmp_path)
    ad.verify()
    secret_file = tmp_path / "data" / "tinfoil_user_cache_secret"
    assert secret_file.exists() and (secret_file.stat().st_mode & 0o777) == 0o600
    assert ad._sc._user_cache_secret == secret_file.read_text()
    assert not (tmp_path / "home" / ".tinfoil").exists()
    assert _adapter(tmp_path)._secure_client()._user_cache_secret == secret_file.read_text()  # stable


def test_adapter_router_discovery_is_recorded(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path, enclave=None, router_discovery=lambda: "r7.example")
    assert ad.verify().enclave_host == "r7.example" and ad.enclave_source == "router_discovery"
    assert ad.verify().evidence["enclave_source"] == "router_discovery"


@pytest.mark.parametrize("breakage", ["raise", "not_verified", "step_failed", "no_fingerprint", "wrong_repo"])
def test_adapter_verify_raises_verify_error_on_anything(tmp_path, monkeypatch, rec, breakage):
    _stub_sdk(monkeypatch, rec, fail="boom" if breakage == "raise" else None)
    real_sync = tinfoil_client.SecureClient.make_secure_http_client

    def sync_then_break(self):
        http = real_sync(self)
        doc = self._verification_document
        if breakage == "not_verified":
            doc.security_verified = False
        elif breakage == "step_failed":
            doc.steps["verify_code"].status = "failed"
        elif breakage == "no_fingerprint":
            doc.code_fingerprint = ""
        elif breakage == "wrong_repo":
            doc.config_repo = "attacker/repo"
        return http
    monkeypatch.setattr(tinfoil_client.SecureClient, "make_secure_http_client", sync_then_break)
    ad = _adapter(tmp_path)
    with pytest.raises(VerifyError):
        ad.verify()
    with pytest.raises(VerifyError):
        ad.sync_http_view()  # no pool after a failed first verify
    assert ad.last_result is None


def test_adapter_never_uses_pinned_measurement_mode(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path)
    ad.verify()
    assert ad._sc.measurement is None and ad._sc.repo == "tinfoilsh/confidential-model-router"
    with pytest.raises(ValueError):
        _adapter(tmp_path, repo="")


def test_adapter_sync_views_are_non_closing_and_share_one_attested_pool(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path, hold_until_accepted=False)
    ad.verify()
    for _ in range(4):
        view = ad.sync_http_view()
        view.post("https://router.example/v1/chat/completions", json={"model": "m"})
        view.close()
    assert ad.attestation_count == 1 and rec.labels() == ["secure-sync"] * 4
    assert not ad._sync_http.is_closed


def test_adapter_hold_blocks_views_until_released(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path)  # hold_until_accepted default
    ad.verify()
    view = ad.sync_http_view()
    with pytest.raises(VerifyError):
        view.post("https://router.example/v1/chat/completions", json={})
    ad.release()
    view.post("https://router.example/v1/chat/completions", json={})
    ad.hold("pin mismatch")

    async def go():
        a = ad.async_http_for_loop()
        await a.post("https://router.example/v1/chat/completions", json={})
    with pytest.raises(VerifyError):
        asyncio.run(go())
    assert rec.labels() == ["secure-sync"]


def test_adapter_one_async_attestation_per_loop_and_prunes_closed_loops(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path, hold_until_accepted=False)
    ad.verify()

    async def go():
        for _ in range(3):
            a = ad.async_http_for_loop()
            await a.post("https://router.example/v1/chat/completions", json={})
            await a.aclose()
    asyncio.run(go())
    assert ad.async_attestation_count == 1 and ad.async_pool_count() == 1
    asyncio.run(go())
    assert ad.async_attestation_count == 2 and ad.async_pool_count() == 1  # first loop pruned
    assert ad.attestation_count == 3 and rec.labels().count("secure-async") == 6


def test_adapter_rotation_reverification_to_a_different_build_is_refused(tmp_path, monkeypatch, rec):
    _, state = _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path, hold_until_accepted=False)
    ad.verify()
    state["code"] = "c-evil"
    # SDK-internal re-verification (what _EHBPReVerifyingTransport does on key rotation) goes
    # through the guard and is rejected because the fingerprints moved.
    with pytest.raises(VerifyError):
        ad._sc.verify()

    async def go():
        ad.async_http_for_loop()
    with pytest.raises(VerifyError):
        asyncio.run(go())
    # An explicit verify() accepts the new build (the pin check upstream decides about it).
    assert ad.verify().code_fingerprint == "c-evil"


def test_adapter_async_before_verify_refuses(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path)

    async def go():
        ad.async_http_for_loop()
    with pytest.raises(VerifyError):
        asyncio.run(go())
    assert ad.attestation_count == 0


def test_confidential_client_over_real_adapter_end_to_end(tmp_path, monkeypatch, rec):
    _stub_sdk(monkeypatch, rec)
    ad = _adapter(tmp_path, hold_until_accepted=False)
    ad.verify()
    c = ConfidentialClient(ad, api_key="k", base_url=ad.base_url)
    c.chat.completions.create(model="m", messages=MSG)

    async def go():
        return await c.chat.completions.create(model="m", messages=MSG)
    asyncio.run(go())
    c.close()
    assert rec.labels() == ["secure-sync", "secure-async"]
    assert ad.sync_attestation_count == 1 and ad.async_attestation_count == 1
    assert isinstance(c._sync, openai.OpenAI)

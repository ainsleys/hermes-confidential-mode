"""Amendment 14: a vendor endpoint's HTTP error names the vendor, the subject, the status and one next step."""
from __future__ import annotations

import httpx
import pytest

from confidential_mode.verify.base import VendorHTTPError, VerifyError, http_status_in


def test_the_text_names_vendor_subject_status_and_a_next_step():
    e = VendorHTTPError(vendor="NEAR", subject="Qwen/Qwen3-VL-30B-A3B-Instruct", status=503)
    assert isinstance(e, VerifyError)
    assert str(e) == ("Qwen/Qwen3-VL-30B-A3B-Instruct: attestation unavailable (HTTP 503 from NEAR); "
                      "try again in a few minutes")
    assert "check the model id" in str(VendorHTTPError(vendor="NEAR", subject="m", status=404))
    assert "check the router id" in str(VendorHTTPError(vendor="Tinfoil", subject="r", status=404,
                                                        subject_kind="router"))


def test_the_status_is_found_anywhere_in_the_chain():
    req = httpx.Request("GET", "https://x.invalid/")
    inner = httpx.HTTPStatusError("boom", request=req, response=httpx.Response(502, request=req))
    try:
        try:
            raise inner
        except Exception as exc:
            raise RuntimeError("wrapped") from exc
    except RuntimeError as outer:
        assert http_status_in(outer) == 502
    assert http_status_in(ValueError("no status")) is None


def test_near_get_names_the_model_and_the_gateway(tmp_path):
    from ..near_world import BASE, NearWorld
    world = NearWorld()

    def handler(request):
        return httpx.Response(503, json={})
    ad = world.adapter(tmp_path)
    ad._transport_factory = lambda: httpx.MockTransport(handler)
    with pytest.raises(VendorHTTPError) as got:
        ad.prepare_verification()
    assert str(got.value).startswith(f"NEAR gateway {ad.host}: attestation unavailable (HTTP 503 from NEAR)")
    assert got.value.subject_kind == "gateway" and BASE.startswith("https://")


# ── review SF3: the Tinfoil SDK's HTTP errors through the adapter, named by the host that answered ─────────

def _http_error(status, url):
    import requests
    resp = requests.models.Response()
    resp.status_code, resp.url = status, url
    return requests.HTTPError(f"{status} error for url: {url}", response=resp)


@pytest.fixture
def tinfoil_sdk(monkeypatch):
    """The SDK's own SecureClient.verify, reached through the adapter's guard; only its fetches are faked."""
    tf_client = pytest.importorskip("tinfoil.client")
    monkeypatch.setattr(tf_client.SecureClient, "make_secure_http_client", lambda self: self.verify())
    return tf_client


def _adapter(tmp_path):
    from confidential_mode.verify.tinfoil import TinfoilAdapter
    return TinfoilAdapter(data_dir=tmp_path / "d", enclave="router.example", tls_probe=False)


def test_a_router_503_names_tinfoil_and_the_router(tinfoil_sdk, monkeypatch, tmp_path):
    def fetch(host):
        raise _http_error(503, f"https://{host}/.well-known/tinfoil-attestation")
    monkeypatch.setattr(tinfoil_sdk, "fetch_attestation", fetch)
    with pytest.raises(VendorHTTPError) as got:
        _adapter(tmp_path).prepare_verification()
    assert str(got.value) == ("Tinfoil router router.example: attestation unavailable (HTTP 503 from Tinfoil); "
                              "try again in a few minutes")


def test_an_intel_pcs_403_names_the_intel_pcs_proxy(tinfoil_sdk, monkeypatch, tmp_path):
    """The URL the SDK requests: collateral_tdx._proxy_url of Intel's TCB-info URL."""
    from tinfoil.attestation import collateral_tdx
    url = collateral_tdx._proxy_url(f"{collateral_tdx.INTEL_PCS_TDX_BASE_URL}/tcb?fmspc=00806f050000")
    assert url.startswith("https://tdx-proxy.tinfoil.sh/api.trustedservices.intel.com/")

    class Doc:
        def verify(self):
            raise _http_error(403, url)
    monkeypatch.setattr(tinfoil_sdk, "fetch_attestation", lambda host: Doc())
    with pytest.raises(VendorHTTPError) as got:
        _adapter(tmp_path).prepare_verification()
    assert str(got.value).startswith("Tinfoil router router.example: Intel TDX collateral fetch unavailable "
                                     "(HTTP 403 from Tinfoil's Intel PCS proxy)"), str(got.value)


def test_hosts_match_on_a_dot_boundary():
    from confidential_mode.verify.base import http_source
    assert http_source("https://api.github.com/x")[0] == "GitHub"
    assert http_source("https://evilgithub.com/x")[0] == "evilgithub.com"
    assert http_source("https://eviltinfoil.sh/x")[0] == "eviltinfoil.sh"
    assert http_source("https://atc.tinfoil.sh/x")[0] == "Tinfoil's atc.tinfoil.sh"


def test_a_github_proxy_error_names_the_proxy(tinfoil_sdk, monkeypatch, tmp_path):
    class Doc:
        def verify(self):
            raise _http_error(502, "https://github-proxy.tinfoil.sh/repos/tinfoilsh/x/releases/latest")
    monkeypatch.setattr(tinfoil_sdk, "fetch_attestation", lambda host: Doc())
    with pytest.raises(VendorHTTPError) as got:
        _adapter(tmp_path).prepare_verification()
    assert "(HTTP 502 from Tinfoil's GitHub proxy)" in str(got.value)


def test_router_discovery_says_discovery(tmp_path):
    import urllib.error

    from confidential_mode.verify.tinfoil import TinfoilAdapter

    def discover():
        raise urllib.error.HTTPError("https://atc.tinfoil.sh/routers", 503, "Service Unavailable", {}, None)
    ad = TinfoilAdapter(data_dir=tmp_path / "d", tls_probe=False, router_discovery=discover)
    with pytest.raises(VendorHTTPError) as got:
        ad.resolve_enclave_host()
    assert str(got.value) == ("Tinfoil: router discovery unavailable (HTTP 503 from Tinfoil's atc.tinfoil.sh); "
                              "try again in a few minutes")


# ── issue #2: a plaintext non-2xx reply through the pinned EHBP transports ─────────────────────────────────

def _hpke_hex() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    key = x25519.X25519PrivateKey.generate().public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


UNTRUSTED_BODY = b'{"error": {"message": "rate limited; echo of messages[0].content=SECRET-PROMPT"}}'


def _plaintext_reply(status: int):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"content-type": "application/json"}, content=UNTRUSTED_BODY)
    return handler


def _pinned_sync_transport(monkeypatch, tmp_path, status: int):
    """The adapter's pinned sync EHBP transport with the network transport replaced by a plaintext reply."""
    from types import SimpleNamespace

    from confidential_mode.verify.tinfoil import TinfoilAdapter

    class _Net(httpx.MockTransport):
        def __init__(self, verify=None, **_kw):
            super().__init__(_plaintext_reply(status))
    monkeypatch.setattr(httpx, "HTTPTransport", _Net)
    ad = TinfoilAdapter(data_dir=tmp_path / "d", enclave="inf.example", tls_probe=False)
    return ad.pinned_ehbp_sync_transport(SimpleNamespace(_require_hpke_public_key=_hpke_hex))


def _pinned_async_transport(monkeypatch, tmp_path, status: int):
    import asyncio
    from types import SimpleNamespace

    from confidential_mode.verify.tinfoil import TinfoilAdapter

    class _Net(httpx.MockTransport):
        def __init__(self, verify=None, **_kw):
            super().__init__(_plaintext_reply(status))
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", _Net)
    ad = TinfoilAdapter(data_dir=tmp_path / "d", enclave="inf.example", tls_probe=False)
    return asyncio.run(ad.pinned_ehbp_async_transport(SimpleNamespace(_require_hpke_public_key=_hpke_hex)))


@pytest.mark.parametrize("status, tail", [
    (429, "the router is rate limiting; try again in a few minutes"),
    (503, "try again in a few minutes"),
    (401, "check TINFOIL_API_KEY"),
    (404, "check the model id; the router does not serve it"),
    (302, "the router answered with a redirect, which the plugin does not follow"),
])
def test_a_plaintext_error_reply_names_the_status_and_the_router_and_never_the_body_sync(
        monkeypatch, tmp_path, status, tail):
    """Issue #2: the router answered an encrypted request in plaintext with an HTTP error (a rate limit, an
    outage, a bad key). The send fails as a VendorHTTPError in the attestation errors' text form; the body is
    the router's and is never quoted."""
    t = _pinned_sync_transport(monkeypatch, tmp_path, status)
    with httpx.Client(transport=t) as c, pytest.raises(VendorHTTPError) as got:
        c.post("https://inf.example/v1/chat/completions", content=b'{"messages": [{"content": "hi"}]}')
    assert str(got.value) == f"Tinfoil router inf.example: inference unavailable (HTTP {status} from Tinfoil); {tail}"
    assert got.value.status == status and got.value.status_code == status
    assert "SECRET-PROMPT" not in str(got.value) and "SECRET-PROMPT" not in repr(got.value)


def test_a_plaintext_error_reply_names_the_status_and_the_router_and_never_the_body_async(monkeypatch, tmp_path):
    import asyncio
    t = _pinned_async_transport(monkeypatch, tmp_path, 503)

    async def go():
        async with httpx.AsyncClient(transport=t) as c:
            await c.post("https://inf.example/v1/chat/completions", content=b'{"messages": [{"content": "hi"}]}')
    with pytest.raises(VendorHTTPError) as got:
        asyncio.run(go())
    assert str(got.value) == ("Tinfoil router inf.example: inference unavailable (HTTP 503 from Tinfoil); "
                              "try again in a few minutes")
    assert "SECRET-PROMPT" not in str(got.value)


def test_a_plaintext_2xx_reply_is_still_a_cryptographic_failure(monkeypatch, tmp_path):
    """A success without a response nonce is not a vendor outage: the EHBP layer refuses it as before."""
    from ehbp import MissingResponseNonceError
    t = _pinned_sync_transport(monkeypatch, tmp_path, 200)
    with httpx.Client(transport=t) as c, pytest.raises(MissingResponseNonceError):
        c.post("https://inf.example/v1/chat/completions", content=b'{"messages": [{"content": "hi"}]}')


def test_a_bodiless_request_passes_a_plaintext_2xx_through(monkeypatch, tmp_path):
    """The EHBP layer sends a request without a body in plaintext and expects a plaintext reply."""
    t = _pinned_sync_transport(monkeypatch, tmp_path, 200)
    with httpx.Client(transport=t) as c:
        assert c.get("https://inf.example/.well-known/tinfoil-attestation").status_code == 200


KEY_CONFIG_PROBLEM = (b'{"type": "urn:ietf:params:ehbp:error:key-config", "title": "stale key", '
                      b'"detail": "echo of messages[0].content=SECRET-PROMPT"}')


def _net_replying(monkeypatch, replies: list, seen: list, attr: str = "HTTPTransport"):
    """httpx's network transport replaced by one that answers ``replies`` in order (status, headers, body)."""
    class _Net(httpx.MockTransport):
        def __init__(self, verify=None, **_kw):
            def handler(request: httpx.Request) -> httpx.Response:
                seen.append(request.url.path)
                status, headers, body = replies[min(len(seen), len(replies)) - 1]
                return httpx.Response(status, headers=headers, content=body)
            super().__init__(handler)
    monkeypatch.setattr(httpx, attr, _Net)


def test_the_key_config_mismatch_reply_reaches_the_ehbp_layer_through_the_guard(monkeypatch, tmp_path):
    """Review B3: ehbp 0.4.2 turns a plaintext 422 application/problem+json reply of type key-config into
    KeyConfigMismatchError, which the Tinfoil SDK catches to re-attest and retry. The guard must let that reply
    through; every other plaintext error is still a VendorHTTPError."""
    from types import SimpleNamespace

    from ehbp import KeyConfigMismatchError

    from confidential_mode.verify.tinfoil import TinfoilAdapter
    seen: list = []
    _net_replying(monkeypatch, [(422, {"content-type": "application/problem+json"}, KEY_CONFIG_PROBLEM)], seen)
    ad = TinfoilAdapter(data_dir=tmp_path / "d", enclave="inf.example", tls_probe=False)
    t = ad.pinned_ehbp_sync_transport(SimpleNamespace(_require_hpke_public_key=_hpke_hex))
    with httpx.Client(transport=t) as c, pytest.raises(KeyConfigMismatchError):
        c.post("https://inf.example/v1/chat/completions", content=b'{"messages": [{"content": "hi"}]}')
    # a 422 that is not a problem+json document is a vendor error like any other
    seen.clear()
    _net_replying(monkeypatch, [(422, {"content-type": "application/json"}, KEY_CONFIG_PROBLEM)], seen)
    t = ad.pinned_ehbp_sync_transport(SimpleNamespace(_require_hpke_public_key=_hpke_hex))
    with httpx.Client(transport=t) as c, pytest.raises(VendorHTTPError, match="HTTP 422 from Tinfoil"):
        c.post("https://inf.example/v1/chat/completions", content=b'{"messages": [{"content": "hi"}]}')


def test_a_key_rotation_still_re_attests_and_retries_through_the_sdk_chain(monkeypatch, tmp_path):
    """The SDK's _EHBPReVerifyingTransport sits above the pinned EHBP transport the adapter builds. A 422
    key-config reply makes it rebuild the transport from a fresh attestation and retry once; the second 422
    surfaces as the mismatch. The adapter's builder (and so its attestation hook) runs twice and the router
    sees two requests."""
    from types import SimpleNamespace

    from ehbp import KeyConfigMismatchError
    from tinfoil.client import _EHBPReVerifyingTransport

    from confidential_mode.verify.tinfoil import TinfoilAdapter
    seen: list = []
    reply = (422, {"content-type": "application/problem+json"}, KEY_CONFIG_PROBLEM)
    _net_replying(monkeypatch, [reply, reply], seen)
    ad = TinfoilAdapter(data_dir=tmp_path / "d", enclave="inf.example", tls_probe=False)
    attestations: list = []
    key = _hpke_hex()

    def require_key():
        attestations.append(1)
        return key
    sc = SimpleNamespace(_require_hpke_public_key=require_key)
    ad._pin_ehbp_builders(sc)
    chain = _EHBPReVerifyingTransport(sc, sc._build_ehbp_sync_transport())
    with httpx.Client(transport=chain) as c, pytest.raises(KeyConfigMismatchError):
        c.post("https://inf.example/v1/chat/completions", content=b'{"messages": [{"content": "hi"}]}')
    assert len(attestations) == 2 and seen == ["/v1/chat/completions"] * 2

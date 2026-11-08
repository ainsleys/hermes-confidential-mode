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
    from tests.near_world import BASE, NearWorld
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


def test_an_intel_pcs_403_names_intel_not_tinfoil(tinfoil_sdk, monkeypatch, tmp_path):
    class Doc:
        def verify(self):
            raise _http_error(403, "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00")
    monkeypatch.setattr(tinfoil_sdk, "fetch_attestation", lambda host: Doc())
    with pytest.raises(VendorHTTPError) as got:
        _adapter(tmp_path).prepare_verification()
    text = str(got.value)
    assert text.startswith("Tinfoil router router.example: Intel TDX collateral fetch unavailable (HTTP 403 from "
                           "Intel PCS)"), text
    assert "from Tinfoil" not in text and got.value.vendor == "Intel PCS"


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

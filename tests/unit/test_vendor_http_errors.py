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

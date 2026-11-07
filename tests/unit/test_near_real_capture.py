"""A real NEAR AI Cloud capture (public endpoints, no API key, 2026-11-07) replays offline.

tests/fixtures/near_real_capture/raw_public_responses.json holds the gateway report, one model report
(Qwen/Qwen3.8-27B), Intel Trust Authority's tokens and Intel's JWKS as received (see its _note). The real
verifiers run: tinfoil 0.14.2's TDX quote verifier against the Intel SGX root, and the PS384 JWTs
against the JWKS whose x5c chain ends at the pinned Intel Trust Authority root.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("tinfoil.attestation.verify_tdx")

from confidential_mode.verify import near, near_checks as nc, replay_near  # noqa: E402

RAW = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "near_real_capture" /
                  "raw_public_responses.json").read_text())
CODE_FP = "111f9bf87dc011150753990dfbeae4bbeac9a5b603559055d23947edc663bc7b"
ENCLAVE_FP = "ce1f0519a96cbd217d59cd065e1f60698075576fb52338523779f5a5665f437d"


def _spki_of_report_cert() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as s
    cert = x509.load_pem_x509_certificate(RAW["gateway_report"]["tls_certificate"].encode())
    return hashlib.sha256(cert.public_key().public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def evidence(raw=RAW) -> dict:
    model = raw["model"]
    return near.build_evidence(
        {"gateway_report": raw["gateway_report"], "model_reports": {model: raw["model_report"]},
         "ita": {model: raw["ita_model"]}, "jwks": raw["jwks"], "jwks_url_fetched": nc.ITA_JWKS_URLS[0]},
        base_url=near.DEFAULT_BASE_URL, models=[model], nonce=raw["nonce"],
        captured_at_unix=raw["captured_at_unix"],
        tls_observation={"captured": True, "spki_sha256": _spki_of_report_cert()})


def test_real_capture_appraises_with_real_intel_signatures():
    ev = evidence()
    assert ev["capture_complete"] is True
    a = near.appraise(ev)
    assert a.ok, a.checks
    assert a.identity == "cloud-api.near.ai#Qwen/Qwen3.8-27B"
    assert (a.code_fingerprint, a.enclave_fingerprint) == (CODE_FP, ENCLAVE_FP)
    assert a.tcb_status == "UpToDate"
    assert a.gateway_signer == "40599fb284f43953bb356b09080fd803c960fc10285ad90eca462ca711ad4acb"
    assert a.model_signers == {"Qwen/Qwen3.8-27B": ["89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93"]}
    assert "GPU verdict True" in a.checks["ita_model_tokens"]


def test_real_capture_replays_through_the_replay_module():
    ev = evidence()
    ev["claims"] = near.evidence_claims(ev, near.appraise(ev))
    r = replay_near.replay(json.loads(json.dumps(ev)), expected_repo="cloud-api.near.ai#Qwen/Qwen3.8-27B",
                           expected_fingerprints=(CODE_FP, ENCLAVE_FP))
    assert r.ok, r.checks
    assert r.captured_at_asserted == ev["captured_at"]


def _mutated(fn):
    raw = copy.deepcopy(RAW)
    fn(raw)
    return near.appraise(evidence(raw))


@pytest.mark.parametrize("fn,key", [
    (lambda r: r["model_report"]["model_attestations"][0].__setitem__(
        "signing_address", "00" * 32), "model_quotes"),
    (lambda r: r["gateway_report"]["gateway_attestation"]["info"]["tcb_info"].__setitem__(
        "app_compose", r["gateway_report"]["gateway_attestation"]["info"]["tcb_info"]["app_compose"] + " "),
     "gateway_quote"),
    (lambda r: r.__setitem__("nonce", "00" * 32), "gateway_quote"),
    (lambda r: r["jwks"]["keys"][0]["x5c"].pop(), "ita_jwks"),
    (lambda r: r["ita_model"]["gateway"].__setitem__("token", r["ita_model"]["gateway"]["token"][:-8] + "AAAAAAAA"),
     "ita_gateway_token"),
])
def test_real_capture_tampering_fails(fn, key):
    a = _mutated(fn)
    assert not a.ok and str(a.checks[key]).startswith("fail"), a.checks


def test_flipped_quote_byte_fails_the_real_quote_verifier():
    raw = copy.deepcopy(RAW)
    rep = raw["model_report"]["model_attestations"][0]
    q = bytearray(bytes.fromhex(rep["intel_quote"]))
    q[600] ^= 1
    rep["intel_quote"] = q.hex()
    a = near.appraise(evidence(raw))
    assert not a.ok and str(a.checks["model_quotes"]).startswith("fail") and "quote" in a.checks["model_quotes"]


def test_real_capture_is_not_valid_long_after_its_tokens_expired():
    a = near.appraise(evidence(), as_of=RAW["captured_at_unix"] + 86400)
    assert not a.ok and "not valid at the capture time" in a.checks["ita_gateway_token"]

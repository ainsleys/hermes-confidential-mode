"""Spike: can a tinfoil 0.14.2 verification be replayed OFFLINE from stored inputs?

Spike only (no feature code). Every test runs with the network blocked at the socket layer and HOME
pointed at a temp dir (the SDK and sigstore-python cache under platformdirs paths derived from HOME).
No real Tinfoil, GitHub, AMD, Intel or Sigstore endpoint is contacted. Fixtures are synthetic and made
by stubs: hardware-signed reports cannot be fabricated, so where a verifier needs a genuine vendor
signature the test proves only that it RUNS on stored bytes without network (and reaches its
cryptographic verdict), not that a real report would pass.

(a) Inputs SecureClient.verify() fetches on the default path (client.py:836-945) and where each is
    observable as bytes during a live verify:
      1 attestation document   GET https://<enclave>/.well-known/tinfoil-attestation -> {format, body}
                               hook: tinfoil.client.fetch_attestation -> Document(format, body)
      2 release metadata       GET github-proxy.tinfoil.sh/repos/<repo>/releases/latest (+ tinfoil.hash)
                               hook: tinfoil.client.fetch_latest_release -> Release(tag, digest)
      3 code Sigstore bundle   GET github-proxy.tinfoil.sh/repos/<repo>/attestations/sha256:<digest>
                               hook: tinfoil.client.fetch_attestation_bundle -> bytes
      4 Sigstore trust root    TUF refresh of tuf-repo-cdn.sigstore.dev inside Verifier.production()
                               (tinfoil/sigstore.py:179); file: ClientTrustConfig trusted_root path
      5 SEV only: VCEK DER     GET kds-proxy.tinfoil.sh/vcek/v1/Genoa/<chip_id>?<tcb> (verify_sev.py:123)
                               hook: verify_sev.CertificateChain.from_report -> chain.vcek; ARK/ASK are
                               compiled into the SDK (genoa_cert_chain.py), so not fetched
      6 TDX only: collateral   TCB info, QE identity (+ issuer chains), PCK CRL, Intel root CA CRL via
                               tdx-proxy.tinfoil.sh (collateral_tdx.py:1183 fetch_collateral) -> TdxCollateral
                               (raw JSON kept in tcb_info_raw / qe_identity_raw); PCK chain is in the quote
      7 TDX only: hardware     github-proxy release digest + Sigstore bundle of tinfoilsh/hardware-measurements
         measurements          (sigstore.py:290 fetch_latest_hardware_measurements; hooks
                               tinfoil.sigstore.fetch_latest_digest / fetch_attestation_bundle)
    The enclave TLS certificate is NOT fetched on the default ehbp path (only verify_from_bundle binds it).

(b) proven below: which verifier functions take stored bytes offline, and which need patching.
(c) see the final test and the report.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

tinfoil_client = pytest.importorskip("tinfoil.client")
from tinfoil.attestation import bundle as tf_bundle  # noqa: E402
from tinfoil.attestation import collateral_tdx, verify_sev  # noqa: E402
from tinfoil.attestation.abi_sev import ReportSigner  # noqa: E402
from tinfoil.attestation.types import Measurement, PredicateType, Verification  # noqa: E402
import tinfoil.sigstore as tf_sigstore  # noqa: E402

ENCLAVE = "router.tinfoil.invalid"
REPO = "tinfoilsh/confidential-model-router"
DIGEST = "ab" * 32
SNP = "11" * 48
RTMR1, RTMR2 = "22" * 48, "33" * 48


@pytest.fixture
def offline(tmp_path, monkeypatch):
    """Block every socket and every requests/urllib call; record attempts."""
    attempts = []

    def blocked(*a, **k):
        attempts.append(repr(a[:1])[:120])
        raise OSError("NETWORK BLOCKED (replay spike)")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", lambda self, *a, **k: blocked(*a))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # The SDK computes its platformdirs cache paths at import time, so HOME alone does not redirect them.
    import tinfoil.github as tf_github
    cache = str(tmp_path / "tinfoil-cache")
    monkeypatch.setattr(tf_github, "_GITHUB_CACHE_DIR", cache)
    monkeypatch.setattr(verify_sev, "_VCEK_CACHE_DIR", cache)
    monkeypatch.setattr(collateral_tdx, "_TDX_CACHE_DIR", cache)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return attempts


# ── (a) capture: hook points see every default-path input as bytes ────────────────────────────


def test_a_capture_hooks_record_every_default_path_input(offline, monkeypatch):
    """A live verify with only the network leaf (requests.get) faked and the two vendor-crypto steps
    stubbed: recording wrappers around the SDK's own fetchers capture each input exactly once."""
    import requests

    body = base64.b64encode(gzip.compress(b"\x02" * 1184)).decode()  # SEV report size, synthetic bytes
    sigstore_bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "synthetic": True}
    served = {
        f"https://{ENCLAVE}/.well-known/tinfoil-attestation":
            {"format": PredicateType.SEV_GUEST_V2.value, "body": body},
        f"https://github-proxy.tinfoil.sh/repos/{REPO}/releases/latest":
            {"tag_name": "v9.9.9", "body": f"Digest: `{DIGEST}`"},
        f"https://github-proxy.tinfoil.sh/repos/{REPO}/attestations/sha256:{DIGEST}":
            {"attestations": [{"bundle": sigstore_bundle}]},
    }
    urls = []

    class Resp:
        def __init__(self, data):
            self.content = json.dumps(data).encode()
            self.status_code, self.reason, self.text = 200, "OK", self.content.decode()

        def json(self):
            return json.loads(self.content)

        def raise_for_status(self):
            pass

    def fake_get(url, *a, **k):
        urls.append(url)
        return Resp(served[url])
    monkeypatch.setattr(requests, "get", fake_get)

    # Vendor crypto cannot run on synthetic bytes: stub exactly the two verdict functions.
    enclave_v = Verification(measurement=Measurement(PredicateType.SEV_GUEST_V2, [SNP]),
                             public_key_fp="cd" * 32, hpke_public_key="ef" * 32)
    from tinfoil.attestation import Document
    monkeypatch.setattr(Document, "verify", lambda self, vcek_der=None: enclave_v)
    monkeypatch.setattr(tinfoil_client, "verify_attestation",
                        lambda b, d, r, t: Measurement(PredicateType.SNP_TDX_MULTIPLATFORM_v1, [SNP, RTMR1, RTMR2]))

    captured = {}

    def record(name, fn):
        def wrapper(*a, **k):
            out = fn(*a, **k)
            captured[name] = out
            return out
        return wrapper
    for name in ("fetch_attestation", "fetch_latest_release", "fetch_attestation_bundle"):
        monkeypatch.setattr(tinfoil_client, name, record(name, getattr(tinfoil_client, name)))

    sc = tinfoil_client.SecureClient(enclave=ENCLAVE, repo=REPO, user_cache_secret="s")
    gt = sc.verify()
    doc = sc.get_verification_document()

    assert urls == list(served)  # exactly these three fetches, in this order, for SEV
    assert captured["fetch_attestation"].body == body
    assert captured["fetch_latest_release"].tag == "v9.9.9" and captured["fetch_latest_release"].digest == DIGEST
    assert json.loads(captured["fetch_attestation_bundle"]) == sigstore_bundle
    assert doc.security_verified and doc.release_tag == "v9.9.9" and gt.hpke_public_key == "ef" * 32
    # The real assert_equal / fingerprint ran on the captured measurements.
    assert doc.enclave_fingerprint == SNP
    assert doc.code_fingerprint == Measurement(PredicateType.SNP_TDX_MULTIPLATFORM_v1, [SNP, RTMR1, RTMR2]).fingerprint()
    assert offline == []
    print("CAPTURED_SIZES", {"attestation_body_b64": len(body),
                             "sigstore_bundle": len(captured["fetch_attestation_bundle"])})


# ── (b) which verifiers replay on stored bytes ────────────────────────────────────────────────


def test_b1_measurement_match_and_fingerprints_replay_offline(offline):
    """Pure functions: code measurement (from the Sigstore predicate) vs enclave measurement (from the
    report). Fully reproducible from stored registers; tampering is detected."""
    code = Measurement(PredicateType.SNP_TDX_MULTIPLATFORM_v1, [SNP, RTMR1, RTMR2])
    sev = Measurement(PredicateType.SEV_GUEST_V2, [SNP])
    tdx = Measurement(PredicateType.TDX_GUEST_V2, ["aa" * 48, "bb" * 48, RTMR1, RTMR2, "0" * 96])
    code.assert_equal(sev)
    code.assert_equal(tdx)
    assert sev.fingerprint() == SNP and sev.fingerprint() != tdx.fingerprint()  # the SNP/TDX flapping risk
    with pytest.raises(Exception):
        code.assert_equal(Measurement(PredicateType.SEV_GUEST_V2, ["99" * 48]))
    assert offline == []


def _dcode_sans(data: bytes, prefix: str, domain: str) -> list[str]:
    enc = base64.b32encode(data).decode().rstrip("=").lower()
    chunks = [enc[i:i + 50] for i in range(0, len(enc), 50)]
    return [f"{i:02d}{c}.{prefix}.{domain}" for i, c in enumerate(chunks)]


def _enclave_cert(domain: str, hpke_hex: str, att_hash: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    sans = [domain] + _dcode_sans(bytes.fromhex(hpke_hex), "hpke", domain) + _dcode_sans(
        att_hash.encode(), "hatt", domain)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_b2_key_binding_replays_offline_when_the_tls_cert_was_captured(offline):
    """verify_certificate (bundle.py:90) binds a captured TLS cert to the report (attestation hash) and
    the attested HPKE key. Pure, offline. NB: the default ehbp path never fetches this cert, so the
    plugin would have to capture it itself; the report_data binding (TLS fp + HPKE key) needs nothing."""
    from tinfoil.attestation import Document
    doc = Document(PredicateType.SEV_GUEST_V2, base64.b64encode(gzip.compress(b"r" * 1184)).decode())
    hpke = "ef" * 32
    pem = _enclave_cert(ENCLAVE, hpke, doc.hash())
    assert tf_bundle.verify_certificate(pem, ENCLAVE, doc, hpke) == hpke
    with pytest.raises(ValueError, match="HPKE key mismatch"):
        tf_bundle.verify_certificate(pem, ENCLAVE, doc, "00" * 32)
    other = Document(doc.format, base64.b64encode(gzip.compress(b"x" * 1184)).decode())
    with pytest.raises(ValueError, match="attestation hash mismatch"):
        tf_bundle.verify_certificate(pem, ENCLAVE, other, hpke)
    assert offline == []


def test_b3_sev_vcek_from_stored_bytes_needs_no_fetch_but_unstored_does(offline):
    """SEV: Document.verify(vcek_der=...) / CertificateChain.from_report(vcek_der=...) take the VCEK
    out-of-band (verify_sev.py:106) and still check it against the compiled-in AMD ARK/ASK. Without it,
    the SDK fetches from kds-proxy (blocked here)."""
    import inspect
    from cryptography.hazmat.primitives import serialization
    from tinfoil.attestation import Document
    assert "vcek_der" in inspect.signature(Document.verify).parameters

    pem = _enclave_cert("vcek.invalid", "ef" * 32, "h")  # a stand-in DER cert, not AMD-issued
    from cryptography import x509
    vcek_der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    report = SimpleNamespace(productName="Genoa", chip_id=b"\x01" * 64, reported_tcb=0,
                             signer_info_parsed=SimpleNamespace(signingKey=ReportSigner.VcekReportSigner))
    chain = verify_sev.CertificateChain.from_report(report, vcek_der=vcek_der)
    assert chain.vcek.public_bytes(serialization.Encoding.DER) == vcek_der
    assert chain.verify_chain() is False  # real AMD chain check ran offline and rejected the stand-in
    assert offline == []

    with pytest.raises(ValueError, match="Failed to fetch VCEK"):
        verify_sev.CertificateChain.from_report(report)  # no stored VCEK -> network -> blocked
    assert offline, "the unstored path tried the network"


def test_b4_sigstore_needs_a_patched_verifier_but_then_runs_offline(offline, monkeypatch, tmp_path):
    """tinfoil.sigstore._verify_dsse_bundle hard-codes Verifier.production() (online TUF refresh). As
    shipped it cannot run offline; patching Verifier to one built from a STORED trusted_root.json makes
    the full DSSE/policy/Rekor-inclusion check run with zero network (Rekor proofs are in the bundle;
    certificate validity is judged at the bundle's integrated time, not now)."""
    from sigstore.models import TrustedRoot
    from sigstore.verify import Verifier
    import sigstore as _sg

    junk = json.dumps({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}).encode()
    with pytest.raises(ValueError) as unpatched:
        tf_sigstore.verify_attestation(junk, DIGEST, REPO, "v1")
    assert "TUF" in repr(unpatched.value.__cause__) or "TUF" in str(unpatched.value)
    assert offline, "as shipped, sigstore verification tried to refresh TUF over the network"
    offline.clear()

    # The trust root a live verify used would be persisted (content-addressed); here, sigstore's embedded copy.
    stored_root = (Path(_sg.__file__).parent / "_store" / "https%3A%2F%2Ftuf-repo-cdn.sigstore.dev"
                   / "trusted_root.json").read_bytes()
    root_path = tmp_path / "trusted_root.json"
    root_path.write_bytes(stored_root)

    class StoredRootVerifier(Verifier):
        @classmethod
        def production(cls, *, offline=False):
            return cls(trusted_root=TrustedRoot.from_file(str(root_path)))
    monkeypatch.setattr(tf_sigstore, "Verifier", StoredRootVerifier)
    with pytest.raises(ValueError) as patched:
        tf_sigstore.verify_attestation(junk, DIGEST, REPO, "v1")
    assert "TUF" not in str(patched.value) and "NETWORK BLOCKED" not in str(patched.value)
    assert "Attestation processing failed" in str(patched.value)
    print("PATCHED_SIGSTORE_VERDICT", repr(patched.value)[:200])
    assert offline == []  # reached bundle validation (and rejected the junk) with no network
    print("TRUSTED_ROOT_BYTES", len(stored_root), hashlib.sha256(stored_root).hexdigest())


def test_b5_tdx_collateral_needs_patched_fetchers_and_a_clock(offline, monkeypatch):
    """TDX: verify_tdx_attestation_v2 takes no collateral argument; validate_collateral always calls
    fetch_collateral (Intel PCS via tdx-proxy; a cache under platformdirs may short-circuit while fresh).
    Replay therefore needs collateral_tdx.fetch_collateral patched to stored bytes AND the freshness
    checks (datetime.now in check_collateral_freshness / validate_certificate_revocation / cert_utils)
    evaluated at capture time, because TCB info / QE identity / CRLs expire (next_update)."""
    pck = SimpleNamespace(fmspc="00906ED50000")
    with pytest.raises(collateral_tdx.CollateralError):
        collateral_tdx.fetch_tcb_info(pck.fmspc, 1.0)  # unstored -> network -> blocked
    assert offline

    captured_at = datetime(2026, 11, 6, tzinfo=timezone.utc)
    stored = SimpleNamespace(
        tcb_info=SimpleNamespace(tcb_info=SimpleNamespace(next_update=captured_at + timedelta(days=30),
                                                          tcb_evaluation_data_number=19)),
        qe_identity=SimpleNamespace(enclave_identity=SimpleNamespace(next_update=captured_at + timedelta(days=30),
                                                                     tcb_evaluation_data_number=19)))
    collateral_tdx.check_collateral_freshness(stored, 19)  # fresh "now" (inside the window)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return captured_at + timedelta(days=90)
    monkeypatch.setattr(collateral_tdx, "datetime", Later)
    with pytest.raises(collateral_tdx.CollateralError, match="expired"):
        collateral_tdx.check_collateral_freshness(stored, 19)  # a replay 90 days later fails on the clock

    class AtCapture(datetime):
        @classmethod
        def now(cls, tz=None):
            return captured_at
    monkeypatch.setattr(collateral_tdx, "datetime", AtCapture)
    collateral_tdx.check_collateral_freshness(stored, 19)  # "as of capture" replay passes


def test_c_what_a_replay_cannot_establish():
    """Nothing in the stored inputs references the requests we sent. The report commits to keys
    (report_data = TLS key fp || HPKE pubkey), not to any request; Sigstore binds a release digest, not
    "latest at the time" (release metadata from github-proxy is unsigned; only the digest is checked
    through the signed predicate). So a replay can never show that a request reached that enclave."""
    fields = set(tinfoil_client.VerificationDocument().to_dict())
    assert not any(k in fields for k in ("requestHash", "requestId", "nonce", "transcript"))
    import inspect
    src = inspect.getsource(tinfoil_client.SecureClient.verify)
    assert "nonce" not in src  # no client challenge: the report is not fresh per verify either

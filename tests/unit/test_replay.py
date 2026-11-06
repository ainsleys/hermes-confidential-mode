"""Evidence capture (verify/tinfoil.py) and offline replay (verify/replay.py), network blocked throughout.

SEV runs the SDK's REAL parsing, AMD-chain, signature and policy code end to end. Only the trust
anchor is substituted: verify_sev.ARK_CERT / ASK_CERT are swapped for a test ARK/ASK generated here
(same subject names, RSA-PSS 4096), and the VCEK and report are signed with it. Sigstore's DSSE/Rekor
verification cannot be fabricated, so tinfoil.sigstore._verify_dsse_bundle is replaced by a fake that
accepts only bundles HMAC-signed by this test (and, like the real one, calls Verifier.production(),
which exercises the trust-root capture and the stored-root override). TDX quote parsing and Intel
signatures cannot be fabricated either: the TDX tests stub those and run the SDK's REAL collateral
freshness check under the pinned clock.
"""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import hmac
import json
import socket
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

tinfoil_client = pytest.importorskip("tinfoil.client")

import httpx  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import tinfoil.github as tf_github  # noqa: E402
import tinfoil.sigstore as tf_sigstore  # noqa: E402
from tinfoil.attestation import attestation_tdx, collateral_tdx, verify_sev  # noqa: E402
from tinfoil.attestation.types import Measurement, PredicateType  # noqa: E402

from confidential_mode.verify import _sdkpatch, replay as replay_mod  # noqa: E402
from confidential_mode.verify.replay import CHECK_KEYS, NOT_ESTABLISHED, replay  # noqa: E402
from confidential_mode.verify.tinfoil import TinfoilAdapter  # noqa: E402

ENCLAVE = "router.tinfoil.invalid"
REPO = "tinfoilsh/confidential-model-router"
TAG = "v1.2.3"
DIGEST = "ab" * 32
CAPTURED_AT = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
FIXTURE_KEY = b"test-only sigstore stand-in"
SNP = bytes(range(48))
RTMR1, RTMR2 = "22" * 48, "33" * 48
TCB = (0x48 << 56) | (0x0E << 48) | (0 << 8) | 7   # meets the SDK's minimum TCB


# ── network ban + cache isolation ─────────────────────────────────────────────────────────────

@pytest.fixture
def offline(tmp_path, monkeypatch):
    attempts = []

    def blocked(*a, **k):
        attempts.append(repr(a[:1])[:120])
        raise OSError("NETWORK BLOCKED (test)")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", lambda self, *a, **k: blocked(*a))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # Register restores for the process-wide constants redirect_sdk_caches() rewrites.
    import sigstore._internal.tuf as sg_tuf
    for mod, name in ((tf_github, "_GITHUB_CACHE_DIR"), (verify_sev, "_VCEK_CACHE_DIR"),
                      (collateral_tdx, "_TDX_CACHE_DIR"), (sg_tuf, "_get_dirs")):
        monkeypatch.setattr(mod, name, getattr(mod, name))
    _sdkpatch.redirect_sdk_caches(tmp_path / "isolated")
    return attempts


# ── test AMD trust anchor, VCEK and SEV report ────────────────────────────────────────────────

def _amd_name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                      x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


def _der_int(n: int) -> bytes:
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return bytes([0x02, len(body)]) + body


def _cert(subject, issuer, pub, signer, *, ca, extensions=()):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(CAPTURED_AT - timedelta(days=30)).not_valid_after(CAPTURED_AT + timedelta(days=3650)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                          content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True)
    for ext in extensions:
        b = b.add_extension(ext, critical=False)
    return b.sign(signer, hashes.SHA384(), rsa_padding=_PSS)


@pytest.fixture(scope="module")
def amd():
    ark_key = rsa.generate_private_key(65537, 4096)
    ask_key = rsa.generate_private_key(65537, 4096)
    ark = _cert(_amd_name("ARK-Genoa"), _amd_name("ARK-Genoa"), ark_key.public_key(), ark_key, ca=True)
    ask = _cert(_amd_name("SEV-Genoa"), _amd_name("ARK-Genoa"), ask_key.public_key(), ark_key, ca=True)
    chip_id = bytes(range(64))

    def vcek_for(key, chip=chip_id, signer=ask_key):
        oid = verify_sev.SnpOid
        exts = [x509.UnrecognizedExtension(oid.PRODUCT_NAME_1, b"\x16\x05Genoa"),
                x509.UnrecognizedExtension(oid.BL_SPL, _der_int(7)),
                x509.UnrecognizedExtension(oid.TEE_SPL, _der_int(0)),
                x509.UnrecognizedExtension(oid.SNP_SPL, _der_int(0x0E)),
                x509.UnrecognizedExtension(oid.UCODE, _der_int(0x48)),
                x509.UnrecognizedExtension(oid.HWID, chip)]
        return _cert(_amd_name("SEV-VCEK"), _amd_name("SEV-Genoa"), key.public_key(), signer, ca=False,
                     extensions=exts)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    return SimpleNamespace(ark=ark, ask=ask, ark_key=ark_key, ask_key=ask_key, chip_id=chip_id,
                           vcek_key=vcek_key, vcek=vcek_for(vcek_key), vcek_for=vcek_for)


@pytest.fixture
def amd_anchor(amd, monkeypatch):
    monkeypatch.setattr(verify_sev, "ARK_CERT", amd.ark.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setattr(verify_sev, "ASK_CERT", amd.ask.public_bytes(serialization.Encoding.PEM))
    # The independent checker pins the REAL AMD ARK by hash; for synthetic reports substitute the test
    # anchor there too, and the SDK's lower TCB floor (the synthetic report uses it).
    from confidential_mode.verify import sev_check
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    monkeypatch.setattr(sev_check, "ARK_PEM", amd.ark.public_bytes(serialization.Encoding.PEM).decode())
    monkeypatch.setattr(sev_check, "ASK_PEM", amd.ask.public_bytes(serialization.Encoding.PEM).decode())
    monkeypatch.setattr(sev_check, "ARK_SHA256", hashlib.sha256(der(amd.ark)).hexdigest())
    monkeypatch.setattr(sev_check, "ASK_SHA256", hashlib.sha256(der(amd.ask)).hexdigest())
    monkeypatch.setattr(sev_check, "MIN_TCB", {"bl": 7, "tee": 0, "snp": 0x0E, "ucode": 0x48})
    return amd


def _keys():
    tls_fp = hashlib.sha256(b"tls").digest()
    hpke = x25519.X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,
                                                                        serialization.PublicFormat.Raw)
    return tls_fp, hpke


def sev_report(amd, *, tls_fp, hpke, measurement=SNP, build=21, sign_key=None, tamper_after_sign=None):
    r = bytearray(0x4A0)

    def put(off, val, n):
        r[off:off + n] = val.to_bytes(n, "little")
    put(0x00, 2, 4)                              # version 2 => Genoa
    put(0x08, (1 << 17) | (1 << 16), 8)          # policy: reserved bit + SMT
    put(0x34, 1, 4)                              # ECDSA P-384 SHA-384
    put(0x38, TCB, 8)                            # current_tcb
    put(0x40, 0b11, 8)                           # platform_info: SMT + TSME
    r[0x50:0x70], r[0x70:0x90] = tls_fp, hpke    # report_data
    r[0x90:0xC0] = measurement
    put(0x180, TCB, 8)                           # reported_tcb
    r[0x1A0:0x1E0] = amd.chip_id
    put(0x1E0, TCB, 8)                           # committed_tcb
    r[0x1E8], r[0x1E9], r[0x1EA] = build, 55, 1  # current build / minor / major
    r[0x1EC], r[0x1ED], r[0x1EE] = build, 55, 1  # committed
    put(0x1F0, TCB, 8)                           # launch_tcb
    sig = (sign_key or amd.vcek_key).sign(bytes(r[:0x2A0]), ec.ECDSA(hashes.SHA384()))
    rr, ss = decode_dss_signature(sig)
    r[0x2A0:0x2E8] = rr.to_bytes(72, "little")
    r[0x2E8:0x330] = ss.to_bytes(72, "little")
    if tamper_after_sign:
        tamper_after_sign(r)
    return base64.b64encode(gzip.compress(bytes(r))).decode()


# ── Sigstore stand-in ─────────────────────────────────────────────────────────────────────────

REPO_ID, OWNER_ID = "800001", "700001"
COMMIT = "1f" * 20


def _der_utf8(text: str) -> bytes:
    b = text.encode()
    assert len(b) < 128
    return bytes([0x0C, len(b)]) + b


def fulcio_cert_der(repo: str, tag: str | None, *, repo_id=REPO_ID, owner_id=OWNER_ID) -> bytes:
    """A stand-in Fulcio leaf carrying the GitHub Actions identity extensions (DER UTF8String values)."""
    from cryptography.x509 import ObjectIdentifier as O
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-intermediate")])
    ref = f"refs/tags/{tag or 'v0'}"
    raw_v1 = {"1.3.6.1.4.1.57264.1.5": repo, "1.3.6.1.4.1.57264.1.6": ref}  # v1 extensions: raw bytes
    exts = {"1.3.6.1.4.1.57264.1.8": "https://token.actions.githubusercontent.com",
            "1.3.6.1.4.1.57264.1.9": f"https://github.com/{repo}/.github/workflows/release.yml@{ref}",
            "1.3.6.1.4.1.57264.1.12": f"https://github.com/{repo}",
            "1.3.6.1.4.1.57264.1.13": COMMIT,
            "1.3.6.1.4.1.57264.1.14": ref}
    if repo_id is not None:
        exts["1.3.6.1.4.1.57264.1.15"] = str(repo_id)
    if owner_id is not None:
        exts["1.3.6.1.4.1.57264.1.17"] = str(owner_id)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(1).not_valid_before(CAPTURED_AT - timedelta(days=1))
         .not_valid_after(CAPTURED_AT + timedelta(minutes=10)))
    for oid, val in exts.items():
        b = b.add_extension(x509.UnrecognizedExtension(O(oid), _der_utf8(val)), critical=False)
    for oid, val in raw_v1.items():
        b = b.add_extension(x509.UnrecognizedExtension(O(oid), val.encode()), critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def signed_bundle(statement: dict, *, repo: str, tag: str | None, cert_repo: str | None = None,
                  repo_id=REPO_ID, owner_id=OWNER_ID) -> dict:
    payload = json.dumps({"statement": statement, "repo": repo, "tag": tag}).encode()
    cert = fulcio_cert_der(cert_repo or repo, tag, repo_id=repo_id, owner_id=owner_id)
    return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(cert).decode()},
                                     "tlogEntries": [{"logIndex": "123456789", "integratedTime": "1762400000"}]},
            "testEnvelope": {"payload": base64.b64encode(payload).decode(),
                             "mac": hmac.new(FIXTURE_KEY, payload, "sha256").hexdigest()}}


def code_statement(digest=DIGEST, snp=SNP.hex()):
    return {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "x", "digest": {"sha256": digest}}],
            "predicateType": PredicateType.SNP_TDX_MULTIPLATFORM_v1.value,
            "predicate": {"snp_measurement": snp, "tdx_measurement": {"rtmr1": RTMR1, "rtmr2": RTMR2}}}


@pytest.fixture
def fake_sigstore(monkeypatch):
    from sigstore.errors import VerificationError
    from sigstore.verify import Verifier
    used = []

    def fake(bundle_json, digest, repo, expected_release_tag=None):
        used.append(type(Verifier.production(offline=True)).__name__)  # real entry point, as the SDK does
        env = json.loads(bundle_json)["testEnvelope"]
        payload = base64.b64decode(env["payload"])
        if not hmac.compare_digest(env["mac"], hmac.new(FIXTURE_KEY, payload, "sha256").hexdigest()):
            raise VerificationError("bundle signature invalid")
        signed = json.loads(payload)
        if signed["repo"] != repo or (expected_release_tag is not None and signed["tag"] != expected_release_tag):
            raise VerificationError("certificate identity policy failed")
        st = signed["statement"]
        if st["subject"][0]["digest"]["sha256"] != digest:
            raise ValueError(f"Digest mismatch: expected {digest}")
        return st
    monkeypatch.setattr(tf_sigstore, "_verify_dsse_bundle", fake)

    # The standalone policy checker's sigstore-python calls get the same stand-in; its own policy
    # object still runs against the bundle's (stand-in) Fulcio certificate.
    from confidential_mode.verify import policy_check as pc

    class _FakeBundle:
        def __init__(self, raw):
            self.raw = json.loads(raw)
            der = pc.bundle_certificate_der(self.raw)
            if der is None:
                raise VerificationError("bundle has no certificate")
            self.signing_certificate = x509.load_der_x509_certificate(der)

    class _FakeVerifier:
        def __init__(self, root):
            from sigstore.models import TrustedRoot
            from sigstore_models.trustroot.v1 import TrustedRoot as _Inner
            TrustedRoot(_Inner.from_json(root))  # the stored root must at least parse
            used.append("policy_check")

        def verify_dsse(self, bundle, policy):
            policy.verify(bundle.signing_certificate)
            env = bundle.raw["testEnvelope"]
            payload = base64.b64decode(env["payload"])
            if not hmac.compare_digest(env["mac"], hmac.new(FIXTURE_KEY, payload, "sha256").hexdigest()):
                raise VerificationError("bundle signature invalid")
            return "application/vnd.in-toto+json", json.dumps(json.loads(payload)["statement"]).encode()
    monkeypatch.setattr(pc, "_load_bundle", _FakeBundle)
    monkeypatch.setattr(pc, "_make_verifier", _FakeVerifier)
    return used


# ── a live (stubbed-network) SEV capture through the real adapter ─────────────────────────────

class _Resp:
    def __init__(self, body: bytes, status=200):
        self.content, self.status_code, self.reason = body, status, "OK"
        self.text = body.decode("latin-1")

    def json(self):
        return json.loads(self.content)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError("status")


class _FakeSSL:
    def __init__(self, der):
        self.der = der

    def getpeercert(self, binary_form=False):
        return self.der


class _FakeStream:
    def __init__(self, der):
        self.ssl = _FakeSSL(der)

    def get_extra_info(self, name):
        return self.ssl if name == "ssl_object" else None


def _tls_server_cert(key, host, hpke: bytes, attestation_hash: str) -> bytes:
    """What a Tinfoil router presents if TLS terminates in the enclave: SANs carry the HPKE key and the
    attestation document hash (dcode-encoded, as tinfoil.attestation.bundle._decode_domains reads)."""
    def dcode(data, prefix):
        enc = base64.b32encode(data).decode().rstrip("=").lower()
        return [f"{i:02d}{enc[j:j + 50]}.{prefix}.{host}" for i, j in enumerate(range(0, len(enc), 50))]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    sans = [host] + dcode(hpke, "hpke") + dcode(attestation_hash.encode(), "hatt")
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(CAPTURED_AT - timedelta(days=1))
            .not_valid_after(CAPTURED_AT + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def _capture(amd_anchor, tmp_path, monkeypatch, *, tls: str | None = None):
    """Run TinfoilAdapter.verify() for real against a faked network leaf. tls: None (the stub transport
    shows no certificate), "enclave" (peer cert key == report TLS key, SANs bind H and the report) or
    "proxy" (a different key terminates TLS)."""
    import requests
    from tinfoil.attestation import Document
    tls_key = ec.generate_private_key(ec.SECP256R1())
    spki = tls_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _, hpke = _keys()
    tls_fp = hashlib.sha256(spki).digest()
    body = sev_report(amd_anchor, tls_fp=tls_fp, hpke=hpke)
    if tls is not None:
        att_hash = Document(PredicateType.SEV_GUEST_V2, body).hash()
        key = tls_key if tls == "enclave" else ec.generate_private_key(ec.SECP256R1())
        der = _tls_server_cert(key, ENCLAVE, hpke, att_hash)

        def fake_inner(self, request):  # the HTTPTransport under ehbp: a stubbed TLS server
            return httpx.Response(200, json={"format": "x", "body": "y"},
                                  extensions={"network_stream": _FakeStream(der)})
        monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake_inner)
    bundle = signed_bundle(code_statement(), repo=REPO, tag=TAG)
    vcek_der = amd_anchor.vcek.public_bytes(serialization.Encoding.DER)
    urls = []

    def fake_request(self, method, url, *a, **k):  # the network leaf under requests.get
        urls.append(url.split("?")[0])
        if url == f"https://{ENCLAVE}/.well-known/tinfoil-attestation":
            return _Resp(json.dumps({"format": PredicateType.SEV_GUEST_V2.value, "body": body}).encode())
        if url == f"https://github-proxy.tinfoil.sh/repos/{REPO}/releases/latest":
            return _Resp(json.dumps({"tag_name": TAG, "body": f"Digest: `{DIGEST}`",
                                     "published_at": "2026-11-01T09:30:00Z",
                                     "html_url": f"https://github.com/{REPO}/releases/tag/{TAG}"}).encode())
        if url == f"https://github-proxy.tinfoil.sh/repos/{REPO}/attestations/sha256:{DIGEST}":
            return _Resp(json.dumps({"attestations": [{"bundle": bundle}]}).encode())
        if url.startswith("https://kds-proxy.tinfoil.sh/vcek/v1/Genoa/"):
            return _Resp(vcek_der)
        raise AssertionError(f"unexpected fetch {url}")
    monkeypatch.setattr(requests.Session, "request", fake_request)
    ad = TinfoilAdapter(data_dir=tmp_path / "plugin-data", enclave=ENCLAVE, hold_until_accepted=False,
                        tls_probe=tls is not None)
    res = ad.verify()
    return SimpleNamespace(adapter=ad, result=res, evidence=res.evidence, urls=urls, tls_fp=tls_fp, hpke=hpke,
                           data_dir=tmp_path / "plugin-data", vcek_der=vcek_der)


@pytest.fixture
def captured(offline, amd_anchor, fake_sigstore, tmp_path, monkeypatch):
    return _capture(amd_anchor, tmp_path, monkeypatch)


def test_capture_records_every_input_under_the_v1_schema(captured, offline):
    ev, res = captured.evidence, captured.result
    assert ev["schema"] == "confidential-mode/tinfoil-evidence/v1" and ev["capture_complete"] is True, ev.get(
        "capture_missing")
    assert ev["platform"] == "sev-snp" and ev["sdk_version"] == "0.14.2"
    assert ev["repo"] == REPO and ev["enclave_host"] == ENCLAVE and ev["enclave_source"] == "config"
    assert ev["release"] == {"tag": TAG, "digest": DIGEST, "published_at": "2026-11-01T09:30:00Z",
                             "html_url": f"https://github.com/{REPO}/releases/tag/{TAG}"}
    assert ev["attestation"]["format"] == PredicateType.SEV_GUEST_V2.value
    assert base64.b64decode(ev["sev"]["vcek_der_b64"]) == captured.vcek_der
    assert ev["claims"]["code_fingerprint"] == res.code_fingerprint
    assert ev["claims"]["hpke_public_key"] == captured.hpke.hex()
    tr = Path(ev["trusted_root"]["path"])
    assert tr.parent == captured.data_dir / "trust-roots"
    assert hashlib.sha256(tr.read_bytes()).hexdigest() == ev["trusted_root"]["sha256"]
    assert ev["tdx"] is None and ev["hardware_measurements"] is None and ev["tls_cert_pem"] is None
    json.dumps(ev)
    assert offline == []  # no socket was touched; every fetch went through the faked requests.get
    assert captured.urls == [f"https://{ENCLAVE}/.well-known/tinfoil-attestation",
                             f"https://kds-proxy.tinfoil.sh/vcek/v1/Genoa/{bytes(range(64)).hex()}",
                             f"https://github-proxy.tinfoil.sh/repos/{REPO}/releases/latest",
                             f"https://github-proxy.tinfoil.sh/repos/{REPO}/attestations/sha256:{DIGEST}"]
    sizes = {"attestation.body": len(ev["attestation"]["body"]), "sev.vcek_der_b64": len(ev["sev"]["vcek_der_b64"]),
             "sigstore_bundle": len(ev["sigstore_bundle"]), "trusted_root(file)": tr.stat().st_size,
             "evidence_json_total": len(json.dumps(ev))}
    print("EVIDENCE_SIZES", sizes, "FETCH_ORDER", captured.urls)


def test_capture_is_stable_across_trust_root_dedup(captured):
    again = captured.adapter.verify().evidence
    assert again["trusted_root"] == captured.evidence["trusted_root"]
    assert len(list((captured.data_dir / "trust-roots").iterdir())) == 1  # stored once


def test_evidence_fits_the_ledger(captured, tmp_path):
    from confidential_mode.ledger import Ledger
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "verify_ok", "provider": "attested-tinfoil", "detail": captured.evidence})
    (row,) = led.tail()
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail["claims"] == captured.evidence["claims"]


def test_sdk_caches_are_redirected_under_the_plugin_data_dir(captured, tmp_path):
    cache = captured.data_dir / "sdk-cache"
    assert tf_github._GITHUB_CACHE_DIR == str(cache / "tinfoil")
    assert verify_sev._VCEK_CACHE_DIR == str(cache / "tinfoil")
    written = sorted(p.name for p in (cache / "tinfoil").iterdir())
    assert any(n.startswith("bundle_") for n in written) and any(n.startswith("vcek") or "Genoa" in n
                                                                for n in written), written
    assert (cache / "sigstore-tuf-targets").exists()
    home = tmp_path / "home"
    assert not (home / "Library" / "Caches" / "tinfoil").exists() and not (home / ".cache" / "tinfoil").exists()
    assert captured.adapter.sdk_cache_paths["tinfoil"] == str(cache / "tinfoil")


# ── replay: SEV passes on synthetic bytes, tampering fails the right check ────────────────────

def _expect(result, failed: str, also: tuple = ()):
    assert result.ok is False
    assert isinstance(result.checks[failed], str) and result.checks[failed].startswith("fail:"), result.checks
    for key, value in result.checks.items():
        if key != failed and key not in also:
            assert not (isinstance(value, str) and value.startswith("fail:")), (key, value)


def test_sev_replay_passes_offline(captured, offline, fake_sigstore):
    fake_sigstore.clear()
    r = replay(captured.evidence)
    assert r.ok is True, r.checks
    assert r.checks == {"repo_match": True, "repo_identity": "name only (ids not supplied)",
                        "trust_root_source": "from_evidence", "hardware_signature": True, "cert_chain": True, "tcb_policy": True,
                        "collateral_fresh_at_capture": "n/a: SEV-SNP has no Intel collateral",
                        "code_signature": True, "policy_check": True, "sev_check": True,
                        "measurement_match": True,
                        "hardware_platform_match": "n/a: SEV-SNP", "report_data_keys": True,
                        "tls_cert_binding": "n/a: TLS certificate not captured"}
    assert set(r.checks) == set(CHECK_KEYS)
    assert r.code_fingerprint == captured.result.code_fingerprint
    assert r.enclave_fingerprint == captured.result.enclave_fingerprint == SNP.hex()
    assert r.hpke_public_key == captured.hpke.hex() and r.tls_key_fp == captured.tls_fp.hex()
    assert r.release_tag == TAG and r.sdk_version == "0.14.2"
    assert (r.repo, r.enclave_host_asserted, r.platform, r.captured_at_asserted) == (REPO, ENCLAVE, "sev-snp",
                                                                   captured.evidence["captured_at"])
    assert r.as_of == captured.evidence["captured_at"]
    assert r.not_established == NOT_ESTABLISHED and len(NOT_ESTABLISHED) == 5
    assert any("captured_at is when the capture happened" in x for x in NOT_ESTABLISHED)
    assert any("binds the release tag" in x and "latest" in x for x in NOT_ESTABLISHED)
    assert fake_sigstore == ["Verifier", "policy_check"]  # SDK path from the stored root + second column
    assert (r.log_index, r.integrated_time) == (123456789, 1762400000)
    assert offline == []


def test_replay_needs_no_sdk_cache(captured, offline):
    import shutil
    shutil.rmtree(captured.data_dir / "sdk-cache")
    assert replay(captured.evidence).ok is True


@pytest.mark.parametrize("case,failed", [
    ("report_bytes", "hardware_signature"),
    ("wrong_vcek", "cert_chain"),
    ("policy_build_too_old", "tcb_policy"),
    ("bundle_payload", "code_signature"),
    ("release_digest", "code_signature"),
    ("release_tag", "code_signature"),
    ("trusted_root_file", "code_signature"),
    ("code_measurement", "measurement_match"),
    ("claimed_fingerprint", "measurement_match"),
    ("claimed_hpke", "report_data_keys"),
])
def test_tampering_fails_the_right_check(captured, amd_anchor, offline, tmp_path, case, failed):
    ev = copy.deepcopy(captured.evidence)
    tls_fp, hpke = captured.tls_fp, captured.hpke
    if case == "report_bytes":
        def flip(r):
            r[0x90] ^= 0xFF  # measurement changed after signing
        ev["attestation"]["body"] = sev_report(amd_anchor, tls_fp=tls_fp, hpke=hpke, tamper_after_sign=flip)
    elif case == "wrong_vcek":
        # Same key and extensions, but signed by an ASK that does not chain to the anchored ARK.
        cert = amd_anchor.vcek_for(amd_anchor.vcek_key, signer=rsa.generate_private_key(65537, 2048))
        ev["sev"]["vcek_der_b64"] = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    elif case == "policy_build_too_old":
        ev["attestation"]["body"] = sev_report(amd_anchor, tls_fp=tls_fp, hpke=hpke, build=20)  # validly signed
    elif case == "bundle_payload":
        b = json.loads(ev["sigstore_bundle"])
        p = json.loads(base64.b64decode(b["testEnvelope"]["payload"]))
        p["statement"]["predicate"]["snp_measurement"] = "00" * 48
        b["testEnvelope"]["payload"] = base64.b64encode(json.dumps(p).encode()).decode()
        ev["sigstore_bundle"] = json.dumps(b)
    elif case == "release_digest":
        ev["release"]["digest"] = "cd" * 32
    elif case == "release_tag":
        ev["release"]["tag"] = "v6.6.6"
    elif case == "trusted_root_file":
        p = tmp_path / "trust"
        p.mkdir()
        (p / f"{ev['trusted_root']['sha256']}.json").write_bytes(b'{"tampered": true}')
        r = replay(ev, trust_root_dir=p)
        _expect(r, failed)
        assert "sha256" in r.checks[failed]
        return
    elif case == "code_measurement":
        ev["sigstore_bundle"] = json.dumps(signed_bundle(code_statement(snp="77" * 48), repo=REPO, tag=TAG))
    elif case == "claimed_fingerprint":
        ev["claims"]["code_fingerprint"] = "f" * 64
    elif case == "claimed_hpke":
        ev["claims"]["hpke_public_key"] = "00" * 32
    r = replay(ev)
    print("TAMPER", case, r.checks[failed][:160])
    _expect(r, failed, also=("sev_check", "policy_check"))  # the independent columns may (should) agree
    assert offline == []


def test_malformed_evidence_never_raises():
    for ev in ({}, {"schema": "nope", "captured_at": "2026-11-06T00:00:00Z"}, {"schema": replay_mod.EVIDENCE_SCHEMA},
               None):
        r = replay(ev)  # type: ignore[arg-type]
        assert r.ok is False and r.not_established == NOT_ESTABLISHED


def test_replay_network_ban_is_thread_scoped(offline):
    import requests
    attempts = []
    seen_other = []

    def other_thread():
        try:
            requests.Session().request("GET", "https://x.invalid/")
        except replay_mod.ReplayNetworkError:
            seen_other.append("banned")
        except Exception as exc:  # the socket-level block from the fixture, i.e. NOT the replay ban
            seen_other.append(type(exc).__name__)
    with _sdkpatch.overrides(replay_mod._network_ban(attempts)):
        with pytest.raises(replay_mod.ReplayNetworkError):
            requests.get("https://x.invalid/")
        t = threading.Thread(target=other_thread)
        t.start()
        t.join()
    assert attempts and seen_other and seen_other[0] != "banned"


# ── TDX: collateral rebuilt from stored bytes, freshness under the pinned clock ───────────────

def _pem_chain():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(CAPTURED_AT - timedelta(days=1))
            .not_valid_after(CAPTURED_AT + timedelta(days=365)).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    crl = (x509.CertificateRevocationListBuilder().issuer_name(name).last_update(CAPTURED_AT - timedelta(days=1))
           .next_update(CAPTURED_AT + timedelta(days=30)).sign(key, hashes.SHA256()))
    return pem, crl


@pytest.fixture
def tdx_world(monkeypatch, fake_sigstore, tmp_path):
    """Stub what cannot be fabricated (TDX quote crypto, Intel collateral signatures, PCK details);
    keep the SDK's real collateral freshness check, CRL parsing and TDX hardware matching."""
    tls_fp, hpke = _keys()
    mrtd, rtmr0, rtmr3 = "aa" * 48, "bb" * 48, "0" * 96
    regs = [bytes.fromhex(x) for x in (mrtd, rtmr0, RTMR1, RTMR2, rtmr3)]
    quote = SimpleNamespace(
        td_quote_body=SimpleNamespace(tee_tcb_svn=b"", mr_signer_seam=b"", seam_attributes=b"",
                                      report_data=tls_fp + hpke, get_measurements=lambda: regs),
        signed_data=SimpleNamespace(certification_data=SimpleNamespace(qe_report_data=SimpleNamespace(
            qe_report_parsed=SimpleNamespace(misc_select=0, isv_svn=0, mr_signer=b"", attributes=b"",
                                             isv_prod_id=0)))))
    monkeypatch.setattr(attestation_tdx, "parse_quote", lambda raw: quote)
    monkeypatch.setattr(attestation_tdx, "verify_tdx_quote", lambda q, raw: SimpleNamespace(
        pck_cert=None, intermediate_cert=None))
    monkeypatch.setattr(attestation_tdx, "validate_tdx_policy", lambda q, opts: None)
    monkeypatch.setattr(collateral_tdx, "extract_pck_extensions", lambda cert: SimpleNamespace(fmspc="00906ED50000"))

    def parse_tcb(raw):
        d = json.loads(raw)
        return SimpleNamespace(tcb_info=SimpleNamespace(fmspc=d["fmspc"], tcb_evaluation_data_number=d["eval"],
                                                        next_update=datetime.fromisoformat(d["nextUpdate"])))

    def parse_qe(raw):
        d = json.loads(raw)
        return SimpleNamespace(enclave_identity=SimpleNamespace(tcb_evaluation_data_number=d["eval"],
                                                                next_update=datetime.fromisoformat(d["nextUpdate"])))
    monkeypatch.setattr(collateral_tdx, "parse_tcb_info_response", parse_tcb)
    monkeypatch.setattr(collateral_tdx, "parse_qe_identity_response", parse_qe)
    for name in ("verify_tcb_info_signature", "verify_qe_identity_signature", "_verify_crl_signature",
                 "_verify_root_crl_signature", "validate_certificate_revocation", "validate_tdx_module_identity",
                 "validate_qe_identity"):
        monkeypatch.setattr(collateral_tdx, name, lambda *a, **k: None)
    monkeypatch.setattr(collateral_tdx, "validate_tcb_status", lambda *a, **k: "UpToDate")
    monkeypatch.setattr(collateral_tdx, "_determine_pck_ca_type", lambda cert: "platform")

    pem, crl = _pem_chain()
    nxt = (CAPTURED_AT + timedelta(days=30)).isoformat()
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    from confidential_mode.verify.tinfoil import store_trust_root
    import sigstore as _sg
    root = (Path(_sg.__file__).parent / "_store" / "https%3A%2F%2Ftuf-repo-cdn.sigstore.dev" /
            "trusted_root.json").read_bytes()
    sha, path = store_trust_root(tmp_path / "trust-roots", root)
    code = Measurement(PredicateType.SNP_TDX_MULTIPLATFORM_v1, ["11" * 48, RTMR1, RTMR2])
    enclave = Measurement(PredicateType.TDX_GUEST_V2, [mrtd, rtmr0, RTMR1, RTMR2, rtmr3])
    hw_digest = "ef" * 32
    hw_statement = {"_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": "hw", "digest": {"sha256": hw_digest}}],
                    "predicateType": PredicateType.HARDWARE_MEASUREMENTS_V1.value,
                    "predicate": {"platform-a": {"mrtd": mrtd, "rtmr0": rtmr0}}}
    ev = {
        "schema": replay_mod.EVIDENCE_SCHEMA, "vendor": "tinfoil",
        "captured_at": CAPTURED_AT.isoformat().replace("+00:00", "Z"), "captured_at_unix": CAPTURED_AT.timestamp(),
        "sdk_version": "0.14.2", "repo": REPO, "enclave_host": ENCLAVE, "enclave_source": "config",
        "platform": "tdx",
        "attestation": {"format": PredicateType.TDX_GUEST_V2.value,
                        "body": b64(gzip.compress(b"\x04" * 5000))},
        "sev": None,
        "tdx": {"tcb_info_raw_b64": b64(json.dumps({"fmspc": "00906ED50000", "eval": 19, "nextUpdate": nxt}).encode()),
                "tcb_info_issuer_chain_pem": pem,
                "qe_identity_raw_b64": b64(json.dumps({"eval": 19, "nextUpdate": nxt}).encode()),
                "qe_identity_issuer_chain_pem": pem,
                "pck_crl_pem": crl.public_bytes(serialization.Encoding.PEM).decode(), "pck_crl_ca_type": "platform",
                "pck_crl_issuer_chain_pem": pem,
                "root_crl_der_b64": b64(crl.public_bytes(serialization.Encoding.DER))},
        "release": {"tag": TAG, "digest": DIGEST},
        "sigstore_bundle": json.dumps(signed_bundle(code_statement(snp="11" * 48), repo=REPO, tag=TAG)),
        "hardware_measurements": {"repo": "tinfoilsh/hardware-measurements", "digest": hw_digest,
                                  "bundle": json.dumps(signed_bundle(hw_statement, repo="tinfoilsh/hardware-measurements",
                                                                     tag=None))},
        "trusted_root": {"sha256": sha, "path": str(path)},
        "tls_cert_pem": None,
        "claims": {"code_fingerprint": code.fingerprint(), "enclave_fingerprint": enclave.fingerprint(),
                   "release_tag": TAG, "tls_public_key_fp": tls_fp.hex(), "hpke_public_key": hpke.hex()},
        "verification_document": {}, "capture_complete": True, "capture_missing": [],
    }
    return ev


def test_tdx_replay_at_capture_time_passes(tdx_world, offline):
    r = replay(tdx_world)
    assert r.ok is True, r.checks
    assert r.checks["collateral_fresh_at_capture"] is True and r.checks["hardware_platform_match"] is True
    assert r.checks["sev_check"] == "n/a: TDX: no independent checker"
    assert r.as_of == tdx_world["captured_at"]
    assert offline == []


def test_tdx_replay_90_days_later_fails_collateral_freshness(tdx_world, offline):
    later = CAPTURED_AT + timedelta(days=90)
    r = replay(tdx_world, as_of=later)
    assert r.ok is False
    assert r.checks["collateral_fresh_at_capture"].startswith("fail:") and "expired" in r.checks[
        "collateral_fresh_at_capture"]
    assert r.as_of == "2027-02-04T12:00:00Z"
    assert r.checks["hardware_signature"] is True  # it failed on the clock, not on the bytes
    assert r.checks["code_signature"].startswith("not_run:")
    assert offline == []


def test_tdx_stored_collateral_for_another_platform_fails_cert_chain(tdx_world, offline):
    ev = copy.deepcopy(tdx_world)
    ev["tdx"]["tcb_info_raw_b64"] = base64.b64encode(json.dumps(
        {"fmspc": "FFFFFFFFFFFF", "eval": 19, "nextUpdate": (CAPTURED_AT + timedelta(days=30)).isoformat()}
    ).encode()).decode()
    _expect(replay(ev), "cert_chain")


def test_tdx_hardware_measurement_mismatch_fails_platform_match(tdx_world, offline):
    ev = copy.deepcopy(tdx_world)
    hw = json.loads(ev["hardware_measurements"]["bundle"])
    p = json.loads(base64.b64decode(hw["testEnvelope"]["payload"]))
    p["statement"]["predicate"] = {"platform-z": {"mrtd": "99" * 48, "rtmr0": "99" * 48}}
    ev["hardware_measurements"]["bundle"] = json.dumps(signed_bundle(p["statement"], repo=p["repo"], tag=None))
    _expect(replay(ev), "hardware_platform_match")


def test_replay_overrides_do_not_leak_to_a_concurrent_live_verify(tdx_world, offline):
    """A per-thread override (what replay installs) is invisible to another thread calling the same
    SDK function, e.g. a live verify running during a replay."""
    replay(tdx_world)  # installs the dispatching wrappers
    other = []
    with _sdkpatch.overrides({(collateral_tdx, "_determine_pck_ca_type"): lambda orig, cert: "OVERRIDDEN"}):
        here = collateral_tdx._determine_pck_ca_type(None)
        t = threading.Thread(target=lambda: other.append(collateral_tdx._determine_pck_ca_type(None)))
        t.start()
        t.join()
    assert here == "OVERRIDDEN" and other == ["platform"]
    assert collateral_tdx._determine_pck_ca_type(None) == "platform"


# ── identity, not just validity (Miller-frame review) ─────────────────────────────────────────

def test_capture_records_release_published_at(captured):
    rel = captured.evidence["release"]
    assert rel["published_at"] == "2026-11-01T09:30:00Z"
    assert rel["html_url"] == f"https://github.com/{REPO}/releases/tag/{TAG}"


def test_forged_evidence_from_another_repo_fails_repo_match(captured, amd_anchor, offline):
    """Someone with a genuine SEV-SNP VM and their OWN tag-signing repo produces internally consistent
    evidence. Validity checks pass; identity does not."""
    ev = copy.deepcopy(captured.evidence)
    ev["repo"] = "attacker/router"
    ev["sigstore_bundle"] = json.dumps(signed_bundle(code_statement(), repo="attacker/router", tag=TAG))
    r = replay(ev)
    assert r.ok is False and r.checks["repo_match"].startswith("fail:")
    assert r.checks["code_signature"].startswith("fail:")  # Sigstore policy uses the EXPECTED repo
    assert r.repo == "attacker/router"
    # With no expected repo the same forgery is merely valid, and says so.
    loose = replay(ev, expected_repo=None)
    assert loose.checks["repo_match"].startswith("n/a:") and loose.checks["code_signature"] is True


def test_expected_fingerprints(captured, offline):
    good = (captured.result.code_fingerprint, captured.result.enclave_fingerprint)
    assert replay(captured.evidence, expected_fingerprints=good).ok is True
    r = replay(captured.evidence, expected_fingerprints=(good[0], "00" * 48))
    _expect(r, "measurement_match")
    assert "expected_fingerprints" in r.checks["measurement_match"]


def test_supplied_trusted_root_is_independent(captured, offline, tmp_path):
    root = Path(captured.evidence["trusted_root"]["path"]).read_bytes()
    r = replay(captured.evidence, trusted_root=root)
    assert r.ok is True and r.checks["trust_root_source"] == "supplied"
    p = tmp_path / "root.json"
    p.write_bytes(root)
    assert replay(captured.evidence, trusted_root=p).checks["trust_root_source"] == "supplied"
    bad = replay(captured.evidence, trusted_root=b'{"not": "a trusted root"}')
    assert bad.ok is False and bad.checks["code_signature"].startswith("fail:")


def test_pending_pin_from_a_captured_result_carries_the_prompt_context(captured, tmp_path):
    from confidential_mode.pins import PinStore
    store = PinStore(tmp_path / "pins.yaml")
    p = store.stage(captured.result)
    assert p.platform == "sev-snp" and p.enclave_host == ENCLAVE
    assert p.release_published_at == "2026-11-01T09:30:00Z" and p.rekor_log_index == 123456789
    assert p.code_changed is True and p.previous is None and p.previous_platform is None
    assert p.hardware_measurements_verified is False  # SEV-SNP: the SDK runs no hardware-measurements check
    assert p.release_url == f"https://github.com/{REPO}/releases/tag/{TAG}" and p.compare_url is None


def test_override_applies_once_even_when_the_attribute_is_wrapped_twice():
    """A second copy of the plugin (Hermes loads it under another package name) or a re-wrap over a
    monkeypatch leaves two dispatching wrappers stacked; the override must still run exactly once."""
    import types
    mod = types.ModuleType("dummy_sdk")
    mod.f = lambda x: x + 1
    _sdkpatch.install(mod, "f")
    inner = mod.f
    mod.f = lambda x: inner(x)       # something else wraps our wrapper...
    _sdkpatch.install(mod, "f")      # ...and we wrap again on top
    calls = []

    def ov(orig, x):
        calls.append(x)
        return orig(x) * 10
    with _sdkpatch.overrides({(mod, "f"): ov}):
        assert mod.f(1) == 20
    assert calls == [1] and mod.f(1) == 2


# ── repository identity by numeric id (Fulcio 1.15 / 1.17) ────────────────────────────────────

def _with_bundle(captured, **kw):
    ev = copy.deepcopy(captured.evidence)
    ev["sigstore_bundle"] = json.dumps(signed_bundle(code_statement(), repo=REPO, tag=TAG, **kw))
    return ev


def test_repo_identity_right_name_and_ids(captured, offline):
    r = replay(_with_bundle(captured), expected_repo_id=REPO_ID, expected_owner_id=OWNER_ID)
    assert r.ok is True and r.checks["repo_identity"] == "name+id", r.checks
    assert (r.source_repo_id, r.source_owner_id, r.source_commit) == (REPO_ID, OWNER_ID, COMMIT)
    assert r.build_signer_uri == f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{TAG}"
    assert (r.log_index, r.integrated_time) == (123456789, 1762400000)


def test_repo_identity_wrong_repo_id_with_the_right_name_fails(captured, offline):
    """A deleted-and-recreated (or transferred) repository keeps the name but not the numeric id."""
    r = replay(_with_bundle(captured, repo_id="999999"), expected_repo_id=REPO_ID, expected_owner_id=OWNER_ID)
    _expect(r, "repo_identity", also=("policy_check",))
    assert "repo_id 999999" in r.checks["repo_identity"] and r.checks["policy_check"].startswith("fail:")
    r = replay(_with_bundle(captured, owner_id="1"), expected_repo_id=REPO_ID, expected_owner_id=OWNER_ID)
    _expect(r, "repo_identity", also=("policy_check",))


def test_repo_identity_wrong_repo_name_in_the_certificate_fails(captured, offline):
    r = replay(_with_bundle(captured, cert_repo="attacker/router"))
    _expect(r, "repo_identity", also=("policy_check",))
    assert "attacker/router" in r.checks["repo_identity"]


def test_repo_identity_ids_requested_but_absent_from_the_certificate(captured, offline):
    r = replay(_with_bundle(captured, repo_id=None, owner_id=None), expected_repo_id=REPO_ID)
    _expect(r, "repo_identity", also=("policy_check",))


def test_policy_check_module_has_no_tinfoil_import_and_runs_isolated(captured, tmp_path):
    import subprocess
    from confidential_mode.verify import policy_check
    src = Path(policy_check.__file__).read_text()
    import re
    assert not re.search(r"^\s*(import|from)\s+(tinfoil|confidential_mode|\.)", src, re.M)
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(signed_bundle(code_statement(), repo=REPO, tag=TAG)))
    done = subprocess.run([sys.executable, "-I", policy_check.__file__, "--bundle", str(p), "--identity-only"], capture_output=True, text=True,
                          timeout=60)
    assert done.returncode == 0, done.stderr
    out = json.loads(done.stdout)
    assert out["repo_id"] == REPO_ID and out["repository"] == REPO and out["log_index"] == 123456789


def test_verify_time_policy_check_detail(captured):
    """What provider.py puts in verify_ok detail.policy_check for a captured verification."""
    from confidential_mode import provider as provider_mod
    d = provider_mod._policy_check_detail(captured.evidence)
    assert d["ok"] is True and d["repo_id"] == REPO_ID, d
    assert provider_mod._tlog_fields(captured.evidence) == {"log_index": 123456789, "integrated_time": 1762400000}
    bad = copy.deepcopy(captured.evidence)
    bad["release"]["tag"] = "v0.0.0"
    assert provider_mod._policy_check_detail(bad)["ok"] is False
    assert provider_mod._policy_check_detail({})["ok"] is False


# ── TLS certificate on the EHBP connection (stubbed TLS server) ───────────────────────────────

@pytest.mark.parametrize("mode", ["enclave", "proxy"])
def test_tls_probe_records_who_terminates_tls(offline, amd_anchor, fake_sigstore, tmp_path, monkeypatch, mode):
    c = _capture(amd_anchor, tmp_path, monkeypatch, tls=mode)
    obs = c.evidence["tls_observation"]
    assert obs["captured"] is True and c.evidence["tls_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert obs["spki_sha256"] != "" and obs["issuer"] and obs["not_after"]
    r = replay(c.evidence)
    if mode == "enclave":
        assert obs["matches_report_tls_key"] is True and obs["san_binding"] is True
        assert obs["verdict"].startswith("TLS terminates in the attested enclave")
        assert r.checks["tls_cert_binding"] is True and r.ok is True, r.checks
    else:
        assert obs["matches_report_tls_key"] is False
        assert obs["verdict"] == "TLS terminated by a non-enclave key"
        assert r.checks["tls_cert_binding"].startswith("n/a: TLS terminated by a non-enclave key")
        assert r.ok is True  # recorded, not failed: bodies are still sealed to H
    assert offline == []


def test_tls_probe_without_a_visible_certificate_is_recorded(offline, amd_anchor, fake_sigstore, tmp_path,
                                                            monkeypatch):
    def plain(self, request):
        return httpx.Response(200, json={})
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", plain)
    c = _capture(amd_anchor, tmp_path, monkeypatch)
    c.adapter.tls_probe = True
    ev = c.adapter.verify().evidence
    assert ev["tls_observation"] == {"captured": False, "reason": "transport exposes no TLS peer certificate"}
    assert ev["tls_cert_pem"] is None


def test_tampered_tls_cert_binding_fails_replay(offline, amd_anchor, fake_sigstore, tmp_path, monkeypatch):
    c = _capture(amd_anchor, tmp_path, monkeypatch, tls="enclave")
    ev = copy.deepcopy(c.evidence)
    ev["claims"]["hpke_public_key"] = c.evidence["claims"]["hpke_public_key"]
    ev["enclave_host"] = "other.tinfoil.invalid"  # SAN binding is to the host the capture named
    r = replay(ev)
    assert r.checks["tls_cert_binding"].startswith("fail:"), r.checks

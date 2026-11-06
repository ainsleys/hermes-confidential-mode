"""Minimal standalone AMD SEV-SNP (Genoa) report checker: an independent second column for replay.

No tinfoil import (stdlib + cryptography only); runnable as
    python -I confidential_mode/verify/sev_check.py --report-b64 <gzip+base64 report> --vcek <der file>
What it establishes, and nothing more: AMD hardware signed a report containing measurement M, TLS key
fingerprint T and HPKE key H, under a VCEK that chains to the AMD Genoa ARK pinned below by SHA-256,
with debug and migration-agent disabled, the observed VMPL, and every TCB component of the current,
committed and reported TCB at or above a plugin-owned dated minimum. It does NOT check AMD CRLs (no
network) and is identified in receipts by this file's SHA-256.

Re-implementation notes (review finding 5): the signed region is bytes 0x000-0x29F; the signature
at 0x2A0 is r||s, 72 bytes each, LITTLE-endian, converted to a DER ECDSA-P384 signature; TCB is
compared per component (Genoa layout: bl bits 0-7, tee 8-15, snp 48-55, microcode 56-63), never as
one integer; Turin and other products are refused (their TCB layout differs).
"""
from __future__ import annotations

import base64
import gzip
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

# AMD Genoa root (ARK) and SEV signing (ASK) certificates, public, from AMD KDS. Pinned by the SHA-256
# of their DER encoding; cross-checked 2026-11-07 against tinfoil 0.14.2's embedded copy
# (tinfoil/attestation/genoa_cert_chain.py) by tests/unit/test_sev_check.py.
ARK_SHA256 = "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1"
ASK_SHA256 = "5464738c1546aed5f2cecf1dc98c5c960a92e8913238a61711bc90ec6e828521"
ARK_PEM = """-----BEGIN CERTIFICATE-----
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
/wMz1R1BHg==
-----END CERTIFICATE-----
"""
ASK_PEM = """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
"""

# Plugin-owned minimum TCB for Genoa, dated. Taken from the live capture of router-0.tinfoil.sh on
# 2026-11-06 (current = committed = reported = launch = 0x581b00000000000a), i.e. "no older than what we
# observed". Raise it deliberately; a router on older firmware fails THIS column only (sends are gated
# by the vendor SDK, whose own minimum is lower).
MIN_TCB_DATED = "2026-11-07"
MIN_TCB = {"bl": 0x0A, "tee": 0x00, "snp": 0x1B, "ucode": 0x58}
EXPECTED_VMPL = 0  # as observed in the live report

REPORT_SIZE = 0x4A0
SIGNED_END = 0x2A0
GENOA_FAMILY, GENOA_MODEL = 0x19, 0x11
_VCEK_OIDS = {"bl": "1.3.6.1.4.1.3704.1.3.1", "tee": "1.3.6.1.4.1.3704.1.3.2", "snp": "1.3.6.1.4.1.3704.1.3.3",
              "ucode": "1.3.6.1.4.1.3704.1.3.8"}
_HWID_OID = "1.3.6.1.4.1.3704.1.4"
_PRODUCT_OID = "1.3.6.1.4.1.3704.1.2"


class SevCheckError(Exception):
    pass


@dataclass(frozen=True)
class SevCheckResult:
    ok: bool
    reason: str
    measurement: str | None = None       # hex, 48 bytes
    tls_key_fp: str | None = None        # report_data[0:32]
    hpke_public_key: str | None = None   # report_data[32:64]
    vmpl: int | None = None
    version: int | None = None
    tcb: dict = field(default_factory=dict)
    checker_sha256: str = ""


def checker_sha256() -> str:
    with open(__file__, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _u(r: bytes, a: int, b: int) -> int:
    return int.from_bytes(r[a:b], "little")


def tcb_parts(v: int) -> dict:
    return {"bl": v & 0xFF, "tee": (v >> 8) & 0xFF, "snp": (v >> 48) & 0xFF, "ucode": (v >> 56) & 0xFF}


def _der_int(b: bytes) -> int:
    if len(b) < 3 or b[0] != 0x02 or b[1] != len(b) - 2:
        raise SevCheckError(f"VCEK extension is not a DER INTEGER: {b.hex()}")
    return int.from_bytes(b[2:], "big", signed=True)


def _pss_verify(issuer, cert) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    params = cert.signature_algorithm_parameters
    if not isinstance(params, padding.PSS) or cert.signature_hash_algorithm.name != "sha384":
        raise SevCheckError(f"{cert.subject.rfc4514_string()}: expected RSASSA-PSS SHA-384")
    issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                               padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())


def _valid_at(cert, when: datetime) -> None:
    if not (cert.not_valid_before_utc <= when <= cert.not_valid_after_utc):
        raise SevCheckError(f"{cert.subject.rfc4514_string()} not valid at {when.isoformat()}")


def check(report_b64: str, vcek_der: bytes, *, as_of: datetime | None = None, compressed: bool = True,
          ark_pem: str | None = None, ask_pem: str | None = None) -> SevCheckResult:
    """Never raises; ok False with a reason on any failure."""
    sha = checker_sha256()
    ark_pem = ark_pem or ARK_PEM
    ask_pem = ask_pem or ASK_PEM
    try:
        import warnings

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        when = as_of or datetime.now(timezone.utc)
        raw = base64.b64decode(report_b64, validate=True)
        r = gzip.decompress(raw) if compressed else raw
        if len(r) != REPORT_SIZE:
            raise SevCheckError(f"report is {len(r)} bytes, expected {REPORT_SIZE}")
        version = _u(r, 0x00, 0x04)
        if version < 2:
            raise SevCheckError(f"report version {version} < 2")
        if _u(r, 0x34, 0x38) != 1:
            raise SevCheckError("signature algorithm is not ECDSA P-384 with SHA-384")
        policy = _u(r, 0x08, 0x10)
        if policy & (1 << 19):
            raise SevCheckError("guest policy allows DEBUG")
        if policy & (1 << 18):
            raise SevCheckError("guest policy allows a migration agent")
        vmpl = _u(r, 0x30, 0x34)
        if vmpl != EXPECTED_VMPL:
            raise SevCheckError(f"VMPL {vmpl} is not the expected {EXPECTED_VMPL}")
        signer = _u(r, 0x48, 0x4C)
        if (signer >> 2) & 7 != 0:
            raise SevCheckError("report is not VCEK-signed")
        mask_chip = bool(signer & 2)
        if version >= 3 and (r[0x188], r[0x189]) != (GENOA_FAMILY, GENOA_MODEL):
            raise SevCheckError(f"CPU family/model {r[0x188]:#x}/{r[0x189]:#x} is not Genoa")
        tcbs = {"current": tcb_parts(_u(r, 0x38, 0x40)), "reported": tcb_parts(_u(r, 0x180, 0x188)),
                "committed": tcb_parts(_u(r, 0x1E0, 0x1E8))}
        for name, parts in tcbs.items():
            for comp, floor in MIN_TCB.items():
                if parts[comp] < floor:
                    raise SevCheckError(f"{name} TCB {comp}={parts[comp]:#x} below the {MIN_TCB_DATED} minimum {floor:#x}")
        if tcbs["current"] != tcbs["committed"]:
            raise SevCheckError("current TCB differs from committed TCB (provisional firmware)")

        ark = x509.load_pem_x509_certificate(ark_pem.encode())
        ask = x509.load_pem_x509_certificate(ask_pem.encode())
        if hashlib.sha256(ark.public_bytes(serialization.Encoding.DER)).hexdigest() != ARK_SHA256:
            raise SevCheckError("ARK does not match the pinned SHA-256")
        if hashlib.sha256(ask.public_bytes(serialization.Encoding.DER)).hexdigest() != ASK_SHA256:
            raise SevCheckError("ASK does not match the pinned SHA-256")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # AMD VCEKs carry a non-positive serial number
            vcek = x509.load_der_x509_certificate(vcek_der)
        for issuer, cert in ((ark, ark), (ark, ask), (ask, vcek)):
            _pss_verify(issuer, cert)
            _valid_at(cert, when)
        cn = vcek.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not cn or cn[0].value != "SEV-VCEK":
            raise SevCheckError("VCEK subject CN is not SEV-VCEK")
        pub = vcek.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
            raise SevCheckError("VCEK key is not P-384")
        exts = {e.oid.dotted_string: getattr(e.value, "value", None) for e in vcek.extensions}
        if exts.get(_PRODUCT_OID) != b"\x16\x05Genoa":
            raise SevCheckError("VCEK product name is not Genoa")
        for comp, oid in _VCEK_OIDS.items():
            if oid not in exts or _der_int(exts[oid]) != tcbs["reported"][comp]:
                raise SevCheckError(f"VCEK {comp} SPL does not equal the reported TCB")
        chip_id = r[0x1A0:0x1E0]
        if not mask_chip and exts.get(_HWID_OID) != chip_id:
            raise SevCheckError("VCEK HWID does not equal the report's CHIP_ID")

        sig = r[SIGNED_END:SIGNED_END + 144]
        rr = int.from_bytes(sig[0:72], "little")
        ss = int.from_bytes(sig[72:144], "little")
        if any(r[SIGNED_END + 144:REPORT_SIZE]):
            raise SevCheckError("bytes after the signature are not zero")
        pub.verify(encode_dss_signature(rr, ss), r[0:SIGNED_END], ec.ECDSA(hashes.SHA384()))
        return SevCheckResult(ok=True, reason="ok", measurement=r[0x90:0xC0].hex(), tls_key_fp=r[0x50:0x70].hex(),
                              hpke_public_key=r[0x70:0x90].hex(), vmpl=vmpl, version=version,
                              tcb={k: dict(v) for k, v in tcbs.items()}, checker_sha256=sha)
    except Exception as exc:
        return SevCheckResult(ok=False, reason=f"{type(exc).__name__}: {exc}"[:400], checker_sha256=sha)


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess in tests
    import argparse
    import json
    ap = argparse.ArgumentParser(description="standalone SEV-SNP (Genoa) report check")
    ap.add_argument("--report-b64", required=True, help="gzip+base64 report (evidence.attestation.body)")
    ap.add_argument("--vcek", required=True, help="VCEK DER file")
    ap.add_argument("--as-of", help="ISO time for certificate validity (default now)")
    a = ap.parse_args()
    when = datetime.fromisoformat(a.as_of.replace("Z", "+00:00")) if a.as_of else None
    res = check(open(a.report_b64).read().strip() if a.report_b64.endswith(".txt") else a.report_b64,
                open(a.vcek, "rb").read(), as_of=when)
    print(json.dumps(res.__dict__, indent=2))
    raise SystemExit(0 if res.ok else 1)

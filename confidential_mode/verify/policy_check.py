"""Standalone Sigstore identity extraction and policy check for a stored release bundle.

Deliberately imports nothing from tinfoil or from this package, so it can be run on its own:

    python -I confidential_mode/verify/policy_check.py --bundle bundle.json --digest <hex> \\
        --repo tinfoilsh/confidential-model-router --tag v1.2.3 --trusted-root trusted_root.json \\
        [--repo-id 123] [--owner-id 456]

Only the standard library, ``cryptography`` and ``sigstore`` (sigstore-python) are used.
"""
from __future__ import annotations

import base64
import json
from typing import Any

# Fulcio certificate extension OIDs (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
OID_WORKFLOW_REPOSITORY_V1 = "1.3.6.1.4.1.57264.1.5"
OID_WORKFLOW_REF_V1 = "1.3.6.1.4.1.57264.1.6"
OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
OID_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9"
OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12"
OID_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13"
OID_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14"
OID_SOURCE_REPOSITORY_IDENTIFIER = "1.3.6.1.4.1.57264.1.15"
OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER = "1.3.6.1.4.1.57264.1.17"

_V1_RAW = {OID_ISSUER_V1, OID_WORKFLOW_REPOSITORY_V1, OID_WORKFLOW_REF_V1}  # raw bytes, not DER

IDENTITY_FIELDS = {
    "issuer": (OID_ISSUER_V2, OID_ISSUER_V1),
    "repository_v1": (OID_WORKFLOW_REPOSITORY_V1,),
    "ref_v1": (OID_WORKFLOW_REF_V1,),
    "build_signer_uri": (OID_BUILD_SIGNER_URI,),
    "source_repository_uri": (OID_SOURCE_REPOSITORY_URI,),
    "source_commit": (OID_SOURCE_REPOSITORY_DIGEST,),
    "source_ref": (OID_SOURCE_REPOSITORY_REF,),
    "repo_id": (OID_SOURCE_REPOSITORY_IDENTIFIER,),
    "owner_id": (OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER,),
}


def _der_utf8(value: bytes) -> str:
    """Fulcio 'v2' extensions are DER UTF8String; v1 ones are raw bytes."""
    if len(value) >= 2 and value[0] == 0x0C:
        n, i = value[1], 2
        if n & 0x80:
            k = n & 0x7F
            n, i = int.from_bytes(value[2:2 + k], "big"), 2 + k
        return value[i:i + n].decode("utf-8")
    return value.decode("utf-8")


def bundle_certificate_der(bundle: dict) -> bytes | None:
    vm = bundle.get("verificationMaterial") or {}
    cert = vm.get("certificate") or {}
    raw = cert.get("rawBytes")
    if not raw:
        chain = (vm.get("x509CertificateChain") or {}).get("certificates") or []
        raw = chain[0].get("rawBytes") if chain else None
    return base64.b64decode(raw) if raw else None


def fulcio_identity(bundle_json: bytes | str | dict) -> dict[str, Any]:
    """Identity claims from the bundle's signing certificate WITHOUT verifying anything (callers verify
    the bundle first). Keys: issuer, repository_v1, ref_v1, build_signer_uri, source_repository_uri,
    source_commit, source_ref, repo_id, owner_id, repository (owner/name, from the source URI or the v1
    extension); missing values are None. Also log_index / integrated_time from the first tlog entry."""
    from cryptography import x509
    bundle = bundle_json if isinstance(bundle_json, dict) else json.loads(bundle_json)
    out: dict[str, Any] = {k: None for k in IDENTITY_FIELDS}
    out.update(repository=None, log_index=None, integrated_time=None, has_certificate=False)
    entries = (bundle.get("verificationMaterial") or {}).get("tlogEntries") or []
    if entries:
        e0 = entries[0]
        for key, src in (("log_index", "logIndex"), ("integrated_time", "integratedTime")):
            v = e0.get(src)
            if v is not None and str(v).strip().lstrip("-").isdigit():
                out[key] = int(v)
    der = bundle_certificate_der(bundle)
    if der is None:
        return out
    cert = x509.load_der_x509_certificate(der)
    out["has_certificate"] = True
    exts = {e.oid.dotted_string: e.value for e in cert.extensions}
    for key, oids in IDENTITY_FIELDS.items():
        for oid in oids:
            val = exts.get(oid)
            if val is None:
                continue
            raw = getattr(val, "value", None)
            if isinstance(raw, bytes):
                out[key] = raw.decode("utf-8") if oid in _V1_RAW else _der_utf8(raw)
                break
    uri = out.get("source_repository_uri") or ""
    if uri.startswith("https://github.com/"):
        out["repository"] = uri[len("https://github.com/"):].rstrip("/")
    elif out.get("repository_v1"):
        out["repository"] = out["repository_v1"]
    return out


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess in tests
    import sys
    data = open(sys.argv[1], "rb").read()
    print(json.dumps(fulcio_identity(data), indent=2))

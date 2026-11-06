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


# ── restated policy check ───────────────────────────────────────────────────────────────────────

OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE_MULTIPLATFORM = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
PREDICATE_HARDWARE = "https://tinfoil.sh/predicate/hardware-measurements/v1"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
INTOTO_FIELDS = frozenset({"_type", "subject", "predicateType", "predicate"})


class PolicyError(Exception):
    pass


from dataclasses import dataclass, field  # noqa: E402


@dataclass(frozen=True)
class PolicyResult:
    ok: bool
    reason: str
    predicate_type: str | None = None
    statement: dict | None = None
    log_index: int | None = None
    integrated_time: int | None = None
    repo_id: str | None = None
    owner_id: str | None = None
    workflow: str | None = None          # Build Signer URI (1.9)
    commit: str | None = None            # Source Repository Digest (1.13)
    repository: str | None = None
    identity: dict = field(default_factory=dict)


def _ext_text(cert, oid: str) -> str | None:
    from cryptography import x509
    try:
        val = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value.value
    except x509.ExtensionNotFound:
        return None
    return val.decode("utf-8") if oid in _V1_RAW else _der_utf8(val)


class _Policy:
    """Restated policy, at least as strict as tinfoil 0.14.2 (sigstore.py _verify_dsse_bundle):
    OIDC issuer (V2 extension authoritative, V1 only when V2 is absent), workflow repository, the
    workflow ref == refs/tags/<re.escape(tag)> anchored with \\Z, plus (stricter) the V2 source repository URI when
    present and, when given, the numeric source repository / owner identifiers."""

    def __init__(self, repo: str, tag: str | None, repo_id=None, owner_id=None):
        self.repo, self.tag, self.repo_id, self.owner_id = repo, tag, repo_id, owner_id

    def verify(self, cert) -> None:
        import re
        issuer = _ext_text(cert, OID_ISSUER_V2) or _ext_text(cert, OID_ISSUER_V1)
        if issuer != OIDC_ISSUER:
            raise PolicyError(f"OIDC issuer {issuer!r} is not {OIDC_ISSUER}")
        repo_v1 = _ext_text(cert, OID_WORKFLOW_REPOSITORY_V1)
        uri = _ext_text(cert, OID_SOURCE_REPOSITORY_URI)
        if repo_v1 is None:  # the SDK's GitHubWorkflowRepository requires it too
            raise PolicyError("certificate lacks the workflow repository extension (1.5)")
        if repo_v1 != self.repo:
            raise PolicyError(f"workflow repository {repo_v1!r} is not {self.repo!r}")
        if uri is not None and uri != f"https://github.com/{self.repo}":
            raise PolicyError(f"source repository URI {uri!r} is not https://github.com/{self.repo}")
        pattern = rf"^refs/tags/{re.escape(self.tag)}\Z" if self.tag is not None else r"^refs/tags/.+\Z"
        ref = _ext_text(cert, OID_WORKFLOW_REF_V1)  # required, as in the SDK (GitHubWorkflowRefPattern)
        if ref is None or not re.match(pattern, ref):
            raise PolicyError(f"workflow ref {ref!r} does not match {pattern}")
        source_ref = _ext_text(cert, OID_SOURCE_REPOSITORY_REF)
        if source_ref is not None and not re.match(pattern, source_ref):  # stricter: V2 ref must agree
            raise PolicyError(f"source repository ref {source_ref!r} does not match {pattern}")
        for oid, want, label in ((OID_SOURCE_REPOSITORY_IDENTIFIER, self.repo_id, "repository id"),
                                 (OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER, self.owner_id, "owner id")):
            if want is not None and _ext_text(cert, oid) != str(want):
                raise PolicyError(f"source {label} {_ext_text(cert, oid)!r} is not {want!r}")


def _reject_legacy(bundle: dict) -> None:
    vm = bundle.get("verificationMaterial")
    if isinstance(vm, dict) and "x509CertificateChain" in vm:
        raise PolicyError("legacy bundle layout (x509CertificateChain) rejected")


def _reject_duplicate_scts(cert) -> None:
    from cryptography import x509
    try:
        scts = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value
    except x509.ExtensionNotFound:
        return
    ids = [s.log_id for s in scts]
    if len(set(ids)) != len(ids):
        raise PolicyError("duplicate SCT log id")


def _load_bundle(bundle_json: bytes):
    """sigstore-python Bundle (tests replace this hook)."""
    from sigstore.models import Bundle
    return Bundle.from_json(bundle_json)


def _make_verifier(trusted_root: bytes):
    """sigstore-python Verifier from a trusted_root.json; never TUF, never online Rekor (tests replace
    this hook). verify_dsse checks the signed entry timestamp, inclusion proof and checkpoint offline."""
    from sigstore.models import TrustedRoot
    from sigstore.verify import Verifier
    from sigstore_models.trustroot.v1 import TrustedRoot as _Inner
    return Verifier(trusted_root=TrustedRoot(_Inner.from_json(trusted_root)))


def check_bundle(bundle_json: bytes | str, *, digest: str, repo: str, tag: str | None, trusted_root: bytes,
                 predicate_type: str = PREDICATE_MULTIPLATFORM, expected_repo_id=None,
                 expected_owner_id=None) -> PolicyResult:
    """Re-verify a stored DSSE release bundle against the restated policy. Never raises."""
    raw = bundle_json.encode("utf-8") if isinstance(bundle_json, str) else bytes(bundle_json)
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict):
            raise PolicyError("bundle is not a JSON object")
        _reject_legacy(doc)
        bundle = _load_bundle(raw)
        cert = bundle.signing_certificate
        _reject_duplicate_scts(cert)
        policy = _Policy(repo, tag, expected_repo_id, expected_owner_id)
        payload_type, payload = _make_verifier(trusted_root).verify_dsse(bundle, policy)
        if payload_type != INTOTO_PAYLOAD_TYPE:
            raise PolicyError(f"payload type {payload_type!r} is not {INTOTO_PAYLOAD_TYPE}")
        statement = json.loads(payload)
        if not isinstance(statement, dict):
            raise PolicyError("in-toto statement is not an object")
        extra = set(statement) - INTOTO_FIELDS
        if extra:
            raise PolicyError(f"in-toto statement has unknown field(s): {', '.join(sorted(extra))}")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1:
            raise PolicyError(f"expected exactly one subject, got {len(subjects) if isinstance(subjects, list) else 0}")
        got = ((subjects[0] or {}).get("digest") or {}).get("sha256")
        if got != digest:
            raise PolicyError(f"subject digest {got!r} is not {digest!r}")
        if statement.get("predicateType") != predicate_type:
            raise PolicyError(f"predicateType {statement.get('predicateType')!r} is not {predicate_type!r}")
        ident = fulcio_identity(doc)
        return PolicyResult(ok=True, reason="ok", predicate_type=predicate_type, statement=statement,
                            log_index=ident.get("log_index"), integrated_time=ident.get("integrated_time"),
                            repo_id=ident.get("repo_id"), owner_id=ident.get("owner_id"),
                            workflow=ident.get("build_signer_uri"), commit=ident.get("source_commit"),
                            repository=ident.get("repository"), identity=ident)
    except Exception as exc:
        return PolicyResult(ok=False, reason=f"{type(exc).__name__}: {exc}"[:400])


def _main(argv=None) -> int:  # pragma: no cover - exercised as a subprocess in tests
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--identity-only", action="store_true")
    ap.add_argument("--digest")
    ap.add_argument("--repo")
    ap.add_argument("--tag")
    ap.add_argument("--trusted-root")
    ap.add_argument("--predicate-type", default=PREDICATE_MULTIPLATFORM)
    ap.add_argument("--repo-id")
    ap.add_argument("--owner-id")
    a = ap.parse_args(argv)
    data = open(a.bundle, "rb").read()
    if a.identity_only:
        print(json.dumps(fulcio_identity(data), indent=2))
        return 0
    r = check_bundle(data, digest=a.digest, repo=a.repo, tag=a.tag, trusted_root=open(a.trusted_root, "rb").read(),
                     predicate_type=a.predicate_type, expected_repo_id=a.repo_id, expected_owner_id=a.owner_id)
    out = {k: v for k, v in r.__dict__.items() if k not in ("statement", "identity")}
    print(json.dumps(out, indent=2))
    return 0 if r.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())

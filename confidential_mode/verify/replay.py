"""Offline replay of a captured tinfoil 0.14.2 verification (evidence schema v1, see verify/tinfoil.py).

``replay(evidence) -> ReplayResult`` re-runs the SDK's own verifier functions on the stored bytes with
ZERO network: within the replaying thread every ``requests`` / ``urllib`` call raises, Sigstore uses a
``Verifier`` built from the stored, content-addressed trusted_root.json (never TUF), SEV gets the stored
VCEK via ``vcek_der``, TDX collateral is rebuilt from the stored bytes (Intel signatures re-verified) in
place of ``collateral_tdx.fetch_collateral``, and every clock the SDK consults (``datetime.now`` in
collateral_tdx / cert_utils, the OpenSSL store time for the AMD chain) is pinned to ``as_of``
(default: captured_at). Overrides are thread-scoped (verify/_sdkpatch.py): a live verify on another
thread is unaffected.

Check values: ``True`` (passed), or a string starting with ``fail:``, ``n/a:`` or ``not_run:``.
``ok`` is True iff every check is True or ``n/a``.

What a replay can NOT establish is fixed in ``NOT_ESTABLISHED`` and returned with every result.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import _sdkpatch, policy_check

EVIDENCE_SCHEMA = "confidential-mode/tinfoil-evidence/v1"
HARDWARE_MEASUREMENTS_REPO = "tinfoilsh/hardware-measurements"
TINFOIL_ROUTER_REPO = "tinfoilsh/confidential-model-router"

CHECK_KEYS = (
    "repo_match",                   # evidence repo == expected_repo (identity, not just validity)
    "repo_identity",                # Fulcio cert: "name+id" | "name only (ids not supplied)" | "fail: ..."
    "trust_root_source",            # INFORMATIONAL: "supplied" or "from_evidence" (not independent)
    "hardware_signature",           # report / quote signature by the CPU vendor key
    "cert_chain",                   # VCEK -> AMD ARK/ASK, or PCK -> Intel root, collateral signatures, revocation
    "tcb_policy",                   # SDK policy: guest policy, minimum TCB/firmware, TDX module / QE identity
    "collateral_fresh_at_capture",  # TDX: TCB info / QE identity not expired at as_of (n/a for SEV)
    "code_signature",               # Sigstore DSSE + Rekor + GitHub workflow policy for the release digest
    "measurement_match",            # signed code measurement == enclave measurement; fingerprints == claims
    "hardware_platform_match",      # TDX: MRTD/RTMR0 match a signed hardware-measurements entry (n/a for SEV)
    "report_data_keys",             # report_data (TLS key fp || HPKE key) == the keys the client used
    "tls_cert_binding",             # captured TLS cert binds the HPKE key + report hash (n/a: not captured)
)

NOT_ESTABLISHED = (
    "that any request was sent to or answered by this enclave (the report commits to keys, not to "
    "requests, and carries no client nonce)",
    "that requests were encrypted to this HPKE key (only the plugin's own log says so)",
    "that this release was the latest release when verified (tinfoil 0.14.2 binds the release tag "
    "and digest through the Sigstore workflow-ref policy, but which release is 'latest' comes from an "
    "unsigned GitHub API answer)",
    "revocation or TCB changes after captured_at",
    "that captured_at is when the capture happened (it is taken from the evidence itself)",
)
INFORMATIONAL_CHECKS = ("trust_root_source",)
REPO_IDENTITY_PASSING = ("name+id", "name only (ids not supplied)")


@dataclass(frozen=True)
class ReplayResult:
    ok: bool
    checks: dict[str, Any]
    code_fingerprint: str | None
    enclave_fingerprint: str | None
    release_tag: str | None
    tls_key_fp: str | None
    hpke_public_key: str | None
    as_of: str
    sdk_version: str
    repo: str | None = None
    enclave_host_asserted: str | None = None   # capturer-asserted: the evidence says so, nothing proves it
    platform: str | None = None
    captured_at_asserted: str | None = None    # capturer-asserted (see NOT_ESTABLISHED)
    # From the release bundle's Fulcio certificate and tlog entry (after code_signature passed):
    source_repo_id: str | None = None
    source_owner_id: str | None = None
    build_signer_uri: str | None = None        # workflow path, e.g. https://github.com/o/r/.github/workflows/x.yml@refs/tags/v1
    source_commit: str | None = None
    log_index: int | None = None
    integrated_time: int | None = None
    not_established: tuple[str, ...] = field(default=NOT_ESTABLISHED)


class _Checks:
    def __init__(self):
        self.values: dict[str, Any] = {k: "not_run: an earlier check failed" for k in CHECK_KEYS}
        self._touched: set[str] = set()

    def passed(self, key: str) -> None:
        if key not in self._touched:
            self.values[key] = True
            self._touched.add(key)
        elif self.values[key] is not True:
            return  # a failure is never overwritten by a later pass

    def failed(self, key: str, why: Any) -> None:
        if key in self._touched and isinstance(self.values[key], str) and self.values[key].startswith("fail:"):
            return  # keep the first failure
        self.values[key] = f"fail: {str(why)[:300]}"
        self._touched.add(key)

    def na(self, key: str, why: str) -> None:
        self.values[key] = f"n/a: {why}"
        self._touched.add(key)

    def touched(self, key: str) -> bool:
        return key in self._touched

    def first_failure(self) -> bool:
        return any(isinstance(v, str) and v.startswith("fail:") for v in self.values.values())


def _sdk_version() -> str:
    try:
        from tinfoil._sdkinfo import sdk_version
        return sdk_version()
    except Exception:
        return "unknown"


def _as_datetime(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    raise ValueError(f"unusable time {value!r}")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


# ── network ban (thread-scoped) ───────────────────────────────────────────────────────────────

class ReplayNetworkError(RuntimeError):
    pass


def _network_ban(attempts: list) -> dict:
    import urllib.request

    import requests

    def ban(orig, *a, **kw):
        attempts.append(repr(a[:2])[:160])
        raise ReplayNetworkError("network access attempted during offline replay")
    return {(requests.Session, "request"): ban, (urllib.request, "urlopen"): ban}


# ── OpenSSL store clock for the AMD chain ────────────────────────────────────────────────────

class _CryptoProxy:
    """Stands in for ``OpenSSL.crypto`` inside verify_sev: X509Store() honours the pinned clock."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def X509Store(self):  # noqa: N802 - mirrors the pyOpenSSL name
        store = self._real.X509Store()
        when = _sdkpatch.pinned_now()
        if when is not None:
            store.set_time(when.astimezone(timezone.utc).replace(tzinfo=None))
        return store


_install_lock = threading.Lock()


def _install_clocks() -> None:
    from tinfoil.attestation import cert_utils, collateral_tdx, verify_sev
    _sdkpatch.install_clock(collateral_tdx, cert_utils)
    with _install_lock:
        if not isinstance(verify_sev.crypto, _CryptoProxy):
            verify_sev.crypto = _CryptoProxy(verify_sev.crypto)


# ── stage attribution ────────────────────────────────────────────────────────────────────────

def _attributing(checks: _Checks, key: str):
    def override(orig, *a, **kw):
        try:
            out = orig(*a, **kw)
        except Exception as exc:
            checks.failed(key, f"{type(exc).__name__}: {exc}")
            raise
        if out is False:
            checks.failed(key, f"{getattr(orig, '__name__', key)} returned False")
        else:
            checks.passed(key)
        return out
    return override


def _sev_stages(checks: _Checks) -> dict:
    from tinfoil.attestation import attestation_sev, verify_sev
    return {
        (attestation_sev, "Report"): _attributing(checks, "hardware_signature"),
        (verify_sev.CertificateChain, "from_report"): _attributing(checks, "cert_chain"),
        (verify_sev.CertificateChain, "verify_chain"): _attributing(checks, "cert_chain"),
        (verify_sev, "_verify_report_signature"): _attributing(checks, "hardware_signature"),
        (attestation_sev, "validate_report"): _attributing(checks, "tcb_policy"),
    }


def _tdx_stages(checks: _Checks, evidence: dict) -> dict:
    from tinfoil.attestation import attestation_tdx, collateral_tdx, verify_tdx
    return {
        (attestation_tdx, "parse_quote"): _attributing(checks, "hardware_signature"),
        (verify_tdx, "verify_pck_chain"): _attributing(checks, "cert_chain"),
        (attestation_tdx, "verify_tdx_quote"): _attributing(checks, "hardware_signature"),
        (attestation_tdx, "validate_tdx_policy"): _attributing(checks, "tcb_policy"),
        (collateral_tdx, "fetch_collateral"): _stored_collateral(checks, evidence),
        (collateral_tdx, "check_collateral_freshness"): _attributing(checks, "collateral_fresh_at_capture"),
        (collateral_tdx, "validate_certificate_revocation"): _attributing(checks, "cert_chain"),
        (collateral_tdx, "validate_tcb_status"): _attributing(checks, "tcb_policy"),
        (collateral_tdx, "validate_tdx_module_identity"): _attributing(checks, "tcb_policy"),
        (collateral_tdx, "validate_qe_identity"): _attributing(checks, "tcb_policy"),
    }


def _stored_collateral(checks: _Checks, evidence: dict):
    """Replaces fetch_collateral: rebuild TdxCollateral from stored bytes, re-verifying every Intel
    signature exactly as the SDK does after a download (fetch_tcb_info / fetch_qe_identity /
    fetch_pck_crl / fetch_root_ca_crl)."""
    def override(orig, pck_extensions, pck_cert, *a, **kw):
        from cryptography import x509
        from tinfoil.attestation import cert_utils, collateral_tdx as c
        try:
            t = evidence.get("tdx") or {}
            for k in ("tcb_info_raw_b64", "tcb_info_issuer_chain_pem", "qe_identity_raw_b64",
                      "qe_identity_issuer_chain_pem", "pck_crl_pem", "pck_crl_ca_type",
                      "pck_crl_issuer_chain_pem", "root_crl_der_b64"):
                if not t.get(k):
                    raise c.CollateralError(f"stored collateral lacks {k}")
            tcb_raw = _b64d(t["tcb_info_raw_b64"])
            tcb = c.parse_tcb_info_response(tcb_raw)
            tcb_chain = cert_utils.parse_pem_chain(t["tcb_info_issuer_chain_pem"].encode())
            c.verify_tcb_info_signature(tcb_raw, tcb, tcb_chain)
            if str(tcb.tcb_info.fmspc).lower() != str(pck_extensions.fmspc).lower():
                raise c.CollateralError("stored TCB info is for a different FMSPC than the quote's PCK")
            qe_raw = _b64d(t["qe_identity_raw_b64"])
            qe = c.parse_qe_identity_response(qe_raw)
            qe_chain = cert_utils.parse_pem_chain(t["qe_identity_issuer_chain_pem"].encode())
            c.verify_qe_identity_signature(qe_raw, qe, qe_chain)
            ca_type = c._determine_pck_ca_type(pck_cert)
            if ca_type != t["pck_crl_ca_type"]:
                raise c.CollateralError(f"stored PCK CRL is for CA {t['pck_crl_ca_type']}, quote needs {ca_type}")
            pck_crl = x509.load_pem_x509_crl(t["pck_crl_pem"].encode())
            c._verify_crl_signature(pck_crl, cert_utils.parse_pem_chain(t["pck_crl_issuer_chain_pem"].encode()),
                                    ca_type)
            root_crl = x509.load_der_x509_crl(_b64d(t["root_crl_der_b64"]))
            c._verify_root_crl_signature(root_crl)
            out = c.TdxCollateral(
                tcb_info=tcb, qe_identity=qe, tcb_info_raw=tcb_raw, qe_identity_raw=qe_raw,
                pck_crl=c.PckCrl(crl=pck_crl, ca_type=ca_type, next_update=pck_crl.next_update_utc),
                root_crl=c.RootCrl(crl=root_crl, next_update=root_crl.next_update_utc),
                tcb_info_issuer_chain=tcb_chain, qe_identity_issuer_chain=qe_chain)
        except Exception as exc:
            checks.failed("cert_chain", f"stored collateral: {type(exc).__name__}: {exc}")
            raise
        checks.passed("cert_chain")
        return out
    return override


# ── Sigstore from the stored trust root ──────────────────────────────────────────────────────

def _load_trusted_root(evidence: dict, trust_root_dir: Path | None, supplied=None) -> tuple[bytes, str]:
    """(bytes, source). A supplied root (bytes or a path) is independent of the evidence; otherwise the
    evidence's own content-addressed root is used and reported as "from_evidence"."""
    if supplied is not None:
        return (bytes(supplied) if isinstance(supplied, (bytes, bytearray)) else Path(supplied).read_bytes()), \
            "supplied"
    tr = evidence.get("trusted_root") or {}
    digest = tr.get("sha256")
    if not digest:
        raise ValueError("evidence has no trusted root")
    path = Path(trust_root_dir) / f"{digest}.json" if trust_root_dir else Path(tr.get("path") or "")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("stored trusted root does not match its recorded sha256")
    return data, "from_evidence"


def _sigstore_verifier_override(trusted_root_bytes: bytes) -> dict:
    from sigstore.models import TrustedRoot
    from sigstore.verify import Verifier
    from sigstore_models.trustroot.v1 import TrustedRoot as _InnerTrustedRoot

    def production(orig, *a, **kw):
        return Verifier(trusted_root=TrustedRoot(_InnerTrustedRoot.from_json(trusted_root_bytes)))
    return {(Verifier, "production"): production}


# ── replay ───────────────────────────────────────────────────────────────────────────────────

def replay(evidence: dict, *, expected_repo: str | None = TINFOIL_ROUTER_REPO,
           expected_repo_id: str | int | None = None, expected_owner_id: str | int | None = None,
           expected_fingerprints: tuple[str, str] | None = None, trusted_root: Path | str | bytes | None = None,
           as_of=None, trust_root_dir: Path | str | None = None) -> ReplayResult:
    """Re-run the captured verification offline, checking IDENTITY as well as validity: the Sigstore
    policy is evaluated against ``expected_repo`` (not the evidence's own repo), ``expected_fingerprints``
    = (code, enclave) must match the recomputed ones, and ``trusted_root`` (bytes or path) is used
    instead of the evidence's own root when given. Never raises; problems surface as failed checks.
    ``captured_at`` and the default ``as_of`` come from the evidence (see NOT_ESTABLISHED)."""
    checks = _Checks()
    ev = evidence if isinstance(evidence, dict) else {}
    out: dict[str, Any] = {"code_fingerprint": None, "enclave_fingerprint": None, "release_tag": None,
                           "tls_key_fp": None, "hpke_public_key": None, "repo": ev.get("repo"),
                           "enclave_host_asserted": ev.get("enclave_host"), "platform": ev.get("platform"),
                           "captured_at_asserted": ev.get("captured_at")}
    opts = {"expected_repo": expected_repo, "expected_fingerprints": expected_fingerprints,
            "trusted_root": trusted_root, "expected_repo_id": expected_repo_id,
            "expected_owner_id": expected_owner_id}
    try:
        when = _as_datetime(as_of if as_of is not None else (evidence.get("captured_at")
                                                             or evidence.get("captured_at_unix")))
    except Exception:
        when = datetime.now(timezone.utc)
        checks.failed("hardware_signature", "evidence: no usable captured_at / as_of")
        return _result(checks, out, when)
    try:
        _replay(evidence, checks, out, when, Path(trust_root_dir) if trust_root_dir else None, opts)
    except Exception as exc:  # defensive: anything unattributed fails the first unrun check
        for key in CHECK_KEYS:
            if not checks.touched(key):
                checks.failed(key, f"{type(exc).__name__}: {exc}")
                break
    return _result(checks, out, when)


def _result(checks: _Checks, out: dict, when: datetime) -> ReplayResult:
    vals = dict(checks.values)
    ok = all(v is True or (isinstance(v, str) and (v.startswith("n/a:") or v in REPO_IDENTITY_PASSING))
             for k, v in vals.items() if k not in INFORMATIONAL_CHECKS)
    return ReplayResult(ok=ok, checks=vals, as_of=when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                        sdk_version=_sdk_version(), **out)


def _repo_identity(checks: _Checks, out: dict, bundle: bytes, opts: dict, evidence_repo: str) -> None:
    """Bind the release signature to the repository by NUMERIC id, not only by name (names can be
    renamed or transferred): Fulcio's Source Repository Identifier (1.15) and Owner Identifier (1.17)."""
    try:
        ident = policy_check.fulcio_identity(bundle)
    except Exception as exc:
        checks.failed("repo_identity", f"cannot read the signing certificate: {type(exc).__name__}: {exc}")
        return
    for k in ("build_signer_uri", "source_commit", "log_index", "integrated_time"):
        out[k] = ident.get(k)
    out["source_repo_id"], out["source_owner_id"] = ident.get("repo_id"), ident.get("owner_id")
    expected_repo = opts.get("expected_repo")
    name = ident.get("repository") or evidence_repo
    if expected_repo and name != expected_repo:
        checks.failed("repo_identity", f"certificate repository {name or '(none)'} is not the expected {expected_repo}")
        return
    want = {"repo_id": opts.get("expected_repo_id"), "owner_id": opts.get("expected_owner_id")}
    if all(v is None for v in want.values()):
        checks.values["repo_identity"] = "name only (ids not supplied)"
        checks._touched.add("repo_identity")
        return
    if not ident.get("has_certificate"):
        checks.failed("repo_identity", "bundle carries no signing certificate to read repository ids from")
        return
    for key, expected in want.items():
        if expected is None:
            continue
        got = ident.get(key)
        if got is None or str(got) != str(expected):
            checks.failed("repo_identity", f"certificate {key} {got or '(absent)'} is not the expected {expected}")
            return
    checks.values["repo_identity"] = "name+id"
    checks._touched.add("repo_identity")


def _replay(ev: dict, checks: _Checks, out: dict, when: datetime, trust_root_dir: Path | None,
            opts: dict) -> None:
    expected_repo = opts.get("expected_repo")
    repo = (ev.get("repo") if isinstance(ev, dict) else None) or ""
    if expected_repo is None:
        checks.na("repo_match", "no expected_repo given")
    elif repo == expected_repo:
        checks.passed("repo_match")
    else:
        checks.failed("repo_match", f"repo {repo or '(none)'} is not the expected {expected_repo}")
    if not isinstance(ev, dict) or ev.get("schema") != EVIDENCE_SCHEMA:
        checks.failed("hardware_signature", f"evidence: schema is not {EVIDENCE_SCHEMA}")
        return
    from tinfoil import sigstore as tf_sigstore
    from tinfoil.attestation.attestation_sev import verify_sev_attestation_v2
    from tinfoil.attestation.attestation_tdx import verify_tdx_attestation_v2, verify_tdx_hardware
    from tinfoil.attestation.bundle import verify_certificate
    from tinfoil.attestation import Document
    from tinfoil.attestation.types import PredicateType

    _install_clocks()
    attempts: list = []
    claims = ev.get("claims") or {}
    att = ev.get("attestation") or {}
    release = ev.get("release") or {}
    out["release_tag"] = release.get("tag")
    policy_repo = expected_repo or repo  # Sigstore identity policy uses the EXPECTED repo

    try:
        doc = Document(format=PredicateType(att["format"]), body=att["body"])
    except Exception as exc:
        checks.failed("hardware_signature", f"evidence: attestation unusable: {exc}")
        return
    is_tdx = doc.format == PredicateType.TDX_GUEST_V2

    base = _network_ban(attempts)
    stages = _tdx_stages(checks, ev) if is_tdx else _sev_stages(checks)
    with _sdkpatch.overrides({**base, **stages}), _sdkpatch.pinned_clock(when):
        # 1) hardware attestation (signature, chain, policy, TDX collateral)
        try:
            if is_tdx:
                enclave = verify_tdx_attestation_v2(doc.body)
            else:
                sev = ev.get("sev") or {}
                if not sev.get("vcek_der_b64"):
                    checks.failed("cert_chain", "evidence: no stored VCEK")
                    return
                enclave = verify_sev_attestation_v2(doc.body, vcek_der=_b64d(sev["vcek_der_b64"]))
        except Exception as exc:
            if not checks.first_failure():
                checks.failed("hardware_signature", f"{type(exc).__name__}: {exc}")
            return
        for key in ("hardware_signature", "cert_chain", "tcb_policy"):
            if not checks.touched(key):
                checks.passed(key)
        if not is_tdx:
            checks.na("collateral_fresh_at_capture", "SEV-SNP has no Intel collateral")
            checks.na("hardware_platform_match", "SEV-SNP")
        out["enclave_fingerprint"] = enclave.measurement.fingerprint()
        out["tls_key_fp"] = enclave.public_key_fp
        out["hpke_public_key"] = enclave.hpke_public_key

        # 2) report_data keys == what the client used
        if claims.get("tls_public_key_fp") == enclave.public_key_fp and \
                claims.get("hpke_public_key") == enclave.hpke_public_key:
            checks.passed("report_data_keys")
        else:
            checks.failed("report_data_keys", "report_data keys differ from the keys recorded at capture")

        # 3) TLS certificate binding (only if captured)
        pem = ev.get("tls_cert_pem")
        if not pem:
            checks.na("tls_cert_binding", "TLS certificate not captured on the ehbp path")
        else:
            try:
                verify_certificate(pem, ev.get("enclave_host") or "", doc, enclave.hpke_public_key or "")
                checks.passed("tls_cert_binding")
            except Exception as exc:
                checks.failed("tls_cert_binding", exc)

        # 4) code signature from the stored trust root
        try:
            root, source = _load_trusted_root(ev, trust_root_dir, opts.get("trusted_root"))
        except Exception as exc:
            checks.failed("code_signature", f"trusted root: {exc}")
            return
        checks.values["trust_root_source"] = source
        checks._touched.add("trust_root_source")
        with _sdkpatch.overrides(_sigstore_verifier_override(root)):
            try:
                bundle = (ev.get("sigstore_bundle") or "").encode("utf-8")
                code = tf_sigstore.verify_attestation(bundle, release.get("digest") or "", policy_repo,
                                                    release.get("tag"))
                checks.passed("code_signature")
            except Exception as exc:
                checks.failed("code_signature", exc)
                return
            out["code_fingerprint"] = code.fingerprint()
            _repo_identity(checks, out, bundle, opts, repo)

            # 5) measurement match + the fingerprints recorded at capture
            try:
                code.assert_equal(enclave.measurement)
                if claims.get("code_fingerprint") != out["code_fingerprint"] or \
                        claims.get("enclave_fingerprint") != out["enclave_fingerprint"]:
                    raise ValueError("recomputed fingerprints differ from those recorded at capture")
                exp = opts.get("expected_fingerprints")
                if exp is not None and tuple(exp) != (out["code_fingerprint"], out["enclave_fingerprint"]):
                    raise ValueError("recomputed fingerprints differ from expected_fingerprints")
                checks.passed("measurement_match")
            except Exception as exc:
                checks.failed("measurement_match", f"{type(exc).__name__}: {exc}")

            # 6) TDX hardware platform
            if is_tdx:
                hw = ev.get("hardware_measurements") or {}
                try:
                    hms = tf_sigstore.verify_hardware_measurements(
                        (hw.get("bundle") or "").encode("utf-8"), hw.get("digest") or "",
                        HARDWARE_MEASUREMENTS_REPO)  # never the evidence's own repo field
                    verify_tdx_hardware(hms, enclave.measurement)
                    checks.passed("hardware_platform_match")
                except Exception as exc:
                    checks.failed("hardware_platform_match", f"{type(exc).__name__}: {exc}")
    if attempts:  # belt and braces: a banned call that was swallowed somewhere still fails the replay
        checks.failed("hardware_signature", f"network access attempted during replay: {attempts[0]}")

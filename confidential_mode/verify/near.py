"""NEAR AI Cloud adapter for the attested tier (https://cloud-api.near.ai, OpenAI-compatible).

What one ``verify()`` does (all over plain HTTPS to the configured host, plus one GET to Intel):
  1. a client nonce N (32 random bytes, hex);
  2. GET /v1/attestation/report?nonce=N&signing_algo=ed25519&include_tls_fingerprint=true (gateway),
     recording the TLS peer certificate of that connection;
  3. for every allowed model M: GET /v1/attestation/report?model=M&provider=near&nonce=N&signing_algo=
     ed25519&include_tls_fingerprint=false with header x-no-aliasing: true (model-serving reports);
  4. GET /v1/attestation/ita-token?nonce=N&signing_algo=ed25519[&model=M] (Intel Trust Authority JWTs);
  5. GET the Intel JWKS (one of near_checks.ITA_JWKS_URLS only).
Attestation requests carry no API key (NEAR documents them as public). The bytes are kept as evidence
(schema ``confidential-mode/near-evidence/v2``; v1 still appraises under v1 rules) and appraised by
``appraise()``, the same function the offline replay runs (verify/replay_near.py). Any failed required
check raises VerifyError. Large texts (each app_compose, each compose_manager_attestation) sit in the
evidence's ``blobs`` by SHA-256; the ledger moves them to ``<data_dir>/evidence/blobs/`` and keeps
``blob_refs``, and a JSON receipt embeds them again (ledger.py, receipts.py).

What the checks establish, and with which key:
  * gateway: its TDX quote verifies to Intel's SGX root; report data binds the gateway signing key, the
    raw SPKI fingerprint of its TLS certificate and N; MRCONFIGID equals SHA-256 of the app_compose
    the report carries; the event log replays to RTMR3; the TLS certificate this client saw has that
    SPKI fingerprint. Intel Trust Authority's token (signature checked against the JWKS, whose x5c chain
    must end at a pinned Intel root) adds Intel's TCB status for the gateway platform and must name the
    same signing key, N, MRCONFIGID, MRTD and RTMR0-2.
  * each model: every candidate report's quote verifies; report data binds the model signing key and N;
    MRCONFIGID and RTMR3 as above. At least one candidate per allowed model. app_id, instance_id,
    os_image_hash and the KMS key are read from the RTMR3 events (an ``info`` value that differs fails).
  * each model candidate's compose_manager_attestation (near_checks.check_compose_manager): its quote
    verifies and its event log replays; MRTD and RTMR0-3 equal the model quote's; report data is
    actions_hash || N with nonce_source "client"; the actions log hashes to actions_hash; the log replays
    into a per-service map, restricted to the model's prompt-path services. This establishes that a TD of
    this instance reported this actions log for this nonce, that the log's hash is bound in a hardware
    quote, and that the map is what the operator's own tooling reported. It does not establish that the
    inner compose is measured or that the reported services are the ones running. The running
    compose-manager image is compared with the measured one and a mismatch is recorded (cm_image,
    informational), never a pass. With require_provider_tee a candidate without the block fails.
Not established here (see replay_near.NOT_ESTABLISHED): the model CVM's TCB status, GPU evidence
binding, image provenance, what runs after launch, and anything about a specific serving instance.

Identity mapping for pins (docs/INTERFACES.md Amendment 5):
  vendor              "near"
  router_repo         "<host>#<model,model,...>" (sorted allowlist), the identity a pin is keyed by
  code_fingerprint    SHA-256 of canonical JSON {"gateway": [compose_hash], "models": {M: sorted compose
                      hashes}}: what MRCONFIGID measures, the docker-compose (image digests) each CVM runs
  enclave_fingerprint SHA-256 of canonical JSON of "MRTD:RTMR0:RTMR1:RTMR2" per CVM (firmware, kernel,
                      initrd and command line), gateway and every model candidate, sorted
  release_tag         None: NEAR publishes no signed release tag for a deployment
RTMR3 (instance id, key provider) and the signing keys are checked per verify but kept out of the
fingerprints, since they differ per instance.

Signed responses: every POST to /chat/completions or /responses through this adapter's views is sent
with ``x-no-aliasing: true`` and ``accept-encoding: identity`` and recorded as an exchange: SHA-256 of
the exact request body bytes, SHA-256 of the response body bytes as received (after any content
decoding, before any parsing; for SSE that is every byte of every ``data:`` line and blank line,
``[DONE]`` included, which is what NEAR signs), and the completion id (``id`` of the JSON body, or of
the first SSE event carrying one; ``response.id`` for Responses streams). When the body ends, the
adapter fetches GET /v1/signature/<id>?signing_algo=ed25519 with the request's own Authorization
header, retrying 404 until ``signature_wait_seconds`` (default 5 s) after the body ended, and judges it
with near_checks.check_signature. A body closed before its end (an interrupted stream) gets no fetch,
because NEAR records no signature for it. One ledger row of kind ``send_signed`` is written per
exchange through ``event_sink``; the gate's send context (sendctx.py) supplies session and purpose.

Request encryption (``encrypt``, config confidential.near.encrypt, default true; near_e2ee.py): the only
POST that leaves is chat completions, rebuilt as a new request whose body has every field of NEAR's table
sealed to the one verified model key (``model_public_key``), with a fresh Ed25519 client key held on the
exchange. Streaming, non-text parts, unlisted top-level text and every other POST raise VerifyError
before sending. The digests are over the ciphertext bytes, which is what NEAR signs (live probe,
2026-11-07). The reply is buffered, hashed and finished first; it is decrypted and handed over only when
the send is fully attested (a verified provider_tee signature over those digests, on the attested TLS
connection). HTTP 421 means the gateway no longer accepts the model key: the adapter holds and asks the
cache to re-verify.

TLS: inference sends and signature fetches use pools pinned at the handshake to the SPKI fingerprint the
accepted gateway quote binds (``pinned_ssl_context``); the attestation GETs use an unpinned pool.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote as _urlquote
from urllib.parse import urlsplit

import httpx
import openai

from .. import sendctx
from . import near_checks as nc
from .base import VerificationResult, VerifyError

logger = logging.getLogger(__name__)

VENDOR = "near"
DEFAULT_BASE_URL = "https://cloud-api.near.ai/v1"
EVIDENCE_SCHEMA_V1 = "confidential-mode/near-evidence/v1"
EVIDENCE_SCHEMA = "confidential-mode/near-evidence/v2"
EVIDENCE_SCHEMAS = (EVIDENCE_SCHEMA_V1, EVIDENCE_SCHEMA)
VERIFIER = "confidential-mode near_checks/1 (TDX quote via tinfoil 0.14.2, ITA JWT via cryptography)"
DEFAULT_ACCEPTED_TCB = ("UpToDate",)
DEFAULT_SIGNATURE_WAIT_SECONDS = 5.0
DEFAULT_REVERIFY_BACKOFF_SECONDS = 30.0   # at most one 421- or pin-triggered re-attestation per window
SIGNABLE_SUFFIXES = ("/chat/completions", "/responses")
NO_ALIASING_HEADER = "x-no-aliasing"
MAX_ID_BUFFER = 8 * 1024 * 1024
MAX_SEALED_BODY = 32 * 1024 * 1024   # an unstreamed encrypted response is buffered whole before release
CHECK_KEYS = ("schema", "gateway_quote", "gateway_tls_binding", "ita_jwks", "ita_gateway_token",
              "model_quotes", *nc.CM_CHECK_KEYS, "ita_model_tokens", "fingerprints")
# cm_image compares the running compose-manager image with the measured one: a mismatch is recorded and
# shown in the pin prompt, never a pass and never a verification failure (NEAR's own launcher swaps the
# image after boot on every instance seen, 2026-11-07).
INFORMATIONAL_CHECKS = ("ita_model_tokens", "cm_image")
CM_NOT_RUN_V1 = "n/a: not run (evidence schema v1 carries no compose-manager attestation)"


# ── evidence ────────────────────────────────────────────────────────────────────────────────────

def _tcb_info(report: Mapping) -> Mapping:
    info = report.get("info") if isinstance(report.get("info"), Mapping) else {}
    tcb = info.get("tcb_info")
    if isinstance(tcb, str):
        tcb = json.loads(tcb)
    return tcb if isinstance(tcb, Mapping) else {}


def blob_text(value: Any) -> str:
    """The canonical text a JSON value is stored as in the evidence blob store (sorted keys, compact)."""
    return nc.canonical(value)


def put_blob(blobs: dict, text: str) -> str:
    """Add ``text`` to ``blobs`` under its SHA-256 (lower-case hex); returns that id."""
    h = nc.sha256_hex(text.encode("utf-8"))
    blobs[h] = text
    return h


BLOB_REF = "$blob"   # {"$blob": <sha256>} stands for a string kept in the evidence's blobs


def _ref(blobs: dict, value: Any) -> Any:
    return {BLOB_REF: put_blob(blobs, value)} if isinstance(value, str) and value else value


def _blobify(evidence: dict, blobs: dict) -> None:
    """Move the remaining large strings (every TDX quote, every Intel Trust Authority token) into ``blobs``,
    leaving {"$blob": id} in their place, so a ledger row stays small for any allowlist size."""
    reps = [evidence.get("gateway")] + [c for cs in (evidence.get("model_reports") or {}).values() for c in cs]
    for rep in reps:
        if isinstance(rep, dict):
            rep["intel_quote_b64"] = _ref(blobs, rep.get("intel_quote_b64"))
    ita = evidence.get("ita") or {}
    ita["gateway_token"] = _ref(blobs, ita.get("gateway_token"))
    ita["model_tokens"] = {m: [_ref(blobs, t) for t in toks] for m, toks in (ita.get("model_tokens") or {}).items()}


def resolve_blobs(value: Any, blobs: Mapping) -> Any:
    """``value`` with every {"$blob": id} replaced by that blob's text (None when the blob is missing)."""
    if isinstance(value, Mapping):
        if set(value) == {BLOB_REF}:
            return blobs.get(value[BLOB_REF])
        return {k: resolve_blobs(v, blobs) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_blobs(v, blobs) for v in value]
    return value


def trim_report(report: Mapping, blobs: dict) -> dict:
    """The fields of one NEAR report the checks use. Large texts go into ``blobs`` by SHA-256: the
    app_compose (its id is the compose hash) and, for a model candidate, the whole
    compose_manager_attestation as canonical JSON (its id is recorded under ``compose_manager.blob``)."""
    info = report.get("info") if isinstance(report.get("info"), Mapping) else {}
    app_compose = _tcb_info(report).get("app_compose")
    compose_hash = None
    if isinstance(app_compose, str):
        compose_hash = put_blob(blobs, app_compose)
    quote_hex = report.get("intel_quote")
    out = {
        "signing_address": report.get("signing_address"), "signing_algo": report.get("signing_algo"),
        "request_nonce": report.get("request_nonce"), "report_data": report.get("report_data"),
        "intel_quote_b64": base64.b64encode(bytes.fromhex(quote_hex)).decode("ascii") if isinstance(quote_hex, str) else None,
        "event_log_imr3": nc.imr3_events(report.get("event_log") or []),
        "compose_hash": compose_hash, "app_name": info.get("app_name"), "app_id": info.get("app_id"),
        "instance_id": info.get("instance_id"), "os_image_hash": info.get("os_image_hash"),
        "key_provider_info": info.get("key_provider_info"),
    }
    for key in ("tls_cert_fingerprint", "model_name", "signing_public_key"):
        if report.get(key) is not None:
            out[key] = report.get(key)
    payload = report.get("nvidia_payload")
    if isinstance(payload, str):
        out["nvidia_payload_sha256"] = nc.sha256_hex(payload.encode("utf-8"))
        out["nvidia_payload_bytes"] = len(payload.encode("utf-8"))
    elif report.get("nvidia_payload_sha256"):
        out["nvidia_payload_sha256"] = report["nvidia_payload_sha256"]
        out["nvidia_payload_bytes"] = report.get("nvidia_payload_bytes")
    cm = report.get("compose_manager_attestation")
    if isinstance(cm, Mapping):
        text = blob_text(cm)
        out["compose_manager"] = {"blob": put_blob(blobs, text), "bytes": len(text.encode("utf-8"))}
    return out


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_evidence(raw: Mapping, *, base_url: str, models: list[str], nonce: str, captured_at_unix: float,
                   tls_observation: Mapping | None) -> dict:
    """Evidence (JSON-serialisable, every blob a string) from the parsed public responses."""
    blobs: dict[str, str] = {}
    errors = list(raw.get("errors") or [])
    gateway = None
    gw_raw = raw.get("gateway_report")
    try:
        if isinstance(gw_raw, Mapping) and isinstance(gw_raw.get("gateway_attestation"), Mapping):
            gateway = trim_report(gw_raw["gateway_attestation"], blobs)
    except Exception as exc:
        errors.append(f"gateway_report: {type(exc).__name__}: {exc}"[:300])
    model_reports: dict[str, list] = {}
    for model in models:
        rep = (raw.get("model_reports") or {}).get(model)
        try:
            cands = rep.get("model_attestations") if isinstance(rep, Mapping) else None
            model_reports[model] = [trim_report(c, blobs) for c in (cands or []) if isinstance(c, Mapping)]
        except Exception as exc:
            errors.append(f"model_report[{model}]: {type(exc).__name__}: {exc}"[:300])
            model_reports[model] = []
    ita = {"gateway_token": None, "model_tokens": {}, "jwks_url": None}
    for key, resp in (raw.get("ita") or {}).items():
        if not isinstance(resp, Mapping):
            continue
        if ita["gateway_token"] is None and isinstance((resp.get("gateway") or {}).get("token"), str):
            ita["gateway_token"] = resp["gateway"]["token"]
        ita["jwks_url"] = ita["jwks_url"] or resp.get("jwks_url")
        if key:
            ita["model_tokens"][key] = [m.get("token") for m in (resp.get("models") or [])
                                        if isinstance(m, Mapping) and isinstance(m.get("token"), str)]
    host = urlsplit(base_url).hostname or ""
    _blobify({"gateway": gateway, "model_reports": model_reports, "ita": ita}, blobs)
    evidence = {
        "schema": EVIDENCE_SCHEMA, "vendor": VENDOR, "base_url": base_url, "enclave_host": host,
        "platform": "tdx", "sdk_version": VERIFIER, "nonce": nonce, "signing_algo": nc.SIGNING_ALGO,
        "models": list(models),
        "captured_at": _iso(captured_at_unix), "captured_at_unix": captured_at_unix,
        "gateway": gateway, "model_reports": model_reports, "blobs": blobs, "blob_refs": sorted(blobs), "ita": ita,
        "jwks": raw.get("jwks") if isinstance(raw.get("jwks"), Mapping) else None,
        "jwks_url_fetched": raw.get("jwks_url_fetched"),
        "tls_observation": dict(tls_observation) if tls_observation else None,
    }
    missing = [k for k, v in (("gateway", gateway), ("ita.gateway_token", ita["gateway_token"]),
                              ("jwks", evidence["jwks"]), ("tls_observation", evidence["tls_observation"])) if not v]
    missing += [f"model_reports[{m}]" for m in models if not model_reports.get(m)]
    evidence["capture_complete"] = not missing and not errors
    evidence["capture_missing"] = missing
    if errors:
        evidence["capture_errors"] = errors
    return evidence


# ── appraisal (shared with the offline replay) ─────────────────────────────────────────────────

@dataclass(frozen=True)
class Appraisal:
    ok: bool
    checks: dict
    code_fingerprint: str | None = None
    enclave_fingerprint: str | None = None
    identity: str | None = None
    gateway_signer: str | None = None
    model_signers: dict = field(default_factory=dict)
    components: tuple = ()
    tcb_status: str | None = None
    first_failure: str | None = None
    # per CVM: role, app_id, instance_id, compose_hash, signing_address, os_image_hash, kms_id, services,
    # services_scope, cm_image_running, cm_image_measured (v2 evidence; the last four are None for the gateway)
    cvms: tuple = ()


def identity_for(host: str, models: list[str]) -> str:
    return f"{host}#{','.join(sorted(models)) if models else 'gateway-only'}"


def _measure(q: Mapping) -> str:
    return ":".join(str(q.get(k) or "") for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2"))


def _cvm(role: str, rep: Mapping, ident: Mapping | None = None, cm: Mapping | None = None) -> dict:
    """What identifies one CVM in the evidence. With v2 evidence, app_id, instance_id, os_image_hash and
    kms_id come from the RTMR3 events (``ident``), and a model CVM adds what its compose-manager reported
    (``cm``). W12 pins these."""
    ident = ident or {}
    cm = cm or {}
    return {"role": role, "app_id": ident.get("app_id", rep.get("app_id")),
            "instance_id": ident.get("instance_id", rep.get("instance_id")),
            "compose_hash": rep.get("compose_hash"), "signing_address": str(rep.get("signing_address") or "").lower(),
            "os_image_hash": ident.get("os_image_hash"), "kms_id": ident.get("kms_id"),
            "services": cm.get("services"), "services_scope": cm.get("services_scope"),
            "cm_image_running": cm.get("cm_image_running"), "cm_image_measured": cm.get("cm_image_measured")}


def _app_name(composes: Mapping, h: str | None) -> str:
    try:
        name = json.loads(composes.get(h) or "{}").get("name")
        return f" ({name})" if isinstance(name, str) and name else ""
    except Exception:
        return ""


def verified_blobs(evidence: Mapping) -> dict:
    """The evidence's blobs whose SHA-256 is their id (a blob that does not hash to its id is dropped, so
    every check that needs it fails)."""
    blobs = evidence.get("blobs") if isinstance(evidence.get("blobs"), Mapping) else {}
    return {k: v for k, v in blobs.items()
            if isinstance(k, str) and isinstance(v, str) and nc.sha256_hex(v.encode("utf-8")) == k}


def _short_ref(ref: str | None) -> str:
    if not ref:
        return "(none recorded)"
    repo, _, digest = ref.partition("@sha256:")
    return f"{repo}@sha256:{digest[:16]}..." if digest else ref[:80]


def _cvm_lines(c: Mapping) -> list[str]:
    """Pin-prompt lines for one CVM. Lines that begin "reported: " are what the model CVM's compose-manager
    reported after launch, not measurements; the prompt shows them under their own heading."""
    role = c["role"].replace("model:", "model ", 1)
    iid = str(c.get("instance_id") or "?")[:12]
    out = [f"{role} instance {iid}: app_id {c.get('app_id')}, os image {str(c.get('os_image_hash'))[:16]}..., "
           f"KMS key sha256:{str(c.get('kms_id'))[:16]}... (recorded in RTMR3)"]
    if c.get("services") is None:
        return out
    out.append(f"reported: {role} instance {iid}: services ({c.get('services_scope')}):"
               + ("" if c["services"] else " none"))
    for key, v in c["services"].items():
        out.append(f"reported:   {key} {v.get('tag') or '(no tag)'} commit {str(v.get('commit'))[:12]} "
                   f"file sha256:{str(v.get('file_sha256'))[:16]}...")
    run, meas = c.get("cm_image_running"), c.get("cm_image_measured")
    verdict = "same as measured" if run and run == meas else \
        "MISMATCH: the running compose-manager is not the measured one"
    out.append(f"reported: {role} instance {iid}: compose-manager running {_short_ref(run)}; measured "
               f"{_short_ref(meas)} ({verdict})")
    return out


def appraise(evidence: Mapping, *, as_of: float | None = None, quote_verifier: nc.QuoteVerifier | None = None,
             ita_roots: Mapping[str, str] | None = None, accepted_tcb=DEFAULT_ACCEPTED_TCB,
             require_tls_binding: bool = True, require_compose_manager: bool = True) -> Appraisal:
    """Every check over one evidence blob, offline. Values: True, or "fail: ...", "n/a: ...",
    "not_run: ..."; informational checks never decide ``ok``. Schema v1 evidence is appraised under v1
    rules: the compose-manager checks are reported as not run, and identity values are not bound to RTMR3.
    ``require_compose_manager`` (the adapter passes require_provider_tee) makes a model candidate without a
    compose_manager_attestation fail."""
    checks: dict[str, Any] = {k: "not_run: an earlier check failed" for k in CHECK_KEYS}
    qv = quote_verifier or nc.default_quote_verifier
    roots = ita_roots if ita_roots is not None else nc.ITA_ROOT_SHA256
    out: dict[str, Any] = {"model_signers": {}}

    def done(fail: str | None = None) -> Appraisal:
        ok = all(v is True or (isinstance(v, str) and v.startswith("n/a")) for k, v in checks.items()
                 if k not in INFORMATIONAL_CHECKS)
        return Appraisal(ok=ok and fail is None, checks=checks, first_failure=fail, **out)

    if not isinstance(evidence, Mapping) or evidence.get("schema") not in EVIDENCE_SCHEMAS:
        checks["schema"] = f"fail: not {' or '.join(EVIDENCE_SCHEMAS)}"
        return done(checks["schema"])
    if evidence.get("signing_algo") != nc.SIGNING_ALGO:
        checks["schema"] = "fail: signing_algo is not ed25519"
        return done(checks["schema"])
    checks["schema"] = True
    v1 = evidence.get("schema") == EVIDENCE_SCHEMA_V1
    nonce = str(evidence.get("nonce") or "")
    if v1:
        composes = evidence.get("app_composes") if isinstance(evidence.get("app_composes"), Mapping) else {}
        for k in nc.CM_CHECK_KEYS:
            checks[k] = CM_NOT_RUN_V1
    else:
        composes = verified_blobs(evidence)
        evidence = {k: (resolve_blobs(v, composes) if k in ("gateway", "model_reports", "ita") else v)
                    for k, v in evidence.items()}
    at = float(as_of if as_of is not None else evidence.get("captured_at_unix") or 0)
    models = [m for m in (evidence.get("models") or []) if isinstance(m, str)]

    def ident(rep: Mapping) -> dict | None:
        return None if v1 else nc.rtmr3_identity(rep)

    gw = evidence.get("gateway") if isinstance(evidence.get("gateway"), Mapping) else None
    try:
        if gw is None:
            raise nc.CheckError("no gateway report captured")
        gwq = nc.check_report(gw, nonce=nonce, app_composes=composes, quote_verifier=qv,
                              tls_cert_fingerprint=gw.get("tls_cert_fingerprint"))
        cvms = [_cvm("gateway", gw, ident(gw))]
        checks["gateway_quote"] = True
        out["gateway_signer"] = str(gw.get("signing_address")).lower()
    except Exception as exc:
        checks["gateway_quote"] = f"fail: {exc}"[:320]
        return done(checks["gateway_quote"])

    obs = evidence.get("tls_observation") if isinstance(evidence.get("tls_observation"), Mapping) else None
    fp = (gw.get("tls_cert_fingerprint") or "").lower()
    if obs and obs.get("spki_sha256"):
        checks["gateway_tls_binding"] = True if fp and str(obs["spki_sha256"]).lower() == fp else \
            "fail: the TLS certificate this client saw is not the one the gateway quote binds"
    elif require_tls_binding:
        checks["gateway_tls_binding"] = "fail: no TLS peer certificate was recorded"
    else:
        checks["gateway_tls_binding"] = "n/a: TLS binding not required by config"

    ita = evidence.get("ita") if isinstance(evidence.get("ita"), Mapping) else {}
    try:
        keys = nc.jwks_keys(evidence.get("jwks") or {}, roots=roots, at=nc.utc(at))
        checks["ita_jwks"] = True
    except Exception as exc:
        checks["ita_jwks"] = f"fail: {exc}"[:320]
        keys = None
    if keys is not None:
        try:
            claims = nc.verify_jwt(ita.get("gateway_token") or "", keys, at=at)
            t = nc.tdx_claims(claims)
            if t.get("attester_type") != "TDX":
                raise nc.CheckError(f"attester_type {t.get('attester_type')!r} is not TDX")
            if t.get("tdx_is_debuggable") is not False:
                raise nc.CheckError("Intel reports the gateway TD as debuggable (or does not say)")
            status = t.get("attester_tcb_status")
            out["tcb_status"] = status if isinstance(status, str) else None
            if status not in tuple(accepted_tcb):
                raise nc.CheckError(f"TCB status {status!r} not accepted ({', '.join(accepted_tcb)})")
            rd = t.get("attester_runtime_data") if isinstance(t.get("attester_runtime_data"), Mapping) else {}
            if str(rd.get("caller_nonce") or "").lower() != nonce.lower():
                raise nc.CheckError("ITA runtime data does not carry the client nonce")
            if str(rd.get("signing_address") or "").lower() != out["gateway_signer"] or \
                    rd.get("signing_algo") != nc.SIGNING_ALGO:
                raise nc.CheckError("ITA runtime data names another gateway signing key")
            for claim, field_ in (("tdx_mrconfigid", "mr_config_id"), ("tdx_mrtd", "mrtd"), ("tdx_rtmr0", "rtmr0"),
                                  ("tdx_rtmr1", "rtmr1"), ("tdx_rtmr2", "rtmr2")):
                if str(t.get(claim) or "").lower() != str(gwq.get(field_) or "").lower():
                    raise nc.CheckError(f"ITA {claim} differs from the gateway quote")
            checks["ita_gateway_token"] = True
        except Exception as exc:
            checks["ita_gateway_token"] = f"fail: {exc}"[:320]

    model_quotes: dict[str, list] = {}
    idents: dict[tuple, dict | None] = {}
    try:
        for model in models:
            cands = (evidence.get("model_reports") or {}).get(model) or []
            if not cands:
                raise nc.CheckError(f"no model report for {model}")
            for i, cand in enumerate(cands):
                if cand.get("model_name") not in (None, model):
                    raise nc.CheckError(f"{model}[{i}]: report names model {cand.get('model_name')!r}")
                try:
                    q = nc.check_report(cand, nonce=nonce, app_composes=composes, quote_verifier=qv,
                                        require_signing_public_key=True)
                    idents[(model, i)] = ident(cand)
                except nc.CheckError as exc:
                    raise nc.CheckError(f"{model}[{i}]: {exc}") from exc
                model_quotes.setdefault(model, []).append((cand, q))
            signers = sorted({str(c.get("signing_address")).lower() for c, _ in model_quotes[model]})
            if len(signers) != 1:
                # Requests are encrypted to the model key and signatures are judged against it: candidates
                # naming different keys are refused, never resolved by picking one.
                raise nc.CheckError(f"{model}: its {len(model_quotes[model])} verified reports name {len(signers)} "
                                    "different signing keys; refused rather than picking one")
            out["model_signers"][model] = signers
        checks["model_quotes"] = True if models else "n/a: no model allowlisted (gateway only)"
    except Exception as exc:
        checks["model_quotes"] = f"fail: {exc}"[:320]

    cm_results: dict[tuple, dict] = {}
    if not v1 and checks["model_quotes"] is True:
        cm_results = _compose_manager_checks(checks, evidence, composes, models, model_quotes, nonce=nonce,
                                             quote_verifier=qv, required=require_compose_manager)
    elif not v1 and str(checks["model_quotes"]).startswith("n/a"):
        for k in nc.CM_CHECK_KEYS:
            checks[k] = "n/a: no model allowlisted (gateway only)"

    if keys is None or not ita.get("model_tokens"):
        checks["ita_model_tokens"] = "n/a: no model-provider token captured"
    else:
        notes = []
        for model, tokens in (ita.get("model_tokens") or {}).items():
            for tok in tokens or []:
                try:
                    c = nc.verify_jwt(tok, keys, at=at)
                    gpu = (c.get("nvgpu") or {}).get("x-nvidia-overall-att-result")
                    notes.append(f"{model}: GPU verdict {gpu!r}")
                except Exception as exc:
                    notes.append(f"{model}: {exc}")
        checks["ita_model_tokens"] = ("recorded (its TDX claims are the gateway's; not bound to the model CVM): "
                                      + "; ".join(notes))[:320]

    if all(checks[k] is True or str(checks[k]).startswith("n/a") for k in ("gateway_quote", "model_quotes")):
        for m in models:
            for i, (c, _) in enumerate(model_quotes.get(m, [])):
                cvms.append(_cvm(f"model:{m}", c, idents.get((m, i)), cm_results.get((m, i))))
        code = {"gateway": [gw.get("compose_hash")],
                "models": {m: sorted({c.get("compose_hash") for c, _ in model_quotes.get(m, [])}) for m in models}}
        enclave = {"gateway": [_measure(gwq)],
                   "models": {m: sorted({_measure(q) for _, q in model_quotes.get(m, [])}) for m in models}}
        out["code_fingerprint"] = nc.sha256_hex(nc.canonical(code).encode("utf-8"))
        out["enclave_fingerprint"] = nc.sha256_hex(nc.canonical(enclave).encode("utf-8"))
        out["identity"] = identity_for(str(evidence.get("enclave_host") or ""), models)
        comps = [f"gateway compose sha256:{str(gw.get('compose_hash'))[:16]}...{_app_name(composes, gw.get('compose_hash'))}"]
        for m in models:
            for h in code["models"][m]:
                comps.append(f"model {m} compose sha256:{str(h)[:16]}...{_app_name(composes, h)}")
        if not v1:
            for c in cvms:
                comps += _cvm_lines(c)
        out["components"] = tuple(comps)
        out["cvms"] = tuple(cvms)
        claims = evidence.get("claims") if isinstance(evidence.get("claims"), Mapping) else None
        if claims and (claims.get("code_fingerprint"), claims.get("enclave_fingerprint")) != (
                out["code_fingerprint"], out["enclave_fingerprint"]):
            checks["fingerprints"] = "fail: recomputed fingerprints differ from the evidence's claims"
        else:
            checks["fingerprints"] = True
    fail = next((v for k, v in checks.items() if k not in INFORMATIONAL_CHECKS
                 and isinstance(v, str) and v.startswith(("fail", "not_run"))), None)
    return done(fail)


def _compose_manager_checks(checks: dict, evidence: Mapping, blobs: Mapping, models: list[str],
                            model_quotes: Mapping, *, nonce: str, quote_verifier, required: bool) -> dict:
    """Run near_checks.check_compose_manager for every verified model candidate and fold the per-step
    outcomes into ``checks``. Returns {(model, index): result} for the candidates that passed."""
    steps = nc.CM_CHECK_KEYS
    per_step: dict[str, list] = {k: [] for k in steps}   # (outcome, text); outcome pass | fail | not_run | skip
    results: dict[tuple, dict] = {}
    for model in models:
        for i, (cand, q) in enumerate(model_quotes.get(model, [])):
            where = f"{model}[{i}]"
            ref = cand.get("compose_manager") if isinstance(cand.get("compose_manager"), Mapping) else None
            text = blobs.get(ref.get("blob")) if ref else None
            if text is None:
                why = ("its report carries no compose_manager_attestation" if ref is None else
                       "its compose_manager_attestation blob is missing or does not hash to its id")
                outcome = "fail" if required or ref is not None else "skip"
                for k in steps:
                    per_step[k].append((outcome if k == "cm_quote" or outcome == "skip" else "not_run",
                                        f"{where}: {why}"))
                continue
            try:
                res = nc.check_compose_manager(json.loads(text), nonce=nonce, model_quote=q,
                                               quote_verifier=quote_verifier, model=model,
                                               app_compose=blobs.get(cand.get("compose_hash")))
            except nc.CmCheckError as exc:
                failed = steps.index(exc.step)
                for j, k in enumerate(steps):
                    per_step[k].append(("pass", "") if j < failed else
                                       ("fail", f"{where}: {exc}") if j == failed else
                                       ("not_run", f"{where}: an earlier compose-manager check failed"))
                continue
            except Exception as exc:
                for j, k in enumerate(steps):
                    per_step[k].append(("fail", f"{where}: {type(exc).__name__}: {exc}") if j == 0 else
                                       ("not_run", f"{where}: an earlier compose-manager check failed"))
                continue
            results[(model, i)] = res
            for k in steps:
                per_step[k].append(("pass", ""))
            if not res["cm_image_match"]:
                per_step["cm_image"][-1] = ("recorded", f"{where}: running {_short_ref(res['cm_image_running'])} is "
                                            f"not the measured {_short_ref(res['cm_image_measured'])}")
    for k in steps:
        items = per_step[k]
        fails = [t for o, t in items if o == "fail"]
        if fails:
            checks[k] = f"fail: {fails[0]}"[:320]
        elif any(o == "not_run" for o, _ in items):
            checks[k] = "not_run: " + next(t for o, t in items if o == "not_run")[:300]
        elif any(o == "recorded" for o, _ in items):
            checks[k] = ("recorded (not a pass): " + "; ".join(t for o, t in items if o == "recorded"))[:320]
        elif items and all(o == "skip" for o, _ in items):
            checks[k] = ("n/a: no compose_manager_attestation captured, and it is not required "
                         "(require_provider_tee is off)")
        elif any(o == "skip" for o, _ in items):
            checks[k] = ("n/a: passed where captured; " + next(t for o, t in items if o == "skip")
                         + " (not required: require_provider_tee is off)")[:320]
        else:
            checks[k] = True
    return results


def evidence_claims(evidence: Mapping, a: Appraisal) -> dict:
    gw = evidence.get("gateway") if isinstance(evidence.get("gateway"), Mapping) else {}
    return {"code_fingerprint": a.code_fingerprint, "enclave_fingerprint": a.enclave_fingerprint,
            "release_tag": None, "identity": a.identity, "tls_public_key_fp": gw.get("tls_cert_fingerprint"),
            "hpke_public_key": None, "gateway_signer": a.gateway_signer, "model_signers": a.model_signers,
            "components": list(a.components), "tcb_status": a.tcb_status, "cvms": [dict(c) for c in a.cvms]}


# ── the adapter ─────────────────────────────────────────────────────────────────────────────────

def _peer_der(response) -> bytes | None:
    from .tinfoil import peer_certificate_der
    try:
        return peer_certificate_der(response)
    except Exception:
        return None


def _spki_sha256(der: bytes) -> str:
    from .tinfoil import spki_sha256
    return spki_sha256(der)


class NearRefusal(VerifyError, openai.OpenAIError):
    """A refusal raised from the NEAR transport. It is an ``openai.OpenAIError``, which the OpenAI SDK
    re-raises as is (no retry, no APIConnectionError wrapping); the attested profile's
    ``classify_api_error`` hook (provider.classify_refusal) tells Hermes' loop what to do with it.

    ``status_code`` and ``body`` are set when the gateway answered with an HTTP error (not 200): they are
    unauthenticated and only steer local recovery (backoff, compression), never what is released. A retry
    is a new encrypted exchange; only a 200 that is fully attested and decrypts is ever handed over."""

    def __init__(self, message: str, *, status_code: int | None = None, body: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body or {}


def _refusal(exc: BaseException) -> NearRefusal:
    return exc if isinstance(exc, NearRefusal) else NearRefusal(str(exc) or type(exc).__name__)


class TLSPinMismatch(VerifyError):
    """The TLS peer of an inference connection is not the certificate the verified gateway quote binds."""


def _default_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def pinned_ssl_context(expected_spki: Callable[[], str | None], *,
                       base: Callable[[], ssl.SSLContext] | None = None,
                       required: Callable[[], bool] = lambda: True) -> ssl.SSLContext:
    """An SSL context that keeps the normal chain and host-name checks and adds one: right after the
    handshake, and before httpcore writes a request byte, the peer certificate's SPKI SHA-256 must equal
    ``expected_spki()`` (the fingerprint the verified gateway quote binds). A mismatch, an unreadable peer
   certificate, or no expected fingerprint (unless ``required()`` is false) raises TLSPinMismatch and the
    connection is closed.

    Same mechanism as the Tinfoil SDK (tinfoil/client.py ``_create_socket_wrapper``/``_create_bio_wrapper``):
    the sync httpcore backend completes the handshake inside ``wrap_socket``; the async (anyio) backend and
    TLS-in-TLS proxying drive an ``SSLObject`` from ``wrap_bio``, whose ``do_handshake`` is wrapped."""
    ctx = (base or _default_context)()
    orig_wrap_socket, orig_wrap_bio = ctx.wrap_socket, ctx.wrap_bio

    def check(der: bytes | None) -> None:
        want = expected_spki()
        if not want:
            if not required():
                return  # confidential.near.require_tls_binding: false and no fingerprint was attested
            raise TLSPinMismatch("no attested gateway TLS fingerprint to pin this connection to")
        got = _spki_sha256(der) if der else None
        if got != str(want).lower():
            raise TLSPinMismatch("the TLS certificate of this connection is not the one the verified gateway "
                                 "quote binds; refused before sending")

    def wrap_socket(*args, **kwargs):
        sock = orig_wrap_socket(*args, **kwargs)
        try:
            check(sock.getpeercert(True))
        except BaseException:
            try:
                sock.close()
            finally:
                raise
        return sock

    def wrap_bio(*args, **kwargs):
        obj = orig_wrap_bio(*args, **kwargs)
        orig_handshake = obj.do_handshake

        def do_handshake():
            result = orig_handshake()
            check(obj.getpeercert(True))
            return result
        obj.do_handshake = do_handshake
        return obj

    ctx.wrap_socket = wrap_socket
    ctx.wrap_bio = wrap_bio
    return ctx


class NearAdapter:
    """VendorAdapter for NEAR AI Cloud. See the module docstring."""

    vendor = VENDOR

    def __init__(self, *, data_dir: Path | str, base_url: str = DEFAULT_BASE_URL, models: list[str] | tuple = (),
                 require_provider_tee: bool = True, require_tls_binding: bool = True,
                 accepted_tcb_statuses=DEFAULT_ACCEPTED_TCB,
                 signature_wait_seconds: float = DEFAULT_SIGNATURE_WAIT_SECONDS,
                 transport_factory: Callable[[], httpx.BaseTransport] | None = None,
                 async_transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
                 send_transport_factory: Callable[[], httpx.BaseTransport] | None = None,
                 quote_verifier: nc.QuoteVerifier | None = None, ita_roots: Mapping[str, str] | None = None,
                 hold_until_accepted: bool = True, encrypt: bool = True,
                 reverify_backoff_seconds: float = DEFAULT_REVERIFY_BACKOFF_SECONDS,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep):
        parts = urlsplit(base_url or "")
        if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
            raise ValueError("confidential.near.base_url must be an https URL without query or fragment")
        self.data_dir = Path(data_dir)
        self._base_url = base_url.rstrip("/")
        self.host = parts.hostname
        self.models = sorted({m for m in models if isinstance(m, str) and m.strip()})
        self.require_provider_tee = bool(require_provider_tee)
        self.require_tls_binding = bool(require_tls_binding)
        self.accepted_tcb = tuple(accepted_tcb_statuses or DEFAULT_ACCEPTED_TCB)
        self.signature_wait_seconds = max(0.0, float(signature_wait_seconds))
        self.encrypt = bool(encrypt)   # confidential.near.encrypt; the preflight refuses a lock with it off
        self.on_stale: Callable[[], None] | None = None   # set by the verification cache (provider.py)
        self.reverify_backoff_seconds = max(0.0, float(reverify_backoff_seconds))
        self._last_stale_mono: float | None = None
        # Attestation GETs use an unpinned pool: their certificate is what the quote is checked against
        # (gateway_tls_binding). Inference sends and signature fetches (both carry the API key) use pools
        # whose every handshake is pinned to the verified gateway's TLS fingerprint. Tests inject one
        # factory for both.
        self._transport_factory = transport_factory or (lambda: httpx.HTTPTransport(retries=0))
        self._send_transport_factory = send_transport_factory or transport_factory or self.default_send_transport
        self._async_transport_factory = async_transport_factory or self.default_async_transport
        self._quote_verifier = quote_verifier
        self._ita_roots = ita_roots
        self._clock, self._sleep = clock, sleep
        self._lock = threading.RLock()
        self._sync_transport: httpx.BaseTransport | None = None
        self._attest_transport: httpx.BaseTransport | None = None
        self._inflight: dict[int, int] = {}            # id(send pool) -> requests in flight on it
        self._retired: list[httpx.BaseTransport] = []  # dropped pools waiting for their last request
        self._async_transports: dict[int, tuple[asyncio.AbstractEventLoop, httpx.AsyncBaseTransport]] = {}
        self._accepted: VerificationResult | None = None
        self._appraisal: Appraisal | None = None
        self.verified_mono: float | None = None
        self.event_sink: Callable[[dict], None] | None = None
        self._hold_until_accepted = hold_until_accepted
        self.held_reason: str | None = None
        self.provider_name = "attested-near"
        self.attestation_count = 0

    # ── VendorAdapter surface ───────────────────────────────────────────────────────────────────
    @property
    def enclave_host(self) -> str:
        return self.host

    @property
    def base_url(self) -> str:
        return self._base_url

    def resolve_enclave_host(self) -> str:
        return self.host

    @property
    def last_result(self) -> VerificationResult | None:
        return self._accepted

    @property
    def identity(self) -> str:
        return identity_for(self.host, self.models)

    def default_send_transport(self) -> httpx.BaseTransport:
        return httpx.HTTPTransport(retries=0, verify=pinned_ssl_context(
            self.pinned_spki, required=lambda: self.require_tls_binding))

    def default_async_transport(self) -> httpx.AsyncBaseTransport:
        return httpx.AsyncHTTPTransport(retries=0, verify=pinned_ssl_context(
            self.pinned_spki, required=lambda: self.require_tls_binding))

    def pinned_spki(self) -> str | None:
        """The TLS SPKI fingerprint the accepted gateway quote binds (lower-case hex), or None."""
        acc = self._accepted
        fp = (((acc.evidence or {}).get("gateway") or {}).get("tls_cert_fingerprint") if acc else None)
        return str(fp).lower() if isinstance(fp, str) and fp else None

    def _pool(self) -> httpx.BaseTransport:
        """The pinned pool for inference sends and signature fetches."""
        with self._lock:
            if self._sync_transport is None:
                self._sync_transport = self._send_transport_factory()
            return self._sync_transport

    def _attest_pool(self) -> httpx.BaseTransport:
        with self._lock:
            if self._attest_transport is None:
                self._attest_transport = self._transport_factory()
            return self._attest_transport

    def _acquire(self) -> tuple[httpx.BaseTransport, Callable[[], None]]:
        """The current send pool, counted as in use until the returned release() is called (once)."""
        with self._lock:
            t = self._pool()
            self._inflight[id(t)] = self._inflight.get(id(t), 0) + 1
        done = [False]

        def release() -> None:
            if done[0]:
                return
            done[0] = True
            close = False
            with self._lock:
                n = self._inflight.get(id(t), 0) - 1
                if n > 0:
                    self._inflight[id(t)] = n
                else:
                    self._inflight.pop(id(t), None)
                    if any(r is t for r in self._retired):
                        self._retired = [r for r in self._retired if r is not t]
                        close = True
            if close:
                _close_quietly(t)
        return t, release

    def _drop_send_pools(self) -> None:
        """A newly accepted TLS fingerprint, a 421 or a pin mismatch: new requests get a fresh pool; the old
        one is closed once the requests other threads still have in flight on it have finished."""
        with self._lock:
            t, self._sync_transport = self._sync_transport, None
            self._async_transports.clear()
            if t is None:
                return
            if self._inflight.get(id(t), 0) > 0:
                self._retired.append(t)
                return
        _close_quietly(t)

    def _get(self, client: httpx.Client, path: str, params: dict, headers: dict | None = None):
        url = f"{self._base_url}/{path}"
        with client.stream("GET", url, params=params, headers={"accept": "application/json", **(headers or {})}) as r:
            body = r.read()
            der = _peer_der(r)
        if r.status_code != 200:
            raise VerifyError(f"GET {path} returned HTTP {r.status_code}")
        try:
            return json.loads(body), der
        except ValueError as exc:
            raise VerifyError(f"GET {path} returned invalid JSON") from exc

    def capture(self, nonce: str) -> tuple[dict, dict | None]:
        """The public attestation responses for ``nonce`` (network). Raises VerifyError."""
        raw: dict = {"model_reports": {}, "ita": {}, "errors": []}
        client = httpx.Client(transport=_NonClosing(self._attest_pool()), timeout=30.0, follow_redirects=False)
        tls = None
        try:
            base = {"nonce": nonce, "signing_algo": nc.SIGNING_ALGO}
            raw["gateway_report"], der = self._get(client, "attestation/report",
                                                   {**base, "include_tls_fingerprint": "true"})
            if der is not None:
                tls = {"captured": True, "spki_sha256": _spki_sha256(der)}
                try:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(der)
                    tls.update(issuer=cert.issuer.rfc4514_string(), subject=cert.subject.rfc4514_string(),
                               not_after=cert.not_valid_after_utc.isoformat())
                except Exception:
                    pass
            for model in self.models:
                raw["model_reports"][model], _ = self._get(
                    client, "attestation/report",
                    {**base, "model": model, "provider": "near", "include_tls_fingerprint": "false"},
                    {NO_ALIASING_HEADER: "true"})
            for model in (self.models or [""]):
                params = {**base, **({"model": model} if model else {})}
                raw["ita"][model], _ = self._get(client, "attestation/ita-token", params,
                                                 {NO_ALIASING_HEADER: "true"} if model else None)
            jwks_url = next((r.get("jwks_url") for r in raw["ita"].values() if isinstance(r, Mapping)), None)
            if jwks_url not in nc.ITA_JWKS_URLS:
                jwks_url = nc.ITA_JWKS_URLS[0]  # never fetch keys from a URL the vendor chose
            with client.stream("GET", jwks_url) as r:
                body = r.read()
            if r.status_code != 200:
                raise VerifyError(f"Intel JWKS returned HTTP {r.status_code}")
            raw["jwks"], raw["jwks_url_fetched"] = json.loads(body), jwks_url
        except VerifyError:
            raise
        except Exception as exc:
            raise VerifyError(f"NEAR attestation capture failed: {type(exc).__name__}: {exc}"[:300]) from exc
        finally:
            client.close()
        return raw, tls

    def verify(self) -> VerificationResult:
        try:
            with self._lock:
                self.attestation_count += 1
                if self.require_provider_tee and not self.models:
                    raise VerifyError("require_provider_tee is on but no NEAR model is allowlisted "
                                      "(confidential.near.models, or model.default with provider attested-near)")
                nonce = secrets.token_hex(32)
                raw, tls = self.capture(nonce)
                now = self._clock()
                evidence = build_evidence(raw, base_url=self._base_url, models=self.models, nonce=nonce,
                                          captured_at_unix=now, tls_observation=tls)
                a = appraise(evidence, quote_verifier=self._quote_verifier, ita_roots=self._ita_roots,
                             accepted_tcb=self.accepted_tcb, require_tls_binding=self.require_tls_binding,
                             require_compose_manager=self.require_provider_tee)
                evidence["checks"] = a.checks
                evidence["policy"] = {"require_tls_binding": self.require_tls_binding,
                                      "require_provider_tee": self.require_provider_tee,
                                      "accepted_tcb_statuses": list(self.accepted_tcb)}
                if not a.ok:
                    raise VerifyError(f"NEAR attestation did not verify: {a.first_failure}"[:300])
                evidence["claims"] = evidence_claims(evidence, a)
                evidence["repo"] = a.identity
                result = VerificationResult(
                    vendor=VENDOR, router_repo=a.identity or self.identity, enclave_host=self.host,
                    code_fingerprint=a.code_fingerprint or "", enclave_fingerprint=a.enclave_fingerprint or "",
                    release_tag=None, verifier=VERIFIER, verified_at_host_clock=now, evidence=evidence)
                prev = self._appraisal
                if prev is not None:
                    changed = sorted(m for m in self.models
                                     if prev.model_signers.get(m) and prev.model_signers.get(m) != a.model_signers.get(m))
                    if changed:
                        # The key requests are encrypted to is not yet covered by a pin (W12). Until it is, a
                        # key change inside one process is refused rather than adopted silently.
                        m = changed[0]
                        raise VerifyError(
                            f"NEAR model signing key for {m} changed from {prev.model_signers[m][0][:16]}... to "
                            f"{(a.model_signers.get(m) or ['?'])[0][:16]}...; refused: requests are encrypted to "
                            "this key and pins do not cover it yet. Check the new report, then restart Hermes to "
                            "accept it")
                old_pin = self.pinned_spki()
                self._accepted, self._appraisal = result, a
                if old_pin is not None and old_pin != self.pinned_spki():
                    self._drop_send_pools()
                self.verified_mono = time.monotonic()
                if self._hold_until_accepted:
                    self.held_reason = "verification not yet accepted against pins"
                return result
        except VerifyError:
            raise
        except Exception as exc:
            raise VerifyError(f"NEAR attestation failed: {type(exc).__name__}: {exc}"[:300]) from exc

    def hold(self, reason: str) -> None:
        self.held_reason = reason or "held"

    def release(self) -> None:
        self.held_reason = None

    def _check_not_held(self) -> None:
        if self.held_reason is not None:
            raise VerifyError(f"attested transport held: {self.held_reason}")

    def sync_http_view(self) -> httpx.Client:
        if self._accepted is None:
            raise VerifyError("sync_http_view() before a successful verify()")
        return httpx.Client(transport=_SyncView(self), follow_redirects=False)

    def _async_pool(self) -> httpx.AsyncBaseTransport:
        loop = asyncio.get_running_loop()
        with self._lock:
            for key in [k for k, (lp, _) in self._async_transports.items() if lp.is_closed()]:
                self._async_transports.pop(key, None)
            entry = self._async_transports.get(id(loop))
            if entry is None or entry[0] is not loop:
                entry = (loop, self._async_transport_factory())
                self._async_transports[id(loop)] = entry
            return entry[1]

    def async_http_for_loop(self) -> httpx.AsyncClient:
        if self._accepted is None:
            raise VerifyError("async_http_for_loop() before a successful verify()")
        self._async_pool()
        return httpx.AsyncClient(transport=_AsyncView(self), follow_redirects=False)

    def close(self) -> None:
        with self._lock:
            ts = [self._sync_transport, self._attest_transport]
            self._sync_transport = self._attest_transport = None
            self._async_transports.clear()
        for t in ts:
            if t is None:
                continue
            try:
                t.close()
            except Exception:
                pass

    # ── exchanges and signatures ───────────────────────────────────────────────────────────────
    def _check_request(self, request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host != self.host:
            raise VerifyError(f"request to {request.url.host!r} is not the attested NEAR host")

    def encryption_ready(self) -> tuple[bool, str]:
        """(True, "") when request encryption can run (PyNaCl imports); else the reason."""
        from . import near_e2ee
        return near_e2ee.available()

    def model_public_key(self, model: str | None) -> str:
        """The one verified Ed25519 key of ``model`` (appraise refuses candidates naming different keys).
        Requests are encrypted to it; it is taken only from a candidate that passed every check."""
        a = self._appraisal
        keys = (a.model_signers.get(model) if (a and model) else None) or []
        if len(keys) != 1:
            raise VerifyError(f"no single verified model key for {model!r}; refused before sending")
        return keys[0]

    def mark_stale(self, reason: str) -> bool:
        """The gateway says the model key is no longer valid (HTTP 421), or a send met a certificate other
        than the attested one: hold the transport, drop the adapter's own acceptance and have the cache
        re-verify on the next call. At most once per ``reverify_backoff_seconds`` (the trigger is not
        authenticated, so the gateway must not be able to force an attestation per turn). Returns whether
        a re-verify was requested."""
        now = time.monotonic()
        with self._lock:
            if self._last_stale_mono is not None and now - self._last_stale_mono < self.reverify_backoff_seconds:
                return False
            self._last_stale_mono = now
        self._drop_send_pools()
        self.hold(reason)
        self.verified_mono = None
        cb = self.on_stale
        if cb is not None:
            try:
                cb()
            except Exception:
                logger.warning("confidential-mode: could not invalidate the NEAR verification", exc_info=True)
        return True

    def begin_exchange(self, request: httpx.Request) -> "_Exchange | None":
        """Classify one request before it is sent. Returns None for a request that carries no conversation
        (GET), an _Exchange for a signable POST (whose ``request`` is what to send), and raises VerifyError
        for anything refused. While encrypting, the only POST that leaves is chat completions, encrypted;
        while ``require_provider_tee`` (or encrypting), any POST outside the signable set is refused
        (codebase review medium 11: it would skip the model allowlist and the signature record)."""
        path = request.url.path
        if request.method in ("GET", "HEAD", "OPTIONS") and not request.content:
            return None
        if request.method != "POST" or not path.endswith(SIGNABLE_SUFFIXES):
            if self.encrypt or self.require_provider_tee:
                raise VerifyError(f"{request.method} {path} is refused through attested-near: only chat "
                                  "completions leave while encryption or require_provider_tee is on; "
                                  "refused before sending")
            return None
        if self.encrypt and not path.endswith("/chat/completions"):
            raise VerifyError(f"POST {path} is refused: NEAR's encryption does not cover the Responses API; "
                              "only chat completions leave while confidential.near.encrypt is on")
        request.headers[NO_ALIASING_HEADER] = "true"
        request.headers["accept-encoding"] = "identity"
        body = request.content  # bytes for every request the OpenAI client builds (read() was called)
        model, stream, parsed = None, False, None
        try:
            parsed = json.loads(body)
            model = parsed.get("model") if isinstance(parsed.get("model"), str) else None
            stream = parsed.get("stream") is True
        except Exception:
            parsed = None
        if self.require_provider_tee and model not in self.models:
            raise VerifyError(f"model {model!r} is not an attested NEAR model on the allowlist "
                              "(confidential.near.models); refused before sending")
        acc = self._accepted
        ex = _Exchange(adapter=self, path=path, model=model, stream=stream,
                       request_sha256="", request_bytes=0,
                       authorization=request.headers.get("authorization"), context=sendctx.current() or {},
                       attestation_nonce=((acc.evidence or {}).get("nonce") if acc else None),
                       code_fingerprint=acc.code_fingerprint if acc else None,
                       responses_api=path.endswith("/responses"))
        if self.encrypt:
            request, body = self._encrypt(request, parsed, model, stream, ex)
        ex.request = request
        ex.request_sha256, ex.request_bytes = hashlib.sha256(body).hexdigest(), len(body)
        return ex

    def _encrypt(self, request: httpx.Request, parsed: Any, model: str | None, stream: bool,
                 ex: "_Exchange") -> tuple[httpx.Request, bytes]:
        """A new request carrying the encrypted body (plan section 3). Any failure raises VerifyError
        before a byte is sent; nothing is ever sent in plaintext instead."""
        from . import near_e2ee as e2
        try:
            if not isinstance(parsed, dict):
                raise VerifyError("the request body is not a JSON object")
            if stream:
                raise VerifyError("streaming is refused while encrypting: NEAR signs streamed completions "
                                  "with the gateway key only, so decrypted streamed output would be "
                                  "unauthenticated (send unstreamed)")
            model_pub = self.model_public_key(model)
            client = e2.ClientKey.generate()
            new_body, report = e2.encrypt_request(parsed, model_pub)
            raw = json.dumps(new_body, ensure_ascii=False).encode("utf-8")
            headers = httpx.Headers({k: v for k, v in request.headers.multi_items()
                                     if k.lower() not in ("content-length", "transfer-encoding")})
            for k, v in e2.request_headers(client.public_hex, model_pub).items():
                headers[k] = v
            headers["accept-encoding"] = "identity"
            new = httpx.Request(request.method, request.url, headers=headers, content=raw,
                                extensions=dict(request.extensions))
        except VerifyError as exc:
            raise VerifyError(f"NEAR request refused before sending: {exc}") from exc
        except e2.E2EEError as exc:
            raise VerifyError(f"NEAR request refused before sending: {exc}") from exc
        except Exception as exc:
            raise VerifyError(f"NEAR request refused before sending: encryption failed "
                              f"({type(exc).__name__})") from exc
        ex.encrypted, ex.client_key, ex.model_pub, ex.e2ee_report = True, client, model_pub, report
        return new, raw

    def fetch_signature(self, chat_id: str, authorization: str | None, *, deadline: float) -> dict:
        """{"status": "fetched", "json": {...}} or {"status": "missing"/"unavailable"/"error", "reason": ...}."""
        url = f"{self._base_url}/signature/{_urlquote(chat_id, safe='').replace('.', '%2E')}"
        headers = {"accept": "application/json"}
        if authorization:
            headers["authorization"] = authorization
        pool, release_pool = self._acquire()
        client = httpx.Client(transport=_NonClosing(pool), timeout=max(1.0, self.signature_wait_seconds),
                              follow_redirects=False)
        try:
            while True:
                try:
                    r = client.get(url, params={"signing_algo": nc.SIGNING_ALGO}, headers=headers)
                except Exception as exc:
                    if time.monotonic() >= deadline:
                        return {"status": "error", "reason": f"fetch failed: {type(exc).__name__}"}
                    self._sleep(0.5)
                    continue
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except ValueError:
                        return {"status": "error", "reason": "signature response is not JSON"}
                    if isinstance(data, Mapping) and not ({"text", "signature", "signing_address"} & set(data)):
                        return {"status": "unavailable",
                                "reason": f"NEAR reports no signature ({str(data.get('error_code') or '')[:60]}: "
                                          f"{str(data.get('message') or '')[:120]})"}
                    return {"status": "fetched", "json": data}
                if r.status_code == 404 and time.monotonic() < deadline:
                    self._sleep(0.5)
                    continue
                return {"status": "missing" if r.status_code == 404 else "error",
                        "reason": f"HTTP {r.status_code} from /v1/signature"}
        finally:
            client.close()
            release_pool()

    def finish_exchange(self, ex: "_Exchange") -> dict:
        """Fetch (when the body ended), judge and ledger one exchange. Returns the row detail."""
        sig: dict = {"status": "not_fetched", "reason": ex.end_reason or ""}
        if ex.completed and ex.status == 200 and ex.chat_id:
            sig = self.fetch_signature(ex.chat_id, ex.authorization,
                                       deadline=time.monotonic() + self.signature_wait_seconds)
        elif ex.completed and ex.status == 200:
            sig = {"status": "missing", "reason": "response carries no completion id"}
        elif ex.completed:
            sig = {"status": "missing", "reason": f"HTTP {ex.status}: no signature for a failed request"}
        elif ex.stream:
            sig = {"status": "missing", "reason": f"interrupted stream ({ex.end_reason or 'closed before its end'}): "
                                                  "NEAR records no signature"}
        else:
            sig = {"status": "missing", "reason": f"the response did not complete ({ex.end_reason or 'closed before its end'})"}
        a = self._appraisal
        data = sig.get("json") if sig.get("status") == "fetched" else None
        check = nc.check_signature(data, model=ex.model, request_sha256=ex.request_sha256,
                                   response_sha256=ex.response_sha256 if ex.completed else None,
                                   gateway_signer=a.gateway_signer if a else None,
                                   model_signers=(a.model_signers.get(ex.model, []) if (a and ex.model) else []),
                                   require_provider_tee=self.require_provider_tee)
        if data is None:
            check["reason"] = sig.get("reason") or check["reason"]
        signature = {"status": sig.get("status"), "reason": sig.get("reason")}
        if isinstance(data, Mapping):
            signature.update(signature_hex=data.get("signature"), signature_kind=data.get("signature_kind"),
                             signing_algo=data.get("signing_algo"), signing_address=data.get("signing_address"),
                             text=data.get("text"))
        if ex.tls_matches is not True and (self.require_tls_binding or ex.tls_matches is False):
            # The pinned handshake already refuses another certificate; this per-response observation is
            # the record, and a send whose certificate is not the attested one is never "verified".
            check["tls_verified"] = False
            check["verdict"] = "unverified"
            check["reason"] = ("the TLS certificate of this send is not the one the gateway quote binds"
                               if ex.tls_matches is False else
                               "the TLS certificate of this send was not observable") + (
                f"; signature: {check['reason']}" if check.get("reason") else "")
        else:
            check["tls_verified"] = ex.tls_matches is True
        fully = check["verdict"] == "verified" and check["provider_tee_verified"] is True
        detail = {
            "vendor": VENDOR, "source": "near_signature", "chat_id": ex.chat_id, "endpoint": ex.path,
            "stream": ex.stream, "request_sha256": ex.request_sha256, "request_bytes": ex.request_bytes,
            "response_sha256": ex.response_sha256 if ex.completed else None,
            "response_bytes": ex.response_bytes, "response_status": ex.status,
            "response_content_encoding": ex.content_encoding, "body_complete": ex.completed,
            "signature": signature, "check": check, "require_provider_tee": self.require_provider_tee,
            "fully_attested": fully, "attestation_nonce": ex.attestation_nonce,
            "verify_code_fingerprint": ex.code_fingerprint, "tls_spki_sha256": ex.tls_spki_sha256,
            "tls_matches_attested": ex.tls_matches,
            # Request encryption (plugin self-report): which fields left as ciphertext, to which model key.
            "near_e2ee": ex.encrypted,
            "e2ee_fields": list((ex.e2ee_report or {}).get("encrypted_fields") or []),
            "e2ee_field_count": (ex.e2ee_report or {}).get("encrypted_count", 0),
            "dropped_fields": list((ex.e2ee_report or {}).get("dropped_fields") or []),
            # Top-level keys that left in plaintext (names only), besides model and messages' roles and ids.
            "plaintext_keys": list((ex.e2ee_report or {}).get("plaintext_keys") or []),
            "e2ee_version": (ex.e2ee_report or {}).get("encryption_version") if ex.encrypted else None,
            "client_pub": ex.client_key.public_hex if ex.client_key is not None else None,
            "model_pub": ex.model_pub,
            "hashing": "sha256 of the exact request body; sha256 of the response body as received after content "
                       "decoding (SSE framing and [DONE] included)",
        }
        ctx = ex.context or {}
        row = {"kind": "send_signed", "session_id": str(ctx.get("session_id") or ""),
               "purpose": str(ctx.get("purpose") or "unattributed"), "provider": self.provider_name,
               "host": self.host, "model": ex.model or "", "bytes": ex.request_bytes,
               "tier": ctx.get("tier"), "verdict": check["verdict"],
               "decision": (check["kind"] or "missing") if data is not None else "missing", "detail": detail}
        ex.detail = detail
        if ex.encrypted:
            # The row waits for the release decision (decrypted and handed over, or withheld), so a reply
            # that fails to decrypt or times out is never recorded as fully attested.
            ex.pending_row = row
            ex.settle(None)
            return detail
        self._emit_row(row)
        return detail

    def _emit_row(self, row: dict) -> None:
        sink = self.event_sink
        if sink is not None:
            try:
                sink(row)
            except Exception:
                logger.warning("confidential-mode: could not ledger a NEAR signature row", exc_info=True)


def _close_quietly(t) -> None:
    try:
        t.close()
    except Exception:
        pass


class _NonClosing(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner

    def handle_request(self, request):
        return self._inner.handle_request(request)

    def close(self) -> None:
        pass


@dataclass
class _Exchange:
    adapter: NearAdapter
    path: str
    model: str | None
    stream: bool
    request_sha256: str
    request_bytes: int
    authorization: str | None
    context: dict
    attestation_nonce: str | None
    code_fingerprint: str | None
    responses_api: bool = False
    status: int | None = None
    content_encoding: str | None = None
    chat_id: str | None = None
    response_sha256: str | None = None
    response_bytes: int = 0
    completed: bool = False
    finished: bool = False
    end_reason: str | None = None
    tls_spki_sha256: str | None = None
    tls_matches: bool | None = None
    _hash: Any = field(default_factory=hashlib.sha256)
    _buf: bytearray = field(default_factory=bytearray)
    _decoder: Any = None
    _tail: bytes = b""
    saw_done: bool = False
    request: Any = None                 # the httpx.Request actually sent (the encrypted one when encrypting)
    encrypted: bool = False
    client_key: Any = field(default=None, repr=False)   # this exchange's Ed25519 key; memory only
    model_pub: str | None = None
    e2ee_report: dict | None = None
    detail: dict | None = None          # the send_signed row detail, once finished
    keep_body: bool = False
    body: bytearray = field(default_factory=bytearray)
    pending_row: dict | None = None
    outcome: tuple | None = None        # (released: bool, reason: str) for an encrypted exchange
    emitted: bool = False
    _settle_lock: Any = field(default_factory=threading.Lock, repr=False)

    def settle(self, outcome: tuple | None) -> None:
        """Record the release outcome of an encrypted exchange and write its row once both the row (from
        finish) and the outcome (from the view) exist, whichever comes last."""
        with self._settle_lock:
            if outcome is not None and self.outcome is None:
                self.outcome = outcome
            if self.emitted or self.pending_row is None or self.outcome is None:
                return
            self.emitted = True
            row = self.pending_row
        released, reason = self.outcome
        d = row["detail"]
        d["reply_released"] = bool(released)
        d["withheld_reason"] = None if released else str(reason)[:300]
        if not released:
            d["fully_attested"] = False
            if row.get("verdict") == "verified":
                row["verdict"] = "unverified"
                d["check"]["verdict"] = "unverified"
                d["check"]["reason"] = f"reply withheld after the signature check: {reason}"[:300]
        self.adapter._emit_row(row)

    def on_response(self, response: httpx.Response) -> None:
        self.status = response.status_code
        enc = (response.headers.get("content-encoding") or "").strip().lower()
        self.content_encoding = enc or None
        if enc and enc != "identity":
            try:
                from httpx._decoders import SUPPORTED_DECODERS
                self._decoder = SUPPORTED_DECODERS[enc]()
            except Exception:
                self._decoder = None
        der = _peer_der(response)
        if der is not None:
            try:
                self.tls_spki_sha256 = _spki_sha256(der)
                acc = self.adapter._accepted
                fp = (((acc.evidence or {}).get("gateway") or {}).get("tls_cert_fingerprint") if acc else None)
                self.tls_matches = (self.tls_spki_sha256 == str(fp).lower()) if fp else None
            except Exception:
                pass

    def feed(self, chunk: bytes) -> None:
        data = self._decoder.decode(chunk) if self._decoder is not None else chunk
        self._take(data)

    def _take(self, data: bytes) -> None:
        if not data:
            return
        self._hash.update(data)
        self.response_bytes += len(data)
        if self.keep_body:
            if len(self.body) + len(data) > MAX_SEALED_BODY:
                raise VerifyError("encrypted NEAR response exceeds the buffer bound; refused")
            self.body.extend(data)
        if self.stream and not self.saw_done:
            window = self._tail + data
            self.saw_done = b"data: [DONE]" in window
            self._tail = window[-16:]
        if self.chat_id is None and len(self._buf) < MAX_ID_BUFFER:
            self._buf.extend(data)
            if self.stream:
                self._scan_sse()

    def _scan_sse(self) -> None:
        text = bytes(self._buf).decode("utf-8", errors="replace")
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                value = json.loads(payload)
            except ValueError:
                continue  # an incomplete line; the next chunk completes it
            if self.responses_api and isinstance(value, Mapping):
                value = value.get("response") if isinstance(value.get("response"), Mapping) else None
            if isinstance(value, Mapping) and isinstance(value.get("id"), str) and value["id"]:
                self.chat_id = value["id"]
                self._buf.clear()
                return

    def complete(self) -> None:
        if self._decoder is not None:
            try:
                self._take(self._decoder.flush())
            except Exception:
                pass
        self.response_sha256 = self._hash.hexdigest()
        if self.chat_id is None and not self.stream:
            try:
                value = json.loads(bytes(self._buf))
                if isinstance(value, Mapping) and isinstance(value.get("id"), str):
                    self.chat_id = value["id"]
            except ValueError:
                pass
        self._buf = bytearray()
        self.completed = True

    def finish(self, reason: str | None = None) -> None:
        if self.finished:
            return
        self.finished = True
        if reason:
            self.end_reason = reason
        self.adapter.finish_exchange(self)


def _drain_after_done(ex: "_Exchange", nxt: Callable[[], bytes]) -> None:
    """The consumer stopped at ``data: [DONE]`` (the OpenAI SDK does) and closed the body: read the rest of
    the wire bytes so the digest covers the whole body NEAR signed. Bounded by the body itself."""
    try:
        while True:
            ex.feed(nxt())
    except StopIteration:
        ex.complete()
    except Exception as exc:
        ex.end_reason = f"{type(exc).__name__} while draining after [DONE]"


def _already_read(response: httpx.Response, ex: "_Exchange") -> bool:
    """A transport that hands back a response whose body is already in memory (httpx reads a body given as
    bytes at construction): hash that body, already content-decoded, and complete the exchange."""
    try:
        content = response._content
    except AttributeError:
        return False
    ex._decoder = None
    ex._take(content)
    ex.complete()
    return True


_DROP_ON_RELEASE = ("content-length", "content-encoding", "transfer-encoding")


def _error_type(body: bytes) -> str:
    t = _error_body(body).get("error", {}).get("type")
    return f" ({str(t)[:40]})" if isinstance(t, str) and t else ""


def _error_body(body: bytes) -> dict:
    """{"error": {"type", "code", "message"}} clipped, from a gateway error body (unauthenticated)."""
    try:
        err = json.loads(body).get("error")
    except Exception:
        return {}
    if not isinstance(err, Mapping):
        return {}
    return {"error": {k: str(err.get(k))[:300] for k in ("type", "code", "message") if err.get(k) is not None}}


def _release_sealed(adapter: "NearAdapter", ex: "_Exchange", response: httpx.Response) -> httpx.Response:
    """The tail of an encrypted exchange, after the body was buffered, hashed, completed and finished
    (signature fetched and judged). Only one outcome hands a body to the caller: HTTP 200, a send that
    is fully attested (a verified provider_tee signature over these ciphertext digests, on the attested
    TLS connection), and a body that decrypts under this exchange's key. Every other outcome raises
    NearRefusal (no status is synthesised, nothing is retried by the SDK), and the row records it."""
    from . import near_e2ee as e2
    body = bytes(ex.body)
    ex.body = bytearray()
    try:
        status = response.status_code
        if status == 421:
            asked = adapter.mark_stale("NEAR reports the model encryption key is no longer valid (HTTP 421); "
                                       "re-verifying")
            raise NearRefusal("NEAR refused this exchange's model key (HTTP 421: the key is no longer valid); "
                              + ("the verification was invalidated and the next call re-verifies" if asked else
                                 "a re-verification ran less than confidential.near.reverify_backoff_seconds ago"),
                              status_code=421, body=_error_body(body))
        if status != 200:
            # Any status but 200, success-looking 2xx included, carries nothing the plugin can authenticate.
            raise NearRefusal(f"NEAR reply refused: HTTP {status}{_error_type(body)}; only a signed, encrypted "
                              "HTTP 200 reply is handed over", status_code=status,
                              body=_error_body(body) if status >= 400 else {})
        detail = ex.detail or {}
        if ex.detail is None:
            raise NearRefusal("NEAR response withheld: the signature step did not finish in time")
        if detail.get("fully_attested") is not True:
            reason = (detail.get("check") or {}).get("reason") or "no verified provider_tee signature"
            raise NearRefusal(f"NEAR response withheld: decrypted output is released only after a verified "
                              f"provider_tee signature over the ciphertext ({reason})"[:400])
        try:
            plain, _report = e2.decrypt_response(json.loads(body), ex.client_key)
        except ValueError as exc:  # E2EEError and JSONDecodeError
            raise NearRefusal(f"NEAR response withheld: the signature verified but the reply does not decrypt "
                              f"for this client ({exc}); a gateway that replaced X-Client-Pub-Key would look "
                              "like this"[:400]) from exc
        headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in _DROP_ON_RELEASE]
        out = httpx.Response(200, headers=headers, content=json.dumps(plain, ensure_ascii=False).encode("utf-8"),
                             extensions=response.extensions)
        ex.settle((True, ""))
        return out
    except BaseException as exc:
        ex.settle((False, str(exc) or type(exc).__name__))
        raise
    finally:
        ex.client_key = None


def _send_failed(adapter: "NearAdapter", ex: "_Exchange", exc: BaseException) -> NearRefusal | None:
    """A send that raised before a response arrived still gets its row. A TLS pin mismatch also drops the
    pooled connections and asks for a re-verify (bounded by the backoff)."""
    pin = next((e for e in _chain(exc) if isinstance(e, TLSPinMismatch)), None)
    reason = ("TLS pin mismatch, nothing sent" if pin is not None else
              f"transport error ({type(exc).__name__}); the request may have reached NEAR")
    try:
        if not ex.finished:
            ex.finished = True
            ex.end_reason = reason
            adapter.finish_exchange(ex)
        ex.settle((False, reason))
    except Exception:
        logger.warning("confidential-mode: could not ledger a failed NEAR send", exc_info=True)
    ex.client_key = None
    if pin is not None:
        adapter.mark_stale("a NEAR connection presented a certificate other than the attested one; re-verifying")
        return _refusal(pin)
    return None


def _chain(exc: BaseException):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _sealed_sync(adapter: "NearAdapter", ex: "_Exchange", response: httpx.Response) -> httpx.Response:
    ex.keep_body = True
    try:
        if hasattr(response, "_content"):           # a body already in memory, already content-decoded
            ex._decoder = None
            ex._take(response._content)
        else:
            for chunk in response.stream:
                ex.feed(chunk)
        ex.complete()
    except BaseException as exc:
        ex.finish(f"{type(exc).__name__} while reading the body")
        ex.settle((False, f"{type(exc).__name__} while reading the body"))
        ex.client_key = None
        raise
    finally:
        try:
            response.close()
        except Exception:
            pass
    ex.finish()
    return _release_sealed(adapter, ex, response)


async def _sealed_async(adapter: "NearAdapter", ex: "_Exchange", response: httpx.Response, finish) -> httpx.Response:
    ex.keep_body = True
    try:
        if hasattr(response, "_content"):
            ex._decoder = None
            ex._take(response._content)
        else:
            async for chunk in response.stream:
                ex.feed(chunk)
        ex.complete()
    except BaseException as exc:
        await finish(f"{type(exc).__name__} while reading the body")
        ex.settle((False, f"{type(exc).__name__} while reading the body"))
        ex.client_key = None
        raise
    finally:
        try:
            await response.aclose()
        except Exception:
            pass
    await finish()
    return _release_sealed(adapter, ex, response)


def _signature_step_bound(adapter: "NearAdapter") -> float:
    """The async wait for finish(): the fetch loop's deadline plus one last GET at its own timeout."""
    w = adapter.signature_wait_seconds
    return w + 4 * max(1.0, w) + 5.0


class _Releasing(httpx.SyncByteStream):
    """A response body that releases its send pool when closed."""

    def __init__(self, inner, release):
        self._inner, self._release = inner, release

    def __iter__(self):
        yield from self._inner

    def close(self):
        try:
            self._inner.close()
        finally:
            self._release()


class _SyncView(httpx.BaseTransport):
    def __init__(self, adapter: NearAdapter):
        self._adapter = adapter

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        a = self._adapter
        try:
            a._check_not_held()
            a._check_request(request)
        except VerifyError as exc:
            raise _refusal(exc) from exc
        try:
            request.read()
            ex = a.begin_exchange(request)
        except VerifyError as exc:
            raise _refusal(exc) from exc
        pool, release_pool = a._acquire()
        try:
            response = pool.handle_request(ex.request if ex is not None else request)
        except BaseException as exc:
            release_pool()
            refusal = _send_failed(a, ex, exc) if ex is not None else None
            if refusal is None and any(isinstance(e, TLSPinMismatch) for e in _chain(exc)):
                a.mark_stale("a NEAR connection presented a certificate other than the attested one; re-verifying")
                refusal = _refusal(next(e for e in _chain(exc) if isinstance(e, TLSPinMismatch)))
            if refusal is not None:
                raise refusal from exc
            raise
        if ex is None:
            response.stream = _Releasing(response.stream, release_pool)
            return response
        ex.on_response(response)
        if ex.encrypted:
            try:
                return _sealed_sync(a, ex, response)
            except VerifyError as exc:
                raise _refusal(exc) from exc
            finally:
                release_pool()
        if _already_read(response, ex):
            release_pool()
            ex.finish()
            return response
        inner = response.stream

        class _Hashing(httpx.SyncByteStream):
            def __init__(self_inner):
                self_inner._it = None

            def __iter__(self_inner):
                self_inner._it = iter(inner)
                try:
                    for chunk in self_inner._it:
                        ex.feed(chunk)
                        yield chunk
                except GeneratorExit:
                    raise  # the consumer let go; close() decides
                except BaseException as exc:
                    ex.finish(f"{type(exc).__name__} while reading the body")
                    raise
                ex.complete()
                ex.finish()

            def close(self_inner):
                try:
                    if not ex.completed and ex.saw_done and self_inner._it is not None:
                        _drain_after_done(ex, lambda: next(self_inner._it))
                    inner.close()
                finally:
                    release_pool()
                    ex.finish(None if ex.completed else "closed before its end")
        response.stream = _Hashing()
        return response

    def close(self) -> None:
        pass


class _AsyncView(httpx.AsyncBaseTransport):
    def __init__(self, adapter: NearAdapter):
        self._adapter = adapter

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        a = self._adapter
        try:
            a._check_not_held()
            a._check_request(request)
            await request.aread()
            ex = a.begin_exchange(request)
        except VerifyError as exc:
            raise _refusal(exc) from exc
        try:
            response = await a._async_pool().handle_async_request(ex.request if ex is not None else request)
        except BaseException as exc:
            refusal = _send_failed(a, ex, exc) if ex is not None else None
            if refusal is None and any(isinstance(e, TLSPinMismatch) for e in _chain(exc)):
                a.mark_stale("a NEAR connection presented a certificate other than the attested one; re-verifying")
                refusal = _refusal(next(e for e in _chain(exc) if isinstance(e, TLSPinMismatch)))
            if refusal is not None:
                raise refusal from exc
            raise
        if ex is None:
            return response
        ex.on_response(response)
        bound = _signature_step_bound(a)

        async def finish(reason=None):
            if ex.finished:
                return
            try:
                await asyncio.wait_for(asyncio.to_thread(ex.finish, reason), bound)
            except Exception:
                logger.warning("confidential-mode: NEAR signature step timed out", exc_info=True)

        if ex.encrypted:
            try:
                return await _sealed_async(a, ex, response, finish)
            except VerifyError as exc:
                raise _refusal(exc) from exc
        if _already_read(response, ex):
            await asyncio.wait_for(asyncio.to_thread(ex.finish), bound)
            return response
        inner = response.stream

        class _Hashing(httpx.AsyncByteStream):
            def __init__(self_inner):
                self_inner._it = None

            async def __aiter__(self_inner):
                self_inner._it = inner.__aiter__()
                try:
                    async for chunk in self_inner._it:
                        ex.feed(chunk)
                        yield chunk
                except GeneratorExit:
                    raise
                except BaseException as exc:
                    await finish(f"{type(exc).__name__} while reading the body")
                    raise
                ex.complete()
                await finish()

            async def aclose(self_inner):
                try:
                    if not ex.completed and ex.saw_done and self_inner._it is not None:
                        try:
                            while True:
                                ex.feed(await self_inner._it.__anext__())
                        except StopAsyncIteration:
                            ex.complete()
                        except Exception as exc:
                            ex.end_reason = f"{type(exc).__name__} while draining after [DONE]"
                    await inner.aclose()
                finally:
                    await finish(None if ex.completed else "closed before its end")
        response.stream = _Hashing()
        return response

    async def aclose(self) -> None:
        pass

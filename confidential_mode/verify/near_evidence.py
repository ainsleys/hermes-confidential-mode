"""NEAR AI Cloud evidence: the captured attestation responses as one JSON document.

``build_evidence`` trims the raw gateway, model and Intel Trust Authority responses into the evidence
schema ``confidential-mode/near-evidence/v2`` and moves each large string (app_compose,
compose_manager_attestation, TDX quote, ITA token) into the document's ``blobs`` by SHA-256
(``put_blob``, ``{"$blob": <sha256>}``). ``resolve_blobs`` puts them back. The adapter (near.py) captures
the responses; the appraisal (near_appraise.py) and the offline replay (replay_near.py) read the document.
"""
from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlsplit

from . import near_checks as nc

VENDOR = "near"
EVIDENCE_SCHEMA_V1 = "confidential-mode/near-evidence/v1"
EVIDENCE_SCHEMA = "confidential-mode/near-evidence/v2"
EVIDENCE_SCHEMAS = (EVIDENCE_SCHEMA_V1, EVIDENCE_SCHEMA)
VERIFIER = "confidential-mode near_checks/1 (TDX quote via tinfoil 0.14.2, ITA JWT via cryptography)"


def _tcb_info(report: Mapping) -> Mapping:
    info = cast(Mapping, report.get("info")) if isinstance(report.get("info"), Mapping) else {}
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
    info = cast(Mapping, report.get("info")) if isinstance(report.get("info"), Mapping) else {}
    app_compose = _tcb_info(report).get("app_compose")
    compose_hash = None
    if isinstance(app_compose, str):
        compose_hash = put_blob(blobs, app_compose)
    quote_hex = report.get("intel_quote")
    out = {
        "signing_address": report.get("signing_address"), "signing_algo": report.get("signing_algo"),
        "request_nonce": report.get("request_nonce"), "report_data": report.get("report_data"),
        "intel_quote_b64": (base64.b64encode(bytes.fromhex(quote_hex)).decode("ascii")
                            if isinstance(quote_hex, str) else None),
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
    return datetime.fromtimestamp(ts, tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    ita: dict[str, Any] = {"gateway_token": None, "model_tokens": {}, "jwks_url": None}
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
        "jwks": cast(Mapping, raw.get("jwks")) if isinstance(raw.get("jwks"), Mapping) else None,
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

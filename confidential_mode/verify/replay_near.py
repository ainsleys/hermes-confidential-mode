"""Offline replay of NEAR AI Cloud evidence (schemas confidential-mode/near-evidence/v1 and v2; v1 under v1
rules) and of the signed responses a receipt records. No network: the TDX quotes are re-verified with tinfoil
0.14.2's verifier
against the Intel SGX Root CA it embeds, the Intel Trust Authority JWTs against the captured JWKS whose
x5c chains must end at a root pinned in near_checks.ITA_ROOT_SHA256, and each response signature against
the signing key the replayed evidence binds, over the payload rebuilt from the digests in the row.

``replay(evidence)`` mirrors verify/replay.py's ReplayResult fields so ``hermes confidential replay``
prints both vendors the same way. ``replay_signed_send(detail, evidence)`` judges one ``send_signed``
row. ``replay_receipt(doc)`` does both for every NEAR row of a receipt (JSON form) and needs nothing
but the receipt.

v2 evidence keeps its large strings (each app_compose, each compose_manager_attestation, each TDX quote
and each Intel Trust Authority token) as blobs by SHA-256. A ledger row holds only ``blob_refs``; a JSON
receipt carries the texts beside the evidence
(``blobs``), and ``with_blobs`` joins them for replay. A blob that is missing or does not hash to its id
fails the check that needs it.

What a replay can NOT establish is in ``NOT_ESTABLISHED`` (returned with every result; v1 evidence gets
``NOT_ESTABLISHED_V1``).
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any, cast

from . import near as _near, near_checks as nc

EVIDENCE_SCHEMA = _near.EVIDENCE_SCHEMA
EVIDENCE_SCHEMAS = _near.EVIDENCE_SCHEMAS

_AFTER_LAUNCH_V1 = (
    "what the model CVM ran after launch: its compose starts a compose-manager that can apply further "
    "deployment actions; NEAR's compose_manager_attestation is not checked here")

NOT_ESTABLISHED = (
    "that the digests in a send row are digests of the conversation Hermes shows: a receipt holds digests, "
    "never bytes, so only someone holding the exact request and response bytes can recompute them",
    "anything about which model produced the bytes of a gateway-kind signature: the gateway signs its own "
    "output when it rewrites the bytes (streams, model aliases, the Responses API), and NEAR documents no "
    "link from that signature to the model provider's response",
    "that a provider_tee signature and the gateway or TLS evidence form one chain: NEAR documents that a "
    "provider_tee signature does not bind the model-signed bytes to the gateway or TLS evidence",
    "which serving instance answered: instances of one model share one signing key, also across different "
    "measured configurations (NEAR's own warning), so a matching key does not name an instance",
    "what the model CVM runs after launch: what runs after launch is not measured. The compose-manager "
    "check establishes only that a TD of this instance reported this actions log for this nonce, that the "
    "log's hash is bound in a hardware quote, and that the per-service deployment map derived from the log "
    "is what the operator's own tooling reported. It does not establish that the inner compose is measured "
    "or that the reported services are the ones running",
    "that the measured compose-manager wrote the actions log: the log reports a compose-manager image other "
    "than the one the measured docker-compose names (it records a launcher swap on every instance seen); the "
    "cm_image check records both images and never scores them, because the log is operator-reported, not "
    "verified",
    "that the actions log came from the compose-manager at all: the inner services it deploys, the model "
    "proxies among them, hold the dstack quote socket and run privileged, so any of them can obtain a quote "
    "of this TD over report data it chooses",
    "the model CVM's TCB status (patch level, advisories, revocation): its quote is checked against Intel's "
    "SGX root offline, but Intel's TCB collateral is not; only the gateway's TCB status comes from Intel "
    "Trust Authority",
    "that the NVIDIA GPU verdict in Intel Trust Authority's model token belongs to the model CVM: that "
    "token's TDX claims are the gateway's own",
    "which source code built the container images the measured docker-compose names (image provenance)",
    "that the gateway handles plaintext as its code claims: TLS terminates inside the gateway CVM, which "
    "reads every request's model id, plaintext parameters, sizes and timing, and its message text too when a "
    "send is not encrypted; the attestation says which code it runs, not what that code does",
    "that a send marked encrypted left this host encrypted, or which fields were: that is the plugin's own "
    "report (plugin self-report); the digests and the signature cover the ciphertext bytes, so a replay checks "
    "the signature over the ciphertext digests (third-party checkable) and never sees the plaintext",
    "that only an approved instance could read an encrypted request: it is encrypted to the model's signing "
    "key, which every instance of that model shares, approved or not",
    "that the gateway did not read an image: NEAR's encryption covers text only, so an image part of an "
    "encrypted request leaves in plaintext (the send row's plaintext_parts counts them)",
    "that only this client could read a reply: the model seals it to the key in the X-Client-Pub-Key request "
    "header, which the signature does not cover, so a gateway that swaps that key reads the reply and is "
    "detected only afterwards, when the reply fails to decrypt or to verify and the send is marked unverified",
    "revocation or TCB changes after captured_at, and that captured_at is when the capture happened (the "
    "capturer asserts it)",
)
# v1 evidence carries no compose-manager attestation: its list keeps the earlier after-launch item.
NOT_ESTABLISHED_V1 = NOT_ESTABLISHED[:4] + (_AFTER_LAUNCH_V1,) + NOT_ESTABLISHED[7:]


def with_blobs(evidence: Mapping, blobs: Mapping | None) -> Mapping:
    """``evidence`` with ``blobs`` joined in (as a receipt item carries them). Inline blobs win."""
    if not isinstance(evidence, Mapping) or not isinstance(blobs, Mapping) or not blobs:
        return evidence
    return {**evidence, "blobs": {**dict(blobs), **dict(evidence.get("blobs") or {})}}


@dataclass(frozen=True)
class NearReplayResult:
    ok: bool
    checks: dict
    code_fingerprint: str | None
    enclave_fingerprint: str | None
    release_tag: str | None
    as_of: str
    sdk_version: str
    repo: str | None = None                   # the pin identity "<host>#<models>"
    enclave_host_asserted: str | None = None
    platform: str | None = "tdx"
    captured_at_asserted: str | None = None
    gateway_signer: str | None = None
    model_signers: dict = field(default_factory=dict)
    tcb_status: str | None = None
    not_established: tuple[str, ...] = field(default=NOT_ESTABLISHED)
    enclave_host: str | None = None
    captured_at: str | None = None
    vendor: str = "near"
    schema: str | None = None
    cvms: tuple = ()
    components: tuple = ()


def replay(evidence: Mapping, *, as_of: str | float | None = None, expected_repo: str | None = None,
           expected_fingerprints: tuple[str, str] | None = None, quote_verifier=None, ita_roots=None,
           accepted_tcb=_near.DEFAULT_ACCEPTED_TCB, **_ignored: Any) -> NearReplayResult:
    """Re-run every check on stored bytes. ``expected_repo`` is the expected pin identity;
    ``expected_fingerprints`` (code, enclave) usually come from the approved pin."""
    at = _as_unix(as_of, evidence)
    policy = (evidence.get("policy") if isinstance(evidence, Mapping) else None) or {}
    a = _near.appraise(evidence, as_of=at, quote_verifier=quote_verifier, ita_roots=ita_roots,
                       accepted_tcb=accepted_tcb, require_tls_binding=policy.get("require_tls_binding") is not False,
                       require_compose_manager=policy.get("require_provider_tee") is not False)
    checks = dict(a.checks)
    if expected_repo is not None:
        checks["identity_match"] = True if a.identity == expected_repo else \
            f"fail: identity {a.identity!r} is not the expected {expected_repo!r}"
    if expected_fingerprints:
        checks["expected_fingerprints"] = True if (a.code_fingerprint, a.enclave_fingerprint) == tuple(
            expected_fingerprints) else "fail: replayed fingerprints differ from the expected ones"
    ok = a.ok and all(v is True for k, v in checks.items() if k in ("identity_match", "expected_fingerprints"))
    ev = evidence if isinstance(evidence, Mapping) else {}
    return NearReplayResult(
        ok=ok, checks=checks, code_fingerprint=a.code_fingerprint, enclave_fingerprint=a.enclave_fingerprint,
        release_tag=None, as_of=nc.utc(at).isoformat(), sdk_version=_near.VERIFIER, repo=a.identity,
        enclave_host_asserted=ev.get("enclave_host"), captured_at_asserted=ev.get("captured_at"),
        enclave_host=ev.get("enclave_host"), captured_at=ev.get("captured_at"),
        gateway_signer=a.gateway_signer, model_signers=dict(a.model_signers), tcb_status=a.tcb_status,
        schema=ev.get("schema"), cvms=a.cvms, components=a.components,
        not_established=NOT_ESTABLISHED_V1 if ev.get("schema") == _near.EVIDENCE_SCHEMA_V1 else NOT_ESTABLISHED)


def _as_unix(as_of, evidence) -> float:
    if isinstance(as_of, (int, float)) and not isinstance(as_of, bool):
        return float(as_of)
    if isinstance(as_of, str) and as_of:
        from datetime import datetime
        dt = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()
    try:
        return float((evidence or {}).get("captured_at_unix") or 0)
    except (TypeError, ValueError, AttributeError):
        return 0.0


def replay_signed_send(detail: Mapping, evidence: Mapping | None, *, model: str | None = None,
                       require_provider_tee: bool | None = None, quote_verifier=None, ita_roots=None,
                       replayed: NearReplayResult | None = None) -> dict:
    """Judge one send_signed row from the receipt alone: the evidence must replay, the signature must
    verify under the key that evidence binds, over the payload rebuilt from the row's digests and the
    request's model id, and the kind must be the one the policy requires. Never raises."""
    out: dict[str, Any] = {"verdict": "fail", "reason": "", "kind": None, "evidence_ok": False, "signature": None}
    try:
        if not isinstance(detail, Mapping):
            out["reason"] = "row has no detail"
            return out
        sig = cast(Mapping, detail.get("signature")) if isinstance(detail.get("signature"), Mapping) else {}
        out["kind"] = sig.get("signature_kind")
        if sig.get("status") != "fetched":
            out["reason"] = f"no signature recorded ({sig.get('status') or 'none'}: {sig.get('reason') or ''})".strip()
            out["verdict"] = "missing"
            return out
        if not isinstance(evidence, Mapping):
            out["reason"] = "no NEAR evidence in this receipt with this row's attestation nonce"
            return out
        r = replayed if replayed is not None else replay(evidence, quote_verifier=quote_verifier, ita_roots=ita_roots)
        out["evidence_ok"] = r.ok
        if not r.ok:
            out["reason"] = "the referenced evidence does not replay"
            return out
        mdl = model if model is not None else None
        req = detail.get("require_provider_tee") if require_provider_tee is None else require_provider_tee
        wire = {"signature_kind": sig.get("signature_kind"), "signing_algo": sig.get("signing_algo"),
                "signing_address": sig.get("signing_address"), "signature": sig.get("signature_hex"),
                "text": sig.get("text")}
        check = nc.check_signature(wire, model=mdl, request_sha256=detail.get("request_sha256"),
                                   response_sha256=detail.get("response_sha256"), gateway_signer=r.gateway_signer,
                                   model_signers=r.model_signers.get(mdl, []) if mdl else [],
                                   require_provider_tee=req is not False)
        out["signature"] = check
        out["reason"] = check["reason"]
        out["verdict"] = "pass" if check["verdict"] == "verified" else "fail"
        return out
    except Exception as exc:  # a malformed receipt is a failed replay, never a crash
        out["reason"] = f"{type(exc).__name__}: {exc}"[:200]
        return out


def evidence_by_nonce(doc: Mapping) -> dict:
    out: dict = {}
    for item in (doc.get("evidence") or []) if isinstance(doc, Mapping) else []:
        ev = item.get("evidence") if isinstance(item, Mapping) else None
        if isinstance(ev, Mapping) and ev.get("schema") in EVIDENCE_SCHEMAS and ev.get("nonce"):
            out.setdefault(ev["nonce"], with_blobs(ev, item.get("blobs")))
    return out


def replay_receipt(doc: Mapping, *, quote_verifier=None, ita_roots=None) -> dict:
    """{"sends": [{row, chat_id, kind, verdict, reason}], "all_pass": bool, "fully_attested": bool}
    for every send_signed row of a JSON receipt."""
    by_nonce = evidence_by_nonce(doc)
    cache: dict = {}
    sends = []
    for row in (doc.get("rows") or []) if isinstance(doc, Mapping) else []:
        if not isinstance(row, Mapping) or row.get("kind") != "send_signed":
            continue
        d = cast(Mapping, row.get("detail")) if isinstance(row.get("detail"), Mapping) else {}
        ev = by_nonce.get(d.get("attestation_nonce"))
        nonce = d.get("attestation_nonce")
        if ev is not None and nonce not in cache:
            try:
                cache[nonce] = replay(ev, quote_verifier=quote_verifier, ita_roots=ita_roots)
            except Exception:
                cache[nonce] = None
        res = replay_signed_send(d, ev, model=row.get("model") or None, quote_verifier=quote_verifier,
                                 ita_roots=ita_roots, replayed=cache.get(nonce))
        tee = bool(res["verdict"] == "pass" and (res.get("signature") or {}).get("provider_tee_verified"))
        sends.append({"row": row.get("id"), "chat_id": d.get("chat_id"), "kind": res["kind"],
                      "verdict": res["verdict"], "reason": res["reason"], "provider_tee": tee,
                      "near_e2ee": d.get("near_e2ee") is True})
    return {"sends": sends, "all_pass": all(s["verdict"] == "pass" for s in sends),
            "fully_attested": bool(sends) and all(s["provider_tee"] for s in sends)}

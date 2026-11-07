"""Offline checks for NEAR AI Cloud evidence and signed responses (no network, no SDK of NEAR's).

Everything here is a pure function over bytes the capture recorded, so the live adapter
(verify/near.py) and the offline replay (verify/replay_near.py) run the same code on the same
evidence. The formats come from NEAR's published documentation, read 2026-11-07:

- docs.near.ai/cloud/verification/reference/quote-nonce-signer: report data is 64 bytes, the last 32
  are the client nonce; the first 32 are the signing identity zero-padded on the right, or
  SHA-256(identity || raw TLS SPKI fingerprint) when a TLS fingerprint was requested. MRCONFIGID is
  0x01 || SHA-256(app_compose) || 15 zero bytes. RTMR3 is replayed from the imr-3 events:
  digest = SHA-384(event_type as 4 little-endian bytes || ":" || event || ":" || event_payload).
- docs.near.ai/cloud/verification/cloud-api/response-signatures and
  .../reference/response-signature-verification: provider_tee signs "{model_id}:{request_hash}:
  {response_hash}", gateway signs "{request_hash}:{response_hash}"; hashes are lower-case hex SHA-256
  of the exact request and response body bytes; for ed25519 the signing_address IS the 32-byte public
  key (hex) and the signature (64 bytes, hex) is over the UTF-8 bytes of the text; an absent or
  unfamiliar signature_kind is never inferred from the shape of the text; a provider_tee signer must
  match exactly one verified model report.
- Intel Trust Authority EAT profile (portal.trustauthority.intel.com/eat_profile.html): tokens are
  JWTs signed PS384 (RS256 on request); v2 tokens nest TDX claims under "tdx".

Only ed25519 is supported: ecdsa signers are Ethereum addresses that need Keccak-256 and public-key
recovery, which neither Python's standard library nor ``cryptography`` provides, and this plugin does
not vendor them. The adapter always requests signing_algo=ed25519.

The TDX quote signature is checked with tinfoil 0.14.2's own TDX verifier (already a pinned
dependency): PCK chain to the Intel SGX Root CA embedded in that SDK, quote signature, QE report
signature and QE report-data binding. It does NOT evaluate Intel's TCB collateral for that quote.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

SIGNING_ALGO = "ed25519"
SIGNATURE_KINDS = ("provider_tee", "gateway")

# Intel Trust Authority token-signing roots, pinned by the SHA-256 of their DER certificate (fetched from
# https://portal.trustauthority.intel.com/certs and https://portal.eu.trustauthority.intel.com/certs on
# 2026-11-07; the last x5c entry of every key). A JWKS whose chain ends anywhere else is rejected.
ITA_ROOT_SHA256 = {
    "7091e89e9a17b939edc01f0a87b0c3863f2242299bf3c0ffd5ee4a217ff74f5f": "Intel Trust Authority Root CA",
    "de0457343f28d90bdcf00f46490f78132b23cceb5204cea4a89e07f45dcd4842": "IntelTA EU Production Root CA",
}
ITA_JWKS_URLS = ("https://portal.trustauthority.intel.com/certs",
                 "https://portal.eu.trustauthority.intel.com/certs")
ITA_ISSUERS = ("https://portal.trustauthority.intel.com", "https://portal.eu.trustauthority.intel.com",
               "Intel Trust Authority")
JWT_ALGS = ("PS384", "RS256", "PS256", "RS384")
JWT_SKEW_SECONDS = 120


class CheckError(ValueError):
    """A check failed; the message says which and why (no secrets, no content)."""


# ── small encodings ─────────────────────────────────────────────────────────────────────────────

def hexbytes(value: Any, label: str, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise CheckError(f"{label} is not hex text")
    v = value[2:] if value[:2] in ("0x", "0X") else value
    if not v or len(v) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", v):
        raise CheckError(f"{label} is not hexadecimal")
    out = bytes.fromhex(v)
    if length is not None and len(out) != length:
        raise CheckError(f"{label} is {len(out)} bytes, expected {length}")
    return out


def b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── NEAR report data, configuration measurement, RTMR3 ──────────────────────────────────────────

def bound_identity(signing_address: str, tls_cert_fingerprint: str | None = None) -> bytes:
    """The first 32 bytes of NEAR report data for an ed25519 signer (quote-nonce-signer page)."""
    identity = hexbytes(signing_address, "signing_address", 32)
    if tls_cert_fingerprint:
        return hashlib.sha256(identity + hexbytes(tls_cert_fingerprint, "tls_cert_fingerprint", 32)).digest()
    return identity.ljust(32, b"\0")


def expected_report_data(signing_address: str, nonce: str, tls_cert_fingerprint: str | None = None) -> bytes:
    return bound_identity(signing_address, tls_cert_fingerprint) + hexbytes(nonce, "nonce", 32)


def mr_config_id_for(app_compose: str) -> bytes:
    return b"\x01" + hashlib.sha256(app_compose.encode("utf-8")).digest() + bytes(15)


def replay_rtmr3(events: Iterable[Mapping]) -> bytes:
    rtmr3 = bytes(48)
    for ev in events:
        if not isinstance(ev, Mapping) or ev.get("imr") != 3:
            continue
        et = ev.get("event_type")
        if not isinstance(et, int) or isinstance(et, bool) or not 0 <= et < 2 ** 32:
            raise CheckError("event_log: event_type is not a 32-bit unsigned integer")
        payload = ev.get("event_payload") or ""
        digest = hashlib.sha384(struct.pack("<I", et) + b":" + str(ev.get("event") or "").encode("utf-8") + b":"
                                + (bytes.fromhex(payload) if payload else b"")).digest()
        if ev.get("digest") and hexbytes(ev["digest"], "event_log digest") != digest:
            raise CheckError(f"event_log: digest mismatch for event {str(ev.get('event'))[:40]!r}")
        rtmr3 = hashlib.sha384(rtmr3 + digest).digest()
    return rtmr3


def imr3_events(event_log: Any) -> list[dict]:
    """The imr-3 events of a report's event_log (a JSON string from the gateway, a list from models)."""
    if isinstance(event_log, str):
        event_log = json.loads(event_log)
    if not isinstance(event_log, list):
        raise CheckError("event_log is not a list")
    return [{k: e.get(k) for k in ("imr", "event_type", "digest", "event", "event_payload")}
            for e in event_log if isinstance(e, Mapping) and e.get("imr") == 3]


# ── TDX quote (tinfoil 0.14.2's verifier) ───────────────────────────────────────────────────────

def default_quote_verifier(quote: bytes) -> dict:
    """Verify a TDX v4 quote's signatures offline and return its measured fields (hex).
    Raises CheckError on any failure."""
    try:
        from tinfoil.attestation.abi_tdx import parse_quote
        from tinfoil.attestation.verify_tdx import verify_tdx_quote
    except Exception as exc:  # pragma: no cover - tinfoil is a pinned dependency
        raise CheckError(f"TDX quote verifier unavailable: {type(exc).__name__}") from exc
    try:
        q = parse_quote(quote)
        chain = verify_tdx_quote(q, quote)
    except Exception as exc:
        raise CheckError(f"TDX quote did not verify: {type(exc).__name__}: {exc}"[:300]) from exc
    b = q.td_quote_body
    return {"report_data": b.report_data.hex(), "mr_config_id": b.mr_config_id.hex(), "mrtd": b.mr_td.hex(),
            "rtmr0": b.rtmrs[0].hex(), "rtmr1": b.rtmrs[1].hex(), "rtmr2": b.rtmrs[2].hex(),
            "rtmr3": b.rtmrs[3].hex(), "td_attributes": b.td_attributes.hex(),
            "debug": bool(b.td_attributes[0] & 1), "root": chain.root_cert.subject.rfc4514_string(),
            "verifier": "tinfoil 0.14.2 verify_tdx_quote (PCK chain to the Intel SGX Root CA it embeds)"}


QuoteVerifier = Callable[[bytes], dict]


def check_signing_public_key(report: Mapping, *, required: bool) -> None:
    """For ed25519 the signing address IS the public key (response-signature-verification page), and the
    E2EE guide sends ``signing_public_key`` as X-Model-Pub-Key. Only ``signing_address`` is bound into
    report data, so the two must be byte-identical: 32 bytes as lower-case hex, equal. ``required`` (model
    candidates, whose key encrypts requests) makes an absent ``signing_public_key`` a failure too; a
    gateway report carries none and is checked only when one is present."""
    spk = report.get("signing_public_key")
    if spk is None and not required:
        return
    for label, value in (("signing_address", report.get("signing_address")), ("signing_public_key", spk)):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise CheckError(f"{label} is not 32 bytes of lower-case hex")
    if spk != report.get("signing_address"):
        raise CheckError("signing_public_key is not the signing_address the quote binds")


def check_report(report: Mapping, *, nonce: str, app_composes: Mapping[str, str], quote_verifier: QuoteVerifier,
                 tls_cert_fingerprint: str | None = None, require_signing_public_key: bool = False) -> dict:
    """One NEAR report (gateway or model candidate), per docs.near.ai quote-nonce-signer. Returns the
    verified quote fields; raises CheckError naming the first failed check."""
    if report.get("signing_algo") != SIGNING_ALGO:
        raise CheckError(f"signing_algo {report.get('signing_algo')!r} is not {SIGNING_ALGO}")
    if (report.get("request_nonce") or "").lower() != nonce.lower():
        raise CheckError("request_nonce does not echo the client nonce")
    try:
        quote = base64.b64decode(report.get("intel_quote_b64") or "", validate=True)
    except Exception as exc:
        raise CheckError("intel_quote is not base64") from exc
    q = quote_verifier(quote)
    if q.get("debug") is not False:
        raise CheckError("TDX debug mode is enabled (or unknown)")
    want = expected_report_data(report.get("signing_address") or "", nonce, tls_cert_fingerprint)
    if hexbytes(q.get("report_data"), "quote report_data", 64) != want:
        raise CheckError("quote report_data does not bind the signing key and the client nonce")
    if report.get("report_data") not in (None, "") and \
            hexbytes(report["report_data"], "report_data") != want:
        raise CheckError("echoed report_data differs from the verified quote")
    compose_hash = report.get("compose_hash") or ""
    text = app_composes.get(compose_hash)
    if not isinstance(text, str) or sha256_hex(text.encode("utf-8")) != compose_hash:
        raise CheckError("app_compose missing or its SHA-256 differs from compose_hash")
    if hexbytes(q.get("mr_config_id"), "quote mr_config_id", 48) != mr_config_id_for(text):
        raise CheckError("MRCONFIGID does not match SHA-256(app_compose)")
    if replay_rtmr3(report.get("event_log_imr3") or []) != hexbytes(q.get("rtmr3"), "quote rtmr3", 48):
        raise CheckError("event log does not replay to the quote's RTMR3")
    check_signing_public_key(report, required=require_signing_public_key)
    return q


# ── JWS / JWKS (Intel Trust Authority) ─────────────────────────────────────────────────────────

def _cert_chain_ok(x5c: list, roots: Mapping[str, str], at: datetime):
    from cryptography import x509
    if not isinstance(x5c, list) or len(x5c) < 2:
        raise CheckError("JWKS key has no x5c chain")
    certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c]
    for i, cert in enumerate(certs):
        if not (cert.not_valid_before_utc <= at <= cert.not_valid_after_utc):
            raise CheckError(f"x5c[{i}] not valid at {at.isoformat()}")
        issuer = certs[i + 1] if i + 1 < len(certs) else cert
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception as exc:
            raise CheckError(f"x5c[{i}] is not signed by x5c[{min(i + 1, len(certs) - 1)}]") from exc
    from cryptography.hazmat.primitives import serialization
    root_fp = sha256_hex(certs[-1].public_bytes(serialization.Encoding.DER))
    if root_fp not in roots:
        raise CheckError(f"x5c chain ends at an unpinned root (sha256 {root_fp[:16]}...)")
    return certs[0], roots[root_fp]


def jwks_keys(jwks: Mapping, *, roots: Mapping[str, str] = ITA_ROOT_SHA256, at: datetime) -> dict:
    """kid+alg -> (public key, root name) for every RSA key whose x5c chain reaches a pinned root and whose
    leaf certificate carries the JWK's own modulus and exponent."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    out = {}
    keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
    if not isinstance(keys, list) or not keys:
        raise CheckError("JWKS has no keys")
    for k in keys:
        if not isinstance(k, Mapping) or k.get("kty") != "RSA":
            continue
        leaf, root = _cert_chain_ok(k.get("x5c"), roots, at)
        pub = leaf.public_key()
        n = int.from_bytes(b64url(k["n"]), "big")
        e = int.from_bytes(b64url(k["e"]), "big")
        if not isinstance(pub, rsa.RSAPublicKey) or pub.public_numbers().n != n or pub.public_numbers().e != e:
            raise CheckError(f"JWK {str(k.get('kid'))[:16]}... does not match its certificate")
        out[(k.get("kid"), k.get("alg"))] = (pub, root)
    if not out:
        raise CheckError("JWKS has no usable RSA key")
    return out


def verify_jwt(token: str, keys: Mapping, *, at: float, issuers: Iterable[str] = ITA_ISSUERS) -> dict:
    """Verify a compact JWS against ``keys`` (from jwks_keys) and its time claims at ``at`` (unix).
    Returns the claims."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    if not isinstance(token, str) or token.count(".") != 2:
        raise CheckError("token is not a compact JWS")
    h64, p64, s64 = token.split(".")
    try:
        header, claims, sig = json.loads(b64url(h64)), json.loads(b64url(p64)), b64url(s64)
    except Exception as exc:
        raise CheckError("token is not decodable") from exc
    alg = header.get("alg")
    if alg not in JWT_ALGS:
        raise CheckError(f"token alg {alg!r} not accepted")
    entry = keys.get((header.get("kid"), alg))
    if entry is None:
        raise CheckError("token kid/alg not in the JWKS")
    pub, _root = entry
    hash_cls = {"256": hashes.SHA256, "384": hashes.SHA384}[alg[2:]]
    pad = (padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=hash_cls.digest_size) if alg.startswith("PS")
           else padding.PKCS1v15())
    try:
        pub.verify(sig, f"{h64}.{p64}".encode("ascii"), pad, hash_cls())
    except Exception as exc:
        raise CheckError("token signature does not verify") from exc
    if claims.get("iss") not in tuple(issuers):
        raise CheckError(f"token issuer {str(claims.get('iss'))[:60]!r} not accepted")
    for name in ("iat", "exp"):
        if not isinstance(claims.get(name), (int, float)):
            raise CheckError(f"token has no {name}")
    if not (claims["iat"] - JWT_SKEW_SECONDS <= at <= claims["exp"] + JWT_SKEW_SECONDS):
        raise CheckError("token was not valid at the capture time")
    return claims


def tdx_claims(claims: Mapping) -> Mapping:
    """v2 tokens nest TDX claims under "tdx"; v1 tokens are flat."""
    t = claims.get("tdx")
    return t if isinstance(t, Mapping) else claims


# ── signed responses ────────────────────────────────────────────────────────────────────────────

def expected_signature_text(kind: str, *, model: str | None, request_sha256: str, response_sha256: str) -> str:
    if kind == "provider_tee":
        if not isinstance(model, str) or not model:
            raise CheckError("provider_tee payload needs the request's model id")
        return f"{model}:{request_sha256}:{response_sha256}"
    if kind == "gateway":
        return f"{request_sha256}:{response_sha256}"
    raise CheckError(f"signature kind {kind!r} is not provider_tee or gateway (not inferred)")


def ed25519_ok(public_key_hex: str, signature_hex: str, text: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = Ed25519PublicKey.from_public_bytes(hexbytes(public_key_hex, "signing_address", 32))
        key.verify(hexbytes(signature_hex, "signature", 64), text.encode("utf-8"))
        return True
    except Exception:
        return False


def check_signature(sig: Mapping | None, *, model: str | None, request_sha256: str | None,
                    response_sha256: str | None, gateway_signer: str | None, model_signers: Iterable[str],
                    require_provider_tee: bool) -> dict:
    """Judge one fetched signature against the digests the client recorded and the signers the preflight
    verified. Never raises. ``verdict`` is "verified" only when the text equals the expected payload
    exactly, the ed25519 signature verifies, the signer matches the right preflight report (exactly one
    model report for provider_tee, the gateway report for gateway), and, when ``require_provider_tee``,
    the kind is provider_tee."""
    out = {"verdict": "unverified", "kind": None, "reason": "", "expected_text": None, "payload_match": False,
           "signature_valid": False, "signer_match": False, "signer_role": None, "provider_tee_verified": False}
    if not isinstance(sig, Mapping):
        out["reason"] = "no signature"
        return out
    kind = sig.get("signature_kind")
    out["kind"] = kind if isinstance(kind, str) else None
    if not (isinstance(request_sha256, str) and isinstance(response_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", request_sha256) and re.fullmatch(r"[0-9a-f]{64}", response_sha256)):
        out["reason"] = "the client recorded no request/response digest"
        return out
    if kind not in SIGNATURE_KINDS:
        out["reason"] = f"signature_kind {kind!r} absent or unfamiliar; not inferred from the text"
        return out
    if sig.get("signing_algo") != SIGNING_ALGO:
        out["reason"] = f"signing_algo {sig.get('signing_algo')!r} is not {SIGNING_ALGO}"
        return out
    try:
        expected = expected_signature_text(kind, model=model, request_sha256=request_sha256,
                                           response_sha256=response_sha256)
    except CheckError as exc:
        out["reason"] = str(exc)
        return out
    out["expected_text"] = expected
    text = sig.get("text")
    out["payload_match"] = isinstance(text, str) and hmac.compare_digest(text.encode("utf-8"), expected.encode("utf-8"))
    if not out["payload_match"]:
        out["reason"] = "signed text does not equal the expected payload for this kind and these digests"
        return out
    address = sig.get("signing_address")
    out["signature_valid"] = isinstance(address, str) and ed25519_ok(address, str(sig.get("signature") or ""), text)
    if not out["signature_valid"]:
        out["reason"] = "ed25519 signature does not verify under signing_address"
        return out
    addr = address.lower().removeprefix("0x")
    if kind == "provider_tee":
        # Instances of one model share one key (NEAR's documentation), so equal keys are one signer, not an
        # ambiguity; which instance answered is listed as not established.
        keys = {s.lower().removeprefix("0x") for s in model_signers if isinstance(s, str)}
        if addr not in keys:
            out["reason"] = "signer matches no verified model report"
            return out
        if len(keys) != 1:
            out["reason"] = f"the verified model reports name {len(keys)} different signing keys (ambiguous)"
            return out
        out["signer_role"] = "model"
    else:
        if not (isinstance(gateway_signer, str) and gateway_signer.lower().removeprefix("0x") == addr):
            out["reason"] = "signer is not the verified gateway signer"
            return out
        out["signer_role"] = "gateway"
    out["signer_match"] = True
    out["provider_tee_verified"] = kind == "provider_tee"
    if require_provider_tee and kind != "provider_tee":
        out["reason"] = "gateway signature only: it does not bind the response to a model TEE"
        return out
    out["verdict"] = "verified"
    out["reason"] = ("provider_tee signature by the verified model key" if kind == "provider_tee"
                     else "gateway signature by the verified gateway key (no model binding)")
    return out


def utc(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc)


# ── RTMR3-recorded identity (dstack boot events) ───────────────────────────────────────────────

RTMR3_IDENTITY_EVENTS = {"app-id": "app_id", "instance-id": "instance_id", "os-image-hash": "os_image_hash",
                         "key-provider": "key_provider_info"}
# dstack's boot events, as every captured NEAR report (gateway, model, compose-manager; 2026-11-07) lays them
# out: ten imr-3 events of event_type 0x08000001, from "system-preparing" to "system-ready", each name once:
# system-preparing, app-id, compose-hash, instance-id, boot-mr-done, mr-kms, os-image-hash, key-provider,
# storage-fs, system-ready. An identity event counts only inside that boot segment, with that type, once.
BOOT_EVENT_TYPE = 0x08000001
BOOT_END_EVENT = "system-ready"


def rtmr3_identity(report: Mapping) -> dict:
    """app_id, instance_id, os_image_hash, key_provider_info and kms_id as the report's dstack boot events
    record them. Call only after ``check_report``, which replays those events to the quote's RTMR3.

    Each identity event must appear exactly once in the imr-3 log, before the first "system-ready" event,
    with event_type BOOT_EVENT_TYPE; a missing, repeated, late or mistyped one fails, and so does an
    ``info`` value that differs. Values are never taken from ``info``. ``kms_id`` is SHA-256 of the hex-
    decoded ``id`` of the key-provider JSON (the KMS public key as DER), lower-case hex; an id that is not
    hex fails."""
    events = [ev for ev in report.get("event_log_imr3") or [] if isinstance(ev, Mapping)]
    names = [ev.get("event") for ev in events]
    if BOOT_END_EVENT not in names:
        raise CheckError(f"RTMR3 log has no {BOOT_END_EVENT!r} event (the boot sequence is incomplete)")
    end = names.index(BOOT_END_EVENT)
    out: dict[str, Any] = {}
    for event, key in RTMR3_IDENTITY_EVENTS.items():
        at = [i for i, n in enumerate(names) if n == event]
        if not at:
            raise CheckError(f"RTMR3 log has no {event} event")
        if len(at) > 1:
            raise CheckError(f"RTMR3 log repeats the {event} event")
        ev = events[at[0]]
        if at[0] > end:
            raise CheckError(f"RTMR3 {event} event comes after {BOOT_END_EVENT}")
        if ev.get("event_type") != BOOT_EVENT_TYPE:
            raise CheckError(f"RTMR3 {event} event has event_type {ev.get('event_type')!r}, not dstack's boot type")
        payload = str(ev.get("event_payload") or "")
        if key == "key_provider_info":
            try:
                value: Any = bytes.fromhex(payload).decode("utf-8")
            except ValueError as exc:
                raise CheckError("RTMR3 key-provider event is not UTF-8 hex") from exc
        else:
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", payload):
                raise CheckError(f"RTMR3 {event} event payload is not hex")
            value = payload.lower()
        stated = report.get(key)
        if stated not in (None, "") and (str(stated) if key == "key_provider_info" else str(stated).lower()) != value:
            raise CheckError(f"info.{key} differs from the RTMR3 {event} event")
        out[key] = value
    try:
        kid = json.loads(out["key_provider_info"]).get("id")
    except (ValueError, AttributeError) as exc:
        raise CheckError("RTMR3 key-provider event is not a JSON object") from exc
    if not isinstance(kid, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", kid):
        raise CheckError("RTMR3 key-provider id is not hex")
    out["kms_id"] = sha256_hex(bytes.fromhex(kid))
    return out


# ── display ─────────────────────────────────────────────────────────────────────────────────────

CONTROL_TAG = " [control characters in vendor string]"


def _hidden(ch: str) -> bool:
    """A character a reader cannot see as itself: not printable, Unicode category Cc, Cf, Co or Cn, or in the
    tag block U+E0000-U+E007F."""
    import unicodedata
    return (not ch.isprintable() or unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cn")
            or 0xE0000 <= ord(ch) <= 0xE007F)


def _has_hidden(text: str) -> bool:
    return any(_hidden(ch) for ch in text)


def _esc(ch: str) -> str:
    o = ord(ch)
    return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}"


def render_vendor(text: Any) -> str:
    """One line of text that carries vendor-supplied strings, made safe to show a person on a terminal or a
    chat surface that renders markdown. A rendering step only: hashes, pins, the ledger and receipt JSON
    keep the raw bytes. Nothing is stripped or cut: a backslash becomes two, every hidden character (not
    printable, Unicode category Cc, Cf, Co or Cn, or the tag block; this covers ANSI escape sequences, line
    separators, bidirectional, zero-width and soft-hyphen marks) and every backtick becomes a visible
    \\xNN, \\uNNNN or \\UNNNNNNNN escape, the line is wrapped in a code span so markdown characters are
    inert, and a line that held a hidden character ends with CONTROL_TAG."""
    raw = str(text)
    bad = _has_hidden(raw)
    out = "".join(_esc(ch) if (ch == "`" or _hidden(ch)) else ("\\\\" if ch == "\\" else ch) for ch in raw)
    return f"`{out}`" + (CONTROL_TAG if bad else "")


def render_if_needed(text: Any) -> str:
    """``text`` as is when it holds no control character and nothing a markdown renderer would act on
    (backtick, asterisk, a link "](", an angle bracket); else render_vendor(text). For text that is mostly
    the plugin's own (check results, receipt fields): plain values stay readable, vendor strings stay inert."""
    raw = str(text)
    if _has_hidden(raw) or any(t in raw for t in ("`", "*", "](", "<", ">")):
        return render_vendor(raw)
    return raw


# ── compose-manager attestation ─────────────────────────────────────────────────────────────────
# NEAR documents none of this (docs.near.ai verification, model-attestations and image-provenance pages,
# read 2026-11-07, do not mention compose-manager). The construction is reverse-engineered from captures
# of 2026-11-07 on two instances: report_data = actions_hash || client nonce, actions_hash = SHA-256 of
# json.dumps(actions, sort_keys=True, separators=(",", ":")) with Python's default ensure_ascii,
# nonce_source "client". If NEAR changes any of it, these checks fail closed.
#
# What a passing check establishes, and no more: a TD of this instance (same MRTD and RTMR0-3 as the
# model quote) reported this actions log for this nonce, the log's hash is bound in a hardware quote, and
# the per-service deployment map derived from the log is what the operator's own tooling reported. It
# does not establish that the inner compose is measured or that the reported services are the ones
# running: the model proxies the log deploys hold the dstack quote socket, so any of them can obtain a
# quote of this TD over report data it chooses. The component is the whole map; nothing is left out.

CM_CHECK_KEYS = ("cm_quote", "cm_same_td", "cm_report_data", "cm_actions_hash", "cm_services", "cm_image")
CM_ACTION_KINDS = ("compose_up", "compose_down", "compose_stage", "docker_restart", "compose_manager_started")
WHOLE_FILE = "*"   # a compose_up or compose_down with no services acts on every service of the file

# Display order only: the services a per-model name list puts first in the pin prompt, because they are the
# ones that list names for the model. The list is taken from the inner compose files at the commit each
# service was started from (github.com/nearai/cvm-compose-files, read 2026-11-07: prod/small-models.yaml and
# prod/qwen38-27b-abliterated-cc-1gpu.yaml): services whose served_model or model tag or MODEL_NAME names the
# model, the engine behind its proxy, the nginx that routes to the proxy, its registrar, and the downloaders
# of its weights and of the LoRA adapter the engine loads. A name list can miss services, so it never
# narrows what is recorded or compared: every other service is listed after these.
PROMPT_PATH_SERVICES: dict[str, dict[str, tuple[str, ...]]] = {
    "Qwen/Qwen3.8-27B": {"proxy": ("proxy-qwen38-27b",), "engine": ("model-sg-qwen38-27b-*",),
                         "also": ("nginx-qwen38", "qwen38-registrar", "model-downloader-qwen38",
                                  "qwen38-lora-adapter-downloader")},
}
# A compose service name is [A-Za-z0-9._-] (no colon), so "<file>::<service>" keys cannot collide; a log
# naming any other service fails cm_services. Files, tags and images are kept as raw strings and escaped
# only when shown to a person (render_vendor).
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")


class CmCheckError(CheckError):
    """A compose-manager check failed; ``step`` is the CM_CHECK_KEYS entry it belongs to."""

    def __init__(self, step: str, message: str):
        super().__init__(message)
        self.step = step


def actions_hash(actions: Any) -> str:
    """SHA-256 (lower-case hex) of the compact, sorted-keys JSON of the actions log, as NEAR computes it."""
    return sha256_hex(json.dumps(actions, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _hexfield(a: Mapping, key: str, length: int, where: str) -> str:
    v = a.get(key)
    if not isinstance(v, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", v):
        raise CmCheckError("cm_services", f"{where}: {key} is not {length} lower-case hex digits")
    return v


def deployment_map(actions: Any) -> tuple[dict, list]:
    """Replay the actions log into (per-service state, compose-manager images started, in log order).
    State keys are "<file>::<service>" (service WHOLE_FILE when an action named no services); values are
    {file, service, commit, file_sha256, tag}. compose_up sets, compose_down removes, compose_stage and
    docker_restart change nothing. Any malformed or unknown action fails (cm_services)."""
    if not isinstance(actions, list) or not actions:
        raise CmCheckError("cm_services", "the actions log is empty")
    state: dict[str, dict] = {}
    images: list[str] = []
    for i, a in enumerate(actions):
        where = f"actions[{i}]"
        if not isinstance(a, Mapping):
            raise CmCheckError("cm_services", f"{where} is not an object")
        kind = a.get("action")
        if kind not in CM_ACTION_KINDS:
            raise CmCheckError("cm_services", f"{where}: unknown action {str(kind)[:40]!r}")
        if kind in ("compose_stage", "docker_restart"):
            continue
        if kind == "compose_manager_started":
            image = a.get("image")
            if not isinstance(image, str) or not image:
                raise CmCheckError("cm_services", f"{where}: compose_manager_started names no image")
            images.append(image)
            continue
        file = a.get("file")
        services = a.get("services") if a.get("services") is not None else []
        if not isinstance(file, str) or not file or not isinstance(services, list):
            raise CmCheckError("cm_services", f"{where}: {kind} has no file or no services list")
        if not all(isinstance(s, str) and _SERVICE_NAME.fullmatch(s) for s in services):
            raise CmCheckError("cm_services", f"{where}: {kind} names a service that is not a compose service name")
        tag = a.get("tag")
        if tag is not None and not isinstance(tag, str):
            raise CmCheckError("cm_services", f"{where}: {kind} has a tag that is not text")
        if kind == "compose_down":
            if not services:
                state = {k: v for k, v in state.items() if v["file"] != file}
            for s in services:
                state.pop(f"{file}::{s}", None)
            continue
        entry = {"file": file, "commit": _hexfield(a, "commit", 40, where),
                 "file_sha256": _hexfield(a, "file_sha256", 64, where),
                 "tag": tag}
        if not services:   # the whole file at this commit replaces every earlier entry of that file
            state = {k: v for k, v in state.items() if v["file"] != file}
        for s in services or [WHOLE_FILE]:
            state[f"{file}::{s}"] = {**entry, "service": s}
    return state, images


def prompt_path(state: Mapping[str, Mapping], model: str | None) -> tuple[list, str]:
    """(the keys of ``state`` the model's name list puts first, sorted; a label saying which list). Display
    order only: the whole map is always recorded."""
    import fnmatch
    rule = PROMPT_PATH_SERVICES.get(model or "")
    if rule is None:
        return sorted(k for k, v in state.items() if v["service"] == WHOLE_FILE), \
            f"whole-file deployments (no service name list for {model})"
    pats = tuple(rule.get("proxy", ())) + tuple(rule.get("engine", ())) + tuple(rule.get("also", ()))
    keys = sorted(k for k, v in state.items()
                  if v["service"] == WHOLE_FILE or any(fnmatch.fnmatchcase(v["service"], p) for p in pats))
    return keys, (f"named for {model} by the plugin's name list (it can miss services), and every whole-file "
                  "deployment")


def services_sha256(state: Mapping) -> str:
    """The services component: SHA-256 of the canonical JSON of the whole per-service map."""
    return sha256_hex(canonical(dict(state)).encode("utf-8"))


_IMAGE_REF = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64})\s*")
_ENV_DEFAULT = re.compile(r"\s*\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}\s*")


def image_ref(text: Any) -> str | None:
    """"repo@sha256:<64 hex>" from an image string, or from the default of ``${VAR:-default}``; else None."""
    if not isinstance(text, str):
        return None
    d = _ENV_DEFAULT.fullmatch(text)
    m = _IMAGE_REF.fullmatch(d.group(1) if d else text)
    return m.group(1) if m else None


def measured_cm_image(app_compose: str | None) -> str | None:
    """The compose-manager image reference the measured docker-compose names (its ``image:`` line under
    the ``compose-manager:`` service), or None. A line scan, not a YAML parser: Hermes ships no PyYAML."""
    try:
        dc = json.loads(app_compose or "").get("docker_compose_file")
    except (ValueError, AttributeError):
        return None
    if not isinstance(dc, str):
        return None
    lines = dc.splitlines()
    for i, line in enumerate(lines):
        m = re.fullmatch(r"( +)compose-manager:\s*", line)
        if not m:
            continue
        indent = len(m.group(1))
        for sub in lines[i + 1:]:
            if sub.strip() and not sub.strip().startswith("#") and len(sub) - len(sub.lstrip(" ")) <= indent:
                break
            im = re.fullmatch(r" +image:\s*(.+?)\s*", sub)
            if im and image_ref(im.group(1)):
                return image_ref(im.group(1))
    return None


def check_compose_manager(cm: Any, *, nonce: str, model_quote: Mapping, quote_verifier: QuoteVerifier,
                          model: str | None, app_compose: str | None) -> dict:
    """Every compose-manager step for one model candidate whose own report already passed check_report
    (``model_quote`` is that report's verified quote fields). Raises CmCheckError naming the failed step.
    Returns {"services" (the whole map), "services_sha256", "services_first", "services_scope",
    "cm_image_reported", "cm_image_measured", "cm_image_match", "actions_count", "services_reported"}."""
    if not isinstance(cm, Mapping):
        raise CmCheckError("cm_quote", "the compose-manager attestation is not an object")
    # 1. the quote verifies with the same TDX verifier, and its event log replays to its RTMR3
    try:
        q = quote_verifier(hexbytes(cm.get("quote"), "compose-manager quote"))
        if q.get("debug") is not False:
            raise CheckError("TDX debug mode is enabled (or unknown)")
        if replay_rtmr3(imr3_events(cm.get("event_log") or [])) != hexbytes(q.get("rtmr3"), "quote rtmr3", 48):
            raise CheckError("its event log does not replay to its RTMR3")
    except CmCheckError:
        raise
    except Exception as exc:
        raise CmCheckError("cm_quote", f"compose-manager quote: {exc}"[:300]) from exc
    # 2. the same TD as the model quote, quote to quote
    for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
        if str(q.get(k) or "").lower() != str(model_quote.get(k) or "").lower() or not q.get(k):
            raise CmCheckError("cm_same_td", f"compose-manager quote {k.upper()} differs from the model quote's")
    # 3. report data = actions_hash || nonce, the nonce is ours and the client chose it
    try:
        ah = hexbytes(cm.get("actions_hash"), "actions_hash", 32)
        cn = hexbytes(cm.get("nonce"), "compose-manager nonce", 32)
    except CheckError as exc:
        raise CmCheckError("cm_report_data", str(exc)) from exc
    if cn != hexbytes(nonce, "nonce", 32):
        raise CmCheckError("cm_report_data", "compose-manager nonce is not this client's nonce")
    if cm.get("nonce_source") != "client":
        raise CmCheckError("cm_report_data", f"nonce_source {str(cm.get('nonce_source'))[:20]!r} is not 'client'")
    if hexbytes(q.get("report_data"), "quote report_data", 64) != ah + cn:
        raise CmCheckError("cm_report_data", "compose-manager quote report_data is not actions_hash || nonce")
    if cm.get("report_data") not in (None, "") and hexbytes(cm["report_data"], "report_data") != ah + cn:
        raise CmCheckError("cm_report_data", "echoed report_data differs from the verified quote")
    # 4. the actions log hashes to the bound actions_hash (mandatory; no construction is guessed)
    actions = cm.get("actions")
    if actions_hash(actions) != ah.hex():
        raise CmCheckError("cm_actions_hash", "the actions log does not hash to the bound actions_hash")
    # 5. replay the log; 6. order it for display (the component is the whole map)
    state, images = deployment_map(actions)
    first, scope = prompt_path(state, model)
    # 7. the image the log reports against the one the measured compose names (recorded, never scored)
    reported = (image_ref(images[-1]) or images[-1]) if images else None
    measured = measured_cm_image(app_compose)
    return {"services": state, "services_sha256": services_sha256(state), "services_first": first,
            "services_scope": scope, "cm_image_reported": reported, "cm_image_measured": measured,
            "cm_image_match": bool(reported and measured and reported == measured),
            "actions_count": len(actions), "services_reported": len(state)}

"""Tinfoil adapter (SDK 0.14.2) for the attested tier.

One SecureClient per profile, bound to an explicit enclave host. Attestation runs only through the
SDK's default path (GitHub release digest + Sigstore code measurement compared against the enclave's
hardware attestation); pinned-measurement mode is never used.

Pool model (docs/C0-spikes.md, spike 2 follow-up):
- sync: ``verify()`` builds ONE attested ``httpx.Client`` via ``SecureClient.make_secure_http_client()``
  (that build is the attestation), and ``sync_http_view()`` hands out cheap non-closing views over it.
  Hermes closes request-scoped clients every turn; closing a view never touches the pool.
- async: one attested ``httpx.AsyncClient`` pool per running event loop, built with
  ``make_secure_async_http_client()`` (one attestation per loop); ``async_http_for_loop()`` hands out
  non-closing views over the current loop's pool and prunes pools whose loop has closed.

Every SDK attestation (including the SDK's own silent re-verification on key/cert rotation) passes
through a counting guard. Outside an explicit ``verify()`` the guard refuses any attestation whose
fingerprints differ from the last accepted result, so a rotation can never move traffic to an
enclave build the pin check has not seen.

Enclave host and the network: constructing the adapter and registering the profile never touch the
network. A configured ``confidential.tinfoil.enclave`` is used as-is; otherwise the host is chosen by
``get_router_address()`` lazily, on the first verify() (first create_client / attested_ok) or from a
setup command, and the profile's base_url is a placeholder until then.

Flapping risk with router discovery: the pin covers the enclave fingerprint, which is the hardware
measurement of the router that answered. Routers on AMD SEV-SNP and Intel TDX hosts report different
measurement types, so their enclave fingerprints differ even for the same release (see
tinfoil/attestation/types.py Measurement.fingerprint). Discovery picks a random router once per process,
so a restart can land on the other platform and refuse with "enclave build changed" until a human
re-approves. Configuring ``confidential.tinfoil.enclave`` to one router host avoids this.

Evidence capture (VerificationResult.evidence, schema ``confidential-mode/tinfoil-evidence/v1``):
every SDK attestation runs inside thread-scoped wrappers (verify/_sdkpatch.py) around the SDK's own
fetch points, which call through and record the bytes:
  tinfoil.client.fetch_attestation          -> attestation {format, body}
  tinfoil.client.fetch_latest_release       -> release {tag, digest}
  tinfoil.client.fetch_attestation_bundle   -> sigstore_bundle (JSON text)
  verify_sev.CertificateChain.from_report   -> sev.vcek_der_b64                      (SEV-SNP)
  collateral_tdx.fetch_collateral           -> tdx.* raw TCB info / QE identity + chains, CRLs (TDX)
  collateral_tdx._verify_crl_signature      -> tdx.pck_crl_issuer_chain_pem          (TDX)
  tinfoil.sigstore.fetch_latest_digest / fetch_attestation_bundle -> hardware_measurements (TDX)
  sigstore TrustUpdater.get_trusted_root_path -> trusted_root.json, stored once as
                                               <data_dir>/trust-roots/<sha256>.json
Layout: schema, vendor, captured_at (SDK verifiedAt), captured_at_unix, sdk_version, repo, enclave_host,
enclave_source, platform ("sev-snp"|"tdx"), attestation, sev, tdx, release, sigstore_bundle,
hardware_measurements, trusted_root {sha256, path}, tls_cert_pem + tls_observation (TLS spike, below),
claims {code_fingerprint, enclave_fingerprint, release_tag, tls_public_key_fp, hpke_public_key},
verification_document (SDK to_dict), capture_complete, capture_missing[, capture_errors]. Every blob is
a string, so the dict is JSON-serialisable and passes the ledger's content-key filter.
verify/replay.py re-verifies it offline. Release binding: tinfoil 0.14.2 binds the release TAG (and
digest) through the Sigstore workflow-ref policy (SDK sigstore.py:164-172, refs/tags/<tag>); what is
unsigned is which release is "latest" (github.py:50, GitHub's releases/latest answer). The capture also
records that answer's published_at / html_url (release.published_at, release.html_url) for the pin prompt.

Sizes measured from a stubbed SEV capture (tests/unit/test_replay.py, real SDK code, test AMD anchor):
  attestation.body      404 chars (gzip+base64 of the fixed 1184-byte report; the synthetic report is
                        mostly zeros, a real one has ~600 B of high-entropy fields: expect ~1.2-1.6 KB)
  sev.vcek_der_b64      1696 chars (~1.27 KB DER; format-faithful: P-384 key, RSA-PSS-4096 signature)
  sigstore_bundle       1090 chars (test stand-in, NOT representative; real v0.3 DSSE bundles carry a
                        Fulcio cert and a Rekor inclusion proof: unmeasured, estimate 4-8 KB)
  trusted_root.json     6787 B (real file, sigstore-python 4.5.1 embedded root; stored once, not per verify)
  evidence JSON total   6404 chars for that capture (without the trust root)
TDX sizes were not measured (no format-faithful quote or Intel collateral can be produced offline).

TLS spike (confidential.tinfoil.tls_probe, default on): after each explicit verify the adapter sends
one bodyless GET of /.well-known/tinfoil-attestation over the VERIFIED EHBP pool and reads the peer
certificate from response.extensions["network_stream"].get_extra_info("ssl_object") (httpcore exposes it;
ehbp passes extensions through). tls_observation = {captured, spki_sha256, matches_report_tls_key,
san_binding (the SDK's verify_certificate: host, HPKE key, report hash in SANs), issuer, subject, serial,
not_before, not_after, verdict}. verdict "TLS terminates in the attested enclave ..." vs "TLS terminated
by a non-enclave key" is what a live run against Tinfoil will tell us; it is recorded, never enforced.
Per request, the views record the peer SPKI too (send records, below).

SDK on-disk caches: tinfoil 0.14.2 fixes platformdirs paths at import (default macOS
~/Library/Caches/tinfoil, Linux ~/.cache/tinfoil: Sigstore bundles, VCEKs, Intel collateral) and
sigstore-python uses ~/Library/Application Support/sigstore-python/tuf and ~/Library/Caches/sigstore-python/tuf
(Linux ~/.local/share/sigstore-python/tuf, ~/.cache/sigstore-python/tuf). The adapter re-points all of
them under <data_dir>/sdk-cache before its first verify (_sdkpatch.redirect_sdk_caches); a process that
used the SDK before the adapter existed may already have written to the defaults.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from . import _sdkpatch
from .base import VerificationResult, VerifyError

VENDOR = "tinfoil"
ROUTER_REPO = "tinfoilsh/confidential-model-router"
USER_CACHE_SECRET_FILE = "tinfoil_user_cache_secret"
ENCLAVE_SOURCE_CONFIG = "config"
ENCLAVE_SOURCE_ROUTER = "router_discovery"
# Profile base_url before router discovery has run. RFC 6761 .invalid never resolves, so anything that
# used it would fail to connect, and the attested predicate's host check fails closed against it.
PLACEHOLDER_BASE_URL = "https://unresolved.attested-tinfoil.invalid/v1"
_REQUIRED_STEPS = ("fetch_digest", "verify_code", "verify_enclave", "compare_measurements")
EVIDENCE_SCHEMA = "confidential-mode/tinfoil-evidence/v1"
TRUST_ROOTS_SUBDIR = "trust-roots"


def _sdk():
    """Import the SDK lazily so unit tests that never build an adapter do not need it."""
    from tinfoil import client as tinfoil_client  # tinfoil==0.14.2
    return tinfoil_client


def load_or_create_user_cache_secret(data_dir: Path) -> str:
    """The prompt-cache scoping secret, persisted under the plugin data dir (never ~/.tinfoil)."""
    data_dir = Path(data_dir)
    path = data_dir / USER_CACHE_SECRET_FILE
    try:
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    data_dir.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    fd, tmp = tempfile.mkstemp(prefix=f".{USER_CACHE_SECRET_FILE}.", dir=str(data_dir))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return value


_WRAPPER_ATTRS = ("_inner", "_transport", "transport", "inner")


def ehbp_request_key(transport) -> str | None:
    """Hex HPKE public key of the EHBP transport inside the SDK's transport chain (tinfoil 0.14.2:
    _HostBoundTransport -> [_EnclaveURLHeaderTransport] -> [_UserCacheSecretTransport] ->
    _EHBPReVerifyingTransport -> EHBPTransport, whose ServerIdentity holds the key). Read after the
    response arrives: the re-verifying layer swaps its inner transport before a retry, so the key found then
    is the one the returned response's request was encrypted to. None when no such transport is found."""
    try:
        layer, seen = [transport], set()
        for _ in range(8):
            nxt = []
            for t in layer:
                if t is None or id(t) in seen:
                    continue
                seen.add(id(t))
                key = getattr(getattr(t, "_identity", None), "_public_key_bytes", None)
                if isinstance(key, (bytes, bytearray)) and len(key) == 32:
                    return bytes(key).hex()
                nxt.extend(getattr(t, a, None) for a in _WRAPPER_ATTRS)
            if not nxt:
                break
            layer = nxt
    except Exception:  # noqa: BLE001
        return None
    return None


class _SyncView(httpx.BaseTransport):
    """Forwards to the adapter's CURRENT verified sync pool; close() is a no-op for the pool."""

    def __init__(self, adapter: "TinfoilAdapter"):
        self._adapter = adapter

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._adapter._check_not_held()
        transport = self._adapter._current_sync_transport()
        response = transport.handle_request(request)
        return self._adapter._observe_send(request, response, request_key=ehbp_request_key(transport))

    def close(self) -> None:
        pass


class _AsyncView(httpx.AsyncBaseTransport):
    """Forwards to the running loop's CURRENT verified async pool; aclose() is a no-op for the pool."""

    def __init__(self, adapter: "TinfoilAdapter"):
        self._adapter = adapter

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._adapter._check_not_held()
        pool = self._adapter._async_pool_for_running_loop()
        response = await pool._transport.handle_async_request(request)
        return self._adapter._observe_send(request, response, request_key=ehbp_request_key(pool._transport))

    async def aclose(self) -> None:
        pass


class TinfoilAdapter:
    """VendorAdapter for Tinfoil. See module docstring for the pool and guard model."""

    vendor = VENDOR

    def __init__(self, *, data_dir: Path | str, enclave: str | None = None, repo: str = ROUTER_REPO,
                 transport: str = "ehbp", router_discovery: Callable[[], str] | None = None,
                 hold_until_accepted: bool = True, tls_probe: bool = True):
        if not repo:
            raise ValueError("repo is required: pinned-measurement mode is not supported")
        self.data_dir = Path(data_dir)
        self.router_repo = repo
        self.transport = transport
        self._configured_enclave = (enclave or "").strip() or None
        self._router_discovery = router_discovery
        self._enclave: str | None = None
        self.enclave_source: str | None = None
        if self._configured_enclave:  # known without any network
            self._enclave, self.enclave_source = self._configured_enclave, ENCLAVE_SOURCE_CONFIG
        self._lock = threading.RLock()
        self._explicit = threading.local()
        self._sc: Any = None
        self._sync_http: httpx.Client | None = None
        self._retired_sync: list[httpx.Client] = []
        self._async_pools: dict[int, tuple[asyncio.AbstractEventLoop, httpx.AsyncClient]] = {}
        self._accepted: VerificationResult | None = None
        # Attestation counters (every SDK verify() call, including SDK-internal re-verification).
        self.attestation_count = 0
        self.sync_attestation_count = 0
        self.async_attestation_count = 0
        self._counter_bucket = threading.local()
        self._capture_local = threading.local()
        # TLS spike: after each explicit verify, one bodyless GET of the attestation document over the
        # VERIFIED EHBP pool records the TLS peer certificate (evidence.tls_cert_pem/tls_observation).
        self.tls_probe = bool(tls_probe)
        self.verified_mono: float | None = None
        self.event_sink: Callable[[dict], None] | None = None  # set by provider: ledger verify rows it cannot see
        self._spki_cache: dict[bytes, str] = {}
        self.sdk_cache_paths: dict[str, str] = {}
        # Transport-level hold: while set, every view (sync and async) raises before sending. verify()
        # sets it (when hold_until_accepted) atomically with the pool swap; the provider releases it
        # once the pins match, and re-holds on mismatch or failure. This covers paths that bypass
        # ConfidentialClient's create() gate (with_options, raw _client use, other resources).
        self._hold_until_accepted = hold_until_accepted
        self.held_reason: str | None = None

    # ── enclave + SecureClient ────────────────────────────────────────────────────────────────
    @property
    def enclave_host(self) -> str:
        """The resolved enclave host, or "" while unresolved. Never touches the network."""
        return self._enclave or ""

    @property
    def enclave_resolved(self) -> bool:
        return self._enclave is not None

    def resolve_enclave_host(self) -> str:
        """Resolve the explicit enclave host once: config if set (no network), else one router chosen by
        SDK discovery (``get_router_address()``, a network call). Raises VerifyError on failure; a later
        call retries. Called from verify() (first create_client / attested_ok) or a setup command,
        never from register(ctx)."""
        with self._lock:
            if self._enclave is None:
                discover = self._router_discovery or _sdk().get_router_address
                try:
                    host = discover()
                except Exception as exc:
                    raise VerifyError(f"router discovery failed: {type(exc).__name__}: {exc}") from exc
                if not host or not isinstance(host, str):
                    raise VerifyError("router discovery returned no host")
                self._enclave, self.enclave_source = host, ENCLAVE_SOURCE_ROUTER
            return self._enclave

    @property
    def base_url(self) -> str:
        """The enclave URL, or PLACEHOLDER_BASE_URL (an unroutable .invalid host) while unresolved."""
        return f"https://{self._enclave}/v1" if self._enclave else PLACEHOLDER_BASE_URL

    def _secure_client(self):
        with self._lock:
            if self._sc is None:
                host = self.resolve_enclave_host()
                self.sdk_cache_paths = _sdkpatch.redirect_sdk_caches(self.data_dir)
                secret = load_or_create_user_cache_secret(self.data_dir)
                sc = _sdk().SecureClient(enclave=host, repo=self.router_repo, measurement=None,
                                         transport=self.transport, user_cache_secret=secret)
                if getattr(sc, "measurement", None) is not None or not getattr(sc, "repo", ""):
                    raise VerifyError("SecureClient is in pinned-measurement mode; refusing")
                # Instance attribute shadows the class method: every self.verify() inside the SDK
                # (http-client builds, rotation re-verification) comes through the guard.
                sc.verify = lambda: self._guarded_verify(sc)
                self._sc = sc
            return self._sc

    def _guarded_verify(self, sc):
        self.attestation_count += 1
        bucket = getattr(self._counter_bucket, "name", None)
        if bucket == "sync":
            self.sync_attestation_count += 1
        elif bucket == "async":
            self.async_attestation_count += 1
        with _sdkpatch.capture_sink() as sink, _sdkpatch.overrides(_capture_hooks()):
            ground_truth = type(sc).verify(sc)
        self._capture_local.sink = sink
        if not getattr(self._explicit, "active", False):
            # Re-verification outside verify(): the SDK is about to rebind a transport (key/cert
            # rotation: "silent_reattest"; or a new per-loop async pool: "async_pool"). Only allow it
            # if the enclave is still the build we accepted, and LEDGER it: the keys it binds are the
            # keys later sends use, so every key in use has a verify row (review finding 9).
            accepted = self._accepted
            if accepted is None:
                raise VerifyError("re-verification before any accepted verification")
            got = self._result_from_document(sc, sink)
            if (got.code_fingerprint, got.enclave_fingerprint) != (accepted.code_fingerprint,
                                                                  accepted.enclave_fingerprint):
                raise VerifyError("enclave fingerprints changed during re-verification; refusing to rebind")
            self._accepted = got  # accepted keys follow the rotation (same build)
            self._emit_verify_row(got, source="async_pool" if bucket == "async" else "silent_reattest")
        return ground_truth

    # ── key observation (warn-only) and ledger hooks ─────────────────────────────────────────────
    KEY_OBSERVATIONS_FILE = "key-observations.json"

    def observe_key(self, host: str, tls_fp: str | None, hpke: str | None) -> dict:
        """First-seen time per (host, T, H), persisted under the data dir. Warn-only: a key never seen
        before on a host that had other keys is logged, nothing is refused, there is no maximum age."""
        import json as _json
        key = f"{host}|{tls_fp or ''}|{hpke or ''}"
        path = self.data_dir / self.KEY_OBSERVATIONS_FILE
        with self._lock:
            try:
                seen = _json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(seen, dict):
                    seen = {}
            except (FileNotFoundError, ValueError):
                seen = {}
            new = key not in seen
            if new:
                seen[key] = _iso_now()
                try:
                    self.data_dir.mkdir(parents=True, exist_ok=True)
                    fd, tmp = tempfile.mkstemp(prefix=".key-observations.", dir=str(self.data_dir))
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        _json.dump(seen, fh, sort_keys=True)
                    os.replace(tmp, path)
                except OSError:
                    pass
            others = sum(1 for k in seen if k.startswith(f"{host}|") and k != key)
        if new and others:
            import logging
            logging.getLogger(__name__).warning(
                "confidential-mode: new enclave key pair on %s (T %s..., H %s...); %d other pair(s) seen before",
                host, (tls_fp or "")[:16], (hpke or "")[:16], others)
        return {"host": host, "tls_key_fp": tls_fp, "hpke_public_key": hpke, "first_seen": seen[key],
                "new": new, "other_keys_for_host": others}

    def _emit_verify_row(self, result: VerificationResult, *, source: str) -> None:
        sink = self.event_sink
        if sink is None:
            return
        try:
            claims = (result.evidence or {}).get("claims") or {}
            sink({"kind": "verify_ok", "purpose": "verify", "host": result.enclave_host,
                  "detail": {"vendor": result.vendor, "source": source,
                             "code_fingerprint": result.code_fingerprint,
                             "enclave_fingerprint": result.enclave_fingerprint,
                             "release_tag": result.release_tag, "enclave_host": result.enclave_host,
                             "verifier": result.verifier,
                             "key_first_seen": self.observe_key(result.enclave_host, claims.get("tls_public_key_fp"),
                                                                claims.get("hpke_public_key")),
                             "evidence": result.evidence}})
        except Exception:
            import logging
            logging.getLogger(__name__).warning("confidential-mode: could not ledger a %s verification", source,
                                                exc_info=True)

    def current_hpke_key(self) -> str | None:
        """Hex HPKE public key the SDK's transports currently encrypt to (the latest attested H)."""
        gt = getattr(self._sc, "ground_truth", None) if self._sc is not None else None
        key = getattr(gt, "hpke_public_key", None)
        if key:
            return key
        acc = self._accepted
        return ((acc.evidence or {}).get("claims") or {}).get("hpke_public_key") if acc else None

    def _observe_send(self, request, response, request_key: str | None = None):
        """Per-request send record (hpke_key_used, response_decrypted, TLS peer SPKI); see capture_sends.
        ``hpke_key_used`` is the key the EHBP transport encrypted the request to when it can be read
        (``hpke_key_source`` "ehbp_transport"), else the key the SDK held when the response arrived
        ("sdk_state")."""
        try:
            rec: dict = {"host": request.url.host, "path": request.url.path,
                         "hpke_key_used": request_key or self.current_hpke_key(),
                         "hpke_key_source": "ehbp_transport" if request_key else "sdk_state",
                         "encrypted": ENCAPSULATED_KEY_HEADER in request.headers or _has_body(request),
                         "response_decrypted": None, "tls_spki_sha256": None, "tls_matches_report": None}
            der = peer_certificate_der(response)
            if der is not None:
                spki = self._spki_cache.get(der)
                if spki is None:
                    spki = self._spki_cache[der] = spki_sha256(der)
                    if len(self._spki_cache) > 16:
                        self._spki_cache.pop(next(iter(self._spki_cache)))
                acc = self._accepted
                tls_fp = ((acc.evidence or {}).get("claims") or {}).get("tls_public_key_fp") if acc else None
                rec["tls_spki_sha256"], rec["tls_matches_report"] = spki, (spki == tls_fp) if tls_fp else None
            if RESPONSE_NONCE_HEADER in response.headers:
                _wrap_stream_for_decryption_flag(response, rec)
            _record_send(rec)
        except Exception:
            pass
        return response

    # ── verification ─────────────────────────────────────────────────────────────────────────
    def _result_from_document(self, sc, capture: dict | None = None) -> VerificationResult:
        doc = sc.get_verification_document()
        if doc is None:
            raise VerifyError("SDK produced no verification document")
        if not getattr(doc, "security_verified", False):
            raise VerifyError("SDK verification document is not security_verified")
        steps = getattr(doc, "steps", {}) or {}
        for name in _REQUIRED_STEPS:
            step = steps.get(name)
            if step is None or step.status != "success":
                raise VerifyError(f"verification step {name} did not succeed: "
                                  f"{getattr(step, 'status', 'missing')} {getattr(step, 'error', '') or ''}".strip())
        if doc.config_repo != self.router_repo:
            raise VerifyError(f"verified repo {doc.config_repo!r} is not {self.router_repo!r}")
        if doc.enclave_host != self.enclave_host:
            raise VerifyError(f"verified host {doc.enclave_host!r} is not {self.enclave_host!r}")
        if not doc.code_fingerprint or not doc.enclave_fingerprint:
            raise VerifyError("verification document lacks code or enclave fingerprint")
        verifier = getattr(doc, "verifier", None)
        verifier_s = f"{getattr(verifier, 'name', 'tinfoil')}/{getattr(verifier, 'version', 'unknown')}"
        now = time.time()
        evidence = build_evidence(capture or {}, doc, repo=self.router_repo, enclave_source=self.enclave_source,
                                  trust_root_dir=self.data_dir / TRUST_ROOTS_SUBDIR, captured_at_unix=now)
        return VerificationResult(
            vendor=VENDOR, router_repo=self.router_repo, enclave_host=doc.enclave_host,
            code_fingerprint=doc.code_fingerprint, enclave_fingerprint=doc.enclave_fingerprint,
            release_tag=doc.release_tag, verifier=verifier_s, verified_at_host_clock=now,
            evidence=evidence,
        )

    def verify(self) -> VerificationResult:
        """Attest via the SDK default path by building the sync pool; raise VerifyError on anything."""
        try:
            with self._lock:
                sc = self._secure_client()
                self._explicit.active = True
                self._counter_bucket.name = "sync"
                self._capture_local.sink = None
                try:
                    http = sc.make_secure_http_client()
                finally:
                    self._explicit.active = False
                    self._counter_bucket.name = None
                try:
                    result = self._result_from_document(sc, getattr(self._capture_local, "sink", None))
                except BaseException:
                    _close_quietly(http)
                    raise
                prev = self._accepted
                if prev is not None and (prev.code_fingerprint, prev.enclave_fingerprint) != (
                        result.code_fingerprint, result.enclave_fingerprint):
                    # New enclave build: async pools were attested against the old one; rebuild lazily.
                    self._async_pools.clear()
                old, self._sync_http = self._sync_http, http
                if old is not None:
                    # Keep one generation alive for in-flight requests on another thread.
                    for stale in self._retired_sync:
                        _close_quietly(stale)
                    self._retired_sync = [old]
                self._accepted = result
                self.verified_mono = time.monotonic()  # lets the provider adopt this instead of re-attesting
                if self._hold_until_accepted:
                    self.held_reason = "verification not yet accepted against pins"
                if self.tls_probe:
                    self._probe_tls(http, result)
                return result
        except VerifyError:
            raise
        except Exception as exc:
            raise VerifyError(f"attestation failed: {type(exc).__name__}: {exc}") from exc

    def _probe_tls(self, http, result) -> None:
        """Observation only (never fails a verify): which key terminated TLS on the EHBP connection?"""
        ev = result.evidence if isinstance(result.evidence, dict) else None
        if ev is None:
            return
        url = f"https://{result.enclave_host}/.well-known/tinfoil-attestation"
        try:
            with http.stream("GET", url) as resp:
                der = peer_certificate_der(resp)
        except Exception as exc:
            ev["tls_observation"] = {"captured": False, "reason": f"probe failed: {type(exc).__name__}: {exc}"[:300]}
            return
        if der is None:
            ev["tls_observation"] = {"captured": False, "reason": "transport exposes no TLS peer certificate"}
            return
        claims = ev.get("claims") or {}
        obs = tls_observation(der, host=result.enclave_host, attestation=ev.get("attestation") or {},
                              tls_fp=claims.get("tls_public_key_fp"), hpke=claims.get("hpke_public_key"))
        ev["tls_cert_pem"] = obs.pop("cert_pem")
        ev["tls_observation"] = obs

    def hold(self, reason: str) -> None:
        self.held_reason = reason or "held"

    def release(self) -> None:
        self.held_reason = None

    def _check_not_held(self) -> None:
        reason = self.held_reason
        if reason is not None:
            raise VerifyError(f"attested transport held: {reason}")

    @property
    def last_result(self) -> VerificationResult | None:
        return self._accepted

    # ── pools ────────────────────────────────────────────────────────────────────────────────
    def _current_sync_transport(self) -> httpx.BaseTransport:
        http = self._sync_http
        if http is None:
            raise VerifyError("no verified sync pool")
        return http._transport  # the SDK's attested transport chain

    def sync_http_view(self) -> httpx.Client:
        """A fresh non-closing view over the one verified sync pool (requires a prior verify())."""
        if self._sync_http is None:
            raise VerifyError("sync_http_view() before a successful verify()")
        return httpx.Client(transport=_SyncView(self), follow_redirects=False)

    def _async_pool_for_running_loop(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._accepted is None:
                raise VerifyError("async pool requested before a successful verify()")
            for key in [k for k, (lp, _) in self._async_pools.items() if lp.is_closed()]:
                self._async_pools.pop(key, None)  # cannot aclose on a dead loop; drop the reference
            entry = self._async_pools.get(id(loop))
            if entry is None or entry[0] is not loop:
                sc = self._secure_client()
                self._counter_bucket.name = "async"
                try:
                    pool = sc.make_secure_async_http_client()
                except VerifyError:
                    raise
                except Exception as exc:
                    raise VerifyError(f"async attestation failed: {type(exc).__name__}: {exc}") from exc
                finally:
                    self._counter_bucket.name = None
                entry = (loop, pool)
                self._async_pools[id(loop)] = entry
            return entry[1]

    def async_http_for_loop(self) -> httpx.AsyncClient:
        """A non-closing view over the running loop's verified async pool. The pool is attested once
        per loop (here, eagerly); the view always forwards to the loop's current pool."""
        self._async_pool_for_running_loop()
        return httpx.AsyncClient(transport=_AsyncView(self), follow_redirects=False)

    def async_pool_count(self) -> int:
        return len(self._async_pools)

    def close(self) -> None:
        with self._lock:
            for http in [self._sync_http, *self._retired_sync]:
                if http is not None:
                    _close_quietly(http)
            self._sync_http, self._retired_sync = None, []
            self._async_pools.clear()


ENCAPSULATED_KEY_HEADER = "Ehbp-Encapsulated-Key"  # ehbp.protocol
RESPONSE_NONCE_HEADER = "Ehbp-Response-Nonce"     # ehbp.protocol


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _has_body(request) -> bool:
    try:
        return bool(request.headers.get("content-length", "0") not in ("", "0"))
    except Exception:
        return False


# ── per-send records ────────────────────────────────────────────────────────────────────────────
import contextvars as _contextvars  # noqa: E402

_SEND_RECORDS: "_contextvars.ContextVar[list | None]" = _contextvars.ContextVar("confidential_send_records",
                                                                                default=None)
_LAST_SEND: "_contextvars.ContextVar[dict | None]" = _contextvars.ContextVar("confidential_last_send", default=None)


def _record_send(rec: dict) -> None:
    _LAST_SEND.set(rec)
    bucket = _SEND_RECORDS.get()
    if bucket is not None:
        bucket.append(rec)
    # The llm gate's bucket (sendctx.capture_records): the record reaches the send_observed row.
    from .. import sendctx
    sendctx.add_record(rec)


def last_send_record() -> dict | None:
    """The most recent send record in this context (dict, updated in place when a streamed response
    finishes decrypting)."""
    return _LAST_SEND.get()


class capture_sends:
    """``with capture_sends() as records: next_call(...)`` collects every attested send in this context.
    Each record: host, path, hpke_key_used (hex, same encoding as evidence.claims.hpke_public_key),
    encrypted (request body sealed with EHBP), response_decrypted (True once an EHBP response body was
    read to the end and every AEAD frame verified; False if decryption failed; None while a stream is
    unread or when the response was not EHBP-encrypted), tls_spki_sha256, tls_matches_report."""

    def __enter__(self) -> list:
        self._records: list = []
        self._token = _SEND_RECORDS.set(self._records)
        return self._records

    def __exit__(self, *exc) -> None:
        _SEND_RECORDS.reset(self._token)


#: After an SSE stream's ``[DONE]``, at most this many further bytes are read to reach the end of the
#: body (and so the last AEAD frame check) when the client closes early, as the openai SDK does.
DRAIN_AFTER_DONE_BYTES = 64 * 1024
_SSE_DONE = b"[DONE]"


def _wrap_stream_for_decryption_flag(response, rec: dict) -> None:
    """Set ``rec["response_decrypted"]``: True once the EHBP body was read to the end and every frame
    verified, False if decryption failed. The openai SDK stops reading a stream at ``data: [DONE]`` and
    closes the response, so on close after ``[DONE]`` the rest of the body is drained (bounded), the way the
    NEAR view does, and the flag is then set (second review, item 2). A stream closed before ``[DONE]`` keeps
    None and is marked ``stream_closed_before_eof``."""
    inner = response.stream

    if isinstance(inner, httpx.AsyncByteStream):
        class _A(httpx.AsyncByteStream):
            def __init__(self):
                self._it = inner.__aiter__()
                self._tail = b""

            async def __aiter__(self):
                try:
                    while True:
                        try:
                            chunk = await self._it.__anext__()
                        except StopAsyncIteration:
                            break
                        self._tail = (self._tail + chunk)[-64:]
                        yield chunk
                except Exception:
                    rec["response_decrypted"] = False
                    raise
                rec["response_decrypted"] = True

            async def aclose(self):
                try:
                    if rec.get("response_decrypted") is None:
                        if _SSE_DONE in self._tail:
                            drained = 0
                            try:
                                while drained <= DRAIN_AFTER_DONE_BYTES:
                                    try:
                                        drained += len(await self._it.__anext__())
                                    except StopAsyncIteration:
                                        rec["response_decrypted"] = True
                                        break
                            except Exception:
                                rec["response_decrypted"] = False
                        if rec.get("response_decrypted") is None:
                            rec["stream_closed_before_eof"] = True
                finally:
                    await inner.aclose()
        response.stream = _A()
    else:
        class _S(httpx.SyncByteStream):
            def __init__(self):
                self._it = iter(inner)
                self._tail = b""

            def __iter__(self):
                try:
                    for chunk in self._it:
                        self._tail = (self._tail + chunk)[-64:]
                        yield chunk
                except Exception:
                    rec["response_decrypted"] = False
                    raise
                rec["response_decrypted"] = True

            def close(self):
                try:
                    if rec.get("response_decrypted") is None:
                        if _SSE_DONE in self._tail:
                            drained = 0
                            try:
                                for chunk in self._it:
                                    drained += len(chunk)
                                    if drained > DRAIN_AFTER_DONE_BYTES:
                                        break
                                else:
                                    rec["response_decrypted"] = True
                            except Exception:
                                rec["response_decrypted"] = False
                        if rec.get("response_decrypted") is None:
                            rec["stream_closed_before_eof"] = True
                finally:
                    inner.close()
        response.stream = _S()


def _close_quietly(http) -> None:
    try:
        http.close()
    except Exception:
        pass


# ── evidence capture ─────────────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def _capture_hooks() -> dict:
    """Per-thread wrappers around the SDK's own fetch points (call through, then record the bytes)."""
    from cryptography.hazmat.primitives import serialization
    from tinfoil import client as tf_client
    from tinfoil import sigstore as tf_sigstore
    from tinfoil.attestation import collateral_tdx, verify_sev
    from tinfoil.attestation.cert_utils import certs_to_pem

    def rec(name, fn):
        def override(orig, *a, **kw):
            out = orig(*a, **kw)
            sink = _sdkpatch.current_sink()
            if sink is not None:
                try:
                    fn(sink, out, a, kw)
                except Exception as exc:  # capture must never break verification
                    sink.setdefault("capture_errors", []).append(f"{name}: {type(exc).__name__}: {exc}")
            return out
        return override

    def attestation(sink, out, a, kw):
        sink["attestation"] = {"format": out.format.value, "body": out.body}

    def release(sink, out, a, kw):
        sink["release"] = {"tag": out.tag, "digest": out.digest}

    def code_bundle(sink, out, a, kw):
        sink["sigstore_bundle"] = out.decode("utf-8")

    def hw_digest(sink, out, a, kw):
        sink.setdefault("hardware_measurements", {}).update(repo=a[0] if a else kw.get("repo"), digest=out)

    def hw_bundle(sink, out, a, kw):
        sink.setdefault("hardware_measurements", {})["bundle"] = out.decode("utf-8")

    def vcek(sink, out, a, kw):
        sink["vcek_der_b64"] = _b64(out.vcek.public_bytes(serialization.Encoding.DER))

    def collateral(sink, out, a, kw):
        sink.setdefault("tdx", {}).update(
            tcb_info_raw_b64=_b64(out.tcb_info_raw),
            tcb_info_issuer_chain_pem=certs_to_pem(out.tcb_info_issuer_chain or []),
            qe_identity_raw_b64=_b64(out.qe_identity_raw),
            qe_identity_issuer_chain_pem=certs_to_pem(out.qe_identity_issuer_chain or []),
            pck_crl_pem=out.pck_crl.crl.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            pck_crl_ca_type=out.pck_crl.ca_type,
            root_crl_der_b64=_b64(out.root_crl.crl.public_bytes(serialization.Encoding.DER)),
        )

    def pck_crl_chain(sink, out, a, kw):
        sink.setdefault("tdx", {})["pck_crl_issuer_chain_pem"] = certs_to_pem(a[1])

    def trusted_root(sink, out, a, kw):
        sink["trusted_root_bytes"] = Path(out).read_bytes()

    hooks = {
        (tf_client, "fetch_attestation"): rec("attestation", attestation),
        (tf_client, "fetch_latest_release"): _release_with_metadata(rec("release", release)),
        (tf_client, "fetch_attestation_bundle"): rec("sigstore_bundle", code_bundle),
        (tf_sigstore, "fetch_latest_digest"): rec("hardware_measurements.digest", hw_digest),
        (tf_sigstore, "fetch_attestation_bundle"): rec("hardware_measurements.bundle", hw_bundle),
        (verify_sev.CertificateChain, "from_report"): rec("vcek", vcek),
        (collateral_tdx, "fetch_collateral"): rec("tdx_collateral", collateral),
        (collateral_tdx, "_verify_crl_signature"): rec("pck_crl_issuer_chain", pck_crl_chain),
    }
    try:
        from sigstore._internal.tuf import TrustUpdater
        hooks[(TrustUpdater, "get_trusted_root_path")] = rec("trusted_root", trusted_root)
    except Exception:  # pragma: no cover - sigstore internals moved
        pass
    return hooks


# ── TLS peer certificate on the EHBP connection ─────────────────────────────────────────────────

def peer_certificate_der(response) -> bytes | None:
    """The TLS peer certificate of the connection that carried ``response`` (httpcore exposes the
    stream as response.extensions["network_stream"]; ehbp passes extensions through)."""
    ns = (getattr(response, "extensions", None) or {}).get("network_stream")
    if ns is None:
        return None
    get = getattr(ns, "get_extra_info", None)
    ssl_obj = get("ssl_object") if callable(get) else None
    if ssl_obj is None:
        return None
    der = ssl_obj.getpeercert(True)  # positional: the raw _ssl._SSLSocket rejects keywords
    return der or None


def spki_sha256(der: bytes) -> str:
    """SHA-256 of the SubjectPublicKeyInfo: the TLS key fingerprint the report carries (T)."""
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def tls_observation(der: bytes, *, host: str, attestation: dict, tls_fp: str | None, hpke: str | None) -> dict:
    """Compare the peer certificate with the report: SPKI SHA-256 == T, and the SDK's SAN binding
    (verify_certificate: host, HPKE key and attestation-document hash encoded in SANs)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(der)
    spki = spki_sha256(der)
    obs = {"captured": True, "spki_sha256": spki, "matches_report_tls_key": bool(tls_fp) and spki == tls_fp,
           "issuer": cert.issuer.rfc4514_string(), "subject": cert.subject.rfc4514_string(),
           "serial": format(cert.serial_number, "x"),
           "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
           "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii")}
    try:
        from tinfoil.attestation import Document
        from tinfoil.attestation.bundle import verify_certificate
        from tinfoil.attestation.types import PredicateType
        doc = Document(format=PredicateType(attestation["format"]), body=attestation["body"])
        verify_certificate(obs["cert_pem"], host, doc, hpke or "")
        obs["san_binding"] = True
    except Exception as exc:
        obs["san_binding"] = f"fail: {type(exc).__name__}: {exc}"[:300]
    if obs["matches_report_tls_key"] and obs["san_binding"] is True:
        obs["verdict"] = "TLS terminates in the attested enclave (SPKI == report TLS key, SAN binding ok)"
    elif not obs["matches_report_tls_key"]:
        obs["verdict"] = "TLS terminated by a non-enclave key"
    else:
        obs["verdict"] = "SPKI matches the report but the SAN binding failed"
    return obs


def _release_with_metadata(inner):
    """Run fetch_latest_release with a thread-scoped spy on requests.Session.request that records the
    GitHub release JSON's published_at / html_url (the SDK parses then discards them)."""
    import requests

    def override(orig, *a, **kw):
        seen: dict = {}

        def spy(orig_request, *ra, **rkw):
            resp = orig_request(*ra, **rkw)
            try:
                url = str(ra[1] if len(ra) > 1 else rkw.get("url", ""))
                if url.endswith("/releases/latest") and resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        seen.update(published_at=data.get("published_at"), html_url=data.get("html_url"))
            except Exception:
                pass
            return resp
        with _sdkpatch.overrides({(requests.Session, "request"): spy}):
            out = inner(orig, *a, **kw)
        sink = _sdkpatch.current_sink()
        if sink is not None and isinstance(sink.get("release"), dict):
            sink["release"].update({k: v for k, v in seen.items() if isinstance(v, str)})
        return out
    return override


def store_trust_root(trust_root_dir: Path, data: bytes) -> tuple[str, Path]:
    """Content-addressed, written once: <dir>/<sha256>.json."""
    import hashlib
    digest = hashlib.sha256(data).hexdigest()
    trust_root_dir = Path(trust_root_dir)
    path = trust_root_dir / f"{digest}.json"
    if not path.exists():
        trust_root_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".trusted_root.", dir=str(trust_root_dir))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return digest, path


def build_evidence(capture: dict, doc, *, repo: str, enclave_source: str | None, trust_root_dir: Path,
                   captured_at_unix: float) -> dict:
    """The schema'd evidence for one verification (JSON-serialisable; every blob is a string)."""
    from tinfoil._sdkinfo import sdk_version
    from tinfoil.attestation.types import PredicateType
    att = capture.get("attestation")
    platform = None
    if att:
        platform = {PredicateType.SEV_GUEST_V2.value: "sev-snp",
                    PredicateType.TDX_GUEST_V2.value: "tdx"}.get(att.get("format"), "unknown")
    trusted_root = None
    if capture.get("trusted_root_bytes"):
        import base64
        digest, _path = store_trust_root(trust_root_dir, capture["trusted_root_bytes"])
        # Review finding 5: the bytes (about 7 KB) travel inside the evidence, so a receipt replays on any
        # machine; no local path is recorded (it named the capturer's home directory).
        trusted_root = {"sha256": digest, "json_b64": base64.b64encode(capture["trusted_root_bytes"]).decode("ascii")}
    hw = capture.get("hardware_measurements")
    enclave_m = getattr(doc, "enclave_measurement", None)
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "vendor": VENDOR,
        "captured_at": getattr(doc, "verified_at", None),
        "captured_at_unix": captured_at_unix,
        "sdk_version": sdk_version(),
        "repo": repo,
        "enclave_host": doc.enclave_host,
        "enclave_source": enclave_source,
        "platform": platform,
        "attestation": att,
        "sev": {"vcek_der_b64": capture["vcek_der_b64"]} if capture.get("vcek_der_b64") else None,
        "tdx": capture.get("tdx") or None,
        "release": capture.get("release"),
        "sigstore_bundle": capture.get("sigstore_bundle"),
        "hardware_measurements": hw if hw and hw.get("bundle") else None,
        "trusted_root": trusted_root,
        "tls_cert_pem": None,       # filled by the TLS probe after verify (TinfoilAdapter._probe_tls)
        "tls_observation": None,
        "claims": {
            "code_fingerprint": doc.code_fingerprint,
            "enclave_fingerprint": doc.enclave_fingerprint,
            "release_tag": doc.release_tag,
            "tls_public_key_fp": getattr(enclave_m, "public_key_fp", None) or doc.tls_public_key or None,
            "hpke_public_key": getattr(enclave_m, "hpke_public_key", None) or doc.hpke_public_key or None,
        },
        "verification_document": doc.to_dict(),
    }
    missing = [k for k in ("attestation", "release", "sigstore_bundle", "trusted_root") if not evidence[k]]
    if platform == "sev-snp" and not evidence["sev"]:
        missing.append("sev")
    if platform == "tdx":
        tdx = evidence["tdx"] or {}
        if not tdx.get("tcb_info_raw_b64") or not tdx.get("pck_crl_issuer_chain_pem"):
            missing.append("tdx")
        if not evidence["hardware_measurements"]:
            missing.append("hardware_measurements")
    evidence["capture_complete"] = not missing
    evidence["capture_missing"] = missing
    if capture.get("capture_errors"):
        evidence["capture_errors"] = list(capture["capture_errors"])
    return evidence

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

from .base import VerificationResult, VerifyError

VENDOR = "tinfoil"
ROUTER_REPO = "tinfoilsh/confidential-model-router"
USER_CACHE_SECRET_FILE = "tinfoil_user_cache_secret"
ENCLAVE_SOURCE_CONFIG = "config"
ENCLAVE_SOURCE_ROUTER = "router_discovery"
_REQUIRED_STEPS = ("fetch_digest", "verify_code", "verify_enclave", "compare_measurements")


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


class _SyncView(httpx.BaseTransport):
    """Forwards to the adapter's CURRENT verified sync pool; close() is a no-op for the pool."""

    def __init__(self, adapter: "TinfoilAdapter"):
        self._adapter = adapter

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._adapter._check_not_held()
        return self._adapter._current_sync_transport().handle_request(request)

    def close(self) -> None:
        pass


class _AsyncView(httpx.AsyncBaseTransport):
    """Forwards to the running loop's CURRENT verified async pool; aclose() is a no-op for the pool."""

    def __init__(self, adapter: "TinfoilAdapter"):
        self._adapter = adapter

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._adapter._check_not_held()
        pool = self._adapter._async_pool_for_running_loop()
        return await pool._transport.handle_async_request(request)

    async def aclose(self) -> None:
        pass


class TinfoilAdapter:
    """VendorAdapter for Tinfoil. See module docstring for the pool and guard model."""

    vendor = VENDOR

    def __init__(self, *, data_dir: Path | str, enclave: str | None = None, repo: str = ROUTER_REPO,
                 transport: str = "ehbp", router_discovery: Callable[[], str] | None = None,
                 hold_until_accepted: bool = True):
        if not repo:
            raise ValueError("repo is required: pinned-measurement mode is not supported")
        self.data_dir = Path(data_dir)
        self.router_repo = repo
        self.transport = transport
        self._configured_enclave = (enclave or "").strip() or None
        self._router_discovery = router_discovery
        self._enclave: str | None = None
        self.enclave_source: str | None = None
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
        # Transport-level hold: while set, every view (sync and async) raises before sending. verify()
        # sets it (when hold_until_accepted) atomically with the pool swap; the provider releases it
        # once the pins match, and re-holds on mismatch or failure. This covers paths that bypass
        # ConfidentialClient's create() gate (with_options, raw _client use, other resources).
        self._hold_until_accepted = hold_until_accepted
        self.held_reason: str | None = None

    # ── enclave + SecureClient ────────────────────────────────────────────────────────────────
    @property
    def enclave_host(self) -> str:
        """The explicit enclave host: config if set, else one router chosen by SDK discovery (once)."""
        with self._lock:
            if self._enclave is None:
                if self._configured_enclave:
                    self._enclave, self.enclave_source = self._configured_enclave, ENCLAVE_SOURCE_CONFIG
                else:
                    discover = self._router_discovery or _sdk().get_router_address
                    try:
                        host = discover()
                    except Exception as exc:
                        raise VerifyError(f"router discovery failed: {type(exc).__name__}: {exc}") from exc
                    if not host:
                        raise VerifyError("router discovery returned no host")
                    self._enclave, self.enclave_source = str(host), ENCLAVE_SOURCE_ROUTER
            return self._enclave

    @property
    def base_url(self) -> str:
        return f"https://{self.enclave_host}/v1"

    def _secure_client(self):
        with self._lock:
            if self._sc is None:
                host = self.enclave_host
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
        ground_truth = type(sc).verify(sc)
        if not getattr(self._explicit, "active", False):
            # Re-verification outside verify(): the SDK is about to rebind a transport. Only allow
            # it if the enclave is still the build we accepted.
            accepted = self._accepted
            if accepted is None:
                raise VerifyError("re-verification before any accepted verification")
            got = self._result_from_document(sc)
            if (got.code_fingerprint, got.enclave_fingerprint) != (accepted.code_fingerprint,
                                                                  accepted.enclave_fingerprint):
                raise VerifyError("enclave fingerprints changed during re-verification; refusing to rebind")
        return ground_truth

    # ── verification ─────────────────────────────────────────────────────────────────────────
    def _result_from_document(self, sc) -> VerificationResult:
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
        evidence = doc.to_dict()
        verifier = getattr(doc, "verifier", None)
        verifier_s = f"{getattr(verifier, 'name', 'tinfoil')}/{getattr(verifier, 'version', 'unknown')}"
        evidence = dict(evidence, pluginEnclaveSource=self.enclave_source)
        return VerificationResult(
            vendor=VENDOR, router_repo=self.router_repo, enclave_host=doc.enclave_host,
            code_fingerprint=doc.code_fingerprint, enclave_fingerprint=doc.enclave_fingerprint,
            release_tag=doc.release_tag, verifier=verifier_s, verified_at_local=time.time(),
            evidence=evidence,
        )

    def verify(self) -> VerificationResult:
        """Attest via the SDK default path by building the sync pool; raise VerifyError on anything."""
        try:
            with self._lock:
                sc = self._secure_client()
                self._explicit.active = True
                self._counter_bucket.name = "sync"
                try:
                    http = sc.make_secure_http_client()
                finally:
                    self._explicit.active = False
                    self._counter_bucket.name = None
                try:
                    result = self._result_from_document(sc)
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
                if self._hold_until_accepted:
                    self.held_reason = "verification not yet accepted against pins"
                return result
        except VerifyError:
            raise
        except Exception as exc:
            raise VerifyError(f"attestation failed: {type(exc).__name__}: {exc}") from exc

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


def _close_quietly(http) -> None:
    try:
        http.close()
    except Exception:
        pass

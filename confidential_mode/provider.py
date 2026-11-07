"""The 'attested-tinfoil' ProviderProfile, its verification cache, and the attested_ok() verdict.

create_client(**kw) NEVER raises and NEVER returns None (either makes Hermes build a plain
openai.OpenAI to the same base_url, docs/C0-spikes.md spike 2). It returns a ConfidentialClient when
verification is fresh and the pins match, otherwise refreshes once (if the cached result is stale or
missing), otherwise a RefusingClient.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .client import ConfidentialClient, ConfidentialRefused, RefusingClient, openai_kwargs_from
from .pins import PinStore
from .tiers import Verdict
from .verify.base import VerificationResult, VerifyError

logger = logging.getLogger(__name__)

PROFILE_NAME = "attested-tinfoil"
API_KEY_ENV = "TINFOIL_API_KEY"
NEAR_PROFILE_NAME = "attested-near"
NEAR_API_KEY_ENV = "NEAR_AI_API_KEY"
# Every attested profile this plugin can register (locking.ATTESTED_PROFILES repeats it without importing
# this module). A destination is in the attested tier only through one of these names.
ATTESTED_PROFILES = (PROFILE_NAME, NEAR_PROFILE_NAME)
DEFAULT_TTL_SECONDS = 300.0
# After a failed attestation, further create_client()/attested_ok() calls refuse without re-attesting
# for this long (Hermes calls create_client ~4 times before the first turn).
DEFAULT_FAILURE_BACKOFF_SECONDS = 10.0

# create_client / attested_ok wait at most this long for an attestation, then refuse while it continues
# in the background (Amendment 4 ruling 1, revised 2026-11-07: default 20 s). A cold live verify()
# measured ~5.6 s against router-0.tinfoil.sh, so a 5 s wait would refuse most first turns.
DEFAULT_VERIFY_WAIT_SECONDS = 20.0
# Context window reported to Hermes without probing the endpoint (confidential.tinfoil.context_length).
DEFAULT_CONTEXT_LENGTH = 65536

VERIFY_PENDING_PREFIX = "verification pending"
REASON_VERIFY_PENDING = "verification pending: attestation still in progress; this turn ended; resend"


def is_verification_pending(reason: str | None) -> bool:
    """For preflight/status wording: a pending attestation is not an off-tier destination."""
    return isinstance(reason, str) and reason.startswith(VERIFY_PENDING_PREFIX)
REASON_NO_CONSENT = "pin has no consent record"
REASON_BAD_RESULT = "attestation returned no usable fingerprints"
REASON_NOT_REGISTERED = "attested provider is not registered"
REASON_PIN_MISMATCH = "enclave build changed; run /confidential pins approve"
REASON_NO_PIN = "no approved enclave build pinned; run /confidential pins approve"


@dataclass
class _Entry:
    adapter: Any
    pins: PinStore
    ttl_seconds: float
    failure_backoff_seconds: float
    result: VerificationResult | None = None
    verified_mono: float = 0.0
    last_error: str | None = None
    failed_mono: float | None = None
    lock: Any = None
    profile: Any = None   # the registered ProviderProfile; its base_url follows the adapter's resolved host
    on_event: Callable[[dict], None] | None = None  # ledger sink (plain dicts, ledger.py column names)
    verify_wait_seconds: float = DEFAULT_VERIFY_WAIT_SECONDS
    verify_lock: Any = field(default_factory=threading.Lock)
    inflight: threading.Event | None = None
    consent_ledger: Any = None      # Ledger-like (.tail); when set, a pin needs a matching pin_applied row
    consented: set = field(default_factory=set)
    auto_approve_platform_only: bool = False  # (vendor, code_fp, enclave_fp) already seen in the ledger


class VerificationCache:
    """In-process verification cache keyed by provider name (not stored in ctx.state)."""

    def __init__(self, clock: Callable[[], float] | None = None):
        self._entries: dict[str, _Entry] = {}
        self._clock = clock
        self._lock = threading.Lock()

    def _wire_adapter_sink(self, provider: str, e: _Entry) -> None:
        """Let the adapter ledger verifications the cache never sees (SDK silent re-attest, per-loop
        async pool attestation) through this entry's on_event."""
        if hasattr(e.adapter, "event_sink"):
            try:
                e.adapter.event_sink = lambda ev: _emit(e, {**ev, "provider": provider})
            except Exception:
                pass

    def register(self, provider: str, adapter, pins: PinStore, ttl_seconds: float,
                 failure_backoff_seconds: float = DEFAULT_FAILURE_BACKOFF_SECONDS, *,
                 on_event: Callable[[dict], None] | None = None,
                 verify_wait_seconds: float = DEFAULT_VERIFY_WAIT_SECONDS) -> None:
        with self._lock:
            self._entries[provider] = _Entry(adapter=adapter, pins=pins, ttl_seconds=float(ttl_seconds),
                                             failure_backoff_seconds=float(failure_backoff_seconds),
                                             lock=threading.RLock(), on_event=on_event,
                                             verify_wait_seconds=float(verify_wait_seconds))
            self._wire_adapter_sink(provider, self._entries[provider])

    def unregister(self, provider: str) -> None:
        with self._lock:
            self._entries.pop(provider, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def entry(self, provider: str) -> _Entry | None:
        return self._entries.get(provider)

    def result(self, provider: str) -> VerificationResult | None:
        e = self._entries.get(provider)
        return e.result if e else None

    def last_error(self, provider: str) -> str | None:
        e = self._entries.get(provider)
        return e.last_error if e else None

    def fresh(self, provider: str) -> bool:
        e = self._entries.get(provider)
        return bool(e and e.result is not None and self._now() - e.verified_mono < e.ttl_seconds)

    def invalidate(self, provider: str) -> None:
        e = self._entries.get(provider)
        if e:
            with e.lock:
                e.result, e.failed_mono = None, None

    def _now(self) -> float:
        # Looked up at call time (module ``time``), never the wall clock or verified_at_host_clock.
        return self._clock() if self._clock is not None else time.monotonic()

    def refresh(self, provider: str) -> VerificationResult:
        """Re-attest now, blocking. Raises VerifyError (and clears the cached result) on failure."""
        e = self._entries.get(provider)
        if e is None:
            raise VerifyError(REASON_NOT_REGISTERED)
        with e.verify_lock:  # serialises attestations; the state lock is NOT held during verify()
            try:
                try:
                    result = e.adapter.verify()  # resolves the enclave host on first use (may hit network)
                finally:
                    _sync_profile_base_url(e)
                if not isinstance(result, VerificationResult):
                    raise VerifyError(f"adapter returned {type(result).__name__}, not VerificationResult")
            except Exception as exc:
                with e.lock:
                    e.result, e.failed_mono = None, self._now()
                    e.last_error = str(exc) if isinstance(exc, VerifyError) else f"{type(exc).__name__}: {exc}"
                _emit(e, {"kind": "verify_fail", "provider": provider, "purpose": "verify",
                          "host": _adapter_host(e.adapter),
                          "detail": {"vendor": getattr(e.adapter, "vendor", ""),
                                     "error_type": type(exc).__name__, "error": str(exc)[:300],
                                     "enclave_host": _adapter_host(e.adapter)}})
                raise exc if isinstance(exc, VerifyError) else VerifyError(e.last_error) from exc
            with e.lock:
                e.result, e.verified_mono, e.last_error, e.failed_mono = result, self._now(), None, None
            self._emit_verify_ok(provider, e, result)
            return result

    def _start_refresh(self, provider: str, e: _Entry) -> threading.Event:
        """Start (or join) the one background attestation for this entry. Caller holds e.lock."""
        if e.inflight is None:
            done = threading.Event()
            e.inflight = done

            def run():
                try:
                    self.refresh(provider)
                except Exception:
                    pass
                finally:
                    with e.lock:
                        e.inflight = None
                    done.set()
            threading.Thread(target=run, name=f"confidential-verify-{provider}", daemon=True).start()
        return e.inflight

    def _emit_verify_ok(self, provider: str, e: _Entry, result: VerificationResult) -> None:
        claims = (result.evidence or {}).get("claims") or {} if isinstance(result.evidence, dict) else {}
        observe = getattr(e.adapter, "observe_key", None)
        try:
            first_seen = observe(result.enclave_host, claims.get("tls_public_key_fp"),
                                 claims.get("hpke_public_key")) if callable(observe) else None
        except Exception:
            first_seen = None
        _emit(e, {"kind": "verify_ok", "provider": provider, "purpose": "verify", "host": result.enclave_host,
                  "detail": {"vendor": result.vendor, "source": "verify", "key_first_seen": first_seen,
                             "code_fingerprint": result.code_fingerprint,
                             "enclave_fingerprint": result.enclave_fingerprint,
                             "release_tag": result.release_tag, "enclave_host": result.enclave_host,
                             "verifier": result.verifier, "ttl_seconds": e.ttl_seconds,
                             **_tlog_fields(result.evidence),
                             "policy_check": _policy_check_detail(result.evidence),
                             "evidence": result.evidence}})

    def _adopt_adapter_result(self, provider: str, e: _Entry) -> bool:
        """If the adapter itself holds a fresh verification (e.g. a setup command or script called
        adapter.verify() directly), adopt it instead of attesting again. Caller holds e.lock."""
        res = getattr(e.adapter, "last_result", None)
        at = getattr(e.adapter, "verified_mono", None)
        if not isinstance(res, VerificationResult) or not isinstance(at, (int, float)) or res is e.result:
            return False
        if self._now() - at >= e.ttl_seconds:
            return False
        if at <= max(e.verified_mono or 0.0, e.failed_mono or 0.0):
            return False  # never resurrect a result older than the cache's last attempt (e.g. a failed refresh)
        e.result, e.verified_mono, e.last_error, e.failed_mono = res, float(at), None, None
        self._emit_verify_ok(provider, e, res)
        return True

    def ensure(self, provider: str, *, wait_seconds: float | None = None) -> tuple[bool, str, VerificationResult | None]:
        """(ok, reason, result). ok iff a fresh result exists and the pins match it. Re-attests once if
        the cached result is stale or missing (subject to the failure backoff), waiting at most
        ``verify_wait_seconds``; on timeout it refuses while the attestation continues in the
        background (Amendment 4). Never raises."""
        e = None
        try:
            e = self._entries.get(provider)
            if e is None:
                return False, REASON_NOT_REGISTERED, None
            with e.lock:
                needs = not self.fresh(provider)
                if needs and e.inflight is None and self._adopt_adapter_result(provider, e):
                    needs = False
                if needs:
                    if e.failed_mono is not None and self._now() - e.failed_mono < e.failure_backoff_seconds:
                        _hold(e.adapter, _fail_reason(e.last_error))
                        return False, _fail_reason(e.last_error), None
                    e.result = None  # stale results never vouch again (TTL is elapsed < ttl, monotonic)
                    done = self._start_refresh(provider, e)
            if needs and not done.wait(e.verify_wait_seconds if wait_seconds is None else float(wait_seconds)):
                _hold(e.adapter, REASON_VERIFY_PENDING)
                return False, REASON_VERIFY_PENDING, None
            with e.lock:
                result = e.result
                if result is None or not self.fresh(provider):
                    _hold(e.adapter, _fail_reason(e.last_error))
                    return False, _fail_reason(e.last_error), None
                if e.pins.match(result) is True:
                    if not _consent_recorded(e, result):
                        _hold(e.adapter, REASON_NO_CONSENT)
                        return False, REASON_NO_CONSENT, result  # stage nothing (F8)
                    _release(e.adapter)
                    return True, "attested enclave verified and pinned", result
                try:
                    had_pin = e.pins.get(result.vendor, result.router_repo) is not None
                except Exception:
                    had_pin = False
                reason = REASON_PIN_MISMATCH if had_pin else REASON_NO_PIN
                _hold(e.adapter, reason)
                try:
                    before = e.pins.pending()
                except Exception:
                    before = None
                try:
                    staged = e.pins.stage(result)
                except Exception as exc:  # empty fingerprints, unreadable store: refuse, do not stage
                    logger.warning("attested: not staging a pending pin: %s", exc)
                    return False, (REASON_BAD_RESULT if not (result.code_fingerprint and result.enclave_fingerprint)
                                   else reason), result
                if had_pin and e.auto_approve_platform_only and _auto_platform_only_ok(staged):
                    if _auto_apply(provider, e, staged):
                        if e.pins.match(result) is True and _consent_recorded(e, result):
                            _release(e.adapter)
                            return True, "attested enclave verified; platform-only pin applied by policy", result
                if staged != before:  # a new pending pin, not an idempotent re-stage
                    _emit(e, {"kind": "pin_staged", "provider": provider, "purpose": "verify",
                              "host": result.enclave_host,
                              "detail": {"vendor": staged.vendor, "router_repo": staged.router_repo,
                                         "code_fingerprint": staged.code_fingerprint,
                                         "enclave_fingerprint": staged.enclave_fingerprint,
                                         "release_tag": staged.release_tag, "enclave_host": staged.enclave_host,
                                         "previous": staged.previous,
                                         "previous_enclave_fingerprint": staged.previous_enclave_fingerprint,
                                         "reason": reason}})
                return False, reason, result
        except Exception as exc:  # fail closed
            logger.warning("attested verification check failed: %s", exc, exc_info=True)
            reason = f"attested verification check failed: {type(exc).__name__}"
            if e is not None:
                _hold(e.adapter, reason)
            return False, reason, None


def _sync_profile_base_url(e: _Entry) -> None:
    """Keep profile.base_url (what the attested predicate's host check reads via profile_base_url)
    equal to the adapter's resolved enclave URL; it stays the .invalid placeholder until resolution."""
    if e.profile is None:
        return
    try:
        url = e.adapter.base_url
        if isinstance(url, str) and url and e.profile.base_url != url:
            e.profile.base_url = url
    except Exception:
        logger.debug("could not sync attested profile base_url", exc_info=True)


AUTO_PLATFORM_ONLY = "auto_platform_only"


def _auto_platform_only_ok(pending) -> bool:
    """confidential.pins.auto_approve_platform_only: the code fingerprint is unchanged, only the
    enclave (platform) fingerprint differs, and the SDK's SIGNED hardware-measurements check passed
    (tinfoil 0.14.2 runs one only for TDX: verify_tdx_hardware against tinfoilsh/hardware-measurements)."""
    return bool(getattr(pending, "platform_only", False)
                and getattr(pending, "hardware_measurements_verified", False))


def _auto_apply(provider: str, e: _Entry, pending) -> bool:
    try:
        e.pins.apply(pending, approved_via=AUTO_PLATFORM_ONLY, approval_rule_key="confidential-mode:pin:auto-platform-only",
                     approved_by="policy")
    except Exception as exc:
        logger.warning("attested: platform-only auto-approval failed: %s", exc)
        return False
    ok = _emit(e, {"kind": "pin_applied", "provider": provider, "purpose": "verify", "host": pending.enclave_host,
                   "decision": AUTO_PLATFORM_ONLY,
                   "detail": {"vendor": pending.vendor, "router_repo": pending.router_repo,
                              "code_fingerprint": pending.code_fingerprint,
                              "enclave_fingerprint": pending.enclave_fingerprint,
                              "previous_enclave_fingerprint": pending.previous_enclave_fingerprint,
                              "platform": pending.platform, "previous_platform": pending.previous_platform,
                              "release_tag": pending.release_tag, "policy": "auto_approve_platform_only"}})
    # Without a consent ledger nothing will look for the row; with one, a failed write means the next
    # check refuses ("pin has no consent record"), which is the fail-closed outcome.
    return ok or e.consent_ledger is None


def _consent_recorded(e: _Entry, result: VerificationResult) -> bool:
    """F8: the pin in force must have a ``pin_applied`` (decision approve) ledger row with the same
    fingerprints, i.e. it went through consent.py's ask_choice flow, not a direct PinStore.apply by other
    in-process code. In-process code can still forge the row; this raises the bar (disclosed). Without a
    consent ledger configured the check is skipped. A ledger read error refuses (fail closed)."""
    if e.consent_ledger is None:
        return True
    key = (result.vendor, result.code_fingerprint, result.enclave_fingerprint)
    if key in e.consented:
        return True
    try:
        since = 0
        while True:
            rows = e.consent_ledger.tail(since, limit=5000)
            if not rows:
                return False
            for row in rows:
                since = max(since, int(getattr(row, "id", since) or since))
                if getattr(row, "kind", None) != "pin_applied" or \
                        getattr(row, "decision", None) not in ("approve", AUTO_PLATFORM_ONLY):
                    continue
                d = getattr(row, "detail", None)
                if isinstance(d, str):
                    import json
                    d = json.loads(d)
                if not isinstance(d, dict):
                    continue
                if (d.get("code_fingerprint"), d.get("enclave_fingerprint")) == key[1:] and \
                        (d.get("vendor") or key[0]) == key[0]:
                    e.consented.add(key)
                    return True
            if len(rows) < 5000:
                return False
    except Exception:
        logger.warning("attested: consent ledger unreadable; refusing", exc_info=True)
        return False


def _policy_check_detail(evidence) -> dict:
    """Second column at verify time: the standalone verify/policy_check.py re-verifies the captured
    release bundle against the captured trust root (offline). {"ok": bool, "reason": str, ...}.
    NEAR evidence has no release bundle: n/a (its checks are in evidence["checks"])."""
    if isinstance(evidence, dict) and evidence.get("vendor") == "near":
        return {"ok": None, "reason": "n/a: NEAR evidence carries no Sigstore release bundle"}
    try:
        from pathlib import Path as _P
        from .verify import policy_check
        ev = evidence or {}
        rel, tr, bundle = ev.get("release") or {}, ev.get("trusted_root") or {}, ev.get("sigstore_bundle")
        if not (bundle and rel.get("digest") and (tr.get("json_b64") or tr.get("path"))):
            return {"ok": False, "reason": "evidence incomplete: no bundle, digest or trust root captured"}
        if tr.get("json_b64"):
            import base64
            root = base64.b64decode(tr["json_b64"], validate=True)
        else:
            root = _P(tr["path"]).read_bytes()      # evidence captured before the bytes were embedded
        r = policy_check.check_bundle(bundle, digest=rel["digest"], repo=ev.get("repo") or "",
                                      tag=rel.get("tag"), trusted_root=root)
        return {"ok": bool(r.ok), "reason": r.reason, "repo_id": r.repo_id, "owner_id": r.owner_id,
                "workflow": r.workflow, "commit": r.commit}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"[:300]}


def _tlog_fields(evidence) -> dict:
    """logIndex / integratedTime of the release signature's transparency-log entry, from the stored
    bundle (no online Rekor)."""
    try:
        from .verify.policy_check import fulcio_identity
        bundle = (evidence or {}).get("sigstore_bundle")
        if not bundle:
            return {"log_index": None, "integrated_time": None}
        ident = fulcio_identity(bundle)
        return {"log_index": ident.get("log_index"), "integrated_time": ident.get("integrated_time")}
    except Exception:
        return {"log_index": None, "integrated_time": None}


def _adapter_host(adapter) -> str:
    try:
        return getattr(adapter, "enclave_host", "") or ""
    except Exception:
        return ""


def _emit(e: _Entry, event: dict) -> bool:
    """Best effort: a failing ledger never changes a verification decision. True iff written."""
    if e.on_event is None:
        return False
    try:
        e.on_event(event)
        return True
    except Exception:
        logger.warning("confidential-mode: ledger write for %s failed", event.get("kind"), exc_info=True)
        return False


def _fail_reason(err: str | None) -> str:
    return "attested verification failed" + (f" ({err[:160]})" if err else "")


def _hold(adapter, reason: str) -> None:
    hold = getattr(adapter, "hold", None)
    if callable(hold):
        hold(reason)


def _release(adapter) -> None:
    release = getattr(adapter, "release", None)
    if callable(release):
        release()


verification_cache = VerificationCache()


def adapter_for(provider_name: str):
    """The VendorAdapter behind a registered attested profile (W1/W5: current_hpke_key(), and
    verify.tinfoil.capture_sends / last_send_record for send rows), or None."""
    e = verification_cache.entry(provider_name)
    return e.adapter if e is not None else None


def _reset_for_tests() -> None:
    verification_cache.clear()


def attested_ok(provider_name: str, *, wait_seconds: float | None = None) -> Verdict:
    """ATTESTED-tier verdict for W1/W3: fresh verification (TTL handled here) and pins match.
    ``wait_seconds`` overrides the bounded wait (interactive commands such as check/setup may pass
    e.g. 60); a reason starting with VERIFY_PENDING_PREFIX means "verification pending", not off-tier."""
    entry = verification_cache.entry(provider_name)
    ok, reason, result = verification_cache.ensure(provider_name, wait_seconds=wait_seconds)
    host = ""
    if result is not None:
        host = result.enclave_host
    elif entry is not None:
        try:
            host = entry.adapter.enclave_host or ""  # resolved host, never a network call
        except Exception:
            host = ""
    return Verdict(in_tier=ok, reason=reason, host=host)


def _profile_base():
    from providers.base import ProviderProfile
    return ProviderProfile


def make_profile(adapter, pins: PinStore, ttl_seconds: float = DEFAULT_TTL_SECONDS, *,
                 cache: VerificationCache | None = None,
                 failure_backoff_seconds: float = DEFAULT_FAILURE_BACKOFF_SECONDS,
                 on_event: Callable[[dict], None] | None = None, ledger=None,
                 context_length: int = DEFAULT_CONTEXT_LENGTH,
                 verify_wait_seconds: float = DEFAULT_VERIFY_WAIT_SECONDS,
                 consent_ledger=None, auto_approve_platform_only: bool = False,
                 name: str = PROFILE_NAME, display_name: str = "Tinfoil (attested)",
                 description: str = "Tinfoil confidential inference; every client is bound to an attested enclave",
                 env_var: str = API_KEY_ENV, supports_streaming: bool | None = None):
    """Build an attested ProviderProfile (default 'attested-tinfoil') and register its cache entry. Never
    touches the network: base_url is the configured enclave URL, or the adapter's .invalid placeholder
    until the first verify() resolves the host by router discovery (then it is updated in place).
    ``supports_streaming=False`` makes Hermes send its main calls unstreamed (agent/turn_api_call.py
    _should_stream), which NEAR needs for model-signed (provider_tee) responses."""
    cache = cache if cache is not None else verification_cache
    ProviderProfile = _profile_base()

    class AttestedTinfoilProfile(ProviderProfile):
        def create_client(self, **client_kwargs: Any):
            return _create_client(self, cache, client_kwargs)

        def get_model_context_length(self, model: str) -> int | None:
            # Returning an int pre-empts Hermes' context-window probes (GET {base_url}/models, POST
            # /api/show with plain httpx and the API key at agent build), which would otherwise reach the
            # enclave host off the attested transport (Amendment 4, T2).
            return int(self._confidential_context_length)

    extra = {} if supports_streaming is None else {"supports_streaming": supports_streaming}
    profile = AttestedTinfoilProfile(
        name=name,
        display_name=display_name,
        description=description,
        base_url=adapter.base_url,
        env_vars=(env_var,),
        auth_type="api_key",
        **extra,
    )
    profile._confidential_adapter = adapter
    profile._confidential_env_var = env_var
    profile._confidential_context_length = int(context_length)
    profile._confidential_pins = pins
    if on_event is None and ledger is not None:
        on_event = ledger.append
    cache.register(name, adapter, pins, ttl_seconds, failure_backoff_seconds, on_event=on_event,
                   verify_wait_seconds=verify_wait_seconds)
    if consent_ledger is None and ledger is not None and callable(getattr(ledger, "tail", None)):
        consent_ledger = ledger
    cache.entry(name).consent_ledger = consent_ledger
    cache.entry(name).auto_approve_platform_only = bool(auto_approve_platform_only)
    cache.entry(name).profile = profile
    return profile


def _create_client(profile, cache: VerificationCache, client_kwargs: dict):
    api_key = client_kwargs.get("api_key") or api_key_for(getattr(profile, "_confidential_env_var", API_KEY_ENV))
    base_url = profile.base_url
    try:
        ok, reason, _ = cache.ensure(profile.name)
        base_url = profile.base_url  # may have just been resolved from the placeholder
        if not ok:
            return RefusingClient(reason, api_key=api_key, base_url=base_url)

        def gate() -> None:
            g_ok, g_reason, _ = cache.ensure(profile.name)
            if not g_ok:
                raise ConfidentialRefused(g_reason)

        return ConfidentialClient(profile._confidential_adapter, api_key=api_key, base_url=base_url, gate=gate,
                                  openai_kwargs=openai_kwargs_from(client_kwargs))
    except Exception as exc:
        logger.warning("attested create_client failed closed: %s", exc, exc_info=True)
        try:
            return RefusingClient(f"attested client unavailable: {type(exc).__name__}", api_key=api_key,
                                  base_url=base_url)
        except Exception:
            return RefusingClient("attested client unavailable")


def tinfoil_api_key() -> str:
    """TINFOIL_API_KEY through Hermes' secret scope (agent.secret_scope.get_secret, as Hermes' own
    provider plugins do); never os.environ directly. get_secret falls back to the environment itself
    where Hermes allows it, and fails closed under multiplexing."""
    return api_key_for(API_KEY_ENV)


def api_key_for(env_var: str) -> str:
    """An attested profile's API key through Hermes' secret scope (see tinfoil_api_key)."""
    try:
        from agent.secret_scope import get_secret
        return (get_secret(env_var) or "").strip()
    except Exception as exc:
        logger.warning("attested: could not resolve %s: %s", env_var, type(exc).__name__)
        return ""


def _cfg_get(config: dict | None, *path, default=None):
    node: Any = config or {}
    for key in path:
        if not isinstance(node, dict):
            return default
        node = node.get(key)
        if node is None:
            return default
    return node


def register_provider_profile(ctx, *, config: dict | None = None, data_dir: Path | str | None = None,
                              adapter=None, pins: PinStore | None = None,
                              on_event: Callable[[dict], None] | None = None, ledger=None):
    """Wire the attested profile into Hermes. Called by W1's register(ctx). Returns the profile.
    Makes no network call: router discovery (when no enclave is configured) waits for the first
    create_client / attested_ok, or for a setup command calling ``adapter.resolve_enclave_host()``.

    config: Hermes' loaded config (defaults to hermes_cli.config.load_config_readonly()); reads
    ``confidential.tinfoil.enclave`` and ``confidential.verify_ttl_seconds``.
    data_dir: plugin data dir (defaults to ``ctx.state.data_dir``); holds pins.yaml and the Tinfoil
    user cache secret.
    """
    import providers
    if config is None:
        from hermes_cli.config import load_config_readonly
        config = load_config_readonly() or {}
    if data_dir is None:
        data_dir = ctx.state.data_dir
    data_dir = Path(data_dir)
    if adapter is None:
        from .verify.tinfoil import TinfoilAdapter
        adapter = TinfoilAdapter(data_dir=data_dir, enclave=_cfg_get(config, "confidential", "tinfoil", "enclave"),
                                 tls_probe=_cfg_get(config, "confidential", "tinfoil", "tls_probe", default=True)
                                 is not False)
    if pins is None:
        pins = PinStore(data_dir / "pins.yaml")
    if ledger is None and on_event is None and ctx is not None:
        # The plugin's ledger (same default file consent.py writes pin_applied rows to): verify rows go
        # there, and attested_ok requires a consent record for the pin in force (F8).
        try:
            from .ledger import Ledger
            ledger = Ledger()
        except Exception:
            logger.warning("attested: no ledger; pins will not be cross-checked against consent", exc_info=True)
    ttl = float(_cfg_get(config, "confidential", "verify_ttl_seconds", default=DEFAULT_TTL_SECONDS))
    profile = make_profile(
        adapter, pins, ttl, on_event=on_event, ledger=ledger,
        context_length=int(_cfg_get(config, "confidential", "tinfoil", "context_length",
                                    default=DEFAULT_CONTEXT_LENGTH)),
        verify_wait_seconds=float(_cfg_get(config, "confidential", "verify_wait_seconds",
                                           default=DEFAULT_VERIFY_WAIT_SECONDS)),
        auto_approve_platform_only=_cfg_get(config, "confidential", "pins", "auto_approve_platform_only",
                                            default=False) is True)
    providers.register_provider(profile)
    return profile


# ── NEAR AI Cloud ────────────────────────────────────────────────────────────────────────────────

def near_models(config: dict | None) -> list[str]:
    """The NEAR model allowlist: confidential.near.models, plus model.default and any auxiliary.<task>.model
    whose provider is attested-near (Hermes sends those ids verbatim; NEAR signs the id in the request)."""
    out: list[str] = []
    listed = _cfg_get(config, "confidential", "near", "models", default=[])
    if isinstance(listed, list):
        out += [m.strip() for m in listed if isinstance(m, str) and m.strip()]
    model = _cfg_get(config, "model")
    if isinstance(model, dict) and model.get("provider") == NEAR_PROFILE_NAME:
        name = model.get("default") or model.get("model")
        if isinstance(name, str) and name.strip():
            out.append(name.strip())
    aux = _cfg_get(config, "auxiliary", default={})
    if isinstance(aux, dict):
        for task in aux.values():
            if isinstance(task, dict) and task.get("provider") == NEAR_PROFILE_NAME and \
                    isinstance(task.get("model"), str) and task["model"].strip():
                out.append(task["model"].strip())
    return sorted(set(out))


def register_near_profile(ctx, *, config: dict | None = None, data_dir: Path | str | None = None,
                          adapter=None, pins: PinStore | None = None,
                          on_event: Callable[[dict], None] | None = None, ledger=None):
    """Wire the 'attested-near' profile into Hermes (same cache, pins file and ledger as Tinfoil's).
    No network at register. Reads confidential.near.{base_url, models, require_provider_tee,
    require_tls_binding, accepted_tcb_statuses, signature_wait_seconds, streaming, context_length}."""
    import providers
    if config is None:
        from hermes_cli.config import load_config_readonly
        config = load_config_readonly() or {}
    if data_dir is None:
        data_dir = ctx.state.data_dir
    data_dir = Path(data_dir)
    near = lambda *p, default=None: _cfg_get(config, "confidential", "near", *p, default=default)  # noqa: E731
    require_tee = near("require_provider_tee", default=True) is not False
    if adapter is None:
        from .verify.near import DEFAULT_ACCEPTED_TCB, DEFAULT_BASE_URL, DEFAULT_SIGNATURE_WAIT_SECONDS, NearAdapter
        tcb = near("accepted_tcb_statuses", default=list(DEFAULT_ACCEPTED_TCB))
        adapter = NearAdapter(
            data_dir=data_dir, base_url=str(near("base_url", default=DEFAULT_BASE_URL)), models=near_models(config),
            require_provider_tee=require_tee, require_tls_binding=near("require_tls_binding", default=True) is not False,
            accepted_tcb_statuses=[t for t in tcb if isinstance(t, str)] if isinstance(tcb, list) else DEFAULT_ACCEPTED_TCB,
            signature_wait_seconds=float(near("signature_wait_seconds", default=DEFAULT_SIGNATURE_WAIT_SECONDS)))
    if hasattr(adapter, "provider_name"):
        adapter.provider_name = NEAR_PROFILE_NAME
    if pins is None:
        pins = PinStore(data_dir / "pins.yaml")
    if ledger is None and on_event is None and ctx is not None:
        try:
            from .ledger import Ledger
            ledger = Ledger()
        except Exception:
            logger.warning("attested-near: no ledger; pins will not be cross-checked against consent", exc_info=True)
    # Unstreamed by default: NEAR's gateway re-signs streamed completions itself (gateway kind), so only an
    # unstreamed completion can carry a model-signed provider_tee signature.
    streaming = near("streaming", default=False) is True
    profile = make_profile(
        adapter, pins, float(_cfg_get(config, "confidential", "verify_ttl_seconds", default=DEFAULT_TTL_SECONDS)),
        on_event=on_event, ledger=ledger, name=NEAR_PROFILE_NAME, display_name="NEAR AI Cloud (attested)",
        description="NEAR AI Cloud private inference; the gateway and model TEEs are attested and every "
                    "response signature is checked",
        env_var=NEAR_API_KEY_ENV, supports_streaming=streaming,
        context_length=int(near("context_length", default=DEFAULT_CONTEXT_LENGTH)),
        verify_wait_seconds=float(_cfg_get(config, "confidential", "verify_wait_seconds",
                                           default=DEFAULT_VERIFY_WAIT_SECONDS)))
    providers.register_provider(profile)
    return profile

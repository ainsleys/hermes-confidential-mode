"""The 'attested-tinfoil' ProviderProfile, its verification cache, and the attested_ok() verdict.

create_client(**kw) NEVER raises and NEVER returns None (either makes Hermes build a plain
openai.OpenAI to the same base_url, docs/dev/C0-spikes.md spike 2). It returns a ConfidentialClient when
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
# The background refresh (Amendment 9) starts a re-verification this long before the TTL ends
# (confidential.verify_refresh_lead_seconds; 0 turns the refresh off). It checks the lock and the clock at
# least every REFRESH_POLL_SECONDS.
DEFAULT_REFRESH_LEAD_SECONDS = 60.0
REFRESH_POLL_SECONDS = 5.0
# Context window reported to Hermes without probing the endpoint (confidential.tinfoil.context_length).
DEFAULT_CONTEXT_LENGTH = 65536

VERIFY_PENDING_PREFIX = "verification pending"
REASON_VERIFY_PENDING = "verification pending: attestation still in progress; this turn ended; resend"


def is_verification_pending(reason: str | None) -> bool:
    """For preflight/status wording: a pending attestation is not an off-tier destination."""
    return isinstance(reason, str) and reason.startswith(VERIFY_PENDING_PREFIX)
REASON_NO_CONSENT = "pin has no consent record"
REASON_BAD_RESULT = "attestation returned no usable fingerprints"
REASON_VERIFY_ROW_LOST = ("attestation verified but its verify_ok ledger row could not be written (for example its "
                          "evidence is over the ledger size cap); refused, because no receipt could show it")
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
    # (vendor, code_fp, enclave_fp) -> consented, from the ledger rows up to consent_scan_id (pin_applied
    # makes a key consented, a later pin_retired takes it back; Amendment 7)
    consented: dict = field(default_factory=dict)
    consent_scan_id: int = 0
    auto_approve_platform_only: bool = False
    observed_result: Any = None     # the last result counted by PinStore.observe
    refresh_lead_seconds: float = DEFAULT_REFRESH_LEAD_SECONDS
    refresher: Any = None           # the entry's BackgroundRefresh, when one was started
    used_mono: float = float("-inf")  # the last time ensure() accepted the cached result


class VerificationCache:
    """In-process verification cache keyed by provider name (not stored in ctx.state)."""

    def __init__(self, clock: Callable[[], float] | None = None):
        self._entries: dict[str, _Entry] = {}
        self._clock = clock
        self._lock = threading.Lock()
        # Whether the background refresh may run (the plugin passes "the profile is locked"). None defers
        # to the module's set_background_gate(); with neither, the refresh never runs.
        self.active: Callable[[], bool] | None = None
        self.refresh_poll_seconds = REFRESH_POLL_SECONDS

    def _wire_adapter_sink(self, provider: str, e: _Entry) -> None:
        """Let the adapter ledger verifications the cache never sees (SDK silent re-attest, per-loop
        async pool attestation) through this entry's on_event."""
        if hasattr(e.adapter, "event_sink"):
            try:
                e.adapter.event_sink = lambda ev: _emit(e, {**ev, "provider": provider})
            except Exception:
                pass
        if hasattr(e.adapter, "on_close"):
            try:
                e.adapter.on_close = lambda: self.stop_refresh(provider)
            except Exception:
                pass
        if hasattr(e.adapter, "on_stale"):
            # NEAR: the gateway refused the model key (HTTP 421); the next ensure() re-verifies.
            try:
                e.adapter.on_stale = lambda: self.invalidate(provider)
            except Exception:
                pass

    def register(self, provider: str, adapter, pins: PinStore, ttl_seconds: float,
                 failure_backoff_seconds: float = DEFAULT_FAILURE_BACKOFF_SECONDS, *,
                 on_event: Callable[[dict], None] | None = None,
                 verify_wait_seconds: float = DEFAULT_VERIFY_WAIT_SECONDS,
                 refresh_lead_seconds: float = DEFAULT_REFRESH_LEAD_SECONDS) -> None:
        with self._lock:
            old = self._entries.get(provider)
            self._entries[provider] = _Entry(adapter=adapter, pins=pins, ttl_seconds=float(ttl_seconds),
                                             failure_backoff_seconds=float(failure_backoff_seconds),
                                             lock=threading.RLock(), on_event=on_event,
                                             verify_wait_seconds=float(verify_wait_seconds),
                                             refresh_lead_seconds=float(refresh_lead_seconds))
            self._wire_adapter_sink(provider, self._entries[provider])
        _stop_entry(old)

    def unregister(self, provider: str) -> None:
        with self._lock:
            e = self._entries.pop(provider, None)
        _stop_entry(e)

    def clear(self) -> None:
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
        for e in entries:
            _stop_entry(e)

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
        """Drop the cached verification (unlock, an HTTP 421, a TLS pin mismatch) and stop the entry's
        background refresh; the next call verifies inline."""
        e = self._entries.get(provider)
        if e:
            with e.lock:
                e.result, e.failed_mono = None, None
            _stop_entry(e)

    def stop_refresh(self, provider: str | None = None) -> None:
        """Stop the background refresh of one entry (adapter close) or of every entry (unlock)."""
        entries = [self._entries.get(provider)] if provider is not None else list(self._entries.values())
        for e in entries:
            _stop_entry(e)

    def background_allowed(self, e: _Entry) -> bool:
        """The background refresh runs only while the profile is locked, the adapter is open and can
        prepare a verification without publishing it, and the lead is positive. Never raises."""
        try:
            gate = self.active if self.active is not None else _BACKGROUND_GATE
            if gate is None or gate() is not True:
                return False
            ad = e.adapter
            if getattr(ad, "closed", False) is True or e.refresh_lead_seconds <= 0:
                return False
            return callable(getattr(ad, "prepare_verification", None)) and \
                callable(getattr(ad, "commit_verification", None))
        except Exception:
            return False

    def _ensure_refresher(self, provider: str, e: _Entry) -> None:
        """Start the entry's background refresh after an accepted verification, unless one is running.
        Caller holds e.lock."""
        try:
            r = e.refresher
            if r is not None and r.alive():
                return
            if not self.background_allowed(e):
                return
            r = BackgroundRefresh(self, provider, e)
            e.refresher = r
            r.start()
        except Exception:
            logger.warning("attested: could not start the background refresh", exc_info=True)

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
                self._emit_verify_fail(provider, e, exc)
                raise exc if isinstance(exc, VerifyError) else VerifyError(e.last_error) from exc
            if not self._emit_verify_ok(provider, e, result):
                reason = REASON_VERIFY_ROW_LOST
                with e.lock:
                    e.result, e.failed_mono, e.last_error = None, self._now(), reason
                _emit(e, {"kind": "verify_fail", "provider": provider, "purpose": "verify",
                          "host": result.enclave_host,
                          "detail": {"vendor": result.vendor, "error_type": "LedgerError", "error": reason,
                                     "reason": reason, "enclave_host": result.enclave_host}})
                raise VerifyError(reason)
            with e.lock:
                e.result, e.verified_mono, e.last_error, e.failed_mono = result, self._now(), None, None
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

    def _emit_verify_fail(self, provider: str, e: _Entry, exc: BaseException, *, source: str | None = None) -> None:
        detail = {"vendor": getattr(e.adapter, "vendor", ""), "error_type": type(exc).__name__,
                  "error": str(exc)[:300], "reason": (str(exc) or type(exc).__name__)[:300],
                  "enclave_host": _adapter_host(e.adapter)}
        if source is not None:
            detail["source"] = source
        _emit(e, {"kind": "verify_fail", "provider": provider, "purpose": "verify",
                  "host": _adapter_host(e.adapter), "detail": detail})

    def _emit_verify_ok(self, provider: str, e: _Entry, result: VerificationResult, *, source: str = "verify",
                        accepted: bool | None = None) -> bool:
        """Write the verify_ok row. False only when a ledger sink is configured and the write failed (for
        example a detail over the size cap): the caller then refuses the verification, loudly, rather than
        accept a result whose evidence no receipt could show."""
        claims = (result.evidence or {}).get("claims") or {} if isinstance(result.evidence, dict) else {}
        observe = getattr(e.adapter, "observe_key", None)
        try:
            first_seen = observe(result.enclave_host, claims.get("tls_public_key_fp"),
                                 claims.get("hpke_public_key")) if callable(observe) else None
        except Exception:
            first_seen = None
        return e.on_event is None or _emit(e, {"kind": "verify_ok", "provider": provider, "purpose": "verify",
                  "host": result.enclave_host,
                  "detail": {"vendor": result.vendor, "source": source, "key_first_seen": first_seen,
                             **({} if accepted is None else {"accepted": accepted}),
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
        if not self._emit_verify_ok(provider, e, res):
            e.result, e.failed_mono, e.last_error = None, self._now(), REASON_VERIFY_ROW_LOST
            return False
        e.result, e.verified_mono, e.last_error, e.failed_mono = res, float(at), None, None
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
                if e.observed_result is not result:
                    e.observed_result = result
                    _background(e, "observe", lambda r=result: e.pins.observe(r))   # its fsync is off e.lock
                if e.pins.match(result) is True:
                    if not _consent_recorded(e, result):
                        _hold(e.adapter, REASON_NO_CONSENT)
                        return False, REASON_NO_CONSENT, result  # stage nothing (F8)
                    _release(e.adapter)
                    e.used_mono = self._now()
                    self._ensure_refresher(provider, e)
                    return True, "attested enclave verified and pinned", result
                return self._stage(provider, e, result, hold=True)
        except Exception as exc:  # fail closed
            logger.warning("attested verification check failed: %s", exc, exc_info=True)
            reason = f"attested verification check failed: {type(exc).__name__}"
            if e is not None:
                _hold(e.adapter, reason)
            return False, reason, None

    def _stage(self, provider: str, e: _Entry, result: VerificationResult, *,
               hold: bool) -> tuple[bool, str, VerificationResult | None]:
        """The pins do not match ``result``: stage its pending batch (a pin_staged row when the batch is new)
        and refuse. ``hold`` holds the adapter and allows the platform-only policy (the inline path); the
        background refresh passes False, so the verification in use keeps vouching until its TTL ends and
        the next inline verification refuses. Caller holds e.lock."""
        try:
            had_pin = e.pins.get(result.vendor, result.router_repo) is not None
        except Exception:
            had_pin = False
        reason = REASON_PIN_MISMATCH if had_pin else REASON_NO_PIN
        if hold:
            _hold(e.adapter, reason)
        try:   # this identity's own batch: another identity's batch is not "before" (Amendment 7)
            before = (e.pins.pending_for(result.vendor, result.router_repo)
                      if hasattr(e.pins, "pending_for") else e.pins.pending())
        except Exception:
            before = None
        try:
            staged = e.pins.stage(result)
        except Exception as exc:  # empty fingerprints, unreadable store: refuse, do not stage
            logger.warning("attested: not staging a pending pin: %s", exc)
            return False, (REASON_BAD_RESULT if not (result.code_fingerprint and result.enclave_fingerprint)
                           else reason), result
        if hold and had_pin and e.auto_approve_platform_only and _auto_platform_only_ok(staged):
            if _auto_apply(provider, e, staged):
                if e.pins.match(result) is True and _consent_recorded(e, result):
                    _release(e.adapter)
                    return True, "attested enclave verified; platform-only pin applied by policy", result
        if _needs_composes(staged) and hasattr(e.pins, "prefetch_composes"):
            _background(e, "prefetch", lambda s=staged: _prefetch(provider, e, s))
        if _ckey(staged) != _ckey(before):  # a new pending batch, not a re-stage or a display refresh
            _emit(e, {"kind": "pin_staged", "provider": provider, "purpose": "verify",
                      "host": result.enclave_host,
                      "detail": {"vendor": staged.vendor, "router_repo": staged.router_repo,
                                 "code_fingerprint": staged.code_fingerprint,
                                 "enclave_fingerprint": staged.enclave_fingerprint,
                                 "release_tag": staged.release_tag, "enclave_host": staged.enclave_host,
                                 "previous": staged.previous,
                                 "previous_enclave_fingerprint": staged.previous_enclave_fingerprint,
                                 "entries": _entry_rows(staged),
                                 "reason": reason}})
        return False, reason, result


_BACKGROUND_GATE: Callable[[], bool] | None = None


def set_background_gate(fn: Callable[[], bool] | None) -> None:
    """Register the predicate the background refresh checks before every step (the plugin passes "the
    profile is locked"). None, the default, keeps the refresh off."""
    global _BACKGROUND_GATE
    _BACKGROUND_GATE = fn


def _stop_entry(e: _Entry | None) -> None:
    r = getattr(e, "refresher", None) if e is not None else None
    if r is not None:
        r.stop()


def _accepts(e: _Entry, result: VerificationResult) -> bool:
    """The pin check the inline path makes before it releases a verification: every CVM matches an
    approved entry and each match has its consent row. Never raises (False on any error)."""
    try:
        return e.pins.match(result) is True and _consent_recorded(e, result)
    except Exception:
        return False


class BackgroundRefresh:
    """One daemon thread per cache entry that re-verifies before the TTL ends (Amendment 9).

    The thread starts after an accepted verification while the profile is locked. At
    ``refresh_lead_seconds`` before the TTL ends it calls the adapter's ``prepare_verification()``, which
    captures over the network without the adapter's send lock and publishes nothing. The pin check then
    runs on the new result. Only an accepted result is committed to the adapter and swapped into the
    cache, both under the entry lock. A failed capture, a lost verify_ok row or a result the pins do not
    accept changes nothing: the verification in use keeps vouching until its TTL ends, and the next call
    verifies inline and refuses as it would without the refresh. A failure is retried after the failure
    backoff while time remains; a staged result is not retried. A verification is refreshed only when a
    call used it within two lead periods of its end (the lead window or the lead before it), so a session
    idle that long makes no request; a call in the window still refreshes. The thread stops on unlock, on adapter
    close, on invalidation (an HTTP 421 or a TLS pin mismatch) and when the profile is no longer locked.
    Each attempt writes a verify_ok or verify_fail row with ``source: background``."""

    def __init__(self, cache: VerificationCache, provider: str, e: _Entry):
        self.cache, self.provider, self.e = cache, provider, e
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.failed_mono: float | None = None
        self.done_for: tuple | None = None    # (id(result), verified_mono) the refresh gave up on
        self.attempts = 0
        self.outcomes: list[str] = []

    def start(self) -> None:
        t = threading.Thread(target=self._run, name=f"confidential-refresh-{self.provider}", daemon=True)
        self.thread = t
        t.start()

    def stop(self) -> None:
        self.stop_event.set()

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive() and not self.stop_event.is_set()

    def _run(self) -> None:
        try:
            while not self.stop_event.is_set():
                delay = self.step()
                if delay is None:
                    break
                self.stop_event.wait(max(0.0, float(delay)))
        except Exception:
            logger.warning("attested: background refresh stopped on an error", exc_info=True)
        finally:
            self.stop_event.set()

    def step(self) -> float | None:
        """One decision: seconds until the next look, or None to end the thread. Never raises."""
        try:
            cache, e = self.cache, self.e
            poll = max(0.001, float(cache.refresh_poll_seconds))
            if self.stop_event.is_set() or not cache.background_allowed(e):
                return None
            now = cache._now()
            with e.lock:
                result, t0 = e.result, e.verified_mono
            if result is None:
                return None                      # nothing to refresh: the next call verifies inline
            expires = t0 + e.ttl_seconds
            if now >= expires:
                return None                      # expired: the inline path takes over, as without the refresh
            due = expires - e.refresh_lead_seconds
            if now < due:
                return min(due - now, poll)
            if self.e.used_mono < due - e.refresh_lead_seconds:
                # No call used the verification in the lead window or the lead before it: an idle session
                # is not refreshed. Keep looking until expiry, so a call inside the window still refreshes.
                return min(expires - now, poll)
            if self.done_for == (id(result), t0):
                return min(expires - now, poll)
            if self.failed_mono is not None and now - self.failed_mono < e.failure_backoff_seconds:
                return min(e.failure_backoff_seconds - (now - self.failed_mono), poll)
            self.outcomes.append(self.attempt(result, t0))
            return 0.0
        except Exception:
            logger.warning("attested: background refresh step failed", exc_info=True)
            return None

    def _current(self, result, t0) -> bool:
        e = self.e
        return (not self.stop_event.is_set() and e.result is result and e.verified_mono == t0
                and self.cache.background_allowed(e))

    def attempt(self, result: VerificationResult, t0: float) -> str:
        """One background verification. Returns accepted, staged, failed, discarded or busy."""
        cache, e, provider = self.cache, self.e, self.provider
        if not e.verify_lock.acquire(blocking=False):
            return "busy"                        # an inline verification is running
        try:
            self.attempts += 1
            try:
                prepared = e.adapter.prepare_verification()   # network; no send lock, nothing published
                if not isinstance(getattr(prepared, "result", None), VerificationResult):
                    raise VerifyError(f"adapter prepared {type(getattr(prepared, 'result', None)).__name__}, "
                                      "not VerificationResult")
            except Exception as exc:
                self.failed_mono = cache._now()
                cache._emit_verify_fail(provider, e, exc, source="background")
                return "failed"
            new = prepared.result
            with e.lock:
                if not self._current(result, t0):
                    prepared.discard()           # unlocked, invalidated or replaced during the capture
                    return "discarded"
                if not _accepts(e, new):
                    cache._emit_verify_ok(provider, e, new, source="background", accepted=False)
                    cache._stage(provider, e, new, hold=False)
                    prepared.discard()
                    self.done_for = (id(result), t0)
                    return "staged"
                try:
                    e.adapter.commit_verification(prepared, hold=False)
                except Exception as exc:
                    prepared.discard()
                    self.failed_mono = cache._now()
                    cache._emit_verify_fail(provider, e, exc, source="background")
                    return "failed"
                # The row is written after the commit, so no accepted row names a verification the adapter
                # never used. A lost row cannot be undone by un-committing, so it fails closed instead: the
                # adapter is held and the entry dropped; the next call verifies inline and writes its row.
                if not cache._emit_verify_ok(provider, e, new, source="background", accepted=True):
                    _hold(e.adapter, REASON_VERIFY_ROW_LOST)
                    e.result, e.failed_mono, e.last_error = None, cache._now(), REASON_VERIFY_ROW_LOST
                    self.failed_mono = cache._now()
                    cache._emit_verify_fail(provider, e, VerifyError(REASON_VERIFY_ROW_LOST), source="background")
                    self.stop()
                    return "failed"
                e.result, e.verified_mono, e.last_error, e.failed_mono = new, cache._now(), None, None
                self.failed_mono, self.done_for = None, None
                return "accepted"
        finally:
            e.verify_lock.release()


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


def _background(e: _Entry, name: str, fn: Callable[[], Any]) -> None:
    """Run ``fn`` on one daemon thread per (entry, name); a call while one runs is dropped (coalesced)."""
    running = e.__dict__.setdefault("_bg", {})
    t = running.get(name)
    if t is not None and t.is_alive():
        return

    def run():
        try:
            fn()
        except Exception:
            logger.debug("attested: background %s failed", name, exc_info=True)
    t = threading.Thread(target=run, name=f"confidential-{name}", daemon=True)
    running[name] = t
    t.start()


def _needs_composes(pending) -> bool:
    return any(str(getattr(x, "cvm_role", "")).startswith("model:") and getattr(x, "components", None) is not None
               and "services" not in (getattr(x, "pinned", ()) or ()) for x in (getattr(pending, "entries", ()) or ()))


def _prefetch(provider: str, e: _Entry, staged) -> None:
    """Fetch the inner compose files of a staged NEAR batch (public GitHub texts) so that its service map
    can be pinned; a batch whose consent key changed gets its own pin_staged row."""
    before = _ckey(staged)
    for after in e.pins.prefetch_composes():
        if after.key == staged.key and _ckey(after) != before:
            _emit(e, {"kind": "pin_staged", "provider": provider, "purpose": "verify", "host": after.enclave_host,
                      "detail": {"vendor": after.vendor, "router_repo": after.router_repo,
                                 "code_fingerprint": after.code_fingerprint,
                                 "enclave_fingerprint": after.enclave_fingerprint, "entries": _entry_rows(after),
                                 "reason": "the inner compose files were fetched: the service map is now pinned"}})


def _ckey(pending) -> Any:
    from .pins import consent_key
    return None if pending is None else consent_key(pending)


def _entry_rows(pending) -> list:
    """One {cvm_role, code_fingerprint, enclave_fingerprint, pinned} per entry of a pending batch."""
    return [{"cvm_role": getattr(x, "cvm_role", None), "code_fingerprint": getattr(x, "code_fingerprint", None),
             "enclave_fingerprint": getattr(x, "enclave_fingerprint", None),
             "pinned": list(getattr(x, "pinned", ()) or ())}
            for x in (getattr(pending, "entries", ()) or ())]


def _auto_platform_only_ok(pending) -> bool:
    """confidential.pins.auto_approve_platform_only: the code fingerprint is unchanged, only the
    enclave (platform) fingerprint differs, and the SDK's SIGNED hardware-measurements check passed
    (tinfoil 0.14.2 runs one only for TDX: verify_tdx_hardware against tinfoilsh/hardware-measurements)."""
    return bool(getattr(pending, "platform_only", False)
                and getattr(pending, "hardware_measurements_verified", False))


AUTO_APPLY_VENDORS = ("tinfoil",)   # replace-only vendors; never a concurrent (approved-set) vendor such as NEAR


def _auto_apply(provider: str, e: _Entry, pending) -> bool:
    """Apply a platform-only pin by policy. Tinfoil only, and only as a replacement (Amendment 7): a vendor
    whose approved pins form a set (NEAR) is never widened without a person's answer. PinStore.apply
    refuses approved_by="policy" for such a vendor too."""
    if getattr(pending, "vendor", None) not in AUTO_APPLY_VENDORS:
        return False
    try:
        e.pins.apply(pending, approved_via=AUTO_PLATFORM_ONLY, approval_rule_key="confidential-mode:pin:auto-platform-only",
                     approved_by="policy")
    except Exception as exc:
        logger.warning("attested: platform-only auto-approval failed: %s", exc)
        return False
    entry = (getattr(pending, "entries", ()) or (pending,))[0]
    ok = _emit(e, {"kind": "pin_applied", "provider": provider, "purpose": "verify", "host": pending.enclave_host,
                   "decision": AUTO_PLATFORM_ONLY,
                   "detail": {"vendor": pending.vendor, "router_repo": pending.router_repo,
                              "cvm_role": getattr(entry, "cvm_role", None) or "router",
                              "approved_via": AUTO_PLATFORM_ONLY,
                              "code_fingerprint": entry.code_fingerprint,
                              "enclave_fingerprint": entry.enclave_fingerprint,
                              "previous_enclave_fingerprint": pending.previous_enclave_fingerprint,
                              "platform": pending.platform, "previous_platform": pending.previous_platform,
                              "release_tag": pending.release_tag, "policy": "auto_approve_platform_only"}})
    # Without a consent ledger nothing will look for the row; with one, a failed write means the next
    # check refuses ("pin has no consent record"), which is the fail-closed outcome.
    return ok or e.consent_ledger is None


def _consent_recorded(e: _Entry, result: VerificationResult) -> bool:
    """F8 and Amendment 7: every approved entry the result matches must have a ``pin_applied`` row (decision
    approve, or the Tinfoil platform-only policy) with the entry's own fingerprints, and no later
    ``pin_retired`` row for them. So the entry went through consent.py's flow, not a hand edit of pins.yaml
    or a direct PinStore.apply. In-process code can still forge the row; this raises the bar (disclosed).
    Rows are read incrementally and in order, so a retirement in another process counts here too. Without a
    consent ledger configured the check is skipped. A ledger read error refuses (fail closed)."""
    if e.consent_ledger is None:
        return True
    try:
        entries = e.pins.matching_entries(result) if hasattr(e.pins, "matching_entries") else None
    except Exception:
        entries = None
    if entries:
        keys = [(result.vendor, x.router_repo, x.cvm_role, x.code_fingerprint, x.enclave_fingerprint)
                for x in entries]
    else:
        keys = [(result.vendor, result.router_repo, None, result.code_fingerprint, result.enclave_fingerprint)]
    try:
        _scan_consent(e)
    except Exception:
        logger.warning("attested: consent ledger unreadable; refusing", exc_info=True)
        return False
    return all(_consented(e, k) for k in keys)


def _consented(e: _Entry, k: tuple) -> bool:
    """A row naming identity and role decides for exactly that entry; an older row that names only the
    fingerprints (and maybe the vendor) counts when no such row exists (a row without a vendor counts
    under any vendor)."""
    if k in e.consented:
        return e.consented[k] is True
    vendor, _, _, code, enclave = k
    return e.consented.get((vendor, code, enclave), e.consented.get((None, code, enclave))) is True


def _scan_consent(e: _Entry) -> None:
    """Fold every ledger row after ``e.consent_scan_id`` into ``e.consented``, in id order."""
    import json
    while True:
        rows = e.consent_ledger.tail(e.consent_scan_id, limit=5000)
        if not rows:
            return
        for row in rows:
            e.consent_scan_id = max(e.consent_scan_id, int(getattr(row, "id", e.consent_scan_id) or e.consent_scan_id))
            kind = getattr(row, "kind", None)
            if kind == "pin_applied":
                if getattr(row, "decision", None) not in ("approve", AUTO_PLATFORM_ONLY):
                    continue
            elif kind != "pin_retired":
                continue
            d = getattr(row, "detail", None)
            if isinstance(d, str):
                d = json.loads(d)
            if not isinstance(d, dict):
                continue
            from .ledger import is_truncated
            if is_truncated(d):
                # FI-6: a row stored with the too-large marker. A pin_applied row grants nothing; a pin_retired
                # row withdraws consent for every entry with the kept fingerprints, or for every entry when the
                # fingerprints were not kept.
                if kind == "pin_retired":
                    code, enclave = d.get("code_fingerprint"), d.get("enclave_fingerprint")
                    for k in list(e.consented):
                        if not (code and enclave) or (k[-2], k[-1]) == (code, enclave):
                            e.consented[k] = False
                    if code and enclave:
                        e.consented[(d.get("vendor") or None, code, enclave)] = False
                        e.consented[(None, code, enclave)] = False
                continue
            if d.get("router_repo") and d.get("cvm_role"):
                key = (d.get("vendor") or None, d["router_repo"], d["cvm_role"], d.get("code_fingerprint"),
                       d.get("enclave_fingerprint"))
            else:   # written before rows named the identity and role (Amendment 7)
                key = (d.get("vendor") or None, d.get("code_fingerprint"), d.get("enclave_fingerprint"))
            e.consented[key] = kind == "pin_applied"
        if len(rows) < 5000:
            return


def clear_consent_cache(provider: str | None = None) -> None:
    """Forget what the consent check has read from the ledger (after ``pins retire`` in this process)."""
    for name, e in list(verification_cache._entries.items()):
        if provider is None or name == provider:
            with e.lock:
                e.consented, e.consent_scan_id = {}, 0


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
        import hashlib
        if hashlib.sha256(root).hexdigest() != tr.get("sha256"):
            return {"ok": False, "reason": "trusted root does not match its recorded sha256"}
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


LEDGER_RETRY_DELAY_SECONDS = 0.25   # one retry on a transient "database is locked"


def _emit(e: _Entry, event: dict) -> bool:
    """Write one ledger row; True iff written. A transient "database is locked" is retried once after
    LEDGER_RETRY_DELAY_SECONDS. A failed verify_ok write refuses that verification (Amendment 5.2); other
    rows stay best effort."""
    if e.on_event is None:
        return False
    for attempt in (0, 1):
        try:
            e.on_event(event)
            return True
        except Exception as exc:
            if attempt == 0 and "database is locked" in str(exc).lower():
                time.sleep(LEDGER_RETRY_DELAY_SECONDS)
                continue
            logger.warning("confidential-mode: ledger write for %s failed", event.get("kind"), exc_info=True)
            return False
    return False


def _fail_reason(err: str | None) -> str:
    return "attested verification failed" + (f" ({err[:300]})" if err else "")


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
                 env_var: str = API_KEY_ENV, supports_streaming: bool | None = None,
                 refresh_lead_seconds: float = DEFAULT_REFRESH_LEAD_SECONDS):
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
    profile.classify_api_error = classify_refusal  # Hermes' error classifier consults it for this provider
    profile._confidential_env_var = env_var
    profile._confidential_context_length = int(context_length)
    profile._confidential_pins = pins
    if on_event is None and ledger is not None:
        on_event = ledger.append
    cache.register(name, adapter, pins, ttl_seconds, failure_backoff_seconds, on_event=on_event,
                   verify_wait_seconds=verify_wait_seconds, refresh_lead_seconds=refresh_lead_seconds)
    if consent_ledger is None and ledger is not None and callable(getattr(ledger, "tail", None)):
        consent_ledger = ledger
    cache.entry(name).consent_ledger = consent_ledger
    cache.entry(name).auto_approve_platform_only = bool(auto_approve_platform_only)
    cache.entry(name).profile = profile
    return profile


_OVERFLOW_HINTS = ("context_length_exceeded", "context length", "maximum context", "context window",
                   "too many tokens", "prompt is too long", "max_tokens_exceeded", "reduce the length")


def _is_overflow(body: Any, message: str) -> bool:
    err = body.get("error") if isinstance(body, dict) else None
    text = " ".join(str(v) for v in ((err or {}).values() if isinstance(err, dict) else ())) + " " + (message or "")
    text = text.lower()
    try:
        from .hermes_compat import context_overflow_patterns
        hints = context_overflow_patterns() + _OVERFLOW_HINTS
    except Exception:
        hints = _OVERFLOW_HINTS
    return any(h in text for h in hints)


def classify_refusal(error, **_context):
    """``ProviderProfile.classify_api_error`` (agent/error_classifier.py ``_profile_verdict``) for a refusal
    raised by an attested transport (verify.near.NearRefusal). Never raises; None for anything else.

    A retry never changes what is released (only a 200 that is fully attested and decrypts reaches
    Hermes), so ordinary gateway errors keep Hermes' recovery: 429 backs off (rate_limit), 5xx retries
    (overloaded for 503/529, else server_error), a 400 that says the context is too long compresses
    (context_overflow). None of them falls back to another provider. A 421 (model key no longer valid:
    re-verified under the backoff) and every genuine refusal (withheld, undecryptable, unsigned, swapped
    key, success-shaped non-200, refused before sending) are not retried."""
    try:
        seen, exc = set(), error
        while exc is not None and id(exc) not in seen:
            seen.add(id(exc))
            if type(exc).__name__ == "NearRefusal":
                status = getattr(exc, "status_code", None)
                body = getattr(exc, "body", None) or {}
                stay = {"should_fallback": False, "should_rotate_credential": False}
                if status == 429:
                    return {"reason": "rate_limit", "retryable": True, "should_compress": False, **stay}
                if isinstance(status, int) and 500 <= status < 600:
                    return {"reason": "overloaded" if status in (503, 529) else "server_error", "retryable": True,
                            "should_compress": False, **stay}
                if status in (400, 413) and _is_overflow(body, ""):
                    return {"reason": "context_overflow", "retryable": True, "should_compress": True, **stay}
                return {"reason": "provider_policy_blocked", "retryable": False, "should_compress": False, **stay}
            exc = exc.__cause__ or exc.__context__
    except Exception:
        pass
    return None


def _refusal_recorder(profile, cache: "VerificationCache | None" = None):
    """The ledger hook for a provider-gate refusal: one send_refused row with stage provider_gate, skipped
    inside the llm gate (which writes its own). NEAR uses its adapter's record_refusal; Tinfoil writes the
    same row through the cache entry's ledger sink. None when neither exists."""
    adapter = getattr(profile, "_confidential_adapter", None)
    record = getattr(adapter, "record_refusal", None)
    if callable(record):
        return lambda exc: record(exc, stage="provider_gate")
    e = (cache or verification_cache).entry(getattr(profile, "name", ""))
    if e is None or e.on_event is None:
        return None

    def write(exc: BaseException) -> None:
        try:
            if getattr(exc, "ledgered", False) is True:
                return
            exc.ledgered = True
            from . import sendctx
            ctx = sendctx.current() or {}
            if ctx.get("refusals_ledgered_by") == "llm_gate":
                return
            _emit(e, {"kind": "send_refused", "session_id": str(ctx.get("session_id") or ""),
                      "purpose": str(ctx.get("purpose") or "unattributed"), "provider": profile.name,
                      "host": _adapter_host(adapter), "model": str(ctx.get("model") or ""), "tier": ctx.get("tier"),
                      "verdict": "refused", "decision": "refused",
                      "detail": {"vendor": getattr(adapter, "vendor", ""), "source": "provider_gate",
                                 "reason_code": "refused_provider_gate", "stage": "provider_gate",
                                 "reason": (str(exc) or type(exc).__name__)[:300]}})
        except Exception:
            logger.warning("attested: could not ledger a provider-gate refusal", exc_info=True)
    return write


#: The refusal reason when a client is built with no API key from any source (Amendment 11). The lock checks the
#: key; a process that cannot read the key later (a service without the variable, a multiplexed gateway) refuses
#: each call with this reason and a send_refused row, never a breach: nothing left the tier.
REASON_KEY_UNREADABLE = "vendor key unreadable"


def _create_client(profile, cache: VerificationCache, client_kwargs: dict):
    env_var = getattr(profile, "_confidential_env_var", API_KEY_ENV)
    api_key = client_kwargs.get("api_key") or api_key_for(env_var)
    base_url = profile.base_url
    on_refuse = _refusal_recorder(profile, cache)
    if not (isinstance(api_key, str) and api_key.strip()):
        return RefusingClient(f"{REASON_KEY_UNREADABLE}: {env_var} is not set or not readable in this process",
                              base_url=base_url, on_refuse=on_refuse)
    try:
        ok, reason, _ = cache.ensure(profile.name)
        base_url = profile.base_url  # may have just been resolved from the placeholder
        if not ok:
            return RefusingClient(reason, api_key=api_key, base_url=base_url, on_refuse=on_refuse)

        def gate() -> None:
            g_ok, g_reason, _ = cache.ensure(profile.name)
            if not g_ok:
                raise ConfidentialRefused(g_reason)

        return ConfidentialClient(profile._confidential_adapter, api_key=api_key, base_url=base_url, gate=gate,
                                  openai_kwargs=openai_kwargs_from(client_kwargs), on_refuse=on_refuse)
    except Exception as exc:
        logger.warning("attested create_client failed closed: %s", exc, exc_info=True)
        try:
            return RefusingClient(f"attested client unavailable: {type(exc).__name__}", api_key=api_key,
                                  base_url=base_url, on_refuse=on_refuse)
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


def image_parts_from(config: dict | None) -> str:
    """confidential.near.image_parts: "disclose" (default, also when absent) or "refuse"; any other value
    is "refuse" (fail closed; the preflight refuses the lock on it)."""
    v = _cfg_get(config, "confidential", "near", "image_parts", default="disclose")
    return v if v in ("disclose", "refuse") else "refuse"


def refresh_lead_from(config: dict | None) -> float:
    """confidential.verify_refresh_lead_seconds: a number (0 or less turns the background refresh off);
    anything else is the default."""
    v = _cfg_get(config, "confidential", "verify_refresh_lead_seconds", default=DEFAULT_REFRESH_LEAD_SECONDS)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return DEFAULT_REFRESH_LEAD_SECONDS
    return float(v)


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
                                            default=False) is True,
        refresh_lead_seconds=refresh_lead_from(config))
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
    require_tls_binding, accepted_tcb_statuses, signature_wait_seconds, streaming, context_length, encrypt,
    reverify_backoff_seconds, image_parts}."""
    import providers
    if config is None:
        from hermes_cli.config import load_config_readonly
        config = load_config_readonly() or {}
    if data_dir is None:
        data_dir = ctx.state.data_dir
    data_dir = Path(data_dir)
    near = lambda *p, default=None: _cfg_get(config, "confidential", "near", *p, default=default)  # noqa: E731
    require_tee = near("require_provider_tee", default=True) is not False
    encrypt = near("encrypt", default=True) is not False
    if adapter is None:
        from .verify.near import DEFAULT_ACCEPTED_TCB, DEFAULT_BASE_URL, DEFAULT_SIGNATURE_WAIT_SECONDS, NearAdapter
        tcb = near("accepted_tcb_statuses", default=list(DEFAULT_ACCEPTED_TCB))
        adapter = NearAdapter(
            data_dir=data_dir, base_url=str(near("base_url", default=DEFAULT_BASE_URL)), models=near_models(config),
            require_provider_tee=require_tee, require_tls_binding=near("require_tls_binding", default=True) is not False,
            accepted_tcb_statuses=[t for t in tcb if isinstance(t, str)] if isinstance(tcb, list) else DEFAULT_ACCEPTED_TCB,
            signature_wait_seconds=float(near("signature_wait_seconds", default=DEFAULT_SIGNATURE_WAIT_SECONDS)),
            encrypt=encrypt, reverify_backoff_seconds=float(near("reverify_backoff_seconds", default=30.0)),
            image_parts=image_parts_from(config))
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
    # While encrypting (confidential.near.encrypt, default true) streaming is refused by the transport, so
    # the profile never asks Hermes to stream; confidential.near.streaming has no effect then.
    streaming = near("streaming", default=False) is True and not encrypt
    profile = make_profile(
        adapter, pins, float(_cfg_get(config, "confidential", "verify_ttl_seconds", default=DEFAULT_TTL_SECONDS)),
        on_event=on_event, ledger=ledger, name=NEAR_PROFILE_NAME, display_name="NEAR AI Cloud (attested)",
        description="NEAR AI Cloud private inference; the gateway and model TEEs are attested and every "
                    "response signature is checked",
        env_var=NEAR_API_KEY_ENV, supports_streaming=streaming,
        context_length=int(near("context_length", default=DEFAULT_CONTEXT_LENGTH)),
        verify_wait_seconds=float(_cfg_get(config, "confidential", "verify_wait_seconds",
                                           default=DEFAULT_VERIFY_WAIT_SECONDS)),
        refresh_lead_seconds=refresh_lead_from(config))
    providers.register_provider(profile)
    return profile

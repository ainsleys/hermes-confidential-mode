"""The 'attested-tinfoil' ProviderProfile, its verification cache, and the attested_ok() verdict.

create_client(**kw) NEVER raises and NEVER returns None (either makes Hermes build a plain
openai.OpenAI to the same base_url, docs/C0-spikes.md spike 2). It returns a ConfidentialClient when
verification is fresh and the pins match, otherwise refreshes once (if the cached result is stale or
missing), otherwise a RefusingClient.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .client import ConfidentialClient, ConfidentialRefused, RefusingClient, openai_kwargs_from
from .pins import PinStore
from .tiers import Verdict
from .verify.base import VerificationResult, VerifyError

logger = logging.getLogger(__name__)

PROFILE_NAME = "attested-tinfoil"
API_KEY_ENV = "TINFOIL_API_KEY"
DEFAULT_TTL_SECONDS = 300.0
# After a failed attestation, further create_client()/attested_ok() calls refuse without re-attesting
# for this long (Hermes calls create_client ~4 times before the first turn).
DEFAULT_FAILURE_BACKOFF_SECONDS = 10.0

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


class VerificationCache:
    """In-process verification cache keyed by provider name (not stored in ctx.state)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._entries: dict[str, _Entry] = {}
        self._clock = clock
        self._lock = threading.Lock()

    def register(self, provider: str, adapter, pins: PinStore, ttl_seconds: float,
                 failure_backoff_seconds: float = DEFAULT_FAILURE_BACKOFF_SECONDS, *,
                 on_event: Callable[[dict], None] | None = None) -> None:
        with self._lock:
            self._entries[provider] = _Entry(adapter=adapter, pins=pins, ttl_seconds=float(ttl_seconds),
                                             failure_backoff_seconds=float(failure_backoff_seconds),
                                             lock=threading.RLock(), on_event=on_event)

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
        return bool(e and e.result is not None and self._clock() - e.verified_mono < e.ttl_seconds)

    def invalidate(self, provider: str) -> None:
        e = self._entries.get(provider)
        if e:
            with e.lock:
                e.result, e.failed_mono = None, None

    def refresh(self, provider: str) -> VerificationResult:
        """Re-attest now. Raises VerifyError (and clears the cached result) on failure."""
        e = self._entries.get(provider)
        if e is None:
            raise VerifyError(REASON_NOT_REGISTERED)
        with e.lock:
            try:
                try:
                    result = e.adapter.verify()  # resolves the enclave host on first use (may hit network)
                finally:
                    _sync_profile_base_url(e)
                if not isinstance(result, VerificationResult):
                    raise VerifyError(f"adapter returned {type(result).__name__}, not VerificationResult")
            except Exception as exc:
                e.result, e.failed_mono = None, self._clock()
                e.last_error = str(exc) if isinstance(exc, VerifyError) else f"{type(exc).__name__}: {exc}"
                _emit(e, {"kind": "verify_fail", "provider": provider, "purpose": "verify",
                          "host": _adapter_host(e.adapter),
                          "detail": {"vendor": getattr(e.adapter, "vendor", ""),
                                     "error_type": type(exc).__name__, "error": str(exc)[:300],
                                     "enclave_host": _adapter_host(e.adapter)}})
                raise exc if isinstance(exc, VerifyError) else VerifyError(e.last_error) from exc
            e.result, e.verified_mono, e.last_error, e.failed_mono = result, self._clock(), None, None
            _emit(e, {"kind": "verify_ok", "provider": provider, "purpose": "verify", "host": result.enclave_host,
                      "detail": {"vendor": result.vendor, "code_fingerprint": result.code_fingerprint,
                                 "enclave_fingerprint": result.enclave_fingerprint,
                                 "release_tag": result.release_tag, "enclave_host": result.enclave_host,
                                 "verifier": result.verifier, "evidence": result.evidence}})
            return result

    def ensure(self, provider: str) -> tuple[bool, str, VerificationResult | None]:
        """(ok, reason, result). ok iff a fresh result exists and the pins match it. Re-attests once if
        the cached result is stale or missing (subject to the failure backoff). Never raises."""
        try:
            e = self._entries.get(provider)
            if e is None:
                return False, REASON_NOT_REGISTERED, None
            with e.lock:
                if not self.fresh(provider):
                    if e.failed_mono is not None and self._clock() - e.failed_mono < e.failure_backoff_seconds:
                        _hold(e.adapter, _fail_reason(e.last_error))
                        return False, _fail_reason(e.last_error), None
                    try:
                        self.refresh(provider)
                    except VerifyError:
                        _hold(e.adapter, _fail_reason(e.last_error))
                        return False, _fail_reason(e.last_error), None
                result = e.result
                if result is None:
                    _hold(e.adapter, _fail_reason(e.last_error))
                    return False, _fail_reason(e.last_error), None
                if e.pins.match(result):
                    _release(e.adapter)
                    return True, "attested enclave verified and pinned", result
                had_pin = e.pins.get(result.vendor, result.router_repo) is not None
                reason = REASON_PIN_MISMATCH if had_pin else REASON_NO_PIN
                _hold(e.adapter, reason)
                before = e.pins.pending()
                staged = e.pins.stage(result)
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
        except Exception as exc:  # pins.yaml unreadable, etc.: fail closed
            logger.warning("attested verification check failed: %s", exc, exc_info=True)
            reason = f"attested verification check failed: {type(exc).__name__}"
            e = self._entries.get(provider)
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


def _adapter_host(adapter) -> str:
    try:
        return getattr(adapter, "enclave_host", "") or ""
    except Exception:
        return ""


def _emit(e: _Entry, event: dict) -> None:
    """Best effort: a failing ledger never changes a verification decision."""
    if e.on_event is None:
        return
    try:
        e.on_event(event)
    except Exception:
        logger.warning("confidential-mode: ledger write for %s failed", event.get("kind"), exc_info=True)


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


def attested_ok(provider_name: str) -> Verdict:
    """ATTESTED-tier verdict for W1/W3: fresh verification (TTL handled here) and pins match."""
    entry = verification_cache.entry(provider_name)
    ok, reason, result = verification_cache.ensure(provider_name)
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
                 on_event: Callable[[dict], None] | None = None, ledger=None):
    """Build the 'attested-tinfoil' ProviderProfile and register its cache entry. Never touches the
    network: base_url is the configured enclave URL, or the adapter's .invalid placeholder until the
    first verify() resolves the host by router discovery (then it is updated in place)."""
    cache = cache if cache is not None else verification_cache
    ProviderProfile = _profile_base()

    class AttestedTinfoilProfile(ProviderProfile):
        def create_client(self, **client_kwargs: Any):
            return _create_client(self, cache, client_kwargs)

    profile = AttestedTinfoilProfile(
        name=PROFILE_NAME,
        display_name="Tinfoil (attested)",
        description="Tinfoil confidential inference; every client is bound to an attested enclave",
        base_url=adapter.base_url,
        env_vars=(API_KEY_ENV,),
        auth_type="api_key",
    )
    profile._confidential_adapter = adapter
    profile._confidential_pins = pins
    if on_event is None and ledger is not None:
        on_event = ledger.append
    cache.register(PROFILE_NAME, adapter, pins, ttl_seconds, failure_backoff_seconds, on_event=on_event)
    cache.entry(PROFILE_NAME).profile = profile
    return profile


def _create_client(profile, cache: VerificationCache, client_kwargs: dict):
    api_key = client_kwargs.get("api_key") or os.environ.get(API_KEY_ENV, "")
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
        adapter = TinfoilAdapter(data_dir=data_dir, enclave=_cfg_get(config, "confidential", "tinfoil", "enclave"))
    if pins is None:
        pins = PinStore(data_dir / "pins.yaml")
    ttl = float(_cfg_get(config, "confidential", "verify_ttl_seconds", default=DEFAULT_TTL_SECONDS))
    profile = make_profile(adapter, pins, ttl, on_event=on_event, ledger=ledger)
    providers.register_provider(profile)
    return profile

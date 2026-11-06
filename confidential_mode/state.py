"""Thin accessors over ``ctx.state`` for the frozen confidential-mode keys (W1).

``ctx.state`` is Hermes' ``PluginState`` (hermes_cli/plugins.py ``PluginContext.state``,
hermes_cli/plugins_state.py): a profile-scoped JSON key/value store with ``get(key, default)``
and ``set(key, value)`` only (no delete). Frozen keys (docs/INTERFACES.md):

    sealed (bool), sealed_tier (str), sealed_since (float),
    config_fingerprint (str), breached_sessions (list[str])

Reads are strict: a malformed value raises ``StateError`` so callers (the gate) fail closed
instead of guessing whether the profile is sealed.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Protocol

from .tiers import Tier

KEY_SEALED = "sealed"
KEY_SEALED_TIER = "sealed_tier"
KEY_SEALED_SINCE = "sealed_since"
KEY_CONFIG_FINGERPRINT = "config_fingerprint"
KEY_BREACHED_SESSIONS = "breached_sessions"
KEYS = (KEY_SEALED, KEY_SEALED_TIER, KEY_SEALED_SINCE, KEY_CONFIG_FINGERPRINT, KEY_BREACHED_SESSIONS)


class StateError(RuntimeError):
    """Persisted state is malformed; treat as sealed-and-broken (refuse)."""


class StateStore(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...
    def set(self, key: str, value: Any) -> None: ...


class InMemoryState:
    """Fake ``ctx.state`` for tests: same get/set surface, JSON round-trip semantics."""

    def __init__(self, initial: dict | None = None):
        import json
        self._json = json
        self._data: dict[str, Any] = json.loads(json.dumps(initial or {}))

    def get(self, key: str, default: Any = None) -> Any:
        if key not in self._data:
            return default
        return self._json.loads(self._json.dumps(self._data[key]))

    def set(self, key: str, value: Any) -> None:
        self._data[key] = self._json.loads(self._json.dumps(value))


class ConfidentialState:
    def __init__(self, store: StateStore, *, clock: Callable[[], float] = time.time):
        self._store = store
        self._clock = clock

    # -- seal -----------------------------------------------------------------
    def sealed(self) -> tuple[bool, Tier | None]:
        """(sealed, tier). Raises StateError when the stored values are inconsistent."""
        raw = self._store.get(KEY_SEALED, False)
        if raw is False or raw is None:
            return False, None
        if raw is not True:
            raise StateError(f"state key {KEY_SEALED!r} is not a bool")
        tier_raw = self._store.get(KEY_SEALED_TIER)
        try:
            return True, Tier(tier_raw)
        except ValueError as exc:
            raise StateError(f"sealed with unknown tier {tier_raw!r}") from exc

    def seal(self, tier: Tier, config_fingerprint: str) -> None:
        tier = Tier(tier)
        # Tier first, flag last: a crash between writes leaves the profile unsealed-with-a-tier,
        # never sealed-without-one.
        self._store.set(KEY_SEALED_TIER, tier.value)
        self._store.set(KEY_SEALED_SINCE, float(self._clock()))
        self._store.set(KEY_CONFIG_FINGERPRINT, str(config_fingerprint))
        self._store.set(KEY_SEALED, True)

    def unseal(self) -> None:
        self._store.set(KEY_SEALED, False)

    def sealed_since(self) -> float | None:
        value = self._store.get(KEY_SEALED_SINCE)
        return float(value) if value is not None else None

    def config_fingerprint(self) -> str | None:
        value = self._store.get(KEY_CONFIG_FINGERPRINT)
        return str(value) if value is not None else None

    # -- breaches -------------------------------------------------------------
    def breached_sessions(self) -> list[str]:
        value = self._store.get(KEY_BREACHED_SESSIONS, [])
        if not isinstance(value, list):
            raise StateError(f"state key {KEY_BREACHED_SESSIONS!r} is not a list")
        return [str(v) for v in value]

    def mark_breached(self, session_id: str) -> None:
        current = self.breached_sessions()
        if session_id not in current:
            current.append(session_id)
            self._store.set(KEY_BREACHED_SESSIONS, current)

    def is_breached(self, session_id: str) -> bool:
        return session_id in self.breached_sessions()

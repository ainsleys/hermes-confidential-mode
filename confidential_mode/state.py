"""Thin accessors over ``ctx.state`` for the frozen confidential-mode keys (W1).

``ctx.state`` is Hermes' ``PluginState`` (hermes_cli/plugins.py ``PluginContext.state``,
hermes_cli/plugins_state.py): a profile-scoped JSON key/value store with ``get(key, default)``
and ``set(key, value)`` only (no delete). Frozen keys (docs/INTERFACES.md):

    locked (bool), locked_tier (str), locked_since (float),
    config_fingerprint (str), breached_sessions (list[str])

Reads are strict: a malformed value raises ``StateError`` so callers (the gate) fail closed
instead of guessing whether the profile is locked.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Protocol

from .tiers import Tier

KEY_LOCKED = "locked"
KEY_LOCKED_TIER = "locked_tier"
KEY_LOCKED_SINCE = "locked_since"
KEY_CONFIG_FINGERPRINT = "config_fingerprint"
KEY_BREACHED_SESSIONS = "breached_sessions"
KEYS = (KEY_LOCKED, KEY_LOCKED_TIER, KEY_LOCKED_SINCE, KEY_CONFIG_FINGERPRINT, KEY_BREACHED_SESSIONS)


def _parses(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return isinstance(json.load(fh), dict)
    except FileNotFoundError:
        return True
    except (OSError, ValueError):
        return False


def _replace_unparseable(path: Path, data: dict) -> bool:
    """Replace ``path`` with ``data`` when the file is a regular file that does not parse as a JSON object.
    Holds the sibling ``.<name>.lock`` flock Hermes' PluginState takes, so a concurrent Hermes write is not
    interleaved; re-checks under that lock, and returns False (nothing written) when the file parses (another
    process repaired it, or the failure was something else) or is not a regular file. Atomic: a temp file,
    fsync, then os.replace, mode 0600."""
    from .filelock import LockBusy, exclusive
    if not path.is_file() or _parses(path):
        return False
    try:
        with exclusive(path.with_name(f".{path.name}.lock")):
            if not path.is_file() or _parses(path):
                return False
            fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(data, indent=2))
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
    except LockBusy:
        return False
    return True


class StateError(RuntimeError):
    """Persisted state is malformed; treat as locked-and-broken (refuse)."""


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

    # -- lock -----------------------------------------------------------------
    def locked(self) -> tuple[bool, Tier | None]:
        """(locked, tier). Raises StateError when the stored values are inconsistent."""
        raw = self._store.get(KEY_LOCKED, False)
        if raw is False or raw is None:
            return False, None
        if raw is not True:
            raise StateError(f"state key {KEY_LOCKED!r} is not a bool")
        tier_raw = self._store.get(KEY_LOCKED_TIER)
        try:
            return True, Tier(tier_raw)
        except ValueError as exc:
            raise StateError(f"locked with unknown tier {tier_raw!r}") from exc

    def now(self) -> float:
        """The clock ``lock`` stamps ``locked_since`` with (so a caller can compute the lock id first)."""
        return float(self._clock())

    def lock(self, tier: Tier, config_fingerprint: str, *, since: float | None = None) -> None:
        tier = Tier(tier)
        # Tier first, flag last: a crash between writes leaves the profile unlocked-with-a-tier,
        # never locked-without-one.
        self._store.set(KEY_LOCKED_TIER, tier.value)
        self._store.set(KEY_LOCKED_SINCE, float(self._clock() if since is None else since))
        self._store.set(KEY_CONFIG_FINGERPRINT, str(config_fingerprint))
        self._store.set(KEY_LOCKED, True)

    def unlock(self) -> None:
        """Clear the lock flag. When the store's file does not parse (truncated, not JSON), Hermes'
        ``PluginState.set`` re-reads that file and raises, so the file is replaced instead (FI-3): this is
        the repair ``/confidential off`` promises. Any other failure (a write error on a readable file)
        propagates, and the profile stays locked."""
        try:
            self._store.set(KEY_LOCKED, False)
        except Exception:
            path = getattr(self._store, "path", None)
            if not isinstance(path, (str, os.PathLike)) or not _replace_unparseable(Path(path), {KEY_LOCKED: False}):
                raise

    def locked_since(self) -> float | None:
        value = self._store.get(KEY_LOCKED_SINCE)
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

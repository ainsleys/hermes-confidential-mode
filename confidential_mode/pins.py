"""PinStore over pins.yaml v2.

File shape:

    version: 2
    pins:
      - vendor: tinfoil
        router_repo: tinfoilsh/confidential-model-router
        code_fingerprint: ...
        enclave_fingerprint: ...
        release_tag: v1.2.3
        models_seen: [model-a]
        approved_by: human
        approved_at: 2026-11-06T12:00:00Z
        approved_via: telegram
        approval_rule_key: confidential-mode:pin:tinfoil
        previous: <code fingerprint of the replaced pin> | null
        previous_enclave_fingerprint: <enclave fingerprint of the replaced pin> | null
    pending: {...} | null

Pins are keyed by (vendor, router_repo); the model is only a label in models_seen. Only consent.py
calls apply(). Writes are atomic (temp file in the same directory, fsync, os.replace).
"""
from __future__ import annotations

import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:  # Hermes ships ruamel-backed hermes_yaml and no PyYAML in its venv
    import hermes_yaml as yaml
except ImportError:  # standalone use (unit tests outside Hermes)
    import yaml  # type: ignore[no-redef]

from .verify.base import VerificationResult

SCHEMA_VERSION = 2
DEFAULT_APPROVAL_RULE_KEY = "confidential-mode:pin"


class PinStoreError(Exception):
    """pins.yaml is unreadable or of an unknown version. Callers fail closed."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class PendingPin:
    vendor: str
    router_repo: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None
    enclave_host: str
    verifier: str
    staged_at: str
    previous: str | None                       # code fingerprint of the pin this would replace
    previous_enclave_fingerprint: str | None
    models_seen: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.router_repo)


@dataclass(frozen=True)
class PinRecord:
    vendor: str
    router_repo: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None
    models_seen: tuple[str, ...]
    approved_by: str
    approved_at: str
    approved_via: str
    approval_rule_key: str
    previous: str | None
    previous_enclave_fingerprint: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.router_repo)


def _record_to_dict(rec) -> dict:
    d = asdict(rec)
    d["models_seen"] = list(d["models_seen"])
    return d


def _record_from_dict(cls, d: dict):
    if not isinstance(d, dict):
        raise PinStoreError(f"malformed {cls.__name__} entry: {d!r}")
    fields = cls.__dataclass_fields__
    kwargs = {k: v for k, v in d.items() if k in fields}
    kwargs["models_seen"] = tuple(kwargs.get("models_seen") or ())
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise PinStoreError(f"malformed {cls.__name__} entry: {exc}") from exc


class PinStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.RLock()

    # ── persistence ──────────────────────────────────────────────────────────────────────────
    def load(self) -> tuple[dict[tuple[str, str], PinRecord], PendingPin | None]:
        with self._lock:
            try:
                raw = self.path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return {}, None
            except OSError as exc:
                raise PinStoreError(f"cannot read {self.path}: {exc}") from exc
            try:
                data = yaml.safe_load(raw) or {}
            except yaml.YAMLError as exc:
                raise PinStoreError(f"cannot parse {self.path}: {exc}") from exc
            if not isinstance(data, dict) or data.get("version") != SCHEMA_VERSION:
                raise PinStoreError(f"{self.path}: expected version {SCHEMA_VERSION}, "
                                    f"got {data.get('version') if isinstance(data, dict) else type(data).__name__}")
            pins: dict[tuple[str, str], PinRecord] = {}
            for entry in data.get("pins") or []:
                rec = _record_from_dict(PinRecord, entry)
                pins[rec.key] = rec
            pending_raw = data.get("pending")
            pending = _record_from_dict(PendingPin, pending_raw) if pending_raw else None
            return pins, pending

    def _last_applied(self) -> tuple[PendingPin] | None:
        try:
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            return None
        raw = data.get("last_applied") if isinstance(data, dict) else None
        return (_record_from_dict(PendingPin, raw),) if raw else None

    def save(self, pins: dict[tuple[str, str], PinRecord], pending: PendingPin | None, *,
             applied: PendingPin | None | bool = False) -> None:
        """Atomic write. ``applied`` records the pending pin apply() just promoted (False keeps the
        stored value), which makes a repeated apply() of the same pending a no-op."""
        with self._lock:
            if applied is False:
                last = self._last_applied() if self.path.exists() else None
                applied = last[0] if last else None
            data = {"version": SCHEMA_VERSION,
                    "pins": [_record_to_dict(p) for _, p in sorted(pins.items())],
                    "pending": _record_to_dict(pending) if pending else None,
                    "last_applied": _record_to_dict(applied) if applied else None}
            text = yaml.safe_dump(data, sort_keys=False)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    # ── queries ──────────────────────────────────────────────────────────────────────────────
    def get(self, vendor: str, router_repo: str) -> PinRecord | None:
        return self.load()[0].get((vendor, router_repo))

    def match(self, result: VerificationResult) -> bool:
        pin = self.get(result.vendor, result.router_repo)
        return (pin is not None and pin.code_fingerprint == result.code_fingerprint
                and pin.enclave_fingerprint == result.enclave_fingerprint)

    def pending(self) -> PendingPin | None:
        return self.load()[1]

    # ── mutations ────────────────────────────────────────────────────────────────────────────
    def stage(self, result: VerificationResult, *, model: str | None = None) -> PendingPin:
        """Record ``result`` as the pending pin (replacing any other pending). Idempotent for an identical
        build (fingerprints, release tag, host): re-staging returns the existing PendingPin unchanged, so a
        consent prompt's equality re-check survives repeat stages. Anything else, including the same
        fingerprints under a different release tag, is a new PendingPin (a swap, Amendment 3)."""
        with self._lock:
            pins, pending = self.load()
            if (pending is not None and pending.key == (result.vendor, result.router_repo)
                    and pending.code_fingerprint == result.code_fingerprint
                    and pending.enclave_fingerprint == result.enclave_fingerprint
                    and pending.release_tag == result.release_tag
                    and pending.enclave_host == result.enclave_host):
                return pending
            current = pins.get((result.vendor, result.router_repo))
            new = PendingPin(
                vendor=result.vendor, router_repo=result.router_repo,
                code_fingerprint=result.code_fingerprint, enclave_fingerprint=result.enclave_fingerprint,
                release_tag=result.release_tag, enclave_host=result.enclave_host, verifier=result.verifier,
                staged_at=_utc_now_iso(),
                previous=current.code_fingerprint if current else None,
                previous_enclave_fingerprint=current.enclave_fingerprint if current else None,
                models_seen=(model,) if model else (),
            )
            self.save(pins, new)
            return new

    def apply(self, pending: PendingPin, *, approved_via: str,
              approval_rule_key: str = DEFAULT_APPROVAL_RULE_KEY, approved_by: str = "human",
              approved_at: str | None = None) -> PinRecord:
        """Promote ``pending`` to the pin for its key. Raises PinStoreError if ``pending`` is no longer
        the stored pending pin. Keeps the replaced pin's fingerprints in ``previous*``."""
        with self._lock:
            if not approved_via:
                raise ValueError("approved_via (the approval surface) is required")
            pins, stored = self.load()
            last = self._last_applied()
            if stored is None and last is not None and last[0] == pending and pending.key in pins:
                return pins[pending.key]  # idempotent: this exact pending was already applied once
            if stored != pending:
                raise PinStoreError("pending pin changed since it was shown; not applied")
            current = pins.get(pending.key)
            models = tuple(dict.fromkeys((current.models_seen if current else ()) + pending.models_seen))
            rec = PinRecord(
                vendor=pending.vendor, router_repo=pending.router_repo,
                code_fingerprint=pending.code_fingerprint, enclave_fingerprint=pending.enclave_fingerprint,
                release_tag=pending.release_tag, models_seen=models,
                approved_by=approved_by, approved_at=approved_at or _utc_now_iso(),
                approved_via=approved_via, approval_rule_key=approval_rule_key,
                previous=current.code_fingerprint if current else None,
                previous_enclave_fingerprint=current.enclave_fingerprint if current else None,
            )
            pins[rec.key] = rec
            self.save(pins, None, applied=pending)
            return rec

    def clear_pending(self) -> None:
        with self._lock:
            pins, _ = self.load()
            self.save(pins, None)

    def note_model(self, vendor: str, router_repo: str, model: str) -> None:
        """Add ``model`` to the pin's models_seen label list (no effect on matching)."""
        if not model:
            return
        with self._lock:
            pins, pending = self.load()
            rec = pins.get((vendor, router_repo))
            if rec is None or model in rec.models_seen:
                return
            pins[rec.key] = PinRecord(**{**asdict(rec), "models_seen": rec.models_seen + (model,)})
            self.save(pins, pending)

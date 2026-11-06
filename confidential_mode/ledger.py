"""Append-only SQLite ledger of what confidential mode observed, allowed and refused (W1).

Schema and event kinds are frozen in docs/INTERFACES.md. The ledger stores metadata only:
destination, byte counts, verdicts and decisions. It never stores prompt or response text;
``append`` rejects ``detail`` payloads that carry conversation-shaped keys.

Storage is Hermes' plugin storage (``plugins.plugin_storage.plugin_db``), i.e.
``<hermes home>/plugin-data/confidential-mode/ledger.sqlite``, opened through Hermes'
WAL-aware ``open_db``. Tests inject a path or a connection factory instead.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

PLUGIN_STORAGE_NAME = "confidential-mode"
LEDGER_FILENAME = "ledger.sqlite"

KINDS = frozenset({
    "send_observed", "send_refused", "verify_ok", "verify_fail", "tool_asked", "tool_allowed",
    "tool_refused", "pin_staged", "pin_applied", "pin_denied", "seal", "unseal", "preflight_fail",
    "breach", "compaction",
})

# Keys that carry conversation content in the provider request shapes Hermes sends
# (chat ``messages``, Responses ``input``/``instructions``, Anthropic ``system``, Bedrock
# ``contents``/``content``). Rejected at any depth inside ``detail``. Kept narrow so W2's
# verification evidence is not caught by accident.
FORBIDDEN_DETAIL_KEYS = frozenset({
    "messages", "prompt", "prompts", "request", "input", "instructions", "system", "content",
    "contents",
})
MAX_DETAIL_BYTES = 256 * 1024  # verification evidence can carry certificate chains

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    session_id TEXT,
    kind TEXT NOT NULL,
    purpose TEXT,
    provider TEXT,
    host TEXT,
    model TEXT,
    bytes INTEGER NULL,
    tier TEXT NULL,
    verdict TEXT NULL,
    decision TEXT NULL,
    surface TEXT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, id);
"""

_COLUMNS = ("id", "ts", "session_id", "kind", "purpose", "provider", "host", "model", "bytes",
            "tier", "verdict", "decision", "surface", "detail")


class LedgerError(ValueError):
    """An event was rejected (unknown kind, content-shaped detail, oversized detail)."""


@dataclass(frozen=True)
class LedgerEvent:
    kind: str
    session_id: str = ""
    purpose: str = ""
    provider: str = ""
    host: str = ""
    model: str = ""
    bytes: int | None = None
    tier: str | None = None
    verdict: str | None = None
    decision: str | None = None
    surface: str | None = None
    detail: dict = field(default_factory=dict)
    ts: float | None = None
    id: int | None = None   # set on rows read back; ignored by append


def _check_detail(value: Any, path: str = "detail") -> None:
    if isinstance(value, dict):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise LedgerError(f"{path}: non-string key")
            if key.lower() in FORBIDDEN_DETAIL_KEYS:
                raise LedgerError(f"{path}.{key}: content-shaped keys are never stored in the ledger")
            _check_detail(sub, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, sub in enumerate(value):
            _check_detail(sub, f"{path}[{i}]")


_EVENT_FIELDS = frozenset(_COLUMNS)


def coerce_event(event: Any) -> LedgerEvent:
    """LedgerEvent passes through; a Mapping with column-name keys becomes a LedgerEvent.
    Unknown keys are rejected (a typo must not silently drop a field); ``id`` is ignored;
    ``detail`` None means {}."""
    if isinstance(event, LedgerEvent):
        return event
    if not isinstance(event, Mapping):
        raise LedgerError(f"ledger event must be a LedgerEvent or a dict, not {type(event).__name__}")
    unknown = sorted(str(k) for k in event if k not in _EVENT_FIELDS)
    if unknown:
        raise LedgerError(f"unknown ledger event fields: {', '.join(unknown)}")
    if "kind" not in event:
        raise LedgerError("ledger event dict has no kind")
    fields = {k: v for k, v in event.items() if k != "id"}
    detail = fields.get("detail")
    if detail is None:
        fields["detail"] = {}
    elif not isinstance(detail, Mapping):
        raise LedgerError("detail must be a dict")
    else:
        fields["detail"] = dict(detail)
    return LedgerEvent(**fields)


def _default_connect() -> sqlite3.Connection:
    from plugins.plugin_storage import plugin_db
    return plugin_db(PLUGIN_STORAGE_NAME, LEDGER_FILENAME)


def default_ledger_path() -> Path:
    from plugins.plugin_storage import plugin_data_dir
    return plugin_data_dir(PLUGIN_STORAGE_NAME) / LEDGER_FILENAME


class Ledger:
    """Thread-safe append-only event log. One connection per Ledger, guarded by a lock."""

    def __init__(self, path: str | Path | None = None, *,
                 connect: Callable[[], sqlite3.Connection] | None = None,
                 clock: Callable[[], float] = time.time):
        if path is not None and connect is not None:
            raise ValueError("pass path or connect, not both")
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            connect = lambda: sqlite3.connect(p, check_same_thread=False, timeout=5.0)  # noqa: E731
        self._connect = connect or _default_connect
        self._clock = clock
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            conn = self._connect()
            conn.row_factory = None
            conn.executescript(_SCHEMA)
            conn.commit()
            self._conn = conn
        return self._conn

    def append(self, event: LedgerEvent | Mapping[str, Any]) -> int:
        """Validate and insert one event; returns its id. Accepts a LedgerEvent or a plain dict
        keyed by column names (W4 emits dicts; INTERFACES Amendment 2). Raises LedgerError on a
        rejected event."""
        event = coerce_event(event)
        if event.kind not in KINDS:
            raise LedgerError(f"unknown ledger kind {event.kind!r}")
        detail = dict(event.detail or {})
        _check_detail(detail)
        encoded = json.dumps(detail, sort_keys=True, default=str)
        if len(encoded.encode("utf-8")) > MAX_DETAIL_BYTES:
            raise LedgerError("detail exceeds the ledger size cap")
        if event.bytes is not None and not isinstance(event.bytes, int):
            raise LedgerError("bytes must be an int or None")
        row = (
            float(event.ts if event.ts is not None else self._clock()), event.session_id or "",
            event.kind, event.purpose or "", event.provider or "", event.host or "", event.model or "",
            event.bytes, event.tier, event.verdict, event.decision, event.surface, encoded,
        )
        with self._lock:
            db = self._db()
            cur = db.execute(
                "INSERT INTO events (ts, session_id, kind, purpose, provider, host, model, bytes, tier,"
                " verdict, decision, surface, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
            db.commit()
            return int(cur.lastrowid)

    def _rows(self, sql: str, params: Iterable[Any]) -> list[LedgerEvent]:
        with self._lock:
            rows = self._db().execute(sql, tuple(params)).fetchall()
        out = []
        for r in rows:
            rec = dict(zip(_COLUMNS, r))
            try:
                rec["detail"] = json.loads(rec["detail"] or "{}")
            except ValueError:
                rec["detail"] = {"unparseable": True}
            out.append(LedgerEvent(**rec))
        return out

    def tail(self, since_id: int = 0, limit: int = 1000) -> list[LedgerEvent]:
        """Events with id > since_id, oldest first (the watch view polls this)."""
        return self._rows(f"SELECT {', '.join(_COLUMNS)} FROM events WHERE id > ? ORDER BY id LIMIT ?",
                          (int(since_id), int(limit)))

    def session(self, session_id: str) -> list[LedgerEvent]:
        """Every event for one session, oldest first (receipts)."""
        return self._rows(f"SELECT {', '.join(_COLUMNS)} FROM events WHERE session_id = ? ORDER BY id",
                          (session_id,))

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


def event_dict(event: LedgerEvent) -> dict:
    return asdict(event)

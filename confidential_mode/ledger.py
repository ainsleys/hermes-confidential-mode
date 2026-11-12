"""Append-only SQLite ledger of what confidential mode observed, allowed and refused (W1).

Schema and event kinds are frozen in docs/INTERFACES.md. The ledger stores metadata only:
destination, byte counts, verdicts and decisions. It never stores prompt or response text;
``append`` rejects ``detail`` payloads that carry conversation-shaped keys.

Storage is Hermes' plugin storage (``plugins.plugin_storage.plugin_db``), i.e.
``<hermes home>/plugin-data/confidential-mode/ledger.sqlite``, opened through Hermes'
WAL-aware ``open_db``. Tests inject a path or a connection factory instead.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .atomicwrite import write_atomic

PLUGIN_STORAGE_NAME = "confidential-mode"
LEDGER_FILENAME = "ledger.sqlite"

KINDS = frozenset({
    "send_observed", "send_refused", "verify_ok", "verify_fail", "tool_asked", "tool_allowed",
    "tool_refused", "pin_staged", "pin_applied", "pin_denied", "lock", "unlock", "preflight_fail",
    "breach", "compaction",
    # Amendment 4 F7: session boundary markers (never "lock": receipts open a locked period only at a lock row).
    "session_start", "session_end",
    # Amendment 5: one row per send through a vendor that signs responses (NEAR AI Cloud): digests,
    # signature, kind and the check's verdict ("verified" / "unverified").
    "send_signed",
    # Amendment 7: `pins retire` removed an approved entry; a later consent check no longer counts the
    # entry's earlier pin_applied row.
    "pin_retired",
    # Amendment 9: something the user is told about, without a refusal (decision names it; today
    # "image_plaintext": the first image part of a lock left as plaintext to NEAR's gateway).
    "notice",
    # Amendment 10: `revoke <tool>` / `revoke --all` removed tool grants confidential mode wrote.
    "grant_revoked",
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
# FI-6: free-text strings a caller does not bound (a tool name the model chose, Hermes' compaction reason, an
# error or message text) are clipped to this many characters before the row is built: the ``purpose`` column
# (it carries the tool name) and these top-level detail keys. Hashes, fingerprints, session ids, tool call ids,
# reason codes and verification evidence are never clipped. A clipped value ends in a marker naming its full
# length and the first 16 hex digits of its SHA-256, so two different long values stay distinct.
MAX_CALLER_CHARS = 1024
FREE_TEXT_KEYS = frozenset({"tool", "reason", "error", "message", "raw_pick", "choice"})
# A detail still over MAX_DETAIL_BYTES keeps its top-level fields that are numbers, booleans, None or strings of
# at most this many characters (identities, fingerprints, codes), plus the marker key DETAIL_TOO_LARGE_KEY.
MARKER_KEEP_CHARS = 512
DETAIL_TOO_LARGE_KEY = "detail_too_large"
# Content-addressed store for large evidence texts (NEAR app_compose files and compose-manager logs),
# next to the ledger file: <data_dir>/evidence/blobs/<sha256>. A row keeps only the ids (Amendment 5.2).
BLOB_SUBDIR = ("evidence", "blobs")
MAX_BLOB_BYTES = 8 * 1024 * 1024
# Retention: a blob stays while any ledger row lists it in blob_refs (receipts and replays need it; pins keep
# their own copy of what they show). A blob no row lists, which only a refused or failed append leaves, is
# deleted once it is older than this, at the first evidence write of each Ledger instance.
BLOB_ORPHAN_SECONDS = 24 * 3600

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


MISSING_SESSION_ID = "(no session)"


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


def clip_text(value: Any, limit: int = MAX_CALLER_CHARS) -> Any:
    """``value`` clipped to ``limit`` characters with a marker naming its full length and a digest; non-strings
    unchanged."""
    if isinstance(value, str) and len(value) > limit:
        digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]
        return f"{value[:limit]}...(clipped, {len(value)} chars, sha256 {digest})"
    return value


def clip_caller_strings(detail: dict) -> dict:
    """A copy of ``detail`` whose top-level free-text values (FREE_TEXT_KEYS) are clipped (FI-6)."""
    return {k: clip_text(v) if k in FREE_TEXT_KEYS else v for k, v in detail.items()}


def is_truncated(detail: Any) -> bool:
    """True for a row whose detail was too large and was replaced by the marker (FI-6). Readers treat such a
    row as unknown: never covered, never consent, "detail lost" rendered."""
    return isinstance(detail, Mapping) and DETAIL_TOO_LARGE_KEY in detail


def marker_detail(detail: Mapping, size: int) -> dict:
    """The detail written in place of one still over MAX_DETAIL_BYTES after clipping: its short structural
    top-level fields plus the marker."""
    kept = {k: v for k, v in detail.items()
            if k != DETAIL_TOO_LARGE_KEY and (v is None or isinstance(v, (bool, int, float))
                                              or (isinstance(v, str) and len(v) <= MARKER_KEEP_CHARS))}
    return {**kept, DETAIL_TOO_LARGE_KEY: f"detail too large: {size} bytes, truncated"}


def _encode_detail(kind: str, detail: dict) -> tuple[str, bool]:
    """(the encoded detail to store, whether it is the marker). Raises LedgerError for a verify_ok row or a
    row with evidence over the cap (Amendment 5.2), and when even the structural fields exceed the cap."""
    encoded = json.dumps(detail, sort_keys=True, default=str)
    size = len(encoded.encode("utf-8"))
    if size <= MAX_DETAIL_BYTES:
        return encoded, False
    if kind == "verify_ok" or "evidence" in detail:
        # Amendment 5.2: a verify_ok row, or a row with evidence, that no receipt could show in full is
        # refused by its caller (a verify_fail row says so), never written without its detail.
        raise LedgerError("detail exceeds the ledger size cap")
    encoded = json.dumps(marker_detail(detail, size), sort_keys=True, default=str)
    if len(encoded.encode("utf-8")) > MAX_DETAIL_BYTES:
        raise LedgerError("detail exceeds the ledger size cap, even its structural fields")
    return encoded, True


def would_truncate(event: Any) -> bool:
    """Whether ``Ledger.append`` would store ``event`` (a LedgerEvent or a dict) with the marker detail. A
    caller whose warning depends on the row's full detail (pins retire) checks this. Never raises."""
    try:
        ev = coerce_event(event)
        detail = clip_caller_strings(dict(ev.detail or {}))
        return _encode_detail(ev.kind, detail)[1]
    except Exception:  # noqa: BLE001
        return False


class BlobStore:
    """Write-once files named by the SHA-256 of their UTF-8 text. ``get`` returns None for a missing blob
    or one whose bytes no longer hash to its name, so a replay that needs it fails closed."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, blob_id: str) -> Path | None:
        if not isinstance(blob_id, str) or len(blob_id) != 64 or any(c not in "0123456789abcdef" for c in blob_id):
            return None
        return self.root / blob_id

    def put(self, blob_id: str, text: str) -> bool:
        """Write the blob durably (fsync of the file, then of the directory). True when this call created
        it, False when an intact copy was already there."""
        path = self._path(blob_id)
        data = text.encode("utf-8") if isinstance(text, str) else None
        if path is None or data is None or hashlib.sha256(data).hexdigest() != blob_id:
            raise LedgerError("evidence blob does not hash to its id")
        if len(data) > MAX_BLOB_BYTES:
            raise LedgerError("evidence blob exceeds the blob size cap")
        if path.exists() and self.get(blob_id) is not None:
            try:   # a row is about to list it: keep it young, so another process's cleanup leaves it alone
                os.utime(path)
            except OSError:
                pass
            return False
        # Mode 0600 from creation, like every plugin data file (ux-pass-1 item 8); fsync of the file, the
        # rename, then fsync of the directory (atomicwrite.py).
        write_atomic(path, data)
        return True

    def delete(self, blob_id: str) -> None:
        path = self._path(blob_id)
        try:
            if path is not None:
                path.unlink()
        except FileNotFoundError:
            pass

    def gc(self, referenced: set, *, older_than: float = BLOB_ORPHAN_SECONDS, now: float | None = None) -> list:
        """Delete blobs (and stale temporary files) not in ``referenced`` and older than ``older_than``
        seconds. Returns the ids deleted."""
        now = time.time() if now is None else now
        gone: list = []
        try:
            entries = list(self.root.iterdir())
        except OSError:
            return gone
        for f in entries:
            try:
                old = now - f.stat().st_mtime > older_than
                if f.name.startswith(".") and f.name.endswith(".tmp") and old:
                    f.unlink()
                elif self._path(f.name) is not None and f.name not in referenced and old:
                    f.unlink()
                    gone.append(f.name)
            except OSError:
                continue
        return gone

    def get(self, blob_id: str) -> str | None:
        path = self._path(blob_id)
        try:
            data = path.read_bytes() if path is not None else None
        except OSError:
            return None
        if data is None or hashlib.sha256(data).hexdigest() != blob_id:
            return None
        return data.decode("utf-8")


def _blob_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def externalize_evidence(detail: dict, store: BlobStore | None) -> tuple[dict, dict]:
    """(a copy of ``detail`` whose ``evidence.blobs`` are replaced by ``evidence.blob_refs``, the blobs to
    write). Each blob must hash to its id and pass the content-key scan. Nothing is written here, so a row
    refused for its size leaves no blob behind. With no store the detail is returned unchanged (blobs stay
    inline and count toward the size cap)."""
    ev = detail.get("evidence")
    if not isinstance(ev, Mapping) or not isinstance(ev.get("blobs"), Mapping):
        return detail, {}
    for blob_id, text in ev["blobs"].items():
        if not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != blob_id:
            raise LedgerError("evidence blob does not hash to its id")
        _check_detail(_blob_json(text), f"detail.evidence.blobs[{blob_id[:12]}]")
    if store is None:
        return detail, {}
    stripped = {k: v for k, v in ev.items() if k != "blobs"}
    stripped["blob_refs"] = sorted(ev["blobs"])
    return {**detail, "evidence": stripped}, dict(ev["blobs"])


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


#: Mode of every file the plugin keeps (the ledger, its WAL and shared-memory files, evidence blobs, the
#: state, pins and grants files). Readable and writable by the user only.
DATA_FILE_MODE = 0o600
_SQLITE_SIDE_FILES = ("", "-wal", "-shm", "-journal")


def secure_file(path: str | Path) -> None:
    """chmod 0600 a regular file the plugin owns (not a symlink). Never raises."""
    try:
        p = Path(path)
        if p.is_file() and not p.is_symlink() and (p.stat().st_mode & 0o777) != DATA_FILE_MODE:
            os.chmod(p, DATA_FILE_MODE)
    except OSError:
        pass


def secure_data_files(roots: Iterable[str | Path], *, max_files_per_root: int = 5000) -> int:
    """chmod 0600 every regular file under the plugin's data directories (existing installs created some
    files 0644), at most ``max_files_per_root`` per directory, so a large cache in one directory never keeps the
    walk from the other. Symlinks are not followed. Returns how many files were looked at. Never raises. POSIX
    only: on Windows chmod sets the read-only flag and nothing else."""
    seen = 0
    for root in roots:
        here = 0
        try:
            for dirpath, _dirs, files in os.walk(str(root), followlinks=False):
                for name in files:
                    secure_file(Path(dirpath) / name)
                    seen += 1
                    here += 1
                    if here >= max_files_per_root:
                        break
                if here >= max_files_per_root:
                    break
        except Exception:
            continue
    return seen


MODES_MARKER = "modes-checked"


def needs_mode_walk(state_dir: Path, ledger_dir: Path, commit: str) -> bool:
    """Whether the start-up chmod walk is due: once per installed commit (``modes-checked`` in the state
    directory), or whenever a file the plugin always keeps has a wrong mode. Never raises."""
    try:
        if (Path(state_dir) / MODES_MARKER).read_text(encoding="utf-8").strip() != commit:
            return True
    except Exception:  # noqa: BLE001
        return True
    for f in (Path(ledger_dir) / LEDGER_FILENAME, Path(state_dir) / "pins.yaml", Path(state_dir) / "allowlist.yaml"):
        try:
            if f.is_file() and (f.stat().st_mode & 0o777) != DATA_FILE_MODE:
                return True
        except OSError:
            continue
    return False


def mark_mode_walk(state_dir: Path, commit: str) -> None:
    try:
        path = Path(state_dir) / MODES_MARKER
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, DATA_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(commit + "\n")
    except Exception:  # noqa: BLE001
        pass


def _create_private(path: Path) -> None:
    """Create an empty ``path`` with mode 0600 when absent, so SQLite never creates it 0644. Never raises."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, DATA_FILE_MODE))
    except OSError:
        pass


def _default_connect() -> sqlite3.Connection:
    from plugins.plugin_storage import plugin_db
    return plugin_db(PLUGIN_STORAGE_NAME, LEDGER_FILENAME)


def _discard_transaction(conn: sqlite3.Connection) -> bool:
    """Roll back whatever ``conn`` has open after a failed INSERT or COMMIT (FI-1), so the row can never be
    committed by a later append. True when the rollback worked; False means the caller must drop the
    connection (closing it discards the open transaction)."""
    try:
        conn.rollback()
    except Exception:  # noqa: BLE001
        return False
    return not conn.in_transaction


def default_ledger_path() -> Path:
    from plugins.plugin_storage import plugin_data_dir
    return plugin_data_dir(PLUGIN_STORAGE_NAME) / LEDGER_FILENAME


class Ledger:
    """Thread-safe append-only event log. One connection per Ledger, guarded by a lock."""

    def __init__(self, path: str | Path | None = None, *,
                 connect: Callable[[], sqlite3.Connection] | None = None,
                 clock: Callable[[], float] = time.time, blob_dir: str | Path | None = None):
        if path is not None and connect is not None:
            raise ValueError("pass path or connect, not both")
        self._file: Path | None = None   # the SQLite file (default ledger: resolved on first use)
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._file = p
            connect = lambda: sqlite3.connect(p, check_same_thread=False, timeout=5.0)  # noqa: E731
            if blob_dir is None:
                blob_dir = p.parent.joinpath(*BLOB_SUBDIR)
        # blob_dir: given, next to the ledger file, or (default ledger) <plugin data dir>/evidence/blobs
        # resolved on first use; an injected connection without blob_dir has no store.
        self._blob_dir = Path(blob_dir) if blob_dir is not None else None
        self._blob_default = path is None and connect is None
        self._gc_done = False
        self._connect = connect or _default_connect
        self._clock = clock
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @property
    def blobs(self) -> BlobStore | None:
        """The evidence blob store, or None when this ledger has none."""
        if self._blob_dir is None and self._blob_default:
            try:
                self._blob_dir = default_ledger_path().parent.joinpath(*BLOB_SUBDIR)
            except Exception:
                return None
        return BlobStore(self._blob_dir) if self._blob_dir is not None else None

    def blob(self, blob_id: str) -> str | None:
        store = self.blobs
        return store.get(blob_id) if store is not None else None

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            target = self._file
            if target is None and self._blob_default:
                try:
                    target = default_ledger_path()
                except Exception:  # noqa: BLE001
                    target = None
            if target is not None:
                _create_private(target)
            conn = self._connect()
            conn.row_factory = None
            conn.executescript(_SCHEMA)
            conn.commit()
            self._conn = conn
            if target is not None:   # an existing ledger made 0644 by an earlier build, and SQLite's side files
                for suffix in _SQLITE_SIDE_FILES:
                    secure_file(Path(str(target) + suffix))
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
        detail = clip_caller_strings(detail)
        store = self.blobs
        detail, to_write = externalize_evidence(detail, store)
        encoded, _marked = _encode_detail(event.kind, detail)   # FI-6: an oversized row is written, never dropped
        if event.bytes is not None and not isinstance(event.bytes, int):
            raise LedgerError("bytes must be an int or None")
        row = (
            float(event.ts if event.ts is not None else self._clock()),
            (event.session_id or MISSING_SESSION_ID) if event.kind == "breach" else (event.session_id or ""),
            event.kind, clip_text(event.purpose or ""), event.provider or "", event.host or "", event.model or "",
            event.bytes, event.tier, event.verdict, event.decision, event.surface, encoded,
        )
        created: list[str] = []
        committed = False
        try:
            for blob_id, text in to_write.items():
                if store.put(blob_id, text):  # type: ignore[union-attr]  # to_write is empty without a store
                    created.append(blob_id)
            with self._lock:
                db = self._db()
                try:
                    cur = db.execute(
                        "INSERT INTO events (ts, session_id, kind, purpose, provider, host, model, bytes, tier,"
                        " verdict, decision, surface, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
                    db.commit()
                    committed = True
                except BaseException:
                    # FI-1: a failed INSERT or COMMIT leaves the row in the open transaction, where the next
                    # append's COMMIT would land it. Roll back, or drop the connection when that fails.
                    if not _discard_transaction(db):
                        try:
                            db.close()
                        except Exception:  # noqa: BLE001
                            pass
                        self._conn = None
                    raise
                row_id = int(cur.lastrowid)  # type: ignore[arg-type]  # set by the INSERT above
        except BaseException:
            if not committed:   # no row lists them: remove what this append wrote
                for blob_id in created:
                    store.delete(blob_id)  # type: ignore[union-attr]  # created is empty without a store
            raise
        if to_write and not self._gc_done:
            self._gc_done = True
            try:
                self.gc_blobs()
            except Exception:
                pass
        return row_id

    def referenced_blobs(self) -> set:
        """Every blob id any row lists in its evidence's blob_refs."""
        with self._lock:
            rows = self._db().execute("SELECT detail FROM events WHERE detail LIKE '%\"blob_refs\"%'").fetchall()
        out: set = set()
        for (text,) in rows:
            try:
                refs = (json.loads(text or "{}").get("evidence") or {}).get("blob_refs")
            except (ValueError, AttributeError):
                continue
            out.update(r for r in refs or [] if isinstance(r, str))
        return out

    def gc_blobs(self, *, older_than: float = BLOB_ORPHAN_SECONDS) -> list:
        """Delete blobs no row references once older than ``older_than`` seconds (the retention rule above)."""
        store = self.blobs
        return store.gc(self.referenced_blobs(), older_than=older_than) if store is not None else []

    def _rows(self, sql: str, params: Iterable[Any]) -> list[LedgerEvent]:
        with self._lock:
            rows = self._db().execute(sql, tuple(params)).fetchall()
        out = []
        for r in rows:
            rec = dict(zip(_COLUMNS, r, strict=False))
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

    def tool_rows(self, kinds: Iterable[str], since_id: int = 0, limit: int = 1000) -> list[LedgerEvent]:
        """Events of ``kinds`` whose purpose is ``tool:<name>``, id > since_id, oldest first (a revoke reads
        only these; Amendment 14)."""
        kinds = [str(k) for k in kinds]
        if not kinds:
            return []
        marks = ", ".join("?" for _ in kinds)
        return self._rows(f"SELECT {', '.join(_COLUMNS)} FROM events WHERE id > ? AND kind IN ({marks}) "
                          "AND purpose LIKE 'tool:%' ORDER BY id LIMIT ?", (int(since_id), *kinds, int(limit)))

    def last_key_moving_revoke(self, purposes: Iterable[str]) -> int:
        """The id of the latest ``grant_revoked`` row for one of ``purposes`` whose detail says the rule key
        moved, or 0 (a revoke starts its ledger read there; re-review L8-scan). Reads newest first."""
        purposes = [str(p) for p in purposes]
        if not purposes:
            return 0
        marks = ", ".join("?" for _ in purposes)
        last = None
        while True:
            bound = "" if last is None else "AND id < ? "
            with self._lock:
                rows = self._db().execute(
                    f"SELECT id, detail FROM events WHERE kind = 'grant_revoked' AND purpose IN ({marks}) {bound}"
                    "ORDER BY id DESC LIMIT 200", (*purposes, *([] if last is None else [last]))).fetchall()
            for row_id, detail in rows:
                try:
                    if (json.loads(detail or "{}") or {}).get("rule_key_rotated"):
                        return int(row_id)
                except ValueError:
                    continue
            if len(rows) < 200:
                return 0
            last = rows[-1][0]

    def last_id_before(self, kind: str, before_id: int) -> int | None:
        """The id of the latest event of ``kind`` with id < ``before_id``, or None (receipts bound their read)."""
        with self._lock:
            row = self._db().execute("SELECT MAX(id) FROM events WHERE kind = ? AND id < ?",
                                     (kind, int(before_id))).fetchone()
        return int(row[0]) if row and row[0] is not None else None

    def verification_by_nonce(self, nonce: str, before_id: int) -> LedgerEvent | None:
        """The latest verify_ok or verify_fail row with id < ``before_id`` whose evidence carries ``nonce``,
        or None. A receipt pulls in the verification a send vouches by when it lies before the receipt's
        window (a verification made in a long-lived process, still inside its TTL across an unlock)."""
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-fA-F]{16,128}", nonce):
            return None
        rows = self._rows(f"SELECT {', '.join(_COLUMNS)} FROM events WHERE kind IN ('verify_ok', 'verify_fail') "
                          "AND id < ? AND detail LIKE '%' || ? || '%' ORDER BY id DESC LIMIT 8",
                          (int(before_id), nonce))
        for r in rows:
            ev = r.detail.get("evidence") if isinstance(r.detail, dict) else None
            if isinstance(ev, dict) and ev.get("nonce") == nonce:
                return r
        return None

    def session(self, session_id: str) -> list[LedgerEvent]:
        """Every event for one session, oldest first (receipts)."""
        return self._rows(f"SELECT {', '.join(_COLUMNS)} FROM events WHERE session_id = ? ORDER BY id",
                          (session_id,))

    @property
    def journal_mode(self) -> str:
        """SQLite's journal mode for this ledger ("wal", "delete", ...), or "" when it cannot be read."""
        try:
            with self._lock:
                row = self._db().execute("PRAGMA journal_mode").fetchone()
            return str(row[0]).lower() if row else ""
        except Exception:  # noqa: BLE001
            return ""

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


def event_dict(event: LedgerEvent) -> dict:
    return asdict(event)

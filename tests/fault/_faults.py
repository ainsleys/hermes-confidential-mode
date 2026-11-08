"""Fault injectors for tests/fault: each patches a boundary (the OS call, the SQLite connection, the HTTP
transport, the human) and never the unit under test.

- ``fail_replace``: ``os.replace`` raises an OSError with the given errno when the destination's name matches,
  the way a full disk or a read-only mount fails an atomic write at its last step.
- ``faulty_sqlite``: a ``sqlite3.Connection`` subclass (``sqlite3.connect(..., factory=)``) whose ``execute`` or
  ``commit`` raises the OperationalError SQLite raises on a full disk or a busy database, a set number of times.
- ``truncate``: cut a file in half, as a crash mid-write without an atomic rename would leave it.
- ``chmod_ro``: a read-only directory for the duration of a ``with``.
"""
from __future__ import annotations

import contextlib
import errno
import os
import sqlite3
import stat
from collections.abc import Callable
from pathlib import Path

ENOSPC = errno.ENOSPC
EACCES = errno.EACCES


def fail_replace(monkeypatch, names: set[str] | Callable[[str], bool], err: int = ENOSPC, *, times: int | None = None):
    """Make ``os.replace(src, dst)`` raise ``OSError(err)`` when ``basename(dst)`` is in ``names`` (or the
    predicate says so). Returns a list that records each refused destination. ``times`` limits the failures."""
    real = os.replace
    refused = Refusals()
    match = names if callable(names) else (lambda n: n in names)

    def replace(src, dst, *a, **k):
        name = os.path.basename(os.fspath(dst))
        if refused.active and match(name) and (times is None or len(refused) < times):
            refused.append(os.fspath(dst))
            raise OSError(err, os.strerror(err), os.fspath(dst))
        return real(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", replace)
    return refused


class Refusals(list):
    """The destinations refused so far; ``stop()`` ends the fault without undoing other monkeypatches."""
    active = True

    def stop(self):
        self.active = False


class FaultPlan:
    """What a faulty connection does: ``insert``/``commit`` hold the exception to raise and ``*_times`` how
    many more times (None: always)."""

    def __init__(self):
        self.insert: BaseException | None = None
        self.insert_times: int | None = None
        self.commit: BaseException | None = None
        self.commit_times: int | None = None
        self.insert_after: BaseException | None = None    # raised after the real INSERT ran (row pending)
        self.insert_after_times: int | None = None
        self.rollback: BaseException | None = None
        self.rollback_times: int | None = None
        self.raised: list[str] = []

    def _take(self, what: str):
        exc = getattr(self, what)
        left = getattr(self, f"{what}_times")
        if exc is None or left == 0:
            return None
        if left is not None:
            setattr(self, f"{what}_times", left - 1)
        self.raised.append(what)
        return exc


def faulty_sqlite(plan: FaultPlan):
    class FaultyConnection(sqlite3.Connection):
        def execute(self, sql, *a, **k):
            if sql.lstrip().upper().startswith("INSERT"):
                exc = plan._take("insert")
                if exc is not None:
                    raise exc
                cur = super().execute(sql, *a, **k)
                exc = plan._take("insert_after")
                if exc is not None:
                    raise exc
                return cur
            return super().execute(sql, *a, **k)

        def rollback(self):
            exc = plan._take("rollback")
            if exc is not None:
                raise exc
            return super().rollback()

        def commit(self):
            exc = plan._take("commit")
            if exc is not None:
                raise exc     # SQLite: a COMMIT that fails with SQLITE_BUSY leaves the transaction open
            return super().commit()
    return FaultyConnection


def faulty_ledger(path: Path, plan: FaultPlan, **kw):
    """The real Ledger on ``path`` through a faulty connection (its documented ``connect`` injection point)."""
    from confidential_mode.ledger import BLOB_SUBDIR, Ledger
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    factory = faulty_sqlite(plan)
    return Ledger(connect=lambda: sqlite3.connect(path, check_same_thread=False, timeout=0.05, factory=factory),
                  blob_dir=kw.pop("blob_dir", path.parent.joinpath(*BLOB_SUBDIR)), **kw)


def disk_full() -> sqlite3.OperationalError:
    return sqlite3.OperationalError("database or disk is full")


def db_locked() -> sqlite3.OperationalError:
    return sqlite3.OperationalError("database is locked")


def truncate(path: Path, keep: float = 0.5) -> bytes:
    path = Path(path)
    data = path.read_bytes()
    cut = data[: max(1, int(len(data) * keep))]
    path.write_bytes(cut)
    return cut


@contextlib.contextmanager
def chmod_ro(directory: Path):
    directory = Path(directory)
    old = stat.S_IMODE(directory.stat().st_mode)
    os.chmod(directory, 0o500)
    try:
        yield directory
    finally:
        os.chmod(directory, old)


def tmp_leftovers(directory: Path) -> list[str]:
    try:
        return sorted(p.name for p in Path(directory).iterdir() if p.name.endswith(".tmp"))
    except FileNotFoundError:
        return []

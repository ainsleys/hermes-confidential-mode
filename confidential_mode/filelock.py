"""Bounded advisory file locks for the plugin's state files (Amendment 10, review N1).

A lock is a thread lock plus ``flock`` on ``<file>.lock``. Both are tried without blocking, a bounded number
of times, so a process that holds a lock file (an agent could hold one from a terminal) cannot hang a
revoke, an allow, a pin approval or a gateway hook. A lock still busy after the last attempt raises
``LockBusy``, which names the lock file; every caller fails closed on it.

A lock file that cannot be opened or locked at all (EACCES, a directory in its place, a read-only data
directory, an flock error such as EBADF on NFS) raises ``LockUnusable``, a ``LockBusy`` that names the errno
and says whether the directory is writable (FI-7): this process could not exclude another one, so it changes
nothing. Only a platform without the fcntl module (Windows) holds the thread lock alone; DISCLOSURE states
that limit.
"""
from __future__ import annotations

import contextlib
import errno as _errno
import os
import threading
import time
from pathlib import Path
from typing import Any

ATTEMPTS = 10
INTERVAL_SECONDS = 0.2

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_GUARD = threading.Lock()


class LockBusy(Exception):
    """The lock is held elsewhere (or, as LockUnusable, cannot be taken at all). Nothing was changed."""

    def __init__(self, lock_path: Path, reason: str = ""):
        self.lock_path = Path(lock_path)
        self.reason = reason
        if reason:
            super().__init__(f"{self.lock_path.name} could not be opened ({reason}); nothing was changed")
        else:
            super().__init__(f"{self.lock_path.name} is held by another process or thread "
                             f"({ATTEMPTS * INTERVAL_SECONDS:g} s waited); nothing was changed")


class LockUnusable(LockBusy):
    """The lock file could not be opened or locked: no other process holds it, but this one cannot exclude
    another. ``errno_name`` names the error (EACCES, EBADF, ...); ``dir_writable`` is False when the lock
    file's directory is not writable (a read-only data directory), which callers report as such."""

    def __init__(self, lock_path: Path, errno_name: str, *, action: str = "opened"):
        self.errno_name = errno_name
        self.directory = Path(lock_path).parent
        try:
            self.dir_writable = os.access(self.directory, os.W_OK)
        except OSError:
            self.dir_writable = False
        super().__init__(lock_path, errno_name)
        if action != "opened":
            self.args = (f"{self.lock_path.name} could not be {action} ({errno_name}); nothing was changed",)


def describe(exc: LockBusy) -> str:
    """Plain text for a reply (may name a local path; never for the ledger): a read-only directory is named
    as such, any other unusable lock file by its error, and a held lock as held."""
    if isinstance(exc, LockUnusable):
        if not exc.dir_writable:
            return f"the data directory is not writable: {exc.directory}"
        return f"the lock file {exc.lock_path} cannot be used ({exc.errno_name})"
    return f"{exc.lock_path.name} is held by another process"


def ledger_reason(exc: LockBusy) -> dict:
    """Path-free ledger detail for a LockBusy: reason code, errno name and the lock file's basename."""
    if isinstance(exc, LockUnusable):
        code = "data_dir_not_writable" if not exc.dir_writable else "lock_file_unusable"
        return {"reason_code": code, "errno": exc.errno_name, "lock_file": exc.lock_path.name}
    return {"reason_code": "lock_busy", "lock_file": exc.lock_path.name}


def _errno_name(exc: BaseException) -> str:
    code = getattr(exc, "errno", None)
    return _errno.errorcode.get(code, type(exc).__name__) if isinstance(code, int) else type(exc).__name__


def lock_path_for(path: Any) -> Path:
    path = Path(path)
    return path.with_name(path.name + ".lock")


@contextlib.contextmanager
def exclusive(lock_path: Any, *, thread_lock: threading.Lock | None = None):
    """Hold ``lock_path`` exclusively, or raise LockBusy after ATTEMPTS tries INTERVAL_SECONDS apart. A lock
    file that cannot be opened for append is opened read-only (flock accepts a read-only descriptor on local
    filesystems). Any failure to open or flock the file other than "held" raises LockUnusable (fail closed,
    FI-7). On a platform without the fcntl module only the thread lock is held. Not reentrant."""
    lock_path = Path(lock_path)
    if thread_lock is None:
        with _GUARD:
            thread_lock = _THREAD_LOCKS.setdefault(str(lock_path), threading.Lock())
    if not thread_lock.acquire(timeout=ATTEMPTS * INTERVAL_SECONDS):
        raise LockBusy(lock_path)
    fh = None
    try:
        try:
            import fcntl
        except ImportError:
            fcntl = None   # Windows: thread lock only (DISCLOSURE, Processes and threads)
        if fcntl is not None:
            try:
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                fh = open(lock_path, "a")
            except OSError:
                try:
                    fh = open(lock_path, "r")
                except OSError as exc:
                    fh = None
                    raise LockUnusable(lock_path, _errno_name(exc)) from None
            for attempt in range(ATTEMPTS):
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if attempt == ATTEMPTS - 1:
                        raise LockBusy(lock_path) from None
                    time.sleep(INTERVAL_SECONDS)
                except OSError as exc:   # EBADF (NFS, read-only descriptor), ENOLCK, EOPNOTSUPP, ...
                    raise LockUnusable(lock_path, _errno_name(exc), action="locked") from None
        yield
    finally:
        if fh is not None:
            fh.close()
        thread_lock.release()

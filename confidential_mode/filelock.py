"""Bounded advisory file locks for the plugin's state files (Amendment 9, review N1).

A lock is a thread lock plus ``flock`` on ``<file>.lock``. Both are tried without blocking, a bounded number
of times, so a process that holds a lock file (an agent could hold one from a terminal) cannot hang a
revoke, an allow, a pin approval or a gateway hook. A lock still busy after the last attempt raises
``LockBusy``, which names the lock file; every caller fails closed on it.
"""
from __future__ import annotations

import contextlib
import threading
import time
from pathlib import Path
from typing import Any

ATTEMPTS = 10
INTERVAL_SECONDS = 0.2

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_GUARD = threading.Lock()


class LockBusy(Exception):
    def __init__(self, lock_path: Path):
        self.lock_path = Path(lock_path)
        super().__init__(f"{self.lock_path.name} is held by another process or thread "
                         f"({ATTEMPTS * INTERVAL_SECONDS:g} s waited); nothing was changed")


def lock_path_for(path: Any) -> Path:
    path = Path(path)
    return path.with_name(path.name + ".lock")


@contextlib.contextmanager
def exclusive(lock_path: Any, *, thread_lock: threading.Lock | None = None):
    """Hold ``lock_path`` exclusively, or raise LockBusy after ATTEMPTS tries INTERVAL_SECONDS apart. On a
    platform without fcntl, or when the lock file cannot be opened, only the thread lock is held (as
    before). Not reentrant."""
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
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fh = open(lock_path, "a")
        except (ImportError, OSError):
            fh = None
        if fh is not None:
            for attempt in range(ATTEMPTS):
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if attempt == ATTEMPTS - 1:
                        raise LockBusy(lock_path) from None
                    time.sleep(INTERVAL_SECONDS)
                except OSError:
                    break   # flock unsupported on this filesystem: thread lock only, as before
        yield
    finally:
        if fh is not None:
            fh.close()
        thread_lock.release()

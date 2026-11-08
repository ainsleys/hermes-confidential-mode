"""One durable atomic write for every plugin state file (issue #37).

``write_atomic(path, data)`` writes ``data`` to a temporary file in the target's directory (mode 0600 from
creation), fsyncs the file, renames it over the target with ``os.replace`` and then fsyncs the directory.
POSIX makes a rename durable only once the directory itself is fsynced; without that step a crash after the
rename can bring the old file back, or no file at all, so an approved pin is lost or a replaced pin returns.
A failure anywhere leaves the target as it was and removes the temporary file. Used by pins.py
(``pins.yaml``), state.py (the repaired lock state), gate_tools_allowlist.py (``allowlist.yaml``), revoke.py
(``grants_revoked.json``), review.py (fetched compose files), ledger.py (evidence blobs) and verify/tinfoil.py
(the prompt-cache secret, key observations and Sigstore trust roots).
"""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def fsync_directory(directory: Path) -> None:
    """fsync ``directory`` so a rename inside it is durable. A platform or filesystem that cannot fsync a
    directory (Windows, some network mounts) raises OSError, which is ignored: the file is already written
    and renamed, and nothing else can be done for it here."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_atomic(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` durably and atomically: temporary file in the same directory (``.<name>.*.tmp``,
    mode ``mode`` from creation), fsync of the file, ``os.replace`` onto ``path``, fsync of the directory.
    Creates the directory when it is missing. Raises the OSError of the step that failed; the target is then
    unchanged and the temporary file removed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    fsync_directory(path.parent)

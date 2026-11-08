"""Short progress lines on stderr for the plugin's own start-up work (ux-pass-1, item 7).

After `hermes plugins install` and `hermes plugins enable`, the first Hermes start loads the plugin. The
lines show what the plugin itself is doing then, one line per phase, for example
"confidential-mode: registering the NEAR provider... ok (1.2 s)". The dependency install that the enable
step runs is Hermes' own work; the plugin cannot report on it (README, Install).

The lines are written only to a terminal (stderr is a TTY), and only on the first start of each installed
commit, so an ordinary start stays quiet. ``CONFIDENTIAL_MODE_PROGRESS=1`` shows them on every start, with or
without a terminal, and ``CONFIDENTIAL_MODE_PROGRESS=0`` never. No line carries a secret: phase names and
counts only. Nothing here raises.
"""
from __future__ import annotations

import contextlib
import os
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

ENV = "CONFIDENTIAL_MODE_PROGRESS"
PREFIX = "confidential-mode: "
MARKER = "loaded-commit"
SLOW_SECONDS = 1.0


def _stream_is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001
        return False


def wanted(data_dir: Path | None, commit: str, *, environ=None, stream=None) -> bool:
    """Whether to show the lines: forced by the environment variable, else only on a TTY for a commit that
    has not started here before."""
    env = (environ if environ is not None else os.environ).get(ENV, "").strip()
    if env == "0":
        return False
    if env == "1":
        return True                      # an explicit request: shown without a terminal too
    if not _stream_is_tty(stream if stream is not None else sys.stderr):
        return False
    try:
        return data_dir is None or (Path(data_dir) / MARKER).read_text(encoding="utf-8").strip() != commit
    except Exception:  # noqa: BLE001
        return True


def remember(data_dir: Path | None, commit: str) -> None:
    """Record that this commit has started here (mode 0600). Never raises."""
    if data_dir is None:
        return
    try:
        path = Path(data_dir) / MARKER
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(commit + "\n")
    except Exception:  # noqa: BLE001
        pass


class Progress:
    """``with progress.phase("preparing the data directory"):`` writes "confidential-mode: preparing the data
    directory..." when the phase starts and " ok" (with the seconds when over one) when it ends. ``result``
    replaces "ok" with a short count, such as "78 found"."""

    def __init__(self, enabled: bool, stream=None, clock: Callable[[], float] = time.monotonic):
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr
        self.clock = clock

    def _write(self, text: str) -> None:
        if not self.enabled:
            return
        try:
            self.stream.write(text)
            self.stream.flush()
        except Exception:  # noqa: BLE001
            self.enabled = False

    def line(self, text: str) -> None:
        self._write(f"{PREFIX}{text}\n")

    @contextlib.contextmanager
    def phase(self, name: str) -> Iterator[dict]:
        box = {"result": "ok"}
        start = self.clock()
        self._write(f"{PREFIX}{name}... ")
        try:
            yield box
        except BaseException:
            self._write("failed\n")
            raise
        took = self.clock() - start
        self._write(f"{box['result']}" + (f" ({took:.1f} s)" if took > SLOW_SECONDS else "") + "\n")

    def start(self, name: str) -> None:
        """The start of a phase without a ``with`` block; ``done`` ends it."""
        self._started = self.clock()
        self._write(f"{PREFIX}{name}... ")

    def done(self, result: str = "ok") -> None:
        started = getattr(self, "_started", None)
        took = self.clock() - started if started is not None else 0.0
        self._write(result + (f" ({took:.1f} s)" if took > SLOW_SECONDS else "") + "\n")


QUIET = Progress(False)


def for_cli() -> Progress:
    """Progress for a command a person runs in a terminal (lock, allow): shown when stderr is a TTY, unless
    the environment variable is 0."""
    env = os.environ.get(ENV, "").strip()
    if env == "0":
        return QUIET
    return Progress(env == "1" or _stream_is_tty(sys.stderr))

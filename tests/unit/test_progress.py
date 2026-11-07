"""Start-up progress lines (ux-pass-1 item 7): one line per phase, on a terminal only, first start of a commit."""
from __future__ import annotations

import io

from confidential_mode import progress


class TTY(io.StringIO):
    def isatty(self):
        return True


def test_one_line_per_phase_with_seconds_when_slow():
    t = iter([0.0, 0.2, 10.0, 12.5])
    out = TTY()
    p = progress.Progress(True, stream=out, clock=lambda: next(t))
    p.start("preparing the data directory")
    p.done()
    with p.phase("discovering tools") as box:
        box["result"] = "78 found"
    assert out.getvalue() == ("confidential-mode: preparing the data directory... ok\n"
                              "confidential-mode: discovering tools... 78 found (2.5 s)\n")


def test_shown_only_on_a_terminal_and_on_the_first_start_of_a_commit(tmp_path):
    assert progress.wanted(tmp_path, "abc", environ={}, stream=io.StringIO()) is False      # not a terminal
    assert progress.wanted(tmp_path, "abc", environ={}, stream=TTY()) is True
    progress.remember(tmp_path, "abc")
    assert (tmp_path / progress.MARKER).stat().st_mode & 0o777 == 0o600
    assert progress.wanted(tmp_path, "abc", environ={}, stream=TTY()) is False
    assert progress.wanted(tmp_path, "def", environ={}, stream=TTY()) is True               # a new commit
    assert progress.wanted(tmp_path, "abc", environ={progress.ENV: "1"}, stream=TTY()) is True
    assert progress.wanted(tmp_path, "def", environ={progress.ENV: "0"}, stream=TTY()) is False
    quiet = io.StringIO()
    p = progress.Progress(False, stream=quiet)
    p.start("x")
    p.done()
    assert quiet.getvalue() == ""

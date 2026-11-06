"""Unit tests for confidential_mode.watch over a real (path-injected) Ledger; no Hermes import."""
from __future__ import annotations

import io

from confidential_mode import watch
from confidential_mode.ledger import Ledger, LedgerEvent


class TTY(io.StringIO):
    def isatty(self):
        return True


def _ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite", clock=lambda: 1_700_000_000.0)
    led.append(LedgerEvent(kind="send_observed", session_id="sess-abcdefghijklmnop", purpose="main",
                           host="127.0.0.1", bytes=1234, decision="observed"))
    led.append(LedgerEvent(kind="send_refused", session_id="s2", purpose="main", host="openrouter.ai",
                           bytes=20_480, tier="on-host-only", verdict="off_tier", decision="refused"))
    led.append(LedgerEvent(kind="send_observed", session_id="s2", purpose="aux:title_generation",
                           host="openrouter.ai", bytes=88, tier="on-host-only", verdict="off_tier", decision="observed"))
    led.append(LedgerEvent(kind="breach", session_id="s2", purpose="aux:title_generation", host="openrouter.ai",
                           verdict="off_tier", decision="aux_sent"))
    return led


def test_once_prints_header_and_every_row_without_ansi_when_not_a_tty(tmp_path):
    led = _ledger(tmp_path)
    out = io.StringIO()
    last = watch.run(led, once=True, out=out)
    lines = out.getvalue().splitlines()
    assert lines[0].split() == ["TIME", "SESSION", "PURPOSE", "HOST", "BYTES", "VERDICT/DECISION"]
    assert len(lines) == 5 and last == 4
    assert "\x1b[" not in out.getvalue()
    assert "127.0.0.1" in lines[1] and "1234" in lines[1] and "send_observed observed" in lines[1]
    assert "sess-abcdef~" in lines[1]                       # fixed-width session column
    assert "20K" in lines[2] and "send_refused off_tier refused" in lines[2]


def test_fixed_width_columns_line_up(tmp_path):
    out = io.StringIO()
    watch.run(_ledger(tmp_path), once=True, out=out)
    lines = out.getvalue().splitlines()
    starts = {line.index(line.split()[-1]) for line in lines[1:] if "observed" in line.split()[-1]}
    host_col = lines[0].index("HOST")
    assert all(line[host_col - 2:host_col] == "  " for line in lines[1:])
    assert starts                                            # last column present


def test_colour_only_on_a_tty_and_only_for_off_tier_or_breach_rows(tmp_path):
    out = TTY()
    watch.run(_ledger(tmp_path), once=True, out=out)
    lines = out.getvalue().splitlines()
    assert lines[1].startswith(watch.RESET) is False and "\x1b[3" not in lines[1]      # in-tier: plain
    assert lines[2].startswith(watch.RED) and lines[2].endswith(watch.RESET)          # refusal
    assert lines[3].startswith(watch.YELLOW)                                           # off-tier observed
    assert lines[4].startswith(watch.RED)                                              # breach


def test_limit_shows_only_the_latest_rows(tmp_path):
    out = io.StringIO()
    watch.run(_ledger(tmp_path), once=True, limit=2, out=out)
    lines = out.getvalue().splitlines()
    assert len(lines) == 3 and "aux:title_generation" in lines[1] and "breach" in lines[2]


def test_streaming_polls_tail_for_new_rows(tmp_path):
    led = _ledger(tmp_path)
    out = io.StringIO()

    def sleep(_s):
        led.append(LedgerEvent(kind="tool_refused", session_id="s3", purpose="tool:web_search", decision="cron"))

    last = watch.run(led, out=out, sleep=sleep, max_polls=2)
    lines = out.getvalue().splitlines()
    assert last == 6 and len(lines) == 7
    assert lines[-1].split()[2] == "tool:web_search"


def test_unprintable_values_cannot_forge_lines(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    led.append(LedgerEvent(kind="send_observed", purpose="main\nFAKE ROW", host="h\x1b[2J"))
    out = io.StringIO()
    watch.run(led, once=True, out=out)
    assert len(out.getvalue().splitlines()) == 2 and "\x1b" not in out.getvalue()


def test_works_on_an_empty_ledger(tmp_path):
    out = io.StringIO()
    assert watch.run(Ledger(tmp_path / "e.sqlite"), once=True, out=out) == 0
    assert out.getvalue().startswith("TIME")

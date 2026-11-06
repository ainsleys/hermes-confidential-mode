"""``hermes confidential watch``: a live fixed-width view of the ledger (W5).

Columns: time, session, purpose, host, bytes, verdict/decision. Rows that left (or tried to leave)
the tier are coloured: refusals and breaches red, off-tier verdicts yellow. ANSI colour is used only
when the output stream is a tty. Works locked or unlocked (the gate ledgers ``send_observed`` either
way). ``once=True`` prints the most recent rows and returns (tests, scripts).
"""
from __future__ import annotations

import sys
import time
from collections import deque
from typing import Any, Callable, Iterable, Optional, TextIO

COLUMNS = (("TIME", 8), ("SESSION", 12), ("PURPOSE", 24), ("HOST", 30), ("BYTES", 8), ("VERDICT/DECISION", 0))
RED, YELLOW, DIM, RESET = "\x1b[31m", "\x1b[33m", "\x1b[2m", "\x1b[0m"
ALERT_KINDS = frozenset({"send_refused", "tool_refused", "breach", "preflight_fail", "verify_fail", "pin_denied"})


def _clip(text: str, width: int) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in str(text))
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "~"


def _bytes(n: Any) -> str:
    if not isinstance(n, int):
        return "-"
    if n < 10_000:
        return str(n)
    if n < 10_000_000:
        return f"{n // 1024}K"
    return f"{n // (1024 * 1024)}M"


def severity(ev: Any) -> str:
    """"alert" | "warn" | "" for one ledger event."""
    if ev.kind in ALERT_KINDS:
        return "alert"
    if (ev.verdict or "") == "off_tier":
        return "warn"
    return ""


def verdict_text(ev: Any) -> str:
    parts = [ev.kind]
    for value in (ev.verdict, ev.decision):
        if value and value not in parts:
            parts.append(str(value))
    return " ".join(parts)


def header() -> str:
    return "  ".join(f"{name:<{w}}" if w else name for name, w in COLUMNS)


def format_row(ev: Any, *, color: bool = False) -> str:
    ts = time.strftime("%H:%M:%S", time.localtime(ev.ts or 0))
    cells = (ts, ev.session_id or "-", ev.purpose or "-", ev.host or "-", _bytes(ev.bytes), verdict_text(ev))
    line = "  ".join(f"{_clip(c, w):<{w}}" if w else _clip(c, 0) for c, (_, w) in zip(cells, COLUMNS))
    if not color:
        return line.rstrip()
    sev = severity(ev)
    code = RED if sev == "alert" else YELLOW if sev == "warn" else ""
    return f"{code}{line.rstrip()}{RESET}" if code else line.rstrip()


def _is_tty(out: TextIO) -> bool:
    try:
        return bool(out.isatty())
    except Exception:
        return False


def latest(ledger: Any, limit: int, *, page: int = 1000) -> tuple[list, int]:
    """(last ``limit`` events oldest first, id of the newest event)."""
    buf: deque = deque(maxlen=max(1, limit))
    last = 0
    while True:
        rows = ledger.tail(last, limit=page)
        buf.extend(rows)
        if rows:
            last = rows[-1].id
        if len(rows) < page:
            return list(buf), last


def run(ledger: Any, *, once: bool = False, limit: int = 50, interval: float = 1.0,
        out: Optional[TextIO] = None, color: Optional[bool] = None,
        sleep: Callable[[float], None] = time.sleep, max_polls: Optional[int] = None) -> int:
    """Print the last ``limit`` rows, then (unless ``once``) poll ``Ledger.tail`` for new rows until
    interrupted. Returns the id of the last row printed."""
    out = out or sys.stdout
    use_color = _is_tty(out) if color is None else color
    rows, last = latest(ledger, limit)
    hdr = header()
    out.write((f"{DIM}{hdr}{RESET}" if use_color else hdr) + "\n")
    for ev in rows:
        out.write(format_row(ev, color=use_color) + "\n")
    out.flush()
    if once:
        return last
    polls = 0
    try:
        while max_polls is None or polls < max_polls:
            sleep(interval)
            polls += 1
            for ev in ledger.tail(last):
                out.write(format_row(ev, color=use_color) + "\n")
                last = ev.id
            out.flush()
    except KeyboardInterrupt:
        pass
    return last


def setup_parser(parser: Any) -> None:
    parser.add_argument("--once", action="store_true", help="print the latest rows and exit")
    parser.add_argument("--limit", type=int, default=50, help="rows to show first (default 50)")
    parser.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds")

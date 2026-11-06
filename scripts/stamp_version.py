#!/usr/bin/env python3
"""Write the current git short sha into confidential_mode/_version.py (PLUGIN_COMMIT).

Run from the repository before packaging / catalog submission:

    python3 scripts/stamp_version.py          # stamps e.g. "16c0265" (or "16c0265-dirty")
    python3 scripts/stamp_version.py --reset  # back to "unpackaged"

A tree with uncommitted changes (other than _version.py itself) is stamped "<sha>-dirty".
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "confidential_mode" / "_version.py"
LINE = re.compile(r'^PLUGIN_COMMIT = ".*"$', re.M)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def current_commit() -> str:
    sha = git("rev-parse", "--short", "HEAD")
    changes = [l for l in git("status", "--porcelain").splitlines() if not l.endswith("confidential_mode/_version.py")]
    return f"{sha}-dirty" if changes else sha


def stamp(value: str) -> None:
    text = VERSION_FILE.read_text(encoding="utf-8")
    if not LINE.search(text):
        raise SystemExit(f"{VERSION_FILE}: no PLUGIN_COMMIT line to replace")
    VERSION_FILE.write_text(LINE.sub(f'PLUGIN_COMMIT = "{value}"', text, count=1), encoding="utf-8")


def main(argv: list[str]) -> int:
    value = "unpackaged" if "--reset" in argv else current_commit()
    stamp(value)
    print(f"PLUGIN_COMMIT = {value!r} -> {VERSION_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Plugin build identity, printed by `hermes confidential status` and in receipts.

A git checkout reports the commit its ``.git`` names (HEAD), marked "git checkout", because local edits are
not detected. `hermes plugins install` clones the repository, so an installed plugin is a git checkout and
reports the commit that was installed, also after `hermes plugins update`. The stamp below is written by
packaging (scripts/stamp_version.py) and is used only when there is no readable ``.git``, as in a packaged
copy. With neither, the commit reads "unpackaged". The commit is read from files only: no git command, no
subprocess.

Root cause of the stale commit (first-time user walkthrough, 2026-11-07): the stamp was committed to the
repository, and the stamp took precedence over ``.git``, so every later checkout reported the stamped commit.
"""
from __future__ import annotations

from pathlib import Path

PLUGIN_VERSION = "0.1.0"
PLUGIN_COMMIT = "unpackaged"

CHECKOUT_SUFFIX = " (git checkout)"
UNSTAMPED_SUFFIX = CHECKOUT_SUFFIX   # the older name


def checkout_commit(root: Path | None = None) -> str | None:
    """The 40-hex commit HEAD names in ``<root>/.git`` (a loose ref or packed-refs), or None. Never raises."""
    try:
        git = (Path(root) if root is not None else Path(__file__).resolve().parents[1]) / ".git"
        if git.is_file():                       # a worktree: "gitdir: <path>"
            text = git.read_text(encoding="utf-8").strip()
            if not text.startswith("gitdir:"):
                return None
            git = (git.parent / text[len("gitdir:"):].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref = head[4:].strip()
            common = git
            if (git / "commondir").is_file():
                common = (git / (git / "commondir").read_text(encoding="utf-8").strip()).resolve()
            sha = None
            for base in (git, common):
                if (base / ref).is_file():
                    sha = (base / ref).read_text(encoding="utf-8").strip()
                    break
            if sha is None and (common / "packed-refs").is_file():
                for line in (common / "packed-refs").read_text(encoding="utf-8").splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        sha = parts[0]
                        break
        else:
            sha = head
        if sha and len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
            return sha
    except Exception:  # noqa: BLE001
        return None
    return None


def resolve_commit(stamp: str, root: Path | None = None) -> str:
    """The commit to report: the checkout's HEAD when ``.git`` is readable, else the packaging stamp, else
    "unpackaged". Never raises."""
    sha = checkout_commit(root)
    if sha:
        return sha[:12] + CHECKOUT_SUFFIX
    return stamp if stamp and stamp != "unpackaged" else "unpackaged"


PLUGIN_COMMIT = resolve_commit(PLUGIN_COMMIT)

"""Plugin build identity, printed in receipts beside the verifier SDK version.

PLUGIN_COMMIT is filled in by packaging (scripts/stamp_version.py writes the git commit the release was
built from). A source checkout that was not stamped reports the commit its ``.git`` directory names,
marked "unstamped checkout", because local edits are not detected. Without a readable ``.git`` it
reports "unpackaged". The commit is read from files only: no git command, no subprocess.
"""
from __future__ import annotations

from pathlib import Path

PLUGIN_VERSION = "0.1.0"
PLUGIN_COMMIT = "unpackaged"

UNSTAMPED_SUFFIX = " (unstamped checkout)"


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


if PLUGIN_COMMIT == "unpackaged":
    _sha = checkout_commit()
    if _sha:
        PLUGIN_COMMIT = _sha[:12] + UNSTAMPED_SUFFIX

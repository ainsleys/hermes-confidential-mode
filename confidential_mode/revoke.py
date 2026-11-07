"""`revoke <tool>` and `revoke --all`: withdraw the tool grants confidential mode is responsible for
(INTERFACES Amendment 9, backlog U06).

A grant that lets an off-host tool run without a prompt while locked lives in one of three places:

* ``allowlist.yaml`` ``allowed``: written by ``/confidential allow <tool>`` (consent.allow_tool ->
  Allowlist.add -> Allowlist.persist), scoped to one lock by ``lock_id``.
* Hermes' ``command_allowlist`` in config.yaml: written by Hermes when a person answers "always" to the
  plugin's approve prompt (tools/approval.py _persist_choice -> save_permanent_allowlist), under the
  plugin's own rule key ``plugin_rule:confidential-mode:tool:<tool>``.
* Hermes' in-memory session approvals (tools/approval.py ``_session_approved``), under the same key, for
  a "session" or "always" answer, in the process that asked.

Revoke removes exactly those entries and nothing else: a command_allowlist entry under any other key is
the user's or another plugin's, and is left alone. The key prefix is a convention, not something Hermes
enforces: Hermes forms the key from the rule_key a caller chooses, so another plugin could write an entry
under this prefix, and revoke would remove that entry too (which only narrows). Revoking narrows and never widens, so it asks nobody
and runs under the self-approval marker.

How a running gateway sees a revoke made in another process (the ``hermes confidential`` CLI): the
gateway re-reads allowlist.yaml on its next tool call when the file changes, and Hermes re-syncs
``command_allowlist`` from disk on every approval check. Session approvals live only in the gateway's
memory, so every revoke of a named tool (or ``--all``) appends a record to ``grants_revoked.json``, even
when the revoking process found nothing to remove itself; the gateway applies each new record on its next
tool call (``RevocationWatcher``), before the gate consults any grant.

Writes to allowlist.yaml and grants_revoked.json take an advisory lock file next to each file
(``file_lock``, the pins-file pattern), so a CLI and a gateway never interleave a read-modify-write.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

REVOCATIONS_FILE = "grants_revoked.json"
MAX_RECORDS = 200
ALL = "*"


def _prefix() -> str:
    from .gate_tools import PATTERN_KEY_PREFIX
    return PATTERN_KEY_PREFIX


def plugin_key(tool: str) -> str:
    """The key Hermes stores an answer to the plugin's prompt under (tools/approval.py:1226)."""
    return _prefix() + tool


def tool_name_problem(name: Any) -> str:
    if not isinstance(name, str) or not name:
        return "a tool name is required"
    if len(name) > 200 or not name.isprintable() or any(c.isspace() for c in name) or name == ALL:
        return f"{name!r} is not a tool name"
    return ""


def _is_ours(entry: Any, tools: Optional[set[str]]) -> bool:
    if not isinstance(entry, str) or not entry.startswith(_prefix()):
        return False
    return tools is None or entry[len(_prefix()):] in tools


@contextlib.contextmanager
def file_lock(path: Any):
    """Bounded advisory lock on ``<path>.lock`` (filelock.exclusive), so two processes never interleave a
    read-modify-write of one of the plugin's JSON files. Raises filelock.LockBusy when the lock stays held."""
    from .filelock import exclusive, lock_path_for
    with exclusive(lock_path_for(path)):
        yield


def allowed_on_disk(path: Any, lock_id: str) -> Optional[set[str]]:
    """The ``allowed`` names in allowlist.yaml when the file belongs to ``lock_id``, else None."""
    data = _read_json(Path(path)) if path is not None else None
    if not isinstance(data, dict) or not lock_id or data.get("lock_id") != lock_id \
            or not isinstance(data.get("allowed"), list):
        return None
    return {n for n in data["allowed"] if isinstance(n, str)}


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_json(path: Optional[Path]) -> Any:
    if path is None:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - missing or corrupt: nothing to remove
        return None


# ── allowlist.yaml (written by `allow <tool>`) ──────────────────────────────────────────────────

def remove_allowlist_grants(path: Optional[Path], lock_id: str, tools: Optional[set[str]]) -> list[str]:
    """Remove ``tools`` (None = every name) from ``allowed`` in allowlist.yaml, only when the file belongs
    to ``lock_id``. Every other key of the file is kept. Returns the names removed."""
    if path is None or not lock_id:
        return []
    with file_lock(path):
        data = _read_json(path)
        if not isinstance(data, dict) or data.get("lock_id") != lock_id or not isinstance(data.get("allowed"), list):
            return []
        allowed = data["allowed"]
        removed = sorted({n for n in allowed if isinstance(n, str) and (tools is None or n in tools)})
        if not removed:
            return []
        data["allowed"] = [n for n in allowed if n not in removed]
        _atomic_write_json(Path(path), data)
    return removed


# ── Hermes' command_allowlist (written by Hermes for an "always" answer to our prompt) ─────────────

class RevokeError(Exception):
    pass


def _command_allowlist(config: Any) -> list:
    raw = config.get("command_allowlist") if isinstance(config, dict) else None
    return raw if isinstance(raw, list) else []


def remove_command_allowlist_grants(tools: Optional[set[str]]) -> tuple[list[str], list[str]]:
    """Remove the plugin's keys for ``tools`` (None = every plugin key) from command_allowlist.
    Returns (tools removed, other entries that name one of ``tools`` and were left alone)."""
    from hermes_cli.config import load_config, save_config
    config = load_config()
    entries = _command_allowlist(config)
    ours = [e for e in entries if _is_ours(e, tools)]
    foreign = sorted({e for e in entries if isinstance(e, str) and not _is_ours(e, None) and tools
                      and any(e == t or e.endswith(":" + t) for t in tools)})
    if not ours:
        return [], foreign
    config["command_allowlist"] = [e for e in entries if e not in ours]
    save_config(config)
    left = [e for e in _command_allowlist(load_config()) if e in ours]
    if left:
        raise RevokeError("config.yaml was not updated (a managed install, or the file is not writable); "
                          f"remove {', '.join(left)} from command_allowlist by hand")
    return sorted({e[len(_prefix()):] for e in ours}), foreign


# ── Hermes' in-memory session approvals (this process) ─────────────────────────────────────────

_HERMES_STATE = ("_lock", "_session_approved", "_permanent_set")
SESSION_ERROR = ("Hermes' in-memory session approval could not be dropped (tools.approval has no {name}); "
                 "restart the gateway to end that grant")


def forget_session_grants(tools: Optional[set[str]]) -> tuple[list[str], str]:
    """Drop the plugin's keys for ``tools`` (None = every plugin key) from Hermes' session approvals, for
    every session in this process, and from this process's copy of the permanent allowlist (Hermes also
    re-syncs that copy from config.yaml on every check). Returns (tools whose session approval was dropped,
    error). The error is "" on success, and names the missing private attribute when this Hermes does not
    have the 84a0301 state (``_lock``, ``_session_approved``, ``_permanent_set``). Never raises."""
    dropped: set[str] = set()
    try:
        from tools import approval
    except Exception as exc:  # noqa: BLE001
        return [], SESSION_ERROR.format(name=f"importable module ({type(exc).__name__})")
    missing = [n for n in _HERMES_STATE if not hasattr(approval, n)]
    if missing:
        return [], SESSION_ERROR.format(name=", ".join(missing))
    try:
        with approval._lock:
            for keys in list(approval._session_approved.values()):
                for key in [k for k in keys if _is_ours(k, tools)]:
                    keys.discard(key)
                    dropped.add(key[len(_prefix()):])
            permanent = approval._permanent_set()
            for key in [k for k in permanent if _is_ours(k, tools)]:
                permanent.discard(key)
    except Exception as exc:  # noqa: BLE001
        return sorted(dropped), SESSION_ERROR.format(name=f"usable session state ({type(exc).__name__})")
    return sorted(dropped), ""


# ── revocation records for other processes ─────────────────────────────────────────────────────

def revocations_path(allowlist_path: Optional[Path]) -> Optional[Path]:
    return Path(allowlist_path).parent / REVOCATIONS_FILE if allowlist_path is not None else None


def _records(path: Optional[Path]) -> list[dict]:
    data = _read_json(path)
    recs = data.get("records") if isinstance(data, dict) else None
    return [r for r in recs if isinstance(r, dict) and isinstance(r.get("id"), str)] if isinstance(recs, list) else []


def append_record(path: Optional[Path], tools: Optional[set[str]]) -> str:
    if path is None:
        return ""
    rec = {"id": uuid.uuid4().hex, "ts": time.time(), "tools": sorted(tools) if tools is not None else [ALL]}
    with file_lock(path):
        recs = (_records(path) + [rec])[-MAX_RECORDS:]
        _atomic_write_json(Path(path), {"version": 1, "records": recs})
    return rec["id"]


class RevocationWatcher:
    """Applies revocation records another process wrote, once each, in this process. ``baseline()`` at
    load marks the records already present as applied: a fresh process has no session grants, and its
    file-backed grants already reflect them. ``apply()`` runs before each gate decision. Never raises."""

    def __init__(self, path: Optional[Path], drop_added=None, on_error=None):
        self.path = path
        self.drop_added = drop_added
        self.on_error = on_error      # on_error(tools, error): a session approval this process could not drop
        self.applied: set[str] = set()
        self._stamp: Any = None
        self._lock = threading.Lock()

    def _file_stamp(self):
        try:
            st = os.stat(self.path)
            return st.st_mtime_ns, st.st_size
        except Exception:  # noqa: BLE001
            return None

    def baseline(self) -> None:
        try:
            with self._lock:
                self._stamp = self._file_stamp()
                self.applied |= {r["id"] for r in _records(self.path)}
        except Exception:  # noqa: BLE001
            pass

    def mark(self, rec_id: str) -> None:
        with self._lock:
            if rec_id:
                self.applied.add(rec_id)

    def apply(self) -> None:
        try:
            stamp = self._file_stamp()
            with self._lock:
                if stamp == self._stamp:
                    return
                self._stamp = stamp
                fresh = [r for r in _records(self.path) if r["id"] not in self.applied]
                self.applied |= {r["id"] for r in fresh}
            for rec in fresh:
                names = rec.get("tools") if isinstance(rec.get("tools"), list) else [ALL]
                tools = None if ALL in names else {n for n in names if isinstance(n, str)}
                _, error = forget_session_grants(tools)
                if error and self.on_error is not None:
                    with contextlib.suppress(Exception):
                        self.on_error(tools, error)
                if self.drop_added is not None:
                    self.drop_added(tools)
        except Exception:  # noqa: BLE001
            pass


# ── the command ─────────────────────────────────────────────────────────────────────────────────

def _drop_cached_added(rt: Any, tools: Optional[set[str]]) -> list[str]:
    al = getattr(rt, "_allowlist", None)
    if al is None:
        return []
    try:
        with al._lock:
            gone = sorted(n for n in al.added if tools is None or n in tools)
            al.added -= set(gone)
    except Exception:  # noqa: BLE001
        return []
    return gone


REVOKED, NOTHING, FAILED = "revoked", "nothing", "failed"
_GATEWAY = "A running gateway applies the revoke on its next tool call"


def revoke(rt: Any, tool: Optional[str], *, revoke_all: bool = False, session_id: str = "",
           surface: str = "") -> tuple[str, str]:
    """(status, message); status is REVOKED, NOTHING or FAILED. Removes the plugin's grants for ``tool``
    (or all of them) from allowlist.yaml, command_allowlist and this process's session approvals, records
    the revoke for other processes in every case, and writes a ``grant_revoked`` ledger row. FAILED when any
    step did not take effect; the message then starts with the failure."""
    from .gate_tools import lock_id_for
    if revoke_all:
        tools, what = None, "every confidential-mode tool grant"
    else:
        problem = tool_name_problem(tool)
        if problem:
            return FAILED, f"Usage: /confidential revoke <tool>|--all ({problem})"
        tools, what = {tool}, tool
    try:
        locked, _ = rt.is_locked()
    except Exception:  # noqa: BLE001
        locked = False
    lock_id = lock_id_for(rt.state) if locked is True else ""
    errors: list[str] = []
    from .filelock import LockBusy
    try:
        from_allowlist = remove_allowlist_grants(getattr(rt, "allowlist_path", None), lock_id, tools)
    except LockBusy as exc:
        from_allowlist = []
        errors.append(f"allowlist.yaml was not changed: {exc}")
    except Exception as exc:  # noqa: BLE001
        from_allowlist = []
        errors.append(f"allowlist.yaml could not be written ({type(exc).__name__})")
    from_cache = _drop_cached_added(rt, tools)
    foreign: list[str] = []
    try:
        from_hermes, foreign = remove_command_allowlist_grants(tools)
    except RevokeError as exc:
        from_hermes = []
        errors.append(str(exc))
    except Exception as exc:  # noqa: BLE001
        from_hermes = []
        errors.append(f"command_allowlist in config.yaml could not be read or written ({type(exc).__name__}); "
                      "the grant may still be there")
    from_session, session_error = forget_session_grants(tools)
    if session_error:
        errors.append(session_error)
    try:
        rec_id = append_record(revocations_path(getattr(rt, "allowlist_path", None)), tools)
        watcher = getattr(rt, "revocations", None)
        if watcher is not None and rec_id:
            watcher.mark(rec_id)
        if not rec_id:
            errors.append("the plugin's data directory is unknown, so no running process was told")
    except LockBusy as exc:
        errors.append(f"the revocation record was not written: {exc}; a running gateway keeps any session grant "
                      "until its session ends")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"the revocation record could not be written ({type(exc).__name__}), so a running gateway "
                      "keeps any session grant until its session ends")
    removed = sorted(set(from_allowlist) | set(from_cache) | set(from_hermes) | set(from_session))
    status = FAILED if errors else (REVOKED if removed else NOTHING)
    row = {"ts": time.time(), "session_id": session_id or "", "kind": "grant_revoked",
           "purpose": f"tool:{tool if not revoke_all else ALL}", "provider": "", "host": "", "model": "",
           "bytes": None, "tier": None, "verdict": None,
           "decision": ("revoke_all" if revoke_all else "revoke") + ("_failed" if status == FAILED else ""),
           "surface": surface or None,
           "detail": {"tool": tool if not revoke_all else ALL, "lock_id": lock_id, "surface": surface or "unknown",
                      "removed": {"allowlist": sorted(set(from_allowlist) | set(from_cache)),
                                  "command_allowlist": from_hermes, "session": from_session},
                      "errors": errors, "session_dropped": not session_error}}
    note = ""
    try:
        rt.ledger.append(row)
    except Exception as exc:  # noqa: BLE001
        note = f" The grant_revoked ledger row could not be written ({type(exc).__name__})."
    left_alone = (f" Entries in command_allowlist that confidential mode did not write were left alone: "
                  f"{', '.join(foreign)}." if foreign else "")
    places = []
    if from_allowlist or from_cache:
        places.append("this lock's allowlist (allowlist.yaml)")
    if from_hermes:
        places.append("Hermes' command_allowlist")
    if from_session:
        places.append("this process's session approvals")
    done = f" Removed {', '.join(removed)} from {' and '.join(places)}." if removed else ""
    if status == FAILED:
        return FAILED, (f"Revoke failed for {what}: {'; '.join(errors)}." + done
                        + " Until this is fixed, the tool may still run without asking." + left_alone + note)
    if status == NOTHING:
        return NOTHING, (f"Nothing to revoke for {what} in this process: no grant written by confidential mode "
                         "was found in allowlist.yaml or command_allowlist. The revoke was recorded. " + _GATEWAY
                         + " and drops any session grant it holds." + left_alone + note)
    nxt = "The next call of each asks again" if (revoke_all or len(removed) > 1) else f"The next {tool} call asks again"
    return REVOKED, (f"Revoked {', '.join(removed)}: removed from {' and '.join(places)}. {nxt} while locked. "
                     + _GATEWAY + "." + left_alone + note)

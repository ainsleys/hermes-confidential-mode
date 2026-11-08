"""`revoke <tool>` and `revoke --all`: withdraw the tool grants confidential mode is responsible for
(INTERFACES Amendment 10, backlog U06).

A grant that lets an off-host tool run without a prompt while locked lives in one of three places:

* ``allowlist.yaml`` ``allowed``: written by ``/confidential allow <tool>`` (consent.allow_tool ->
  Allowlist.add -> Allowlist.persist), scoped to one lock by ``lock_id``.
* Hermes' ``command_allowlist`` in config.yaml: written by Hermes when a person answers "always" to the
  plugin's approve prompt (tools/approval.py _persist_choice -> save_permanent_allowlist), under the
  plugin's own rule key ``plugin_rule:confidential-mode:tool:<tool>``.
* Hermes' in-memory session approvals, under the same key, for a "session" or "always" answer, in the
  process that asked.
Revoke removes the first two and leaves Hermes' session approvals where they are: the plugin never
writes Hermes' approval tables (catalog rule 9). It withdraws them instead by changing the rule key it asks
under: every revoke appends a record to ``grants_revoked.json``, and from then on the gate asks under
``confidential-mode:tool@<generation>:<tool>``, where the generation names the latest record covering the
tool. A session or always answer Hermes holds for the older key then matches nothing the plugin asks for.
A command_allowlist entry under any other key is the user's or another plugin's, and is left alone. The key prefix is a convention, not something Hermes
enforces: Hermes forms the key from the rule_key a caller chooses, so another plugin could write an entry
under this prefix, and revoke would remove that entry too (which only narrows). Revoking narrows and never widens, so it asks nobody
and runs under the self-approval marker.

How a running gateway sees a revoke made in another process (the ``hermes confidential`` CLI): the
gateway re-reads allowlist.yaml on its next tool call when the file changes, and Hermes re-syncs
``command_allowlist`` from disk on every approval check. Every revoke of a named tool (or ``--all``)
appends a record, even when the revoking process found nothing to remove itself; the gateway reads each new
record on its next tool call (``RevocationWatcher``), before the gate consults any grant, drops its cached
grants for the tools named and asks under the new generation's rule key.

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


def _parse(entry: Any) -> Optional[tuple[str, str]]:
    from .gate_tools import parse_pattern_key
    return parse_pattern_key(entry)


def _is_ours(entry: Any, tools: Optional[set[str]]) -> bool:
    """A Hermes key the plugin asked under (any generation), for one of ``tools`` (None = any tool)."""
    parsed = _parse(entry)
    return parsed is not None and (tools is None or parsed[0] in tools)


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
    """Remove the plugin's keys for ``tools`` (None = every plugin key) from command_allowlist in config.yaml:
    read the user's file with ``read_raw_config``, drop only entries ``gate_tools.parse_pattern_key`` reads as
    the plugin's own rule key, and save with ``save_config``; nothing is written when there is none. Returns
    (tools removed, other entries that name one of ``tools`` and were left alone)."""
    from hermes_cli.config import load_config, read_raw_config, save_config
    # The user's file as written (no defaults merged, no migration stamp), so the save changes the plugin's own
    # command_allowlist entries and nothing else; Hermes' save_config keeps comments and env references.
    config = read_raw_config()
    entries = _command_allowlist(config)
    ours = [e for e in entries if _is_ours(e, tools)]
    foreign = sorted({e for e in entries if isinstance(e, str) and not _is_ours(e, None) and tools
                      and any(e == t or e.endswith(":" + t) for t in tools)})
    if not ours:
        return [], foreign
    config["command_allowlist"] = [e for e in entries if e not in ours]
    save_config(config)
    left = sorted({e for e in _command_allowlist(load_config()) if e in ours})
    if left:
        raise RevokeError("config.yaml was not updated (a managed install, or the file is not writable); "
                          f"delete the line{'s' if len(left) > 1 else ''} {', '.join(left)} under "
                          "command_allowlist in config.yaml by hand")
    return sorted({_parse(e)[0] for e in ours}), foreign


# ── revocation records: every process, and the rule-key generation ───────────────────────────────

def revocations_path(allowlist_path: Optional[Path]) -> Optional[Path]:
    return Path(allowlist_path).parent / REVOCATIONS_FILE if allowlist_path is not None else None


def _records(path: Optional[Path]) -> list[dict]:
    return _records_of(_read_json(path))


def _records_of(data: Any) -> list[dict]:
    recs = data.get("records") if isinstance(data, dict) else None
    return [r for r in recs if isinstance(r, dict) and isinstance(r.get("id"), str)] if isinstance(recs, list) else []


def _rec_id(value: Any) -> str:
    return value if isinstance(value, str) and 0 < len(value) <= 200 else ""


GENERATION_CHARS = 12


def latest_of(data: Any) -> dict[str, tuple[int, str]]:
    """{tool or "*": (seq, record id)}: the latest record naming each tool, from the file's ``latest`` map
    (never truncated) and its records (a version 1 file has no ``latest``; its records count in file order)."""
    out: dict[str, tuple[int, str]] = {}

    def put(name: Any, seq: Any, rec_id: Any) -> None:
        rid = _rec_id(rec_id)
        if not isinstance(name, str) or not rid or isinstance(seq, bool) or not isinstance(seq, int):
            return
        if name not in out or seq > out[name][0]:
            out[name] = (seq, rid)
    latest = data.get("latest") if isinstance(data, dict) else None
    if isinstance(latest, dict):
        for name, value in latest.items():
            if isinstance(value, list) and len(value) == 2:
                put(name, value[0], value[1])
    for i, rec in enumerate(_records_of(data)):
        seq = rec.get("seq") if isinstance(rec.get("seq"), int) else i + 1
        names = rec.get("tools") if isinstance(rec.get("tools"), list) else [ALL]
        for name in names:
            put(name, seq, rec.get("id"))
    return out


def append_record(path: Optional[Path], tools: Optional[set[str]]) -> str:
    """Append one record (and update the ``latest`` map) under the file lock; returns its id."""
    if path is None:
        return ""
    rec_id = uuid.uuid4().hex
    names = sorted(tools) if tools is not None else [ALL]
    with file_lock(path):
        data = _read_json(path)
        latest = latest_of(data)
        seq = max([s for s, _ in latest.values()] + [0]) + 1
        rec = {"id": rec_id, "ts": time.time(), "tools": names, "seq": seq}
        recs = (_records_of(data) + [rec])[-MAX_RECORDS:]
        for name in names:
            latest[name] = (seq, rec_id)
        _atomic_write_json(Path(path), {"version": 2, "records": recs,
                                        "latest": {k: [v[0], v[1]] for k, v in sorted(latest.items())}})
    return rec_id


def generation_from(latest: dict[str, tuple[int, str]], tool: str) -> str:
    """The rule-key generation for ``tool``: a hex digest of the id of the latest record naming it or ``*``;
    "" when no record does. Any record id counts, a forged one included: a record can only take grants away."""
    import hashlib
    found = [v for v in (latest.get(tool), latest.get(ALL)) if v is not None]
    if not found:
        return ""
    return hashlib.sha256(max(found)[1].encode("utf-8")).hexdigest()[:GENERATION_CHARS]


class RevocationWatcher:
    """Reads the revocation records in this process. ``baseline()`` at load marks the records already present
    as applied: a fresh process holds no cached grant, and its file-backed grants already reflect them.
    ``apply()`` runs before each gate decision: each new record drops this process's cached grants for its
    tools (``drop_added``). ``generation(tool)`` gives the rule-key generation the gate asks under, which
    never goes back: a record file that is deleted, replaced by an older copy or unreadable keeps the newest
    generation this process has seen, and an unreadable file with nothing seen gives a generation of this
    process alone, so no older grant matches. Never raises."""

    def __init__(self, path: Optional[Path], drop_added=None):
        self.path = path
        self.drop_added = drop_added
        self.applied: set[str] = set()
        self.latest: dict[str, tuple[int, str]] = {}
        self.unreadable = False
        self._own = uuid.uuid4().hex[:GENERATION_CHARS]
        self._stamp: Any = None
        self._lock = threading.Lock()

    def _file_stamp(self):
        try:
            st = os.stat(self.path)
            return st.st_mtime_ns, st.st_size
        except Exception:  # noqa: BLE001
            return None

    def _read(self) -> Any:
        """The parsed file; None when missing; _UNREADABLE when present and not readable as a record file."""
        if self.path is None or not os.path.lexists(self.path):
            return None
        data = _read_json(self.path)
        return data if isinstance(data, dict) else _UNREADABLE

    def _merge(self, data: Any) -> None:
        self.unreadable = data is _UNREADABLE
        if not isinstance(data, dict):
            return
        top = max([s for s, _ in self.latest.values()] + [0])
        for name, (seq, rid) in latest_of(data).items():
            mine = self.latest.get(name)
            if mine is None or (seq > mine[0] and rid != mine[1]):
                self.latest[name] = (seq, rid)
            elif rid != mine[1] and seq <= mine[0]:
                # A replaced file restarted its sequence: a record this process has not seen is still newer.
                if rid not in self.applied:
                    top += 1
                    self.latest[name] = (max(top, mine[0] + 1), rid)

    def baseline(self) -> None:
        try:
            with self._lock:
                self._stamp = self._file_stamp()
                data = self._read()
                self._merge(data)
                self.applied |= {r["id"] for r in _records_of(data)}
        except Exception:  # noqa: BLE001
            pass

    def mark(self, rec_id: str) -> None:
        with self._lock:
            if rec_id:
                self.applied.add(rec_id)

    def refresh(self) -> list[dict]:
        """Re-read the file when it changed; returns the records not seen before (already marked)."""
        stamp = self._file_stamp()
        with self._lock:
            if stamp == self._stamp:
                return []
            self._stamp = stamp
            data = self._read()
            self._merge(data)
            fresh = [r for r in _records_of(data) if r["id"] not in self.applied]
            self.applied |= {r["id"] for r in fresh}
        return fresh

    def apply(self) -> None:
        try:
            fresh = self.refresh()
            for rec in fresh:
                names = rec.get("tools") if isinstance(rec.get("tools"), list) else [ALL]
                tools = None if ALL in names else {n for n in names if isinstance(n, str)}
                if self.drop_added is not None:
                    with contextlib.suppress(Exception):
                        self.drop_added(tools)
        except Exception:  # noqa: BLE001
            pass

    def generation(self, tool: str) -> str:
        try:
            self.apply()
            with self._lock:
                gen = generation_from(self.latest, tool)
                if not gen and self.unreadable:
                    return self._own
                return gen
        except Exception:  # noqa: BLE001
            return self._own


_UNREADABLE = object()


def rule_key(watcher: Optional[RevocationWatcher], tool: str) -> str:
    """The rule key the gate asks Hermes under for ``tool`` (gate_tools.rule_key_for with the generation)."""
    from .gate_tools import rule_key_for
    return rule_key_for(tool, watcher.generation(tool) if watcher is not None else "")


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


def left_alone_text(foreign: list) -> str:
    return (f" Entries in command_allowlist that confidential mode did not write were left alone: "
            f"{', '.join(foreign)}." if foreign else "")
_GATEWAY = "A running gateway applies the revoke on its next tool call"
_SESSION_NOT_ENDED = ("the running gateway applies the revoke on its next tool call; a grant Hermes itself holds "
                      "for this session ends when the session ends or Hermes restarts")
_ROTATED = ("A session or always answer Hermes holds for {what} no longer applies: confidential mode now asks under "
            "a new approval key.")


def _drop_lock_grants(rt: Any, tools: Optional[set[str]]) -> list[str]:
    grants = getattr(rt, "lock_grants", None)
    if grants is None:
        return []
    try:
        return grants.drop(tools)
    except Exception:  # noqa: BLE001
        return []


_GRANT_TRACE_KINDS = ("grant_revoked", "tool_asked", "tool_allowed")


def granted_since_last_revoke(ledger: Any, tools: Optional[set[str]]) -> Optional[set[str]]:
    """The tools (of ``tools``, or any tool when None) that may hold a grant: a ``tool_asked`` or
    ``tool_allowed`` ledger row after the latest revoke that moved their rule key (Amendment 14). Every grant
    starts with an ask of the plugin's own prompt, and the gate refuses the call when that ask's
    ``tool_asked`` row cannot be written (the hook and the middleware both let a failed append become a
    refusal), so an ask stands in for an answer row that was lost. An empty set means confidential mode
    asked nothing and granted nothing since the last revoke. None when the ledger cannot be read (the
    caller then revokes as before)."""
    cut: dict[str, int] = {}
    touched: dict[str, int] = {}
    try:
        read = getattr(ledger, "tool_rows", None)
        last = 0
        while True:
            rows = read(_GRANT_TRACE_KINDS, last) if callable(read) else ledger.tail(last)
            for ev in rows:
                purpose = str(getattr(ev, "purpose", "") or "")
                if not purpose.startswith("tool:"):
                    continue
                name = purpose[len("tool:"):]
                if ev.kind == "grant_revoked" and (getattr(ev, "detail", None) or {}).get("rule_key_rotated"):
                    cut[name] = ev.id
                elif ev.kind in ("tool_asked", "tool_allowed"):
                    touched[name] = ev.id
            if len(rows) < 1000:
                break
            last = rows[-1].id
    except Exception:  # noqa: BLE001
        return None
    every = cut.get(ALL, 0)
    return {t for t, row in touched.items() if (tools is None or t in tools) and row > max(cut.get(t, 0), every)}


def hermes_holds_grant(rt: Any, tools: Optional[set[str]]) -> bool:
    """Whether Hermes holds, in this process, a session or always approval under the rule key the gate asks
    under now for one of ``tools`` (any tool when None), in any approval session. Read-only; True when
    Hermes' tables cannot be read (the caller then revokes as before)."""
    try:
        from .commands import hermes_approval_keys
        from .gate_tools import parse_pattern_key
        watcher = getattr(rt, "revocations", None)
        permanent, session = hermes_approval_keys(None)
        for key in permanent | session:
            if not isinstance(key, str) or not key.startswith("plugin_rule:"):
                continue
            parsed = parse_pattern_key(key)
            if parsed is None or (tools is not None and parsed[0] not in tools):
                continue
            if key == f"plugin_rule:{rule_key(watcher, parsed[0])}":
                return True
        return False
    except Exception:  # noqa: BLE001
        return True


def revoke(rt: Any, tool: Optional[str], *, revoke_all: bool = False, session_id: str = "",
           surface: str = "") -> tuple[str, str]:
    """(status, message); status is REVOKED, NOTHING or FAILED. Removes the plugin's grants for ``tool``
    (or all of them) from allowlist.yaml, command_allowlist and this process's lock grants, and appends a
    revocation record in every case, which moves the gate to a new rule key (so Hermes' session approvals for
    the old key stop applying, without the plugin touching them) and tells other processes. Writes a
    ``grant_revoked`` ledger row. FAILED when any step did not take effect; the message then starts with the
    failure."""
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
    from_lock_grants = _drop_lock_grants(rt, tools)
    foreign: list[str] = []
    config_error = ""
    try:
        from_hermes, foreign = remove_command_allowlist_grants(tools)
    except RevokeError as exc:
        from_hermes = []
        config_error = str(exc)
    except Exception as exc:  # noqa: BLE001
        from_hermes = []
        config_error = (f"command_allowlist in config.yaml could not be read or written ({type(exc).__name__}); "
                        "an entry for the tool may still be there")
    if not (from_allowlist or from_cache or from_lock_grants or from_hermes or errors or config_error):
        # Amendment 14: nothing was granted since the last revoke, so nothing is recorded and no key moves.
        granted = granted_since_last_revoke(getattr(rt, "ledger", None), tools)
        if granted == set() and not hermes_holds_grant(rt, tools):
            whom = f" for {tool}: confidential mode has not granted {tool}" if tools else \
                ": confidential mode has granted no tool"
            return NOTHING, (f"Nothing to revoke{whom} since the last revoke (no allow, no prompt asked, no "
                             "allowlist or command_allowlist entry). Nothing was recorded."
                             + left_alone_text(foreign))
    rotated = False
    try:
        rec_id = append_record(revocations_path(getattr(rt, "allowlist_path", None)), tools)
        watcher = getattr(rt, "revocations", None)
        if watcher is not None and rec_id:
            watcher.mark(rec_id)
            watcher.refresh()
        rotated = bool(rec_id)
        if not rec_id:
            errors.append("the plugin's data directory is unknown, so the revoke was not recorded; "
                          + _SESSION_NOT_ENDED)
    except LockBusy as exc:
        errors.append(f"the revocation record was not written: {exc}; {_SESSION_NOT_ENDED}")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"the revocation record could not be written ({type(exc).__name__}); {_SESSION_NOT_ENDED}")
    if config_error:
        # With the record written, the entry no longer matches the key the plugin asks under; it is still the
        # user's line to delete, so the revoke reports it.
        errors.append(config_error + (" (the entry no longer grants anything: confidential mode now asks under a "
                                       "new approval key)" if rotated else ""))
    removed = sorted(set(from_allowlist) | set(from_cache) | set(from_hermes) | set(from_lock_grants))
    status = FAILED if errors else (REVOKED if removed else NOTHING)
    row = {"ts": time.time(), "session_id": session_id or "", "kind": "grant_revoked",
           "purpose": f"tool:{tool if not revoke_all else ALL}", "provider": "", "host": "", "model": "",
           "bytes": None, "tier": None, "verdict": None,
           "decision": ("revoke_all" if revoke_all else "revoke") + ("_failed" if status == FAILED else ""),
           "surface": surface or None,
           "detail": {"tool": tool if not revoke_all else ALL, "lock_id": lock_id, "surface": surface or "unknown",
                      "removed": {"allowlist": sorted(set(from_allowlist) | set(from_cache)),
                                  "command_allowlist": from_hermes, "lock_grants": from_lock_grants},
                      "errors": errors, "rule_key_rotated": rotated}}
    note = ""
    try:
        rt.ledger.append(row)
    except Exception as exc:  # noqa: BLE001
        note = f" The grant_revoked ledger row could not be written ({type(exc).__name__})."
    left_alone = left_alone_text(foreign)
    places = []
    if from_allowlist or from_cache:
        places.append("this lock's allowlist (allowlist.yaml)")
    if from_lock_grants:
        places.append("this lock's grants in this process")
    if from_hermes:
        places.append("Hermes' command_allowlist")
    done = f" Removed {', '.join(removed)} from {' and '.join(places)}." if removed else ""
    rotated_text = (" " + _ROTATED.format(what=what)) if rotated else ""
    if status == FAILED:
        still = "" if rotated else " Until this is fixed, the tool may still run without asking."
        return FAILED, (f"Revoke failed for {what}: {'; '.join(errors)}." + done + rotated_text + still
                        + left_alone + note)
    if status == NOTHING:
        return NOTHING, (f"Nothing to revoke for {what} in this process: no grant written by confidential mode "
                         "was found in allowlist.yaml or command_allowlist. The revoke was recorded." + rotated_text
                         + " " + _GATEWAY + "." + left_alone + note)
    nxt = "The next call of each asks again" if (revoke_all or len(removed) > 1) else f"The next {tool} call asks again"
    return REVOKED, (f"Revoked {', '.join(removed)}: removed from {' and '.join(places)}. {nxt} while locked."
                     + rotated_text + " " + _GATEWAY + "." + left_alone + note)

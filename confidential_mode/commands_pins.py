"""``/confidential pins`` and ``pins retire``: the pin lines, tool grants and approval history.

``pins_text`` lists the pins in force, any pending pin, Hermes' remembered tool grants under the plugin's
rule keys (``remembered_grants``) and the approval history; ``retire_text`` retires an approved entry by
fingerprint; ``pending_pin_note`` is the line status and setup print while a pin waits.
"""
from __future__ import annotations

import time
from typing import Any

from .commands_common import _provider_module, _short


def _pin_lines(rt: Any) -> list[str]:
    lines = []
    pins = getattr(rt, "pins", None)
    if pins is None:
        return ["Pins: unavailable (pin store not loaded)"]
    try:
        records, pending = pins.load()
        every = pins.approved_entries() if callable(getattr(pins, "approved_entries", None)) else list(records.values())
        batches = pins.pending_all() if callable(getattr(pins, "pending_all", None)) else [p for p in [pending] if p]
    except Exception as exc:  # noqa: BLE001
        return [f"Pins: unreadable ({type(exc).__name__}: {exc}); attested sends are refused until fixed"]
    from .verify.near_checks import render_if_needed, render_vendor
    if not every:
        lines.append("Pinned: none")
    for rec in every:
        role = getattr(rec, "cvm_role", None)
        role_text = f" {render_if_needed(role)}" if role not in (None, "router") else ""
        lines.append(f"Pinned: {rec.vendor} {render_if_needed(rec.router_repo)}{role_text} "
                     f"code {_short(rec.code_fingerprint)} "
                     f"enclave {_short(rec.enclave_fingerprint)} "
                     f"release {render_if_needed(rec.release_tag or '(untagged)')} "
                     f"(approved {rec.approved_at} via {rec.approved_via}"
                     + (f", reviewed by {render_if_needed(rec.reviewed_by)}"
                        if getattr(rec, "reviewed_by", None) else "")
                     + f"; previous {_short(rec.previous)})")
    if not batches:
        lines.append("Pending pin: none")
    for pend in batches:
        ents = list(getattr(pend, "entries", ()) or ())
        lines.append(f"Pending pin: {pend.vendor} code {_short(pend.code_fingerprint)} enclave "
                     f"{_short(pend.enclave_fingerprint)} release {render_if_needed(pend.release_tag or '(untagged)')} "
                     f"staged {pend.staged_at}; {len(ents) or 1} {'entry' if len(ents) <= 1 else 'entries'}; "
                     "run /confidential pins approve (hermes confidential pins review builds a review bundle)")
        for ent in ents:
            if getattr(ent, "cvm_role", None) not in (None, "router"):
                lines.append(f"  entry {render_if_needed(ent.cvm_role)} code {_short(ent.code_fingerprint, 16)} "
                             f"enclave {_short(ent.enclave_fingerprint, 16)} "
                             f"pins {', '.join(ent.pinned) or '(whole result)'}")
        if pend.components:
            lines.append("Pending pin components (every line; \"reported\" lines are shown for review, not pinned):")
            lines.extend(f"  {render_vendor(c)}" for c in pend.components)
    return lines


def hermes_approval_keys(session_key: str | None = None) -> tuple[set, set]:
    """(Hermes' permanent approval keys, its session approval keys for ``session_key``, or for every session
    when None). Read-only, under Hermes' own lock (hermes_compat.approval_keys); raises when Hermes' tables
    cannot be read."""
    from . import hermes_compat
    return hermes_compat.approval_keys(session_key)


def remembered_grants(session_key: str = "", current_key=None) -> list[str]:
    """Hermes-held session/always grants under OUR rule keys (Amendment 2), as 'tool (scope)'. Read-only.
    ``current_key(tool)``: the rule key the gate asks under now (Amendment 13); a grant under an older key
    matches nothing the plugin asks for and is not listed."""
    out: list[str] = []
    try:
        from .gate_tools import parse_pattern_key, rule_key_for
        current = current_key or rule_key_for
        permanent, session = hermes_approval_keys(session_key)    # "" names no session: none of its keys
        for keys, scope in ((permanent, "always"), (session, "session")):
            for key in sorted(k for k in keys if isinstance(k, str)):
                parsed = parse_pattern_key(key)
                if parsed is not None and key == f"plugin_rule:{current(parsed[0])}":
                    out.append(f"{parsed[0]} ({scope})")
    except Exception:  # noqa: BLE001
        pass
    return out


def _grant_lines(rt: Any, session_key: str) -> list[str]:
    added: list[str] = []
    try:
        al = rt._allowlist
        if al is not None:
            added = sorted(al.added)
        elif rt.allowlist_path is not None:
            from .gate_tools import _read_added
            added = sorted(_read_added(rt.allowlist_path))
    except Exception:  # noqa: BLE001
        pass
    remembered = remembered_grants(session_key, getattr(rt, "rule_key", None))
    granted: list[str] = []
    try:
        from .gate_tools import lock_id_for
        if getattr(rt, "lock_grants", None) is not None:
            granted = rt.lock_grants.names(lock_id_for(rt.state))
    except Exception:  # noqa: BLE001
        pass
    return [f"Tool grants (allowlist): {', '.join(added) if added else 'none'}",
            f"Tool grants (answered once, this lock, this process, each for its own conversation): "
            f"{', '.join(granted) if granted else 'none'}",
            f"Tool grants (remembered by Hermes): {', '.join(remembered) if remembered else 'none'}"]


def pending_pin_note(rt: Any) -> str:
    """'' unless a pin update is waiting for approval. Said by the lock reply and by status, because a lock can
    succeed on an approved instance while NEAR runs another instance of the same model that is pending: a
    send NEAR routes to the pending instance is then refused."""
    pins: Any = getattr(rt, "pins", None)
    try:
        batches = pins.pending_all() if callable(getattr(pins, "pending_all", None)) else \
            [p for p in [pins.pending()] if p] if pins is not None else []
    except Exception:  # noqa: BLE001
        return ""
    if not batches:
        return ""
    vendors = ", ".join(sorted({str(getattr(b, "vendor", "?")) for b in batches}))
    entries = sum(len(list(getattr(b, "entries", ()) or ())) or 1 for b in batches)
    return (f"A pin update for {vendors} is pending ({entries} {'entry' if entries == 1 else 'entries'}). This "
            "lock uses the approved builds; a send that reaches a build in the pending update is refused until "
            "you approve it: hermes confidential pins review, then hermes confidential pins approve.")


def pins_text(rt: Any, *, session_key: str = "") -> str:
    lines = _pin_lines(rt)
    history: list = []
    try:
        last = 0
        while True:
            rows = rt.ledger.tail(last)
            history.extend(ev for ev in rows if ev.kind in ("pin_staged", "pin_applied", "pin_denied", "pin_retired"))
            if len(rows) < 1000:
                break
            last = rows[-1].id
    except Exception:  # noqa: BLE001
        pass
    lines.append("Approval history:" + ("" if history else " none"))
    for ev in history[-20:]:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.ts or 0))
        lines.append(f"  {when}  {ev.kind:<11} {ev.decision or '':<10} via {ev.surface or '?'}"
                     f"  code {_short((ev.detail or {}).get('code_fingerprint'))}")
    lines.extend(_grant_lines(rt, session_key))
    return "\n".join(lines)


def _approve_flags(args: list) -> dict:
    """--reviewed-by <name> and --note <text> (each at most once); anything else is a ValueError."""
    out: dict = {}
    it = iter(args)
    for a in it:
        name = {"--reviewed-by": "reviewed_by", "--note": "review_note"}.get(a)
        if name is None or name in out:
            raise ValueError(f"unexpected {a!r}")
        try:
            out[name] = next(it)
        except StopIteration:
            raise ValueError(f"{a} needs a value") from None
    return out


def retire_text(rt: Any, fingerprint: str, *, session_id: str = "", surface: str = "unknown",
                identity: str | None = None) -> str:
    """`pins retire <fingerprint>`: remove one approved entry, write a pin_retired row, and clear the
    in-process consent cache so the entry's earlier pin_applied row no longer counts."""
    from .pins import PinStoreError
    if rt.pins is None:
        return "The pin store is not available; see /confidential status."
    try:
        e = rt.pins.retire(fingerprint, identity) if identity else rt.pins.retire(fingerprint)
    except PinStoreError as exc:
        return f"Nothing retired: {exc}"
    row = {"ts": time.time(), "session_id": session_id or "", "kind": "pin_retired", "purpose": "pin",
           "provider": e.vendor, "host": "", "model": "", "bytes": None, "tier": None, "verdict": None,
           "decision": "retire", "surface": surface or None,
           "detail": {"vendor": e.vendor, "router_repo": e.router_repo, "cvm_role": e.cvm_role,
                      "code_fingerprint": e.code_fingerprint, "enclave_fingerprint": e.enclave_fingerprint,
                      "retired_via": surface or "unknown"}}
    note = ""
    try:
        rt.ledger.append(row)
    except Exception as exc:  # noqa: BLE001
        note = (f" The pin_retired ledger row could not be written ({type(exc).__name__}); a hand-made copy of "
                "this entry would still count as consented in another process.")
    else:
        from .ledger import would_truncate
        if would_truncate(row):
            # FI-6: the row was written with the too-large marker. It still withdraws consent for entries with
            # these fingerprints, but not by identity, so the warning stays.
            note = (" The pin_retired ledger row could not be written in full (its detail was too large); a "
                    "hand-made copy of this entry would still count as consented in another process.")
    try:
        _provider_module(rt).clear_consent_cache()
    except Exception:  # noqa: BLE001
        pass
    from .verify.near_checks import render_vendor
    return (f"Retired {e.vendor} {render_vendor(e.router_repo)} {render_vendor(e.cvm_role)} entry code "
            f"{_short(e.code_fingerprint, 16)} enclave {_short(e.enclave_fingerprint, 16)}. A verification that "
            "reports it again asks for approval again." + note)

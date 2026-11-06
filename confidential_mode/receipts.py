"""Session receipts over the ledger (W6): ``render(ledger, session_id, *, pins, fmt)`` and ``verify_chain``.

A receipt is a rendering of ledger rows. It never contains prompt or response text: the ledger stores
none, and every row is scanned again here for the ledger's content-shaped keys
(``ledger.FORBIDDEN_DETAIL_KEYS``); such keys are dropped from the row and their paths listed under
``redacted``. A final scan of the JSON document raises ``ReceiptError`` if one survived.

Which rows a session's receipt covers:
  * every row whose ``session_id`` is the session;
  * profile-wide rows (seal, unseal, verification and pin events, preflight failures), whatever their
    session_id, from the end of the sealed period before the session's first row (the last unseal
    before it) up to the session's last row, plus the unseal that closes the period. Seal is profile-wide in the MVP and verification has no session context, so these rows
    are usually written with another session id or none.

The text form lists, in order: header, trust roots, verification events, sends, refusals, asks and
answers, breaches, compactions, and CLOSING_PARAGRAPH, a module constant that is never templated.
Every timestamp is the local clock and is labelled so.

The JSON form carries the same, the raw ``evidence`` blobs of verify rows, and a SHA-256 hash chain over
the rows: ``hash_i = sha256(hash_{i-1} + canonical_json(row_i))`` with ``hash_0 = CHAIN_GENESIS``, where
canonical_json is ``json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`` of the row
without its ``hash`` field. The head is in the header. ``verify_chain`` recomputes it.

What the chain shows: the receipt has not been edited since it was rendered, relative to its own head.
It does not show that the ledger itself was not edited before rendering (the ledger is a local SQLite
file the user controls); a head published or sent elsewhere at render time is what makes later edits
detectable.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .ledger import FORBIDDEN_DETAIL_KEYS

RECEIPT_FORMAT = "confidential-mode-receipt"
RECEIPT_VERSION = 1
CHAIN_GENESIS = "0" * 64
CHAIN_ALGORITHM = "sha256(prev_hash + canonical_row_json)"
CLOCK_LABEL = "(local clock)"

# Kinds that describe the profile, not one session: included in every session receipt they overlap.
PROFILE_KINDS = frozenset({"seal", "unseal", "verify_ok", "verify_fail", "pin_staged", "pin_applied",
                           "pin_denied", "preflight_fail"})
VERIFICATION_KINDS = ("verify_ok", "verify_fail", "pin_staged", "pin_applied", "pin_denied")
REFUSAL_KINDS = ("send_refused", "tool_refused", "preflight_fail")
ANSWER_KINDS = ("tool_allowed", "tool_refused")

_ROW_FIELDS = ("id", "ts", "session_id", "kind", "purpose", "provider", "host", "model", "bytes", "tier",
               "verdict", "decision", "surface", "detail")

CLOSING_PARAGRAPH = (
    "What this receipt proves and what it only records. EVIDENCE: when the receipt says an enclave build "
    "was verified, the plugin checked that build's hardware-signed attestation against the vendor's "
    "published code measurement and bound the session key to it; where the raw verification evidence is "
    "attached (JSON form), anyone can replay that check offline. RECORD ONLY, not proven by anything in "
    "this receipt: that this session's requests actually went to that enclave; that request bodies were "
    "encrypted to that key; that the verified build was the vendor's latest release at the time; whether "
    "the build or its key was revoked after the evidence was captured; what shell, terminal and "
    "code-execution tools sent off the machine (they run locally and can reach the network); which model "
    "backends sit behind the vendor's router; any other access the vendor's operators have to the "
    "machines involved; Hermes' auxiliary model calls (titles, compression, memory prefetch, vision, smart "
    "approvals, MCP sampling, background review), which a plugin cannot stop and which appear here only "
    "after the fact as observed sends or breaches; and anything that happened while Hermes ran in "
    "safe-worker mode, where sealed mode does not apply and nothing is recorded. Timestamps come from this machine's clock and are not attested. The hash chain "
    "shows only that this receipt was not edited after it was rendered; it does not show that the local "
    "ledger was complete or unedited before that."
)


class ReceiptError(ValueError):
    """The receipt could not be rendered without exposing content-shaped data."""


# ── row collection ──────────────────────────────────────────────────────────────────────────────

def _all_rows(ledger, since_id: int = 0, page: int = 1000) -> list:
    out, last = [], since_id
    while True:
        batch = ledger.tail(last, limit=page)
        if not batch:
            return out
        out.extend(batch)
        last = batch[-1].id
        if len(batch) < page:
            return out


def collect_rows(ledger, session_id: str, *, include_profile_rows: bool = True) -> list:
    """The ledger rows a receipt for ``session_id`` covers, in id order (see module docstring)."""
    own = ledger.session(session_id)
    if not include_profile_rows or not own:
        return list(own)
    rows = _all_rows(ledger)
    first, last = own[0].id, own[-1].id
    # Profile-wide rows count from the end of the previous sealed period: the seal in force, and the
    # preflight failures and verifications that led up to it, are part of this session's story.
    unseal_before = [r for r in rows if r.kind == "unseal" and r.id < first]
    start = unseal_before[-1].id + 1 if unseal_before else 0
    picked = [r for r in rows if start <= r.id <= last
              and (r.session_id == session_id or r.kind in PROFILE_KINDS)]
    # The unseal that closes the period, if it came after the session's last row.
    after = [r for r in rows if r.id > last and r.kind in ("seal", "unseal")]
    if after and after[0].kind == "unseal":
        picked.append(after[0])
    return picked


# ── redaction ───────────────────────────────────────────────────────────────────────────────────

def _redact(value: Any, path: str, dropped: list[str]) -> Any:
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            key = str(k)
            if key.lower() in FORBIDDEN_DETAIL_KEYS:
                dropped.append(f"{path}.{key}")
                continue
            out[key] = _redact(v, f"{path}.{key}", dropped)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact(v, f"{path}[{i}]", dropped) for i, v in enumerate(value)]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def forbidden_keys_in(value: Any, path: str = "$") -> list[str]:
    """Paths of every mapping key in ``value`` that is a ledger-forbidden (content-shaped) key."""
    found: list[str] = []
    if isinstance(value, Mapping):
        for k, v in value.items():
            if str(k).lower() in FORBIDDEN_DETAIL_KEYS:
                found.append(f"{path}.{k}")
            found.extend(forbidden_keys_in(v, f"{path}.{k}"))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            found.extend(forbidden_keys_in(v, f"{path}[{i}]"))
    return found


def _row_dict(event) -> dict:
    dropped: list[str] = []
    detail = event.detail if isinstance(event.detail, Mapping) else {"unparseable": True}
    row = {f: getattr(event, f) for f in _ROW_FIELDS if f != "detail"}
    row["detail"] = _redact(detail, "detail", dropped)
    if dropped:
        row["redacted"] = dropped
    return row


# ── hash chain ──────────────────────────────────────────────────────────────────────────────────

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def chain_hash(prev_hash: str, row: Mapping) -> str:
    body = {k: v for k, v in row.items() if k != "hash"}
    return hashlib.sha256((prev_hash + canonical_json(body)).encode("utf-8")).hexdigest()


def _chain(rows: list[dict]) -> str:
    prev = CHAIN_GENESIS
    for row in rows:
        prev = chain_hash(prev, row)
        row["hash"] = prev
    return prev


# ── trust roots ─────────────────────────────────────────────────────────────────────────────────

def _pin_records(pins: Any) -> list:
    if pins is None:
        return []
    load = getattr(pins, "load", None)
    if callable(load):
        records = load()[0]
    else:
        records = pins
    if isinstance(records, Mapping):
        records = records.values()
    return sorted(records, key=lambda p: (str(_get(p, "vendor")), str(_get(p, "router_repo"))))


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


_PIN_FIELDS = ("vendor", "router_repo", "code_fingerprint", "enclave_fingerprint", "release_tag", "models_seen",
               "approved_by", "approved_at", "approved_via", "approval_rule_key", "previous",
               "previous_enclave_fingerprint")


def _trust_roots(tier: str | None, rows: list[dict], pins: Any, local_hosts: Iterable[str]) -> dict:
    roots: dict[str, Any] = {"tier": tier}
    if tier in (None, "local-only"):
        observed = sorted({r["host"] for r in rows
                           if r["kind"] == "send_observed" and r.get("tier") == "local-only" and r["host"]})
        roots["local"] = {
            "rule": ("loopback, RFC1918, 100.64.0.0/10, fe80::/10, fc00::/7, localhost, plus "
                     "confidential.local.extra_hosts"),
            "extra_hosts": sorted({str(h) for h in local_hosts}),
            "hosts_used": observed,
        }
    if tier in (None, "attested") or pins is not None:
        roots["pins"] = [{f: (list(v) if isinstance(v := _get(p, f), tuple) else v) for f in _PIN_FIELDS}
                         for p in _pin_records(pins)]
        roots["pins_note"] = "pins in force when this receipt was rendered; pin_applied rows show when each was set"
    return roots


# ── sections ────────────────────────────────────────────────────────────────────────────────────

def _sections(rows: list[dict]) -> dict:
    by_kind = lambda kinds: [r["id"] for r in rows if r["kind"] in kinds]  # noqa: E731
    asks = []
    answered: set[int] = set()
    for i, r in enumerate(rows):
        if r["kind"] != "tool_asked":
            continue
        answers = []
        for later in rows[i + 1:]:
            if later["purpose"] != r["purpose"]:
                continue
            if later["kind"] == "tool_asked":
                break
            if later["kind"] in ANSWER_KINDS:
                answers.append(later["id"])
                answered.add(later["id"])
        asks.append({"ask": r["id"], "answers": answers})
    unprompted = [r["id"] for r in rows if r["kind"] == "tool_allowed" and r["id"] not in answered]
    return {
        "seal": by_kind(("seal", "unseal")),
        "verification": by_kind(VERIFICATION_KINDS),
        "sends": by_kind(("send_observed",)),
        "refusals": by_kind(REFUSAL_KINDS),
        "asks": asks,
        "allowed_without_prompt": unprompted,
        "breaches": by_kind(("breach",)),
        "compactions": by_kind(("compaction",)),
    }


def _seal_info(rows: list[dict]) -> dict:
    """Every seal period the rows show (seal .. next unseal), the last one's tier as the sealed tier."""
    periods: list[dict] = []
    for r in rows:
        if r["kind"] == "seal":
            if periods and periods[-1]["until"] is None:
                periods[-1]["until"] = r["ts"]          # resealed without an unseal row
            periods.append({"tier": r.get("tier") or r["detail"].get("tier"), "since": r["ts"], "until": None,
                            "seal_row": r["id"]})
        elif r["kind"] == "unseal" and periods and periods[-1]["until"] is None:
            periods[-1]["until"] = r["ts"]
    if periods:
        last = periods[-1]
        return {"tier": last["tier"], "since": last["since"], "until": last["until"], "source": "seal row",
                "periods": periods}
    tiers = [r.get("tier") for r in rows if r.get("tier")]
    tier = tiers[0] if tiers else None
    return {"tier": tier, "since": None, "until": None, "source": "send rows" if tier else "none", "periods": []}


def build_receipt(ledger, session_id: str, *, pins: Any = None, local_hosts: Iterable[str] = (),
                  include_profile_rows: bool = True) -> dict:
    """The JSON receipt as a dict (``render(fmt="json")`` serialises this)."""
    rows = [_row_dict(e) for e in collect_rows(ledger, session_id, include_profile_rows=include_profile_rows)]
    head = _chain(rows)
    seal = _seal_info(rows)
    trust = _trust_roots(seal["tier"], rows, pins, local_hosts)
    sends = [r for r in rows if r["kind"] in ("send_observed", "send_refused")]
    providers = sorted({(r["provider"], r["model"]) for r in sends if r["provider"] or r["model"]})
    enclave_hosts = [{"row_id": r["id"], "host": r["host"]} for r in rows
                     if r["kind"] == "send_observed" and r.get("tier") == "attested" and r["host"]]
    evidence = [{"row_id": r["id"], "evidence": r["detail"]["evidence"]} for r in rows
                if r["kind"] in ("verify_ok", "verify_fail") and isinstance(r["detail"].get("evidence"), Mapping)]
    doc = {
        "format": RECEIPT_FORMAT,
        "version": RECEIPT_VERSION,
        "header": {
            "session_id": session_id,
            "sealed_tier": seal["tier"],
            "sealed_period": {"since": seal["since"], "until": seal["until"], "source": seal["source"]},
            "sealed_periods": seal["periods"],
            "clock": "local (timestamps are this machine's clock, not attested)",
            "providers": [{"provider": p, "model": m} for p, m in providers],
            "enclave_hosts": enclave_hosts,
            "row_count": len(rows),
            "chain_algorithm": CHAIN_ALGORITHM,
            "chain_genesis": CHAIN_GENESIS,
            "chain_head": head,
            "trust_roots_sha256": hashlib.sha256(canonical_json(trust).encode("utf-8")).hexdigest(),
        },
        "trust_roots": trust,
        "sections": _sections(rows),
        "rows": rows,
        "evidence": evidence,
        "closing": CLOSING_PARAGRAPH,
    }
    leaks = forbidden_keys_in(doc)
    if leaks:  # unreachable after _redact; kept as the last line of defence
        raise ReceiptError(f"content-shaped keys in receipt: {', '.join(leaks[:5])}")
    return doc


def verify_chain(receipt_json: str | Mapping) -> bool:
    """True iff the rows' hash chain recomputes, the header head matches it, every evidence blob equals
    its row's, the trust roots match their digest, and the closing paragraph is the constant."""
    try:
        doc = json.loads(receipt_json) if isinstance(receipt_json, (str, bytes)) else receipt_json
        if not isinstance(doc, Mapping) or doc.get("format") != RECEIPT_FORMAT:
            return False
        header, rows = doc["header"], doc["rows"]
        prev = header.get("chain_genesis")
        if prev != CHAIN_GENESIS:
            return False
        by_id = {}
        for row in rows:
            expected = chain_hash(prev, row)
            if row.get("hash") != expected:
                return False
            prev = expected
            by_id[row.get("id")] = row
        if header.get("chain_head") != prev or header.get("row_count") != len(rows):
            return False
        for item in doc.get("evidence", []):
            row = by_id.get(item.get("row_id"))
            if row is None or canonical_json(row["detail"].get("evidence")) != canonical_json(item.get("evidence")):
                return False
        trust_digest = hashlib.sha256(canonical_json(doc["trust_roots"]).encode("utf-8")).hexdigest()
        if header.get("trust_roots_sha256") != trust_digest:
            return False
        return doc.get("closing") == CLOSING_PARAGRAPH
    except Exception:
        return False


# ── text ────────────────────────────────────────────────────────────────────────────────────────

def ts_text(ts: Any) -> str:
    if ts is None:
        return "(unknown) " + CLOCK_LABEL
    try:
        dt = datetime.fromtimestamp(float(ts), timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return "(invalid) " + CLOCK_LABEL
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z {CLOCK_LABEL}"


def _p(value: Any) -> str:
    """Printable, single-line: a value in a row can never forge a receipt line."""
    s = "" if value is None else str(value)
    return "".join(ch if ch.isprintable() else "?" for ch in s)[:200]


def _reason(row: Mapping) -> str:
    d = row["detail"]
    # An in-tier verdict's reason ("local host ...") is not why the row was refused.
    reason = d.get("reason") if row.get("verdict") != "in_tier" else None
    parts = [_p(x) for x in (d.get("reason_code"), reason) if x]
    if d.get("status_code") is not None:
        parts.append(f"HTTP {_p(d['status_code'])}")
    if d.get("error_type"):
        parts.append(_p(d["error_type"]))
    if not parts and row.get("decision"):
        parts.append(_p(row["decision"]))
    return "; ".join(dict.fromkeys(parts)) or "(no reason recorded)"


def _line(row: Mapping, session_id: str, body: str) -> str:
    scope = "" if row["session_id"] == session_id else " [profile]"
    return f"  #{row['id']} {ts_text(row['ts'])}{scope}  {body}"


def _send_body(r: Mapping) -> str:
    nbytes = f"{r['bytes']} bytes" if r.get("bytes") is not None else "size unknown"
    return (f"{_p(r['purpose']) or '?'}  host={_p(r['host']) or '(none)'}  {nbytes}  "
            f"{_p(r['provider']) or '?'}/{_p(r['model']) or '?'}  {_p(r['decision']) or ''}").rstrip()


def _verify_body(r: Mapping) -> str:
    d = r["detail"]
    k = r["kind"]
    fp = lambda key: _p(d.get(key))[:16] or "?"  # noqa: E731
    if k in ("verify_ok", "verify_fail"):
        bits = [k, f"vendor={_p(d.get('vendor') or r['provider']) or '?'}",
                f"enclave={_p(d.get('enclave_host') or r['host']) or '?'}"]
        if d.get("code_fingerprint"):
            bits.append(f"code={fp('code_fingerprint')}")
        if d.get("enclave_fingerprint"):
            bits.append(f"measurement={fp('enclave_fingerprint')}")
        if d.get("release_tag"):
            bits.append(f"release={_p(d['release_tag'])}")
        if k == "verify_fail":
            bits.append(f"reason: {_p(d.get('error') or d.get('reason')) or '(none)'}")
        if isinstance(d.get("evidence"), Mapping):
            blob = canonical_json(d["evidence"]).encode("utf-8")
            bits.append(f"evidence attached ({len(blob)} bytes, sha256 {hashlib.sha256(blob).hexdigest()[:16]})")
        else:
            bits.append("no evidence attached")
        return "  ".join(bits)
    bits = [k, f"vendor={_p(d.get('vendor') or r['provider']) or '?'}"]
    if d.get("code_fingerprint"):
        bits.append(f"code={fp('code_fingerprint')}")
    if d.get("enclave_fingerprint"):
        bits.append(f"measurement={fp('enclave_fingerprint')}")
    if r.get("decision"):
        bits.append(f"decision={_p(r['decision'])}")
    if r.get("surface"):
        bits.append(f"via={_p(r['surface'])}")
    return "  ".join(bits)


def render_text(doc: Mapping) -> str:
    h = doc["header"]
    sid = h["session_id"]
    rows = {r["id"]: r for r in doc["rows"]}
    sec = doc["sections"]
    out: list[str] = []
    add = out.append

    period = h["sealed_period"]
    add(f"Confidential mode receipt for session {_p(sid)}")
    add(f"Sealed tier: {_p(h['sealed_tier']) or '(not sealed / unknown)'}  (from {period['source']})")
    if period["since"] is not None:
        for p in h["sealed_periods"]:
            until = ts_text(p["until"]) if p["until"] is not None else "still sealed at the last row"
            add(f"Sealed period: {_p(p['tier']) or '?'} from {ts_text(p['since'])} to {until}  (seal row #{p['seal_row']})")
    else:
        add("Sealed period: no seal row covers this session")
    if h["providers"]:
        add("Provider / model: " + ", ".join(f"{_p(p['provider']) or '?'} / {_p(p['model']) or '?'}"
                                             for p in h["providers"]))
    else:
        add("Provider / model: (no model requests recorded)")
    if h["enclave_hosts"]:
        add("Enclave host per request:")
        for e in h["enclave_hosts"]:
            add(f"  #{e['row_id']} {_p(e['host'])}")
    add(f"Rows: {h['row_count']}  chain head: {h['chain_head']}")
    if not doc["rows"]:
        add("No events were recorded for this session.")

    add("")
    add("Trust roots in force")
    tr = doc["trust_roots"]
    if "local" in tr:
        loc = tr["local"]
        add(f"  Local endpoint set: {loc['rule']}")
        add(f"  Extra local hosts: {', '.join(_p(x) for x in loc['extra_hosts']) or '(none)'}")
        add(f"  Local hosts used: {', '.join(_p(x) for x in loc['hosts_used']) or '(none)'}")
    if "pins" in tr:
        if not tr["pins"]:
            add("  Pins: (none)")
        for p in tr["pins"]:
            add(f"  Pin {_p(p['vendor'])} {_p(p['router_repo'])} release {_p(p['release_tag']) or '(untagged)'}")
            add(f"    code {_p(p['code_fingerprint'])}  measurement {_p(p['enclave_fingerprint'])}")
            add(f"    approved by {_p(p['approved_by'])} at {_p(p['approved_at'])} via {_p(p['approved_via'])} "
                f"(rule {_p(p['approval_rule_key'])}); replaced {_p(p['previous']) or '(nothing)'}")
        add(f"  ({tr.get('pins_note', '')})")

    def section(title: str, ids: list[int], body) -> None:
        add("")
        add(title)
        if not ids:
            add("  (none)")
        for i in ids:
            add(_line(rows[i], sid, body(rows[i])))

    section("Verification events", sec["verification"], _verify_body)
    section("Sends (purpose, host, bytes; never text)", sec["sends"], _send_body)
    section("Refusals", sec["refusals"],
            lambda r: f"{r['kind']}  {_p(r['purpose']) or '?'}  host={_p(r['host']) or '(none)'}  "
                      f"reason: {_reason(r)}")

    add("")
    add("Asks and answers")
    if not sec["asks"] and not sec["allowed_without_prompt"]:
        add("  (none)")
    for ask in sec["asks"]:
        r = rows[ask["ask"]]
        kb = r["detail"].get("kb")
        add(_line(r, sid, f"asked  {_p(r['purpose'])}" + (f"  ~{_p(kb)} KB" if kb is not None else "")))
        if not ask["answers"]:
            add("      answer: (none recorded)")
        for a in ask["answers"]:
            ar = rows[a]
            verdict = "allowed" if ar["kind"] == "tool_allowed" else "refused"
            add(f"      answer #{ar['id']} {ts_text(ar['ts'])}: {verdict} ({_p(ar['decision']) or 'no decision'})")
    for i in sec["allowed_without_prompt"]:
        r = rows[i]
        how = "remembered" if r["decision"] == "remembered" else _p(r["decision"]) or "allowed"
        add(_line(r, sid, f"allowed without a prompt  {_p(r['purpose'])}  ({how})"))

    section("Breaches", sec["breaches"],
            lambda r: f"{_p(r['purpose']) or '?'}  host={_p(r['host']) or '(none)'}  "
                      f"{r['bytes'] if r.get('bytes') is not None else '?'} bytes  reason: {_reason(r)}")
    section("Compactions", sec["compactions"],
            lambda r: f"{_p(r['purpose']) or 'compaction'}  host={_p(r['host']) or '(none)'}  "
                      f"{_p(r['provider']) or '?'}/{_p(r['model']) or '?'}")

    add("")
    add(CLOSING_PARAGRAPH)
    return "\n".join(out) + "\n"


def render(ledger, session_id: str, *, pins: Any = None, fmt: str = "text", local_hosts: Iterable[str] = (),
           include_profile_rows: bool = True) -> str:
    """Render the receipt for ``session_id``. ``pins``: a PinStore, a mapping or iterable of PinRecord,
    or None. ``fmt``: "text" or "json"."""
    if fmt not in ("text", "json"):
        raise ValueError(f"fmt must be 'text' or 'json', not {fmt!r}")
    doc = build_receipt(ledger, session_id, pins=pins, local_hosts=local_hosts,
                        include_profile_rows=include_profile_rows)
    if fmt == "json":
        return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    return render_text(doc)

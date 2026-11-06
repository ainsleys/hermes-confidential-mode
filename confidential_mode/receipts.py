"""Session receipts over the ledger (W6): ``render(ledger, session_id, *, pins, fmt)`` and ``verify_chain``.

A receipt is a rendering of ledger rows. It never contains prompt or response text: the ledger stores
none, and every row is scanned again here for the ledger's content-shaped keys
(``ledger.FORBIDDEN_DETAIL_KEYS``); such keys are dropped from the row and their paths listed under
``redacted``. A final scan of the JSON document raises ``ReceiptError`` if one survived.

Which rows a session's receipt covers:
  * every row whose ``session_id`` is the session;
  * profile-wide rows (seal, unseal, verification and pin events, preflight failures), whatever their
    session_id, from the end of the sealed period before the session's first row (the last unseal
    before it) up to the session's last row, plus the unseal that closes the period. Seal is
    profile-wide in the MVP and verification has no session context, so these rows are usually
    written with another session id or none.

The text form lists, in order: header, trust roots, verification events, sends, refusals, asks and
answers, breaches, compactions, and CLOSING_PARAGRAPH, a module constant that is never templated.
Every timestamp is the local clock and is labelled so.

The JSON form carries the same, the raw ``evidence`` blobs of verify rows, and a SHA-256 hash chain over
the rows: ``hash_i = sha256(hash_{i-1} + canonical_json(row_i))`` with ``hash_0 = CHAIN_GENESIS``, where
canonical_json is ``json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`` of the row
without its ``hash`` field. The head is in the header. ``verify_chain`` recomputes it.

What the chain is: a checksum over this document that anyone holding the file can recompute (so can
anyone editing it). It detects edits only when compared with a chain head recorded somewhere else at
render time, which is why the text form prints the head at the top with that instruction. It says
nothing about whether the ledger was complete or its rows genuine (the ledger is a local SQLite file,
writable by any code in the Hermes process).

Each attested send is matched to the latest verify_ok row before it and that row's TTL window
(``sections.send_coverage``); the TTL comes from the verify row's ``detail.ttl_seconds`` when present,
else the ``ttl_seconds`` argument, else the 300 s default, and the receipt says which.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from ._version import PLUGIN_COMMIT, PLUGIN_VERSION
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

SESSION_MARKERS = frozenset({"session_start", "session_end"})


def is_session_marker(row: Any) -> bool:
    """Session start/end markers are not seals, whatever kind they were written under (Amendment 4 F7:
    W5 moves them to kinds session_start/session_end; older builds wrote kind "seal" with that decision)."""
    kind = _get(row, "kind")
    return kind in SESSION_MARKERS or (kind == "seal" and _get(row, "decision") in SESSION_MARKERS)


def _is_seal(row: Any) -> bool:
    return _get(row, "kind") == "seal" and not is_session_marker(row)


_ROW_FIELDS = ("id", "ts", "session_id", "kind", "purpose", "provider", "host", "model", "bytes", "tier",
               "verdict", "decision", "surface", "detail")

CLOSING_PARAGRAPH = (
    "What this receipt proves and what it only records. This receipt is a self-report written by the "
    "plugin from a ledger on this machine; the only part a third party can check independently is the "
    "attached verification evidence. EVIDENCE: attached evidence bytes that replay offline "
    "(confidential_mode.verify.replay, or hermes confidential replay <receipt.json>) show that an enclave "
    "whose hardware report commits to TLS key fingerprint T and HPKE public key H ran code with measurement "
    "M, signed by repository R at release tag G, as of the capture time the file claims. T and H are the "
    "enclave's long-lived keys, not a per-session key. Each verification row says which checks its "
    "evidence replays under: the vendor SDK at a stated version, and the plugin's restated policy check, "
    "identified by the SHA-256 of confidential_mode/verify/policy_check.py, or n/a. Sends were gated by "
    "the vendor SDK only; the restated check never decided whether a request was sent. The enclave host "
    "and capture time inside the evidence are asserted by whoever captured it. A row marked \"unverified "
    "entry\" (no evidence, or an incomplete capture) shows nothing. RECORD ONLY, not proven by anything in "
    "this receipt: that the plugin itself checked that evidence during this session; that this session's "
    "requests actually went to that enclave; that request bodies were encrypted to that key; the HPKE key "
    "each send recorded and whether its response decrypted (the plugin's own observations); that the "
    "attested build was the vendor's latest release at the time; whether the build or its key was revoked "
    "after the evidence was captured; what shell, terminal and code-execution tools sent off the machine "
    "(they run locally and can reach the network); which model backends sit behind the vendor's router; "
    "any other access the vendor's operators have to the machines involved; and Hermes' auxiliary calls "
    "(title generation, compaction, memory prefetch, vision, and plugin auxiliary tasks), which can leave "
    "the sealed tier while sealed, for example after a runtime model or provider switch, and are recorded "
    "here after the fact, not prevented. The ledger is a local file and is not protected against code "
    "running in the same Hermes process: another plugin can write rows that look exactly like this "
    "plugin's own. The hash chain is a checksum over this document that anyone holding the file can "
    "recompute; it detects edits only when compared with a chain head recorded somewhere else when the "
    "receipt was rendered, and it says nothing about whether the ledger was complete or its rows genuine. "
    "Sealed mode does not apply when Hermes runs in safe-worker mode, which loads no plugins. Timestamps "
    "come from this machine's clock and are not attested."
)

SELF_REPORT_NOTE = ("This receipt is a self-report by the plugin from its local ledger. Only the attached evidence "
                    "blobs (JSON form) can be checked by a third party, by replaying them offline.")
CHAIN_HEAD_NOTE = ("Record this chain head somewhere other than this machine now; later edits to this receipt are "
                   "detectable only against a copy kept elsewhere.")
GATING_NOTE = "sends were gated by the vendor SDK only"
ASSERTED = "asserted by capturer"
POLICY_CHECK_PATH = Path(__file__).resolve().parent / "verify" / "policy_check.py"
DEFAULT_TTL_SECONDS = 300.0   # provider.DEFAULT_TTL_SECONDS; the ledger does not record the TTL in force


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
              and (r.session_id == session_id or (r.kind in PROFILE_KINDS and not is_session_marker(r)))]
    # The unseal that closes the period, if it came after the session's last row.
    after = [r for r in rows if r.id > last and (r.kind == "unseal" or _is_seal(r))]
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


_LOCAL_RULE = "loopback, RFC1918, 100.64.0.0/10, fe80::/10, fc00::/7, localhost, plus confidential.local.extra_hosts"


def _local_hosts_used(rows: Iterable[dict]) -> list[str]:
    return sorted({r["host"] for r in rows
                   if r["kind"] == "send_observed" and r.get("tier") == "local-only" and r["host"]})


def _trust_roots(seal: dict, rows: list[dict], pins: Any, local_hosts: Iterable[str]) -> dict:
    """Trust roots for every sealed period (Amendment 4 F11), plus the union at the top level."""
    tier = seal["tier"]
    periods = seal["periods"]
    roots: dict[str, Any] = {"tier": tier}
    per_period = []
    for p in periods:
        window = [r for r in rows if p["seal_row"] <= r["id"] <= p["end_row"]]
        entry: dict[str, Any] = {"seal_row": p["seal_row"], "tier": p["tier"], "since": p["since"], "until": p["until"]}
        if p["tier"] == "local-only":
            entry["local_hosts_used"] = _local_hosts_used(window)
        elif p["tier"] == "attested":
            consents = [r for r in rows if r["kind"] == "pin_applied" and r["id"] <= p["end_row"]]
            before = [r["id"] for r in consents if r["id"] < p["seal_row"]][-1:]
            entry["pin_consent_rows"] = before + [r["id"] for r in consents if r["id"] >= p["seal_row"]]
        per_period.append(entry)
    tiers = {p["tier"] for p in periods} or {tier}
    if tiers & {None, "local-only"}:
        local_rows = rows if not periods else [r for p in periods if p["tier"] == "local-only"
                                               for r in rows if p["seal_row"] <= r["id"] <= p["end_row"]]
        roots["local"] = {"rule": _LOCAL_RULE, "extra_hosts": sorted({str(h) for h in local_hosts}),
                          "hosts_used": _local_hosts_used(local_rows)}
    if tiers & {None, "attested"} or pins is not None:
        roots["pins"] = [{f: (list(v) if isinstance(v := _get(p, f), tuple) else v) for f in _PIN_FIELDS}
                         for p in _pin_records(pins)]
        roots["pins_note"] = "pins in force when this receipt was rendered; pin_applied rows show when each was set"
    roots["periods"] = per_period
    return roots


# ── sections ────────────────────────────────────────────────────────────────────────────────────

def is_unverified_entry(row: Mapping) -> bool:
    """A verify_ok row whose evidence is missing or whose capture is not marked complete (Amendment 4 F9).
    Fail closed: ``capture_complete`` must be exactly True."""
    if row.get("kind") != "verify_ok":
        return False
    detail = row.get("detail")
    evidence = detail.get("evidence") if isinstance(detail, Mapping) else None
    return not (isinstance(evidence, Mapping) and evidence and evidence.get("capture_complete") is True)


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
        "seal": [r["id"] for r in rows if _is_seal(r) or r["kind"] == "unseal"],
        "verification": by_kind(VERIFICATION_KINDS),
        "unverified_entries": [r["id"] for r in rows if is_unverified_entry(r)],
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
        if _is_seal(r):
            if periods and periods[-1]["until"] is None:
                periods[-1]["until"] = r["ts"]          # resealed without an unseal row
            if periods and periods[-1]["end_row"] is None:
                periods[-1]["end_row"] = r["id"] - 1
            periods.append({"tier": r.get("tier") or r["detail"].get("tier"), "since": r["ts"], "until": None,
                            "seal_row": r["id"], "end_row": None})
        elif r["kind"] == "unseal" and periods and periods[-1]["until"] is None:
            periods[-1]["until"] = r["ts"]
            periods[-1]["end_row"] = r["id"]
    for p in periods:
        if p["end_row"] is None:
            p["end_row"] = rows[-1]["id"]
    if periods:
        last = periods[-1]
        return {"tier": last["tier"], "since": last["since"], "until": last["until"], "source": "seal row",
                "periods": periods}
    tiers = [r.get("tier") for r in rows if r.get("tier")]
    tier = tiers[0] if tiers else None
    return {"tier": tier, "since": None, "until": None, "source": "send rows" if tier else "none", "periods": []}


def verify_facts(row: Mapping) -> dict:
    """Repo, platform, enclave host, fingerprints and committed keys of a verify row, from its detail and
    (preferred) its evidence blob. Missing values are None."""
    d = row.get("detail") if isinstance(row.get("detail"), Mapping) else {}
    ev = d.get("evidence") if isinstance(d.get("evidence"), Mapping) else {}
    claims = ev.get("claims") if isinstance(ev.get("claims"), Mapping) else {}
    pick = lambda *vals: next((v for v in vals if v not in (None, "")), None)  # noqa: E731
    return {
        "repo": pick(ev.get("repo"), d.get("router_repo"), d.get("repo")),
        "platform": pick(ev.get("platform"), d.get("platform")),
        "enclave_host": pick(ev.get("enclave_host"), d.get("enclave_host"), row.get("host")),
        "code_fingerprint": pick(claims.get("code_fingerprint"), d.get("code_fingerprint")),
        "enclave_fingerprint": pick(claims.get("enclave_fingerprint"), d.get("enclave_fingerprint")),
        "release_tag": pick(claims.get("release_tag"), d.get("release_tag")),
        "tls_public_key_fp": pick(claims.get("tls_public_key_fp")),
        "hpke_public_key": pick(claims.get("hpke_public_key")),
        "sdk_version": pick(ev.get("sdk_version")),
        "captured_at": pick(ev.get("captured_at")),
    }


def policy_checker_id(path: Path | None = None) -> str:
    """``sha256:<hex>`` of the restated policy checker file, computed now; "n/a" when it does not exist."""
    try:
        return "sha256:" + hashlib.sha256(Path(path or POLICY_CHECK_PATH).read_bytes()).hexdigest()
    except OSError:
        return "n/a"


def _check_result(value: Any) -> str | None:
    """pass / fail from the shapes a check result may be recorded in; None when absent or unreadable."""
    if isinstance(value, bool):
        return "pass" if value else "fail"
    if isinstance(value, str) and value.strip().lower() in ("pass", "fail", "ok", "failed"):
        return "pass" if value.strip().lower() in ("pass", "ok") else "fail"
    if isinstance(value, Mapping):
        for key in ("ok", "passed", "result", "verdict", "status"):
            if key in value:
                return _check_result(value[key])
    return None


def replay_status(row: Mapping, checker_id: str) -> dict:
    """What a verify row's evidence replays under (plan review finding 7). The vendor SDK result is the
    live result the row records (verify_ok pass, verify_fail fail) unless the row records a replay result;
    the restated policy check is n/a unless the checker file exists AND the row records its result."""
    d = row.get("detail") if isinstance(row.get("detail"), Mapping) else {}
    ev = d.get("evidence") if isinstance(d.get("evidence"), Mapping) else {}
    f = verify_facts(row)
    if is_unverified_entry(row):
        sdk = "n/a"
    else:
        sdk = _check_result(d.get("sdk_replay")) or ("pass" if row.get("kind") == "verify_ok" else "fail")
    policy = None
    if checker_id != "n/a":
        policy = _check_result(d.get("policy_check")) or _check_result(ev.get("policy_check"))
    return {
        "row": row["id"],
        "vendor_sdk": {"version": f["sdk_version"], "result": sdk},
        "restated_policy_check": {"checker": checker_id, "result": policy or "n/a"},
        "gating": GATING_NOTE,
        "enclave_host": {"value": f["enclave_host"], "asserted_by": "capturer"},
        "captured_at": {"value": f["captured_at"], "asserted_by": "capturer"},
    }


def replay_status_text(st: Mapping) -> str:
    sdk, pol = st["vendor_sdk"], st["restated_policy_check"]
    return (f"evidence replays under: vendor SDK {_p(sdk['version']) or '(version unknown)'} [{sdk['result']}]; "
            f"restated policy check ({_p(pol['checker'])}) [{pol['result']}]; {GATING_NOTE}")


def _send_coverage(rows: list[dict], ttl_seconds: float, ttl_source: str) -> list[dict]:
    """For every attested send: the latest verify_ok before it (same enclave host when both are known)
    and whether the send fell inside that row's TTL window. Wall-clock ledger times; the gate's own TTL
    is monotonic, so this is the record's view, not the gate's."""
    out = []
    verifies: list[dict] = []
    for r in rows:
        if r["kind"] == "verify_ok":
            verifies.append(r)
            continue
        if r["kind"] != "send_observed" or r.get("tier") != "attested":
            continue
        cands = [v for v in verifies
                 if not (r["host"] and verify_facts(v)["enclave_host"]) or verify_facts(v)["enclave_host"] == r["host"]]
        v = cands[-1] if cands else None
        entry = {"send": r["id"], "verify": None, "ttl_seconds": ttl_seconds, "ttl_source": ttl_source,
                 "window_start": None, "window_end": None, "covered": False, "verify_unverified_entry": None}
        # W2's per-send observations, when present (plan item 4); absent fields stay absent.
        d = r["detail"] if isinstance(r["detail"], Mapping) else {}
        if "hpke_key_used" in d:
            entry["hpke_key_used"] = d.get("hpke_key_used")
        if "response_decrypted" in d:
            entry["response_decrypted"] = d.get("response_decrypted")
        if v is not None:
            row_ttl = v["detail"].get("ttl_seconds")
            from_row = isinstance(row_ttl, (int, float)) and not isinstance(row_ttl, bool)
            ttl = float(row_ttl) if from_row else ttl_seconds
            entry.update(verify=v["id"], ttl_seconds=ttl, ttl_source="verify row" if from_row else ttl_source,
                         window_start=v["ts"], window_end=v["ts"] + ttl,
                         covered=bool(v["ts"] <= r["ts"] <= v["ts"] + ttl),
                         verify_unverified_entry=is_unverified_entry(v))
        if "hpke_key_used" in entry:
            h = verify_facts(v)["hpke_public_key"] if v is not None else None
            entry["verify_hpke_public_key"] = h
            entry["hpke_matches"] = None if (h is None or entry["hpke_key_used"] in (None, "")) \
                else str(entry["hpke_key_used"]).lower() == str(h).lower()
        out.append(entry)
    return out


def build_receipt(ledger, session_id: str, *, pins: Any = None, local_hosts: Iterable[str] = (),
                  include_profile_rows: bool = True, ttl_seconds: float | None = None) -> dict:
    """The JSON receipt as a dict (``render(fmt="json")`` serialises this). ``ttl_seconds``: the
    verification TTL in force (``confidential.verify_ttl_seconds``); default 300 s, labelled as a default."""
    rows = [_row_dict(e) for e in collect_rows(ledger, session_id, include_profile_rows=include_profile_rows)]
    head = _chain(rows)
    seal = _seal_info(rows)
    ttl_source = "config" if ttl_seconds is not None else "default (the ledger does not record the TTL)"
    ttl = float(ttl_seconds) if ttl_seconds is not None else DEFAULT_TTL_SECONDS
    checker_id = policy_checker_id()
    sdk_versions = sorted({f for r in rows if r["kind"] in ("verify_ok", "verify_fail")
                           if (f := verify_facts(r)["sdk_version"])})
    trust = _trust_roots(seal, rows, pins, local_hosts)
    sends = [r for r in rows if r["kind"] in ("send_observed", "send_refused")]
    providers = sorted({(r["provider"], r["model"]) for r in sends if r["provider"] or r["model"]})
    enclave_hosts = [{"row_id": r["id"], "host": r["host"]} for r in rows
                     if r["kind"] == "send_observed" and r.get("tier") == "attested" and r["host"]]
    evidence = [{"row_id": r["id"], "evidence": r["detail"]["evidence"], "unverified_entry": is_unverified_entry(r)}
                for r in rows
                if r["kind"] in ("verify_ok", "verify_fail") and isinstance(r["detail"].get("evidence"), Mapping)]
    doc = {
        "format": RECEIPT_FORMAT,
        "version": RECEIPT_VERSION,
        "header": {
            "session_id": session_id,
            "nature": SELF_REPORT_NOTE,
            "chain_head": head,
            "chain_head_note": CHAIN_HEAD_NOTE,
            "plugin_version": PLUGIN_VERSION,
            "plugin_commit": PLUGIN_COMMIT,
            "sdk_versions": sdk_versions,
            "verify_ttl_seconds": ttl,
            "verify_ttl_source": ttl_source,
            "policy_checker": checker_id,
            "gating": GATING_NOTE,
            "hpke_mismatches": [],
            "sealed_tier": seal["tier"],
            "sealed_period": {"since": seal["since"], "until": seal["until"], "source": seal["source"]},
            "sealed_periods": seal["periods"],
            "clock": "local (timestamps are this machine's clock, not attested)",
            "providers": [{"provider": p, "model": m} for p, m in providers],
            "enclave_hosts": enclave_hosts,
            "unverified_entries": [r["id"] for r in rows if is_unverified_entry(r)],
            "row_count": len(rows),
            "chain_algorithm": CHAIN_ALGORITHM,
            "chain_genesis": CHAIN_GENESIS,
            "trust_roots_sha256": hashlib.sha256(canonical_json(trust).encode("utf-8")).hexdigest(),
        },
        "trust_roots": trust,
        "sections": {**_sections(rows), "send_coverage": _send_coverage(rows, ttl, ttl_source),
                     "replay_status": [replay_status(r, checker_id) for r in rows
                                       if r["kind"] in ("verify_ok", "verify_fail")]},
        "rows": rows,
        "evidence": evidence,
        "closing": CLOSING_PARAGRAPH,
    }
    doc["header"]["hpke_mismatches"] = [c["send"] for c in doc["sections"]["send_coverage"]
                                        if c.get("hpke_matches") is False]
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


def _verify_body(r: Mapping, status: Mapping | None = None) -> str:
    d = r["detail"]
    k = r["kind"]
    full = lambda v: _p(v) or "?"  # noqa: E731
    if k in ("verify_ok", "verify_fail"):
        f = verify_facts(r)
        bits = ["UNVERIFIED ENTRY (no evidence or incomplete capture; proves nothing)"] if is_unverified_entry(r) else []
        bits += [k, f"vendor={_p(d.get('vendor') or r['provider']) or '?'}", f"repo={full(f['repo'])}",
                 f"platform={full(f['platform'])}", f"enclave={full(f['enclave_host'])} ({ASSERTED})"]
        if f["code_fingerprint"]:
            bits.append(f"code={full(f['code_fingerprint'])}")
        if f["enclave_fingerprint"]:
            bits.append(f"measurement={full(f['enclave_fingerprint'])}")
        if f["release_tag"]:
            bits.append(f"release={full(f['release_tag'])}")
        if f["tls_public_key_fp"]:
            bits.append(f"tls_key_fp={full(f['tls_public_key_fp'])}")
        if f["hpke_public_key"]:
            bits.append(f"hpke_key={full(f['hpke_public_key'])}")
        if f["captured_at"]:
            bits.append(f"captured_at={full(f['captured_at'])} ({ASSERTED})")
        if k == "verify_fail":
            bits.append(f"reason: {_p(d.get('error') or d.get('reason')) or '(none)'}")
        if status is not None:
            bits.append(replay_status_text(status))
        if isinstance(d.get("evidence"), Mapping):
            blob = canonical_json(d["evidence"]).encode("utf-8")
            bits.append(f"evidence attached ({len(blob)} bytes, sha256 {hashlib.sha256(blob).hexdigest()[:16]})")
        else:
            bits.append("no evidence attached")
        return "  ".join(bits)
    bits = [k, f"vendor={_p(d.get('vendor') or r['provider']) or '?'}"]
    if d.get("code_fingerprint"):
        bits.append(f"code={full(d.get('code_fingerprint'))}")
    if d.get("enclave_fingerprint"):
        bits.append(f"measurement={full(d.get('enclave_fingerprint'))}")
    if r.get("decision"):
        bits.append(f"decision={_p(r['decision'])}")
    if r.get("surface"):
        bits.append(f"via={_p(r['surface'])}")
    return "  ".join(bits)


def _hpke_text(c: Mapping) -> str:
    out = ""
    if "hpke_key_used" in c:
        used = _p(c["hpke_key_used"]) or "(none recorded)"
        if c.get("hpke_matches") is True:
            out += f"  hpke_key_used={used} (matches H of verify #{c['verify']})"
        elif c.get("hpke_matches") is False:
            out += (f"  hpke_key_used={used} HPKE KEY MISMATCH: verify #{c['verify']} H="
                    f"{_p(c.get('verify_hpke_public_key'))}")
        else:
            out += f"  hpke_key_used={used} (no H to compare)"
    if "response_decrypted" in c:
        rd = c["response_decrypted"]
        out += f"  response_decrypted={'yes' if rd is True else 'no' if rd is False else _p(rd) or '?'}"
    return out


def render_text(doc: Mapping) -> str:
    h = doc["header"]
    sid = h["session_id"]
    rows = {r["id"]: r for r in doc["rows"]}
    sec = doc["sections"]
    out: list[str] = []
    add = out.append

    period = h["sealed_period"]
    add(f"Confidential mode receipt for session {_p(sid)}")
    add(f"CHAIN HEAD: {h['chain_head']}")
    add(f"  {CHAIN_HEAD_NOTE}")
    add(SELF_REPORT_NOTE)
    add(f"Plugin: {_p(h['plugin_version'])} (commit {_p(h['plugin_commit'])})  verifier SDK: "
        f"{', '.join(_p(v) for v in h['sdk_versions']) or '(no verification in this receipt)'}")
    add(f"Restated policy checker: {_p(h['policy_checker'])}; {GATING_NOTE}.")
    if h.get("hpke_mismatches"):
        add("HPKE KEY MISMATCH on sends: " + ", ".join(f"#{i}" for i in h["hpke_mismatches"]))
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
    add(f"Rows: {h['row_count']}")
    if h["unverified_entries"]:
        add("Unverified entries (verify_ok rows without complete evidence): "
            + ", ".join(f"#{i}" for i in h["unverified_entries"]))
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
    for p in tr.get("periods", []):
        head = f"  Period {_p(p['tier']) or '?'} from {ts_text(p['since'])} (seal row #{p['seal_row']}): "
        if "local_hosts_used" in p:
            add(head + "local hosts used: " + (", ".join(_p(x) for x in p["local_hosts_used"]) or "(none)"))
        elif "pin_consent_rows" in p:
            add(head + "pin consent rows: " + (", ".join(f"#{i}" for i in p["pin_consent_rows"]) or "(none)"))
        else:
            add(head + "no trust roots recorded for this tier")

    def section(title: str, ids: list[int], body) -> None:
        add("")
        add(title)
        if not ids:
            add("  (none)")
        for i in ids:
            add(_line(rows[i], sid, body(rows[i])))

    statuses = {st["row"]: st for st in sec.get("replay_status", [])}
    section("Verification events", sec["verification"], lambda r: _verify_body(r, statuses.get(r["id"])))
    coverage = {c["send"]: c for c in sec.get("send_coverage", [])}

    def send_line(r: Mapping) -> str:
        body = _send_body(r)
        c = coverage.get(r["id"])
        if c is None:
            return body
        if c["verify"] is None:
            return (body + f"  NOT covered: no verify_ok row before this send (TTL {c['ttl_seconds']:g} s)"
                    + _hpke_text(c))
        state = "covered by" if c["covered"] else "NOT covered: outside the TTL window of"
        flag = " (an unverified entry)" if c["verify_unverified_entry"] else ""
        line = (body + f"  {state} verify #{c['verify']}{flag}, TTL {c['ttl_seconds']:g} s ({c['ttl_source']}), "
                f"window {ts_text(c['window_start'])} to {ts_text(c['window_end'])}")
        return line + _hpke_text(c)

    section("Sends (purpose, host, bytes; never text)", sec["sends"], send_line)
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
           include_profile_rows: bool = True, ttl_seconds: float | None = None) -> str:
    """Render the receipt for ``session_id``. ``pins``: a PinStore, a mapping or iterable of PinRecord,
    or None. ``fmt``: "text" or "json"."""
    if fmt not in ("text", "json"):
        raise ValueError(f"fmt must be 'text' or 'json', not {fmt!r}")
    doc = build_receipt(ledger, session_id, pins=pins, local_hosts=local_hosts,
                        include_profile_rows=include_profile_rows, ttl_seconds=ttl_seconds)
    if fmt == "json":
        return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    return render_text(doc)

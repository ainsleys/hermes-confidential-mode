"""Unit tests for receipts.py over the real SQLite ledger (no Hermes import)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from confidential_mode import receipts  # noqa: E402
from confidential_mode.ledger import FORBIDDEN_DETAIL_KEYS, KINDS, Ledger  # noqa: E402
from confidential_mode.pins import PinStore  # noqa: E402
from confidential_mode.receipts import (  # noqa: E402
    CHAIN_GENESIS, CLOSING_PARAGRAPH, build_receipt, forbidden_keys_in, render, verify_chain,
)
from confidential_mode.verify.base import VerificationResult  # noqa: E402

SID = "sess-A"
SECRET = "the merger closes on friday"   # stands in for prompt text; must never appear
# Golden digest of the closing paragraph: editing the claims split must be a deliberate change here.
CLOSING_SHA256 = hashlib.sha256(CLOSING_PARAGRAPH.encode("utf-8")).hexdigest()
CLOSING_SHA256_PINNED = "5a788ff013a8bb32b388e45dbfbbefc8369a7841902905b9519a6f568a5a18d6"


class Clock:
    def __init__(self, t=1_762_400_000.0):
        self.t = t

    def __call__(self):
        self.t += 1.25
        return self.t


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite", clock=Clock())
    yield led
    led.close()


def _ev(kind, **kw):
    return {"kind": kind, "session_id": kw.pop("session_id", SID), **kw}


EVIDENCE = {"format": "tinfoil-attestation", "body": "eyJyZXBvcnQiOiAiZmFrZSJ9",
            "codeFingerprint": "c1" * 32, "enclaveFingerprint": "e1" * 32, "capture_complete": True}


def fill_every_kind(led: Ledger, sid: str = SID) -> None:
    """One session that exercises every ledger kind, in demo order."""
    led.append(_ev("preflight_fail", session_id="", purpose="lock", tier="attested",
                   detail={"reason": "fallback_providers[0].provider off_tier", "failures": 1}))
    led.append(_ev("lock", session_id="", tier="attested", decision="locked", detail={"tier": "attested"}))
    led.append(_ev("verify_ok", session_id="", provider="attested-tinfoil", host="r1.tinfoil.invalid",
                   detail={"vendor": "tinfoil", "enclave_host": "r1.tinfoil.invalid", "code_fingerprint": "c1" * 32,
                           "enclave_fingerprint": "e1" * 32, "release_tag": "v1.0.0", "evidence": EVIDENCE}))
    led.append(_ev("send_observed", purpose="main", provider="attested-tinfoil", host="r1.tinfoil.invalid",
                   model="tf-model", bytes=1234, tier="attested", verdict="in_tier", decision="allowed"))
    led.append(_ev("send_refused", purpose="main", provider="attested-tinfoil", host="r1.tinfoil.invalid",
                   model="tf-model", bytes=1234, tier="attested", verdict="in_tier", decision="refused",
                   detail={"reason_code": "provider_error", "error_type": "InternalServerError", "status_code": 500}))
    led.append(_ev("tool_asked", purpose="tool:web_search", bytes=40, decision="ask", surface="gate",
                   detail={"tool": "web_search", "tool_call_id": "c1", "kb": 1,
                           "message": "web_search wants to send ~1 KB of this conversation off the machine"}))
    led.append(_ev("tool_allowed", purpose="tool:web_search", decision="once", detail={"tool": "web_search",
                                                                                      "tool_call_id": "c1"}))
    led.append(_ev("tool_asked", purpose="tool:web_search", bytes=40, decision="ask", detail={"kb": 1}))
    led.append(_ev("tool_refused", purpose="tool:web_search", decision="unexpected_choice",
                   detail={"reason": "unexpected_choice", "choice": ""}))
    led.append(_ev("tool_allowed", purpose="tool:web_extract", decision="remembered", detail={"kb": 2}))
    led.append(_ev("verify_fail", session_id="", provider="attested-tinfoil", host="r1.tinfoil.invalid",
                   detail={"vendor": "tinfoil", "error": "code fingerprint does not match pin"}))
    led.append(_ev("pin_staged", session_id="", provider="tinfoil", detail={"vendor": "tinfoil",
                   "code_fingerprint": "c2" * 32, "enclave_fingerprint": "e2" * 32}))
    led.append(_ev("pin_denied", provider="tinfoil", decision="no_answer", surface="telegram",
                   detail={"vendor": "tinfoil", "raw_pick": None}))
    led.append(_ev("pin_applied", provider="tinfoil", decision="approve", surface="telegram",
                   detail={"vendor": "tinfoil", "code_fingerprint": "c2" * 32, "raw_pick": "approve"}))
    led.append(_ev("pin_retired", provider="tinfoil", decision="retire", surface="cli",
                   detail={"vendor": "tinfoil", "code_fingerprint": "c0" * 32, "enclave_fingerprint": "e0" * 32}))
    led.append(_ev("grant_revoked", purpose="tool:web_search", decision="revoke", surface="cli",
                   detail={"tool": "web_search", "lock_id": "100.0|fp", "surface": "cli",
                           "removed": {"allowlist": [], "command_allowlist": ["web_search"], "session": []}}))
    led.append(_ev("breach", purpose="aux:compression", provider="openrouter", host="openrouter.ai", bytes=900,
                   detail={"reason": "compression summary sent off-tier"}))
    led.append(_ev("compaction", purpose="compaction", provider="attested-tinfoil", host="r1.tinfoil.invalid",
                   model="tf-model"))
    led.append(_ev("notice", purpose="aux:vision", provider="attested-near", host="cloud-api.near.ai",
                   verdict="disclosed", decision="image_plaintext",
                   detail={"note": "1 image part(s) left this host in plaintext to NEAR's gateway"}))
    led.append(_ev("unlock", session_id="", decision="unlocked"))
    # Session markers (W5): never open or close a locked period; appended last so earlier row ids hold.
    led.append(_ev("session_start", decision="session_start", detail={"platform": "cli"}))
    led.append(_ev("session_end", decision="session_end", detail={"platform": "cli"}))
    # Amendment 5: a NEAR signed-response row (no matching evidence here, so its replay verdict is fail).
    led.append(_ev("send_signed", purpose="main", provider="attested-near", host="cloud-api.near.ai",
                   model="m", bytes=10, verdict="unverified", decision="missing",
                   detail={"vendor": "near", "signature": {"status": "missing", "reason": "interrupted stream"}}))


def _pins(tmp_path) -> PinStore:
    store = PinStore(tmp_path / "pins.yaml")
    if store.load()[0]:
        return store
    r = VerificationResult(vendor="tinfoil", router_repo="tinfoilsh/confidential-model-router",
                           enclave_host="r1.tinfoil.invalid", code_fingerprint="c1" * 32,
                           enclave_fingerprint="e1" * 32, release_tag="v1.0.0", verifier="tinfoil/0.14.2",
                           verified_at_host_clock=0.0)
    store.apply(store.stage(r), approved_via="telegram", approved_at="2026-11-06T10:00:00Z")
    return store


# ── empty session ───────────────────────────────────────────────────────────────────────────────

def test_empty_session(ledger):
    text = render(ledger, "nobody", pins=None)
    assert "session nobody" in text and "No events were recorded" in text
    assert text.endswith(CLOSING_PARAGRAPH + "\n")
    doc = json.loads(render(ledger, "nobody", pins=None, fmt="json"))
    assert doc["rows"] == [] and doc["evidence"] == []
    assert doc["header"]["chain_head"] == CHAIN_GENESIS and doc["header"]["row_count"] == 0
    assert verify_chain(doc) is True


def test_empty_session_ignores_other_sessions_and_profile_rows(ledger):
    fill_every_kind(ledger, "other")
    doc = build_receipt(ledger, "nobody")
    assert doc["rows"] == []


def test_bad_format_rejected(ledger):
    with pytest.raises(ValueError):
        render(ledger, SID, fmt="yaml")


# ── every kind ──────────────────────────────────────────────────────────────────────────────────

def test_every_kind_is_rendered_in_order(ledger, tmp_path):
    fill_every_kind(ledger)
    ledger.append(_ev("send_observed", session_id="unrelated", purpose="main", host="elsewhere.test"))
    doc = build_receipt(ledger, SID, pins=_pins(tmp_path))
    kinds = {r["kind"] for r in doc["rows"]}
    assert kinds == set(KINDS), set(KINDS) - kinds
    assert "elsewhere.test" not in json.dumps(doc)

    text = render(ledger, SID, pins=_pins(tmp_path))
    titles = ["Confidential mode receipt for session", "Trust roots in force", "Verification events",
              "Sends (purpose, host, bytes; never text)", "Refusals", "Asks and answers", "Breaches",
              "Compactions", "Notices", CLOSING_PARAGRAPH]
    positions = [text.index(t) for t in titles]
    assert positions == sorted(positions)
    assert "Locked tier: attested" in text and "to " in text.split("Locked period:")[1].splitlines()[0]
    assert "Provider / model: attested-tinfoil / tf-model" in text
    assert "Enclave host per request:\n  #4 r1.tinfoil.invalid" in text
    # trust roots: the pin with its approval metadata
    assert "approved by human at 2026-11-06T10:00:00Z via telegram" in text
    # verification: evidence attached on verify_ok, reason on verify_fail
    assert "evidence attached (" in text and "reason: code fingerprint does not match pin" in text
    assert "pin_staged" in text and "pin_applied" in text and "decision=no_answer" in text
    # sends by purpose / host / bytes
    assert "main  host=r1.tinfoil.invalid  1234 bytes" in text
    # refusals with reason
    assert "reason: provider_error; HTTP 500; InternalServerError" in text
    assert "reason: fallback_providers[0].provider off_tier" in text
    # asks and their answers, including remembered
    assert "answer #7" in text and "allowed (once)" in text
    assert "refused (unexpected_choice)" in text
    assert "allowed without a prompt  tool:web_extract  (remembered)" in text
    assert "aux:compression  host=openrouter.ai  900 bytes" in text
    assert "compaction  host=r1.tinfoil.invalid" in text
    # profile-wide rows are marked
    assert "[profile]" in text


def test_every_timestamp_is_labelled_host_clock(ledger, tmp_path):
    fill_every_kind(ledger)
    text = render(ledger, SID, pins=_pins(tmp_path))
    import re
    stamps = re.findall(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z( \(host clock\))?", text)
    assert stamps and all(s == " (host clock)" for s in stamps), stamps


def test_json_carries_evidence_and_sections(ledger, tmp_path):
    fill_every_kind(ledger)
    doc = json.loads(render(ledger, SID, pins=_pins(tmp_path), fmt="json"))
    assert doc["evidence"] == [{"row_id": 3, "evidence": EVIDENCE, "unverified_entry": False}]
    assert doc["header"]["unverified_entries"] == [] and doc["sections"]["unverified_entries"] == []
    sec = doc["sections"]
    assert sec["asks"][0] == {"ask": 6, "answers": [7]} and sec["asks"][1]["answers"] == [9]
    assert sec["allowed_without_prompt"] == [10]
    assert doc["header"]["locked_tier"] == "attested"
    assert doc["header"]["locked_period"]["until"] is not None
    assert doc["trust_roots"]["pins"][0]["approved_via"] == "telegram"
    assert verify_chain(json.dumps(doc)) is True


def test_on_host_tier_trust_roots(ledger):
    ledger.append(_ev("lock", tier="on-host-only"))
    ledger.append(_ev("send_observed", purpose="main", provider="custom", host="127.0.0.1", bytes=10,
                      tier="on-host-only", decision="allowed"))
    text = render(ledger, SID, pins=None, on_host_extra_hosts=["gpu-box.lan"])
    assert "On-host endpoint set: loopback (127.0.0.0/8, ::1)" in text and "RFC1918" not in text
    assert "Extra on-host names: gpu-box.lan" in text and "On-host endpoints used: 127.0.0.1" in text
    assert "Pin " not in text


def test_profile_rows_window_runs_from_the_previous_unlock(ledger):
    ledger.append(_ev("verify_ok", session_id="", detail={"vendor": "old"}))        # previous period: excluded
    ledger.append(_ev("unlock", session_id="cli"))
    ledger.append(_ev("lock", session_id="cli", tier="on-host-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="on-host-only"))
    ledger.append(_ev("verify_ok", session_id="", detail={"vendor": "late"}))       # after last row: excluded
    doc = build_receipt(ledger, SID)
    assert [r["kind"] for r in doc["rows"]] == ["lock", "send_observed"]
    assert doc["header"]["locked_period"]["source"] == "lock row"


# ── redaction ───────────────────────────────────────────────────────────────────────────────────

def _raw_insert(path, detail: dict, kind="send_observed", sid=SID):
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO events (ts, session_id, kind, purpose, provider, host, model, bytes, tier, verdict,"
                 " decision, surface, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (1.0, sid, kind, "main", "custom", "h", "m", 5, None, None, None, None, json.dumps(detail)))
    conn.commit()
    conn.close()


def test_content_keys_written_behind_the_ledger_are_redacted(ledger, tmp_path):
    ledger.append(_ev("lock", tier="on-host-only"))   # creates the schema
    _raw_insert(tmp_path / "ledger.sqlite", {"messages": [{"role": "user", "content": SECRET}],
                                             "nested": {"Prompt": SECRET, "ok": 1}, "list": [{"input": SECRET}]})
    for fmt in ("text", "json"):
        out = render(ledger, SID, fmt=fmt)
        assert SECRET not in out
    doc = build_receipt(ledger, SID)
    assert forbidden_keys_in(doc) == []
    row = doc["rows"][-1]
    assert row["detail"] == {"nested": {"ok": 1}, "list": [{}]}
    assert sorted(row["redacted"]) == ["detail.list[0].input", "detail.messages", "detail.nested.Prompt"]
    assert verify_chain(doc)


def test_forbidden_list_is_the_ledgers():
    assert receipts.FORBIDDEN_DETAIL_KEYS is FORBIDDEN_DETAIL_KEYS
    assert forbidden_keys_in({"a": [{"CONTENT": 1}]}) == ["$.a[0].CONTENT"]


def test_every_kind_receipt_has_no_forbidden_keys(ledger, tmp_path):
    fill_every_kind(ledger)
    assert forbidden_keys_in(json.loads(render(ledger, SID, pins=_pins(tmp_path), fmt="json"))) == []


def test_control_characters_cannot_forge_receipt_lines(ledger):
    ledger.append(_ev("send_refused", purpose="main\n  #99 forged line", host="h",
                      detail={"reason": "x\nCLOSING"}))
    text = render(ledger, SID)
    assert "\n  #99 forged" not in text and "\nCLOSING" not in text


# ── chain ───────────────────────────────────────────────────────────────────────────────────────

def test_chain_is_deterministic_and_matches_the_spec(ledger, tmp_path):
    fill_every_kind(ledger)
    pins = _pins(tmp_path)
    a = render(ledger, SID, pins=pins, fmt="json")
    b = render(ledger, SID, pins=pins, fmt="json")
    assert a == b
    doc = json.loads(a)
    prev = CHAIN_GENESIS
    for row in doc["rows"]:
        body = {k: v for k, v in row.items() if k != "hash"}
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        prev = hashlib.sha256((prev + canon).encode()).hexdigest()
        assert row["hash"] == prev
    assert doc["header"]["chain_head"] == prev


def test_same_events_in_another_ledger_give_the_same_head(tmp_path):
    heads = []
    for name in ("a", "b"):
        led = Ledger(tmp_path / name / "l.sqlite", clock=Clock())
        fill_every_kind(led)
        heads.append(build_receipt(led, SID)["header"]["chain_head"])
        led.close()
    assert heads[0] == heads[1]


@pytest.mark.parametrize("mutate", [
    lambda d: d["rows"][3].__setitem__("bytes", 1),
    lambda d: d["rows"][0]["detail"].__setitem__("reason", "edited"),
    lambda d: d["rows"].pop(4),
    lambda d: d["rows"].insert(0, dict(d["rows"][0])),
    lambda d: d["rows"].reverse(),
    lambda d: d["header"].__setitem__("chain_head", "f" * 64),
    lambda d: d["evidence"][0]["evidence"].__setitem__("body", "forged"),
    lambda d: d["trust_roots"]["pins"][0].__setitem__("approved_via", "nobody"),
    lambda d: d.__setitem__("closing", d["closing"] + " Also fully proven."),
    lambda d: d.__setitem__("format", "other"),
])
def test_tamper_is_detected(ledger, tmp_path, mutate):
    fill_every_kind(ledger)
    doc = json.loads(render(ledger, SID, pins=_pins(tmp_path), fmt="json"))
    assert verify_chain(doc) is True
    mutate(doc)
    assert verify_chain(doc) is False
    assert verify_chain(json.dumps(doc)) is False


def test_verify_chain_never_raises_on_garbage():
    for junk in ("", "{", "[]", "null", '{"format": "confidential-mode-receipt"}', {"rows": 3}):
        assert verify_chain(junk) is False


# ── closing paragraph ───────────────────────────────────────────────────────────────────────────

def test_closing_paragraph_is_a_pinned_constant():
    assert CLOSING_SHA256 == CLOSING_SHA256_PINNED, (
        "CLOSING_PARAGRAPH changed; if deliberate, update CLOSING_SHA256_PINNED in this test")
    assert "{" not in CLOSING_PARAGRAPH and "%" not in CLOSING_PARAGRAPH   # not a template


def test_closing_paragraph_states_the_claims_split():
    text = CLOSING_PARAGRAPH
    ev, rec = text.index("EVIDENCE:"), text.index("RECORD ONLY")
    assert ev < rec
    evidence_part, record_part = text[ev:rec], text[rec:]
    assert "replay offline" in evidence_part
    for fact in ("TLS key fingerprint T", "HPKE public key H", "measurement M", "repository R", "release tag G",
                 "as of the capture time the file claims", "long-lived keys, not a per-session key"):
        assert fact in evidence_part, fact
    assert "session key" not in text.replace("per-session key", "")
    assert "plugin checked" not in evidence_part
    assert "plugin itself checked that evidence during this session" in record_part
    assert "Sends were gated by the vendor SDK only" in evidence_part
    assert "asserted by whoever captured it" in evidence_part
    assert "confidential_mode/verify/policy_check.py" in evidence_part
    assert "verified by" not in text.lower()
    for claim in ("latest release at the time", "requests actually went to that enclave",
                  "HPKE key each send recorded and whether its response decrypted"):
        assert claim in record_part, claim
    for claim in ("requests actually went to that enclave", "encrypted to that key", "latest release",
                  "revoked after the evidence was captured", "shell", "code-execution",
                  "model backends sit behind the vendor's router", "vendor's operators"):
        assert claim in record_part, claim


def test_closing_paragraph_is_identical_across_receipts(ledger, tmp_path):
    fill_every_kind(ledger)
    outs = [render(ledger, SID, pins=_pins(tmp_path)), render(ledger, "nobody"),
            render(ledger, SID, pins=None, on_host_extra_hosts=["x"])]
    for out in outs:
        assert out.endswith("\n\n" + CLOSING_PARAGRAPH + "\n")
    for fmt_out in (render(ledger, SID, fmt="json"), render(ledger, "nobody", fmt="json")):
        assert json.loads(fmt_out)["closing"] == CLOSING_PARAGRAPH


def test_every_lock_period_is_listed(ledger):
    ledger.append(_ev("lock", tier="on-host-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="on-host-only"))
    ledger.append(_ev("unlock"))
    ledger.append(_ev("lock", tier="attested"))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    doc = build_receipt(ledger, SID)
    periods = doc["header"]["locked_periods"]
    assert [(p["tier"], p["until"] is None, p["lock_row"]) for p in periods] == [
        ("on-host-only", False, 1), ("attested", True, 4)]
    text = render(ledger, SID)
    lines = [ln for ln in text.splitlines() if ln.startswith("Locked period:")]
    assert lines[0].startswith("Locked period: on-host-only from ") and "(host clock) to 20" in lines[0]
    assert lines[1].startswith("Locked period: attested from ") and "still locked at the last row" in lines[1]
    assert doc["header"]["locked_tier"] == "attested"


# ── Amendment 4: unverified entries (F9), per-period trust roots (F11), session markers (F7) ─────

@pytest.mark.parametrize("detail", [
    {"vendor": "tinfoil"},                                                        # no evidence
    {"vendor": "tinfoil", "evidence": {}},                                        # empty evidence
    {"vendor": "tinfoil", "evidence": {"format": "made-up", "quote": "AAAA"}},    # no capture_complete
    {"vendor": "tinfoil", "evidence": {"format": "x", "capture_complete": False}},
    {"vendor": "tinfoil", "evidence": {"format": "x", "capture_complete": "true"}},  # not exactly True
])
def test_verify_ok_without_complete_evidence_is_an_unverified_entry(ledger, detail):
    ledger.append(_ev("lock", tier="on-host-only"))
    vid = ledger.append(_ev("verify_ok", session_id="", provider="attested-tinfoil", detail=detail))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="on-host-only"))
    doc = json.loads(render(ledger, SID, fmt="json"))
    assert doc["header"]["unverified_entries"] == [vid] and doc["sections"]["unverified_entries"] == [vid]
    assert all(e["unverified_entry"] is True for e in doc["evidence"])
    assert verify_chain(doc) is True        # the chain is over the ledger as held; the paragraph says so
    text = render(ledger, SID)
    line = next(ln for ln in text.splitlines() if f"#{vid} " in ln and "verify_ok" in ln)
    assert "UNVERIFIED ENTRY" in line
    assert f"Unverified entries (verify_ok rows without complete evidence): #{vid}" in text


def test_complete_evidence_is_not_flagged(ledger):
    ledger.append(_ev("lock", tier="attested"))
    ledger.append(_ev("verify_ok", session_id="", detail={"evidence": EVIDENCE}))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    assert "UNVERIFIED" not in render(ledger, SID)
    assert build_receipt(ledger, SID)["header"]["unverified_entries"] == []


def test_trust_roots_per_period_across_a_relock(ledger, tmp_path):
    ledger.append(_ev("lock", tier="on-host-only"))                                                     # 1
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="on-host-only"))          # 2
    ledger.append(_ev("unlock"))                                                                      # 3
    ledger.append(_ev("pin_applied", provider="tinfoil", decision="approve", detail={"vendor": "tinfoil"}))  # 4
    ledger.append(_ev("lock", tier="attested"))                                                       # 5
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))   # 6
    ledger.append(_ev("pin_applied", provider="tinfoil", decision="approve", detail={"vendor": "tinfoil"}))  # 7
    doc = build_receipt(ledger, SID, pins=_pins(tmp_path))
    tr = doc["trust_roots"]
    assert tr["tier"] == "attested"
    assert tr["on_host"]["hosts_used"] == ["127.0.0.1"] and tr["pins"]
    assert [(p["tier"], p["lock_row"]) for p in tr["periods"]] == [("on-host-only", 1), ("attested", 5)]
    assert tr["periods"][0]["on_host_endpoints_used"] == ["127.0.0.1"]
    assert tr["periods"][1]["pin_consent_rows"] == [4, 7]
    text = render(ledger, SID, pins=_pins(tmp_path))
    assert "Period on-host-only from " in text and "(lock row #1): on-host endpoints used: 127.0.0.1" in text
    assert "(lock row #5): pin consent rows: #4, #7" in text
    assert "On-host endpoint set:" in text and "Pin tinfoil" in text


@pytest.mark.parametrize("marker", [
    {"kind": "lock", "decision": "session_start"}, {"kind": "lock", "decision": "session_end"},
])
def test_session_markers_are_not_lock_periods(ledger, marker):
    sid_lock = ledger.append(_ev("lock", session_id="cli", tier="on-host-only", decision="locked"))
    ledger.append(_ev(marker["kind"], decision=marker["decision"], tier="on-host-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="on-host-only"))
    ledger.append(_ev("lock", decision="session_end", tier="on-host-only"))
    doc = build_receipt(ledger, SID)
    periods = doc["header"]["locked_periods"]
    assert [p["lock_row"] for p in periods] == [sid_lock]
    assert doc["header"]["locked_period"]["since"] == doc["rows"][0]["ts"]
    assert doc["sections"]["lock"] == [sid_lock]


def test_closing_paragraph_discloses_the_in_process_and_aux_limits():
    text = CLOSING_PARAGRAPH
    rec = text.index("RECORD ONLY")
    assert "file on this host" in text and "same Hermes process" in text
    assert "replay offline" in text[:rec] and "confidential_mode.verify.replay" in text[:rec]
    assert "hermes confidential replay <receipt.json>" in text[:rec] and '"unverified entry"' in text[:rec]
    assert "self-report" in text[:rec]
    assert "checksum over this document that anyone holding the file can recompute" in text
    assert "only when compared with a chain head recorded somewhere else" in text
    assert "says nothing about whether the ledger was complete" in text
    for aux in ("title generation", "compaction", "memory prefetch", "vision", "plugin auxiliary tasks",
                "recorded here after the fact, not prevented"):
        assert aux in text[rec:], aux
    assert "safe-worker" in text


# ── Miller-frame review: header framing, verification facts, send coverage ───────────────────────

def test_header_frames_a_self_report_with_the_chain_head_first(ledger):
    fill_every_kind(ledger)
    text = render(ledger, SID)
    lines = text.splitlines()
    head = build_receipt(ledger, SID)["header"]["chain_head"]
    assert lines[1] == f"CHAIN HEAD: {head}"
    assert lines[2] == "  " + receipts.CHAIN_HEAD_NOTE and "somewhere other than this machine" in lines[2]
    assert lines[3] == receipts.SELF_REPORT_NOTE and "self-report" in lines[3]
    assert lines[4].startswith(f"Plugin: {receipts.PLUGIN_VERSION} (commit {receipts.PLUGIN_COMMIT})")
    doc = build_receipt(ledger, SID)
    h = doc["header"]
    assert h["nature"] == receipts.SELF_REPORT_NOTE and h["chain_head_note"] == receipts.CHAIN_HEAD_NOTE
    assert h["plugin_commit"] == receipts.PLUGIN_COMMIT


def test_plugin_commit_comes_from_version_module(ledger, monkeypatch):
    from confidential_mode import _version
    assert receipts.PLUGIN_COMMIT is _version.PLUGIN_COMMIT
    monkeypatch.setattr(receipts, "PLUGIN_COMMIT", "abc1234")
    ledger.append(_ev("lock", tier="on-host-only"))
    assert "(commit abc1234)" in render(ledger, SID)


FULL_EVIDENCE = {"schema": 1, "vendor": "tinfoil", "repo": "tinfoilsh/confidential-model-router",
                 "platform": "sev-snp", "enclave_host": "r1.tinfoil.invalid", "sdk_version": "0.14.2",
                 "captured_at": "2026-11-06T00:00:00Z", "capture_complete": True,
                 "claims": {"code_fingerprint": "c1" * 32, "enclave_fingerprint": "e1" * 32, "release_tag": "v1.0.0",
                            "tls_public_key_fp": "71" * 32, "hpke_public_key": "48" * 32}}


def test_verification_row_shows_repo_platform_host_and_committed_keys(ledger):
    ledger.append(_ev("lock", tier="attested"))
    ledger.append(_ev("verify_ok", session_id="", host="r1.tinfoil.invalid", detail={"vendor": "tinfoil",
                                                                                     "evidence": FULL_EVIDENCE}))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    text = render(ledger, SID)
    line = next(ln for ln in text.splitlines() if "verify_ok  vendor=" in ln)
    for part in ("repo=tinfoilsh/confidential-model-router", "platform=sev-snp", "enclave=r1.tinfoil.invalid",
                 f"code={'c1' * 32}", f"measurement={'e1' * 32}", f"tls_key_fp={'71' * 32}",
                 f"hpke_key={'48' * 32}", "release=v1.0.0", "captured_at=2026-11-06T00:00:00Z (asserted by capturer)",
                 "enclave=r1.tinfoil.invalid (asserted by capturer)"):
        assert part in line, part
    assert "verifier SDK: 0.14.2" in text
    assert build_receipt(ledger, SID)["header"]["sdk_versions"] == ["0.14.2"]


def _attested_sends(ledger, gaps, **verify_detail):
    clock = ledger._clock
    ledger.append(_ev("lock", tier="attested"))
    vid = ledger.append(_ev("verify_ok", session_id="", host="r1.tinfoil.invalid",
                            detail={"evidence": FULL_EVIDENCE, **verify_detail}))
    ids = []
    for gap in gaps:
        clock.t += gap
        ids.append(ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested",
                                     decision="allowed")))
    return vid, ids


def test_each_attested_send_names_its_verify_row_and_ttl_window(ledger):
    vid, (inside, outside) = _attested_sends(ledger, [10, 400])
    doc = build_receipt(ledger, SID)
    cov = {c["send"]: c for c in doc["sections"]["send_coverage"]}
    assert cov[inside]["verify"] == vid and cov[inside]["covered"] is True
    assert cov[inside]["ttl_seconds"] == 300.0 and cov[inside]["ttl_source"].startswith("default")
    vrow = next(r for r in doc["rows"] if r["id"] == vid)
    assert cov[inside]["window_start"] == vrow["ts"] and cov[inside]["window_end"] == vrow["ts"] + 300.0
    assert cov[outside]["verify"] == vid and cov[outside]["covered"] is False
    text = render(ledger, SID)
    send_lines = [ln for ln in text.splitlines() if "main  host=r1.tinfoil.invalid" in ln]
    assert f"covered by verify #{vid}, TTL 300 s (default" in send_lines[0] and "(host clock) to " in send_lines[0]
    assert f"NOT covered: outside the TTL window of verify #{vid}" in send_lines[1]
    assert doc["header"]["verify_ttl_seconds"] == 300.0


def test_ttl_from_argument_and_from_the_verify_row(ledger, tmp_path):
    vid, (send,) = _attested_sends(ledger, [400])
    doc = build_receipt(ledger, SID, ttl_seconds=600)
    c = doc["sections"]["send_coverage"][0]
    assert (c["covered"], c["ttl_seconds"], c["ttl_source"]) == (True, 600.0, "config")
    led2 = Ledger(tmp_path / "l2.sqlite", clock=Clock())
    _attested_sends(led2, [400], ttl_seconds=900)
    c = build_receipt(led2, SID, ttl_seconds=60)["sections"]["send_coverage"][0]
    assert (c["covered"], c["ttl_seconds"], c["ttl_source"]) == (True, 900.0, "verify row")
    led2.close()


def test_attested_send_with_no_verify_row_is_not_covered(ledger):
    ledger.append(_ev("lock", tier="attested"))
    sid_send = ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    c = build_receipt(ledger, SID)["sections"]["send_coverage"]
    assert c == [{"send": sid_send, "verify": None, "ttl_seconds": 300.0, "ttl_source": c[0]["ttl_source"],
                  "window_start": None, "window_end": None, "covered": False, "verify_unverified_entry": None}]
    assert "NOT covered: no verify_ok row before this send" in render(ledger, SID)


def test_coverage_by_an_unverified_entry_is_flagged(ledger):
    ledger.append(_ev("lock", tier="attested"))
    vid = ledger.append(_ev("verify_ok", session_id="", host="r1.tinfoil.invalid", detail={"vendor": "x"}))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    assert f"covered by verify #{vid} (an unverified entry)" in render(ledger, SID)


def test_on_host_sends_have_no_coverage_entry(ledger):
    ledger.append(_ev("lock", tier="on-host-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="on-host-only"))
    assert build_receipt(ledger, SID)["sections"]["send_coverage"] == []


# ── plan review finding 7 / item 5: replay status, capturer-asserted fields, per-send HPKE ────────

def _one_verify(ledger, kind="verify_ok", **detail):
    ledger.append(_ev("lock", tier="attested"))
    vid = ledger.append(_ev(kind, session_id="", host="r1.tinfoil.invalid",
                            detail={"vendor": "tinfoil", "evidence": FULL_EVIDENCE, **detail}))
    return vid


def test_replay_status_without_a_policy_checker_file(ledger, monkeypatch, tmp_path):
    monkeypatch.setattr(receipts, "POLICY_CHECK_PATH", tmp_path / "absent.py")
    vid = _one_verify(ledger, policy_check="pass")
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    doc = build_receipt(ledger, SID)
    st = doc["sections"]["replay_status"][0]
    assert st["row"] == vid and st["vendor_sdk"] == {"version": "0.14.2", "result": "pass"}
    assert st["restated_policy_check"] == {"checker": "n/a", "result": "n/a"}
    assert st["gating"] == "sends were gated by the vendor SDK only"
    assert st["enclave_host"] == {"value": "r1.tinfoil.invalid", "asserted_by": "capturer"}
    assert st["captured_at"] == {"value": "2026-11-06T00:00:00Z", "asserted_by": "capturer"}
    assert doc["header"]["policy_checker"] == "n/a"
    text = render(ledger, SID)
    line = next(ln for ln in text.splitlines() if "verify_ok  vendor=" in ln)
    assert ("evidence replays under: vendor SDK 0.14.2 [pass]; restated policy check (n/a) [n/a]; "
            "sends were gated by the vendor SDK only") in line
    assert "Restated policy checker: n/a; sends were gated by the vendor SDK only." in text
    assert "verified by" not in text.lower()


@pytest.mark.parametrize("recorded,expected", [("pass", "pass"), ({"ok": False}, "fail"), (None, "n/a")])
def test_replay_status_with_the_checker_file_hash(ledger, monkeypatch, tmp_path, recorded, expected):
    checker = tmp_path / "policy_check.py"
    checker.write_bytes(b"# restated policy\n")
    monkeypatch.setattr(receipts, "POLICY_CHECK_PATH", checker)
    digest = "sha256:" + hashlib.sha256(b"# restated policy\n").hexdigest()
    _one_verify(ledger, **({} if recorded is None else {"policy_check": recorded}))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    st = build_receipt(ledger, SID)["sections"]["replay_status"][0]
    assert st["restated_policy_check"] == {"checker": digest, "result": expected}
    assert f"restated policy check ({digest}) [{expected}]" in render(ledger, SID)


def test_policy_checker_hash_is_computed_at_render_time(monkeypatch, tmp_path):
    f = tmp_path / "pc.py"
    monkeypatch.setattr(receipts, "POLICY_CHECK_PATH", f)
    assert receipts.policy_checker_id() == "n/a"
    f.write_text("a")
    first = receipts.policy_checker_id()
    f.write_text("b")
    assert first.startswith("sha256:") and receipts.policy_checker_id() != first


def test_replay_status_for_failed_and_unverified_rows(ledger):
    ledger.append(_ev("lock", tier="attested"))
    fail = ledger.append(_ev("verify_fail", session_id="", detail={"evidence": FULL_EVIDENCE, "error": "x"}))
    bare = ledger.append(_ev("verify_ok", session_id="", detail={"vendor": "tinfoil"}))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    st = {s["row"]: s for s in build_receipt(ledger, SID)["sections"]["replay_status"]}
    assert st[fail]["vendor_sdk"]["result"] == "fail" and st[bare]["vendor_sdk"]["result"] == "n/a"


def _hpke_send(ledger, **detail):
    vid = _one_verify(ledger)
    sid_send = ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested",
                                 detail=detail))
    return vid, sid_send


def test_per_send_hpke_key_matching_the_covering_verify_row(ledger):
    vid, send = _hpke_send(ledger, hpke_key_used="48" * 32, response_decrypted=True)
    doc = build_receipt(ledger, SID)
    c = doc["sections"]["send_coverage"][0]
    assert (c["hpke_key_used"], c["hpke_matches"], c["response_decrypted"]) == ("48" * 32, True, True)
    assert doc["header"]["hpke_mismatches"] == []
    line = next(ln for ln in render(ledger, SID).splitlines() if f"#{send} " in ln and "main  host=" in ln)
    assert f"hpke_key_used={'48' * 32} (matches H of verify #{vid})" in line and "response_decrypted=yes" in line


def test_per_send_hpke_key_mismatch_is_flagged(ledger):
    vid, send = _hpke_send(ledger, hpke_key_used="99" * 32, response_decrypted=False)
    doc = build_receipt(ledger, SID)
    assert doc["sections"]["send_coverage"][0]["hpke_matches"] is False
    assert doc["header"]["hpke_mismatches"] == [send]
    text = render(ledger, SID)
    assert f"HPKE KEY MISMATCH on sends: #{send}" in text
    line = next(ln for ln in text.splitlines() if f"#{send} " in ln and "main  host=" in ln)
    assert f"HPKE KEY MISMATCH: verify #{vid} H={'48' * 32}" in line and "response_decrypted=no" in line


def test_per_send_fields_absent_render_nothing(ledger):
    _hpke_send(ledger)
    doc = build_receipt(ledger, SID)
    c = doc["sections"]["send_coverage"][0]
    assert "hpke_key_used" not in c and "response_decrypted" not in c and "hpke_matches" not in c
    assert "hpke_key_used" not in render(ledger, SID)


def test_unstamped_checkout_reports_its_git_commit_without_running_git(tmp_path):
    """Review finding 12: a source checkout names its commit (read from .git files, no subprocess)."""
    from confidential_mode._version import checkout_commit
    sha = "ab" * 20
    loose = tmp_path / "loose"
    (loose / ".git" / "refs" / "heads").mkdir(parents=True)
    (loose / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (loose / ".git" / "refs" / "heads" / "main").write_text(sha + "\n")
    assert checkout_commit(loose) == sha
    packed = tmp_path / "packed"
    (packed / ".git").mkdir(parents=True)
    (packed / ".git" / "HEAD").write_text("ref: refs/heads/dev\n")
    (packed / ".git" / "packed-refs").write_text(f"# pack-refs with: peeled\n{'cd' * 20} refs/heads/dev\n")
    assert checkout_commit(packed) == "cd" * 20
    detached = tmp_path / "detached"
    (detached / ".git").mkdir(parents=True)
    (detached / ".git" / "HEAD").write_text("ef" * 20 + "\n")
    assert checkout_commit(detached) == "ef" * 20
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {loose / '.git'}\n")
    assert checkout_commit(worktree) == sha
    assert checkout_commit(tmp_path / "nothing") is None
    (detached / ".git" / "HEAD").write_text("not a sha\n")
    assert checkout_commit(detached) is None


def test_receipt_reads_only_the_sessions_locked_period(ledger):
    """Review finding 22: a receipt reads the rows from the unlock before the session to the lock or unlock
    after it, not the whole ledger, and the result is the same as the full read."""
    for i in range(50):                                        # an older locked period, long finished
        ledger.append(_ev("send_observed", session_id=f"old-{i}", purpose="main", host="127.0.0.1"))
    ledger.append(_ev("unlock", session_id=""))
    lock = ledger.append(_ev("lock", session_id="", tier="on-host-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1"))
    ledger.append(_ev("unlock", session_id=""))
    for i in range(30):                                        # later periods
        ledger.append(_ev("send_observed", session_id=f"new-{i}", purpose="main", host="127.0.0.1"))
    seen = []
    real_tail = ledger.tail

    def tail(since_id=0, limit=1000):
        out = real_tail(since_id, limit)
        seen.extend(r.id for r in out)
        return out
    ledger.tail = tail
    bounded = [r.id for r in receipts.collect_rows(ledger, SID)]
    assert min(seen) > 50 and len(seen) < 70, seen          # rows 1-50 (the older period) are never read
    del ledger.tail

    class Unbounded:                                           # the old full read, for comparison
        def __getattr__(self, name):
            if name == "last_id_before":
                raise AttributeError(name)
            return getattr(ledger, name)
    assert [r.id for r in receipts.collect_rows(Unbounded(), SID)] == bounded and lock in bounded

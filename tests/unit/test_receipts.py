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
CLOSING_SHA256_PINNED = "5a3d5d5151b697de16e9863f12c1f29262c0b15d431ee2b262475def628a8fa3"


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
            "codeFingerprint": "c1" * 32, "enclaveFingerprint": "e1" * 32}


def fill_every_kind(led: Ledger, sid: str = SID) -> None:
    """One session that exercises every ledger kind, in demo order."""
    led.append(_ev("session_start", purpose="session", tier="attested", decision="session_start"))  # Amendment 4 F7
    led.append(_ev("preflight_fail", session_id="", purpose="seal", tier="attested",
                   detail={"reason": "fallback_providers[0].provider off_tier", "failures": 1}))
    led.append(_ev("seal", session_id="", tier="attested", decision="sealed", detail={"tier": "attested"}))
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
    led.append(_ev("breach", purpose="aux:compression", provider="openrouter", host="openrouter.ai", bytes=900,
                   detail={"reason": "compression summary sent off-tier"}))
    led.append(_ev("compaction", purpose="compaction", provider="attested-tinfoil", host="r1.tinfoil.invalid",
                   model="tf-model"))
    led.append(_ev("session_end", purpose="session", tier="attested", decision="session_end"))
    led.append(_ev("unseal", session_id="", decision="unsealed"))


def _pins(tmp_path) -> PinStore:
    store = PinStore(tmp_path / "pins.yaml")
    if store.load()[0]:
        return store
    r = VerificationResult(vendor="tinfoil", router_repo="tinfoilsh/confidential-model-router",
                           enclave_host="r1.tinfoil.invalid", code_fingerprint="c1" * 32,
                           enclave_fingerprint="e1" * 32, release_tag="v1.0.0", verifier="tinfoil/0.14.2",
                           verified_at_local=0.0)
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
              "Compactions", CLOSING_PARAGRAPH]
    positions = [text.index(t) for t in titles]
    assert positions == sorted(positions)
    assert "Sealed tier: attested" in text and "to " in text.split("Sealed period:")[1].splitlines()[0]
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


def test_every_timestamp_is_labelled_local_clock(ledger, tmp_path):
    fill_every_kind(ledger)
    text = render(ledger, SID, pins=_pins(tmp_path))
    import re
    stamps = re.findall(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z( \(local clock\))?", text)
    assert stamps and all(s == " (local clock)" for s in stamps), stamps


def test_json_carries_evidence_and_sections(ledger, tmp_path):
    fill_every_kind(ledger)
    doc = json.loads(render(ledger, SID, pins=_pins(tmp_path), fmt="json"))
    assert doc["evidence"] == [{"row_id": 3, "evidence": EVIDENCE}]
    sec = doc["sections"]
    assert sec["asks"][0] == {"ask": 6, "answers": [7]} and sec["asks"][1]["answers"] == [9]
    assert sec["allowed_without_prompt"] == [10]
    assert doc["header"]["sealed_tier"] == "attested"
    assert doc["header"]["sealed_period"]["until"] is not None
    assert doc["trust_roots"]["pins"][0]["approved_via"] == "telegram"
    assert verify_chain(json.dumps(doc)) is True


def test_local_tier_trust_roots(ledger):
    ledger.append(_ev("seal", tier="local-only"))
    ledger.append(_ev("send_observed", purpose="main", provider="custom", host="127.0.0.1", bytes=10,
                      tier="local-only", decision="allowed"))
    text = render(ledger, SID, pins=None, local_hosts=["gpu-box.lan"])
    assert "Local endpoint set: loopback, RFC1918" in text
    assert "Extra local hosts: gpu-box.lan" in text and "Local hosts used: 127.0.0.1" in text
    assert "Pin " not in text


def test_profile_rows_window_runs_from_the_previous_unseal(ledger):
    ledger.append(_ev("verify_ok", session_id="", detail={"vendor": "old"}))        # previous period: excluded
    ledger.append(_ev("unseal", session_id="cli"))
    ledger.append(_ev("seal", session_id="cli", tier="local-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="local-only"))
    ledger.append(_ev("verify_ok", session_id="", detail={"vendor": "late"}))       # after last row: excluded
    doc = build_receipt(ledger, SID)
    assert [r["kind"] for r in doc["rows"]] == ["seal", "send_observed"]
    assert doc["header"]["sealed_period"]["source"] == "seal row"


# ── redaction ───────────────────────────────────────────────────────────────────────────────────

def _raw_insert(path, detail: dict, kind="send_observed", sid=SID):
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO events (ts, session_id, kind, purpose, provider, host, model, bytes, tier, verdict,"
                 " decision, surface, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (1.0, sid, kind, "main", "custom", "h", "m", 5, None, None, None, None, json.dumps(detail)))
    conn.commit()
    conn.close()


def test_content_keys_written_behind_the_ledger_are_redacted(ledger, tmp_path):
    ledger.append(_ev("seal", tier="local-only"))   # creates the schema
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
    assert "verified" in evidence_part and "bound the session key" in evidence_part and "replay" in evidence_part
    for claim in ("requests actually went to that enclave", "encrypted to that key", "latest release",
                  "revoked after the evidence was captured", "shell", "code-execution",
                  "model backends sit behind the vendor's router", "vendor's operators"):
        assert claim in record_part, claim


def test_closing_paragraph_is_identical_across_receipts(ledger, tmp_path):
    fill_every_kind(ledger)
    outs = [render(ledger, SID, pins=_pins(tmp_path)), render(ledger, "nobody"),
            render(ledger, SID, pins=None, local_hosts=["x"])]
    for out in outs:
        assert out.endswith("\n\n" + CLOSING_PARAGRAPH + "\n")
    for fmt_out in (render(ledger, SID, fmt="json"), render(ledger, "nobody", fmt="json")):
        assert json.loads(fmt_out)["closing"] == CLOSING_PARAGRAPH


def test_every_seal_period_is_listed(ledger):
    ledger.append(_ev("seal", tier="local-only"))
    ledger.append(_ev("send_observed", purpose="main", host="127.0.0.1", tier="local-only"))
    ledger.append(_ev("unseal"))
    ledger.append(_ev("seal", tier="attested"))
    ledger.append(_ev("send_observed", purpose="main", host="r1.tinfoil.invalid", tier="attested"))
    doc = build_receipt(ledger, SID)
    periods = doc["header"]["sealed_periods"]
    assert [(p["tier"], p["until"] is None, p["seal_row"]) for p in periods] == [
        ("local-only", False, 1), ("attested", True, 4)]
    text = render(ledger, SID)
    lines = [ln for ln in text.splitlines() if ln.startswith("Sealed period:")]
    assert lines[0].startswith("Sealed period: local-only from ") and "(local clock) to 20" in lines[0]
    assert lines[1].startswith("Sealed period: attested from ") and "still sealed at the last row" in lines[1]
    assert doc["header"]["sealed_tier"] == "attested"

"""Unit tests for ledger.py and state.py (no Hermes import except the plugin-storage test)."""
from __future__ import annotations

import sqlite3
import sys
import threading
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from confidential_mode.ledger import KINDS, MISSING_SESSION_ID, Ledger, LedgerError, LedgerEvent  # noqa: E402
from confidential_mode.state import ConfidentialState, InMemoryState, StateError  # noqa: E402
from confidential_mode.tiers import Tier  # noqa: E402

FROZEN_COLUMNS = ["id", "ts", "session_id", "kind", "purpose", "provider", "host", "model", "bytes",
                  "tier", "verdict", "decision", "surface", "detail"]
FROZEN_KINDS = {"notice", "send_observed", "send_refused", "verify_ok", "verify_fail", "tool_asked", "tool_allowed",
                "tool_refused", "pin_staged", "pin_applied", "pin_denied", "lock", "unlock", "preflight_fail",
                "breach", "compaction",
                "session_start", "session_end",   # Amendment 4 F7
                "send_signed",                    # Amendment 5 (NEAR signed responses)
                "pin_retired",                    # Amendment 7 (pins retire)
                "grant_revoked"}                  # Amendment 10 (revoke <tool>)


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite", clock=lambda: 1000.0)
    yield led
    led.close()


def test_schema_matches_contract(ledger, tmp_path):
    ledger.append(LedgerEvent(kind="lock"))
    conn = sqlite3.connect(tmp_path / "ledger.sqlite")
    cols = conn.execute("PRAGMA table_info(events)").fetchall()
    assert [c[1] for c in cols] == FROZEN_COLUMNS
    assert {c[1]: c[2] for c in cols}["bytes"] == "INTEGER"
    assert [c[1] for c in cols if c[5]] == ["id"], "id is the primary key"


def test_kinds_match_contract():
    assert set(KINDS) == FROZEN_KINDS


def test_append_tail_session_roundtrip(ledger):
    a = ledger.append(LedgerEvent(kind="send_observed", session_id="s1", purpose="main", provider="custom",
                                  host="h.test", model="m", bytes=123, decision="observed",
                                  detail={"k": 1}))
    b = ledger.append(LedgerEvent(kind="send_refused", session_id="s2", tier="on-host-only", verdict="off_tier"))
    c = ledger.append(LedgerEvent(kind="lock", session_id="s1", tier="on-host-only"))
    assert a < b < c
    assert [e.id for e in ledger.tail(0)] == [a, b, c]
    assert [e.id for e in ledger.tail(a)] == [b, c]
    assert ledger.tail(c) == []
    s1 = ledger.session("s1")
    assert [e.kind for e in s1] == ["send_observed", "lock"]
    e = s1[0]
    assert (e.ts, e.purpose, e.provider, e.host, e.model, e.bytes, e.decision, e.detail) == \
        (1000.0, "main", "custom", "h.test", "m", 123, "observed", {"k": 1})
    assert e.tier is None and e.surface is None


def test_mutant_twin_tail_is_strictly_after_since_id(ledger):
    """Twin of the roundtrip: a >= comparison would return the since_id row again."""
    a = ledger.append(LedgerEvent(kind="lock"))
    assert a not in [e.id for e in ledger.tail(a)]


def test_unknown_kind_rejected(ledger):
    with pytest.raises(LedgerError):
        ledger.append(LedgerEvent(kind="prompt_logged"))
    assert ledger.tail(0) == []


@pytest.mark.parametrize("detail", [
    {"messages": [{"role": "user", "content": "secret"}]},
    {"nested": {"prompt": "secret"}},
    {"list": [{"input": "secret"}]},
    {"Instructions": "secret"},
])
def test_content_shaped_detail_rejected(ledger, detail):
    with pytest.raises(LedgerError):
        ledger.append(LedgerEvent(kind="send_observed", detail=detail))
    assert ledger.tail(0) == []


def test_oversized_detail_rejected(ledger):
    with pytest.raises(LedgerError):
        ledger.append(LedgerEvent(kind="verify_ok", detail={"blob": "x" * (300 * 1024)}))


def test_an_oversized_detail_without_evidence_is_written_with_a_marker(ledger):
    """FI-6: a row still over the cap after clipping keeps its columns and its short structural fields, and
    gets the marker."""
    from confidential_mode.ledger import MAX_DETAIL_BYTES, is_truncated
    rid = ledger.append(LedgerEvent(kind="tool_refused", decision="unclassified",
                                    detail={"args_shape": ["x" * 1000] * 400, "tool_call_id": "c1",
                                            "reason_code": "unclassified", "n": 3}))
    (row,) = [r for r in ledger.tail(0) if r.id == rid]
    assert row.kind == "tool_refused" and row.decision == "unclassified" and is_truncated(row.detail)
    assert row.detail["tool_call_id"] == "c1" and row.detail["reason_code"] == "unclassified"
    assert row.detail["n"] == 3 and "args_shape" not in row.detail
    marker = row.detail["detail_too_large"]
    assert marker.startswith("detail too large: ") and marker.endswith(" bytes, truncated")
    assert int(marker.split()[3]) > MAX_DETAIL_BYTES


def test_a_row_whose_structural_fields_alone_exceed_the_cap_is_refused(ledger):
    """FI-6: the marker keeps short structural fields; when even those exceed the cap the row is refused."""
    detail = {f"k{i}": "y" * 500 for i in range(600)}
    with pytest.raises(LedgerError, match="structural"):
        ledger.append(LedgerEvent(kind="tool_refused", detail=detail))
    assert ledger.tail(0) == []


def test_free_text_is_clipped_and_identifiers_are_not(ledger):
    """FI-6: a model-chosen tool name and Hermes' free text are clipped before the row is built, with a digest
    so different values stay distinct; session ids, tool call ids and fingerprints are never clipped."""
    from confidential_mode.ledger import MAX_CALLER_CHARS
    name = "t" * 300_000
    sid, call = "s" * 5000, "c" * 5000
    ledger.append(LedgerEvent(kind="tool_refused", purpose=f"tool:{name}", session_id=sid,
                              detail={"tool": name, "reason": "r" * 5000, "tool_call_id": call,
                                      "code_fingerprint": "f" * 2000, "n": 1}))
    ledger.append(LedgerEvent(kind="tool_refused", purpose=f"tool:{name}x", detail={"tool": name + "x"}))
    a, b = ledger.tail(0)
    assert len(a.purpose) < MAX_CALLER_CHARS + 80 and "(clipped, 300005 chars, sha256 " in a.purpose
    assert a.purpose != b.purpose and a.detail["tool"] != b.detail["tool"]
    assert a.detail["tool"].startswith("ttt") and "(clipped, 300000 chars, sha256 " in a.detail["tool"]
    assert "(clipped, 5000 chars, sha256 " in a.detail["reason"] and a.detail["n"] == 1
    assert a.session_id == sid and a.detail["tool_call_id"] == call and a.detail["code_fingerprint"] == "f" * 2000
    assert len(ledger.session(sid)) == 1


def test_non_int_bytes_rejected(ledger):
    with pytest.raises(LedgerError):
        ledger.append(LedgerEvent(kind="send_observed", bytes="12"))


def test_persists_across_instances(tmp_path):
    p = tmp_path / "l.sqlite"
    Ledger(p).append(LedgerEvent(kind="lock", session_id="x"))
    assert [e.kind for e in Ledger(p).session("x")] == ["lock"]


def test_concurrent_appends(ledger):
    def worker(n):
        for i in range(25):
            ledger.append(LedgerEvent(kind="send_observed", session_id=f"t{n}", bytes=i))
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ledger.tail(0)) == 100


def test_injectable_connect(tmp_path):
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    led = Ledger(connect=lambda: conn)
    led.append(LedgerEvent(kind="lock"))
    assert conn.execute("SELECT kind FROM events").fetchall() == [("lock",)]
    with pytest.raises(ValueError):
        Ledger(tmp_path / "a", connect=lambda: conn)


def test_default_uses_hermes_plugin_storage(tmp_path, monkeypatch):
    pytest.importorskip("plugins.plugin_storage")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    led = Ledger()
    led.append(LedgerEvent(kind="lock"))
    led.close()
    from confidential_mode.ledger import default_ledger_path
    assert default_ledger_path() == tmp_path / "plugin-data" / "confidential-mode" / "ledger.sqlite"
    assert default_ledger_path().exists()


# --------------------------------------------------------------------------- state


def test_state_unlocked_by_default():
    st = ConfidentialState(InMemoryState())
    assert st.locked() == (False, None)
    assert st.breached_sessions() == []


def test_state_lock_unlock_roundtrip():
    store = InMemoryState()
    st = ConfidentialState(store, clock=lambda: 42.0)
    st.lock(Tier.ATTESTED, "abc")
    assert st.locked() == (True, Tier.ATTESTED)
    assert store.get("locked") is True and store.get("locked_tier") == "attested"
    assert st.locked_since() == 42.0 and st.config_fingerprint() == "abc"
    st.unlock()
    assert st.locked() == (False, None)


@pytest.mark.parametrize("locked,tier", [("yes", "on-host-only"), (1, "on-host-only"), (True, "bogus"), (True, None)])
def test_state_malformed_raises(locked, tier):
    st = ConfidentialState(InMemoryState({"locked": locked, "locked_tier": tier}))
    with pytest.raises(StateError):
        st.locked()


def test_state_breached_sessions():
    st = ConfidentialState(InMemoryState())
    st.mark_breached("s1")
    st.mark_breached("s1")
    st.mark_breached("s2")
    assert st.breached_sessions() == ["s1", "s2"] and st.is_breached("s1") and not st.is_breached("s3")
    bad = ConfidentialState(InMemoryState({"breached_sessions": "s1"}))
    with pytest.raises(StateError):
        bad.breached_sessions()


def test_state_over_real_plugin_state(tmp_path, monkeypatch):
    """The accessors work over Hermes' real PluginState (ctx.state) with its key rules."""
    mod = pytest.importorskip("hermes_cli.plugins_state")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    st = ConfidentialState(mod.PluginState("confidential-mode"))
    st.lock(Tier.ON_HOST, "fp")
    st.mark_breached("sess")
    again = ConfidentialState(mod.PluginState("confidential-mode"))
    assert again.locked() == (True, Tier.ON_HOST) and again.breached_sessions() == ["sess"]


# --------------------------------------------------------------------------- dict events (Amendment 2)


def _w4_tool_event(kind, decision, **over):
    """Exactly the shape gate_tools._event / consent._event build."""
    ev = {"ts": 5.0, "session_id": "s9", "kind": kind, "purpose": "tool:web_search", "provider": "",
          "host": "", "model": "", "bytes": 2048, "tier": None, "verdict": None, "decision": decision,
          "surface": "gate", "detail": {"tool": "web_search", "tool_call_id": "c1", "kb": 2}}
    ev.update(over)
    return ev


@pytest.mark.parametrize("kind,decision,purpose", [
    ("tool_asked", "ask", "tool:web_search"),
    ("tool_allowed", "remembered", "tool:web_search"),
    ("tool_allowed", "allowlist", "tool:web_search"),
    ("tool_refused", "bypass_active", "tool:web_search"),
    ("pin_staged", "staged", "pin"),
    ("pin_applied", "approve", "pin"),
    ("pin_denied", "no_answer", "pin"),
])
def test_append_accepts_w4_dicts(ledger, kind, decision, purpose):
    eid = ledger.append(_w4_tool_event(kind, decision, purpose=purpose))
    [row] = ledger.session("s9")
    assert row.id == eid
    assert (row.kind, row.decision, row.purpose, row.bytes, row.ts, row.surface) == \
        (kind, decision, purpose, 2048, 5.0, "gate")
    assert row.detail == {"tool": "web_search", "tool_call_id": "c1", "kb": 2}


def test_dict_and_dataclass_store_identically(ledger):
    ledger.append(_w4_tool_event("tool_asked", "ask"))
    ledger.append(LedgerEvent(**{k: v for k, v in _w4_tool_event("tool_asked", "ask").items()}))
    a, b = ledger.session("s9")
    assert {**a.__dict__, "id": 0} == {**b.__dict__, "id": 0}


def test_minimal_dict_and_none_detail(ledger):
    ledger.append({"kind": "unlock", "detail": None, "id": 999})
    [row] = ledger.tail(0)
    assert row.kind == "unlock" and row.detail == {} and row.id != 999 and row.ts == 1000.0


@pytest.mark.parametrize("bad", [
    {"kind": "tool_asked", "sesion_id": "typo"},          # unknown field
    {"session_id": "s"},                                    # no kind
    {"kind": "tool_banana"},                                # unknown kind
    {"kind": "tool_asked", "detail": "not a dict"},
    {"kind": "tool_asked", "detail": {"args": 1, "messages": ["secret"]}},  # content-shaped
    ["kind", "tool_asked"],                                 # not a mapping
])
def test_bad_dicts_rejected(ledger, bad):
    with pytest.raises(LedgerError):
        ledger.append(bad)
    assert ledger.tail(0) == []


@pytest.mark.parametrize("missing", ["", None, MISSING_SESSION_ID])
def test_breach_missing_session_uses_one_key(ledger, missing):
    """Every breach without a session is grouped under the same ledger key."""
    ledger.append(LedgerEvent(kind="breach", session_id=missing))
    assert len(ledger.session(MISSING_SESSION_ID)) == 1
    assert ledger.tail(0)[-1].session_id == MISSING_SESSION_ID

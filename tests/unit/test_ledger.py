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

from confidential_mode.ledger import KINDS, Ledger, LedgerError, LedgerEvent  # noqa: E402
from confidential_mode.state import ConfidentialState, InMemoryState, StateError  # noqa: E402
from confidential_mode.tiers import Tier  # noqa: E402

FROZEN_COLUMNS = ["id", "ts", "session_id", "kind", "purpose", "provider", "host", "model", "bytes",
                  "tier", "verdict", "decision", "surface", "detail"]
FROZEN_KINDS = {"send_observed", "send_refused", "verify_ok", "verify_fail", "tool_asked", "tool_allowed",
                "tool_refused", "pin_staged", "pin_applied", "pin_denied", "seal", "unseal", "preflight_fail",
                "breach", "compaction",
                "session_start", "session_end"}   # Amendment 4 F7


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite", clock=lambda: 1000.0)
    yield led
    led.close()


def test_schema_matches_contract(ledger, tmp_path):
    ledger.append(LedgerEvent(kind="seal"))
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
    b = ledger.append(LedgerEvent(kind="send_refused", session_id="s2", tier="local-only", verdict="off_tier"))
    c = ledger.append(LedgerEvent(kind="seal", session_id="s1", tier="local-only"))
    assert a < b < c
    assert [e.id for e in ledger.tail(0)] == [a, b, c]
    assert [e.id for e in ledger.tail(a)] == [b, c]
    assert ledger.tail(c) == []
    s1 = ledger.session("s1")
    assert [e.kind for e in s1] == ["send_observed", "seal"]
    e = s1[0]
    assert (e.ts, e.purpose, e.provider, e.host, e.model, e.bytes, e.decision, e.detail) == \
        (1000.0, "main", "custom", "h.test", "m", 123, "observed", {"k": 1})
    assert e.tier is None and e.surface is None


def test_mutant_twin_tail_is_strictly_after_since_id(ledger):
    """Twin of the roundtrip: a >= comparison would return the since_id row again."""
    a = ledger.append(LedgerEvent(kind="seal"))
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


def test_non_int_bytes_rejected(ledger):
    with pytest.raises(LedgerError):
        ledger.append(LedgerEvent(kind="send_observed", bytes="12"))


def test_persists_across_instances(tmp_path):
    p = tmp_path / "l.sqlite"
    Ledger(p).append(LedgerEvent(kind="seal", session_id="x"))
    assert [e.kind for e in Ledger(p).session("x")] == ["seal"]


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
    led.append(LedgerEvent(kind="seal"))
    assert conn.execute("SELECT kind FROM events").fetchall() == [("seal",)]
    with pytest.raises(ValueError):
        Ledger(tmp_path / "a", connect=lambda: conn)


def test_default_uses_hermes_plugin_storage(tmp_path, monkeypatch):
    pytest.importorskip("plugins.plugin_storage")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    led = Ledger()
    led.append(LedgerEvent(kind="seal"))
    led.close()
    from confidential_mode.ledger import default_ledger_path
    assert default_ledger_path() == tmp_path / "plugin-data" / "confidential-mode" / "ledger.sqlite"
    assert default_ledger_path().exists()


# --------------------------------------------------------------------------- state


def test_state_unsealed_by_default():
    st = ConfidentialState(InMemoryState())
    assert st.sealed() == (False, None)
    assert st.breached_sessions() == []


def test_state_seal_unseal_roundtrip():
    store = InMemoryState()
    st = ConfidentialState(store, clock=lambda: 42.0)
    st.seal(Tier.ATTESTED, "abc")
    assert st.sealed() == (True, Tier.ATTESTED)
    assert store.get("sealed") is True and store.get("sealed_tier") == "attested"
    assert st.sealed_since() == 42.0 and st.config_fingerprint() == "abc"
    st.unseal()
    assert st.sealed() == (False, None)


@pytest.mark.parametrize("sealed,tier", [("yes", "local-only"), (1, "local-only"), (True, "bogus"), (True, None)])
def test_state_malformed_raises(sealed, tier):
    st = ConfidentialState(InMemoryState({"sealed": sealed, "sealed_tier": tier}))
    with pytest.raises(StateError):
        st.sealed()


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
    st.seal(Tier.LOCAL, "fp")
    st.mark_breached("sess")
    again = ConfidentialState(mod.PluginState("confidential-mode"))
    assert again.sealed() == (True, Tier.LOCAL) and again.breached_sessions() == ["sess"]


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
    ledger.append({"kind": "unseal", "detail": None, "id": 999})
    [row] = ledger.tail(0)
    assert row.kind == "unseal" and row.detail == {} and row.id != 999 and row.ts == 1000.0


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

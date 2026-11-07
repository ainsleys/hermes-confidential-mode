"""Fault class 1, the filesystem: a full disk, a read-only directory, a file replaced by a directory or a
symlink, a torn write, a corrupt or busy SQLite ledger, a garbage pins.yaml, and evidence blobs that went
missing. Every case uses the real Ledger, PinStore, allowlist and lock code; only the OS call or the SQLite
connection is made to fail. Each test asserts the documented outcome (refusal, row, verdict), never only
that nothing crashed.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from types import SimpleNamespace

import pytest

from confidential_mode import consent, provider as provider_mod
from confidential_mode.gate_llm import TEXT_STATE_UNREADABLE, LlmGate, off_tier_text
from confidential_mode.ledger import BlobStore, Ledger, LedgerError
from confidential_mode.locking import predicate_for
from confidential_mode.pins import PinStore, PinStoreError
from confidential_mode.state import ConfidentialState, InMemoryState
from confidential_mode.tiers import Tier
from confidential_mode.verify.base import VerificationResult, VerifyError

from tests.hostile._harness_integrated import answer_choice, cm, rows  # noqa: F401
from tests.seam._harness import no_lazy_installs  # noqa: F401  (fixture)
from tests.seam.test_register import ON_HOST_URL, plugin  # noqa: F401  (fixture)
from tests.unit.test_background_refresh import FakeAdapter, _result

from ._faults import (EACCES, ENOSPC, FaultPlan, chmod_ro, db_locked, disk_full, fail_replace, faulty_ledger,
                      tmp_leftovers, truncate)

P = provider_mod.PROFILE_NAME
LOST = provider_mod.REASON_VERIFY_ROW_LOST[:60]   # _fail_reason clips the reason at 160 characters
REMOTE = "https://llm.example.test/v1"


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────

def _gate(ledger, *, locked=True):
    st = ConfidentialState(InMemoryState())
    if locked:
        st.lock(Tier.ON_HOST, "fp")
    return LlmGate(ledger=ledger, is_locked=st.locked, predicate_for=lambda t: predicate_for(t, config={}),
                   attested_ok=lambda p: None)


def _call(gate, base_url):
    sent = []

    def next_call(req):
        sent.append(req)
        return "provider-response"
    out = gate({"messages": [{"role": "user", "content": "SECRET"}]}, next_call, provider="custom",
               base_url=base_url, model="m", api_mode="chat_completions", session_id="s1")
    return out, sent


def _text(refusal) -> str:
    return refusal.choices[0].message.content


def _cache(tmp_path, ledger, adapter=None, *, approve=True):
    store = PinStore(tmp_path / "pins.yaml")
    if approve:
        store.apply(store.stage(_result()), approved_via="cli")
    cache = provider_mod.VerificationCache()
    ad = adapter or FakeAdapter([_result()])
    cache.register(P, ad, store, 300.0, on_event=ledger.append, failure_backoff_seconds=30.0,
                   verify_wait_seconds=2.0, refresh_lead_seconds=0.0)
    return cache, ad, store


def _kinds(ledger):
    return [(r.kind, r.decision) for r in ledger.tail(0, limit=10000)]


def _blob_evidence(text="app_compose: services: [x]"):
    import hashlib
    bid = hashlib.sha256(text.encode()).hexdigest()
    return bid, {"schema": "test", "blobs": {bid: text}}


# ── the ledger: full disk, busy, corrupt, wrong schema, a directory ──────────────────────────────

def test_full_disk_ledger_still_refuses_an_off_tier_send_and_sends_nothing(tmp_path):
    """INTERFACES W1: "Off-tier -> ledger send_refused, return refusal (never call next_call)"; gate_llm.record:
    "a ledger failure never changes the gate's decision"."""
    plan = FaultPlan()
    plan.insert = disk_full()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    out, sent = _call(_gate(led), REMOTE)
    assert sent == []
    assert _text(out).startswith(off_tier_text(Tier.ON_HOST, "")[:40])
    assert plan.raised == ["insert"]
    assert led.tail(0) == []           # nothing recorded, and nothing claimed


def test_full_disk_ledger_lets_an_in_tier_send_through_unrecorded_as_documented(tmp_path):
    """gate_llm.record: "Best effort: a ledger failure never changes the gate's decision" (the in-tier send
    still goes out; Amendment 5.2 makes verify_ok rows the only exception)."""
    plan = FaultPlan()
    plan.insert = disk_full()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    out, sent = _call(_gate(led), ON_HOST_URL)
    assert out == "provider-response" and len(sent) == 1
    assert led.tail(0) == [] and plan.raised.count("insert") >= 1


def test_verify_ok_row_lost_to_a_full_disk_refuses_the_verification(tmp_path):
    """Amendment 5.2: "a verification whose verify_ok row cannot be written ... is refused: a verify_fail row
    with REASON_VERIFY_ROW_LOST, no cached result, VerifyError"."""
    plan = FaultPlan()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    cache, ad, _ = _cache(tmp_path, led)
    plan.insert = disk_full()
    plan.insert_times = 1                 # only the verify_ok row is lost; the verify_fail row lands
    with pytest.raises(VerifyError, match="could not be written"):
        cache.refresh(P)
    assert cache.entry(P).result is None
    ok, reason, _ = cache.ensure(P)
    assert ok is False and LOST in reason
    assert ad.held_reason and LOST in ad.held_reason
    assert [k for k, _ in _kinds(led)] == ["verify_fail"]
    assert led.tail(0)[0].detail["error"] == provider_mod.REASON_VERIFY_ROW_LOST


def test_a_busy_ledger_is_retried_once_and_the_verification_stands(tmp_path, monkeypatch):
    """Amendment 5.2: "A transient 'database is locked' is retried once after LEDGER_RETRY_DELAY_SECONDS"."""
    monkeypatch.setattr(provider_mod, "LEDGER_RETRY_DELAY_SECONDS", 0.01)
    plan = FaultPlan()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    cache, ad, _ = _cache(tmp_path, led)
    plan.insert, plan.insert_times = db_locked(), 1
    assert cache.ensure(P)[0] is True
    assert plan.raised == ["insert"]
    assert [k for k, _ in _kinds(led)] == ["verify_ok"]


def test_a_ledger_busy_past_the_retry_refuses_the_verification(tmp_path, monkeypatch):
    """Amendment 5.2: the retry is once; after it "any other ledger exception on a verify_ok write ... blocks
    attested sends ... until the failure backoff expires"."""
    monkeypatch.setattr(provider_mod, "LEDGER_RETRY_DELAY_SECONDS", 0.01)
    plan = FaultPlan()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    cache, _, _ = _cache(tmp_path, led)
    plan.insert, plan.insert_times = db_locked(), 2
    ok, reason, _ = cache.ensure(P)
    assert ok is False and LOST in reason
    assert plan.raised == ["insert", "insert"]
    assert [k for k, _ in _kinds(led)] == ["verify_fail"]
    # within the backoff the next call refuses without attesting again
    assert cache.ensure(P)[0] is False


def _reader_lock(path):
    """Another connection holding a read transaction: in rollback-journal mode a writer's COMMIT then waits
    for it and fails with 'database is locked' once the busy timeout passes."""
    other = sqlite3.connect(path, isolation_level=None)
    other.execute("BEGIN")
    other.execute("SELECT count(*) FROM events").fetchone()
    return other


def test_an_append_whose_commit_failed_is_not_committed_later(tmp_path):
    """ledger.append "Raises LedgerError on a rejected event" and returns the id of a row it wrote; a caller
    told the write failed (provider._emit, Amendment 5.2's refusal) must be able to rely on the row not
    existing. Fault: another connection holds a read lock past the writer's busy timeout."""
    path = tmp_path / "ledger.sqlite"
    led = Ledger(connect=lambda: sqlite3.connect(path, check_same_thread=False, timeout=0.05),
                 blob_dir=tmp_path / "evidence" / "blobs")
    led.append({"kind": "lock", "decision": "locked"})
    reader = _reader_lock(path)
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        led.append({"kind": "verify_ok", "decision": "lost", "detail": {"n": 1}})
    reader.rollback()
    reader.close()
    led.append({"kind": "verify_fail", "decision": "after"})
    assert [r.decision for r in led.tail(0)] == ["locked", "after"]


def test_a_failed_evidence_append_never_leaves_a_row_whose_blobs_were_deleted(tmp_path):
    """Amendment 5.2: "when the insert fails, the blobs it created are deleted" and "a blob stays while any
    row lists it"; both hold only if the failed row never lands."""
    path = tmp_path / "ledger.sqlite"
    led = Ledger(connect=lambda: sqlite3.connect(path, check_same_thread=False, timeout=0.05),
                 blob_dir=tmp_path / "evidence" / "blobs")
    led.append({"kind": "lock", "decision": "locked"})
    bid, ev = _blob_evidence()
    reader = _reader_lock(path)
    with pytest.raises(sqlite3.OperationalError):
        led.append({"kind": "verify_ok", "detail": {"evidence": ev}})
    reader.rollback()
    reader.close()
    assert led.blob(bid) is None                       # the failed append removed what it wrote
    led.append({"kind": "unlock", "decision": "unlocked"})
    for row in led.tail(0):
        for ref in (row.detail.get("evidence") or {}).get("blob_refs") or []:
            assert led.blob(ref) is not None, f"row {row.id} lists blob {ref[:12]} that was deleted"


def test_the_default_ledger_reports_wal_and_a_reader_does_not_fail_its_commit(tmp_path, monkeypatch):
    """FI-1: the default ledger opens through Hermes' plugin_db, which applies WAL where SQLite allows it;
    Ledger.journal_mode reports the mode in force, and in WAL a reader's open transaction does not block the
    writer's COMMIT."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    led = Ledger()
    led.append({"kind": "lock", "decision": "locked"})
    assert led.journal_mode == "wal"
    from confidential_mode.ledger import default_ledger_path
    reader = _reader_lock(default_ledger_path())
    try:
        led.append({"kind": "unlock", "decision": "unlocked"})
    finally:
        reader.rollback()
        reader.close()
    assert [r.decision for r in led.tail(0)] == ["locked", "unlocked"]
    led.close()


def test_an_insert_that_failed_leaves_nothing_for_the_next_commit(tmp_path):
    """FI-1: a failed INSERT (a full disk) is rolled back too, so the next append commits only its own row."""
    plan = FaultPlan()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    led.append({"kind": "lock", "decision": "locked"})
    plan.insert, plan.insert_times = disk_full(), 1
    with pytest.raises(sqlite3.OperationalError):
        led.append({"kind": "verify_ok", "decision": "lost"})
    led.append({"kind": "unlock", "decision": "unlocked"})
    assert [r.decision for r in led.tail(0)] == ["locked", "unlocked"]


@pytest.mark.parametrize("damage", ["truncated", "garbage", "directory"])
def test_a_corrupt_ledger_file_refuses_attested_verification_and_off_tier_sends(tmp_path, damage):
    """Amendment 5.2: "any other ledger exception on a verify_ok write (a full disk, a corrupt file ...)
    blocks attested sends"; W1: an off-tier send is refused whatever the ledger does."""
    path = tmp_path / "ledger.sqlite"
    good = Ledger(path)
    for i in range(50):
        good.append({"kind": "send_observed", "decision": "observed", "detail": {"i": i, "pad": "x" * 200}})
    good.close()
    if damage == "truncated":
        truncate(path, 0.3)
    elif damage == "garbage":
        path.write_bytes(b"SQLite format 3\x00" + os.urandom(4096))
    else:
        path.unlink()
        path.mkdir()
    led = Ledger(path)
    out, sent = _call(_gate(led), REMOTE)
    assert sent == [] and _text(out).startswith("Confidential mode: locked to on-host-only")
    cache, ad, _ = _cache(tmp_path, led)
    ok, reason, _ = cache.ensure(P)
    assert ok is False and LOST in reason
    assert cache.entry(P).result is None and ad.held_reason


def test_a_ledger_with_another_schema_refuses_attested_verification(tmp_path):
    """Amendment 5.2: a verify_ok row that cannot be written refuses the verification. Fault: an events table
    with other columns (CREATE TABLE IF NOT EXISTS keeps it)."""
    path = tmp_path / "ledger.sqlite"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, what TEXT)")
    con.commit()
    con.close()
    led = Ledger(path)
    with pytest.raises(sqlite3.OperationalError):
        led.append({"kind": "lock"})
    cache, _, _ = _cache(tmp_path, led)
    ok, reason, _ = cache.ensure(P)
    assert ok is False and LOST in reason


def test_receipts_of_a_corrupt_ledger_answer_instead_of_raising(plugin):
    """commands.register_slash: "a command bug is reported, never raised into the surface"; receipts read the
    ledger, which now raises DatabaseError."""
    path = cm(plugin, "ledger").default_ledger_path()
    plugin.rt.ledger.append({"kind": "session_start", "session_id": "s"})
    plugin.rt.ledger.close()
    truncate(path, 0.2)
    out = plugin.slash("receipts s")
    assert out.startswith("confidential: error (DatabaseError"), out      # reported, not raised, not empty
    st = plugin.slash("status")
    assert st.startswith("Confidential mode: not locked")


# ── evidence blobs ───────────────────────────────────────────────────────────────────────────────

def test_a_full_disk_on_a_blob_write_refuses_the_row_and_leaves_no_blob(tmp_path, monkeypatch):
    """Amendment 5.2: "BlobStore ... write-once, fsync of file and directory, temporary file removed on
    failure"; append "checks every blob ... then writes the blobs, then the row"."""
    led = Ledger(tmp_path / "ledger.sqlite")
    bid, ev = _blob_evidence()
    refused = fail_replace(monkeypatch, {bid}, ENOSPC)
    with pytest.raises(OSError) as info:
        led.append({"kind": "verify_ok", "detail": {"evidence": ev}})
    assert info.value.errno == ENOSPC and refused
    assert led.tail(0) == [] and led.blob(bid) is None
    assert tmp_leftovers(tmp_path / "evidence" / "blobs") == []


def test_a_read_only_blob_directory_refuses_the_verify_ok_row_and_the_verification(tmp_path):
    """Amendment 5.2: a verify_ok row that cannot be written refuses the verification (fault: EACCES on the
    blob directory, a read-only mount)."""
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock"})
    blobs = tmp_path / "evidence" / "blobs"
    blobs.mkdir(parents=True)
    bid, ev = _blob_evidence()
    r = _result()
    r = VerificationResult(**{**r.__dict__, "evidence": ev})
    cache, ad, _ = _cache(tmp_path, led, FakeAdapter([r]))
    with chmod_ro(blobs):
        ok, reason, _ = cache.ensure(P)
    assert ok is False and LOST in reason
    assert [k for k, _ in _kinds(led)] == ["lock", "verify_fail"]
    assert not (blobs / bid).exists()


def test_a_symlink_planted_at_a_blob_path_is_replaced_never_written_through(tmp_path):
    """Amendment 5.2: a blob is "named by the SHA-256 of its UTF-8 text"; get returns None for bytes that are
    not its id, so a planted link to other bytes is rewritten, and its target is left untouched."""
    led = Ledger(tmp_path / "ledger.sqlite")
    bid, ev = _blob_evidence()
    blobs = tmp_path / "evidence" / "blobs"
    blobs.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("attacker bytes")
    (blobs / bid).symlink_to(outside)
    led.append({"kind": "verify_ok", "detail": {"evidence": ev}})
    assert not (blobs / bid).is_symlink()
    assert led.blob(bid) == ev["blobs"][bid]
    assert outside.read_text() == "attacker bytes"


@pytest.mark.parametrize("damage", ["missing", "truncated", "wrong_bytes", "directory"])
def test_a_damaged_blob_is_named_missing_in_the_receipt_and_fails_the_replay(tmp_path, damage):
    """Amendment 5.2: "each evidence[] item ... gains blobs and, when any is absent or altered, blobs_missing";
    BlobStore.get "returns None for a missing blob or one whose bytes are not its id", "so a replay that
    needs it fails closed"."""
    pytest.importorskip("tinfoil.attestation.verify_tdx")
    from confidential_mode.receipts import build_receipt
    from confidential_mode.verify import replay_near
    from tests.unit import test_near_real_capture as real
    from tests.unit.test_near_evidence_blobs import _row, _verified_evidence
    ev = _verified_evidence(real.evidence())
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "session_id": "s", "detail": {}})
    led.append(_row(ev))
    ref = ev["model_reports"][real.MODEL][0]["compose_manager"]["blob"]
    p = tmp_path / "evidence" / "blobs" / ref
    if damage == "missing":
        p.unlink()
    elif damage == "truncated":
        truncate(p, 0.5)
    elif damage == "wrong_bytes":
        p.write_text(ev["blobs"][ref].replace("compose_up", "compose_down", 1))
    else:
        p.unlink()
        p.mkdir()
    doc = json.loads(json.dumps(build_receipt(led, "s")))
    item = doc["evidence"][0]
    assert item["blobs_missing"] == [ref]
    r = replay_near.replay(replay_near.with_blobs(item["evidence"], item["blobs"]))
    assert r.ok is False
    assert "blob is missing or does not hash to its id" in r.checks["cm_quote"]


# ── pins.yaml ────────────────────────────────────────────────────────────────────────────────────

class _Asker:
    def __init__(self, pick="approve", during=None):
        self.pick, self.during, self.asked = pick, during, 0

    def ask_choice(self, q, choices):
        self.asked += 1
        if self.during:
            self.during()
        return self.pick


def _staged(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    return store


@pytest.mark.parametrize("err", [ENOSPC, EACCES])
def test_a_failed_pins_write_on_approve_is_a_denial_and_the_file_keeps_the_pending_batch(tmp_path, monkeypatch, err):
    """Amendment 3 addendum: "store.apply raising is ledgered as pin_denied with the error type"; consent:
    "apply a batch only ... if it is still the one the human saw"; pins writes are atomic (temp file removed)."""
    store = _staged(tmp_path)
    before = (tmp_path / "pins.yaml").read_bytes()
    led = Ledger(tmp_path / "ledger.sqlite")
    fail_replace(monkeypatch, {"pins.yaml"}, err)
    out = consent.approve_pending_pin(_Asker(), store, led, session_key="k", session_id="s", platform="cli")
    name = "OSError" if err == ENOSPC else "PermissionError"      # OSError(EACCES) is a PermissionError
    assert out == f"The pin could not be applied ({name}); the current pin is unchanged."
    assert (tmp_path / "pins.yaml").read_bytes() == before
    assert store.pending() is not None and store.approved_entries() == []
    assert _kinds(led) == [("pin_denied", "apply_failed")]
    assert led.tail(0)[0].detail["error"] == name
    assert tmp_leftovers(tmp_path) == []


def test_a_read_only_data_directory_refuses_the_pin_apply(tmp_path):
    """Amendment 3 addendum: store.apply raising is pin_denied; the pending batch is kept for a later approve."""
    store = _staged(tmp_path)
    led_dir = tmp_path / "led"
    led = Ledger(led_dir / "ledger.sqlite")
    with chmod_ro(tmp_path):
        out = consent.approve_pending_pin(_Asker(), store, led, session_key="k", session_id="s", platform="cli")
    assert "could not be applied" in out
    assert store.pending() is not None and store.approved_entries() == []
    assert _kinds(led) == [("pin_denied", "apply_failed")]


@pytest.mark.parametrize("damage", ["directory", "truncated", "empty", "binary"])
def test_a_damaged_pins_file_matches_nothing_and_the_attested_check_refuses(tmp_path, damage):
    """pins.match: "An unreadable, corrupt, truncated or unknown-version file matches nothing"; a stage that
    cannot read the store refuses and stages nothing (provider._stage)."""
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    p = tmp_path / "pins.yaml"
    if damage == "directory":
        p.unlink()
        p.mkdir()
    elif damage == "truncated":
        truncate(p, 0.5)
    elif damage == "empty":
        p.write_bytes(b"")
    else:
        p.write_bytes(os.urandom(512))
    assert store.match(_result()) is False
    led = Ledger(tmp_path / "ledger.sqlite")
    cache = provider_mod.VerificationCache()
    ad = FakeAdapter([_result()])
    cache.register(P, ad, store, 300.0, on_event=led.append)
    ok, reason, _ = cache.ensure(P)
    assert ok is False
    assert reason in (provider_mod.REASON_NO_PIN, provider_mod.REASON_PIN_MISMATCH, provider_mod.REASON_BAD_RESULT)
    assert ad.held_reason


V3_OK = None


def _v3_text(tmp_path):
    s = PinStore(tmp_path / "v3src" / "pins.yaml")
    s.apply(s.stage(_result()), approved_via="cli")
    return (tmp_path / "v3src" / "pins.yaml").read_text()


@pytest.mark.parametrize("body", [
    "version: 1\npins: {}\n", "version: 4\nidentities: []\n", "version: '3'\nidentities: []\n",
    "version: 3.0\nidentities: []\n", "version: true\nidentities: []\n", "version: null\n", "- 3\n- 2\n",
    "version: 3\nidentities: {not: a list}\n", "version: 2\nidentities: []\npins: {}\n", "version: [3\n",
    "{{{{", "\x00\x01\x02", "version: 3\nidentities:\n  - 7\n",
    "a: &a [x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b]\n"
    "d: &d [*c, *c, *c, *c, *c, *c, *c, *c]\nversion: 3\nidentities: [*d, *d, *d, *d]\n",
])
def test_garbage_and_unknown_pins_versions_match_nothing_and_are_never_overwritten(tmp_path, body):
    """Amendment 7: "A file that says version 2 but holds identities is refused ...; any other version matches
    nothing and is never overwritten"; PinStoreError: "Callers fail closed"."""
    p = tmp_path / "pins.yaml"
    p.write_text(body)
    before = p.read_bytes()
    store = PinStore(p)
    t0 = time.monotonic()
    assert store.match(_result()) is False
    with pytest.raises(PinStoreError):
        store.load_file()
    with pytest.raises(PinStoreError):
        store.stage(_result())
    store.observe(_result())                   # never raises, writes nothing
    assert p.read_bytes() == before
    assert time.monotonic() - t0 < 1.5


def test_supported_versions_still_match_beside_the_garbage(tmp_path):
    """Amendment 7 migration: "a version-2 file reads as version 3 in memory" and a v3 file matches its pins
    (the control for the garbage cases above)."""
    from tests.unit.test_pins_v3 import LIVE, V170, _tinfoil
    p2 = tmp_path / "v2" / "pins.yaml"
    p2.parent.mkdir()
    p2.write_bytes(LIVE.read_bytes())
    assert PinStore(p2).match(_tinfoil(*V170, "v0.0.170")) is True
    p3 = tmp_path / "pins.yaml"
    p3.write_text(_v3_text(tmp_path))
    assert PinStore(p3).match(_result()) is True


def test_a_symlinked_pins_file_is_replaced_on_write_never_written_through(tmp_path):
    """pins._write_atomic writes a temporary file and os.replace()s it, so a planted link is replaced and the
    file it pointed at keeps its bytes (no write lands outside the data directory)."""
    outside = tmp_path / "elsewhere.yaml"
    src = _v3_text(tmp_path)
    outside.write_text(src)
    (tmp_path / "pins.yaml").symlink_to(outside)
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c9", enclave="e9"))
    assert not (tmp_path / "pins.yaml").is_symlink()
    assert outside.read_text() == src


# ── allowlist.yaml and state.json through the loaded plugin ──────────────────────────────────────

def _llm_mw(plugin):
    return plugin.mgr._middleware["llm_execution"][0]


def _hook(plugin, name):
    return plugin.mgr._hooks[name][0]


def _main_call(plugin, base_url=REMOTE, provider="custom"):
    sent = []
    out = _llm_mw(plugin)(request={"messages": [{"role": "user", "content": "SECRET"}]},
                          next_call=lambda req: sent.append(req) or "provider-response", provider=provider,
                          base_url=base_url, model="m", api_mode="chat_completions", session_id="s1")
    return out, sent


def _state_path(plugin):
    return plugin.rt.ctx.state.path


@pytest.mark.parametrize("err", [ENOSPC, EACCES])
def test_an_unwritable_allowlist_refuses_the_lock(plugin, monkeypatch, err):
    """Amendment 6 finding 9: "locking.lock computes the lock id ..., persists the allowlist, and only then sets
    the locked flag; a failed persist refuses the lock"."""
    fail_replace(monkeypatch, {"allowlist.yaml"}, err)
    out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked: the tool allowlist could not be written"), out
    assert plugin.rt.state.locked() == (False, None)
    assert ("preflight_fail", "refused") in plugin.kinds()
    assert ("lock", "locked") not in plugin.kinds()
    assert tmp_leftovers(plugin.rt.allowlist_path.parent) == []


def test_a_read_only_data_directory_refuses_the_lock(plugin):
    """Amendment 6 finding 9: a failed allowlist persist refuses the lock, before any lock flag is written."""
    plugin.rt.ledger.append({"kind": "session_start"})            # the ledger file exists before the chmod
    d = plugin.rt.allowlist_path.parent
    d.mkdir(parents=True, exist_ok=True)
    with chmod_ro(d):
        out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked"), out
    assert plugin.rt.state.locked() == (False, None)


def test_an_allow_whose_write_fails_grants_nothing(plugin, monkeypatch):
    """Amendment 3: "additions persist in allowlist.yaml through Allowlist.add"; Amendment 10: Allowlist.add
    "starts from the names on disk for its lock under that lock". A grant the file does not hold must not
    apply. Fault: ENOSPC on the allowlist.yaml rename after a human picked Allow."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    answer_choice(plugin, monkeypatch, "approve")
    fail_replace(monkeypatch, {"allowlist.yaml"}, ENOSPC)
    out = plugin.slash("allow web_search")
    assert not out.endswith("added to the allowlist for this lock.")
    assert out.startswith("web_search was not added: the grant could not be recorded"), out
    assert "will ask again" in out                             # the person is told the allow failed
    assert ("tool_refused", "allowlist_write_failed") in plugin.kinds()
    ran = []
    mw = plugin.mgr._middleware["tool_execution"][0]
    mw(tool_name="web_search", args={"query": "q"}, next_call=lambda a: ran.append(a) or "{}", session_id="s1",
       tool_call_id="c-after")
    assert ran == [], "web_search ran without a prompt on a grant the reply said had failed"
    assert plugin.rt.allowlist().is_added("web_search") is False


@pytest.mark.parametrize("damage", ["truncated", "directory"])
def test_a_damaged_allowlist_after_lock_blocks_every_tool_until_relock(plugin, damage):
    """Amendment 4 F5 (load_persisted): "A missing, corrupt or other-lock file yields an empty allowlist: every
    tool blocked"; Amendment 3: unknown names "block (hook) and refuse (middleware)"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    p = plugin.rt.allowlist_path
    if damage == "truncated":
        truncate(p, 0.4)
    else:
        p.unlink()
        p.mkdir()
    plugin.rt.set_allowlist(None)                                 # a restarted gateway: nothing cached
    ran = []
    mw = plugin.mgr._middleware["tool_execution"][0]
    out = mw(tool_name="read_file", args={"path": "/tmp/x"}, next_call=lambda a: ran.append(a) or "ok",
             session_id="s1", tool_call_id="c1")
    assert ran == [] and json.loads(out)["error"]
    assert any(e.kind == "tool_refused" and e.decision == "unclassified" for e in rows(plugin))


@pytest.mark.parametrize("damage", ["truncated", "directory", "garbage"])
def test_an_unreadable_state_file_fails_every_gate_closed(plugin, damage):
    """Amendment 2: "Corrupt lock state: the gate refuses every send until /confidential status or off repairs
    it ... the refusal text must name the command"; Amendment 3: "Unreadable lock state blocks every tool,
    including on-host ones"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    p = _state_path(plugin)
    if damage == "truncated":
        truncate(p, 0.5)
    elif damage == "garbage":
        p.write_bytes(b"\xff\xfe not json")
    else:
        p.unlink()
        p.mkdir()
    out, sent = _main_call(plugin, base_url=ON_HOST_URL)
    assert sent == [] and out.choices[0].message.content == TEXT_STATE_UNREADABLE
    assert "/confidential off" in TEXT_STATE_UNREADABLE
    block = _hook(plugin, "pre_llm_call")(session_id="s1")
    assert block == {"action": "block", "message": TEXT_STATE_UNREADABLE}
    d = _hook(plugin, "pre_tool_call")(tool_name="read_file", args={"path": "/tmp/x"}, session_id="s1",
                                        tool_call_id="c1")
    assert d["action"] == "block"
    assert ("send_refused", "refused") in plugin.kinds()
    assert any(e.kind == "tool_refused" and e.decision == "lock_state_unreadable" for e in rows(plugin))


@pytest.mark.parametrize("damage", ["truncated", "garbage"])
def test_confidential_off_repairs_an_unreadable_state_file(plugin, damage):
    """Amendment 2: "the gate refuses every send until /confidential status or off repairs it"; status text:
    "Run /confidential off to repair it"; locking.unlock: "Clear the lock (also repairs unreadable lock
    state)"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    p = _state_path(plugin)
    if damage == "truncated":
        truncate(p, 0.5)
    else:
        p.write_bytes(b"\xff\xfe not json")
    assert "UNREADABLE" in plugin.slash("status")
    out = plugin.slash("off")
    assert out.startswith("Lock state was unreadable; it is now cleared"), out
    assert plugin.rt.state.locked() == (False, None)


def test_the_repaired_state_file_is_private_and_gates_read_it_again(plugin):
    """FI-3: the replacement state.json is mode 0600 and parses, so a later status and lock work normally."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    p = _state_path(plugin)
    p.write_bytes(b"{\"locked\": tr")
    assert plugin.slash("off").startswith("Lock state was unreadable; it is now cleared")
    assert os.stat(p).st_mode & 0o777 == 0o600
    assert json.loads(p.read_text()) == {"locked": False}
    assert plugin.slash("on on-host-only").startswith("Locked")


def test_a_state_path_that_is_a_directory_is_not_replaced_and_stays_closed(plugin):
    """FI-3: only a regular file that does not parse is replaced; a directory in its place is left alone, the
    off reply is an error, and every gate still fails closed."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    p = _state_path(plugin)
    p.unlink()
    p.mkdir()
    out = plugin.slash("off")
    assert not out.startswith(("Unlocked", "Lock state was unreadable")), out
    assert p.is_dir()
    block = _hook(plugin, "pre_llm_call")(session_id="s1")
    assert block == {"action": "block", "message": TEXT_STATE_UNREADABLE}


def test_a_state_write_that_fails_on_unlock_keeps_the_lock_and_says_so(plugin, monkeypatch):
    """Fail closed: locking.unlock clears the flag with one state write; when it fails the profile stays locked,
    the reply is not "Unlocked", and every off-tier send is still refused."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    fault = fail_replace(monkeypatch, {"state.json"}, ENOSPC)
    out = plugin.slash("off")
    assert not out.startswith("Unlocked"), out
    assert "error" in out.lower()
    fault.stop()
    assert plugin.rt.state.locked()[0] is True
    out, sent = _main_call(plugin)
    assert sent == [] and out.choices[0].message.content.startswith("Confidential mode: locked to on-host-only")
    assert ("unlock", "unlocked") not in plugin.kinds()


def test_a_state_write_that_fails_on_lock_leaves_the_profile_unlocked_and_unclaimed(plugin, monkeypatch):
    """locking.lock sets the flag last ("Tier first, flag last: a crash between writes leaves the profile
    unlocked-with-a-tier, never locked-without-one"); no lock row is written for a lock that did not happen."""
    fault = fail_replace(monkeypatch, {"state.json"}, ENOSPC)
    out = plugin.slash("on on-host-only")
    assert not out.startswith("Locked"), out
    fault.stop()
    assert plugin.rt.state.locked() == (False, None)
    assert ("lock", "locked") not in plugin.kinds()


def test_a_lock_refused_by_a_state_write_failure_is_ledgered_and_cleaned_up(plugin, monkeypatch):
    """locking.lock: "Lock the profile to tier or refuse with the reason. Never raises for a refusal"; every
    other refusal there writes a preflight_fail row (purpose lock:*) and the allowlist is written for a lock
    only (Amendment 4 F6, grants never outlive the lock)."""
    fault = fail_replace(monkeypatch, {"state.json"}, ENOSPC)
    out = plugin.slash("on on-host-only")
    fault.stop()
    assert out.startswith("Not locked"), out
    assert any(k == "preflight_fail" and r for k, r in plugin.kinds())
    assert not plugin.rt.allowlist_path.exists()


def test_a_lock_refused_by_a_state_write_failure_keeps_another_locks_allowlist(plugin, monkeypatch):
    """FI-4: the cleanup removes allowlist.yaml only while the file is still the refused lock's own."""
    locking = cm(plugin, "locking")
    rt = plugin.rt
    other = {"version": 2, "lock_id": "another-lock", "tools": [], "allowed": []}

    class Racing:
        def __init__(self, state):
            self._s = state

        def __getattr__(self, n):
            return getattr(self._s, n)

        def lock(self, *a, **k):
            rt.allowlist_path.write_text(json.dumps(other))   # another lock replaced the file meanwhile
            raise OSError(28, "No space left on device")
    out = locking.lock("on-host-only", state=Racing(rt.state), ledger=rt.ledger, config=rt.load_config(),
                       allowlist_path=rt.allowlist_path, surface="cli")
    assert out.ok is False and out.message.startswith("Not locked: the lock state could not be written"), out
    assert json.loads(rt.allowlist_path.read_text())["lock_id"] == "another-lock"
    assert any(e.kind == "preflight_fail" and e.purpose == "lock:state" for e in rows(plugin))


# ── grants_revoked.json (revoke) ─────────────────────────────────────────────────────────────────

def test_an_unwritable_revocation_record_makes_revoke_fail_loudly(plugin, monkeypatch):
    """Amendment 10: revoke "failed covers ... an allowlist.yaml or record write error ...; the reply then starts
    'Revoke failed for' ... The row's decision gets a _failed suffix and the detail carries errors"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    fail_replace(monkeypatch, {"grants_revoked.json"}, ENOSPC)
    out = plugin.slash("revoke web_search")
    assert out.startswith("Revoke failed for web_search"), out
    row = [e for e in rows(plugin) if e.kind == "grant_revoked"][-1]
    assert row.decision == "revoke_failed" and row.detail["errors"]


@pytest.mark.parametrize("damage", ["truncated", "directory", "garbage"])
def test_a_damaged_revocation_file_never_breaks_a_gate_decision(plugin, damage):
    """Amendment 10: "A forged or corrupt record can only take grants away, and the watcher never raises";
    RevocationWatcher.apply runs "before every gate decision"."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    assert plugin.slash("revoke web_search").startswith(("Nothing to revoke", "Revoked"))
    p = plugin.rt.allowlist_path.parent / "grants_revoked.json"
    if damage == "truncated":
        truncate(p, 0.5)
    elif damage == "garbage":
        p.write_bytes(b"\x00garbage{")
    else:
        p.unlink()
        p.mkdir()
    mw = plugin.mgr._middleware["tool_execution"][0]
    ran = []
    out = mw(tool_name="todo_list", args={}, next_call=lambda a: ran.append(a) or "{\"ok\": 1}", session_id="s1",
             tool_call_id="c1")
    assert ran == [{}] and out == "{\"ok\": 1}"           # an on-host tool still runs
    ran.clear()
    mw(tool_name="cronjob_manage", args={}, next_call=lambda a: ran.append(a), session_id="s1", tool_call_id="c2")
    assert ran == []                                       # a hard block still blocks

"""Fault class 2, processes and threads: two locks at once, a lock or unlock from another process while the
gateway holds a cached allowlist, a CLI approve racing a gateway verify, a background refresh that raises,
hangs or outlives the unlock, a process killed while it holds the pins lock or writes pins.yaml, a refresh
thread leaking across relocks, and KeyboardInterrupt inside a gate. Real PinStore, Ledger, lock code and
VerificationCache; another process is either a real subprocess or a second set of objects over the same
files (which is all two processes share).
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from confidential_mode import consent, filelock, provider as provider_mod
from confidential_mode.gate_llm import LlmGate
from confidential_mode.gate_tools import ApprovalDecisions, Allowlist, build_pre_tool_call, build_tool_execution
from confidential_mode.ledger import Ledger
from confidential_mode.locking import predicate_for
from confidential_mode.pins import PinStore, PinStoreError
from confidential_mode.verify.base import PreparedVerification

from tests.hostile._harness_integrated import answer_choice, cm, rows  # noqa: F401
from tests.seam._harness import no_lazy_installs  # noqa: F401  (fixture)
from tests.seam.test_register import ON_HOST_URL, plugin  # noqa: F401  (fixture)
from tests.unit.test_background_refresh import Clock, FakeAdapter, _result

P = provider_mod.PROFILE_NAME
PLUGIN_ROOT = Path(__file__).resolve().parents[2]


def _kinds(ledger):
    return [(r.kind, r.decision) for r in ledger.tail(0, limit=10000)]


# ── two processes locking, locking against unlocking ─────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="FI-5: locking.lock checks 'already locked' and writes the lock without a "
                                       "lock held across both, so two concurrent locks both report Locked")
def test_two_concurrent_locks_one_of_them_wins(plugin):
    """locking.lock: an existing lock is refused ("Already locked ... Run /confidential off first, then lock
    again"); Amendment 6 finding 9 orders the writes so another process "that sees the new lock always finds
    its allowlist on disk". Fault: a CLI `hermes confidential on` and a gateway `/confidential on` interleave."""
    locking, gt = cm(plugin, "locking"), cm(plugin, "gate_tools")
    rt = plugin.rt
    inside, go = threading.Event(), threading.Event()

    def slow_builder(*a, **k):
        inside.set()
        assert go.wait(5)
        return gt.build_allowlist(*a, **k)

    out = {}

    def cli():
        out["cli"] = locking.lock("on-host-only", state=rt.state, ledger=rt.ledger, config=rt.load_config(),
                                  allowlist_path=rt.allowlist_path, allowlist_builder=slow_builder, surface="cli")
    t = threading.Thread(target=cli, daemon=True)
    t.start()
    assert inside.wait(5)
    gateway = plugin.slash("on on-host-only")          # the gateway locks while the CLI is mid-lock
    go.set()
    t.join(5)
    oks = [gateway.startswith("Locked"), out["cli"].ok]
    assert oks.count(True) == 1, f"both locked: gateway={gateway[:30]!r} cli={out['cli'].message[:30]!r}"
    assert [k for k, _ in plugin.kinds()].count("lock") == 1


def test_a_cli_unlock_reaches_the_gateway_on_its_next_call(plugin):
    """commands.cli_verb: "state is re-read from disk on every gate call, so a lock or unlock here takes effect
    on the gateway's next turn"; Amendment 6: "/confidential off removes allowlist.yaml before clearing the lock
    flag". Fault: another process clears the lock while the gateway holds a cached allowlist."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    rt = plugin.rt
    assert rt.allowlist().tools                                   # the gateway's cached allowlist
    locking, gt, state = cm(plugin, "locking"), cm(plugin, "gate_tools"), cm(plugin, "state")
    other = state.ConfidentialState(rt.ctx.state)                 # the CLI's own view of the same file
    gt.clear_persisted(rt.allowlist_path, lock_id=gt.lock_id_for(other))
    cli_ledger = cm(plugin, "ledger").Ledger()                    # the CLI process opens the same file
    res = locking.unlock(state=other, ledger=cli_ledger, surface="cli", clear_cache=lambda: None)
    assert res.ok and res.message.startswith("Unlocked (on-host-only)"), res.message
    assert [r.kind for r in cli_ledger.tail(0)][-1] == "unlock"
    sent = []
    mw = plugin.mgr._middleware["llm_execution"][0]
    out = mw(request={"m": 1}, next_call=lambda r: sent.append(r) or "provider-response", provider="custom",
             base_url="https://llm.example.test/v1", model="m", api_mode="chat_completions", session_id="s")
    assert out == "provider-response" and len(sent) == 1         # unlocked now: observed and sent
    assert rt.allowlist().tools == {}
    assert ("unlock", "unlocked") in plugin.kinds()
    assert any(e.kind == "send_observed" and e.decision == "observed" for e in rows(plugin))


def test_a_cli_lock_reaches_a_gateway_that_cached_unlocked(plugin, monkeypatch):
    """Runtime.allowlist: "After a restart, or a lock made by another process, it is rebuilt from the identities
    persisted at that lock"; an off-host tool on the gateway then asks or blocks, never runs unasked."""
    rt = plugin.rt
    assert rt.allowlist().tools == {}                             # unlocked, nothing classified
    locking, state = cm(plugin, "locking"), cm(plugin, "state")
    other = state.ConfidentialState(rt.ctx.state)
    res = locking.lock("on-host-only", state=other, ledger=rt.ledger, config=rt.load_config(),
                       allowlist_path=rt.allowlist_path, surface="cli")
    assert res.ok, res.message
    ran = []
    mw = plugin.mgr._middleware["tool_execution"][0]
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    out = mw(tool_name="web_search", args={"query": "q"}, next_call=lambda a: ran.append(a) or "{}",
             session_id="s1", tool_call_id="c1")
    assert ran == [] and json.loads(out)["error"]
    assert any(e.kind == "tool_refused" and e.decision in ("no_surface", "denied", "bypass_active")
               for e in rows(plugin))


# ── a CLI approve racing a gateway verify ────────────────────────────────────────────────────────

def test_a_cli_approve_racing_a_gateway_restage_applies_nothing(tmp_path):
    """INTERFACES W4: "re-check pending equality before apply"; "pending swapped during wait -> not applied";
    Amendment 7: approve compares consent keys. Fault: while the person reads the CLI prompt, the gateway's
    verification (its own PinStore object on the same pins.yaml) stages a different build."""
    cli_store, gw_store = PinStore(tmp_path / "pins.yaml"), PinStore(tmp_path / "pins.yaml")
    cli_store.stage(_result(code="c2", enclave="e2"))
    led = Ledger(tmp_path / "ledger.sqlite")

    class Asker:
        def ask_choice(self, q, choices):
            t = threading.Thread(target=lambda: gw_store.stage(_result(code="c3", enclave="e3")))
            t.start()
            t.join(5)
            return "approve"
    out = consent.approve_pending_pin(Asker(), cli_store, led, session_key="cli", session_id="", platform="cli")
    assert out.startswith("The pending pin changed while you were deciding, so nothing was applied.")
    assert cli_store.approved_entries() == []
    assert gw_store.pending().code_fingerprint == "c3"
    assert _kinds(led) == [("pin_denied", "stale")]


def test_two_processes_approving_one_batch_pin_it_once(tmp_path):
    """Amendment 3 addendum: "concurrent approvals for one pending pin apply exactly once (consent holds a lock
    around re-check and apply; PinStore.apply is additionally idempotent)". Two PinStore objects stand in for
    two processes; only the pins.yaml.lock flock and the file are shared."""
    a, b = PinStore(tmp_path / "pins.yaml"), PinStore(tmp_path / "pins.yaml")
    a.stage(_result(code="c2", enclave="e2"))
    led = Ledger(tmp_path / "ledger.sqlite")
    barrier = threading.Barrier(2)

    class Asker:
        def ask_choice(self, q, choices):
            barrier.wait(5)
            return "approve"
    outs = []
    ts = [threading.Thread(target=lambda s=s: outs.append(consent.approve_pending_pin(
        Asker(), s, led, session_key="k", session_id="", platform="cli"))) for s in (a, b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert len(outs) == 2
    approved = a.approved_entries()
    assert len(approved) == 1 and approved[0].code_fingerprint == "c2"
    assert a.pending() is None


# ── the background refresh: raising, hanging, outliving the unlock, leaking across relocks ──────

class _Gated(FakeAdapter):
    """prepare_verification blocks on ``gate`` (a capture that hangs) after the first, inline, verification."""

    def __init__(self, queue):
        super().__init__(queue)
        self.gate = threading.Event()
        self.hang = False

    def prepare_verification(self):
        if self.hang:
            self.in_capture.set()
            self.gate.wait(10)
        return super().prepare_verification()


def _bg(tmp_path, queue, adapter_cls=FakeAdapter, *, verify_wait=0.2):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    led = Ledger(tmp_path / "ledger.sqlite")
    clock = Clock()
    cache = provider_mod.VerificationCache(clock=clock)
    state = {"locked": True}
    cache.active = lambda: state["locked"]
    cache.refresh_poll_seconds = 0.01
    ad = adapter_cls(queue)
    cache.register(P, ad, store, 300.0, on_event=led.append, failure_backoff_seconds=30.0,
                   verify_wait_seconds=verify_wait, refresh_lead_seconds=60.0)
    return cache, ad, led, clock, state


def _wait(pred, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


def test_a_background_capture_that_raises_writes_verify_fail_and_keeps_the_verification_in_use(tmp_path):
    """Amendment 9: "A failed capture writes verify_fail with source: background"; "A failed capture ... changes
    nothing: the verification in use keeps vouching until its TTL ends". Fault: the vendor raises mid-capture,
    on the refresh's own daemon thread."""
    from confidential_mode.verify.base import VerifyError
    first = _result()
    cache, ad, led, clock, _ = _bg(tmp_path, [first, VerifyError("HTTP 500 from the attestation endpoint")])
    assert cache.ensure(P)[0] is True
    clock.t = 250.0
    assert cache.ensure(P)[0] is True                       # a recent use inside the lead window
    assert _wait(lambda: any(r.kind == "verify_fail" for r in led.tail(0)))
    fail = [r for r in led.tail(0) if r.kind == "verify_fail"][-1]
    assert fail.detail["source"] == "background" and "HTTP 500" in fail.detail["error"]
    assert cache.entry(P).result is first and ad.send() == "c1"
    clock.t = 301.0                                          # TTL over: inline verify; the queue still raises
    ok, reason, _ = cache.ensure(P)
    assert ok is False and "HTTP 500" in reason
    cache.stop_refresh()


def test_a_hung_background_capture_never_blocks_a_send_past_the_bound_and_is_discarded_after_unlock(tmp_path):
    """Amendment 4: create_client refuses within verify_wait_seconds when verification is pending; Amendment 9:
    "invalidate() (unlock ...) ... stop the thread; a capture in progress finishes and is discarded". Fault: the
    vendor never answers the background capture; the TTL runs out under it; then the profile is unlocked."""
    second = _result()
    cache, ad, led, clock, state = _bg(tmp_path, [_result(), second], _Gated)
    assert cache.ensure(P)[0] is True
    ad.hang = True
    clock.t = 250.0
    assert cache.ensure(P)[0] is True
    assert ad.in_capture.wait(3)
    clock.t = 301.0                                          # expired while the capture hangs
    t0 = time.monotonic()
    ok, reason, _ = cache.ensure(P)
    assert ok is False and reason == provider_mod.REASON_VERIFY_PENDING
    assert time.monotonic() - t0 < 1.0
    assert ad.held_reason == provider_mod.REASON_VERIFY_PENDING
    state["locked"] = False                                  # unlock
    cache.invalidate(P)
    ad.hang = False
    ad.gate.set()
    r = cache.entry(P).refresher
    assert _wait(lambda: not r.thread.is_alive())
    bg_ok = [x for x in led.tail(0) if x.kind == "verify_ok" and x.detail.get("source") == "background"]
    assert bg_ok == [], "a capture that finished after the unlock was recorded as a verification"
    assert second in ad.discarded or r.outcomes in ([], ["discarded"], ["busy"])


def test_the_refresh_thread_does_not_leak_across_relocks(tmp_path):
    """Amendment 9: one daemon thread per cache entry, "invalidate() (unlock ...) ... stop the thread"; a
    relock starts at most one new one. Fault: lock, unlock, relock repeatedly with verifications between."""
    cache, ad, led, clock, state = _bg(tmp_path, [_result()])
    for _ in range(4):
        state["locked"] = True
        assert cache.ensure(P)[0] is True
        state["locked"] = False
        cache.invalidate(P)
    state["locked"] = True
    assert cache.ensure(P)[0] is True
    name = f"confidential-refresh-{P}"
    assert _wait(lambda: sum(1 for t in threading.enumerate() if t.name == name and t.is_alive()) <= 1)
    alive = [t for t in threading.enumerate() if t.name == name and t.is_alive()]
    assert len(alive) <= 1 and (not alive or alive[0] is cache.entry(P).refresher.thread)
    cache.stop_refresh()
    assert _wait(lambda: not any(t.name == name and t.is_alive() for t in threading.enumerate()))


# ── a process killed holding the pins lock, or mid-write ─────────────────────────────────────────

_HOLDER = textwrap.dedent("""
    import fcntl, sys, time
    fh = open(sys.argv[1], "a")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    print("held", flush=True)
    time.sleep(30)
""")


def _hold_lock(path: Path):
    p = subprocess.Popen([sys.executable, "-c", _HOLDER, str(path)], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "held"
    return p


def test_a_pins_lock_held_by_another_process_refuses_the_mutation_within_the_bound(tmp_path, monkeypatch):
    """Amendment 10: "A lock still held raises LockBusy naming the lock file ... a pin mutation raises
    PinStoreError, so a process holding a lock file cannot hang"; the pins file is unchanged."""
    monkeypatch.setattr(filelock, "INTERVAL_SECONDS", 0.02)
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    before = (tmp_path / "pins.yaml").read_bytes()
    holder = _hold_lock(tmp_path / "pins.yaml.lock")
    try:
        t0 = time.monotonic()
        with pytest.raises(PinStoreError, match="pins.yaml.lock"):
            store.apply(store.pending(), approved_via="cli")
        assert time.monotonic() - t0 < 1.5
        assert (tmp_path / "pins.yaml").read_bytes() == before
    finally:
        holder.kill()
        holder.wait(5)


def test_a_sigterm_to_the_process_holding_the_pins_lock_releases_it(tmp_path, monkeypatch):
    """Amendment 10: the pins lock is an advisory flock on pins.yaml.lock; a terminated holder's lock is gone
    with it, so the next approval applies (no stale lock file blocks it)."""
    monkeypatch.setattr(filelock, "INTERVAL_SECONDS", 0.02)
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    holder = _hold_lock(tmp_path / "pins.yaml.lock")
    holder.send_signal(signal.SIGTERM)
    assert holder.wait(5) == -signal.SIGTERM
    assert (tmp_path / "pins.yaml.lock").exists()                  # the file stays; only the flock is gone
    store.apply(store.pending(), approved_via="cli")
    assert store.approved_entries()[0].code_fingerprint == "c2"


_WRITER = textwrap.dedent("""
    import os, sys, time
    sys.path.insert(0, sys.argv[2])
    from confidential_mode.pins import PinStore
    from confidential_mode.verify.base import VerificationResult
    real = os.fsync
    def slow(fd):
        print("writing", flush=True)
        time.sleep(30)
    os.fsync = slow
    r = VerificationResult(vendor="tinfoil", router_repo="tinfoilsh/confidential-model-router",
                           enclave_host="r.example", code_fingerprint="c9", enclave_fingerprint="e9",
                           release_tag="v9", verifier="t", verified_at_host_clock=0.0, evidence={})
    PinStore(sys.argv[1]).stage(r)
""")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGKILL])
def test_a_process_killed_while_writing_pins_leaves_the_previous_file_whole(tmp_path, sig):
    """pins.save_file: "Atomic version-3 write" (temporary file, fsync, os.replace); a writer killed before the
    replace leaves pins.yaml as it was, still matching, and its temporary file is all that is left."""
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    before = (tmp_path / "pins.yaml").read_bytes()
    w = subprocess.Popen([sys.executable, "-c", _WRITER, str(tmp_path / "pins.yaml"), str(PLUGIN_ROOT)],
                         stdout=subprocess.PIPE, text=True)
    try:
        assert w.stdout.readline().strip() == "writing"
        w.send_signal(sig)
        w.wait(5)
    finally:
        if w.poll() is None:
            w.kill()
    assert (tmp_path / "pins.yaml").read_bytes() == before
    assert store.match(_result()) is True
    store.stage(_result(code="c2", enclave="e2"))                    # the next writer is not blocked
    assert store.pending().code_fingerprint == "c2"


# ── KeyboardInterrupt inside a gate ──────────────────────────────────────────────────────────────

def _interrupt():
    raise KeyboardInterrupt


def test_keyboard_interrupt_in_the_llm_gate_propagates_and_sends_nothing(tmp_path):
    """gate_llm: "nothing the gate itself raises may escape" covers Exception; KeyboardInterrupt and SystemExit
    re-raise (LlmGate.__call__), and Hermes' middleware chain does not catch BaseException, so the call ends
    with no provider request."""
    led = Ledger(tmp_path / "ledger.sqlite")
    gate = LlmGate(ledger=led, is_locked=_interrupt, predicate_for=lambda t: predicate_for(t, config={}),
                   attested_ok=lambda p: None)
    sent = []
    with pytest.raises(KeyboardInterrupt):
        gate({"m": 1}, lambda r: sent.append(r), provider="custom", base_url=ON_HOST_URL, model="m",
             api_mode="chat_completions", session_id="s")
    assert sent == []


def test_keyboard_interrupt_in_the_tool_gates_propagates_and_runs_nothing(tmp_path):
    """gate_tools.build_tool_execution re-raises a non-Exception (`not isinstance(exc, Exception)`), so a Ctrl-C
    while the gate reads the lock state never runs the tool; the hook does the same."""
    led = Ledger(tmp_path / "ledger.sqlite")
    al = Allowlist(tools={})
    mw = build_tool_execution(_interrupt, al, led, ApprovalDecisions())
    hook = build_pre_tool_call(_interrupt, al, led, decisions=ApprovalDecisions())
    ran = []
    with pytest.raises(KeyboardInterrupt):
        mw(tool_name="web_search", args={}, next_call=lambda a: ran.append(a), session_id="s", tool_call_id="c")
    with pytest.raises(KeyboardInterrupt):
        hook(tool_name="web_search", args={}, session_id="s", tool_call_id="c")
    assert ran == [] and led.tail(0) == []


def test_keyboard_interrupt_at_the_pin_prompt_applies_nothing(tmp_path):
    """consent: "apply a batch only on an explicit Approve"; a Ctrl-C at the prompt is not an answer, so the
    pending batch stays pending and nothing is pinned."""
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    led = Ledger(tmp_path / "ledger.sqlite")

    class Asker:
        def ask_choice(self, q, choices):
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        consent.approve_pending_pin(Asker(), store, led, session_key="k", session_id="", platform="cli")
    assert store.approved_entries() == [] and store.pending().code_fingerprint == "c2"
    assert not any(k == "pin_applied" for k, _ in _kinds(led))


_RO_HOLDER = textwrap.dedent("""
    import fcntl, os, sys, time
    fd = os.open(sys.argv[1], os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX)
    print("held", flush=True)
    time.sleep(30)
""")


def test_a_pins_lock_file_this_process_cannot_open_still_excludes_the_other_process(tmp_path, monkeypatch):
    """Amendment 10: pins.yaml writes "hold PinStore._mutating; both use filelock.exclusive (thread lock plus a
    non-blocking <file>.lock flock ...). A lock still held raises LockBusy ... a pin mutation raises
    PinStoreError". Fault: the lock file is read-only to this process (EACCES on open for append) while another
    process, which opened it read-only, holds the flock."""
    monkeypatch.setattr(filelock, "INTERVAL_SECONDS", 0.02)
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    lock = tmp_path / "pins.yaml.lock"
    lock.write_text("")
    os.chmod(lock, 0o400)
    holder = subprocess.Popen([sys.executable, "-c", _RO_HOLDER, str(lock)], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(PinStoreError):
            store.apply(store.pending(), approved_via="cli")
    finally:
        holder.kill()
        holder.wait(5)
        os.chmod(lock, 0o600)


def test_a_lock_file_that_cannot_be_opened_at_all_fails_closed(tmp_path):
    """FI-7: a directory where the lock file should be cannot be opened for append or for reading, so
    filelock.exclusive raises LockBusy and a pin mutation raises PinStoreError, changing nothing."""
    store = PinStore(tmp_path / "pins.yaml")
    store.stage(_result(code="c2", enclave="e2"))
    (tmp_path / "pins.yaml.lock").unlink(missing_ok=True)
    (tmp_path / "pins.yaml.lock").mkdir()
    with pytest.raises(filelock.LockBusy):
        with filelock.exclusive(tmp_path / "pins.yaml.lock"):
            pass
    with pytest.raises(PinStoreError):
        store.apply(store.pending(), approved_via="cli")
    assert store.approved_entries() == []


def test_a_read_only_lock_file_nobody_holds_still_locks(tmp_path):
    """FI-7: a lock file this process can only read is opened read-only, which flock accepts, so the lock is
    still taken when no other process holds the file."""
    lock = tmp_path / "x.lock"
    lock.write_text("")
    os.chmod(lock, 0o400)
    try:
        with filelock.exclusive(lock):
            pass
    finally:
        os.chmod(lock, 0o600)


def test_a_lost_background_verify_ok_row_holds_the_adapter_and_stops_the_refresh(tmp_path):
    """Amendment 9: the accepted background verify_ok row is written after the commit; "a lost row holds the
    adapter, drops the entry and stops the thread; the next call verifies inline". Fault: the ledger is full at
    exactly that write."""
    from ._faults import FaultPlan, disk_full, faulty_ledger
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    plan = FaultPlan()
    led = faulty_ledger(tmp_path / "ledger.sqlite", plan)
    clock = Clock()
    cache = provider_mod.VerificationCache(clock=clock)
    cache.active = lambda: True
    cache.refresh_poll_seconds = 0.01
    ad = FakeAdapter([_result(), _result()])
    cache.register(P, ad, store, 300.0, on_event=led.append, failure_backoff_seconds=30.0,
                   refresh_lead_seconds=60.0)
    assert cache.ensure(P)[0] is True
    r = cache.entry(P).refresher
    r.stop()                                     # drive the refresh by hand from here
    r.thread.join(2)
    r.stop_event.clear()
    clock.t = 250.0
    assert cache.ensure(P)[0] is True
    plan.insert, plan.insert_times = disk_full(), 1
    assert r.attempt(cache.entry(P).result, cache.entry(P).verified_mono) == "failed"
    e = cache.entry(P)
    assert e.result is None and ad.held_reason == provider_mod.REASON_VERIFY_ROW_LOST
    assert r.stop_event.is_set()
    fail = [x for x in led.tail(0) if x.kind == "verify_fail"][-1]
    assert fail.detail["source"] == "background"
    assert not any(x.kind == "verify_ok" and x.detail.get("source") == "background" for x in led.tail(0))
    with pytest.raises(Exception):
        ad.send()

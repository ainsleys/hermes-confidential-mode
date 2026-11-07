"""Amendment 9 (U06): revoke over plain files and fakes. Hermes' config and approval state are replaced by
fakes here; tests/seam/test_revoke_seam.py runs the same paths against the real ones."""
import json
from types import SimpleNamespace

import pytest

from confidential_mode import revoke as rv
from confidential_mode.gate_tools import Allowlist, ToolInfo, Route, Origin, _policy, lock_id_from
from confidential_mode.tiers import Tier


class FakeLedger:
    def __init__(self):
        self.rows = []

    def append(self, row):
        self.rows.append(row)
        return len(self.rows)


class FakeState:
    def locked_since(self):
        return 100.0

    def config_fingerprint(self):
        return "fp"


LOCK_ID = lock_id_from(100.0, "fp")


@pytest.fixture
def world(tmp_path, monkeypatch):
    hermes = {"command_allowlist": [], "session": set()}

    def fake_remove(tools):
        ours = [e for e in hermes["command_allowlist"] if rv._is_ours(e, tools)]
        hermes["command_allowlist"] = [e for e in hermes["command_allowlist"] if e not in ours]
        return sorted(e[len(rv._prefix()):] for e in ours), []

    def fake_forget(tools):
        gone = {k for k in hermes["session"] if rv._is_ours(k, tools)}
        hermes["session"] -= gone
        return sorted(k[len(rv._prefix()):] for k in gone)
    monkeypatch.setattr(rv, "remove_command_allowlist_grants", fake_remove)
    monkeypatch.setattr(rv, "forget_session_grants", fake_forget)
    path = tmp_path / "allowlist.yaml"
    al = Allowlist(tools={"web_search": ToolInfo("web_search", "web", Origin.BUILTIN, Route.ASK),
                          "vision_analyze": ToolInfo("vision_analyze", "vision", Origin.BUILTIN, Route.ASK)},
                   added_path=path, lock_id=LOCK_ID)
    al.persist()
    rt = SimpleNamespace(is_locked=lambda: (True, Tier.ON_HOST), state=FakeState(), allowlist_path=path,
                         ledger=FakeLedger(), _allowlist=al, revocations=None)
    return SimpleNamespace(rt=rt, al=al, path=path, hermes=hermes)


def _decide(al, remembered=lambda n: False):
    return _policy(al, lambda: False, lambda a: True, remembered).decide("web_search", {})


def test_allow_grant_then_revoke_then_the_gate_asks_again(world):
    world.al.add("web_search")
    assert (_decide(world.al).action, _decide(world.al).decision) == ("run", "allowlist")
    changed, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert changed and msg.startswith("Revoked web_search: removed from this lock's allowlist (allowlist.yaml)")
    assert json.loads(world.path.read_text())["allowed"] == []
    assert (_decide(world.al).action, _decide(world.al).decision) == ("ask", "ask")
    (row,) = world.rt.ledger.rows
    assert row["kind"] == "grant_revoked" and row["purpose"] == "tool:web_search" and row["surface"] == "cli"
    assert row["detail"]["tool"] == "web_search" and row["detail"]["lock_id"] == LOCK_ID


def test_always_grant_then_revoke_then_remembered_is_false(world):
    world.hermes["command_allowlist"] = [rv.plugin_key("web_search"), "git status"]
    world.hermes["session"] = {rv.plugin_key("web_search")}
    remembered = lambda n: rv.plugin_key(n) in world.hermes["command_allowlist"] \
        or rv.plugin_key(n) in world.hermes["session"]  # noqa: E731
    assert _decide(world.al, remembered).decision == "remembered"
    changed, msg = rv.revoke(world.rt, "web_search", surface="telegram")
    assert changed and "Hermes' command_allowlist" in msg and "session approvals" in msg
    assert world.hermes["command_allowlist"] == ["git status"]
    assert _decide(world.al, remembered).decision == "ask"


def test_revoke_all_covers_every_plugin_grant_for_this_lock(world):
    world.al.add("web_search")
    world.al.add("vision_analyze")
    world.hermes["command_allowlist"] = [rv.plugin_key("x"), "plugin_rule:other:tool:x"]
    changed, msg = rv.revoke(world.rt, None, revoke_all=True, surface="cli")
    assert changed and msg.startswith("Revoked vision_analyze, web_search, x")
    assert world.al.added == set() and world.hermes["command_allowlist"] == ["plugin_rule:other:tool:x"]
    assert world.rt.ledger.rows[0]["decision"] == "revoke_all" and world.rt.ledger.rows[0]["detail"]["tool"] == "*"


def test_revoke_writes_a_record_other_processes_apply_once(world, tmp_path):
    world.al.add("web_search")
    path = rv.revocations_path(world.path)
    dropped = []
    watcher = rv.RevocationWatcher(path, drop_added=dropped.append)
    watcher.baseline()
    rv.revoke(world.rt, "web_search", surface="cli")
    watcher.apply()
    watcher.apply()
    assert dropped == [{"web_search"}]
    # A process that starts after the revoke treats the record as already applied.
    late = []
    fresh = rv.RevocationWatcher(path, drop_added=late.append)
    fresh.baseline()
    fresh.apply()
    assert late == []


def test_watcher_never_raises_on_a_corrupt_or_missing_file(tmp_path):
    path = tmp_path / rv.REVOCATIONS_FILE
    w = rv.RevocationWatcher(path, drop_added=lambda t: 1 / 0)
    w.baseline()
    w.apply()
    path.write_text("{not json")
    w.apply()
    path.write_text(json.dumps({"version": 1, "records": [{"id": "a", "tools": "web_search"}, 5, {"id": 7}]}))
    w.apply()                              # drop_added raises; apply swallows it


def test_revoke_with_no_grant_is_a_noop(world):
    before = world.path.read_bytes()
    changed, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert not changed and msg.startswith("Nothing to revoke for web_search")
    assert world.path.read_bytes() == before and world.rt.ledger.rows == []
    assert not rv.revocations_path(world.path).exists()


def test_revoke_works_unlocked_on_hermes_grants_only(world):
    world.rt.is_locked = lambda: (False, None)
    world.al.add("web_search")
    world.hermes["command_allowlist"] = [rv.plugin_key("web_search")]
    changed, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert changed and world.hermes["command_allowlist"] == []
    assert world.rt.ledger.rows[0]["detail"]["lock_id"] == ""
    assert "web_search" in json.loads(world.path.read_text())["allowed"]   # the file is not this lock's


def test_a_ledger_failure_is_reported_not_raised(world):
    world.al.add("web_search")

    class Broken:
        def append(self, row):
            raise RuntimeError("disk full")
    world.rt.ledger = Broken()
    changed, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert changed and "grant_revoked ledger row could not be written" in msg

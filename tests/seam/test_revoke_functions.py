"""Amendment 10 (U06) and Amendment 13: revoke.py's Hermes-facing functions against Hermes' real config.yaml and
approval state (no plugin loaded). The plugin never writes Hermes' approval tables: a revoke moves the gate to a
new rule key instead. The plugin-level paths are in test_revoke_seam.py."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from confidential_mode import revoke as rv
from confidential_mode.gate_tools import Allowlist, Origin, Route, ToolInfo, _policy, lock_id_from
from confidential_mode.tiers import Tier

SK = "cm:revoke:functions"
LOCK_ID = lock_id_from(100.0, "fp")


class FakeLedger:
    def __init__(self):
        self.rows = []

    def append(self, row):
        self.rows.append(row)


@pytest.fixture
def world(tmp_path, monkeypatch):
    from tools import approval, approval_context
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: custom\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    with approval._lock:
        approval._permanent_approved.clear()
        approval._permanent_approved_by_home.clear()
        approval._permanent_baseline_by_home.clear()
    approval.clear_session(SK)
    tok = approval_context.set_current_session_key(SK)
    data = tmp_path / "data"
    path = data / "allowlist.yaml"
    al = Allowlist(tools={n: ToolInfo(n, "x", Origin.BUILTIN, Route.ASK) for n in ("web_search", "vision_analyze")},
                   added_path=path, lock_id=LOCK_ID)
    al.persist()
    state = SimpleNamespace(locked_since=lambda: 100.0, config_fingerprint=lambda: "fp")
    watcher = rv.RevocationWatcher(rv.revocations_path(path))
    watcher.baseline()
    rt = SimpleNamespace(is_locked=lambda: (True, Tier.ON_HOST), state=state, allowlist_path=path,
                         ledger=FakeLedger(), _allowlist=al, revocations=watcher)
    yield SimpleNamespace(rt=rt, al=al, path=path, cfg=home / "config.yaml", approval=approval, watcher=watcher)
    approval.clear_session(SK)
    approval_context.reset_current_session_key(tok)


def _always(world, tool="web_search"):
    world.approval._persist_choice(SK, "always", [rv.plugin_key(tool)])
    assert rv.plugin_key(tool) in world.cfg.read_text()


def _decide(al, watcher=None):
    from confidential_mode.gate_tools import hermes_remembered_grant

    def remembered(tool):
        return hermes_remembered_grant(tool, rule_key=rv.rule_key(watcher, tool))
    return _policy(al, lambda: False, lambda a: True, remembered).decide("web_search", {})


def _session_tables(approval):
    with approval._lock:
        return ({k: set(v) for k, v in approval._session_approved.items()}, set(approval._permanent_set()))


def test_allow_grant_then_revoke_then_the_gate_asks_again(world):
    world.al.add("web_search")
    assert _decide(world.al).decision == "allowlist"
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.REVOKED and msg.startswith("Revoked web_search: removed from this lock's allowlist")
    assert json.loads(world.path.read_text())["allowed"] == []
    assert (_decide(world.al).action, _decide(world.al).decision) == ("ask", "ask")
    (row,) = world.rt.ledger.rows
    assert row["kind"] == "grant_revoked" and row["detail"]["lock_id"] == LOCK_ID and row["surface"] == "cli"


def test_always_grant_then_revoke_then_remembered_is_gone(world):
    _always(world)
    assert _decide(world.al, world.watcher).decision == "remembered"
    status, msg = rv.revoke(world.rt, "web_search", surface="telegram")
    assert status == rv.REVOKED and "Hermes' command_allowlist" in msg and "new approval key" in msg, msg
    assert rv.plugin_key("web_search") not in world.cfg.read_text()
    assert _decide(world.al, world.watcher).decision == "ask"


def test_a_session_only_grant_is_withdrawn_without_touching_hermes_tables(world):
    """Catalog rule 9: Hermes' session approval stays in Hermes' table; the gate no longer asks under its key."""
    world.approval.approve_session(SK, rv.plugin_key("web_search"))
    assert _decide(world.al, world.watcher).decision == "remembered"
    before = _session_tables(world.approval)
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.NOTHING and "no longer applies" in msg, msg
    assert _session_tables(world.approval) == before            # not one write into Hermes' tables
    assert _decide(world.al, world.watcher).decision == "ask"
    # A new session answer is given under the new key and is honoured.
    world.approval.approve_session(SK, "plugin_rule:" + rv.rule_key(world.watcher, "web_search"))
    assert _decide(world.al, world.watcher).decision == "remembered"


def test_revoke_all_keeps_foreign_entries(world):
    world.cfg.write_text("model:\n  provider: custom\ncommand_allowlist:\n"
                         f"- {rv.plugin_key('web_search')}\n- {rv.plugin_key('vision_analyze')}\n"
                         "- plugin_rule:other:tool:web_search\n- web_search\n")
    status, msg = rv.revoke(world.rt, None, revoke_all=True, surface="cli")
    assert status == rv.REVOKED and msg.startswith("Revoked vision_analyze, web_search"), msg
    from hermes_cli.config import load_config
    assert sorted(load_config()["command_allowlist"]) == ["plugin_rule:other:tool:web_search", "web_search"]


def test_a_revoke_that_finds_nothing_still_records_for_running_gateways(world):
    before = world.cfg.read_bytes(), world.path.read_bytes()
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.NOTHING and msg.startswith("Nothing to revoke for web_search in this process")
    assert "A running gateway applies the revoke on its next tool call" in msg
    assert (world.cfg.read_bytes(), world.path.read_bytes()) == before
    recs = json.loads(rv.revocations_path(world.path).read_text())["records"]
    assert [r["tools"] for r in recs] == [["web_search"]]


def test_a_failed_record_write_says_the_session_grant_lasts(world, monkeypatch):
    world.approval.approve_session(SK, rv.plugin_key("web_search"))

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(rv, "append_record", boom)
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.FAILED and "a grant Hermes itself holds for this session ends when the session ends or " \
        "Hermes restarts" in msg and "may still run without asking" in msg, msg
    row = world.rt.ledger.rows[-1]
    assert row["decision"] == "revoke_failed" and row["detail"]["rule_key_rotated"] is False
    assert _decide(world.al, world.watcher).decision == "remembered"


@pytest.mark.parametrize("how", ["managed_noop", "raises"])
def test_a_failed_config_write_is_a_failure(world, monkeypatch, how):
    import hermes_cli.config as hc
    _always(world)
    if how == "managed_noop":
        monkeypatch.setattr(hc, "save_config", lambda *a, **k: None)
    else:
        def boom(*a, **k):
            raise PermissionError("read-only")
        monkeypatch.setattr(hc, "save_config", boom)
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.FAILED and msg.startswith("Revoke failed for web_search:"), msg
    assert "Nothing to revoke" not in msg and "asks again" not in msg
    assert "no longer grants anything" in msg and ("by hand" in msg or "may still be there" in msg)
    assert rv.plugin_key("web_search") in world.cfg.read_text()
    assert _decide(world.al, world.watcher).decision == "ask"     # the stale entry matches no key the gate uses

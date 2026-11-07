"""Amendment 10 (U06): revoke.py's Hermes-facing functions against Hermes' real config.yaml and approval state
(no plugin loaded). The plugin-level paths are in test_revoke_seam.py."""
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
    rt = SimpleNamespace(is_locked=lambda: (True, Tier.ON_HOST), state=state, allowlist_path=path,
                         ledger=FakeLedger(), _allowlist=al, revocations=None)
    yield SimpleNamespace(rt=rt, al=al, path=path, cfg=home / "config.yaml", approval=approval)
    approval.clear_session(SK)
    approval_context.reset_current_session_key(tok)


def _always(world, tool="web_search"):
    world.approval._persist_choice(SK, "always", [rv.plugin_key(tool)])
    assert rv.plugin_key(tool) in world.cfg.read_text()


def _decide(al):
    from confidential_mode.gate_tools import hermes_remembered_grant
    return _policy(al, lambda: False, lambda a: True, hermes_remembered_grant).decide("web_search", {})


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
    assert _decide(world.al).decision == "remembered"
    status, msg = rv.revoke(world.rt, "web_search", surface="telegram")
    assert status == rv.REVOKED and "Hermes' command_allowlist" in msg and "session approvals" in msg
    assert rv.plugin_key("web_search") not in world.cfg.read_text()
    assert _decide(world.al).decision == "ask"


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


def test_missing_hermes_session_state_is_a_failure(world, monkeypatch):
    _always(world)
    with monkeypatch.context() as m:
        m.delattr(world.approval, "_session_approved")
        status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.FAILED and msg.startswith("Revoke failed for web_search: Hermes' in-memory session approval "
                                                  "could not be dropped")
    assert "restart the gateway" in msg and "asks again" not in msg
    row = world.rt.ledger.rows[-1]
    assert row["decision"] == "revoke_failed" and row["detail"]["session_dropped"] is False


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
    assert rv.plugin_key("web_search") in world.cfg.read_text()

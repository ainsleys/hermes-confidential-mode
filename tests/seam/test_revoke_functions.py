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
    """Rows in memory, read back like the real ledger (tail and tool_rows), so a revoke's ledger check runs."""

    def __init__(self):
        self.rows = []

    def append(self, row):
        self.rows.append(dict(row))
        return len(self.rows)

    def _events(self, since_id):
        from types import SimpleNamespace
        return [SimpleNamespace(id=i, **{k: r.get(k) for k in ("kind", "purpose", "decision")},
                                detail=r.get("detail") or {})
                for i, r in enumerate(self.rows, 1) if i > since_id]

    def tail(self, since_id=0, limit=1000):
        return self._events(since_id)[:limit]

    def tool_rows(self, kinds, since_id=0, limit=1000):
        return [e for e in self._events(since_id) if e.kind in kinds
                and str(e.purpose or "").startswith("tool:")][:limit]


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


def test_a_session_grant_whose_answer_row_was_lost_still_ends(world):
    """Review SF1: Hermes holds a session approval under the plugin's rule key and the ledger has no tool_allowed
    row (the answer's append failed). The revoke still records, the key moves, and the approval stops counting."""
    world.approval.approve_session(SK, "plugin_rule:" + rv.rule_key(world.watcher, "web_search"))
    assert rv.granted_since_last_revoke(world.rt.ledger, {"web_search"}) == set()     # nothing in the ledger
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.NOTHING and "Nothing was recorded" not in msg and "no longer applies" in msg, msg
    assert not world.approval.is_approved(SK, "plugin_rule:" + rv.rule_key(world.watcher, "web_search"))
    assert [r["kind"] for r in world.rt.ledger.rows] == ["grant_revoked"]


def test_an_ask_without_an_answer_row_counts_as_a_possible_grant(world):
    """Another process asked (its tool_asked row is in the ledger) and the answer's row was lost: the revoke
    records, so that process's grant ends; after it, nothing asked since: nothing recorded."""
    world.rt.ledger.append({"kind": "tool_asked", "purpose": "tool:web_search", "decision": "ask"})
    assert rv.granted_since_last_revoke(world.rt.ledger, {"web_search"}) == {"web_search"}
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert "Nothing was recorded" not in msg and world.rt.ledger.rows[-1]["kind"] == "grant_revoked", msg
    assert rv.granted_since_last_revoke(world.rt.ledger, {"web_search"}) == set()
    status, msg = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.NOTHING and "Nothing was recorded" in msg and len(world.rt.ledger.rows) == 2


def test_the_config_write_changes_nothing_but_the_plugin_entries(world):
    """Amendment 13: the revoke's config.yaml write removes the plugin's own rule-key entries, both key forms,
    and leaves every other key, value, comment and env reference as it was (no merged defaults written back)."""
    from hermes_cli.config_backend import read_config_doc as load
    world.cfg.write_text("# keep me\nmodel:\n  provider: custom  # inline\n  base_url: ${MY_URL}\nzeta: 1\n"
                         f"command_allowlist:\n- {rv.plugin_key('web_search')}\n- rm -rf /tmp/x\n"
                         "- plugin_rule:confidential-mode:tool@0123456789ab:web_search\nagent:\n  max_turns: 90\n")
    before = dict(load(world.cfg))
    status, _ = rv.revoke(world.rt, "web_search", surface="cli")
    assert status == rv.REVOKED
    text = world.cfg.read_text()
    after = dict(load(world.cfg))
    assert after.pop("command_allowlist") == ["rm -rf /tmp/x"]
    before.pop("command_allowlist")
    assert after == before and "# keep me" in text and "# inline" in text and "_config_version" not in text


def test_revoke_all_keeps_foreign_entries(world):
    world.cfg.write_text("model:\n  provider: custom\ncommand_allowlist:\n"
                         f"- {rv.plugin_key('web_search')}\n- {rv.plugin_key('vision_analyze')}\n"
                         "- plugin_rule:other:tool:web_search\n- web_search\n")
    status, msg = rv.revoke(world.rt, None, revoke_all=True, surface="cli")
    assert status == rv.REVOKED and msg.startswith("Revoked vision_analyze, web_search"), msg
    from hermes_cli.config import load_config
    assert sorted(load_config()["command_allowlist"]) == ["plugin_rule:other:tool:web_search", "web_search"]


def test_a_revoke_that_finds_nothing_still_records_for_running_gateways(world):
    # A gateway asked (and may hold the answer only in memory): this process finds nothing, but records.
    world.rt.ledger.append({"kind": "tool_asked", "purpose": "tool:web_search", "decision": "ask"})
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

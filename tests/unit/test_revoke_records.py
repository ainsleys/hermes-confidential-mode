"""Amendment 9 (U06): revocation records and the watcher, pure logic over files."""
import json

from confidential_mode import revoke as rv


def test_records_are_applied_once_and_a_fresh_process_baselines(tmp_path, monkeypatch):
    monkeypatch.setattr(rv, "forget_session_grants", lambda tools: ([], ""))
    path = tmp_path / rv.REVOCATIONS_FILE
    dropped = []
    w = rv.RevocationWatcher(path, drop_added=dropped.append)
    w.baseline()
    rv.append_record(path, {"web_search"})
    w.apply()
    w.apply()
    assert dropped == [{"web_search"}]
    rv.append_record(path, None)
    w.apply()
    assert dropped == [{"web_search"}, None]
    late = []
    fresh = rv.RevocationWatcher(path, drop_added=late.append)
    fresh.baseline()
    fresh.apply()
    assert late == []


def test_watcher_reports_a_session_drop_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(rv, "forget_session_grants", lambda tools: ([], "no _session_approved"))
    path = tmp_path / rv.REVOCATIONS_FILE
    errors = []
    w = rv.RevocationWatcher(path, on_error=lambda tools, e: errors.append((tools, e)))
    w.baseline()
    rv.append_record(path, {"x"})
    w.apply()
    assert errors == [({"x"}, "no _session_approved")]


def test_watcher_never_raises_on_a_corrupt_or_missing_file(tmp_path):
    path = tmp_path / rv.REVOCATIONS_FILE
    w = rv.RevocationWatcher(path, drop_added=lambda t: 1 / 0, on_error=lambda t, e: 1 / 0)
    w.baseline()
    w.apply()
    path.write_text("{not json")
    w.apply()
    path.write_text(json.dumps({"version": 1, "records": [{"id": "a", "tools": "web_search"}, 5, {"id": 7}]}))
    w.apply()


def test_records_are_capped(tmp_path):
    path = tmp_path / rv.REVOCATIONS_FILE
    for i in range(rv.MAX_RECORDS + 5):
        rv.append_record(path, {f"t{i}"})
    recs = json.loads(path.read_text())["records"]
    assert len(recs) == rv.MAX_RECORDS and recs[-1]["tools"] == [f"t{rv.MAX_RECORDS + 4}"]


def test_allowlist_add_does_not_write_back_a_name_revoked_meanwhile(tmp_path):
    """Finding 11: a gateway that loaded web_search as added, then waited for a human to allow vision_analyze
    while a CLI revoked web_search, must not persist web_search again."""
    from confidential_mode.gate_tools import Allowlist, Origin, Route, ToolInfo
    path = tmp_path / "allowlist.yaml"
    tools = {n: ToolInfo(n, "x", Origin.BUILTIN, Route.ASK) for n in ("web_search", "vision_analyze")}
    al = Allowlist(tools=tools, added_path=path, lock_id="L")
    al.persist()
    al.add("web_search")
    assert rv.remove_allowlist_grants(path, "L", {"web_search"}) == ["web_search"]   # the CLI
    al.add("vision_analyze")                                                          # the gateway, stale
    assert json.loads(path.read_text())["allowed"] == ["vision_analyze"]
    assert al.added == {"vision_analyze"}

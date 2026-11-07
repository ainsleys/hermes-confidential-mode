"""Amendment 10 (U06) and Amendment 13: revocation records, the watcher and the rule-key generation, pure logic
over files."""
import json

from confidential_mode import revoke as rv


def test_records_are_applied_once_and_a_fresh_process_baselines(tmp_path):
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


def test_each_revoke_moves_the_tool_to_a_new_rule_key(tmp_path):
    from confidential_mode.gate_tools import parse_pattern_key, rule_key_for
    path = tmp_path / rv.REVOCATIONS_FILE
    w = rv.RevocationWatcher(path)
    w.baseline()
    assert rv.rule_key(w, "web_search") == rule_key_for("web_search") == "confidential-mode:tool:web_search"
    rv.append_record(path, {"web_search"})
    first = rv.rule_key(w, "web_search")
    assert first != rule_key_for("web_search") and rv.rule_key(w, "vision_analyze") == rule_key_for("vision_analyze")
    assert parse_pattern_key("plugin_rule:" + first) == ("web_search", first.split("@")[1].split(":")[0])
    rv.append_record(path, None)                       # --all moves every tool
    assert rv.rule_key(w, "web_search") not in (first, rule_key_for("web_search"))
    assert rv.rule_key(w, "vision_analyze") != rule_key_for("vision_analyze")
    # A fresh process reads the same generation from the file.
    fresh = rv.RevocationWatcher(path)
    fresh.baseline()
    assert rv.rule_key(fresh, "web_search") == rv.rule_key(w, "web_search")


def test_the_generation_survives_record_truncation(tmp_path):
    path = tmp_path / rv.REVOCATIONS_FILE
    rv.append_record(path, {"web_search"})
    w = rv.RevocationWatcher(path)
    w.baseline()
    key = rv.rule_key(w, "web_search")
    for i in range(rv.MAX_RECORDS + 3):
        rv.append_record(path, {f"t{i}"})
    fresh = rv.RevocationWatcher(path)
    fresh.baseline()
    assert rv.rule_key(fresh, "web_search") == key


def test_the_generation_never_goes_back(tmp_path):
    """A deleted or older record file must not revive a grant held under an earlier key."""
    path = tmp_path / rv.REVOCATIONS_FILE
    w = rv.RevocationWatcher(path)
    w.baseline()
    rv.append_record(path, {"web_search"})
    older = path.read_bytes()
    rv.append_record(path, {"web_search"})
    newest = rv.rule_key(w, "web_search")
    path.write_bytes(older)
    assert rv.rule_key(w, "web_search") == newest
    path.unlink()
    assert rv.rule_key(w, "web_search") == newest
    # A replaced file whose sequence restarted still moves the key on its new record.
    rv.append_record(path, {"web_search"})
    assert rv.rule_key(w, "web_search") != newest


def test_an_unreadable_record_file_gives_a_key_no_earlier_grant_has(tmp_path):
    from confidential_mode.gate_tools import rule_key_for
    path = tmp_path / rv.REVOCATIONS_FILE
    path.write_text("{not json")
    w = rv.RevocationWatcher(path)
    w.baseline()
    key = rv.rule_key(w, "web_search")
    assert key != rule_key_for("web_search") and key == rv.rule_key(w, "web_search")


def test_a_version_1_file_still_counts(tmp_path):
    path = tmp_path / rv.REVOCATIONS_FILE
    path.write_text(json.dumps({"version": 1, "records": [{"id": "ab" * 16, "ts": 1, "tools": ["web_search"]}]}))
    w = rv.RevocationWatcher(path)
    w.baseline()
    first = rv.rule_key(w, "web_search")
    assert first.startswith("confidential-mode:tool@") and first.endswith(":web_search")
    rv.append_record(path, {"web_search"})
    assert rv.rule_key(w, "web_search") != first


def test_watcher_never_raises_on_a_corrupt_or_missing_file(tmp_path):
    path = tmp_path / rv.REVOCATIONS_FILE
    w = rv.RevocationWatcher(path, drop_added=lambda t: 1 / 0)
    w.baseline()
    w.apply()
    path.write_text("{not json")
    w.apply()
    assert w.generation("x")
    path.write_text(json.dumps({"version": 1, "records": [{"id": "a", "tools": "web_search"}, 5, {"id": 7}],
                                "latest": {"x": "bad", "y": [True, "zz"]}}))
    w.apply()
    w.generation("web_search")


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

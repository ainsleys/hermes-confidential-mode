"""Hostile tests for `revoke` (INTERFACES Amendment 10, backlog U06), on the plugin loaded by real discovery
with Hermes' real config.yaml and approval state. Revoke must remove only what confidential mode wrote, must
change nothing when there is nothing to revoke, and must never raise into Hermes."""
from __future__ import annotations

import importlib
import json
import os

import pytest

from tests.seam.test_register import plugin  # noqa: F401  (fixture)
from tests.seam._harness import no_lazy_installs  # noqa: F401  (fixture)

OURS = "plugin_rule:confidential-mode:tool:web_search"
FOREIGN = ["web_search", "plugin_rule:other-plugin:tool:web_search", "plugin_rule:web_search",
           "plugin_rule:confidential-mode:tool:web_search_extra", "plugin_rule:confidential-mode:tool:web_searc",
           "PLUGIN_RULE:CONFIDENTIAL-MODE:TOOL:WEB_SEARCH", "rm -rf /tmp/x"]


def _sub(plugin, name):
    return importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.{name}")


def _with_allowlist(plugin, entries):
    lines = "".join(f"- {json.dumps(e)}\n" for e in entries)
    plugin.cfg.write_text(plugin.cfg.read_text() + "command_allowlist:\n" + lines)


def _grant_rows(plugin):
    return [e for e in plugin.rt.ledger.tail(0) if e.kind == "grant_revoked"]


def test_revoke_of_grants_the_plugin_did_not_write_is_a_noop_with_a_message(plugin):
    assert plugin.slash("on on-host-only").startswith("Locked")
    _with_allowlist(plugin, FOREIGN)
    before = plugin.cfg.read_bytes()
    out = plugin.slash("revoke web_search")
    assert out.startswith("Nothing to revoke for web_search in this process: no grant written by confidential "
                          "mode was found"), out
    assert "did not write were left alone" in out and "plugin_rule:other-plugin:tool:web_search" in out
    assert plugin.cfg.read_bytes() == before
    # The revoke is still recorded for running processes and ledgered, with nothing removed here.
    (row,) = _grant_rows(plugin)
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail["removed"] == {"allowlist": [], "command_allowlist": [], "lock_grants": []}
    rv = _sub(plugin, "revoke")
    assert rv.revocations_path(plugin.rt.allowlist_path).exists()


def test_revoke_removes_only_the_exact_plugin_key(plugin):
    _with_allowlist(plugin, FOREIGN + [OURS])
    out = plugin.slash("revoke web_search")
    assert out.startswith("Revoked web_search"), out
    from hermes_cli.config import load_config
    left = load_config()["command_allowlist"]
    assert sorted(left) == sorted(FOREIGN)


def test_revoke_with_no_grant_at_all_changes_no_grant_file(plugin):
    before = plugin.cfg.read_bytes()
    for state in ("unlocked", "locked"):
        if state == "locked":
            assert plugin.slash("on on-host-only").startswith("Locked")
            before_al = plugin.rt.allowlist_path.read_bytes()
        out = plugin.slash("revoke web_search")
        assert out.startswith("Nothing to revoke for web_search"), (state, out)
        assert plugin.cfg.read_bytes() == before
    assert plugin.rt.allowlist_path.read_bytes() == before_al
    assert plugin.slash("revoke --all").startswith("Nothing to revoke for every confidential-mode tool grant")
    assert all(r.decision in ("revoke", "revoke_all") for r in _grant_rows(plugin))


@pytest.mark.parametrize("args", ["revoke", "revoke a b", "revoke --al", "revoke -x", "revoke '*'",
                                  "revoke 'web search'", "revoke 'web\x07search'", "revoke --all web_search"])
def test_revoke_bad_arguments_change_nothing(plugin, args):
    _with_allowlist(plugin, [OURS])
    before = plugin.cfg.read_bytes()
    out = plugin.slash(args)
    assert out.startswith("Usage: /confidential revoke"), (args, out)
    assert plugin.cfg.read_bytes() == before and _grant_rows(plugin) == []


def test_revoke_runs_under_the_self_approval_marker(plugin):
    # Revoking narrows and never widens: a process a Hermes tool started may revoke, and is not asked anything.
    sa = _sub(plugin, "selfapproval")
    os.environ[sa.TOOL_PROCESS_ENV] = str(os.getpid() + 1)
    assert sa.self_approval_reason() is not None
    _with_allowlist(plugin, [OURS])
    out = plugin.slash("revoke web_search")
    assert out.startswith("Revoked web_search"), out
    assert OURS not in plugin.cfg.read_text()


def test_revoke_leaves_another_locks_allowlist_alone(plugin):
    assert plugin.slash("on on-host-only").startswith("Locked")
    path = plugin.rt.allowlist_path
    data = json.loads(path.read_text())
    data["lock_id"], data["allowed"] = "some-other-lock", ["web_search"]
    path.write_text(json.dumps(data))
    out = plugin.slash("revoke web_search")
    assert out.startswith("Nothing to revoke"), out
    assert json.loads(path.read_text())["allowed"] == ["web_search"]


def test_a_corrupt_revocation_file_never_breaks_the_gate(plugin, monkeypatch):
    import model_tools
    from tools.registry import registry
    ran = []
    monkeypatch.setattr(registry.get_entry("web_search"), "handler",
                        lambda args, **kw: ran.append(args) or json.dumps({"ok": 1}))
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert plugin.slash("on on-host-only").startswith("Locked")
    rv = _sub(plugin, "revoke")
    rv.revocations_path(plugin.rt.allowlist_path).write_text("{\x00 not json")
    plugin.human("once")
    model_tools.handle_function_call("web_search", {"q": 1}, task_id="t", session_id="s", tool_call_id="c1")
    assert ran == [{"q": 1}] and len(plugin.prompts) == 1
    _with_allowlist(plugin, [OURS])
    assert plugin.slash("revoke web_search").startswith("Revoked web_search")   # rewrites the corrupt file
    assert json.loads(rv.revocations_path(plugin.rt.allowlist_path).read_text())["version"] == 2


def test_a_forged_record_only_narrows(plugin, monkeypatch):
    """Anyone who can write grants_revoked.json can only take grants away: a record naming every tool moves
    every tool to a new rule key, so Hermes' session approvals stop applying; it cannot add a grant."""
    import model_tools
    from tools.registry import registry
    ran = []
    monkeypatch.setattr(registry.get_entry("web_search"), "handler",
                        lambda args, **kw: ran.append(args) or json.dumps({"ok": 1}))
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert plugin.slash("on on-host-only").startswith("Locked")
    plugin.human("session")
    model_tools.handle_function_call("web_search", {"q": 1}, task_id="t", session_id="s", tool_call_id="c1")
    rv = _sub(plugin, "revoke")
    path = rv.revocations_path(plugin.rt.allowlist_path)
    path.write_text(json.dumps({"version": 1, "records": [{"id": "forged", "tools": ["*"], "allow": ["x"]}]}))
    plugin.human("deny")
    model_tools.handle_function_call("web_search", {"q": 2}, task_id="t", session_id="s", tool_call_id="c2")
    assert ran == [{"q": 1}] and len(plugin.prompts) == 2


@pytest.mark.parametrize("held", ["allowlist.yaml.lock", "grants_revoked.json.lock"])
def test_a_held_lock_file_fails_the_revoke_instead_of_hanging(plugin, monkeypatch, held):
    """Review N1: a process holding a lock file (an agent could, from a terminal) must not hang revoke or let
    it pass silently. The revoke fails within the bound, names the lock file, and ledgers that."""
    import fcntl
    import time as _time
    fl = _sub(plugin, "filelock")
    monkeypatch.setattr(fl, "INTERVAL_SECONDS", 0.01)
    assert plugin.slash("on on-host-only").startswith("Locked")
    _with_allowlist(plugin, [OURS])
    data = json.loads(plugin.rt.allowlist_path.read_text())
    data["allowed"] = ["web_search"]
    plugin.rt.allowlist_path.write_text(json.dumps(data))
    fh = open(plugin.rt.allowlist_path.parent / held, "a")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)           # another open file description: conflicts like a process
    try:
        t0 = _time.monotonic()
        out = plugin.slash("revoke web_search")
        assert _time.monotonic() - t0 < 5
    finally:
        fh.close()
    assert out.startswith("Revoke failed for web_search:") and held in out, out
    row = _grant_rows(plugin)[-1]
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert row.decision == "revoke_failed" and any(held in e for e in detail["errors"])


def test_a_held_pins_lock_raises_instead_of_hanging(plugin, monkeypatch):
    import fcntl
    fl = _sub(plugin, "filelock")
    monkeypatch.setattr(fl, "INTERVAL_SECONDS", 0.01)
    pins = plugin.rt.pins
    pins.path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(pins.path.with_name(pins.path.name + ".lock"), "a")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    try:
        with pytest.raises(_sub(plugin, "pins").PinStoreError, match="pins.yaml.lock"):
            pins.clear_pending()
    finally:
        fh.close()
    pins.clear_pending()                                # free again: works

"""Seam tests for `revoke <tool>` / `revoke --all` (INTERFACES Amendment 10, backlog U06) on the plugin loaded
by real discovery, with Hermes' real approval state and config.yaml. The human is a fake approval callback."""
from __future__ import annotations

import importlib
import json

import pytest
from hermes_cli.plugin_choices import bind_asker

from ._harness import no_lazy_installs  # noqa: F401  (fixture)
from .test_commands import _hermes
from .test_register import plugin  # noqa: F401  (fixture)

KEY = "plugin_rule:confidential-mode:tool:web_search"


def _sub(plugin, name):
    return importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.{name}")


@pytest.fixture
def web(plugin, monkeypatch):
    from tools.registry import registry
    ran = []
    monkeypatch.setattr(registry.get_entry("web_search"), "handler",
                        lambda args, **kw: ran.append(args) or json.dumps({"ok": 1}))
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert plugin.slash("on on-host-only").startswith("Locked")
    return ran


def _call(n):
    import model_tools
    return model_tools.handle_function_call("web_search", {"query": n}, task_id="t", session_id="s",
                                            tool_call_id=f"c{n}")


def _always(plugin, web):
    plugin.human("always")
    _call(1)
    assert web == [{"query": 1}] and len(plugin.prompts) == 1
    assert KEY in plugin.cfg.read_text()                       # Hermes wrote the "always" grant
    _call(2)
    assert len(web) == 2 and len(plugin.prompts) == 1           # remembered: no second prompt


def test_always_grant_then_revoke_then_the_gate_asks_again(plugin, web):
    _always(plugin, web)
    out = plugin.slash("revoke web_search")
    assert out.startswith("Revoked web_search: removed from Hermes' command_allowlist"), out
    assert "The next web_search call asks again" in out
    assert KEY not in plugin.cfg.read_text()
    plugin.human("deny")
    _call(3)
    assert len(plugin.prompts) == 2 and len(web) == 2           # asked again, and the denial held
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "grant_revoked"]
    assert len(rows) == 1 and rows[0].decision == "revoke" and rows[0].surface == "cli"
    detail = rows[0].detail if isinstance(rows[0].detail, dict) else json.loads(rows[0].detail)
    gt = _sub(plugin, "gate_tools")
    assert detail["tool"] == "web_search" and detail["lock_id"] == gt.lock_id_for(plugin.rt.state)
    assert detail["removed"]["command_allowlist"] == ["web_search"] and detail["rule_key_rotated"] is True
    assert "Tool grants (remembered by Hermes): none" in plugin.slash("status")


def test_allow_grant_then_revoke_then_the_gate_asks_again(plugin, web):
    with bind_asker(lambda q, labels: "Allow"):
        assert plugin.slash("allow web_search") == "web_search added to the allowlist for this lock."
    plugin.human("deny")
    _call(1)
    assert len(web) == 1 and plugin.prompts == []
    out = plugin.slash("revoke web_search")
    assert out.startswith("Revoked web_search: removed from this lock's allowlist (allowlist.yaml)"), out
    assert json.loads(plugin.rt.allowlist_path.read_text())["allowed"] == []
    _call(2)
    assert len(web) == 1 and len(plugin.prompts) == 1
    assert "Tool grants (allowlist): none" in plugin.slash("status")


def test_revoke_all_removes_every_plugin_grant_and_nothing_else(plugin, web):
    with bind_asker(lambda q, labels: "Allow"):
        plugin.slash("allow web_search")
    text = plugin.cfg.read_text() + ("command_allowlist:\n- plugin_rule:confidential-mode:tool:vision_analyze\n"
                                     "- plugin_rule:other-plugin:tool:web_search\n- web_search\n")
    plugin.cfg.write_text(text)
    out = plugin.slash("revoke --all")
    assert out.startswith("Revoked vision_analyze, web_search"), out
    cfg = plugin.cfg.read_text()
    assert "confidential-mode:tool" not in cfg
    assert "plugin_rule:other-plugin:tool:web_search" in cfg and "- web_search" in cfg
    assert json.loads(plugin.rt.allowlist_path.read_text())["allowed"] == []
    assert [e.decision for e in plugin.rt.ledger.tail(0) if e.kind == "grant_revoked"] == ["revoke_all"]


def test_cli_revoke_in_another_process_reaches_the_running_gateway(plugin, web):
    """`hermes confidential revoke` in a separate process: the 'gateway' (the loaded plugin) holds a session
    approval in memory for the "always" answer; the revocation record makes it drop that on its next call."""
    _always(plugin, web)
    proc = _hermes(plugin, "revoke", "web_search")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("Revoked web_search: removed from Hermes' command_allowlist"), proc.stdout
    assert KEY not in plugin.cfg.read_text()
    plugin.human("deny")
    _call(3)
    assert len(plugin.prompts) == 2 and len(web) == 2
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "grant_revoked"]
    assert len(rows) == 1 and rows[0].surface == "cli"
    # Nothing left to revoke: a no-op with a message and exit code 0.
    proc = _hermes(plugin, "revoke", "web_search")
    assert proc.returncode == 0 and proc.stdout.startswith("Nothing to revoke for web_search"), proc.stdout
    proc = _hermes(plugin, "revoke")
    assert proc.returncode == 2 and proc.stdout.startswith("Usage: hermes confidential revoke")


def test_cli_revoke_all_of_an_allow_grant_reaches_the_running_gateway(plugin, web):
    with bind_asker(lambda q, labels: "Allow"):
        plugin.slash("allow web_search")
    plugin.human("deny")
    _call(1)
    assert len(web) == 1 and plugin.prompts == []
    proc = _hermes(plugin, "revoke", "--all")
    assert proc.returncode == 0 and proc.stdout.startswith("Revoked web_search"), proc.stdout + proc.stderr
    _call(2)
    assert len(web) == 1 and len(plugin.prompts) == 1


def test_a_new_answer_after_a_revoke_is_honoured(plugin, web):
    _always(plugin, web)
    assert plugin.slash("revoke web_search").startswith("Revoked")
    plugin.human("session")
    _call(3)
    _call(4)
    assert len(web) == 4 and len(plugin.prompts) == 2           # asked once after the revoke, then remembered


def test_cli_revoke_reaches_a_gateway_session_only_grant(plugin, web):
    """Review finding 1: the gateway holds a 'session' grant only in memory (no command_allowlist entry, no
    allowlist.yaml addition). The CLI process finds nothing itself, but still records the revoke, and the
    gateway's next call asks again."""
    plugin.human("session")
    _call(1)
    _call(2)
    assert len(web) == 2 and len(plugin.prompts) == 1 and KEY not in plugin.cfg.read_text()
    proc = _hermes(plugin, "revoke", "web_search")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("Nothing to revoke for web_search in this process"), proc.stdout
    assert "A running gateway applies the revoke on its next tool call" in proc.stdout
    plugin.human("deny")
    _call(3)
    assert len(plugin.prompts) == 2 and len(web) == 2


def test_cli_revoke_failure_exits_non_zero(plugin, web, monkeypatch):
    """Review finding 3: a config.yaml that is not written (a managed install, where Hermes' save_config
    returns without saving) is a failure, not 'Nothing to revoke'."""
    _always(plugin, web)
    monkeypatch.setenv("HERMES_MANAGED", "1")
    try:
        proc = _hermes(plugin, "revoke", "web_search")
    finally:
        monkeypatch.delenv("HERMES_MANAGED")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stdout.startswith("Revoke failed for web_search:"), proc.stdout
    assert KEY in plugin.cfg.read_text()


def test_receipt_shows_the_revoke(plugin, web):
    _always(plugin, web)
    plugin.slash("revoke web_search")
    text = plugin.slash("receipts sess-w5")
    assert "grant revoked  tool:web_search  (revoke; removed from command_allowlist; new approval key; via cli)" in text, text


def _once_per_lock_grant(plugin, web):
    """Under the default confidential.tools.ask (once_per_lock), a "once" answer grants the tool for the lock in
    this conversation: the second call runs without a prompt, on the grant."""
    plugin.human("once")
    _call(1)
    _call(2)
    assert len(web) == 2 and len(plugin.prompts) == 1
    grants = [e for e in plugin.rt.ledger.tail(0) if e.kind == "tool_allowed" and e.decision == "lock_grant"]
    assert len(grants) == 1
    assert plugin.rt.lock_grants.names(_sub(plugin, "gate_tools").lock_id_for(plugin.rt.state)) == ["web_search"]
    assert KEY not in plugin.cfg.read_text()          # the grant lives in the plugin, not in Hermes' config


def test_cli_revoke_drops_a_once_per_lock_grant_and_the_next_call_asks_again(plugin, web, capsys):
    import argparse
    _once_per_lock_grant(plugin, web)
    parser = argparse.ArgumentParser()
    plugin.mgr._cli_commands["confidential"]["setup_fn"](parser)
    handler = plugin.mgr._cli_commands["confidential"]["handler_fn"]
    assert handler(parser.parse_args(["revoke", "web_search"])) == 0       # `hermes confidential revoke web_search`
    out = capsys.readouterr().out
    assert out.startswith("Revoked web_search: removed from this lock's grants in this process"), out
    assert plugin.rt.lock_grants.names(_sub(plugin, "gate_tools").lock_id_for(plugin.rt.state)) == []
    plugin.human("deny")
    _call(3)
    assert len(plugin.prompts) == 2 and len(web) == 2           # asked again, and the denial held
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "grant_revoked"]
    assert len(rows) == 1
    detail = rows[0].detail if isinstance(rows[0].detail, dict) else json.loads(rows[0].detail)
    assert detail["removed"]["lock_grants"] == ["web_search"]


def test_cli_revoke_in_another_process_drops_a_once_per_lock_grant(plugin, web):
    """The grant is in this process's memory only; the CLI process finds nothing itself, writes the revocation
    record, and the running process drops the grant on its next tool call and asks again."""
    _once_per_lock_grant(plugin, web)
    proc = _hermes(plugin, "revoke", "web_search")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("Nothing to revoke for web_search in this process"), proc.stdout
    assert plugin.rt.revocations.path.exists()
    plugin.human("deny")
    _call(3)
    assert len(plugin.prompts) == 2 and len(web) == 2
    assert plugin.rt.lock_grants.names(_sub(plugin, "gate_tools").lock_id_for(plugin.rt.state)) == []

"""Seam tests for /confidential and `hermes confidential` (W5), on the plugin loaded by real discovery
(fixture from test_register.py). Consent goes through Hermes' real ctx.ask_choice with the asker seat
bound to a fake human (hermes_cli.plugin_choices.bind_asker, the CLI's own mechanism)."""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
import time
import types

import pytest

from hermes_cli.plugin_choices import bind_asker

from .test_register import BASE_CONFIG, plugin  # noqa: F401  (fixture)
from ._harness import no_lazy_installs  # noqa: F401  (fixture)


def _sub(plugin, name):
    return importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.{name}")


def _result(plugin, code="c0de" * 16, enclave="e9c1" * 16, tag="v1.2.3"):
    base = _sub(plugin, "verify.base")
    return base.VerificationResult(vendor="tinfoil", router_repo="tinfoilsh/confidential-model-router",
                                   enclave_host="router.tinfoil.invalid", code_fingerprint=code,
                                   enclave_fingerprint=enclave, release_tag=tag, verifier="test",
                                   verified_at_host_clock=time.time() - 42, evidence={})


def human(answer):
    asked = []

    def asker(question, labels):
        asked.append((question, labels))
        return answer
    return asker, asked


def test_usage_and_unknown(plugin):
    assert plugin.slash("").startswith("Usage: /confidential")
    assert plugin.slash("frobnicate").startswith("Usage: /confidential")


def test_status_unlocked_and_locked(plugin):
    out = plugin.slash("status")
    assert "not locked" in out and "Provider/model: custom / llama3 at 127.0.0.1" in out
    assert "Enclave host: (unresolved" in out and "Pinned: none" in out and "Pending pin: none" in out
    assert "(host clock)" in out and "Tool grants (allowlist): none" in out
    assert plugin.slash("on on-host-only").startswith("Locked")
    out = plugin.slash("status")
    assert "LOCKED (on-host-only)" in out and "(host clock)" in out
    assert "Preflight (on-host-only, routing config): PASS; config unchanged since lock" in out
    assert "Breach: none this lock" in out


def test_status_shows_pinned_and_pending_fingerprints_and_verification_age(plugin):
    pins = plugin.rt.pins
    pending = pins.stage(_result(plugin))
    pins.apply(pending, approved_via="test")
    pins.stage(_result(plugin, code="ab12cd34" * 8))
    cache = _sub(plugin, "provider").verification_cache
    entry = cache.entry("attested-tinfoil")
    entry.result, entry.verified_mono = _result(plugin), time.monotonic()
    out = plugin.slash("status")
    assert "Pinned: tinfoil tinfoilsh/confidential-model-router code c0dec0de enclave e9c1e9c1 release v1.2.3" in out
    assert "Pending pin: tinfoil code ab12cd34" in out and "/confidential pins approve" in out
    assert "Last verification: 42s ago (host clock)" in out or "Last verification: 43s ago (host clock)" in out


def test_pins_approve_applies_only_on_explicit_approve(plugin):
    pins = plugin.rt.pins
    pins.stage(_result(plugin))
    asker, asked = human("maybe later")
    with bind_asker(asker):
        out = plugin.slash("pins approve")
    assert "denied" in out and pins.pending() is not None and len(asked) == 1
    asker, asked = human("Approve")
    with bind_asker(asker):
        out = plugin.slash("pins approve")
    assert out.startswith("Pinned tinfoil build v1.2.3") and pins.pending() is None
    assert pins.get("tinfoil", "tinfoilsh/confidential-model-router").approved_via == "cli"
    kinds = plugin.kinds()
    assert ("pin_denied", "no_answer") in kinds and ("pin_applied", "approve") in kinds  # prose -> None
    listing = plugin.slash("pins")
    assert "Approval history:" in listing and "pin_applied" in listing and "pin_denied" in listing
    assert "code c0dec0de" in listing


def test_consent_refuses_on_an_event_loop(plugin):
    plugin.rt.pins.stage(_result(plugin))

    async def on_loop():
        return plugin.slash("pins approve")
    out = asyncio.run(on_loop())
    assert out.startswith("Not asked:") and plugin.rt.pins.pending() is not None


def test_allow_tool_then_it_runs_without_a_prompt(plugin, monkeypatch):
    import model_tools
    from tools.registry import registry
    ran = []
    monkeypatch.setattr(registry.get_entry("web_search"), "handler",
                        lambda args, **kw: ran.append(args) or json.dumps({"ok": 1}))
    assert plugin.slash("allow web_search").startswith("Not locked")
    assert plugin.slash("on on-host-only").startswith("Locked")
    asker, asked = human("Allow")
    with bind_asker(asker):
        out = plugin.slash("allow web_search")
    assert out == "web_search added to the allowlist for this lock." and len(asked) == 1
    assert plugin.slash("allow cronjob_manage").startswith("cronjob_manage cannot be allowed")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    plugin.human("deny")                                            # would refuse if asked
    model_tools.handle_function_call("web_search", {"query": "x"}, task_id="t", session_id="s", tool_call_id="c1")
    assert ran == [{"query": "x"}] and plugin.prompts == []
    assert "Tool grants (allowlist): web_search" in plugin.slash("status")


def test_off_prints_counts_and_repairs_unreadable_state(plugin):
    assert plugin.slash("on on-host-only").startswith("Locked")
    from hermes_cli.plugins import invoke_hook
    plugin.rt.ledger.append({"kind": "tool_refused", "purpose": "tool:x", "decision": "cron"})
    plugin.rt.ledger.append({"kind": "tool_asked", "purpose": "tool:y", "decision": "ask"})
    out = plugin.slash("off")
    assert out.startswith("Unlocked (on-host-only). Locked for") and "1 refusal(s)" in out and "1 ask(s)" in out
    assert plugin.rt.state.locked() == (False, None)
    plugin.rt.ctx.state.set("locked", "corrupt")
    assert "UNREADABLE" in plugin.slash("status")
    blocked = invoke_hook("pre_llm_call", session_id="s")
    assert blocked and blocked[0]["action"] == "block"
    assert plugin.slash("off").startswith("Lock state was unreadable; it is now cleared")
    assert plugin.rt.state.locked() == (False, None)


def test_check_prints_the_preflight_table(plugin):
    out = plugin.slash("check on-host-only")
    assert out.startswith("confidential preflight: tier=on-host-only PASS")
    assert "KEY" in out and "VERDICT" in out and "auxiliary.vision.provider" in out
    assert plugin.slash("check zero-retention").startswith("zero-retention: zero-retention tier not implemented")


def test_receipts_delegate_to_w6_render(plugin, monkeypatch):
    assert plugin.slash("on on-host-only").startswith("Locked")
    plugin.rt.ledger.append({"kind": "tool_refused", "session_id": "sess-1", "purpose": "tool:web_search",
                             "decision": "cron"})
    text = plugin.slash("receipts sess-1")
    assert "sess-1" in text and "host clock" in text
    receipts = _sub(plugin, "receipts")
    doc = json.loads(plugin.slash("receipts sess-1 --json"))
    assert receipts.verify_chain(doc)
    # ux-pass-1 item 8: an id with no ledger rows is an error, not an empty receipt.
    assert plugin.slash("receipts nosuchsession").startswith("No ledger rows for session 'nosuchsession'")
    proc = _hermes(plugin, "receipts", "nosuchsession")
    assert proc.returncode == 1 and proc.stdout.startswith("No ledger rows for session"), proc.stdout + proc.stderr
    plugin.rt.ledger.append({"kind": "session_start", "session_id": "sess-cur", "purpose": "session"})
    fake = types.ModuleType("receipts")
    fake.render = lambda ledger, session: f"RECEIPT {session}"          # an older two-argument render
    monkeypatch.setitem(sys.modules, f"{plugin.mod.__name__}.confidential_mode.receipts", fake)
    assert plugin.slash("receipts", session_id="sess-cur") == "RECEIPT sess-cur"
    monkeypatch.setitem(sys.modules, f"{plugin.mod.__name__}.confidential_mode.receipts", None)   # absent
    assert plugin.slash("receipts sess-1").startswith("Receipts are not available")


def test_slash_watch_shows_the_ledger(plugin):
    plugin.slash("on on-host-only")
    out = plugin.slash("watch")
    assert out.splitlines()[0].startswith("TIME") and "lock in_tier locked" in out
    assert "\x1b[" not in out


def test_cli_status_check_watch(plugin, capsys):
    entry = plugin.mgr._cli_commands["confidential"]
    parser = argparse.ArgumentParser()
    entry["setup_fn"](parser)
    assert entry["handler_fn"](parser.parse_args(["status"])) == 0
    assert "not locked" in capsys.readouterr().out
    assert entry["handler_fn"](parser.parse_args(["check", "--tier", "on-host-only"])) == 0
    assert "tier=on-host-only PASS" in capsys.readouterr().out
    plugin.slash("on on-host-only")
    assert entry["handler_fn"](parser.parse_args(["watch", "--once"])) == 0
    out = capsys.readouterr().out
    assert out.startswith("TIME") and "\x1b[" not in out           # captured stdout is not a tty
    assert entry["handler_fn"](parser.parse_args(["setup", "--no-verify", "--model", "llama3-3-70b"])) == 0
    out = capsys.readouterr().out
    assert "provider: attested-tinfoil" in out and "default: llama3-3-70b" in out and "fallback_providers: []" in out
    assert "  vision:" in out


def test_setup_terminal_asker_is_exact(plugin):
    commands = _sub(plugin, "commands")
    import io

    class TTY(io.StringIO):
        def isatty(self):
            return True
    choices = [{"value": "approve", "label": "Approve"}, {"value": "deny", "label": "Deny"}]
    assert commands.TerminalAsker(TTY("1\n"), io.StringIO()).ask_choice("q", choices) == "approve"
    assert commands.TerminalAsker(TTY("approve\n"), io.StringIO()).ask_choice("q", choices) == "approve"
    assert commands.TerminalAsker(TTY("yes\n"), io.StringIO()).ask_choice("q", choices) is None
    assert commands.TerminalAsker(io.StringIO("1\n"), io.StringIO()).ask_choice("q", choices) is None  # not a tty


ATTESTED_CONFIG = """\
plugins:
  enabled: [confidential-mode]
model:
  provider: attested-tinfoil
  default: llama3-3-70b
auxiliary:
  vision:
    provider: attested-tinfoil
    model: llama3-3-70b
"""


def test_attested_lock_message_and_refusal_reason_without_network(plugin, monkeypatch):
    """Attested tier through the real AttestedPredicate and profile lookup; only W2's attested_ok (which
    would attest over the network) is replaced."""
    provider = _sub(plugin, "provider")
    tiers = _sub(plugin, "tiers")
    verdict = {"v": tiers.Verdict(False, "no approved enclave build pinned; run /confidential pins approve")}
    monkeypatch.setattr(provider, "attested_ok", lambda name: verdict["v"])
    plugin.cfg.write_text(ATTESTED_CONFIG)
    out = plugin.slash("on attested")
    assert out.startswith("Not locked") and "approve the pending pin: hermes confidential pins approve" in out
    verdict["v"] = tiers.Verdict(True, "attested enclave verified and pinned", "router.tinfoil.invalid")
    entry = provider.verification_cache.entry("attested-tinfoil")
    entry.result, entry.verified_mono = _result(plugin), time.monotonic()
    monkeypatch.setenv("TINFOIL_API_KEY", "test-key")
    out = plugin.slash("on attested")
    assert out == ("Locked to Tinfoil, llama3-3-70b at router.tinfoil.invalid; verified 42 s ago.\n"
                   "Off-host tools ask the first time per lock in each conversation. Shell and code execution are not inspected. Auxiliary calls are "
                   "recorded, not refused. Not active in safe-worker mode.\n"
                   "Details: hermes confidential status --verbose; docs/LIMITATIONS.md"), out
    assert "LOCKED (attested)" in plugin.slash("status")
    assert "Fallbacks: none." in plugin.slash("status --verbose")


def test_gateway_model_switch_is_refused_while_locked(plugin):
    from types import SimpleNamespace as NS
    from hermes_cli.plugins import invoke_hook
    assert invoke_hook("pre_gateway_dispatch", event=NS(text="/model openrouter:x")) == []      # unlocked
    assert plugin.slash("on on-host-only").startswith("Locked")
    out = invoke_hook("pre_gateway_dispatch", event=NS(text="/model openrouter:x"))
    assert out == [{"action": "rewrite", "text": "/confidential blocked model"}]
    assert plugin.slash("blocked model").startswith("Refused while locked: /model")
    assert invoke_hook("pre_gateway_dispatch", event=NS(text="/moa hi")) == [
        {"action": "rewrite", "text": "/confidential blocked moa"}]
    assert invoke_hook("pre_gateway_dispatch", event=NS(text="/help")) == []
    assert invoke_hook("pre_gateway_dispatch", event=NS(text="model please")) == []


def test_gateway_commands_fail_closed_when_resolve_command_is_unavailable(plugin, monkeypatch):
    """Review finding 27: without hermes_cli.commands.resolve_command an alias of /model cannot be told apart,
    so while locked every slash command except /confidential is refused (it used to match the typed word)."""
    import types
    from types import SimpleNamespace as NS
    from hermes_cli.plugins import invoke_hook
    assert plugin.slash("on on-host-only").startswith("Locked")
    monkeypatch.setitem(sys.modules, "hermes_cli.commands", types.ModuleType("hermes_cli.commands"))
    for text in ("/m openrouter:x", "/usage", "/model x", "/retry"):
        word = text[1:].split()[0]
        assert invoke_hook("pre_gateway_dispatch", event=NS(text=text)) == [
            {"action": "rewrite", "text": f"/confidential blocked {word} unresolved"}]
    # The escape hatches stay usable: unlock, stop the agent, answer approvals, new session, help, status.
    for text in ("/confidential off", "/stop", "/approve", "/deny", "/new", "/help", "/status", "/pause"):
        assert invoke_hook("pre_gateway_dispatch", event=NS(text=text)) == [], text
    assert "cannot resolve /m" in plugin.slash("blocked m unresolved")
    assert ("tool_refused", "command_unresolved") in plugin.kinds()


def test_lock_refuses_when_hook_timeout_lets_the_recheck_be_skipped(plugin):
    plugin.cfg.write_text(BASE_CONFIG.replace("plugins:\n", "plugins:\n  hook_callback_timeout: 0.5\n"))
    out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked") and "plugins.hook_callback_timeout" in out
    plugin.cfg.write_text(BASE_CONFIG.replace("plugins:\n", "plugins:\n  hook_callback_timeout: 30\n"))
    assert plugin.slash("on on-host-only").startswith("Locked")


# ── hermes confidential replay ───────────────────────────────────────────────────────────────────

def _receipt_with_scenario_evidence(plugin, tmp_path):
    """A receipt whose verify_ok row carries the scenario fake adapter's evidence (tests/scenario/_fakes.py)."""
    from tests.scenario._fakes import FakeVendorAdapter, MockNet
    r = FakeVendorAdapter(MockNet()).verify()
    plugin.rt.ledger.append({"kind": "verify_ok", "provider": "attested-tinfoil", "purpose": "verify",
                             "host": r.enclave_host, "detail": {
                                 "vendor": r.vendor, "code_fingerprint": r.code_fingerprint,
                                 "enclave_fingerprint": r.enclave_fingerprint, "release_tag": r.release_tag,
                                 "enclave_host": r.enclave_host, "verifier": r.verifier, "evidence": r.evidence}})
    plugin.rt.ledger.append({"kind": "send_observed", "session_id": "sess-rp", "purpose": "main",
                             "host": r.enclave_host, "tier": "attested", "decision": "allowed"})
    path = tmp_path / "receipt.json"
    path.write_text(plugin.slash("receipts sess-rp --json"))
    return path, r


def _replay_parser(plugin):
    parser = argparse.ArgumentParser()
    plugin.mgr._cli_commands["confidential"]["setup_fn"](parser)
    return parser, plugin.mgr._cli_commands["confidential"]["handler_fn"]


def test_cli_replay_runs_the_real_replay_and_fails_on_scenario_evidence(plugin, tmp_path, capsys):
    path, _ = _receipt_with_scenario_evidence(plugin, tmp_path)
    parser, handler = _replay_parser(plugin)
    assert handler(parser.parse_args(["replay", str(path)])) == 1      # fake evidence is not schema v1
    out = capsys.readouterr().out
    replay = _sub(plugin, "verify.replay")
    assert "hash chain intact" in out and "Row #" in out and ": FAIL" in out
    assert f"  hardware_signature: fail: evidence: schema is not {replay.EVIDENCE_SCHEMA}" in out
    assert "repo: tinfoilsh/confidential-model-router" in out
    assert "enclave_host: router.tinfoil.invalid (asserted by capturer)" in out
    assert "Expected repo: tinfoilsh/confidential-model-router" in out
    assert "not independent" in out                                     # trust root and as_of sources named
    for line in replay.NOT_ESTABLISHED:
        assert f"  - {line}\n" in out                                   # verbatim


def test_cli_replay_passes_identity_arguments_and_exits_zero_only_when_all_match(plugin, tmp_path):
    import io
    path, r = _receipt_with_scenario_evidence(plugin, tmp_path)
    commands, replay = _sub(plugin, "commands"), _sub(plugin, "verify.replay")
    calls = []

    def ok_result(**over):
        base = dict(ok=True, checks={k: True for k in replay.CHECK_KEYS}, code_fingerprint=r.code_fingerprint,
                    enclave_fingerprint=r.enclave_fingerprint, release_tag=r.release_tag, tls_key_fp=None,
                    hpke_public_key=None, as_of="2026-11-06T00:00:00Z", sdk_version="0.14.2")
        base.update(over)
        return replay.ReplayResult(**base)

    def new_replay(evidence, *, as_of=None, expected_repo=None, expected_fingerprints=None, trusted_root=None):
        calls.append(dict(as_of=as_of, expected_repo=expected_repo, expected_fingerprints=expected_fingerprints,
                          trusted_root=trusted_root))
        return ok_result()

    args = argparse.Namespace(receipt=str(path), expected_repo="tinfoilsh/confidential-model-router",
                              trusted_root=str(tmp_path / "root.json"), as_of="2026-11-06T00:00:00Z")
    out = io.StringIO()
    assert commands.cli_replay(args, out=out, replay_fn=new_replay) == 0, out.getvalue()
    assert calls == [dict(as_of="2026-11-06T00:00:00Z", expected_repo="tinfoilsh/confidential-model-router",
                          expected_fingerprints=(r.code_fingerprint, r.enclave_fingerprint),
                          trusted_root=str(tmp_path / "root.json"))]
    assert "1/1 evidence row(s) replayed OK" in out.getvalue() and "(supplied with --trusted-root)" in out.getvalue()

    # An older replay without the identity parameters: the command checks repo and fingerprints itself.
    def old_replay(evidence, *, as_of=None, trust_root_dir=None):
        return ok_result()
    args.trusted_root = None
    out = io.StringIO()
    assert commands.cli_replay(args, out=out, replay_fn=old_replay) == 0, out.getvalue()  # repo + fps match
    args.expected_repo = "someone/else"
    out = io.StringIO()
    assert commands.cli_replay(args, out=out, replay_fn=old_replay) == 1
    assert "is not the expected someone/else" in out.getvalue()
    args.expected_repo = "tinfoilsh/confidential-model-router"
    out = io.StringIO()
    wrong = lambda evidence, *, as_of=None, trust_root_dir=None: ok_result(code_fingerprint="0" * 64)  # noqa: E731
    assert commands.cli_replay(args, out=out, replay_fn=wrong) == 1
    assert "do not match the expected ones (taken from the receipt itself (not independent))" in out.getvalue()
    # A replay that is not ok fails, and an unreadable receipt is exit 2.
    assert commands.cli_replay(args, out=io.StringIO(), replay_fn=lambda e, **k: ok_result(ok=False)) == 1
    args.receipt = str(tmp_path / "missing.json")
    assert commands.cli_replay(args, out=io.StringIO(), replay_fn=new_replay) == 2


def test_cli_replay_exits_nonzero_on_a_broken_hash_chain_even_when_evidence_replays(plugin, tmp_path):
    """Review finding 10: an edited receipt (a row changed without re-hashing) whose evidence still
    replays must not exit 0."""
    import io
    path, r = _receipt_with_scenario_evidence(plugin, tmp_path)
    commands, replay = _sub(plugin, "commands"), _sub(plugin, "verify.replay")

    def ok_replay(evidence, *, as_of=None, expected_repo=None, expected_fingerprints=None, trusted_root=None):
        return replay.ReplayResult(ok=True, checks={k: True for k in replay.CHECK_KEYS},
                                   code_fingerprint=r.code_fingerprint, enclave_fingerprint=r.enclave_fingerprint,
                                   release_tag=r.release_tag, tls_key_fp=None, hpke_public_key=None,
                                   as_of="2026-11-06T00:00:00Z", sdk_version="0.14.2")

    args = argparse.Namespace(receipt=str(path), expected_repo="tinfoilsh/confidential-model-router",
                              trusted_root=None, as_of=None)
    out = io.StringIO()
    assert commands.cli_replay(args, out=out, replay_fn=ok_replay) == 0, out.getvalue()
    doc = json.loads(path.read_text())
    edited = next(row for row in doc["rows"] if isinstance(row, dict) and row.get("kind") != "verify_ok")
    edited["decision"] = "edited-after-render"
    path.write_text(json.dumps(doc))
    out = io.StringIO()
    assert commands.cli_replay(args, out=out, replay_fn=ok_replay) == 1
    assert "hash chain BROKEN" in out.getvalue() and "1/1 evidence row(s) replayed OK" in out.getvalue()
    assert "the replay fails" in out.getvalue()


def test_receipt_states_the_configured_ttl_and_status_shows_the_plugin_commit(plugin, monkeypatch):
    receipts = _sub(plugin, "receipts")
    seen = {}
    real = receipts.render

    def spy(ledger, session_id, **kw):
        seen.update(kw)
        return real(ledger, session_id, **kw)
    monkeypatch.setattr(receipts, "render", spy)
    plugin.cfg.write_text(BASE_CONFIG + "confidential:\n  verify_ttl_seconds: 120\n")
    plugin.rt.ledger.append({"kind": "send_observed", "session_id": "sess-ttl", "purpose": "main", "host": "127.0.0.1"})
    plugin.slash("receipts sess-ttl --json")
    assert seen["ttl_seconds"] == 120.0
    plugin.cfg.write_text(BASE_CONFIG)
    seen.clear()
    plugin.slash("receipts sess-ttl")
    assert "ttl_seconds" not in seen                       # unset: the receipt states its own default
    version = _sub(plugin, "_version")
    monkeypatch.setattr(version, "PLUGIN_COMMIT", "abc1234")
    assert f"Plugin: confidential-mode {version.PLUGIN_VERSION} (commit abc1234)" in plugin.slash("status")


def test_stamp_version_script_round_trips(tmp_path):
    import shutil
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    work = tmp_path / "repo"
    (work / "confidential_mode").mkdir(parents=True)
    (work / "scripts").mkdir()
    shutil.copy(root / "scripts" / "stamp_version.py", work / "scripts")
    shutil.copy(root / "confidential_mode" / "_version.py", work / "confidential_mode")
    git = lambda *a: subprocess.run(["git", *a], cwd=work, check=True, capture_output=True, text=True).stdout.strip()  # noqa: E731
    git("init", "-q")
    git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x")
    sha = git("rev-parse", "--short", "HEAD")
    run = lambda *a: subprocess.run([sys.executable, str(work / "scripts" / "stamp_version.py"), *a], check=True)  # noqa: E731
    run()
    assert f'PLUGIN_COMMIT = "{sha}"' in (work / "confidential_mode" / "_version.py").read_text()
    (work / "other.txt").write_text("x")
    run()
    assert f'PLUGIN_COMMIT = "{sha}-dirty"' in (work / "confidential_mode" / "_version.py").read_text()
    run("--reset")
    assert 'PLUGIN_COMMIT = "unpackaged"' in (work / "confidential_mode" / "_version.py").read_text()


def test_cli_replay_expected_fingerprints_come_from_the_pin_or_the_flag_not_the_receipt(plugin, tmp_path):
    import io
    path, r = _receipt_with_scenario_evidence(plugin, tmp_path)
    commands, replay = _sub(plugin, "commands"), _sub(plugin, "verify.replay")
    calls = []

    def result(**over):
        base = dict(ok=True, checks={k: True for k in replay.CHECK_KEYS}, code_fingerprint=r.code_fingerprint,
                    enclave_fingerprint=r.enclave_fingerprint, release_tag=r.release_tag, tls_key_fp=None,
                    hpke_public_key=None, as_of="2026-11-06T00:00:00Z", sdk_version="0.14.2",
                    enclave_host="router.tinfoil.invalid", captured_at="2026-11-06T00:00:00Z",
                    repo="tinfoilsh/confidential-model-router")
        base.update(over)
        return replay.ReplayResult(**base)

    def ids_replay(evidence, *, expected_repo=None, expected_fingerprints=None, trusted_root=None, as_of=None,
                   expected_repo_id=None, expected_owner_id=None):
        calls.append((expected_fingerprints, expected_repo_id, expected_owner_id))
        ok = expected_fingerprints == (r.code_fingerprint, r.enclave_fingerprint)
        return result(ok=ok)

    def args(**kw):
        base = dict(receipt=str(path), expected_repo="tinfoilsh/confidential-model-router", trusted_root=None,
                    as_of=None, pins=None, expected_fingerprints=None, expected_repo_id=None, expected_owner_id=None)
        base.update(kw)
        return argparse.Namespace(**base)

    # 1. No pin yet: the receipt's own values, labelled as not independent.
    out = io.StringIO()
    assert commands.cli_replay(args(), out=out, replay_fn=ids_replay, rt=plugin.rt) == 0
    text = out.getvalue()
    assert "expected fingerprints: taken from the receipt itself (not independent)" in text
    assert "enclave_host: router.tinfoil.invalid (asserted by capturer)" in text
    assert "captured_at: 2026-11-06T00:00:00Z (asserted by capturer)" in text

    # 2. The human-approved pin (a different build) supplies the expectation: the self-report no longer passes.
    pins = plugin.rt.pins
    pins.apply(pins.stage(_result(plugin, code="ab" * 32, enclave="cd" * 32)), approved_via="test")
    out = io.StringIO()
    assert commands.cli_replay(args(), out=out, replay_fn=ids_replay, rt=plugin.rt) == 1
    assert calls[-1][0] == ("ab" * 32, "cd" * 32)
    assert f"the pin in {pins.path} (approved by human" in out.getvalue()
    # ... and an older replay without expected_fingerprints is checked here against the pin.
    old = lambda evidence, *, as_of=None, trust_root_dir=None: result()  # noqa: E731
    out = io.StringIO()
    assert commands.cli_replay(args(), out=out, replay_fn=old, rt=plugin.rt) == 1
    assert "do not match the expected ones (the pin in" in out.getvalue()
    # --pins PATH picks another pins file; an unreadable one is exit 2.
    other = _sub(plugin, "pins").PinStore(tmp_path / "other-pins.yaml")
    other.apply(other.stage(_result(plugin, code=r.code_fingerprint, enclave=r.enclave_fingerprint)),
                approved_via="test")
    assert commands.cli_replay(args(pins=str(other.path)), out=io.StringIO(), replay_fn=ids_replay, rt=plugin.rt) == 0
    assert commands.cli_replay(args(pins=str(tmp_path / "nope.yaml")), out=io.StringIO(), replay_fn=ids_replay,
                               rt=plugin.rt) == 2

    # 3. --expected-fingerprints overrides the pin; malformed is exit 2.
    flag = f"{r.code_fingerprint}:{r.enclave_fingerprint}"
    out = io.StringIO()
    assert commands.cli_replay(args(expected_fingerprints=flag), out=out, replay_fn=ids_replay, rt=plugin.rt) == 0
    assert "expected fingerprints: --expected-fingerprints" in out.getvalue()
    assert commands.cli_replay(args(expected_fingerprints="nothex"), out=io.StringIO(), replay_fn=ids_replay,
                               rt=plugin.rt) == 2

    # 4. Numeric repo / owner ids pass through when replay accepts them; otherwise the row fails.
    assert commands.cli_replay(args(expected_fingerprints=flag, expected_repo_id="123", expected_owner_id="456"),
                               out=io.StringIO(), replay_fn=ids_replay, rt=plugin.rt) == 0
    assert calls[-1][1:] == ("123", "456")
    out = io.StringIO()
    assert commands.cli_replay(args(expected_fingerprints=flag, expected_repo_id="123"), out=out,
                               replay_fn=lambda e, *, expected_repo=None, expected_fingerprints=None, as_of=None,
                               trusted_root=None: result(), rt=plugin.rt) == 1
    assert "cannot check --expected-repo-id" in out.getvalue()


def test_cli_replay_flags_parse(plugin):
    parser, _ = _replay_parser(plugin)
    a = parser.parse_args(["replay", "r.json", "--pins", "p.yaml", "--expected-fingerprints", "aa:bb",
                           "--expected-repo-id", "1", "--expected-owner-id", "2"])
    assert (a.pins, a.expected_fingerprints, a.expected_repo_id, a.expected_owner_id) == ("p.yaml", "aa:bb", "1", "2")


def _setup_block(plugin, capsys, *argv):
    parser, handler = _replay_parser(plugin)
    assert handler(parser.parse_args(["setup", "--no-verify", *argv])) == 0
    out = capsys.readouterr().out
    import hermes_yaml
    return out, hermes_yaml.safe_load(out[out.index("# Add to config.yaml"):out.index("Then run")])


def test_setup_block_gives_vision_and_side_jobs_suitable_models(plugin, capsys, monkeypatch):
    out, cfg = _setup_block(plugin, capsys, "--model", "llama3-3-70b")
    aux = cfg["auxiliary"]
    assert cfg["model"] == {"provider": "attested-tinfoil", "default": "llama3-3-70b"}
    assert aux["vision"]["model"] == "gemma4-31b"
    for task in ("title_generation", "compression", "approval", "mcp", "memory_query_rewrite"):
        assert aux[task] == {"provider": "attested-tinfoil", "model": "deepseek-v4-1-flash"}, task
    assert aux["background_review"]["model"] == "llama3-3-70b"
    assert all(v["provider"] == "attested-tinfoil" for v in aux.values())
    assert {"moa_reference", "moa_aggregator"} <= set(aux)      # every side call pinned (Amendment 11)
    for marker in ("# vision: a vision-capable model", "# short side jobs", "# tasks that reason over"):
        assert out.count(marker) == 1, marker
    assert "confidential:" not in out                          # --no-verify resolved no host
    out, cfg = _setup_block(plugin, capsys, "--model", "m", "--vision-model", "v", "--aux-model", "a")
    assert cfg["auxiliary"]["vision"]["model"] == "v" and cfg["auxiliary"]["title_generation"]["model"] == "a"
    # The printed block passes the attested preflight structurally (no network), with the key set.
    monkeypatch.setenv("TINFOIL_API_KEY", "test-key")
    locking = _sub(plugin, "locking")
    report = locking.run_tier_preflight("attested", config=cfg,
                                        predicate=locking.structural_predicate("attested", config=cfg))
    assert report.ok, _sub(plugin, "preflight").format_report(report)


def test_setup_prints_the_resolved_enclave_line(plugin):
    import io
    commands = _sub(plugin, "commands")
    block = commands.config_block(plugin.rt, "m", enclave="router-3.inf6.tinfoil.sh")
    assert block.rstrip().endswith("  tinfoil:\n    # the router this setup verified and pinned; without it each "
                                   "restart may pick another\n    # router (possibly another hardware platform) and "
                                   "refuse until you re-approve the pin\n    enclave: router-3.inf6.tinfoil.sh")


# ── CLI verbs mirroring /confidential (scriptable demo / live tests) ─────────────────────────────

def _hermes(plugin, *argv, stdin=None):
    import os
    import subprocess
    from pathlib import Path
    exe = Path(sys.executable).with_name("hermes")
    cmd = [str(exe)] if exe.exists() else [sys.executable, "-m", "hermes_cli.main"]
    env = {**os.environ, "HERMES_HOME": str(plugin.home), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(cmd + ["confidential", *argv], capture_output=True, text=True, env=env, timeout=180,
                          input=stdin)


def test_cli_on_and_off_in_another_process_govern_the_running_gateway(plugin, monkeypatch):
    """`hermes confidential on/off` in a separate process (the scripted demo) writes the same ctx.state; the
    loaded plugin (the 'gateway') reads it fresh on its next turn and its allowlist follows the new lock."""
    from .test_register import ON_HOST_URL, REMOTE_URL, build_agent
    from ._harness import Rec
    proc = _hermes(plugin, "on", "on-host-only")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("Locked to this machine (on-host-only)") and len(proc.stdout.splitlines()) == 3
    verbose = _hermes(plugin, "status", "--verbose")
    assert "confidential preflight: tier=on-host-only PASS" in verbose.stdout and "Tools:" in verbose.stdout
    tiers = _sub(plugin, "tiers")
    assert plugin.rt.state.locked() == (True, tiers.Tier.ON_HOST)
    rec = Rec()
    agent = build_agent(monkeypatch, rec, REMOTE_URL)
    assert agent.run_conversation("q1")["final_response"].startswith("Confidential mode: locked to on-host-only")
    assert rec.provider_calls == []
    # The gateway's allowlist is the one persisted by the CLI's lock, not a stale or empty one.
    gt = _sub(plugin, "gate_tools")
    al = plugin.rt.allowlist()
    assert al.lock_id == gt.lock_id_for(plugin.rt.state) and al.get("web_search").route is gt.Route.ASK
    # The CLI process imported the built-in tools before building it (else every tool would be unclassified).
    assert al.get("read_file").route is gt.Route.ON_HOST and len(al.tools) > 40
    # An addition approved in another process (same lock) is honoured without a restart.
    from tools.registry import registry
    other = gt.Allowlist.load_persisted(plugin.rt.allowlist_path, registry, lock_id=al.lock_id)
    other.add("web_search")
    assert plugin.rt.allowlist().is_added("web_search")
    proc = _hermes(plugin, "off")
    assert proc.returncode == 0 and proc.stdout.startswith("Unlocked (on-host-only)"), proc.stdout + proc.stderr
    assert agent.run_conversation("q2")["final_response"] == "provider answered"
    # A relock from the CLI starts a new lock: the earlier addition does not carry over.
    assert _hermes(plugin, "on", "on-host-only").returncode == 0
    assert not plugin.rt.allowlist().is_added("web_search")
    ok = build_agent(monkeypatch, Rec(), ON_HOST_URL).run_conversation("q3")
    assert ok["final_response"] == "provider answered"


def test_allowlist_is_on_disk_before_the_lock_flag_and_an_empty_cache_is_rebuilt(plugin):
    """Review finding 9: the lock writes allowlist.yaml before the locked flag, and a process that cached an
    empty allowlist for the current lock (file missing when it first looked) rebuilds once the file appears."""
    import os
    gt, state_mod = _sub(plugin, "gate_tools"), _sub(plugin, "state")
    path = plugin.rt.allowlist_path
    seen = {}
    real_lock = state_mod.ConfidentialState.lock

    def spy(self, tier, fp, **kw):
        seen["file_before_flag"] = os.path.exists(path)
        seen["lock_id_in_file"] = json.loads(open(path).read()).get("lock_id")
        return real_lock(self, tier, fp, **kw)
    state_mod.ConfidentialState.lock = spy
    try:
        assert plugin.slash("on on-host-only").startswith("Locked")
    finally:
        state_mod.ConfidentialState.lock = real_lock
    assert seen["file_before_flag"] is True and seen["lock_id_in_file"] == gt.lock_id_for(plugin.rt.state)
    # A second process (here: this runtime with its cache cleared) looks while the file is missing...
    saved = open(path).read()
    os.unlink(path)
    plugin.rt._allowlist = None
    assert plugin.rt.allowlist().tools == {}
    # ...then the file appears for the same lock: the empty cache is rebuilt, not merged into.
    open(path, "w").write(saved)
    os.utime(path, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
    al = plugin.rt.allowlist()
    assert al.get("read_file").route is gt.Route.ON_HOST and al.get("web_search").route is gt.Route.ASK


def test_cli_on_refusal_and_receipts_exit_codes(plugin):
    plugin.cfg.write_text(BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    proc = _hermes(plugin, "on", "on-host-only")
    assert proc.returncode == 1 and proc.stdout.startswith("Not locked") and "fallback_providers[0]" in proc.stdout
    plugin.cfg.write_text(BASE_CONFIG)
    assert _hermes(plugin, "receipts").returncode == 2
    plugin.rt.ledger.append({"kind": "send_observed", "session_id": "sess-cli", "purpose": "main", "host": "127.0.0.1"})
    proc = _hermes(plugin, "receipts", "sess-cli", "--json")
    assert proc.returncode == 0, proc.stderr
    assert _sub(plugin, "receipts").verify_chain(json.loads(proc.stdout))


def test_cli_pins_and_allow_use_the_exact_terminal_asker(plugin):
    import io
    commands = _sub(plugin, "commands")

    class TTY(io.StringIO):
        def isatty(self):
            return True

    def run(action, **kw):
        out = io.StringIO()
        rc = commands.cli_verb(plugin.rt, action, argparse.Namespace(**kw), out=out,
                               asker=commands.TerminalAsker(TTY(ANSWER[0]), io.StringIO()))
        return rc, out.getvalue()

    ANSWER = ["yes\n"]
    plugin.rt.pins.stage(_result(plugin))
    rc, out = run("pins", pins_action=None)
    assert rc == 0 and "Pending pin: tinfoil" in out
    rc, out = run("pins", pins_action="approve")                     # "yes" is not an exact choice
    assert rc == 1 and plugin.rt.pins.pending() is not None
    ANSWER[0] = "approve\n"
    rc, out = run("pins", pins_action="approve")
    assert rc == 0 and out.startswith("Pinned tinfoil") and plugin.rt.pins.pending() is None
    rc, out = run("allow", tool="web_search")
    assert rc == 1 and out.startswith("Not locked")
    assert run("on", tier="on-host-only")[0] == 0
    ANSWER[0] = "1\n"
    rc, out = run("allow", tool="web_search")
    assert rc == 0 and plugin.rt.allowlist().is_added("web_search"), out
    rc, out = run("off")
    assert rc == 0 and out.startswith("Unlocked")
    # The non-tty default asker (a script) answers nobody: nothing is pinned.
    plugin.rt.pins.stage(_result(plugin, code="ab" * 32))
    out = io.StringIO()
    assert commands.cli_verb(plugin.rt, "pins", argparse.Namespace(pins_action="approve"), out=out) == 1
    assert plugin.rt.pins.pending() is not None


def test_cli_verbs_parse(plugin):
    parser, _ = _replay_parser(plugin)
    assert parser.parse_args(["on", "attested"]).tier == "attested"
    assert parser.parse_args(["pins", "approve"]).pins_action == "approve"
    assert parser.parse_args(["pins"]).pins_action is None
    a = parser.parse_args(["receipts", "s1", "--json"])
    assert (a.session, a.json) == ("s1", True)
    assert parser.parse_args(["allow", "web_search"]).tool == "web_search"
    assert parser.parse_args(["off"]).confidential_action == "off"


def test_near_setup_block_routes_vision_through_near_with_the_plaintext_note(plugin, capsys, monkeypatch):
    """Amendment 9: image parts leave as plaintext to NEAR's gateway beside the encrypted text, so `setup
    --vendor near` routes auxiliary.vision through attested-near again, with a NEAR vision model and a note."""
    out, cfg = _setup_block(plugin, capsys, "--vendor", "near", "--model", "Qwen/Qwen3.8-27B")
    aux = cfg["auxiliary"]
    assert cfg["model"] == {"provider": "attested-near", "default": "Qwen/Qwen3.8-27B"}
    assert aux["vision"] == {"provider": "attested-near", "model": "Qwen/Qwen3-VL-30B-A3B-Instruct"}
    assert all(v == {"provider": "attested-near", "model": "Qwen/Qwen3.8-27B"} for k, v in aux.items() if k != "vision")
    assert cfg["confidential"]["near"]["models"] == ["Qwen/Qwen3-VL-30B-A3B-Instruct", "Qwen/Qwen3.8-27B"]
    assert cfg["confidential"]["near"]["image_parts"] == "disclose"
    assert out.index("auxiliary.vision goes through attested-near") < out.index("# Add to config.yaml")
    assert "each image leaves" in out and "in plaintext to NEAR's gateway" in out
    assert "#   vision: {provider: attested-tinfoil, model: gemma4-31b}" in out
    monkeypatch.setenv("NEAR_AI_API_KEY", "test-key")
    locking = _sub(plugin, "locking")
    report = locking.run_tier_preflight("attested", config=cfg,
                                        predicate=locking.structural_predicate("attested", config=cfg))
    assert report.ok, _sub(plugin, "preflight").format_report(report)
    out, cfg = _setup_block(plugin, capsys, "--vendor", "near", "--model", "m", "--vision-model", "v")
    assert cfg["auxiliary"]["vision"]["model"] == "v" and cfg["confidential"]["near"]["models"] == ["m", "v"]


# ── Amendment 14: the command form that works where the user is ────────────────────────────────────

def test_status_and_refusals_print_the_form_for_the_surface(plugin, capsys):
    commands = _sub(plugin, "commands")
    assert "Preflight: run /confidential check <tier>" in plugin.slash("status")
    assert "Preflight: run hermes confidential check --tier <tier>" in commands.status_text(plugin.rt, form="terminal")
    parser, handler = _replay_parser(plugin)
    assert handler(parser.parse_args(["status"])) == 0
    assert "hermes confidential check --tier <tier>" in capsys.readouterr().out
    assert "Lock first with /confidential on <tier>" in plugin.slash("allow web_search")
    import io
    out = io.StringIO()
    commands.cli_verb(plugin.rt, "allow", argparse.Namespace(tool="web_search"), out=out)
    assert "Lock first with hermes confidential on <tier>" in out.getvalue()
    assert plugin.slash("on on-host-only").startswith("Locked")
    assert "Run /confidential off first" in plugin.slash("on on-host-only")
    out = io.StringIO()
    commands.cli_verb(plugin.rt, "on", argparse.Namespace(tier="on-host-only"), out=out)
    assert "Run hermes confidential off first" in out.getvalue()


def test_cli_check_takes_a_positional_tier_and_names_the_tier_it_checks(plugin, capsys):
    parser, handler = _replay_parser(plugin)
    assert parser.parse_args(["check", "attested"]).tier_name == "attested"
    assert handler(parser.parse_args(["check", "on-host-only"])) == 0
    out = capsys.readouterr().out
    assert out.startswith("confidential preflight: tier=on-host-only PASS")
    assert handler(parser.parse_args(["check"])) == 0
    out = capsys.readouterr().out
    assert out.startswith("Checking the on-host-only tier (model.base_url is on this machine). To check the "
                          "other tier: hermes confidential check --tier attested\n"), out
    assert handler(parser.parse_args(["check", "attested", "--tier", "on-host-only"])) == 2
    assert plugin.slash("check").startswith("Checking the on-host-only tier (model.base_url is on this "
                                            "machine). To check the other tier: /confidential check attested")

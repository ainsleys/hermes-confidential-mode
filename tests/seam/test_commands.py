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
                                   verified_at_local=time.time() - 42, evidence={})


def human(answer):
    asked = []

    def asker(question, labels):
        asked.append((question, labels))
        return answer
    return asker, asked


def test_usage_and_unknown(plugin):
    assert plugin.slash("").startswith("Usage: /confidential")
    assert plugin.slash("frobnicate").startswith("Usage: /confidential")


def test_status_unsealed_and_sealed(plugin):
    out = plugin.slash("status")
    assert "not sealed" in out and "Provider/model: custom / llama3 at 127.0.0.1" in out
    assert "Enclave host: (unresolved" in out and "Pinned: none" in out and "Pending pin: none" in out
    assert "(local clock)" in out and "Tool grants (allowlist): none" in out
    assert plugin.slash("on local-only").startswith("Sealed")
    out = plugin.slash("status")
    assert "SEALED (local-only)" in out and "(local clock)" in out
    assert "Preflight (local-only, routing config): PASS; config unchanged since seal" in out
    assert "Breach: none this seal" in out


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
    assert "Last verification: 42s ago (local clock)" in out or "Last verification: 43s ago (local clock)" in out


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
    assert plugin.slash("allow web_search").startswith("Not sealed")
    assert plugin.slash("on local-only").startswith("Sealed")
    asker, asked = human("Allow")
    with bind_asker(asker):
        out = plugin.slash("allow web_search")
    assert out == "web_search added to the allowlist for this seal." and len(asked) == 1
    assert plugin.slash("allow cronjob_manage").startswith("cronjob_manage cannot be allowed")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    plugin.human("deny")                                            # would refuse if asked
    model_tools.handle_function_call("web_search", {"query": "x"}, task_id="t", session_id="s", tool_call_id="c1")
    assert ran == [{"query": "x"}] and plugin.prompts == []
    assert "Tool grants (allowlist): web_search" in plugin.slash("status")


def test_off_prints_counts_and_repairs_unreadable_state(plugin):
    assert plugin.slash("on local-only").startswith("Sealed")
    from hermes_cli.plugins import invoke_hook
    plugin.rt.ledger.append({"kind": "tool_refused", "purpose": "tool:x", "decision": "cron"})
    plugin.rt.ledger.append({"kind": "tool_asked", "purpose": "tool:y", "decision": "ask"})
    out = plugin.slash("off")
    assert out.startswith("Unsealed (local-only). Sealed for") and "1 refusal(s)" in out and "1 ask(s)" in out
    assert plugin.rt.state.sealed() == (False, None)
    plugin.rt.ctx.state.set("sealed", "corrupt")
    assert "UNREADABLE" in plugin.slash("status")
    blocked = invoke_hook("pre_llm_call", session_id="s")
    assert blocked and blocked[0]["action"] == "block"
    assert plugin.slash("off").startswith("Seal state was unreadable; it is now cleared")
    assert plugin.rt.state.sealed() == (False, None)


def test_check_prints_the_preflight_table(plugin):
    out = plugin.slash("check local-only")
    assert out.startswith("confidential preflight: tier=local-only PASS")
    assert "KEY" in out and "VERDICT" in out and "auxiliary.vision.provider" in out
    assert plugin.slash("check zero-retention").startswith("zero-retention: zero-retention tier not implemented")


def test_receipts_delegate_to_w6_render(plugin, monkeypatch):
    assert plugin.slash("on local-only").startswith("Sealed")
    plugin.rt.ledger.append({"kind": "tool_refused", "session_id": "sess-1", "purpose": "tool:web_search",
                             "decision": "cron"})
    text = plugin.slash("receipts sess-1")
    assert "sess-1" in text and "local clock" in text
    receipts = _sub(plugin, "receipts")
    doc = json.loads(plugin.slash("receipts sess-1 --json"))
    assert receipts.verify_chain(doc)
    fake = types.ModuleType("receipts")
    fake.render = lambda ledger, session: f"RECEIPT {session}"          # an older two-argument render
    monkeypatch.setitem(sys.modules, f"{plugin.mod.__name__}.confidential_mode.receipts", fake)
    assert plugin.slash("receipts", session_id="sess-cur") == "RECEIPT sess-cur"
    monkeypatch.setitem(sys.modules, f"{plugin.mod.__name__}.confidential_mode.receipts", None)   # absent
    assert plugin.slash("receipts sess-1").startswith("Receipts are not available")


def test_slash_watch_shows_the_ledger(plugin):
    plugin.slash("on local-only")
    out = plugin.slash("watch")
    assert out.splitlines()[0].startswith("TIME") and "seal in_tier sealed" in out
    assert "\x1b[" not in out


def test_cli_status_check_watch(plugin, capsys):
    entry = plugin.mgr._cli_commands["confidential"]
    parser = argparse.ArgumentParser()
    entry["setup_fn"](parser)
    assert entry["handler_fn"](parser.parse_args(["status"])) == 0
    assert "not sealed" in capsys.readouterr().out
    assert entry["handler_fn"](parser.parse_args(["check", "--tier", "local-only"])) == 0
    assert "tier=local-only PASS" in capsys.readouterr().out
    plugin.slash("on local-only")
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


def test_attested_seal_message_and_refusal_reason_without_network(plugin, monkeypatch):
    """Attested tier through the real AttestedPredicate and profile lookup; only W2's attested_ok (which
    would attest over the network) is replaced."""
    provider = _sub(plugin, "provider")
    tiers = _sub(plugin, "tiers")
    verdict = {"v": tiers.Verdict(False, "no approved enclave build pinned; run /confidential pins approve")}
    monkeypatch.setattr(provider, "attested_ok", lambda name: verdict["v"])
    plugin.cfg.write_text(ATTESTED_CONFIG)
    out = plugin.slash("on attested")
    assert out.startswith("Not sealed") and "no approved enclave build pinned" in out
    verdict["v"] = tiers.Verdict(True, "attested enclave verified and pinned", "router.tinfoil.invalid")
    entry = provider.verification_cache.entry("attested-tinfoil")
    entry.result, entry.verified_mono = _result(plugin), time.monotonic()
    out = plugin.slash("on attested")
    assert out.startswith("Sealed. Model: attested-tinfoil/llama3-3-70b at router.tinfoil.invalid, verified 4")
    assert "ago (local clock). Web, browser, messaging, media and remote MCP tools are off. Memory: local. " \
           "Fallbacks: none." in out
    assert "SEALED (attested)" in plugin.slash("status")

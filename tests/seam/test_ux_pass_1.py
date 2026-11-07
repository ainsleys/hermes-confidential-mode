"""Seam tests for ux-pass-1 (INTERFACES Amendment 11), on the plugin loaded by real discovery: the pending-pin
note on an attested lock, `check` exit codes, `/confidential help` parity with the CLI, the unattended
refusal text, the approval size with an image, the 0600 data files, and receipts that show each send once."""
from __future__ import annotations

import argparse
import importlib
import json
import os
import stat
import time

from .test_commands import ATTESTED_CONFIG, _result, _sub
from .test_register import plugin  # noqa: F401  (fixture)
from ._harness import no_lazy_installs  # noqa: F401  (fixture)


def _cli(plugin):
    parser = argparse.ArgumentParser()
    plugin.mgr._cli_commands["confidential"]["setup_fn"](parser)
    return parser, plugin.mgr._cli_commands["confidential"]["handler_fn"]


def test_a_lock_with_a_pin_pending_says_so_in_the_reply_and_in_status(plugin, monkeypatch):
    """A lock can pass on an approved instance while another instance of the same model is pending (NEAR
    runs several). The reply and status say so, because a send that reaches the pending one is refused."""
    provider, tiers = _sub(plugin, "provider"), _sub(plugin, "tiers")
    monkeypatch.setattr(provider, "attested_ok", lambda name: tiers.Verdict(True, "ok", "router.tinfoil.invalid"))
    monkeypatch.setenv("TINFOIL_API_KEY", "test-key")
    plugin.cfg.write_text(ATTESTED_CONFIG)
    entry = provider.verification_cache.entry("attested-tinfoil")
    entry.result, entry.verified_mono = _result(plugin), time.monotonic()
    plugin.rt.pins.stage(_result(plugin, code="ab" * 32))
    out = plugin.slash("on attested")
    first, disclosures, details, second = out.split("\n")
    assert first.startswith("Locked to Tinfoil, llama3-3-70b at router.tinfoil.invalid; verified ")
    assert disclosures == ("Off-host tools ask first. Shell and code execution are not inspected. Auxiliary calls "
                           "are recorded, not refused. Not active in safe-worker mode.")
    assert details == "Details: hermes confidential status --verbose; docs/LIMITATIONS.md"
    assert second.startswith("A pin update for tinfoil is pending (1 entry). This lock uses the approved builds")
    assert "hermes confidential pins review, then hermes confidential pins approve" in second
    assert "Locked with a pin pending: A pin update for tinfoil is pending" in plugin.slash("status")


def test_attested_lock_without_the_key_is_refused_by_the_preflight(plugin, monkeypatch):
    provider, tiers = _sub(plugin, "provider"), _sub(plugin, "tiers")
    monkeypatch.setattr(provider, "attested_ok", lambda name: tiers.Verdict(True, "ok", "router.tinfoil.invalid"))
    monkeypatch.delenv("TINFOIL_API_KEY", raising=False)
    plugin.cfg.write_text(ATTESTED_CONFIG)
    out = plugin.slash("on attested")
    assert out.startswith("Not locked") and "set TINFOIL_API_KEY (export the variable or add the variable" in out
    assert plugin.rt.state.locked() == (False, None)
    parser, handler = _cli(plugin)
    assert handler(parser.parse_args(["check", "--tier", "attested"])) == 1          # check exits 1 on FAIL
    monkeypatch.setenv("TINFOIL_API_KEY", "test-key")
    assert handler(parser.parse_args(["check", "--tier", "attested"])) == 0


def test_check_exits_1_on_fail_and_0_on_pass(plugin, capsys):
    parser, handler = _cli(plugin)
    assert handler(parser.parse_args(["check", "--tier", "on-host-only"])) == 0
    plugin.cfg.write_text(plugin.cfg.read_text().replace("http://127.0.0.1:11434/v1", "https://llm.example.test/v1"))
    assert handler(parser.parse_args(["check", "--tier", "on-host-only"])) == 1
    assert "FAIL" in capsys.readouterr().out
    assert handler(parser.parse_args(["check", "--tier", "zero-retention"])) == 1


def test_chat_help_lists_every_cli_verb(plugin):
    parser, _ = _cli(plugin)
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    help_text = plugin.slash("help")
    verbs = [ln.split()[0] for ln in help_text.splitlines()[1:]]
    for verb in sub.choices:
        assert verb in verbs, verb
    assert "pins review" in help_text
    for verb in ("allow", "revoke", "receipts", "replay", "check", "status", "on", "off"):
        assert verb in verbs, verb
    assert plugin.slash("replay x.json").startswith("Replay reads a receipt file, so it runs only as a command")


def test_an_unattended_block_tells_the_model_the_command(plugin, monkeypatch):
    import model_tools
    assert plugin.slash("on on-host-only").startswith("Locked")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)            # nobody to ask: a one-shot run
    out = model_tools.handle_function_call("web_search", {"query": "q"}, task_id="t", session_id="s",
                                           tool_call_id="c1")
    assert ("web_search was blocked by confidential mode in an unattended run; to allow it, run: hermes "
            "confidential allow web_search, or run interactively to be asked") in out


def test_the_approval_size_counts_an_attached_image(plugin, tmp_path):
    gt = _sub(plugin, "gate_tools")
    img = tmp_path / "big.png"
    img.write_bytes(b"\x89PNG" + b"0" * (3 * 1024 * 1024))
    msg = gt.ask_message("vision_analyze", gt.call_bytes({"image_url": str(img), "question": "what"}))
    assert msg == "Confidential mode: vision_analyze wants to send ~3.0 MB of this conversation off the machine"
    small = tmp_path / "s.jpg"
    small.write_bytes(b"0" * 4000)
    assert gt.size_text(gt.call_bytes({"image_url": f"file://{small}"})) == "~5 KB"
    assert gt.call_bytes({"image_url": str(tmp_path / "missing.png")}) == gt.args_bytes({"image_url": str(tmp_path / "missing.png")})


def test_data_files_are_0600_and_an_old_0644_ledger_is_fixed_at_start(plugin):
    from plugins.plugin_storage import plugin_data_dir
    plugin.slash("on on-host-only")
    plugin.rt.ledger.append({"kind": "session_start", "session_id": "s", "purpose": "session"})
    ledger_file = plugin_data_dir("confidential-mode") / "ledger.sqlite"
    assert stat.S_IMODE(os.stat(ledger_file).st_mode) == 0o600
    for f in plugin.rt.ctx.state.data_dir.iterdir():
        if f.is_file() and not f.name.endswith(".lock"):     # Hermes' own empty lock files
            assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    os.chmod(ledger_file, 0o644)
    ledger = _sub(plugin, "ledger")
    fresh = ledger.Ledger()
    fresh.tail(0)                                                        # opening it re-applies the mode
    assert stat.S_IMODE(os.stat(ledger_file).st_mode) == 0o600
    # The registration walk runs once per commit, or again when a kept file's mode is wrong.
    state_dir, commit = plugin.rt.ctx.state.data_dir, _sub(plugin, "_version").PLUGIN_COMMIT
    assert ledger.needs_mode_walk(state_dir, ledger_file.parent, commit) is False      # done at registration
    os.chmod(ledger_file, 0o644)
    assert ledger.needs_mode_walk(state_dir, ledger_file.parent, commit) is True
    ledger.secure_data_files([ledger_file.parent])                       # the registration step
    assert stat.S_IMODE(os.stat(ledger_file).st_mode) == 0o600
    status = plugin.slash("status")
    assert f"Data: ledger and evidence in {ledger_file.parent}; lock, pins and tool grants in " in status


def test_a_receipt_shows_each_send_once_and_a_denial_once(plugin, monkeypatch):
    """The pre_api_request attempt row and the gate's row for the same call pair up by api_request_id; a
    denied tool has one ask and one refusal (one row from each enforcement point was written before)."""
    from hermes_cli.plugins import invoke_hook
    from tools.registry import registry
    monkeypatch.setattr(registry.get_entry("web_search"), "handler", lambda args, **kw: "{}")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert plugin.slash("on on-host-only").startswith("Locked")          # pins the patched handler
    invoke_hook("pre_api_request", provider="custom", base_url="http://127.0.0.1:11434/v1", model="llama3",
                api_mode="chat_completions", session_id="sess-r", request={"messages": []}, api_request_id="req-1")
    mw = [m for m in plugin.mgr._middleware["llm_execution"]][0]

    class Resp:
        def model_dump_json(self):
            return '{"choices": [1, 2, 3]}'
    mw(request={"model": "llama3", "messages": [{"role": "user", "content": "hi"}]}, next_call=lambda r: Resp(),
       session_id="sess-r", provider="custom", base_url="http://127.0.0.1:11434/v1", model="llama3",
       api_mode="chat_completions", api_request_id="req-1", platform="cli")
    tool_mw = plugin.mgr._middleware["tool_execution"][0]
    plugin.human("deny")
    tool_mw(tool_name="web_search", args={"query": "q"}, next_call=lambda a: "{}", session_id="sess-r",
            tool_call_id="tc-1", turn_id="t")
    rows = [e for e in plugin.rt.ledger.session("sess-r")]
    assert [(e.kind, e.decision) for e in rows if e.kind.startswith("tool_")] == [("tool_asked", "ask"),
                                                                                ("tool_refused", "deny")]
    text = plugin.slash("receipts sess-r")
    sends = text.split("Sends (purpose, host, request and response bytes; never text)\n")[1].split("\n\n")[0]
    lines = sends.splitlines()
    assert len(lines) == 1, sends
    assert "request " in lines[0] and "response 22 bytes" in lines[0] and "attempt, #" in lines[0]
    refusals = text.split("\nRefusals\n")[1].split("\n\n")[0].splitlines()
    assert len(refusals) == 1 and "tool:web_search" in refusals[0], refusals
    asks = text.split("\nAsks and answers\n")[1].split("\n\n")[0]
    assert asks.count("asked  tool:web_search") == 1 and asks.count("answer #") == 1, asks
    doc = json.loads(plugin.slash("receipts sess-r --json"))
    assert len(doc["sections"]["send_pairs"]) == 1 and len(doc["sections"]["sends"]) == 2   # both rows kept


def test_the_near_pin_prompt_explains_abliterated_services_only_when_present(plugin):
    consent = _sub(plugin, "consent")
    pending = {"vendor": "near", "router_repo": "cloud-api.near.ai#m", "components": [], "entries": [],
               "platform": "tdx", "code_fingerprint": "c" * 64, "enclave_fingerprint": "e" * 64}
    note = ('NEAR deploys services named "...-abliterated" in the same enclave as the base model. They share the '
            "enclave and its quote socket, and the plugin lists them for that reason.")
    assert note not in consent.pin_question(pending)
    pending["components"] = ["model m service proxy-qwen38-27b-abliterated image x"]
    assert note in consent.pin_question(pending)


def test_a_key_unreadable_mid_lock_refuses_the_call_and_records_no_breach(plugin, monkeypatch):
    """Review blocker 1: the key is checked at lock and in `check`, never in the per-turn recheck. A process
    that cannot read the key later refuses each call ("vendor key unreadable"), with no breach row."""
    from hermes_cli.plugins import invoke_hook
    provider, tiers = _sub(plugin, "provider"), _sub(plugin, "tiers")
    monkeypatch.setattr(provider, "attested_ok", lambda name: tiers.Verdict(True, "ok", "router.tinfoil.invalid"))
    monkeypatch.setenv("TINFOIL_API_KEY", "test-key")
    plugin.cfg.write_text(ATTESTED_CONFIG)
    entry = provider.verification_cache.entry("attested-tinfoil")
    entry.result, entry.verified_mono = _result(plugin), time.monotonic()
    assert plugin.slash("on attested").startswith("Locked to Tinfoil")
    monkeypatch.delenv("TINFOIL_API_KEY")
    import agent.credential_pool as pool_mod
    monkeypatch.setattr(pool_mod, "load_pool", lambda name: type("P", (), {"has_credentials": lambda self: False})())
    results = invoke_hook("pre_llm_call", session_id="sess-k")
    assert not any(isinstance(r, dict) and r.get("action") == "block" for r in results), results
    client = provider._create_client(plugin.rt.profile, provider.verification_cache, {})
    assert client.reason.startswith("vendor key unreadable: TINFOIL_API_KEY")
    mw = plugin.mgr._middleware["llm_execution"][0]
    monkeypatch.setattr(mw.gate, "attested_ok", lambda name: tiers.Verdict(True, "ok", "router.tinfoil.invalid"))
    mw(request={"model": "llama3-3-70b", "messages": [{"role": "user", "content": "hi"}]},
       next_call=lambda r: client.chat.completions.create(**r), session_id="sess-k", provider="attested-tinfoil",
       base_url=plugin.rt.profile.base_url, model="llama3-3-70b", api_mode="chat_completions",
       api_request_id="req-k", platform="cli")
    rows = plugin.rt.ledger.session("sess-k")
    assert not [e for e in rows if e.kind == "breach"]
    refused = [e for e in rows if e.kind == "send_refused"]
    assert len(refused) == 1 and refused[0].detail["reason_code"] == "vendor_key_unreadable"
    assert refused[0].detail["reason"].startswith("vendor key unreadable")


def test_tinfoil_setup_pins_every_side_call_and_an_openrouter_key_blocks_auto(plugin, monkeypatch, capsys):
    import hermes_yaml
    parser, handler = _cli(plugin)
    assert handler(parser.parse_args(["setup", "--no-verify", "--model", "llama3-3-70b"])) == 0
    out = capsys.readouterr().out
    cfg = hermes_yaml.safe_load(out[out.index("# Add to config.yaml"):out.index("Then run")])
    pf, locking = _sub(plugin, "preflight"), _sub(plugin, "locking")
    tasks = set(pf.builtin_aux_task_names())
    assert tasks <= set(cfg["auxiliary"]) and all(v["provider"] == "attested-tinfoil" for v in cfg["auxiliary"].values())
    monkeypatch.setenv("TINFOIL_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    report = locking.run_tier_preflight("attested", config=cfg, check_keys=True,
                                        predicate=locking.structural_predicate("attested", config=cfg))
    assert report.ok, pf.format_report(report)                      # nothing is left on auto
    # The on-host test config leaves side calls on auto: with an OpenRouter key readable, the lock refuses.
    out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked") and "auto can fall through to OpenRouter or Nous on failure" in out
    monkeypatch.delenv("OPENROUTER_API_KEY")
    assert plugin.slash("on on-host-only").startswith("Locked to this machine")

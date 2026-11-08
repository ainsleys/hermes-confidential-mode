"""Seam tests for register(ctx) (W5): the plugin is copied into a temp HERMES_HOME/plugins/, loaded
through Hermes' REAL directory discovery (PluginManager.discover_and_load, as
tests/hermes_cli/test_plugins.py does), and driven through real turns:

* unlocked: the call goes through and is observed in the ledger;
* locked on-host-only + in-tier provider: passes, and the locked note is in the model's context;
* locked + off-tier provider: refused with zero provider calls;
* locked + web_search: our ask prompt, the tool runs only on the exact answer "once" (W4's harness:
  only the CLI approval callback seat is substituted);
* a config edit after lock blocks the next turn (pre_llm_call), and the llm gate refuses too;
* one registration raising leaves every other registration in place;
* ``hermes plugins doctor --ci`` passes on the worktree.

Fakes only at the network/human boundaries: the agent's terminal provider call (the C0 recorder)
and the approval callback.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import hermes_cli.plugins as plugins_mod
import pytest
import run_agent
from hermes_cli.plugins import PluginContext, PluginManager
from hermes_cli.plugins_manifest import PluginManifest

from ._harness import Rec, no_lazy_installs, provider_ok  # noqa: F401  (fixture)

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
MODULE = "hermes_plugins.confidential_mode"
HOOKS = {"pre_tool_call", "post_approval_response", "pre_llm_call", "pre_api_request", "pre_auxiliary_call",
         "post_auxiliary_call", "on_session_start", "on_session_end", "post_compaction", "pre_gateway_dispatch",
         "transform_llm_output"}
ON_HOST_URL = "http://127.0.0.1:11434/v1"
REMOTE_URL = "https://llm.example.test/v1"
SK = "cm:w5:seam"
BASE_CONFIG = f"""\
plugins:
  enabled: [confidential-mode]
model:
  provider: custom
  default: llama3
  base_url: {ON_HOST_URL}
auxiliary:
  vision:
    provider: custom
    model: llava
    base_url: {ON_HOST_URL}
"""


def _ignore(dirpath, names):
    return [n for n in names if n in {".git", "tests", "__pycache__", ".pytest_cache", "docs"}]


def _evict_plugin_modules():
    for name in [n for n in sys.modules if n == MODULE or n.startswith(MODULE + ".") or n.startswith(MODULE + "__")]:
        sys.modules.pop(name, None)


@pytest.fixture
def plugin(monkeypatch, tmp_path):
    """The plugin installed in a temp Hermes home and loaded by real discovery."""
    import providers
    from tools import approval, approval_context, terminal_tool

    for name in ("HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION", "HERMES_EXEC_ASK", "HERMES_SESSION_PLATFORM",
                 "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION", "HERMES_YOLO_MODE", "HERMES_SESSION_KEY",
                 "HERMES_ENABLE_PROJECT_PLUGINS"):
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    (home / "plugins").mkdir(parents=True)
    shutil.copytree(PLUGIN_ROOT, home / "plugins" / "confidential-mode", ignore=_ignore)
    cfg = home / "config.yaml"
    cfg.write_text(BASE_CONFIG)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_ENABLE_PROJECT_PLUGINS", "0")
    before_providers = dict(providers._REGISTRY)
    _evict_plugin_modules()
    mgr = PluginManager()
    monkeypatch.setattr(plugins_mod, "get_plugin_manager", lambda: mgr)
    mgr.discover_and_load()
    loaded = mgr._plugins.get("confidential-mode")
    assert loaded is not None and loaded.enabled, getattr(loaded, "error", "not discovered")
    mod = loaded.module            # hermes_plugins.confidential_mode[__home_<digest>]
    rt = mod._RUNTIME
    assert rt is not None and rt.ctx.manifest.name == "confidential-mode"

    terminal_tool.set_approval_callback(None)
    approval.clear_session(SK)
    tok = approval_context.set_current_session_key(SK)
    prompts: list[tuple] = []

    def human(answer):
        def cb(command, description, **kw):
            prompts.append((command, description))
            return answer
        terminal_tool.set_approval_callback(cb)

    def slash(text, **kw):
        handler = mgr._plugin_commands["confidential"]["handler"]
        return handler(text, session_id=kw.get("session_id", "sess-w5"), session_key=kw.get("session_key", SK),
                       platform=kw.get("platform", "cli"))

    def kinds():
        return [(e.kind, e.decision) for e in rt.ledger.tail(0)]

    try:
        yield SimpleNamespace(mgr=mgr, loaded=loaded, mod=mod, rt=rt, cfg=cfg, home=home, human=human,
                              prompts=prompts, slash=slash, kinds=kinds)
    finally:
        try:
            mgr.unload()
        except Exception:
            pass
        terminal_tool.set_approval_callback(None)
        approval.clear_session(SK)
        approval_context.reset_current_session_key(tok)
        for name in [n for n in providers._REGISTRY if before_providers.get(n) is not providers._REGISTRY[n]]:
            providers._REGISTRY.pop(name, None)
        providers._REGISTRY.update(before_providers)
        providers._PROVIDER_LIST_CACHE = None
        _evict_plugin_modules()


def build_agent(monkeypatch, rec: Rec, base_url: str):
    """One chat_completions agent whose terminal provider call is the C0 recorder (tests/seam/_harness.py)."""
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("model_tools.check_toolset_requirements", dict)
    agent = run_agent.AIAgent(model="llama3", provider="custom", api_mode="chat_completions", base_url=base_url,
                              api_key="sk-test", quiet_mode=True, skip_context_files=True, skip_memory=True,
                              max_iterations=4)
    agent._cleanup_task_resources = lambda task_id: None
    agent._persist_session = lambda messages, history=None: None
    agent._save_trajectory = lambda messages, user_message, completed: None
    agent._disable_streaming = True

    def _call(api_kwargs, **_kw):
        rec.provider_calls.append(api_kwargs)
        return provider_ok("chat_completions")

    agent._interruptible_api_call = _call
    agent._interruptible_streaming_api_call = lambda api_kwargs, **kw: rec.streaming_calls.append(api_kwargs)
    agent._try_activate_fallback = lambda *a, **k: rec.fallback_calls.append((a, k)) or False
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    return agent


def _sent_text(api_kwargs) -> str:
    return json.dumps(api_kwargs.get("messages"), default=str)


# ── registration ─────────────────────────────────────────────────────────────────────────────────

def test_real_discovery_registers_every_hook_middleware_command_and_provider(plugin):
    import providers
    loaded = plugin.loaded
    assert set(loaded.hooks_registered) == HOOKS
    assert set(loaded.middleware_registered) == {"llm_execution", "tool_execution"}
    assert "confidential" in loaded.commands_registered and "confidential" in plugin.mgr._plugin_commands
    assert "confidential" in plugin.mgr._cli_commands
    for hook in HOOKS:
        assert plugin.mgr.has_hook(hook), hook
    assert plugin.mgr.has_middleware("llm_execution") and plugin.mgr.has_middleware("tool_execution")
    assert providers.get_provider_profile("attested-tinfoil") is plugin.rt.profile
    assert plugin.rt.errors == []
    # One ApprovalDecisions shared by the three tool-gate registrations, one ledger, one state.
    assert plugin.rt.decisions is not None and plugin.rt.ledger is not None and plugin.rt.state is not None
    # Manifest lists exactly what register() registered.
    import hermes_yaml
    manifest = hermes_yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text())
    assert set(manifest["provides_hooks"]) == HOOKS
    assert manifest["provides_middleware"] == ["llm_execution", "tool_execution"]
    assert manifest["provides_tools"] == [] and manifest["requires_env"] == ["TINFOIL_API_KEY"]
    assert [e["name"] for e in manifest["optional_env"]] == ["NEAR_AI_API_KEY", "OPENROUTER_API_KEY", "NOUS_API_KEY"]


def test_cli_command_parses_through_argparse(plugin):
    import argparse
    entry = plugin.mgr._cli_commands["confidential"]
    parser = argparse.ArgumentParser()
    entry["setup_fn"](parser)
    args = parser.parse_args(["watch", "--once"])
    assert args.confidential_action == "watch" and args.once is True
    args = parser.parse_args(["check", "--tier", "on-host-only"])
    assert entry["handler_fn"](args) == 0


# ── turns ────────────────────────────────────────────────────────────────────────────────────────

def test_unlocked_turn_is_observed_and_sent(plugin, monkeypatch):
    rec = Rec()
    agent = build_agent(monkeypatch, rec, REMOTE_URL)
    result = agent.run_conversation("hello there")
    assert result["final_response"] == "provider answered"
    assert len(rec.provider_calls) == 1
    observed = [e for e in plugin.rt.ledger.tail(0) if e.kind == "send_observed"]
    assert any(e.decision == "observed" and e.host == "llm.example.test" and e.bytes for e in observed)
    assert "[confidential mode]" not in _sent_text(rec.provider_calls[0])


def test_locked_on_host_in_tier_turn_passes_with_the_locked_note(plugin, monkeypatch):
    out = plugin.slash("on on-host-only")
    # ux-pass-1 item 4: one line; the disclosure, the tool list and the preflight are in status --verbose.
    assert out == ("Locked to this machine (on-host-only), custom/llama3 at 127.0.0.1.\n"
                   "Off-host tools ask the first time per lock in each conversation. Shell and code execution are not inspected. Auxiliary calls are "
                   "recorded, not refused. Not active in safe-worker mode.\n"
                   "Details: hermes confidential status --verbose; docs/LIMITATIONS.md"), out
    status = plugin.slash("status")       # plain status carries the same four disclosures (Amendment 4 F12)
    assert ("Limits: Off-host tools ask the first time per lock in each conversation. Shell and code execution are not inspected. Auxiliary calls are "
            "recorded, not refused. Not active in safe-worker mode.") in status
    # A listed host is not "this machine".
    locking = importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.locking")
    tiers = importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.tiers")
    cfg = {"model": {"provider": "custom", "default": "llama3", "base_url": "http://gpu-box.lan:11434/v1"},
           "confidential": {"on_host": {"extra_hosts": ["gpu-box.lan"]}}}
    assert locking.lock_message(tiers.Tier.ON_HOST, cfg).startswith(
        "Locked to listed host gpu-box.lan (on-host-only), custom/llama3 at gpu-box.lan.")
    # confidential.tools.ask: each_call changes the lock reply and the locked note (Amendment 13).
    each = {**cfg, "confidential": {**cfg["confidential"], "tools": {"ask": "each_call"}}}
    assert locking.lock_message(tiers.Tier.ON_HOST, each).split("\n")[1].startswith("Off-host tools ask each call. ")
    assert "ask the user first, each call" in locking.locked_note(tiers.Tier.ON_HOST, "each_call")
    assert "each call" not in locking.locked_note(tiers.Tier.ON_HOST, "once_per_lock")
    verbose = plugin.slash("status --verbose")
    assert "ask you the first time each runs during a lock" in verbose and "Memory: on-host. Fallbacks: none." in verbose
    assert "safe-worker" in verbose and "recorded after the fact" in verbose
    assert "on-host (runs without asking)" in verbose and "web_search" in verbose and "Preflight:" in verbose
    rec = Rec()
    agent = build_agent(monkeypatch, rec, ON_HOST_URL)
    result = agent.run_conversation("summarise the board minutes")
    assert result["final_response"] == "provider answered"
    assert len(rec.provider_calls) == 1
    assert "[confidential mode] This profile is locked (on-host-only)" in _sent_text(rec.provider_calls[0])
    assert "the first time each tool outside the on-host list runs in this conversation" in \
        _sent_text(rec.provider_calls[0])
    rows = [(e.kind, e.decision, e.verdict) for e in plugin.rt.ledger.tail(0)]
    assert ("lock", "locked", "in_tier") in rows
    assert ("send_observed", "allowed", "in_tier") in rows


def test_locked_off_tier_provider_is_refused_with_zero_provider_calls(plugin, monkeypatch):
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = build_agent(monkeypatch, rec, REMOTE_URL)
    result = agent.run_conversation("the merger terms are")
    assert result["final_response"].startswith("Confidential mode: locked to on-host-only; this request was not sent.")
    assert "live model runtime is custom at llm.example.test" in result["final_response"]
    assert rec.provider_calls == [] and rec.streaming_calls == [] and rec.fallback_calls == []
    assert ("send_refused", "refused") in plugin.kinds() and ("breach", "live_runtime_off_tier") in plugin.kinds()
    assert "OFF-TIER" in plugin.slash("status")
    # mutant twin: the same agent unlocked reaches the provider.
    plugin.slash("off")
    agent.run_conversation("again")
    assert len(rec.provider_calls) == 1


def test_unreadable_live_runtime_blocks_the_turn_and_the_lock(plugin, monkeypatch):
    """Review finding 8: when Hermes no longer exposes the live-runtime accessor, the per-turn check blocks
    (it used to return no block) and the lock is refused. "Bound to no runtime" stays a pass."""
    import sys
    import types
    locking = importlib.import_module(plugin.mod.__name__ + ".confidential_mode.locking")
    moved = types.ModuleType("agent.auxiliary_client")          # an upgrade renamed _RUNTIME_MAIN_CONTEXT
    with monkeypatch.context() as m:
        m.setitem(sys.modules, "agent.auxiliary_client", moved)
        with pytest.raises(locking.LiveRuntimeUnreadable):
            locking.live_main_runtime()
        out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked: this Hermes version does not expose the live model runtime"), out
    assert ("preflight_fail", "refused") in plugin.kinds()
    assert locking.live_main_runtime() is None                   # unbound outside a turn: not an error
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = build_agent(monkeypatch, rec, ON_HOST_URL)

    def unreadable():
        raise locking.LiveRuntimeUnreadable("cannot import the live runtime accessor (ImportError)")
    monkeypatch.setattr(locking, "live_main_runtime", unreadable)
    result = agent.run_conversation("the merger terms are")
    assert "does not expose the live model runtime" in (result["final_response"] or "")
    assert rec.provider_calls == [] and rec.streaming_calls == []
    assert ("send_refused", "refused") in plugin.kinds()
    assert "UNREADABLE" in plugin.slash("status")


def test_remote_terminal_backend_refuses_the_lock_with_the_key_to_change(plugin, monkeypatch):
    """Review finding 2: with terminal.backend: ssh the 'on-host' terminal and file tools run on another
    machine, so the lock is refused with a preflight row naming the backend and the key; after the fix it
    locks, and a backend switched in the environment after the lock ends the next turn."""
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    plugin.cfg.write_text(BASE_CONFIG + "terminal:\n  backend: ssh\n")
    out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked"), out
    row = next(line for line in out.splitlines() if line.startswith("terminal.backend"))
    assert "ssh" in row and "off_tier" in row and "set terminal.backend: local" in row
    # A terminal environment Hermes still caches from a remote backend also refuses the lock (second review,
    # item 4): the tools would keep using it.
    from types import SimpleNamespace

    from tools import terminal_tool
    plugin.cfg.write_text(BASE_CONFIG)           # no terminal section: the environment variable decides
    monkeypatch.setattr(terminal_tool, "_active_environments", {"default": SimpleNamespace(env_type="ssh")})
    out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked: Hermes still holds terminal environments on a non-local backend"), out
    monkeypatch.setattr(terminal_tool, "_active_environments", {})
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = build_agent(monkeypatch, rec, ON_HOST_URL)
    assert agent.run_conversation("first")["final_response"] == "provider answered"
    monkeypatch.setenv("TERMINAL_ENV", "modal")
    result = agent.run_conversation("second")
    assert "routing config changed after this profile was locked" in (result["final_response"] or "")
    assert len(rec.provider_calls) == 1


def test_a_lock_made_before_the_terminal_keys_joined_the_fingerprint_is_not_a_breach(plugin, monkeypatch):
    """Second review, item 1: a profile locked under the version-1 fingerprint (before this plugin version)
    keeps working after the upgrade; no session is marked breached by the upgrade itself."""
    assert plugin.slash("on on-host-only").startswith("Locked")
    locking = importlib.import_module(plugin.mod.__name__ + ".confidential_mode.locking")
    pf = importlib.import_module(plugin.mod.__name__ + ".confidential_mode.preflight")
    v1 = pf.config_fingerprint(plugin.rt.load_config(), plugin_aux_tasks=locking._plugin_aux(None), version=1)
    plugin.rt.state._store.set("config_fingerprint", v1)          # what main recorded at lock
    plugin.rt.allowlist_path.unlink()                               # its allowlist named the old lock id
    rec = Rec()
    agent = build_agent(monkeypatch, rec, ON_HOST_URL)
    assert agent.run_conversation("after the upgrade")["final_response"] == "provider answered"
    assert ("breach", "config_changed") not in plugin.kinds() and not plugin.rt.state.is_breached(agent.session_id)


def test_terminal_tool_call_through_hermes_dispatch_is_blocked_on_a_remote_backend(plugin, monkeypatch):
    """Second review, minor item 15: a real read_file call through model_tools.handle_function_call (Hermes'
    own task_id plumbing) is refused while the backend Hermes resolves is ssh, and runs on local."""
    import model_tools
    plugin.cfg.write_text(BASE_CONFIG)
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    assert plugin.slash("on on-host-only").startswith("Locked")
    target = plugin.home / "note.txt"
    target.write_text("hello from this host")
    ok = model_tools.handle_function_call("read_file", {"path": str(target)}, task_id="t-local", session_id="s")
    assert "hello from this host" in ok, ok
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    out = model_tools.handle_function_call("read_file", {"path": str(target)}, task_id="t-ssh", session_id="s")
    assert "terminal backend is ssh" in out and "hello from this host" not in out, out
    assert ("tool_refused", "terminal_backend") in plugin.kinds()


def test_config_edit_after_lock_blocks_the_next_turn(plugin, monkeypatch):
    assert plugin.slash("on on-host-only").startswith("Locked")
    rec = Rec()
    agent = build_agent(monkeypatch, rec, ON_HOST_URL)
    assert agent.run_conversation("first")["final_response"] == "provider answered"
    plugin.cfg.write_text(BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    result = agent.run_conversation("second")
    assert "routing config changed after this profile was locked" in (result["final_response"] or "")
    assert len(rec.provider_calls) == 1, "the blocked turn made no provider call"
    assert ("breach", "config_changed") in plugin.kinds()
    assert plugin.rt.state.is_breached(agent.session_id)
    # Second line: the llm gate's predicate refuses every destination while the fingerprint differs.
    tiers = importlib.import_module(plugin.mod.__name__ + ".confidential_mode.tiers")
    Destination, Tier = tiers.Destination, tiers.Tier
    v = plugin.rt.predicate_for(Tier.ON_HOST).classify(Destination("custom", ON_HOST_URL, "m", "chat_completions", "main"))
    assert v.in_tier is False and "changed since lock" in v.reason
    # Restoring the locked config restores service.
    plugin.cfg.write_text(BASE_CONFIG)
    assert agent.run_conversation("third")["final_response"] == "provider answered"


def test_lock_refuses_with_the_report_when_preflight_fails(plugin):
    plugin.cfg.write_text(BASE_CONFIG + "fallback_providers:\n  - provider: openrouter\n    model: x/y\n")
    out = plugin.slash("on on-host-only")
    assert out.startswith("Not locked: the preflight found routes")
    assert "fallback_providers[0]" in out and "off_tier" in out
    assert plugin.rt.state.locked() == (False, None)
    assert ("preflight_fail", "refused") in plugin.kinds()
    assert plugin.slash("on zero-retention").startswith("Not locked: zero-retention tier not implemented")


def test_aux_call_to_off_tier_host_while_locked_is_a_breach(plugin):
    assert plugin.slash("on on-host-only").startswith("Locked")
    from hermes_cli.plugins import invoke_hook
    invoke_hook("pre_auxiliary_call", aux_task="title_generation", provider="openrouter",
                base_url="https://openrouter.ai/api/v1", model="m", api_mode="chat_completions",
                session_id="sess-aux", api_request_id="aux-1", request={"method": "POST", "body": {"m": "x" * 50}},
                request_char_count=50)
    invoke_hook("post_auxiliary_call", aux_task="title_generation", provider="openrouter",
                base_url="https://openrouter.ai/api/v1", api_request_id="aux-1", session_id="sess-aux")
    invoke_hook("pre_auxiliary_call", aux_task="compression", provider="custom", base_url=ON_HOST_URL,
                model="m", session_id="sess-aux", api_request_id="aux-2", request_char_count=10)
    rows = [e for e in plugin.rt.ledger.tail(0) if e.purpose.startswith("aux:")]
    assert [(e.kind, e.purpose, e.verdict) for e in rows] == [
        ("send_observed", "aux:title_generation", "off_tier"), ("breach", "aux:title_generation", "off_tier"),
        ("send_observed", "aux:compression", "in_tier")]
    assert rows[0].host == "openrouter.ai" and rows[0].bytes and rows[0].bytes > 50
    assert plugin.rt.state.is_breached("sess-aux")


# ── tool gate through the plugin's registrations ─────────────────────────────────────────────────

def test_locked_web_search_asks_and_runs_only_on_exact_once(plugin, monkeypatch):
    import model_tools
    from tools.registry import registry
    ran = []

    def handler(args, **kw):
        ran.append(args)
        return json.dumps({"ok": "web_search"})

    monkeypatch.setattr(registry.get_entry("web_search"), "handler", handler)   # before lock: identity pinned
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert plugin.slash("on on-host-only").startswith("Locked")

    def call(n):
        return model_tools.handle_function_call("web_search", {"query": "q" * 1500}, task_id="t1",
                                                session_id="sess-w5", tool_call_id=f"call-{n}")

    for i, answer in enumerate(["deny", "", "yes", None]):
        plugin.human(answer)
        call(i)
    assert ran == []
    assert len(plugin.prompts) == 4
    assert plugin.prompts[0][1] == ("Confidential mode: web_search wants to send ~2 KB of this conversation off the "
                                    "machine; allowing once covers web_search in this conversation until this profile is unlocked")
    plugin.human("once")
    out = call(9)
    assert ran == [{"query": "q" * 1500}] and json.loads(out) == {"ok": "web_search"}
    assert plugin.kinds()[-2:] == [("tool_asked", "ask"), ("tool_allowed", "once")]
    # Amendment 13: once_per_lock (the default) grants web_search for the rest of this lock.
    plugin.human("deny")
    call(10)
    assert len(ran) == 2 and len(plugin.prompts) == 5
    assert plugin.kinds()[-1] == ("tool_allowed", "lock_grant")
    # A revoke ends the grant; the next call asks again.
    assert plugin.slash("revoke web_search").startswith("Revoked web_search")
    call(11)
    assert len(ran) == 2 and len(plugin.prompts) == 6


# ── isolation of registration failures ───────────────────────────────────────────────────────────

def _load_standalone(name: str):
    spec = importlib.util.spec_from_file_location(name, PLUGIN_ROOT / "__init__.py",
                                                  submodule_search_locations=[str(PLUGIN_ROOT)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("target,attr,missing", [
    ("gate_llm", "build_middleware", ("middleware", "llm_execution")),
    ("gate_tools", "build_pre_tool_call", ("hooks", "pre_tool_call")),
    ("provider", "register_provider_profile", ("providers", "attested-tinfoil")),
])
def test_one_registration_raising_leaves_the_others(monkeypatch, tmp_path, target, attr, missing):
    import providers
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    name = f"cm_regtest_{target}"
    before = dict(providers._REGISTRY)
    try:
        mod = _load_standalone(name)
        sub = importlib.import_module(f"{name}.confidential_mode.{target}")

        def boom(*a, **k):
            raise RuntimeError("builder exploded")

        monkeypatch.setattr(sub, attr, boom)
        mgr = PluginManager()
        ctx = PluginContext(PluginManifest(name="confidential-mode", source="user"), mgr)
        assert mod.register(ctx) is None                         # never raises
        rt = mod._RUNTIME
        expected = {"hooks": set(HOOKS), "middleware": {"llm_execution", "tool_execution"},
                    "commands": {"confidential"}, "cli_commands": {"confidential"},
                    "providers": {"attested-tinfoil", "attested-near"}}   # Amendment 5: NEAR registers too
        expected[missing[0]].discard(missing[1])
        assert {k: set(v) for k, v in rt.registered.items()} == expected
        assert set(mgr._hooks) == expected["hooks"]
        assert set(mgr._middleware) == expected["middleware"]
        assert "confidential" in mgr._plugin_commands and "confidential" in mgr._cli_commands
        assert [step for step, _ in rt.errors] == [{"gate_llm": "llm_execution", "gate_tools": "pre_tool_call",
                                                    "provider": "provider"}[target]]
        rows = [(e.kind, e.purpose) for e in rt.ledger.tail(0)]
        assert ("preflight_fail", f"register:{rt.errors[0][0]}") in rows
        assert rt.pins is not None                               # fallback pin store when the provider failed
        assert "Plugin registration problem" in mgr._plugin_commands["confidential"]["handler"]("status")
    finally:
        for n in [n for n in providers._REGISTRY if before.get(n) is not providers._REGISTRY[n]]:
            providers._REGISTRY.pop(n, None)
        providers._REGISTRY.update(before)
        for n in [n for n in sys.modules if n == name or n.startswith(name + ".")]:
            sys.modules.pop(n, None)


# ── catalog tooling ──────────────────────────────────────────────────────────────────────────────

def test_plugins_doctor_ci_passes(tmp_path):
    hermes = Path(sys.executable).with_name("hermes")
    argv = [str(hermes)] if hermes.exists() else [sys.executable, "-m", "hermes_cli.main"]
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "doctor-home"), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(argv + ["plugins", "doctor", "--ci", str(PLUGIN_ROOT)], capture_output=True, text=True,
                          env=env, timeout=240)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: runtime discovery, manifest parsing, import, and registration passed" in proc.stdout
    assert "ERROR" not in proc.stdout and "registration adds" not in proc.stdout
    assert "11 hook(s)" in proc.stdout


def test_live_verification_is_ledgered_with_evidence(plugin):
    """Amendment 4 F4: register(ctx) hands the plugin's ledger to the provider, so a verification writes
    verify_ok with the evidence attached (only the vendor adapter is faked: no network)."""
    provider = importlib.import_module(plugin.mod.__name__ + ".confidential_mode.provider")
    base = importlib.import_module(plugin.mod.__name__ + ".confidential_mode.verify.base")
    evidence = {"format": "test-attestation", "body": "eyJmYWtlIjogdHJ1ZX0="}

    class Adapter:
        vendor, enclave_host, base_url = "tinfoil", "router.tinfoil.invalid", "https://router.tinfoil.invalid/v1"

        def verify(self):
            return base.VerificationResult(vendor="tinfoil", router_repo="tinfoilsh/confidential-model-router",
                                           enclave_host=self.enclave_host, code_fingerprint="c" * 64,
                                           enclave_fingerprint="e" * 64, release_tag="v9", verifier="test",
                                           verified_at_host_clock=time.time(), evidence=evidence)

    entry = provider.verification_cache.entry(provider.PROFILE_NAME)
    entry.adapter = Adapter()
    provider.verification_cache.refresh(provider.PROFILE_NAME)
    rows = [e for e in plugin.rt.ledger.tail(0) if e.kind == "verify_ok"]
    assert rows and rows[-1].detail["evidence"] == evidence and rows[-1].host == "router.tinfoil.invalid"

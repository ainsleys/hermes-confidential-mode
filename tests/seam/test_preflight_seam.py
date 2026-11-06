"""W3 seam: preflight over Hermes' real config loader and real plugin aux-task registry.

Runs against the pinned checkout with HERMES_HOME pointing at a temp dir (see docs/RUNNING_TESTS.md).
No network: provider profiles are looked up in-process only.
"""
import os
from pathlib import Path

import pytest

from confidential_mode import preflight as pf
from confidential_mode.tiers import OnHostPredicate, Tier

CONFIG_YAML = """\
model:
  provider: custom
  default: qwen3:8b
  base_url: http://127.0.0.1:11434/v1
fallback_providers: []
auxiliary:
  vision:
    provider: custom
    base_url: http://127.0.0.1:11434/v1
    model: llava
  w3seam_task:
    provider: openrouter
    model: google/gemini-3-flash-preview
memory:
  provider: ""
mcp_servers:
  fs:
    command: npx
  remote:
    url: https://mcp.example.com/sse
plugins:
  isolation: in_process
"""


@pytest.fixture
def hermes_home(monkeypatch):
    home = os.environ.get("HERMES_HOME")
    assert home and Path(home).is_dir(), "run with HERMES_HOME=<temp dir> (docs/RUNNING_TESTS.md)"
    assert Path(home).resolve() != (Path.home() / ".hermes").resolve(), "refusing to touch the real ~/.hermes"
    from hermes_cli.config import get_config_path
    cfg = get_config_path()
    assert str(cfg).startswith(str(Path(home)))
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(CONFIG_YAML)
    try:
        yield cfg
    finally:
        cfg.unlink(missing_ok=True)


@pytest.fixture
def plugin_task():
    from hermes_cli.plugins import PluginContext, discover_plugins, get_plugin_manager
    from hermes_cli.plugins_manifest import PluginManifest
    discover_plugins()
    ctx = PluginContext(PluginManifest(name="w3-seam", source="user"), get_plugin_manager())
    reg = ctx.register_auxiliary_task("w3seam_task", display_name="W3 seam", description="preflight seam test",
                                      defaults={"timeout": 5})
    inh = ctx.register_auxiliary_task("w3seam_inherit", display_name="W3 inherit", description="inherits vision",
                                      inherit_from="vision")
    try:
        yield
    finally:
        for r in (inh, reg):
            dispose = getattr(r, "dispose", None)
            if dispose:
                dispose()


def test_load_core_config_reads_temp_home_readonly(hermes_home):
    cfg = pf.load_core_config()
    assert cfg["model"]["provider"] == "custom"
    assert cfg["model"]["base_url"] == "http://127.0.0.1:11434/v1"
    # merged with DEFAULT_CONFIG: built-in aux tasks we did not write are present
    assert cfg["auxiliary"]["compression"]["provider"] == "auto"
    from hermes_cli.config import load_config_readonly
    assert pf.load_core_config() is load_config_readonly()  # the read-only cached object, not a copy


def test_plugin_registered_aux_task_appears_in_report(hermes_home, plugin_task):
    names = pf.plugin_aux_task_names()
    assert "w3seam_task" in names and "w3seam_inherit" in names
    cfg = pf.load_core_config()
    report = pf.run_preflight(
        Tier.ON_HOST, OnHostPredicate(profile_base_url=pf.profile_base_url), cfg,
        plugin_aux_tasks=pf.plugin_aux_task_entries(), isolation=pf.plugin_isolation(cfg),
        provider_lookup=pf.provider_lookup, attested_profile=None)
    by_key = {i.key: i for i in report.items}
    text = pf.format_report(report)

    assert by_key["model.provider"].verdict == "on_host"
    assert by_key["auxiliary.vision.provider"].verdict == "on_host"
    assert by_key["auxiliary.compression.provider"].verdict == "on_host"  # auto -> main
    seam = by_key["auxiliary.w3seam_task.provider"]
    assert seam.verdict == "off_tier" and "auxiliary.w3seam_task.provider" in seam.fix
    assert by_key["auxiliary.w3seam_inherit.provider"].verdict == "on_host"  # follows vision
    assert by_key["mcp_servers.fs.command"].verdict == "on_host"
    assert by_key["mcp_servers.remote.url"].verdict == "off_tier"
    assert by_key["plugins.isolation"].verdict == "on_host"
    # Hermes' merged default tts.provider is "edge" (hosted); delegation unset inherits the on-host main.
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    assert DEFAULT_CONFIG["tts"]["provider"] == "edge" and "enabled" not in DEFAULT_CONFIG["tts"]
    # (Hermes has no tts.enabled key; per the coordinator ruling an unset flag counts as disabled.)
    assert by_key["tts.provider"].value_redacted == "(edge, disabled)"
    assert by_key["tts.provider"].verdict == "disabled"
    assert by_key["delegation.provider"].verdict == "on_host"
    assert "auxiliary.w3seam_task.provider" in text
    assert not report.ok
    for task in pf.builtin_aux_task_names():
        assert f"auxiliary.{task}.provider" in by_key


def test_preflight_matches_hermes_own_aux_resolution(hermes_home, plugin_task):
    """Our pure layering must agree with agent/auxiliary_task_config._get_auxiliary_task_config."""
    from agent.auxiliary_task_config import _get_auxiliary_task_config
    cfg = pf.load_core_config()
    plugins = pf._normalize_plugin_tasks(pf.plugin_aux_task_entries())
    for task in [*pf.builtin_aux_task_names(), *plugins]:
        ours = pf._effective_aux(cfg, task, plugins)
        theirs = _get_auxiliary_task_config(task)
        for k in ("provider", "base_url", "fallback_chain"):
            assert ours.get(k) == theirs.get(k), (task, k)


def test_fingerprint_changes_when_config_file_changes(hermes_home):
    before = pf.config_fingerprint(pf.load_core_config())
    assert before == pf.config_fingerprint(pf.load_core_config())
    hermes_home.write_text(CONFIG_YAML.replace("fallback_providers: []",
                                               "fallback_providers:\n  - provider: openrouter\n    model: x"))
    st = hermes_home.stat()
    os.utime(hermes_home, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    cfg = pf.load_core_config()
    assert cfg["fallback_providers"][0]["provider"] == "openrouter"
    assert pf.config_fingerprint(cfg) != before


def test_attested_profile_lookup_missing_in_process(hermes_home):
    cfg = pf.load_core_config()
    from confidential_mode.tiers import AttestedPredicate, Verdict
    report = pf.run_preflight(
        Tier.ATTESTED, AttestedPredicate({"attested-tinfoil"}, lambda _p: Verdict(True, "ok", "")), cfg,
        plugin_aux_tasks=[], isolation=pf.plugin_isolation(cfg), provider_lookup=pf.provider_lookup,
        attested_profile="attested-tinfoil")
    item = next(i for i in report.items if i.key == "provider_profile[attested-tinfoil]")
    assert item.verdict == "missing"
    assert pf.provider_lookup("openrouter") is not None

"""W3: preflight rules over plain config dicts. Each rule has a passing and a failing fixture."""
import copy

import pytest

from confidential_mode import preflight as pf
from confidential_mode.preflight import (
    BUILTIN_AUX_TASKS_SNAPSHOT, PreflightReport, config_fingerprint, format_report, run_preflight,
)
from confidential_mode.tiers import AttestedPredicate, LocalPredicate, Tier, Verdict, ZdrPredicate

LOCAL_URL = "http://127.0.0.1:11434/v1"
PROFILES = {"ollama": LOCAL_URL, "openrouter": "https://openrouter.ai/api/v1",
            "attested-tinfoil": "https://inference.tinfoil.sh/v1"}


def local_pred():
    return LocalPredicate(profile_base_url=lambda p: PROFILES.get(p, ""))


def attested_pred(ok=True):
    return AttestedPredicate({"attested-tinfoil"}, lambda _p: Verdict(ok, "fresh" if ok else "stale", ""))


def base_config(**over):
    cfg = {
        "model": {"provider": "ollama", "default": "qwen3:8b", "base_url": LOCAL_URL},
        "fallback_providers": [],
        "auxiliary": {"vision": {"provider": "ollama", "model": "llava", "base_url": ""}},
        "memory": {"provider": ""},
        "mcp_servers": {},
        "plugins": {"isolation": "in_process"},
        "tts": {"provider": "piper"},
    }
    cfg.update(over)
    return cfg


def run(cfg, tier=Tier.LOCAL, pred=None, *, plugin=(), isolation="in_process", lookup=None, profile=None):
    return run_preflight(tier, pred or local_pred(), cfg, plugin_aux_tasks=list(plugin), isolation=isolation,
                         provider_lookup=lookup or (lambda n: object() if n in PROFILES else None),
                         attested_profile=profile)


def item(report: PreflightReport, key):
    matches = [i for i in report.items if i.key == key]
    assert matches, f"{key} not in {[i.key for i in report.items]}"
    return matches[0]


def test_baseline_local_config_passes():
    r = run(base_config())
    assert r.ok, format_report(r)
    assert item(r, "model.provider").verdict == "local"
    assert item(r, "fallback_providers").verdict == "disabled"


def test_builtin_aux_tasks_come_from_hermes_defaults():
    names = pf.builtin_aux_task_names()
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    assert names == [k for k, v in DEFAULT_CONFIG["auxiliary"].items() if isinstance(v, dict)]
    assert tuple(names) == BUILTIN_AUX_TASKS_SNAPSHOT  # snapshot is current at the pin
    r = run(base_config())
    for task in names:
        assert item(r, f"auxiliary.{task}.provider")
    assert r.aux_tasks[: len(names)] == tuple(names)


# --- main provider ------------------------------------------------------------------------------

def test_main_remote_provider_off_tier_and_aux_inherit_it():
    cfg = base_config(model={"provider": "openrouter", "default": "x/y"})
    r = run(cfg)
    assert item(r, "model.provider").verdict == "off_tier"
    assert item(r, "model.default").verdict == "off_tier"
    comp = item(r, "auxiliary.compression.provider")
    assert comp.verdict == "off_tier" and "inherits the main route" in comp.fix
    assert "openrouter" in comp.value_redacted


def test_main_empty_base_url_resolved_via_profile():
    r = run(base_config(model={"provider": "ollama", "default": "q"}))
    assert item(r, "model.provider").verdict == "local"
    assert item(r, "auxiliary.compression.provider").verdict == "local"


@pytest.mark.parametrize("provider", ["", "auto"])
def test_main_auto_off_tier(provider):
    r = run(base_config(model={"provider": provider, "default": "q", "base_url": LOCAL_URL}))
    assert item(r, "model.provider").verdict == "off_tier"
    assert "model.provider" in item(r, "model.provider").fix


def test_main_string_model_is_off_tier():
    r = run(base_config(model="qwen3:8b"))
    assert item(r, "model.provider").verdict == "off_tier"
    assert item(r, "model.default").value_redacted == "qwen3:8b"


def test_main_model_alias_key():
    r = run(base_config(model={"provider": "ollama", "model": "legacy-key"}))
    assert item(r, "model.default").value_redacted == "legacy-key"


def test_main_moa_off_tier():
    r = run(base_config(model={"provider": "moa", "default": "preset", "base_url": LOCAL_URL}))
    i = item(r, "model.provider")
    assert i.verdict == "off_tier" and "moa" in i.fix


@pytest.mark.parametrize("provider", ["openai-codex", "codex"])
def test_main_openai_codex_off_tier_even_if_local(provider):
    r = run(base_config(model={"provider": provider, "default": "gpt", "base_url": LOCAL_URL}))
    i = item(r, "model.provider")
    assert i.verdict == "off_tier" and "app-server" in i.fix


# --- fallbacks ----------------------------------------------------------------------------------

def test_fallback_providers_nonempty_off_tier_even_if_local():
    cfg = base_config(fallback_providers=[{"provider": "ollama", "model": "q", "base_url": LOCAL_URL},
                                          {"provider": "moa", "model": "p"}])
    r = run(cfg)
    assert [i.verdict for i in r.items if i.key.startswith("fallback_providers[")] == ["off_tier", "off_tier"]
    assert item(r, "fallback_providers[0]").fix == "remove fallback_providers entries while sealed"
    assert not r.ok


def test_fallback_providers_dict_form_and_legacy_fallback_model():
    r = run(base_config(fallback_providers={"provider": "openrouter", "model": "x"},
                        fallback_model={"provider": "openrouter", "model": "y"}))
    assert item(r, "fallback_providers[0]").verdict == "off_tier"
    assert item(r, "fallback_model").verdict == "off_tier"


# --- auxiliary ----------------------------------------------------------------------------------

def test_vision_auto_is_off_tier_even_with_local_main():
    cfg = base_config(auxiliary={"vision": {"provider": "auto"}})
    i = item(run(cfg), "auxiliary.vision.provider")
    assert i.verdict == "off_tier"
    assert "openrouter -> nous -> deepinfra" in i.fix and "auxiliary.vision.provider" in i.fix


def test_vision_missing_block_is_off_tier():
    cfg = base_config(auxiliary={})
    assert item(run(cfg), "auxiliary.vision.provider").verdict == "off_tier"


@pytest.mark.parametrize("value", ["none", "off", "disabled"])
def test_vision_has_no_disabled_convention(value):
    # Amendment 1: no "disabled" convention; these are just unknown provider names -> off-tier.
    cfg = base_config(auxiliary={"vision": {"provider": value}})
    assert item(run(cfg), "auxiliary.vision.provider").verdict == "off_tier"


@pytest.mark.parametrize("vision", ["openrouter", ["x"], 3])
def test_vision_non_dict_block_off_tier(vision):
    r = run(base_config(auxiliary={"vision": vision}))
    assert item(r, "auxiliary.vision").verdict == "off_tier"
    i = item(r, "auxiliary.vision.provider")
    assert i.verdict == "off_tier" and "inbound images" in i.fix


def test_vision_main_inherits_main():
    assert item(run(base_config(auxiliary={"vision": {"provider": "main"}})),
                "auxiliary.vision.provider").verdict == "local"
    cfg = base_config(model={"provider": "openrouter", "default": "x"}, auxiliary={"vision": {"provider": "main"}})
    assert item(run(cfg), "auxiliary.vision.provider").verdict == "off_tier"


def test_vision_auto_with_local_base_url_is_explicit_custom():
    cfg = base_config(auxiliary={"vision": {"provider": "auto", "base_url": "http://10.0.0.9:8000/v1"}})
    r = run(cfg)
    assert item(r, "auxiliary.vision.provider").verdict == "local"
    assert item(r, "auxiliary.vision.base_url").verdict == "local"


def test_vision_explicit_remote_off_tier():
    cfg = base_config(auxiliary={"vision": {"provider": "openrouter"}})
    assert item(run(cfg), "auxiliary.vision.provider").verdict == "off_tier"


def test_aux_explicit_provider_and_base_url():
    ok = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL},
                                "compression": {"provider": "custom", "base_url": "http://192.168.1.4:8080/v1"}})
    r = run(ok)
    assert item(r, "auxiliary.compression.provider").verdict == "local"
    assert item(r, "auxiliary.compression.base_url").value_redacted == "http://192.168.1.4:8080/v1"
    bad = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL},
                                 "compression": {"provider": "custom", "base_url": "https://api.example.com/v1"}})
    r = run(bad)
    i = item(r, "auxiliary.compression.base_url")
    assert i.verdict == "off_tier" and "auxiliary.compression.provider" in i.fix


def test_aux_moa_provider_off_tier():
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL},
                                 "approval": {"provider": "moa", "base_url": LOCAL_URL}})
    assert item(run(cfg), "auxiliary.approval.provider").verdict == "off_tier"


def test_aux_fallback_chain_entries():
    good = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL}, "curator": {
        "provider": "auto", "fallback_chain": [{"provider": "ollama", "model": "q"}]}})
    assert item(run(good), "auxiliary.curator.fallback_chain[0]").verdict == "local"
    bad = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL}, "curator": {
        "provider": "auto", "fallback_chain": [{"provider": "ollama"}, {"provider": "openrouter", "model": "x"},
                                               {"provider": "moa"}, {"provider": "auto"}, "junk"]}})
    r = run(bad)
    verdicts = [item(r, f"auxiliary.curator.fallback_chain[{i}]").verdict for i in range(5)]
    assert verdicts == ["local", "off_tier", "off_tier", "off_tier", "off_tier"]


def test_plugin_aux_task_by_name_inherits_main():
    r = run(base_config(), plugin=["my_plugin_task"])
    assert item(r, "auxiliary.my_plugin_task.provider").verdict == "local"
    assert "my_plugin_task" in r.aux_tasks
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL}, "my_plugin_task": {"provider": "openrouter"}})
    assert item(run(cfg, plugin=["my_plugin_task"]), "auxiliary.my_plugin_task.provider").verdict == "off_tier"


def test_plugin_aux_task_defaults_are_honoured():
    entry = {"key": "pt", "defaults": {"provider": "openrouter", "model": "x"}, "inherit_from": None}
    r = run(base_config(), plugin=[entry])
    assert item(r, "auxiliary.pt.provider").verdict == "off_tier"
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL}, "pt": {"provider": "ollama"}})
    assert item(run(cfg, plugin=[entry]), "auxiliary.pt.provider").verdict == "local"  # user wins


def test_plugin_aux_task_inherit_from():
    entry = {"key": "pt", "defaults": {}, "inherit_from": "compression"}
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": LOCAL_URL}, "compression": {"provider": "openrouter"}})
    assert item(run(cfg, plugin=[entry]), "auxiliary.pt.provider").verdict == "off_tier"
    cfg["auxiliary"]["pt"] = {"provider": "ollama"}  # pinned on the task itself
    assert item(run(cfg, plugin=[entry]), "auxiliary.pt.provider").verdict == "local"


# --- memory / mcp / isolation / attested --------------------------------------------------------

@pytest.mark.parametrize("value", ["", "builtin", "built-in", "local", "none", "None"])
def test_memory_local(value):
    assert item(run(base_config(memory={"provider": value})), "memory.provider").verdict == "local"


@pytest.mark.parametrize("value", ["honcho", "mem0", "supermemory"])
def test_memory_external_off_tier(value):
    i = item(run(base_config(memory={"provider": value})), "memory.provider")
    assert i.verdict == "off_tier" and "memory.provider" in i.fix


def test_mcp_servers():
    cfg = base_config(mcp_servers={
        "fs": {"command": "npx", "args": ["-y", "server-fs", "--token=abc"]},
        "remote": {"url": "https://mcp.example.com/sse?token=SECRET", "headers": {"Authorization": "Bearer x"}},
        "off": {"url": "https://mcp.example.com", "enabled": False},
        "weird": {"foo": 1},
    })
    r = run(cfg)
    assert item(r, "mcp_servers.fs.command").verdict == "local"
    remote = item(r, "mcp_servers.remote.url")
    assert remote.verdict == "off_tier" and "SECRET" not in remote.value_redacted
    assert "mcp_servers.remote.enabled: false" in remote.fix
    assert item(r, "mcp_servers.off.url").verdict == "disabled"
    assert item(r, "mcp_servers.weird").verdict == "missing"
    assert "abc" not in format_report(r)


@pytest.mark.parametrize("iso,verdict", [("in_process", "local"), ("host", "off_tier"), ("", "missing"),
                                         (None, "local"), ("IN-PROCESS", "off_tier"), (1, "off_tier"),
                                         (["in_process"], "off_tier")])
def test_plugins_isolation(iso, verdict):
    i = item(run(base_config(), isolation=iso), "plugins.isolation")
    assert i.verdict == verdict
    if verdict != "local":
        assert "plugins.isolation: in_process" in i.fix


def test_plugins_isolation_read_from_config_when_not_passed():
    def go(cfg):
        return run_preflight(Tier.LOCAL, local_pred(), cfg, plugin_aux_tasks=[], provider_lookup=lambda n: None,
                             attested_profile=None)
    assert item(go(base_config()), "plugins.isolation").verdict == "local"
    assert item(go(base_config(plugins={})), "plugins.isolation").verdict == "local"   # absent -> default
    cfg = base_config()
    del cfg["plugins"]
    assert item(go(cfg), "plugins.isolation").verdict == "local"
    assert item(go(base_config(plugins={"isolation": "host"})), "plugins.isolation").verdict == "off_tier"
    assert item(go(base_config(plugins={"isolation": ""})), "plugins.isolation").verdict == "missing"
    assert item(go(base_config(plugins={"isolation": None})), "plugins.isolation").verdict == "missing"
    assert item(go(base_config(plugins="in_process")), "plugins.isolation").verdict == "off_tier"


def attested_config(**over):
    cfg = base_config(model={"provider": "attested-tinfoil", "default": "llama"},
                      auxiliary={"vision": {"provider": "attested-tinfoil"}})
    cfg.update(over)
    return cfg


def test_attested_tier_passes_with_profile():
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(), profile="attested-tinfoil")
    assert r.ok, format_report(r)
    assert item(r, "model.provider").verdict == "in_tier"
    assert item(r, "provider_profile[attested-tinfoil]").verdict == "in_tier"
    assert item(r, "auxiliary.compression.provider").verdict == "in_tier"
    assert item(r, "plugins.isolation").verdict == "in_tier"


def test_attested_tier_profile_missing():
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(), profile="attested-tinfoil",
            lookup=lambda _n: None)
    i = item(r, "provider_profile[attested-tinfoil]")
    assert i.verdict == "missing" and "isolation" in i.fix
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(), profile=None)
    assert item(r, "provider_profile[?]").verdict == "missing"


def test_attested_tier_stale_verification_off_tier():
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(ok=False), profile="attested-tinfoil")
    assert item(r, "model.provider").verdict == "off_tier"


def test_local_tier_has_no_profile_item():
    assert not [i for i in run(base_config()).items if i.key.startswith("provider_profile")]


def test_zdr_tier_everything_off():
    r = run(base_config(), tier=Tier.ZDR, pred=ZdrPredicate())
    assert item(r, "model.provider").verdict == "off_tier"
    assert not r.ok


def test_predicate_raising_is_off_tier():
    class Boom:
        tier = Tier.LOCAL

        def classify(self, dest):
            raise RuntimeError("x")
    assert item(run(base_config(), pred=Boom()), "model.provider").verdict == "off_tier"


# --- redaction / formatting / fingerprint -------------------------------------------------------

def test_redaction():
    cfg = base_config(model={"provider": "ollama", "default": "q",
                             "base_url": "http://user:hunter2@127.0.0.1:11434/v1?api_key=sk-live"},
                      fallback_providers=[{"provider": "openrouter", "model": "x", "api_key": "sk-or-SECRET"}])
    r = run(cfg)
    text = format_report(r)
    assert "hunter2" not in text and "sk-live" not in text and "sk-or-SECRET" not in text
    assert "127.0.0.1:11434" in text
    assert pf.redact_value("auxiliary.vision.api_key", "sk-1") == "***"
    assert pf.redact_value("x.token", "") == ""


def test_format_report_table_shape():
    r = run(base_config(fallback_providers=[{"provider": "openrouter", "model": "x"}]))
    lines = format_report(r).splitlines()
    assert lines[0].startswith("confidential preflight: tier=local-only FAIL")
    header = lines[1]
    assert header.split() == ["KEY", "VALUE", "VERDICT", "FIX"]
    vcol = header.index("VERDICT")
    fcol = header.index("FIX")
    for line, it in zip(lines[3:], r.items):
        assert line[vcol:vcol + len(it.verdict)] == it.verdict
        if it.fix:
            assert line[fcol:] == it.fix
    assert len(lines) == 3 + len(r.items)


def test_passing_items_have_no_fix():
    r = run(base_config())
    assert all(i.fix == "" for i in r.items)


def test_run_preflight_does_not_mutate_config():
    cfg = base_config(fallback_providers=[{"provider": "x", "model": "y"}])
    snapshot = copy.deepcopy(cfg)
    run(cfg, plugin=[{"key": "pt", "defaults": {"provider": "openrouter"}, "inherit_from": "compression"}])
    assert cfg == snapshot


def test_fingerprint_stable_and_order_independent():
    a = base_config()
    b = dict(reversed(list(copy.deepcopy(a).items())))
    assert config_fingerprint(a) == config_fingerprint(b) == run(a).fingerprint
    assert len(config_fingerprint(a)) == 64


def test_fingerprint_ignores_unrelated_and_secret_keys():
    a = base_config()
    b = copy.deepcopy(a)
    b["display"] = {"compact": True}
    b["auxiliary"]["vision"]["api_key"] = "sk-rotated"
    b["auxiliary"]["vision"]["timeout"] = 999
    assert config_fingerprint(a) == config_fingerprint(b)


@pytest.mark.parametrize("mutate", [
    lambda c: c["model"].update(provider="openrouter"),
    lambda c: c["model"].update(default="other"),
    lambda c: c["model"].update(base_url="http://10.0.0.1/v1"),
    lambda c: c.update(fallback_providers=[{"provider": "x", "model": "y"}]),
    lambda c: c.update(fallback_model={"provider": "x", "model": "y"}),
    lambda c: c["auxiliary"]["vision"].update(provider="auto"),
    lambda c: c["auxiliary"].update(compression={"base_url": "http://x"}),
    lambda c: c["auxiliary"].update(curator={"fallback_chain": [{"provider": "x"}]}),
    lambda c: c["auxiliary"].update(some_plugin_task={"provider": "x"}),
    lambda c: c["memory"].update(provider="honcho"),
    lambda c: c["mcp_servers"].update(r={"url": "https://x"}),
    lambda c: c["plugins"].update(isolation="host"),
])
def test_fingerprint_changes_on_enumerated_keys(mutate):
    a = base_config()
    b = copy.deepcopy(a)
    mutate(b)
    assert config_fingerprint(a) != config_fingerprint(b)


def test_fingerprint_covers_plugin_defaults():
    a = base_config()
    e1 = [{"key": "pt", "defaults": {"provider": "auto"}}]
    e2 = [{"key": "pt", "defaults": {"provider": "openrouter"}}]
    assert config_fingerprint(a, plugin_aux_tasks=e1) != config_fingerprint(a, plugin_aux_tasks=e2)


def test_builtin_aux_snapshot_used_when_import_fails(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "hermes_cli.config_defaults":
            raise ImportError("no hermes")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    assert pf.builtin_aux_task_names() == list(BUILTIN_AUX_TASKS_SNAPSHOT)


# --- Amendment 1 additions ----------------------------------------------------------------------

def test_mcp_url_server_classified_by_host():
    cfg = base_config(mcp_servers={"lh": {"url": "http://localhost:8000/mcp"},
                                   "lan": {"url": "http://192.168.1.20:9000/sse", "command": "npx"},
                                   "bad": {"url": "http://evil.com\\@127.0.0.1/mcp"},
                                   "empty": {"url": ""}})
    r = run(cfg)
    assert item(r, "mcp_servers.lh.url").verdict == "local"
    assert item(r, "mcp_servers.lan.url").verdict == "local"   # url wins over command
    assert item(r, "mcp_servers.bad.url").verdict == "off_tier"
    assert item(r, "mcp_servers.empty.url").verdict == "off_tier"


@pytest.mark.parametrize("servers", [["https://x"], "https://x"])
def test_mcp_servers_non_mapping_off_tier(servers):
    assert item(run(base_config(mcp_servers=servers)), "mcp_servers").verdict == "off_tier"


def test_delegation_inherits_main_when_unset():
    r = run(base_config())
    assert item(r, "delegation.provider").verdict == "local"
    assert item(r, "delegation.model").verdict == "local"
    r = run(base_config(model={"provider": "openrouter", "default": "x"}))
    assert item(r, "delegation.provider").verdict == "off_tier"


def test_delegation_explicit_routes():
    ok = run(base_config(delegation={"provider": "custom", "model": "q", "base_url": "http://10.0.0.3/v1"}))
    assert item(ok, "delegation.base_url").verdict == "local"
    assert ok.ok, format_report(ok)
    for deleg in ({"provider": "openrouter", "model": "x"}, {"base_url": "https://api.example.com/v1"},
                  {"provider": "moa"}, {"provider": "openai-codex", "base_url": LOCAL_URL}):
        r = run(base_config(delegation=deleg))
        assert item(r, "delegation.provider").verdict == "off_tier", deleg
        assert "delegation." in item(r, "delegation.provider").fix
    r = run(base_config(delegation={"fallback_providers": [{"provider": "openrouter", "model": "x"}]}))
    assert item(r, "delegation.fallback_providers").verdict == "off_tier"


@pytest.mark.parametrize("tts,verdict", [
    ({"provider": "piper"}, "local"), ({"provider": "kittentts", "enabled": True}, "local"),
    ({"provider": "neutts"}, "local"), ({"provider": "none"}, "local"),
    ({"provider": "edge"}, "disabled"),                      # enabled unset => disabled (ruling)
    ({"provider": "edge", "enabled": False}, "disabled"),
    ({"provider": "elevenlabs", "enabled": "false"}, "disabled"),
    ({}, "disabled"), ({"provider": ""}, "disabled"), (None, "disabled"), ("junk", "disabled"),
    ({"provider": "edge", "enabled": True}, "off_tier"),
    ({"provider": "", "enabled": True}, "off_tier"),         # unset provider resolves to edge
    ({"provider": "elevenlabs", "enabled": "yes"}, "off_tier"),
    ({"provider": "openai", "enabled": True}, "off_tier"),
])
def test_tts_rules(tts, verdict):
    i = item(run(base_config(tts=tts)), "tts.provider")
    assert i.verdict == verdict, i
    if verdict == "off_tier":
        assert "tts.provider" in i.fix


def test_tts_absent_is_disabled_default_edge():
    cfg = base_config()
    del cfg["tts"]
    i = item(run(cfg), "tts.provider")
    assert i.verdict == "disabled" and i.value_redacted == "(default edge, disabled)"


@pytest.mark.parametrize("tts", [{"provider": "edge", "enabled": False}, {}, {"provider": ""}])
def test_tts_auto_tts_overrides_disabled(tts):
    # Hermes has no tts.enabled key; voice.auto_tts makes it speak replies through tts.provider anyway.
    i = item(run(base_config(tts=tts, voice={"auto_tts": True})), "tts.provider")
    assert i.verdict == "off_tier" and "voice.auto_tts" in i.fix
    assert item(run(base_config(tts={"provider": "piper"}, voice={"auto_tts": True})),
                "tts.provider").verdict == "local"


def test_tts_named_command_provider_is_local():
    cfg = base_config(tts={"provider": "mysay", "enabled": True,
                           "providers": {"mysay": {"command": "say -o {out} {text}"}}})
    assert item(run(cfg), "tts.provider").verdict == "local"
    cfg = base_config(tts={"provider": "myhttp", "enabled": True, "providers": {"myhttp": {"url": "https://x"}}})
    assert item(run(cfg), "tts.provider").verdict == "off_tier"


def test_fingerprint_covers_tts_enabled_and_auto_tts():
    a = base_config()
    assert config_fingerprint(a) != config_fingerprint(base_config(tts={"provider": "piper", "enabled": True}))
    assert config_fingerprint(a) != config_fingerprint(base_config(voice={"auto_tts": True}))


@pytest.mark.parametrize("mem", ["honcho", ["honcho"], 3])
def test_memory_non_mapping_off_tier(mem):
    assert item(run(base_config(memory=mem)), "memory").verdict == "off_tier"


def test_memory_absent_or_null_is_builtin():
    cfg = base_config()
    del cfg["memory"]
    assert item(run(cfg), "memory.provider").verdict == "local"
    assert item(run(base_config(memory=None)), "memory.provider").verdict == "local"


@pytest.mark.parametrize("fb", ["openrouter", 1, [None]])
def test_fallback_providers_junk_off_tier(fb):
    r = run(base_config(fallback_providers=fb))
    assert item(r, "fallback_providers[0]").verdict == "off_tier"


@pytest.mark.parametrize("chain", [{"provider": "openrouter"}, "openrouter"])
def test_aux_fallback_chain_non_list_off_tier(chain):
    cfg = base_config()
    cfg["auxiliary"]["approval"] = {"fallback_chain": chain}
    assert item(run(cfg), "auxiliary.approval.fallback_chain").verdict == "off_tier"


def test_aux_non_dict_block_off_tier():
    cfg = base_config()
    cfg["auxiliary"]["compression"] = "openrouter"
    assert item(run(cfg), "auxiliary.compression").verdict == "off_tier"


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(delegation={"provider": "openrouter"}),
    lambda c: c.update(delegation={"model": "x"}),
    lambda c: c.update(delegation={"base_url": "http://x"}),
    lambda c: c.update(delegation={"fallback_providers": [{"provider": "x"}]}),
    lambda c: c["tts"].update(provider="edge"),
    lambda c: c["model"].update(api_mode="codex_responses"),
    lambda c: c["auxiliary"].update(compression="openrouter"),
    lambda c: c.update(mcp_servers=["https://x"]),
    lambda c: c.update(memory="honcho"),
    lambda c: c.update(plugins="host"),
])
def test_fingerprint_changes_on_amendment_keys(mutate):
    a = base_config()
    b = copy.deepcopy(a)
    mutate(b)
    assert config_fingerprint(a) != config_fingerprint(b)


def test_fingerprint_ignores_non_task_aux_scalars():
    a = base_config()
    b = copy.deepcopy(a)
    b["auxiliary"]["transient_retries"] = 6
    assert config_fingerprint(a) == config_fingerprint(b)

"""W3: preflight rules over plain config dicts. Each rule has a passing and a failing fixture."""
import copy

import pytest

from confidential_mode import preflight as pf
from confidential_mode.preflight import (
    BUILTIN_AUX_TASKS_SNAPSHOT,
    PreflightReport,
    config_fingerprint,
    format_report,
    run_preflight,
)
from confidential_mode.tiers import AttestedPredicate, OnHostPredicate, Tier, Verdict, ZdrPredicate

ON_HOST_URL = "http://127.0.0.1:11434/v1"
PROFILES = {"ollama": ON_HOST_URL, "openrouter": "https://openrouter.ai/api/v1",
            "attested-tinfoil": "https://inference.tinfoil.sh/v1"}


def on_host_pred():
    return OnHostPredicate(profile_base_url=lambda p: PROFILES.get(p, ""))


def attested_pred(ok=True):
    return AttestedPredicate({"attested-tinfoil"}, lambda _p: Verdict(ok, "fresh" if ok else "stale", ""))


def base_config(**over):
    cfg = {
        "model": {"provider": "ollama", "default": "qwen3:8b", "base_url": ON_HOST_URL},
        "fallback_providers": [],
        "auxiliary": {"vision": {"provider": "ollama", "model": "llava", "base_url": ""}},
        "memory": {"provider": ""},
        "mcp_servers": {},
        "plugins": {"isolation": "in_process"},
        "tts": {"provider": "piper"},
    }
    cfg.update(over)
    return cfg


def run(cfg, tier=Tier.ON_HOST, pred=None, *, plugin=(), isolation="in_process", lookup=None, profile=None,
        keys=("TINFOIL_API_KEY", "NEAR_AI_API_KEY")):
    return run_preflight(tier, pred or on_host_pred(), cfg, plugin_aux_tasks=list(plugin), isolation=isolation,
                         provider_lookup=lookup or (lambda n: object() if n in PROFILES else None),
                         attested_profile=profile, key_state=lambda p, env: "set" if env in keys else "not set")


def item(report: PreflightReport, key):
    matches = [i for i in report.items if i.key == key]
    assert matches, f"{key} not in {[i.key for i in report.items]}"
    return matches[0]


def test_baseline_on_host_config_passes():
    r = run(base_config())
    assert r.ok, format_report(r)
    assert item(r, "model.provider").verdict == "on_host"
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
    assert item(r, "model.provider").verdict == "on_host"
    assert item(r, "auxiliary.compression.provider").verdict == "on_host"


@pytest.mark.parametrize("provider", ["", "auto"])
def test_main_auto_off_tier(provider):
    r = run(base_config(model={"provider": provider, "default": "q", "base_url": ON_HOST_URL}))
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
    r = run(base_config(model={"provider": "moa", "default": "preset", "base_url": ON_HOST_URL}))
    i = item(r, "model.provider")
    assert i.verdict == "off_tier" and "moa" in i.fix


@pytest.mark.parametrize("provider", ["openai-codex", "codex"])
def test_main_openai_codex_off_tier_even_if_on_host(provider):
    r = run(base_config(model={"provider": provider, "default": "gpt", "base_url": ON_HOST_URL}))
    i = item(r, "model.provider")
    assert i.verdict == "off_tier" and "app-server" in i.fix


# --- fallbacks ----------------------------------------------------------------------------------

def test_fallback_providers_nonempty_off_tier_even_if_on_host():
    cfg = base_config(fallback_providers=[{"provider": "ollama", "model": "q", "base_url": ON_HOST_URL},
                                          {"provider": "moa", "model": "p"}])
    r = run(cfg)
    assert [i.verdict for i in r.items if i.key.startswith("fallback_providers[")] == ["off_tier", "off_tier"]
    assert item(r, "fallback_providers[0]").fix == "remove fallback_providers entries while locked"
    assert not r.ok


def test_fallback_providers_dict_form_and_legacy_fallback_model():
    r = run(base_config(fallback_providers={"provider": "openrouter", "model": "x"},
                        fallback_model={"provider": "openrouter", "model": "y"}))
    assert item(r, "fallback_providers[0]").verdict == "off_tier"
    assert item(r, "fallback_model").verdict == "off_tier"


# --- auxiliary ----------------------------------------------------------------------------------

def test_vision_auto_is_off_tier_even_with_on_host_main():
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
                "auxiliary.vision.provider").verdict == "on_host"
    cfg = base_config(model={"provider": "openrouter", "default": "x"}, auxiliary={"vision": {"provider": "main"}})
    assert item(run(cfg), "auxiliary.vision.provider").verdict == "off_tier"


def test_vision_auto_with_on_host_base_url_is_explicit_custom():
    cfg = base_config(auxiliary={"vision": {"provider": "auto", "base_url": "http://127.0.0.9:8000/v1"}})
    r = run(cfg)
    assert item(r, "auxiliary.vision.provider").verdict == "on_host"
    assert item(r, "auxiliary.vision.base_url").verdict == "on_host"


def test_vision_explicit_remote_off_tier():
    cfg = base_config(auxiliary={"vision": {"provider": "openrouter"}})
    assert item(run(cfg), "auxiliary.vision.provider").verdict == "off_tier"


def test_aux_explicit_provider_and_base_url():
    ok = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL},
                                "compression": {"provider": "custom", "base_url": "http://127.0.0.4:8080/v1"}})
    r = run(ok)
    assert item(r, "auxiliary.compression.provider").verdict == "on_host"
    assert item(r, "auxiliary.compression.base_url").value_redacted == "http://127.0.0.4:8080/v1"
    bad = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL},
                                 "compression": {"provider": "custom", "base_url": "https://api.example.com/v1"}})
    r = run(bad)
    i = item(r, "auxiliary.compression.base_url")
    assert i.verdict == "off_tier" and "set auxiliary.compression.base_url to a server on this machine" in i.fix


def test_aux_moa_provider_off_tier():
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL},
                                 "approval": {"provider": "moa", "base_url": ON_HOST_URL}})
    assert item(run(cfg), "auxiliary.approval.provider").verdict == "off_tier"


def test_aux_fallback_chain_entries():
    good = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL}, "curator": {
        "provider": "auto", "fallback_chain": [{"provider": "ollama", "model": "q"}]}})
    assert item(run(good), "auxiliary.curator.fallback_chain[0]").verdict == "on_host"
    bad = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL}, "curator": {
        "provider": "auto", "fallback_chain": [{"provider": "ollama"}, {"provider": "openrouter", "model": "x"},
                                               {"provider": "moa"}, {"provider": "auto"}, "junk"]}})
    r = run(bad)
    verdicts = [item(r, f"auxiliary.curator.fallback_chain[{i}]").verdict for i in range(5)]
    assert verdicts == ["on_host", "off_tier", "off_tier", "off_tier", "off_tier"]


def test_plugin_aux_task_by_name_inherits_main():
    r = run(base_config(), plugin=["my_plugin_task"])
    assert item(r, "auxiliary.my_plugin_task.provider").verdict == "on_host"
    assert "my_plugin_task" in r.aux_tasks
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL}, "my_plugin_task": {"provider": "openrouter"}})
    assert item(run(cfg, plugin=["my_plugin_task"]), "auxiliary.my_plugin_task.provider").verdict == "off_tier"


def test_plugin_aux_task_defaults_are_honoured():
    entry = {"key": "pt", "defaults": {"provider": "openrouter", "model": "x"}, "inherit_from": None}
    r = run(base_config(), plugin=[entry])
    assert item(r, "auxiliary.pt.provider").verdict == "off_tier"
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL}, "pt": {"provider": "ollama"}})
    assert item(run(cfg, plugin=[entry]), "auxiliary.pt.provider").verdict == "on_host"  # user wins


def test_plugin_aux_task_inherit_from():
    entry = {"key": "pt", "defaults": {}, "inherit_from": "compression"}
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL}, "compression": {"provider": "openrouter"}})
    assert item(run(cfg, plugin=[entry]), "auxiliary.pt.provider").verdict == "off_tier"
    cfg["auxiliary"]["pt"] = {"provider": "ollama"}  # pinned on the task itself
    assert item(run(cfg, plugin=[entry]), "auxiliary.pt.provider").verdict == "on_host"


# --- memory / mcp / isolation / attested --------------------------------------------------------

@pytest.mark.parametrize("value", ["", "builtin", "built-in", "local", "none", "None"])
def test_memory_on_host(value):
    assert item(run(base_config(memory={"provider": value})), "memory.provider").verdict == "on_host"


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
    assert item(r, "mcp_servers.fs.command").verdict == "on_host"
    remote = item(r, "mcp_servers.remote.url")
    assert remote.verdict == "off_tier" and "SECRET" not in remote.value_redacted
    assert "mcp_servers.remote.enabled: false" in remote.fix
    assert item(r, "mcp_servers.off.url").verdict == "disabled"
    assert item(r, "mcp_servers.weird").verdict == "missing"
    assert "abc" not in format_report(r)


@pytest.mark.parametrize("iso,verdict", [("in_process", "on_host"), ("host", "off_tier"), ("", "missing"),
                                         (None, "on_host"), ("IN-PROCESS", "off_tier"), (1, "off_tier"),
                                         (["in_process"], "off_tier")])
def test_plugins_isolation(iso, verdict):
    i = item(run(base_config(), isolation=iso), "plugins.isolation")
    assert i.verdict == verdict
    if verdict != "on_host":
        assert "plugins.isolation: in_process" in i.fix


def test_plugins_isolation_read_from_config_when_not_passed():
    def go(cfg):
        return run_preflight(Tier.ON_HOST, on_host_pred(), cfg, plugin_aux_tasks=[], provider_lookup=lambda n: None,
                             attested_profile=None)
    assert item(go(base_config()), "plugins.isolation").verdict == "on_host"
    assert item(go(base_config(plugins={})), "plugins.isolation").verdict == "on_host"   # absent -> default
    cfg = base_config()
    del cfg["plugins"]
    assert item(go(cfg), "plugins.isolation").verdict == "on_host"
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


def test_attested_tier_needs_the_vendor_api_key():
    """ux-pass-1 item 1: verification is public, so a keyless profile verified, pinned and locked, and then
    failed on its first turn. One row per attested vendor a route uses; the value is never shown."""
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(), profile="attested-tinfoil")
    assert item(r, "TINFOIL_API_KEY").verdict == "in_tier" and item(r, "TINFOIL_API_KEY").value_redacted == "set"
    assert "NEAR_AI_API_KEY" not in [i.key for i in r.items]          # no NEAR route, no NEAR row
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(), profile="attested-tinfoil", keys=())
    i = item(r, "TINFOIL_API_KEY")
    assert not r.ok and i.verdict == "off_tier" and i.value_redacted == "not set"
    assert i.fix == ("set TINFOIL_API_KEY (see Requirements in README.md): export the variable or add the variable "
                     "to Hermes' env file, or give Hermes the key through model.api_key; a key added only with "
                     "hermes auth is not visible to the plugin")
    # A NEAR route anywhere (here one auxiliary task) adds the NEAR row.
    both = AttestedPredicate({"attested-tinfoil", "attested-near"}, lambda _p: Verdict(True, "fresh", ""))
    cfg = attested_config(auxiliary={"vision": {"provider": "attested-tinfoil"},
                                     "compression": {"provider": "attested-near", "model": "m"}})
    r = run(cfg, tier=Tier.ATTESTED, pred=both, profile="attested-tinfoil", keys=("TINFOIL_API_KEY",))
    assert item(r, "NEAR_AI_API_KEY").verdict == "off_tier" and item(r, "TINFOIL_API_KEY").verdict == "in_tier"
    # The on-host tier never asks for a vendor key.
    assert "TINFOIL_API_KEY" not in [i.key for i in run(base_config(), keys=()).items]


def test_key_state_reads_every_source_and_never_shows_the_value(monkeypatch, tmp_path):
    """Amendment 11 and 13: the secret scope and a route's api_key in config count; Hermes' auth store is never
    opened (catalog rule 11); an unscoped read (a multiplexed gateway with no scope) is "not readable in this
    scope"."""
    import json as _json

    import agent.secret_scope as scope
    import hermes_constants

    from confidential_mode import preflight
    monkeypatch.setattr(hermes_constants, "get_hermes_home", lambda: tmp_path)
    monkeypatch.delenv("TINFOIL_API_KEY", raising=False)
    cfg = attested_config()
    assert preflight.key_state("attested-tinfoil", "TINFOIL_API_KEY", cfg) == "not set"
    monkeypatch.setenv("TINFOIL_API_KEY", "sk-secret-value")
    assert preflight.key_state("attested-tinfoil", "TINFOIL_API_KEY", cfg) == "set"
    r = run_preflight(Tier.ATTESTED, attested_pred(), cfg, plugin_aux_tasks=[], isolation="in_process",
                      provider_lookup=lambda n: object(), attested_profile="attested-tinfoil",
                      key_state=lambda p, e: preflight.key_state(p, e, cfg))
    assert "sk-secret-value" not in format_report(r) and item(r, "TINFOIL_API_KEY").value_redacted == "set"
    monkeypatch.setenv("TINFOIL_API_KEY", "  ")
    assert preflight.key_state("attested-tinfoil", "TINFOIL_API_KEY", cfg) == "not set"
    # model.api_key on the route that names the profile
    keyed = attested_config(model={"provider": "attested-tinfoil", "default": "llama", "api_key": "sk-cfg"})
    assert preflight.key_state("attested-tinfoil", "TINFOIL_API_KEY", keyed) == "set"
    assert preflight.key_state("attested-near", "NEAR_AI_API_KEY", keyed) == "not set"   # another profile's
    # Hermes' auth store is never opened: a pool entry alone reads as not set, and no open() names auth.json.
    auth = tmp_path / "auth.json"
    auth.write_text(_json.dumps({"credential_pool": {"attested-tinfoil": [{"id": "x", "access_token": "t"}]},
                                 "providers": {"nous": {"access_token": "t"}}}))
    import builtins
    real_open, opened = builtins.open, []

    def spy_open(file, *a, **k):
        opened.append(str(file))
        return real_open(file, *a, **k)
    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.delenv("TINFOIL_API_KEY", raising=False)
    monkeypatch.delenv("NOUS_API_KEY", raising=False)
    assert preflight.key_state("attested-tinfoil", "TINFOIL_API_KEY", cfg) == "not set"
    assert preflight.key_state("nous", "NOUS_API_KEY", cfg) == "not set"
    monkeypatch.setattr(builtins, "open", real_open)
    assert not [f for f in opened if f.endswith("auth.json")]
    assert not hasattr(preflight, "auth_store_has")

    def unscoped(name, default=None):
        raise scope.UnscopedSecretError(name, "no scope")
    monkeypatch.setattr(scope, "get_secret", unscoped)
    assert preflight.key_state("attested-tinfoil", "TINFOIL_API_KEY", cfg) == "not readable in this scope"


def test_no_key_rows_without_a_key_state():
    """The per-turn recheck passes no key_state: a key the turn cannot read is not a config failure."""
    r = run_preflight(Tier.ATTESTED, attested_pred(), attested_config(), plugin_aux_tasks=[], isolation="in_process",
                      provider_lookup=lambda n: object(), attested_profile="attested-tinfoil")
    assert "TINFOIL_API_KEY" not in [i.key for i in r.items] and r.ok


def test_a_pending_pin_is_named_as_the_fix_not_the_route():
    """ux-pass-1 item 3: with the route right and only the pin missing, the FIX column named the route key."""
    no_pin = "no approved enclave build pinned; run /confidential pins approve"
    pred = AttestedPredicate({"attested-tinfoil"}, lambda _p: Verdict(False, no_pin, ""))
    cfg = attested_config(auxiliary={"vision": {"provider": "attested-tinfoil", "model": "v"}})
    r = run(cfg, tier=Tier.ATTESTED, pred=pred, profile="attested-tinfoil")
    pin_fix = "approve the pending pin: hermes confidential pins approve (review it first with pins review)"
    assert item(r, "model.provider").fix == pin_fix and item(r, "model.default").fix == pin_fix
    assert item(r, "auxiliary.vision.provider").fix == pin_fix                      # an explicit route
    assert item(r, "auxiliary.compression.provider").fix == "inherits the main route; fix the main route first"
    assert item(r, "delegation.provider").fix == "inherits the main route; fix the main route first"
    # Another cause keeps the route fix.
    r = run(cfg, tier=Tier.ATTESTED, pred=attested_pred(ok=False), profile="attested-tinfoil")
    assert item(r, "model.provider").fix.startswith("model.provider is attested-tinfoil; that route does not pass yet")


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


def test_on_host_tier_has_no_profile_item():
    assert not [i for i in run(base_config()).items if i.key.startswith("provider_profile")]


def test_zdr_tier_everything_off():
    r = run(base_config(), tier=Tier.ZDR, pred=ZdrPredicate())
    assert item(r, "model.provider").verdict == "off_tier"
    assert not r.ok


def test_predicate_raising_is_off_tier():
    class Boom:
        tier = Tier.ON_HOST

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
    assert lines[0].startswith("confidential preflight: tier=on-host-only FAIL")
    header = lines[1]
    assert header.split() == ["KEY", "VALUE", "VERDICT", "FIX"]
    vcol = header.index("VERDICT")
    fcol = header.index("FIX")
    for line, it in zip(lines[3:], r.items, strict=False):
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
    assert item(r, "mcp_servers.lh.url").verdict == "on_host"
    assert item(r, "mcp_servers.lan.url").verdict == "off_tier"  # url wins over command; private range unless listed
    assert item(r, "mcp_servers.bad.url").verdict == "off_tier"
    assert item(r, "mcp_servers.empty.url").verdict == "off_tier"


@pytest.mark.parametrize("servers", [["https://x"], "https://x"])
def test_mcp_servers_non_mapping_off_tier(servers):
    assert item(run(base_config(mcp_servers=servers)), "mcp_servers").verdict == "off_tier"


def test_delegation_inherits_main_when_unset():
    r = run(base_config())
    assert item(r, "delegation.provider").verdict == "on_host"
    assert item(r, "delegation.model").verdict == "on_host"
    r = run(base_config(model={"provider": "openrouter", "default": "x"}))
    assert item(r, "delegation.provider").verdict == "off_tier"


def test_delegation_explicit_routes():
    ok = run(base_config(delegation={"provider": "custom", "model": "q", "base_url": "http://127.0.0.3/v1"}))
    assert item(ok, "delegation.base_url").verdict == "on_host"
    assert ok.ok, format_report(ok)
    for deleg in ({"provider": "openrouter", "model": "x"}, {"base_url": "https://api.example.com/v1"},
                  {"provider": "moa"}, {"provider": "openai-codex", "base_url": ON_HOST_URL}):
        r = run(base_config(delegation=deleg))
        assert item(r, "delegation.provider").verdict == "off_tier", deleg
        assert "delegation." in item(r, "delegation.provider").fix
    r = run(base_config(delegation={"fallback_providers": [{"provider": "openrouter", "model": "x"}]}))
    assert item(r, "delegation.fallback_providers").verdict == "off_tier"


@pytest.mark.parametrize("tts,verdict", [
    ({"provider": "piper"}, "on_host"), ({"provider": "kittentts", "enabled": True}, "on_host"),
    ({"provider": "neutts"}, "on_host"), ({"provider": "none"}, "on_host"),
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
                "tts.provider").verdict == "on_host"


def test_tts_named_command_provider_is_on_host():
    cfg = base_config(tts={"provider": "mysay", "enabled": True,
                           "providers": {"mysay": {"command": "say -o {out} {text}"}}})
    assert item(run(cfg), "tts.provider").verdict == "on_host"
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
    assert item(run(cfg), "memory.provider").verdict == "on_host"
    assert item(run(base_config(memory=None)), "memory.provider").verdict == "on_host"


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


# --- terminal backend (review finding 2) ----------------------------------------------------------

@pytest.mark.parametrize("backend", ["ssh", "modal", "docker", "daytona", "vercel_sandbox", "managed_modal", "x"])
def test_non_local_terminal_backend_refuses_the_lock_and_names_the_key(backend):
    r = run_preflight(Tier.ON_HOST, on_host_pred(), base_config(terminal={"backend": backend}), plugin_aux_tasks=[],
                      isolation="in_process", provider_lookup=lambda n: object(), attested_profile=None,
                      terminal_env=None)
    assert not r.ok
    it = item(r, "terminal.backend")
    assert it.verdict == "off_tier" and it.value_redacted == backend
    assert it.fix.startswith("set terminal.backend: local while locked") and f"the {backend} backend" in it.fix
    for tool in ("terminal", "execute_code", "read_file", "write_file", "patch", "search_files", "process_manage"):
        assert tool in it.fix
    assert "terminal.backend" in format_report(r)


def test_resolved_terminal_backend_must_also_be_local():
    def pf_run(cfg, env):
        return run_preflight(Tier.ON_HOST, on_host_pred(), cfg, plugin_aux_tasks=[], isolation="in_process",
                             provider_lookup=lambda n: object(), attested_profile=None, terminal_env=env)
    ok = pf_run(base_config(terminal={"backend": "local"}), None)
    assert ok.ok and item(ok, "terminal.backend").verdict == "on_host"
    assert [i for i in ok.items if i.key == pf.TERMINAL_RESOLVED_KEY] == []
    assert pf_run(base_config(), None).ok and item(pf_run(base_config(), None), "terminal.backend").value_redacted \
        == "(default local)"
    assert pf_run(base_config(terminal={"backend": "local"}), "local").ok
    bad = pf_run(base_config(terminal={"backend": "local"}), "ssh")
    env_item = item(bad, pf.TERMINAL_RESOLVED_KEY)
    assert not bad.ok and env_item.verdict == "off_tier" and "with no key, unset the variable" in env_item.fix
    assert not pf_run(base_config(terminal="ssh"), None).ok          # junk section fails closed
    # An unset variable and "local" fingerprint the same; a backend change does not.
    fp = lambda cfg, env: config_fingerprint(cfg, terminal_env=env)  # noqa: E731
    assert fp(base_config(), None) == fp(base_config(), "local") == fp(base_config(terminal={"backend": "local"}), "")
    assert fp(base_config(), None) != fp(base_config(terminal={"backend": "ssh"}), None)
    assert fp(base_config(), None) != fp(base_config(), "modal")



def test_a_lock_recorded_under_the_version_1_fingerprint_still_matches():
    """Second review, item 1: the terminal keys joined the fingerprint later. A lock recorded under the
    old layout must not read as a config change after the upgrade, or every session would be marked breached."""
    from confidential_mode.locking import fingerprint_matches
    cfg = base_config()
    v1 = config_fingerprint(cfg, version=1, terminal_env=None)
    v2 = config_fingerprint(cfg, terminal_env=None)
    assert v1 != v2
    assert fingerprint_matches(v1, cfg, terminal_env=None) and fingerprint_matches(v2, cfg, terminal_env=None)
    edited = base_config(fallback_providers=[{"provider": "openrouter", "model": "x"}])
    assert not fingerprint_matches(v1, edited, terminal_env=None)      # a real change still counts
    assert not fingerprint_matches(v2, cfg, terminal_env="ssh")
    assert not fingerprint_matches("", cfg, terminal_env=None) and not fingerprint_matches(None, cfg)


def test_resolved_terminal_backend_reads_the_profile_scope_not_the_process_environment(monkeypatch):
    """Second review, item 1: a gateway serving several profiles binds each profile's terminal settings in a
    scope; the plugin resolves the backend the way Hermes' tools do, through that scope."""
    from tools.terminal_scope import reset_terminal_scope, set_terminal_scope
    monkeypatch.setenv("TERMINAL_ENV", "docker")                    # the launch profile's backend
    token = set_terminal_scope({"TERMINAL_ENV": "local"})
    try:
        assert pf.resolved_terminal_backend() == "local"
    finally:
        reset_terminal_scope(token)
    monkeypatch.delenv("TERMINAL_ENV")
    token = set_terminal_scope({"TERMINAL_ENV": "ssh"})
    try:
        assert pf.resolved_terminal_backend() == "ssh"
    finally:
        reset_terminal_scope(token)


# --- Amendment 10 (backlog D03): on-host means loopback plus exact listed hosts ------------------------

def _listed_pred(hosts):
    return OnHostPredicate(extra_hosts=hosts, profile_base_url=lambda p: PROFILES.get(p, ""))


@pytest.mark.parametrize("url,rng", [
    ("http://10.0.0.9:8000/v1", "10.0.0.0/8"), ("http://172.20.1.2/v1", "172.16.0.0/12"),
    ("http://192.168.1.4:8080/v1", "192.168.0.0/16"), ("http://100.101.102.103/v1", "100.64.0.0/10"),
    ("http://[fe80::2%25en0]/v1", "fe80::/10"), ("http://[fd00::2]/v1", "fc00::/7"),
])
def test_private_range_row_names_the_range_and_the_key(url, rng):
    r = run(base_config(model={"provider": "custom", "default": "q", "base_url": url}))
    row = item(r, "model.base_url")
    assert row.verdict == "off_tier" and not r.ok
    assert rng in row.fix and "confidential.on_host.extra_hosts" in row.fix, row.fix


def test_listed_private_host_passes_and_shows_its_row():
    cfg = base_config(model={"provider": "custom", "default": "q", "base_url": "http://192.168.1.4:8080/v1"},
                      confidential={"on_host": {"extra_hosts": ["192.168.1.4"]}})
    r = run(cfg, pred=_listed_pred(["192.168.1.4"]))
    assert r.ok, format_report(r)
    assert item(r, "model.base_url").verdict == "on_host"
    assert item(r, "confidential.on_host.extra_hosts[0]").verdict == "on_host"


@pytest.mark.parametrize("entry", ["192.168.1.0/24", "10.0.0.*", "*.lan", "http://gpu-box.lan", "gpu-box.lan:8000",
                                   "10.0.0.1-10.0.0.9", 42])
def test_extra_hosts_range_or_junk_entry_fails_the_lock(entry):
    cfg = base_config(confidential={"on_host": {"extra_hosts": ["gpu-box.lan", entry]}})
    r = run(cfg, pred=_listed_pred(["gpu-box.lan", entry]))
    assert not r.ok
    assert item(r, "confidential.on_host.extra_hosts[0]").verdict == "on_host"
    bad = item(r, "confidential.on_host.extra_hosts[1]")
    assert bad.verdict == "off_tier" and "exact host" in bad.fix, bad.fix


def test_extra_hosts_not_a_list_fails_the_lock():
    r = run(base_config(confidential={"on_host": {"extra_hosts": "gpu-box.lan"}}))
    assert not r.ok and item(r, "confidential.on_host.extra_hosts").verdict == "off_tier"


def test_extra_hosts_rows_only_on_the_on_host_tier():
    cfg = base_config(confidential={"on_host": {"extra_hosts": ["10.0.0.0/8"]}})
    r = run(cfg, tier=Tier.ATTESTED, pred=attested_pred(), profile="attested-tinfoil")
    assert not [i for i in r.items if i.key.startswith("confidential.on_host")]


def test_fingerprint_covers_extra_hosts():
    a = base_config()
    assert config_fingerprint(a) == config_fingerprint(base_config(confidential={"on_host": {"extra_hosts": []}}))
    b = base_config(confidential={"on_host": {"extra_hosts": ["gpu-box.lan"]}})
    c = base_config(confidential={"on_host": {"extra_hosts": ["gpu-box.lan", "10.0.0.5"]}})
    assert len({config_fingerprint(a), config_fingerprint(b), config_fingerprint(c)}) == 3
    assert config_fingerprint(b, version=1) != config_fingerprint(a, version=1)


def test_auto_side_calls_stay_in_tier_with_a_note_while_an_openrouter_or_nous_credential_is_readable():
    """Amendment 11: Hermes' fall-through to OpenRouter or Nous runs only for an unset or auto main provider,
    which the lock refuses (agent/auxiliary_client.py:4529-4541). An `auto` side call stays in-tier; with such a
    credential readable its row carries the note, and `check` adds a summary line."""
    from confidential_mode import preflight
    r = run(base_config(), keys=("OPENROUTER_API_KEY",))
    i = item(r, "auxiliary.compression.provider")
    assert r.ok and i.verdict == "on_host"
    assert i.value_redacted == f"auto -> ollama (note: {preflight.AUTO_NOTE})"
    assert preflight.AUTO_NOTE == ("auto resolves to the main provider; Hermes' fall-through to OpenRouter or Nous "
                                   "runs only when the main provider is unset or auto, which the lock refuses")
    line = preflight.auto_summary(r, ["openrouter"])
    n = sum(1 for x in r.items if x.key.startswith("auxiliary.") and x.value_redacted.startswith("auto"))
    assert line.startswith(f"Side calls on auto: {n}. ") and "OpenRouter (OPENROUTER_API_KEY)" in line
    assert line.endswith(preflight.AUTO_SIGN_IN_NOTE)
    r = run(base_config(), keys=())
    i = item(r, "auxiliary.compression.provider")
    assert r.ok and i.value_redacted == "auto -> ollama (no OpenRouter or Nous credential readable)"
    assert preflight.auto_summary(r, []) == ""
    # The per-turn recheck (no key_state) adds nothing.
    r = run_preflight(Tier.ON_HOST, on_host_pred(), base_config(), plugin_aux_tasks=[], isolation="in_process",
                      provider_lookup=lambda n: None, attested_profile=None)
    assert item(r, "auxiliary.compression.provider").value_redacted == "auto -> ollama"


# ── Amendment 14: the collapsed table and the provider value each FIX names ──────────────────────────

def test_a_fresh_config_collapses_the_inheriting_tasks_into_one_row_per_verdict():
    r = run({}, tier=Tier.ATTESTED, keys=())
    inheriting = [i for i in r.items if i.group == "inherit"]
    assert len(inheriting) >= 15 and all(i.verdict == "off_tier" for i in inheriting)
    full = format_report(r)
    short = format_report(r, collapse=True)
    assert all(i.key in full for i in inheriting)
    assert not any(i.key in short for i in inheriting)
    rows = [line for line in short.splitlines() if line.startswith("auxiliary.* (")]
    assert len(rows) == 1 and f"auxiliary.* ({len(inheriting)} tasks)" in rows[0]
    assert "inherit the main route" in rows[0] and "the main route is off_tier" in rows[0]
    assert "check --verbose lists each task" in rows[0]
    assert len(short.splitlines()) < len(full.splitlines()) - 10
    assert short.splitlines()[0] == full.splitlines()[0]          # the same verdict and count


def test_every_in_tier_provider_fix_names_the_value_to_write():
    for tier, want in ((Tier.ATTESTED, "attested-tinfoil"), (Tier.ON_HOST, "custom")):
        r = run({}, tier=tier, keys=())
        text = format_report(r)
        assert "an in-tier provider" not in text, text
        assert want in item(r, "model.provider").fix
        assert want in item(r, "auxiliary.title_generation.provider").fix
    r = run(base_config(model={"provider": "attested-near", "default": "m"}), tier=Tier.ATTESTED,
            pred=None, keys=())
    fix = item(r, "auxiliary.title_generation.provider").fix
    assert fix == "" or "set auxiliary.title_generation.provider: attested-near" in fix


def test_a_passing_group_collapses_too():
    r = run(base_config())
    short = format_report(r, collapse=True)
    assert r.ok and "auxiliary.* (" in short and "PASS" in short.splitlines()[0]


def test_explicit_off_tier_routes_name_the_value_to_write_on_both_tiers():
    """Review SF2: an explicit off-tier main provider (the common first run: openrouter), an explicit off-tier
    auxiliary provider and an auxiliary fallback entry each name a value, never only "an in-tier route"."""
    cfg = base_config(model={"provider": "openrouter", "default": "x"},
                      auxiliary={"vision": {"provider": "custom", "base_url": ON_HOST_URL},
                                 "compression": {"provider": "deepinfra",
                                                 "fallback_chain": [{"provider": "openrouter", "model": "y"}]}})
    for tier, want, pred in ((Tier.ATTESTED, "attested-tinfoil", attested_pred()),
                             (Tier.ON_HOST, "custom", on_host_pred())):
        r = run(cfg, tier=tier, pred=pred, keys=())
        text = format_report(r)
        assert "an in-tier route" not in text and "an in-tier provider" not in text, text
        for key in ("model.provider", "auxiliary.compression.provider", "auxiliary.compression.fallback_chain[0]"):
            fix = item(r, key).fix
            assert want in fix and "openrouter (with" not in fix, (tier, key, fix)
        assert item(r, "model.provider").fix.startswith("set model.provider: ")


def test_a_key_not_readable_in_this_scope_is_not_told_to_set_the_key():
    """Review L2: on a gateway with no profile scope the key may be set; the headline and the row say so."""
    r = run_preflight(Tier.ATTESTED, attested_pred(), attested_config(), plugin_aux_tasks=[], isolation="in_process",
                      provider_lookup=lambda n: object() if n in PROFILES else None,
                      attested_profile="attested-tinfoil", key_state=lambda p, env: pf.KEY_UNSCOPED)
    head = pf.missing_key_headline(r)
    assert head.startswith("Not locked: TINFOIL_API_KEY is not readable in this scope; this process"), head
    assert "set TINFOIL_API_KEY (" not in head and "hermes confidential on attested" in head
    assert item(r, "TINFOIL_API_KEY").fix.startswith("TINFOIL_API_KEY may be set, but this process")
    r = run(attested_config(), tier=Tier.ATTESTED, pred=attested_pred(), profile="attested-tinfoil", keys=())
    assert pf.missing_key_headline(r) == ("Not locked: TINFOIL_API_KEY is not set; set TINFOIL_API_KEY (see "
                                          "Requirements in README.md).")


def test_an_on_host_route_fix_follows_the_failure_reason():
    """Re-review SF2-on-host: only a host off this machine gets "a server on this machine"; an unusable URL is
    told to be rewritten, and a moa provider on a loopback URL is told the provider value."""
    pf_route = pf.route_fix
    assert pf_route(Tier.ON_HOST, "auxiliary.x", "custom", "https://api.example.com/v1",
                    "host api.example.com is not an IP literal or a listed on-host name", "custom").startswith(
        "set auxiliary.x.base_url to a server on this machine")
    assert pf_route(Tier.ON_HOST, "auxiliary.x", "custom", "ftp://127.0.0.1/v1",
                    "base_url must start with http:// or https://", "custom").startswith(
        "rewrite auxiliary.x.base_url as a plain http:// or https:// URL")
    cfg = base_config(auxiliary={"vision": {"provider": "ollama", "base_url": ON_HOST_URL},
                                 "compression": {"provider": "moa", "base_url": ON_HOST_URL}})
    fix = item(run(cfg), "auxiliary.compression.provider").fix
    assert "server on this machine" not in fix and fix.startswith("set auxiliary.compression.provider: "), fix

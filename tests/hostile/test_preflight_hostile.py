"""Hostile tests for confidential_mode.preflight (W3 contract, docs/INTERFACES.md).

Written blind, then adapted to W3's public signatures and INTERFACES.md Amendments 1 and 2:
    run_preflight(tier, predicate, config, *, plugin_aux_tasks, isolation, provider_lookup,
                  attested_profile, builtin_aux_tasks=None) -> PreflightReport
    config_fingerprint(config, *, plugin_aux_tasks=(), builtin_aux_tasks=None) -> str
The harness derives `isolation` with the public helper `preflight.plugin_isolation(config)`, the
way the lock command does.

Every negative test first proves the in-tier baseline passes (otherwise "not ok" would be
vacuous) and then requires a bad item (off_tier/missing) whose key names the mutated YAML path.
"""
from __future__ import annotations

import copy
import os
import re

import pytest

from confidential_mode import preflight  # ImportError until W3 merges is expected
from confidential_mode.preflight import (config_fingerprint, format_report, load_core_config,
                                         plugin_aux_task_names, run_preflight)
from confidential_mode.tiers import AttestedPredicate, OnHostPredicate, Tier, Verdict, ZdrPredicate

ON_HOST_URL = "http://127.0.0.1:11434/v1"
HOSTED_URL = "https://api.evil.example/v1"
ATTESTED = "attested-tinfoil"
GOOD = {"in_tier", "on_host", "disabled"}
BAD = {"off_tier", "missing"}
ALL_VERDICTS = GOOD | BAD


def builtin_tasks() -> list[str]:
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    return [k for k, v in DEFAULT_CONFIG["auxiliary"].items() if isinstance(v, dict)]


def on_host_route(**over):
    return {"provider": "custom", "model": "llama3", "base_url": ON_HOST_URL, "api_key": "", **over}


def baseline() -> dict:
    return {
        "model": on_host_route(),
        "fallback_providers": [],
        "auxiliary": {"transient_retries": 2, **{t: on_host_route() for t in builtin_tasks()}},
        "memory": {"provider": "", "memory_enabled": True, "memory_char_limit": 2200},
        "mcp_servers": {"fs": {"command": "npx", "args": ["-y", "@mcp/fs", "/tmp"]}},
        "plugins": {"isolation": "in_process"},
        "display": {"compact": False},
        "agent": {"max_turns": 90},
    }


# --------------------------------------------------------------------------- report probing

def _get(obj, *names, default=None):
    for n in names:
        if isinstance(obj, dict) and n in obj:
            return obj[n]
        if hasattr(obj, n):
            return getattr(obj, n)
    return default


def _items(report) -> list:
    its = _get(report, "items", "checks", "entries", "rows")
    if its is None and isinstance(report, (list, tuple)):
        its = report
    if callable(its):
        its = its()
    if its is None:
        pytest.fail(f"cannot find items on PreflightReport {type(report)} (ADJUDICATE: name it)")
    return list(its.values()) if isinstance(its, dict) else list(its)


def _key(item) -> str:
    return str(_get(item, "key", "path", "name", default=""))


def _fix(item) -> str:
    return str(_get(item, "fix", "remedy", "hint", default="") or "")


def _verdict(item) -> str:
    v = _get(item, "verdict", "status", "result")
    v = getattr(v, "value", v)
    return str(v).strip().lower().replace("-", "_").replace(" ", "_")


def _ok(report):
    o = _get(report, "ok", "passed", "is_ok", "lockable")
    return o() if callable(o) else o


def _bad(report):
    return [i for i in _items(report) if _verdict(i) in BAD]


def _desc(report):
    return "\n".join(f"  {_key(i)!r}: {_verdict(i)}  fix={_fix(i)!r}" for i in _items(report))


# --------------------------------------------------------------------------- invocation

class FakeProfile:
    def __init__(self, name, base_url):
        self.name, self.base_url = name, base_url


def _profile_url(profiles):
    def f(name):
        prof = (profiles or {}).get(name)
        return getattr(prof, "base_url", "") if prof is not None else ""
    return f


class _AttestOk:
    def __call__(self, provider):
        return Verdict(True, "fresh+pinned (fake)", "inference.tinfoil.sh")


def predicate_for(tier, profiles):
    if tier == Tier.ON_HOST:
        return OnHostPredicate(extra_hosts=(), profile_base_url=_profile_url(profiles))
    if tier == Tier.ATTESTED:
        return AttestedPredicate(attested_profiles={ATTESTED}, attested_ok=_AttestOk(),
                                 profile_base_url=_profile_url(profiles))
    return ZdrPredicate()


def run(tier, cfg, monkeypatch=None, *, plugin_tasks=(), profiles=None):
    tasks = list(plugin_tasks)
    lookup = (lambda name, *a, **k: (profiles or {}).get(name))
    kwargs = dict(plugin_aux_tasks=tasks, isolation=preflight.plugin_isolation(cfg),
                  provider_lookup=lookup, attested_profile=ATTESTED if tier == Tier.ATTESTED else None)
    snapshot = copy.deepcopy(cfg)
    report = run_preflight(tier, predicate_for(tier, profiles), cfg, **kwargs)
    assert cfg == snapshot, "run_preflight mutated its input (load_config_readonly cache corruption)"
    for i in _items(report):
        assert _verdict(i) in ALL_VERDICTS, f"verdict outside contract set: {_key(i)} {_verdict(i)}"
    ok = _ok(report)
    if ok is not None and _bad(report):
        assert ok is False, f"report claims ok with bad items:\n{_desc(report)}"
    return report


def assert_ok(report):
    assert not _bad(report), f"expected clean report:\n{_desc(report)}"
    ok = _ok(report)
    assert ok in (True, None), f"report not ok but has no bad items:\n{_desc(report)}"


def assert_flagged(report, *fragments):
    """Not ok, and some bad item's key (or fix) mentions every fragment."""
    ok = _ok(report)
    assert ok in (False, None), "report claims ok"
    bad = _bad(report)
    assert bad, f"expected a bad item for {fragments}:\n{_desc(report)}"
    frs = [f.lower() for f in fragments]
    hit = [i for i in bad if all(f in (_key(i) + " " + _fix(i)).lower() for f in frs)]
    assert hit, f"no bad item mentions {fragments}:\n{_desc(report)}"
    for i in hit:
        assert _fix(i).strip(), f"bad item {_key(i)} has no fix"
    return hit


@pytest.fixture
def base(monkeypatch):
    cfg = baseline()
    assert_ok(run(Tier.ON_HOST, cfg, monkeypatch))
    return cfg


# --------------------------------------------------------------------------- baseline / coverage

def test_baseline_enumerates_every_builtin_aux_task(monkeypatch, base):
    keys = " ".join(_key(i) for i in _items(run(Tier.ON_HOST, base, monkeypatch)))
    missing = [t for t in builtin_tasks() if f"auxiliary.{t}" not in keys]
    assert not missing, f"built-in aux tasks never checked: {missing}"


def test_each_builtin_task_hosted_is_flagged(monkeypatch, base):
    for t in builtin_tasks():
        cfg = copy.deepcopy(base)
        cfg["auxiliary"][t] = on_host_route(provider="openrouter", base_url="")
        assert_flagged(run(Tier.ON_HOST, cfg, monkeypatch), f"auxiliary.{t}")


def test_aux_base_url_overrides_auto(monkeypatch, base):
    # Hermes: "base_url overrides provider". provider auto + hosted base_url must NOT inherit main.
    base["auxiliary"]["compression"] = {"provider": "auto", "model": "", "base_url": HOSTED_URL}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "auxiliary.compression")


# --------------------------------------------------------------------------- fallback chains

def test_one_hosted_entry_deep_in_aux_fallback_chain(monkeypatch, base):
    base["auxiliary"]["curator"]["fallback_chain"] = [
        on_host_route(), on_host_route(model="b"),
        {"provider": "openrouter", "model": "google/gemini-3-flash-preview"},
    ]
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "auxiliary.curator", "fallback_chain")


@pytest.mark.parametrize("entry", [
    {"base_url": HOSTED_URL},                       # no provider at all
    {"provider": "custom", "base_url": HOSTED_URL},
    {"provider": "auto", "base_url": HOSTED_URL},
    {"provider": "my-named-provider"},              # unknown named provider, no URL
    {"provider": "moa", "model": "default"},
    {"provider": "MoA", "model": "default"},
    "openrouter:google/gemini-3-flash-preview",     # string entry
    None,
    42,
])
def test_aux_fallback_chain_bad_entries(monkeypatch, base, entry):
    base["auxiliary"]["compression"]["fallback_chain"] = [on_host_route(), entry]
    report = run(Tier.ON_HOST, base, monkeypatch)
    format_report(report)
    assert_flagged(report, "auxiliary.compression")


def test_aux_fallback_chain_not_a_list(monkeypatch, base):
    # Hermes ignores a non-list fallback_chain (agent/auxiliary_client.py:4301-4303, 3830-3831), so
    # no verdict is required; it must not crash and must not hide the task's own item.
    for junk in ({"provider": "openrouter", "model": "x"}, "openrouter"):
        cfg = copy.deepcopy(base)
        cfg["auxiliary"]["approval"]["fallback_chain"] = junk
        r = run(Tier.ON_HOST, cfg, monkeypatch)
        format_report(r)
        assert any(_key(i).startswith("auxiliary.approval") for i in _items(r))


def test_fallback_providers_string_is_ignored_by_hermes(monkeypatch, base):
    # hermes_cli/fallback_config._iter_fallback_entries drops a non-list, non-dict value.
    base["fallback_providers"] = "openrouter"
    format_report(run(Tier.ON_HOST, base, monkeypatch))


@pytest.mark.parametrize("fp", [
    [{}],
    [{"model": "gpt-x"}],
    [{"provider": "openrouter"}],
    [on_host_route()],                     # in-tier entry still violates "must be empty"
    [None],
    {"provider": "openrouter", "model": "x"},   # dict: Hermes reads it as one entry
])
def test_fallback_providers_must_be_empty(monkeypatch, base, fp):
    base["fallback_providers"] = fp
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "fallback")


def test_legacy_fallback_model_key_is_checked(monkeypatch, base):
    # hermes_cli/fallback_config.get_fallback_chain merges legacy `fallback_model` after
    # fallback_providers. A preflight that reads only fallback_providers misses it.
    base["fallback_model"] = {"provider": "openrouter", "model": "anthropic/claude-x"}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "fallback")


# --------------------------------------------------------------------------- plugin aux tasks

def test_plugin_task_hosted_is_flagged(monkeypatch, base):
    base["auxiliary"]["zz_plugin_summarizer"] = {"provider": "openrouter", "model": "x"}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch, plugin_tasks=["zz_plugin_summarizer"]),
                   "zz_plugin_summarizer")


def test_plugin_task_without_config_block_is_still_enumerated(monkeypatch, base):
    # The plugin's registered defaults may be hosted; the user config may have no block at all.
    report = run(Tier.ON_HOST, base, monkeypatch, plugin_tasks=["zz_plugin_noblock"])
    assert any("zz_plugin_noblock" in _key(i) for i in _items(report)), _desc(report)


def test_plugin_task_hosted_defaults_are_flagged(monkeypatch, base):
    entry = {"key": "zz_plugin_dflt", "defaults": {"provider": "openrouter", "model": "x"},
             "inherit_from": None}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch, plugin_tasks=[entry]), "zz_plugin_dflt")


def test_plugin_task_inheriting_hosted_base_is_flagged(monkeypatch, base):
    base["auxiliary"]["compression"] = {"provider": "openrouter", "model": "x", "base_url": ""}
    entry = {"key": "zz_plugin_inh", "defaults": {}, "inherit_from": "compression"}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch, plugin_tasks=[entry]), "zz_plugin_inh")


def test_plugin_task_user_pin_overrides_hosted_defaults(monkeypatch, base):
    # Control: Hermes layers user config over plugin defaults; an on-host user pin wins.
    entry = {"key": "zz_plugin_pin", "defaults": {"provider": "openrouter", "model": "x"}}
    base["auxiliary"]["zz_plugin_pin"] = on_host_route()
    assert_ok(run(Tier.ON_HOST, base, monkeypatch, plugin_tasks=[entry]))


def test_real_plugin_aux_task_names_shape():
    # Unpatched: with an empty HERMES_HOME there are no user plugins; must not raise, must return
    # strings, and must not duplicate built-ins.
    names = list(preflight.plugin_aux_task_names())
    assert all(isinstance(n, str) for n in names)
    assert not set(names) & set(builtin_tasks()), "plugin list must not duplicate built-ins"


# --------------------------------------------------------------------------- vision

@pytest.mark.parametrize("vision", [
    {"provider": "auto", "model": "", "base_url": ""},
    {"provider": "Auto"},
    {"provider": " auto "},
    {"provider": ""},
    {},
    None,
    "openrouter",
    ["custom"],
    {"provider": "none"},       # Amendment 1: no "disabled" convention for vision
    {"provider": "off"},
])
def test_vision_auto_or_implicit_is_flagged_even_with_on_host_main(monkeypatch, base, vision):
    if vision is None:
        del base["auxiliary"]["vision"]
    else:
        base["auxiliary"]["vision"] = vision
    hit = assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "auxiliary.vision")
    # Amendment 1 (A6): off_tier.
    assert {_verdict(i) for i in hit} == {"off_tier"}, _desc(run(Tier.ON_HOST, base, monkeypatch))


# --------------------------------------------------------------------------- memory

@pytest.mark.parametrize("prov", ["local-cloud-sync", "localsync", "honcho", "mem0", "supermemory",
                                  "hindsight", "retaindb", "byterover", "openviking", "Honcho"])
def test_hosted_memory_provider_is_flagged(monkeypatch, base, prov):
    base["memory"]["provider"] = prov
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "memory")


@pytest.mark.parametrize("mem", [None, "honcho", ["honcho"], {"provider": None}])
def test_memory_block_junk_does_not_crash(monkeypatch, base, mem):
    base["memory"] = mem
    report = run(Tier.ON_HOST, base, monkeypatch)
    format_report(report)
    # No verdict asserted: Hermes reads only memory.provider from a mapping, so a non-mapping
    # memory block selects the built-in store.


# --------------------------------------------------------------------------- mcp_servers

def test_mcp_url_and_command_is_flagged(monkeypatch, base):
    base["mcp_servers"]["both"] = {"url": "https://mcp.evil.example/sse", "command": "npx"}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "mcp_servers", "both")


def test_mcp_hosted_url_is_flagged(monkeypatch, base):
    base["mcp_servers"]["remote"] = {"url": "https://mcp.evil.example/mcp",
                                     "headers": {"Authorization": "Bearer x"}}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "mcp_servers", "remote")


def test_mcp_localhost_url_is_on_host(monkeypatch, base):
    # Amendment 1 (A5): URL servers classify by host_of(url) with the active predicate.
    base["mcp_servers"]["localhttp"] = {"url": "http://localhost:8000/mcp"}
    assert_ok(run(Tier.ON_HOST, base, monkeypatch))
    # Amendment 10: a private-range URL server is off-tier unless its exact host is listed.
    base["mcp_servers"]["lanhttp"] = {"url": "http://192.168.1.20:8000/mcp", "command": "x"}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "mcp_servers", "lanhttp")


@pytest.mark.parametrize("url", ["http://localhost.evil.example/mcp", "http://evil.com\\@127.0.0.1/mcp",
                                 "http://10.0.0.1@evil.example/mcp", "localhost:8000/mcp"])
def test_mcp_lookalike_url_is_flagged(monkeypatch, base, url):
    base["mcp_servers"]["sneaky"] = {"url": url}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "mcp_servers", "sneaky")


def test_mcp_disabled_url_server_is_disabled(monkeypatch, base):
    base["mcp_servers"]["off"] = {"url": "https://mcp.evil.example/mcp", "enabled": False}
    r = run(Tier.ON_HOST, base, monkeypatch)
    assert_ok(r)
    assert any("mcp_servers.off" in _key(i) and _verdict(i) == "disabled" for i in _items(r))


def test_stdio_only_mcp_is_not_flagged(monkeypatch, base):
    keys = [_key(i) for i in _bad(run(Tier.ON_HOST, base, monkeypatch))]
    assert not any("mcp_servers.fs" in k for k in keys)


@pytest.mark.parametrize("mcp", [["https://mcp.evil.example"], "https://mcp.evil.example",
                                 {"x": "https://mcp.evil.example"}, {"x": None}, None])
def test_mcp_servers_junk_does_not_crash(monkeypatch, base, mcp):
    base["mcp_servers"] = mcp
    report = run(Tier.ON_HOST, base, monkeypatch)
    format_report(report)
    # Hermes ignores a non-mapping mcp_servers (tools/mcp_tool_config.py:719-727); only a
    # malformed server entry inside a mapping must be flagged.
    if mcp == {"x": "https://mcp.evil.example"}:
        assert _bad(report), f"mcp_servers={mcp!r} containing a URL passed silently"


# --------------------------------------------------------------------------- plugins.isolation

@pytest.mark.parametrize("iso", ["host", "garbage", "", "IN-PROCESS", 1, ["in_process"]])
def test_isolation_not_in_process_is_flagged(monkeypatch, base, iso):
    base["plugins"]["isolation"] = iso
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "isolation")


def test_isolation_absent_passes(monkeypatch, base):
    # Amendment 1 (A7): absent resolves to Hermes' default in_process (config_defaults.py:1719).
    del base["plugins"]["isolation"]
    r1 = run(Tier.ON_HOST, base, monkeypatch)
    del base["plugins"]
    r2 = run(Tier.ON_HOST, base, monkeypatch)
    for r in (r1, r2):
        iso = [i for i in _items(r) if "isolation" in _key(i)]
        assert iso, "plugins.isolation must always be reported"
        assert _verdict(iso[0]) in GOOD, _desc(r)
        assert_ok(r)
    base["plugins"] = "in_process"   # wrong shape: must not crash
    run(Tier.ON_HOST, base, monkeypatch)


def test_isolation_explicit_empty_is_missing(monkeypatch, base):
    base["plugins"]["isolation"] = ""
    hit = assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "isolation")
    assert {_verdict(i) for i in hit} == {"missing"}


# --------------------------------------------------------------------------- moa / codex / main

@pytest.mark.parametrize("prov", ["moa", "MoA", "MOA", " moa"])
def test_main_moa_is_flagged(monkeypatch, base, prov):
    base["model"]["provider"] = prov
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "model")


@pytest.mark.parametrize("prov", ["openai-codex", "OpenAI-Codex"])
def test_main_openai_codex_is_flagged(monkeypatch, base, prov):
    base["model"] = {"provider": prov, "model": "gpt-5.5", "base_url": ON_HOST_URL}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "model")


def test_main_hosted_is_flagged(monkeypatch, base):
    base["model"]["base_url"] = HOSTED_URL
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "model")


@pytest.mark.parametrize("model", ["llama3", "", None, ["custom"], {}])
def test_model_not_a_dict(monkeypatch, base, model):
    # Hermes accepts `model: <string>` (DEFAULT_CONFIG["model"] == ""). Then no in-tier main
    # provider is provable -> must not pass the on-host tier.
    base["model"] = model
    report = run(Tier.ON_HOST, base, monkeypatch)
    format_report(report)
    assert_flagged(report, "model")


def test_empty_config_is_not_ok(monkeypatch):
    for cfg in ({}, {"auxiliary": None}, {"auxiliary": "x", "model": "y"},
                {"auxiliary": [], "plugins": [], "mcp_servers": [], "memory": []}):
        report = run(Tier.ON_HOST, cfg, monkeypatch)
        format_report(report)
        assert _bad(report), f"config {cfg!r} passed preflight"


def test_moa_tasks_and_presets_cannot_smuggle_hosted(monkeypatch, base):
    base["auxiliary"]["moa_reference"] = {"provider": "openrouter", "model": "x"}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "auxiliary.moa_reference")


# --------------------------------------------------------------------------- attested tier

def attested_cfg():
    cfg = baseline()
    cfg["model"] = {"provider": ATTESTED, "model": "llama3-3-70b", "base_url": ""}
    for t in builtin_tasks():
        cfg["auxiliary"][t] = {"provider": ATTESTED, "model": "llama3-3-70b", "base_url": ""}
    return cfg


def test_attested_profile_lookup_none_is_flagged(monkeypatch):
    report = run(Tier.ATTESTED, attested_cfg(), monkeypatch, profiles={})
    ok = _ok(report)
    assert ok in (False, None)
    hit = [i for i in _bad(report)
           if ATTESTED in (_key(i) + _fix(i)).lower() or "profile" in (_key(i) + _fix(i)).lower()
           or "isolation" in (_key(i) + _fix(i)).lower()]
    assert hit, f"missing attested profile not reported as its own item:\n{_desc(report)}"


def test_attested_profile_registered_vs_not_differs(monkeypatch):
    # Non-vacuity: the profile item must flip on the lookup alone.
    prof = {ATTESTED: FakeProfile(ATTESTED, "https://inference.tinfoil.sh/v1")}
    good = {_key(i) for i in _bad(run(Tier.ATTESTED, attested_cfg(), monkeypatch, profiles=prof))}
    bad = {_key(i) for i in _bad(run(Tier.ATTESTED, attested_cfg(), monkeypatch, profiles={}))}
    assert bad - good, "provider_lookup returning None changed nothing in the report"


def test_attested_tier_rejects_on_host_main(monkeypatch):
    cfg = baseline()  # on-host main is NOT attested
    prof = {ATTESTED: FakeProfile(ATTESTED, "https://inference.tinfoil.sh/v1")}
    assert_flagged(run(Tier.ATTESTED, cfg, monkeypatch, profiles=prof), "model")


@pytest.mark.parametrize("deleg", [
    {"backend": "default", "provider": "openrouter", "model": "x", "base_url": ""},
    {"backend": "default", "provider": "", "model": "", "base_url": HOSTED_URL},
    {"provider": "custom", "base_url": "http://localhost.evil.example/v1"},
    {"provider": "moa"},
])
def test_delegation_route_is_checked(monkeypatch, base, deleg):
    # Amendment 1 (A11): delegation.* is enumerated.
    base["delegation"] = deleg
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "delegation")


def test_delegation_unset_inherits_main(monkeypatch, base):
    base["delegation"] = {"backend": "default", "provider": "", "model": "", "base_url": ""}
    assert_ok(run(Tier.ON_HOST, base, monkeypatch))


@pytest.mark.parametrize("prov", ["edge", "elevenlabs", "openai", "xai", "minimax", "mistral",
                                  "gemini", "deepinfra", "ElevenLabs"])
def test_hosted_tts_provider_is_flagged(monkeypatch, base, prov):
    # Amendment 1 (A11): tts.provider is enumerated; assistant text is conversation content.
    # Hosted engines per hermes_cli/config_defaults.py tts comment.
    base["tts"] = {"provider": prov, "enabled": True}
    assert_flagged(run(Tier.ON_HOST, base, monkeypatch), "tts")


@pytest.mark.parametrize("tts", [None, {}, {"provider": ""}, {"provider": "none"},
                                 {"provider": "piper"}, {"provider": "kittentts"}, {"provider": "neutts"}])
def test_on_host_or_unset_tts_passes(monkeypatch, base, tts):
    if tts is not None:
        base["tts"] = tts
    assert_ok(run(Tier.ON_HOST, base, monkeypatch))


# --------------------------------------------------------------------------- redaction

SECRETS = ["sk-live-MAINSECRET", "sk-AUXSECRET", "QSECRET", "HDRSECRET", "ENVSECRET", "PWSECRET",
           "FBSECRET"]


def secret_cfg():
    cfg = baseline()
    cfg["model"]["base_url"] = "http://user:sk-live-MAINSECRET@127.0.0.1:11434/v1"
    cfg["model"]["api_key"] = "sk-live-MAINSECRET"
    cfg["auxiliary"]["compression"]["api_key"] = "sk-AUXSECRET"
    cfg["auxiliary"]["vision"]["base_url"] = "https://evil.example/v1?api_key=QSECRET"
    cfg["auxiliary"]["curator"]["base_url"] = "https://admin:PWSECRET@evil.example/v1"
    cfg["auxiliary"]["approval"]["fallback_chain"] = [
        {"provider": "custom", "base_url": "https://k:FBSECRET@evil.example/v1", "api_key": "FBSECRET"}]
    cfg["mcp_servers"]["remote"] = {"url": "https://mcp.evil.example/mcp",
                                    "headers": {"Authorization": "Bearer HDRSECRET"},
                                    "env": {"API_KEY": "ENVSECRET"}}
    cfg["fallback_providers"] = [{"provider": "openrouter", "model": "x", "api_key": "sk-AUXSECRET"}]
    return cfg


def test_format_report_redacts_secrets(monkeypatch):
    report = run(Tier.ON_HOST, secret_cfg(), monkeypatch)
    text = format_report(report)
    assert isinstance(text, str) and text.strip()
    leaked = [s for s in SECRETS if s in text]
    assert not leaked, f"format_report leaked {leaked}:\n{text}"
    # Also the report object itself (it may be ledgered as preflight_fail detail).
    blob = repr(report) + "".join(str(_get(i, "value_redacted", "value", default="")) + _fix(i) for i in _items(report))
    leaked = [s for s in SECRETS if s in blob]
    assert not leaked, f"report object carries plaintext secrets {leaked}"


def test_format_report_shows_every_bad_item(monkeypatch):
    report = run(Tier.ON_HOST, secret_cfg(), monkeypatch)
    text = format_report(report)
    low = text.lower().replace("-", "_")
    for i in _bad(report):
        assert _key(i) in text, f"bad item {_key(i)} missing from formatted table"
    assert any(b in low for b in BAD), "formatted report shows no off_tier/missing verdict"


def test_format_report_never_says_ok_when_bad(monkeypatch, base):
    cfg = copy.deepcopy(base)
    cfg["auxiliary"]["curator"]["fallback_chain"] = [{"provider": "openrouter", "model": "x"}]
    text = format_report(run(Tier.ON_HOST, cfg, monkeypatch))
    assert not re.search(r"\b(all (checks )?pass(ed)?|ready to lock|ok to lock)\b", text, re.I), text
    assert not re.search(r"\bPASS\b", text), text


# --------------------------------------------------------------------------- fingerprint

def fp(cfg, monkeypatch=None, plugin_tasks=()):
    snapshot = copy.deepcopy(cfg)
    out = config_fingerprint(cfg, plugin_aux_tasks=list(plugin_tasks))
    assert cfg == snapshot, "config_fingerprint mutated its input"
    assert isinstance(out, str) and re.fullmatch(r"[0-9a-f]{64}", out), f"not sha256 hex: {out!r}"
    return out


def _set(cfg, path, value):
    parts = path.split(".")
    node = cfg
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = value


ENUMERATED_MUTATIONS = [
    ("model.provider", "openrouter"),
    ("model.base_url", HOSTED_URL),
    ("model.api_mode", "codex_responses"),
    ("delegation.provider", "openrouter"),
    ("delegation.base_url", HOSTED_URL),
    ("tts.provider", "elevenlabs"),
    ("fallback_providers", [{"provider": "openrouter", "model": "x"}]),
    ("fallback_model", {"provider": "openrouter", "model": "x"}),
    ("auxiliary.compression.provider", "openrouter"),
    ("auxiliary.compression.base_url", HOSTED_URL),
    ("auxiliary.curator.fallback_chain", [{"provider": "openrouter", "model": "x"}]),
    ("auxiliary.vision.provider", "auto"),
    ("auxiliary.moa_aggregator.base_url", HOSTED_URL),
    ("memory.provider", "honcho"),
    ("mcp_servers.remote", {"url": "https://mcp.evil.example/mcp"}),
    ("mcp_servers.fs.url", "https://mcp.evil.example/mcp"),
    ("plugins.isolation", "host"),
]


@pytest.mark.parametrize("path,value", ENUMERATED_MUTATIONS)
def test_fingerprint_changes_on_enumerated_key(monkeypatch, path, value):
    cfg = baseline()
    before = fp(cfg, monkeypatch)
    _set(cfg, path, value)
    assert fp(cfg, monkeypatch) != before, f"fingerprint blind to {path}"


def test_fingerprint_changes_deep_in_fallback_chain(monkeypatch):
    cfg = baseline()
    cfg["auxiliary"]["curator"]["fallback_chain"] = [on_host_route(), on_host_route(), on_host_route()]
    before = fp(cfg, monkeypatch)
    cfg["auxiliary"]["curator"]["fallback_chain"][2]["base_url"] = HOSTED_URL
    assert fp(cfg, monkeypatch) != before


def test_fingerprint_covers_plugin_task(monkeypatch):
    cfg = baseline()
    cfg["auxiliary"]["zz_plugin"] = on_host_route()
    before = fp(cfg, monkeypatch, plugin_tasks=["zz_plugin"])
    cfg["auxiliary"]["zz_plugin"]["base_url"] = HOSTED_URL
    assert fp(cfg, monkeypatch, plugin_tasks=["zz_plugin"]) != before


NON_ENUMERATED_MUTATIONS = [
    ("display.compact", True),
    ("agent.max_turns", 5),
    ("auxiliary.compression.timeout", 999),
    ("auxiliary.compression.reasoning_effort", "high"),
    ("auxiliary.transient_retries", 6),
    ("memory.memory_char_limit", 10),
    ("memory.nudge_interval", 0),
    ("mcp_servers.fs.args", ["-y", "@mcp/fs", "/home"]),
    ("brand_new_section", {"x": 1}),
]


@pytest.mark.parametrize("path,value", NON_ENUMERATED_MUTATIONS)
def test_fingerprint_stable_on_non_enumerated_key(monkeypatch, path, value):
    cfg = baseline()
    before = fp(cfg, monkeypatch)
    _set(cfg, path, value)
    assert fp(cfg, monkeypatch) == before, f"fingerprint changed on unrelated {path}: per-turn " \
                                            "recheck would breach the lock on cosmetic edits"


def test_fingerprint_independent_of_dict_order(monkeypatch):
    cfg = baseline()
    cfg["auxiliary"]["curator"]["fallback_chain"] = [{"provider": "custom", "model": "a",
                                                      "base_url": ON_HOST_URL}]
    cfg["mcp_servers"]["h"] = {"url": "http://localhost:1/mcp", "headers": {"a": "1", "b": "2"}}
    cfg["mcp_servers"]["g"] = {"url": "http://localhost:2/mcp"}
    rev = {k: cfg[k] for k in reversed(list(cfg))}
    rev["auxiliary"] = {k: dict(reversed(list(v.items()))) if isinstance(v, dict) else v
                        for k, v in reversed(list(cfg["auxiliary"].items()))}
    rev["auxiliary"]["curator"]["fallback_chain"] = [{"base_url": ON_HOST_URL, "model": "a",
                                                      "provider": "custom"}]
    rev["mcp_servers"] = {"g": {"url": "http://localhost:2/mcp"},
                          "h": {"headers": {"b": "2", "a": "1"}, "url": "http://localhost:1/mcp"},
                          "fs": cfg["mcp_servers"]["fs"]}
    assert fp(cfg, monkeypatch) == fp(rev, monkeypatch)


def test_fingerprint_is_deterministic_and_secret_free(monkeypatch):
    cfg = secret_cfg()
    a, b = fp(cfg, monkeypatch), fp(copy.deepcopy(cfg), monkeypatch)
    assert a == b
    for s in SECRETS:
        assert s not in a


@pytest.mark.parametrize("junk", [{}, {"model": "x"}, {"auxiliary": None}, {"mcp_servers": []},
                                  {"auxiliary": {"vision": "openrouter"}}])
def test_fingerprint_on_junk_does_not_crash(monkeypatch, junk):
    fp(junk, monkeypatch)


def test_fingerprint_distinguishes_absent_from_empty(monkeypatch):
    # fallback_providers: [] (disabled) vs a list holding one empty entry must differ.
    a = baseline()
    b = baseline()
    b["fallback_providers"] = [{}]
    assert fp(a, monkeypatch) != fp(b, monkeypatch)


# --------------------------------------------------------------------------- load_core_config

def test_load_core_config_is_read_only():
    home = os.environ.get("HERMES_HOME", "")
    cfg_path = os.path.join(home, "config.yaml") if home else ""
    existed = bool(cfg_path) and os.path.exists(cfg_path)
    before = open(cfg_path, "rb").read() if existed else None
    cfg = load_core_config()
    assert isinstance(cfg, dict)
    if cfg_path:
        assert os.path.exists(cfg_path) == existed, "load_core_config created config.yaml"
        if existed:
            assert open(cfg_path, "rb").read() == before


def test_default_hermes_config_does_not_pass_on_host_or_attested(monkeypatch):
    cfg = copy.deepcopy(load_core_config())
    for tier in (Tier.ON_HOST, Tier.ATTESTED, Tier.ZDR):
        report = run(tier, cfg, monkeypatch)
        assert _bad(report), f"stock Hermes defaults pass {tier}:\n{_desc(report)}"

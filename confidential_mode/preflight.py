"""Preflight: classify every route Hermes' core config can send conversation bytes over (W3).

``run_preflight`` is pure over a config dict. The ``load_core_config`` / ``plugin_aux_*`` /
``builtin_aux_task_names`` / ``profile_base_url`` / ``provider_lookup`` helpers are the only places
that import Hermes, lazily, so the core logic stays unit-testable.

Hermes facts this module relies on (pinned at 84a0301):
- Main route is ``model.provider`` + ``model.default`` (``model.model`` is an accepted alias;
  agent/auxiliary_client.py:2440-2461). An empty/"auto" main provider enables the built-in
  discovery chain for every auxiliary task (auxiliary_client.py:4529-4541).
- Fallbacks: ``fallback_providers`` and the legacy ``fallback_model`` key are both read
  (hermes_cli/fallback_config.py:126-143) and also consulted by auxiliary calls (:4378-4390).
- Aux "auto"/"" (and "main") resolve to the main provider; vision "auto" walks
  openrouter -> nous -> deepinfra when the main route cannot serve vision (auxiliary_client.py:5545-5566).
- A bare ``base_url`` on an aux task means a custom endpoint (auxiliary_client.py:5590-5597, 6061).
- Plugin aux tasks layer their ``defaults`` under the user's block and may ``inherit_from`` another
  task (agent/auxiliary_task_config.py:59-117).
- MCP servers with ``enabled: false`` are not started (tools/mcp_tool_common.py:144).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from .tiers import Destination, Tier, TierPredicate, Verdict, host_of

IN_TIER, LOCAL, DISABLED, OFF_TIER, MISSING = "in_tier", "local", "disabled", "off_tier", "missing"
VERDICTS = (IN_TIER, LOCAL, DISABLED, OFF_TIER, MISSING)
PASSING = frozenset({IN_TIER, LOCAL, DISABLED})

#: Built-in auxiliary tasks at Hermes 84a0301 (dict-valued keys of DEFAULT_CONFIG["auxiliary"],
#: hermes_cli/config_defaults.py:725-800). Used only if that import fails; the import wins.
BUILTIN_AUX_TASKS_SNAPSHOT = (
    "vision", "compression", "approval", "review", "mcp", "title_generation", "memory_query_rewrite",
    "tts_audio_tags", "voice_chat", "triage_specifier", "kanban_decomposer", "profile_describer",
    "goal_judge", "group_router", "curator", "monitor", "background_review", "moa_reference",
    "moa_aggregator",
)

_AUTO = frozenset({"", "auto"})
_MOA = "moa"
_CODEX = frozenset({"openai-codex", "codex"})
_LOCAL_TTS = frozenset({"neutts", "kittentts", "piper", "none"})
#: Hermes resolves an unset/empty tts.provider to "edge" (tools/tts_tool.py:105,145-148), a hosted service.
_TTS_DEFAULT = "edge"
_VISION_FIX = ("set {p}.provider (or {p}.base_url) explicitly to an in-tier vision route; Hermes describes "
               "gateway inbound images through vision even without a tool call, and 'auto' walks "
               "openrouter -> nous -> deepinfra when the main model cannot take images")
_ABSENT = object()
#: Amendment 4 F2: a positive plugins.hook_callback_timeout below this lets Hermes skip pre_llm_call.
HOOK_TIMEOUT_FLOOR_SECONDS = 5.0
#: plugins.* keys that govern whether and how plugin hooks run; all are fingerprinted.
_PLUGIN_EXECUTION_KEYS = ("isolation", "hook_callback_timeout", "load_timeout_seconds", "enabled", "disabled")
_LOCAL_MEMORY = frozenset({"", "builtin", "built-in", "local", "none"})
_AUX_ROUTE_KEYS = frozenset({"provider", "model", "base_url", "api_key", "api_mode", "key_env",
                             "api_key_env", "reasoning_effort"})
_SECRET_WORDS = ("api_key", "apikey", "token", "secret", "password", "authorization", "key_env")


@dataclass(frozen=True)
class PreflightItem:
    key: str              # exact YAML path, e.g. "auxiliary.vision.provider"
    value_redacted: str
    verdict: str          # one of VERDICTS
    fix: str = ""         # one line naming the YAML key to change; "" when passing


@dataclass(frozen=True)
class PreflightReport:
    tier: Tier
    items: tuple[PreflightItem, ...]
    fingerprint: str
    aux_tasks: tuple[str, ...] = field(default=())

    @property
    def ok(self) -> bool:
        return all(i.verdict in PASSING for i in self.items)

    def failures(self) -> list[PreflightItem]:
        return [i for i in self.items if i.verdict not in PASSING]


# ── redaction ────────────────────────────────────────────────────────────────────────────────────

def _is_secret_key(key: str) -> bool:
    last = key.rsplit(".", 1)[-1].lower()
    return any(w in last for w in _SECRET_WORDS)


def redact_url(url: str) -> str:
    """Drop userinfo, query and fragment (where tokens hide); keep scheme://host:port/path."""
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw if "://" in raw else "//" + raw)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        if "@" in parts.netloc:
            netloc = "***@" + netloc
        query = "***" if parts.query else ""
        out = urlunsplit((parts.scheme, netloc, parts.path, query, ""))
        return out if "://" in raw else out.lstrip("/")
    except ValueError:
        return "<unparsable url>"


def redact_value(key: str, value: Any) -> str:
    if _is_secret_key(key):
        return "***" if value not in (None, "", [], {}) else ""
    if value is None:
        return ""
    if isinstance(value, str):
        return redact_url(value) if ("url" in key.rsplit(".", 1)[-1].lower() or "://" in value) else value
    if isinstance(value, Mapping):
        parts = []
        for k in ("provider", "model", "base_url", "url", "command"):
            if value.get(k):
                parts.append(f"{k}={redact_value(k, value.get(k))}")
        return ", ".join(parts) or "{...}"
    if isinstance(value, (list, tuple)):
        return "[]" if not value else f"[{len(value)} entries]"
    return str(value)


# ── config access ────────────────────────────────────────────────────────────────────────────────

def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _main_block(config: Mapping) -> dict:
    model = config.get("model")
    if isinstance(model, Mapping):
        return dict(model)
    if isinstance(model, str):
        return {"default": model}
    return {}


def _main_model(block: Mapping) -> str:
    return _s(block.get("default")) or _s(block.get("model"))


def _aux_section(config: Mapping) -> Mapping:
    aux = config.get("auxiliary")
    return aux if isinstance(aux, Mapping) else {}


def _layer_over_inherited(inherited: Mapping, user: Mapping) -> dict:
    """Mirror of agent/auxiliary_task_config.py:_layer_over_inherited (pure copy, same rules)."""
    provider = _s(user.get("provider")).lower()
    pinned = provider not in _AUTO or bool(_s(user.get("model"))) or bool(_s(user.get("base_url")))
    merged = {k: v for k, v in inherited.items() if not (pinned and k in _AUX_ROUTE_KEYS)}
    for key, value in user.items():
        if value == "" and not (pinned and key in _AUX_ROUTE_KEYS):
            continue
        if key == "provider" and not pinned:
            continue
        merged[key] = value
    return merged


def _normalize_plugin_tasks(plugin_aux_tasks: Iterable[Any]) -> dict[str, dict]:
    """Accept bare names or the registration dicts from get_plugin_auxiliary_tasks()."""
    out: dict[str, dict] = {}
    for entry in plugin_aux_tasks or ():
        if isinstance(entry, str) and entry:
            out.setdefault(entry, {"key": entry, "defaults": {}, "inherit_from": None})
        elif isinstance(entry, Mapping) and isinstance(entry.get("key"), str) and entry["key"]:
            defaults = entry.get("defaults")
            out[entry["key"]] = {"key": entry["key"],
                                 "defaults": dict(defaults) if isinstance(defaults, Mapping) else {},
                                 "inherit_from": entry.get("inherit_from") or None}
    return out


def _effective_aux(config: Mapping, task: str, plugins: Mapping[str, dict], _seen: frozenset = frozenset()) -> dict:
    user = _aux_section(config).get(task)
    user = dict(user) if isinstance(user, Mapping) else {}
    entry = plugins.get(task)
    if entry is None:
        return user
    defaults = entry.get("defaults") or {}
    base_name = entry.get("inherit_from")
    if not base_name or task in _seen:
        return {**defaults, **user}
    base = _effective_aux(config, base_name, plugins, _seen | {task})
    return _layer_over_inherited({**base, **defaults}, user)


# ── classification ───────────────────────────────────────────────────────────────────────────────

class _Ctx:
    def __init__(self, tier: Tier, predicate: TierPredicate):
        self.tier = tier
        self.predicate = predicate
        self.pass_verdict = LOCAL if tier == Tier.LOCAL else IN_TIER

    def classify(self, provider: str, base_url: str, model: str, api_mode: str, purpose: str) -> tuple[str, str]:
        """(verdict, reason) for one concrete route."""
        try:
            v = self.predicate.classify(Destination(provider=provider, base_url=base_url, model=model,
                                                    api_mode=api_mode, purpose=purpose))
        except Exception:
            return OFF_TIER, "tier check failed"
        if not isinstance(v, Verdict):
            return OFF_TIER, "tier check returned no verdict"
        return (self.pass_verdict if v.in_tier else OFF_TIER), v.reason


def _main_route(ctx: _Ctx, config: Mapping) -> tuple[str, str, str]:
    """(verdict, reason, provider) for the main route."""
    block = _main_block(config)
    provider = _s(block.get("provider")).lower()
    if provider in _AUTO:
        return OFF_TIER, "main provider unset/auto: Hermes auto-detects and aux tasks may walk the discovery chain", provider
    if provider == _MOA:
        return OFF_TIER, "MoA runs advisor calls before the middleware", provider
    if provider in _CODEX:
        return OFF_TIER, "openai-codex app-server runtime bypasses the middleware", provider
    verdict, reason = ctx.classify(provider, _s(block.get("base_url")), _main_model(block),
                                   _s(block.get("api_mode")), "main")
    return verdict, reason, provider


def _route_item_verdict(ctx: _Ctx, cfg: Mapping, purpose: str) -> tuple[str, str]:
    provider = _s(cfg.get("provider")).lower()
    base_url = _s(cfg.get("base_url"))
    if provider == _MOA:
        return OFF_TIER, "moa provider runs outside the middleware"
    if provider in _AUTO:
        provider = "custom"
    return ctx.classify(provider, base_url, _s(cfg.get("model")), _s(cfg.get("api_mode")), purpose)


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"true", "1", "yes", "on"}) \
        or (isinstance(value, int) and not isinstance(value, bool) and value != 0)


def _falsy(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() in {"false", "0", "no", "off"}) \
        or (isinstance(value, int) and not isinstance(value, bool) and value == 0)


def run_preflight(tier: Tier, predicate: TierPredicate, config: Mapping, *, plugin_aux_tasks: Sequence[Any],
                  isolation: Any = _ABSENT, provider_lookup: Callable[[str], object | None],
                  attested_profile: str | None, builtin_aux_tasks: Sequence[str] | None = None) -> PreflightReport:
    """Classify every route in ``config`` for ``tier``. Never mutates ``config``.

    ``plugin_aux_tasks``: plugin task names, or the registration dicts from
    ``get_plugin_auxiliary_tasks()`` (then their ``defaults``/``inherit_from`` are honoured).
    ``isolation``: the ``plugins.isolation`` value; omitted => read from ``config``. ``None`` means the
    key is absent (Hermes default in_process, passing); ``""`` or anything but "in_process" fails.
    ``builtin_aux_tasks`` defaults to :func:`builtin_aux_task_names`.
    """
    config = config if isinstance(config, Mapping) else {}
    ctx = _Ctx(tier, predicate)
    items: list[PreflightItem] = []

    def add(key: str, value: Any, verdict: str, fix: str = "") -> None:
        items.append(PreflightItem(key, redact_value(key, value), verdict, "" if verdict in PASSING else fix))

    # main
    block = _main_block(config)
    main_verdict, main_reason, main_provider = _main_route(ctx, config)
    if main_provider in _CODEX:
        main_fix = "set model.provider to an in-tier provider; openai-codex runs turns in an app-server subprocess the middleware never sees"
    elif main_provider == _MOA:
        main_fix = "set model.provider to an in-tier provider; moa is not allowed while sealed"
    elif main_provider in _AUTO:
        main_fix = "set model.provider explicitly to an in-tier provider"
    else:
        main_fix = f"set model.provider/model.base_url to an in-tier route ({main_reason})"
    add("model.provider", block.get("provider", ""), main_verdict, main_fix)
    add("model.default", _main_model(block), main_verdict, main_fix)
    if _s(block.get("base_url")):
        add("model.base_url", block.get("base_url"), main_verdict, main_fix)

    # fallbacks: must be empty (both keys feed get_fallback_chain)
    fb = config.get("fallback_providers")
    fb_list = fb if isinstance(fb, list) else ([] if fb in (None, "", {}) else [fb])
    if not fb_list:
        add("fallback_providers", [], DISABLED)
    for i, entry in enumerate(fb_list):
        add(f"fallback_providers[{i}]", entry, OFF_TIER, "remove fallback_providers entries while sealed")
    legacy = config.get("fallback_model")
    if legacy:
        add("fallback_model", legacy, OFF_TIER, "remove the legacy fallback_model key while sealed")

    # auxiliary tasks
    builtins = list(builtin_aux_tasks) if builtin_aux_tasks is not None else builtin_aux_task_names()
    plugins = _normalize_plugin_tasks(plugin_aux_tasks)
    tasks = list(dict.fromkeys([*builtins, *plugins]))
    for task in tasks:
        cfg = _effective_aux(config, task, plugins)
        prefix = f"auxiliary.{task}"
        provider = _s(cfg.get("provider")).lower()
        base_url = _s(cfg.get("base_url"))
        purpose = f"aux:{task}"
        raw_block = _aux_section(config).get(task, _ABSENT)
        if raw_block is not _ABSENT and raw_block is not None and not isinstance(raw_block, Mapping):
            # Hermes ignores a non-dict block (treats it as auto); never let junk pass silently.
            add(f"{prefix}", raw_block, OFF_TIER, f"{prefix} must be a mapping with provider/model/base_url")
        if task == "vision" and provider in _AUTO and not base_url:
            add(f"{prefix}.provider", cfg.get("provider") or "auto", OFF_TIER, _VISION_FIX.format(p=prefix))
        elif (provider in _AUTO or provider == "main") and not base_url:
            # "auto"/"" resolve to the main route (text tasks); "main" is the main route for every task.
            shown = f"{cfg.get('provider') or 'auto'} -> {main_provider or 'auto'}"
            add(f"{prefix}.provider", shown, main_verdict,
                f"inherits the main route: fix model.provider, or pin {prefix}.provider to an in-tier provider")
        else:
            if provider == "main":  # "main" + base_url: main provider identity on an explicit endpoint
                cfg = {**cfg, "provider": main_provider}
            v, reason = _route_item_verdict(ctx, cfg, purpose)
            fix = f"set {prefix}.provider/{prefix}.base_url to an in-tier route ({reason})"
            add(f"{prefix}.provider", cfg.get("provider") or "auto", v, fix)
            if base_url:
                add(f"{prefix}.base_url", base_url, v, fix)
        chain = cfg.get("fallback_chain")
        if chain not in (None, []) and not isinstance(chain, list):
            add(f"{prefix}.fallback_chain", chain, OFF_TIER, f"{prefix}.fallback_chain must be a list; remove it")
        for i, entry in enumerate(chain if isinstance(chain, list) else []):
            key = f"{prefix}.fallback_chain[{i}]"
            if not isinstance(entry, Mapping):
                add(key, entry, OFF_TIER, f"remove malformed {key}")
                continue
            ep = _s(entry.get("provider")).lower()
            if ep in _AUTO:
                add(key, entry, OFF_TIER, f"give {key}.provider an explicit in-tier provider or remove the entry")
                continue
            v, reason = _route_item_verdict(ctx, entry, f"{purpose}:fallback")
            add(key, entry, v, f"remove {key} or point it at an in-tier route ({reason})")

    # delegation (delegate_task children; tools/delegate_tool.py resolves these like a main route)
    deleg = config.get("delegation")
    deleg = deleg if isinstance(deleg, Mapping) else {}
    d_provider = _s(deleg.get("provider")).lower()
    d_base = _s(deleg.get("base_url"))
    d_fix = "clear delegation.provider/delegation.base_url (inherit the sealed main route) or point them in-tier"
    if d_provider in _AUTO and not d_base:
        d_verdict = main_verdict
        shown = f"(inherit) -> {main_provider or 'auto'}"
        d_fix = "delegation inherits the main route: fix model.provider"
    else:
        d_cfg = {"provider": d_provider or "custom", "base_url": d_base, "model": deleg.get("model"),
                 "api_mode": deleg.get("api_mode")}
        if d_provider in _CODEX:
            d_verdict, d_reason = OFF_TIER, "openai-codex runtime bypasses the middleware"
        else:
            d_verdict, d_reason = _route_item_verdict(ctx, d_cfg, "delegation")
        shown = deleg.get("provider") or "custom"
        d_fix = f"{d_fix} ({d_reason})"
    add("delegation.provider", shown, d_verdict, d_fix)
    add("delegation.model", _s(deleg.get("model")) or "(inherit)", d_verdict, d_fix)
    if d_base:
        add("delegation.base_url", d_base, d_verdict, d_fix)
    d_fb = deleg.get("fallback_providers")
    if d_fb not in (None, [], "", {}):
        add("delegation.fallback_providers", d_fb, OFF_TIER, "set delegation.fallback_providers: [] while sealed")

    # tts (assistant text is conversation content). Coordinator ruling (Amendment 3 addendum): the enabled
    # flag applies first; unset/false => disabled; enabled true + hosted (or unset provider, which Hermes
    # resolves to edge: tools/tts_tool.py:105,145-148) => off_tier; local engine or command provider =>
    # local. NOTE: Hermes 84a0301 has no tts.enabled key at all (DEFAULT_CONFIG["tts"]), so the flag is a
    # plugin-side convention. Fail-closed guard: when voice.auto_tts is on, Hermes speaks replies
    # automatically through tts.provider, so a non-local provider is off_tier whatever tts.enabled says.
    tts = config.get("tts")
    tts = tts if isinstance(tts, Mapping) else {}
    voice = config.get("voice")
    auto_tts = isinstance(voice, Mapping) and _truthy(voice.get("auto_tts"))
    raw_provider = _s(tts.get("provider")).lower()
    effective = raw_provider or _TTS_DEFAULT
    named = tts.get("providers") if isinstance(tts.get("providers"), Mapping) else {}
    named_cfg = named.get(raw_provider) if isinstance(named.get(raw_provider), Mapping) else None
    engine_local = raw_provider in _LOCAL_TTS or (named_cfg is not None and "command" in named_cfg)
    enabled_raw = tts.get("enabled", _ABSENT)
    enabled = enabled_raw is not _ABSENT and _truthy(enabled_raw)
    tts_fix = ("set tts.provider to a local engine (piper, kittentts, neutts) or a tts.providers.<name> command, "
               "or tts.enabled: false with voice.auto_tts: false, while sealed")
    if engine_local:
        tts_verdict, tts_value = LOCAL, raw_provider
    elif auto_tts:
        tts_verdict, tts_value = OFF_TIER, effective
        tts_fix += f"; voice.auto_tts is on and the provider resolves to {effective} (hosted)"
    elif enabled:
        tts_verdict, tts_value = OFF_TIER, effective
    else:
        tts_verdict = DISABLED
        tts_value = f"({'default ' if not raw_provider else ''}{effective}, disabled)"
    add("tts.provider", tts_value, tts_verdict, tts_fix)

    # memory
    mem = config.get("memory", _ABSENT)
    if mem is _ABSENT or mem is None:
        mem_provider, mem_ok_shape = "", True
    elif isinstance(mem, Mapping):
        mem_provider, mem_ok_shape = _s(mem.get("provider")), True
    else:
        mem_provider, mem_ok_shape = "", False
    if not mem_ok_shape:
        add("memory", mem, OFF_TIER, "memory must be a mapping; set memory.provider: \"\" (built-in)")
    else:
        add("memory.provider", mem_provider or "(built-in)",
            LOCAL if mem_provider.lower() in _LOCAL_MEMORY else OFF_TIER,
            'set memory.provider: "" (built-in local memory) while sealed')

    # MCP servers
    servers = config.get("mcp_servers")
    if servers not in (None, {}, [], "") and not isinstance(servers, Mapping):
        add("mcp_servers", servers, OFF_TIER, "mcp_servers must be a mapping of name -> {command|url}")
    for name, scfg in (servers.items() if isinstance(servers, Mapping) else ()):
        key = f"mcp_servers.{name}"
        if not isinstance(scfg, Mapping):
            add(key, scfg, MISSING, f"{key} is malformed; fix or remove it")
            continue
        enabled = scfg.get("enabled", True)
        off = enabled is False or (isinstance(enabled, str) and enabled.strip().lower() in {"false", "0", "no", "off"})
        if "url" in scfg:
            if off:
                add(f"{key}.url", scfg.get("url"), DISABLED)
            else:
                url = scfg.get("url")
                v, reason = ctx.classify("mcp", url if isinstance(url, str) else "", "", "", f"mcp:{name}")
                if not (isinstance(url, str) and url.strip()):
                    v, reason = OFF_TIER, "url is empty or not a string"
                add(f"{key}.url", url, v, f"set {key}.enabled: false or point {key}.url at an in-tier host ({reason})")
        elif "command" in scfg:
            add(f"{key}.command", scfg.get("command"), DISABLED if off else LOCAL)
        else:
            add(key, "", MISSING, f"{key} has neither url nor command")

    # plugin isolation
    iso = plugin_isolation(config) if isolation is _ABSENT else isolation
    iso_fix_key = "plugins.isolation"
    if iso is None:
        add(iso_fix_key, "(default in_process)", ctx.pass_verdict)
    elif iso == "in_process":
        add(iso_fix_key, iso, ctx.pass_verdict)
    else:
        add(iso_fix_key, iso if isinstance(iso, str) else repr(iso), MISSING if iso == "" else OFF_TIER,
            "set plugins.isolation: in_process; under host isolation the plugin's provider and middleware "
            "register in the plugin-host child and are invisible to Hermes")

    # hook execution (Amendment 4 F2): pre_llm_call (the per-turn recheck) is a timeout-bounded hook that
    # Hermes SKIPS, fail-open, when it overruns plugins.hook_callback_timeout (hermes_cli/plugins_dispatch.py
    # _HOOK_TIMEOUT_BOUNDED_HOOKS, plugins.py _resolve_hook_callback_timeout). <= 0 runs hooks synchronously
    # (safe); a positive value below HOOK_TIMEOUT_FLOOR_SECONDS lets the recheck be skipped.
    pcfg = config.get("plugins") if isinstance(config.get("plugins"), Mapping) else {}
    t_key = "plugins.hook_callback_timeout"
    raw_t = pcfg.get("hook_callback_timeout", _ABSENT)
    t_fix = (f"remove {t_key} or set it to at least {HOOK_TIMEOUT_FLOOR_SECONDS:g} (seconds) while sealed; a "
             "shorter timeout lets Hermes skip the per-turn seal recheck")
    if raw_t is _ABSENT or raw_t is None:
        add(t_key, "(default 30s)", ctx.pass_verdict)
    else:
        try:
            if isinstance(raw_t, bool):
                raise ValueError("bool")
            t = float(raw_t)
            if t != t:  # NaN
                raise ValueError("nan")
        except (TypeError, ValueError):
            add(t_key, repr(raw_t), OFF_TIER, t_fix + " (the value is not a number)")
        else:
            ok = t <= 0 or t >= HOOK_TIMEOUT_FLOOR_SECONDS
            add(t_key, f"{t:g}s" if t > 0 else f"{t:g} (hooks run synchronously)",
                ctx.pass_verdict if ok else OFF_TIER, t_fix)

    # attested profile presence
    if tier == Tier.ATTESTED:
        name = _s(attested_profile)
        key = f"provider_profile[{name or '?'}]"
        try:
            found = provider_lookup(name) if name else None
        except Exception:
            found = None
        if found is None:
            add(key, name, MISSING,
                "attested provider profile is not registered in this process; keep plugins.isolation: in_process "
                "and enable the confidential-mode plugin (host isolation registers it in the child only)")
        else:
            add(key, name, IN_TIER)

    return PreflightReport(tier=tier, items=tuple(items),
                           fingerprint=config_fingerprint(config, plugin_aux_tasks=plugin_aux_tasks,
                                                          builtin_aux_tasks=builtins),
                           aux_tasks=tuple(tasks))


# ── fingerprint ──────────────────────────────────────────────────────────────────────────────────

def _route_view(cfg: Any) -> Any:
    if not isinstance(cfg, Mapping):
        return cfg
    return {k: cfg.get(k) for k in ("provider", "model", "base_url", "api_mode") if k in cfg}


def config_fingerprint(config: Mapping, *, plugin_aux_tasks: Sequence[Any] = (),
                       builtin_aux_tasks: Sequence[str] | None = None) -> str:
    """sha256 over exactly the keys run_preflight enumerates (no api keys, no unrelated config).

    Aux tasks covered: the built-ins, ``plugin_aux_tasks``, and any dict-valued key the user wrote under
    ``auxiliary:`` (so a plugin task the user configured is covered even when the caller omits it).
    """
    config = config if isinstance(config, Mapping) else {}
    builtins = list(builtin_aux_tasks) if builtin_aux_tasks is not None else builtin_aux_task_names()
    plugins = _normalize_plugin_tasks(plugin_aux_tasks)
    user_aux = [k for k, v in _aux_section(config).items() if isinstance(v, Mapping)]
    tasks = sorted(set(builtins) | set(plugins) | set(user_aux))
    block = _main_block(config)
    aux_view = {}
    for task in tasks:
        cfg = _effective_aux(config, task, plugins)
        chain = cfg.get("fallback_chain")
        raw = _aux_section(config).get(task)
        aux_view[task] = {"provider": cfg.get("provider"), "base_url": cfg.get("base_url"),
                          "fallback_chain": [_route_view(e) for e in chain] if isinstance(chain, list) else chain,
                          "raw": None if isinstance(raw, Mapping) else raw}
    deleg = config.get("delegation")
    tts = config.get("tts")
    mem = config.get("memory")
    servers = config.get("mcp_servers")
    plugins_cfg = config.get("plugins")
    view = {
        "model": {"provider": block.get("provider"), "default": _main_model(block), "base_url": block.get("base_url"),
                  "api_mode": block.get("api_mode")},
        "fallback_providers": [_route_view(e) for e in config.get("fallback_providers") or []]
        if isinstance(config.get("fallback_providers"), list) else _route_view(config.get("fallback_providers")),
        "fallback_model": _route_view(config.get("fallback_model")),
        "auxiliary": aux_view,
        "delegation": ({k: _route_view(deleg.get(k)) if k == "fallback_providers" and isinstance(deleg.get(k), Mapping)
                        else ([_route_view(e) for e in deleg[k]] if k == "fallback_providers"
                              and isinstance(deleg.get(k), list) else deleg.get(k))
                        for k in ("provider", "model", "base_url", "api_mode", "fallback_providers")}
                       if isinstance(deleg, Mapping) else deleg),
        "tts.provider": tts.get("provider") if isinstance(tts, Mapping) else tts,
        "tts.enabled": tts.get("enabled", "<absent>") if isinstance(tts, Mapping) else None,
        "voice.auto_tts": (config.get("voice") or {}).get("auto_tts") if isinstance(config.get("voice"), Mapping)
        else config.get("voice"),
        "memory.provider": mem.get("provider") if isinstance(mem, Mapping) else mem,
        "mcp_servers": {n: ({k: s.get(k) for k in ("url", "command", "enabled") if k in s}
                            if isinstance(s, Mapping) else s)
                        for n, s in (servers.items() if isinstance(servers, Mapping) else ())}
        if isinstance(servers, Mapping) or servers is None else servers,
        "plugins.isolation": plugins_cfg.get("isolation", "<absent>") if isinstance(plugins_cfg, Mapping)
        else plugins_cfg,
        # Amendment 4 F2: every plugins.* key that governs hook execution.
        "plugins.execution": {k: plugins_cfg.get(k, "<absent>") for k in _PLUGIN_EXECUTION_KEYS}
        if isinstance(plugins_cfg, Mapping) else plugins_cfg,
    }
    blob = json.dumps(view, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ── table output ─────────────────────────────────────────────────────────────────────────────────

def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."


def format_report(report: PreflightReport, *, value_width: int = 40, key_width: int = 44) -> str:
    """Fixed-width table: KEY, VALUE (redacted), VERDICT, FIX. Fix text is not clipped."""
    kw = min(key_width, max([3] + [len(i.key) for i in report.items]))
    vw = min(value_width, max([5] + [len(i.value_redacted) for i in report.items]))
    dw = max(len(v) for v in VERDICTS)
    status = "PASS" if report.ok else f"FAIL ({len(report.failures())} item(s))"
    lines = [f"confidential preflight: tier={report.tier.value} {status} fingerprint={report.fingerprint[:12]}",
             f"{'KEY':<{kw}}  {'VALUE':<{vw}}  {'VERDICT':<{dw}}  FIX",
             f"{'-' * kw}  {'-' * vw}  {'-' * dw}  ---"]
    for i in report.items:
        lines.append(f"{_clip(i.key, kw):<{kw}}  {_clip(i.value_redacted, vw):<{vw}}  {i.verdict:<{dw}}  {i.fix}".rstrip())
    return "\n".join(lines)


# ── Hermes seam (lazy imports) ───────────────────────────────────────────────────────────────────

def load_core_config() -> dict:
    """Hermes' merged config via ``hermes_cli.config.load_config_readonly`` (config.py:1985).

    The returned dict is Hermes' cached object: callers must not mutate it (run_preflight does not).
    """
    from hermes_cli.config import load_config_readonly
    cfg = load_config_readonly()
    return cfg if isinstance(cfg, dict) else {}


def builtin_aux_task_names() -> list[str]:
    """Dict-valued keys of DEFAULT_CONFIG['auxiliary'] (hermes_cli/config_defaults.py:725-800)."""
    try:
        from hermes_cli.config_defaults import DEFAULT_CONFIG
        aux = DEFAULT_CONFIG.get("auxiliary", {})
        names = [k for k, v in aux.items() if isinstance(v, dict)]
        if names:
            return names
    except Exception:
        pass
    return list(BUILTIN_AUX_TASKS_SNAPSHOT)


def plugin_aux_task_entries() -> list[dict]:
    """Registration dicts from ``hermes_cli.plugins.get_plugin_auxiliary_tasks`` (plugins.py:2130)."""
    from hermes_cli.plugins import get_plugin_auxiliary_tasks
    return [dict(e) for e in get_plugin_auxiliary_tasks()]


def plugin_aux_task_names() -> list[str]:
    return [e["key"] for e in plugin_aux_task_entries() if e.get("key")]


def provider_lookup(name: str) -> object | None:
    """``providers.get_provider_profile(name)``; None when absent or on any error."""
    try:
        from providers import get_provider_profile
        return get_provider_profile(name)
    except Exception:
        return None


def profile_base_url(provider: str) -> str:
    profile = provider_lookup(provider) if provider else None
    url = getattr(profile, "base_url", "") if profile is not None else ""
    return url if isinstance(url, str) else ""


def plugin_isolation(config: Mapping) -> Any:
    """Raw ``plugins.isolation``: None when the key (or ``plugins:``) is absent, else the value as written.

    Hermes itself (hermes_cli/plugin_isolation.py:96-106) maps null, "", and unknown values to in_process;
    preflight is stricter and only lets a truly absent key (or "in_process") pass.

    A non-mapping ``plugins:`` block yields a marker string so it fails the in_process check.
    """
    plugins_cfg = config.get("plugins") if isinstance(config, Mapping) else None
    if plugins_cfg is None:
        return None
    if not isinstance(plugins_cfg, Mapping):
        return f"<plugins block is a {type(plugins_cfg).__name__}>"
    if "isolation" not in plugins_cfg:
        return None
    value = plugins_cfg["isolation"]
    return "" if value is None else value  # explicit null is treated like "" (missing), not as absent

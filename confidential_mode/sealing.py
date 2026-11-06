"""Seal, unseal and the per-turn recheck (W5): the glue between preflight (W3), the tool allowlist
(W4), the attested provider (W2), and the persisted seal state / ledger (W1).

Every Hermes-facing collaborator is an injectable keyword with a default that reads Hermes' live
state, so unit tests pass fakes and register(ctx) passes nothing.

- ``seal(tier, ...)``: run the preflight for the tier; refuse with the formatted report on any
  failure (ledger ``preflight_fail``); otherwise build the registry allowlist, write the seal state
  with the config fingerprint, ledger ``seal`` and return the seal message plus the allowlist.
  zero-retention always refuses (the predicate is a stub).
- ``unseal(...)``: ledger ``unseal`` with refusal/ask counts for the seal period, clear the seal flag
  and the attested verification cache.
- ``recheck(...)``: for ``pre_llm_call``. Re-runs the preflight structurally (no network: the
  attestation check is replaced by "is the attested profile registered", the gate does the real
  check per request) and compares its fingerprint with the one recorded at seal. A change, or a
  structural failure, marks the session breached (ledger ``breach``) and returns the block message.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from . import preflight as _pf
from .ledger import LedgerEvent
from .tiers import AttestedPredicate, LocalPredicate, Tier, TierPredicate, Verdict, ZdrPredicate, host_of

PROFILE_NAME = "attested-tinfoil"   # provider.PROFILE_NAME; repeated so this module imports no SDK code
ZDR_REASON = "zero-retention tier not implemented"

# User-facing disclosures (Amendment 4 F1(d), F12; must agree with the tool gate and the README).
TOOLS_TEXT = ("Tools that send data off this machine (web, browser, messaging, media and other non-local tools) "
              "ask you first, each call; under yolo, approvals off or an unattended run those asks become "
              "blocks. Off-tier remote MCP servers, scheduled jobs and routed delegation are blocked.")
AUX_TEXT = ("Not prevented, only recorded after the fact: Hermes' auxiliary model calls (session titles, "
            "compression, memory prefetch, vision, smart approvals, MCP sampling, background review) cannot be "
            "stopped by a plugin. The plugin checks the configured and live model runtime before each turn and "
            "ends the turn when either is off-tier, but an auxiliary call that runs anyway (outside a turn, "
            "mid-turn after a switch, or when Hermes skips the check) is recorded as a breach, not refused.")
SAFE_WORKER_TEXT = ("Sealed mode does not apply when Hermes runs in safe-worker mode: plugins are not loaded there, "
                    "so nothing is checked, refused or recorded.")
SEAL_TAIL = (f"{TOOLS_TEXT} Memory: local. Fallbacks: none. {AUX_TEXT} {SAFE_WORKER_TEXT}")
CONFIG_CHANGED_TEXT = (
    "Confidential mode: the routing config changed after this profile was sealed, so this turn was not "
    "sent to any model. Run /confidential check to see what changed, then /confidential off and "
    "/confidential on <tier> to seal again.")
STRUCTURE_FAILED_TEXT = (
    "Confidential mode: the sealed routing config no longer passes the preflight, so this turn was not "
    "sent to any model. Run /confidential check, fix the listed keys, then /confidential off and "
    "/confidential on <tier>.")
SEALED_NOTE = (
    "[confidential mode] This profile is sealed ({tier}). Tools that send data off this machine ask the user "
    "first, each call (blocked outright under yolo or approvals off); off-tier remote MCP servers, scheduled "
    "jobs and routed delegation are blocked. If a tool is blocked or refused, tell the user what was blocked "
    "and ask them to unseal if they need it; do not retry it or look for a workaround. Disclosure for the "
    "user if asked: auxiliary model calls (titles, compression, vision) are recorded, not prevented, and "
    "sealed mode does not apply in Hermes safe-worker mode.")


def live_runtime_text(tier: Tier, provider: str, host: str, reason: str) -> str:
    """Starts like the llm gate's off-tier refusal (gate_llm.off_tier_text)."""
    return (f"Confidential mode: sealed to {Tier(tier).value}; this request was not sent. The session's live "
            f"model runtime is {provider or '(unknown)'} at {host or '(no host)'}, which is off-tier ({reason}), "
            "so this turn was ended before any model or auxiliary call. Switch the session back to the sealed "
            "model (/model), or run /confidential off.")


REFUSAL_KINDS = frozenset({"send_refused", "tool_refused"})
ASK_KINDS = frozenset({"tool_asked"})


@dataclass
class SealResult:
    ok: bool
    message: str
    tier: Optional[Tier] = None
    report: Any = None            # PreflightReport
    allowlist: Any = None         # gate_tools.Allowlist
    allowlist_text: str = ""
    fingerprint: str = ""
    counts: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


# ── predicates ───────────────────────────────────────────────────────────────────────────────────

def _cfg(config: Any, *path: str, default: Any = None) -> Any:
    node = config
    for key in path:
        if not isinstance(node, Mapping):
            return default
        node = node.get(key)
    return default if node is None else node


def extra_hosts(config: Mapping | None) -> list[str]:
    hosts = _cfg(config or {}, "confidential", "local", "extra_hosts", default=[])
    return [h for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else []


def _default_attested_ok(provider: str) -> Verdict:
    from .provider import attested_ok
    return attested_ok(provider)


def predicate_for(tier: Tier | str, *, config: Mapping | None = None,
                  attested_ok: Callable[[str], Verdict] | None = None,
                  profile_base_url: Callable[[str], Any] | None = None) -> TierPredicate:
    """The TierPredicate for ``tier`` built from tiers.py, with ``profile_base_url`` from preflight
    and ``attested_ok`` from provider (both injectable)."""
    tier = Tier(tier)
    pbu = profile_base_url if profile_base_url is not None else _pf.profile_base_url
    if tier is Tier.LOCAL:
        return LocalPredicate(extra_hosts=extra_hosts(config), profile_base_url=pbu)
    if tier is Tier.ATTESTED:
        return AttestedPredicate([PROFILE_NAME], attested_ok or _default_attested_ok, profile_base_url=pbu)
    return ZdrPredicate()


def structural_predicate(tier: Tier | str, *, config: Mapping | None = None,
                         provider_lookup: Callable[[str], Any] | None = None,
                         profile_base_url: Callable[[str], Any] | None = None) -> TierPredicate:
    """Like predicate_for, but the attestation check is "profile registered" (never the network)."""
    tier = Tier(tier)
    if tier is not Tier.ATTESTED:
        return predicate_for(tier, config=config, profile_base_url=profile_base_url)
    lookup = provider_lookup or _pf.provider_lookup

    def registered(provider: str) -> Verdict:
        ok = lookup(provider) is not None
        return Verdict(ok, "attested profile registered" if ok else "attested profile not registered")
    return predicate_for(tier, config=config, attested_ok=registered, profile_base_url=profile_base_url)


# ── preflight ────────────────────────────────────────────────────────────────────────────────────

def _plugin_aux(plugin_aux_tasks: Optional[Sequence[Any]]) -> list:
    if plugin_aux_tasks is not None:
        return list(plugin_aux_tasks)
    try:
        return _pf.plugin_aux_task_entries()
    except Exception:
        return []


def run_tier_preflight(tier: Tier | str, *, config: Mapping | None = None,
                       predicate: TierPredicate | None = None,
                       plugin_aux_tasks: Optional[Sequence[Any]] = None,
                       provider_lookup: Callable[[str], Any] | None = None,
                       attested_ok: Callable[[str], Verdict] | None = None,
                       profile_base_url: Callable[[str], Any] | None = None,
                       builtin_aux_tasks: Optional[Sequence[str]] = None):
    """PreflightReport for ``tier`` over Hermes' loaded config (read-only)."""
    tier = Tier(tier)
    config = _pf.load_core_config() if config is None else config
    predicate = predicate or predicate_for(tier, config=config, attested_ok=attested_ok,
                                           profile_base_url=profile_base_url)
    return _pf.run_preflight(tier, predicate, config, plugin_aux_tasks=_plugin_aux(plugin_aux_tasks),
                             provider_lookup=provider_lookup or _pf.provider_lookup,
                             attested_profile=PROFILE_NAME if tier is Tier.ATTESTED else None,
                             builtin_aux_tasks=builtin_aux_tasks)


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────

def age_text(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    s = max(0, int(seconds))
    if s < 90:
        return f"{s}s"
    if s < 90 * 60:
        return f"{s // 60}m"
    if s < 48 * 3600:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _append(ledger: Any, event: Any) -> None:
    """Best effort: a ledger failure never changes a seal decision."""
    try:
        ledger.append(event)
    except Exception:
        pass


def _main_route(config: Mapping) -> tuple[str, str, str]:
    model = config.get("model") if isinstance(config, Mapping) else None
    if isinstance(model, str):
        return "", model, ""
    if not isinstance(model, Mapping):
        return "", "", ""
    def s(v): return v.strip() if isinstance(v, str) else ""
    return s(model.get("provider")), s(model.get("default")) or s(model.get("model")), s(model.get("base_url"))


def _default_verification(provider: str):
    try:
        from .provider import verification_cache
        return verification_cache.result(provider)
    except Exception:
        return None


def seal_message(tier: Tier, config: Mapping, *, verification: Any = None,
                 clock: Callable[[], float] = time.time) -> str:
    provider, model, base_url = _main_route(config)
    route = f"{provider or '?'}/{model or '?'}"
    if tier is Tier.ATTESTED:
        verified_at = getattr(verification, "verified_at_local", None)
        host = getattr(verification, "enclave_host", "") or host_of(base_url)
        age = age_text(clock() - verified_at) if isinstance(verified_at, (int, float)) else "never"
        head = f"Sealed. Model: {route} at {host or '(enclave unresolved)'}, verified {age} ago (local clock)."
    else:
        head = f"Sealed ({tier.value}). Model: {route} at {host_of(base_url) or '(provider default)'} (local endpoint)."
    return f"{head} {SEAL_TAIL}"


# ── live main runtime (Amendment 4 F1) ───────────────────────────────────────────────────────────

def live_main_runtime() -> Optional[dict]:
    """The live main runtime Hermes published for this context (agent/turn_context.py
    _publish_runtime_main -> agent.auxiliary_client.set_runtime_main, a ContextVar; hook workers run on a
    copied context, so pre_llm_call sees the turn's value). "auto" auxiliary tasks resolve to THIS, not to
    config. None when unbound (slash commands outside a turn, other threads)."""
    try:
        from agent.auxiliary_client import _RUNTIME_MAIN_CONTEXT
        runtime = _RUNTIME_MAIN_CONTEXT.get()
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(runtime, dict) or not (runtime.get("provider") or runtime.get("base_url")):
        return None
    return {k: runtime.get(k) or "" for k in ("provider", "model", "base_url", "api_mode", "requested_provider")}


def classify_live_runtime(tier: Tier | str, runtime: Mapping, *, config: Mapping | None = None,
                          provider_lookup: Callable[[str], Any] | None = None,
                          profile_base_url: Callable[[str], Any] | None = None) -> Verdict:
    """Structural verdict (no network) for the live main runtime under ``tier``."""
    from .tiers import Destination
    dest = Destination(provider=str(runtime.get("provider") or ""), base_url=str(runtime.get("base_url") or ""),
                       model=str(runtime.get("model") or ""), api_mode=str(runtime.get("api_mode") or ""),
                       purpose="main")
    try:
        v = structural_predicate(tier, config=config, provider_lookup=provider_lookup,
                                 profile_base_url=profile_base_url).classify(dest)
    except Exception as exc:  # noqa: BLE001
        return Verdict(False, f"tier check failed ({type(exc).__name__})", host_of(dest.base_url))
    if not isinstance(v, Verdict) or v.in_tier is not True:
        return Verdict(False, getattr(v, "reason", "") or "off-tier", getattr(v, "host", "") or host_of(dest.base_url))
    return v


# ── seal / unseal ────────────────────────────────────────────────────────────────────────────────

def seal(tier: Tier | str, *, state, ledger, config: Mapping | None = None, registry: Any = None,
         plugin_aux_tasks: Optional[Sequence[Any]] = None,
         provider_lookup: Callable[[str], Any] | None = None,
         attested_ok: Callable[[str], Verdict] | None = None,
         profile_base_url: Callable[[str], Any] | None = None,
         builtin_aux_tasks: Optional[Sequence[str]] = None,
         allowlist_builder: Callable[..., Any] | None = None, allowlist_path: Any = None,
         verification: Callable[[str], Any] | None = None, session_id: str = "", surface: str = "",
         live_runtime: Callable[[], Optional[dict]] | None = None,
         clock: Callable[[], float] = time.time) -> SealResult:
    """Seal the profile to ``tier`` or refuse with the reason. Never raises for a refusal."""
    try:
        tier = Tier(tier)
    except ValueError:
        names = ", ".join(t.value for t in Tier)
        return SealResult(False, f"Not sealed: unknown tier {tier!r} (one of: {names}).")

    base = dict(session_id=session_id or "", tier=tier.value, surface=surface or None)
    if tier is Tier.ZDR:
        _append(ledger, LedgerEvent(kind="preflight_fail", purpose="seal", verdict="off_tier", decision="refused",
                                    detail={"reason": ZDR_REASON}, **base))
        return SealResult(False, f"Not sealed: {ZDR_REASON}. Use local-only or attested.", tier=tier)

    try:
        sealed, current = state.sealed()
    except Exception:
        sealed, current = None, None
    if sealed is True:
        return SealResult(False, f"Already sealed ({current.value}). Run /confidential off first, then seal again.",
                          tier=current)

    config = _pf.load_core_config() if config is None else config
    aux = _plugin_aux(plugin_aux_tasks)
    predicate = predicate_for(tier, config=config, attested_ok=attested_ok, profile_base_url=profile_base_url)
    report = run_tier_preflight(tier, config=config, predicate=predicate, plugin_aux_tasks=aux,
                                provider_lookup=provider_lookup, builtin_aux_tasks=builtin_aux_tasks)
    if not report.ok:
        _append(ledger, LedgerEvent(
            kind="preflight_fail", purpose="seal", verdict="off_tier", decision="refused",
            detail={"failures": [i.key for i in report.failures()][:100], "fingerprint": report.fingerprint}, **base))
        return SealResult(False, "Not sealed: the preflight found routes that would leave the tier.\n"
                          + _pf.format_report(report), tier=tier, report=report, fingerprint=report.fingerprint)

    runtime = (live_runtime or live_main_runtime)()
    if runtime:
        lv = classify_live_runtime(tier, runtime, config=config, provider_lookup=provider_lookup,
                                   profile_base_url=profile_base_url)
        if lv.in_tier is not True:
            _append(ledger, LedgerEvent(
                kind="preflight_fail", purpose="seal:live_runtime", provider=str(runtime.get("provider") or ""),
                host=lv.host, verdict="off_tier", decision="refused", detail={"reason": lv.reason}, **base))
            return SealResult(False, f"Not sealed: this session's live model runtime ({runtime.get('provider')} at "
                              f"{lv.host or '(no host)'}) is off-tier ({lv.reason}), although the config passes. "
                              "Switch the session to the configured model (/model) first.", tier=tier, report=report)

    if registry is None:
        from tools.registry import registry as _registry
        registry = _registry
        try:
            # Built-in tools self-register on import; a `hermes confidential on` process never imported them,
            # and an allowlist built from that registry would classify nothing (every tool blocked later).
            from tools.registry import discover_builtin_tools
            discover_builtin_tools()
        except Exception:  # noqa: BLE001
            pass
    if allowlist_builder is None:
        from .gate_tools import build_allowlist as allowlist_builder
    from .gate_tools import format_allowlist
    allowlist = allowlist_builder(registry, predicate=predicate, added_path=allowlist_path)
    allowlist_text = format_allowlist(allowlist)

    state.seal(tier, report.fingerprint)
    # Amendment 4 F5/F6 (W4): persist this seal's tool identities, tagged with the seal, so a restart
    # rebuilds from them (not from the live registry) and grants never outlive the seal.
    if hasattr(allowlist, "persist"):
        from .gate_tools import seal_id_for
        allowlist.seal_id = seal_id_for(state)
        try:
            allowlist.persist(allowlist_path)
        except Exception:
            pass   # an unpersisted seal rebuilds as an empty allowlist after a restart: fail closed
    verification_result = (verification or _default_verification)(PROFILE_NAME) if tier is Tier.ATTESTED else None
    message = seal_message(tier, config, verification=verification_result, clock=clock)
    provider, model, base_url = _main_route(config)
    from .gate_tools import Route
    routes = {r.value: len(allowlist.names(r)) for r in Route}
    _append(ledger, LedgerEvent(
        kind="seal", purpose="seal", provider=provider, model=model, host=host_of(base_url), verdict="in_tier",
        decision="sealed", detail={"fingerprint": report.fingerprint, "routes": routes,
                                   "aux_tasks": len(report.aux_tasks)}, **base))
    return SealResult(True, message + "\n\nTools:\n" + allowlist_text, tier=tier, report=report,
                      allowlist=allowlist, allowlist_text=allowlist_text, fingerprint=report.fingerprint)


def period_counts(ledger: Any, since: float | None, *, page: int = 1000) -> dict:
    """Refusal / ask / breach counts for events at or after ``since`` (local clock)."""
    counts = {"refused": 0, "asked": 0, "allowed": 0, "breach": 0, "send_refused": 0, "tool_refused": 0}
    last = 0
    while True:
        rows = ledger.tail(last, limit=page)
        for ev in rows:
            if since is not None and (ev.ts or 0) < since:
                continue
            if ev.kind in REFUSAL_KINDS:
                counts["refused"] += 1
                counts[ev.kind] += 1
            elif ev.kind in ASK_KINDS:
                counts["asked"] += 1
            elif ev.kind == "tool_allowed":
                counts["allowed"] += 1
            elif ev.kind == "breach":
                counts["breach"] += 1
        if len(rows) < page:
            return counts
        last = rows[-1].id


def unseal(*, state, ledger, session_id: str = "", surface: str = "",
           clear_cache: Callable[[], None] | None = None, clock: Callable[[], float] = time.time) -> SealResult:
    """Clear the seal (also repairs unreadable seal state) and print the seal period's counts."""
    try:
        sealed, tier = state.sealed()
    except Exception:
        sealed, tier = None, None   # unreadable: unsealing is the repair
    try:
        since = state.sealed_since()
    except Exception:
        since = None
    try:
        counts = period_counts(ledger, since)
    except Exception:
        counts = {}
    state.unseal()
    try:
        (clear_cache or _clear_verification_cache)()
    except Exception:
        pass
    _append(ledger, LedgerEvent(kind="unseal", session_id=session_id or "", purpose="seal",
                                tier=tier.value if tier else None, decision="unsealed", surface=surface or None,
                                detail={"counts": counts, "was_sealed": sealed is True,
                                        "repaired": sealed is None}))
    if sealed is False:
        return SealResult(True, "Not sealed; nothing to do.", counts=counts)
    period = f" for {age_text(clock() - since)}" if since else ""
    head = "Seal state was unreadable; it is now cleared (unsealed)." if sealed is None else \
        f"Unsealed ({tier.value}). Sealed{period}:"
    return SealResult(True, f"{head} {counts.get('refused', 0)} refusal(s) "
                            f"({counts.get('send_refused', 0)} model, {counts.get('tool_refused', 0)} tool), "
                            f"{counts.get('asked', 0)} ask(s), {counts.get('breach', 0)} breach(es).",
                      tier=tier, counts=counts)


def _clear_verification_cache() -> None:
    from .provider import verification_cache
    verification_cache.invalidate(PROFILE_NAME)


# ── per-turn recheck ─────────────────────────────────────────────────────────────────────────────

def recheck(*, state, ledger, config: Mapping | None = None, session_id: str = "",
            plugin_aux_tasks: Optional[Sequence[Any]] = None,
            provider_lookup: Callable[[str], Any] | None = None,
            profile_base_url: Callable[[str], Any] | None = None,
            builtin_aux_tasks: Optional[Sequence[str]] = None) -> Optional[str]:
    """None when unsealed or the sealed config is unchanged; otherwise the block message (and the
    session is marked breached, ledgered once per session). Read-only, no network."""
    sealed, tier = state.sealed()       # StateError propagates: the caller fails closed
    if sealed is not True:
        return None
    config = _pf.load_core_config() if config is None else config
    predicate = structural_predicate(tier, config=config, provider_lookup=provider_lookup,
                                     profile_base_url=profile_base_url)
    report = run_tier_preflight(tier, config=config, predicate=predicate, plugin_aux_tasks=plugin_aux_tasks,
                                provider_lookup=provider_lookup, builtin_aux_tasks=builtin_aux_tasks)
    recorded = state.config_fingerprint()
    if report.fingerprint == recorded and report.ok:
        return None
    changed = report.fingerprint != recorded
    sid = session_id or ""
    try:
        already = state.is_breached(sid)
    except Exception:
        already = False
    if not already:
        try:
            state.mark_breached(sid)
        except Exception:
            pass
        _append(ledger, LedgerEvent(
            kind="breach", session_id=sid, purpose="config", tier=tier.value, verdict="off_tier",
            decision="config_changed" if changed else "preflight_failed",
            detail={"recorded": (recorded or "")[:16], "current": report.fingerprint[:16],
                    "failures": [i.key for i in report.failures()][:50]}))
    return CONFIG_CHANGED_TEXT if changed else STRUCTURE_FAILED_TEXT

"""hermes-confidential-mode: attested inference provider plus sealed mode for Hermes Agent.

``register(ctx)`` wires one Ledger, one ConfidentialState and one ApprovalDecisions into:

- llm_execution middleware (gate_llm): every main-loop provider call is checked against the sealed
  tier; the predicate also refuses everything if the routing config changed since seal;
- tool_execution middleware + pre_tool_call + post_approval_response (gate_tools), sharing ONE
  ApprovalDecisions (the hook asks, the middleware enforces on the recorded exact answer);
- pre_llm_call: sealed note into the model's context, and the per-turn config recheck (block);
- pre_api_request / pre_auxiliary_call / post_auxiliary_call: ledger ``send_observed`` with host and
  bytes; an off-tier auxiliary destination while sealed is a breach (aux calls cannot be blocked);
- on_session_start / on_session_end / post_compaction: receipt rows;
- the 'attested-tinfoil' provider profile (no network at register);
- ``/confidential`` and ``hermes confidential``.

Every registration is its own step: a failure is logged, ledgered (``preflight_fail``, purpose
``register:<step>``) and recorded on the runtime, and never stops the other steps or escapes.
Submodules are imported inside the steps so even an import error is contained.
"""
from __future__ import annotations

import importlib
import logging
import os
import threading
from collections import deque
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

HOOKS = ("pre_tool_call", "post_approval_response", "pre_llm_call", "pre_api_request", "pre_auxiliary_call",
         "post_auxiliary_call", "on_session_start", "on_session_end", "post_compaction", "pre_gateway_dispatch")
# Gateway slash commands that switch the session's live model runtime (Amendment 4 F1(c)); refused while
# sealed. The CLI/TUI never fire pre_gateway_dispatch: there the per-turn live-runtime check ends the turn.
RUNTIME_SWITCH_COMMANDS = frozenset({"model", "moa"})
MIDDLEWARE = ("llm_execution", "tool_execution")
NO_SESSION = "(no session)"

_RUNTIME: Optional["Runtime"] = None   # the last registered runtime (commands, tests)


def _cm(name: str):
    """Import ``<this package>.confidential_mode.<name>`` (or the top-level package when this file is
    imported outside a package)."""
    base = f"{__name__}.confidential_mode" if __package__ else "confidential_mode"
    return importlib.import_module(f"{base}.{name}")


class Runtime:
    """Everything the gates, hooks and commands share for one registered plugin instance."""

    def __init__(self, ctx: Any):
        self.ctx = ctx
        self.ledger: Any = None
        self.state: Any = None
        self.decisions: Any = None
        self.profile: Any = None
        self.pins: Any = None
        self.adapter: Any = None
        self.allowlist_path: Any = None
        self.registered: dict[str, list[str]] = {"hooks": [], "middleware": [], "commands": [],
                                                 "cli_commands": [], "providers": []}
        self.errors: list[tuple[str, str]] = []
        self._allowlist: Any = None
        self._allowlist_stamp: Any = None
        self._lock = threading.Lock()
        self._aux_seen: deque = deque(maxlen=512)
        self.last_live: Optional[dict] = None      # last live main runtime seen by pre_llm_call (status)

    # ── shared collaborators ──────────────────────────────────────────────────────────────────
    def module(self, name: str):
        return _cm(name)

    def load_config(self) -> dict:
        return _cm("preflight").load_core_config()

    def is_sealed(self):
        if self.state is None:
            raise _cm("state").StateError("confidential state is unavailable")
        return self.state.sealed()

    def set_allowlist(self, allowlist: Any) -> None:
        with self._lock:
            self._allowlist = allowlist
            self._allowlist_stamp = self._file_stamp()

    def _file_stamp(self):
        """(mtime_ns, size) of the persisted allowlist, or None. A seal, unseal or allow from ANOTHER
        process (the `hermes confidential` CLI next to a running gateway) changes it."""
        try:
            st = os.stat(self.allowlist_path)
            return st.st_mtime_ns, st.st_size
        except Exception:  # noqa: BLE001
            return None

    def allowlist(self):
        """The allowlist for the CURRENT seal. The seal lives in ctx.state (re-read from disk on every
        call), so another process may have sealed, unsealed or resealed since this one cached its
        allowlist: the cache is used only while its seal_id matches the persisted seal, and additions
        another process approved (allowlist.yaml changed, same seal) are merged in. After a restart, or a
        seal made by another process, it is rebuilt from the identities persisted at that seal and ledgered."""
        gt = _cm("gate_tools")
        try:
            sealed, tier = self.is_sealed()
        except Exception:  # noqa: BLE001
            sealed, tier = False, None
        if sealed is not True:
            with self._lock:
                self._allowlist = None
            return gt.Allowlist(tools={})
        seal_id = gt.seal_id_for(self.state)
        stamp = self._file_stamp()
        with self._lock:
            cached = self._allowlist
            if cached is not None and getattr(cached, "seal_id", "") == seal_id:
                if stamp != self._allowlist_stamp:
                    _merge_added(cached, self.allowlist_path, seal_id)
                    self._allowlist_stamp = stamp
                return cached
        from tools.registry import registry
        predicate = _cm("sealing").predicate_for(tier, config=self.load_config())
        # Amendment 4 F5 (W4): rebuild from the identities persisted at THIS seal; anything registered
        # after the seal, changed, or a missing/other-seal file is unclassified until a reseal.
        allowlist = gt.Allowlist.load_persisted(self.allowlist_path, registry, predicate=predicate, seal_id=seal_id)
        with self._lock:
            current = self._allowlist
            if current is None or getattr(current, "seal_id", "") != seal_id:
                self._allowlist, self._allowlist_stamp = allowlist, stamp
            allowlist = self._allowlist
        # Not kind "seal": receipts open a sealed period at every seal row (Amendment 4 F7).
        self.append({"kind": "session_start", "purpose": "seal", "tier": tier.value, "decision": "allowlist_rebuilt",
                     "detail": {"tools": len(allowlist.tools)}})
        return allowlist

    def predicate_for(self, tier):
        """The sealed tier's predicate for the llm gate. If the routing config no longer matches the
        fingerprint recorded at seal, every destination is off-tier (second line behind pre_llm_call,
        which Hermes skips for agents with persistence disabled: agent/turn_context.py:860)."""
        sealing, pf = _cm("sealing"), _cm("preflight")
        config = self.load_config()
        current = pf.config_fingerprint(config, plugin_aux_tasks=sealing._plugin_aux(None))
        if current != self.state.config_fingerprint():
            return _ChangedConfigPredicate(_cm("tiers").Tier(tier))
        return sealing.predicate_for(tier, config=config)

    def pin_pending(self) -> bool:
        return self.pins is not None and self.pins.pending() is not None

    def append(self, event: Any) -> None:
        try:
            if self.ledger is not None:
                self.ledger.append(event)
        except Exception as exc:  # noqa: BLE001
            logger.warning("confidential-mode ledger append failed: %s", type(exc).__name__)


def _merge_added(allowlist: Any, path: Any, seal_id: str) -> None:
    """Pull human-approved additions another process persisted for the SAME seal into ``allowlist``.
    Only names still on the ask route count; a file for another seal adds nothing."""
    import json
    try:
        data = json.loads(open(path, encoding="utf-8").read())
    except Exception:  # noqa: BLE001
        return
    if not isinstance(data, dict) or data.get("seal_id") != seal_id or not isinstance(data.get("allowed"), list):
        return
    route_ask = _cm("gate_tools").Route.ASK
    names = {n for n in data["allowed"] if isinstance(n, str)
             and getattr(allowlist.tools.get(n), "route", None) is route_ask}
    with allowlist._lock:
        allowlist.added |= names


class _ChangedConfigPredicate:
    REASON = "routing config changed since seal; run /confidential off and seal again"

    def __init__(self, tier):
        self.tier = tier

    def classify(self, dest):
        tiers = _cm("tiers")
        return tiers.Verdict(False, self.REASON, tiers.host_of(dest.base_url))


# ── registration steps ───────────────────────────────────────────────────────────────────────────

def _step(rt: Runtime, name: str, fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one failing registration never stops the others
        text = f"{type(exc).__name__}: {exc}"[:300]
        rt.errors.append((name, text))
        logger.warning("confidential-mode: registration step %s failed: %s", name, text)
        rt.append({"kind": "preflight_fail", "purpose": f"register:{name}", "decision": "register_failed",
                   "detail": {"step": name, "error": text}})
        return None


def _hook(rt: Runtime, name: str, fn: Callable[..., Any]) -> None:
    rt.ctx.register_hook(name, fn)
    rt.registered["hooks"].append(name)


def _middleware(rt: Runtime, kind: str, fn: Callable[..., Any]) -> None:
    rt.ctx.register_middleware(kind, fn)
    rt.registered["middleware"].append(kind)


def register(ctx) -> None:
    global _RUNTIME
    rt = Runtime(ctx)
    _RUNTIME = rt
    try:
        _register(rt)
    except Exception as exc:  # noqa: BLE001 - belt and braces: register never raises
        rt.errors.append(("register", f"{type(exc).__name__}: {exc}"[:300]))
        logger.warning("confidential-mode: register failed: %s", exc)
    return None


def _register(rt: Runtime) -> None:
    ctx = rt.ctx

    def core():
        rt.ledger = _cm("ledger").Ledger()          # opens plugin_db lazily, on first append
    _step(rt, "ledger", core)

    def state():
        rt.state = _cm("state").ConfidentialState(ctx.state)
    _step(rt, "state", state)

    def decisions():
        rt.decisions = _cm("gate_tools").ApprovalDecisions()
    _step(rt, "decisions", decisions)

    def data_paths():
        rt.allowlist_path = ctx.state.data_dir / "allowlist.yaml"
    _step(rt, "data_paths", data_paths)

    def provider_profile():
        provider = _cm("provider")
        # ledger= : the verification cache ledgers verify_ok/verify_fail/pin_staged (Amendment 4 F4).
        profile = provider.register_provider_profile(ctx, config=rt.load_config(), ledger=rt.ledger)
        rt.profile = profile
        rt.pins = getattr(profile, "_confidential_pins", None)
        rt.adapter = getattr(profile, "_confidential_adapter", None)
        rt.registered["providers"].append(profile.name)
    _step(rt, "provider", provider_profile)
    if rt.pins is None:
        def fallback_pins():
            rt.pins = _cm("pins").PinStore(ctx.state.data_dir / "pins.yaml")
        _step(rt, "pins", fallback_pins)

    # -- llm gate -----------------------------------------------------------------------------
    def llm():
        provider = _cm("provider")
        mw = _cm("gate_llm").build_middleware(ledger=rt.ledger, is_sealed=rt.is_sealed,
                                               predicate_for=rt.predicate_for, attested_ok=provider.attested_ok,
                                               pin_pending=rt.pin_pending)
        _middleware(rt, "llm_execution", mw)
    _step(rt, "llm_execution", llm)

    # -- tool gate: one ApprovalDecisions shared by all three (gate_tools.build_pre_tool_call doc) ---
    def tool_mw():
        gt = _cm("gate_tools")
        _middleware(rt, "tool_execution", gt.build_tool_execution(rt.is_sealed, rt.allowlist, rt.ledger,
                                                                  rt.decisions))
    _step(rt, "tool_execution", tool_mw)

    def pre_tool():
        gt = _cm("gate_tools")
        _hook(rt, "pre_tool_call", gt.build_pre_tool_call(rt.is_sealed, rt.allowlist, rt.ledger,
                                                           decisions=rt.decisions))
    _step(rt, "pre_tool_call", pre_tool)

    def post_approval():
        gt = _cm("gate_tools")
        _hook(rt, "post_approval_response", gt.build_post_approval_response(rt.is_sealed, rt.ledger, rt.decisions))
    _step(rt, "post_approval_response", post_approval)

    for name, builder in (("pre_llm_call", _pre_llm_call), ("pre_api_request", _pre_api_request),
                          ("pre_auxiliary_call", _pre_auxiliary_call),
                          ("post_auxiliary_call", _post_auxiliary_call),
                          ("on_session_start", _session_marker("session_start")),
                          ("on_session_end", _session_marker("session_end")),
                          ("post_compaction", _post_compaction), ("pre_gateway_dispatch", _pre_gateway_dispatch)):
        _step(rt, name, lambda name=name, builder=builder: _hook(rt, name, builder(rt)))

    def slash():
        _cm("commands").register_slash(ctx, rt)
        rt.registered["commands"].append("confidential")
    _step(rt, "slash_command", slash)

    def cli():
        _cm("commands").register_cli(ctx, rt)
        rt.registered["cli_commands"].append("confidential")
    _step(rt, "cli_command", cli)


# ── hooks ────────────────────────────────────────────────────────────────────────────────────────

def _pre_llm_call(rt: Runtime):
    def pre_llm_call(session_id: str = "", **_kw: Any):
        try:
            gate_llm, sealing = _cm("gate_llm"), _cm("sealing")
        except Exception:  # noqa: BLE001
            return {"action": "block", "message": "Confidential mode: the plugin failed to load; turn not sent."}
        try:
            sealed, tier = rt.is_sealed()
        except Exception:  # noqa: BLE001 - unreadable seal state blocks (Amendment 2)
            return {"action": "block", "message": gate_llm.TEXT_STATE_UNREADABLE}
        if sealed is not True:
            return None
        try:
            message = sealing.recheck(state=rt.state, ledger=rt.ledger, config=rt.load_config(),
                                      session_id=session_id or "")
        except Exception as exc:  # noqa: BLE001
            message = (f"Confidential mode: the sealed-config recheck failed ({type(exc).__name__}), so this turn "
                       "was not sent. Run /confidential check.")
        if message:
            return {"action": "block", "message": message}
        try:
            message = _live_runtime_check(rt, sealing, tier, session_id or "")
        except Exception as exc:  # noqa: BLE001
            message = (f"Confidential mode: the live-runtime check failed ({type(exc).__name__}), so this turn "
                       "was not sent. Run /confidential status.")
        if message:
            return {"action": "block", "message": message}
        return {"context": sealing.SEALED_NOTE.format(tier=tier.value)}
    return pre_llm_call


def _live_runtime_check(rt: Runtime, sealing: Any, tier: Any, session_id: str) -> Optional[str]:
    """Amendment 4 F1(a): the live main runtime (what "auto" aux tasks and the main call use) must be in-tier.
    It is published at agent/turn_context.py:1140, before this hook (:1236); turn-start compaction (:1245),
    memory prefetch (:1264) and titling (:1271) all run after it and are skipped when it blocks."""
    runtime = sealing.live_main_runtime()
    if not runtime:
        return None
    v = sealing.classify_live_runtime(tier, runtime, config=rt.load_config())
    rt.last_live = {"provider": runtime.get("provider"), "model": runtime.get("model"), "host": v.host,
                    "in_tier": v.in_tier is True, "reason": v.reason}
    if v.in_tier is True:
        return None
    provider = str(runtime.get("provider") or "")
    rt.append({"kind": "send_refused", "session_id": session_id, "purpose": "main", "provider": provider,
               "host": v.host, "model": str(runtime.get("model") or ""), "tier": tier.value, "verdict": "off_tier",
               "decision": "refused", "detail": {"reason_code": "live_runtime_off_tier", "reason": v.reason}})
    try:
        already = rt.state.is_breached(session_id or NO_SESSION)
    except Exception:  # noqa: BLE001
        already = False
    if not already:
        # The runtime drifted before this turn: auxiliary work between turns may already have used it.
        try:
            rt.state.mark_breached(session_id or NO_SESSION)
        except Exception:  # noqa: BLE001
            pass
        rt.append({"kind": "breach", "session_id": session_id, "purpose": "main:live_runtime", "provider": provider,
                   "host": v.host, "tier": tier.value, "verdict": "off_tier", "decision": "live_runtime_off_tier",
                   "detail": {"reason": v.reason}})
    return sealing.live_runtime_text(tier, provider, v.host, v.reason)


def _pre_gateway_dispatch(rt: Runtime):
    def pre_gateway_dispatch(event: Any = None, **_kw: Any):
        """While sealed, a gateway /model (or /moa) is rewritten to /confidential blocked <cmd>, which
        replies with the refusal: the session's live runtime cannot be switched off-tier from chat."""
        try:
            text = getattr(event, "text", None)
            if not isinstance(text, str) or not text.lstrip().startswith("/"):
                return None
            word = text.strip()[1:].split(None, 1)[0] if text.strip()[1:] else ""
            name = word.split("@", 1)[0].lower()
            canonical = name
            try:
                from hermes_cli.commands import resolve_command
                found = resolve_command(name)
                canonical = str(getattr(found, "name", None) or name).lower()
            except Exception:  # noqa: BLE001
                pass
            if canonical not in RUNTIME_SWITCH_COMMANDS:
                return None
            try:
                sealed, _tier = rt.is_sealed()
            except Exception:  # noqa: BLE001
                sealed = True                      # unreadable seal state: refuse (fail closed)
            if sealed is False:
                return None
            rt.append({"kind": "tool_refused", "purpose": f"command:{canonical}", "decision": "runtime_switch",
                       "surface": "gateway", "detail": {"command": canonical}})
            return {"action": "rewrite", "text": f"/confidential blocked {canonical}"}
        except Exception:  # noqa: BLE001
            return None
    return pre_gateway_dispatch


def _bytes_of(request: Any, chars: Any) -> Optional[int]:
    n = _cm("gate_llm").request_bytes(request) if request is not None else None
    if n is None and isinstance(chars, int) and not isinstance(chars, bool):
        n = chars
    return n


def _observe(rt: Runtime, *, purpose: str, provider: Any, base_url: Any, model: Any, api_mode: Any,
             session_id: Any, request: Any, chars: Any, platform: Any, decision: str, source: str,
             breach_on_off_tier: bool) -> None:
    tiers, sealing = _cm("tiers"), _cm("sealing")
    dest = tiers.Destination(provider=str(provider or ""), base_url=str(base_url or ""), model=str(model or ""),
                             api_mode=str(api_mode or ""), purpose=purpose)
    host = tiers.host_of(dest.base_url)
    tier_value = verdict_label = reason = None
    off = False
    try:
        sealed, tier = rt.is_sealed()
    except Exception:  # noqa: BLE001
        sealed, tier = None, None
        verdict_label, reason, off = "error", "seal state unreadable", True
    if sealed is True:
        tier_value = tier.value
        try:
            v = sealing.structural_predicate(tier, config=rt.load_config()).classify(dest)
            off, reason = not (v.in_tier is True), v.reason
            host = v.host or host
        except Exception as exc:  # noqa: BLE001
            off, reason = True, f"tier check failed ({type(exc).__name__})"
        verdict_label = "off_tier" if off else "in_tier"
    sid = str(session_id or "")
    nbytes = _bytes_of(request, chars)
    rt.append({"kind": "send_observed", "session_id": sid, "purpose": purpose, "provider": dest.provider,
               "host": host, "model": dest.model, "bytes": nbytes, "tier": tier_value,
               "verdict": verdict_label, "decision": decision, "surface": str(platform or "") or None,
               "detail": {"source": source, **({"reason": reason} if reason else {})}})
    if breach_on_off_tier and sealed is not False and off:
        try:
            rt.state.mark_breached(sid or NO_SESSION)
        except Exception:  # noqa: BLE001
            pass
        rt.append({"kind": "breach", "session_id": sid, "purpose": purpose, "provider": dest.provider, "host": host,
                   "model": dest.model, "bytes": nbytes, "tier": tier_value, "verdict": "off_tier",
                   "decision": "aux_sent", "surface": str(platform or "") or None,
                   "detail": {"source": source, "reason": reason or ""}})


def _pre_api_request(rt: Runtime):
    def pre_api_request(provider: str = "", base_url: str = "", model: str = "", api_mode: str = "",
                        session_id: str = "", request: Any = None, request_char_count: Any = None,
                        platform: str = "", **_kw: Any) -> None:
        # The main call's outcome is ledgered by the llm gate (allowed/refused); this row is the attempt.
        try:
            _observe(rt, purpose="main", provider=provider, base_url=base_url, model=model, api_mode=api_mode,
                     session_id=session_id, request=request, chars=request_char_count, platform=platform,
                     decision="attempt", source="pre_api_request", breach_on_off_tier=False)
        except Exception:  # noqa: BLE001
            pass
        return None
    return pre_api_request


def _aux(rt: Runtime, source: str):
    def aux_call(aux_task: str = "", provider: str = "", base_url: str = "", model: str = "", api_mode: str = "",
                 session_id: str = "", request: Any = None, request_char_count: Any = None, platform: str = "",
                 api_request_id: str = "", **_kw: Any) -> None:
        try:
            if source == "post_auxiliary_call":
                if api_request_id and api_request_id in rt._aux_seen:
                    return None              # already observed (and judged) by pre_auxiliary_call
            elif api_request_id:
                rt._aux_seen.append(api_request_id)
            _observe(rt, purpose=f"aux:{aux_task or '?'}", provider=provider, base_url=base_url, model=model,
                     api_mode=api_mode, session_id=session_id, request=request, chars=request_char_count,
                     platform=platform, decision="observed", source=source, breach_on_off_tier=True)
        except Exception:  # noqa: BLE001
            pass
        return None
    aux_call.__name__ = source
    return aux_call


def _pre_auxiliary_call(rt: Runtime):
    return _aux(rt, "pre_auxiliary_call")


def _post_auxiliary_call(rt: Runtime):
    return _aux(rt, "post_auxiliary_call")


def _session_marker(decision: str):
    def build(rt: Runtime):
        def marker(session_id: str = "", platform: str = "", **_kw: Any) -> None:
            try:
                sealed, tier = rt.is_sealed()
            except Exception:  # noqa: BLE001
                sealed, tier = None, None
            if sealed is False:
                return None
            rt.append({"kind": decision, "session_id": str(session_id or ""), "purpose": "session",
                       "tier": tier.value if tier else None, "decision": decision,
                       "surface": str(platform or "") or None, "detail": {"sealed": sealed is True}})
            return None
        marker.__name__ = f"on_{decision}"
        return marker
    return build


def _post_compaction(rt: Runtime):
    def post_compaction(session_id: str = "", old_session_id: str = "", kind: Any = None, reason: Any = None,
                        before_tokens: Any = None, after_tokens: Any = None, messages_removed: Any = None,
                        **_kw: Any) -> None:
        try:
            sealed, tier = rt.is_sealed()
        except Exception:  # noqa: BLE001
            sealed, tier = None, None
        rt.append({"kind": "compaction", "session_id": str(session_id or ""), "purpose": "compaction",
                   "tier": tier.value if sealed is True else None, "decision": str(kind or "") or None,
                   "detail": {"old_session_id": str(old_session_id or ""), "reason": str(reason or ""),
                              "before_tokens": before_tokens if isinstance(before_tokens, int) else None,
                              "after_tokens": after_tokens if isinstance(after_tokens, int) else None,
                              "messages_removed": messages_removed if isinstance(messages_removed, int) else None}})
        return None
    return post_compaction

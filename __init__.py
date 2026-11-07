"""hermes-confidential-mode: attested inference provider plus locked mode for Hermes Agent.

``register(ctx)`` wires one Ledger, one ConfidentialState and one ApprovalDecisions into:

- llm_execution middleware (gate_llm): every main-loop provider call is checked against the locked
  tier; the predicate also refuses everything if the routing config changed since lock;
- tool_execution middleware + pre_tool_call + post_approval_response (gate_tools), sharing ONE
  ApprovalDecisions (the hook asks, the middleware enforces on the recorded exact answer);
- pre_llm_call: locked note into the model's context, and the per-turn config recheck (block);
- pre_api_request / pre_auxiliary_call / post_auxiliary_call: ledger ``send_observed`` with host and
  bytes; an off-tier auxiliary destination while locked is a breach (aux calls cannot be blocked);
- on_session_start / on_session_end / post_compaction: receipt rows;
- the 'attested-tinfoil' and 'attested-near' provider profiles (no network at register);
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
# locked. The CLI/TUI never fire pre_gateway_dispatch: there the per-turn live-runtime check ends the turn.
RUNTIME_SWITCH_COMMANDS = frozenset({"model", "moa"})
# Built-ins kept usable while locked when the command table cannot be read (second review, minor item):
# stopping the agent, answering the plugin's own approval prompts, a new session, help and status. None of
# them switches the model runtime. Matched on the exact typed word, so an alias is refused.
UNRESOLVED_SAFE_COMMANDS = frozenset({"confidential", "stop", "pause", "approve", "deny", "new", "help", "status"})
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
        self.near_profile: Any = None
        self.near_adapter: Any = None
        self.allowlist_path: Any = None
        self.registered: dict[str, list[str]] = {"hooks": [], "middleware": [], "commands": [],
                                                 "cli_commands": [], "providers": []}
        self.errors: list[tuple[str, str]] = []
        self._allowlist: Any = None
        self._allowlist_stamp: Any = None
        self.revocations: Any = None             # revoke.RevocationWatcher (Amendment 10)
        self._lock = threading.Lock()
        self._aux_seen: deque = deque(maxlen=512)
        self.last_live: Optional[dict] = None      # last live main runtime seen by pre_llm_call (status)
        # Amendment 9: the lock (its locked_since) whose first plaintext image part was already noticed,
        # and the sessions whose next reply gets the one-line notice.
        self.image_notice_lock: Any = _NO_LOCK
        self.reply_notices: dict = {}
        self._notice_lock = threading.Lock()

    # ── shared collaborators ──────────────────────────────────────────────────────────────────
    def module(self, name: str):
        return _cm(name)

    def load_config(self) -> dict:
        return _cm("preflight").load_core_config()

    def is_locked(self):
        if self.state is None:
            raise _cm("state").StateError("confidential state is unavailable")
        return self.state.locked()

    def set_allowlist(self, allowlist: Any) -> None:
        with self._lock:
            self._allowlist = allowlist
            self._allowlist_stamp = self._file_stamp()

    def _file_stamp(self):
        """(mtime_ns, size) of the persisted allowlist, or None. A lock, unlock or allow from ANOTHER
        process (the `hermes confidential` CLI next to a running gateway) changes it."""
        try:
            st = os.stat(self.allowlist_path)
            return st.st_mtime_ns, st.st_size
        except Exception:  # noqa: BLE001
            return None

    def allowlist(self):
        """The allowlist for the CURRENT lock. The lock lives in ctx.state (re-read from disk on every
        call), so another process may have locked, unlocked or relocked since this one cached its
        allowlist: the cache is used only while its lock_id matches the persisted lock, and additions
        another process approved (allowlist.yaml changed, same lock) are merged in. After a restart, or a
        lock made by another process, it is rebuilt from the identities persisted at that lock and ledgered."""
        gt = _cm("gate_tools")
        if self.revocations is not None:   # a revoke made in another process, before any grant is read
            self.revocations.apply()
        try:
            locked, tier = self.is_locked()
        except Exception:  # noqa: BLE001
            locked, tier = False, None
        if locked is not True:
            with self._lock:
                self._allowlist = None
            return gt.Allowlist(tools={})
        lock_id = gt.lock_id_for(self.state)
        stamp = self._file_stamp()
        with self._lock:
            cached = self._allowlist
            if cached is not None and getattr(cached, "lock_id", "") == lock_id:
                if stamp == self._allowlist_stamp:
                    return cached
                if getattr(cached, "tools", None):
                    _merge_added(cached, self.allowlist_path, lock_id)
                    self._allowlist_stamp = stamp
                    return cached
                # Review finding 9: an EMPTY cached allowlist for this lock (the file was missing or
                # unreadable when this process first looked) is rebuilt from the file once it changes,
                # not merged into; merging adds approvals only and would keep every tool blocked.
                self._allowlist = None
        from tools.registry import registry
        # A CLI process (`hermes confidential allow`) has not imported the built-in tools; without them the
        # rebuild below would keep no built-in tool, and every allow would be refused as unregistered.
        gt.ensure_builtin_tools()
        predicate = _cm("locking").predicate_for(tier, config=self.load_config())
        # Amendment 4 F5 (W4): rebuild from the identities persisted at THIS lock; anything registered
        # after the lock, changed, or a missing/other-lock file is unclassified until a relock.
        allowlist = gt.Allowlist.load_persisted(self.allowlist_path, registry, predicate=predicate, lock_id=lock_id)
        with self._lock:
            current = self._allowlist
            if current is None or getattr(current, "lock_id", "") != lock_id or not getattr(current, "tools", None):
                self._allowlist, self._allowlist_stamp = allowlist, stamp
            allowlist = self._allowlist
        # Not kind "lock": receipts open a locked period at every lock row (Amendment 4 F7).
        self.append({"kind": "session_start", "purpose": "lock", "tier": tier.value, "decision": "allowlist_rebuilt",
                     "detail": {"tools": len(allowlist.tools)}})
        return allowlist

    def predicate_for(self, tier):
        """The locked tier's predicate for the llm gate. If the routing config no longer matches the
        fingerprint recorded at lock, every destination is off-tier (second line behind pre_llm_call,
        which Hermes skips for agents with persistence disabled: agent/turn_context.py:860)."""
        locking = _cm("locking")
        config = self.load_config()
        if not locking.fingerprint_matches(self.state.config_fingerprint(), config,
                                           plugin_aux_tasks=locking._plugin_aux(None)):
            return _ChangedConfigPredicate(_cm("tiers").Tier(tier))
        return locking.predicate_for(tier, config=config)

    def pin_pending(self) -> bool:
        return self.pins is not None and self.pins.pending() is not None

    def append(self, event: Any) -> None:
        try:
            if self.ledger is not None:
                self.ledger.append(event)
        except Exception as exc:  # noqa: BLE001
            logger.warning("confidential-mode ledger append failed: %s", type(exc).__name__)


def _merge_added(allowlist: Any, path: Any, lock_id: str) -> None:
    """Take the human-approved additions persisted for the SAME lock as ``allowlist.added``: additions
    another process approved are added, and names another process revoked (Amendment 10) are dropped.
    Only names still on the ask route count; a file for another lock changes nothing."""
    import json
    try:
        data = json.loads(open(path, encoding="utf-8").read())
    except Exception:  # noqa: BLE001
        return
    if not isinstance(data, dict) or data.get("lock_id") != lock_id or not isinstance(data.get("allowed"), list):
        return
    route_ask = _cm("gate_tools").Route.ASK
    names = {n for n in data["allowed"] if isinstance(n, str)
             and getattr(allowlist.tools.get(n), "route", None) is route_ask}
    with allowlist._lock:
        allowlist.added = names


class _ChangedConfigPredicate:
    REASON = "routing config changed since lock; run /confidential off and lock again"

    def __init__(self, tier):
        self.tier = tier

    def classify(self, dest):
        tiers = _cm("tiers")
        return tiers.Verdict(False, self.REASON, tiers.host_of(dest.base_url))


# ── registration steps ───────────────────────────────────────────────────────────────────────────

def _locked_now(rt: Runtime) -> bool:
    """True only when the persisted state reads locked on the attested tier. Never raises (unreadable counts as not locked,
    which stops the background refresh; the gates fail closed on their own)."""
    try:
        locked, tier = rt.is_locked()
        return locked is True and getattr(tier, "value", tier) == "attested"
    except Exception:  # noqa: BLE001
        return False


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

    def revocations():
        rv = _cm("revoke")

        def drop_added(tools):
            al = rt._allowlist
            if al is not None:
                with al._lock:
                    al.added -= {n for n in al.added if tools is None or n in tools}
        def on_error(tools, error):
            rt.append({"kind": "grant_revoked", "purpose": f"tool:{','.join(sorted(tools)) if tools else '*'}",
                       "decision": "apply_failed", "detail": {"tools": sorted(tools) if tools else ["*"],
                                                              "errors": [error], "session_dropped": False}})
        rt.revocations = rv.RevocationWatcher(rv.revocations_path(rt.allowlist_path), drop_added=drop_added,
                                              on_error=on_error)
        rt.revocations.baseline()
    _step(rt, "revocations", revocations)

    def provider_profile():
        provider = _cm("provider")
        # ledger= : the verification cache ledgers verify_ok/verify_fail/pin_staged (Amendment 4 F4).
        profile = provider.register_provider_profile(ctx, config=rt.load_config(), ledger=rt.ledger)
        rt.profile = profile
        rt.pins = getattr(profile, "_confidential_pins", None)
        rt.adapter = getattr(profile, "_confidential_adapter", None)
        rt.registered["providers"].append(profile.name)
    _step(rt, "provider", provider_profile)

    def near_profile():
        # Amendment 5: NEAR AI Cloud, same verification cache, pins file and ledger as Tinfoil's.
        provider = _cm("provider")
        profile = provider.register_near_profile(ctx, config=rt.load_config(), ledger=rt.ledger, pins=rt.pins)
        rt.near_profile = profile
        rt.near_adapter = getattr(profile, "_confidential_adapter", None)
        if rt.near_adapter is not None and hasattr(rt.near_adapter, "on_plaintext_parts"):
            rt.near_adapter.on_plaintext_parts = _image_notice(rt)   # Amendment 9
        rt.registered["providers"].append(profile.name)
    _step(rt, "provider_near", near_profile)

    def background_gate():
        # Amendment 9: the background re-verification runs only while this profile is locked on the attested
        # tier. Its own step, so a failed Tinfoil or NEAR registration does not leave it unset.
        _cm("provider").set_background_gate(lambda: _locked_now(rt))
    _step(rt, "background_refresh_gate", background_gate)
    if rt.pins is None:
        def fallback_pins():
            rt.pins = _cm("pins").PinStore(ctx.state.data_dir / "pins.yaml")
        _step(rt, "pins", fallback_pins)

    # -- llm gate -----------------------------------------------------------------------------
    def llm():
        provider = _cm("provider")
        mw = _cm("gate_llm").build_middleware(ledger=rt.ledger, is_locked=rt.is_locked,
                                               predicate_for=rt.predicate_for, attested_ok=provider.attested_ok,
                                               pin_pending=rt.pin_pending)
        _middleware(rt, "llm_execution", mw)
    _step(rt, "llm_execution", llm)

    # -- tool gate: one ApprovalDecisions shared by all three (gate_tools.build_pre_tool_call doc) ---
    def tool_mw():
        gt = _cm("gate_tools")
        _middleware(rt, "tool_execution", gt.build_tool_execution(rt.is_locked, rt.allowlist, rt.ledger,
                                                                  rt.decisions))
    _step(rt, "tool_execution", tool_mw)

    def pre_tool():
        gt = _cm("gate_tools")
        _hook(rt, "pre_tool_call", gt.build_pre_tool_call(rt.is_locked, rt.allowlist, rt.ledger,
                                                           decisions=rt.decisions))
    _step(rt, "pre_tool_call", pre_tool)

    def post_approval():
        gt = _cm("gate_tools")
        _hook(rt, "post_approval_response", gt.build_post_approval_response(rt.is_locked, rt.ledger, rt.decisions))
    _step(rt, "post_approval_response", post_approval)

    for name, builder in (("pre_llm_call", _pre_llm_call), ("pre_api_request", _pre_api_request),
                          ("pre_auxiliary_call", _pre_auxiliary_call),
                          ("post_auxiliary_call", _post_auxiliary_call),
                          ("on_session_start", _session_marker("session_start")),
                          ("on_session_end", _session_marker("session_end")),
                          ("post_compaction", _post_compaction), ("pre_gateway_dispatch", _pre_gateway_dispatch),
                          ("transform_llm_output", _transform_llm_output)):
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

_NO_LOCK = object()
def image_notice_line(parts: Any) -> str:
    """The reply line, naming the part types that left in plaintext, for example "Confidential mode: an image
    part (image_url) in this turn went to NEAR's gateway in plaintext; the text around it was encrypted." """
    types = (parts or {}).get("types") if isinstance(parts, dict) else None
    types = types if isinstance(types, dict) and types else {"image_url": 1}
    n = sum(int(v) for v in types.values() if isinstance(v, int)) or 1
    names = ", ".join(sorted(types))
    what = f"an image part ({names})" if n == 1 else f"{n} image parts ({names})"
    return (f"Confidential mode: {what} in this turn went to NEAR's gateway in plaintext; the text around "
            f"{'it' if n == 1 else 'them'} was encrypted.")


def _image_notice(rt: Runtime):
    """NearAdapter.on_plaintext_parts: the first time per lock an image part left as plaintext to NEAR's
    gateway, write a ``notice`` ledger row and, once that row is written, mark the session so
    ``transform_llm_output`` appends the line naming the part types to its next reply. A failed write
    leaves the lock unmarked, so the next image tries again. An unreadable lock time never deduplicates.
    Every send's own row already records the parts. Never raises."""
    def notice(context: dict, row: dict) -> None:
        try:
            locked, tier = rt.is_locked()
            if locked is not True:
                return
            try:
                since = rt.state.locked_since()
            except Exception:  # noqa: BLE001
                since = None
            sid = str((context or {}).get("session_id") or "")
            with rt._notice_lock:        # one notice row per lock, even for images sent concurrently
                if since is not None and rt.image_notice_lock == since:
                    return
                d = row.get("detail") or {}
                line = image_notice_line(d.get("plaintext_parts"))
                rt.ledger.append({"kind": "notice", "session_id": sid, "purpose": row.get("purpose") or "",
                                  "provider": row.get("provider") or "", "host": row.get("host") or "",
                                  "model": row.get("model") or "", "tier": getattr(tier, "value", None),
                                  "verdict": "disclosed", "decision": "image_plaintext",
                                  "detail": {"notice": line, "note": d.get("plaintext_parts_note"),
                                             "plaintext_parts": d.get("plaintext_parts"), "chat_id": d.get("chat_id"),
                                             "locked_since": since, "reply_line": "transform_llm_output"}})
                with rt._lock:
                    rt.image_notice_lock = since
                    rt.reply_notices[sid] = line
            logger.info("confidential-mode: %s", d.get("plaintext_parts_note"))
        except Exception:  # noqa: BLE001
            logger.warning("confidential-mode: could not record the plaintext image notice", exc_info=True)
    return notice


def _transform_llm_output(rt: Runtime):
    """Append the image notice line to the reply of a session whose turn sent the lock's first plaintext image
    part to NEAR (a notice with no session id goes to the next reply). Returns None otherwise, so the reply
    is unchanged. Never raises."""
    def transform(response_text: str = "", session_id: str = "", **_kw: Any):
        try:
            if not rt.reply_notices or not isinstance(response_text, str) or not response_text:
                return None
            sid = str(session_id or "")
            with rt._lock:
                key = sid if sid in rt.reply_notices else ("" if "" in rt.reply_notices else None)
                if key is None:
                    return None
                line = rt.reply_notices.pop(key)
            return f"{response_text.rstrip()}\n\n{line}"
        except Exception:  # noqa: BLE001
            return None
    return transform


def _pre_llm_call(rt: Runtime):
    def pre_llm_call(session_id: str = "", **_kw: Any):
        try:
            gate_llm, locking = _cm("gate_llm"), _cm("locking")
        except Exception:  # noqa: BLE001
            return {"action": "block", "message": "Confidential mode: the plugin failed to load; turn not sent."}
        try:
            locked, tier = rt.is_locked()
        except Exception:  # noqa: BLE001 - unreadable lock state blocks (Amendment 2)
            return {"action": "block", "message": gate_llm.TEXT_STATE_UNREADABLE}
        if locked is not True:
            return None
        try:
            message = locking.recheck(state=rt.state, ledger=rt.ledger, config=rt.load_config(),
                                      session_id=session_id or "")
        except Exception as exc:  # noqa: BLE001
            message = (f"Confidential mode: the locked-config recheck failed ({type(exc).__name__}), so this turn "
                       "was not sent. Run /confidential check.")
        if message:
            return {"action": "block", "message": message}
        try:
            message = _live_runtime_check(rt, locking, tier, session_id or "")
        except Exception as exc:  # noqa: BLE001
            message = (f"Confidential mode: the live-runtime check failed ({type(exc).__name__}), so this turn "
                       "was not sent. Run /confidential status.")
        if message:
            return {"action": "block", "message": message}
        return {"context": locking.LOCKED_NOTE.format(tier=tier.value)}
    return pre_llm_call


def _live_runtime_check(rt: Runtime, locking: Any, tier: Any, session_id: str) -> Optional[str]:
    """Amendment 4 F1(a): the live main runtime (what "auto" aux tasks and the main call use) must be in-tier.
    It is published at agent/turn_context.py:1140, before this hook (:1236); turn-start compaction (:1245),
    memory prefetch (:1264) and titling (:1271) all run after it and are skipped when it blocks."""
    try:
        runtime = locking.live_main_runtime()
    except Exception as exc:  # noqa: BLE001 - review finding 8: cannot read the runtime => block and record
        rt.last_live = {"provider": "", "model": "", "host": "", "in_tier": False,
                        "reason": f"live runtime unreadable ({type(exc).__name__})"}
        rt.append({"kind": "send_refused", "session_id": session_id, "purpose": "main", "tier": tier.value,
                   "verdict": "error", "decision": "refused",
                   "detail": {"reason_code": "live_runtime_unreadable", "error_type": type(exc).__name__}})
        return getattr(locking, "LIVE_RUNTIME_UNREADABLE_TEXT", None) or (
            "Confidential mode: the live model runtime cannot be read, so this turn was not sent.")
    if not runtime:
        return None
    v = locking.classify_live_runtime(tier, runtime, config=rt.load_config())
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
    return locking.live_runtime_text(tier, provider, v.host, v.reason)


def _pre_gateway_dispatch(rt: Runtime):
    def pre_gateway_dispatch(event: Any = None, **_kw: Any):
        """While locked, a gateway /model (or /moa) is rewritten to /confidential blocked <cmd>, which
        replies with the refusal: the session's live runtime cannot be switched off-tier from chat."""
        try:
            text = getattr(event, "text", None)
            if not isinstance(text, str) or not text.lstrip().startswith("/"):
                return None
            word = text.strip()[1:].split(None, 1)[0] if text.strip()[1:] else ""
            name = word.split("@", 1)[0].lower()
            canonical, resolved = name, True
            try:
                from hermes_cli.commands import resolve_command
                found = resolve_command(name)
                canonical = str(getattr(found, "name", None) or name).lower()
            except Exception:  # noqa: BLE001
                resolved = False
            if resolved and canonical not in RUNTIME_SWITCH_COMMANDS:
                return None
            if not resolved and name in UNRESOLVED_SAFE_COMMANDS:
                return None                        # /confidential to unlock, and the escape hatches
            # Review finding 27: without resolve_command an alias of /model cannot be recognised, so while
            # locked every other slash command is refused (fail closed) instead of matching the typed word.
            try:
                locked, _tier = rt.is_locked()
            except Exception:  # noqa: BLE001
                locked = True                      # unreadable lock state: refuse (fail closed)
            if locked is False:
                return None
            rt.append({"kind": "tool_refused", "purpose": f"command:{canonical}",
                       "decision": "runtime_switch" if resolved else "command_unresolved",
                       "surface": "gateway", "detail": {"command": canonical, "resolved": resolved}})
            return {"action": "rewrite",
                    "text": f"/confidential blocked {canonical}" + ("" if resolved else " unresolved")}
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
    tiers, locking = _cm("tiers"), _cm("locking")
    dest = tiers.Destination(provider=str(provider or ""), base_url=str(base_url or ""), model=str(model or ""),
                             api_mode=str(api_mode or ""), purpose=purpose)
    host = tiers.host_of(dest.base_url)
    tier_value = verdict_label = reason = None
    off = False
    try:
        locked, tier = rt.is_locked()
    except Exception:  # noqa: BLE001
        locked, tier = None, None
        verdict_label, reason, off = "error", "lock state unreadable", True
    if locked is True:
        tier_value = tier.value
        try:
            v = locking.structural_predicate(tier, config=rt.load_config()).classify(dest)
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
    if breach_on_off_tier and locked is not False and off:
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
        _aux_send_context(rt, source, api_request_id=api_request_id, session_id=session_id)
        return None
    aux_call.__name__ = source
    return aux_call


def _aux_send_context(rt: Runtime, source: str, *, api_request_id: Any, session_id: Any) -> None:
    """Note session and tier for the vendor adapters' own rows (NEAR's send_signed and send_refused) during
    one auxiliary call, keyed by Hermes' relay request id (sendctx.note_aux). Never raises."""
    if source != "pre_auxiliary_call":
        return
    try:
        tier = None
        try:
            locked, t = rt.is_locked()
            tier = t.value if locked is True and t is not None else None
        except Exception:  # noqa: BLE001
            pass
        _cm("sendctx").note_aux(str(api_request_id or ""), session_id=str(session_id or ""), tier=tier)
    except Exception:  # noqa: BLE001
        pass


def _pre_auxiliary_call(rt: Runtime):
    return _aux(rt, "pre_auxiliary_call")


def _post_auxiliary_call(rt: Runtime):
    return _aux(rt, "post_auxiliary_call")


def _session_marker(decision: str):
    def build(rt: Runtime):
        def marker(session_id: str = "", platform: str = "", **_kw: Any) -> None:
            try:
                locked, tier = rt.is_locked()
            except Exception:  # noqa: BLE001
                locked, tier = None, None
            if locked is False:
                return None
            rt.append({"kind": decision, "session_id": str(session_id or ""), "purpose": "session",
                       "tier": tier.value if tier else None, "decision": decision,
                       "surface": str(platform or "") or None, "detail": {"locked": locked is True}})
            return None
        marker.__name__ = f"on_{decision}"
        return marker
    return build


def _post_compaction(rt: Runtime):
    def post_compaction(session_id: str = "", old_session_id: str = "", kind: Any = None, reason: Any = None,
                        before_tokens: Any = None, after_tokens: Any = None, messages_removed: Any = None,
                        **_kw: Any) -> None:
        try:
            locked, tier = rt.is_locked()
        except Exception:  # noqa: BLE001
            locked, tier = None, None
        rt.append({"kind": "compaction", "session_id": str(session_id or ""), "purpose": "compaction",
                   "tier": tier.value if locked is True else None, "decision": str(kind or "") or None,
                   "detail": {"old_session_id": str(old_session_id or ""), "reason": str(reason or ""),
                              "before_tokens": before_tokens if isinstance(before_tokens, int) else None,
                              "after_tokens": after_tokens if isinstance(after_tokens, int) else None,
                              "messages_removed": messages_removed if isinstance(messages_removed, int) else None}})
        return None
    return post_compaction

"""``/confidential`` slash command and ``hermes confidential`` CLI command (W5).

Slash (``ctx.register_command``; the handler is a plain ``def``, so the gateway runs it on an executor
thread, which consent.py's ask_choice needs):

    /confidential on <on-host-only|attested|zero-retention>   lock (preflight first; refuses with the report)
    /confidential off                                         unlock (also repairs unreadable lock state)
    /confidential status                                      tier, route, enclave, pins, verification, breaches
    /confidential check [tier]                                the preflight table
    /confidential pins                                        pins, pending pin, approval history, tool grants
    /confidential pins approve                                approve the staged pin (ask_choice)
    /confidential receipts [session]                          receipt (confidential_mode.receipts, when present)
    /confidential allow <tool>                                add an off-host tool for this lock (ask_choice)
    /confidential watch                                       the latest ledger rows

CLI (``ctx.register_cli_command``): ``hermes confidential setup|check|watch|status``.

``rt`` is the plugin runtime from the root ``__init__`` (ledger, state, pins, adapter, allowlist).
"""
from __future__ import annotations

import argparse
import importlib
import io
import json
import os
import shlex
import sys
import time
from typing import Any, Callable, Optional

from . import preflight as _pf
from . import locking as _locking
from .tiers import Tier

PROFILE_NAME = _locking.PROFILE_NAME
USAGE = ("Usage: /confidential on <on-host-only|attested>|off|status|check [tier]|pins [approve]|"
         "receipts [session]|allow <tool>|watch")
RECEIPTS_PLACEHOLDER = ("Receipts are not available in this build yet (confidential_mode.receipts is missing). "
                        "The raw ledger is visible with /confidential watch or `hermes confidential watch`.")


def _short(fp: Any, n: int = 8) -> str:
    s = str(fp or "")
    return s[:n] if s else "(none)"


# ── shared text builders ─────────────────────────────────────────────────────────────────────────

def _verification_line(rt: Any, clock: Callable[[], float] = time.time) -> str:
    try:
        cache = _provider_module(rt).verification_cache
    except Exception:  # noqa: BLE001
        return "Last verification: unavailable"
    near = _near_verification_line(cache, clock)
    result = cache.result(PROFILE_NAME)
    error = cache.last_error(PROFILE_NAME)
    if near and result is None and not error:
        return near
    if near:
        return _tinfoil_verification_line(result, error, clock) + "\n" + near
    return _tinfoil_verification_line(result, error, clock)


def _near_verification_line(cache: Any, clock: Callable[[], float]) -> str:
    """'' unless the NEAR profile has verified or failed in this process."""
    name = _locking.NEAR_PROFILE_NAME
    try:
        result, error = cache.result(name), cache.last_error(name)
    except Exception:  # noqa: BLE001
        return ""
    if result is not None:
        claims = (result.evidence or {}).get("claims") or {} if isinstance(result.evidence, dict) else {}
        return (f"NEAR verification: {_locking.age_text(clock() - result.verified_at_host_clock)} ago (host clock), "
                f"{result.router_repo}, code {_short(result.code_fingerprint)} enclave "
                f"{_short(result.enclave_fingerprint)}, gateway TCB {claims.get('tcb_status') or 'unknown'}")
    if error:
        return f"NEAR verification: failed ({error[:120]})"
    return ""


def _tinfoil_verification_line(result: Any, error: Any, clock: Callable[[], float]) -> str:
    if result is not None:
        return (f"Last verification: {_locking.age_text(clock() - result.verified_at_host_clock)} ago (host clock), "
                f"code {_short(result.code_fingerprint)} enclave {_short(result.enclave_fingerprint)}"
                f"{' release ' + result.release_tag if result.release_tag else ''}")
    if error:
        return f"Last verification: failed ({error[:120]})"
    return "Last verification: never in this process (host clock)"


def _provider_module(rt: Any):
    """The provider module the runtime registered (the plugin's own package copy)."""
    return importlib.import_module(__package__ + ".provider")


def _pin_lines(rt: Any) -> list[str]:
    lines = []
    pins = getattr(rt, "pins", None)
    if pins is None:
        return ["Pins: unavailable (pin store not loaded)"]
    try:
        records, pending = pins.load()
    except Exception as exc:  # noqa: BLE001
        return [f"Pins: unreadable ({type(exc).__name__}: {exc}); attested sends are refused until fixed"]
    if not records:
        lines.append("Pinned: none")
    for rec in records.values():
        lines.append(f"Pinned: {rec.vendor} {rec.router_repo} code {_short(rec.code_fingerprint)} "
                     f"enclave {_short(rec.enclave_fingerprint)} release {rec.release_tag or '(untagged)'} "
                     f"(approved {rec.approved_at} via {rec.approved_via}; previous {_short(rec.previous)})")
    if pending is None:
        lines.append("Pending pin: none")
    else:
        lines.append(f"Pending pin: {pending.vendor} code {_short(pending.code_fingerprint)} enclave "
                     f"{_short(pending.enclave_fingerprint)} release {pending.release_tag or '(untagged)'} "
                     f"staged {pending.staged_at}; run /confidential pins approve")
    return lines


def remembered_grants(session_key: str = "") -> list[str]:
    """Hermes-held once/session/always grants under OUR rule keys (Amendment 2), as 'tool (scope)'."""
    out: list[str] = []
    try:
        from tools import approval
        from .gate_tools import PATTERN_KEY_PREFIX
        with approval._lock:
            session = set(approval._session_approved.get(session_key, set())) if session_key else set()
            permanent = set(approval._permanent_set())
        for key in sorted(permanent):
            if isinstance(key, str) and key.startswith(PATTERN_KEY_PREFIX):
                out.append(f"{key[len(PATTERN_KEY_PREFIX):]} (always)")
        for key in sorted(session):
            if isinstance(key, str) and key.startswith(PATTERN_KEY_PREFIX):
                out.append(f"{key[len(PATTERN_KEY_PREFIX):]} (session)")
    except Exception:  # noqa: BLE001
        pass
    return out


def _grant_lines(rt: Any, session_key: str) -> list[str]:
    added: list[str] = []
    try:
        al = rt._allowlist
        if al is not None:
            added = sorted(al.added)
        elif rt.allowlist_path is not None:
            from .gate_tools import _read_added
            added = sorted(_read_added(rt.allowlist_path))
    except Exception:  # noqa: BLE001
        pass
    remembered = remembered_grants(session_key)
    return [f"Tool grants (allowlist): {', '.join(added) if added else 'none'}",
            f"Tool grants (remembered by Hermes): {', '.join(remembered) if remembered else 'none'}"]


def _main_route_line(config: dict) -> str:
    provider, model, base_url = _locking._main_route(config)
    from .tiers import host_of
    return f"Provider/model: {provider or '(unset)'} / {model or '(unset)'}" + \
        (f" at {host_of(base_url)}" if base_url else "")


def _enclave_line(rt: Any) -> str:
    adapter = getattr(rt, "adapter", None)
    if adapter is None:
        return "Enclave host: (attested provider not registered)"
    try:
        host = adapter.enclave_host
        source = getattr(adapter, "enclave_source", None)
    except Exception:  # noqa: BLE001
        host, source = "", None
    return f"Enclave host: {host or '(unresolved; resolved on first verification)'}" + \
        (f" [{source}]" if host and source else "")


def status_text(rt: Any, *, session_key: str = "", clock: Callable[[], float] = time.time) -> str:
    lines: list[str] = []
    locked = tier = None
    try:
        locked, tier = rt.is_locked()
        if locked:
            since = rt.state.locked_since()
            lines.append(f"Confidential mode: LOCKED ({tier.value}) for "
                         f"{_locking.age_text(clock() - since) if since else '?'} (host clock)")
        else:
            lines.append("Confidential mode: not locked (observing only)")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Confidential mode: lock state UNREADABLE ({type(exc).__name__}); every send and tool is "
                     "refused. Run /confidential off to repair it.")
    try:
        config = rt.load_config()
    except Exception:  # noqa: BLE001
        config = {}
    lines.append(_main_route_line(config))
    lines.append(_live_runtime_line(rt))
    lines.append(_enclave_line(rt))
    lines.extend(_pin_lines(rt))
    lines.append(_verification_line(rt, clock))
    if locked is True:
        try:
            report = _locking.run_tier_preflight(
                tier, config=config, predicate=_locking.structural_predicate(tier, config=config))
            recorded = rt.state.config_fingerprint()
            fp_note = "unchanged since lock" if report.fingerprint == recorded else "CHANGED since lock"
            summary = "PASS" if report.ok else f"FAIL ({', '.join(i.key for i in report.failures()[:5])})"
            lines.append(f"Preflight ({tier.value}, routing config): {summary}; config {fp_note}")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"Preflight: could not run ({type(exc).__name__})")
    else:
        lines.append("Preflight: run /confidential check <tier>")
    try:
        breached = rt.state.breached_sessions()
        since = rt.state.locked_since() if locked else None
        counts = _locking.period_counts(rt.ledger, since) if locked else {}
        flag = "BREACHED" if (locked and counts.get("breach")) else ("none this lock" if locked else "-")
        lines.append(f"Breach: {flag}" + (f"; sessions ever breached: {', '.join(breached[-5:])}" if breached else ""))
        if locked:
            lines.append(f"This lock: {counts.get('refused', 0)} refusal(s), {counts.get('asked', 0)} ask(s), "
                         f"{counts.get('allowed', 0)} allowed")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Breach: unknown ({type(exc).__name__})")
    lines.extend(_grant_lines(rt, session_key))
    for step, err in getattr(rt, "errors", [])[:5]:
        lines.append(f"Plugin registration problem: {step}: {err}")
    lines.append(plugin_identity())
    lines.append(f"Tools: {_locking.TOOLS_TEXT}")
    lines.append(f"Limits: {_locking.AUX_TEXT} {_locking.SAFE_WORKER_TEXT}")
    return "\n".join(lines)


def _live_runtime_line(rt: Any) -> str:
    """The live main runtime (Amendment 4 F1): what the last locked turn ran on, or this context's binding."""
    try:
        live = _locking.live_main_runtime()
    except Exception as exc:  # noqa: BLE001
        return f"Live runtime: UNREADABLE ({exc}); locked turns are refused until the plugin is updated"
    if live:
        from .tiers import host_of
        return (f"Live runtime (this context): {live.get('provider') or '?'} / {live.get('model') or '?'}"
                f" at {host_of(live.get('base_url') or '') or '(provider default)'}")
    last = getattr(rt, "last_live", None)
    if last:
        verdict = "in tier" if last.get("in_tier") else f"OFF-TIER ({last.get('reason')})"
        return (f"Live runtime (last locked turn): {last.get('provider') or '?'} / {last.get('model') or '?'} at "
                f"{last.get('host') or '(no host)'}: {verdict}")
    return "Live runtime: not seen yet (checked at the start of each locked turn)"


def pins_text(rt: Any, *, session_key: str = "") -> str:
    lines = _pin_lines(rt)
    history = []
    try:
        last = 0
        while True:
            rows = rt.ledger.tail(last)
            history.extend(ev for ev in rows if ev.kind in ("pin_staged", "pin_applied", "pin_denied"))
            if len(rows) < 1000:
                break
            last = rows[-1].id
    except Exception:  # noqa: BLE001
        pass
    lines.append("Approval history:" + ("" if history else " none"))
    for ev in history[-20:]:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.ts or 0))
        lines.append(f"  {when}  {ev.kind:<11} {ev.decision or '':<10} via {ev.surface or '?'}"
                     f"  code {_short((ev.detail or {}).get('code_fingerprint'))}")
    lines.extend(_grant_lines(rt, session_key))
    return "\n".join(lines)


INTERACTIVE_VERIFY_WAIT_SECONDS = 60.0   # check / setup / on: a human is waiting; cold attestation ~5-20 s


def interactive_attested_ok(rt: Any, wait_seconds: float = INTERACTIVE_VERIFY_WAIT_SECONDS) -> Callable[[str], Any]:
    """provider.attested_ok with a longer bounded wait for commands a human is waiting on (W2). Resolved at
    call time; an attested_ok without ``wait_seconds`` is called plainly."""
    def call(provider_name: str):
        import inspect
        fn = _provider_module(rt).attested_ok
        try:
            params = inspect.signature(fn).parameters
            takes = "wait_seconds" in params or any(p.kind is p.VAR_KEYWORD for p in params.values())
        except (TypeError, ValueError):
            takes = False
        return fn(provider_name, wait_seconds=wait_seconds) if takes else fn(provider_name)
    return call


def check_text(rt: Any, tier: Optional[str]) -> str:
    try:
        locked, locked_tier = rt.is_locked()
    except Exception:  # noqa: BLE001
        locked, locked_tier = False, None
    chosen = tier or (locked_tier.value if locked and locked_tier else Tier.ATTESTED.value)
    try:
        t = Tier(chosen)
    except ValueError:
        return f"Unknown tier {chosen!r} (one of: {', '.join(x.value for x in Tier)})."
    if t is Tier.ZDR:
        return f"zero-retention: {_locking.ZDR_REASON}."
    report = _locking.run_tier_preflight(t, config=rt.load_config(), attested_ok=interactive_attested_ok(rt))
    return _pf.format_report(report)


def receipts_text(rt: Any, session: str, *, fmt: str = "text") -> str:
    """Delegate to confidential_mode.receipts.render (W6), imported lazily; placeholder if absent."""
    try:
        mod = importlib.import_module(__package__ + ".receipts")
        render = getattr(mod, "render")
    except (ImportError, AttributeError):
        return RECEIPTS_PLACEHOLDER
    if not session:
        return "Usage: /confidential receipts <session id> [--json] (no current session id here)"
    import inspect
    try:
        sig_params = inspect.signature(render).parameters
    except (TypeError, ValueError):
        sig_params = {}
    accepts_any = any(p.kind is p.VAR_KEYWORD for p in sig_params.values())
    params = _AcceptsAll() if accepts_any else sig_params
    kwargs: dict = {}
    if "pins" in params:
        kwargs["pins"] = rt.pins
    if "fmt" in params:
        kwargs["fmt"] = fmt
    try:
        config = rt.load_config()
    except Exception:  # noqa: BLE001
        config = {}
    if "on_host_extra_hosts" in params:
        kwargs["on_host_extra_hosts"] = _locking.extra_hosts(config)
    if "ttl_seconds" in params:
        ttl = verify_ttl_seconds(config)
        if ttl is not None:
            kwargs["ttl_seconds"] = ttl
    return str(render(rt.ledger, session, **kwargs))


class _AcceptsAll:
    def __contains__(self, name: object) -> bool:
        return True


def verify_ttl_seconds(config: Any) -> Optional[float]:
    """``confidential.verify_ttl_seconds`` as the provider reads it, or None when unset/unusable (the
    receipt then states its own default)."""
    raw = _locking._cfg(config or {}, "confidential", "verify_ttl_seconds")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        ttl = float(raw)
    except (TypeError, ValueError):
        return None
    return ttl if ttl > 0 else None


def plugin_identity() -> str:
    from . import _version
    return f"Plugin: confidential-mode {_version.PLUGIN_VERSION} (commit {_version.PLUGIN_COMMIT})"


def watch_text(rt: Any, limit: int = 20) -> str:
    from . import watch
    buf = io.StringIO()
    watch.run(rt.ledger, once=True, limit=limit, out=buf, color=False)
    return buf.getvalue().rstrip()


# ── slash command ────────────────────────────────────────────────────────────────────────────────

def handle_slash(rt: Any, raw_args: str, *, session_id: str = "", session_key: str = "", platform: str = "",
                 asker: Any = None, show_report: bool = False) -> str:
    """One verb of /confidential (and of the mirroring CLI subcommands). ``asker`` is the object whose
    ``ask_choice`` consent uses: ctx (chat surfaces) or a TerminalAsker (CLI)."""
    asker = asker if asker is not None else rt.ctx
    try:
        argv = shlex.split(raw_args or "")
    except ValueError:
        argv = (raw_args or "").split()
    if not argv or argv[0] in ("help", "-h", "--help"):
        return USAGE
    cmd, rest = argv[0].lower(), argv[1:]
    sid, skey, surface = session_id or "", session_key or session_id or "", platform or ""
    if cmd in ("on", "lock"):
        if len(rest) != 1:
            return "Usage: /confidential on <on-host-only|attested>"
        result = _locking.lock(rest[0], state=rt.state, ledger=rt.ledger, config=rt.load_config(),
                               allowlist_path=rt.allowlist_path, session_id=sid, surface=surface,
                               attested_ok=interactive_attested_ok(rt))
        if result.ok:
            rt.set_allowlist(result.allowlist)
            if show_report and result.report is not None:
                return result.message + "\n\nPreflight:\n" + _pf.format_report(result.report)
        return result.message
    if cmd in ("off", "unlock"):
        # Amendment 4 F6 (W4): allow grants are scoped to the lock. Second review, minor item: the file is
        # removed BEFORE the flag is cleared, and only if it belongs to the lock being cleared, so a lock
        # made concurrently by another process never loses its own allowlist.
        try:
            from .gate_tools import clear_persisted, lock_id_for
            clear_persisted(rt.allowlist_path, lock_id=lock_id_for(rt.state))
        except Exception:  # noqa: BLE001
            pass
        result = _locking.unlock(state=rt.state, ledger=rt.ledger, session_id=sid, surface=surface,
                                 clear_cache=lambda: [_provider_module(rt).verification_cache.invalidate(n)
                                                      for n in _locking.ATTESTED_PROFILES])
        rt.set_allowlist(None)
        return result.message
    if cmd == "status":
        return status_text(rt, session_key=skey)
    if cmd == "check":
        return check_text(rt, rest[0] if rest else None)
    if cmd == "pins":
        if not rest:
            return pins_text(rt, session_key=skey)
        if rest == ["approve"]:
            from .consent import ConsentContextError, approve_pending_pin
            if rt.pins is None:
                return "The pin store is not available; see /confidential status."
            try:
                return approve_pending_pin(asker, rt.pins, rt.ledger, session_key=skey, session_id=sid,
                                           platform=surface or "unknown")
            except ConsentContextError as exc:
                return f"Not asked: {exc}"
        return "Usage: /confidential pins [approve]"
    if cmd == "receipts":
        fmt = "json" if "--json" in rest else "text"
        names = [a for a in rest if a != "--json"]
        return receipts_text(rt, names[0] if names else sid, fmt=fmt)
    if cmd in ("allow", "allow-tool"):
        if len(rest) != 1:
            return "Usage: /confidential allow <tool>"
        try:
            locked, _ = rt.is_locked()
        except Exception:  # noqa: BLE001
            return "Lock state is unreadable; run /confidential off first."
        if locked is not True:
            return "Not locked: every tool runs without asking. Lock first with /confidential on <tier>."
        from .consent import ConsentContextError, allow_tool
        try:
            return allow_tool(asker, rt.allowlist(), rt.ledger, rest[0], session_key=skey, session_id=sid,
                              platform=surface)
        except ConsentContextError as exc:
            return f"Not asked: {exc}"
    if cmd == "blocked":       # pre_gateway_dispatch rewrites a locked /model (or /moa) to this
        what = rest[0] if rest else "that command"
        if rest[1:2] == ["unresolved"]:
            return (f"Refused while locked: the plugin cannot resolve /{what} in this Hermes version, so it "
                    "cannot tell whether the command switches this session's live model runtime. Run "
                    "/confidential off first.")
        return (f"Refused while locked: /{what} switches this session's live model runtime, and Hermes routes "
                "auxiliary calls (titles, compression, vision) to the live runtime. Run /confidential off first, "
                "switch, then lock again.")
    if cmd == "watch":
        return watch_text(rt) + "\n(live view: `hermes confidential watch` in a terminal)"
    return USAGE


def register_slash(ctx: Any, rt: Any) -> None:
    def confidential(raw_args: str = "", session_id: Optional[str] = None, session_key: Optional[str] = None,
                     platform: Optional[str] = None) -> str:
        # Sync on purpose: consent's ask_choice must run on the gateway's executor thread.
        try:
            return handle_slash(rt, raw_args, session_id=session_id or "", session_key=session_key or "",
                                platform=platform or "")
        except Exception as exc:  # noqa: BLE001 - a command bug is reported, never raised into the surface
            return f"confidential: error ({type(exc).__name__}: {exc})"

    ctx.register_command("confidential", confidential,
                         description="Confidential mode: lock, unlock, status, pins, receipts, allow, watch",
                         args_hint="on <tier>|off|status|check|pins [approve]|receipts|allow <tool>|watch")


# ── CLI ──────────────────────────────────────────────────────────────────────────────────────────

class TerminalAsker:
    """ask_choice for `hermes confidential setup`: numbered prompt on the controlling terminal; anything
    other than an exact choice value or its number is no answer (None). Non-tty stdin => None."""

    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout

    def ask_choice(self, question: str, choices: list) -> Optional[str]:
        try:
            if not self.stdin.isatty():
                return None
        except Exception:  # noqa: BLE001
            return None
        values = [c["value"] if isinstance(c, dict) else str(c) for c in choices]
        self.stdout.write(question + "\n")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c["value"]) if isinstance(c, dict) else str(c)
            self.stdout.write(f"  {i}. {label}\n")
        self.stdout.write("Choice: ")
        self.stdout.flush()
        answer = (self.stdin.readline() or "").strip()
        if answer in values:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(values):
            return values[int(answer) - 1]
        return None


# Default Tinfoil models for the printed config block (setup never writes config).
DEFAULT_VISION_MODEL = "gemma4-31b"          # vision-capable; the main chat models are text-only
DEFAULT_AUX_MODEL = "deepseek-v4-1-flash"    # cheaper model for short side jobs
#: Short auxiliary jobs that do not need the main model (titles, summaries, classification, rewrites).
CHEAP_AUX_TASKS = ("title_generation", "compression", "approval", "mcp", "memory_query_rewrite",
                   "tts_audio_tags", "group_router", "profile_describer", "monitor", "triage_specifier")
_GROUP_COMMENTS = {
    "vision": "# vision: a vision-capable model; Hermes describes inbound images through this task even "
              "without a tool call, and the main model is text-only",
    "cheap": "# short side jobs (titles, compression, approval checks, MCP helpers, query rewrites): a cheaper "
             "attested model is enough",
    "main": "# tasks that reason over the whole conversation or act for you: the main model",
}


def config_block(rt: Any, model: str, *, vision_model: str = DEFAULT_VISION_MODEL,
                 aux_model: str = DEFAULT_AUX_MODEL, enclave: Optional[str] = None) -> str:
    try:
        tasks = list(dict.fromkeys(_pf.builtin_aux_task_names()
                                   + [e if isinstance(e, str) else e.get("key") for e in _locking._plugin_aux(None)]))
    except Exception:  # noqa: BLE001
        tasks = list(_pf.BUILTIN_AUX_TASKS_SNAPSHOT)
    tasks = [t for t in tasks if t and not t.startswith("moa")]   # moa is refused while locked
    groups = {"vision": [t for t in tasks if t == "vision"],
              "cheap": [t for t in tasks if t in CHEAP_AUX_TASKS],
              "main": [t for t in tasks if t != "vision" and t not in CHEAP_AUX_TASKS]}
    models = {"vision": vision_model, "cheap": aux_model, "main": model}
    lines = ["# Add to config.yaml (review first; setup never writes your config):",
             "model:", f"  provider: {PROFILE_NAME}", f"  default: {model}",
             "fallback_providers: []", "auxiliary:"]
    for group in ("vision", "cheap", "main"):
        if not groups[group]:
            continue
        lines.append("  " + _GROUP_COMMENTS[group])
        for task in groups[group]:
            lines += [f"  {task}:", f"    provider: {PROFILE_NAME}", f"    model: {models[group]}"]
    lines += ["memory:", '  provider: ""', "voice:", "  auto_tts: false"]
    if enclave:
        lines += ["confidential:", "  tinfoil:",
                  "    # the router this setup verified and pinned; without it each restart may pick another",
                  "    # router (possibly another hardware platform) and refuse until you re-approve the pin",
                  f"    enclave: {enclave}"]
    return "\n".join(lines)


DEFAULT_NEAR_MODEL = "Qwen/Qwen3.8-27B"                      # a NEAR-operated vLLM model with attestation
DEFAULT_NEAR_VISION_MODEL = "Qwen/Qwen3-VL-30B-A3B-Instruct"   # vision-capable, also NEAR-operated


def near_config_block(model: str, vision_model: str) -> str:
    try:
        tasks = list(dict.fromkeys(_pf.builtin_aux_task_names()
                                   + [e if isinstance(e, str) else e.get("key") for e in _locking._plugin_aux(None)]))
    except Exception:  # noqa: BLE001
        tasks = list(_pf.BUILTIN_AUX_TASKS_SNAPSHOT)
    tasks = [t for t in tasks if t and not t.startswith("moa")]
    name = _locking.NEAR_PROFILE_NAME
    lines = ["# Add to config.yaml (review first; setup never writes your config):",
             "model:", f"  provider: {name}", f"  default: {model}", "fallback_providers: []", "auxiliary:"]
    for task in tasks:
        lines += [f"  {task}:", f"    provider: {name}", f"    model: {vision_model if task == 'vision' else model}"]
    lines += ["memory:", '  provider: ""', "voice:", "  auto_tts: false", "confidential:", "  near:",
              "    # every model id Hermes may send to NEAR; the pin covers exactly this list",
              f"    models: [{model}{', ' + vision_model if vision_model != model else ''}]",
              "    require_provider_tee: true"]
    return "\n".join(lines)


def cli_setup_near(rt: Any, args: Any, out=None) -> int:
    """`hermes confidential setup --vendor near`: attest the NEAR gateway and the chosen models, approve the
    first pin on this terminal, print a config block. No API key is needed to attest (NEAR documents the
    attestation endpoints as public); one is needed for inference and signatures."""
    out = out or sys.stdout
    model = getattr(args, "model", None) or DEFAULT_NEAR_MODEL
    vision = getattr(args, "vision_model", None) or DEFAULT_NEAR_VISION_MODEL
    key_set = bool(_provider_module(rt).api_key_for(_locking.NEAR_API_KEY_ENV))
    out.write(f"{_locking.NEAR_API_KEY_ENV}: {'set' if key_set else 'NOT set (hermes auth / .env)'}\n")
    if not getattr(args, "no_verify", False):
        adapter = getattr(rt, "near_adapter", None)
        if adapter is None:
            out.write("The attested-near provider is not registered; see `hermes confidential status`.\n")
            return 1
        adapter.models = sorted(set(adapter.models) | {model, vision})
        cache = _provider_module(rt).verification_cache
        cache.invalidate(_locking.NEAR_PROFILE_NAME)
        ok, reason, result = cache.ensure(_locking.NEAR_PROFILE_NAME, wait_seconds=INTERACTIVE_VERIFY_WAIT_SECONDS)
        if result is None:
            out.write(f"Verification failed: {reason}\n")
            return 1
        claims = (result.evidence or {}).get("claims") or {}
        out.write(f"Verified {result.router_repo}: code {_short(result.code_fingerprint, 16)} enclave "
                  f"{_short(result.enclave_fingerprint, 16)}; gateway TCB {claims.get('tcb_status')}\n")
        for line in claims.get("components") or []:
            out.write(f"  {line}\n")
        if rt.pins.match(result):
            out.write("This build is already pinned.\n")
        else:
            rt.pins.stage(result, model=model)
            from .consent import approve_pending_pin
            out.write(approve_pending_pin(TerminalAsker(), rt.pins, rt.ledger, session_key="cli-setup",
                                          session_id="", platform="cli-setup") + "\n")
    out.write(near_config_block(model, vision) + "\n")
    out.write("Then run `hermes confidential check --tier attested` and `/confidential on attested`.\n")
    return 0


def cli_setup(rt: Any, args: Any, out=None) -> int:
    out = out or sys.stdout
    if getattr(args, "vendor", None) == "near":
        return cli_setup_near(rt, args, out)
    model = getattr(args, "model", None) or _locking._cfg(rt.load_config(), "confidential", "model") or "<model>"
    out.write(f"TINFOIL_API_KEY: {'set' if _provider_module(rt).tinfoil_api_key() else 'NOT set (hermes auth / .env)'}\n")
    if not getattr(args, "no_verify", False):
        if rt.adapter is None:
            out.write("The attested provider is not registered; see `hermes confidential status`.\n")
            return 1
        cache = _provider_module(rt).verification_cache
        try:
            rt.adapter.resolve_enclave_host()
        except Exception as exc:  # noqa: BLE001
            out.write(f"Router discovery failed: {exc}\n")
            return 1
        # A fresh attestation, bounded at INTERACTIVE_VERIFY_WAIT_SECONDS (W2). The cache ledgers
        # verify_ok / verify_fail / pin_staged itself (Amendment 4 F4), so nothing is ledgered here.
        cache.invalidate(PROFILE_NAME)
        try:
            ok, reason, result = cache.ensure(PROFILE_NAME, wait_seconds=INTERACTIVE_VERIFY_WAIT_SECONDS)
        except TypeError:   # an older cache without wait_seconds
            ok, reason, result = cache.ensure(PROFILE_NAME)
        if result is None:
            out.write(f"Verification failed: {reason}\n")
            return 1
        out.write(f"Verified {result.enclave_host}: code {_short(result.code_fingerprint, 16)} enclave "
                  f"{_short(result.enclave_fingerprint, 16)} release {result.release_tag or '(untagged)'} "
                  f"(verified_at is the host clock)\n")
        if rt.pins.match(result):
            out.write("This build is already pinned.\n")
        else:
            rt.pins.stage(result, model=model if model != "<model>" else None)
            from .consent import approve_pending_pin
            out.write(approve_pending_pin(TerminalAsker(), rt.pins, rt.ledger, session_key="cli-setup",
                                          session_id="", platform="cli-setup") + "\n")
    enclave = None
    if not getattr(args, "no_verify", False):
        try:
            enclave = rt.adapter.enclave_host or None
        except Exception:  # noqa: BLE001
            enclave = None
    out.write(config_block(rt, model, vision_model=getattr(args, "vision_model", None) or DEFAULT_VISION_MODEL,
                           aux_model=getattr(args, "aux_model", None) or DEFAULT_AUX_MODEL, enclave=enclave) + "\n")
    out.write("Then run `hermes confidential check --tier attested` and `/confidential on attested`.\n")
    return 0


# ── offline replay of a receipt's evidence ───────────────────────────────────────────────────────

DEFAULT_EXPECTED_REPO = "tinfoilsh/confidential-model-router"


def _replay_module():
    return importlib.import_module(__package__ + ".verify.replay")


def _near_replay_module():
    return importlib.import_module(__package__ + ".verify.replay_near")


def _call_replay(replay_fn: Callable[..., Any], evidence: dict, *, expected_repo: str,
                 expected_fingerprints: Optional[tuple], trusted_root: Optional[str], as_of: Optional[str],
                 expected_repo_id: Optional[str] = None, expected_owner_id: Optional[str] = None):
    """Call replay with the keyword arguments it accepts. Returns (result, notes) where notes lists the
    identity checks this replay version cannot do (they are then done here, on the result fields)."""
    import inspect
    try:
        params = inspect.signature(replay_fn).parameters
        var_kw = any(p.kind is p.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        params, var_kw = {}, False

    def takes(name: str) -> bool:
        return var_kw or name in params

    kwargs: dict = {}
    notes: list[str] = []
    if as_of:
        kwargs["as_of"] = as_of
    if takes("expected_repo"):
        kwargs["expected_repo"] = expected_repo
    else:
        notes.append("expected_repo")
    if expected_fingerprints:
        if takes("expected_fingerprints"):
            kwargs["expected_fingerprints"] = expected_fingerprints
        else:
            notes.append("expected_fingerprints")
    # Numeric Fulcio Source Repository / Owner IDs (OIDs 1.3.6.1.4.1.57264.1.15 / .17): passed only when the
    # installed replay accepts them; otherwise the row fails (names can be renamed or transferred).
    for name, value in (("expected_repo_id", expected_repo_id), ("expected_owner_id", expected_owner_id)):
        if value:
            if takes(name):
                kwargs[name] = value
            else:
                notes.append(name)
    if trusted_root:
        if takes("trusted_root"):
            kwargs["trusted_root"] = trusted_root
        elif takes("trust_root_dir"):
            path = os.path.abspath(trusted_root)
            kwargs["trust_root_dir"] = path if os.path.isdir(path) else os.path.dirname(path)
        else:
            notes.append("trusted_root")
    return replay_fn(evidence, **kwargs), notes


def _row_vendor(doc: dict, row_id: Any) -> Optional[str]:
    for row in doc.get("rows") or []:
        if isinstance(row, dict) and row.get("id") == row_id:
            d = row.get("detail") if isinstance(row.get("detail"), dict) else {}
            return d.get("vendor")
    return None


def _row_claims(doc: dict, row_id: Any) -> tuple[Optional[str], Optional[str]]:
    for row in doc.get("rows") or []:
        if isinstance(row, dict) and row.get("id") == row_id:
            d = row.get("detail") if isinstance(row.get("detail"), dict) else {}
            return d.get("code_fingerprint"), d.get("enclave_fingerprint")
    return None, None


def _parse_fingerprints(value: Optional[str]) -> Optional[tuple[str, str]]:
    if not value:
        return None
    code, sep, enclave = value.partition(":")
    code, enclave = code.strip().lower(), enclave.strip().lower()
    if not sep or not code or not enclave or any(c not in "0123456789abcdef" for c in code + enclave):
        raise ValueError("expected CODE:ENCLAVE (hex fingerprints)")
    return code, enclave


def _default_pins_path(rt: Any) -> Optional[str]:
    pins = getattr(rt, "pins", None) if rt is not None else None
    path = getattr(pins, "path", None)
    return str(path) if path else None


def _expected_for_row(*, flag: Optional[tuple], pin_records: Optional[dict], pins_path: Optional[str],
                      vendor: str, expected_repo: str, claimed: tuple) -> tuple[Optional[tuple], str]:
    """(expected fingerprints, source text). Order: --expected-fingerprints, the human-approved pin for
    (vendor, expected repo), and only then the receipt's own claim (which checks the self-report against
    itself and is labelled so)."""
    if flag:
        return flag, "--expected-fingerprints"
    rec = (pin_records or {}).get((vendor, expected_repo))
    if rec is not None:
        return ((rec.code_fingerprint, rec.enclave_fingerprint),
                f"the pin in {pins_path} (approved by {rec.approved_by} at {rec.approved_at} via {rec.approved_via})")
    if all(claimed):
        return tuple(claimed), "taken from the receipt itself (not independent)"
    return None, "none available (no flag, no pin for this vendor/repo, no claim in the receipt)"


def cli_replay(args: Any, out=None, replay_fn: Callable[..., Any] | None = None, rt: Any = None) -> int:
    """`hermes confidential replay <receipt.json>`: re-run every evidence blob in a receipt offline.
    Exit 0 only when the hash chain is intact and every row replays ok AND matches the expected repo and
    the expected fingerprints
    (from --expected-fingerprints, else the approved pin in --pins / the profile's pins.yaml, else, labelled
    as not independent, the receipt's own row)."""
    out = out or sys.stdout
    try:
        flag_fps = _parse_fingerprints(getattr(args, "expected_fingerprints", None))
    except ValueError as exc:
        out.write(f"--expected-fingerprints: {exc}\n")
        return 2
    pins_arg = getattr(args, "pins", None)
    pins_path = pins_arg or _default_pins_path(rt)
    pin_records: Optional[dict] = None
    pins_note = ""
    if pins_path and not flag_fps:
        try:
            from .pins import PinStore
            if pins_arg and not os.path.exists(pins_arg):
                raise FileNotFoundError(pins_arg)
            pin_records = PinStore(pins_path).load()[0]
        except Exception as exc:  # noqa: BLE001
            if pins_arg:
                out.write(f"Cannot read pins {pins_arg!r}: {type(exc).__name__}: {exc}\n")
                return 2
            pins_note = f" (could not read {pins_path}: {type(exc).__name__})"
    path = getattr(args, "receipt", None)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        out.write(f"Cannot read receipt {path!r}: {type(exc).__name__}: {exc}\n")
        return 2
    if not isinstance(doc, dict):
        out.write("Not a receipt: the JSON is not an object.\n")
        return 2
    mod = _replay_module()
    replay_fn = replay_fn or mod.replay
    not_established = tuple(getattr(mod, "NOT_ESTABLISHED", ()) or ())
    expected_repo = getattr(args, "expected_repo", None) or DEFAULT_EXPECTED_REPO
    trusted_root = getattr(args, "trusted_root", None)
    as_of = getattr(args, "as_of", None)
    chain_ok = False
    try:
        from .receipts import verify_chain
        chain_ok = verify_chain(doc) is True
        chain = "intact" if chain_ok else "BROKEN (receipt edited, or rows no longer match)"
    except Exception as exc:  # noqa: BLE001
        chain = f"not checked ({type(exc).__name__})"
    items = [i for i in (doc.get("evidence") or []) if isinstance(i, dict) and isinstance(i.get("evidence"), dict)]
    out.write(f"Receipt: {path}  session {(doc.get('header') or {}).get('session_id', '?')}  hash chain {chain}\n")
    out.write(f"Expected repo: {expected_repo}\n")
    for flag_name, label in (("expected_repo_id", "Expected repo id"), ("expected_owner_id", "Expected owner id")):
        if getattr(args, flag_name, None):
            out.write(f"{label}: {getattr(args, flag_name)}\n")
    out.write("Expected fingerprints: " + ("--expected-fingerprints" if flag_fps else
                                           f"pins {pins_path}{pins_note}" if pins_path else "no pins file")
              + " (per row below)\n")
    out.write("Trust root: " + (f"{trusted_root} (supplied with --trusted-root)" if trusted_root else
                                "the copy recorded in the evidence (chosen by whoever captured it, not independent)")
              + "\n")
    out.write("as_of: " + (f"{as_of} (supplied with --as-of)" if as_of else
                           "the evidence's captured_at (recorded by the capturer, not independent)") + "\n")
    if not items:
        out.write("No evidence rows in this receipt: nothing can be replayed.\n")
        return 1
    failed = 0
    for item in items:
        ev = item["evidence"]
        row_id = item.get("row_id")
        claimed = _row_claims(doc, row_id)
        vendor = str(_row_vendor(doc, row_id) or ev.get("vendor") or "tinfoil")
        row_repo, row_replay = expected_repo, replay_fn
        if ev.get("schema") == _near_replay_module().EVIDENCE_SCHEMA:
            # NEAR (Amendment 5): the pin identity is "<host>#<models>"; --expected-repo overrides it only
            # when given explicitly.
            vendor, row_replay = "near", _near_replay_module().replay
            row_repo = expected_repo if expected_repo != DEFAULT_EXPECTED_REPO else str(ev.get("repo") or "")
        fps, fps_source = _expected_for_row(flag=flag_fps, pin_records=pin_records, pins_path=pins_path,
                                            vendor=vendor, expected_repo=row_repo, claimed=claimed)
        try:
            result, notes = _call_replay(row_replay, ev, expected_repo=row_repo, expected_fingerprints=fps,
                                         trusted_root=trusted_root, as_of=as_of,
                                         expected_repo_id=getattr(args, "expected_repo_id", None),
                                         expected_owner_id=getattr(args, "expected_owner_id", None))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            out.write(f"\nRow #{row_id}: FAIL (replay raised {type(exc).__name__}: {exc})\n")
            continue
        problems: list[str] = []
        repo = getattr(result, "repo", None) or ev.get("repo") or ""
        host = getattr(result, "enclave_host", None) or getattr(result, "host", None) or ev.get("enclave_host") or ""
        platform = getattr(result, "platform", None) or (ev.get("attestation") or {}).get("format") or ""
        if "expected_repo" in notes and repo != row_repo:
            problems.append(f"repo {repo or '(none)'} is not the expected {row_repo}")
        if fps and "expected_fingerprints" in notes:
            got = (getattr(result, "code_fingerprint", None), getattr(result, "enclave_fingerprint", None))
            if got != tuple(fps):
                problems.append(f"replayed fingerprints do not match the expected ones ({fps_source})")
        for name in ("expected_repo_id", "expected_owner_id"):
            if name in notes:
                problems.append(f"this replay version cannot check --{name.replace('_', '-')}")
        if fps is None:
            problems.append("no expected fingerprints: identity not checked")
        if "trusted_root" in notes:
            problems.append("this replay version cannot take --trusted-root; the evidence's own trust root was used")
        if item.get("unverified_entry"):
            problems.append("the receipt flags this row as an unverified entry")
        ok = getattr(result, "ok", False) is True and not problems
        failed += 0 if ok else 1
        out.write(f"\nRow #{row_id}: {'OK' if ok else 'FAIL'}\n")
        captured = getattr(result, "captured_at", None) or ev.get("captured_at") or ev.get("captured_at_unix") or ""
        out.write(f"  repo: {repo or '(none)'}  platform: {platform or '(unknown)'}\n")
        out.write(f"  enclave_host: {host or '(none)'} (asserted by capturer)\n")
        out.write(f"  captured_at: {captured or '(none)'} (asserted by capturer)\n")
        out.write(f"  expected fingerprints: {fps_source}\n")
        out.write(f"  as_of: {getattr(result, 'as_of', '?')}  sdk: {getattr(result, 'sdk_version', '?')}  "
                  f"release: {getattr(result, 'release_tag', None) or '(untagged)'}\n")
        out.write(f"  code {_short(getattr(result, 'code_fingerprint', None), 16)}  "
                  f"enclave {_short(getattr(result, 'enclave_fingerprint', None), 16)}\n")
        for key, value in (getattr(result, "checks", {}) or {}).items():
            out.write(f"  {key}: {'pass' if value is True else value}\n")
        for p in problems:
            out.write(f"  ! {p}\n")
        row_ne = tuple(getattr(result, "not_established", ()) or ())
        if row_ne:
            not_established = row_ne
    signed_failed = 0
    near = None
    if any(isinstance(r, dict) and r.get("kind") == "send_signed" for r in doc.get("rows") or []):
        near = _near_replay_module().replay_receipt(doc)
        out.write("\nSigned responses (NEAR AI Cloud):\n")
        for snd in near["sends"]:
            mark = "OK" if snd["verdict"] == "pass" else snd["verdict"].upper()
            tee = "provider_tee" if snd["provider_tee"] else (snd["kind"] or "no signature")
            out.write(f"  Row #{snd['row']}: {mark}  {tee}  id {snd['chat_id'] or '(none)'}"
                      f"{'' if snd['verdict'] == 'pass' else '  ' + str(snd['reason'] or '')}\n")
            signed_failed += 0 if snd["verdict"] == "pass" else 1
        out.write("  Session fully attested: " + ("yes" if near["fully_attested"] else
                                                   "NO (not every NEAR send has a provider_tee signature that replays)")
                  + "\n")
        not_established = tuple(not_established) + tuple(_near_replay_module().NOT_ESTABLISHED)
    out.write("\nA replay does NOT establish:\n")
    for line in dict.fromkeys(not_established):
        out.write(f"  - {line}\n")
    out.write(f"\n{len(items) - failed}/{len(items)} evidence row(s) replayed OK.\n")
    if near is not None:
        out.write(f"{len(near['sends']) - signed_failed}/{len(near['sends'])} signed response(s) replayed OK.\n")
    if not chain_ok:
        # Review finding 10: a receipt whose rows no longer match their hash chain fails the replay, even
        # when every evidence blob in it replays.
        out.write(f"Hash chain {chain}: the replay fails.\n")
    return 1 if (failed or signed_failed or not chain_ok) else 0


CLI_VERBS = ("on", "off", "receipts", "pins", "allow")


def cli_verb(rt: Any, action: str, args: Any, out=None, asker: Any = None) -> int:
    """`hermes confidential on|off|receipts|pins|allow`: the slash verbs on the same ctx.state, ledger,
    pins and allowlist files as a running gateway (state is re-read from disk on every gate call, so a lock
    or unlock here takes effect on the gateway's next turn). Consent uses the exact-match TerminalAsker."""
    out = out or sys.stdout
    asker = asker if asker is not None else TerminalAsker()
    if action == "on":
        raw, ok_prefix = f"on {args.tier}", "Locked"
    elif action == "off":
        raw, ok_prefix = "off", ""
    elif action == "receipts":
        if not getattr(args, "session", None):
            out.write("Usage: hermes confidential receipts <session id> [--json]\n")
            return 2
        raw, ok_prefix = f"receipts {shlex.quote(args.session)}" + (" --json" if args.json else ""), ""
    elif action == "pins":
        raw = "pins approve" if getattr(args, "pins_action", None) == "approve" else "pins"
        ok_prefix = "Pinned" if raw == "pins approve" else ""
    else:
        raw, ok_prefix = f"allow {shlex.quote(args.tool)}", ""
    text = handle_slash(rt, raw, session_id="", session_key="cli", platform="cli", asker=asker,
                        show_report=(action == "on"))
    out.write(text.rstrip() + "\n")
    if action == "allow":
        return 0 if text.endswith("added to the allowlist for this lock.") or text.endswith("is already allowed.") else 1
    if ok_prefix:
        return 0 if text.startswith(ok_prefix) else 1
    if action == "receipts" and text.startswith(("Receipts are not available", "Usage")):
        return 1
    return 0


def register_cli(ctx: Any, rt: Any) -> None:
    def setup_fn(parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="confidential_action")
        p = sub.add_parser("setup", help="verify the Tinfoil enclave, approve the first pin, print a config block")
        p.add_argument("--model", default=None, help="model id to put in the printed config block")
        p.add_argument("--vision-model", default=None,
                       help=f"vision-capable model for auxiliary.vision (default {DEFAULT_VISION_MODEL})")
        p.add_argument("--aux-model", default=None,
                       help=f"cheaper model for short auxiliary jobs (default {DEFAULT_AUX_MODEL})")
        p.add_argument("--no-verify", action="store_true", help="only print the config block")
        p.add_argument("--vendor", default="tinfoil", choices=["tinfoil", "near"],
                       help="which attested vendor to set up (default tinfoil)")
        p = sub.add_parser("check", help="run the lock preflight and print the table")
        p.add_argument("--tier", default=None, choices=[t.value for t in Tier])
        p = sub.add_parser("watch", help="stream the ledger (works unlocked)")
        from . import watch
        watch.setup_parser(p)
        sub.add_parser("status", help="lock state, pins, verification, breaches")
        p = sub.add_parser("on", help="lock this profile (same path as /confidential on)")
        p.add_argument("tier", choices=[t.value for t in Tier])
        sub.add_parser("off", help="unlock this profile and print the lock period's counts")
        p = sub.add_parser("receipts", help="render a session receipt")
        p.add_argument("session", nargs="?", default=None, help="session id")
        p.add_argument("--json", action="store_true", help="hash-chained JSON form")
        p = sub.add_parser("pins", help="list pins; 'approve' approves the staged pin on this terminal")
        p.add_argument("pins_action", nargs="?", choices=["approve"], default=None)
        p = sub.add_parser("allow", help="allow an off-host tool for this lock (asks on this terminal)")
        p.add_argument("tool")
        p = sub.add_parser("replay", help="replay a receipt's attestation evidence offline")
        p.add_argument("receipt", help="receipt JSON (/confidential receipts <session> --json)")
        p.add_argument("--expected-repo", default=DEFAULT_EXPECTED_REPO,
                       help=f"code repo the enclave must run (default {DEFAULT_EXPECTED_REPO})")
        p.add_argument("--trusted-root", default=None,
                       help="Sigstore trusted_root.json obtained independently (default: the evidence's copy)")
        p.add_argument("--as-of", default=None, help="ISO time to check certificates at (default: captured_at)")
        p.add_argument("--pins", default=None,
                       help="pins.yaml whose human-approved pin supplies the expected fingerprints "
                            "(default: this profile's pins.yaml)")
        p.add_argument("--expected-fingerprints", default=None, metavar="CODE:ENCLAVE",
                       help="expected code and enclave fingerprints (overrides --pins)")
        p.add_argument("--expected-repo-id", default=None,
                       help="numeric Fulcio Source Repository ID (OID 1.3.6.1.4.1.57264.1.15)")
        p.add_argument("--expected-owner-id", default=None,
                       help="numeric Fulcio Source Repository Owner ID (OID 1.3.6.1.4.1.57264.1.17)")

    def handler(args: Any) -> int:
        action = getattr(args, "confidential_action", None)
        try:
            if action == "setup":
                return cli_setup(rt, args)
            if action == "replay":
                return cli_replay(args, rt=rt)
            if action in CLI_VERBS:
                return cli_verb(rt, action, args)
            if action == "check":
                print(check_text(rt, getattr(args, "tier", None)))
                return 0
            if action == "watch":
                from . import watch
                watch.run(rt.ledger, once=getattr(args, "once", False), limit=getattr(args, "limit", 50),
                          interval=getattr(args, "interval", 1.0))
                return 0
            if action == "status":
                print(status_text(rt))
                return 0
            print("Usage: hermes confidential setup|check|watch|status|on <tier>|off|receipts <session>|"
                  "pins [approve]|allow <tool>|replay <receipt.json>")
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"confidential: error ({type(exc).__name__}: {exc})", file=sys.stderr)
            return 1

    ctx.register_cli_command("confidential", "Confidential mode: setup, check, watch, status", setup_fn, handler,
                             description="Attested inference and locked mode")

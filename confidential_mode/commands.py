"""``/confidential`` slash command and ``hermes confidential`` CLI command (W5).

Slash (``ctx.register_command``; the handler is a plain ``def``, so the gateway runs it on an executor
thread, which consent.py's ask_choice needs):

    /confidential on <local-only|attested|zero-retention>   seal (preflight first; refuses with the report)
    /confidential off                                       unseal (also repairs unreadable seal state)
    /confidential status                                    tier, route, enclave, pins, verification, breaches
    /confidential check [tier]                              the preflight table
    /confidential pins                                      pins, pending pin, approval history, tool grants
    /confidential pins approve                              approve the staged pin (ask_choice)
    /confidential receipts [session]                        receipt (confidential_mode.receipts, when present)
    /confidential allow <tool>                              add an off-machine tool for this seal (ask_choice)
    /confidential watch                                     the latest ledger rows

CLI (``ctx.register_cli_command``): ``hermes confidential setup|check|watch|status``.

``rt`` is the plugin runtime from the root ``__init__`` (ledger, state, pins, adapter, allowlist).
"""
from __future__ import annotations

import argparse
import importlib
import io
import os
import shlex
import sys
import time
from typing import Any, Callable, Optional

from . import preflight as _pf
from . import sealing as _sealing
from .tiers import Tier

PROFILE_NAME = _sealing.PROFILE_NAME
USAGE = ("Usage: /confidential on <local-only|attested>|off|status|check [tier]|pins [approve]|"
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
    result = cache.result(PROFILE_NAME)
    error = cache.last_error(PROFILE_NAME)
    if result is not None:
        return (f"Last verification: {_sealing.age_text(clock() - result.verified_at_local)} ago (local clock), "
                f"code {_short(result.code_fingerprint)} enclave {_short(result.enclave_fingerprint)}"
                f"{' release ' + result.release_tag if result.release_tag else ''}")
    if error:
        return f"Last verification: failed ({error[:120]})"
    return "Last verification: never in this process (local clock)"


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
    provider, model, base_url = _sealing._main_route(config)
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
    sealed = tier = None
    try:
        sealed, tier = rt.is_sealed()
        if sealed:
            since = rt.state.sealed_since()
            lines.append(f"Confidential mode: SEALED ({tier.value}) for "
                         f"{_sealing.age_text(clock() - since) if since else '?'} (local clock)")
        else:
            lines.append("Confidential mode: not sealed (observing only)")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Confidential mode: seal state UNREADABLE ({type(exc).__name__}); every send and tool is "
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
    if sealed is True:
        try:
            report = _sealing.run_tier_preflight(
                tier, config=config, predicate=_sealing.structural_predicate(tier, config=config))
            recorded = rt.state.config_fingerprint()
            fp_note = "unchanged since seal" if report.fingerprint == recorded else "CHANGED since seal"
            summary = "PASS" if report.ok else f"FAIL ({', '.join(i.key for i in report.failures()[:5])})"
            lines.append(f"Preflight ({tier.value}, routing config): {summary}; config {fp_note}")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"Preflight: could not run ({type(exc).__name__})")
    else:
        lines.append("Preflight: run /confidential check <tier>")
    try:
        breached = rt.state.breached_sessions()
        since = rt.state.sealed_since() if sealed else None
        counts = _sealing.period_counts(rt.ledger, since) if sealed else {}
        flag = "BREACHED" if (sealed and counts.get("breach")) else ("none this seal" if sealed else "-")
        lines.append(f"Breach: {flag}" + (f"; sessions ever breached: {', '.join(breached[-5:])}" if breached else ""))
        if sealed:
            lines.append(f"This seal: {counts.get('refused', 0)} refusal(s), {counts.get('asked', 0)} ask(s), "
                         f"{counts.get('allowed', 0)} allowed")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Breach: unknown ({type(exc).__name__})")
    lines.extend(_grant_lines(rt, session_key))
    for step, err in getattr(rt, "errors", [])[:5]:
        lines.append(f"Plugin registration problem: {step}: {err}")
    lines.append(f"Tools: {_sealing.TOOLS_TEXT}")
    lines.append(f"Limits: {_sealing.AUX_TEXT} {_sealing.SAFE_WORKER_TEXT}")
    return "\n".join(lines)


def _live_runtime_line(rt: Any) -> str:
    """The live main runtime (Amendment 4 F1): what the last sealed turn ran on, or this context's binding."""
    live = _sealing.live_main_runtime()
    if live:
        from .tiers import host_of
        return (f"Live runtime (this context): {live.get('provider') or '?'} / {live.get('model') or '?'}"
                f" at {host_of(live.get('base_url') or '') or '(provider default)'}")
    last = getattr(rt, "last_live", None)
    if last:
        verdict = "in tier" if last.get("in_tier") else f"OFF-TIER ({last.get('reason')})"
        return (f"Live runtime (last sealed turn): {last.get('provider') or '?'} / {last.get('model') or '?'} at "
                f"{last.get('host') or '(no host)'}: {verdict}")
    return "Live runtime: not seen yet (checked at the start of each sealed turn)"


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


def check_text(rt: Any, tier: Optional[str]) -> str:
    try:
        sealed, sealed_tier = rt.is_sealed()
    except Exception:  # noqa: BLE001
        sealed, sealed_tier = False, None
    chosen = tier or (sealed_tier.value if sealed and sealed_tier else Tier.ATTESTED.value)
    try:
        t = Tier(chosen)
    except ValueError:
        return f"Unknown tier {chosen!r} (one of: {', '.join(x.value for x in Tier)})."
    if t is Tier.ZDR:
        return f"zero-retention: {_sealing.ZDR_REASON}."
    report = _sealing.run_tier_preflight(t, config=rt.load_config())
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
        params = inspect.signature(render).parameters
    except (TypeError, ValueError):
        params = {}
    kwargs: dict = {}
    if "pins" in params:
        kwargs["pins"] = rt.pins
    if "fmt" in params:
        kwargs["fmt"] = fmt
    if "local_hosts" in params:
        try:
            kwargs["local_hosts"] = _sealing.extra_hosts(rt.load_config())
        except Exception:  # noqa: BLE001
            pass
    return str(render(rt.ledger, session, **kwargs))


def watch_text(rt: Any, limit: int = 20) -> str:
    from . import watch
    buf = io.StringIO()
    watch.run(rt.ledger, once=True, limit=limit, out=buf, color=False)
    return buf.getvalue().rstrip()


# ── slash command ────────────────────────────────────────────────────────────────────────────────

def handle_slash(rt: Any, raw_args: str, *, session_id: str = "", session_key: str = "", platform: str = "") -> str:
    try:
        argv = shlex.split(raw_args or "")
    except ValueError:
        argv = (raw_args or "").split()
    if not argv or argv[0] in ("help", "-h", "--help"):
        return USAGE
    cmd, rest = argv[0].lower(), argv[1:]
    sid, skey, surface = session_id or "", session_key or session_id or "", platform or ""
    if cmd in ("on", "seal"):
        if len(rest) != 1:
            return "Usage: /confidential on <local-only|attested>"
        result = _sealing.seal(rest[0], state=rt.state, ledger=rt.ledger, config=rt.load_config(),
                               allowlist_path=rt.allowlist_path, session_id=sid, surface=surface)
        if result.ok:
            rt.set_allowlist(result.allowlist)
        return result.message
    if cmd in ("off", "unseal"):
        result = _sealing.unseal(state=rt.state, ledger=rt.ledger, session_id=sid, surface=surface,
                                 clear_cache=lambda: _provider_module(rt).verification_cache.invalidate(PROFILE_NAME))
        rt.set_allowlist(None)
        try:   # Amendment 4 F6 (W4): allow grants are scoped to the seal
            from .gate_tools import clear_persisted
            clear_persisted(rt.allowlist_path)
        except Exception:  # noqa: BLE001
            pass
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
                return approve_pending_pin(rt.ctx, rt.pins, rt.ledger, session_key=skey, session_id=sid,
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
            sealed, _ = rt.is_sealed()
        except Exception:  # noqa: BLE001
            return "Seal state is unreadable; run /confidential off first."
        if sealed is not True:
            return "Not sealed: every tool runs without asking. Seal first with /confidential on <tier>."
        from .consent import ConsentContextError, allow_tool
        try:
            return allow_tool(rt.ctx, rt.allowlist(), rt.ledger, rest[0], session_key=skey, session_id=sid,
                              platform=surface)
        except ConsentContextError as exc:
            return f"Not asked: {exc}"
    if cmd == "blocked":       # pre_gateway_dispatch rewrites a sealed /model (or /moa) to this
        what = rest[0] if rest else "that command"
        return (f"Refused while sealed: /{what} switches this session's live model runtime, and Hermes routes "
                "auxiliary calls (titles, compression, vision) to the live runtime. Run /confidential off first, "
                "switch, then seal again.")
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
                         description="Confidential mode: seal, unseal, status, pins, receipts, allow, watch",
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


def config_block(rt: Any, model: str) -> str:
    try:
        tasks = list(dict.fromkeys(_pf.builtin_aux_task_names()
                                   + [e if isinstance(e, str) else e.get("key") for e in _sealing._plugin_aux(None)]))
    except Exception:  # noqa: BLE001
        tasks = list(_pf.BUILTIN_AUX_TASKS_SNAPSHOT)
    lines = ["# Add to config.yaml (review first; setup never writes your config):",
             "model:", f"  provider: {PROFILE_NAME}", f"  default: {model}",
             "fallback_providers: []", "auxiliary:"]
    for task in tasks:
        if task and not task.startswith("moa"):
            lines += [f"  {task}:", f"    provider: {PROFILE_NAME}", f"    model: {model}"]
    lines += ["memory:", '  provider: ""', "voice:", "  auto_tts: false"]
    return "\n".join(lines)


def cli_setup(rt: Any, args: Any, out=None) -> int:
    out = out or sys.stdout
    model = getattr(args, "model", None) or _sealing._cfg(rt.load_config(), "confidential", "model") or "<model>"
    out.write(f"TINFOIL_API_KEY: {'set' if os.environ.get('TINFOIL_API_KEY') else 'NOT set (hermes auth / .env)'}\n")
    if not getattr(args, "no_verify", False):
        if rt.adapter is None:
            out.write("The attested provider is not registered; see `hermes confidential status`.\n")
            return 1
        cache = _provider_module(rt).verification_cache
        try:
            rt.adapter.resolve_enclave_host()
            result = cache.refresh(PROFILE_NAME)
        except Exception as exc:  # noqa: BLE001
            rt.append({"kind": "verify_fail", "purpose": "setup", "provider": PROFILE_NAME, "decision": "failed",
                       "surface": "cli", "detail": {"error": f"{type(exc).__name__}: {exc}"[:300]}})
            out.write(f"Verification failed: {exc}\n")
            return 1
        rt.append({"kind": "verify_ok", "purpose": "setup", "provider": PROFILE_NAME, "host": result.enclave_host,
                   "decision": "verified", "surface": "cli",
                   "detail": {"code_fingerprint": result.code_fingerprint,
                              "enclave_fingerprint": result.enclave_fingerprint,
                              "release_tag": result.release_tag, "verifier": result.verifier}})
        out.write(f"Verified {result.enclave_host}: code {_short(result.code_fingerprint, 16)} enclave "
                  f"{_short(result.enclave_fingerprint, 16)} release {result.release_tag or '(untagged)'} "
                  f"(verified_at is the local clock)\n")
        if rt.pins.match(result):
            out.write("This build is already pinned.\n")
        else:
            rt.pins.stage(result, model=model if model != "<model>" else None)
            from .consent import approve_pending_pin
            out.write(approve_pending_pin(TerminalAsker(), rt.pins, rt.ledger, session_key="cli-setup",
                                          session_id="", platform="cli-setup") + "\n")
    out.write(config_block(rt, model) + "\n")
    out.write("Then run `hermes confidential check --tier attested` and `/confidential on attested`.\n")
    return 0


def register_cli(ctx: Any, rt: Any) -> None:
    def setup_fn(parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="confidential_action")
        p = sub.add_parser("setup", help="verify the Tinfoil enclave, approve the first pin, print a config block")
        p.add_argument("--model", default=None, help="model id to put in the printed config block")
        p.add_argument("--no-verify", action="store_true", help="only print the config block")
        p = sub.add_parser("check", help="run the seal preflight and print the table")
        p.add_argument("--tier", default=None, choices=[t.value for t in Tier])
        p = sub.add_parser("watch", help="stream the ledger (works unsealed)")
        from . import watch
        watch.setup_parser(p)
        sub.add_parser("status", help="seal state, pins, verification, breaches")

    def handler(args: Any) -> int:
        action = getattr(args, "confidential_action", None)
        try:
            if action == "setup":
                return cli_setup(rt, args)
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
            print("Usage: hermes confidential setup|check|watch|status")
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"confidential: error ({type(exc).__name__}: {exc})", file=sys.stderr)
            return 1

    ctx.register_cli_command("confidential", "Confidential mode: setup, check, watch, status", setup_fn, handler,
                             description="Attested inference and sealed mode")

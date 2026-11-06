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
import json
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
    lines.append(plugin_identity())
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
    if "local_hosts" in params:
        kwargs["local_hosts"] = _sealing.extra_hosts(config)
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
    raw = _sealing._cfg(config or {}, "confidential", "verify_ttl_seconds")
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
    out.write(f"TINFOIL_API_KEY: {'set' if _provider_module(rt).tinfoil_api_key() else 'NOT set (hermes auth / .env)'}\n")
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


# ── offline replay of a receipt's evidence ───────────────────────────────────────────────────────

DEFAULT_EXPECTED_REPO = "tinfoilsh/confidential-model-router"


def _replay_module():
    return importlib.import_module(__package__ + ".verify.replay")


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
    Exit 0 only when every row replays ok AND matches the expected repo and the expected fingerprints
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
    try:
        from .receipts import verify_chain
        chain = "intact" if verify_chain(doc) else "BROKEN (receipt edited, or rows no longer match)"
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
        fps, fps_source = _expected_for_row(flag=flag_fps, pin_records=pin_records, pins_path=pins_path,
                                            vendor=vendor, expected_repo=expected_repo, claimed=claimed)
        try:
            result, notes = _call_replay(replay_fn, ev, expected_repo=expected_repo, expected_fingerprints=fps,
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
        if "expected_repo" in notes and repo != expected_repo:
            problems.append(f"repo {repo or '(none)'} is not the expected {expected_repo}")
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
    out.write("\nA replay does NOT establish:\n")
    for line in not_established:
        out.write(f"  - {line}\n")
    out.write(f"\n{len(items) - failed}/{len(items)} evidence row(s) replayed OK.\n")
    return 1 if failed else 0


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
            print("Usage: hermes confidential setup|check|watch|status|replay <receipt.json>")
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"confidential: error ({type(exc).__name__}: {exc})", file=sys.stderr)
            return 1

    ctx.register_cli_command("confidential", "Confidential mode: setup, check, watch, status", setup_fn, handler,
                             description="Attested inference and sealed mode")

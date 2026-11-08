"""``/confidential status``, ``check``, ``receipts`` and ``watch``: the read-only reports.

``status_text`` reports the lock, the main route, the enclave, the pins, verification and breaches;
``check_result`` runs the preflight for a tier; ``receipts_text`` renders a session's receipt
(receipts.py); ``watch_text`` prints the latest ledger rows (watch.py).
"""
from __future__ import annotations

import importlib
import io
import time
from collections.abc import Callable, Mapping
from typing import Any

from . import locking as _locking, preflight as _pf
from .commands_common import INTERACTIVE_VERIFY_WAIT_SECONDS, PROFILE_NAME, _provider_module, _short
from .commands_pins import _grant_lines, _pin_lines, pending_pin_note
from .tiers import Tier

NO_SUCH_SESSION = "No ledger rows for session"
RECEIPTS_PLACEHOLDER = ("Receipts are not available in this build yet (confidential_mode.receipts is missing). "
                        "The raw ledger is visible with /confidential watch or `hermes confidential watch`.")


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
        return f"NEAR verification: failed ({error[:300]})"
    return ""


def _tinfoil_verification_line(result: Any, error: Any, clock: Callable[[], float]) -> str:
    if result is not None:
        return (f"Last verification: {_locking.age_text(clock() - result.verified_at_host_clock)} ago (host clock), "
                f"code {_short(result.code_fingerprint)} enclave {_short(result.enclave_fingerprint)}"
                f"{' release ' + result.release_tag if result.release_tag else ''}")
    if error:
        return f"Last verification: failed ({error[:300]})"
    return "Last verification: never in this process (host clock)"


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


def data_paths_line(rt: Any) -> str:
    """Both plugin data directories (README, "Where the plugin keeps its files")."""
    try:
        from .ledger import default_ledger_path
        ledger_dir = str(default_ledger_path().parent)
    except Exception:  # noqa: BLE001
        ledger_dir = "(unavailable)"
    try:
        state_dir = str(rt.ctx.state.data_dir)
    except Exception:  # noqa: BLE001
        state_dir = "(unavailable)"
    return f"Data: ledger and evidence in {ledger_dir}; lock, pins and tool grants in {state_dir}"


def status_text(rt: Any, *, session_key: str = "", clock: Callable[[], float] = time.time,
                verbose: bool = False, form: str = "") -> str:
    """``form`` "terminal" prints commands in the terminal form (Amendment 14)."""
    cmd = lambda verb: _locking.command_text(verb, form)  # noqa: E731
    lines: list[str] = []
    locked: Any = None
    tier: Any = None
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
                     f"refused. Run {cmd('off')} to repair it.")
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
        lines.append(f"Preflight: run {cmd('check <tier>')}")
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
    if locked is True and tier is Tier.ATTESTED:
        note = pending_pin_note(rt)
        if note:
            lines.append(f"Locked with a pin pending: {note}")
    lines.extend(_grant_lines(rt, session_key))
    for step, err in getattr(rt, "errors", [])[:5]:
        lines.append(f"Plugin registration problem: {step}: {err}")
    lines.append(plugin_identity())
    lines.append(data_paths_line(rt))
    try:
        mode = rt.tool_ask_mode()
    except Exception:  # noqa: BLE001
        mode = "each_call"
    lines.append(f"Limits: {_locking.lock_disclosures(mode)}")
    if not verbose:
        lines.append(_locking.LOCK_DETAILS)
        return "\n".join(lines)
    lines.append(("While locked: " if locked is True else "When locked: ") + _locking.LOCK_TAIL)
    if locked is True:
        try:
            from .gate_tools import format_allowlist
            lines.append("Tools:\n" + format_allowlist(rt.allowlist()))
        except Exception as exc:  # noqa: BLE001
            lines.append(f"Tools: could not list ({type(exc).__name__})")
        try:
            report = _locking.run_tier_preflight(
                tier, config=config, predicate=_locking.structural_predicate(tier, config=config))
            lines.append("Preflight:\n" + _pf.format_report(report))
        except Exception as exc:  # noqa: BLE001
            lines.append(f"Preflight: could not run ({type(exc).__name__})")
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


def check_text(rt: Any, tier: str | None, *, verbose: bool = False, form: str = "") -> str:
    return check_result(rt, tier, verbose=verbose, form=form)[0]


def default_check_tier(rt: Any, config: Any) -> tuple[str, str]:
    """(tier, why) for `check` with no tier (Amendment 14): the locked tier; else attested when the main
    provider is an attested profile; else on-host-only when the main route is on this machine; else
    attested, the default."""
    try:
        locked, locked_tier = rt.is_locked()
    except Exception:  # noqa: BLE001
        locked, locked_tier = False, None
    if locked is True and locked_tier:
        return locked_tier.value, "the tier this profile is locked to"
    try:
        provider, _model, base_url = _locking._main_route(config or {})
    except Exception:  # noqa: BLE001
        provider, base_url = "", ""
    provider = str(provider or "").lower()
    if provider in _locking.ATTESTED_PROFILES:
        return Tier.ATTESTED.value, f"model.provider is {provider}"
    try:
        from .tiers import host_of, is_on_host
        on_host = bool(base_url) and is_on_host(host_of(base_url), _locking.extra_hosts(config or {}))
    except Exception:  # noqa: BLE001
        on_host = False
    if on_host:
        return Tier.ON_HOST.value, "model.base_url is on this machine"
    return Tier.ATTESTED.value, "the default when the config names no attested or on-host main route"


def check_result(rt: Any, tier: str | None, *, verbose: bool = False, form: str = "") -> tuple[str, bool]:
    """(the preflight table, whether it passed). `hermes confidential check` exits 1 unless it passed. The
    table is collapsed unless ``verbose`` (Amendment 14). With no tier, the first line names the tier
    checked and why."""
    header = ""
    if tier:
        chosen = tier
    else:
        try:
            cfg = rt.load_config()
        except Exception:  # noqa: BLE001
            cfg = {}
        chosen, why = default_check_tier(rt, cfg)
        other = Tier.ON_HOST.value if chosen == Tier.ATTESTED.value else Tier.ATTESTED.value
        header = (f"Checking the {chosen} tier ({why}). To check the other tier: "
                  f"{_locking.command_text('check ' + other, form)}\n")
    try:
        t = Tier(chosen)
    except ValueError:
        return f"Unknown tier {chosen!r} (one of: {', '.join(x.value for x in Tier)}).", False
    if t is Tier.ZDR:
        return f"zero-retention: {_locking.ZDR_REASON}.", False
    config = rt.load_config()
    report = _locking.run_tier_preflight(t, config=config, attested_ok=interactive_attested_ok(rt),
                                         check_keys=True)
    text = _pf.format_report(report, collapse=not verbose)
    try:
        summary = _pf.auto_summary(report, _pf.auto_chain_readable(lambda p, e: _pf.key_state(p, e, config)))
    except Exception:  # noqa: BLE001
        summary = ""
    return header + (f"{text}\n{summary}" if summary else text), report.ok is True


def receipts_text(rt: Any, session: str, *, fmt: str = "text") -> str:
    """Delegate to confidential_mode.receipts.render (W6), imported lazily; placeholder if absent."""
    try:
        mod = importlib.import_module(__package__ + ".receipts")
        render = mod.render
    except (ImportError, AttributeError):
        return RECEIPTS_PLACEHOLDER
    if not session:
        return "Usage: /confidential receipts <session id> [--json] (no current session id here)"
    try:
        known = bool(rt.ledger.session(session))
    except Exception:  # noqa: BLE001 - an unreadable ledger is reported by render itself
        known = True
    if not known:
        return (f"{NO_SUCH_SESSION} {session!r}. Check the id: hermes confidential watch shows recent rows "
                "with their session ids.")
    import inspect
    sig_params: Mapping[str, inspect.Parameter]
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


def verify_ttl_seconds(config: Any) -> float | None:
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

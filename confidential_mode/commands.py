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

Layout: this module holds the dispatch (``handle_slash``, ``cli_verb``) and the registration
(``register_slash``, ``register_cli``). The reports are in commands_status.py, the pin commands in
commands_pins.py, ``setup`` in commands_setup.py, ``replay`` in commands_replay.py, and the shared
helpers (``TerminalAsker`` among them) in commands_common.py. Names imported below as ``X as X`` were
defined here before that split and stay importable from here.
"""
from __future__ import annotations

import argparse
import re
import shlex
import sys
from typing import Any

from . import locking as _locking, revoke as _revoke
from .commands_common import (
    INTERACTIVE_VERIFY_WAIT_SECONDS as INTERACTIVE_VERIFY_WAIT_SECONDS,
    PROFILE_NAME as PROFILE_NAME,
    TerminalAsker,
    _provider_module,
)
from .commands_pins import (
    _approve_flags,
    hermes_approval_keys as hermes_approval_keys,
    pending_pin_note,
    pins_text,
    remembered_grants as remembered_grants,
    retire_text,
)
from .commands_replay import DEFAULT_EXPECTED_REPO, _expected_for_row as _expected_for_row, cli_replay
from .commands_setup import (
    CHEAP_AUX_TASKS as CHEAP_AUX_TASKS,
    DEFAULT_AUX_MODEL,
    DEFAULT_NEAR_MODEL as DEFAULT_NEAR_MODEL,
    DEFAULT_NEAR_VISION_MODEL,
    DEFAULT_VISION_MODEL,
    KEY_NOT_SET_TEXT as KEY_NOT_SET_TEXT,
    NEAR_VISION_NOTE as NEAR_VISION_NOTE,
    NEAR_VISION_UNSET_NOTE as NEAR_VISION_UNSET_NOTE,
    TINFOIL_DOCUMENTED_MODELS as TINFOIL_DOCUMENTED_MODELS,
    attest_near_models as attest_near_models,
    cli_setup,
    cli_setup_near as cli_setup_near,
    config_block as config_block,
    near_config_block as near_config_block,
    near_model_failure as near_model_failure,
    setup_next_steps as setup_next_steps,
    tinfoil_model_note as tinfoil_model_note,
)
from .commands_status import (
    NO_SUCH_SESSION,
    RECEIPTS_PLACEHOLDER as RECEIPTS_PLACEHOLDER,
    check_result,
    check_text,
    data_paths_line as data_paths_line,
    default_check_tier as default_check_tier,
    interactive_attested_ok,
    plugin_identity as plugin_identity,
    receipts_text,
    status_text,
    verify_ttl_seconds as verify_ttl_seconds,
    watch_text,
)
from .tiers import Tier

USAGE = ("Usage: /confidential on <on-host-only|attested>|off|status [--verbose]|check [tier]|"
         "pins [approve|review|retire <fp>]|receipts [session]|allow <tool>|revoke <tool>|revoke --all|watch|"
         "replay <receipt.json>|setup")
#: Every verb of `hermes confidential`, in chat too (ux-pass-1 item 9). Verbs that need a terminal say so.
HELP_LINES = (
    ("on <on-host-only|attested>", "lock this profile (the preflight runs first)"),
    ("off", "unlock, with the lock period's counts"),
    ("status [--verbose]", "lock state, pins, verification, installed commit; --verbose adds the tool list"),
    ("check [tier] [--verbose]", "the preflight table; --verbose lists each auxiliary task"),
    ("pins", "approved pins, the pending pin, tool grants"),
    ("pins approve", "approve the pending pin (asks you)"),
    ("pins review", "terminal only: hermes confidential pins review (fetches the review bundle)"),
    ("pins retire <fingerprint>", "remove one approved entry"),
    ("receipts <session> [--json]", "a session receipt"),
    ("allow <tool>", "let an off-host tool run without asking, for this lock (asks you)"),
    ("revoke <tool> | revoke --all", "withdraw the grants confidential mode holds"),
    ("watch", "the latest ledger rows (live: hermes confidential watch)"),
    ("replay <receipt.json>", "terminal only: hermes confidential replay <receipt.json>"),
    ("setup", "terminal only: hermes confidential setup [--vendor near] --model <id>"),
)
HELP = USAGE + "\n" + "\n".join(f"  {verb:<30} {what}" for verb, what in HELP_LINES)
TERMINAL_ONLY = {
    "replay": "Replay reads a receipt file, so it runs only as a command in a terminal: "
              "hermes confidential replay <receipt.json>.",
    "setup": "Setup verifies the enclave and asks you to approve the first pin, so it runs only as a command in "
             "a terminal: hermes confidential setup [--vendor near] --model <model id>.",
}


# ── slash command ────────────────────────────────────────────────────────────────────────────────

def handle_slash(rt: Any, raw_args: str, *, session_id: str = "", session_key: str = "", platform: str = "",
                 asker: Any = None, show_report: bool = False, terminal: bool = False) -> str:
    """One verb of /confidential (and of the mirroring CLI subcommands). ``asker`` is the object whose
    ``ask_choice`` consent uses: ctx (chat surfaces) or a TerminalAsker (CLI)."""
    asker = asker if asker is not None else rt.ctx
    try:
        argv = shlex.split(raw_args or "")
    except ValueError:
        argv = (raw_args or "").split()
    if not argv or argv[0] in ("help", "-h", "--help"):
        return HELP
    cmd, rest = argv[0].lower(), argv[1:]
    if cmd in TERMINAL_ONLY:
        return TERMINAL_ONLY[cmd]
    sid, skey, surface = session_id or "", session_key or session_id or "", platform or ""
    form = "terminal" if terminal else ""     # a `hermes confidential` command, not chat (Amendment 14)
    cmd_for = lambda verb: _locking.command_text(verb, form)  # noqa: E731
    if cmd in ("on", "lock"):
        if len(rest) != 1:
            return "Usage: /confidential on <on-host-only|attested>"
        result = _locking.lock(rest[0], state=rt.state, ledger=rt.ledger, config=rt.load_config(),
                               allowlist_path=rt.allowlist_path, session_id=sid, surface=surface,
                               attested_ok=interactive_attested_ok(rt), progress=getattr(rt, "progress", None),
                               command_form=form)
        if result.ok:
            rt.set_allowlist(result.allowlist)
            note = pending_pin_note(rt) if result.tier is Tier.ATTESTED else ""
            if note:
                return f"{result.message}\n{note}"
        return result.message
    if cmd in ("off", "unlock"):
        # Amendment 4 F6 (W4): allow grants are scoped to the lock. locking.unlock removes allowlist.yaml
        # BEFORE clearing the flag, only if it belongs to the lock being cleared, under the transition lock
        # (FI-5), so a lock in progress in another process never loses its own allowlist.
        result = _locking.unlock(state=rt.state, ledger=rt.ledger, session_id=sid, surface=surface,
                                 allowlist_path=rt.allowlist_path,
                                 clear_cache=lambda: [_provider_module(rt).verification_cache.invalidate(n)
                                                      for n in _locking.ATTESTED_PROFILES])
        if result.ok:
            rt.set_allowlist(None)
        return result.message
    if cmd == "status":
        if rest not in ([], ["--verbose"], ["-v"]):
            return "Usage: /confidential status [--verbose]"
        return status_text(rt, session_key=skey, verbose=bool(rest), form=form)
    if cmd == "check":
        verbose = any(a in ("--verbose", "-v") for a in rest)
        names = [a for a in rest if a not in ("--verbose", "-v")]
        return check_text(rt, names[0] if names else None, verbose=verbose, form=form)
    if cmd == "pins":
        if not rest:
            return pins_text(rt, session_key=skey)
        if rest[0] == "approve":
            from .consent import ConsentContextError, approve_pending_pin
            if rt.pins is None:
                return "The pin store is not available; see /confidential status."
            try:
                flags = _approve_flags(rest[1:])
            except ValueError as exc:
                return f"Usage: /confidential pins approve [--reviewed-by <name>] [--note <text>] ({exc})"
            try:
                return approve_pending_pin(asker, rt.pins, rt.ledger, session_key=skey, session_id=sid,
                                           platform=surface or "unknown", **flags)
            except ConsentContextError as exc:
                return f"Not asked: {exc}"
        if rest[0] == "retire" and len(rest) in (2, 3):
            return retire_text(rt, rest[1], session_id=sid, surface=surface or "unknown",
                               identity=rest[2] if len(rest) == 3 else None)
        if rest == ["review"] or rest == ["review", "--json"]:
            return ("The review bundle fetches the inner compose files from GitHub, so it runs only as a command "
                    "in a terminal you open yourself: hermes confidential pins review [--json].")
        return "Usage: /confidential pins [approve|retire <fingerprint> [identity]]"
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
            return f"Lock state is unreadable; run {cmd_for('off')} first."
        if locked is not True:
            return f"Not locked: every tool runs without asking. Lock first with {cmd_for('on <tier>')}."
        from .consent import ConsentContextError, allow_tool
        try:
            return allow_tool(asker, rt.allowlist(), rt.ledger, rest[0], session_key=skey, session_id=sid,
                              platform=surface)
        except ConsentContextError as exc:
            return f"Not asked: {exc}"
    if cmd == "revoke":
        # Amendment 10 (U06): narrows only, so no consent prompt and no self-approval refusal.
        if rest == ["--all"]:
            return _revoke.revoke(rt, None, revoke_all=True, session_id=sid, surface=surface)[1]
        if len(rest) != 1 or rest[0].startswith("-"):
            return "Usage: /confidential revoke <tool>|--all"
        return _revoke.revoke(rt, rest[0], session_id=sid, surface=surface)[1]
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
    return HELP


def register_slash(ctx: Any, rt: Any) -> None:
    def confidential(raw_args: str = "", session_id: str | None = None, session_key: str | None = None,
                     platform: str | None = None) -> str:
        # Sync on purpose: consent's ask_choice must run on the gateway's executor thread.
        try:
            return handle_slash(rt, raw_args, session_id=session_id or "", session_key=session_key or "",
                                platform=platform or "")
        except Exception as exc:  # noqa: BLE001 - a command bug is reported, never raised into the surface
            return f"confidential: error ({type(exc).__name__}: {exc})"

    ctx.register_command("confidential", confidential,
                         description="Confidential mode: lock, unlock, status, pins, receipts, allow, revoke, watch",
                         args_hint="help|on <tier>|off|status|check|pins [approve|review|retire <fp>]|receipts|"
                                   "allow <tool>|revoke <tool>|revoke --all|watch|replay|setup")


# ── CLI ──────────────────────────────────────────────────────────────────────────────────────────

_SLASH = re.compile(r"(?<![\w/])/confidential(?= |$)")
_SENTENCE = re.compile(r"(?<=[.;])\s+")


def terminal_text(text: str) -> str:
    """A reply printed by a `hermes confidential` command, with each chat command form ``/confidential <verb>``
    written as ``hermes confidential <verb>``, which the CLI accepts for every verb (review L1). A sentence
    that names the chat (such as "In the chat session, run /confidential allow ...") keeps its chat form."""
    out = []
    for line in str(text).split("\n"):
        parts = _SENTENCE.split(line)
        seps = _SENTENCE.findall(line)
        fixed = [p if "chat" in p.lower() else _SLASH.sub("hermes confidential", p) for p in parts]
        out.append("".join(f + (seps[i] if i < len(seps) else "") for i, f in enumerate(fixed)))
    return "\n".join(out)


CLI_VERBS = ("on", "off", "receipts", "pins", "allow", "revoke")


def cli_verb(rt: Any, action: str, args: Any, out=None, asker: Any = None) -> int:
    """`hermes confidential on|off|receipts|pins|allow|revoke`: the slash verbs on the same ctx.state, ledger,
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
        pa = getattr(args, "pins_action", None)
        if pa == "review":
            from . import review
            return review.cli_review(rt, args, out=out)
        if pa == "retire":
            if not getattr(args, "fingerprint", None):
                out.write("Usage: hermes confidential pins retire <fingerprint>\n")
                return 2
            text = retire_text(rt, args.fingerprint, surface="cli", identity=getattr(args, "identity", None))
            out.write(terminal_text(text).rstrip() + "\n")
            return 0 if text.startswith("Retired") else 1
        raw = "pins"
        if pa == "approve":
            raw = "pins approve"
            for flag, attr in (("--reviewed-by", "reviewed_by"), ("--note", "note")):
                if getattr(args, attr, None):
                    raw += f" {flag} {shlex.quote(str(getattr(args, attr)))}"
        ok_prefix = "Pinned" if pa == "approve" else ""
    elif action == "revoke":
        tool, every = getattr(args, "tool", None), bool(getattr(args, "all", False))
        if every == bool(tool):
            out.write("Usage: hermes confidential revoke <tool> | --all\n")
            return 2
        status, text = (_revoke.revoke(rt, None, revoke_all=True, surface="cli") if every
                        else _revoke.revoke(rt, tool, surface="cli"))
        out.write(terminal_text(text).rstrip() + "\n")
        return 1 if status == _revoke.FAILED else 0
    else:
        raw, ok_prefix = f"allow {shlex.quote(args.tool)}", ""
    from .progress import for_cli
    previous = getattr(rt, "progress", None)
    rt.progress = for_cli()        # this command runs in a terminal a person is watching
    try:
        text = handle_slash(rt, raw, session_id="", session_key="cli", platform="cli", asker=asker,
                            show_report=(action == "on"), terminal=True)
    finally:
        rt.progress = previous
    if action == "receipts" and getattr(args, "json", False) and text.lstrip().startswith("{"):
        # The JSON receipt is hash-chained over its rows: rewriting "/confidential" to "hermes confidential"
        # inside it (as terminal_text does for every other reply) changes row text after the rows were
        # hashed, and `hermes confidential replay` then reports the chain broken. Write it byte for byte.
        out.write(text.rstrip() + "\n")
    else:
        out.write(terminal_text(text).rstrip() + "\n")
    if action == "allow":
        allowed = text.endswith("added to the allowlist for this lock.") or text.endswith("is already allowed.")
        return 0 if allowed else 1
    if ok_prefix:
        # `pins approve` with nothing pending is a no-op, not a failure
        return 0 if text.startswith(ok_prefix) or text.startswith("No pin update is waiting") else 1
    if action == "receipts" and text.startswith(("Receipts are not available", "Usage", NO_SUCH_SESSION)):
        return 1
    return 0


def register_cli(ctx: Any, rt: Any) -> None:
    def setup_fn(parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="confidential_action")
        p = sub.add_parser("setup", help="verify the Tinfoil enclave (or, with --vendor near, NEAR AI Cloud), "
                                         "approve the first pin, print a config block")
        p.add_argument("--model", default=None, help="model id to put in the printed config block")
        p.add_argument("--vision-model", default=None,
                       help=f"vision-capable model for auxiliary.vision (default {DEFAULT_VISION_MODEL}; with "
                            f"--vendor near, a NEAR model, default {DEFAULT_NEAR_VISION_MODEL})")
        p.add_argument("--aux-model", default=None,
                       help=f"cheaper model for short auxiliary jobs (default {DEFAULT_AUX_MODEL})")
        p.add_argument("--no-verify", action="store_true", help="only print the config block")
        p.add_argument("--vendor", default="tinfoil", choices=["tinfoil", "near"],
                       help="which attested vendor to set up (default tinfoil)")
        p = sub.add_parser("check", help="run the lock preflight and print the table")
        p.add_argument("tier_name", nargs="?", default=None, choices=[t.value for t in Tier], metavar="tier",
                       help="the tier to check (the same as --tier)")
        p.add_argument("--tier", default=None, choices=[t.value for t in Tier])
        p.add_argument("--verbose", "-v", action="store_true",
                       help="one row per auxiliary task, not one row per verdict")
        p = sub.add_parser("watch", help="stream the ledger (works unlocked)")
        from . import watch
        watch.setup_parser(p)
        p = sub.add_parser("status", help="lock state, pins, verification, breaches, installed commit")
        p.add_argument("--verbose", "-v", action="store_true",
                       help="also the full disclosure, the locked tool list and the preflight table")
        p = sub.add_parser("on", help="lock this profile (same path as /confidential on)")
        p.add_argument("tier", choices=[t.value for t in Tier])
        sub.add_parser("off", help="unlock this profile and print the lock period's counts")
        p = sub.add_parser("receipts", help="render a session receipt")
        p.add_argument("session", nargs="?", default=None, help="session id")
        p.add_argument("--json", action="store_true", help="hash-chained JSON form")
        p = sub.add_parser("pins", help="list pins; 'approve' approves the staged pin on this terminal; 'review' "
                                        "builds the review bundle; 'retire <fingerprint>' removes an approved entry")
        p.add_argument("pins_action", nargs="?", choices=["approve", "review", "retire"], default=None)
        p.add_argument("fingerprint", nargs="?", default=None, help="for retire: 8 or more hex digits of a fingerprint")
        p.add_argument("--reviewed-by", default=None,
                       help="for approve: who reviewed the bundle (recorded on the entries)")
        p.add_argument("--note", default=None, help="for approve: the reviewer's verdict (recorded on the entries)")
        p.add_argument("--json", action="store_true", help="for review: the bundle as JSON")
        p.add_argument("--no-fetch", action="store_true", help="for review: use cached inner compose files only")
        p.add_argument("--identity", default=None,
                       help="for retire: the identity (host#models) when one entry is approved under several")
        p = sub.add_parser("allow", help="allow an off-host tool for this lock (asks on this terminal)")
        p.add_argument("tool")
        p = sub.add_parser("revoke", help="withdraw the allow or 'always' grant confidential mode holds for a tool")
        p.add_argument("tool", nargs="?", default=None)
        p.add_argument("--all", action="store_true", help="withdraw every grant confidential mode holds")
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
                named = getattr(args, "tier", None) or getattr(args, "tier_name", None)
                if getattr(args, "tier", None) and getattr(args, "tier_name", None) \
                        and args.tier != args.tier_name:
                    print(f"Two tiers given ({args.tier_name} and --tier {args.tier}); name one.")
                    return 2
                text, ok = check_result(rt, named, verbose=bool(getattr(args, "verbose", False)), form="terminal")
                print(terminal_text(text))
                return 0 if ok else 1
            if action == "watch":
                from . import watch
                watch.run(rt.ledger, once=getattr(args, "once", False), limit=getattr(args, "limit", 50),
                          interval=getattr(args, "interval", 1.0))
                return 0
            if action == "status":
                print(terminal_text(status_text(rt, verbose=bool(getattr(args, "verbose", False)),
                                                form="terminal")))
                return 0
            print("Usage: hermes confidential setup|check|watch|status|on <tier>|off|receipts <session>|"
                  "pins [approve|review|retire <fp>]|allow <tool>|revoke <tool>|revoke --all|replay <receipt.json>")
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"confidential: error ({type(exc).__name__}: {exc})", file=sys.stderr)
            return 1

    ctx.register_cli_command("confidential", "Confidential mode: setup, check, watch, status", setup_fn, handler,
                             description="Attested inference and locked mode")

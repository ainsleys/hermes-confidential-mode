"""Human consent outside a turn (W4), on ``ctx.ask_choice`` only.

Why ask_choice and not ``tools.approval.request_tool_approval`` (docs/C0-spikes.md, spike 3):
request_tool_approval asks nobody from a slash command (no turn -> no gateway notifier -> it returns
``approval_required`` at once) and auto-approves under every bypass state (yolo, approvals.mode off,
remembered grants, cron/unattended approve modes). ``ctx.ask_choice`` blocks on the surface with no
turn running, never auto-picks, and returns None on no surface / timeout / cancel / prose /
out-of-range (tests/spikes/test_ask_choice.py). It fires no approval hooks, so we ledger here.

Both entry points are SYNC and refuse to run on an event loop. Reason: ask_choice waits for the
user's reply, which the gateway delivers on its event loop; waiting on that loop would deadlock it,
so Hermes' ask_choice returns None with only a warning when called from a coroutine
(hermes_cli/plugin_choices.py; tests/spikes/test_ask_choice.py::test_a). A None there would look
exactly like the user saying no. We raise ``ConsentContextError`` instead so the mistake is loud
and is never ledgered as a human denial. Register the slash-command handler as a plain ``def``;
the gateway runs it on an executor thread (tests/spikes/test_ask_choice.py::test_b_e).

Interfaces used (duck-typed, W1/W2 own the real ones):
  ledger.append(event: dict)
  store.pending() -> PendingPin | None ; store.apply(pending, *, approved_via=surface) -> PinRecord
  (approved_via is being added by W2, Amendment 2; older stores without it get apply(pending))
  allowlist.get(name) -> ToolInfo | None ; allowlist.add(name) ; allowlist.is_added(name)
"""
from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .gate_tools import Route

PIN_CHOICES = [
    {"value": "approve", "label": "Approve", "description": "pin the new enclave measurement"},
    {"value": "deny", "label": "Deny", "description": "keep the current pin"},
]
TOOL_CHOICES = [
    {"value": "approve", "label": "Allow", "description": "let this tool run while locked without asking each call"},
    {"value": "deny", "label": "Deny", "description": "keep asking (or blocking) for this tool"},
]


_APPLY_LOCK = threading.Lock()


class ConsentContextError(RuntimeError):
    """Raised when consent is requested from a coroutine (see module docstring)."""


class SelfApprovalRefused(RuntimeError):
    """Raised by an asker that will not ask because the agent may be the one answering (Amendment 7)."""


SELF_APPROVAL_REPLY = ("Refused: a Hermes tool started this process, so the agent could answer this prompt "
                       "itself. Approve from a terminal you opened outside Hermes")


def _self_approval(error: Optional[str]) -> bool:
    return bool(error) and str(error).startswith(SelfApprovalRefused.__name__ + ":")


def _guard(asker: Any) -> Optional[str]:
    """selfapproval.self_approval_reason() for this asker: every asker path checks it before asking (the chat
    surface's ctx included), so no tool-driven prompt is ever answered. An asker may carry its own
    ``environ`` (TerminalAsker in tests); otherwise this process's environment is read."""
    from .selfapproval import self_approval_reason
    env = getattr(asker, "environ", None)
    return self_approval_reason(env if isinstance(env, dict) else None)


def _refuse_on_event_loop(what: str) -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise ConsentContextError(
        f"{what} must run from a sync handler (the gateway runs those on an executor thread); "
        "called on an event loop, ask_choice would return None and look like a denial.")


def _ask(ctx: Any, question: str, choices: list) -> tuple[Optional[str], Optional[str]]:
    """(raw_pick, error). An exception from the surface counts as no answer."""
    try:
        return ctx.ask_choice(question, choices), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _pick_repr(raw: Any) -> Any:
    """What is stored for an answer: a choice value or None verbatim, anything else classified, never the
    text itself (review finding 20: a surface that passed free text through must not ledger a secret)."""
    if raw is None or (type(raw) is str and raw in ("approve", "deny")):
        return raw
    return "other" if isinstance(raw, str) else f"<{type(raw).__name__}>"


def _is_exact(raw: Any, value: str) -> bool:
    """Exact str match: a str subclass with a lying __eq__ must never count as a pick (C3 review)."""
    return type(raw) is str and raw == value


def _ledger(ledger: Any, event: dict) -> None:
    """Best effort: a ledger failure never changes a consent decision or hides a successful apply."""
    try:
        ledger.append(event)
    except Exception:
        pass


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _short(fp: Any) -> str:
    s = str(fp or "")
    return s[:16] if s else "(none)"


UNKNOWN = "unknown"
Observer = Callable[[Any], Optional[str]]


def _value(pending: Any, name: str) -> Any:
    """A PendingPin field, or W2's helper of that name (property or zero-arg method); None if absent."""
    result = _field(pending, "result", None)
    try:
        v = _field(pending, name, None)
        if v is None and result is not None:
            v = _field(result, name, None)
        if callable(v):
            v = v()
    except Exception:
        return None
    return v


def _text(v: Any) -> str:
    return UNKNOWN if v in (None, "") else str(v)


def _published_epoch(v: Any) -> Optional[float]:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).timestamp()
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _age(published: Any, now: float) -> str:
    ts = _published_epoch(published)
    if ts is None:
        return "release age: unknown (no published timestamp)"
    hours = (now - ts) / 3600
    if hours < 0:
        return "release age: published timestamp is in the future (check the clock)"
    if hours < 48:
        n = int(hours)
        return f"released {n} hour{'s' if n != 1 else ''} ago"
    n = int(hours // 24)
    return f"released {n} days ago"


def _release_urls(pending: Any) -> tuple[str, str]:
    repo, tag = _value(pending, "router_repo"), _value(pending, "release_tag")
    prev_tag = _value(pending, "previous_release_tag")
    url, compare = _value(pending, "release_url"), _value(pending, "compare_url")
    if not url and repo and tag:
        url = f"https://github.com/{repo}/releases/tag/{tag}"
    if not compare and repo and tag and prev_tag:
        compare = f"https://github.com/{repo}/compare/{prev_tag}...{tag}"
    return _text(url), _text(compare)


def _change_line(pending: Any) -> str:
    previous = _value(pending, "previous")
    if previous in (None, ""):
        return "TRUST ON FIRST USE: no prior pin to compare against"
    changed = _value(pending, "code_changed")
    if not isinstance(changed, bool):
        changed = str(previous) != str(_value(pending, "code_fingerprint") or "")
    if changed:
        return "CODE CHANGED"
    return (f"code unchanged; platform changed from {_text(_value(pending, 'previous_platform'))} "
            f"to {_text(_value(pending, 'platform'))}")


def _observations(pending: Any, observers: Optional[list]) -> list[str]:
    if not observers:
        return ["independent observations: none configured"]
    lines = []
    for obs in observers:
        try:
            line = obs(pending)
        except Exception as exc:  # an observer must never stop the human from deciding
            line = f"observer {getattr(obs, '__name__', 'observer')} failed ({type(exc).__name__})"
        if isinstance(line, str) and line.strip():
            lines.append("independent observation: " + " ".join(line.split()))
    return lines or [f"independent observations: none reported ({len(observers)} configured)"]


def pin_question(pending: Any, *, observers: Optional[list] = None, now: Optional[float] = None,
                 approved: Optional[tuple] = None) -> str:
    """The text a human judges before trusting an enclave build (Miller-frame review, "Pin prompt").
    Every field falls back to "unknown" so the prompt works with older PendingPin shapes. ``approved`` is
    PinStore.approved_set() for the pending identity: (entries, unseen flags)."""
    now = time.time() if now is None else now
    if _value(pending, "vendor") == "near":
        return _near_pin_question(pending, observers=observers, approved=approved)
    url, compare = _release_urls(pending)
    rekor = _value(pending, "rekor_log_index")
    lines = [
        "Approve confidential pin update?",
        _change_line(pending),
        f"Vendor: {_text(_value(pending, 'vendor'))}",
        f"Release: {_text(_value(pending, 'release_tag'))} ({_text(_value(pending, 'router_repo'))})",
        f"Release URL: {url}",
        f"Compare: {compare}",
        f"Rekor log index: {_text(rekor)}",
        _age(_value(pending, "release_published_at"), now),
        f"Enclave host: {_text(_value(pending, 'enclave_host'))}",
        f"Platform: old {_text(_value(pending, 'previous_platform'))}, new {_text(_value(pending, 'platform'))}",
        f"Code fingerprint old: {_text(_value(pending, 'previous'))}",
        f"Code fingerprint new: {_text(_value(pending, 'code_fingerprint'))}",
        f"Enclave fingerprint old: {_text(_value(pending, 'previous_enclave_fingerprint'))}",
        f"Enclave fingerprint new: {_text(_value(pending, 'enclave_fingerprint'))}",
        *_observations(pending, observers),
        "Approving means trusting this build until it changes again.",
    ]
    return "\n".join(lines)


# Component line prefixes (verify/near.py _cvm_lines). A line without one feeds the pin's fingerprints.
# "reported: " and "reported-other: " lines are what a model CVM's compose-manager log reported: shown for
# review, not pinned, not measurements.
REPORTED_PREFIX = "reported: "
REPORTED_OTHER_PREFIX = "reported-other: "
MAX_REPORTED_LINES = 40   # longer service lists fold into a count; `hermes confidential pins` prints them all
PINNED_HEADING = ("Pinned (a change in any of these asks again): each CVM's docker-compose (MRCONFIGID is "
                  "SHA-256 of it), its firmware and kernel measurements (MRTD, RTMR0-2: the enclave "
                  "fingerprint), and, where listed, its app_id, OS image and KMS key as its RTMR3 boot events "
                  "record them; each checked against its quote:")
REPORTED_HEADING = ("Reported after launch by each model CVM's compose-manager. This is not a measurement. A TD of "
                    "this instance reported this actions log for this nonce, and the log's hash is bound in a "
                    "hardware quote. The services below are what the operator's own tooling reported, not "
                    "proof of what runs:")
REPORTED_NOT_PINNED = ("Shown for review only, not pinned: the instance id, and the reported services unless an "
                       "entry above says they are pinned. A change in those alone does not ask again. The "
                       "compose-manager image the log reports is pinned for each model entry, although it is the "
                       "operator's report and not a measurement.")
ENTRIES_HEADING = ("Approving adds every entry below to the approved set for this identity. A verification "
                   "passes when each CVM it reports matches an approved entry, so one approval never covers a "
                   "different configuration.")
SERVICES_NOT_PINNED = ("services: not pinned, so this entry cannot be approved yet. The socket tags are unavailable: "
                       "{why}. Approval is unavailable until the command hermes confidential pins review fetches and "
                       "hash-checks the inner compose files; the prompt then pins the whole service map with its "
                       "tags.")
RETIRE_HINT = ("not seen in the last {n} verifications; if the vendor no longer runs it, retire it with "
               "hermes confidential pins retire {fp}")


def _display_if_needed(value: Any) -> str:
    from .verify.near_checks import render_if_needed
    return render_if_needed(value)


def _display(value: Any) -> str:
    """Component lines carry vendor strings: escape and code-span them for the terminal and chat surfaces."""
    from .verify.near_checks import render_vendor
    return render_vendor(value)


_COMPONENT_LABELS = {"app_id": "app_id", "compose": "compose sha256:", "os_image": "OS image", "kms_id": "KMS key sha256:",
                     "services": "service map sha256:", "cm_image_running": "compose-manager image reported by the log"}


def _component_text(name: str, value: Any) -> str:
    label = _COMPONENT_LABELS.get(name, name)
    return f"{label}{'' if label.endswith(':') else ' '}{_text(value)}"


def _entry_lines(n: int, ent: Any) -> list[str]:
    role = str(_field(ent, "cvm_role", "") or "")
    lines = [f"  {n}. {_display(role.replace('model:', 'model ', 1))}: code {_text(_field(ent, 'code_fingerprint'))} "
             f"enclave {_text(_field(ent, 'enclave_fingerprint'))}"]
    comps = _field(ent, "components", None)
    pinned = list(_field(ent, "pinned", ()) or ())
    if not isinstance(comps, dict):
        lines.append("     pinned: the whole result's fingerprints (no per-CVM components in this evidence)")
        return lines
    lines.append("     pinned: " + "; ".join(_display(_component_text(k, comps.get(k))) for k in sorted(pinned)))
    obs = _field(ent, "observed", None) or {}
    if role != "gateway":
        from .review import tag_summary
        tags = obs.get("tags")
        missing = obs.get("tags_missing") or []
        if "services" in pinned and isinstance(tags, dict):
            lines.append(f"     services: pinned, the whole map of {len(tags)} services, with the socket tags of every "
                         "service from the hash-checked inner compose files (a missing tag is not evidence):")
            lines.extend(f"       {_display(t)}" for t in (tag_summary(tags) or ["no service carries a tag"]))
        elif "services" in pinned:
            lines.append("     services: no service map (this CVM's report carried no compose-manager log); the "
                         "absence is pinned")
        else:
            n_missing = sum(1 for m in missing if m.get("reason") == "text not fetched")
            unparsed = [m for m in missing if m.get("reason") != "text not fetched"]
            parts = []
            if n_missing:
                parts.append(f"{n_missing} inner compose {'file' if n_missing == 1 else 'files'} named in the log "
                             f"{'is' if n_missing == 1 else 'are'} not fetched (text not fetched)")
            if unparsed:
                parts.append(f"{len(unparsed)} fetched {'file does' if len(unparsed) == 1 else 'files do'} not parse "
                             "as a compose file")
            lines.append("     " + SERVICES_NOT_PINNED.format(why="; ".join(parts) or "the tags were not computed"))
    ids = list(_field(ent, "instance_ids_seen", ()) or ())
    if ids:
        lines.append("     instances seen (shown only): " + ", ".join(_display(i) for i in ids))
    return lines


def _approved_lines(approved: Optional[tuple]) -> list[str]:
    if approved is None:
        return ["Approved set: not available from this pin store"]
    entries, unseen = approved
    if not entries:
        return ["Approved set: none (TRUST ON FIRST USE for this identity)"]
    from .pins import UNSEEN_VERIFICATIONS
    lines = [f"Approved set ({len(entries)} {'entry' if len(entries) == 1 else 'entries'}; all stay approved):"]
    for ent, old in zip(entries, unseen):
        code = str(_field(ent, "code_fingerprint", "") or "")
        line = (f"  {_display(str(_field(ent, 'cvm_role', '') or ''))} code {_short(code)} enclave "
                f"{_short(_field(ent, 'enclave_fingerprint'))}, approved {_text(_field(ent, 'approved_at'))} via "
                f"{_text(_field(ent, 'approved_via'))}")
        if _field(ent, "reviewed_by", None):
            line += f", reviewed by {_display(_field(ent, 'reviewed_by'))}"
        if _field(ent, "cvm_role", None) == "result":
            line += ("; migrated from pins file version 2: it matches nothing now, and approving the entries "
                     "above replaces it")
        elif old:
            line += "; " + RETIRE_HINT.format(n=UNSEEN_VERIFICATIONS, fp=code[:16])
        lines.append(line)
    return lines


def _near_pin_question(pending: Any, *, observers: Optional[list] = None, approved: Optional[tuple] = None) -> str:
    """NEAR has no release tag or Sigstore bundle: the prompt shows the identity (host and model allowlist),
    every entry to approve with what it pins, the whole approved set, and, separately, what the
    compose-manager logs reported (Amendments 5, 5.2, 7)."""
    comps = [str(c) for c in (_value(pending, "components") or ())]
    pinned = [c for c in comps if not c.startswith((REPORTED_PREFIX, REPORTED_OTHER_PREFIX))]
    reported = [c for c in comps if c.startswith((REPORTED_PREFIX, REPORTED_OTHER_PREFIX))]
    if len(reported) > MAX_REPORTED_LINES:
        reported = [c for c in reported if not c.startswith(REPORTED_OTHER_PREFIX)]
    reported = [c.split(": ", 1)[1] for c in reported]
    entries = list(_value(pending, "entries") or ())
    lines = [
        "Approve confidential pin update?",
        _change_line(pending) if approved is None else
        ("TRUST ON FIRST USE: no approved entry for this identity yet" if not approved[0] else
         f"NEW CVM CONFIGURATION: {len(entries) or 1} not covered by the approved set"),
        "Vendor: near (NEAR AI Cloud)",
        f"Identity: {_display_if_needed(_text(_value(pending, 'router_repo')))} (gateway host # attested model "
        "allowlist)",
    ]
    if entries:
        lines += [ENTRIES_HEADING, f"Entries to approve ({len(entries)}):"]
        for n, ent in enumerate(entries, 1):
            lines += _entry_lines(n, ent)
    lines += _approved_lines(approved)
    lines += [
        PINNED_HEADING,
        *([f"  {_display(c)}" for c in pinned] or ["  unknown"]),
        *([REPORTED_HEADING, *[f"  {_display(c)}" for c in reported]] if reported else []),
        REPORTED_NOT_PINNED,
        "NEAR runs instances of one model with different measured configurations under one signing key, so a "
        "new instance can show up here as a change.",
        f"Platform: {_text(_value(pending, 'platform'))}",
        f"Whole-result code fingerprint: {_text(_value(pending, 'code_fingerprint'))}",
        f"Whole-result enclave fingerprint: {_text(_value(pending, 'enclave_fingerprint'))}",
        *_observations(pending, observers),
        "A reviewer can be given the bundle from the command hermes confidential pins review (run it yourself, "
        "outside Hermes).",
        "Approving means trusting the pinned values above until they change again.",
    ]
    return "\n".join(lines)


def _event(kind: str, *, session_id: str, platform: str, decision: str, detail: dict,
           purpose: str = "pin", provider: str = "") -> dict:
    return {
        "ts": time.time(), "session_id": session_id or "", "kind": kind, "purpose": purpose,
        "provider": provider, "host": "", "model": "", "bytes": None, "tier": None, "verdict": None,
        "decision": decision, "surface": platform or None, "detail": detail,
    }


def _same_batch(a: Any, b: Any) -> bool:
    """Equal by consent key (fingerprints, release, host; Amendment 7), so a display refresh between the
    prompt and the answer keeps the answer valid. Objects without a consent key compare by equality."""
    from .pins import consent_key
    return consent_key(a) == consent_key(b)


def _approved_set(store: Any, pending: Any) -> Optional[tuple]:
    get = getattr(store, "approved_set", None)
    if not callable(get):
        return None
    try:
        return get(_field(pending, "vendor", ""), _field(pending, "router_repo", ""))
    except Exception:
        return None


SERVICES_UNPINNED_REPLY = ("Not asked: the service map of {roles} is not pinned, because its socket tags cannot be "
                           "shown ({why}). Approval is unavailable until the command hermes confidential pins "
                           "review fetches and hash-checks the inner compose files; run it in a terminal you "
                           "opened, then approve again.")


def _pending_batches(store: Any) -> list:
    """Every pending batch, oldest first (a store without pending_all has at most one)."""
    every = getattr(store, "pending_all", None)
    if callable(every):
        try:
            return sorted(every(), key=lambda p: str(_field(p, "staged_at", "") or ""))
        except Exception:
            pass
    one = store.pending()
    return [one] if one is not None else []


def _unpinned_services(pending: Any) -> list[str]:
    """Roles of NEAR model entries whose service map is not pinned (approval is refused for them)."""
    out = []
    for ent in _field(pending, "entries", ()) or ():
        role = str(_field(ent, "cvm_role", "") or "")
        if role.startswith("model:") and isinstance(_field(ent, "components", None), dict) \
                and "services" not in (_field(ent, "pinned", ()) or ()):
            out.append(role)
    return out


def _tags_missing_why(pending: Any) -> str:
    for ent in _field(pending, "entries", ()) or ():
        for m in ((_field(ent, "observed", None) or {}).get("tags_missing") or []):
            return str(m.get("reason") or "text not fetched")
    return "text not fetched"


def approve_pending_pin(ctx: Any, store: Any, ledger: Any, *, session_key: str, session_id: str,
                        platform: str, observers: Optional[list] = None, reviewed_by: Optional[str] = None,
                        review_note: Optional[str] = None) -> str:
    """Ask the human to approve every pending batch, oldest first; apply a batch only on an explicit
    Approve and only if it is still the one the human saw (by consent key). Writes one ``pin_applied`` row
    per approved entry. ``reviewed_by`` and ``review_note`` (from --reviewed-by and --note) are recorded on
    the entries, null without the flags. Refuses before asking anything when selfapproval says the agent
    may be driving the prompt. Returns the user-facing reply (one paragraph per batch)."""
    _refuse_on_event_loop("approve_pending_pin")
    reason = _guard(ctx)
    if reason:
        _ledger(ledger, _event("pin_denied", session_id=session_id, platform=platform, decision="self_approval",
                             detail={"session_key": session_key or "", "error": f"SelfApprovalRefused: {reason}"}))
        return f"{SELF_APPROVAL_REPLY} ({reason}.) Nothing was applied."
    prefetch = getattr(store, "prefetch_composes", None)
    if callable(prefetch):
        try:
            prefetch()       # public GitHub texts; on failure the batch says why and is not asked
        except Exception:
            pass
    batches = _pending_batches(store)
    if not batches:
        return "No pin update is waiting for approval."
    return "\n".join(_approve_batch(ctx, store, ledger, pending, session_key=session_key, session_id=session_id,
                                    platform=platform, observers=observers, reviewed_by=reviewed_by,
                                    review_note=review_note) for pending in batches)


def _approve_batch(ctx: Any, store: Any, ledger: Any, pending: Any, *, session_key: str, session_id: str,
                   platform: str, observers: Optional[list], reviewed_by: Optional[str],
                   review_note: Optional[str]) -> str:
    vendor = str(_field(pending, "vendor", "") or "")
    unpinned = _unpinned_services(pending)
    if unpinned:
        _ledger(ledger, _event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                             decision="services_unpinned",
                             detail={"session_key": session_key or "", "vendor": vendor, "roles": unpinned,
                                     "code_fingerprint": str(_field(pending, "code_fingerprint", "") or ""),
                                     "enclave_fingerprint": str(_field(pending, "enclave_fingerprint", "") or "")}))
        from .verify.near_checks import render_vendor
        return SERVICES_UNPINNED_REPLY.format(roles=", ".join(render_vendor(r) for r in unpinned),
                                              why=render_vendor(_tags_missing_why(pending)))
    base = {"session_key": session_key or "", "vendor": vendor,
            "router_repo": str(_field(pending, "router_repo", "") or ""),
            "code_fingerprint": str(_field(pending, "code_fingerprint", "") or ""),
            "enclave_fingerprint": str(_field(pending, "enclave_fingerprint", "") or "")}

    raw, error = _ask(ctx, pin_question(pending, observers=observers, approved=_approved_set(store, pending)),
                      PIN_CHOICES)
    detail = {**base, "raw_pick": _pick_repr(raw)}
    if error:
        detail["error"] = error
    if not _is_exact(raw, "approve"):
        refused = raw is None and _self_approval(error)
        _ledger(ledger, _event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                             decision="self_approval" if refused else
                             "no_answer" if raw is None else str(_pick_repr(raw)), detail=detail))
        if refused:
            return SELF_APPROVAL_REPLY + ". Pin update not applied; current pin kept."
        if raw is None:
            return "No answer (timed out, cancelled, or not one of the options): pin update denied; current pin kept."
        return "Pin update denied; current pin kept."

    # Re-check and apply under one lock: two approvals racing for the same pending pin apply once
    # (the second sees pending cleared or changed). PinStore.apply is additionally idempotent (W2).
    with _APPLY_LOCK:
        try:
            current = next((b for b in _pending_batches(store) if _same_batch(b, pending)), None)
        except Exception as exc:
            current, detail["recheck_error"] = None, f"{type(exc).__name__}: {exc}"[:200]
        if current is None:
            detail["reason"] = "pending pin changed while waiting for the answer"
            _ledger(ledger, _event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                                 decision="stale", detail=detail))
            return ("The pending pin changed while you were deciding, so nothing was applied. "
                    "Run /confidential pins approve again to review the new one.")
        try:
            record = _apply(store, pending, platform or "unknown", reviewed_by=reviewed_by, review_note=review_note)
        except Exception as exc:
            detail["error"] = type(exc).__name__
            _ledger(ledger, _event("pin_denied", session_id=session_id, platform=platform, provider=vendor,
                                 decision="apply_failed", detail=detail))
            return f"The pin could not be applied ({type(exc).__name__}); the current pin is unchanged."
    detail["approved_at"] = str(_field(record, "approved_at", "") or "")
    detail["approved_via"] = platform or "unknown"
    detail["reviewed_by"] = reviewed_by
    entries = tuple(_field(pending, "entries", ()) or ())
    if not entries:
        _ledger(ledger, _event("pin_applied", session_id=session_id, platform=platform, provider=vendor,
                             decision="approve", detail=detail))
    for n, ent in enumerate(entries):     # one consent row per entry, keyed on the entry's own fingerprints
        _ledger(ledger, _event("pin_applied", session_id=session_id, platform=platform, provider=vendor,
                             decision="approve",
                             detail={**detail, "batch_code_fingerprint": base["code_fingerprint"],
                                     "batch_enclave_fingerprint": base["enclave_fingerprint"],
                                     "cvm_role": _field(ent, "cvm_role", None),
                                     "pinned": list(_field(ent, "pinned", ()) or ()),
                                     "entry": f"{n + 1}/{len(entries)}",
                                     "code_fingerprint": str(_field(ent, "code_fingerprint", "") or ""),
                                     "enclave_fingerprint": str(_field(ent, "enclave_fingerprint", "") or "")}))
    if vendor == "near" and entries:
        return (f"Pinned {len(entries)} NEAR {'entry' if len(entries) == 1 else 'entries'} for "
                f"{_field(pending, 'router_repo', '')} (added to the approved set; "
                + ", ".join(f"{_field(x, 'cvm_role', '')} code {_short(_field(x, 'code_fingerprint', ''))}"
                            for x in entries) + ").")
    tag = _field(record, 'release_tag', None) or _field(pending, 'release_tag', None) or ''
    return (f"Pinned {vendor or 'enclave'} build {_display_if_needed(tag) if tag else ''}".rstrip()
            + f" (code {_short(base['code_fingerprint'])}, enclave {_short(base['enclave_fingerprint'])}).")


def _apply(store: Any, pending: Any, surface: str, *, reviewed_by: Optional[str] = None,
           review_note: Optional[str] = None) -> Any:
    """store.apply(pending, approved_via=surface[, reviewed_by, review_note]) with the keywords the store
    takes, else store.apply(pending). Decided by signature, not by catching TypeError, so an error inside
    apply is never retried."""
    import inspect
    try:
        params = inspect.signature(store.apply).parameters
        var_kw = any(p.kind is p.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        params, var_kw = {}, False
    kw: dict = {}
    if "approved_via" in params or var_kw:
        kw["approved_via"] = surface
    for name, value in (("reviewed_by", reviewed_by), ("review_note", review_note)):
        if value is not None and (name in params or var_kw):
            kw[name] = value
    return store.apply(pending, **kw)


def allow_tool(ctx: Any, allowlist: Any, ledger: Any, name: str, *, session_key: str = "",
               session_id: str = "", platform: str = "") -> str:
    """Ask the human to add an off-host tool to the locked allowlist (no per-call prompt after).
    Hard-blocked tools (cronjob_manage, delegate_task routing, MCP-by-URL) cannot be added."""
    _refuse_on_event_loop("allow_tool")
    reason = _guard(ctx)
    if reason:
        _ledger(ledger, _event("tool_refused", session_id=session_id, platform=platform, purpose=f"tool:{name}",
                             decision="self_approval",
                             detail={"tool": name, "session_key": session_key or "", "change": "allowlist_add",
                                     "error": f"SelfApprovalRefused: {reason}"}))
        return f"{SELF_APPROVAL_REPLY} ({reason}.) {name} was not added."
    info = allowlist.get(name)
    if info is None:
        return f"Unknown tool {name!r}; it was not registered when the session was locked."
    if info.route is Route.ON_HOST:
        return f"{name} is on-host and already runs without asking."
    if info.route is not Route.ASK:
        return f"{name} cannot be allowed while locked ({info.route.value})."
    if allowlist.is_added(name):
        return f"{name} is already allowed."
    question = (f"Allow {name} while locked?\n"
                f"It sends data off this machine (toolset {info.toolset}, origin {info.origin.value}).\n"
                "Once allowed, it runs without asking for the rest of this lock.")
    raw, error = _ask(ctx, question, TOOL_CHOICES)
    detail = {"tool": name, "raw_pick": _pick_repr(raw), "session_key": session_key or "", "change": "allowlist_add"}
    if error:
        detail["error"] = error
    if not _is_exact(raw, "approve"):
        refused = raw is None and _self_approval(error)
        _ledger(ledger, _event("tool_refused", session_id=session_id, platform=platform, purpose=f"tool:{name}",
                             decision="self_approval" if refused else
                             "no_answer" if raw is None else str(_pick_repr(raw)), detail=detail))
        if refused:
            return SELF_APPROVAL_REPLY + f". {name} was not added."
        return f"{name} was not added; it still needs approval each call."
    allowlist.add(name)
    _ledger(ledger, _event("tool_allowed", session_id=session_id, platform=platform, purpose=f"tool:{name}",
                         decision="allowlist_add", detail=detail))
    return f"{name} added to the allowlist for this lock."

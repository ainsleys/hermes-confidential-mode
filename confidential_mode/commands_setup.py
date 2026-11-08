"""``hermes confidential setup``: attest a vendor, ask for the first pin, print a config block.

``cli_setup`` (Tinfoil) and ``cli_setup_near`` (``--vendor near``) verify the enclave, ask for the first
pin with ``TerminalAsker`` and print the config block (``config_block``, ``near_config_block``) and the
next steps.
"""
from __future__ import annotations

import sys
import time
from typing import Any

from . import locking as _locking, preflight as _pf
from .commands_common import INTERACTIVE_VERIFY_WAIT_SECONDS, PROFILE_NAME, TerminalAsker, _provider_module, _short

# Default Tinfoil models for the printed config block (setup never writes config).
# Tinfoil's model list (https://docs.tinfoil.sh/models/chat.md, read 2026-11-06; the SDK carries no model
# table) gives image input for gemma4-31b, kimi-k3-1-pro and deepseek-v4-1-flash. gemma4-31b is the default
# vision model because it works beside any main model, including the text-only ones (llama3-3-70b).
DEFAULT_VISION_MODEL = "gemma4-31b"
DEFAULT_AUX_MODEL = "deepseek-v4-1-flash"    # cheaper model for short side jobs
#: Short auxiliary jobs that do not need the main model (titles, summaries, classification, rewrites).
CHEAP_AUX_TASKS = ("title_generation", "compression", "approval", "mcp", "memory_query_rewrite",
                   "tts_audio_tags", "group_router", "profile_describer", "monitor", "triage_specifier")
_GROUP_COMMENTS = {
    "vision": "# vision: a vision-capable model; Hermes describes inbound images through this task even "
              "without a tool call. A main model that accepts images (kimi-k3-1-pro does) can serve vision too",
    "cheap": "# short side jobs (titles, compression, approval checks, MCP helpers, query rewrites): a cheaper "
             "attested model is enough",
    "main": "# tasks that reason over the whole conversation or act for you: the main model",
}


def config_block(rt: Any, model: str, *, vision_model: str = DEFAULT_VISION_MODEL,
                 aux_model: str = DEFAULT_AUX_MODEL, enclave: str | None = None) -> str:
    try:
        tasks = list(dict.fromkeys(_pf.builtin_aux_task_names()
                                   + [e if isinstance(e, str) else e.get("key") for e in _locking._plugin_aux(None)]))
    except Exception:  # noqa: BLE001
        tasks = list(_pf.BUILTIN_AUX_TASKS_SNAPSHOT)
    # Every side call is pinned, the moa tasks too (MoA itself is refused while locked): a task left on auto
    # fails the preflight while an OpenRouter or Nous credential is readable (Amendment 11).
    tasks = [t for t in tasks if t]
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


#: The Tinfoil model ids docs/config.example.yaml lists (Tinfoil's list, read 2026-11-06).
TINFOIL_DOCUMENTED_MODELS = ("kimi-k3-1-pro", "glm-5-3", "deepseek-v4-1-flash", "gemma4-31b", "gpt-oss-120b",
                             "llama3-3-70b")


def tinfoil_model_note(model: str) -> str:
    """Setup cannot validate a Tinfoil model id (Amendment 14): Tinfoil offers no model list the plugin can
    fetch, and the SDK carries none. Says so, and whether the id is one config.example.yaml lists."""
    listed = model in TINFOIL_DOCUMENTED_MODELS
    return (f"Model {model}: setup cannot check model ids against Tinfoil, which offers no model list the plugin "
            "can fetch. " + (f"{model} is one of the ids docs/config.example.yaml lists." if listed else
                             f"{model} is not one of the ids docs/config.example.yaml lists ("
                             + ", ".join(TINFOIL_DOCUMENTED_MODELS) + "); check the id before you lock."))


DEFAULT_NEAR_MODEL = "Qwen/Qwen3.8-27B"                      # a NEAR-operated vLLM model with attestation

DEFAULT_NEAR_VISION_MODEL = "Qwen/Qwen3-VL-30B-A3B-Instruct"   # vision-capable, also NEAR-operated

#: Printed above the auxiliary.vision route by `setup --vendor near` (Amendment 9). Image parts leave as
#: plaintext to NEAR's gateway beside the encrypted text (confidential.near.image_parts: disclose).
NEAR_VISION_NOTE = (
    "  # vision runs through attested-near. NEAR's request encryption covers text only: each image leaves\n"
    "  # this host in plaintext to NEAR's gateway, and the text around it is encrypted. Every send records\n"
    "  # its image parts. To refuse images instead, set confidential.near.image_parts: refuse, or route\n"
    "  # vision through attested-tinfoil:\n"
    "  #   vision: {{provider: attested-tinfoil, model: {tinfoil_vision}}}   # needs TINFOIL_API_KEY and a Tinfoil pin")


NEAR_VISION_UNSET_NOTE = (
    "  # vision left unset: {reason}. The attested preflight refuses this block until auxiliary.vision\n"
    "  # is set. Run setup again once NEAR attests {vision}, or route vision through attested-tinfoil:\n"
    "  #   vision: {{provider: attested-tinfoil, model: {tinfoil_vision}}}   # needs TINFOIL_API_KEY and a Tinfoil pin")


def near_config_block(model: str, vision_model: str | None = DEFAULT_NEAR_VISION_MODEL, *,
                      tinfoil_vision_model: str = DEFAULT_VISION_MODEL, vision_unset_reason: str = "",
                      unset_vision: str = "") -> str:
    """The NEAR config block. ``vision_model`` None leaves auxiliary.vision out of the block, with a note
    naming ``vision_unset_reason`` (setup could not attest ``unset_vision``; Amendment 14)."""
    try:
        tasks = list(dict.fromkeys(_pf.builtin_aux_task_names()
                                   + [e if isinstance(e, str) else e.get("key") for e in _locking._plugin_aux(None)]))
    except Exception:  # noqa: BLE001
        tasks = list(_pf.BUILTIN_AUX_TASKS_SNAPSHOT)
    tasks = [t for t in tasks if t]
    name = _locking.NEAR_PROFILE_NAME
    lines = ["# Add to config.yaml (review first; setup never writes your config):",
             "model:", f"  provider: {name}", f"  default: {model}", "fallback_providers: []", "auxiliary:"]
    for task in tasks:
        if task == "vision":
            if vision_model is None:
                lines.append(NEAR_VISION_UNSET_NOTE.format(reason=vision_unset_reason or "not attested",
                                                           vision=unset_vision or "the vision model",
                                                           tinfoil_vision=tinfoil_vision_model))
                continue
            lines.append(NEAR_VISION_NOTE.format(tinfoil_vision=tinfoil_vision_model))
        lines += [f"  {task}:", f"    provider: {name}", f"    model: {vision_model if task == 'vision' else model}"]
    models = sorted({model} | ({vision_model} if vision_model else set()))
    lines += ["memory:", '  provider: ""', "voice:", "  auto_tts: false", "confidential:", "  near:",
              "    # every model id Hermes may send to NEAR. A NEAR pin's identity is this list, so changing it",
              "    # needs a new pin.",
              f"    models: [{', '.join(models)}]",
              "    require_provider_tee: true",
              "    # images leave in plaintext to NEAR's gateway and are recorded; refuse refuses them",
              "    image_parts: disclose"]
    return "\n".join(lines)


def near_model_failure(model: str, exc: BaseException) -> str:
    """One line for a NEAR model that did not verify (Amendment 14): the model, the vendor, the HTTP status
    when there is one, and why."""
    from .verify.base import VendorHTTPError
    if isinstance(exc, VendorHTTPError):
        if exc.subject == model:
            return f"{model}: attestation unavailable (HTTP {exc.status} from {exc.vendor})"
        return f"{model}: not attested, because {exc.subject} answered HTTP {exc.status} ({exc.vendor})"
    return f"{model}: attestation did not verify ({str(exc)[:200]})"


def attest_near_models(adapter: Any, models: list) -> tuple[list, dict]:
    """Attest each model on its own (gateway and that model's reports, appraised as a lock would) without
    publishing anything: (models that verified, {model: the VerifyError}). The adapter's model list is
    restored afterwards. Amendment 14: one model whose attestation endpoint fails leaves the others usable."""
    from .verify.base import VerifyError
    saved = list(getattr(adapter, "models", []) or [])
    ok: list = []
    bad: dict = {}
    try:
        for m in dict.fromkeys(models):
            adapter.models = [m]
            try:
                prepared = adapter.prepare_verification()
            except VerifyError as exc:
                bad[m] = exc
                continue
            except Exception as exc:  # noqa: BLE001
                bad[m] = VerifyError(f"{type(exc).__name__}: {exc}")
                continue
            try:
                prepared.discard()
            except Exception:  # noqa: BLE001
                pass
            ok.append(m)
    finally:
        adapter.models = saved
    return ok, bad


def setup_next_steps(rt: Any, *, vendor: str, key_env: str, key_set: bool, verified: bool,
                     vision_unset: bool = False) -> str:
    """Setup's closing lines (Amendment 14): the steps still to do, in order, in the terminal form."""
    steps: list[str] = []
    if not key_set:
        steps.append(f"Set {key_env} ({_pf.KEY_REQUIREMENTS}).")
    steps.append("Merge the block above into config.yaml.")
    if vision_unset:
        steps.append("Set auxiliary.vision as the note in the block says.")
    pins: Any = getattr(rt, "pins", None)
    try:
        pending = [b for b in (pins.pending_all() if callable(getattr(pins, "pending_all", None))
                               else [pins.pending()]) if b is not None and getattr(b, "vendor", vendor) == vendor]
        approved = [e for e in pins.approved_entries() if getattr(e, "vendor", vendor) == vendor]
    except Exception:  # noqa: BLE001
        pending, approved = [], []
    if pending:
        steps.append("Approve the pin in a terminal you opened: hermes confidential pins review, then "
                     "hermes confidential pins approve.")
    elif not approved and not verified:
        steps.append("Verify and pin the enclave: run this setup again without --no-verify.")
    steps += ["Check: hermes confidential check --tier attested.", "Lock: hermes confidential on attested."]
    return "Next steps:\n" + "\n".join(f"  {n}. {t}" for n, t in enumerate(steps, 1))


KEY_NOT_SET_TEXT = "NOT set (export it or add it to Hermes' env file)"


def cli_setup_near(rt: Any, args: Any, out=None) -> int:
    """`hermes confidential setup --vendor near`: attest the NEAR gateway with each chosen model on its own,
    approve the first pin on this terminal, print a config block. No API key is needed to attest (NEAR
    documents the attestation endpoints as public); one is needed for inference and signatures.
    auxiliary.vision goes through attested-near with a NEAR vision model, under a note that images are
    plaintext to the gateway (NEAR_VISION_NOTE). A vision model that does not verify is left out of the
    block, with a note; a main model that does not verify stops setup (Amendment 14)."""
    out = out or sys.stdout
    model = getattr(args, "model", None) or DEFAULT_NEAR_MODEL
    vision = getattr(args, "vision_model", None) or DEFAULT_NEAR_VISION_MODEL
    key_set = bool(_provider_module(rt).api_key_for(_locking.NEAR_API_KEY_ENV))
    out.write(f"{_locking.NEAR_API_KEY_ENV}: {'set' if key_set else KEY_NOT_SET_TEXT}\n")
    block_vision: str | None = vision
    unset_reason = ""
    if not getattr(args, "no_verify", False):
        adapter = getattr(rt, "near_adapter", None)
        if adapter is None:
            out.write("The attested-near provider is not registered; see `hermes confidential status`.\n")
            return 1
        verified, failed = attest_near_models(adapter, [model, vision])
        for m, exc in failed.items():
            line = near_model_failure(m, exc)
            try:   # review L3: the watch view shows each model that did not verify
                rt.ledger.append({"ts": time.time(), "session_id": "", "kind": "verify_fail", "purpose": "verify",
                                  "provider": _locking.NEAR_PROFILE_NAME, "host": getattr(adapter, "host", ""),
                                  "model": m, "surface": "cli-setup",
                                  "detail": {"vendor": "near", "source": "setup", "model": m,
                                             "error_type": type(exc).__name__, "error": str(exc)[:300],
                                             "reason": line[:300], "enclave_host": getattr(adapter, "host", "")}})
            except Exception:  # noqa: BLE001 - setup still reports the failure on the terminal
                pass
            if m == model:
                out.write(f"{line}; setup stopped, because {m} is the main model.\n")
            else:
                out.write(f"{line}; vision left unset.\n")
        if model in failed:
            from .verify.base import VendorHTTPError
            exc = failed[model]
            step = (exc.next_step if isinstance(exc, VendorHTTPError) else
                    "check that NEAR runs and attests this model (docs/GUIDE.md, Models)")
            out.write(f"Next step: {step}, or choose another model with --model <id>. No config block was "
                      "printed.\n")
            return 1
        if vision in failed:
            block_vision, unset_reason = None, near_model_failure(vision, failed[vision])
        adapter.models = sorted(verified)
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
    if block_vision is not None:
        out.write("auxiliary.vision goes through attested-near: images leave in plaintext to NEAR's gateway, and "
                  "the text around them is encrypted. The note in the block says how to refuse them instead.\n")
    out.write(near_config_block(model, block_vision, vision_unset_reason=unset_reason, unset_vision=vision) + "\n")
    out.write(setup_next_steps(rt, vendor="near", key_env=_locking.NEAR_API_KEY_ENV, key_set=key_set,
                               verified=not getattr(args, "no_verify", False),
                               vision_unset=block_vision is None) + "\n")
    return 0


def cli_setup(rt: Any, args: Any, out=None) -> int:
    out = out or sys.stdout
    if getattr(args, "vendor", None) == "near":
        return cli_setup_near(rt, args, out)
    model = getattr(args, "model", None) or _locking._cfg(rt.load_config(), "confidential", "model") or "<model>"
    key_set = bool(_provider_module(rt).tinfoil_api_key())
    out.write(f"TINFOIL_API_KEY: {'set' if key_set else KEY_NOT_SET_TEXT}\n")
    if model != "<model>":
        out.write(tinfoil_model_note(model) + "\n")
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
    out.write(setup_next_steps(rt, vendor="tinfoil", key_env="TINFOIL_API_KEY", key_set=key_set,
                               verified=not getattr(args, "no_verify", False)) + "\n")
    return 0

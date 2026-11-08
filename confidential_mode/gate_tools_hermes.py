"""Tool gate, Hermes' approval state: rule keys, bypass states, remembered grants and the prompt.

The gate asks under its own rule key (``rule_key_for``; a revoke moves it to a new generation) and reads
Hermes' approval state through hermes_compat.py: whether a bypass (yolo, approvals off, an unattended
run) would auto-approve, whether Hermes remembers a session or always answer for the key, the terminal
backend, and the prompt itself (``hermes_request_approval``).
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Our approve directive's rule_key. Hermes prefixes it with ``plugin_rule:`` (tools/approval.py:1226);
# the remembered-grant check MUST use the prefixed key (see hermes_remembered_grant).
RULE_KEY_PREFIX = "confidential-mode:tool:"
PATTERN_KEY_PREFIX = "plugin_rule:" + RULE_KEY_PREFIX
# After a revoke the plugin asks under a new rule key, ``confidential-mode:tool@<generation>:<tool>``
# (revoke.py, Amendment 13): a session or always answer Hermes holds for the old key then matches nothing the
# plugin asks for, so the grant is withdrawn without editing Hermes' approval tables.
RULE_KEY_STEM = "confidential-mode:tool"
PATTERN_KEY_STEM = "plugin_rule:" + RULE_KEY_STEM
_GENERATION_CHARS = frozenset("0123456789abcdef")


def rule_key_for(tool_name: str, generation: str = "") -> str:
    """The rule key the plugin asks Hermes under. ``generation`` (hex, from the latest revoke naming the tool,
    revoke.RevocationWatcher.generation) is empty until the first revoke."""
    if generation:
        return f"{RULE_KEY_STEM}@{generation}:{tool_name}"
    return f"{RULE_KEY_PREFIX}{tool_name}"


def parse_pattern_key(pattern_key: Any) -> tuple[str, str] | None:
    """(tool, generation) for a Hermes pattern key the plugin asked under (``plugin_rule:`` plus a rule key of
    rule_key_for), else None. The generation is "" for the key before any revoke."""
    if not isinstance(pattern_key, str) or not pattern_key.startswith(PATTERN_KEY_STEM):
        return None
    rest = pattern_key[len(PATTERN_KEY_STEM):]
    if rest.startswith(":"):
        tool, generation = rest[1:], ""
    elif rest.startswith("@") and ":" in rest:
        generation, tool = rest[1:].split(":", 1)
        if not generation or not set(generation) <= _GENERATION_CHARS:
            return None
    else:
        return None
    return (tool, generation) if tool else None


def _hermes_approval_state() -> tuple[bool, bool]:
    """(bypassed, someone present): ``bypassed`` is yolo or approvals.mode off; ``someone present`` is a CLI,
    gateway or ask surface that could answer. Mirrors ``_run_approval_gate`` (tools/approval.py:1071-1113).
    Raises when Hermes cannot be read; each caller fails closed."""
    from .hermes_compat import approval_state_functions
    _yolo_active, _get_approval_mode, _presence = approval_state_functions()
    bypassed = bool(_yolo_active() or _get_approval_mode() == "off")
    _cb, is_cli, is_gateway, is_ask = _presence(None)
    return bypassed, bool(is_cli or is_gateway or is_ask)


def hermes_bypass_active(tool_name: str) -> bool:
    """True when Hermes' approval gate would NOT put our approve directive in front of a human: a bypass, or
    nobody to ask (Hermes then blocks, or under cron/unattended/single_query approve mode auto-approves; either
    way no human decides, so we block ourselves). Any error -> True (block)."""
    try:
        bypassed, present = _hermes_approval_state()
        return bypassed or not present
    except Exception:
        return True


def hermes_remembered_grant(tool_name: str, rule_key: str | None = None) -> bool:
    """True when Hermes holds a session/always grant for our rule key (``rule_key``, default the key before any
    revoke) in this session.
    The plugin_rule: prefix trap: the grant is stored under the PREFIXED key; is_approved(sk, rule_key)
    without it is always False (tools/approval.py, approve_session). Any error -> False (ask)."""
    try:
        from . import hermes_compat
        key = rule_key if rule_key is not None else rule_key_for(tool_name)
        return bool(hermes_compat.is_approved(hermes_compat.current_session_key(), f"plugin_rule:{key}"))
    except Exception:
        return False


def hermes_terminal_backend(task_id: str = "") -> str:
    """The terminal backend a call for ``task_id`` would run on (review finding 2). Two readings, both must
    be local:

    * the backend Hermes' tools resolve, ``tools.terminal_tool._get_env_config()["env_type"]`` (it bridges
      config.yaml first and reads the profile's terminal scope on multiplexed surfaces);
    * the environment object Hermes has cached for this task, if any
      (``tools.terminal_tool_lifecycle.get_active_env``). The terminal, code and file tools reuse a cached
      environment without re-reading the backend, so an environment created under a remote backend before
      the lock would otherwise keep serving calls after it. Its backend is the ``env_type`` (or
      ``_hermes_backend_name``) tag Hermes sets when it creates the environment; an untagged one is
      reported as unknown, which blocks.

    Raises when Hermes cannot be read; the caller then blocks."""
    from .hermes_compat import active_env_reader, env_backend_tag, terminal_env_config_reader
    from .preflight import LOCAL_BACKEND, normalize_backend
    _get_env_config = terminal_env_config_reader()
    get_active_env = active_env_reader()
    backend = normalize_backend(_get_env_config().get("env_type"))
    if backend != LOCAL_BACKEND:
        return backend
    env = get_active_env(task_id or "default")
    if env is None:
        return backend
    tag = env_backend_tag(env)
    if not isinstance(tag, str) or not tag.strip():
        return "unknown (a cached environment with no backend tag)"
    return normalize_backend(tag)


def cached_remote_environments() -> list[tuple[str, str]]:
    """(task key, backend) of every environment Hermes has cached that is not local (or not tagged).
    The lock is refused while any exists. Raises when Hermes cannot be read."""
    from .hermes_compat import cached_terminal_environments, env_backend_tag
    from .preflight import LOCAL_BACKEND, normalize_backend
    items = cached_terminal_environments()
    out = []
    for key, env in items:
        tag = env_backend_tag(env)
        backend = normalize_backend(tag) if isinstance(tag, str) and tag.strip() else "unknown"
        if backend != LOCAL_BACKEND:
            out.append((str(key), backend))
    return out


def bypass_active_for(tool_name: str) -> Callable[[], bool]:
    return lambda: hermes_bypass_active(tool_name)


#: The label the plugin gives Hermes' approval prompt in place of the tool name (Hermes shows
#: "<label> (plugin approval rule)" under its own fixed "Dangerous Command" title; docs/LIMITATIONS.md).
APPROVAL_LABEL = "confidential mode: off-host tool"


def hermes_bypass_is_interactive() -> bool:
    """True when the bypass is yolo or approvals.mode off while a person is present (a CLI or gateway surface
    that could be asked); False for a genuinely unattended run (one-shot, cron, no surface). Any error: False."""
    try:
        bypassed, present = _hermes_approval_state()
        return bypassed and present
    except Exception:
        return False


def bypass_text(name: str, interactive: bool = False) -> str:
    """The tool result the model gets for an off-host tool under an approval bypass. It names the cause and the
    remedy, so the model can tell the person the exact command (Amendment 11)."""
    if interactive:
        return (f"confidential mode: {name} was blocked because approvals are bypassed (yolo or approvals off); "
                f"turn the bypass off to be asked, or run: hermes confidential allow {name} "
                f"(in chat: /confidential allow {name})")
    return (f"confidential mode: {name} was blocked by confidential mode in an unattended run; to allow it, "
            f"run: hermes confidential allow {name}, or run interactively to be asked (approvals are bypassed "
            "in an unattended run: nobody can be asked)")


def hermes_request_approval(tool_name: str, message: str, *, rule_key: str, approval_id: str,
                            session_id: str = "", turn_id: str = "") -> dict:
    """Ask through Hermes' own gate (CLI panel / gateway card), from the agent thread, with the
    observability context set so post_approval_response carries ``approval_id`` as tool_call_id
    (same mechanism as hermes_cli/plugins.py:1996-2009)."""
    from .hermes_compat import request_tool_approval_functions
    # All three resolved before anything is set: a missing one raises here, before the context is bound or
    # anyone is asked, so the plugin's ids never stay bound for Hermes' later approvals.
    request_tool_approval, set_context, reset_context = request_tool_approval_functions()
    tokens = set_context(turn_id=turn_id, tool_call_id=approval_id, session_id=session_id)
    try:
        # Hermes shows "<name> (plugin approval rule)" as the prompt's target line; the plugin's label goes
        # there in place of the bare tool name. The rule key (our grant key) still names the tool.
        return request_tool_approval(f"{APPROVAL_LABEL} {tool_name}", message, rule_key=rule_key)
    finally:
        reset_context(tokens)

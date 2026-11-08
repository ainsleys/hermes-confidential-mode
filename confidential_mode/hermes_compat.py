"""Every import of a private (undocumented) Hermes core module, in one place.

Hermes documents a plugin surface (``ctx.*``, the hooks, ``tools.registry``, ``agent.secret_scope``,
``providers``, ``hermes_cli.config``, ``plugins.plugin_storage``); modules that use only that surface import it
where they use it. Every private Hermes module or name the plugin imports, and every private attribute it reads
on a Hermes object (``MCPServerTask._config``, an environment's ``_hermes_backend_name``, the plugin manager's
``_plugin_tool_names``), goes through an accessor below. A Hermes release that moves or renames one of these
names breaks this file and no other, and ``hermes plugins validate`` names only this file in its private-import
warning. ``tests/unit/test_hermes_compat.py`` fails when any other plugin module imports a private Hermes module.

Rules every accessor follows (INTERFACES Amendment 15):

* The import happens inside the accessor, at call time. Nothing here is imported when this module loads, so
  importing this module costs nothing and cannot cycle into Hermes, and a test that patches the Hermes module
  (``monkeypatch.setattr(tools.approval, ...)``, ``sys.modules[...]``) is seen by the next call.
* An accessor never swallows an error. A missing module or name raises ``ImportError``; a failing Hermes
  call raises whatever it raises. The fallback is at the call site; each docstring names it. The exceptions:
  ``yaml_module`` falls back to PyYAML, and the attribute readers (``mcp_server_config``,
  ``env_backend_tag``, ``plugin_tool_names``) read with a ``getattr`` default.
* Where a call site needs several Hermes functions and must fail before the first has any effect, one
  accessor returns them all uncalled (``*_functions``, ``*_reader``), so a missing one raises before any runs.
* Each private Hermes name is imported at one line only, so the validator lists each name once.
* "Verified" names the Hermes commit the symbol, its signature and its use were read at: 84a0301.
"""
from __future__ import annotations

import importlib

# typing, not collections.abc: tests/unit/test_hermes_compat.py allows only __future__, importlib and typing
# at load.
from typing import Any, Callable  # noqa: UP035

HERMES_VERIFIED_COMMIT = "84a0301"


# --------------------------------------------------------------------------------------------------
# YAML
# --------------------------------------------------------------------------------------------------

def hermes_yaml() -> Any:
    """Hermes' ``hermes_yaml`` module (ruamel-backed ``safe_load`` / ``safe_dump``). Verified at 84a0301.

    Used by ``gate_tools._read_json_or_yaml`` to read a hand-edited ``allowlist.yaml``.
    Missing: raises ImportError; the caller returns None (the file adds no tool)."""
    import hermes_yaml as module
    return module


def yaml_module() -> Any:
    """``hermes_yaml`` when Hermes is importable, else PyYAML's ``yaml``. Verified at 84a0301.

    Used by ``pins`` (at module load) to read and write ``pins.yaml``, and by
    ``review._yaml_load`` for compose files. Hermes' venv ships ``hermes_yaml`` and no PyYAML.
    Missing ``hermes_yaml``: falls back to PyYAML (standalone use, unit tests outside Hermes); neither:
    raises ImportError, which fails the ``pins`` import."""
    try:
        return hermes_yaml()
    except ImportError:
        import yaml as module
    return module


# --------------------------------------------------------------------------------------------------
# Slash commands
# --------------------------------------------------------------------------------------------------

def resolve_command(name: str) -> Any:
    """``hermes_cli.commands.resolve_command(name)``: the CommandDef for a typed slash word or alias, or None.
    Verified at 84a0301.

    Used by ``pre_gateway_dispatch`` (``__init__.py``) to recognise ``/model``, ``/moa`` and their aliases.
    Missing: raises ImportError; the hook treats the word as unresolved and, while locked, refuses every slash
    command outside ``UNRESOLVED_SAFE_COMMANDS`` (fail closed)."""
    from hermes_cli.commands import resolve_command as _resolve_command
    return _resolve_command(name)


# --------------------------------------------------------------------------------------------------
# Approvals (tools.approval, tools.approval_context)
# --------------------------------------------------------------------------------------------------

def approval_keys(session_key: str | None = None) -> tuple[set, set]:
    """(Hermes' permanent approval keys, its session approval keys for ``session_key``, or for every session
    when None), read under Hermes' own lock: ``tools.approval._lock``, ``_permanent_set()``,
    ``_session_approved``. Read only. Verified at 84a0301.

    Used by ``commands.hermes_approval_keys`` (``/confidential status`` grant lines, ``revoke``'s check for a
    grant Hermes still holds). Missing: raises ImportError; ``remembered_grants`` lists nothing and
    ``revoke.hermes_holds_grant`` returns True (the revoke records and moves the rule key)."""
    from tools.approval import _lock, _permanent_set, _session_approved
    with _lock:
        permanent = set(_permanent_set())
        if session_key is None:
            session: set = set()
            for held in _session_approved.values():
                session |= set(held)
        else:
            session = set(_session_approved.get(session_key, set()))
    return permanent, session


def approval_state_functions() -> tuple[Callable[[], bool], Callable[[], str], Callable[..., tuple]]:
    """(``tools.approval._yolo_active``, ``tools.approval_context._get_approval_mode``,
    ``tools.approval._presence``), uncalled: yolo is on for this context; ``approvals.mode`` ("off" is a
    bypass); (callback, is_cli, is_gateway, is_ask), the surfaces Hermes' gate could ask. Verified at 84a0301.

    Used by ``gate_tools._hermes_approval_state``, which resolves all three before reading any. Missing (any
    of the three): raises ImportError; ``hermes_bypass_active`` returns True (block) and
    ``hermes_bypass_is_interactive`` False (the unattended refusal text)."""
    from tools.approval import _presence, _yolo_active
    from tools.approval_context import _get_approval_mode
    return _yolo_active, _get_approval_mode, _presence


def is_approved(session_key: str, pattern_key: str) -> bool:
    """``tools.approval.is_approved(session_key, pattern_key)``: Hermes holds a session or always grant.
    Verified at 84a0301.

    Used by ``gate_tools.hermes_remembered_grant`` with the ``plugin_rule:`` prefixed key. Missing: raises
    ImportError; the gate reads it as no grant and asks."""
    from tools.approval import is_approved as _is_approved
    return _is_approved(session_key, pattern_key)


def current_session_key(*args: Any) -> str:
    """``tools.approval_context.get_current_session_key(default="default")``: the approval session key of
    this context. Verified at 84a0301.

    Used by ``gate_tools.hermes_remembered_grant`` (no argument) and ``gate_tools.grant_scope`` (default "").
    Missing: raises ImportError; ``hermes_remembered_grant`` returns False (ask), ``grant_scope`` uses an empty
    key."""
    from tools.approval_context import get_current_session_key
    return get_current_session_key(*args)


def request_tool_approval_functions() -> tuple[Callable[..., dict], Callable[..., Any], Callable[[Any], None]]:
    """(``tools.approval.request_tool_approval``, ``tools.approval_context.set_current_observability_context``,
    ``tools.approval_context.reset_current_observability_context``), uncalled. Verified at 84a0301.

    ``request_tool_approval(tool_name, reason, *, rule_key=)`` asks through Hermes' own gate (CLI panel,
    gateway card); ``set_current_observability_context(turn_id=, tool_call_id=, session_id=)`` binds the ids
    ``post_approval_response`` reports and returns the tokens ``reset_current_observability_context(tokens)``
    takes. Used by ``gate_tools.hermes_request_approval``, which resolves all three before it sets the context,
    so a missing reset can never leave the plugin's ids bound for Hermes' later approvals. Missing (any of the
    three): raises ImportError before any context is set or anyone is asked; the tool gate refuses the call."""
    from tools.approval import request_tool_approval
    from tools.approval_context import reset_current_observability_context, set_current_observability_context
    return request_tool_approval, set_current_observability_context, reset_current_observability_context


# --------------------------------------------------------------------------------------------------
# Terminal backend (tools.terminal_tool, tools.terminal_tool_lifecycle, tools.terminal_scope)
# --------------------------------------------------------------------------------------------------

def terminal_env_config_reader() -> Callable[[], dict]:
    """``tools.terminal_tool._get_env_config``, the function itself (not called): its result's ``env_type`` is
    the backend Hermes' terminal, code and file tools resolve. Verified at 84a0301.

    Returned uncalled because ``preflight.resolved_terminal_backend`` treats a failed import (fall back to
    ``terminal_env_fallback``) differently from a failed call (a non-local marker). Missing: raises
    ImportError; ``gate_tools.hermes_terminal_backend`` raises and the gate blocks; the preflight falls back."""
    from tools.terminal_tool import _get_env_config
    return _get_env_config


def env_backend_tag(env: Any) -> Any:
    """The backend tag Hermes puts on a terminal environment it creates: ``env.env_type``, else the private
    ``env._hermes_backend_name``. Verified at 84a0301.

    Used by ``gate_tools.hermes_terminal_backend`` and ``cached_remote_environments``. Missing: None (read with
    a ``getattr`` default); both callers report an untagged environment as unknown, which blocks."""
    return getattr(env, "env_type", None) or getattr(env, "_hermes_backend_name", None)


def active_env_reader() -> Callable[[str], Any]:
    """``tools.terminal_tool_lifecycle.get_active_env``, the function itself: the environment Hermes cached
    for a task id, or None. Verified at 84a0301.

    Used by ``gate_tools.hermes_terminal_backend``, which obtains it together with
    ``terminal_env_config_reader`` before reading either. Missing: raises ImportError; the gate blocks."""
    from tools.terminal_tool_lifecycle import get_active_env
    return get_active_env


def cached_terminal_environments() -> list:
    """``list(tools.terminal_tool._active_environments.items())`` read under ``_env_lock``: (task key,
    environment) of every environment Hermes has cached. Verified at 84a0301.

    Used by ``gate_tools.cached_remote_environments`` (the lock is refused while a remote one exists).
    Missing: raises ImportError; the caller raises and the lock is refused."""
    from tools.terminal_tool import _active_environments, _env_lock
    with _env_lock:
        return list(_active_environments.items())


def terminal_env_fallback(name: str, default: str = "") -> str:
    """``tools.terminal_scope.terminal_env(name, default)``: the scope-aware terminal setting. Verified at
    84a0301.

    Used by ``preflight.resolved_terminal_backend`` only when ``_get_env_config`` cannot be imported.
    Missing: raises ImportError; the preflight reads ``os.environ`` (any other error: a non-local marker)."""
    from tools.terminal_scope import terminal_env
    return terminal_env(name, default)


# --------------------------------------------------------------------------------------------------
# MCP (tools.mcp_tool, tools.mcp_tool_config, tools.mcp_tool_scope)
# --------------------------------------------------------------------------------------------------

def mcp_server_configs() -> Any:
    """``tools.mcp_tool_config._load_mcp_config()``: ``mcp_servers`` from config, portable packages included.
    Verified at 84a0301.

    Used by ``gate_tools._default_mcp_configs``. Missing: raises ImportError; the caller skips this source
    and keeps the live configs."""
    from tools.mcp_tool_config import _load_mcp_config
    return _load_mcp_config()


def _mcp_lock() -> Any:
    """``tools.mcp_tool._lock``, the lock Hermes holds while it changes its MCP server tables. Verified at
    84a0301. Missing: raises ImportError (the callers' fallbacks apply)."""
    from tools.mcp_tool import _lock
    return _lock


def mcp_live_servers() -> list:
    """``list(tools.mcp_tool._servers.items())`` read under ``tools.mcp_tool._lock``: (server key, server
    task) of every connected MCP server. Verified at 84a0301.

    Used by ``gate_tools._default_mcp_configs`` (a server's live ``_config``). Missing: raises ImportError; the
    caller keeps the configured servers only."""
    from tools.mcp_tool import _servers
    with _mcp_lock():
        return list(_servers.items())


def mcp_server_config(server: Any) -> Any:
    """The private ``MCPServerTask._config`` of a live MCP server: the config it was connected with. Verified
    at 84a0301.

    Used by ``gate_tools._default_mcp_configs``. Missing: None (read with a ``getattr`` default); the caller
    skips that server and keeps its configured entry."""
    return getattr(server, "_config", None)


def mcp_key_name(key: Any) -> str:
    """``tools.mcp_tool_scope._key_name(key)``: the server name of a live server key. Verified at 84a0301.

    Used by ``gate_tools._default_mcp_configs``. Missing: raises ImportError; the caller keeps the configured
    servers only."""
    from tools.mcp_tool_scope import _key_name
    return _key_name(key)


def mcp_tool_server_names() -> dict:
    """``dict(tools.mcp_tool._mcp_tool_server_names)`` read under ``tools.mcp_tool._lock``: MCP tool name to
    server name. Verified at 84a0301.

    Used by ``gate_tools._default_mcp_tool_servers``. Missing: raises ImportError; the caller returns {} (no
    MCP tool maps to a server, so none is on-host)."""
    from tools.mcp_tool import _mcp_tool_server_names
    with _mcp_lock():
        return dict(_mcp_tool_server_names)


# --------------------------------------------------------------------------------------------------
# Plugins and config (hermes_cli.plugins, hermes_cli.config_defaults, tools.delegate_tool_config)
# --------------------------------------------------------------------------------------------------

def plugin_tool_names() -> set:
    """``hermes_cli.plugins.get_plugin_manager()._plugin_tool_names``: the tools plugins registered.
    Verified at 84a0301.

    Used by ``gate_tools._default_plugin_tool_names`` to tell plugin tools from built-in ones. Missing
    ``get_plugin_manager``: raises ImportError and the caller returns an empty set. Missing
    ``_plugin_tool_names`` on the manager: an empty set (read with a ``getattr`` default)."""
    from hermes_cli.plugins import get_plugin_manager
    return set(getattr(get_plugin_manager(), "_plugin_tool_names", ()) or ())


def plugin_auxiliary_tasks() -> list:
    """``hermes_cli.plugins.get_plugin_auxiliary_tasks()``: registration dicts of plugin-registered
    auxiliary tasks. Verified at 84a0301.

    Used by ``preflight.plugin_aux_task_entries``. Missing: raises ImportError; ``plugin_aux_task_entries``
    raises and ``locking._plugin_aux`` checks no plugin auxiliary task."""
    from hermes_cli.plugins import get_plugin_auxiliary_tasks
    return get_plugin_auxiliary_tasks()


def default_config() -> dict:
    """``hermes_cli.config_defaults.DEFAULT_CONFIG``: Hermes' default config (its ``auxiliary`` keys are the
    built-in auxiliary tasks). Verified at 84a0301.

    Used by ``preflight.builtin_aux_task_names``. Missing: raises ImportError; the caller uses
    ``BUILTIN_AUX_TASKS_SNAPSHOT``."""
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    return DEFAULT_CONFIG


def delegation_config() -> Any:
    """``tools.delegate_tool_config._load_config()``: the ``delegation`` config section. Verified at 84a0301.

    Used by ``gate_tools._load_delegation_config``, read per ``delegate_task`` call. Missing: raises
    ImportError; ``default_delegation_ok`` returns False and ``delegate_task`` is blocked."""
    from tools.delegate_tool_config import _load_config
    return _load_config()


def load_hermes_dotenv(**kwargs: Any) -> Any:
    """``hermes_cli.env_loader.load_hermes_dotenv(**kwargs)``: Hermes' env-file loader for ``HERMES_HOME``
    (DISCLOSURE lists its effects). Verified at 84a0301.

    Used by ``scripts/near_first_contact.py`` only, with ``load_external_secrets=False``. Missing: raises
    ImportError; the script skips it and reads the key through ``get_secret`` alone."""
    from hermes_cli.env_loader import load_hermes_dotenv as _load_hermes_dotenv
    return _load_hermes_dotenv(**kwargs)


# --------------------------------------------------------------------------------------------------
# Runtime context (agent.auxiliary_client, agent.error_classifier)
# --------------------------------------------------------------------------------------------------

def runtime_main_context() -> Any:
    """``agent.auxiliary_client._RUNTIME_MAIN_CONTEXT``, the ContextVar holding the live main runtime of this
    turn. Verified at 84a0301.

    Used by ``locking.live_main_runtime``. Missing: raises ImportError; the caller raises
    LiveRuntimeUnreadable and every turn check fails closed (the turn is not sent)."""
    from agent.auxiliary_client import _RUNTIME_MAIN_CONTEXT
    return _RUNTIME_MAIN_CONTEXT


def relay_aux_call_context() -> Any:
    """``agent.auxiliary_client._RELAY_AUX_CALL_CONTEXT``, the ContextVar Hermes binds per auxiliary call
    (its ``task`` gives the purpose). Verified at 84a0301.

    Used by ``sendctx.aux_current``. Missing: raises ImportError; the caller returns None and the send takes
    the purpose of the turn around it, or reads "unattributed"."""
    from agent.auxiliary_client import _RELAY_AUX_CALL_CONTEXT
    return _RELAY_AUX_CALL_CONTEXT


def context_overflow_patterns() -> tuple:
    """``agent.error_classifier._CONTEXT_OVERFLOW_PATTERNS`` as a tuple: the phrases Hermes reads as a
    context-length error. Verified at 84a0301.

    Used by ``provider._is_overflow`` for NEAR errors. Missing: raises ImportError; the caller uses its own
    ``_OVERFLOW_HINTS`` alone."""
    from agent.error_classifier import _CONTEXT_OVERFLOW_PATTERNS
    return tuple(_CONTEXT_OVERFLOW_PATTERNS)


# --------------------------------------------------------------------------------------------------
# Built-in tool modules named in a lock
# --------------------------------------------------------------------------------------------------

def import_tool_module(name: str) -> Any:
    """``importlib.import_module(name)`` for a Hermes built-in tool module named in ``allowlist.yaml``
    (``tools.*``): importing it registers its tools. Verified at 84a0301.

    Used by ``gate_tools._import_modules``. Missing: raises ImportError; the caller skips the module (and
    ``ensure_tools_for_lock`` falls back to the full discovery)."""
    return importlib.import_module(name)

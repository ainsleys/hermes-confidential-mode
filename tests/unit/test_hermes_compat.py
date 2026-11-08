"""hermes_compat is the plugin's only importer of private Hermes core modules (INTERFACES Amendment 15).

(a) No other plugin module imports a Hermes module outside the documented plugin surface (an ast scan of
    every module that loads inside Hermes, and the validator's own findings).
(b) Each accessor raises ImportError when its Hermes symbol is missing, and the call site it serves keeps
    its fallback (fail closed where it failed closed, fail open where it failed open).
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

import pytest

import hermes_cli
from confidential_mode import hermes_compat as hc

ROOT = Path(__file__).resolve().parents[2]
HERMES_ROOT = Path(hermes_cli.__file__).resolve().parents[1]
COMPAT = "confidential_mode/hermes_compat.py"

# The documented plugin surface the other modules may import directly (DISCLOSURE "Core modules imported").
PUBLIC = frozenset({
    "tools.registry", "agent.secret_scope", "providers", "providers.base", "hermes_cli.config",
    "plugins.plugin_storage",
})


def _hermes_top_level() -> set[str]:
    names = {p.name for p in HERMES_ROOT.iterdir() if p.is_dir() and (p / "__init__.py").is_file()}
    names |= {p.stem for p in HERMES_ROOT.glob("*.py")}
    return names - {"tests", "setup", "conftest", "confidential_mode", "scripts"}


def _plugin_sources() -> list[Path]:
    files = [ROOT / "__init__.py", *sorted((ROOT / "confidential_mode").rglob("*.py")),
             *sorted((ROOT / "scripts").glob("*.py"))]
    return [p for p in files if "__pycache__" not in p.parts]


def _imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                yield node.lineno, f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) \
                and ast.unparse(node.func) in ("importlib.import_module", "import_module", "__import__"):
            yield node.lineno, node.args[0].value


def _is_public(target: str) -> bool:
    return any(target == mod or target.startswith(mod + ".") and not target[len(mod) + 1:].startswith("_")
               for mod in PUBLIC)


def test_no_module_but_hermes_compat_imports_a_private_hermes_module():
    hermes = _hermes_top_level()
    assert {"tools", "agent", "hermes_cli", "hermes_yaml"} <= hermes
    offenders = []
    for path in _plugin_sources():
        rel = path.relative_to(ROOT).as_posix()
        if rel == COMPAT:
            continue
        for line, target in _imports(ast.parse(path.read_text(encoding="utf-8"))):
            if target.split(".")[0] in hermes and not _is_public(target):
                offenders.append(f"{rel}:{line} {target}")
    assert offenders == [], "import private Hermes names through confidential_mode/hermes_compat.py"


def test_the_scan_sees_the_imports_in_hermes_compat():
    """Guards the scan itself: hermes_compat's own imports read as private."""
    found = [t for _l, t in _imports(ast.parse((ROOT / COMPAT).read_text(encoding="utf-8")))
             if t.split(".")[0] in _hermes_top_level() and not _is_public(t)]
    assert "tools.approval._presence" in found and "hermes_yaml" in found


def test_the_validator_names_only_hermes_compat():
    from hermes_cli.plugin_validate_private_imports import private_import_findings
    hits = private_import_findings(ROOT)
    assert hits and all(h.startswith(COMPAT + ":") for h in hits), hits


def test_hermes_compat_imports_nothing_from_hermes_at_load():
    tree = ast.parse((ROOT / COMPAT).read_text(encoding="utf-8"))
    top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert {m for n in top for m in ([a.name for a in n.names] if isinstance(n, ast.Import) else [n.module])} \
        <= {"__future__", "importlib", "typing"}


# --------------------------------------------------------------------------------------------------
# (b) missing-symbol behaviour
# --------------------------------------------------------------------------------------------------

def _without(monkeypatch, module: str, *names: str) -> None:
    """Make ``module`` lack ``names`` (or, with no names, make the module unimportable)."""
    if not names:
        monkeypatch.setitem(sys.modules, module, None)        # import raises ImportError
        return
    real = __import__(module, fromlist=["_"])
    for name in names:
        monkeypatch.delattr(real, name)


ACCESSORS = [
    ("hermes_yaml", (), lambda: hc.hermes_yaml(), ()),
    ("hermes_cli.commands", ("resolve_command",), lambda: hc.resolve_command("model"), ()),
    ("tools.approval", ("_session_approved",), lambda: hc.approval_keys(None), ()),
    ("tools.approval", ("_permanent_set",), lambda: hc.approval_keys("s"), ()),
    ("tools.approval", ("_yolo_active",), hc.yolo_active, ()),
    ("tools.approval_context", ("_get_approval_mode",), hc.approval_mode, ()),
    ("tools.approval", ("_presence",), lambda: hc.approval_presence(None), ()),
    ("tools.approval", ("is_approved",), lambda: hc.is_approved("s", "plugin_rule:x"), ()),
    ("tools.approval_context", ("get_current_session_key",), lambda: hc.current_session_key(""), ()),
    ("tools.approval", ("request_tool_approval",), lambda: hc.request_tool_approval("t", "m", rule_key="k"), ()),
    ("tools.approval_context", ("set_current_observability_context",), lambda: hc.set_observability_context(), ()),
    ("tools.approval_context", ("reset_current_observability_context",),
     lambda: hc.reset_observability_context(None), ()),
    ("tools.terminal_tool", ("_get_env_config",), hc.terminal_env_config_reader, ()),
    ("tools.terminal_tool_lifecycle", ("get_active_env",), hc.active_env_reader, ()),
    ("tools.terminal_tool", ("_active_environments",), hc.cached_terminal_environments, ()),
    ("tools.terminal_scope", ("terminal_env",), lambda: hc.terminal_env_fallback("TERMINAL_ENV"), ()),
    ("tools.mcp_tool_config", ("_load_mcp_config",), hc.mcp_server_configs, ()),
    ("tools.mcp_tool", ("_servers",), hc.mcp_live_servers, ()),
    ("tools.mcp_tool_scope", ("_key_name",), lambda: hc.mcp_key_name("x"), ()),
    ("tools.mcp_tool", ("_mcp_tool_server_names",), hc.mcp_tool_server_names, ()),
    ("hermes_cli.plugins", ("get_plugin_manager",), hc.plugin_tool_names, ()),
    ("hermes_cli.plugins", ("get_plugin_auxiliary_tasks",), hc.plugin_auxiliary_tasks, ()),
    ("hermes_cli.config_defaults", ("DEFAULT_CONFIG",), hc.default_config, ()),
    ("tools.delegate_tool_config", ("_load_config",), hc.delegation_config, ()),
    ("hermes_cli.env_loader", ("load_hermes_dotenv",), lambda: hc.load_hermes_dotenv(load_external_secrets=False), ()),
    ("agent.auxiliary_client", ("_RUNTIME_MAIN_CONTEXT",), hc.runtime_main_context, ()),
    ("agent.auxiliary_client", ("_RELAY_AUX_CALL_CONTEXT",), hc.relay_aux_call_context, ()),
    ("agent.error_classifier", ("_CONTEXT_OVERFLOW_PATTERNS",), hc.context_overflow_patterns, ()),
]


@pytest.mark.parametrize("module,names,call,_", ACCESSORS, ids=[f"{m}.{'.'.join(n) or '*'}" for m, n, _c, _ in ACCESSORS])
def test_each_accessor_raises_import_error_when_its_symbol_is_missing(monkeypatch, module, names, call, _):
    _without(monkeypatch, module, *names)
    with pytest.raises(ImportError):
        call()


def test_every_accessor_is_covered():
    public = {n for n, v in vars(hc).items() if callable(v) and not n.startswith("_")
              and getattr(v, "__module__", "") == hc.__name__}
    covered = {"yaml_module", "import_tool_module"}           # tested on their own below
    for _m, _n, call, _ in ACCESSORS:
        code = call.__code__
        covered |= set(code.co_names) | {getattr(call, "__name__", "")}
    assert public <= covered, public - covered


def test_each_accessor_reads_hermes_at_call_time(monkeypatch):
    """A patch of the Hermes module is seen by the next call: nothing is cached at import."""
    import tools.approval as approval
    monkeypatch.setattr(approval, "_yolo_active", lambda: "patched")
    assert hc.yolo_active() == "patched"


def test_yaml_module_falls_back_to_pyyaml(monkeypatch):
    fake = types.ModuleType("yaml")
    monkeypatch.setitem(sys.modules, "hermes_yaml", None)
    monkeypatch.setitem(sys.modules, "yaml", fake)
    assert hc.yaml_module() is fake
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(ImportError):
        hc.yaml_module()


def test_import_tool_module_raises_for_a_missing_module():
    with pytest.raises(ImportError):
        hc.import_tool_module("tools.no_such_tool_module_cm")


# --------------------------------------------------------------------------------------------------
# call sites keep their fallbacks
# --------------------------------------------------------------------------------------------------

def test_approval_reads_fail_closed(monkeypatch):
    from confidential_mode import gate_tools
    _without(monkeypatch, "tools.approval", "_presence")
    assert gate_tools.hermes_bypass_active("terminal") is True            # block
    assert gate_tools.hermes_bypass_is_interactive() is False
    _without(monkeypatch, "tools.approval", "is_approved")
    assert gate_tools.hermes_remembered_grant("terminal") is False        # ask


def test_grant_scope_and_remembered_grants_without_hermes(monkeypatch):
    from confidential_mode import commands, gate_tools
    _without(monkeypatch, "tools.approval_context", "get_current_session_key")
    assert gate_tools.grant_scope("sid") == ("", "sid")
    _without(monkeypatch, "tools.approval", "_session_approved")
    assert commands.remembered_grants("s") == []
    with pytest.raises(ImportError):
        commands.hermes_approval_keys(None)


def test_terminal_backend_fails_closed_and_preflight_falls_back(monkeypatch):
    from confidential_mode import gate_tools, preflight
    _without(monkeypatch, "tools.terminal_tool_lifecycle", "get_active_env")
    with pytest.raises(ImportError):
        gate_tools.hermes_terminal_backend("t1")                           # the caller blocks
    _without(monkeypatch, "tools.terminal_tool", "_get_env_config")
    monkeypatch.setitem(sys.modules, "tools.terminal_scope", None)
    monkeypatch.setenv(preflight.TERMINAL_BACKEND_ENV, "docker")
    assert preflight.resolved_terminal_backend() == "docker"              # os.environ, non-local: fails
    _without(monkeypatch, "tools.terminal_tool", "_active_environments")
    with pytest.raises(ImportError):
        gate_tools.cached_remote_environments()


def test_mcp_and_plugin_reads_fail_to_empty(monkeypatch):
    from confidential_mode import gate_tools
    _without(monkeypatch, "tools.mcp_tool", "_mcp_tool_server_names")
    assert gate_tools._default_mcp_tool_servers() == {}
    _without(monkeypatch, "hermes_cli.plugins", "get_plugin_manager")
    assert gate_tools._default_plugin_tool_names() == set()
    _without(monkeypatch, "tools.mcp_tool_config", "_load_mcp_config")
    _without(monkeypatch, "tools.mcp_tool_scope", "_key_name")
    assert gate_tools._default_mcp_configs() == {}


def test_delegation_without_its_config_is_blocked(monkeypatch):
    from confidential_mode import gate_tools
    _without(monkeypatch, "tools.delegate_tool_config", "_load_config")
    assert gate_tools.default_delegation_ok({"goal": "x"}) is False


def test_preflight_and_provider_fall_back_to_their_snapshots(monkeypatch):
    from confidential_mode import locking, preflight, provider
    _without(monkeypatch, "hermes_cli.config_defaults", "DEFAULT_CONFIG")
    assert preflight.builtin_aux_task_names() == list(preflight.BUILTIN_AUX_TASKS_SNAPSHOT)
    _without(monkeypatch, "hermes_cli.plugins", "get_plugin_auxiliary_tasks")
    assert locking._plugin_aux(None) == []
    _without(monkeypatch, "agent.error_classifier", "_CONTEXT_OVERFLOW_PATTERNS")
    assert provider._is_overflow({}, "maximum context length exceeded") is True
    assert provider._is_overflow({}, "rate limited") is False


def test_runtime_contexts_fail_closed_and_open(monkeypatch):
    from confidential_mode import locking, sendctx
    _without(monkeypatch, "agent.auxiliary_client", "_RUNTIME_MAIN_CONTEXT", "_RELAY_AUX_CALL_CONTEXT")
    with pytest.raises(locking.LiveRuntimeUnreadable):
        locking.live_main_runtime()                                        # the turn is not sent
    assert sendctx.aux_current() is None                                   # unattributed, never raises


def test_yaml_read_of_the_allowlist_without_hermes_yaml(monkeypatch, tmp_path):
    from confidential_mode import gate_tools
    path = tmp_path / "allowlist.yaml"
    path.write_text("allowed: [a]\n")
    assert gate_tools._read_added(path) == {"a"}
    monkeypatch.setitem(sys.modules, "hermes_yaml", None)
    assert gate_tools._read_added(path) == set()                           # adds nothing

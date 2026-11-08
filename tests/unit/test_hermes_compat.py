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


def _is_public(module: str, name: str = "") -> bool:
    """Exactly the documented modules (``import providers``), or a public name taken from one
    (``from providers import get_provider_profile``); a submodule (``import providers.openrouter``) is not."""
    if not name:
        return module in PUBLIC
    return module in PUBLIC and not name.startswith("_")


def _private_uses(tree: ast.AST, hermes: set[str]) -> list[tuple[int, str]]:
    """(line, target) of every reach into a private Hermes name the scan can see statically:

    * ``import m`` / ``from m import n`` of a Hermes module outside the documented surface, or of a ``_`` name;
    * a ``_`` attribute on a name an import bound to a Hermes module or object (``tools.registry._x``,
      ``import tools.registry as r; r._x``, ``from tools.registry import registry; registry._tools``);
    * ``importlib.import_module("m")`` (``importlib`` or ``import_module`` under any alias) and
      ``__import__("m")`` with a literal name;
    * ``sys.modules["m"]`` and ``sys.modules.get / pop / setdefault("m")`` with a literal name.

    Out of reach, and left to review: module names built at run time (``"tools." + x``),
    ``getattr(__import__(...), ...)``, ``builtins.__import__`` and ``_`` attributes on values returned by calls.
    """
    out: list[tuple[int, str]] = []
    bound: dict[str, str] = {}
    importlib_names, import_module_names, sys_names = {"importlib"}, set(), {"sys"}

    def hermes_target(module: str) -> bool:
        return module.split(".")[0] in hermes

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or "importlib")
                elif alias.name == "sys":
                    sys_names.add(alias.asname or "sys")
                elif hermes_target(alias.name):
                    if not _is_public(alias.name):
                        out.append((node.lineno, alias.name))
                    if alias.asname:
                        bound[alias.asname] = alias.name
                    else:
                        top = alias.name.split(".")[0]
                        bound[top] = top
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                if node.module == "importlib" and alias.name == "import_module":
                    import_module_names.add(alias.asname or alias.name)
                elif hermes_target(node.module):
                    if not _is_public(node.module, alias.name):
                        out.append((node.lineno, f"{node.module}.{alias.name}"))
                    bound[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    loaders = {"__import__"} | {f"{n}.import_module" for n in importlib_names} | import_module_names
    sys_modules = {f"{n}.modules" for n in sys_names}

    def literal(arg: ast.AST) -> str:
        return arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in bound:
                out.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.Call) and node.args:
            func, module = ast.unparse(node.func), literal(node.args[0])
            sys_lookup = func in {f"{m}.{verb}" for m in sys_modules for verb in ("get", "pop", "setdefault")}
            if (func in loaders or sys_lookup) and module and hermes_target(module) and not _is_public(module):
                out.append((node.lineno, module))
        elif isinstance(node, ast.Subscript) and ast.unparse(node.value) in sys_modules:
            module = literal(node.slice)
            if module and hermes_target(module) and not _is_public(module):
                out.append((node.lineno, module))
    return out


def test_no_module_but_hermes_compat_imports_a_private_hermes_module():
    hermes = _hermes_top_level()
    assert {"tools", "agent", "hermes_cli", "hermes_yaml"} <= hermes
    offenders = []
    for path in _plugin_sources():
        rel = path.relative_to(ROOT).as_posix()
        if rel == COMPAT:
            continue
        offenders += [f"{rel}:{line} {target}"
                      for line, target in _private_uses(ast.parse(path.read_text(encoding="utf-8")), hermes)]
    assert offenders == [], "import private Hermes names through confidential_mode/hermes_compat.py"


def test_the_scan_sees_the_imports_in_hermes_compat():
    """Guards the scan itself: hermes_compat's own imports read as private."""
    found = [t for _l, t in _private_uses(ast.parse((ROOT / COMPAT).read_text(encoding="utf-8")),
                                          _hermes_top_level())]
    assert "tools.approval._presence" in found and "hermes_yaml" in found


@pytest.mark.parametrize("source", [
    "from tools import approval",
    "import tools.approval",
    "import providers.openrouter",
    "from providers import _private",
    "import tools.registry\ntools.registry._x",
    "import tools.registry as r\nr._x",
    "from tools.registry import registry\nregistry._tools",
    "import importlib as il\nil.import_module('tools.approval')",
    "from importlib import import_module as im\nim('tools.approval')",
    "__import__('tools.approval')",
    "import sys\nsys.modules['tools.approval']",
    "import sys\nsys.modules.get('agent.auxiliary_client')",
])
def test_the_scan_flags_each_form_it_covers(source):
    assert _private_uses(ast.parse(source), _hermes_top_level())


@pytest.mark.parametrize("source", [
    "import providers",
    "from providers import get_provider_profile",
    "from tools.registry import registry\nregistry.get_entry('x')",
    "import importlib\nimportlib.import_module(__package__ + '.provider')",
    "import sys\nsys.modules['confidential_mode.pins']",
    "import yaml",
    "x = object()\nx._y",
])
def test_the_scan_allows_the_documented_surface(source):
    assert _private_uses(ast.parse(source), _hermes_top_level()) == []


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
    ("tools.approval", ("_lock",), lambda: hc.approval_keys(None), ()),
    ("tools.approval", ("_yolo_active",), hc.approval_state_functions, ()),
    ("tools.approval_context", ("_get_approval_mode",), hc.approval_state_functions, ()),
    ("tools.approval", ("_presence",), hc.approval_state_functions, ()),
    ("tools.approval", ("is_approved",), lambda: hc.is_approved("s", "plugin_rule:x"), ()),
    ("tools.approval_context", ("get_current_session_key",), lambda: hc.current_session_key(""), ()),
    ("tools.approval", ("request_tool_approval",), hc.request_tool_approval_functions, ()),
    ("tools.approval_context", ("set_current_observability_context",), hc.request_tool_approval_functions, ()),
    ("tools.approval_context", ("reset_current_observability_context",), hc.request_tool_approval_functions, ()),
    ("tools.terminal_tool", ("_get_env_config",), hc.terminal_env_config_reader, ()),
    ("tools.terminal_tool_lifecycle", ("get_active_env",), hc.active_env_reader, ()),
    ("tools.terminal_tool", ("_active_environments",), hc.cached_terminal_environments, ()),
    ("tools.terminal_tool", ("_env_lock",), hc.cached_terminal_environments, ()),
    ("tools.terminal_scope", ("terminal_env",), lambda: hc.terminal_env_fallback("TERMINAL_ENV"), ()),
    ("tools.mcp_tool_config", ("_load_mcp_config",), hc.mcp_server_configs, ()),
    ("tools.mcp_tool", ("_servers",), hc.mcp_live_servers, ()),
    ("tools.mcp_tool", ("_lock",), hc.mcp_live_servers, ()),
    ("tools.mcp_tool", ("_lock",), hc.mcp_tool_server_names, ()),
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
    covered = {"yaml_module", "import_tool_module",           # tested on their own below
               "mcp_server_config", "env_backend_tag"}
    for _m, _n, call, _ in ACCESSORS:
        code = call.__code__
        covered |= set(code.co_names) | {getattr(call, "__name__", "")}
    assert public <= covered, public - covered


def test_each_accessor_reads_hermes_at_call_time(monkeypatch):
    """A patch of the Hermes module is seen by the next call: nothing is cached at import."""
    import tools.approval as approval
    monkeypatch.setattr(approval, "_yolo_active", lambda: "patched")
    assert hc.approval_state_functions()[0]() == "patched"


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


def test_attribute_readers_default_to_none():
    from types import SimpleNamespace
    assert hc.mcp_server_config(SimpleNamespace(_config={"url": "u"})) == {"url": "u"}
    assert hc.mcp_server_config(object()) is None
    assert hc.env_backend_tag(SimpleNamespace(env_type="ssh", _hermes_backend_name="docker")) == "ssh"
    assert hc.env_backend_tag(SimpleNamespace(_hermes_backend_name="docker")) == "docker"
    assert hc.env_backend_tag(object()) is None


def test_plugin_tool_names_without_the_attribute_is_empty(monkeypatch):
    import hermes_cli.plugins as plugins
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: object())
    assert hc.plugin_tool_names() == set()


@pytest.mark.parametrize("missing", ["request_tool_approval", "set_current_observability_context",
                                     "reset_current_observability_context"])
def test_a_missing_approval_function_asks_nobody_and_binds_nothing(monkeypatch, missing):
    """Review S1: the three functions are resolved before the context is set, so a Hermes without one of
    them neither shows the prompt nor leaves the plugin's ids bound for Hermes' later approvals."""
    import tools.approval as approval
    import tools.approval_context as ac
    from confidential_mode import gate_tools
    asked, bound = [], []
    if missing != "request_tool_approval":
        monkeypatch.setattr(approval, "request_tool_approval",
                            lambda name, reason, rule_key="": asked.append(name) or {"choice": "once"})
    if missing != "set_current_observability_context":
        real_set = ac.set_current_observability_context
        monkeypatch.setattr(ac, "set_current_observability_context",
                            lambda **kw: bound.append(kw) or real_set(**kw))
    monkeypatch.delattr(approval if missing == "request_tool_approval" else ac, missing)
    before = (ac._approval_tool_call_id.get(), ac._approval_turn_id.get(), ac._approval_session_id.get())
    with pytest.raises(ImportError):
        gate_tools.hermes_request_approval("web_search", "m", rule_key="k", approval_id="APPROVAL-1",
                                           turn_id="t", session_id="s")
    assert asked == [] and bound == []
    assert (ac._approval_tool_call_id.get(), ac._approval_turn_id.get(), ac._approval_session_id.get()) == before


def test_yolo_on_with_approval_mode_missing_reads_as_unattended(monkeypatch):
    """Review L1: the three approval readers are resolved before any is read, so a missing one gives the
    unattended refusal text even while yolo is on."""
    import tools.approval as approval
    import tools.approval_context as ac
    from confidential_mode import gate_tools
    monkeypatch.setattr(approval, "_yolo_active", lambda: True)
    monkeypatch.setattr(approval, "_presence", lambda cb=None: (None, True, False, False))
    monkeypatch.delattr(ac, "_get_approval_mode")
    assert gate_tools.hermes_bypass_active("web_search") is True
    assert gate_tools.hermes_bypass_is_interactive() is False

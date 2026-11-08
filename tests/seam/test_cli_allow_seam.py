"""Seam test for `hermes confidential allow <tool>` run in its own process (ux-pass-1, item 2).

The CLI process never builds an agent, so Hermes' built-in tools were never imported there and its registry
held no built-in tool. Its allowlist rebuild then kept nothing, and every `allow` was refused as "not
registered when the session was locked". The plugin loaded by real discovery plays the running gateway. The
CLI runs as a real `hermes confidential` subprocess on a pseudo-terminal, and the person's answer is typed
into it."""
from __future__ import annotations

import json
import os
import pty
import subprocess
import sys
from pathlib import Path

from ._harness import no_lazy_installs  # noqa: F401  (fixture)
from .test_register import plugin  # noqa: F401  (fixture)


def _hermes_tty(plugin, *argv, answer: str):
    """`hermes confidential <argv>` with stdin on a pseudo-terminal holding ``answer``."""
    exe = Path(sys.executable).with_name("hermes")
    cmd = [str(exe)] if exe.exists() else [sys.executable, "-m", "hermes_cli.main"]
    env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIDENTIAL_MODE_TOOL_PROCESS"}
    env.update({"HERMES_HOME": str(plugin.home), "PYTHONDONTWRITEBYTECODE": "1"})
    master, slave = pty.openpty()
    try:
        os.write(master, answer.encode())
        return subprocess.run(cmd + ["confidential", *argv], stdin=slave, capture_output=True, text=True,
                              env=env, timeout=180)
    finally:
        os.close(slave)
        os.close(master)


def _hermes(plugin, *argv):
    exe = Path(sys.executable).with_name("hermes")
    cmd = [str(exe)] if exe.exists() else [sys.executable, "-m", "hermes_cli.main"]
    env = {**os.environ, "HERMES_HOME": str(plugin.home), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(cmd + ["confidential", *argv], capture_output=True, text=True, env=env, timeout=180,
                          stdin=subprocess.DEVNULL)


def test_cli_lock_then_cli_allow_web_search_reaches_the_gateway(plugin, monkeypatch):
    import model_tools
    import tools.web_tools as web_tools
    ran = []
    # The registered handler stays the real one (its identity is what the CLI's lock recorded); only the
    # search it calls is replaced, so nothing leaves the machine.
    monkeypatch.setattr(web_tools, "web_search_tool", lambda query, limit=5: ran.append(query) or json.dumps({"ok": 1}))
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    proc = _hermes(plugin, "on", "on-host-only")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    proc = _hermes_tty(plugin, "allow", "web_search", answer="1\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.rstrip().endswith("web_search added to the allowlist for this lock."), proc.stdout
    assert json.loads(plugin.rt.allowlist_path.read_text())["allowed"] == ["web_search"]

    plugin.human("deny")            # a prompt would be answered "deny": the call runs only if nobody is asked
    model_tools.handle_function_call("web_search", {"query": "q1"}, task_id="t", session_id="s", tool_call_id="c1")
    assert ran == ["q1"] and plugin.prompts == []
    kinds = [(e.kind, e.decision) for e in plugin.rt.ledger.tail(0)]
    assert ("tool_allowed", "allowlist_add") in kinds and ("tool_allowed", "allowlist") in kinds


def test_cli_allow_of_a_tool_only_the_gateway_registered_says_so(plugin, monkeypatch):
    """Through a real CLI process. A tool the lock recorded but only the gateway registered (an MCP tool):
    the CLI refuses and says to allow the tool from chat. A tool the lock never recorded: the CLI says no
    allow can help and that a relock from chat records gateway-only tools."""
    import importlib

    from tools.registry import registry
    schema = {"name": "mcp_docs_search", "description": "x", "parameters": {"type": "object", "properties": {}}}
    # A real MCP handler, as tools/mcp_tool_registration.py builds one: its module is tools.mcp_tool_handlers,
    # which registers nothing on import, so the CLI must not fall back to a full tool discovery for it.
    handlers = importlib.import_module("tools.mcp_tool_handlers")
    handler = handlers._make_tool_handler("docs", "search", 30.0)
    registry.register(name="mcp_docs_search", toolset="mcp-docs", schema=schema, handler=handler)
    cache = plugin.home / "cache" / "tool_discovery_cache.json"
    try:
        assert plugin.slash("on on-host-only").startswith("Locked")        # the gateway locks: records the tool
        persisted = json.loads(plugin.rt.allowlist_path.read_text())["tools"]
        assert any(t["name"] == "mcp_docs_search" and t["module"] == "tools.mcp_tool_handlers" for t in persisted)
        before = cache.stat().st_mtime_ns if cache.exists() else None
        proc = _hermes(plugin, "allow", "mcp_docs_search")
    finally:
        registry.deregister("mcp_docs_search")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.stdout.startswith("mcp_docs_search is an MCP tool that only the gateway connects, so this "
                                  "terminal process cannot allow mcp_docs_search."), proc.stdout
    assert "In the chat session, run /confidential allow mcp_docs_search." in proc.stdout
    assert "relock from chat first: /confidential off, then /confidential on <tier>." in proc.stdout
    assert (cache.stat().st_mtime_ns if cache.exists() else None) == before      # no discovery-cache rewrite
    proc = _hermes(plugin, "allow", "never_registered_tool")
    assert proc.returncode == 1 and proc.stdout.startswith(
        "Unknown tool 'never_registered_tool'; never_registered_tool was not registered when this lock was made."
    ), proc.stdout
    assert "relock from chat: /confidential off, then /confidential on <tier>." in proc.stdout
    assert "/confidential allow never_registered_tool" not in proc.stdout

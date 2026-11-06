"""Unit tests for confidential_mode.gate_tools over a fake registry. No Hermes import: every Hermes
default (MCP configs, plugin names, bypass detection, delegation config) is injected."""
from __future__ import annotations

import functools
import json
from types import SimpleNamespace

import pytest

from confidential_mode.gate_tools import (
    LOCAL_TOOLS, PATTERN_KEY_PREFIX, Allowlist, Origin, Route, args_kb, build_allowlist,
    build_post_approval_response, build_pre_tool_call, default_delegation_ok, format_allowlist, rule_key_for,
)


def _builtin_handler(args, **kw):
    return "{}"


def _plugin_handler_factory():
    ns = {"__name__": "hermes_plugins.someplugin.tools"}
    exec("def handler(args, **kw):\n    return '{}'\n", ns)
    return ns["handler"]


class FakeRegistry:
    def __init__(self, entries):
        self._entries = [SimpleNamespace(name=n, toolset=ts, handler=h) for n, ts, h in entries]

    def get_all_entries(self):
        return list(self._entries)


class FakeLedger:
    def __init__(self, fail=False):
        self.events, self.fail = [], fail

    def append(self, event):
        if self.fail:
            raise OSError("disk full")
        self.events.append(event)

    def kinds(self):
        return [e["kind"] for e in self.events]


ENTRIES = [(n, "core", _builtin_handler) for n in sorted(LOCAL_TOOLS)] + [
    ("cronjob_manage", "cronjob", _builtin_handler),
    ("delegate_task", "delegation", _builtin_handler),
    ("web_search", "web", _builtin_handler),
    ("vision_analyze", "vision", functools.partial(_builtin_handler)),
    ("remote_query", "mcp-remote", _builtin_handler),
    ("local_query", "mcp-localsrv", _builtin_handler),
    ("ghost_query", "mcp-ghost", _builtin_handler),          # no config anywhere
    ("both_query", "mcp-both", _builtin_handler),            # url AND command: url wins
    ("lh_query", "mcp-lh", _builtin_handler),                # http://localhost URL: local
    ("lan_query", "mcp-lan", _builtin_handler),              # RFC1918 URL: local
    ("obf_query", "mcp-obf", _builtin_handler),              # obfuscated loopback: off-tier
    ("plug_tool", "someplugin", _plugin_handler_factory()),
    ("named_plug", "other", _builtin_handler),               # plugin by manager name list
]
MCP_CONFIGS = {
    "remote": {"url": "https://mcp.example.com/mcp"},
    "localsrv": {"command": "npx", "args": ["some-server"]},
    "both": {"url": "https://x.example/mcp", "command": "x"},
    "lh": {"url": "http://localhost:8765/mcp"},
    "lan": {"url": "http://10.0.0.5:9000/mcp"},
    "obf": {"url": "http://0x7f000001/mcp"},
}


def allowlist(**kw):
    return build_allowlist(FakeRegistry(kw.pop("entries", ENTRIES)), mcp_configs=kw.pop("mcp_configs", MCP_CONFIGS),
                           mcp_tool_servers=kw.pop("mcp_tool_servers", {}),
                           plugin_tool_names=kw.pop("plugin_tool_names", {"named_plug"}))


# --------------------------------------------------------------------------------------------------
# allowlist
# --------------------------------------------------------------------------------------------------

def test_local_set_is_exactly_the_contract():
    assert LOCAL_TOOLS == {
        "terminal", "process_manage", "execute_code", "read_file", "write_file", "patch", "search_files",
        "skills_list", "skill_view", "skill_manage", "todo_list", "memory", "clarify", "session_search"}
    al = allowlist()
    assert set(al.local) - {"lh_query", "lan_query"} == LOCAL_TOOLS


def test_registry_driven_classification():
    al = allowlist()
    r = {n: al.get(n).route for n in al.tools}
    assert r["cronjob_manage"] is Route.BLOCK_CRON
    assert r["delegate_task"] is Route.DELEGATE
    assert r["web_search"] is Route.ASK and r["vision_analyze"] is Route.ASK
    assert r["remote_query"] is Route.BLOCK_MCP_URL
    assert r["both_query"] is Route.BLOCK_MCP_URL
    assert r["ghost_query"] is Route.BLOCK_MCP_URL          # unknown transport: fail closed
    assert r["local_query"] is Route.ASK                    # stdio MCP: off-machine, ask
    assert al.get("remote_query").origin is Origin.MCP
    assert (al.get("remote_query").mcp_server, al.get("remote_query").mcp_transport) == ("remote", "url")
    assert al.get("local_query").mcp_transport == "stdio"
    assert al.get("ghost_query").mcp_transport == "unknown"
    assert r["lh_query"] is Route.LOCAL and al.get("lh_query").mcp_host == "localhost"
    assert r["lan_query"] is Route.LOCAL
    assert r["obf_query"] is Route.BLOCK_MCP_URL
    assert al.get("plug_tool").origin is Origin.PLUGIN      # hermes_plugins.* handler module
    assert al.get("named_plug").origin is Origin.PLUGIN     # plugin manager's tool-name list
    assert al.get("web_search").origin is Origin.BUILTIN
    assert al.get("vision_analyze").origin is Origin.BUILTIN  # partial unwrapped to this module


def test_mcp_server_name_comes_from_hermes_map_when_present():
    # Hermes' raw-name map wins over the toolset suffix (tools/mcp_tool.py:561).
    al = allowlist(entries=[("q", "mcp-remote", _builtin_handler)], mcp_tool_servers={"q": "localsrv"})
    assert al.get("q").mcp_server == "localsrv" and al.get("q").route is Route.ASK


def test_local_name_overridden_by_plugin_is_not_local():
    al = allowlist(entries=[("read_file", "evil", _plugin_handler_factory())])
    assert al.get("read_file").origin is Origin.PLUGIN and al.get("read_file").route is Route.ASK


def test_format_allowlist_lists_every_bucket():
    al = allowlist()
    text = format_allowlist(al)
    assert "local (runs without asking): 16" in text
    assert "blocked (MCP server URL off-tier or unreadable): 4" in text
    assert "blocked (scheduled jobs): 1" in text
    assert "remote_query  [mcp-remote; mcp; server=remote, transport=url, host=mcp.example.com]" in text
    for name in al.tools:
        assert f"  {name}  [" in text


def test_allowlist_add_only_for_ask_route():
    al = allowlist()
    al.add("web_search")
    assert al.is_added("web_search")
    for name in ("cronjob_manage", "delegate_task", "remote_query", "read_file", "nope"):
        with pytest.raises(ValueError):
            al.add(name)


# --------------------------------------------------------------------------------------------------
# pre_tool_call
# --------------------------------------------------------------------------------------------------

def gate(sealed=True, bypass=False, delegation=True, al=None, ledger=None, remembered=False):
    ledger = ledger if ledger is not None else FakeLedger()
    al = al or allowlist()
    calls = {"bypass": [], "delegation": []}

    def bypass_active(name):
        calls["bypass"].append(name)
        return bypass

    def delegation_ok(args):
        calls["delegation"].append(args)
        return delegation

    fn = build_pre_tool_call(lambda: sealed, al, ledger, bypass_active, delegation_ok, lambda n: remembered)
    return fn, ledger, calls, al


def test_unsealed_returns_none_and_ledgers_nothing():
    fn, ledger, calls, _ = gate(sealed=False)
    for name in ("web_search", "cronjob_manage", "remote_query", "delegate_task", "never_registered"):
        assert fn(tool_name=name, args={"q": "x"}, session_id="s") is None
    assert ledger.events == [] and calls == {"bypass": [], "delegation": []}


def test_sealed_local_tools_pass_silently():
    fn, ledger, calls, _ = gate(bypass=True)
    for name in LOCAL_TOOLS:
        assert fn(tool_name=name, args={"path": "/etc/hosts"}, session_id="s") is None
    assert ledger.events == [] and calls["bypass"] == []


def test_cronjob_manage_blocked_even_when_everything_else_would_allow():
    fn, ledger, calls, _ = gate(bypass=False, delegation=True)
    d = fn(tool_name="cronjob_manage", args={"action": "create"}, session_id="s", tool_call_id="c1")
    assert d["action"] == "block" and "cronjob_manage" in d["message"]
    assert ledger.kinds() == ["tool_refused"]
    e = ledger.events[0]
    assert e["decision"] == "cron" and e["purpose"] == "tool:cronjob_manage" and e["session_id"] == "s"
    assert e["detail"]["tool_call_id"] == "c1"


def test_mcp_url_tool_blocked_without_asking():
    fn, ledger, calls, _ = gate(bypass=False)
    d = fn(tool_name="remote_query", args={}, session_id="s")
    assert d["action"] == "block" and "remote" in d["message"]
    assert ledger.kinds() == ["tool_refused"] and ledger.events[0]["decision"] == "mcp_url"
    assert calls["bypass"] == []


def test_delegate_task_allowed_only_via_delegation_ok():
    fn, ledger, calls, _ = gate(delegation=True)
    args = {"tasks": [{"goal": "g"}]}
    assert fn(tool_name="delegate_task", args=args, session_id="s") is None
    assert calls["delegation"] == [args]
    assert ledger.kinds() == ["tool_allowed"] and ledger.events[0]["decision"] == "delegation_default"
    # mutant twin: predicate says no -> block
    fn, ledger, calls, _ = gate(delegation=False)
    d = fn(tool_name="delegate_task", args=args, session_id="s")
    assert d["action"] == "block" and ledger.kinds() == ["tool_refused"]
    assert ledger.events[0]["decision"] == "delegation_route"


def test_off_machine_tool_returns_approve_directive_with_kb_message():
    fn, ledger, calls, _ = gate(bypass=False)
    args = {"query": "x" * 3000}
    d = fn(tool_name="web_search", args=args, session_id="s")
    n = -(-len(json.dumps(args)) // 1024)
    assert n == 3
    assert d == {"action": "approve", "message": f"web_search wants to send ~{n} KB of this conversation off the machine",
                 "rule_key": rule_key_for("web_search")}
    assert calls["bypass"] == ["web_search"]
    assert ledger.kinds() == ["tool_asked"]
    assert ledger.events[0]["bytes"] == len(json.dumps(args)) and ledger.events[0]["detail"]["kb"] == 3


def test_stdio_mcp_tool_is_asked_like_other_off_machine_tools():
    fn, ledger, _, _ = gate(bypass=False)
    assert fn(tool_name="local_query", args={}, session_id="s")["action"] == "approve"


@pytest.mark.parametrize("size,kb", [(0, 1), (1, 1), (1024, 1), (1025, 2), (2048, 2), (2049, 3), (10 * 1024 + 1, 11)])
def test_kb_rounding_is_ceiling_of_json_length(size, kb):
    # json.dumps({"q": s}) adds 9 chars of framing: {"q": ""}
    s = "a" * max(0, size - 9)
    args = {"q": s}
    if size >= 9:
        assert len(json.dumps(args)) == size
    assert args_kb(args) == max(1, -(-len(json.dumps(args)) // 1024))
    if size >= 9:
        assert args_kb(args) == kb


def test_kb_uses_json_dumps_default_escaping():
    args = {"q": "é" * 600}   # json.dumps escapes to é: 6 chars each -> 3609 chars
    assert len(json.dumps(args)) == 3609 and args_kb(args) == 4


def test_yolo_or_any_bypass_blocks_instead_of_approving():
    fn, ledger, calls, _ = gate(bypass=True)
    d = fn(tool_name="web_search", args={"q": "x"}, session_id="s")
    assert d["action"] == "block" and "bypassed" in d["message"]
    assert ledger.kinds() == ["tool_refused"] and ledger.events[0]["decision"] == "bypass_active"
    # mutant twin: same tool, no bypass -> approve
    fn, ledger, _, _ = gate(bypass=False)
    assert fn(tool_name="web_search", args={"q": "x"}, session_id="s")["action"] == "approve"


def test_zero_arg_bypass_callable_from_the_contract_is_accepted():
    ledger = FakeLedger()
    fn = build_pre_tool_call(lambda: True, allowlist(), ledger, lambda: True, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    fn = build_pre_tool_call(lambda: True, allowlist(), ledger, lambda: False, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "approve"


def test_user_added_tool_runs_without_asking_and_is_ledgered():
    fn, ledger, calls, al = gate(bypass=True)
    al.add("web_search")
    assert fn(tool_name="web_search", args={}, session_id="s") is None
    assert ledger.kinds() == ["tool_allowed"] and ledger.events[0]["decision"] == "allowlist"


def test_unclassified_tool_is_blocked():
    fn, ledger, _, _ = gate(bypass=False)
    d = fn(tool_name="registered_after_seal", args={}, session_id="s")
    assert d["action"] == "block" and ledger.events[0]["decision"] == "unclassified"


def test_errors_fail_closed():
    # bypass predicate raising -> block
    def boom(name):
        raise RuntimeError("x")
    fn = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(), boom, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    # ledger raising -> block (even for the would-be approve)
    fn = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(fail=True), lambda n: False, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    # is_sealed raising -> treated as sealed
    def sealed_boom():
        raise RuntimeError("state gone")
    fn = build_pre_tool_call(sealed_boom, allowlist(), FakeLedger(), lambda n: False, lambda a: True)
    assert fn(tool_name="cronjob_manage", args={}, session_id="s")["action"] == "block"
    # local still passes when the ledger is broken (nothing to ledger)
    fn = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(fail=True), lambda n: False, lambda a: True)
    assert fn(tool_name="read_file", args={}, session_id="s") is None


def test_allowlist_may_be_a_callable_for_reseal():
    box = {"al": allowlist()}
    fn = build_pre_tool_call(lambda: True, lambda: box["al"], FakeLedger(), lambda n: False, lambda a: True)
    assert fn(tool_name="new_tool", args={}, session_id="s")["action"] == "block"
    box["al"] = allowlist(entries=ENTRIES + [("new_tool", "x", _builtin_handler)])
    assert fn(tool_name="new_tool", args={}, session_id="s")["action"] == "approve"


# --------------------------------------------------------------------------------------------------
# post_approval_response
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("choice,kind", [
    ("once", "tool_allowed"), ("session", "tool_allowed"), ("always", "tool_allowed"),
    ("deny", "tool_refused"), ("timeout", "tool_refused"), ("cancelled", "tool_refused"),
    ("notify_failed", "tool_refused"), ("", "tool_refused"),
])
def test_post_approval_response_ledgers_choice(choice, kind):
    ledger = FakeLedger()
    post = build_post_approval_response(lambda: True, ledger)
    post(command="<web_search> (plugin approval rule)", description="m", pattern_key=PATTERN_KEY_PREFIX + "web_search",
         pattern_keys=[], session_key="sk", surface="cli", choice=choice, session_id="s", tool_call_id="c")
    assert ledger.kinds() == [kind]
    e = ledger.events[0]
    assert e["purpose"] == "tool:web_search" and e["detail"]["choice"] == choice and e["surface"] == "cli"


def test_post_approval_response_ignores_other_rules_and_never_raises():
    ledger = FakeLedger()
    post = build_post_approval_response(lambda: True, ledger)
    post(pattern_key="plugin_rule:web_search", choice="once")              # someone else's (default rule_key)
    post(pattern_key="rm -rf", choice="once")                               # a dangerous-command key
    post(choice="once")
    assert ledger.events == []
    post = build_post_approval_response(lambda: True, FakeLedger(fail=True))
    assert post(pattern_key=PATTERN_KEY_PREFIX + "x", choice="once") is None


# --------------------------------------------------------------------------------------------------
# default delegation predicate
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cfg,args,ok", [
    ({}, {"tasks": [{"goal": "g"}]}, True),
    ({"backend": "default", "model": "m", "max_iterations": 5}, {"goal": "g"}, True),
    ({"backend": "Default"}, {"tasks": [{"goal": "g", "context": "c"}]}, True),
    ({"backend": "other"}, {"tasks": [{"goal": "g"}]}, False),
    ({"backend": 3}, {"tasks": [{"goal": "g"}]}, False),
    ({"profile": "work"}, {"tasks": [{"goal": "g"}]}, False),
    ({"command": "claude"}, {"tasks": [{"goal": "g"}]}, False),
    ({"args": ["--acp"]}, {"tasks": [{"goal": "g"}]}, False),
    ({"provider": "openrouter"}, {"tasks": [{"goal": "g"}]}, False),
    ({"base_url": "https://api.example.com/v1"}, {"tasks": [{"goal": "g"}]}, False),
    ({}, {"tasks": [{"goal": "g", "acp_command": "claude"}]}, False),
    ({}, {"tasks": [{"goal": "g", "acp_args": ["x"]}]}, False),
    ({}, {"tasks": [{"goal": "g", "profile": "work"}]}, False),
    ({}, {"tasks": [{"goal": "g", "provider": "openrouter"}]}, False),
    ({}, {"goal": "g", "profile": "work"}, False),
    ({}, {"tasks": "not a list"}, False),
    ({}, {"tasks": ["not a dict"]}, False),
])
def test_default_delegation_ok(cfg, args, ok):
    assert default_delegation_ok(args, load_config=lambda: cfg) is ok


def test_default_delegation_ok_fails_closed_on_config_error():
    def boom():
        raise RuntimeError("config unreadable")
    assert default_delegation_ok({"goal": "g"}, load_config=boom) is False


# --------------------------------------------------------------------------------------------------
# Amendment 1: MCP URL servers classified by host under the active predicate
# --------------------------------------------------------------------------------------------------

def _mcp_only(url, predicate=None):
    al = build_allowlist(FakeRegistry([("q", "mcp-s", _builtin_handler)]), mcp_configs={"s": {"url": url}},
                         mcp_tool_servers={}, plugin_tool_names=set(), predicate=predicate)
    return al.get("q")


@pytest.mark.parametrize("url,route", [
    ("http://127.0.0.1:8000/mcp", Route.LOCAL), ("http://[::1]:8000/mcp", Route.LOCAL),
    ("http://192.168.1.4/mcp", Route.LOCAL), ("https://api.example.com/mcp", Route.BLOCK_MCP_URL),
    ("http://169.254.169.254/mcp", Route.BLOCK_MCP_URL), ("http://127.1/mcp", Route.BLOCK_MCP_URL),
    ("http://localhost\\@evil.com/mcp", Route.BLOCK_MCP_URL), ("", Route.BLOCK_MCP_URL),
])
def test_mcp_url_host_classification_default_local_predicate(url, route):
    assert _mcp_only(url).route is route


def test_mcp_url_uses_injected_predicate():
    from confidential_mode.tiers import AttestedPredicate, LocalPredicate, Verdict

    class InTier:
        def classify(self, dest):
            assert dest.purpose == "mcp:s" and dest.base_url == "https://enclave.example/mcp"
            return Verdict(True, "fake in-tier", "enclave.example")
    info = _mcp_only("https://enclave.example/mcp", InTier())
    assert info.route is Route.ASK and info.reason == "fake in-tier"   # not blocked, still asked
    # attested predicate: a remote MCP host is not an attested profile -> blocked; localhost still local
    att = AttestedPredicate(["attested-tinfoil"], lambda p: Verdict(True, "ok", ""))
    assert _mcp_only("https://mcp.example.com/mcp", att).route is Route.BLOCK_MCP_URL
    assert _mcp_only("http://localhost:9/mcp", att).route is Route.LOCAL
    # LocalPredicate extra_hosts are honoured
    assert _mcp_only("http://mcpbox.lan/mcp", LocalPredicate(extra_hosts=["mcpbox.lan"])).route is Route.LOCAL
    assert _mcp_only("http://mcpbox.lan/mcp").route is Route.BLOCK_MCP_URL

    class Raises:
        def classify(self, dest):
            raise RuntimeError("x")
    assert _mcp_only("https://mcp.example.com/mcp", Raises()).route is Route.BLOCK_MCP_URL


def test_localhost_mcp_tool_runs_without_asking():
    fn, ledger, calls, _ = gate(bypass=True)
    assert fn(tool_name="lh_query", args={}, session_id="s") is None
    assert ledger.events == [] and calls["bypass"] == []


def test_mode_tools_are_plain_local_today():
    from confidential_mode.gate_tools import MODE_TOOLS
    assert MODE_TOOLS == {"terminal", "execute_code"} and MODE_TOOLS <= LOCAL_TOOLS
    al = allowlist()
    assert all(al.get(n).mode is None and al.get(n).route is Route.LOCAL for n in MODE_TOOLS)


# --------------------------------------------------------------------------------------------------
# Amendment 2: remembered grants honoured; is_sealed() -> (bool, Tier | None)
# --------------------------------------------------------------------------------------------------

def test_remembered_grant_is_honoured_and_ledgered():
    fn, ledger, calls, _ = gate(bypass=False, remembered=True)
    d = fn(tool_name="web_search", args={"q": "x"}, session_id="s")
    assert d["action"] == "approve" and d["rule_key"] == rule_key_for("web_search")
    assert ledger.kinds() == ["tool_allowed"] and ledger.events[0]["decision"] == "remembered"
    # mutant twin: no grant -> asked
    fn, ledger, _, _ = gate(bypass=False, remembered=False)
    fn(tool_name="web_search", args={"q": "x"}, session_id="s")
    assert ledger.kinds() == ["tool_asked"]


def test_bypass_still_blocks_with_a_remembered_grant():
    fn, ledger, _, _ = gate(bypass=True, remembered=True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    assert ledger.events[0]["decision"] == "bypass_active"


def test_is_sealed_tuple_shape():
    from confidential_mode.tiers import Tier
    ledger = FakeLedger()
    fn = build_pre_tool_call(lambda: (False, None), allowlist(), ledger, lambda n: False, lambda a: True)
    assert fn(tool_name="cronjob_manage", args={}, session_id="s") is None and ledger.events == []
    fn = build_pre_tool_call(lambda: (True, Tier.LOCAL), allowlist(), ledger, lambda n: False, lambda a: True)
    assert fn(tool_name="cronjob_manage", args={}, session_id="s")["action"] == "block"

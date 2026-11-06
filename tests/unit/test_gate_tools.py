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
    assert set(al.local) - {"lh_query", "lan_query", "local_query"} == LOCAL_TOOLS


def test_registry_driven_classification():
    al = allowlist()
    r = {n: al.get(n).route for n in al.tools}
    assert r["cronjob_manage"] is Route.BLOCK_CRON
    assert r["delegate_task"] is Route.DELEGATE
    assert r["web_search"] is Route.ASK and r["vision_analyze"] is Route.ASK
    assert r["remote_query"] is Route.BLOCK_MCP_URL
    assert r["both_query"] is Route.BLOCK_MCP_URL
    assert r["ghost_query"] is Route.BLOCK_MCP_URL          # unknown transport: fail closed
    assert r["local_query"] is Route.LOCAL                  # stdio MCP: allowed per Amendment 3
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
    assert al.get("q").mcp_server == "localsrv" and al.get("q").route is Route.LOCAL


def test_local_name_overridden_by_plugin_is_not_local():
    al = allowlist(entries=[("read_file", "evil", _plugin_handler_factory())])
    assert al.get("read_file").origin is Origin.PLUGIN and al.get("read_file").route is Route.ASK


def test_format_allowlist_lists_every_bucket():
    al = allowlist()
    text = format_allowlist(al)
    assert "local (runs without asking): 17" in text
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
# pre_tool_call (first line: blocks refusals, never asks) and tool_execution (enforcement, asks)
# --------------------------------------------------------------------------------------------------

class Rig:
    """Both enforcement points over one fake world. ``answer`` is the recorded post_approval_response
    choice (None = no hook fired); ``hermes_approved`` is what Hermes' gate returned."""

    def __init__(self, sealed=True, bypass=False, delegation=True, remembered=False, answer="once",
                 hermes_approved=True, al=None, ledger=None, status=None):
        from confidential_mode.gate_tools import ApprovalDecisions, build_tool_execution
        self.ledger = ledger if ledger is not None else FakeLedger()
        self.al = al or allowlist()
        self.calls = {"bypass": [], "delegation": [], "ask": [], "ran": []}
        self.decisions = ApprovalDecisions()
        self.post = build_post_approval_response(lambda: sealed, self.ledger, self.decisions)

        def bypass_active(name):
            self.calls["bypass"].append(name)
            return bypass

        def delegation_ok(args):
            self.calls["delegation"].append(args)
            return delegation

        def ask(tool_name, message, *, rule_key, approval_id, session_id="", turn_id=""):
            self.calls["ask"].append((tool_name, message, rule_key))
            if answer is not None:
                self.post(pattern_key="plugin_rule:" + rule_key, choice=answer, session_id=session_id,
                          tool_call_id=approval_id, surface="cli")
            res = {"approved": hermes_approved, "message": None if hermes_approved else "BLOCKED: denied"}
            if status:
                res["status"] = status
            return res

        sealed_fn = sealed if callable(sealed) else (lambda: sealed)
        self.hook = build_pre_tool_call(sealed_fn, self.al, self.ledger, bypass_active, delegation_ok,
                                        lambda n: remembered)
        self.mw = build_tool_execution(sealed_fn, self.al, self.ledger, self.decisions, bypass_active=bypass_active,
                                       delegation_ok=delegation_ok, remembered=lambda n: remembered, ask=ask)

    def run(self, name, args=None, **kw):
        args = {} if args is None else args

        def next_call(a):
            self.calls["ran"].append((name, a))
            return '{"ok": true}'
        return self.mw(tool_name=name, args=args, next_call=next_call, session_id="s", tool_call_id="c1", **kw)

    def ran(self):
        return [n for n, _ in self.calls["ran"]]


def refused(out):
    return isinstance(out, str) and "error" in json.loads(out)


def test_unsealed_passes_everything_and_ledgers_nothing():
    for sealed in (False, (False, None)):
        r = Rig(sealed=sealed)
        for name in ("web_search", "cronjob_manage", "remote_query", "delegate_task", "never_registered"):
            assert r.hook(tool_name=name, args={"q": "x"}, session_id="s") is None
            assert r.run(name, {"q": "x"}) == '{"ok": true}'
        assert r.ledger.events == [] and r.calls["ask"] == [] and r.calls["bypass"] == []


def test_sealed_local_tools_run_silently_even_under_bypass():
    r = Rig(bypass=True)
    for name in sorted(LOCAL_TOOLS) + ["lh_query", "lan_query", "local_query"]:
        assert r.hook(tool_name=name, args={}, session_id="s") is None
        r.run(name)
    assert len(r.ran()) == len(LOCAL_TOOLS) + 3 and r.ledger.events == [] and r.calls["bypass"] == []


@pytest.mark.parametrize("name,decision", [("cronjob_manage", "cron"), ("remote_query", "mcp_url"),
                                           ("ghost_query", "mcp_url"), ("registered_after_seal", "unclassified")])
def test_block_routes_refused_by_both_lines(name, decision):
    r = Rig(bypass=False, delegation=True, answer="once")
    d = r.hook(tool_name=name, args={"x": 1}, session_id="s", tool_call_id="c1")
    assert d["action"] == "block" and r.ledger.events[-1]["decision"] == decision
    out = r.run(name, {"x": 1})
    assert refused(out) and r.ran() == [] and r.calls["ask"] == []
    assert r.ledger.kinds() == ["tool_refused", "tool_refused"]
    assert r.ledger.events[1]["surface"] == "middleware" and r.ledger.events[1]["decision"] == decision
    if decision == "unclassified":
        assert "seal again" in d["message"]


def test_delegate_task_only_via_delegation_ok():
    r = Rig(delegation=True)
    args = {"tasks": [{"goal": "g"}]}
    assert r.hook(tool_name="delegate_task", args=args, session_id="s") is None
    r.run("delegate_task", args)
    assert r.ran() == ["delegate_task"] and r.ledger.kinds() == ["tool_allowed"]
    assert r.ledger.events[0]["decision"] == "delegation_default"
    r = Rig(delegation=False)
    assert r.hook(tool_name="delegate_task", args=args, session_id="s")["action"] == "block"
    assert refused(r.run("delegate_task", args)) and r.ran() == []
    assert [e["decision"] for e in r.ledger.events] == ["delegation_route", "delegation_route"]


def test_hook_never_returns_the_approve_directive():
    r = Rig()
    assert r.hook(tool_name="web_search", args={"q": "x"}, session_id="s") is None
    assert r.ledger.events == [] and r.calls["ask"] == []


def test_off_machine_tool_asks_with_kb_message_and_runs_on_explicit_answer():
    for answer in ("once", "session", "always"):
        r = Rig(answer=answer)
        args = {"query": "x" * 3000}
        out = r.run("web_search", args)
        n = -(-len(json.dumps(args)) // 1024)
        assert n == 3 and out == '{"ok": true}' and r.ran() == ["web_search"]
        assert r.calls["ask"] == [("web_search", f"web_search wants to send ~{n} KB of this conversation off the machine",
                                   rule_key_for("web_search"))]
        assert r.ledger.kinds() == ["tool_asked", "tool_allowed"]
        assert r.ledger.events[0]["bytes"] == len(json.dumps(args)) and r.ledger.events[0]["detail"]["kb"] == 3
        assert r.ledger.events[1]["decision"] == answer


@pytest.mark.parametrize("answer", [None, "", "d", "yes", "Deny", "ONCE", "approve"])
def test_hermes_grant_on_an_unexpected_answer_is_refused(answer):
    # tools/approval.py:1006-1009: anything but the exact "deny" is a grant on the CLI.
    r = Rig(answer=answer, hermes_approved=True)
    out = r.run("web_search", {"q": "x"})
    assert refused(out) and r.ran() == []
    assert r.ledger.kinds()[-1] == "tool_refused" and r.ledger.events[-1]["decision"] == "unexpected_choice"
    assert r.ledger.events[-1]["detail"]["choice"] == answer


def test_denied_and_no_surface_are_refused():
    r = Rig(answer="deny", hermes_approved=False)
    assert refused(r.run("web_search")) and r.ran() == []
    assert r.ledger.events[-1]["decision"] == "denied"
    r = Rig(answer=None, hermes_approved=False, status="approval_required")
    assert refused(r.run("web_search")) and r.ledger.events[-1]["decision"] == "no_surface"
    # an explicit answer recorded but Hermes said no (e.g. a race): still refused
    r = Rig(answer="once", hermes_approved=False)
    assert refused(r.run("web_search")) and r.ran() == []


def test_answer_for_another_call_does_not_count():
    from confidential_mode.gate_tools import ApprovalDecisions
    r = Rig(answer=None, hermes_approved=True)
    r.decisions.record("some-other-call", "once")
    assert refused(r.run("web_search")) and r.ran() == []


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
    args = {"q": "é" * 600}   # json.dumps escapes to \u00e9: 6 chars each -> 3609 chars
    assert len(json.dumps(args)) == 3609 and args_kb(args) == 4


def test_bypass_blocks_in_both_lines_and_never_asks():
    r = Rig(bypass=True, answer="once")
    d = r.hook(tool_name="web_search", args={"q": "x"}, session_id="s")
    assert d["action"] == "block" and "bypassed" in d["message"]
    assert refused(r.run("web_search", {"q": "x"})) and r.ran() == [] and r.calls["ask"] == []
    assert [e["decision"] for e in r.ledger.events] == ["bypass_active", "bypass_active"]


def test_zero_arg_bypass_callable_from_the_contract_is_accepted():
    ledger = FakeLedger()
    fn = build_pre_tool_call(lambda: True, allowlist(), ledger, lambda: True, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    fn = build_pre_tool_call(lambda: True, allowlist(), ledger, lambda: False, lambda a: True)
    assert fn(tool_name="web_search", args={}, session_id="s") is None


def test_user_added_tool_runs_without_asking_and_is_ledgered():
    r = Rig(bypass=True)
    r.al.add("web_search")
    assert r.hook(tool_name="web_search", args={}, session_id="s") is None
    r.run("web_search")
    assert r.ran() == ["web_search"] and r.calls["ask"] == []
    assert r.ledger.kinds() == ["tool_allowed"] and r.ledger.events[0]["decision"] == "allowlist"


def test_remembered_grant_is_honoured_and_ledgered():
    r = Rig(remembered=True, answer=None)
    r.run("web_search", {"q": "x"})
    assert r.ran() == ["web_search"] and r.calls["ask"] == []
    assert r.ledger.kinds() == ["tool_allowed"] and r.ledger.events[0]["decision"] == "remembered"
    r = Rig(remembered=False, answer=None, hermes_approved=True)   # mutant twin: no grant -> asked
    assert refused(r.run("web_search")) and len(r.calls["ask"]) == 1


def test_bypass_still_blocks_with_a_remembered_grant():
    r = Rig(bypass=True, remembered=True)
    assert refused(r.run("web_search")) and r.ran() == []
    assert r.ledger.events[0]["decision"] == "bypass_active"


@pytest.mark.parametrize("sealed", [None, "yes", 1, (True,), ("x", None), [True, None]])
def test_unexpected_seal_shape_blocks_everything_including_local(sealed):
    r = Rig(sealed=sealed)
    assert r.hook(tool_name="read_file", args={}, session_id="s")["action"] == "block"
    out = r.run("read_file")
    assert refused(out) and "/confidential status" in json.loads(out)["error"] and r.ran() == []


def test_unreadable_seal_state_blocks_everything_including_local():
    def boom():
        raise RuntimeError("state corrupt")
    r = Rig(sealed=boom)
    d = r.hook(tool_name="read_file", args={}, session_id="s")
    assert d["action"] == "block" and "/confidential status" in d["message"]
    assert refused(r.run("read_file")) and r.ran() == []
    assert [e["decision"] for e in r.ledger.events] == ["seal_state_unreadable"] * 2


def test_is_sealed_tuple_shape():
    from confidential_mode.tiers import Tier
    r = Rig(sealed=(True, Tier.LOCAL))
    assert r.hook(tool_name="cronjob_manage", args={}, session_id="s")["action"] == "block"
    assert refused(r.run("cronjob_manage"))
    r = Rig(sealed=(False, None))
    assert r.hook(tool_name="cronjob_manage", args={}, session_id="s") is None
    r.run("cronjob_manage")
    assert r.ran() == ["cronjob_manage"]


def test_errors_fail_closed():
    def boom(name):
        raise RuntimeError("x")
    r = Rig()
    hook = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(), boom, lambda a: True)
    assert hook(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    # ledger raising -> hook blocks; middleware refuses (never runs the tool)
    hook = build_pre_tool_call(lambda: True, allowlist(), FakeLedger(fail=True), lambda n: True, lambda a: True)
    assert hook(tool_name="web_search", args={}, session_id="s")["action"] == "block"
    r = Rig(ledger=FakeLedger(fail=True))
    assert refused(r.run("web_search")) and r.ran() == []
    # local still runs with a broken ledger (nothing to ledger)
    r = Rig(ledger=FakeLedger(fail=True))
    r.run("read_file")
    assert r.ran() == ["read_file"]


def test_middleware_propagates_the_tools_own_exception_untouched():
    from confidential_mode.gate_tools import ApprovalDecisions, build_tool_execution
    mw = build_tool_execution(lambda: True, allowlist(), FakeLedger(), ApprovalDecisions(),
                              bypass_active=lambda n: False, remembered=lambda n: False)

    class ToolBoom(Exception):
        pass

    def next_call(a):
        raise ToolBoom("handler failed")
    with pytest.raises(ToolBoom):
        mw(tool_name="read_file", args={}, next_call=next_call)
    with pytest.raises(KeyboardInterrupt):
        mw(tool_name="read_file", args={}, next_call=lambda a: (_ for _ in ()).throw(KeyboardInterrupt()))


def test_allowlist_may_be_a_callable_for_reseal():
    box = {"al": allowlist()}
    fn = build_pre_tool_call(lambda: True, lambda: box["al"], FakeLedger(), lambda n: False, lambda a: True)
    assert fn(tool_name="new_tool", args={}, session_id="s")["action"] == "block"
    box["al"] = allowlist(entries=ENTRIES + [("new_tool", "x", _builtin_handler)])
    assert fn(tool_name="new_tool", args={}, session_id="s") is None


def test_allowlist_additions_persist_in_yaml(tmp_path):
    path = tmp_path / "allowlist.yaml"
    al = build_allowlist(FakeRegistry(ENTRIES), mcp_configs=MCP_CONFIGS, mcp_tool_servers={},
                         plugin_tool_names=set(), added_path=path)
    al.add("web_search")
    assert "web_search" in path.read_text()
    al2 = build_allowlist(FakeRegistry(ENTRIES), mcp_configs=MCP_CONFIGS, mcp_tool_servers={},
                          plugin_tool_names=set(), added_path=path)
    assert al2.is_added("web_search")
    # a persisted name that is now a hard block is not honoured
    path.write_text("version: 1\nallowed: [web_search, cronjob_manage, remote_query, nope]\n")
    al3 = build_allowlist(FakeRegistry(ENTRIES), mcp_configs=MCP_CONFIGS, mcp_tool_servers={},
                          plugin_tool_names=set(), added_path=path)
    assert al3.added == {"web_search"}
    path.write_text("version: 1\nallowed:\n- web_search\n")      # hand-edited YAML (needs hermes_yaml)
    import importlib.util
    if importlib.util.find_spec("hermes_yaml") is not None:
        assert build_allowlist(FakeRegistry(ENTRIES), mcp_configs=MCP_CONFIGS, mcp_tool_servers={},
                               plugin_tool_names=set(), added_path=path).added == {"web_search"}
    path.write_text(": not yaml [")
    assert build_allowlist(FakeRegistry(ENTRIES), mcp_configs=MCP_CONFIGS, mcp_tool_servers={},
                           plugin_tool_names=set(), added_path=path).added == set()


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
    ({}, {"tasks": json.dumps([{"goal": "g"}])}, False),               # JSON-string tasks
    ({}, {"tasks": [{"goal": "g", "request_overrides": {"x": 1}}]}, False),
    ({}, {"tasks": [{"goal": "g", "fallback_providers": ["openrouter"]}]}, False),
    ({}, {"tasks": [{"goal": "g", "base_url": "http://x"}]}, False),
    ({}, {"tasks": [{"goal": "g", "api_mode": "chat_completions"}]}, False),
    ({}, {"goal": "g", "provider": "openrouter"}, False),               # top-level legacy
    ({}, {"goal": "g", "request_overrides": {"x": 1}}, False),
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


def test_mode_tools_are_plain_local_today():
    from confidential_mode.gate_tools import MODE_TOOLS
    assert MODE_TOOLS == {"terminal", "execute_code"} and MODE_TOOLS <= LOCAL_TOOLS
    al = allowlist()
    assert all(al.get(n).mode is None and al.get(n).route is Route.LOCAL for n in MODE_TOOLS)



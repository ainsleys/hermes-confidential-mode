"""Each main send in a receipt shows the request size and the response size (fix-pass-3 item 1), on the plugin
loaded by real discovery, through Hermes' real llm_execution chain, with the response object Hermes' streaming
path returns. A live ledger showed "response size unknown" for every main send because the gate measured only
pydantic models and dicts, and the CLI's default streaming path returns a SimpleNamespace."""
from __future__ import annotations

import importlib
from types import SimpleNamespace

from .test_register import plugin  # noqa: F401  (fixture)
from ._harness import no_lazy_installs  # noqa: F401  (fixture)

BASE = "http://127.0.0.1:11434/v1"


def _stream_response(text: str) -> SimpleNamespace:
    """The object agent/chat_completion_helpers.py builds at the end of a chat-completions stream."""
    message = SimpleNamespace(role="assistant", content=text, tool_calls=None, reasoning_content=None, refusal=None)
    usage = SimpleNamespace(prompt_tokens=12, completion_tokens=3, total_tokens=15)
    return SimpleNamespace(id="chatcmpl-1", model="llama3", usage=usage, provider=None,
                           choices=[SimpleNamespace(index=0, message=message, finish_reason="stop")])


def _send(plugin, session_id, request_id, response, *, record=None):
    from hermes_cli.middleware import run_llm_execution_middleware
    from hermes_cli.plugins import invoke_hook
    request = {"model": "llama3", "messages": [{"role": "user", "content": "hi"}]}
    invoke_hook("pre_api_request", provider="custom", base_url=BASE, model="llama3", api_mode="chat_completions",
                session_id=session_id, request=request, api_request_id=request_id)
    sendctx = importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.sendctx")

    def terminal(req):
        if record is not None:
            sendctx.add_record(dict(record))     # a vendor transport's per-send record (Tinfoil)
        return response
    return run_llm_execution_middleware(request, terminal, task_id="t", turn_id="turn", api_request_id=request_id,
                                        session_id=session_id, platform="cli", model="llama3", provider="custom",
                                        base_url=BASE, api_mode="chat_completions", api_call_count=1,
                                        middleware_trace=[])


def _send_lines(plugin, session_id):
    text = plugin.slash(f"receipts {session_id}")
    sends = text.split("Sends (purpose, host, request and response bytes; never text)\n")[1].split("\n\n")[0]
    return [ln for ln in sends.splitlines() if ln.strip()]


def test_each_main_send_shows_request_and_response_sizes(plugin):
    from agent.chat_completion_helpers import _build_partial_stream_stub
    assert plugin.slash("on on-host-only").startswith("Locked")
    stub = _build_partial_stream_stub("assistant", "partial", None, "llama3", None)   # Hermes' own builder
    responses = [_stream_response("hello"), _stream_response("a longer reply"), stub]
    record = {"encrypted": True, "hpke_key_used": "ab" * 32, "hpke_key_source": "ehbp_transport",
              "response_decrypted": True}
    for i, resp in enumerate(responses, 1):
        assert _send(plugin, "sess-sz", f"sess-sz:api:{i}", resp, record=record) is resp
    rows = [e for e in plugin.rt.ledger.session("sess-sz") if e.kind == "send_observed"]
    assert [e.decision for e in rows] == ["attempt", "allowed"] * 3
    lines = _send_lines(plugin, "sess-sz")
    assert len(lines) == 3, lines
    for line, row_pair in zip(lines, zip(rows[0::2], rows[1::2])):
        attempt, result = row_pair
        assert f"rows #{attempt.id} attempt, #{result.id} result" in line, line
        assert f"request {result.bytes} bytes, response " in line and "response size unknown" not in line, line
    sizes = [int(ln.split(", response ")[1].split(" bytes")[0]) for ln in lines]
    assert sizes[0] < sizes[1] and all(s > 0 for s in sizes), sizes
    # Hermes' markers on the stub (_dropped_tool_names, _overflow_terminal, _clean_eof) are not counted: the stub
    # measures the same as a copy with them deleted (fix-pass-3 review finding 1; removing the filter fails this).
    gate_llm = importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.gate_llm")
    bare = _build_partial_stream_stub("assistant", "partial", None, "llama3", None)
    for name in [k for k in vars(bare) if k.startswith("_")]:
        delattr(bare, name)
    assert [k for k in vars(stub) if k.startswith("_")]          # the real stub carries markers
    assert sizes[2] == gate_llm.response_bytes(bare) == gate_llm.response_bytes(stub)


def test_a_live_stream_is_not_consumed_and_says_size_unknown(plugin):
    assert plugin.slash("on on-host-only").startswith("Locked")
    consumed = []

    def stream():
        consumed.append(1)
        yield "chunk"
    live = stream()
    assert _send(plugin, "sess-st", "sess-st:api:1", live) is live
    assert consumed == []
    lines = _send_lines(plugin, "sess-st")
    assert len(lines) == 1 and "response size unknown" in lines[0], lines


def test_a_response_with_tool_calls_is_measured_with_its_arguments(plugin):
    """The tool-call shape Hermes' stream assembly builds (agent/chat_completion_helpers.py
    _StreamingCall._assemble_tool_calls), measured larger than the same reply without the call."""
    from agent.chat_completion_helpers import _StreamingCall
    gate_llm = importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.gate_llm")
    acc = {0: {"id": "call_1", "type": "function", "thought_signature": None,
               "function": {"name": "web_search", "arguments": '{"query": "' + "x" * 500 + '"}'}}}
    calls, truncated = _StreamingCall._assemble_tool_calls(acc, "tool_calls")
    assert truncated is False and calls[0].function.args_repaired is False
    with_calls = _stream_response("")
    with_calls.choices[0].message.tool_calls = calls
    plain = _stream_response("")
    assert gate_llm.response_bytes(with_calls) > gate_llm.response_bytes(plain) + 500
    assert plugin.slash("on on-host-only").startswith("Locked")
    assert _send(plugin, "sess-tc", "sess-tc:api:1", with_calls) is with_calls
    (line,) = _send_lines(plugin, "sess-tc")
    assert f"response {gate_llm.response_bytes(with_calls)} bytes" in line, line


def test_underscore_dict_keys_and_bytes_are_measured_as_the_rule_says(plugin):
    gate_llm = importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.gate_llm")
    marked = {"type": "reasoning", "encrypted_content": "abc", "_issuer_kind": "codex", "_issuer_model": "gpt"}
    assert gate_llm.response_bytes(marked) == gate_llm.response_bytes({"type": "reasoning", "encrypted_content": "abc"})
    assert gate_llm.response_bytes({"blob": b"\x00" * 100}) == gate_llm.response_bytes({"blob": "b" * 100})

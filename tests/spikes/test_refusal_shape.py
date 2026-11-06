"""C0 spike: what an ``llm_execution`` middleware must return to refuse a turn cleanly.

Every test drives ONE real turn through ``AIAgent.run_conversation`` on the pinned Hermes
checkout (84a0301): agent/turn_api_call.py perform_api_call -> hermes_cli/middleware.py
_run_execution_chain -> agent/turn_response_check.py check_api_response -> agent/turn_recovery.py
validate_response_shape -> transport normalize -> finish_text_response.

The middleware is registered with the real ``PluginContext.register_middleware`` on a real
``PluginManager`` that ``hermes_cli.plugins.get_plugin_manager`` is pointed at. Only the
terminal provider call (``agent._interruptible_api_call`` / ``_interruptible_streaming_api_call``,
the same seam Hermes' own tests fake) and the backoff delay are replaced.

pytest is only in Hermes' ``dev`` dependency group (not installed in the pinned .venv,
``default-groups = []``), so run it as an ephemeral overlay that leaves .venv untouched:

    cd ~/hermes-agent && PYTHONDONTWRITEBYTECODE=1 HERMES_HOME=$(mktemp -d) \
        uv run --no-sync --offline --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \
        pytest /Users/ainsleys/hermes-confidential-mode-wt/spike-refusal/tests/spikes -q
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import httpx
import openai
import pytest

import run_agent
import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins import PluginContext, PluginManager
from hermes_cli.plugins_manifest import PluginManifest

REFUSAL = "Confidential mode: this request was not sent to any model provider."

# --------------------------------------------------------------------------------------------
# Refusal constructors, one per api_mode (the deliverable for sub-question (a)).
# --------------------------------------------------------------------------------------------


def chat_completions_refusal(text: str = REFUSAL, *, finish_reason="stop", usage=None, model="confidential-mode"):
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice

    return ChatCompletion(
        id="confidential-refusal", object="chat.completion", created=int(time.time()), model=model,
        choices=[Choice(index=0, finish_reason=finish_reason,
                        message=ChatCompletionMessage(role="assistant", content=text))],
        usage=usage,
    )


def codex_responses_refusal(text: str = REFUSAL, model="confidential-mode"):
    from openai.types.responses import Response, ResponseOutputMessage, ResponseOutputText

    return Response(
        id="resp_confidential_refusal", object="response", created_at=time.time(), model=model,
        status="completed", parallel_tool_calls=False, tool_choice="auto", tools=[],
        output=[ResponseOutputMessage(
            id="msg_confidential_refusal", type="message", role="assistant", status="completed",
            content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
        )],
    )


def anthropic_messages_refusal(text: str = REFUSAL, model="confidential-mode"):
    # The ``anthropic`` SDK is not installed in the pinned checkout's venv, so this is the
    # attribute shape ``anthropic.types.Message`` exposes (content[].type/.text, stop_reason).
    return SimpleNamespace(
        id="msg_confidential_refusal", type="message", role="assistant", model=model,
        content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
        stop_sequence=None, usage=None,
    )


def bedrock_converse_refusal(text: str = REFUSAL):
    # The raw boto3 ``converse()`` dict. Hermes' own dispatch normally hands back the
    # already-normalized namespace (agent/bedrock_adapter.normalize_converse_response); the
    # transport accepts both (agent/transports/bedrock.py:56-60, 80-84).
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "stopReason": "end_turn"}


REFUSALS = {
    "chat_completions": chat_completions_refusal,
    "codex_responses": codex_responses_refusal,
    "anthropic_messages": anthropic_messages_refusal,
    "bedrock_converse": bedrock_converse_refusal,
}
MODES = list(REFUSALS)


def provider_ok(api_mode: str, text: str = "provider answered"):
    return REFUSALS[api_mode](text)


# --------------------------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_lazy_installs(monkeypatch):
    """Building an anthropic agent makes Hermes lazily ``uv sync`` the anthropic extra
    (agent/anthropic_adapter.py:42-56 -> pm/extras.py:187). Never let that happen here."""
    import pm
    from pm.package import InstallError

    def _refuse(extra, *a, **k):
        raise InstallError("venv", f"spike: lazy install of {extra!r} disabled")

    monkeypatch.setattr(pm, "ensure_import", _refuse, raising=False)
    monkeypatch.setattr("pm.extras.ensure_import", _refuse)


@pytest.fixture
def manager(monkeypatch):
    mgr = PluginManager()
    mgr._discovered = True
    monkeypatch.setattr(plugins_mod, "get_plugin_manager", lambda: mgr)
    return mgr


def register(manager, fn):
    ctx = PluginContext(PluginManifest(name="confidential_mode_spike"), manager)
    ctx.register_middleware("llm_execution", fn)
    return ctx


class Rec:
    """Records everything the spike asserts on."""

    def __init__(self):
        self.provider_calls = []
        self.streaming_calls = []
        self.middleware_calls = []
        self.fallback_calls = []
        self.backoff_calls = []
        self.error_hook_calls = []
        self.backoff_sleeps = []


_AGENT_KW = dict(quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=4)


def build_agent(monkeypatch, api_mode: str, rec: Rec, *, provider_response=None, provider_exc=None,
                streaming=False):
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("model_tools.check_toolset_requirements", dict)
    if api_mode == "chat_completions":
        agent = run_agent.AIAgent(model="gpt-4o", provider="custom", api_mode="chat_completions",
                                  base_url="https://llm.example.test/v1", api_key="sk-test", **_AGENT_KW)
    elif api_mode == "codex_responses":
        # Same construction as tests/agent/test_run_agent_codex_responses.py::_build_agent.
        agent = run_agent.AIAgent(model="gpt-5-codex", base_url="https://chatgpt.com/backend-api/codex",
                                  api_key="codex-token", **_AGENT_KW)
    elif api_mode == "anthropic_messages":
        # The ``anthropic`` SDK is not installed in the pinned venv, so the SDK client builder is
        # stubbed (cf. tests/agent/test_anthropic_stream_fallbacks.py::_anthropic_agent); the
        # terminal call is faked anyway.
        monkeypatch.setattr("agent.anthropic_adapter.build_anthropic_client",
                            lambda *a, **k: SimpleNamespace(messages=SimpleNamespace()))
        agent = run_agent.AIAgent(model="claude-sonnet-4-5", provider="anthropic", api_mode="anthropic_messages",
                                  base_url="https://api.anthropic.com", api_key="sk-ant-api03-test", **_AGENT_KW)
    elif api_mode == "bedrock_converse":
        agent = run_agent.AIAgent(model="us.anthropic.claude-sonnet-4-5-20250929-v1:0", provider="bedrock",
                                  api_mode="bedrock_converse",
                                  base_url="https://bedrock-runtime.us-east-1.amazonaws.com",
                                  api_key="aws-test", **_AGENT_KW)
    else:  # pragma: no cover
        raise ValueError(api_mode)
    assert agent.api_mode == api_mode
    agent._cleanup_task_resources = lambda task_id: None
    agent._persist_session = lambda messages, history=None: None
    agent._save_trajectory = lambda messages, user_message, completed: None
    agent._disable_streaming = not streaming

    def _terminal(kind):
        def _call(api_kwargs, **_kw):
            (rec.streaming_calls if kind == "stream" else rec.provider_calls).append(api_kwargs)
            if provider_exc is not None:
                raise provider_exc() if callable(provider_exc) and not isinstance(provider_exc, BaseException) else provider_exc
            return provider_response if provider_response is not None else provider_ok(api_mode)
        return _call

    agent._interruptible_api_call = _terminal("nonstream")
    agent._interruptible_streaming_api_call = _terminal("stream")

    real_fallback = agent._try_activate_fallback

    def _spy_fallback(*a, **k):
        rec.fallback_calls.append((a, k))
        return real_fallback(*a, **k)

    agent._try_activate_fallback = _spy_fallback

    real_hook = agent._invoke_api_request_error_hook

    def _spy_hook(**kw):
        rec.error_hook_calls.append(kw)
        return real_hook(**kw)

    agent._invoke_api_request_error_hook = _spy_hook

    def _backoff(attempt, *a, **k):
        rec.backoff_calls.append((attempt, a, k))
        return 0.0

    monkeypatch.setattr("agent.retry_utils.jittered_backoff", _backoff)

    def _sleep(agent_, wait_time, *a, **k):
        rec.backoff_sleeps.append(wait_time)
        return None

    # The real helper busy-waits on time.time(); record the requested wait instead.
    monkeypatch.setattr("agent.turn_recovery.interruptible_backoff_sleep", _sleep)
    monkeypatch.setattr("agent.turn_api_error.interruptible_backoff_sleep", _sleep)
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    return agent


def refusing_middleware(rec: Rec, factory):
    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(context.get("api_mode"))
        return factory()
    return llm_execution


def assert_clean_refusal(result, rec: Rec, agent, text=REFUSAL):
    assert result["final_response"] == text
    assert result.get("completed") is True, result
    assert not result.get("failed"), result
    assert result["api_calls"] == 1
    last = result["messages"][-1]
    assert last["role"] == "assistant" and last["content"] == text
    assert rec.middleware_calls == [agent.api_mode], "exactly one middleware call (no retry); api_mode in context"
    assert rec.provider_calls == [] and rec.streaming_calls == [], "provider must never be reached"
    assert rec.fallback_calls == [], "_try_activate_fallback must never be called"
    assert rec.backoff_calls == [], "no jittered backoff"
    assert rec.backoff_sleeps == [], "no backoff sleep of any kind"
    assert rec.error_hook_calls == [], "no api_request_error hook"
    assert getattr(agent, "_rate_limited_until", 0) in (0, None)
    assert agent._fallback_index == 0


# --------------------------------------------------------------------------------------------
# (a) Accepted refusal object per api_mode, returned WITHOUT calling next_call
# --------------------------------------------------------------------------------------------


def test_chat_completions_refusal_object_accepted(monkeypatch, manager):
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, chat_completions_refusal))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_chat_completions_refusal_finish_reason_none_also_accepted(monkeypatch, manager):
    """finish_reason is NOT strictly required to be "stop": None normalizes to "stop"
    (agent/transports/chat_completions.py:715). Built with model_construct since the SDK type
    forbids None."""
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice

    def _factory():
        return ChatCompletion.model_construct(
            id="r", object="chat.completion", created=0, model="m", usage=None,
            choices=[Choice.model_construct(index=0, finish_reason=None,
                                            message=ChatCompletionMessage(role="assistant", content=REFUSAL))])
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, _factory))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_chat_completions_refusal_with_usage_block_accepted(monkeypatch, manager):
    from openai.types import CompletionUsage
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, lambda: chat_completions_refusal(
        usage=CompletionUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0))))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_chat_completions_simplenamespace_duck_type_accepted(monkeypatch, manager):
    """Validation and normalization are attribute-based; an SDK type is not required."""
    def _factory():
        return SimpleNamespace(id="r", model="m", usage=None, choices=[SimpleNamespace(
            index=0, finish_reason="stop",
            message=SimpleNamespace(role="assistant", content=REFUSAL, tool_calls=None))])
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, _factory))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_chat_completions_refusal_finish_reason_content_filter_triggers_fallback(monkeypatch, manager):
    """Do NOT use finish_reason="content_filter": it routes to handle_content_policy_refusal
    (agent/turn_response_check.py:155-171), which tries the fallback chain."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, lambda: chat_completions_refusal(finish_reason="content_filter")))
    result = agent.run_conversation("secret question")
    assert len(rec.fallback_calls) == 1, "content_filter path attempts a fallback"
    assert rec.provider_calls == []
    # ...and the turn FAILS with Hermes' own safety-filter copy instead of the refusal text.
    assert result["failed"] is True and result["completed"] is False
    assert result["final_response"] != REFUSAL and "safety filter" in result["final_response"]


def test_chat_completions_message_refusal_field_triggers_fallback(monkeypatch, manager):
    """Do NOT use ChatCompletionMessage(refusal=...) with empty content: normalize promotes it to
    finish_reason content_filter (agent/transports/chat_completions.py:740-749)."""
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice

    def _factory():
        return ChatCompletion(id="r", object="chat.completion", created=0, model="m", choices=[Choice(
            index=0, finish_reason="stop",
            message=ChatCompletionMessage(role="assistant", content=None, refusal=REFUSAL))])
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, _factory))
    agent.run_conversation("secret question")
    assert rec.fallback_calls


def test_chat_completions_refusal_finish_reason_length_reenters_middleware(monkeypatch, manager):
    """finish_reason="length" goes to recover_from_truncation, which issues more calls; each
    re-enters the middleware. Not a clean refusal."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, lambda: chat_completions_refusal(finish_reason="length")))
    result = agent.run_conversation("secret question")
    assert len(rec.middleware_calls) == 4, "1 call + 3 continuation attempts"
    assert rec.provider_calls == []
    assert result["completed"] is False
    assert result["error"] == "Response remained truncated after 4 continuation attempts"


def test_codex_responses_refusal_object_accepted(monkeypatch, manager):
    rec = Rec()
    agent = build_agent(monkeypatch, "codex_responses", rec)
    register(manager, refusing_middleware(rec, codex_responses_refusal))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_codex_responses_simplenamespace_duck_type_accepted(monkeypatch, manager):
    def _factory():
        return SimpleNamespace(status="completed", model="m", usage=None, output=[SimpleNamespace(
            type="message", role="assistant", status="completed",
            content=[SimpleNamespace(type="output_text", text=REFUSAL)])])
    rec = Rec()
    agent = build_agent(monkeypatch, "codex_responses", rec)
    register(manager, refusing_middleware(rec, _factory))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_anthropic_messages_refusal_object_accepted(monkeypatch, manager):
    rec = Rec()
    agent = build_agent(monkeypatch, "anthropic_messages", rec)
    register(manager, refusing_middleware(rec, anthropic_messages_refusal))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_bedrock_converse_refusal_raw_dict_accepted(monkeypatch, manager):
    rec = Rec()
    agent = build_agent(monkeypatch, "bedrock_converse", rec)
    register(manager, refusing_middleware(rec, bedrock_converse_refusal))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_bedrock_converse_refusal_normalized_namespace_accepted(monkeypatch, manager):
    from agent.bedrock_adapter import normalize_converse_response
    rec = Rec()
    agent = build_agent(monkeypatch, "bedrock_converse", rec)
    register(manager, refusing_middleware(rec, lambda: normalize_converse_response(bedrock_converse_refusal())))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


# --------------------------------------------------------------------------------------------
# (b) Wrong shape: plain dict, or an object of the wrong api_mode
# --------------------------------------------------------------------------------------------


def _assert_invalid_response_cycle(result, rec: Rec, agent):
    max_retries = agent._api_max_retries
    assert max_retries == 3
    # Every attempt re-enters the middleware; the provider is still never reached.
    assert len(rec.middleware_calls) == max_retries
    assert rec.provider_calls == [] and rec.streaming_calls == []
    # api_request_error fires once per invalid attempt with reason invalid_response.
    assert [c["reason"] for c in rec.error_hook_calls] == ["invalid_response"] * max_retries
    assert all(c["error_type"] == "InvalidAPIResponse" for c in rec.error_hook_calls)
    # Eager fallback once per attempt, plus once more at max retries.
    assert len(rec.fallback_calls) == max_retries + 1
    # Jittered backoff before attempts 2 and 3 (retry_count 1, 2): 5s base, 120s cap.
    assert [c[0] for c in rec.backoff_calls] == list(range(1, max_retries))
    assert all(c[2] == {"base_delay": 5.0, "max_delay": 120.0} for c in rec.backoff_calls)
    assert result.get("failed") is True
    assert result.get("completed") is False
    assert REFUSAL not in (result.get("final_response") or "")


def _assert_plain_dict_crash(result, rec: Rec, agent):
    """A plain dict is invalid, then CRASHES retry_invalid_response: describe_invalid_response
    calls ``vars(response)`` (agent/turn_recovery.py:1646-1647) after the eager fallback attempt
    (turn_response_check.py:291-298). The TypeError escapes check_api_response into
    handle_api_error (conversation_loop.py:1594-1599), which classifies it as a non-retryable
    client error, tries the fallback chain AGAIN, and fails the turn. No backoff, no retry."""
    assert len(rec.middleware_calls) == 1
    assert rec.provider_calls == [] and rec.streaming_calls == []
    assert [(c["reason"], c["error_type"]) for c in rec.error_hook_calls] == [
        ("invalid_response", "InvalidAPIResponse"), ("unknown", "TypeError")]
    assert len(rec.fallback_calls) == 2, "eager fallback + handle_api_error fallback"
    assert rec.backoff_calls == []
    assert result.get("failed") is True and result.get("completed") is False
    assert result.get("error") == "vars() argument must have __dict__ attribute"
    assert "rejected the request and retrying won't help" in result["final_response"]
    assert REFUSAL not in result["final_response"]


@pytest.mark.parametrize("api_mode", MODES)
def test_plain_dict_refusal_rejected_and_crashes_turn(monkeypatch, manager, api_mode):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec)
    register(manager, refusing_middleware(rec, lambda: {"role": "assistant", "content": REFUSAL}))
    _assert_plain_dict_crash(agent.run_conversation("secret question"), rec, agent)


def test_plain_dict_chat_shape_rejected_and_crashes_turn(monkeypatch, manager):
    """Even a dict that is a perfect JSON ChatCompletion fails: validation is getattr-based."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, lambda: chat_completions_refusal().model_dump()))
    _assert_plain_dict_crash(agent.run_conversation("secret question"), rec, agent)


@pytest.mark.parametrize("api_mode,wrong", [
    ("chat_completions", "codex_responses"),
    ("chat_completions", "anthropic_messages"),
    ("codex_responses", "chat_completions"),
    ("codex_responses", "anthropic_messages"),
    ("anthropic_messages", "chat_completions"),
    ("anthropic_messages", "codex_responses"),
    ("bedrock_converse", "codex_responses"),
    ("bedrock_converse", "anthropic_messages"),
])
def test_wrong_mode_refusal_rejected_and_retried(monkeypatch, manager, api_mode, wrong):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec)
    register(manager, refusing_middleware(rec, REFUSALS[wrong]))
    _assert_invalid_response_cycle(agent.run_conversation("secret question"), rec, agent)


def test_bedrock_converse_accepts_chat_completions_object(monkeypatch, manager):
    """Surprise: bedrock_converse validates "non-empty .choices", so a ChatCompletion passes."""
    rec = Rec()
    agent = build_agent(monkeypatch, "bedrock_converse", rec)
    register(manager, refusing_middleware(rec, chat_completions_refusal))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_plain_dict_with_fallback_configured_switches_provider(monkeypatch, manager):
    """With a fallback chain, the FIRST invalid response activates it (eager fallback) and the
    retry goes to the fallback runtime -- which re-enters the middleware."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    agent._fallback_chain = [{"provider": "openrouter", "model": "fallback/model"}]
    agent._fallback_index = 0
    fake_client = SimpleNamespace(base_url="https://openrouter.ai/api/v1", api_key="fb")
    monkeypatch.setattr("agent.auxiliary_client.resolve_provider_client",
                        lambda *a, **k: (fake_client, "fallback/model"))
    register(manager, refusing_middleware(rec, lambda: {"content": REFUSAL}))
    agent.run_conversation("secret question")
    assert rec.fallback_calls
    assert agent._fallback_index >= 1, "fallback activated (sticky until next turn's restore)"
    assert agent.model == "fallback/model"


# --------------------------------------------------------------------------------------------
# (c) Middleware calls next_call, provider raises, middleware returns the refusal
# --------------------------------------------------------------------------------------------


def _status_error_500():
    req = httpx.Request("POST", "https://llm.example.test/v1/chat/completions")
    return openai.InternalServerError("upstream exploded", response=httpx.Response(500, request=req), body=None)


def _rate_limit_429():
    req = httpx.Request("POST", "https://llm.example.test/v1/chat/completions")
    return openai.RateLimitError("slow down", response=httpx.Response(
        429, request=req, headers={"retry-after": "30"}), body=None)


def catching_middleware(rec: Rec, factory, seen: list):
    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(context.get("api_mode"))
        try:
            return next_call(request)
        except Exception as exc:  # what the middleware actually sees: _DownstreamExecutionError
            seen.append(exc)
            return factory()
    return llm_execution


@pytest.mark.parametrize("api_mode", MODES)
@pytest.mark.parametrize("err", [_status_error_500, _rate_limit_429], ids=["500", "429"])
def test_catch_provider_error_returns_refusal(monkeypatch, manager, api_mode, err):
    rec, seen = Rec(), []
    agent = build_agent(monkeypatch, api_mode, rec, provider_exc=err)
    register(manager, catching_middleware(rec, REFUSALS[api_mode], seen))
    result = agent.run_conversation("secret question")
    assert result["final_response"] == REFUSAL and result["completed"] is True
    assert len(rec.provider_calls) == 1, "provider called exactly once, no retry"
    assert rec.fallback_calls == [] and rec.backoff_calls == [] and rec.error_hook_calls == []
    assert rec.backoff_sleeps == []
    assert getattr(agent, "_rate_limited_until", 0) in (0, None), "no rate-limit cooldown armed"
    assert getattr(agent, "_rate_limit_backoff_count", 0) == 0
    assert agent._fallback_index == 0
    # The middleware sees Hermes' private wrapper, not the openai exception.
    from hermes_cli.middleware import _DownstreamExecutionError
    assert len(seen) == 1 and type(seen[0]) is _DownstreamExecutionError
    assert isinstance(seen[0].original, openai.APIStatusError)
    assert not isinstance(seen[0], openai.APIStatusError)


def test_control_uncaught_429_arms_rate_limit_cooldown(monkeypatch, manager):
    """Control for the test above: with a pass-through middleware the same 429 reaches
    handle_api_error, which retries, calls _try_activate_fallback and arms _rate_limited_until
    (agent/fallback_cooldown.py:45-71 via chat_completion_helpers.py:2057-2060)."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec, provider_exc=_rate_limit_429)

    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(1)
        return next_call(request)

    register(manager, llm_execution)
    result = agent.run_conversation("secret question")
    assert len(rec.provider_calls) == 3
    assert rec.fallback_calls
    assert getattr(agent, "_rate_limited_until", 0) > time.monotonic(), "cooldown armed"
    assert rec.backoff_sleeps == [30.0, 30.0], "Retry-After honoured between the 3 attempts"
    assert result["failed"] is True


def test_catching_only_openai_errors_misses_the_wrapper(monkeypatch, manager):
    """``except openai.APIStatusError`` never matches: the original is re-raised past the
    middleware (middleware.py:203-204) into handle_api_error -> retries + fallback."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec, provider_exc=_status_error_500)

    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(1)
        try:
            return next_call(request)
        except openai.APIStatusError:
            return chat_completions_refusal()

    register(manager, llm_execution)
    result = agent.run_conversation("secret question")
    assert result["final_response"] != REFUSAL
    assert len(rec.provider_calls) > 1, "Hermes retried the provider"
    assert rec.fallback_calls, "fallback was attempted"


def test_catch_all_swallows_user_interrupt(monkeypatch, manager):
    """InterruptedError (user stop / redirect mid-call) is an Exception too: a bare
    ``except Exception`` turns an interrupt into a refusal message."""
    rec, seen = Rec(), []
    agent = build_agent(monkeypatch, "chat_completions", rec, provider_exc=InterruptedError)
    register(manager, catching_middleware(rec, chat_completions_refusal, seen))
    result = agent.run_conversation("secret question")
    assert isinstance(seen[0].original, InterruptedError)
    assert result["final_response"] == REFUSAL and not result.get("interrupted")


# --------------------------------------------------------------------------------------------
# (d) Fail-open: a raising middleware
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("api_mode", MODES)
def test_raising_middleware_before_next_call_fails_open(monkeypatch, manager, api_mode):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec)

    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(1)
        raise RuntimeError("policy check crashed")

    register(manager, llm_execution)
    result = agent.run_conversation("secret question")
    assert len(rec.provider_calls) == 1, "Hermes called the provider itself (FAIL-OPEN)"
    assert result["final_response"] == "provider answered"
    assert result["completed"] is True


def test_raising_middleware_after_next_call_returns_provider_response(monkeypatch, manager):
    """Raising AFTER a successful next_call also fails open: Hermes returns next_result
    (middleware.py:208-209), i.e. the provider's answer the middleware wanted to suppress."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)

    def llm_execution(request, next_call, **context):
        next_call(request)
        raise RuntimeError("post-check crashed")

    register(manager, llm_execution)
    result = agent.run_conversation("secret question")
    assert result["final_response"] == "provider answered"


def test_raising_middleware_after_failed_next_call_propagates_as_api_error(monkeypatch, manager):
    """After a failed next_call, the middleware's own exception propagates (middleware.py:210-211)
    and Hermes' API-error path retries the WHOLE chain (provider called again)."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec, provider_exc=_status_error_500)

    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(1)
        try:
            next_call(request)
        except Exception:
            raise RuntimeError("refusal builder crashed")

    register(manager, llm_execution)
    agent.run_conversation("secret question")
    assert len(rec.provider_calls) > 1
    assert rec.fallback_calls


def test_middleware_that_returns_none_is_treated_as_invalid_response(monkeypatch, manager):
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec)
    register(manager, refusing_middleware(rec, lambda: None))
    _assert_invalid_response_cycle(agent.run_conversation("secret question"), rec, agent)


# --------------------------------------------------------------------------------------------
# (e) Where the middleware is / is not on the main turn path
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("api_mode", MODES)
def test_streaming_turn_still_runs_middleware(monkeypatch, manager, api_mode):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec, streaming=True)
    from agent.turn_api_call import _should_stream
    if not _should_stream(agent):
        pytest.skip(f"{api_mode}: Hermes does not stream for this agent configuration")
    register(manager, refusing_middleware(rec, REFUSALS[api_mode]))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


@pytest.mark.parametrize("api_mode", MODES)
def test_streaming_passthrough_goes_through_middleware(monkeypatch, manager, api_mode):
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec, streaming=True)
    from agent.turn_api_call import _should_stream
    streams = _should_stream(agent)

    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(1)
        return next_call(request)

    register(manager, llm_execution)
    agent.run_conversation("secret question")
    assert rec.middleware_calls == [1]
    assert (len(rec.streaming_calls), len(rec.provider_calls)) == ((1, 0) if streams else (0, 1))


def test_external_process_provider_still_runs_middleware(monkeypatch, manager):
    """External-process providers only change the streaming decision (turn_api_call.py:59-60)."""
    rec = Rec()
    agent = build_agent(monkeypatch, "chat_completions", rec, streaming=True)
    monkeypatch.setattr("hermes_cli.runtime_provider_backends._is_external_process_provider", lambda p: True)
    from agent.turn_api_call import _should_stream
    assert _should_stream(agent) is False
    register(manager, refusing_middleware(rec, chat_completions_refusal))
    assert_clean_refusal(agent.run_conversation("secret question"), rec, agent)


def test_codex_app_server_bypasses_middleware(monkeypatch, manager):
    """api_mode codex_app_server runs the whole turn in a subprocess before the generic loop
    (agent/conversation_loop.py:1611-1637): llm_execution middleware never runs."""
    rec = Rec()
    agent = build_agent(monkeypatch, "codex_responses", rec)
    agent.api_mode = "codex_app_server"
    app_server_calls = []

    def _fake_app_server_turn(**kw):
        app_server_calls.append(kw)
        return {"final_response": "app-server answered", "messages": kw["messages"],
                "completed": True, "api_calls": 1}

    agent._run_codex_app_server_turn = _fake_app_server_turn
    register(manager, refusing_middleware(rec, codex_responses_refusal))
    result = agent.run_conversation("secret question")
    assert app_server_calls, "the subprocess runtime handled the turn"
    assert rec.middleware_calls == [], "llm_execution middleware was NOT invoked"
    assert result["final_response"] == "app-server answered"


@pytest.mark.parametrize("api_mode", ["chat_completions", "codex_responses", "anthropic_messages"])
def test_max_iterations_summary_bypasses_middleware(monkeypatch, manager, api_mode):
    """When the iteration budget runs out, handle_max_iterations calls agent._interruptible_api_call
    DIRECTLY (agent/chat_completion_helpers.py:2225-2273): a provider call on the main turn path
    with no llm_execution middleware around it."""
    rec = Rec()
    agent = build_agent(monkeypatch, api_mode, rec)
    agent.max_iterations = 1

    def llm_execution(request, next_call, **context):
        rec.middleware_calls.append(1)
        return tool_call_response(api_mode)

    def _tool_terminal(api_kwargs, **_kw):
        rec.provider_calls.append(api_kwargs)
        return provider_ok(api_mode, "summary from provider")

    agent._interruptible_api_call = _tool_terminal
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    register(manager, llm_execution)
    agent.tools = [{"type": "function", "function": {"name": "todo_list", "description": "x",
                                                     "parameters": {"type": "object", "properties": {}}}}]
    agent.valid_tool_names = {"todo_list"}
    monkeypatch.setattr(agent, "_execute_tool_calls", lambda *a, **k: None, raising=False)
    result = agent.run_conversation("secret question")
    assert rec.middleware_calls == [1]
    assert len(rec.provider_calls) == 1, "summary request reached the provider without middleware"
    assert result["final_response"].startswith("summary from provider")


def tool_call_response(api_mode):
    if api_mode == "chat_completions":
        from openai.types.chat import ChatCompletion, ChatCompletionMessage
        from openai.types.chat.chat_completion import Choice
        from openai.types.chat.chat_completion_message_tool_call import ChatCompletionMessageToolCall, Function
        return ChatCompletion(id="t", object="chat.completion", created=0, model="m", choices=[Choice(
            index=0, finish_reason="tool_calls", message=ChatCompletionMessage(
                role="assistant", content=None, tool_calls=[ChatCompletionMessageToolCall(
                    id="call_1", type="function", function=Function(name="todo_list", arguments="{}"))]))])
    if api_mode == "codex_responses":
        return SimpleNamespace(status="completed", model="m", usage=None, output=[SimpleNamespace(
            type="function_call", id="fc_1", call_id="call_1", name="todo_list", arguments="{}",
            status="completed")])
    if api_mode == "anthropic_messages":
        return SimpleNamespace(id="m", model="m", usage=None, stop_reason="tool_use", content=[
            SimpleNamespace(type="tool_use", id="toolu_1", name="todo_list", input={})])
    raise ValueError(api_mode)

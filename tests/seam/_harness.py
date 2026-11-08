"""Shared seam harness: one real ``AIAgent.run_conversation`` turn through a real PluginManager.

Copied from the C0 spike (tests/spikes/test_refusal_shape.py, Hermes 84a0301). Only the terminal
provider call (``agent._interruptible_api_call`` / ``_interruptible_streaming_api_call``) and the
backoff delays are replaced; everything between ``perform_api_call`` and ``finish_text_response``
is real Hermes code. The recording terminal is the "recording transport": an empty
``rec.provider_calls`` means the provider received zero requests.

Import fixtures into a test module with ``from ._harness import manager, no_lazy_installs``.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

import hermes_cli.plugins as plugins_mod  # noqa: E402
import run_agent  # noqa: E402
from hermes_cli.plugins import PluginContext, PluginManager  # noqa: E402
from hermes_cli.plugins_manifest import PluginManifest  # noqa: E402

from confidential_mode.gate_llm import REFUSAL_BUILDERS  # noqa: E402

MODES = ["chat_completions", "codex_responses", "anthropic_messages", "bedrock_converse"]
PROVIDER_TEXT = "provider answered"


def provider_ok(api_mode: str, text: str = PROVIDER_TEXT):
    return REFUSAL_BUILDERS[api_mode](text)


@pytest.fixture(autouse=True)
def no_lazy_installs(monkeypatch):
    """Building an anthropic agent makes Hermes lazily ``uv sync`` the anthropic extra
    (agent/anthropic_adapter.py:42-56 -> pm/extras.py:187). Never let that happen here."""
    import pm
    from pm.package import InstallError

    def _refuse(extra, *a, **k):
        raise InstallError("venv", f"seam: lazy install of {extra!r} disabled")

    monkeypatch.setattr(pm, "ensure_import", _refuse, raising=False)
    monkeypatch.setattr("pm.extras.ensure_import", _refuse)


@pytest.fixture
def manager(monkeypatch):
    mgr = PluginManager()
    mgr._discovered = True
    monkeypatch.setattr(plugins_mod, "get_plugin_manager", lambda: mgr)
    return mgr


def register(manager, fn, name="confidential-mode"):
    ctx = PluginContext(PluginManifest(name=name), manager)
    ctx.register_middleware("llm_execution", fn)
    return ctx


class Rec:
    def __init__(self):
        self.provider_calls = []
        self.streaming_calls = []
        self.fallback_calls = []
        self.backoff_calls = []
        self.error_hook_calls = []
        self.backoff_sleeps = []

    @property
    def all_provider_calls(self):
        return self.provider_calls + self.streaming_calls


_AGENT_KW = dict(quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=4)


def build_agent(monkeypatch, api_mode: str, rec: Rec, *, provider_response=None, provider_exc=None,
                streaming=False):
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("model_tools.check_toolset_requirements", dict)
    if api_mode == "chat_completions":
        agent = run_agent.AIAgent(model="gpt-4o", provider="custom", api_mode="chat_completions",
                                  base_url="https://llm.example.test/v1", api_key="sk-test", **_AGENT_KW)
    elif api_mode == "codex_responses":
        agent = run_agent.AIAgent(model="gpt-5-codex", base_url="https://chatgpt.com/backend-api/codex",
                                  api_key="codex-token", **_AGENT_KW)
    elif api_mode == "anthropic_messages":
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
                raise provider_exc() if callable(provider_exc) and not isinstance(provider_exc, BaseException) \
                    else provider_exc
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

    monkeypatch.setattr("agent.turn_recovery.interruptible_backoff_sleep", _sleep)
    monkeypatch.setattr("agent.turn_api_error.interruptible_backoff_sleep", _sleep)
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    return agent


def arm_fallback_chain(monkeypatch, agent):
    """Give the agent a real fallback chain so arming it would be observable (_fallback_index)."""
    agent._fallback_chain = [{"provider": "openrouter", "model": "fallback/model"}]
    agent._fallback_index = 0
    fake_client = SimpleNamespace(base_url="https://openrouter.ai/api/v1", api_key="fb")
    monkeypatch.setattr("agent.auxiliary_client.resolve_provider_client",
                        lambda *a, **k: (fake_client, "fallback/model"))


def status_error_500():
    req = httpx.Request("POST", "https://llm.example.test/v1/chat/completions")
    return openai.InternalServerError("upstream exploded", response=httpx.Response(500, request=req), body=None)


def rate_limit_429():
    req = httpx.Request("POST", "https://llm.example.test/v1/chat/completions")
    return openai.RateLimitError("slow down", response=httpx.Response(
        429, request=req, headers={"retry-after": "30"}), body=None)


def assert_clean_refusal(result, rec: Rec, agent, text: str):
    """The turn ended with exactly ``text``, the provider got zero requests, and none of Hermes'
    recovery machinery (fallback, backoff, error hook, rate-limit cooldown) ran."""
    assert result["final_response"] == text, result.get("final_response")
    assert result.get("completed") is True, result
    assert not result.get("failed"), result
    assert result["api_calls"] == 1
    assert rec.all_provider_calls == [], "provider must receive zero requests"
    assert rec.fallback_calls == [], "_try_activate_fallback must never be called"
    assert rec.backoff_calls == [] and rec.backoff_sleeps == [], "no backoff"
    assert rec.error_hook_calls == [], "no api_request_error hook"
    assert getattr(agent, "_rate_limited_until", 0) in (0, None)
    assert agent._fallback_index == 0

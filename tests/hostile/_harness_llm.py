"""Hostile-test harness for the W1 ``llm_execution`` gate (confidential_mode.gate_llm).

Every test drives a REAL ``AIAgent.run_conversation`` turn on the pinned Hermes checkout
(84a0301) through a real ``PluginManager`` / ``PluginContext.register_middleware``. Only the
terminal provider seam (``agent._interruptible_api_call`` / ``_interruptible_streaming_api_call``,
or, for the request-scoped client path, ``agent._create_openai_client`` backed by an
``httpx.MockTransport``) and the backoff sleeps are replaced. This is the C0 harness from
tests/spikes/test_refusal_shape.py, extended to record WHERE each provider call was going
(agent.provider / agent.base_url at call time) so a send to a fallback host is visible.

The gate is built through the public W1 name only:

    confidential_mode.gate_llm.build_middleware(predicate=..., attested_ok=..., is_sealed=..., ledger=...)

``HOSTILE_GATE_MODULE`` overrides the module path (used to run this suite against a reference
gate and its mutants while W1 does not exist yet).
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import httpx
import openai
import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

import run_agent  # noqa: E402
import hermes_cli.plugins as plugins_mod  # noqa: E402
from hermes_cli.plugins import PluginContext, PluginManager  # noqa: E402
from hermes_cli.plugins_manifest import PluginManifest  # noqa: E402

from confidential_mode.tiers import Destination, Tier, Verdict  # noqa: E402

SECRET = "ZEBRA-7731-prompt-secret-do-not-store"
PROVIDER_TEXT = "provider answered"
IN_TIER_URL = "https://llm.example.test/v1"
OFF_TIER_URL = "https://openrouter.ai/api/v1"
GATE_MODULE = os.environ.get("HOSTILE_GATE_MODULE", "confidential_mode.gate_llm")

# ---------------------------------------------------------------------------------------------
# Provider response objects per api_mode (shapes proven in C0)
# ---------------------------------------------------------------------------------------------


def chat_completions_obj(text: str = PROVIDER_TEXT, model="m"):
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice

    return ChatCompletion(id="x", object="chat.completion", created=int(time.time()), model=model,
                          choices=[Choice(index=0, finish_reason="stop",
                                          message=ChatCompletionMessage(role="assistant", content=text))])


def codex_responses_obj(text: str = PROVIDER_TEXT, model="m"):
    from openai.types.responses import Response, ResponseOutputMessage, ResponseOutputText

    return Response(id="resp_x", object="response", created_at=time.time(), model=model, status="completed",
                    parallel_tool_calls=False, tool_choice="auto", tools=[],
                    output=[ResponseOutputMessage(id="msg_x", type="message", role="assistant", status="completed",
                                                  content=[ResponseOutputText(type="output_text", text=text,
                                                                              annotations=[])])])


def anthropic_messages_obj(text: str = PROVIDER_TEXT, model="m"):
    return SimpleNamespace(id="msg_x", type="message", role="assistant", model=model,
                           content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn",
                           stop_sequence=None, usage=None)


def bedrock_converse_obj(text: str = PROVIDER_TEXT):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}, "stopReason": "end_turn"}


PROVIDER_OK = {
    "chat_completions": chat_completions_obj,
    "codex_responses": codex_responses_obj,
    "anthropic_messages": anthropic_messages_obj,
    "bedrock_converse": bedrock_converse_obj,
}
MODES = list(PROVIDER_OK)


def provider_ok(api_mode: str, text: str = PROVIDER_TEXT):
    return PROVIDER_OK[api_mode](text)


def status_error_500(msg: str = "upstream exploded"):
    req = httpx.Request("POST", IN_TIER_URL + "/chat/completions")
    return openai.InternalServerError(msg, response=httpx.Response(500, request=req), body=None)


def rate_limit_429(retry_after: str = "30"):
    req = httpx.Request("POST", IN_TIER_URL + "/chat/completions")
    return openai.RateLimitError("slow down", response=httpx.Response(
        429, request=req, headers={"retry-after": retry_after}), body=None)


# ---------------------------------------------------------------------------------------------
# Fakes for the gate's injected dependencies
# ---------------------------------------------------------------------------------------------


class FakePredicate:
    """TierPredicate fake. ``decide(dest) -> Verdict`` (or raise). Records every Destination."""

    def __init__(self, decide: Callable[[Destination], Any], tier: Tier = Tier.LOCAL):
        self.tier = tier
        self._decide = decide
        self.seen: list[Destination] = []
        self.lock = threading.Lock()

    def classify(self, dest):
        with self.lock:
            self.seen.append(dest)
        return self._decide(dest)


def host_of(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except Exception:
        return ""


def by_host(*allowed_hosts: str):
    """A strict oracle predicate: in-tier iff the parsed hostname is in ``allowed_hosts``."""
    allowed = {h.lower() for h in allowed_hosts}

    def decide(dest):
        h = host_of(dest.base_url)
        if h in allowed:
            return Verdict(in_tier=True, reason="in tier", host=h)
        return Verdict(in_tier=False, reason=f"{h or 'unknown host'} is off-tier", host=h)
    return decide


def always(in_tier: bool, reason: str | None = None):
    def decide(dest):
        return Verdict(in_tier=in_tier, reason=reason or ("in tier" if in_tier else "off tier"),
                       host=host_of(dest.base_url))
    return decide


class FakeLedger:
    """Ledger fake with ``.append(event)``. ``fail`` = exception to raise on append (after recording
    the attempt in ``attempts``) or a predicate on the event deciding whether to raise."""

    def __init__(self, fail: BaseException | Callable[[Any], bool] | None = None, exc_factory=None):
        self.events: list[Any] = []
        self.attempts: list[Any] = []
        self._fail = fail
        self._exc_factory = exc_factory or (lambda: OSError("ledger.sqlite: database is locked"))
        self.lock = threading.Lock()

    def append(self, event):
        with self.lock:
            self.attempts.append(event)
            fail = self._fail
            if fail is not None:
                if isinstance(fail, BaseException):
                    raise fail
                if callable(fail) and fail(event):
                    raise self._exc_factory()
            self.events.append(event)


def ev_field(event: Any, name: str, default=None):
    if isinstance(event, dict):
        return event.get(name, default)
    if is_dataclass(event) and not isinstance(event, type):
        return getattr(event, name, default)
    return getattr(event, name, default)


def kinds(ledger: FakeLedger, attempts: bool = False) -> list[str]:
    return [str(getattr(ev_field(e, "kind"), "value", ev_field(e, "kind"))) for e in
            (ledger.attempts if attempts else ledger.events)]


def ledger_text(ledger: FakeLedger) -> str:
    out = []
    for e in ledger.attempts:
        try:
            if is_dataclass(e) and not isinstance(e, type):
                out.append(json.dumps(asdict(e), default=repr))
            else:
                out.append(json.dumps(e, default=repr))
        except Exception:
            out.append(repr(e))
        out.append(repr(e))
    return "\n".join(out)


class Seal:
    """is_sealed fake: ``values`` is either a bool or a list consumed per invocation (last repeats)."""

    def __init__(self, values):
        self._values = values if isinstance(values, list) else [values]
        self.calls = 0
        self.lock = threading.Lock()

    def __call__(self, *a, **k):
        with self.lock:
            i = min(self.calls, len(self._values) - 1)
            self.calls += 1
            return self._values[i]


class AttestedOk:
    def __init__(self, behaviour: Callable[[Any], Any]):
        self._b = behaviour
        self.calls: list[Any] = []

    def __call__(self, provider, *a, **k):
        self.calls.append(provider)
        return self._b(provider)


def attested_verdict(in_tier: bool, reason: str | None = None):
    return AttestedOk(lambda p: Verdict(in_tier=in_tier, reason=reason or ("fresh" if in_tier else "stale"),
                                        host=""))


# ---------------------------------------------------------------------------------------------
# Hermes harness
# ---------------------------------------------------------------------------------------------


def _no_lazy_installs_impl(monkeypatch):
    import pm
    from pm.package import InstallError

    def _refuse(extra, *a, **k):
        raise InstallError("venv", f"hostile: lazy install of {extra!r} disabled")

    monkeypatch.setattr(pm, "ensure_import", _refuse, raising=False)
    monkeypatch.setattr("pm.extras.ensure_import", _refuse)


@pytest.fixture(autouse=True)
def _no_lazy_installs(monkeypatch):
    _no_lazy_installs_impl(monkeypatch)


@pytest.fixture
def manager(monkeypatch):
    mgr = PluginManager()
    mgr._discovered = True
    monkeypatch.setattr(plugins_mod, "get_plugin_manager", lambda: mgr)
    return mgr


class Rec:
    def __init__(self):
        self.provider_calls: list[dict] = []   # {"kind", "api_kwargs", "provider", "base_url", "model"}
        self.middleware_calls: list[dict] = []
        self.fallback_calls: list = []
        self.backoff_calls: list = []
        self.backoff_sleeps: list = []
        self.error_hook_calls: list = []
        self.lock = threading.Lock()

    @property
    def sends(self):
        return list(self.provider_calls)

    def sends_to(self, host: str):
        return [c for c in self.provider_calls if host_of(c["base_url"]) == host]


_AGENT_KW = dict(quiet_mode=True, skip_context_files=True, skip_memory=True, max_iterations=4)


def _construct(api_mode: str, monkeypatch, base_url: str | None):
    if api_mode == "chat_completions":
        return run_agent.AIAgent(model="gpt-4o", provider="custom", api_mode="chat_completions",
                                 base_url=base_url or IN_TIER_URL, api_key="sk-test", **_AGENT_KW)
    if api_mode == "codex_responses":
        return run_agent.AIAgent(model="gpt-5-codex", base_url=base_url or "https://chatgpt.com/backend-api/codex",
                                 api_key="codex-token", **_AGENT_KW)
    if api_mode == "anthropic_messages":
        monkeypatch.setattr("agent.anthropic_adapter.build_anthropic_client",
                            lambda *a, **k: SimpleNamespace(messages=SimpleNamespace()))
        return run_agent.AIAgent(model="claude-sonnet-4-5", provider="anthropic", api_mode="anthropic_messages",
                                 base_url=base_url or "https://api.anthropic.com", api_key="sk-ant-api03-test",
                                 **_AGENT_KW)
    if api_mode == "bedrock_converse":
        return run_agent.AIAgent(model="us.anthropic.claude-sonnet-4-5-20250929-v1:0", provider="bedrock",
                                 api_mode="bedrock_converse",
                                 base_url=base_url or "https://bedrock-runtime.us-east-1.amazonaws.com",
                                 api_key="aws-test", **_AGENT_KW)
    raise ValueError(api_mode)


def default_url(api_mode: str) -> str:
    return {"chat_completions": IN_TIER_URL, "codex_responses": "https://chatgpt.com/backend-api/codex",
            "anthropic_messages": "https://api.anthropic.com",
            "bedrock_converse": "https://bedrock-runtime.us-east-1.amazonaws.com"}[api_mode]


def build_agent(monkeypatch, api_mode: str, rec: Rec, *, respond: Callable[[int, dict, Any], Any] | None = None,
                streaming: bool = False, base_url: str | None = None, fake_terminal: bool = True):
    """``respond(n, api_kwargs, agent)`` -> response object or raises. n is the 0-based provider call index."""
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("model_tools.check_toolset_requirements", dict)
    agent = _construct(api_mode, monkeypatch, base_url)
    assert agent.api_mode == api_mode
    agent._cleanup_task_resources = lambda task_id: None
    agent._persist_session = lambda messages, history=None: None
    agent._save_trajectory = lambda messages, user_message, completed: None
    agent._disable_streaming = not streaming

    if fake_terminal:
        def _terminal(kind):
            def _call(api_kwargs, **_kw):
                with rec.lock:
                    n = len(rec.provider_calls)
                    rec.provider_calls.append({"kind": kind, "api_kwargs": api_kwargs, "provider": agent.provider,
                                               "base_url": str(agent.base_url or ""), "model": agent.model})
                if respond is not None:
                    return respond(n, api_kwargs, agent)
                return provider_ok(agent.api_mode)
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


def configure_fallback_to_openrouter(monkeypatch, agent):
    agent._fallback_chain = [{"provider": "openrouter", "model": "fallback/model"}]
    agent._fallback_index = 0
    fake_client = SimpleNamespace(base_url=OFF_TIER_URL, api_key="fb")
    monkeypatch.setattr("agent.auxiliary_client.resolve_provider_client",
                        lambda *a, **k: (fake_client, "fallback/model"))


# ---------------------------------------------------------------------------------------------
# Request-scoped client path: real _interruptible_api_call, real openai.OpenAI, MockTransport
# ---------------------------------------------------------------------------------------------


class WireRecorder:
    """httpx.MockTransport handler: records every HTTP request that would hit the wire."""

    def __init__(self, respond: Callable[[httpx.Request, int], httpx.Response] | None = None):
        self.requests: list[httpx.Request] = []
        self._respond = respond
        self.clients_built = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        n = len(self.requests)
        self.requests.append(request)
        if self._respond is not None:
            return self._respond(request, n)
        return httpx.Response(200, json=chat_completions_obj().model_dump(mode="json"))

    def install(self, agent):
        def _create(client_kwargs, *, reason="", shared=False, **_k):
            self.clients_built += 1
            kw = dict(client_kwargs)
            return openai.OpenAI(api_key=kw.get("api_key") or "sk-test", base_url=kw.get("base_url"),
                                 max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(self)))
        agent._create_openai_client = _create
        agent.client = _create(dict(agent._client_kwargs), reason="hostile", shared=True)


# ---------------------------------------------------------------------------------------------
# Gate construction and registration
# ---------------------------------------------------------------------------------------------


def gate_module():
    return importlib.import_module(GATE_MODULE)


def build_gate(*, predicate, ledger, is_sealed, attested_ok=None):
    mod = gate_module()
    if attested_ok is None:
        attested_ok = AttestedOk(lambda p: Verdict(in_tier=True, reason="fresh", host=""))
    return mod.build_middleware(predicate=predicate, attested_ok=attested_ok, is_sealed=is_sealed, ledger=ledger)


def install_gate(manager, rec: Rec, *, predicate, ledger, is_sealed, attested_ok=None):
    """Build the gate via the public W1 name and register it with the real PluginContext.
    A thin counting shim records each middleware entry; exceptions and returns pass through
    unchanged, so Hermes' fail-open semantics apply to the gate exactly as registered."""
    gate = build_gate(predicate=predicate, ledger=ledger, is_sealed=is_sealed, attested_ok=attested_ok)

    def llm_execution(request, next_call, **context):
        with rec.lock:
            rec.middleware_calls.append(dict(context))
        return gate(request=request, next_call=next_call, **context)

    ctx = PluginContext(PluginManifest(name="confidential_mode_hostile"), manager)
    ctx.register_middleware("llm_execution", llm_execution)
    return gate


def mutate_context(monkeypatch, mutate: Callable[[dict], None]):
    """Rewrite the context Hermes hands every llm_execution callback, on the real turn path
    (perform_api_call imports run_llm_execution_middleware from hermes_cli.middleware per call)."""
    import hermes_cli.middleware as mw
    real = mw.run_llm_execution_middleware

    def wrapped(request, next_call, **context):
        mutate(context)
        return real(request, next_call, **context)

    monkeypatch.setattr(mw, "run_llm_execution_middleware", wrapped)


def install_outer_payload_mutator(manager, mutate: Callable[[dict], dict]):
    """An outer llm_execution middleware (registered BEFORE the gate) that hands the gate a
    different request payload via next_call(payload)."""
    def outer(request, next_call, **context):
        return next_call(mutate(request))
    PluginContext(PluginManifest(name="hostile_outer"), manager).register_middleware("llm_execution", outer)


# ---------------------------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------------------------


def assert_refused_clean(result, rec: Rec, agent, *, middleware_calls: int = 1):
    """The gate refused: a completed, non-failed turn whose answer is not the provider's, with
    zero provider requests, no fallback, no backoff, no rate-limit cooldown."""
    assert rec.provider_calls == [], f"LEAK: provider received {len(rec.provider_calls)} request(s)"
    assert len(rec.middleware_calls) == middleware_calls, rec.middleware_calls
    assert result.get("completed") is True, result
    assert not result.get("failed"), result
    fr = result.get("final_response") or ""
    assert fr and fr != PROVIDER_TEXT
    assert SECRET not in fr, "refusal echoes the prompt"
    assert rec.fallback_calls == [], "_try_activate_fallback must never be called"
    assert rec.backoff_calls == [] and rec.backoff_sleeps == [], "no backoff"
    assert rec.error_hook_calls == [], "no api_request_error hook"
    assert getattr(agent, "_rate_limited_until", 0) in (0, None)
    assert getattr(agent, "_rate_limit_backoff_count", 0) == 0
    assert agent._fallback_index == 0


def assert_no_secret_in_ledger(ledger: FakeLedger):
    assert SECRET not in ledger_text(ledger), "ledger stored prompt text"


def run_in_thread(fn, timeout: float = 30.0):
    box: dict[str, Any] = {}

    def target():
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - we want to see everything
            box["exc"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "turn hung"
    return box

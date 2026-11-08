"""Harness for the integrated hostile suite (T5): the plugin as Hermes actually loads it.

Reuses, rather than rebuilds:
  * tests/seam/test_register.py ``plugin`` fixture: the worktree copied into a temp HERMES_HOME/plugins,
    loaded by the REAL ``PluginManager.discover_and_load``; ``plugin.slash`` drives ``/confidential``;
  * tests/scenario/_fakes.py ``MockNet`` (on-host / enclave / openrouter recorders) and ``patch_hermes_http``
    (Hermes' keepalive httpx builder -> MockNet, so real openai clients Hermes builds send real HTTP into
    the mock);
  * tests/seam/_harness.py ``Rec`` / ``provider_ok`` (the C0 recording terminal for the main call).

Added here only what those do not provide:
  * ``net`` fixture: MockNet + a hard network ban (any request on httpx's real transports is recorded in
    ``BANNED`` and raises), so "Hermes' default transport" is observable and nothing can reach a network;
  * ``make_agent``: test_register.build_agent with a choosable provider/base_url/session_db (the live
    runtime of an agent whose session switched models, or was launched with ``--provider``);
  * ``PluginFakeAdapter``: the VendorAdapter fake built from the PLUGIN PACKAGE's own VerificationResult
    (tests/scenario/_fakes.FakeVendorAdapter builds the top-level ``confidential_mode`` copy's class,
    which the loaded plugin's isinstance check rejects);
  * ``second_plugin``: a second fake plugin context on the same manager (in-process trust boundary).
"""
from __future__ import annotations

import importlib
import json
import threading
import time
from types import SimpleNamespace

import httpx
import pytest

import run_agent
from hermes_cli.plugins import PluginContext
from hermes_cli.plugins_manifest import PluginManifest

from ..scenario._fakes import (  # noqa: F401  (re-exported for the tests)
    ENCLAVE, ENCLAVE_URL, ON_HOST_URL as NET_ON_HOST_URL, OPENROUTER_HOST, OPENROUTER_URL, REPO, MockNet,
    patch_hermes_http,
)
from ..seam._harness import Rec, no_lazy_installs, provider_ok  # noqa: F401  (fixture)
from ..seam.test_register import BASE_CONFIG, ON_HOST_URL, SK, plugin  # noqa: F401  (fixture)

SECRET = "MERGER-TERMS-7731-CONFIDENTIAL"

_SCRUB_ENV = (
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "NOUS_API_KEY",
    "DEEPINFRA_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY", "HERMES_INFERENCE_PROVIDER",
    "HERMES_MODEL", "TINFOIL_USER_CACHE_SECRET",
)

BANNED: list[str] = []


def cm(plugin, name: str):
    """A submodule of the LOADED plugin package (hermes_plugins.confidential_mode...)."""
    return importlib.import_module(f"{plugin.mod.__name__}.confidential_mode.{name}")


@pytest.fixture
def net(monkeypatch):
    """MockNet behind Hermes' keepalive builder, and a ban on httpx's real transports."""
    from agent import auxiliary_client as aux
    BANNED.clear()
    for var in _SCRUB_ENV:
        monkeypatch.delenv(var, raising=False)

    def ban(self, request, *a, **k):
        BANNED.append(str(request.url))
        raise httpx.ConnectError(f"hostile harness: network banned ({request.url})")

    async def aban(self, request, *a, **k):
        BANNED.append(str(request.url))
        raise httpx.ConnectError(f"hostile harness: network banned ({request.url})")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", ban)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", aban)
    n = MockNet()
    patch_hermes_http(monkeypatch, n)
    aux._client_cache.clear()
    yield n
    aux._client_cache.clear()


def bytes_seen(router) -> int:
    return len(router.requests)


def make_agent(monkeypatch, rec: Rec, *, provider: str = "custom", base_url: str = ON_HOST_URL,
               model: str = "llama3", api_key: str = "sk-test", session_db=None, max_iterations: int = 4,
               terminal: bool = True):
    """test_register.build_agent with the live runtime chosen by the test. ``terminal`` replaces the main
    provider call with the C0 recorder (the main path is not what these tests attack)."""
    monkeypatch.setattr("model_tools.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("model_tools.check_toolset_requirements", dict)
    agent = run_agent.AIAgent(model=model, provider=provider, api_mode="chat_completions", base_url=base_url,
                              api_key=api_key, quiet_mode=True, skip_context_files=True, skip_memory=True,
                              max_iterations=max_iterations, session_db=session_db)
    agent._cleanup_task_resources = lambda task_id: None
    agent._save_trajectory = lambda messages, user_message, completed: None
    agent._disable_streaming = True
    if terminal:
        def _call(api_kwargs, **_kw):
            rec.provider_calls.append(api_kwargs)
            return provider_ok("chat_completions")
        agent._interruptible_api_call = _call
        agent._interruptible_streaming_api_call = lambda api_kwargs, **kw: rec.streaming_calls.append(api_kwargs)
    agent._try_activate_fallback = lambda *a, **k: rec.fallback_calls.append((a, k)) or False
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    return agent


def session_db(home):
    from hermes_state import SessionDB
    return SessionDB(db_path=home / "state.db")


def wait_for(pred, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        threading.Event().wait(0.02)
    return pred()


def join_background(prefixes=("auto-title", "hermes-hook", "confidential-verify"), timeout: float = 5.0) -> None:
    end = time.monotonic() + timeout
    for t in list(threading.enumerate()):
        if t is threading.current_thread() or not any(t.name.startswith(p) for p in prefixes):
            continue
        t.join(max(0.0, end - time.monotonic()))


class BodyRouter:
    """Wrap a MockNet Router so request bodies are kept (the scenario Router keeps only metadata)."""

    def __init__(self, router):
        self.router = router
        self.bodies: list[str] = []
        orig = router.handle

        def handle(request):
            try:
                self.bodies.append(request.content.decode("utf-8", "replace"))
            except Exception:
                self.bodies.append("<unreadable>")
            return orig(request)
        router.handle = handle

    @property
    def requests(self):
        return self.router.requests

    def saw(self, needle: str) -> bool:
        return any(needle in b for b in self.bodies)


def second_plugin(mgr, name: str = "hostile-second") -> PluginContext:
    """A second plugin in the same process (same manager): the in-process trust boundary."""
    return PluginContext(PluginManifest(name=name, source="user"), mgr)


# ── attested: a fake vendor adapter built from the plugin package's own types ──────────────────

class PluginFakeAdapter:
    vendor = "tinfoil"
    enclave_host = ENCLAVE
    base_url = ENCLAVE_URL
    enclave_source = "test"

    def __init__(self, plugin, net: MockNet, *, code: str = "c0de1" * 8, enclave: str = "e1c1" * 8,
                 release: str = "v1.0.0", evidence: dict | None = None):
        self._base = cm(plugin, "verify.base")
        self.net = net
        self.code, self.enclave, self.release = code, enclave, release
        self.fail: str | None = None
        self.attestations = 0
        self.held = None
        self.evidence = evidence

    def resolve_enclave_host(self) -> str:
        return ENCLAVE

    def verify(self):
        self.attestations += 1
        if self.fail:
            raise self._base.VerifyError(self.fail)
        ev = self.evidence if self.evidence is not None else {
            "format": "fake-attestation", "enclaveHost": ENCLAVE, "codeFingerprint": self.code,
            "enclaveFingerprint": self.enclave, "releaseTag": self.release, "n": self.attestations}
        return self._base.VerificationResult(
            vendor=self.vendor, router_repo=REPO, enclave_host=ENCLAVE, code_fingerprint=self.code,
            enclave_fingerprint=self.enclave, release_tag=self.release, verifier="fake-tinfoil/0.14.2",
            verified_at_host_clock=time.time(), evidence=ev)

    def hold(self, reason):
        self.held = reason

    def release(self):
        self.held = None

    def sync_http_view(self):
        return self.net.sync_client()

    def async_http_for_loop(self):
        return self.net.async_client()


def install_fake_adapter(plugin, net: MockNet, **kw) -> PluginFakeAdapter:
    """Swap the registered TinfoilAdapter for the fake inside the plugin's OWN cache entry, keeping
    everything register(ctx) wired (on_event, pins, profile, ttl)."""
    provider = cm(plugin, "provider")
    adapter = PluginFakeAdapter(plugin, net, **kw)
    entry = provider.verification_cache.entry(provider.PROFILE_NAME)
    assert entry is not None, "register(ctx) did not register the attested cache entry"
    entry.adapter = adapter
    entry.result, entry.failed_mono = None, None
    plugin.rt.adapter = adapter
    plugin.rt.profile._confidential_adapter = adapter
    plugin.rt.profile.base_url = ENCLAVE_URL
    return adapter


ATTESTED_CONFIG = f"""\
plugins:
  enabled: [confidential-mode]
model:
  provider: attested-tinfoil
  default: tf-main-model
  base_url: {ENCLAVE_URL}
auxiliary:
  vision:
    provider: attested-tinfoil
    model: tf-vision
confidential:
  tinfoil:
    enclave: {ENCLAVE}
"""


def answer_choice(plugin, monkeypatch, *answers):
    """Script ctx.ask_choice on the REAL PluginContext the plugin registered with."""
    queue = list(answers)
    asked: list = []

    def ask_choice(question, choices, **kw):
        asked.append((question, choices))
        return queue.pop(0) if queue else None
    monkeypatch.setattr(plugin.rt.ctx, "ask_choice", ask_choice, raising=False)
    return asked


def rows(plugin, kind=None):
    out = plugin.rt.ledger.tail(0, limit=100000)
    return [e for e in out if kind is None or e.kind == kind]


"""Shared harness for the hostile W2 tests (attested client, provider profile, pin store).

Written against the C1 contract in docs/INTERFACES.md before the W2 implementation existed. Everything
that crosses the SDK or network boundary is a fake defined here:

  * StubAdapter            a VendorAdapter whose verify() is scripted (ok / raise / hang / mismatch) and
                           whose transports are recording httpx transports:
      - "secure-sync"      ONE shared sync pool behind per-call non-closing views (what the real adapter
                           must hand out); closing the pool is recorded and makes it unusable.
      - "secure-async"     one AsyncClient per running loop, bound to that loop; use from any other loop
                           (or after its loop closed) is recorded as "DEAD-LOOP" and raises.
  * hermes-default-*       Hermes' own keepalive client builder patched to a recorder: any request that
                           lost the attested transport lands here.
  * network                socket connect/getaddrinfo blocked and recorded: a plain httpx/openai client
                           built anywhere ends up here.

REQUESTS is the single source of truth: every test asserts on which label every request used.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import socket
import sys
import threading
import time as _real_time
import types
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

WORKTREE = Path(__file__).resolve().parents[2]
if str(WORKTREE) not in sys.path:
    sys.path.insert(0, str(WORKTREE))

PROFILE_NAME = "attested-tinfoil"
KEY_ENV = "TINFOIL_API_KEY"
ENCLAVE_HOST = "enclave.hostile.invalid"
ENCLAVE_URL = f"https://{ENCLAVE_HOST}/v1"
ROUTER_REPO = "tinfoilsh/confidential-model-router"
FP_CODE = "c0de" * 16
FP_ENCLAVE = "e0c1" * 16
FP_CODE_2 = "beef" * 16
FP_ENCLAVE_2 = "f00d" * 16
FAKE_REPLY = "HOSTILE-FAKE-REPLY"
MSG = [{"role": "user", "content": "hi"}]

# ── request recording ─────────────────────────────────────────────────────────────────────────


@dataclass
class Req:
    label: str
    host: str
    path: str
    stream: bool
    transport_id: int
    loop_id: int | None = None


REQUESTS: list[Req] = []
NETWORK_ATTEMPTS: list[str] = []      # socket-level attempts not explained by Hermes' metadata probes
METADATA_ATTEMPTS: list[str] = []     # Hermes model-metadata probes (context length, models.dev catalog)
_METADATA_MODULES = ("agent/model_metadata", "agent/models_dev", "agent/context_default_record")
_LOCK = threading.Lock()


def _record(req: Req) -> None:
    with _LOCK:
        REQUESTS.append(req)


def labels(since: int = 0) -> list[str]:
    return [r.label for r in REQUESTS[since:]]


def insecure_requests() -> list[Req]:
    return [r for r in REQUESTS if not r.label.startswith("secure-")]


def _completion(model: str) -> dict:
    return {"id": "hostile-1", "object": "chat.completion", "created": int(_real_time.time()), "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": FAKE_REPLY}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _sse(model: str) -> bytes:
    base = {"id": "hostile-1", "object": "chat.completion.chunk", "created": int(_real_time.time()), "model": model}
    chunks = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": FAKE_REPLY},
                                   "finish_reason": None}]),
              dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])]
    return b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"


def _respond(request: httpx.Request) -> httpx.Response:
    try:
        body = json.loads(request.content or b"{}")
    except Exception:
        body = {}
    model = body.get("model") or "m"
    if request.url.path.endswith("/models"):
        return httpx.Response(200, json={"object": "list", "data": [{"id": "m", "object": "model",
                                                                      "created": 0, "owned_by": "x"}]})
    if body.get("stream"):
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=_sse(model))
    return httpx.Response(200, json=_completion(model))


def _stream_flag(request: httpx.Request) -> bool:
    try:
        return bool(json.loads(request.content or b"{}").get("stream"))
    except Exception:
        return False


class SharedSyncPool(httpx.BaseTransport):
    """The ONE verified sync pool. close() is recorded and makes the pool unusable (like a closed pool)."""

    def __init__(self, label: str = "secure-sync"):
        self.label = label
        self.closed = False
        self.close_calls = 0

    def handle_request(self, request):
        if self.closed:
            _record(Req("secure-sync-AFTER-POOL-CLOSE", request.url.host, request.url.path,
                        _stream_flag(request), id(self)))
            raise httpx.ConnectError("shared attested pool was closed", request=request)
        _record(Req(self.label, request.url.host, request.url.path, _stream_flag(request), id(self)))
        return _respond(request)

    def close(self):
        self.closed = True
        self.close_calls += 1


class NonClosingView(httpx.BaseTransport):
    """Per-client view: closing it never closes the shared pool. Deliberately has no _pool attribute so
    Hermes' socket sweep (agent_runtime_helpers._iter_pool_sockets) cannot reach the shared pool."""

    def __init__(self, inner: SharedSyncPool):
        self._inner = inner
        self.closed = False

    def handle_request(self, request):
        return self._inner.handle_request(request)

    def close(self):
        self.closed = True


_LOOP_SERIALS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_SERIAL = [0]


def _serial() -> int:
    with _LOCK:
        _SERIAL[0] += 1
        return _SERIAL[0]


def loop_serial(loop) -> int | None:
    """A never-reused identity for a loop (id(loop) is reused once a loop is collected)."""
    if loop is None:
        return None
    if loop not in _LOOP_SERIALS:
        _LOOP_SERIALS[loop] = _serial()
    return _LOOP_SERIALS[loop]


class LoopBoundAsyncTransport(httpx.AsyncBaseTransport):
    """Bound to the loop it was built on, held WEAKLY so the stub never keeps a dead loop alive (a strong
    ref would stop CPython reusing id(loop) and hide id-keyed caches in the client)."""

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self._loop_ref = weakref.ref(loop)
        self.closed = False
        self.serial = _serial()

    async def handle_async_request(self, request):
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        bound = self._loop_ref()
        if bound is None or running is not bound or bound.is_closed() or self.closed:
            _record(Req("DEAD-LOOP", request.url.host, request.url.path, _stream_flag(request), self.serial,
                        loop_serial(running)))
            raise RuntimeError("async attested client used outside the loop it was built for")
        _record(Req("secure-async", request.url.host, request.url.path, _stream_flag(request), self.serial,
                    loop_serial(running)))
        return _respond(request)

    async def aclose(self):
        self.closed = True


# ── verification results and the stub adapter ────────────────────────────────────────────────


def make_result(cm, *, code: str = FP_CODE, enclave: str = FP_ENCLAVE, vendor: str = "tinfoil",
                router_repo: str = ROUTER_REPO, host: str = ENCLAVE_HOST, verified_at: float | None = None,
                release_tag: str | None = "v1.0.0"):
    return cm.VerificationResult(
        vendor=vendor, router_repo=router_repo, enclave_host=host, code_fingerprint=code,
        enclave_fingerprint=enclave, release_tag=release_tag, verifier="hostile-stub/0",
        verified_at_host_clock=_real_time.time() if verified_at is None else verified_at,
        evidence={"stub": True, "code": code, "enclave": enclave})


class Hang:
    """Script step: verify() blocks until release() (or the test's teardown)."""

    def __init__(self):
        self.event = threading.Event()
        self.entered = threading.Event()

    def release(self):
        self.event.set()


class StubAdapter:
    """VendorAdapter fake. `script` is consumed one step per verify() call; the last step repeats.
    A step is a VerificationResult (returned), an exception instance (raised), a Hang, or a callable."""

    # Not in the frozen protocol, but the profile needs its base_url before the first verify(); offer the
    # obvious spellings so an implementation reading one of them is not failed by the stub.
    enclave_host = enclave = host = ENCLAVE_HOST
    base_url = ENCLAVE_URL
    router_repo = ROUTER_REPO

    def __init__(self, cm, script: list, vendor: str = "tinfoil"):
        self.cm = cm
        self.vendor = vendor
        self.script = list(script)
        self.verify_calls = 0
        self.pool = SharedSyncPool()
        self.views: list[httpx.Client] = []
        self.async_clients: dict[int, tuple[weakref.ref, httpx.AsyncClient]] = {}
        self.async_builds: list[int] = []
        self.hangs: list[Hang] = [s for s in self.script if isinstance(s, Hang)]
        self._lock = threading.Lock()

    def verify(self):
        with self._lock:
            self.verify_calls += 1
            idx = min(self.verify_calls - 1, len(self.script) - 1)
            step = self.script[idx]
        if isinstance(step, Hang):
            step.entered.set()
            step.event.wait(60)
            return make_result(self.cm)
        if isinstance(step, BaseException):
            raise step
        if callable(step) and not isinstance(step, type):
            return step()
        return step

    def sync_http_view(self) -> httpx.Client:
        view = httpx.Client(transport=NonClosingView(self.pool), follow_redirects=False)
        self.views.append(view)
        return view

    def async_http_for_loop(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        entry = self.async_clients.get(id(loop))
        if entry is None or entry[0]() is not loop:  # identity check: never hand a dead loop's client out
            entry = (weakref.ref(loop), httpx.AsyncClient(transport=LoopBoundAsyncTransport(loop),
                                                          follow_redirects=False))
            self.async_clients[id(loop)] = entry
            self.async_builds.append(id(loop))
        return entry[1]

    def release_all(self):
        for h in self.hangs:
            h.release()


# ── contract import ───────────────────────────────────────────────────────────────────────────


def load_contract():
    """Import the W2 contract names. ImportError here means W2 has not merged yet."""
    from confidential_mode import client as client_mod, pins as pins_mod, provider as provider_mod
    from confidential_mode.verify import base as base_mod
    return types.SimpleNamespace(
        client_mod=client_mod, provider_mod=provider_mod, pins_mod=pins_mod, base_mod=base_mod,
        ConfidentialClient=client_mod.ConfidentialClient, RefusingClient=client_mod.RefusingClient,
        ConfidentialRefused=client_mod.ConfidentialRefused, make_profile=provider_mod.make_profile,
        attested_ok=provider_mod.attested_ok, PinStore=pins_mod.PinStore,
        VendorAdapter=base_mod.VendorAdapter, VerificationResult=base_mod.VerificationResult,
        VerifyError=base_mod.VerifyError,
    )


def _reset_w2_caches(cm) -> None:
    """Best effort: call a test-reset hook if W2 provides one (names guessed; absence is fine)."""
    for mod in (cm.provider_mod, cm.client_mod, cm.pins_mod):
        for name in ("_reset_for_tests", "reset_for_tests", "_reset_cache", "reset_cache", "_reset"):
            fn = getattr(mod, name, None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass


# ── pin store adaptors (constructor / apply signatures are not frozen) ────────────────────────


def make_store(cm, directory: Path):
    """PinStore over `directory`. The contract does not freeze the constructor: pass a directory if the
    first parameter is named like one, else the pins.yaml path."""
    directory.mkdir(parents=True, exist_ok=True)
    try:
        params = [p for p in inspect.signature(cm.PinStore).parameters.values() if p.name != "self"]
    except (TypeError, ValueError):
        params = []
    first = params[0].name.lower() if params else "path"
    arg = directory if any(t in first for t in ("dir", "home", "root", "folder")) else directory / "pins.yaml"
    return cm.PinStore(arg)


def pins_file(directory: Path) -> Path | None:
    cands = sorted(p for p in directory.rglob("*") if p.is_file() and p.suffix in (".yaml", ".yml")
                   and "pending" not in p.name)
    named = [p for p in cands if p.name.startswith("pins")]
    return (named or cands or [None])[0]


_APPLY_DEFAULTS = {"approved_by": "human", "approved_via": "hostile-test", "via": "hostile-test",
                   "surface": "hostile-test", "approval_rule_key": "hostile-test", "rule_key": "hostile-test",
                   "models_seen": [], "session_id": "hostile-session", "platform": "cli"}


def apply(store, pending):
    """store.apply(pending), supplying any extra required keyword the implementation demands."""
    try:
        params = list(inspect.signature(store.apply).parameters.values())[1:]
    except (TypeError, ValueError):
        params = []
    extra = {}
    for p in params:
        if p.default is inspect.Parameter.empty and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD):
            extra[p.name] = _APPLY_DEFAULTS.get(p.name, "hostile-test")
    return store.apply(pending, **extra)


def pin(store, result):
    """Stage + apply: the store now pins `result`."""
    return apply(store, store.stage(result))


def contains(obj: Any, needle: str, _depth: int = 0) -> bool:
    """True if `needle` appears anywhere in obj's (nested) attributes/values/repr."""
    if _depth > 6:
        return False
    if isinstance(obj, str):
        return needle in obj
    if isinstance(obj, dict):
        return any(contains(k, needle, _depth + 1) or contains(v, needle, _depth + 1) for k, v in obj.items())
    if isinstance(obj, (list, tuple, set, frozenset)):
        return any(contains(v, needle, _depth + 1) for v in obj)
    d = getattr(obj, "__dict__", None)
    if isinstance(d, dict) and contains(d, needle, _depth + 1):
        return True
    slots = getattr(type(obj), "__dataclass_fields__", None)
    if slots and any(contains(getattr(obj, k, None), needle, _depth + 1) for k in slots):
        return True
    try:
        return needle in repr(obj)
    except Exception:
        return False


# ── fake clock ────────────────────────────────────────────────────────────────────────────────


class FakeClock:
    """Independently controllable wall (time.time) and monotonic clocks, installed into every loaded
    confidential_mode module (module-level `time` and from-imported functions). asyncio keeps the real
    monotonic clock because only the plugin's references are swapped."""

    def __init__(self, wall: float = 1_000_000.0, mono: float = 5_000.0):
        self.wall = wall
        self.mono = mono

    def advance(self, seconds: float, *, wall: bool = True, mono: bool = True):
        if wall:
            self.wall += seconds
        if mono:
            self.mono += seconds

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def namespace(self):
        clock = self

        class _T(types.ModuleType):
            def __getattr__(self, name):
                return getattr(_real_time, name)
        ns = _T("time")
        ns.time = clock.time
        ns.time_ns = lambda: int(clock.wall * 1e9)
        ns.monotonic = clock.monotonic
        ns.monotonic_ns = lambda: int(clock.mono * 1e9)
        ns.perf_counter = clock.monotonic
        ns.perf_counter_ns = lambda: int(clock.mono * 1e9)
        return ns

    def install(self, monkeypatch):
        ns = self.namespace()
        swaps = {_real_time.time: self.time, _real_time.monotonic: self.monotonic,
                 _real_time.perf_counter: self.monotonic}
        for name, mod in list(sys.modules.items()):
            if not (name == "confidential_mode" or name.startswith("confidential_mode.")) or mod is None:
                continue
            for attr, val in list(vars(mod).items()):
                if val is _real_time:
                    monkeypatch.setattr(mod, attr, ns)
                elif callable(val) and any(val is k for k in swaps):
                    monkeypatch.setattr(mod, attr, next(v for k, v in swaps.items() if val is k))
            # datetime.now-based TTL is not intercepted; the tests below would then show it.


# ── profile + client helpers ──────────────────────────────────────────────────────────────────


def build_profile(cm, adapter, store, ttl: float = 300.0):
    return cm.make_profile(adapter, store, ttl_seconds=ttl, verify_wait_seconds=5)


def create(profile, **extra):
    kw = {"api_key": "hostile-key", "base_url": ENCLAVE_URL}
    kw.update(extra)
    return profile.create_client(**kw)


def chat(client, **extra):
    """Sync call. NOTE: this helper is a sync frame, so even `await chat(c)` is dispatched as sync by a
    caller-frame check; async tests must use achat()."""
    kw = {"model": "hostile-model", "messages": MSG}
    kw.update(extra)
    return client.chat.completions.create(**kw)


async def achat(client, **extra):
    kw = {"model": "hostile-model", "messages": MSG}
    kw.update(extra)
    return await client.chat.completions.create(**kw)


def run_with_timeout(fn: Callable, seconds: float):
    """Run fn in a daemon thread. Returns (finished, value, exception)."""
    box: dict = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            box["exc"] = exc
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), box.get("value"), box.get("exc")


def reply_text(resp) -> str:
    try:
        return resp.choices[0].message.content or ""
    except Exception:
        return ""


# ── fixtures ──────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def cm():
    contract = load_contract()
    _reset_w2_caches(contract)
    yield contract
    _reset_w2_caches(contract)


@pytest.fixture(autouse=True)
def _wire(monkeypatch):
    """Clear the recorders, block the network, record Hermes' own transport (when Hermes is importable)."""
    REQUESTS.clear()
    NETWORK_ATTEMPTS.clear()
    METADATA_ATTEMPTS.clear()

    def blocked(*args, **kwargs):
        import traceback
        stack = "".join(traceback.format_stack(limit=40))
        entry = repr(args[:1])[:200]
        if any(m in stack for m in _METADATA_MODULES):
            METADATA_ATTEMPTS.append(entry)
        else:
            NETWORK_ATTEMPTS.append(entry + "\n" + stack[-3000:])
        raise OSError("NETWORK BLOCKED by hostile harness")
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", lambda self, *a, **k: blocked(*a))
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, *a, **k: blocked(*a))

    try:
        import agent.process_bootstrap as _bootstrap
    except Exception:
        _bootstrap = None
    if _bootstrap is not None:
        def fake_keepalive(base_url="", *, async_mode=False, verify=True):
            label = "hermes-default-" + ("async" if async_mode else "sync")
            if async_mode:
                async def ahandle(request):
                    _record(Req(label, request.url.host, request.url.path, _stream_flag(request), 0))
                    return _respond(request)
                return httpx.AsyncClient(transport=httpx.MockTransport(ahandle))

            def handle(request):
                _record(Req(label, request.url.host, request.url.path, _stream_flag(request), 0))
                return _respond(request)
            return httpx.Client(transport=httpx.MockTransport(handle))
        monkeypatch.setattr(_bootstrap, "build_keepalive_http_client", fake_keepalive)
    yield


@pytest.fixture
def clock(cm, monkeypatch):
    c = FakeClock()
    c.install(monkeypatch)
    return c


@pytest.fixture
def adapters():
    """Collects StubAdapters so hung verify() threads are released at teardown."""
    made: list[StubAdapter] = []
    yield made
    for a in made:
        a.release_all()


@pytest.fixture
def setup(cm, tmp_path, clock, adapters):
    """Factory: (adapter, store, profile) with the store already pinned to `pinned` (default: the good
    result) unless pinned=None."""
    def _make(script, *, pinned="default", ttl: float = 300.0, vendor: str = "tinfoil"):
        if pinned == "default":
            pinned = make_result(cm, verified_at=clock.wall)
        adapter = StubAdapter(cm, script, vendor=vendor)
        adapters.append(adapter)
        store = make_store(cm, tmp_path / f"pins-{len(adapters)}")
        if pinned is not None:
            pin(store, pinned)
        profile = build_profile(cm, adapter, store, ttl)
        return adapter, store, profile
    return _make


# Credential env vars that would let Hermes' auxiliary auto-router reach a real provider.
_SCRUB_ENV = (
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "NOUS_API_KEY",
    "DEEPINFRA_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY", "HERMES_INFERENCE_PROVIDER",
    "HERMES_MODEL", "HERMES_PLUGIN_HOST_PROCESS",
)


@pytest.fixture
def hermes(tmp_path, monkeypatch):
    """Fresh HERMES_HOME + isolated provider/auth/plugin/aux-cache state. Returns a
    register(profile) function that installs the W2 profile into Hermes' provider registry."""
    import hermes_cli.auth as _auth
    import hermes_cli.plugins as _plugins
    import hermes_yaml as yaml
    import providers as _providers
    from agent import auxiliary_client as _aux

    home = tmp_path / ".hermes"
    (home / "plugins").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    for var in _SCRUB_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(KEY_ENV, "hostile-key")
    _providers._discover_providers()
    monkeypatch.setattr(_providers, "_REGISTRY", dict(_providers._REGISTRY))
    monkeypatch.setattr(_providers, "_ALIASES", dict(_providers._ALIASES))
    monkeypatch.setattr(_providers, "_SOURCES", dict(_providers._SOURCES))
    monkeypatch.setattr(_providers, "_PROVIDER_LIST_CACHE", None)
    monkeypatch.setattr(_auth, "PROVIDER_REGISTRY", dict(_auth.PROVIDER_REGISTRY))
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()
    cfg = {"model": {"provider": PROFILE_NAME, "default": "hostile-model", "base_url": ENCLAVE_URL},
           "auxiliary": {"compression": {"provider": PROFILE_NAME, "model": "hostile-model"}}}
    (home / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")

    def register(profile):
        assert profile.name == PROFILE_NAME, profile.name
        _providers.register_provider(profile)
        assert _providers.get_provider_profile(PROFILE_NAME) is profile

    def agent():
        from run_agent import AIAgent
        return AIAgent(model="hostile-model", provider=PROFILE_NAME, api_key="hostile-key", base_url=ENCLAVE_URL,
                       quiet_mode=True, skip_context_files=True, skip_memory=True)

    yield types.SimpleNamespace(home=home, register=register, agent=agent, aux=_aux)
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()

"""C0 follow-up spike (Gap 1): can a create_client()-supplied client keep its attested httpx transport
on BOTH the sync and async auxiliary paths, without any Hermes change?

Spike only. A throwaway plugin (written into a temp HERMES_HOME) registers a ProviderProfile whose
create_client() returns one of three candidate client shapes, selected by SPIKE_CANDIDATE:

  subclass    openai.OpenAI subclass on the "secure" sync transport, carrying an async-twin factory
              attribute (_to_async_client reads no such attribute: expected to LOSE the transport).
  dual-frame  thin dual client, HERMES_SKIP_TRANSPORT_WRAP/HERMES_SKIP_ASYNC_WRAP = True, whose
              chat.completions.create returns a coroutine (AsyncOpenAI on the secure async transport)
              when its CALLER is a coroutine frame, else runs the sync OpenAI on the secure sync transport.
  dual-loop   same, but "async" = asyncio.get_running_loop() succeeds in the calling thread.

"Secure" transports are httpx.MockTransport stand-ins that record every request with a label.
Hermes' own keepalive httpx client builder is patched to a recording transport labelled
"hermes-default-*", so a request that lost the secure transport is visible (and never hits the network).
Every attribute Hermes code reads on the client object is logged with its Hermes file:line.

Run (Hermes .venv has no pytest; the overlay leaves it untouched):
    cd ~/hermes-agent && HERMES_HOME=$(mktemp -d) uv run --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \\
        pytest <worktree>/tests/spikes -q -p no:cacheprovider
"""
from __future__ import annotations

import asyncio
import os
import struct
import sys
import textwrap
import zlib
from pathlib import Path

import pytest

PROFILE_NAME = "spike-tinfoil"
KEY_ENV = "SPIKE_TINFOIL_API_KEY"
BASE_URL = "https://spike-tinfoil.invalid/v1"

PLUGIN_SOURCE = textwrap.dedent(
    r'''
    import asyncio
    import inspect
    import json
    import os
    import sys
    import time
    from types import SimpleNamespace

    import httpx
    import openai
    import providers
    from providers.base import ProviderProfile

    REQUESTS = []    # (transport label, url path, stream?)
    ATTR_READS = []  # (client class, attribute, hermes file:line)
    CREATED = []     # (candidate, client class)
    HERMES_ROOT = os.path.realpath(os.environ.get("HERMES_AGENT_ROOT") or os.path.expanduser("~/hermes-agent"))


    # ── recording "transports" ───────────────────────────────────────────────────────────────
    def _completion(model):
        return {"id": "spike-1", "object": "chat.completion", "created": int(time.time()), "model": model,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "SPIKE-FAKE-REPLY"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


    def _sse(model):
        base = {"id": "spike-1", "object": "chat.completion.chunk", "created": int(time.time()), "model": model}
        chunks = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": "SPIKE-FAKE-REPLY"},
                                       "finish_reason": None}]),
                  dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])]
        return b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"


    def handler(label):
        def handle(request):
            try:
                body = json.loads(request.content or b"{}")
            except Exception:
                body = {}
            REQUESTS.append((label, request.url.path, bool(body.get("stream"))))
            model = body.get("model") or "m"
            if body.get("stream"):
                return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=_sse(model))
            return httpx.Response(200, json=_completion(model))
        return handle


    class _NonClosingView(httpx.BaseTransport):
        """Per-client view over ONE shared attested transport: closing a Hermes-owned client must not
        tear down the shared verified pool (Hermes closes request-scoped clients after each turn)."""
        def __init__(self, inner):
            self._inner = inner

        def handle_request(self, request):
            return self._inner.handle_request(request)

        def close(self):
            pass


    _SHARED_SECURE_SYNC = httpx.MockTransport(handler("secure-sync"))


    def secure_sync_http():
        return httpx.Client(transport=_NonClosingView(_SHARED_SECURE_SYNC), follow_redirects=False)


    def secure_async_http():
        # Async pools are bound to the loop that first uses them: one per loop.
        return httpx.AsyncClient(transport=httpx.MockTransport(handler("secure-async")), follow_redirects=False)


    # ── attribute-read logging ───────────────────────────────────────────────────────────────
    def _log_read(obj, name):
        frame = sys._getframe(2)
        fn = os.path.realpath(frame.f_code.co_filename)
        if fn.startswith(HERMES_ROOT + os.sep) and "site-packages" not in fn:
            ATTR_READS.append((type(obj).__name__, name, f"{os.path.relpath(fn, HERMES_ROOT)}:{frame.f_lineno}"))


    class _AttrLog:
        def __getattribute__(self, name):
            _log_read(self, name)
            return object.__getattribute__(self, name)


    def _openai_kwargs(kw):
        return {"api_key": kw.get("api_key") or "k", "base_url": kw.get("base_url") or "https://x.invalid/v1",
                "max_retries": 0}


    # ── candidate 1: OpenAI subclass with an async-twin factory attribute ─────────────────────
    class SubclassCandidate(_AttrLog, openai.OpenAI):
        def __init__(self, **kw):
            openai.OpenAI.__init__(self, http_client=secure_sync_http(), **_openai_kwargs(kw))
            base = _openai_kwargs(kw)
            self.async_client_factory = lambda: openai.AsyncOpenAI(http_client=secure_async_http(), **base)
            self.async_twin = None  # nothing in Hermes reads it, see the test


    # ── candidate 2: dual client ─────────────────────────────────────────────────────────────
    class _DualCompletions:
        def __init__(self, owner):
            self._owner = owner

        def create(self, **kwargs):
            owner = self._owner
            if owner._caller_is_async(sys._getframe(1)):
                return owner._async_client().chat.completions.create(**kwargs)  # coroutine
            return owner._sync.chat.completions.create(**kwargs)


    class DualClient(_AttrLog):
        HERMES_SKIP_TRANSPORT_WRAP = True
        HERMES_SKIP_ASYNC_WRAP = True

        def __init__(self, mode, **kw):
            self._mode = mode
            self._kw = _openai_kwargs(kw)
            self._sync = openai.OpenAI(http_client=secure_sync_http(), **self._kw)
            self._async_by_loop = {}
            self.api_key = self._sync.api_key
            self.base_url = self._sync.base_url
            self.chat = SimpleNamespace(completions=_DualCompletions(self))

        def _caller_is_async(self, frame):
            if self._mode == "frame":
                return bool(frame.f_code.co_flags & inspect.CO_COROUTINE)
            try:
                asyncio.get_running_loop()
                return True
            except RuntimeError:
                return False

        def _async_client(self):
            loop = asyncio.get_running_loop()
            entry = self._async_by_loop.get(id(loop))
            if entry is None or entry[0] is not loop:
                entry = (loop, openai.AsyncOpenAI(http_client=secure_async_http(), **self._kw))
                self._async_by_loop[id(loop)] = entry
            return entry[1]

        def __getattr__(self, name):  # with_options, models, is_closed, _client, _custom_headers, ...
            return getattr(object.__getattribute__(self, "_sync"), name)

        def close(self):
            self._sync.close()


    class SpikeProfile(ProviderProfile):
        def create_client(self, **client_kwargs):
            cand = os.environ.get("SPIKE_CANDIDATE", "dual-frame")
            client = SubclassCandidate(**client_kwargs) if cand == "subclass" else DualClient(
                cand.split("-", 1)[1], **client_kwargs)
            CREATED.append((cand, type(client).__name__))
            return client


    def register(ctx):
        providers.register_provider(SpikeProfile(
            name="spike-tinfoil", display_name="Spike Tinfoil", auth_type="api_key",
            env_vars=("SPIKE_TINFOIL_API_KEY",), base_url="https://spike-tinfoil.invalid/v1",
            default_aux_model="spike-aux-model",
        ))
    '''
)

_SCRUB_ENV = (
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "NOUS_API_KEY",
    "DEEPINFRA_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY", "HERMES_INFERENCE_PROVIDER",
    "HERMES_MODEL", "HERMES_PLUGIN_HOST_PROCESS",
)

CANDIDATES = ("subclass", "dual-frame", "dual-loop")


def _png(path: Path) -> Path:
    raw = b"\x00" + b"\xff\x00\x00" * 4
    rows = raw * 4
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    import hermes_yaml as yaml
    import providers as _providers
    import hermes_cli.auth as _auth
    import hermes_cli.plugins as _plugins
    from agent import auxiliary_client as _aux
    import agent.process_bootstrap as _bootstrap

    home = tmp_path / ".hermes"
    plugin_dir = home / "plugins" / "spike-confidential"
    plugin_dir.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    for var in _SCRUB_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(KEY_ENV, "spike-key")
    _providers._discover_providers()
    monkeypatch.setattr(_providers, "_REGISTRY", dict(_providers._REGISTRY))
    monkeypatch.setattr(_providers, "_ALIASES", dict(_providers._ALIASES))
    monkeypatch.setattr(_providers, "_SOURCES", dict(_providers._SOURCES))
    monkeypatch.setattr(_providers, "_PROVIDER_LIST_CACHE", None)
    monkeypatch.setattr(_auth, "PROVIDER_REGISTRY", dict(_auth.PROVIDER_REGISTRY))
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()

    (plugin_dir / "plugin.yaml").write_text("name: spike-confidential\nversion: 0.0.1\nkind: standalone\n",
                                            encoding="utf-8")
    (plugin_dir / "__init__.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
    cfg = {"plugins": {"enabled": ["spike-confidential"]},
           "model": {"provider": PROFILE_NAME, "default": "spike-main-model", "base_url": BASE_URL},
           "auxiliary": {"compression": {"provider": PROFILE_NAME, "model": "spike-aux-model"},
                         "vision": {"provider": PROFILE_NAME, "model": "spike-vision-model"}}}
    (home / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    _plugins.discover_plugins(force=True)
    profile = _providers.get_provider_profile(PROFILE_NAME)
    assert profile is not None
    mod = sys.modules[type(profile).__module__]

    # Hermes' own transport, made visible: anything that drops the plugin transport lands here.
    import httpx

    def fake_keepalive(base_url="", *, async_mode=False, verify=True):
        transport = httpx.MockTransport(mod.handler("hermes-default-" + ("async" if async_mode else "sync")))
        return (httpx.AsyncClient if async_mode else httpx.Client)(transport=transport)
    monkeypatch.setattr(_bootstrap, "build_keepalive_http_client", fake_keepalive)

    yield {"mod": mod, "home": home, "tmp": tmp_path}
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()


def _labels(mod, since=0):
    return [r[0] for r in mod.REQUESTS[since:]]


def _run_paths(env, monkeypatch, candidate) -> dict:
    """Drive every client-consuming path once; return {path: [transport labels]} plus attr reads."""
    monkeypatch.setenv("SPIKE_CANDIDATE", candidate)
    mod = env["mod"]
    from agent import auxiliary_client as aux
    from run_agent import AIAgent
    out: dict = {}

    def run(name, fn):
        start = len(mod.REQUESTS)
        try:
            fn()
            err = None
        except Exception as exc:  # recorded, not raised: the table is the result
            err = f"{type(exc).__name__}: {exc}"[:200]
        out[name] = {"labels": _labels(mod, start), "error": err,
                     "streams": [r[2] for r in mod.REQUESTS[start:]]}

    agent = AIAgent(model="spike-main-model", provider=PROFILE_NAME, api_key="spike-key", base_url=BASE_URL,
                    quiet_mode=True, skip_context_files=True, skip_memory=True)
    out["agent.client type"] = type(agent.client).__name__
    run("main turn (streaming)", lambda: agent.run_conversation("hello"))

    def non_stream_turn():
        agent._disable_streaming = True
        try:
            agent.run_conversation("again")
        finally:
            agent._disable_streaming = False
    run("main turn (non-streaming)", non_stream_turn)

    def rebuild_then_turn():
        assert agent._replace_primary_openai_client(reason="spike_rebuild")
        req = agent._create_request_openai_client(reason="spike_request")
        out["rebuilt types"] = (type(agent.client).__name__, type(req).__name__)
        agent._close_request_openai_client(req, reason="spike_request")
        agent.run_conversation("third")
    run("rebuild + request-scoped + turn", rebuild_then_turn)

    aux._client_cache.clear()
    run("aux text sync call_llm(compression)",
        lambda: aux.call_llm(task="compression", messages=[{"role": "user", "content": "hi"}]))
    aux._client_cache.clear()
    run("aux text async_call_llm(compression)",
        lambda: asyncio.run(aux.async_call_llm(task="compression", messages=[{"role": "user", "content": "hi"}])))
    aux._client_cache.clear()

    def vision():
        from tools.vision_tools import vision_analyze_tool
        result = asyncio.run(vision_analyze_tool(str(_png(env["tmp"] / "img.png")), "describe"))
        out["vision result"] = str(result)[:200]
    run("vision_analyze_tool -> async_call_llm(vision)", vision)

    # Two different event loops in a row (gateway/async callers): per-loop async twin must hold up.
    aux._client_cache.clear()
    run("aux async on a 2nd event loop",
        lambda: asyncio.run(aux.async_call_llm(task="vision", messages=[{"role": "user", "content": "hi"}])))

    # Sync call_llm invoked from INSIDE a running event loop (sync code on the loop thread).
    aux._client_cache.clear()

    async def sync_inside_loop():
        return aux.call_llm(task="compression", messages=[{"role": "user", "content": "hi"}])
    run("sync call_llm on a loop thread", lambda: asyncio.run(sync_inside_loop()))

    out["attr_reads"] = sorted({(r[1], r[2]) for r in mod.ATTR_READS})
    return out


def _secure_only(entry) -> bool:
    return bool(entry["labels"]) and all(lbl.startswith("secure-") for lbl in entry["labels"]) and not entry["error"]


# ── (a) what _to_async_client honours ─────────────────────────────────────────────────────────


def test_a_to_async_client_honours_only_isinstance_and_skip_flag():
    import inspect
    from agent import auxiliary_client as aux
    src = inspect.getsource(aux._to_async_client)
    # The only non-isinstance opt-out is the declared flag...
    assert '_client_declares(sync_client, "HERMES_SKIP_ASYNC_WRAP")' in src
    # ...otherwise it rebuilds from these reads only: base_url, api_key, and (via auxiliary_async_rebuild,
    # only for real openai.OpenAI instances) _api_key_provider and _custom_headers. No twin/factory/http_client.
    for read in ("sync_client.base_url", "async_api_key(sync_client)", "configured_default_headers(sync_client)",
                 "sync_client.api_key"):
        assert read in src
    for absent in ("http_client", "_client", "async_client", "factory", "twin", "with_options"):
        assert f"sync_client.{absent}" not in src and f'"{absent}"' not in src
    assert "_openai_http_client_kwargs(sync_base_url, async_mode=True)" in src  # Hermes' own transport
    from agent import auxiliary_async_rebuild as rebuild
    rsrc = inspect.getsource(rebuild)
    assert '"_api_key_provider"' in rsrc and '"_custom_headers"' in rsrc


# ── (b)/(c) candidates across every path ──────────────────────────────────────────────────────


def test_bc_candidate_subclass_loses_async_transport(env, monkeypatch):
    res = _run_paths(env, monkeypatch, "subclass")
    sync_paths = ("main turn (streaming)", "main turn (non-streaming)", "rebuild + request-scoped + turn",
                  "aux text sync call_llm(compression)")
    for p in sync_paths:
        assert _secure_only(res[p]), (p, res[p])
    # Every async aux path is rebuilt by _to_async_client onto Hermes' transport: attestation LOST.
    for p in ("aux text async_call_llm(compression)", "vision_analyze_tool -> async_call_llm(vision)",
              "aux async on a 2nd event loop"):
        assert res[p]["labels"] and set(res[p]["labels"]) == {"hermes-default-async"}, (p, res[p])
    # The factory attribute is never read by Hermes.
    assert not [r for r in res["attr_reads"] if r[0] in ("async_client_factory", "async_twin")]
    print("SUBCLASS", res)


def test_bc_candidate_dual_frame_keeps_secure_transport_everywhere(env, monkeypatch):
    res = _run_paths(env, monkeypatch, "dual-frame")
    assert res["agent.client type"] == "DualClient"
    for p, entry in res.items():
        if isinstance(entry, dict) and "labels" in entry:
            assert _secure_only(entry), (p, entry)
    assert res["main turn (streaming)"]["streams"][-1] is True
    assert res["main turn (non-streaming)"]["streams"] == [False]
    assert set(res["vision_analyze_tool -> async_call_llm(vision)"]["labels"]) == {"secure-async"}
    assert set(res["aux text sync call_llm(compression)"]["labels"]) == {"secure-sync"}
    assert set(res["sync call_llm on a loop thread"]["labels"]) == {"secure-sync"}
    assert "SPIKE-FAKE-REPLY" in res["vision result"]
    print("DUAL_FRAME", res)


def test_bc_candidate_dual_loop_breaks_sync_calls_made_on_a_loop_thread(env, monkeypatch):
    res = _run_paths(env, monkeypatch, "dual-loop")
    assert set(res["vision_analyze_tool -> async_call_llm(vision)"]["labels"]) == {"secure-async"}
    assert set(res["aux text sync call_llm(compression)"]["labels"]) == {"secure-sync"}
    # A sync caller on a thread that has a running loop gets a coroutine back: the call fails
    # (and goes over the secure ASYNC transport if anything at all is sent).
    bad = res["sync call_llm on a loop thread"]
    assert bad["error"] or set(bad["labels"]) != {"secure-sync"}, bad
    assert not any(lbl.startswith("hermes-default") for e in res.values() if isinstance(e, dict) and "labels" in e
                   for lbl in e["labels"])
    print("DUAL_LOOP", res)


def test_c_attributes_hermes_reads_on_the_dual_client(env, monkeypatch):
    res = _run_paths(env, monkeypatch, "dual-frame")
    names = sorted({name for name, _ in res["attr_reads"]})
    print("ATTR_READS", res["attr_reads"])
    # Every read must be one the dual client satisfies (directly or via __getattr__ -> sync OpenAI).
    allowed = {"HERMES_SKIP_TRANSPORT_WRAP", "HERMES_SKIP_ASYNC_WRAP", "api_key", "base_url", "chat", "close",
               "is_closed", "_client", "_custom_headers", "with_options", "models", "__class__",
               "_hermes_aux_effective_provider", "_real_client", "SUPPORTS_HERMES_TOOL_CALLS",
               # MoA-facade probes via hasattr/getattr-with-default (agent/turn_usage.py:54,61,227): the
               # dual client's __getattr__ forwards to openai.OpenAI, which raises AttributeError -> absent.
               "consume_reference_usage", "consume_and_save_trace", "last_aggregator_slot",
               # recovery-ladder reads (only reached when a call fails)
               "_hermes_fallback_destination"}
    assert set(names) <= allowed | {n for n in names if n.startswith("__")}, names


# ── (d) tinfoil 0.14.2 http clients, no attestation, no network ───────────────────────────────

SPIKE_VENV = Path(__file__).resolve().parents[2] / ".venv"

_TINFOIL_PROBE = textwrap.dedent(
    r'''
    import json, socket, sys
    def _no_net(*a, **k):
        raise RuntimeError("NETWORK BLOCKED: " + repr(a[:1]))
    socket.create_connection = _no_net
    socket.getaddrinfo = _no_net
    socket.socket.connect = lambda self, *a, **k: _no_net(*a)
    import httpx, openai
    from importlib.metadata import version
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from tinfoil.client import SecureClient, GroundTruth
    out = {"tinfoil": version("tinfoil"), "openai": openai.__version__}
    hpke = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    stub = GroundTruth(public_key="ab" * 32, digest="d" * 64, measurement="m", hpke_public_key=hpke)
    for mode in ("ehbp", "tls"):
        sc = SecureClient(enclave="enclave.spike.invalid", transport=mode, user_cache_secret="spike-secret")
        out[mode + ".construct"] = "ok (no network)"
        # Unstubbed: building the http client runs attestation (verify()) -> blocked network.
        try:
            sc.make_secure_http_client()
            out[mode + ".unstubbed_sync"] = "built WITHOUT verify?!"
        except Exception as e:
            out[mode + ".unstubbed_sync"] = type(e).__name__ + ": " + str(e)[:120]
        calls = []
        sc.verify = lambda: (calls.append(1), stub)[1]
        sync_http = sc.make_secure_http_client()
        async_http = sc.make_secure_async_http_client()
        out[mode + ".sync_type"] = type(sync_http).__module__ + "." + type(sync_http).__qualname__
        out[mode + ".async_type"] = type(async_http).__module__ + "." + type(async_http).__qualname__
        out[mode + ".verify_calls"] = len(calls)
        o = openai.OpenAI(api_key="k", base_url="https://enclave.spike.invalid/v1", http_client=sync_http)
        a = openai.AsyncOpenAI(api_key="k", base_url="https://enclave.spike.invalid/v1", http_client=async_http)
        out[mode + ".openai_accepts"] = o._client is sync_http and a._client is async_http
        out[mode + ".transport_chain"] = type(sync_http._transport).__name__
    print(json.dumps(out))
    '''
)


def test_d_tinfoil_0142_http_clients_are_openai_compatible_and_require_attestation():
    import json
    import subprocess
    if not (SPIKE_VENV / "bin" / "python").exists():
        pytest.skip("spike environment not built")
    done = subprocess.run([str(SPIKE_VENV / "bin" / "python"), "-I", "-c", _TINFOIL_PROBE],
                          capture_output=True, text=True, timeout=120, cwd=str(SPIKE_VENV))
    assert done.returncode == 0, done.stderr[-2000:]
    out = json.loads(done.stdout.strip().splitlines()[-1])
    print("TINFOIL_D", out)
    assert out["tinfoil"] == "0.14.2" and out["openai"] == "2.54.0"
    for mode in ("ehbp", "tls"):
        assert out[mode + ".construct"].startswith("ok")
        # Construction of the http client ALWAYS attests (here: hits the network block).
        assert "NETWORK BLOCKED" in out[mode + ".unstubbed_sync"], out[mode + ".unstubbed_sync"]
        assert out[mode + ".sync_type"] == "httpx.Client"
        assert out[mode + ".async_type"] == "httpx.AsyncClient"
        assert out[mode + ".openai_accepts"] is True
        assert out[mode + ".verify_calls"] == 2  # one attestation per http client built

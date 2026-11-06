"""C0 spike: does a plugin-registered ProviderProfile.create_client() own every client Hermes builds?

Spike only. Each test answers one sub-question of the C0 client spike against the pinned Hermes
checkout (~/hermes-agent @ 84a0301). No feature code: the plugin under test is a throwaway written
into a temp HERMES_HOME by the fixtures below.

Hermes' .venv has no pytest (dev group is not a default group, pyproject [tool.uv] default-groups = []),
so run it with an ephemeral overlay that leaves ~/hermes-agent/.venv untouched:
    cd ~/hermes-agent && HERMES_HOME=$(mktemp -d) uv run --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \
        pytest <worktree>/tests/spikes -q -p no:cacheprovider
"""
from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

PROFILE_NAME = "spike-tinfoil"
KEY_ENV = "SPIKE_TINFOIL_API_KEY"
BASE_URL = "https://spike-tinfoil.invalid/v1"

# The throwaway plugin: a kind: standalone plugin whose register(ctx) calls
# providers.register_provider() with a ProviderProfile subclass overriding create_client().
PLUGIN_SOURCE = textwrap.dedent(
    '''
    import time
    import providers
    from providers.base import ProviderProfile

    CALLS = []  # every create_client / extras / chat.completions.create call, in order


    class _Completions:
        def __init__(self, owner):
            self._owner = owner

        def create(self, **kwargs):
            CALLS.append(("chat.completions.create", self._owner.client_id, kwargs))
            from openai.types.chat import ChatCompletion
            from openai.types.chat.chat_completion import Choice
            from openai.types.chat.chat_completion_message import ChatCompletionMessage
            from openai.types.completion_usage import CompletionUsage
            msg = ChatCompletionMessage(role="assistant", content="SPIKE-FAKE-REPLY")
            if kwargs.get("stream"):
                return _stream(kwargs.get("model") or "m")
            return ChatCompletion(
                id="spike-1", object="chat.completion", created=int(time.time()),
                model=kwargs.get("model") or "m",
                choices=[Choice(index=0, finish_reason="stop", message=msg)],
                usage=CompletionUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            )


    def _stream(model):
        from openai.types.chat import ChatCompletionChunk
        from openai.types.chat.chat_completion_chunk import Choice, ChoiceDelta
        yield ChatCompletionChunk(id="spike-1", object="chat.completion.chunk", created=int(time.time()),
                                  model=model, choices=[Choice(index=0, delta=ChoiceDelta(role="assistant",
                                  content="SPIKE-FAKE-REPLY"), finish_reason=None)])
        yield ChatCompletionChunk(id="spike-1", object="chat.completion.chunk", created=int(time.time()),
                                  model=model, choices=[Choice(index=0, delta=ChoiceDelta(), finish_reason="stop")])


    class _Chat:
        def __init__(self, owner):
            self.completions = _Completions(owner)


    class RecordingClient:
        """Fake OpenAI-compatible client. Records construction kwargs and every request."""
        _n = 0

        def __init__(self, **kwargs):
            RecordingClient._n += 1
            self.client_id = RecordingClient._n
            self.kwargs = kwargs
            self.api_key = kwargs.get("api_key", "")
            self.base_url = kwargs.get("base_url", "")
            self.chat = _Chat(self)

        def close(self):
            CALLS.append(("close", self.client_id, {}))


    class FlaggedRecordingClient(RecordingClient):
        """Same fake, declaring the auxiliary opt-out flags (what agent/acp_client.py:280-281 declares)."""
        HERMES_SKIP_TRANSPORT_WRAP = True
        HERMES_SKIP_ASYNC_WRAP = True


    class SpikeProfile(ProviderProfile):
        def create_client(self, **client_kwargs):
            import os
            CALLS.append(("create_client", None, dict(client_kwargs)))
            mode = os.environ.get("SPIKE_CREATE_MODE", "")
            if mode == "raise":
                raise RuntimeError("attestation failed (simulated)")
            if mode == "none":
                return None
            cls = FlaggedRecordingClient if os.environ.get("SPIKE_CLIENT_FLAGS") == "1" else RecordingClient
            return cls(**client_kwargs)

        def build_client_kwargs_extras(self, **context):
            CALLS.append(("build_client_kwargs_extras", None, dict(context)))
            return {"default_query": {"spike_extra_marker": "1"}}  # a real OpenAI() kwarg


    def register(ctx):
        import os
        from pathlib import Path
        Path(os.environ["HERMES_HOME"], "spike-register-pid").write_text(str(os.getpid()))
        providers.register_provider(SpikeProfile(
            name="spike-tinfoil",
            display_name="Spike Tinfoil",
            auth_type="api_key",
            env_vars=("SPIKE_TINFOIL_API_KEY",),
            base_url="https://spike-tinfoil.invalid/v1",
            default_aux_model="spike-aux-model",
        ))
    '''
)

# Credential env vars that would let the auxiliary auto-router reach a real provider.
_SCRUB_ENV = (
    "OPENROUTER_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "NOUS_API_KEY",
    "DEEPINFRA_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XAI_API_KEY", "HERMES_INFERENCE_PROVIDER",
    "HERMES_MODEL", "HERMES_PLUGIN_HOST_PROCESS",
)


def _write_config(home: Path, extra: dict) -> None:
    import hermes_yaml as yaml
    cfg = {"plugins": {"enabled": ["spike-confidential"]},
           "model": {"provider": PROFILE_NAME, "default": "spike-main-model", "base_url": BASE_URL}}
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    (home / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")


@pytest.fixture
def hermes_env(tmp_path, monkeypatch):
    """Fresh HERMES_HOME + clean provider/auth/plugin/aux-cache state; restores everything after."""
    import providers as _providers
    import hermes_cli.auth as _auth
    import hermes_cli.plugins as _plugins
    from agent import auxiliary_client as _aux

    home = tmp_path / ".hermes"
    (home / "plugins").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    for var in _SCRUB_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(KEY_ENV, "spike-key")

    _providers._discover_providers()
    monkeypatch.setattr(_providers, "_REGISTRY", dict(_providers._REGISTRY))
    monkeypatch.setattr(_providers, "_ALIASES", dict(_providers._ALIASES))
    monkeypatch.setattr(_providers, "_SOURCES", dict(_providers._SOURCES))
    monkeypatch.setattr(_providers, "_PROVIDER_LIST_CACHE", None)
    monkeypatch.setattr(_auth, "PROVIDER_REGISTRY", type(_auth.PROVIDER_REGISTRY)(_auth.PROVIDER_REGISTRY)
                        if not isinstance(_auth.PROVIDER_REGISTRY, dict) else dict(_auth.PROVIDER_REGISTRY))
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()

    state = {"home": home}

    def install(config_extra: dict | None = None):
        plugin_dir = home / "plugins" / "spike-confidential"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        (plugin_dir / "plugin.yaml").write_text(
            "name: spike-confidential\nversion: 0.0.1\nkind: standalone\n", encoding="utf-8")
        (plugin_dir / "__init__.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        _write_config(home, config_extra or {})
        _plugins.discover_plugins(force=True)
        manager = _plugins.get_plugin_manager()
        profile = _providers.get_provider_profile(PROFILE_NAME)
        calls = sys.modules[type(profile).__module__].CALLS if profile is not None else None
        state.update(manager=manager, profile=profile, calls=calls)
        return state

    state["install"] = install
    yield state
    _plugins._reset_plugin_managers_for_tests()
    _aux._client_cache.clear()


def _calls(state, kind):
    return [c for c in state["calls"] if c[0] == kind]


# ── (a) main agent client ──────────────────────────────────────────────────────────────────────


def test_a_main_agent_client_comes_from_plugin_create_client(hermes_env):
    state = hermes_env["install"]()
    assert state["profile"] is not None, "plugin register(ctx) -> providers.register_provider did not register"
    loaded = state["manager"]._plugins.get("spike-confidential")
    assert loaded is not None and loaded.enabled, getattr(loaded, "error", None)

    from run_agent import AIAgent
    agent = AIAgent(model="spike-main-model", provider=PROFILE_NAME, api_key="spike-key", base_url=BASE_URL,
                    quiet_mode=True, skip_context_files=True, skip_memory=True)
    assert type(agent.client).__name__ == "RecordingClient"
    built = _calls(state, "create_client")
    assert built and built[0][2]["api_key"] == "spike-key"
    assert built[0][2]["base_url"].startswith(BASE_URL)

    # A full turn goes through the fake: the provider wire call lands in RecordingClient.
    result = agent.run_conversation("hello")
    sent = _calls(state, "chat.completions.create")
    assert sent, "turn did not reach the plugin-supplied client"
    assert "SPIKE-FAKE-REPLY" in str(result.get("final_response"))
    # The turn used a fresh request-scoped client (agent/client_lifecycle.py:464), also from create_client.
    assert sent[-1][1] == len(_calls(state, "create_client")) > 1 and sent[-1][2].get("stream") is True
    # Extras from build_client_kwargs_extras ARE merged into the main create_client kwargs
    # (agent/agent_runtime_helpers.py:1958-1966 runs before _provider_supplied_client at :1992).
    assert built[0][2].get("default_query") == {"spike_extra_marker": "1"}
    assert _calls(state, "build_client_kwargs_extras")


def test_a_main_agent_fails_open_to_plain_openai_when_create_client_raises_or_returns_none(hermes_env, monkeypatch):
    """Surprise check: a create_client failure is NOT fatal. Hermes builds a standard openai.OpenAI
    against the same base_url (agent/agent_runtime_helpers.py:1871-1876, 1998 fall-through)."""
    from openai import OpenAI
    from run_agent import AIAgent
    hermes_env["install"]()
    for mode in ("raise", "none"):
        monkeypatch.setenv("SPIKE_CREATE_MODE", mode)
        agent = AIAgent(model="spike-main-model", provider=PROFILE_NAME, api_key="spike-key", base_url=BASE_URL,
                        quiet_mode=True, skip_context_files=True, skip_memory=True)
        assert isinstance(agent.client, OpenAI), mode
        assert str(agent.client.base_url).startswith(BASE_URL), mode


# ── (b) auxiliary clients ──────────────────────────────────────────────────────────────────────

_MSG = [{"role": "user", "content": "summarize: hi"}]


def _main_runtime():
    return {"provider": PROFILE_NAME, "model": "spike-main-model", "base_url": BASE_URL,
            "api_key": "spike-key", "api_mode": "chat_completions"}


def test_b_auxiliary_explicit_text_and_vision_use_create_client(hermes_env, monkeypatch):
    state = hermes_env["install"]({"auxiliary": {
        "compression": {"provider": PROFILE_NAME, "model": "spike-aux-model"},
        "title_generation": {"provider": PROFILE_NAME, "model": "spike-aux-model"},
        "vision": {"provider": PROFILE_NAME, "model": "spike-vision-model"},
    }})
    from agent import auxiliary_client as aux

    # Text, resolver level: auxiliary.<task>.provider = profile -> api_key branch -> create_client.
    for task in ("compression", "title_generation"):
        client, model = aux.get_text_auxiliary_client(task)
        assert type(client).__name__ == "RecordingClient", task
        assert model == "spike-aux-model"
    # Text, full call path: call_llm reaches the fake's chat.completions.create.
    before = len(_calls(state, "chat.completions.create"))
    resp = aux.call_llm(task="compression", messages=_MSG)
    sent = _calls(state, "chat.completions.create")[before:]
    assert sent and sent[-1][2]["model"] == "spike-aux-model"
    assert resp.choices[0].message.content == "SPIKE-FAKE-REPLY"
    # The aux create_client receives ONLY api_key + base_url (agent/auxiliary_client.py:5202).
    aux_kwargs = _calls(state, "create_client")[-1][2]
    assert set(aux_kwargs) == {"api_key", "base_url"}

    # Vision, sync resolver: explicit provider -> _get_cached_client -> resolve_provider_client -> create_client.
    provider, client, model = aux.resolve_vision_provider_client()
    assert provider == PROFILE_NAME and type(client).__name__ == "RecordingClient"
    assert model == "spike-vision-model"

    # Vision, async resolver (what tools/vision_tools.py:825 async_call_llm uses): WITHOUT the
    # HERMES_SKIP_ASYNC_WRAP flag, _to_async_client (agent/auxiliary_client.py:4604-4652) discards
    # the plugin client and builds a fresh openai.AsyncOpenAI from its base_url/api_key.
    from openai import AsyncOpenAI
    aux._client_cache.clear()
    provider, aclient, _ = aux.resolve_vision_provider_client(async_mode=True)
    assert isinstance(aclient, AsyncOpenAI), "async vision kept the plugin client without the skip flag?"
    assert str(aclient.base_url).startswith(BASE_URL)
    # WITH the flag the plugin's object itself is handed to async callers.
    monkeypatch.setenv("SPIKE_CLIENT_FLAGS", "1")
    aux._client_cache.clear()
    provider, aclient, _ = aux.resolve_vision_provider_client(async_mode=True)
    assert type(aclient).__name__ == "FlaggedRecordingClient"
    # ...and async_call_llm then awaits client.chat.completions.create(), so a sync-only create fails:
    import asyncio
    aux._client_cache.clear()
    before = len(_calls(state, "chat.completions.create"))
    with pytest.raises(Exception) as excinfo:
        asyncio.run(aux.async_call_llm(task="vision", messages=_MSG))
    assert len(_calls(state, "chat.completions.create")) > before  # it DID reach the plugin client
    assert "can't be awaited" in str(excinfo.value)


def test_b_auxiliary_auto_with_profile_as_main_provider(hermes_env, monkeypatch):
    state = hermes_env["install"]()  # auxiliary.* left at defaults ("auto")
    from agent import auxiliary_client as aux

    # Text auto: step 1 routes to the main provider -> create_client (agent/auxiliary_client.py:4568-4590).
    client, _ = aux.get_text_auxiliary_client("compression", main_runtime=_main_runtime())
    assert type(client).__name__ == "RecordingClient"
    # Vision auto: _vision_auto_route tries the main provider first (5541-5556) -> create_client.
    provider, client, _ = aux.resolve_vision_provider_client(main_runtime=_main_runtime())
    assert provider == PROFILE_NAME and type(client).__name__ == "RecordingClient"
    # Same with no live runtime recorded (reads model.provider from config.yaml).
    aux._client_cache.clear()
    provider, client, _ = aux.resolve_vision_provider_client()
    assert provider == PROFILE_NAME and type(client).__name__ == "RecordingClient"

    # Finding 5: when the main provider yields no client, vision auto WALKS to openrouter/nous/deepinfra
    # (5558-5564) with no _discovery_chain_allowed gate; text auto refuses (4597-4598, 4529-4541).
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-spike-not-real")
    for mode in ("none",):
        monkeypatch.setenv("SPIKE_CREATE_MODE", mode)
        aux._client_cache.clear()
        rt = dict(_main_runtime())
        provider, client, _ = aux.resolve_vision_provider_client(main_runtime=rt)
        # create_client returning None -> standard OpenAI to the profile base_url (not a walk).
        assert provider == PROFILE_NAME and str(client.base_url).startswith(BASE_URL)
    monkeypatch.delenv("SPIKE_CREATE_MODE")
    monkeypatch.delenv(KEY_ENV)  # profile has no credential -> api_key branch returns (None, None)
    aux._client_cache.clear()
    provider, client, _ = aux.resolve_vision_provider_client()
    assert provider == "openrouter", (provider, client)
    assert "openrouter.ai" in str(client.base_url)
    aux._client_cache.clear()
    client, _ = aux.get_text_auxiliary_client("compression")
    assert client is None  # text auto does not walk


# ── (c) build_client_kwargs_extras is main-only ───────────────────────────────────────────────


def test_c_build_client_kwargs_extras_not_consulted_by_auxiliary_builds(hermes_env):
    state = hermes_env["install"]({"auxiliary": {
        "compression": {"provider": PROFILE_NAME, "model": "spike-aux-model"},
        "vision": {"provider": PROFILE_NAME, "model": "spike-vision-model"},
    }})
    from agent import auxiliary_client as aux
    aux.get_text_auxiliary_client("compression")
    aux.resolve_vision_provider_client()
    aux.resolve_vision_provider_client(main_runtime=_main_runtime())
    aux.get_text_auxiliary_client("title_generation", main_runtime=_main_runtime())
    assert len(_calls(state, "create_client")) >= 3
    assert _calls(state, "build_client_kwargs_extras") == []
    assert all("default_query" not in c[2] for c in _calls(state, "create_client"))
    # Source-level: the auxiliary module never names the hook.
    import inspect
    assert "build_client_kwargs_extras" not in inspect.getsource(aux)

    # Control: the main client build does consult it.
    from run_agent import AIAgent
    AIAgent(model="spike-main-model", provider=PROFILE_NAME, api_key="spike-key", base_url=BASE_URL,
            quiet_mode=True, skip_context_files=True, skip_memory=True)
    assert _calls(state, "build_client_kwargs_extras")


# ── (d) plugins.isolation ─────────────────────────────────────────────────────────────────────


def test_d_in_process_isolation_allows_plugin_provider_and_audit_flags_it(hermes_env):
    from hermes_cli.plugin_isolation import ISOLATION_IN_PROCESS, isolation_mode
    from hermes_cli.plugin_isolation_audit import VERDICT_IN_PROCESS, audit_plugin_dir
    import providers

    state = hermes_env["install"]()  # config has no plugins.isolation -> default
    assert isolation_mode() == ISOLATION_IN_PROCESS
    assert state["profile"] is not None
    assert int((hermes_env["home"] / "spike-register-pid").read_text()) == os.getpid()
    # Registered from register(ctx) with no home layer in scope -> process-global _REGISTRY, source "runtime".
    assert providers.provider_source(PROFILE_NAME) == "runtime"
    assert PROFILE_NAME in providers._REGISTRY
    # The auth mirror picked it up (needed by aux _resolve_api_key_branch).
    from hermes_cli.auth import PROVIDER_REGISTRY
    assert PROVIDER_REGISTRY[PROFILE_NAME].auth_type == "api_key"

    # Static audit: a standalone plugin calling providers.register_provider is in-process only.
    report = audit_plugin_dir(hermes_env["home"] / "plugins" / "spike-confidential")
    assert report.verdict == VERDICT_IN_PROCESS
    assert any("providers.register_provider" in r for r in report.reasons), report.reasons
    # The same source declared kind: model-provider is flagged for create_client instead.
    report_mp = audit_plugin_dir(hermes_env["home"] / "plugins" / "spike-confidential",
                                 manifest={"name": "spike-confidential", "kind": "model-provider"})
    assert report_mp.verdict == VERDICT_IN_PROCESS
    assert any("create_client" in r for r in report_mp.reasons), report_mp.reasons


def test_d_host_isolation_standalone_plugin_provider_never_reaches_hermes(hermes_env):
    """plugins.isolation: host runs a non-bundled standalone plugin's register(ctx) in the plugin-host
    child (hermes_cli/plugins_loader.py:591-597, 672-675). Its providers.register_provider() call lands in
    the CHILD's registry, so the Hermes process never sees the profile and create_client is unreachable."""
    import hermes_cli.plugins as _plugins
    import providers
    try:
        state = hermes_env["install"]({"plugins": {"isolation": "host"}})
        from hermes_cli.plugin_isolation import ISOLATION_HOST, isolation_mode
        assert isolation_mode() == ISOLATION_HOST
        loaded = state["manager"]._plugins.get("spike-confidential")
        assert loaded.enabled and loaded.error is None
        # register(ctx) really ran, in another process.
        pid = int((hermes_env["home"] / "spike-register-pid").read_text())
        assert pid != os.getpid()
        assert providers.get_provider_profile(PROFILE_NAME) is None
    finally:
        host = getattr(_plugins.get_plugin_manager(), "_plugin_host_instance", None)
        if host is not None:
            host.shutdown()


# ── (e) tinfoil vs Hermes' openai pin ─────────────────────────────────────────────────────────
#
# Runs against the SEPARATE spike environment (<worktree>/.venv, built with
# `UV_PROJECT_ENVIRONMENT=<worktree>/.venv uv sync` from Hermes' lock, then
# `uv pip install --python <worktree>/.venv/bin/python -c <hermes constraints> tinfoil==0.14.2` and
# `uv pip install --python ... --no-deps --target <worktree>/.venv/tinfoil-0.15.0-target tinfoil==0.15.0`).
# Never touches ~/hermes-agent/.venv. Nothing here instantiates a Tinfoil client (no network).

SPIKE_VENV = Path(__file__).resolve().parents[2] / ".venv"
TINFOIL_015_TARGET = SPIKE_VENV / "tinfoil-0.15.0-target"

_PROBE = textwrap.dedent(
    '''
    import importlib, importlib.util, json, sys, types
    if len(sys.argv) > 1:
        sys.path.insert(0, sys.argv[1])
    import openai
    out = {"openai": openai.__version__}
    def purge():
        for m in [k for k in sys.modules if k == "tinfoil" or k.startswith("tinfoil.")]:
            sys.modules.pop(m)
    for label, mod in (("import tinfoil", "tinfoil"), ("import tinfoil.client", "tinfoil.client")):
        purge()
        try:
            importlib.import_module(mod); out[label] = "ok"
        except Exception as e:
            out[label] = f"{type(e).__name__}: {e}"
    purge()
    spec = importlib.util.find_spec("tinfoil")
    out["tinfoil_path"] = list(spec.submodule_search_locations)[0]
    pkg = types.ModuleType("tinfoil"); pkg.__path__ = list(spec.submodule_search_locations)
    sys.modules["tinfoil"] = pkg  # bare package: tinfoil/__init__.py never executes
    try:
        client = importlib.import_module("tinfoil.client")
        sc = client.SecureClient
        out["bypass"] = "ok"
        out["methods"] = sorted(n for n in ("make_secure_http_client", "make_secure_async_http_client",
                                            "get_verification_document") if callable(getattr(sc, n, None)))
    except Exception as e:
        out["bypass"] = f"{type(e).__name__}: {e}"
    print(json.dumps(out))
    '''
)


def _probe(extra_path: str | None = None) -> dict:
    import json
    import subprocess
    argv = [str(SPIKE_VENV / "bin" / "python"), "-I", "-c", _PROBE] + ([extra_path] if extra_path else [])
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=str(SPIKE_VENV))
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_e_tinfoil_version_compatibility_with_hermes_openai_pin():
    import importlib.util
    import re
    hermes_root = Path(os.environ.get("HERMES_AGENT_ROOT", Path.home() / "hermes-agent"))
    lock = (hermes_root / "uv.lock").read_text(encoding="utf-8")
    m = re.search(r'\[\[package\]\]\nname = "openai"\nversion = "([^"]+)"', lock)
    assert m and m.group(1) == "2.54.0"
    # Hermes' own interpreter has no openai.resources.decisions (added in openai 3.26.0).
    assert importlib.util.find_spec("openai.resources.decisions") is None

    if not (SPIKE_VENV / "bin" / "python").exists():
        pytest.skip("spike environment not built (see comment above)")

    # tinfoil 0.14.2 (requires openai>=1.63.0): imports cleanly on openai 2.54.0 and has the API.
    r014 = _probe()
    assert r014["openai"] == "2.54.0"
    assert "/.venv/lib/" in r014["tinfoil_path"]
    assert r014["import tinfoil"] == "ok" and r014["import tinfoil.client"] == "ok"
    assert r014["methods"] == ["get_verification_document", "make_secure_async_http_client",
                               "make_secure_http_client"]

    # tinfoil 0.15.0 (requires openai>=3.26.0): top-level import fails on 2.54.0, and so does
    # `import tinfoil.client` (the package __init__ runs first). Only a bare-package bypass loads
    # tinfoil.client, which itself never imports openai.
    if not TINFOIL_015_TARGET.exists():
        pytest.skip("tinfoil 0.15.0 target not installed")
    r015 = _probe(str(TINFOIL_015_TARGET))
    assert r015["openai"] == "2.54.0"
    assert r015["tinfoil_path"].startswith(str(TINFOIL_015_TARGET))
    assert "openai.resources.decisions" in r015["import tinfoil"]
    assert "openai.resources.decisions" in r015["import tinfoil.client"]
    assert r015["bypass"] == "ok"
    assert r015["methods"] == r014["methods"]

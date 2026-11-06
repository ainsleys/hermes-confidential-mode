"""Fakes and glue for the end-to-end demo scenario (W6).

Fakes sit only at the network, SDK and human boundaries:
  * ``MockNet``: one httpx.MockTransport for every host. ``Router`` is an OpenAI-compatible endpoint
    (chat completions, streaming or not) that can be told to answer 5xx; the "openrouter" router is a
    plain recorder. Hermes' own keepalive httpx builder is patched to it, so the real openai client
    Hermes builds for a ``custom`` provider sends real HTTP requests into the mock.
  * ``FakeVendorAdapter``: the VendorAdapter protocol (verify -> VerificationResult, counts
    attestations) with its verified pool on the same MockNet.
  * ``FakeCtx``: ``ask_choice`` scripted.

``Plugin`` is SCENARIO GLUE, standing in for W5's register(ctx) and /confidential commands, which are
being written concurrently: it calls the real builders (build_middleware, build_pre_tool_call,
build_tool_execution, build_post_approval_response, run_preflight, PinStore, provider.make_profile,
consent.approve_pending_pin) the way the seam tests do, and writes the ledger rows that no merged
module writes yet (seal, unseal, preflight_fail, verify_ok, verify_fail, pin_staged). Those rows are
what W5/W2 are expected to write; see the W6 report.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from confidential_mode import preflight as pf
from confidential_mode import provider as provider_mod
from confidential_mode.gate_llm import build_middleware
from confidential_mode.gate_tools import (
    ApprovalDecisions, build_allowlist, build_post_approval_response, build_pre_tool_call, build_tool_execution,
    format_allowlist,
)
from confidential_mode.ledger import Ledger
from confidential_mode.pins import PinStore
from confidential_mode.state import ConfidentialState, InMemoryState
from confidential_mode.tiers import AttestedPredicate, LocalPredicate, Tier
from confidential_mode.verify.base import VerificationResult, VerifyError

LOCAL_HOST = "127.0.0.1"
LOCAL_URL = f"http://{LOCAL_HOST}:11434/v1"
LOCAL_MODEL = "qwen3:8b"
ENCLAVE = "router.tinfoil.invalid"
ENCLAVE_URL = f"https://{ENCLAVE}/v1"
ATTESTED_MODEL = "tf-main-model"
OPENROUTER_HOST = "openrouter.ai"
OPENROUTER_URL = f"https://{OPENROUTER_HOST}/api/v1"
REPO = "tinfoilsh/confidential-model-router"
PROFILE = provider_mod.PROFILE_NAME
REPLY = "DEMO-PROVIDER-REPLY"


# ── network ─────────────────────────────────────────────────────────────────────────────────────

def _completion(model: str, text: str) -> dict:
    return {"id": "demo-1", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _sse(model: str, text: str) -> bytes:
    base = {"id": "demo-1", "object": "chat.completion.chunk", "created": int(time.time()), "model": model}
    chunks = [dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]),
              dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])]
    return b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"


@dataclass
class Router:
    """OpenAI-compatible endpoint. ``fail_status`` makes every request answer that HTTP status."""
    name: str
    text: str = REPLY
    fail_status: int | None = None
    requests: list = field(default_factory=list)   # (method, host, path, model, stream)

    def handle(self, request: httpx.Request) -> httpx.Response:
        try:
            body = json.loads(request.content or b"{}")
        except Exception:
            body = {}
        self.requests.append((request.method, request.url.host, request.url.path, body.get("model"),
                              bool(body.get("stream"))))
        if self.fail_status is not None:
            return httpx.Response(self.fail_status, json={"error": {"message": f"{self.name} forced failure",
                                                                    "type": "server_error"}})
        model = body.get("model") or "m"
        if body.get("stream"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=_sse(model, self.text))
        return httpx.Response(200, json=_completion(model, self.text))


class MockNet:
    """Every host the scenario can reach. An unknown host is recorded and answered 599."""

    def __init__(self):
        self.local = Router("local-router")
        self.enclave = Router("enclave-router", text="ATTESTED-" + REPLY)
        self.openrouter = Router("openrouter")
        self.routes = {LOCAL_HOST: self.local, ENCLAVE: self.enclave, OPENROUTER_HOST: self.openrouter}
        self.unknown: list = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        router = self.routes.get(request.url.host)
        if router is None:
            self.unknown.append(str(request.url))
            return httpx.Response(599)
        return router.handle(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def sync_client(self) -> httpx.Client:
        return httpx.Client(transport=self.transport(), follow_redirects=False)

    def async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport(), follow_redirects=False)


def patch_hermes_http(monkeypatch, net: MockNet) -> None:
    """Hermes' own keepalive httpx builder (agent/process_bootstrap.py) -> the MockNet."""
    import agent.process_bootstrap as bootstrap

    def fake_keepalive(base_url="", *, async_mode=False, verify=True):
        return net.async_client() if async_mode else net.sync_client()
    monkeypatch.setattr(bootstrap, "build_keepalive_http_client", fake_keepalive)


# ── vendor adapter ──────────────────────────────────────────────────────────────────────────────

class FakeVendorAdapter:
    """VendorAdapter over the MockNet. ``code``/``enclave`` are the build the enclave presents now."""
    vendor = "tinfoil"

    def __init__(self, net: MockNet, *, code: str = "c0de1" * 8, enclave: str = "e1c1" * 8, release: str = "v1.0.0"):
        self.net = net
        self.code, self.enclave, self.release = code, enclave, release
        self.fail: str | None = None
        self.attestation_count = 0
        self.held: str | None = None

    enclave_host = ENCLAVE
    base_url = ENCLAVE_URL

    def verify(self) -> VerificationResult:
        self.attestation_count += 1
        if self.fail:
            raise VerifyError(self.fail)
        return VerificationResult(
            vendor=self.vendor, router_repo=REPO, enclave_host=ENCLAVE, code_fingerprint=self.code,
            enclave_fingerprint=self.enclave, release_tag=self.release, verifier="fake-tinfoil/0.14.2",
            verified_at_local=time.time(),
            evidence={"format": "fake-attestation", "enclaveHost": ENCLAVE, "codeFingerprint": self.code,
                      "enclaveFingerprint": self.enclave, "releaseTag": self.release,
                      "attestationNumber": self.attestation_count})

    def hold(self, reason: str) -> None:
        self.held = reason

    def release(self) -> None:
        self.held = None

    def sync_http_view(self) -> httpx.Client:
        return self.net.sync_client()

    def async_http_for_loop(self) -> httpx.AsyncClient:
        return self.net.async_client()


# ── human surface ───────────────────────────────────────────────────────────────────────────────

class FakeCtx:
    """The slice of PluginContext consent uses: ask_choice, scripted answers in order."""

    def __init__(self, *answers: Any):
        self.answers = list(answers)
        self.questions: list[tuple[str, list]] = []

    def ask_choice(self, question, choices):
        self.questions.append((question, choices))
        return self.answers.pop(0) if self.answers else None


# ── config dicts ────────────────────────────────────────────────────────────────────────────────

def local_config(*, leftover_fallback: bool) -> dict:
    cfg = {"model": {"provider": "custom", "default": LOCAL_MODEL, "base_url": LOCAL_URL},
           "fallback_providers": [],
           "auxiliary": {"vision": {"provider": "custom", "base_url": LOCAL_URL, "model": "llava"}},
           "memory": {"provider": ""}}
    if leftover_fallback:
        cfg["fallback_providers"] = [{"provider": "openrouter", "model": "anthropic/claude-sonnet-4.5"}]
    return cfg


def attested_config() -> dict:
    return {"model": {"provider": PROFILE, "default": ATTESTED_MODEL, "base_url": ENCLAVE_URL},
            "fallback_providers": [],
            "auxiliary": {"vision": {"provider": PROFILE, "model": "tf-vision-model"}},
            "memory": {"provider": ""},
            "confidential": {"tinfoil": {"enclave": ENCLAVE}, "verify_ttl_seconds": 300}}


# ── glue (stands in for W5's register(ctx) + commands) ──────────────────────────────────────────

class Plugin:
    def __init__(self, tmp_path: Path, manager, net: MockNet):
        from hermes_cli.plugins import PluginContext
        from hermes_cli.plugins_manifest import PluginManifest
        self.ledger = Ledger(tmp_path / "ledger.sqlite")
        self.state = ConfidentialState(InMemoryState())
        self.pins = PinStore(tmp_path / "pins.yaml")
        self.net = net
        self.adapter = FakeVendorAdapter(net)
        self.ctx = PluginContext(PluginManifest(name="confidential-mode", source="user"), manager)
        self.decisions = ApprovalDecisions()
        self.allowlist = None
        self.profile = None
        self.local_predicate = LocalPredicate(profile_base_url=pf.profile_base_url)
        self.attested_predicate = AttestedPredicate([PROFILE], self.attested_ok, pf.profile_base_url)
        self.handles = []

    # verification rows: provider.py does not ledger them (see report), so the glue observes the cache.
    def attested_ok(self, provider: str):
        cache = provider_mod.verification_cache
        entry = cache.entry(provider)
        before = entry.result if entry else None
        before_err = entry.failed_mono if entry else None
        before_pending = self._pending()
        verdict = provider_mod.attested_ok(provider)
        entry = cache.entry(provider)
        if entry is not None:
            if entry.result is not None and entry.result is not before:
                r = entry.result
                self.ledger.append({"kind": "verify_ok", "provider": provider, "host": r.enclave_host,
                                    "detail": {"vendor": r.vendor, "router_repo": r.router_repo,
                                               "enclave_host": r.enclave_host, "code_fingerprint": r.code_fingerprint,
                                               "enclave_fingerprint": r.enclave_fingerprint,
                                               "release_tag": r.release_tag, "verifier": r.verifier,
                                               "verified_at_local": r.verified_at_local, "evidence": r.evidence}})
            elif entry.result is None and entry.failed_mono is not None and entry.failed_mono != before_err:
                self.ledger.append({"kind": "verify_fail", "provider": provider, "host": ENCLAVE,
                                    "detail": {"vendor": "tinfoil", "error": entry.last_error or ""}})
        pending = self._pending()
        if pending is not None and pending != before_pending:
            self.ledger.append({"kind": "pin_staged", "provider": pending.vendor, "host": pending.enclave_host,
                                "detail": {"vendor": pending.vendor, "code_fingerprint": pending.code_fingerprint,
                                           "enclave_fingerprint": pending.enclave_fingerprint,
                                           "release_tag": pending.release_tag, "previous": pending.previous}})
        return verdict

    def _pending(self):
        try:
            return self.pins.pending()
        except Exception:
            return None

    def predicate_for(self, tier: Tier):
        return {Tier.LOCAL: self.local_predicate, Tier.ATTESTED: self.attested_predicate}[Tier(tier)]

    def register_attested_profile(self, ttl: float = 300.0):
        import providers
        self.profile = provider_mod.make_profile(self.adapter, self.pins, ttl)
        providers.register_provider(self.profile)
        return self.profile

    def register(self):
        """What register(ctx) wires: llm gate + the three tool-gate callbacks, sharing one decisions."""
        sealed = self.state.sealed
        allowlist = lambda: self.allowlist  # noqa: E731  (built at seal)
        self.handles.append(self.ctx.register_middleware("llm_execution", build_middleware(
            ledger=self.ledger, is_sealed=sealed, predicate_for=self.predicate_for, attested_ok=self.attested_ok,
            pin_pending=lambda: self._pending() is not None)))
        self.handles.append(self.ctx.register_hook("pre_tool_call", build_pre_tool_call(
            sealed, allowlist, self.ledger, decisions=self.decisions)))
        self.handles.append(self.ctx.register_hook("post_approval_response", build_post_approval_response(
            sealed, self.ledger, self.decisions)))
        self.handles.append(self.ctx.register_middleware("tool_execution", build_tool_execution(
            sealed, allowlist, self.ledger, self.decisions)))

    def seal(self, tier: Tier, config: dict, *, session_id: str) -> tuple[bool, str]:
        """/confidential on <tier>: preflight, then seal and print the allowlist; or refuse with the report."""
        from tools.registry import registry
        report = pf.run_preflight(Tier(tier), self.predicate_for(tier), config, plugin_aux_tasks=[],
                                  isolation=pf.plugin_isolation(config), provider_lookup=pf.provider_lookup,
                                  attested_profile=PROFILE if Tier(tier) is Tier.ATTESTED else None)
        text = pf.format_report(report)
        if not report.ok:
            self.ledger.append({"kind": "preflight_fail", "session_id": session_id, "purpose": "seal",
                                "tier": Tier(tier).value,
                                "detail": {"reason": "; ".join(f"{i.key} {i.verdict}" for i in report.failures()),
                                           "failed_keys": [i.key for i in report.failures()]}})
            return False, text
        self.allowlist = build_allowlist(registry)
        self.state.seal(Tier(tier), report.fingerprint)
        self.ledger.append({"kind": "seal", "session_id": session_id, "tier": Tier(tier).value,
                            "decision": "sealed", "detail": {"config_fingerprint": report.fingerprint}})
        return True, text + "\n\n" + format_allowlist(self.allowlist)

    def unseal(self, *, session_id: str) -> None:
        self.state.unseal()
        self.ledger.append({"kind": "unseal", "session_id": session_id, "decision": "unsealed"})

    def events(self, since: int = 0) -> list[tuple]:
        return [(e.kind, e.decision) for e in self.ledger.tail(since)]

    def close(self):
        for h in self.handles:
            if h is not None:
                h.dispose()
        self.ledger.close()

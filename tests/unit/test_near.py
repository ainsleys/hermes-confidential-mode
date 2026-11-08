"""NEAR AI Cloud adapter: evidence, appraisal, signed responses (synthetic NEAR, real cryptography).

The synthetic world (tests/near_world.py) signs every response with its own ed25519 keys and every
attestation JWT with its own RSA chain, so each signature check here runs for real; only the TDX quote
is a stand-in (tests/unit/test_near_real_capture.py covers real Intel quotes and tokens).
"""
from __future__ import annotations

import asyncio
import hashlib
import json

import httpx
import openai
import pytest

from confidential_mode import sendctx
from confidential_mode.verify import near, near_checks as nc, replay_near
from confidential_mode.verify.base import VerifyError

from ..near_world import BASE, HOST, MODEL, NOW, NearWorld, pub_hex
from .. import near_world as _near_world

MSG = [{"role": "user", "content": "hi"}]


@pytest.fixture
def world():
    return NearWorld()


def _accepted(world, tmp_path, **kw):
    ad = world.adapter(tmp_path, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    result = ad.verify()
    ad.release()
    return ad, result, rows


def _client(ad):
    return openai.OpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)


# ── verification ─────────────────────────────────────────────────────────────────────────────────

def test_verify_builds_complete_evidence_and_the_pin_identity(world, tmp_path):
    ad, r, _ = _accepted(world, tmp_path)
    ev = r.evidence
    assert ev["schema"] == near.EVIDENCE_SCHEMA and ev["capture_complete"] is True and ev["capture_missing"] == []
    assert r.vendor == "near" and r.router_repo == f"{HOST}#{MODEL}" and r.release_tag is None
    assert r.enclave_host == HOST and r.verified_at_host_clock == NOW
    assert all(v is True for k, v in ev["checks"].items() if k not in near.INFORMATIONAL_CHECKS), ev["checks"]
    assert ev["claims"]["gateway_signer"] == pub_hex(world.gateway_key)
    assert ev["claims"]["model_signers"] == {MODEL: [pub_hex(world.model_key)]}
    assert ev["claims"]["tcb_status"] == "UpToDate" and ev["policy"]["require_provider_tee"] is True
    assert ev["claims"]["components"][0].startswith("gateway compose sha256:")
    # Attestation requests never carry an API key, and the JWKS comes from Intel's pinned URL.
    assert all("authorization" not in h for h in world.chat_request_headers)
    assert any(p == "/certs" for _, p, _ in world.requests)
    json.dumps(ev)  # JSON-serialisable


def test_fingerprints_are_stable_across_verifies_and_change_with_the_compose(world, tmp_path):
    ad = world.adapter(tmp_path)
    a, b = ad.verify(), ad.verify()
    assert (a.code_fingerprint, a.enclave_fingerprint) == (b.code_fingerprint, b.enclave_fingerprint)
    assert a.evidence["nonce"] != b.evidence["nonce"]           # a fresh client nonce each time
    from .. import near_world as w
    old = w.MODEL_COMPOSE
    try:
        w.MODEL_COMPOSE = old.replace("vllm", "vllm2")
        c = ad.verify()
    finally:
        w.MODEL_COMPOSE = old
    assert c.code_fingerprint != a.code_fingerprint and c.enclave_fingerprint == a.enclave_fingerprint


@pytest.mark.parametrize("mutate,needle", [
    (lambda w: w.gateway_overrides.update(request_nonce="00" * 32), "request_nonce"),
    (lambda w: w.gateway_overrides.update(signing_address="ab" * 32), "report_data does not bind"),
    (lambda w: w.model_overrides.update(signing_address="ab" * 32), "report_data does not bind"),
    (lambda w: w.ita_overrides.update(attester_runtime_data={"caller_nonce": "00" * 32,
                                                             "signing_address": "x", "signing_algo": "ed25519"}),
     "client nonce"),
    (lambda w: setattr(w, "tcb", "OutOfDate"), "TCB status"),
    (lambda w: w.ita_overrides.update(tdx_mrtd="99" * 48), "tdx_mrtd differs"),
    (lambda w: w.ita_overrides.update(tdx_is_debuggable=True), "debuggable"),
    (lambda w: setattr(w, "model_candidates", 0), "no model report"),
    (lambda w: setattr(w, "serve_tls", False), "no TLS peer certificate"),
    (lambda w: setattr(w, "tls_fp", "ee" * 32), "TLS certificate this client saw"),
])
def test_verify_fails_closed(world, tmp_path, mutate, needle):
    mutate(world)
    ad = world.adapter(tmp_path)
    with pytest.raises(VerifyError) as ei:
        ad.verify()
    assert needle in str(ei.value)
    assert ad.last_result is None


def test_tls_certificate_other_than_the_bound_one_fails(world, tmp_path):
    from ..near_world import tls_cert
    world.tls_der, _ = tls_cert()          # the gateway binds the old fingerprint, the connection shows a new cert
    with pytest.raises(VerifyError, match="TLS certificate"):
        world.adapter(tmp_path).verify()


def test_gateway_only_is_refused_when_provider_tee_is_required(tmp_path):
    w = NearWorld(models=())
    with pytest.raises(VerifyError, match="no NEAR model is allowlisted"):
        w.adapter(tmp_path).verify()
    r = w.adapter(tmp_path, require_provider_tee=False).verify()
    assert r.router_repo == f"{HOST}#gateway-only"


def test_jwks_from_another_root_is_rejected(world, tmp_path):
    other = NearWorld().ita
    ad = world.adapter(tmp_path, ita_roots=other.roots)
    with pytest.raises(VerifyError, match="unpinned root"):
        ad.verify()


def test_views_hold_until_the_pins_accept_and_refuse_other_hosts(world, tmp_path):
    ad = world.adapter(tmp_path)
    with pytest.raises(VerifyError):
        ad.sync_http_view()
    ad.verify()
    c = _client(ad)
    with pytest.raises(Exception) as ei:
        c.chat.completions.create(model=MODEL, messages=MSG)
    assert "held" in str(ei.value) or "held" in repr(ei.value.__cause__)
    ad.release()
    other = httpx.Client(transport=ad.sync_http_view()._transport)
    with pytest.raises(VerifyError, match="not the attested NEAR host"):
        other.get("https://evil.example/v1/models")
    assert world.chat_posts() == 0


# ── signed responses ─────────────────────────────────────────────────────────────────────────────

def test_unstreamed_send_is_hashed_signed_and_verified_as_provider_tee(world, tmp_path):
    ad, r, rows = _accepted(world, tmp_path)
    with sendctx.send_context(session_id="s-1", purpose="main", tier="attested"):
        out = _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert out.choices[0].message.content == "NEAR-FAKE-REPLY"
    (row,) = rows
    d = row["detail"]
    assert row["kind"] == "send_signed" and row["session_id"] == "s-1" and row["purpose"] == "main"
    assert row["verdict"] == "verified" and row["decision"] == "provider_tee" and d["fully_attested"] is True
    assert d["request_sha256"] == hashlib.sha256(world.chat_bodies[0]).hexdigest()
    assert d["signature"]["text"] == f"{MODEL}:{d['request_sha256']}:{d['response_sha256']}"
    assert d["signature"]["signing_address"] == pub_hex(world.model_key)
    assert d["chat_id"] == out.id and d["attestation_nonce"] == r.evidence["nonce"]
    assert d["tls_matches_attested"] is True
    hdr = world.chat_request_headers[0]
    assert hdr["x-no-aliasing"] == "true" and hdr["accept-encoding"] == "identity"
    # The row replays offline against the evidence.
    rep = replay_near.replay_signed_send(d, r.evidence, model=MODEL, quote_verifier=_near_world.fake_quote_verifier,
                                         ita_roots=world.ita.roots)
    assert rep["verdict"] == "pass" and rep["signature"]["provider_tee_verified"] is True


def test_streamed_send_hashes_every_sse_byte_and_gateway_kind_is_not_fully_attested(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path, encrypt=False)
    stream = _client(ad).chat.completions.create(model=MODEL, messages=MSG, stream=True)
    text = "".join((c.choices[0].delta.content or "") for c in stream if c.choices)
    assert text == "NEAR-FAKE-REPLY"
    (row,) = rows
    d = row["detail"]
    sse = world._sse(MODEL)[1].replace(b"chatcmpl-2", b"chatcmpl-1")
    assert d["response_sha256"] == hashlib.sha256(sse).hexdigest() and d["body_complete"] is True
    assert row["decision"] == "gateway" and row["verdict"] == "unverified" and d["fully_attested"] is False
    assert d["check"]["signature_valid"] is True and "gateway signature only" in d["check"]["reason"]


def test_streamed_gateway_signature_verifies_when_provider_tee_is_not_required(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path, require_provider_tee=False, encrypt=False)
    list(_client(ad).chat.completions.create(model=MODEL, messages=MSG, stream=True))
    assert rows[0]["verdict"] == "verified" and rows[0]["detail"]["fully_attested"] is False


def test_interrupted_stream_has_no_signature_and_says_so(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path, encrypt=False)
    stream = _client(ad).chat.completions.create(model=MODEL, messages=MSG, stream=True)
    next(iter(stream))
    stream.close()                               # the consumer stops before [DONE]
    (row,) = rows
    assert row["decision"] == "missing" and row["verdict"] == "unverified"
    assert "interrupted stream" in row["detail"]["signature"]["reason"]
    assert row["detail"]["response_sha256"] is None and world.signature_fetches() == 0


def test_signature_404_is_retried_within_the_bound_then_reported_missing(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path, signature_wait_seconds=30.0, encrypt=False)
    world.sig_404_left = 2
    _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["verdict"] == "verified" and world.signature_fetches() == 3
    world.sig_mode = "404"
    ad.signature_wait_seconds = 0.0
    _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert rows[1]["decision"] == "missing" and "HTTP 404" in rows[1]["detail"]["signature"]["reason"]


@pytest.mark.parametrize("mode,status", [("unavailable", "unavailable"), ("http500", "error")])
def test_unavailable_or_failed_signature_fetch_is_explicit(world, tmp_path, mode, status):
    ad, _, rows = _accepted(world, tmp_path, encrypt=False)
    world.sig_mode = mode
    _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["detail"]["signature"]["status"] == status and rows[0]["verdict"] == "unverified"


def test_signature_fetch_carries_the_requests_own_api_key(world, tmp_path):
    ad, _, _ = _accepted(world, tmp_path)
    seen = []
    orig = world.handler

    def spy(req):
        if req.url.path.startswith("/v1/signature/"):
            seen.append(req.headers.get("authorization"))
        return orig(req)
    world.handler = spy
    _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert seen == ["Bearer sk-near-test"]


def test_model_off_the_allowlist_is_refused_before_sending(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path)
    with pytest.raises(Exception):
        _client(ad).chat.completions.create(model="anthropic/claude-external", messages=MSG)
    assert world.chat_posts() == 0 and [r["kind"] for r in rows] == ["send_refused"]
    assert rows[0]["model"] == "anthropic/claude-external" and rows[0]["detail"]["stage"] == "before_send"
    assert rows[0]["purpose"] == "unattributed" and "not an attested NEAR model" in rows[0]["detail"]["reason"]


def test_compressed_response_is_hashed_after_decoding(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path)
    world.gzip = True
    _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["verdict"] == "verified" and rows[0]["detail"]["response_content_encoding"] == "gzip"


@pytest.mark.parametrize("gz", [False, True])
def test_a_body_already_in_memory_is_hashed_once(world, tmp_path, gz):
    ad, _, rows = _accepted(world, tmp_path)
    world.preread, world.gzip = True, gz
    out = _client(ad).chat.completions.create(model=MODEL, messages=MSG)
    assert out.choices[0].message.content == "NEAR-FAKE-REPLY"
    assert rows[0]["verdict"] == "verified", rows[0]["detail"]["check"]


def test_async_send_is_signed_and_verified(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path, encrypt=False)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        r1 = await c.chat.completions.create(model=MODEL, messages=MSG)
        s = await c.chat.completions.create(model=MODEL, messages=MSG, stream=True)
        async for _ in s:
            pass
        return r1
    asyncio.run(go())
    assert [r["decision"] for r in rows] == ["provider_tee", "gateway"]
    assert rows[0]["verdict"] == "verified"


class _ClosingPool(httpx.MockTransport):
    """A mock async pool that records the loop it was closed on."""

    def __init__(self, handler):
        super().__init__(handler)
        self.closed_on: list = []

    async def aclose(self) -> None:
        self.closed_on.append(asyncio.get_running_loop())


def _pools(world, ad):
    made: list[_ClosingPool] = []

    def factory():
        made.append(_ClosingPool(lambda r: world.handler(r)))
        return made[-1]
    ad._async_transport_factory = factory
    return made


async def _settle():
    for _ in range(5):
        await asyncio.sleep(0)


def test_a_dropped_async_pool_is_closed_on_its_loop(world, tmp_path):
    """fix-pass-3 item 3: _drop_send_pools used to clear the async pools without closing them, so their
    sockets lingered. Dropped on the loop's own thread, and from another thread while the loop runs."""
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    made = _pools(world, ad)

    async def go():
        loop = asyncio.get_running_loop()
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        await c.chat.completions.create(model=MODEL, messages=MSG)
        ad._drop_send_pools()                                  # on the loop's thread
        await _settle()
        assert made[0].closed_on == [loop]
        await c.chat.completions.create(model=MODEL, messages=MSG)
        assert len(made) == 2                                  # a fresh pool for the next send
        await loop.run_in_executor(None, ad._drop_send_pools)  # from another thread
        await _settle()
        assert made[1].closed_on == [loop]
        assert ad._async_transports == {} and ad._retired_async == [] and ad._inflight == {}
    asyncio.run(go())
    assert ad._async_closing == set()


def test_an_async_pool_dropped_mid_stream_closes_after_its_last_request(world, tmp_path):
    ad, _, rows = _accepted(world, tmp_path, encrypt=False)
    made = _pools(world, ad)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        s = await c.chat.completions.create(model=MODEL, messages=MSG, stream=True)
        ad._drop_send_pools()
        await _settle()
        assert made[0].closed_on == [] and [p for _, p in ad._retired_async] == [made[0]]
        async for _ in s:
            pass
        await _settle()
        assert made[0].closed_on == [asyncio.get_running_loop()]
        assert ad._retired_async == [] and ad._inflight == {}
    asyncio.run(go())
    assert [r["decision"] for r in rows] == ["gateway"]   # the in-flight stream finished its signature step


def test_closing_the_adapter_closes_its_async_pools(world, tmp_path):
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    made = _pools(world, ad)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        await c.chat.completions.create(model=MODEL, messages=MSG)
        ad.close()
        await _settle()
        assert made[0].closed_on == [asyncio.get_running_loop()]
    asyncio.run(go())


def test_a_pool_whose_loop_has_closed_is_dropped_without_error(world, tmp_path):
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    made = _pools(world, ad)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        await c.chat.completions.create(model=MODEL, messages=MSG)
    asyncio.run(go())
    ad._drop_send_pools()                           # its loop is closed: nothing can run there, nothing raises
    assert made[0].closed_on == [] and ad._async_transports == {} and ad._async_closing == set()


class _SocketPool:
    """A stand-in for httpx.AsyncHTTPTransport's shape: an aclose coroutine and httpcore's pool of
    connections, each with a network stream that hands out a real socket."""

    def __init__(self):
        import socket
        self.sock, self.peer = socket.socketpair()
        stream = type("S", (), {"get_extra_info": lambda _s, name: self.sock if name == "socket" else None})()
        conn = type("C", (), {})()
        conn._connection = type("H", (), {})()
        conn._connection._network_stream = stream
        self._pool = type("P", (), {})()
        self._pool._connections = [conn]
        self.closed_on: list = []

    async def aclose(self) -> None:
        self.closed_on.append(asyncio.get_running_loop())

    def close_peer(self):
        self.peer.close()


def test_a_close_scheduled_onto_a_stopped_loop_that_then_closes_leaves_no_coroutine(world, tmp_path, recwarn):
    """fix-pass-3 review finding 3: a pool whose loop is stopped (not running) when it is dropped, and closed
    before it runs again. The close is deferred onto the loop; when the loop closes first, no close coroutine
    was ever created (no "never awaited" warning) and the pool's sockets are closed directly."""
    import gc
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    loop = asyncio.new_event_loop()
    pool = _SocketPool()
    ad._async_transports[id(loop)] = (loop, pool)
    ad._drop_send_pools()                       # from this thread, with the loop stopped
    assert pool.sock.fileno() != -1 and pool.closed_on == [] and len(ad._async_closing) == 1
    loop.close()
    ad._drop_send_pools()                       # the next drop sweeps the deferred close of a closed loop
    assert pool.sock.fileno() == -1 and ad._async_closing == set()
    gc.collect()
    assert not [w for w in recwarn.list if "never awaited" in str(w.message)]
    pool.close_peer()


def test_a_close_deferred_onto_a_stopped_loop_runs_when_the_loop_runs(world, tmp_path):
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    loop = asyncio.new_event_loop()
    pool = _SocketPool()
    ad._async_transports[id(loop)] = (loop, pool)
    ad._drop_send_pools()
    loop.run_until_complete(_settle())
    assert pool.closed_on == [loop] and ad._async_closing == set()
    loop.close()
    pool.sock.close()
    pool.close_peer()


def test_a_pool_of_an_already_closed_loop_has_its_sockets_closed_directly(world, tmp_path):
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    loop = asyncio.new_event_loop()
    loop.close()
    pool = _SocketPool()
    ad._async_transports[id(loop)] = (loop, pool)
    ad._drop_send_pools()
    assert pool.sock.fileno() == -1 and pool.closed_on == [] and ad._async_transports == {}
    pool.close_peer()


def test_a_retired_pool_with_an_abandoned_body_is_evicted(world, tmp_path):
    """fix-pass-3 review finding 4: a stream left unread and unclosed while its pool is retired. Once the body
    is collected (or its loop closed) the retired entry and its in-flight count are gone."""
    import gc
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    made = _pools(world, ad)
    loop = asyncio.new_event_loop()

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        await c.chat.completions.with_raw_response.create(model=MODEL, messages=MSG, stream=True)
        ad._drop_send_pools()
        assert [p for _, p in ad._retired_async] == [made[0]]   # in flight: the body was never read or closed
    loop.run_until_complete(go())
    gc.collect()
    loop.run_until_complete(_settle())
    assert ad._retired_async == [] and ad._inflight == {}
    loop.close()


def _encrypted_async(world, tmp_path, pool_cls=None):
    ad, _, _ = _accepted(world, tmp_path)
    made: list = []

    def factory():
        made.append((pool_cls or _ClosingPool)(lambda r: world.handler(r)))
        return made[-1]
    ad._async_transport_factory = factory
    return ad, made


def test_http_421_on_an_encrypted_async_send_closes_the_pool_on_its_loop(world, tmp_path):
    """fix-pass-3 review finding 5: the 421 re-verify path calls _drop_send_pools after the sealed response
    released its pool."""
    ad, made = _encrypted_async(world, tmp_path)
    orig = world.handler

    def gone(req):
        if req.url.path == "/v1/chat/completions":
            return httpx.Response(421, json={"error": {"message": "key no longer valid", "type": "provider_error"}})
        return orig(req)
    world.handler = gone

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        with pytest.raises(Exception) as ei:
            await c.chat.completions.create(model=MODEL, messages=MSG)
        assert "421" in repr(ei.value) or "421" in repr(ei.value.__cause__)
        await _settle()
        assert made[0].closed_on == [asyncio.get_running_loop()]
        assert ad._inflight == {} and ad._async_transports == {} and ad._retired_async == []
        assert ad.held_reason and "421" in ad.held_reason
    asyncio.run(go())
    assert ad._async_closing == set()


class _MismatchPool(_ClosingPool):
    async def handle_async_request(self, request):
        raise near.TLSPinMismatch("the TLS certificate of this connection is not the one the quote binds")


def test_a_tls_pin_mismatch_on_an_encrypted_async_send_closes_the_pool_on_its_loop(world, tmp_path):
    ad, made = _encrypted_async(world, tmp_path, _MismatchPool)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-near-test", base_url=BASE, http_client=ad.async_http_for_loop(),
                               max_retries=0)
        with pytest.raises(Exception):
            await c.chat.completions.create(model=MODEL, messages=MSG)
        await _settle()
        assert made[0].closed_on == [asyncio.get_running_loop()]
        assert ad._inflight == {} and ad._async_transports == {} and ad._retired_async == []
        assert ad.held_reason and "certificate" in ad.held_reason
    asyncio.run(go())
    assert ad._async_closing == set()


# ── appraisal and replay ─────────────────────────────────────────────────────────────────────────

def test_replay_recomputes_the_same_result_offline_and_detects_tampering(world, tmp_path):
    from ..near_world import fake_quote_verifier
    ad, r, _ = _accepted(world, tmp_path)
    ev = json.loads(json.dumps(r.evidence))
    res = replay_near.replay(ev, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots,
                             expected_repo=r.router_repo,
                             expected_fingerprints=(r.code_fingerprint, r.enclave_fingerprint))
    assert res.ok, res.checks
    assert res.not_established == replay_near.NOT_ESTABLISHED
    bad = json.loads(json.dumps(ev))
    h = bad["gateway"]["compose_hash"]
    bad["blobs"][h] = bad["blobs"][h] + " "      # no longer hashes to its id: dropped, so the check fails
    assert not replay_near.replay(bad, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots).ok
    bad = json.loads(json.dumps(ev))
    bad["claims"]["code_fingerprint"] = "0" * 64
    assert "fail" in str(replay_near.replay(bad, quote_verifier=fake_quote_verifier,
                                            ita_roots=world.ita.roots).checks["fingerprints"])
    assert not replay_near.replay(ev, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots,
                                  expected_repo="cloud-api.near.ai#other").ok


def test_appraise_without_the_real_quote_verifier_rejects_fake_quotes(world, tmp_path):
    ad, r, _ = _accepted(world, tmp_path)
    a = near.appraise(r.evidence, ita_roots=world.ita.roots)
    assert not a.ok and "TDX quote did not verify" in a.checks["gateway_quote"]


def test_rtmr3_replay_and_report_data_layouts():
    ident = "ab" * 32
    nonce = "cd" * 32
    assert nc.expected_report_data(ident, nonce) == bytes.fromhex(ident) + bytes.fromhex(nonce)
    tls = "ef" * 32
    assert nc.expected_report_data(ident, nonce, tls)[:32] == hashlib.sha256(bytes.fromhex(ident + tls)).digest()
    assert nc.mr_config_id_for("x") == b"\x01" + hashlib.sha256(b"x").digest() + bytes(15)
    from ..near_world import events_for
    ev = events_for("aa" * 20)
    ev[1]["digest"] = "00" * 48
    with pytest.raises(nc.CheckError, match="digest mismatch"):
        nc.replay_rtmr3(ev)


def test_jwt_checks(world):
    keys = nc.jwks_keys(world.ita.jwks, roots=world.ita.roots, at=nc.utc(NOW))
    claims = {"iss": "https://portal.trustauthority.intel.com", "iat": int(NOW), "exp": int(NOW) + 300}
    assert nc.verify_jwt(world.ita.token(claims), keys, at=NOW)["iss"].startswith("https://portal")
    with pytest.raises(nc.CheckError, match="not valid at"):
        nc.verify_jwt(world.ita.token(claims), keys, at=NOW + 3600)
    with pytest.raises(nc.CheckError, match="issuer"):
        nc.verify_jwt(world.ita.token({**claims, "iss": "https://evil"}), keys, at=NOW)
    with pytest.raises(nc.CheckError, match="alg"):
        nc.verify_jwt(world.ita.token(claims, alg="none"), keys, at=NOW)
    tok = world.ita.token(claims)
    h, p, s = tok.split(".")
    forged = json.loads(nc.b64url(p))
    forged["iss"] = forged["iss"]
    forged["tdx"] = {"attester_tcb_status": "UpToDate"}
    import base64
    p2 = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    with pytest.raises(nc.CheckError, match="signature"):
        nc.verify_jwt(f"{h}.{p2}.{s}", keys, at=NOW)
    other = NearWorld().ita
    with pytest.raises(nc.CheckError, match="signature"):
        nc.verify_jwt(world.ita.token(claims, key=other.leaf_key), keys, at=NOW)
    jwks = json.loads(json.dumps(world.ita.jwks))
    jwks["keys"][0]["n"] = other.jwks["keys"][0]["n"]
    with pytest.raises(nc.CheckError, match="does not match its certificate"):
        nc.jwks_keys(jwks, roots=world.ita.roots, at=nc.utc(NOW))


def test_send_context_is_scoped():
    assert sendctx.current() is None
    with sendctx.send_context(session_id="a", purpose="main", tier=None) as c:
        assert sendctx.current() == {"session_id": "a", "purpose": "main"} == c
    assert sendctx.current() is None


def test_pruning_a_closed_loop_pool_forgets_its_in_flight_count(world, tmp_path):
    """Review L7: a pool of a closed loop leaves no in-flight count behind."""
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    loop = asyncio.new_event_loop()
    loop.close()
    pool = _SocketPool()
    ad._async_transports[id(loop)] = (loop, pool)
    ad._inflight[id(pool)] = 1                      # a body abandoned on that loop
    ad._prune_closed_loops()
    assert ad._async_transports == {} and ad._inflight == {} and pool.sock.fileno() == -1
    pool.close_peer()


def test_a_release_during_pruning_is_not_undone(world, tmp_path):
    """Review L5: a finalizer's release that runs on the pruning thread removes its entry for good."""
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    live = asyncio.new_event_loop()
    dead = asyncio.new_event_loop()
    dead.close()
    released, dead_pool = _SocketPool(), _SocketPool()

    class Probe(list):
        fired = False

        def __iter__(inner):
            # The release of ``released`` runs after the first entry is read, as a finalizer would.
            for n, entry in enumerate(list.__iter__(list(list.__iter__(inner)))):
                yield entry
                if n == 0 and not Probe.fired:
                    Probe.fired = True
                    kept = [e for e in list.__iter__(inner) if e[1] is not released]
                    list.__setitem__(inner, slice(None), kept)
    ad._retired_async = Probe([(live, released), (dead, dead_pool)])
    ad._prune_closed_loops()
    assert [p for _, p in ad._retired_async] == []
    live.close()
    for p in (released, dead_pool):
        p.sock.close()
        p.close_peer()


def test_a_release_during_pruning_never_drops_a_live_entry_unclosed(world, tmp_path):
    """Re-review P1: a release that pops an entry while the prune reads the list must not make the prune skip
    and drop another live entry, which would then never have its close scheduled."""
    ad, _, _ = _accepted(world, tmp_path, encrypt=False)
    live = asyncio.new_event_loop()
    dead = asyncio.new_event_loop()
    dead.close()
    first, second, dead_pool = _SocketPool(), _SocketPool(), _SocketPool()

    class Probe(list):
        """Iterates the live list by index, as a list iterator does; on the second read, the first entry's
        release runs right after that entry is read, so a later entry shifts under the iterator."""
        reads = 0

        def __iter__(inner):
            Probe.reads += 1
            fire = Probe.reads == 2
            i = 0
            while i < list.__len__(inner):
                entry = list.__getitem__(inner, i)
                yield entry
                if fire and entry == (live, first):
                    fire = False
                    list.remove(inner, entry)
                i += 1
    ad._retired_async = Probe([(live, first), (live, second), (dead, dead_pool)])
    ad._prune_closed_loops()
    assert second in [p for _, p in list.__iter__(ad._retired_async)]   # still listed: its last release closes it
    assert dead_pool.sock.fileno() == -1
    live.close()
    for p in (first, second, dead_pool):
        p.sock.close()
        p.close_peer()

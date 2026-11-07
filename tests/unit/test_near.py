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
    import tests.near_world as w
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
    rep = replay_near.replay_signed_send(d, r.evidence, model=MODEL, quote_verifier=__import__(
        "tests.near_world", fromlist=["x"]).fake_quote_verifier, ita_roots=world.ita.roots)
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
    assert world.chat_posts() == 0 and rows == []


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

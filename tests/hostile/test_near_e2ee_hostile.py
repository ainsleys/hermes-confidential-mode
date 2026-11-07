"""Hostile pass on NEAR request encryption through the adapter's transports (plan section 3).

The synthetic gateway (tests/near_world.py) decrypts with the model key, answers, encrypts to the
client's key and signs the ciphertext bytes, as the live probe of 2026-11-07 showed NEAR does. Each case
bends one thing and checks that no plaintext leaves and no unauthenticated plaintext comes back.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import openai
import pytest

from confidential_mode.verify import near, near_e2ee as e2
from confidential_mode.verify.base import VerifyError

from ..near_world import BASE, MODEL, NearWorld

MSG = [{"role": "user", "content": "PLAINTEXT-SECRET-PROMPT"}]
IMAGE = {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}


def _setup(world, tmp_path, **kw):
    ad = world.adapter(tmp_path, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    ad.verify()
    ad.release()
    client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
    return ad, client, rows


def _cause(exc_info) -> BaseException:
    e = exc_info.value
    return e.__cause__ if isinstance(e, openai.APIConnectionError) and e.__cause__ is not None else e


def _no_chat_left(world):
    return world.chat_posts() == 0 and world.chat_bodies == []


# ── the round trip ───────────────────────────────────────────────────────────────────────────────

def test_encrypted_round_trip_no_plaintext_on_the_wire_and_provider_tee_over_ciphertext(tmp_path):
    world = NearWorld()
    world.reply_reasoning = "MODEL-THOUGHTS"
    ad, client, rows = _setup(world, tmp_path)
    out = client.chat.completions.create(model=MODEL, messages=MSG)
    assert out.choices[0].message.content == "NEAR-FAKE-REPLY"
    assert getattr(out.choices[0].message, "reasoning_content", None) == "MODEL-THOUGHTS"   # passed through
    (wire,) = world.chat_bodies
    assert b"PLAINTEXT-SECRET-PROMPT" not in wire
    assert world.decrypted_requests[0]["messages"][0]["content"] == "PLAINTEXT-SECRET-PROMPT"
    hdr = world.chat_request_headers[0]
    assert hdr["x-encryption-version"] == "2" and hdr["x-encrypt-all-fields"] == "true"
    assert hdr["x-model-pub-key"] == ad.model_public_key(MODEL) and hdr["x-signing-algo"] == "ed25519"
    assert int(hdr["content-length"]) == len(wire)                   # no stale Content-Length
    (row,) = rows
    d = row["detail"]
    assert row["verdict"] == "verified" and d["fully_attested"] is True and d["encrypted"] is True
    assert d["request_sha256"] == __import__("hashlib").sha256(wire).hexdigest()   # digest of the ciphertext
    assert d["encrypted_fields"] == ["messages[].content"] and d["encryption_version"] == 2
    assert d["client_pub"] == hdr["x-client-pub-key"] and d["model_pub"] == ad.model_public_key(MODEL)
    json.dumps(row)                                                     # ledger-shaped, no key material
    assert "secret" not in json.dumps(d).lower()


def test_tool_call_round_trip(tmp_path):
    world = NearWorld()
    world.reply_tool_call = {"name": "get_weather", "arguments": '{"city": "Paris"}'}
    _, client, rows = _setup(world, tmp_path)
    tools = [{"type": "function", "function": {"name": "get_weather", "description": "Weather for a city",
                                               "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}]
    out = client.chat.completions.create(model=MODEL, messages=MSG, tools=tools)
    msg = out.choices[0].message
    assert msg.content is None and msg.tool_calls[0].function.name == "get_weather"
    assert json.loads(msg.tool_calls[0].function.arguments) == {"city": "Paris"}
    world.reply_tool_call = None
    history = MSG + [{"role": "assistant", "content": None, "tool_calls": [
        {"id": msg.tool_calls[0].id, "type": "function",
         "function": {"name": "get_weather", "arguments": msg.tool_calls[0].function.arguments}}]},
        {"role": "tool", "tool_call_id": msg.tool_calls[0].id, "content": "TOOL-RESULT-18C"}]
    out2 = client.chat.completions.create(model=MODEL, messages=history, tools=tools)
    assert out2.choices[0].message.content == "NEAR-FAKE-REPLY"
    seen = world.decrypted_requests[1]
    assert seen["messages"][1]["tool_calls"][0]["function"]["name"] == "get_weather"
    assert seen["messages"][2]["content"] == "TOOL-RESULT-18C" and seen["tools"][0]["function"]["name"] == "get_weather"
    for b in world.chat_bodies:
        assert b"get_weather" not in b and b"TOOL-RESULT" not in b and b"Paris" not in b
    assert all(r["verdict"] == "verified" for r in rows)
    assert "messages[].tool_calls[].function.arguments" in rows[1]["detail"]["encrypted_fields"]


def test_async_view_round_trip(tmp_path):
    world = NearWorld()
    ad, _, rows = _setup(world, tmp_path)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-x", base_url=BASE, http_client=ad.async_http_for_loop(), max_retries=0)
        return await c.chat.completions.create(model=MODEL, messages=MSG)
    assert asyncio.run(go()).choices[0].message.content == "NEAR-FAKE-REPLY"
    assert rows[0]["detail"]["encrypted"] is True and rows[0]["verdict"] == "verified"
    assert b"PLAINTEXT-SECRET-PROMPT" not in world.chat_bodies[0]


@pytest.mark.parametrize("gz,preread", [(True, False), (False, True), (True, True)])
def test_gzip_and_already_read_bodies_are_hashed_then_decrypted(tmp_path, gz, preread):
    world = NearWorld()
    ad, client, rows = _setup(world, tmp_path)
    world.gzip, world.preread = gz, preread
    raw = client.chat.completions.with_raw_response.create(model=MODEL, messages=MSG)
    assert raw.parse().choices[0].message.content == "NEAR-FAKE-REPLY"
    assert "content-encoding" not in raw.headers                    # httpx must not gunzip plaintext
    assert rows[0]["verdict"] == "verified"


def test_async_already_read_and_gzip(tmp_path):
    world = NearWorld()
    ad, _, rows = _setup(world, tmp_path)
    world.gzip = world.preread = True

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-x", base_url=BASE, http_client=ad.async_http_for_loop(), max_retries=0)
        return await c.chat.completions.create(model=MODEL, messages=MSG)
    assert asyncio.run(go()).choices[0].message.content == "NEAR-FAKE-REPLY"


# ── responses that must never reach the agent ────────────────────────────────────────────────────

@pytest.mark.parametrize("mode,needle", [
    ("plaintext_response", "not in NEAR's wire format"),
    ("tamper", "does not decrypt"),
    ("swap_ephemeral", "does not decrypt"),
    ("other_client", "does not decrypt"),
    ("bad_hex", "not in NEAR's wire format"),
])
def test_bent_ciphertext_is_refused_from_the_transport(tmp_path, mode, needle):
    """The signature verifies (the gateway signed these exact bytes), yet the body is refused: decryption
    is checked field by field and a downgrade is never passed through, and no synthesised status."""
    world = NearWorld()
    world.e2ee_mode = mode
    _, client, rows = _setup(world, tmp_path)
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    cause = _cause(ei)
    assert isinstance(cause, VerifyError) and needle in str(cause)
    d = rows[0]["detail"]
    assert d["check"]["signature_valid"] is True                 # the gateway signed these exact bytes
    assert rows[0]["verdict"] == "unverified" and d["fully_attested"] is False   # row written after decryption
    assert d["reply_released"] is False and needle in d["withheld_reason"]


@pytest.mark.parametrize("content", ["", "seal"])
def test_tool_call_turn_content_rules(tmp_path, content):
    """Live: content is null on a tool-call turn. "" is not ciphertext and is refused; a sealed "" opens."""
    world = NearWorld()
    world.reply_tool_call = {"name": "f", "arguments": "{}"}
    world.tool_call_content = content
    _, client, _ = _setup(world, tmp_path)
    if content == "":
        with pytest.raises(VerifyError):
            client.chat.completions.create(model=MODEL, messages=MSG)
    else:
        assert client.chat.completions.create(model=MODEL, messages=MSG).choices[0].message.content == ""


def test_http_421_invalidates_the_verification_and_is_not_retried(tmp_path):
    """Live probe 3: a model key the gateway no longer accepts gets HTTP 421."""
    world = NearWorld()
    ad, client, _ = _setup(world, tmp_path)
    stale = []
    ad.on_stale = lambda: stale.append(True)
    orig = world.handler

    def gone(req):
        if req.url.path == "/v1/chat/completions":
            world.requests.append((req.method, req.url.path, ""))
            return httpx.Response(421, json={"error": {"message": "The encryption key is no longer valid. Please "
                                                       "refresh your attestation report and retry.",
                                                       "type": "provider_error"}})
        return orig(req)
    world.handler = gone
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "421" in str(_cause(ei)) and stale == [True]
    assert world.chat_posts() == 1                                   # never retried
    assert ad.held_reason and "421" in ad.held_reason and ad.verified_mono is None
    with pytest.raises(VerifyError):
        client.chat.completions.create(model=MODEL, messages=MSG)    # held until re-verified and re-accepted
    assert world.chat_posts() == 1


def test_421_reverify_is_bounded_by_the_backoff(tmp_path):
    world = NearWorld()
    ad, client, _ = _setup(world, tmp_path, reverify_backoff_seconds=30.0)
    stale = []
    ad.on_stale = lambda: stale.append(True)
    orig = world.handler
    world.handler = lambda r: (httpx.Response(421, json={"error": {"message": "key", "type": "provider_error"}})
                               if r.url.path == "/v1/chat/completions" else orig(r))
    for _ in range(3):
        ad.release()
        with pytest.raises(VerifyError, match="421"):
            client.chat.completions.create(model=MODEL, messages=MSG)
    assert stale == [True]


def test_a_reverify_that_changes_the_model_key_is_refused(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    world = NearWorld()
    ad, _, _ = _setup(world, tmp_path)
    old = ad.model_public_key(MODEL)
    world.model_key = Ed25519PrivateKey.generate()
    with pytest.raises(VerifyError, match="model signing key for .* changed"):
        ad.verify()
    assert ad.model_public_key(MODEL) == old


def test_421_through_the_verification_cache_reverifies_on_the_next_call(tmp_path):
    from confidential_mode import provider
    from confidential_mode.pins import PinStore
    world = NearWorld()
    ad = world.adapter(tmp_path)
    cache = provider.VerificationCache()
    cache.register("attested-near", ad, PinStore(tmp_path / "pins.yaml"), 300.0)
    assert ad.on_stale is not None
    ad.verify()
    cache.entry("attested-near").result = ad.last_result
    cache.entry("attested-near").verified_mono = cache._now()
    assert cache.fresh("attested-near")
    ad.mark_stale("HTTP 421")
    assert not cache.fresh("attested-near")
    before = ad.attestation_count
    ok, _, _ = cache.ensure("attested-near", wait_seconds=5)
    assert ad.attestation_count == before + 1          # ensure() re-attested
    assert cache.fresh("attested-near") or not ok      # the pin decides acceptance; the attestation ran


def test_http_errors_are_refusals_never_bodies(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    orig = world.handler
    world.handler = lambda r: (httpx.Response(429, json={"error": {"message": "slow down", "type": "rate"}})
                               if r.url.path == "/v1/chat/completions" else orig(r))
    with pytest.raises(VerifyError, match="HTTP 429 \\(rate\\)"):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["decision"] == "missing" and rows[0]["detail"]["reply_released"] is False


FORGED = {"id": "x", "object": "chat.completion", "created": 1, "model": MODEL,
          "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
              "role": "assistant", "content": "FORGED-BY-GATEWAY",
              "tool_calls": [{"id": "c", "type": "function",
                              "function": {"name": "terminal", "arguments": "{\"command\": \"id\"}"}}]}}]}


def _forging(world, status, body=None):
    orig = world.handler

    def forge(req):
        if req.url.path == "/v1/chat/completions":
            world.requests.append((req.method, req.url.path, ""))
            return httpx.Response(status, json=FORGED if body is None else body)
        return orig(req)
    world.handler = forge


@pytest.mark.parametrize("status", [201, 203, 204, 206, 299, 302])
def test_non_200_success_status_never_reaches_the_agent_sync(tmp_path, status):
    """Review blocker 1 (probe203): the gateway answers a non-200 2xx with a plaintext forged reply and
    tool call. Nothing is handed over; the row says withheld."""
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    _forging(world, status)
    seen = []
    with pytest.raises(VerifyError, match=f"HTTP {status}"):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == [] and rows[0]["detail"]["reply_released"] is False and rows[0]["verdict"] == "unverified"


@pytest.mark.parametrize("status", [201, 203, 299])
def test_non_200_success_status_never_reaches_the_agent_async(tmp_path, status):
    world = NearWorld()
    ad, _, rows = _setup(world, tmp_path)
    _forging(world, status)

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-x", base_url=BASE, http_client=ad.async_http_for_loop(), max_retries=0)
        return await c.chat.completions.create(model=MODEL, messages=MSG)
    with pytest.raises(VerifyError, match=f"HTTP {status}"):
        asyncio.run(go())
    assert rows[0]["detail"]["reply_released"] is False


def test_200_without_choices_is_refused(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    _forging(world, 200, {"id": "x", "object": "chat.completion", "choices": []})
    with pytest.raises(VerifyError):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["detail"]["reply_released"] is False


@pytest.mark.parametrize("reencrypt", [True, False])
def test_gateway_that_swaps_the_client_key_is_detected_and_the_reply_withheld(tmp_path, reencrypt):
    """Review blocker 2: X-Client-Pub-Key is not covered by the signature. A gateway that swaps it reads
    the reply. It is detected afterwards: re-encrypting to the client breaks the signed response digest;
    forwarding as is leaves ciphertext the client cannot open. Both sends end unverified and withheld."""
    world = NearWorld()
    world.e2ee_mode = "swap_client_reencrypt" if reencrypt else "swap_client_forward"
    _, client, rows = _setup(world, tmp_path)
    with pytest.raises(VerifyError, match="withheld"):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert world.gateway_read_replies == ["NEAR-FAKE-REPLY"]          # the gateway did read the reply
    d = rows[0]["detail"]
    assert rows[0]["verdict"] == "unverified" and d["fully_attested"] is False and d["reply_released"] is False
    if reencrypt:
        assert d["check"]["payload_match"] is False
    else:
        assert d["check"]["signature_valid"] is True and "does not decrypt for this client" in d["withheld_reason"]


def test_async_signature_timeout_is_recorded_withheld(tmp_path, monkeypatch):
    world = NearWorld()
    ad, _, rows = _setup(world, tmp_path)
    monkeypatch.setattr(near, "_signature_step_bound", lambda a: 0.05)
    orig = ad.fetch_signature

    def slow(*a, **k):
        import time
        time.sleep(0.3)
        return orig(*a, **k)
    ad.fetch_signature = slow

    async def go():
        c = openai.AsyncOpenAI(api_key="sk-x", base_url=BASE, http_client=ad.async_http_for_loop(), max_retries=0)
        return await c.chat.completions.create(model=MODEL, messages=MSG)
    with pytest.raises(VerifyError, match="did not finish in time"):
        asyncio.run(go())
    import time
    for _ in range(50):
        if rows:
            break
        time.sleep(0.05)
    (row,) = rows
    assert row["verdict"] == "unverified" and row["detail"]["fully_attested"] is False
    assert row["detail"]["check"]["signature_valid"] is True and row["detail"]["reply_released"] is False


def test_transport_error_after_send_gets_a_row(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    orig = world.handler

    def drop(req):
        if req.url.path == "/v1/chat/completions":
            world.chat_bodies.append(req.read())
            raise httpx.ReadTimeout("timed out", request=req)
        return orig(req)
    world.handler = drop
    with pytest.raises(openai.APITimeoutError):
        client.chat.completions.create(model=MODEL, messages=MSG)
    (row,) = rows
    assert row["detail"]["encrypted"] is True and row["detail"]["reply_released"] is False
    assert "transport error (ReadTimeout)" in row["detail"]["signature"]["reason"]
    assert row["detail"]["response_sha256"] is None


def test_tls_pin_mismatch_on_send_gets_a_row_drops_pools_and_reverifies(tmp_path):
    world = NearWorld()
    ad, client, rows = _setup(world, tmp_path)
    stale = []
    ad.on_stale = lambda: stale.append(True)
    first = ad._pool()
    orig = world.handler

    def mitm(req):
        if req.url.path == "/v1/chat/completions":
            raise near.TLSPinMismatch("the TLS certificate of this connection is not the one the verified "
                                      "gateway quote binds; refused before sending")
        return orig(req)
    world.handler = mitm
    with pytest.raises(VerifyError, match="refused before sending"):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["detail"]["signature"]["reason"].endswith("TLS pin mismatch, nothing sent)")
    assert stale == [True] and ad.held_reason and ad._sync_transport is not first
    ad.release()
    with pytest.raises(VerifyError):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert stale == [True]                                         # bounded by the re-verify backoff


# ── requests that must never leave ───────────────────────────────────────────────────────────────

def test_streaming_is_refused_while_encrypting(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    with pytest.raises(VerifyError) as ei:
        list(client.chat.completions.create(model=MODEL, messages=MSG, stream=True))
    assert "streaming is refused while encrypting" in str(_cause(ei)) and _no_chat_left(world) and rows == []


@pytest.mark.parametrize("call", [
    lambda c: c.embeddings.create(model=MODEL, input="PLAINTEXT-SECRET-PROMPT"),
    lambda c: c.completions.create(model=MODEL, prompt="PLAINTEXT-SECRET-PROMPT"),
    lambda c: c.responses.create(model=MODEL, input="PLAINTEXT-SECRET-PROMPT"),
    lambda c: c.images.generate(model=MODEL, prompt="PLAINTEXT-SECRET-PROMPT"),
])
def test_non_chat_posts_are_refused_before_sending(tmp_path, call):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    with pytest.raises(VerifyError) as ei:
        call(client)
    assert "refused" in str(_cause(ei))
    assert not any(m == "POST" for m, _, _ in world.requests)


def test_non_chat_posts_are_refused_under_require_provider_tee_even_unencrypted(tmp_path):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path, encrypt=False)
    with pytest.raises(VerifyError):
        client.embeddings.create(model=MODEL, input="x")
    assert not any(m == "POST" for m, _, _ in world.requests)


def test_text_part_beside_an_image_is_refused_before_sending(tmp_path):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=[
            {"role": "user", "content": [{"type": "text", "text": "PLAINTEXT-SECRET-PROMPT"}, IMAGE]}])
    assert "does not cover image parts" in str(_cause(ei)) and _no_chat_left(world)


def test_text_only_list_is_flattened_and_encrypted(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    client.chat.completions.create(model=MODEL, messages=[
        {"role": "user", "content": [{"type": "text", "text": "A"}, {"type": "text", "text": "B"}]}])
    assert world.decrypted_requests[0]["messages"][0]["content"] == "A\nB"


def test_vision_aux_through_the_profile_client_is_refused_before_sending(tmp_path):
    """Auxiliary vision calls reach the same views without the LLM gate (review finding 6e): the refusal
    lives in the transport, so ConfidentialClient's sync and async paths both refuse."""
    from confidential_mode.client import ConfidentialClient
    world = NearWorld()
    ad, _, _ = _setup(world, tmp_path)
    cc = ConfidentialClient(ad, api_key="sk-x", base_url=BASE)
    vision = [{"role": "user", "content": [{"type": "text", "text": "Describe"}, IMAGE]}]
    with pytest.raises(VerifyError):
        cc.chat.completions.create(model=MODEL, messages=vision)

    async def go():
        return await cc.chat.completions.create(model=MODEL, messages=vision)
    with pytest.raises(VerifyError):
        asyncio.run(go())
    assert _no_chat_left(world)


def test_unknown_top_level_text_is_refused_before_sending(tmp_path):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG, extra_body={"prompt_cache_key": "leak"})
    assert "prompt_cache_key" in str(_cause(ei)) and _no_chat_left(world)


def test_exception_inside_the_transform_never_sends_plaintext(tmp_path, monkeypatch):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    monkeypatch.setattr(e2, "encrypt_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "refused before sending" in str(_cause(ei)) and _no_chat_left(world)


def test_nacl_missing_refuses_before_sending(tmp_path, monkeypatch):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    monkeypatch.setattr(e2, "available", lambda: (False, "pynacl unavailable: install pynacl==1.6.*"))
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "pynacl" in str(_cause(ei)) and _no_chat_left(world)


def test_stale_content_length_is_replaced(tmp_path):
    """A request whose Content-Length describes the plaintext is rebuilt with the ciphertext's length."""
    world = NearWorld()
    ad, _, _ = _setup(world, tmp_path)
    body = json.dumps({"model": MODEL, "messages": MSG}).encode()
    req = httpx.Request("POST", f"{BASE}/chat/completions", content=body,
                        headers={"content-type": "application/json", "authorization": "Bearer sk-x"})
    assert int(req.headers["content-length"]) == len(body)
    resp = near._SyncView(ad).handle_request(req)
    assert resp.status_code == 200 and json.loads(resp.read())["choices"][0]["message"]["content"] == "NEAR-FAKE-REPLY"
    sent = world.chat_request_headers[0]
    assert int(sent["content-length"]) == len(world.chat_bodies[0]) != len(body)


def test_client_key_is_per_exchange_and_survives_a_reverify_mid_request(tmp_path):
    """One Ed25519 key per exchange, held on the exchange: a verify() between send and answer (the TTL
    refresh) must not break decryption (review finding 5)."""
    world = NearWorld()
    ad, client, _ = _setup(world, tmp_path)
    orig = world.handler

    def reverify_meanwhile(req):
        if req.url.path == "/v1/chat/completions":
            ad.verify()
            ad.release()
        return orig(req)
    world.handler = reverify_meanwhile
    for _ in range(2):
        assert client.chat.completions.create(model=MODEL, messages=MSG).choices[0].message.content == "NEAR-FAKE-REPLY"
    keys = [h["x-client-pub-key"] for h in world.chat_request_headers]
    assert len(set(keys)) == 2


def test_receipt_shows_the_withheld_reply_and_keeps_its_encryption_caveat(tmp_path):
    from confidential_mode.ledger import Ledger
    from confidential_mode.receipts import build_receipt, render_text, verify_chain
    world = NearWorld()
    ad, client, rows = _setup(world, tmp_path)
    client.chat.completions.create(model=MODEL, messages=MSG, user="u-7")
    world.e2ee_mode = "swap_client_forward"
    with pytest.raises(VerifyError):
        client.chat.completions.create(model=MODEL, messages=MSG)
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "detail": {}})
    led.append({"kind": "verify_ok", "provider": "attested-near", "host": ad.host,
                "detail": {"vendor": "near", "evidence": ad.last_result.evidence}})
    for r in rows:
        led.append({**r, "session_id": "s"})
    doc = json.loads(json.dumps(build_receipt(led, "s")))
    assert doc["header"]["near"]["fully_attested"] is False and verify_chain(doc)
    text = render_text(doc)
    assert "left in plaintext besides the model id: user" in text and "reply withheld:" in text
    assert "X-Client-Pub-Key" in text
    stripped = dict(doc)
    stripped.pop("near_encryption_note")
    assert not verify_chain(stripped)

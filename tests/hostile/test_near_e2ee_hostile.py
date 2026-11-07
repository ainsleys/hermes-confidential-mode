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
    with pytest.raises(openai.APIConnectionError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    cause = _cause(ei)
    assert isinstance(cause, VerifyError) and needle in str(cause)
    assert rows[0]["verdict"] == "verified"      # the record is about the signature; the body is still refused


@pytest.mark.parametrize("content", ["", "seal"])
def test_tool_call_turn_content_rules(tmp_path, content):
    """Live: content is null on a tool-call turn. "" is not ciphertext and is refused; a sealed "" opens."""
    world = NearWorld()
    world.reply_tool_call = {"name": "f", "arguments": "{}"}
    world.tool_call_content = content
    _, client, _ = _setup(world, tmp_path)
    if content == "":
        with pytest.raises(openai.APIConnectionError):
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
    with pytest.raises(openai.APIConnectionError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "421" in str(_cause(ei)) and stale == [True]
    assert world.chat_posts() == 1                                   # never retried
    assert ad.held_reason and "421" in ad.held_reason and ad.verified_mono is None
    with pytest.raises(openai.APIConnectionError):
        client.chat.completions.create(model=MODEL, messages=MSG)    # held until re-verified and re-accepted
    assert world.chat_posts() == 1


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


def test_other_http_errors_pass_as_errors_never_as_decrypted_text(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    orig = world.handler
    world.handler = lambda r: (httpx.Response(429, json={"error": {"message": "slow down", "type": "rate"}})
                               if r.url.path == "/v1/chat/completions" else orig(r))
    with pytest.raises(openai.RateLimitError):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["decision"] == "missing"


# ── requests that must never leave ───────────────────────────────────────────────────────────────

def test_streaming_is_refused_while_encrypting(tmp_path):
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    with pytest.raises(openai.APIConnectionError) as ei:
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
    with pytest.raises(openai.APIConnectionError) as ei:
        call(client)
    assert "refused" in str(_cause(ei))
    assert not any(m == "POST" for m, _, _ in world.requests)


def test_non_chat_posts_are_refused_under_require_provider_tee_even_unencrypted(tmp_path):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path, encrypt=False)
    with pytest.raises(openai.APIConnectionError):
        client.embeddings.create(model=MODEL, input="x")
    assert not any(m == "POST" for m, _, _ in world.requests)


def test_text_part_beside_an_image_is_refused_before_sending(tmp_path):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    with pytest.raises(openai.APIConnectionError) as ei:
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
    with pytest.raises(openai.APIConnectionError):
        cc.chat.completions.create(model=MODEL, messages=vision)

    async def go():
        return await cc.chat.completions.create(model=MODEL, messages=vision)
    with pytest.raises(openai.APIConnectionError):
        asyncio.run(go())
    assert _no_chat_left(world)


def test_unknown_top_level_text_is_refused_before_sending(tmp_path):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    with pytest.raises(openai.APIConnectionError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG, extra_body={"prompt_cache_key": "leak"})
    assert "prompt_cache_key" in str(_cause(ei)) and _no_chat_left(world)


def test_exception_inside_the_transform_never_sends_plaintext(tmp_path, monkeypatch):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    monkeypatch.setattr(e2, "encrypt_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(openai.APIConnectionError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "refused before sending" in str(_cause(ei)) and _no_chat_left(world)


def test_nacl_missing_refuses_before_sending(tmp_path, monkeypatch):
    world = NearWorld()
    _, client, _ = _setup(world, tmp_path)
    monkeypatch.setattr(e2, "available", lambda: (False, "pynacl unavailable: install pynacl==1.6.*"))
    with pytest.raises(openai.APIConnectionError) as ei:
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

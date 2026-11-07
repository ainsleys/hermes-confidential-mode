"""NEAR request encryption (verify/near_e2ee.py): known-answer vectors and the field table.

Known-answer vectors. NEAR publishes no fixed vector: its verifier repository
(github.com/nearai/nearai-cloud-verifier at 94554726fd548676842b7ea603a8173a60c31341,
py/encrypted_chat_verifier.py) implements the legacy NaCl Box cipher, not version 2. The vectors below
were produced on 2026-11-07 by the reference ``v2_encrypt`` of NEAR's own guide
(https://docs.near.ai/cloud/guides/e2ee-chat-completions, "Quick Start": cryptography's X25519 and HKDF,
PyNaCl's XChaCha20-Poly1305), with ``X25519PrivateKey.generate()`` replaced by ``from_private_bytes`` of
the fixed ephemeral secret and the random nonce by the fixed nonce. They are frozen here, so the plugin's
own path (libsodium scalar multiplication, a standard-library HKDF) is checked against NEAR's code, not
against itself. The XChaCha20-Poly1305 vector is draft-irtf-cfrg-xchacha-03 appendix A.3.1 (libsodium's
own test vector); the HKDF vector is RFC 5869 test case 3; the Ed25519 to X25519 conversion is recomputed
here from the curve equations on RFC 8032 test 1's key.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from confidential_mode.verify import near_e2ee as e2

MODEL_SEED = bytes(range(32))
MODEL_PUB = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
REQ_EPH, REQ_NONCE = bytes(range(32, 64)), bytes(range(64, 88))
REQ_PLAINTEXT = b"What is the capital of France?"
REQ_WIRE = ("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254404142434445464748494a4b4c4d4e4f50515253"
            "54555657dc5ae05b157eefdf3aa16bb37b3040be83b27f67b6b0d05439950b8f8571cde5a1ae180bdcf0860b97fd955fc6f9")
CLIENT_SEED = bytes(range(100, 132))
CLIENT_PUB = "0bbc346a57667c380120bd9c7fd7e51d2c5fdfea37cd2f5bf405b2c6bf6f2d78"
RESP_WIRE = ("152dab99279f45dd66eb2c7f9e5682a2e14a7feb42aff04e5cc4238621c2624bb4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6"
             "c7c8c9cacb74f81c48ed49cdc5bc49cb37e16d76063777e33fed")


def test_frozen_vectors_regenerate_from_the_guides_code_and_independently():
    """tests/fixtures/near_e2ee_vectors/generate.py runs the guide's v2_encrypt (fixed randomness) and an
    independent recomputation (curve map, cryptography X25519 and HKDF); both give the frozen bytes."""
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "fixtures" / "near_e2ee_vectors" / "generate.py"
    spec = importlib.util.spec_from_file_location("near_e2ee_vectors_generate", path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    v = gen.vectors()
    assert (v["MODEL_PUB"], v["REQ_WIRE"], v["CLIENT_PUB"], v["RESP_WIRE"]) == (MODEL_PUB, REQ_WIRE, CLIENT_PUB, RESP_WIRE)


def test_the_fake_gateways_independent_cipher_matches_the_vectors():
    """tests/near_cipher_ref.py (the synthetic model side) shares no code with near_e2ee."""
    from tests import near_cipher_ref as ref
    assert ref.seal(MODEL_PUB, REQ_PLAINTEXT, eph=REQ_EPH, nonce=REQ_NONCE) == REQ_WIRE
    assert ref.open_(ref.ed_seed_to_x_secret(CLIENT_SEED), RESP_WIRE) == b"Paris"
    assert ref.open_(ref.ed_seed_to_x_secret(MODEL_SEED), e2.seal(MODEL_PUB, b"x")) == b"x"


def model_key():
    return e2.ClientKey.from_seed(MODEL_SEED)   # the "model" side of a vector holds a key like any other


# ── known answers ────────────────────────────────────────────────────────────────────────────────

def test_seal_matches_nears_reference_code_byte_for_byte():
    assert model_key().public_hex == MODEL_PUB
    assert e2.seal(MODEL_PUB, REQ_PLAINTEXT, _ephemeral_secret=REQ_EPH, _nonce=REQ_NONCE) == REQ_WIRE
    assert e2.open(model_key(), REQ_WIRE) == REQ_PLAINTEXT


def test_open_decrypts_nears_reference_ciphertext():
    client = e2.ClientKey.from_seed(CLIENT_SEED)
    assert client.public_hex == CLIENT_PUB
    assert e2.open(client, RESP_WIRE) == b"Paris"


def test_xchacha20_poly1305_draft_vector():
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    out = crypto_aead_xchacha20poly1305_ietf_encrypt(
        pt, bytes.fromhex("50515253c0c1c2c3c4c5c6c7"), bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
    assert out.hex() == (
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c670"
        "8c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da97"
        "68812f615c68b13b52e" "c0875924c1c7987947deafd8780acf49")


def test_hkdf_rfc5869_case_3_and_against_cryptography():
    okm = e2.hkdf_sha256(bytes([0x0B]) * 22, info=b"", length=42)
    assert okm.hex() == ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                         "9d201395faa4b61a96c8")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ikm = hashlib.sha256(b"shared").digest()
    assert e2.hkdf_sha256(ikm) == HKDF(hashes.SHA256(), 32, None, b"ed25519_encryption").derive(ikm)


def test_ed25519_to_x25519_against_the_curve_equations():
    """RFC 8032 test 1: Montgomery u = (1 + y) / (1 - y) mod p for the public key; the secret is the
    clamped first half of SHA-512(seed)."""
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    p = 2 ** 255 - 19
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    u = (1 + y) * pow(1 - y, p - 2, p) % p
    assert e2.ed25519_pub_to_x25519(pub) == u.to_bytes(32, "little")
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    assert e2.ClientKey.from_seed(seed)._x25519_secret == bytes(h)
    assert e2.ClientKey.from_seed(seed).public_hex == pub.hex()


def test_seal_is_fresh_each_time_and_keys_are_per_exchange():
    a, b = e2.seal(MODEL_PUB, b"x"), e2.seal(MODEL_PUB, b"x")
    assert a != b and a[:64] != b[:64]                      # new ephemeral key and nonce each field
    assert e2.ClientKey.generate().public_hex != e2.ClientKey.generate().public_hex
    assert "secret" not in repr(e2.ClientKey.generate())


@pytest.mark.parametrize("bad", ["", "zz" * 80, "ab" * 10, "abc", None, 7])
def test_open_refuses_what_is_not_wire_format(bad):
    with pytest.raises(e2.E2EEError):
        e2.open(model_key(), bad)


def test_open_refuses_tampering_and_other_keys():
    w = e2.seal(MODEL_PUB, b"secret")
    flipped = w[:-2] + ("00" if w[-2:] != "00" else "11")
    with pytest.raises(e2.E2EEError, match="does not decrypt"):
        e2.open(model_key(), flipped)
    with pytest.raises(e2.E2EEError, match="does not decrypt"):
        e2.open(model_key(), e2.ClientKey.generate().public_hex + w[64:])   # swapped ephemeral key
    with pytest.raises(e2.E2EEError, match="does not decrypt"):
        e2.open(e2.ClientKey.generate(), w)                                  # someone else's key
    with pytest.raises(e2.E2EEError, match="low-order|all-zero|malformed"):
        e2.open(model_key(), "00" * 32 + w[64:])


@pytest.mark.parametrize("pub", ["AB" * 32, "ab" * 31, "0x" + "ab" * 31, 5])
def test_model_key_must_be_lower_case_hex_32_bytes(pub):
    with pytest.raises(e2.E2EEError):
        e2.seal(pub, b"x")


def test_headers_are_the_guides_with_all_fields_on():
    h = e2.request_headers(CLIENT_PUB, MODEL_PUB)
    assert h == {"X-Signing-Algo": "ed25519", "X-Client-Pub-Key": CLIENT_PUB, "X-Model-Pub-Key": MODEL_PUB,
                 "X-Encryption-Version": "2", "x-no-aliasing": "true", "X-Encrypt-All-Fields": "true"}


# ── the field table ──────────────────────────────────────────────────────────────────────────────

PARAMS = {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}


def full_request():
    """A request with every request field of NEAR's table (default and all-fields)."""
    return {
        "model": "m", "stream": False, "temperature": 0.2, "max_tokens": 9, "user": "u-1", "stop": ["X"],
        "response_format": {"type": "json_object"}, "metadata": {"k": "v"}, "parallel_tool_calls": True,
        "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
        "tools": [{"type": "function", "function": {"name": "get_weather", "description": "Weather for a city",
                                                    "parameters": PARAMS, "strict": True}}],
        "messages": [
            {"role": "system", "content": "SYSTEM-SECRET"},
            {"role": "user", "content": [{"type": "text", "text": "PART-ONE"}, {"type": "text", "text": "PART-TWO",
                                                                               "cache_control": {"type": "ephemeral"}}],
             "name": "alice"},
            {"role": "assistant", "content": None, "refusal": "REFUSAL-TEXT", "reasoning_content": "THOUGHTS",
             "tool_calls": [{"id": "call_1", "type": "function",
                             "function": {"name": "get_weather", "arguments": "{\"city\": \"Paris\"}"}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "TOOL-RESULT"},
            {"role": "assistant", "content": ""},
        ],
    }


def test_every_request_field_in_nears_table_is_encrypted_and_round_trips():
    out, rep = e2.encrypt_request(full_request(), MODEL_PUB)
    assert rep["encrypted_fields"] == sorted([
        "messages[].content", "messages[].name", "messages[].refusal",
        "messages[].tool_calls[].function.name", "messages[].tool_calls[].function.arguments",
        "tools[].function.name", "tools[].function.description", "tools[].function.parameters",
        "tool_choice.function.name"])
    assert rep["dropped_fields"] == ["messages[].reasoning_content"] and rep["flattened_messages"] == 1
    assert rep["all_fields"] is True and rep["encryption_version"] == 2
    wire = json.dumps(out)
    for secret in ("SYSTEM-SECRET", "PART-ONE", "PART-TWO", "alice", "REFUSAL-TEXT", "THOUGHTS", "Paris",
                   "get_weather", "Weather for a city", "TOOL-RESULT", '"city"'):
        assert secret not in wire, secret
    op = lambda v: e2.open(model_key(), v).decode()  # noqa: E731
    m = out["messages"]
    assert op(m[0]["content"]) == "SYSTEM-SECRET" and op(m[1]["content"]) == "PART-ONE\nPART-TWO"
    assert op(m[1]["name"]) == "alice" and op(m[2]["refusal"]) == "REFUSAL-TEXT" and m[2]["content"] is None
    assert "reasoning_content" not in m[2]
    fn = m[2]["tool_calls"][0]["function"]
    assert (op(fn["name"]), json.loads(op(fn["arguments"]))) == ("get_weather", {"city": "Paris"})
    assert m[2]["tool_calls"][0]["id"] == "call_1" and m[3]["tool_call_id"] == "call_1"
    assert op(m[3]["content"]) == "TOOL-RESULT" and op(m[4]["content"]) == ""      # "" is sealed too
    tf = out["tools"][0]["function"]
    assert json.loads(op(tf["parameters"])) == PARAMS and tf["strict"] is True
    assert op(out["tool_choice"]["function"]["name"]) == "get_weather"
    assert out["user"] == "u-1" and out["stop"] == ["X"] and out["metadata"] == {"k": "v"}   # probe 4 allowlist


@pytest.mark.parametrize("content,needle", [
    ([{"type": "text", "text": "look"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}}],
     "does not cover image parts"),
    ([{"type": "input_audio", "input_audio": {"data": "AA", "format": "wav"}}], "does not cover 'input_audio'"),
    ([{"type": "file", "file": {"file_data": "AA"}}], "does not cover 'file'"),
    (["bare string part"], "does not cover"),
    ([{"type": "text", "text": "x", "annotation": "leak"}], "carries fields"),
])
def test_non_text_parts_are_refused(content, needle):
    body = {"model": "m", "messages": [{"role": "user", "content": content}]}
    with pytest.raises(e2.E2EEError, match=needle):
        e2.encrypt_request(body, MODEL_PUB)


@pytest.mark.parametrize("extra,needle", [
    ({"prompt_cache_key": "abc"}, "prompt_cache_key"),
    ({"extra": {"nested": ["leak"]}}, "'extra'"),
    ({"logprobs": True}, "logprobs"),
    ({"top_logprobs": 3}, "top_logprobs"),
    ({"tool_choice": {"type": "allowed_tools", "tools": []}}, "tool_choice"),
    ({"tools": [{"type": "web_search"}]}, "function tool"),
    ({"tools": [{"type": "function", "function": {"name": "f", "title": "leak"}}]}, "title"),
])
def test_top_level_fields_outside_the_table_are_refused(extra, needle):
    body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], **extra}
    with pytest.raises(e2.E2EEError, match=needle):
        e2.encrypt_request(body, MODEL_PUB)


def test_every_top_level_key_that_leaves_in_plaintext_is_reported():
    out, rep = e2.encrypt_request({"model": "m", "messages": [], "parallel_tool_calls": True, "user": "u",
                                   "stop": ["X"], "temperature": 0.1}, MODEL_PUB)
    assert out["parallel_tool_calls"] is True
    assert rep["plaintext_keys"] == ["parallel_tool_calls", "stop", "temperature", "user"]


@pytest.mark.parametrize("value", [{"secret text as a key": 1}, {"include_usage": True}, [{"k": None}]])
def test_mapping_keys_count_as_text(value):
    with pytest.raises(e2.E2EEError, match="carries text"):
        e2.encrypt_request({"model": "m", "messages": [], "extra": value}, MODEL_PUB)


@pytest.mark.parametrize("msg,needle", [
    ({"role": "user", "content": "x", "audio": {"id": "leak"}}, "messages\\[0\\].audio"),
    ({"role": "narrator", "content": "x"}, "role"),
    ({"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f"},
                                           "extra_content": {"sig": "leak"}}]}, "extra_content"),
    ({"role": "user", "content": {"text": "x"}}, "not a string"),
    ("not an object", "not an object"),
])
def test_message_fields_outside_the_table_are_refused(msg, needle):
    with pytest.raises(e2.E2EEError, match=needle):
        e2.encrypt_request({"model": "m", "messages": [msg]}, MODEL_PUB)


def full_response(client_pub):
    s = lambda t: e2.seal(client_pub, t.encode())  # noqa: E731
    return {"id": "chatcmpl-1", "object": "chat.completion", "model": "m", "usage": {"total_tokens": 3},
            "choices": [{"index": 0, "finish_reason": "tool_calls", "logprobs": None, "message": {
                "role": "assistant", "content": s("ANSWER"), "reasoning_content": s("REASON-A"),
                "reasoning": s("REASON-B"), "refusal": s("NO"), "audio": {"id": "a1", "data": s("AUDIO")},
                "tool_calls": [{"id": "call_9", "type": "function",
                                "function": {"name": s("get_weather"), "arguments": s('{"city":"Oslo"}')}}]}}]}


def test_every_response_field_in_nears_table_is_decrypted():
    client = e2.ClientKey.generate()
    plain, rep = e2.decrypt_response(full_response(client.public_hex), client)
    m = plain["choices"][0]["message"]
    assert (m["content"], m["reasoning_content"], m["reasoning"], m["refusal"], m["audio"]["data"]) == (
        "ANSWER", "REASON-A", "REASON-B", "NO", "AUDIO")
    assert m["tool_calls"][0]["function"] == {"name": "get_weather", "arguments": '{"city":"Oslo"}'}
    assert m["tool_calls"][0]["id"] == "call_9" and plain["usage"] == {"total_tokens": 3}
    assert rep["decrypted_count"] == 7


def test_tool_call_turn_with_null_content_is_not_a_downgrade():
    """Probe 1 (live, 2026-11-07): content null, tool_calls and reasoning_content encrypted."""
    client = e2.ClientKey.generate()
    body = full_response(client.public_hex)
    msg = body["choices"][0]["message"]
    msg["content"] = None
    del msg["reasoning"], msg["refusal"], msg["audio"]
    plain, _ = e2.decrypt_response(body, client)
    assert plain["choices"][0]["message"]["content"] is None


@pytest.mark.parametrize("field,value", [
    ("content", "plain text reply"), ("content", ""), ("reasoning_content", "plain reasoning"),
    ("refusal", "plain"), ("content", 42),
])
def test_downgrade_in_a_response_field_is_refused(field, value):
    client = e2.ClientKey.generate()
    body = full_response(client.public_hex)
    body["choices"][0]["message"][field] = value
    with pytest.raises(e2.E2EEError):
        e2.decrypt_response(body, client)


@pytest.mark.parametrize("bend", [
    lambda m: m["tool_calls"][0]["function"].__setitem__("name", "get_weather"),
    lambda m: m["tool_calls"][0]["function"].__setitem__("arguments", '{"city":"Oslo"}'),
    lambda m: m["tool_calls"][0]["function"].__setitem__("name", ""),
    lambda m: m.__setitem__("audio", {"data": "plain"}),
])
def test_downgraded_tool_calls_or_audio_are_refused(bend):
    client = e2.ClientKey.generate()
    body = full_response(client.public_hex)
    bend(body["choices"][0]["message"])
    with pytest.raises(e2.E2EEError):
        e2.decrypt_response(body, client)


def test_response_encrypted_to_another_key_or_with_logprobs_is_refused():
    client = e2.ClientKey.generate()
    with pytest.raises(e2.E2EEError, match="does not decrypt"):
        e2.decrypt_response(full_response(e2.ClientKey.generate().public_hex), client)
    body = full_response(client.public_hex)
    body["choices"][0]["logprobs"] = {"content": [{"token": "aa"}]}
    with pytest.raises(e2.E2EEError, match="logprobs"):
        e2.decrypt_response(body, client)
    with pytest.raises(e2.E2EEError, match="no choices"):
        e2.decrypt_response({"id": "x", "choices": []}, client)


def test_available_names_the_package_when_nacl_is_missing(monkeypatch):
    import builtins
    real = builtins.__import__

    def no_nacl(name, *a, **k):
        if name == "nacl" or name.startswith("nacl."):
            raise ImportError("no nacl")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_nacl)
    ok, reason = e2.available()
    assert ok is False and "pynacl==1.6.*" in reason
    with pytest.raises(e2.E2EEError, match="pynacl"):
        e2.seal(MODEL_PUB, b"x")
    with pytest.raises(e2.E2EEError, match="pynacl"):
        e2.ClientKey.generate()

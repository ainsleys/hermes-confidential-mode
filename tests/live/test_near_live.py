"""Live NEAR AI Cloud: skipped unless NEAR_AI_API_KEY is set. Uses the network and spends tokens.

NEAR_LIVE_MODEL picks the model (default Qwen/Qwen3.8-27B, a NEAR-operated vLLM model with attestation).
The key is read from the environment and never printed; assertions name no secret.
"""
from __future__ import annotations

import json
import os

import pytest

KEY = os.environ.get("NEAR_AI_API_KEY", "").strip()
pytestmark = pytest.mark.skipif(not KEY, reason="NEAR_AI_API_KEY not set (live NEAR tests are opt-in)")
MODEL = os.environ.get("NEAR_LIVE_MODEL", "Qwen/Qwen3.8-27B")


def _adapter(tmp_path, **kw):
    from confidential_mode.verify import near
    ad = near.NearAdapter(data_dir=tmp_path, models=[MODEL], signature_wait_seconds=10.0, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    result = ad.verify()
    ad.release()
    return ad, result, rows


@pytest.fixture
def adapter(tmp_path):
    return _adapter(tmp_path)


@pytest.fixture
def plain_adapter(tmp_path):
    return _adapter(tmp_path, encrypt=False)


def _client(ad):
    import openai
    from confidential_mode.verify.near import DEFAULT_BASE_URL
    return openai.OpenAI(api_key=KEY, base_url=DEFAULT_BASE_URL, http_client=ad.sync_http_view(), max_retries=0)


def test_live_attestation_replays_offline(adapter):
    from confidential_mode.verify import replay_near
    _, result, _ = adapter
    assert result.evidence["capture_complete"] is True
    assert replay_near.replay(json.loads(json.dumps(result.evidence))).ok


def test_live_unstreamed_send_is_provider_tee_signed(adapter):
    from confidential_mode.verify import replay_near
    ad, result, rows = adapter
    _client(ad).chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "Reply with ok."}],
                                        max_tokens=8)
    row = rows[-1]
    assert row["detail"]["signature"]["status"] == "fetched", row["detail"]["signature"]
    assert row["decision"] == "provider_tee" and row["verdict"] == "verified", row["detail"]["check"]
    rep = replay_near.replay_signed_send(row["detail"], result.evidence, model=MODEL)
    assert rep["verdict"] == "pass", rep


def test_live_streamed_send_is_signed_and_its_kind_is_recorded(plain_adapter):
    ad, _, rows = plain_adapter
    stream = _client(ad).chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "Reply with ok."}],
                                                 max_tokens=8, stream=True)
    for _ in stream:
        pass
    sig = rows[-1]["detail"]["signature"]
    assert sig["status"] == "fetched", sig
    assert sig["signature_kind"] in ("provider_tee", "gateway")
    assert rows[-1]["detail"]["check"]["signature_valid"] is True, rows[-1]["detail"]["check"]


# ── request encryption (W11) ─────────────────────────────────────────────────────────────────────

def test_live_encrypted_unstreamed_send_is_provider_tee_verified_over_ciphertext_digests(adapter):
    from confidential_mode.verify import replay_near
    ad, result, rows = adapter
    out = _client(ad).chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "Reply with ok."}],
                                              max_tokens=200)
    assert out.choices[0].message.content is not None or getattr(out.choices[0].message, "reasoning_content", None)
    d = rows[-1]["detail"]
    assert d["near_e2ee"] is True and d["e2ee_fields"] == ["messages[].content"] and d["e2ee_version"] == 2
    assert rows[-1]["decision"] == "provider_tee" and rows[-1]["verdict"] == "verified", d["check"]
    assert d["fully_attested"] is True and d["tls_matches_attested"] is True
    assert d["model_pub"] == ad.model_public_key(MODEL)
    assert replay_near.replay_signed_send(d, result.evidence, model=MODEL)["verdict"] == "pass"


def test_live_tool_call_round_trip(adapter):
    ad, _, rows = adapter
    tools = [{"type": "function", "function": {"name": "get_weather", "description": "Current weather for a city",
                                               "parameters": {"type": "object", "properties": {"city": {"type": "string"}},
                                                              "required": ["city"]}}}]
    msgs = [{"role": "user", "content": "What is the weather in Paris? Call the tool."}]
    c = _client(ad)
    first = c.chat.completions.create(model=MODEL, messages=msgs, tools=tools, tool_choice="required", max_tokens=400)
    call = first.choices[0].message.tool_calls[0]
    assert call.function.name == "get_weather" and "paris" in call.function.arguments.lower()
    msgs += [{"role": "assistant", "content": None,
              "tool_calls": [{"id": call.id, "type": "function",
                              "function": {"name": call.function.name, "arguments": call.function.arguments}}]},
             {"role": "tool", "tool_call_id": call.id, "content": '{"temp_c": 18, "sky": "clear"}'}]
    second = c.chat.completions.create(model=MODEL, messages=msgs, tools=tools, max_tokens=400)
    assert second.choices[0].finish_reason in ("stop", "length")
    assert all(r["verdict"] == "verified" and r["detail"]["near_e2ee"] for r in rows[-2:])
    assert "messages[].tool_calls[].function.arguments" in rows[-1]["detail"]["e2ee_fields"]


def test_live_image_part_is_refused_before_sending(adapter):
    from confidential_mode.verify.base import VerifyError
    ad, _, rows = adapter
    before = len(rows)
    img = {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAf"
                                                     "FcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="}}
    with pytest.raises(VerifyError) as ei:
        _client(ad).chat.completions.create(model=MODEL, messages=[{"role": "user", "content": [
            {"type": "text", "text": "Describe"}, img]}], max_tokens=8)
    assert "does not cover image parts" in str(ei.value) and len(rows) == before


def test_live_streaming_is_refused_while_encrypting(adapter):
    from confidential_mode.verify.base import VerifyError
    ad, _, rows = adapter
    before = len(rows)
    with pytest.raises(VerifyError) as ei:
        list(_client(ad).chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "hi"}],
                                                 max_tokens=8, stream=True))
    assert "streaming is refused while encrypting" in str(ei.value) and len(rows) == before

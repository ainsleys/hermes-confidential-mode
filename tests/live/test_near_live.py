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


@pytest.fixture
def adapter(tmp_path):
    from confidential_mode.verify import near
    ad = near.NearAdapter(data_dir=tmp_path, models=[MODEL], signature_wait_seconds=10.0)
    rows: list[dict] = []
    ad.event_sink = rows.append
    result = ad.verify()
    ad.release()
    return ad, result, rows


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


def test_live_streamed_send_is_signed_and_its_kind_is_recorded(adapter):
    ad, _, rows = adapter
    stream = _client(ad).chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "Reply with ok."}],
                                                 max_tokens=8, stream=True)
    for _ in stream:
        pass
    sig = rows[-1]["detail"]["signature"]
    assert sig["status"] == "fetched", sig
    assert sig["signature_kind"] in ("provider_tee", "gateway")
    assert rows[-1]["detail"]["check"]["signature_valid"] is True, rows[-1]["detail"]["check"]

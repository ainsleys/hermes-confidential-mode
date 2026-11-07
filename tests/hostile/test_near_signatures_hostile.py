"""Hostile pass on NEAR's signed-response path: every way a signature can be wrong must end as an
explicitly unverified row live, and as a failed replay from the receipt alone.

Signatures are real ed25519 over the documented payloads (tests/near_world.py); each case bends one
thing: the bytes, the key, the kind label, the payload format, the chat id, or the evidence.
"""
from __future__ import annotations

import copy
import json

import openai
import pytest

from confidential_mode.ledger import Ledger
from confidential_mode.receipts import build_receipt, verify_chain
from confidential_mode.verify import near_checks as nc, replay_near

from ..near_world import BASE, MODEL, NearWorld, fake_quote_verifier, pub_hex

MSG = [{"role": "user", "content": "hi"}]


def _send(world, tmp_path, *, n=1, stream=False, **kw):
    ad = world.adapter(tmp_path, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    result = ad.verify()
    ad.release()
    client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
    for _ in range(n):
        out = client.chat.completions.create(model=MODEL, messages=MSG, stream=stream)
        if stream:
            list(out)
    return ad, result, rows


@pytest.mark.parametrize("mode,reason", [
    ("tamper_response", "does not equal the expected payload"),
    ("wrong_key", "matches no verified model report"),
    ("gateway_as_tee", "does not equal the expected payload"),        # gateway text presented as provider_tee
    ("gateway_text_labelled_tee", "matches no verified model report"),  # tee-format text, gateway key, tee label
    ("tee_text_as_gateway", "does not equal the expected payload"),   # payload-format confusion the other way
    ("absent_kind", "not inferred"),
    ("ecdsa", "is not ed25519"),
    ("bad_signature_bytes", "does not verify"),
])
def test_bent_signatures_are_unverified_live(tmp_path, mode, reason):
    world = NearWorld(sig_mode=mode)
    _, _, rows = _send(world, tmp_path)
    (row,) = rows
    assert row["verdict"] == "unverified" and row["detail"]["fully_attested"] is False
    assert reason in row["detail"]["check"]["reason"], row["detail"]["check"]


def test_signature_replayed_from_another_chat_id_is_unverified(tmp_path):
    world = NearWorld()
    ad, _, rows = _send(world, tmp_path)
    assert rows[0]["verdict"] == "verified"
    world.sig_mode = "other_chat"      # the server answers chat 2's lookup with chat 1's signature
    client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
    client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "another"}])
    assert rows[1]["verdict"] == "unverified"
    assert "does not equal the expected payload" in rows[1]["detail"]["check"]["reason"]


def test_missing_signature_is_explicit(tmp_path):
    world = NearWorld(sig_mode="404")
    _, _, rows = _send(world, tmp_path)
    assert rows[0]["decision"] == "missing" and rows[0]["detail"]["signature"]["status"] == "missing"


def test_two_model_reports_with_one_key_are_ambiguous(tmp_path):
    world = NearWorld()
    world.model_candidates = 2
    _, _, rows = _send(world, tmp_path)
    assert rows[0]["verdict"] == "unverified" and "ambiguous" in rows[0]["detail"]["check"]["reason"]


def test_signature_over_another_model_id_is_unverified():
    world = NearWorld()
    rh, sh = "a" * 64, "b" * 64
    text = f"other/model:{rh}:{sh}"
    sig = {"signature_kind": "provider_tee", "signing_algo": "ed25519", "text": text,
           "signing_address": pub_hex(world.model_key), "signature": world.model_key.sign(text.encode()).hex()}
    c = nc.check_signature(sig, model=MODEL, request_sha256=rh, response_sha256=sh, gateway_signer=None,
                           model_signers=[pub_hex(world.model_key)], require_provider_tee=True)
    assert c["verdict"] == "unverified" and not c["payload_match"]


# ── from the receipt alone ───────────────────────────────────────────────────────────────────────

def _receipt(tmp_path, world, **kw):
    ad, result, rows = _send(world, tmp_path, **kw)
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "detail": {}})
    led.append({"kind": "verify_ok", "provider": "attested-near", "host": result.enclave_host,
                "detail": {"vendor": "near", "evidence": result.evidence,
                           "code_fingerprint": result.code_fingerprint,
                           "enclave_fingerprint": result.enclave_fingerprint}})
    for r in rows:
        led.append({**r, "session_id": "s-near"})
    return json.loads(json.dumps(build_receipt(led, "s-near")))


def _replay(doc):
    return replay_near.replay_receipt(doc, quote_verifier=fake_quote_verifier, ita_roots=NearWorld().ita.roots)


def test_receipt_replays_and_edits_to_digests_or_labels_fail(tmp_path):
    world = NearWorld()
    doc = _receipt(tmp_path, world)
    ok = replay_near.replay_receipt(doc, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert ok["all_pass"] and ok["fully_attested"], ok
    assert verify_chain(doc)

    def bent(fn):
        d = copy.deepcopy(doc)
        row = next(r for r in d["rows"] if r["kind"] == "send_signed")
        fn(row["detail"])
        res = replay_near.replay_receipt(d, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
        return res["sends"][0], verify_chain(d)

    s, chain = bent(lambda d: d.__setitem__("response_sha256", "0" * 64))        # tampered response bytes
    assert s["verdict"] == "fail" and not chain
    s, _ = bent(lambda d: d["signature"].__setitem__("signature_kind", "gateway"))  # relabel the kind
    assert s["verdict"] == "fail"
    s, _ = bent(lambda d: d.__setitem__("attestation_nonce", "00" * 32))          # point at no evidence
    assert s["verdict"] == "fail" and "no NEAR evidence" in s["reason"]
    s, _ = bent(lambda d: d["signature"].__setitem__("signing_address", pub_hex(world.gateway_key)))
    assert s["verdict"] == "fail"


def test_receipt_with_gateway_signatures_says_not_fully_attested(tmp_path):
    world = NearWorld()
    doc = _receipt(tmp_path, world, stream=True)
    assert doc["header"]["near"]["fully_attested"] is False
    assert doc["sections"]["near_sends"][0]["signature_kind"] == "gateway"
    from confidential_mode.receipts import render_text
    assert "SESSION NOT FULLY ATTESTED" in render_text(doc)


def test_receipt_evidence_whose_quote_is_bent_fails_every_send(tmp_path):
    world = NearWorld()
    doc = _receipt(tmp_path, world)
    item = doc["evidence"][0]["evidence"]
    item["model_reports"][MODEL][0]["signing_address"] = pub_hex(world.gateway_key)
    res = replay_near.replay_receipt(doc, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert not res["all_pass"] and "does not replay" in res["sends"][0]["reason"]

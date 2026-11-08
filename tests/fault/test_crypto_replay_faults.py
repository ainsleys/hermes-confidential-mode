"""Fault class 5, encryption and replay: PyNaCl failing to import after the lock, the model key in the
accepted appraisal changed in memory, the client key not generated, encrypt_request meeting a malformed
message, a reply that decrypts nowhere after its signature verified; and a receipt edited in one byte at every
field class (digests, signatures, signing keys, evidence, blobs, row hashes, chain head, trust-root digest,
caveats), with replay's verdict on each.

The vendor is tests/near_world.py (real ed25519, real E2EE, test quotes); the offline verifier for real
Intel quotes runs on the 2026-11-07 capture in tests/fixtures. The receipt renderer, verify_chain, replay_near
and `hermes confidential replay` are the real ones.
"""
from __future__ import annotations

import argparse
import copy
import io
import json
import sys

import openai
import pytest

from confidential_mode import commands
from confidential_mode.ledger import Ledger
from confidential_mode.receipts import build_receipt, verify_chain
from confidential_mode.verify import near_e2ee as e2, replay_near
from confidential_mode.verify.base import VerifyError

from ..near_world import BASE, MODEL, NearWorld, fake_quote_verifier

SECRET = "PLAINTEXT-SECRET-PROMPT"
MSG = [{"role": "user", "content": SECRET}]


def _setup(world, tmp_path, **kw):
    ad = world.adapter(tmp_path, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    result = ad.verify()
    ad.release()
    client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
    return ad, client, rows, result


def _cause(exc_info) -> BaseException:
    e = exc_info.value
    return e.__cause__ if isinstance(e, openai.APIConnectionError) and e.__cause__ is not None else e


def _nothing_left(world):
    return world.chat_posts() == 0 and world.chat_bodies == []


def _refused_rows(rows):
    return [r for r in rows if r["kind"] == "send_refused"]


# ── encryption faults ────────────────────────────────────────────────────────────────────────────

def test_pynacl_failing_to_import_after_the_lock_refuses_before_sending(tmp_path, monkeypatch):
    """Amendment 5.1: the transport encrypts every chat POST; "Every NearRefusal the views raise, before sending
    ... gets one send_refused row". Fault: the nacl package stops importing after the verification (a venv
    change under a running gateway)."""
    world = NearWorld()
    _, client, rows, _ = _setup(world, tmp_path)
    for name in [n for n in list(sys.modules) if n == "nacl" or n.startswith("nacl.")] or ["nacl"]:
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(Exception) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert isinstance(_cause(ei), VerifyError)
    assert _nothing_left(world)
    (ref,) = _refused_rows(rows)
    assert ref["detail"]["reason_code"] == "near_refused_before_send"


@pytest.mark.parametrize("bend", ["another_valid_key", "not_hex", "two_keys", "no_key"])
def test_a_model_key_changed_in_the_appraisal_never_puts_plaintext_on_the_wire(tmp_path, bend):
    """Amendment 5.1: requests are sealed to "the one verified Ed25519 key of model"; model_public_key refuses
    unless exactly one key is there. Fault: the accepted appraisal's key list is changed in memory after the
    verify (LIMITATIONS 6: the process is the trust boundary, so this checks only that no plaintext leaves and
    nothing unauthenticated comes back)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ..near_world import pub_hex
    world = NearWorld()
    ad, client, rows, _ = _setup(world, tmp_path)
    signers = ad._appraisal.model_signers
    signers[MODEL] = {"another_valid_key": [pub_hex(Ed25519PrivateKey.generate())], "not_hex": ["zz" * 32],
                      "two_keys": [signers[MODEL][0], pub_hex(Ed25519PrivateKey.generate())], "no_key": []}[bend]
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == []
    assert all(SECRET.encode() not in b for b in world.chat_bodies)
    assert world.decrypted_requests == []
    assert all(r["detail"].get("reply_released") is not True for r in rows)
    assert _refused_rows(rows)


def test_a_client_key_that_cannot_be_generated_refuses_before_sending(tmp_path, monkeypatch):
    """near.py: an exception while encrypting is "NEAR request refused before sending: encryption failed";
    Amendment 5.1: such a refusal gets one send_refused row."""
    world = NearWorld()
    _, client, rows, _ = _setup(world, tmp_path)

    def no_key(cls):
        raise OSError("getrandom failed")
    monkeypatch.setattr(e2.ClientKey, "generate", classmethod(no_key))
    with pytest.raises(Exception) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "encryption failed" in str(_cause(ei)) and _nothing_left(world)
    assert _refused_rows(rows)[0]["detail"]["reason_code"] == "near_refused_before_send"


@pytest.mark.parametrize("messages", [
    [{"role": "user", "content": 12345}],
    [{"role": "user", "content": {"secret": SECRET}}],
    [{"role": "user", "content": [SECRET]}],
    [{"role": "user", "content": [{"type": "text"}]}],
    [{"role": "user", "content": [{"type": "text", "text": SECRET, "extra": SECRET}]}],
    [{"role": "user", "content": [{"type": "audio", "data": SECRET}]}],
    ["not a message " + SECRET],
    [{"role": "user", "content": SECRET, "name": {"nested": SECRET}}],
])
def test_a_malformed_message_is_refused_before_sending_and_never_leaves_in_plaintext(tmp_path, messages):
    """Amendment 5.1: "non-text content parts, top-level keys ... that carry text ... raise VerifyError before
    sending"; Amendment 9: "Any other part type ... or an extra field is refused with the type named". Fault:
    shapes Hermes should never build, sent straight through the view."""
    world = NearWorld()
    _, client, rows, _ = _setup(world, tmp_path)
    try:
        client.chat.completions.create(model=MODEL, messages=messages)
    except Exception as exc:  # noqa: BLE001
        cause = exc.__cause__ if isinstance(exc, openai.APIConnectionError) and exc.__cause__ else exc
        assert isinstance(cause, (VerifyError, openai.APIStatusError, TypeError)), repr(exc)
    for body in world.chat_bodies:
        assert SECRET.encode() not in body, "plaintext left the host"


def test_a_reply_that_fails_to_decrypt_after_its_signature_verified_is_withheld(tmp_path):
    """Amendment 5.1: "Only one outcome hands a body over: HTTP 200, a fully_attested send, and a body that
    decrypts under the exchange's key"; "a withheld reply is unverified and not fully_attested even when its
    signature verified". Fault: the ciphertext is bent before it is signed, so the signature verifies."""
    world = NearWorld()
    world.e2ee_mode = "tamper"
    _, client, rows, _ = _setup(world, tmp_path)
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == []
    (row,) = [r for r in rows if r["kind"] == "send_signed"]
    d = row["detail"]
    assert d["signature"]["status"] == "fetched"
    assert d["reply_released"] is False and d["withheld_reason"]
    assert row["verdict"] == "unverified" and d["fully_attested"] is False
    assert d["check"]["reason"].startswith("reply withheld after the signature check")


# ── a receipt edited in one byte ─────────────────────────────────────────────────────────────────

def _near_receipt(tmp_path, *, encrypt=True, stream=False):
    world = NearWorld()
    _, client, rows, result = _setup(world, tmp_path, encrypt=encrypt)
    out = client.chat.completions.create(model=MODEL, messages=MSG, stream=stream)
    if stream:
        list(out)
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "detail": {}})
    led.append({"kind": "verify_ok", "provider": "attested-near", "host": result.enclave_host,
                "detail": {"vendor": "near", "evidence": result.evidence,
                           "code_fingerprint": result.code_fingerprint,
                           "enclave_fingerprint": result.enclave_fingerprint}})
    for r in rows:
        led.append({**r, "session_id": "s-near"})
    return world, json.loads(json.dumps(build_receipt(led, "s-near")))


def _flip(s: str, at: int = -1) -> str:
    """Change one character of a hex or text string (the one-byte edit)."""
    i = at % len(s)
    c = s[i]
    new = "0" if c != "0" else "1"
    return s[:i] + new + s[i + 1:]


def _signed(doc):
    return next(r for r in doc["rows"] if r["kind"] == "send_signed")


def _ev(doc):
    return doc["evidence"][0]["evidence"]


def _edit_blob(d, ref):
    blobs = d["evidence"][0]["blobs"]
    blobs[ref] = _flip(blobs[ref], len(blobs[ref]) // 2)


EDITS = {
    "request_digest": lambda d: _signed(d)["detail"].__setitem__("request_sha256", _flip(_signed(d)["detail"]["request_sha256"])),
    "response_digest": lambda d: _signed(d)["detail"].__setitem__("response_sha256", _flip(_signed(d)["detail"]["response_sha256"], 0)),
    "signature_bytes": lambda d: _signed(d)["detail"]["signature"].__setitem__(
        "signature_hex", _flip(_signed(d)["detail"]["signature"]["signature_hex"], 5)),
    "signing_key": lambda d: _signed(d)["detail"]["signature"].__setitem__(
        "signing_address", _flip(_signed(d)["detail"]["signature"]["signing_address"])),
    "signed_text": lambda d: _signed(d)["detail"]["signature"].__setitem__(
        "text", _flip(_signed(d)["detail"]["signature"]["text"])),
    "attestation_nonce": lambda d: _signed(d)["detail"].__setitem__("attestation_nonce", _flip(_signed(d)["detail"]["attestation_nonce"])),
    "evidence_nonce": lambda d: _ev(d).__setitem__("nonce", _flip(_ev(d)["nonce"])),
    "evidence_gateway_signer": lambda d: _ev(d)["gateway"].__setitem__(
        "signing_address", _flip(_ev(d)["gateway"]["signing_address"])),
    "evidence_model_signer": lambda d: _ev(d)["model_reports"][MODEL][0].__setitem__(
        "signing_address", _flip(_ev(d)["model_reports"][MODEL][0]["signing_address"])),
    "evidence_report_data": lambda d: _ev(d)["gateway"].__setitem__(
        "report_data", _flip(_ev(d)["gateway"]["report_data"], 3)),
    "evidence_quote_blob": lambda d: _edit_blob(d, _ev(d)["model_reports"][MODEL][0]["intel_quote_b64"]["$blob"]),
    "evidence_compose_blob": lambda d: _edit_blob(d, _ev(d)["model_reports"][MODEL][0]["compose_manager"]["blob"]),
}


@pytest.mark.parametrize("field", sorted(EDITS))
def test_a_one_byte_edit_to_a_signed_send_or_its_evidence_fails_the_replay_and_the_chain(tmp_path, field):
    """Amendment 5: "hermes confidential replay replays NEAR evidence ... and every send_signed row ... any
    failed signature makes the exit code 1"; receipts.verify_chain: "True iff the rows' hash chain recomputes
    ... every evidence blob equals its row's". Fault: one character changed in one field."""
    world, doc = _near_receipt(tmp_path)
    ok = replay_near.replay_receipt(doc, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert ok["all_pass"] and ok["fully_attested"] and verify_chain(doc)        # the control
    bad = copy.deepcopy(doc)
    EDITS[field](bad)
    res = replay_near.replay_receipt(bad, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert res["all_pass"] is False and res["fully_attested"] is False, res
    assert res["sends"][0]["verdict"] == "fail"
    assert verify_chain(bad) is False


CHAIN_EDITS = {
    "row_hash": lambda d: d["rows"][1].__setitem__("hash", _flip(d["rows"][1]["hash"])),
    "chain_head": lambda d: d["header"].__setitem__("chain_head", _flip(d["header"]["chain_head"])),
    "row_count": lambda d: d["header"].__setitem__("row_count", d["header"]["row_count"] + 1),
    "trust_roots_digest": lambda d: d["header"].__setitem__("trust_roots_sha256", _flip(d["header"]["trust_roots_sha256"])),
    "closing": lambda d: d.__setitem__("closing", d["closing"][:-1] + "!"),
    "near_closing": lambda d: d.__setitem__("near_closing", d["near_closing"][:-1] + "!"),
    "encryption_note_edited": lambda d: d.__setitem__("near_encryption_note", d["near_encryption_note"][:-1] + "!"),
    "encryption_note_stripped": lambda d: d.pop("near_encryption_note"),
    "row_kind": lambda d: _signed(d).__setitem__("kind", "send_observed"),
    "row_verdict": lambda d: _signed(d).__setitem__("verdict", "verified!"),
    "row_dropped": lambda d: d["rows"].remove(_signed(d)),
    "genesis": lambda d: d["header"].__setitem__("chain_genesis", _flip(d["header"]["chain_genesis"])),
}


@pytest.mark.parametrize("field", sorted(CHAIN_EDITS))
def test_a_one_byte_edit_to_the_chain_or_a_caveat_breaks_verify_chain(tmp_path, field):
    """receipts.verify_chain: "True iff the rows' hash chain recomputes, the header head matches it, ... the trust
    roots match their digest, and the closing paragraph is the constant"; Amendment 5.1: "verify_chain fails a
    receipt that holds an encrypted send without" near_encryption_note."""
    _, doc = _near_receipt(tmp_path)
    assert verify_chain(doc)
    bad = copy.deepcopy(doc)
    CHAIN_EDITS[field](bad)
    assert verify_chain(bad) is False


def test_an_edited_summary_header_is_outside_the_chain_and_replay_still_tells_the_truth(tmp_path):
    """receipts: the chain is "a checksum over this document that anyone holding the file can recompute"; the
    verdict is the replay's. Fault: header.near.fully_attested flipped to true on a gateway-signed (streamed,
    unencrypted) receipt. verify_chain does not cover the header summary; replay recomputes from the rows."""
    world, doc = _near_receipt(tmp_path, encrypt=False, stream=True)
    assert doc["header"]["near"]["fully_attested"] is False
    bad = copy.deepcopy(doc)
    bad["header"]["near"]["fully_attested"] = True
    bad["header"]["near"]["not_fully_attested_sends"] = []
    assert verify_chain(bad) is True                    # documented: the summary is not chained
    res = replay_near.replay_receipt(bad, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert res["fully_attested"] is False and res["sends"][0]["provider_tee"] is False


def _cli_replay(path) -> tuple[int, str]:
    out = io.StringIO()
    code = commands.cli_replay(argparse.Namespace(receipt=str(path), expected_fingerprints=None, pins=None,
                                                  expected_repo=None, trusted_root=None, as_of=None), out=out)
    return code, out.getvalue()


@pytest.mark.parametrize("edit", ["blob_byte", "quote_byte", "row_hash", "truncated_file", "not_json"])
def test_hermes_confidential_replay_exits_1_on_a_one_byte_edit_of_a_real_capture_receipt(tmp_path, edit):
    """Amendment 6 finding 10: "hermes confidential replay exits 1 when the hash chain is broken or cannot be
    checked, whatever the evidence rows say"; Amendment 5.2: verify_chain "fails an item whose blobs holds ...
    bytes that are not its id". Real 2026-11-07 capture, real Intel quote verifier, offline."""
    pytest.importorskip("tinfoil.attestation.verify_tdx")
    from ..unit import test_near_real_capture as real
    from ..unit.test_near_evidence_blobs import _receipt, _verified_evidence
    _, doc = _receipt(tmp_path, _verified_evidence(real.evidence()))
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(doc))
    code, text = _cli_replay(path)
    assert code == 0 and "hash chain intact" in text, text                     # the control
    bad = copy.deepcopy(doc)
    item = bad["evidence"][0]
    if edit == "blob_byte":
        ref = sorted(item["blobs"])[0]
        item["blobs"][ref] = _flip(item["blobs"][ref], len(item["blobs"][ref]) // 2)
    elif edit == "quote_byte":
        q = item["evidence"]["gateway"]
        key = "intel_quote_b64" if "intel_quote_b64" in q else next(k for k in q if "quote" in k)
        if isinstance(q[key], dict):                      # {"$blob": id}: edit the blob it names
            ref = q[key]["$blob"]
            item["blobs"][ref] = _flip(item["blobs"][ref], 40)
        else:
            q[key] = _flip(q[key], 40)
    elif edit == "row_hash":
        bad["rows"][0]["hash"] = _flip(bad["rows"][0]["hash"])
    text_out = json.dumps(bad)
    if edit == "truncated_file":
        text_out = json.dumps(doc)[: len(json.dumps(doc)) // 2]
    elif edit == "not_json":
        text_out = "\x00\x01 not a receipt"
    path.write_text(text_out)
    code, text = _cli_replay(path)
    if edit in ("truncated_file", "not_json"):
        assert code != 0 and text.startswith("Cannot read receipt"), (code, text)   # usage-class exit (2)
    else:
        assert code == 1 and "BROKEN" in text, text

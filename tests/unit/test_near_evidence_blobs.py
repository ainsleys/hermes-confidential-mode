"""NEAR evidence blobs: the ledger keeps a verify_ok row small, the receipt embeds what the row references,
and receipts of either evidence schema replay offline (real 2026-11-07 captures, real Intel verifiers)."""
from __future__ import annotations

import argparse
import copy
import io
import json

import pytest

pytest.importorskip("tinfoil.attestation.verify_tdx")

from confidential_mode import commands  # noqa: E402
from confidential_mode.ledger import MAX_DETAIL_BYTES, BlobStore, Ledger, LedgerError  # noqa: E402
from confidential_mode.receipts import build_receipt, verify_chain  # noqa: E402
from confidential_mode.verify import near, near_checks as nc, replay_near  # noqa: E402

from . import test_near_real_capture as real  # noqa: E402

MODELS = (real.MODEL, "zai-org/GLM-5.3-Flash", "deepseek-ai/DeepSeek-V4.1")


def _verified_evidence(ev: dict) -> dict:
    """What NearAdapter.verify() hands the ledger: the evidence plus checks, policy, claims and repo."""
    a = near.appraise(ev)
    ev = dict(ev)
    ev["checks"] = a.checks
    ev["policy"] = {"require_tls_binding": True, "require_provider_tee": True, "accepted_tcb_statuses": ["UpToDate"]}
    ev["claims"] = near.evidence_claims(ev, a)
    ev["repo"] = a.identity
    return ev


def _row(ev: dict, session: str = "s") -> dict:
    return {"kind": "verify_ok", "provider": "attested-near", "host": "cloud-api.near.ai", "session_id": session,
            "detail": {"vendor": "near", "evidence": ev, "code_fingerprint": (ev.get("claims") or {}).get("code_fingerprint"),
                       "enclave_fingerprint": (ev.get("claims") or {}).get("enclave_fingerprint")}}


def _size(value) -> int:
    return len(json.dumps(value, sort_keys=True, default=str).encode("utf-8"))


def test_the_ledger_moves_evidence_blobs_to_the_store_and_keeps_their_ids(tmp_path):
    ev = _verified_evidence(real.evidence())
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append(_row(ev))
    stored = led.tail()[0].detail["evidence"]
    assert "blobs" not in stored and stored["blob_refs"] == sorted(ev["blobs"])
    store = tmp_path / "evidence" / "blobs"
    assert sorted(p.name for p in store.iterdir()) == stored["blob_refs"]
    assert all(led.blob(b) == ev["blobs"][b] for b in stored["blob_refs"])
    assert _size(stored) < 32 * 1024 < _size(ev), (_size(stored), _size(ev))
    assert "blobs" in ev   # the in-memory evidence is not changed


def _worst_case() -> dict:
    """Three allowlisted models, two candidates each, every candidate with its own 86-action log (the
    longest seen) and its own app_compose; two of the models have no prompt-path rule, so their claims
    carry the whole 46-service map."""
    big = real.GPU13["candidate"]
    models = {}
    for k, name in enumerate(MODELS):
        cands = []
        for i in range(2):
            c = copy.deepcopy(big)
            c["model_name"] = name
            c["compose_manager_attestation"]["actions"].append({"action": "docker_restart", "timestamp": f"{k}{i}"})
            c["info"]["tcb_info"]["app_compose"] += " " * (2 * k + i + 1)
            cands.append(c)
        models[name] = {"model_attestations": cands}
    ev = real.evidence(models=models)
    one = near.appraise(real.evidence())
    state, images = nc.deployment_map(big["compose_manager_attestation"]["actions"])
    cvms = [dict(one.cvms[0])]
    for name in MODELS:
        for i in range(2):
            svc, scope = nc.prompt_path(state, name)
            cm = {"services": svc, "services_scope": scope, "cm_image_running": nc.image_ref(images[-1]),
                  "cm_image_measured": real.CM_MEASURED}
            cvms.append(near._cvm(f"model:{name}", {"compose_hash": "ab" * 32}, one.cvms[1], cm))
    ev["checks"] = one.checks
    ev["policy"] = {"require_tls_binding": True, "require_provider_tee": True, "accepted_tcb_statuses": ["UpToDate"]}
    ev["claims"] = {**near.evidence_claims(ev, one), "cvms": cvms,
                    "components": list(one.components[:2]) + [ln for c in cvms for ln in near._cvm_lines(c)]}
    return ev


def test_worst_case_evidence_row_stays_under_the_ledger_cap(tmp_path):
    ev = _worst_case()
    inline = _size({"vendor": "near", "evidence": ev})
    assert inline > MAX_DETAIL_BYTES, inline        # what the row would be without the store
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append(_row(ev))
    stored = _size(led.tail()[0].detail)
    assert stored < MAX_DETAIL_BYTES * 0.6, (inline, stored)
    assert len(led.tail()[0].detail["evidence"]["blob_refs"]) == len(ev["blobs"]) >= 13


def test_the_content_key_scan_covers_the_compose_manager_block(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append(_row(_verified_evidence(real.evidence())))          # the real block passes the scan
    raw = copy.deepcopy(real.RAW)
    real._cm(raw)["actions"][1]["content"] = "a prompt-shaped key"
    with pytest.raises(LedgerError, match="content-shaped"):
        led.append(_row(real.evidence(raw)))


def test_a_blob_that_does_not_hash_to_its_id_is_refused(tmp_path):
    ev = real.evidence()
    bad = dict(ev, blobs={**ev["blobs"], "00" * 32: "x"})
    with pytest.raises(LedgerError, match="hash to its id"):
        Ledger(tmp_path / "ledger.sqlite").append(_row(bad))
    store = BlobStore(tmp_path / "b")
    with pytest.raises(LedgerError):
        store.put("00" * 32, "x")
    assert store.get("../ledger") is None and store.get("00" * 32) is None


def _receipt(tmp_path, ev: dict, name: str = "ledger.sqlite") -> tuple[Ledger, dict]:
    led = Ledger(tmp_path / name)
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "session_id": "s", "detail": {}})
    led.append(_row(ev))
    return led, json.loads(json.dumps(build_receipt(led, "s")))


def test_the_receipt_embeds_every_referenced_blob_and_replays_offline(tmp_path):
    ev = _verified_evidence(real.evidence())
    _, doc = _receipt(tmp_path, ev)
    assert verify_chain(doc)
    item = doc["evidence"][0]
    assert sorted(item["blobs"]) == item["evidence"]["blob_refs"] and "blobs_missing" not in item
    r = replay_near.replay(replay_near.with_blobs(item["evidence"], item["blobs"]))
    assert r.ok, r.checks
    assert r.checks["cm_actions_hash"] is True and r.checks["cm_image"].startswith("recorded")
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(doc))
    out = io.StringIO()
    code = commands.cli_replay(argparse.Namespace(receipt=str(path), expected_fingerprints=None, pins=None,
                                                  expected_repo=None, trusted_root=None, as_of=None), out=out)
    text = out.getvalue()
    assert "cm_same_td: pass" in text and "cm_image: recorded (not a pass)" in text
    assert "1/1 evidence row(s) replayed OK" in text and code == 0, text
    for line in replay_near.NOT_ESTABLISHED:
        assert f"  - {line}\n" in text


def test_an_edited_embedded_blob_breaks_the_chain_and_a_missing_one_fails_the_replay(tmp_path):
    ev = _verified_evidence(real.evidence())
    led, doc = _receipt(tmp_path, ev)
    ref = ev["model_reports"][real.MODEL][0]["compose_manager"]["blob"]
    bad = copy.deepcopy(doc)
    bad["evidence"][0]["blobs"][ref] = bad["evidence"][0]["blobs"][ref].replace("compose_up", "compose_down", 1)
    assert not verify_chain(bad)
    (tmp_path / "evidence" / "blobs" / ref).write_text("not the block")
    doc2 = json.loads(json.dumps(build_receipt(led, "s")))
    item = doc2["evidence"][0]
    assert verify_chain(doc2) and item["blobs_missing"] == [ref]
    r = replay_near.replay(replay_near.with_blobs(item["evidence"], item["blobs"]))
    assert not r.ok and "blob is missing or does not hash to its id" in r.checks["cm_quote"]


def test_an_old_v1_receipt_still_replays_under_v1_rules(tmp_path):
    _, doc = _receipt(tmp_path, copy.deepcopy(real.V1))
    assert verify_chain(doc) and "blobs" not in doc["evidence"][0]
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(doc))
    out = io.StringIO()
    code = commands.cli_replay(argparse.Namespace(
        receipt=str(path), expected_fingerprints=f"{real.V1_CODE_FP}:{real.V1_ENCLAVE_FP}", pins=None,
        expected_repo=None, trusted_root=None, as_of=None), out=out)
    text = out.getvalue()
    assert code == 0 and "1/1 evidence row(s) replayed OK" in text, text
    assert f"cm_quote: {near.CM_NOT_RUN_V1}" in text
    assert "NEAR's compose_manager_attestation is not checked here" in text
    assert "The compose-manager check establishes only" not in text

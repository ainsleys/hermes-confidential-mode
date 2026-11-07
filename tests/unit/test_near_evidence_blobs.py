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


def _worst_case(tmp_path):
    """Six allowlisted models, none with a service name list, two candidates each, every candidate with the
    longest real actions log seen (86 actions, 46 services): claims from the adapter's own verify()."""
    from tests.near_world import NearWorld
    names = [f"vendor/model-{i}" for i in range(6)]
    world = NearWorld(models=names)
    world.model_candidates = 2
    world.cm_actions = copy.deepcopy(real.GPU13["candidate"]["compose_manager_attestation"]["actions"])
    return world.adapter(tmp_path / "adapter", encrypt=False).verify().evidence


def test_worst_case_evidence_row_stays_under_the_ledger_cap(tmp_path):
    ev = _worst_case(tmp_path)
    assert len(ev["claims"]["cvms"]) == 13 and all(
        set(c["services"]) == {"$blob"} for c in ev["claims"]["cvms"][1:])     # maps live in the blobs
    inline = _size({"vendor": "near", "evidence": ev})
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append(_row(ev))
    stored = _size(led.tail()[0].detail)
    assert stored < MAX_DETAIL_BYTES * 0.5 < inline, (inline, stored)


def test_a_row_refused_for_its_size_leaves_no_blob_behind(tmp_path):
    ev = dict(real.evidence(), padding="x" * (MAX_DETAIL_BYTES + 1))
    led = Ledger(tmp_path / "ledger.sqlite")
    with pytest.raises(LedgerError, match="size cap"):
        led.append(_row(ev))
    assert not (tmp_path / "evidence" / "blobs").exists() or not list((tmp_path / "evidence" / "blobs").iterdir())


def test_unreferenced_blobs_are_deleted_after_the_retention_period(tmp_path):
    import os
    import time
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append(_row(_verified_evidence(real.evidence())))
    store = led.blobs
    store.put("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "")   # an orphan
    kept = set(led.tail()[0].detail["evidence"]["blob_refs"])
    assert led.gc_blobs() == []                                  # too young
    old = time.time() - 2 * 24 * 3600
    for f in store.root.iterdir():
        os.utime(f, (old, old))
    assert led.gc_blobs() == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    assert {f.name for f in store.root.iterdir()} == kept       # every referenced blob stays


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
    assert "cm_same_td: pass" in text and "cm_image: recorded (not a pass; " in text
    assert "schema: confidential-mode/near-evidence/v2" in text
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


def test_a_mixed_v1_and_v2_receipt_prints_every_rows_caveats(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "session_id": "s", "detail": {}})
    led.append(_row(_verified_evidence(real.evidence())))
    led.append(_row(copy.deepcopy(real.V1)))
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(build_receipt(led, "s")))
    out = io.StringIO()
    commands.cli_replay(argparse.Namespace(receipt=str(path), expected_fingerprints=None, pins=None,
                                           expected_repo=None, trusted_root=None, as_of=None), out=out)
    text = out.getvalue()
    assert "schema: confidential-mode/near-evidence/v1" in text and "schema: confidential-mode/near-evidence/v2" in text
    for line in set(replay_near.NOT_ESTABLISHED) | set(replay_near.NOT_ESTABLISHED_V1):
        assert f"  - {line}\n" in text


def test_putting_an_existing_blob_refreshes_its_modified_time(tmp_path):
    import os
    import time
    store = BlobStore(tmp_path / "b")
    blob = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert store.put(blob, "") is True
    old = time.time() - 2 * 24 * 3600
    os.utime(store.root / blob, (old, old))
    assert store.put(blob, "") is False
    assert (store.root / blob).stat().st_mtime > old + 24 * 3600
    assert store.gc(set()) == []          # young again: another process's cleanup leaves it

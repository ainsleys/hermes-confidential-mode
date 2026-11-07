"""Real NEAR AI Cloud captures (public endpoints, no API key, 2026-11-07) replay offline.

tests/fixtures/near_real_capture/ (see each file's _note):
- raw_public_responses.json: the gateway report, one Qwen/Qwen3.8-27B model report (instance 577bdf69)
  with its compose_manager_attestation, Intel Trust Authority's tokens and Intel's JWKS.
- model_candidate_gpu13.json: one model candidate of another instance (a8a25faa), whose actions log holds
  86 actions deployed one service at a time.
- evidence_v1.json: schema v1 evidence as the plugin at 9af0c9e stored it (no compose-manager block).
The real verifiers run: tinfoil 0.14.2's TDX quote verifier against the Intel SGX root, and the PS384 JWTs
against the JWKS whose x5c chain ends at the pinned Intel Trust Authority root.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("tinfoil.attestation.verify_tdx")

from confidential_mode.verify import near, near_checks as nc, replay_near  # noqa: E402

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "near_real_capture"
RAW = json.loads((FIX / "raw_public_responses.json").read_text())
GPU13 = json.loads((FIX / "model_candidate_gpu13.json").read_text())
V1 = json.loads((FIX / "evidence_v1.json").read_text())["evidence"]
MODEL = "Qwen/Qwen3.8-27B"
CODE_FP = "2e7d4ed64e11370b39dd90a802f2fbf1982f0047f5406f12040c598b4dea60ac"   # v2: compose hashes + RTMR3 identity
ENCLAVE_FP = "7b70f47f48848bb33537f916e67288d17d944eb945d579049b5b41cc1ed1df41"
V1_CODE_FP = "111f9bf87dc011150753990dfbeae4bbeac9a5b603559055d23947edc663bc7b"
V1_ENCLAVE_FP = "ce1f0519a96cbd217d59cd065e1f60698075576fb52338523779f5a5665f437d"
CM_MEASURED = "nearaidev/compose-manager@sha256:a320bb4882341c8e19ef1944436f6591ed73303732009ed5db9f6db6c9da756a"
CM_RUNNING = "nearaidev/compose-manager@sha256:a0c073085684e12e19f31bb279fc8da663a374199bfecc47b04167ae79eaa766"

F = "prod/qwen38-27b-abliterated-cc-1gpu.yaml"
C535 = ("v0.0.535", "37c5be809501b222d81d1a4736e466dcc4242ee9", "81d8c1265b5132c716a8a78c47fa78ce5f1a2a6fcd0170079c85fcba9c80b832")
C539 = ("v0.0.539", "cab4087076ad5321f3c2413627d30af455eb3cb6", "815dd63f872e42066ba4f7ff0e5dacb0947d6d8de09c5821675e11c8b54d6102")
C540 = ("v0.0.540", "75d31e6461dc51465a81ff69203200a51a820d1c", "cd58c977f2fbb98e4a242fe83a5d2911355b78247c3dac875012534adc1e49d4")


def _entry(file, service, c):
    return {"file": file, "service": service, "tag": c[0], "commit": c[1], "file_sha256": c[2]}


# Derived by hand from the fixture's ten actions: the whole file at v0.0.535; engine, both proxies, nginx,
# both registrars and otelcol at v0.0.539 one by one; a compose_stage at v0.0.540 (no change); then both
# proxies and nginx up at v0.0.540; two compose_manager_started entries (a320bb48, then a0c07308).
HAND_MAP = {
    f"{F}::*": _entry(F, "*", C535),
    f"{F}::model-sg-qwen38-27b-fp8-tp1-lora": _entry(F, "model-sg-qwen38-27b-fp8-tp1-lora", C539),
    f"{F}::proxy-qwen38-27b": _entry(F, "proxy-qwen38-27b", C540),
    f"{F}::proxy-qwen38-27b-abliterated": _entry(F, "proxy-qwen38-27b-abliterated", C540),
    f"{F}::nginx-qwen38": _entry(F, "nginx-qwen38", C540),
    f"{F}::qwen38-registrar": _entry(F, "qwen38-registrar", C539),
    f"{F}::qwen38-abliterated-registrar": _entry(F, "qwen38-abliterated-registrar", C539),
    f"{F}::otelcol-contrib": _entry(F, "otelcol-contrib", C539),
}
# Listed first in the prompt: the whole-file deployment and the services the Qwen3.8 name list names.
HAND_FIRST = [f"{F}::*", f"{F}::model-sg-qwen38-27b-fp8-tp1-lora", f"{F}::nginx-qwen38", f"{F}::proxy-qwen38-27b",
              f"{F}::qwen38-registrar"]


def _spki_of_report_cert(raw=RAW) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as s
    cert = x509.load_pem_x509_certificate(raw["gateway_report"]["tls_certificate"].encode())
    return hashlib.sha256(cert.public_key().public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def evidence(raw=RAW, models=None) -> dict:
    model = raw["model"]
    reports = models or {model: raw["model_report"]}
    return near.build_evidence(
        {"gateway_report": raw["gateway_report"], "model_reports": reports,
         "ita": {m: raw["ita_model"] for m in reports}, "jwks": raw["jwks"], "jwks_url_fetched": nc.ITA_JWKS_URLS[0]},
        base_url=near.DEFAULT_BASE_URL, models=sorted(reports), nonce=raw["nonce"],
        captured_at_unix=raw["captured_at_unix"],
        tls_observation={"captured": True, "spki_sha256": _spki_of_report_cert(raw)})


def _cand(raw):
    return raw["model_report"]["model_attestations"][0]


def _cm(raw):
    return _cand(raw)["compose_manager_attestation"]


def test_real_capture_appraises_with_real_intel_signatures():
    ev = evidence()
    assert ev["capture_complete"] is True and ev["schema"] == near.EVIDENCE_SCHEMA
    a = near.appraise(ev)
    assert a.ok, a.checks
    assert all(a.checks[k] is True for k in near.CHECK_KEYS if k not in near.INFORMATIONAL_CHECKS), a.checks
    assert a.identity == "cloud-api.near.ai#Qwen/Qwen3.8-27B"
    assert (a.code_fingerprint, a.enclave_fingerprint) == (CODE_FP, ENCLAVE_FP)
    assert a.tcb_status == "UpToDate"
    assert a.gateway_signer == "40599fb284f43953bb356b09080fd803c960fc10285ad90eca462ca711ad4acb"
    assert a.model_signers == {MODEL: ["89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93"]}
    assert "GPU verdict True" in a.checks["ita_model_tokens"]


def test_real_capture_per_cvm_identity_comes_from_rtmr3():
    a = near.appraise(evidence())
    gw, m = a.cvms
    assert gw["role"] == "gateway" and m["role"] == f"model:{MODEL}"
    assert m["app_id"] == "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"
    assert m["instance_id"] == "577bdf69bcef417e61c22e70d798088fcf23ec5a"
    assert m["os_image_hash"] == "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829"
    kid = json.loads(_cand(RAW)["info"]["key_provider_info"])["id"]
    assert m["kms_id"] == hashlib.sha256(bytes.fromhex(kid)).hexdigest() == gw["kms_id"]   # one KMS for both
    assert gw["services"] is None and gw["cm_image_reported"] is None


def test_real_capture_per_service_map_matches_the_hand_derived_map():
    state, images = nc.deployment_map(_cm(RAW)["actions"])
    assert state == HAND_MAP
    assert [nc.image_ref(i) for i in images] == [CM_MEASURED, CM_RUNNING]
    m = near.appraise(evidence()).cvms[1]
    assert m["services"] == HAND_MAP                       # the component is the whole map
    assert m["services_sha256"] == nc.services_sha256(HAND_MAP)
    assert m["services_first"] == HAND_FIRST and "name list" in m["services_scope"]


def test_real_capture_records_the_image_mismatch_as_a_component_never_a_pass():
    a = near.appraise(evidence())
    m = a.cvms[1]
    assert (m["cm_image_reported"], m["cm_image_measured"]) == (CM_RUNNING, CM_MEASURED)
    assert a.checks["cm_image"].startswith("recorded (not a pass") and "cm_image" in near.INFORMATIONAL_CHECKS
    line = next(c for c in a.components if "compose-manager image reported by the log" in c)
    assert line.startswith("reported: ") and "(the two differ)" in line and "operator-reported, not verified" in line
    assert f"reported:   reported by the log: {CM_RUNNING}" in a.components                  # full digest
    assert f"reported:   in the measured compose: {CM_MEASURED}" in a.components
    assert not any("running" in c or "same as measured" in c for c in a.components)
    reported = [c for c in a.components if c.startswith("reported: ")]
    assert any("proxy-qwen38-27b v0.0.540 commit 75d31e6461dc" in c for c in reported)
    others = [c for c in a.components if c.startswith("reported-other: ")]
    assert any("proxy-qwen38-27b-abliterated v0.0.540" in c for c in others)   # shown, after the named ones


def test_real_capture_replays_through_the_replay_module():
    ev = evidence()
    ev["claims"] = near.evidence_claims(ev, near.appraise(ev))
    r = replay_near.replay(json.loads(json.dumps(ev)), expected_repo="cloud-api.near.ai#Qwen/Qwen3.8-27B",
                           expected_fingerprints=(CODE_FP, ENCLAVE_FP))
    assert r.ok, r.checks
    assert r.captured_at_asserted == ev["captured_at"] and r.not_established == replay_near.NOT_ESTABLISHED
    for k in ("cm_quote", "cm_same_td", "cm_report_data", "cm_actions_hash", "cm_services"):
        assert r.checks[k] is True
    assert r.checks["cm_image"].startswith("recorded")


def test_replay_without_the_blobs_fails_closed():
    ev = json.loads(json.dumps(evidence()))
    ev.pop("blobs")   # what a ledger row holds: only blob_refs
    r = replay_near.replay(ev)
    assert not r.ok and r.checks["gateway_quote"].startswith("fail: TDX quote did not verify")
    blobs = evidence()["blobs"]
    assert replay_near.replay(replay_near.with_blobs(ev, blobs)).ok


def _mutated(fn):
    raw = copy.deepcopy(RAW)
    fn(raw)
    return near.appraise(evidence(raw))


def _edit_actions(r):
    # actions_hash left as it was: the log no longer hashes to the bound value
    _cm(r)["actions"][-2]["services"] = ["proxy-qwen38-27b"]


@pytest.mark.parametrize("fn,key", [
    (lambda r: _cand(r).__setitem__("signing_address", "00" * 32), "model_quotes"),
    (lambda r: r["gateway_report"]["gateway_attestation"]["info"]["tcb_info"].__setitem__(
        "app_compose", r["gateway_report"]["gateway_attestation"]["info"]["tcb_info"]["app_compose"] + " "),
     "gateway_quote"),
    (lambda r: r.__setitem__("nonce", "00" * 32), "gateway_quote"),
    (lambda r: r["jwks"]["keys"][0]["x5c"].pop(), "ita_jwks"),
    (lambda r: r["ita_model"]["gateway"].__setitem__("token", r["ita_model"]["gateway"]["token"][:-8] + "AAAAAAAA"),
     "ita_gateway_token"),
    (lambda r: _cand(r)["info"].__setitem__("instance_id", "00" * 20), "model_quotes"),
    (_edit_actions, "cm_actions_hash"),
    (lambda r: _cm(r).__setitem__("actions", []), "cm_actions_hash"),
    (lambda r: _cm(r).__setitem__("nonce_source", "server"), "cm_report_data"),
    (lambda r: _cm(r).__setitem__("nonce", "00" * 32), "cm_report_data"),
    (lambda r: _cm(r).__setitem__("actions_hash", nc.actions_hash(_cm(r)["actions"][:-1])), "cm_report_data"),
    (lambda r: _cm(r).__setitem__("event_log", json.dumps(json.loads(_cm(r)["event_log"])[:-1])), "cm_quote"),
    (lambda r: _cand(r).pop("compose_manager_attestation"), "cm_quote"),
])
def test_real_capture_tampering_fails(fn, key):
    a = _mutated(fn)
    assert not a.ok and str(a.checks[key]).startswith("fail"), a.checks


def test_flipped_quote_byte_fails_the_real_quote_verifier():
    raw = copy.deepcopy(RAW)
    rep = _cand(raw)
    q = bytearray(bytes.fromhex(rep["intel_quote"]))
    q[600] ^= 1
    rep["intel_quote"] = q.hex()
    a = near.appraise(evidence(raw))
    assert not a.ok and str(a.checks["model_quotes"]).startswith("fail") and "quote" in a.checks["model_quotes"]


def test_flipped_compose_manager_quote_byte_fails_the_real_quote_verifier():
    raw = copy.deepcopy(RAW)
    q = bytearray(bytes.fromhex(_cm(raw)["quote"]))
    q[600] ^= 1
    _cm(raw)["quote"] = q.hex()
    a = near.appraise(evidence(raw))
    assert not a.ok and a.checks["cm_quote"].startswith("fail: Qwen/Qwen3.8-27B[0]: compose-manager quote: TDX quote did")
    assert a.checks["cm_same_td"].startswith("not_run")


def test_compose_manager_quote_from_another_td_fails():
    # gpu13's real compose-manager block (a genuine Intel quote) beside instance 577b's model report
    raw = copy.deepcopy(RAW)
    _cand(raw)["compose_manager_attestation"] = copy.deepcopy(GPU13["candidate"]["compose_manager_attestation"])
    a = near.appraise(evidence(raw))
    assert a.checks["cm_quote"] is True
    assert not a.ok and a.checks["cm_same_td"].startswith("fail") and "RTMR" in a.checks["cm_same_td"]


def test_real_capture_is_not_valid_long_after_its_tokens_expired():
    a = near.appraise(evidence(), as_of=RAW["captured_at_unix"] + 86400)
    assert not a.ok and "not valid at the capture time" in a.checks["ita_gateway_token"]


def test_missing_block_passes_only_when_provider_tee_is_not_required():
    raw = copy.deepcopy(RAW)
    _cand(raw).pop("compose_manager_attestation")
    ev = evidence(raw)
    assert not near.appraise(ev).ok
    a = near.appraise(ev, require_compose_manager=False)
    assert a.ok and all(str(a.checks[k]).startswith("n/a") for k in nc.CM_CHECK_KEYS), a.checks


# ── a partial deployment, on real data (instance a8a25faa, 86 actions) ───────────────────────────

def test_partial_compose_up_sequence_names_the_commit_each_service_was_started_from():
    cand, nonce = GPU13["candidate"], GPU13["nonce"]
    q = nc.default_quote_verifier(bytes.fromhex(cand["intel_quote"]))
    cm = cand["compose_manager_attestation"]
    ups = [a for a in cm["actions"] if a["action"] == "compose_up"]
    assert ups[-1]["services"] == ["model-proxy-registrar"] and ups[-1]["tag"] == "v0.0.548"   # not the model's
    res = nc.check_compose_manager(cm, nonce=nonce, model_quote=q, quote_verifier=nc.default_quote_verifier,
                                   model=MODEL, app_compose=cand["info"]["tcb_info"]["app_compose"])
    S = "prod/small-models.yaml"
    got = {k: (res["services"][k]["tag"], res["services"][k]["commit"][:8]) for k in res["services_first"]}
    assert got == {f"{S}::model-downloader-qwen38": ("v0.0.513", "e99f50fc"),
                   f"{S}::model-sg-qwen38-27b-fp8-tp1-coloc": ("v0.0.539", "cab40870"),
                   f"{S}::nginx-qwen38": ("v0.0.540", "75d31e64"),
                   f"{S}::proxy-qwen38-27b": ("v0.0.540", "75d31e64"),
                   f"{S}::qwen38-registrar": ("v0.0.539", "cab40870"),
                   f"{S}::qwen38-lora-adapter-downloader": ("v0.0.516", "28a15af5")}
    assert len(res["services"]) == res["services_reported"] == 46 and res["actions_count"] == 86
    assert res["cm_image_measured"].endswith("6e035c8fb99c1d31f41760d25af178683a658cca4afd73cd0d366fbb5bf884be")
    assert res["cm_image_reported"] == CM_RUNNING and res["cm_image_match"] is False
    with pytest.raises(nc.CmCheckError) as exc:   # the other instance's nonce is not this one's
        nc.check_compose_manager(cm, nonce=RAW["nonce"], model_quote=q, quote_verifier=nc.default_quote_verifier,
                                 model=MODEL, app_compose=None)
    assert exc.value.step == "cm_report_data"


def test_the_actions_hash_serialisation_is_compact_sorted_and_ascii():
    for cand in (_cand(RAW), GPU13["candidate"]):
        cm = cand["compose_manager_attestation"]
        actions = cm["actions"]
        assert nc.actions_hash(actions) == cm["actions_hash"]
        assert hashlib.sha256(json.dumps(actions, sort_keys=True).encode()).hexdigest() != cm["actions_hash"]
        assert hashlib.sha256(json.dumps(actions, separators=(",", ":")).encode()).hexdigest() != cm["actions_hash"]


# ── schema v1 ────────────────────────────────────────────────────────────────────────────────────

def test_v1_evidence_appraises_under_v1_rules_with_the_new_checks_not_run():
    assert V1["schema"] == near.EVIDENCE_SCHEMA_V1 and "app_composes" in V1 and "blobs" not in V1
    a = near.appraise(V1)
    assert a.ok, a.checks
    assert (a.code_fingerprint, a.enclave_fingerprint) == (V1_CODE_FP, V1_ENCLAVE_FP)
    for k in nc.CM_CHECK_KEYS:
        assert a.checks[k] == near.CM_NOT_RUN_V1
    assert not any(c.startswith("reported: ") for c in a.components)
    r = replay_near.replay(V1, expected_repo="cloud-api.near.ai#Qwen/Qwen3.8-27B",
                           expected_fingerprints=(V1_CODE_FP, V1_ENCLAVE_FP))
    assert r.ok and r.not_established == replay_near.NOT_ESTABLISHED_V1
    assert any("compose_manager_attestation is not checked here" in x for x in r.not_established)


def test_the_lora_adapter_downloader_the_engine_loads_from_is_in_the_component_and_listed_first():
    # gpu13: model-sg-qwen38-27b-fp8-tp1-coloc mounts lora_adapter:/adapters and depends on this downloader
    # (inner file at cab40870); a name-list restriction once dropped it. The whole map is the component.
    cand = GPU13["candidate"]
    q = nc.default_quote_verifier(bytes.fromhex(cand["intel_quote"]))
    res = nc.check_compose_manager(cand["compose_manager_attestation"], nonce=GPU13["nonce"], model_quote=q,
                                   quote_verifier=nc.default_quote_verifier, model=MODEL, app_compose=None)
    key = "prod/small-models.yaml::qwen38-lora-adapter-downloader"
    assert key in res["services"] and key in res["services_first"]
    for other in ("proxy-glm53", "sage-dstack", "otelcol-contrib", "proxy-dsv41"):   # dstack.sock holders
        assert f"prod/small-models.yaml::{other}" in res["services"]
    edited = copy.deepcopy(res["services"])
    edited["prod/small-models.yaml::proxy-glm53"]["tag"] = "v9"
    assert nc.services_sha256(edited) != res["services_sha256"]   # any service's redeploy changes the component


@pytest.mark.parametrize("field,value", [
    ("app_id", "00" * 20), ("os_image_hash", "00" * 32),
    ("key_provider_info", '{"name":"kms","id":"00"}'), ("instance_id", "11" * 20)])
def test_an_info_value_other_than_its_rtmr3_boot_event_fails_on_real_data(field, value):
    a = _mutated(lambda r: _cand(r)["info"].__setitem__(field, value))
    assert not a.ok and f"info.{field} differs from the RTMR3" in a.checks["model_quotes"], a.checks


def test_the_identity_is_pinned_by_the_v2_code_fingerprint():
    a = near.appraise(evidence())
    m = a.cvms[1]
    code = {"gateway": [a.cvms[0]["compose_hash"]], "models": {MODEL: [m["compose_hash"]]},
            "identity": {"gateway": [f"{a.cvms[0]['app_id']}:{a.cvms[0]['os_image_hash']}:{a.cvms[0]['kms_id']}"],
                         "models": {MODEL: [f"{m['app_id']}:{m['os_image_hash']}:{m['kms_id']}"]}}}
    assert a.code_fingerprint == nc.sha256_hex(nc.canonical(code).encode()) == CODE_FP

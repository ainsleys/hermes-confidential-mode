"""Hostile tests for the NEAR compose-manager log check (synthetic NEAR, real signatures, fake TDX quote).

Each case bends one thing a gateway or an inner service could bend, and checks that verification fails
at the named step, or, for the running compose-manager image, that the mismatch is recorded and shown but
never counted as a pass.
"""
from __future__ import annotations

import copy
import json

import pytest

from confidential_mode.verify import near, near_checks as nc
from confidential_mode.verify.base import VerifyError

from ..near_world import (CM_IMAGE, CM_IMAGE_SWAPPED, MODEL, NOW, NearWorld, cm_attestation, events_for,
                          fake_quote_verifier, model_app_id)


def _bend(world: NearWorld, fn):
    """Apply ``fn(candidate, nonce)`` to every model candidate the world serves."""
    orig = world.model_report

    def served(nonce, model):
        rep = orig(nonce, model)
        for c in rep["model_attestations"]:
            fn(c, nonce)
        return rep
    world.model_report = served
    return world


def _verify_fails(world, tmp_path, step, needle="", **kw):
    """verify() refuses, and the appraisal names ``step`` as failed and every later step as not run."""
    with pytest.raises(VerifyError, match="did not verify"):
        world.adapter(tmp_path, encrypt=False, **kw).verify()
    ad = world.adapter(tmp_path, encrypt=False, **kw)
    raw, tls = ad.capture("ab" * 32)
    ev = near.build_evidence(raw, base_url=ad.base_url, models=ad.models, nonce="ab" * 32,
                             captured_at_unix=NOW, tls_observation=tls)
    a = near.appraise(ev, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert not a.ok and str(a.checks[step]).startswith("fail"), a.checks
    assert needle in a.checks[step], a.checks[step]
    later = nc.CM_CHECK_KEYS[nc.CM_CHECK_KEYS.index(step) + 1:]
    assert all(str(a.checks[k]).startswith("not_run") for k in later), a.checks
    return a


def test_the_synthetic_world_passes_every_compose_manager_check(tmp_path):
    world = NearWorld()
    r = world.adapter(tmp_path, encrypt=False).verify()
    checks = r.evidence["checks"]
    assert all(checks[k] is True for k in nc.CM_CHECK_KEYS if k != "cm_image"), checks
    cvm = r.evidence["claims"]["cvms"][1]
    assert cvm["services_scope"] == f"all services: no prompt-path rule for {MODEL}"
    assert set(cvm["services"]) == {"prod/test.yaml::proxy-test", "prod/test.yaml::model-test",
                                    "prod/test.yaml::nginx-test"}
    assert cvm["services"]["prod/test.yaml::proxy-test"]["tag"] == "v0.0.2"      # compose_stage changed nothing
    assert cvm["services"]["prod/test.yaml::model-test"]["tag"] == "v0.0.1"
    assert (cvm["cm_image_running"], cvm["cm_image_measured"]) == (CM_IMAGE_SWAPPED, CM_IMAGE)


def test_running_image_mismatch_is_a_component_and_never_a_pass(tmp_path):
    world = NearWorld()
    r = world.adapter(tmp_path, encrypt=False).verify()
    assert r.evidence["checks"]["cm_image"].startswith("recorded (not a pass)")
    assert any(c.startswith("reported: ") and "MISMATCH" in c for c in r.evidence["claims"]["components"])
    world.cm_actions = world.cm_actions[:-1]          # no launcher swap: running == measured
    r = world.adapter(tmp_path, encrypt=False).verify()
    assert r.evidence["checks"]["cm_image"] is True
    assert any("(same as measured)" in c for c in r.evidence["claims"]["components"])


def test_compose_manager_quote_from_a_different_td_fails(tmp_path):
    # a genuine-looking quote of another TD: its own event log replays to its own RTMR3, which is not the
    # model quote's (another instance id)
    def other_td(c, nonce):
        ev = events_for(model_app_id(7))
        c["compose_manager_attestation"] = cm_attestation(
            c, nonce, c["compose_manager_attestation"]["actions"], events=ev,
            quote_overrides={"rtmr3": nc.replay_rtmr3(ev).hex()})
    a = _verify_fails(_bend(NearWorld(), other_td), tmp_path, "cm_same_td", "RTMR3")
    assert a.checks["cm_quote"] is True


def test_compose_manager_quote_with_another_mrtd_fails(tmp_path):
    world = NearWorld()
    world.cm_quote_overrides = {"mrtd": "66" * 48}
    _verify_fails(world, tmp_path, "cm_same_td", "MRTD")


def test_compose_manager_quote_that_does_not_verify_or_is_debug_fails(tmp_path):
    world = NearWorld()
    world.cm_quote_overrides = {"bad_signature": True}
    _verify_fails(world, tmp_path, "cm_quote", "did not verify")
    world = NearWorld()
    world.cm_quote_overrides = {"debug": True}
    _verify_fails(world, tmp_path, "cm_quote", "debug")


def test_compose_manager_event_log_that_does_not_replay_fails(tmp_path):
    def bent(c, nonce):
        cm = c["compose_manager_attestation"]
        cm["event_log"] = json.dumps(json.loads(cm["event_log"])[:-1])
    _verify_fails(_bend(NearWorld(), bent), tmp_path, "cm_quote", "RTMR3")


def test_stale_nonce_fails(tmp_path):
    # a block captured for an earlier nonce, replayed whole: its quote binds the old nonce
    def stale(c, nonce):
        c["compose_manager_attestation"] = cm_attestation(c, "77" * 32, c["compose_manager_attestation"]["actions"])
    _verify_fails(_bend(NearWorld(), stale), tmp_path, "cm_report_data", "not this client's nonce")


def test_nonce_echoed_but_the_quote_binds_another_fails(tmp_path):
    world = NearWorld()
    world.cm_quote_overrides = {"report_data": nc.actions_hash(world.cm_actions) + "77" * 32}
    _verify_fails(world, tmp_path, "cm_report_data", "actions_hash || nonce")


@pytest.mark.parametrize("source", ["server", "", None, "Client"])
def test_nonce_source_other_than_client_fails(tmp_path, source):
    world = NearWorld()
    world.cm_overrides = {"nonce_source": source}
    _verify_fails(world, tmp_path, "cm_report_data", "nonce_source")


def test_empty_actions_log_fails_even_when_its_hash_is_bound(tmp_path):
    world = NearWorld()
    world.cm_actions = []
    _verify_fails(world, tmp_path, "cm_services", "empty")


def test_actions_edited_with_actions_hash_unchanged_fails(tmp_path):
    def edited(c, nonce):
        c["compose_manager_attestation"]["actions"][1]["commit"] = "e0" * 20
    _verify_fails(_bend(NearWorld(), edited), tmp_path, "cm_actions_hash", "does not hash")


def test_actions_hash_recomputed_by_the_gateway_but_not_bound_fails(tmp_path):
    def edited(c, nonce):
        cm = c["compose_manager_attestation"]
        cm["actions"][1]["commit"] = "e0" * 20
        cm["actions_hash"] = nc.actions_hash(cm["actions"])
        cm["report_data"] = cm["actions_hash"] + nonce
    _verify_fails(_bend(NearWorld(), edited), tmp_path, "cm_report_data", "actions_hash || nonce")


@pytest.mark.parametrize("bad", [
    {"action": "compose_rollback", "timestamp": "t"},
    {"action": "compose_up", "file": "prod/test.yaml", "commit": "short", "file_sha256": "f1" * 32, "services": ["x"]},
    {"action": "compose_up", "file": "prod/test.yaml", "commit": "c1" * 20, "file_sha256": "f1" * 32, "services": "x"},
    {"action": "compose_down", "services": ["x"]},
    {"action": "compose_manager_started"},
    "compose_up",
])
def test_unknown_or_malformed_actions_fail_closed(tmp_path, bad):
    world = NearWorld()
    world.cm_actions = world.cm_actions + [bad]
    _verify_fails(world, tmp_path, "cm_services")


def test_partial_compose_up_sequence_is_replayed_per_service(monkeypatch, tmp_path):
    # the latest compose_up names the registrar, not the model server: the model server keeps its own commit
    monkeypatch.setitem(nc.PROMPT_PATH_SERVICES, MODEL, {"proxy": ("proxy-test",), "engine": ("model-test",),
                                                         "also": ("nginx-test",)})
    world = NearWorld()
    up = {"action": "compose_up", "file": "prod/test.yaml", "timestamp": "t"}
    world.cm_actions = [
        {"action": "compose_manager_started", "image": CM_IMAGE, "timestamp": "t"},
        {**up, "tag": "v1", "commit": "a1" * 20, "file_sha256": "b1" * 32,
         "services": ["model-test", "proxy-test", "nginx-test", "registrar-test"]},
        {**up, "tag": "v2", "commit": "a2" * 20, "file_sha256": "b2" * 32, "services": ["proxy-test"]},
        {"action": "compose_down", "file": "prod/test.yaml", "services": ["nginx-test"], "timestamp": "t"},
        {**up, "tag": "v3", "commit": "a3" * 20, "file_sha256": "b3" * 32, "services": ["registrar-test"]},
    ]
    r = world.adapter(tmp_path, encrypt=False).verify()
    cvm = r.evidence["claims"]["cvms"][1]
    assert cvm["services_scope"] == f"prompt path of {MODEL}"
    assert {k: v["tag"] for k, v in cvm["services"].items()} == {"prod/test.yaml::model-test": "v1",
                                                                 "prod/test.yaml::proxy-test": "v2"}
    assert r.evidence["checks"]["cm_image"] is True


def test_whole_file_actions_and_the_prompt_path_fallback(monkeypatch):
    up = {"action": "compose_up", "file": "f.yaml", "timestamp": "t"}
    state, _ = nc.deployment_map([
        {**up, "tag": "v1", "commit": "a1" * 20, "file_sha256": "b1" * 32, "services": ["proxy-m", "engine-m"]},
        {**up, "tag": "v2", "commit": "a2" * 20, "file_sha256": "b2" * 32},           # the whole file
        {**up, "tag": "v3", "commit": "a3" * 20, "file_sha256": "b3" * 32, "services": ["proxy-m"]},
        {**up, "file": "g.yaml", "tag": "v1", "commit": "a1" * 20, "file_sha256": "b1" * 32, "services": ["x"]},
        {"action": "compose_down", "file": "g.yaml", "timestamp": "t"},                # the whole file down
    ])
    assert {k: v["tag"] for k, v in state.items()} == {"f.yaml::*": "v2", "f.yaml::proxy-m": "v3"}
    monkeypatch.setitem(nc.PROMPT_PATH_SERVICES, "m", {"proxy": ("proxy-m",), "engine": ("engine-m",)})
    svc, scope = nc.prompt_path(state, "m")   # the engine was renamed away: the whole map, said so
    assert svc == state and scope == "all services: the prompt-path rule for m matched no engine"


def test_block_missing_fails_closed_under_require_provider_tee(tmp_path):
    world = NearWorld()
    world.cm_omit = True
    with pytest.raises(VerifyError, match="cm_quote|compose_manager_attestation"):
        world.adapter(tmp_path, encrypt=False).verify()
    r = world.adapter(tmp_path, encrypt=False, require_provider_tee=False).verify()
    assert all(str(r.evidence["checks"][k]).startswith("n/a") for k in nc.CM_CHECK_KEYS), r.evidence["checks"]


def test_block_missing_for_one_of_two_candidates_fails(tmp_path):
    world = NearWorld()
    world.model_candidates = 2
    calls = {"n": 0}

    def drop_second(c, nonce):
        calls["n"] += 1
        if calls["n"] % 2 == 0:
            c.pop("compose_manager_attestation")
    _bend(world, drop_second)
    with pytest.raises(VerifyError, match=r"\[1\]: its report carries no compose_manager_attestation"):
        world.adapter(tmp_path, encrypt=False).verify()


def test_evidence_blob_that_does_not_hash_to_its_id_fails(tmp_path):
    world = NearWorld()
    r = world.adapter(tmp_path, encrypt=False).verify()
    ev = copy.deepcopy(r.evidence)
    ref = ev["model_reports"][MODEL][0]["compose_manager"]["blob"]
    block = json.loads(ev["blobs"][ref])
    block["actions"][1]["commit"] = "e0" * 20
    ev["blobs"][ref] = nc.canonical(block)          # same id, other bytes
    a = near.appraise(ev, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots)
    assert not a.ok and "blob is missing or does not hash to its id" in a.checks["cm_quote"]

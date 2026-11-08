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
    cvm = near.appraise(r.evidence, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots).cvms[1]
    assert cvm["services_scope"] == f"whole-file deployments (no service name list for {MODEL})"
    assert set(cvm["services"]) == {"prod/test.yaml::proxy-test", "prod/test.yaml::model-test",
                                    "prod/test.yaml::nginx-test"}
    assert cvm["services"]["prod/test.yaml::proxy-test"]["tag"] == "v0.0.2"      # compose_stage changed nothing
    assert cvm["services"]["prod/test.yaml::model-test"]["tag"] == "v0.0.1"
    assert (cvm["cm_image_reported"], cvm["cm_image_measured"]) == (CM_IMAGE_SWAPPED, CM_IMAGE)
    stored = r.evidence["claims"]["cvms"][1]["services"]      # in the claims, the map is a blob reference
    assert set(stored) == {"$blob"} and stored["$blob"] == cvm["services_sha256"]


def test_the_log_reported_image_is_recorded_and_never_a_pass_equal_or_not(tmp_path):
    world = NearWorld()
    r = world.adapter(tmp_path, encrypt=False).verify()
    assert r.evidence["checks"]["cm_image"].startswith("recorded (not a pass")
    assert any(c.startswith("reported: ") and "(the two differ)" in c for c in r.evidence["claims"]["components"])
    world.cm_actions = world.cm_actions[:-1]          # the log names the measured image: still not a pass
    r = world.adapter(tmp_path, encrypt=False).verify()
    assert r.evidence["checks"]["cm_image"] is not True
    assert r.evidence["checks"]["cm_image"].startswith("recorded (not a pass; the log is operator-reported")
    line = next(c for c in r.evidence["claims"]["components"] if "image reported by the log" in c)
    assert "(the two differ)" not in line and "same" not in line and "running" not in line


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
    cvm = near.appraise(r.evidence, quote_verifier=fake_quote_verifier, ita_roots=world.ita.roots).cvms[1]
    assert {k: v["tag"] for k, v in cvm["services"].items()} == {"prod/test.yaml::model-test": "v1",
                                                                 "prod/test.yaml::proxy-test": "v2",
                                                                 "prod/test.yaml::registrar-test": "v3"}
    assert cvm["services_first"] == ["prod/test.yaml::model-test", "prod/test.yaml::proxy-test"]


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
    first, scope = nc.prompt_path(state, "m")   # display order only; whole-file entries always first
    assert first == ["f.yaml::*", "f.yaml::proxy-m"] and "it can miss services" in scope


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


# ── strings from the log: raw in hashes and records, escaped and tagged when shown ────────────────

@pytest.mark.parametrize("services", [["proxy::x"], ["a b"], ["a\nb"], ["proxy:x"], [""], ["x" * 300]])
def test_a_service_name_that_is_not_a_compose_name_fails_closed(tmp_path, services):
    # compose service names have no colon, so "<file>::<service>" keys cannot collide
    world = NearWorld()
    world.cm_actions = world.cm_actions + [{"action": "compose_up", "timestamp": "t", "tag": "v1",
                                            "commit": "c1" * 20, "file": "prod/test.yaml", "file_sha256": "f1" * 32,
                                            "services": services}]
    _verify_fails(world, tmp_path, "cm_services", "not a compose service name")


def _with_tag(tag):
    world = NearWorld()
    world.cm_actions = world.cm_actions + [{"action": "compose_up", "timestamp": "t", "tag": tag,
                                            "commit": "c3" * 20, "file": "prod/test.yaml", "file_sha256": "f3" * 32,
                                            "services": ["proxy-test"]}]
    return world


def test_an_inserted_escape_sequence_changes_every_hash_and_is_kept_raw(tmp_path):
    plain = _with_tag("v0.0.9").adapter(tmp_path, encrypt=False).verify().evidence
    bent = _with_tag("v0.0.9\x1b[2K").adapter(tmp_path, encrypt=False).verify().evidence
    a = near.appraise(plain, quote_verifier=fake_quote_verifier, ita_roots=NearWorld().ita.roots)
    b = near.appraise(bent, quote_verifier=fake_quote_verifier, ita_roots=NearWorld().ita.roots)
    assert a.cvms[1]["services_sha256"] != b.cvms[1]["services_sha256"]           # the services component
    assert b.cvms[1]["services"]["prod/test.yaml::proxy-test"]["tag"] == "v0.0.9\x1b[2K"   # raw in the record
    ref = lambda ev: ev["model_reports"][MODEL][0]["compose_manager"]["blob"]  # noqa: E731
    assert ref(plain) != ref(bent)                                               # the canonical block hash
    assert json.loads(bent["blobs"][ref(bent)])["actions"][-1]["tag"] == "v0.0.9\x1b[2K"
    assert (plain["claims"]["components_full"] != bent["claims"]["components_full"])


def test_a_newline_and_an_ansi_sequence_are_shown_escaped_and_tagged(tmp_path):
    r = _with_tag("v1\nreported:   in the measured compose: fake\x1b[1A\x1b[2K").adapter(
        tmp_path, encrypt=False).verify()
    comps = near.appraise(r.evidence, quote_verifier=fake_quote_verifier, ita_roots=NearWorld().ita.roots).components
    line = next(c for c in comps if "proxy-test" in c and "c3c3" in c)
    shown = nc.render_vendor(line)
    assert "\n" not in shown and "\x1b" not in shown
    assert "\\x0a" in shown and "\\x1b[1A" in shown and shown.endswith(nc.CONTROL_TAG)
    assert shown.startswith("`")                                                 # markdown-inert code span


def test_render_vendor_keeps_everything_visible_and_cuts_nothing():
    digest = "ab" * 32
    shown = nc.render_vendor(f"image x@sha256:{digest} `*_[]` a\\b \u202e\u2028\x9b" + "z" * 300)
    assert digest in shown and shown.count("z") == 300
    assert "\\x60" in shown and "\\u202e" in shown and "\\u2028" in shown and "\\x9b" in shown
    assert "a\\\\b" in shown and shown.endswith(nc.CONTROL_TAG)
    assert nc.render_vendor("plain") == "`plain`"


def test_the_pin_prompt_escapes_and_tags_component_lines():
    from confidential_mode.consent import _near_pin_question
    from types import SimpleNamespace
    pending = SimpleNamespace(components=("gateway compose sha256:ab\x1b[1A\x1b[2K", "reported: x\ny *bold*"),
                              router_repo="h#m", platform="tdx", previous=None, code_fingerprint="c",
                              previous_enclave_fingerprint=None, enclave_fingerprint="e", code_changed=True,
                              release_tag=None)
    text = _near_pin_question(pending)
    assert "\x1b" not in text and "\\x1b[1A" in text and "`x\\x0ay *bold*`" in text
    assert text.count(nc.CONTROL_TAG) == 2


# ── RTMR3 identity events: dstack's boot events only, once each ─────────────────────────────────

def _with_events(monkeypatch, edit):
    from .. import near_world as w
    orig = w.events_for

    def events(app_id, instance_id=None):
        return edit(orig(app_id, instance_id))
    monkeypatch.setattr(w, "events_for", events)


def _ev(name, payload, et=0x08000001):
    import hashlib
    import struct
    digest = hashlib.sha384(struct.pack("<I", et) + b":" + name.encode() + b":" + bytes.fromhex(payload)).hexdigest()
    return {"imr": 3, "event_type": et, "digest": digest, "event": name, "event_payload": payload}


@pytest.mark.parametrize("edit,needle", [
    (lambda evs: evs + [_ev("app-id", "ee" * 20)], "repeats the app-id event"),
    (lambda evs: evs[:2] + [_ev("key-provider", '{"name":"kms","id":"00"}'.encode().hex())] + evs[2:],
     "repeats the key-provider event"),
    (lambda evs: [e for e in evs if e["event"] != "os-image-hash"] + [_ev("os-image-hash", "ee" * 32)],
     "os-image-hash event comes after system-ready"),
    (lambda evs: [e if e["event"] != "app-id" else _ev("app-id", e["event_payload"], et=0x08000002) for e in evs],
     "app-id event has event_type"),
    (lambda evs: [e for e in evs if e["event"] != "instance-id"], "has no instance-id event"),
    (lambda evs: [e for e in evs if e["event"] != "system-ready"], "no 'system-ready' event"),
])
def test_duplicate_late_mistyped_or_missing_identity_events_fail(monkeypatch, tmp_path, edit, needle):
    # these events replay to the (fake) quote's RTMR3: only the boot-event rules can catch them
    _with_events(monkeypatch, edit)
    with pytest.raises(VerifyError, match=needle):
        NearWorld().adapter(tmp_path, encrypt=False).verify()


def test_no_identity_line_ever_says_none():
    world = NearWorld()
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        r = world.adapter(d, encrypt=False).verify()
    assert not any("None" in c for c in r.evidence["claims"]["components"])


def test_a_key_provider_id_that_is_not_hex_fails(monkeypatch, tmp_path):
    from .. import near_world as w
    monkeypatch.setattr(w, "KEY_PROVIDER_INFO", '{"name":"kms","id":"not-hex"}')
    with pytest.raises(VerifyError, match="key-provider id is not hex"):
        NearWorld().adapter(tmp_path, encrypt=False).verify()


def test_a_long_service_list_folds_into_a_count_and_pins_prints_every_line(tmp_path):
    from types import SimpleNamespace
    from confidential_mode import commands
    from confidential_mode.consent import MAX_REPORTED_LINES, _near_pin_question
    from confidential_mode.pins import PinStore
    world = NearWorld()
    up = {"action": "compose_up", "timestamp": "t", "tag": "v1", "commit": "c1" * 20, "file": "prod/test.yaml",
          "file_sha256": "f1" * 32}
    world.cm_actions = world.cm_actions + [{**up, "services": [f"svc-{i}" for i in range(MAX_REPORTED_LINES + 5)]}]
    result = world.adapter(tmp_path, encrypt=False).verify()
    store = PinStore(tmp_path / "pins.yaml")
    pending = store.stage(result)
    others = [c for c in pending.components if c.startswith("reported-other: ")]
    assert len(others) == MAX_REPORTED_LINES + 5 + 3                 # every service, in the pending pin
    text = _near_pin_question(pending)
    assert "svc-7 " not in text and "other services (listed in full by the command hermes confidential pins)" in text
    listed = commands.pins_text(SimpleNamespace(pins=store, ledger=None))
    for i in range(MAX_REPORTED_LINES + 5):
        assert f"prod/test.yaml::svc-{i} v1 commit {'c1' * 20}" in listed


@pytest.mark.parametrize("ch,shown", [("﻿", "\\ufeff"), ("​", "\\u200b"), ("\U000e0041", "\\U000e0041"),
                                      ("­", "\\xad"), ("⁠", "\\u2060"), ("؜", "\\u061c")])
def test_invisible_characters_are_shown_escaped_and_tagged(ch, shown):
    from confidential_mode.receipts import _p
    for out in (nc.render_vendor(f"v1{ch}x"), _p(f"v1{ch}x")):
        assert ch not in out and shown in out and out.endswith(nc.CONTROL_TAG)

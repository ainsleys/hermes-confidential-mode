"""Pins file version 3 (INTERFACES Amendment 7): migration of the live demo file, the approved set, per-CVM
NEAR entries, retirement, the consent check per entry, and the stale pending refresh."""
from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from confidential_mode import consent, provider
from confidential_mode.pins import (BACKUP_SUFFIX, SCHEMA_VERSION, PinStore, PinStoreError, consent_key,
                                    near_code_fingerprint)
from confidential_mode.verify.base import VerificationResult
from tests.near_world import MODEL, NearWorld

try:
    import hermes_yaml as yaml
except ImportError:  # pragma: no cover
    import yaml

LIVE = Path(__file__).resolve().parents[1] / "fixtures" / "live_pins" / "pins_v2.yaml"
REPO = "tinfoilsh/confidential-model-router"
V170 = ("284bd9e5d470c4812fad60fcec6f99bc0958cd5a1ef4d317a99f702e2913f5fb",
        "fb8eabe68d3b977b05e48e7a41aff6bbb6dc576cbf5639360fbdf49f357f7d6698be2537f1a425975f89b8a73023022a")
V171 = ("bcfaff463b2f9a8ab07975439941bf4f39eebd7d5f882f6322bf3c65b89dab84",
        "f5bcc220a94d5c34c5c80db9593dcc88d7d1a19b43796c05ec4b6cdcf921c8176a56cb3d0224650b1250ee892a0ec438")


def _tinfoil(code, enclave, tag) -> VerificationResult:
    return VerificationResult(vendor="tinfoil", router_repo=REPO, enclave_host="router-0.tinfoil.sh",
                              code_fingerprint=code, enclave_fingerprint=enclave, release_tag=tag,
                              verifier="tinfoil/0.14.2", verified_at_host_clock=0.0, evidence={"platform": "sev-snp"})


class Ledger:
    """tail()-able rows, the shape provider._consent_recorded reads."""

    def __init__(self):
        self.rows = []

    def append(self, ev):
        from types import SimpleNamespace
        self.rows.append(SimpleNamespace(id=len(self.rows) + 1, **{k: ev.get(k) for k in ("kind", "decision", "detail")}))

    def tail(self, since=0, limit=1000):
        return [r for r in self.rows if r.id > since][:limit]


class Asker:
    def __init__(self, pick="approve"):
        self.pick, self.asked = pick, []

    def ask_choice(self, q, choices):
        self.asked.append(q)
        return self.pick


def _approve(store, ledger, **kw):
    return consent.approve_pending_pin(Asker(), store, ledger, session_key="t", session_id="s", platform="cli", **kw)


# ── migration of the live demo file ───────────────────────────────────────────────────────────────

@pytest.fixture
def live(tmp_path):
    path = tmp_path / "pins.yaml"
    shutil.copyfile(LIVE, path)
    return PinStore(path), path


def test_live_file_migrates_with_identical_behaviour(live):
    store, path = live
    original = path.read_bytes()
    assert store.match(_tinfoil(*V170, "v0.0.170")) is True
    assert store.match(_tinfoil(*V171, "v0.0.171")) is False
    pend = store.pending()
    assert (pend.vendor, pend.release_tag, pend.code_fingerprint, pend.enclave_fingerprint) == ("tinfoil", "v0.0.171",
                                                                                               *V171)
    assert pend.previous == V170[0] and pend.previous_release_tag == "v0.0.170" and pend.rekor_log_index == 3725017338
    rec = store.get("tinfoil", REPO)
    assert (rec.code_fingerprint, rec.enclave_fingerprint, rec.release_tag, rec.approved_via) == (*V170, "v0.0.170",
                                                                                                "cli-setup")
    assert rec.components is None and rec.cvm_role == "router" and rec.migrated_from == 2
    assert path.read_bytes() == original, "reading never rewrites the file"
    # a re-verification of v0.0.171 re-stages the same batch (same consent key), so the stored one is kept
    assert consent_key(store.stage(_tinfoil(*V171, "v0.0.171"))) == consent_key(pend)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    assert backup.read_bytes() == original, "the first version-3 save writes the version-2 backup first"
    assert yaml.safe_load(path.read_text())["version"] == SCHEMA_VERSION
    applied = store.apply(store.pending(), approved_via="cli")
    assert (applied.code_fingerprint, applied.enclave_fingerprint) == V171 and applied.previous == V170[0]
    assert store.match(_tinfoil(*V171, "v0.0.171")) is True and store.match(_tinfoil(*V170, "v0.0.170")) is False
    assert store.pending() is None and backup.read_bytes() == original
    assert len(store.approved_entries()) == 1, "Tinfoil replaces: one approved entry"


def test_live_file_pending_applies_directly_after_migration(live):
    store, path = live
    rec = store.apply(store.pending(), approved_via="telegram")
    assert rec.release_tag == "v0.0.171" and store.match(_tinfoil(*V171, "v0.0.171"))
    assert path.with_name(path.name + BACKUP_SUFFIX).exists()


def test_v3_file_edited_to_v2_matches_nothing(live):
    store, path = live
    store.stage(_tinfoil(*V171, "v0.0.171"))           # now version 3 on disk
    doc = yaml.safe_load(path.read_text())
    doc["version"] = 2
    path.write_text(yaml.safe_dump(doc))
    assert store.match(_tinfoil(*V170, "v0.0.170")) is False
    with pytest.raises(PinStoreError):
        store.load()


@pytest.mark.parametrize("version", [1, 4, 99, "3", None])
def test_unknown_version_matches_nothing_and_is_never_overwritten(live, version):
    store, path = live
    store.stage(_tinfoil(*V171, "v0.0.171"))
    doc = yaml.safe_load(path.read_text())
    doc["version"] = version
    path.write_text(yaml.safe_dump(doc))
    before = path.read_bytes()
    assert store.match(_tinfoil(*V170, "v0.0.170")) is False
    with pytest.raises(PinStoreError):
        store.stage(_tinfoil(*V171, "v0.0.171"))
    assert path.read_bytes() == before


def test_tinfoil_entry_fingerprints_are_byte_identical_and_have_no_components(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_tinfoil("c1" * 32, "e1" * 48, "v1")), approved_via="cli")
    (e,) = store.approved_entries()
    assert (e.code_fingerprint, e.enclave_fingerprint, e.components, e.pinned) == ("c1" * 32, "e1" * 48, None, ())
    doc = yaml.safe_load((tmp_path / "pins.yaml").read_text())
    assert doc["identities"][0]["concurrent"] is False


# ── NEAR: per-CVM entries, an approved set ───────────────────────────────────────────────────────

def _near(tmp_path, world=None, **kw):
    world = world or NearWorld()
    for k, v in kw.items():
        setattr(world, k, v)
    return world, world.adapter(tmp_path, encrypt=False).verify()


def test_near_stages_one_entry_per_cvm_with_named_components(tmp_path):
    world, res = _near(tmp_path)
    store = PinStore(tmp_path / "pins.yaml")
    pend = store.stage(res)
    roles = sorted(e.cvm_role for e in pend.entries)
    assert roles == ["gateway", f"model:{MODEL}"]
    gw = next(e for e in pend.entries if e.cvm_role == "gateway")
    model = next(e for e in pend.entries if e.cvm_role != "gateway")
    assert set(gw.components) == {"app_id", "compose", "os_image", "kms_id"}
    assert set(model.components) == {"app_id", "compose", "os_image", "kms_id", "services", "cm_image_running"}
    assert set(model.pinned) == {"app_id", "compose", "os_image", "kms_id", "cm_image_running"}, \
        "services are shown for review only while their socket tags cannot be shown"
    assert model.code_fingerprint == near_code_fingerprint(model.cvm_role, model.components, model.pinned)
    assert store.match(res) is False
    ledger = Ledger()
    assert _approve(store, ledger).startswith("Pinned 2 NEAR entries")
    assert store.match(res) is True
    applied = [r for r in ledger.rows if r.kind == "pin_applied"]
    assert len(applied) == 2 and {r.detail["code_fingerprint"] for r in applied} == {gw.code_fingerprint,
                                                                                    model.code_fingerprint}
    doc = yaml.safe_load((tmp_path / "pins.yaml").read_text())
    assert doc["identities"][0]["concurrent"] is True


def test_approving_one_near_instance_does_not_approve_another(tmp_path):
    world, res1 = _near(tmp_path)
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    store.stage(res1)
    _approve(store, ledger)
    world.model_candidates = 2                          # a second instance with another app_id
    res2 = world.adapter(tmp_path, encrypt=False).verify()
    assert store.match(res2) is False
    pend = store.stage(res2)
    assert [e.cvm_role for e in pend.entries] == [f"model:{MODEL}"], "only the new CVM is pending"
    _approve(store, ledger)
    assert store.match(res2) is True and store.match(res1) is True, "approving adds: both stay approved"
    assert len(store.approved_entries()) == 3


def test_a_changed_service_map_is_new_only_when_services_are_pinned(tmp_path):
    world, res1 = _near(tmp_path)
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    store.stage(res1)
    _approve(store, ledger)
    world.cm_actions = world.cm_actions + [{"action": "compose_up", "timestamp": "t", "tag": "v9", "commit": "c9" * 20,
                                            "file": "prod/test.yaml", "file_sha256": "f9" * 32,
                                            "services": ["proxy-test"]}]
    res2 = world.adapter(tmp_path, encrypt=False).verify()
    assert store.match(res2) is True, "the service map is shown for review only on this entry"
    world.cm_actions = world.cm_actions[:-1] + [{"timestamp": "t", "action": "compose_manager_started",
                                                 "container": "compose-manager", "image": "x/cm@sha256:" + "9" * 64}]
    res3 = world.adapter(tmp_path, encrypt=False).verify()
    assert store.match(res3) is False, "the compose-manager image the log reports is pinned"


def test_hand_written_approved_entry_without_consent_row_does_not_count(tmp_path):
    world, res = _near(tmp_path)
    store = PinStore(tmp_path / "pins.yaml")
    pend = store.stage(res)
    store.apply(pend, approved_via="hand")             # no consent.py, so no pin_applied row
    e = provider._Entry(adapter=None, pins=store, ttl_seconds=60, failure_backoff_seconds=1, consent_ledger=Ledger())
    assert store.match(res) is True and provider._consent_recorded(e, res) is False


def test_retired_entry_re_added_by_hand_does_not_count(tmp_path):
    from types import SimpleNamespace
    from confidential_mode import commands
    world, res = _near(tmp_path)
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    store.stage(res)
    _approve(store, ledger)
    e = provider._Entry(adapter=None, pins=store, ttl_seconds=60, failure_backoff_seconds=1, consent_ledger=ledger)
    assert provider._consent_recorded(e, res) is True
    text_before = (tmp_path / "pins.yaml").read_text()
    model = next(x for x in store.approved_entries() if x.cvm_role != "gateway")
    out = commands.retire_text(SimpleNamespace(pins=store, ledger=ledger), model.code_fingerprint[:12], surface="cli")
    assert out.startswith("Retired") and [r.kind for r in ledger.rows][-1] == "pin_retired"
    assert store.match(res) is False
    (tmp_path / "pins.yaml").write_text(text_before)    # the entry is back, by hand
    assert store.match(res) is True
    assert provider._consent_recorded(e, res) is False, "a pin_retired row after the pin_applied row wins"
    fresh = provider._Entry(adapter=None, pins=store, ttl_seconds=60, failure_backoff_seconds=1, consent_ledger=ledger)
    assert provider._consent_recorded(fresh, res) is False, "also for a process that reads the ledger afresh"


def test_retire_needs_a_unique_prefix(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_tinfoil("ab" * 32, "cd" * 48, "v1")), approved_via="cli")
    with pytest.raises(PinStoreError):
        store.retire("abab")                            # too short
    with pytest.raises(PinStoreError):
        store.retire("ffffffff")
    assert store.retire("abababab").release_tag == "v1" and store.approved_entries() == []


def test_auto_apply_cannot_add_to_a_concurrent_set(tmp_path):
    world, res = _near(tmp_path)
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    pend = store.stage(res)
    with pytest.raises(PinStoreError):
        store.apply(pend, approved_via="auto_platform_only", approved_by="policy")
    flap = replace(pend, previous="x", code_changed=False, hardware_measurements_verified=True)
    e = provider._Entry(adapter=None, pins=store, ttl_seconds=60, failure_backoff_seconds=1, consent_ledger=ledger,
                        on_event=ledger.append)
    assert provider._auto_apply("attested-near", e, flap) is False
    assert store.approved_entries() == [] and ledger.rows == []


def test_stale_pending_refreshes_shown_lines_and_keeps_the_answer_valid(tmp_path):
    world, res1 = _near(tmp_path)
    store = PinStore(tmp_path / "pins.yaml")
    first = store.stage(res1)
    # same pinned values, a different reported (shown-only) service map
    world.cm_actions = world.cm_actions + [{"action": "compose_up", "timestamp": "t", "tag": "v9", "commit": "c9" * 20,
                                            "file": "prod/test.yaml", "file_sha256": "f9" * 32,
                                            "services": ["nginx-test"]}]
    res2 = world.adapter(tmp_path, encrypt=False).verify()
    second = store.stage(res2)
    assert consent_key(second) == consent_key(first) and second.staged_at == first.staged_at
    assert second.components != first.components, "the shown-for-review lines are refreshed"
    assert any("v9" in c for c in store.pending().components)
    assert store.apply(first, approved_via="cli").cvm_role in ("gateway", f"model:{MODEL}"), \
        "an answer to the earlier prompt still applies: equality is keyed on fingerprints"


def test_pins_approve_with_nothing_pending_is_a_no_op_with_a_message(tmp_path):
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    out = _approve(store, ledger)
    assert out == "No pin update is waiting for approval."
    assert ledger.rows == [] and not (tmp_path / "pins.yaml").exists()


def test_cli_approve_records_reviewer_and_note_chat_records_none(tmp_path):
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    store.stage(_tinfoil("c1" * 32, "e1" * 48, "v1"))
    _approve(store, ledger, reviewed_by="reviewer-agent", review_note="Q1 no; Recommendation: approve")
    (e,) = store.approved_entries()
    assert (e.reviewed_by, e.review_note) == ("reviewer-agent", "Q1 no; Recommendation: approve")
    assert ledger.rows[-1].detail["reviewed_by"] == "reviewer-agent" and ledger.rows[-1].detail["approved_via"] == "cli"
    store.stage(_tinfoil("c2" * 32, "e2" * 48, "v2"))
    _approve(store, ledger)
    (e,) = store.approved_entries()
    assert e.reviewed_by is None and e.review_note is None


def test_prompt_lists_every_pending_entry_and_the_approved_set_with_unseen_flags(tmp_path):
    world, res1 = _near(tmp_path)
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    store.stage(res1)
    asker = Asker()
    consent.approve_pending_pin(asker, store, ledger, session_key="t", session_id="s", platform="cli")
    assert "Entries to approve (2):" in asker.asked[0] and "TRUST ON FIRST USE" in asker.asked[0]
    assert "services: shown for review only, not pinned" in asker.asked[0]
    for _ in range(25):
        store.observe(_tinfoil("00" * 32, "00" * 48, None))   # another identity: counts nothing here
    pf = store.load_file()
    pf.identities[0].verifications += 25                     # 25 verifications that never saw these entries
    store.save_file(pf)
    world.model_candidates = 2
    store.stage(world.adapter(tmp_path, encrypt=False).verify())
    asker2 = Asker("deny")
    consent.approve_pending_pin(asker2, store, ledger, session_key="t", session_id="s", platform="cli")
    q = asker2.asked[0]
    assert "Approved set (2 entries; all stay approved):" in q and "Entries to approve (1):" in q
    assert q.count("hermes confidential pins retire") == 2


def test_cli_replay_learns_sets(tmp_path):
    from confidential_mode.commands import _expected_for_row
    world, res = _near(tmp_path)
    store, ledger = PinStore(tmp_path / "pins.yaml"), Ledger()
    store.stage(res)
    _approve(store, ledger)
    fps, source, approved = _expected_for_row(flag=None, pin_records=store.approved_entries(), pins_path="p",
                                              vendor="near", expected_repo=res.router_repo, claimed=(None, None))
    assert fps is None and len(approved) == 2 and "approved set" in source
    from confidential_mode.pins import set_match, views_from_cvms
    from confidential_mode.verify import replay_near
    rr = replay_near.replay(res.evidence, quote_verifier=__import__("tests.near_world", fromlist=["x"]).fake_quote_verifier,
                            ita_roots=world.ita.roots)
    assert set_match(approved, vendor="near", code=rr.code_fingerprint, enclave=rr.enclave_fingerprint,
                     views=views_from_cvms(list(rr.cvms)))

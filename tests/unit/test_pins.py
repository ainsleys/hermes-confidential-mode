"""PinStore over pins.yaml v3 (Tinfoil, one entry per result): match / stage / pending / apply / previous / atomic write."""
from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode import pins as pins_mod  # noqa: E402
from confidential_mode.pins import PendingPin, PinRecord, PinStore, PinStoreError  # noqa: E402
from confidential_mode.verify.base import VerificationResult  # noqa: E402

REPO = "tinfoilsh/confidential-model-router"


def _result(code="c1", enclave="e1", tag="v1", repo=REPO, vendor="tinfoil") -> VerificationResult:
    return VerificationResult(vendor=vendor, router_repo=repo, enclave_host="router.example",
                              code_fingerprint=code, enclave_fingerprint=enclave, release_tag=tag,
                              verifier="tinfoil/0.14.2", verified_at_host_clock=1.0, evidence={"x": 1})


def _approve(store: PinStore, pending: PendingPin, via="cli") -> PinRecord:
    return store.apply(pending, approved_via=via, approval_rule_key="confidential-mode:pin:tinfoil")


def test_empty_store_matches_nothing_and_has_no_pending(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    assert store.match(_result()) is False
    assert store.pending() is None
    assert not (tmp_path / "pins.yaml").exists()


def test_stage_then_apply_then_match(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    pending = store.stage(_result(), model="llama-x")
    assert store.pending() == pending
    assert pending.previous is None and pending.models_seen == ("llama-x",)
    assert store.match(_result()) is False  # staged is not pinned

    rec = _approve(store, pending, via="telegram")
    assert rec.code_fingerprint == "c1" and rec.enclave_fingerprint == "e1" and rec.release_tag == "v1"
    assert rec.approved_by == "human" and rec.approved_via == "telegram"
    assert rec.approval_rule_key == "confidential-mode:pin:tinfoil"
    assert rec.approved_at.endswith("Z") and rec.previous is None
    assert store.pending() is None
    assert store.match(_result()) is True
    # Both fingerprints must match; the key is vendor + router_repo.
    assert store.match(_result(code="c2")) is False
    assert store.match(_result(enclave="e2")) is False
    assert store.match(_result(repo="other/repo")) is False
    assert store.match(_result(vendor="other")) is False


def test_apply_keeps_previous_fingerprint_and_models(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    _approve(store, store.stage(_result(), model="m1"))
    pending = store.stage(_result(code="c2", enclave="e2", tag="v2"), model="m2")
    assert pending.previous == "c1" and pending.previous_enclave_fingerprint == "e1"
    rec = _approve(store, pending)
    assert rec.previous == "c1" and rec.previous_enclave_fingerprint == "e1"
    assert rec.models_seen == ("m1", "m2")
    assert store.match(_result(code="c2", enclave="e2")) and not store.match(_result())


def test_apply_records_caller_supplied_approval_fields(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    rec = store.apply(store.stage(_result()), approved_via="discord", approval_rule_key="k",
                      approved_by="human", approved_at="2026-11-06T00:00:00Z")
    assert (rec.approved_via, rec.approval_rule_key, rec.approved_at) == ("discord", "k", "2026-11-06T00:00:00Z")
    assert PinStore(tmp_path / "pins.yaml").get("tinfoil", REPO) == rec  # round-trips from disk


def test_stage_is_idempotent_for_same_fingerprints_and_replaced_by_different(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    first = store.stage(_result())
    assert store.stage(_result()) == first
    second = store.stage(_result(code="c9"))
    assert second != first and store.pending() == second


def test_apply_refuses_a_pending_that_was_swapped(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    shown = store.stage(_result())
    store.stage(_result(code="evil"))
    with pytest.raises(PinStoreError):
        _approve(store, shown)
    assert store.match(_result()) is False and store.match(_result(code="evil")) is False
    with pytest.raises(PinStoreError):
        _approve(store, replace(store.pending(), code_fingerprint="forged"))


def test_file_is_v3_yaml_and_mode_0600(tmp_path):
    path = tmp_path / "pins.yaml"
    store = PinStore(path)
    _approve(store, store.stage(_result()))
    data = pins_mod.yaml.safe_load(path.read_text())
    (idn,) = data["identities"]
    assert data["version"] == 3 and idn["pending"] == [] and idn["pending_batch"] is None
    (pin,) = idn["approved"]
    assert set(pin) >= {"vendor", "router_repo", "code_fingerprint", "enclave_fingerprint", "release_tag",
                        "models_seen", "approved_by", "approved_at", "approved_via", "approval_rule_key",
                        "previous"}
    assert (path.stat().st_mode & 0o777) == 0o600


def test_unknown_version_or_garbage_fails_closed(tmp_path):
    path = tmp_path / "pins.yaml"
    path.write_text("version: 1\npins: []\n")
    assert PinStore(path).match(_result()) is False  # match never raises (Amendment 4)
    with pytest.raises(PinStoreError):
        PinStore(path).pending()
    path.write_text("{{{not yaml")
    with pytest.raises(PinStoreError):
        PinStore(path).pending()


def test_save_is_atomic_temp_then_replace(tmp_path, monkeypatch):
    path = tmp_path / "pins.yaml"
    store = PinStore(path)
    _approve(store, store.stage(_result()))
    before = path.read_text()

    seen = []
    real_replace = os.replace

    def recording_replace(src, dst):
        seen.append((Path(src).parent, Path(src).name, Path(dst)))
        assert Path(dst).read_text() == before  # target untouched until the rename
        return real_replace(src, dst)
    monkeypatch.setattr(os, "replace", recording_replace)   # pins writes through atomicwrite.write_atomic
    store.stage(_result(code="c2"))
    (src_dir, src_name, dst), = seen
    assert src_dir == tmp_path and src_name.startswith(".pins.yaml.") and dst == path

    # A failure mid-write leaves the old file intact and no temp files behind.
    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", boom)
    after_stage = path.read_text()
    with pytest.raises(OSError):
        store.stage(_result(code="c3"))
    assert path.read_text() == after_stage
    assert sorted(p.name for p in tmp_path.iterdir()) == ["pins.yaml", "pins.yaml.lock"]   # lock file: flock only


def test_note_model_labels_without_affecting_match(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    _approve(store, store.stage(_result()))
    store.note_model("tinfoil", REPO, "deepseek")
    store.note_model("tinfoil", REPO, "deepseek")
    assert store.get("tinfoil", REPO).models_seen == ("deepseek",)
    assert store.match(_result())


def test_pending_pin_is_frozen_with_value_equality(tmp_path):
    import dataclasses
    store = PinStore(tmp_path / "pins.yaml")
    shown = store.stage(_result())
    reread = PinStore(tmp_path / "pins.yaml").pending()
    assert reread == shown and reread is not shown  # value equality across a disk round-trip
    with pytest.raises(dataclasses.FrozenInstanceError):
        shown.code_fingerprint = "x"


def test_apply_requires_surface_and_defaults_rule_key(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    pending = store.stage(_result())
    with pytest.raises(TypeError):
        store.apply(pending)  # approved_via is a required keyword
    with pytest.raises(ValueError):
        store.apply(pending, approved_via="")
    rec = store.apply(pending, approved_via="slack")
    assert rec.approved_via == "slack" and rec.approval_rule_key == pins_mod.DEFAULT_APPROVAL_RULE_KEY


def test_restage_same_fingerprints_different_release_tag_is_a_swap(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    shown = store.stage(_result(tag="v1"))
    swapped = store.stage(_result(tag="v1-relabelled"))
    assert swapped != shown and store.pending() == swapped
    with pytest.raises(PinStoreError):
        store.apply(shown, approved_via="cli")


def test_apply_is_idempotent_per_pending(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    _approve(store, store.stage(_result()))
    pending = store.stage(_result(code="c2"))
    first = store.apply(pending, approved_via="cli")
    again = store.apply(pending, approved_via="cli")
    assert again == first and again.previous == "c1"  # not re-applied (previous would become c2)
    assert PinStore(tmp_path / "pins.yaml").get("tinfoil", REPO) == first
    # A different, never-staged pending is still refused.
    with pytest.raises(PinStoreError):
        store.apply(replace(pending, code_fingerprint="c3"), approved_via="cli")


def test_empty_fingerprints_are_never_staged_or_matched(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    for code, enclave in (("", "e1"), ("c1", ""), ("  ", "e1")):
        with pytest.raises(PinStoreError):
            store.stage(_result(code=code, enclave=enclave))
        assert store.match(_result(code=code, enclave=enclave)) is False
    assert store.pending() is None

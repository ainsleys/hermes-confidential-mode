"""PendingPin prompt context and the platform-only auto-approval policy (no Hermes, no network)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode import provider as provider_mod  # noqa: E402
from confidential_mode.pins import PinStore, compare_url, release_url  # noqa: E402
from confidential_mode.verify.base import VerificationResult  # noqa: E402

REPO = "tinfoilsh/confidential-model-router"
STEPS_OK = {k: {"status": "success"} for k in ("fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements")}


def _result(code="c1", enclave="e1", tag="v1", platform="sev-snp", hw=False, steps=STEPS_OK):
    doc = {"steps": steps}
    if hw:
        doc["hardwareMeasurement"] = {"ID": "platform-a@digest", "MRTD": "aa", "RTMR0": "bb"}
    ev = {"platform": platform, "release": {"tag": tag, "digest": "d", "published_at": "2026-11-01T00:00:00Z"},
          "sigstore_bundle": '{"verificationMaterial": {"tlogEntries": [{"logIndex": "42"}]}}',
          "verification_document": doc}
    return VerificationResult(vendor="tinfoil", router_repo=REPO, enclave_host="r.example", code_fingerprint=code,
                              enclave_fingerprint=enclave, release_tag=tag, verifier="tinfoil/0.14.2",
                              verified_at_host_clock=0.0, evidence=ev)


def test_url_helpers():
    assert release_url(REPO, "v1.2") == f"https://github.com/{REPO}/releases/tag/v1.2"
    assert compare_url(REPO, "v1.1", "v1.2") == f"https://github.com/{REPO}/compare/v1.1...v1.2"
    assert compare_url(REPO, "v1.2", "v1.2") is None and compare_url(REPO, None, "v1") is None
    assert release_url(REPO, None) is None


def test_pending_pin_fields_for_a_platform_flap_and_a_code_change(tmp_path):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    flap = store.stage(_result(enclave="e-tdx", platform="tdx", hw=True))
    assert (flap.platform, flap.previous_platform) == ("tdx", "sev-snp")
    assert flap.code_changed is False and flap.platform_only is True and flap.hardware_measurements_verified
    assert flap.previous_enclave_fingerprint == "e1" and flap.rekor_log_index == 42
    assert flap.release_published_at == "2026-11-01T00:00:00Z" and flap.enclave_host == "r.example"
    new = store.stage(_result(code="c2", tag="v2"))
    assert new.code_changed is True and new.platform_only is False and new.previous_release_tag == "v1"
    assert new.compare_url == f"https://github.com/{REPO}/compare/v1...v2"
    assert PinStore(tmp_path / "pins.yaml").pending() == new  # round-trips with the new fields


class _Adapter:
    vendor = "tinfoil"
    enclave_host = "r.example"
    base_url = "https://r.example/v1"

    def __init__(self, results):
        self.results = list(results)

    def verify(self):
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]

    def hold(self, reason):
        self.held = reason

    def release(self):
        self.held = None


def _cache(tmp_path, results, *, auto):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    events = []
    cache = provider_mod.VerificationCache(clock=lambda: 0.0)
    cache.register("attested-tinfoil", _Adapter(results), store, 300.0, on_event=events.append)
    e = cache.entry("attested-tinfoil")
    e.auto_approve_platform_only = auto
    return cache, store, events


def test_platform_only_flap_is_auto_applied_when_enabled(tmp_path):
    cache, store, events = _cache(tmp_path, [_result(enclave="e-tdx", platform="tdx", hw=True)], auto=True)
    ok, reason, _ = cache.ensure("attested-tinfoil")
    assert ok is True and "platform-only" in reason
    rec = store.get("tinfoil", REPO)
    assert rec.enclave_fingerprint == "e-tdx" and rec.approved_via == "auto_platform_only"
    assert rec.approved_by == "policy" and rec.platform == "tdx" and store.pending() is None
    applied = [ev for ev in events if ev["kind"] == "pin_applied"]
    assert len(applied) == 1 and applied[0]["decision"] == "auto_platform_only"
    assert applied[0]["detail"]["previous_enclave_fingerprint"] == "e1"


@pytest.mark.parametrize("case", ["disabled", "code_changed", "no_hw_check_sev", "hw_step_failed"])
def test_auto_approval_does_not_apply(tmp_path, case):
    result = {
        "disabled": _result(enclave="e-tdx", platform="tdx", hw=True),
        "code_changed": _result(code="c2", enclave="e-tdx", platform="tdx", hw=True),
        "no_hw_check_sev": _result(enclave="e-other", platform="sev-snp"),
        "hw_step_failed": _result(enclave="e-tdx", platform="tdx", hw=True,
                                  steps={**STEPS_OK, "verifyEnclave": {"status": "failed"}}),
    }[case]
    cache, store, events = _cache(tmp_path, [result], auto=case != "disabled")
    ok, reason, _ = cache.ensure("attested-tinfoil")
    assert ok is False and reason == provider_mod.REASON_PIN_MISMATCH
    assert store.get("tinfoil", REPO).enclave_fingerprint == "e1" and store.pending() is not None
    assert [ev["kind"] for ev in events] == ["verify_ok", "pin_staged"]


def test_auto_applied_pin_satisfies_the_consent_cross_check(tmp_path):
    from confidential_mode.ledger import Ledger
    led = Ledger(tmp_path / "ledger.sqlite")
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    led.append({"kind": "pin_applied", "decision": "approve",
                "detail": {"vendor": "tinfoil", "code_fingerprint": "c1", "enclave_fingerprint": "e1"}})
    cache = provider_mod.VerificationCache(clock=lambda: 0.0)
    cache.register("attested-tinfoil", _Adapter([_result(enclave="e-tdx", platform="tdx", hw=True)]), store,
                   300.0, on_event=led.append)
    e = cache.entry("attested-tinfoil")
    e.auto_approve_platform_only, e.consent_ledger = True, led
    ok, reason, _ = cache.ensure("attested-tinfoil")
    assert ok is True, reason
    assert [r.decision for r in led.tail() if r.kind == "pin_applied"] == ["approve", "auto_platform_only"]

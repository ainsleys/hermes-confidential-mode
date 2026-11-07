"""Preflight items for NEAR request encryption (Amendment 5.1): every attested-near route, fallback
chains included, speaks chat completions; encryption and the TLS pin are on in the config and in the
running adapter; PyNaCl imports. Absent or exactly true passes; any other value is refused."""
from __future__ import annotations

import pytest

from confidential_mode.preflight import run_preflight
from confidential_mode.tiers import AttestedPredicate, Tier, Verdict


class _Adapter:
    encrypt = True
    require_tls_binding = True

    def encryption_ready(self):
        return True, ""


class _Profile:
    base_url = "https://cloud-api.near.ai/v1"

    def __init__(self, adapter=None):
        self._confidential_adapter = adapter or _Adapter()


def run(cfg, adapter=None):
    pred = AttestedPredicate({"attested-tinfoil", "attested-near"}, lambda _p: Verdict(True, "fresh", ""))
    profile = _Profile(adapter)
    return run_preflight(Tier.ATTESTED, pred, cfg, plugin_aux_tasks=[], isolation="in_process",
                         provider_lookup=lambda n: profile, attested_profile="attested-tinfoil",
                         builtin_aux_tasks=["compression"])


def items(report):
    return {i.key: i.verdict for i in report.items}


BASE = {"model": {"provider": "attested-near", "default": "m"},
        "auxiliary": {"compression": {"provider": "attested-near", "model": "m"}}}


def test_defaults_pass():
    v = items(run(BASE))
    assert v["confidential.near.encrypt"] == "in_tier" and v["confidential.near.require_tls_binding"] == "in_tier"
    assert v["confidential.near.encryption_library"] == "in_tier"


@pytest.mark.parametrize("key,value", [("encrypt", False), ("encrypt", "no"), ("encrypt", 0), ("encrypt", None),
                                       ("require_tls_binding", False), ("require_tls_binding", "false")])
def test_switches_must_be_absent_or_exactly_true(key, value):
    cfg = {**BASE, "confidential": {"near": {key: value}}}
    assert items(run(cfg))[f"confidential.near.{key}"] == "off_tier"


def test_running_adapter_with_encryption_or_pin_off_refuses():
    a = _Adapter()
    a.encrypt, a.require_tls_binding = False, False
    v = items(run(BASE, a))
    assert v["confidential.near.encrypt"] == "off_tier" and v["confidential.near.require_tls_binding"] == "off_tier"


def test_missing_library_is_missing():
    a = _Adapter()
    a.encryption_ready = lambda: (False, "pynacl unavailable")
    assert items(run(BASE, a))["confidential.near.encryption_library"] == "missing"


def test_attested_near_only_in_an_aux_fallback_chain_is_still_checked():
    cfg = {"model": {"provider": "attested-tinfoil", "default": "t"},
           "auxiliary": {"compression": {"provider": "attested-tinfoil", "model": "t",
                                         "fallback_chain": [{"provider": "attested-near", "model": "m",
                                                             "api_mode": "codex_responses"}]}},
           "confidential": {"near": {"encrypt": False}}}
    v = items(run(cfg))
    assert v["confidential.near.encrypt"] == "off_tier"
    assert v["auxiliary.compression.fallback_chain[0].api_mode"] == "off_tier"


def test_no_near_route_adds_no_near_items():
    cfg = {"model": {"provider": "attested-tinfoil", "default": "t"}}
    assert not any(k.startswith("confidential.near") for k in items(run(cfg)))


@pytest.mark.parametrize("value,verdict,shown", [(None, "in_tier", "disclose"), ("disclose", "in_tier", "disclose"),
                                                 ("refuse", "in_tier", "refuse"), ("maybe", "off_tier", "maybe"),
                                                 (True, "off_tier", "True")])
def test_image_parts_accepts_both_values_and_shows_the_one_in_force(value, verdict, shown):
    """Amendment 9: confidential.near.image_parts is disclose (default) or refuse; the item shows which."""
    cfg = BASE if value is None else {**BASE, "confidential": {"near": {"image_parts": value}}}
    item = next(i for i in run(cfg).items if i.key == "confidential.near.image_parts")
    assert item.verdict == verdict and shown in str(item.value_redacted)

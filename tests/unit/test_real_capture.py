"""Replay of a REAL Tinfoil capture (router-0.tinfoil.sh, SEV-SNP, release v0.0.170, 2026-11-06), offline.

tests/fixtures/real_capture_sev/evidence.json was captured by TinfoilAdapter.verify() against the live
service; it contains no secret (attestation report, VCEK, release metadata, Sigstore bundle, claims).
trusted_root.json is the Sigstore public-good root the capture used (sha256 6494e21e..., identical to
sigstore-python 4.5.1's embedded copy). Everything here runs with the network blocked: real AMD
signature and chain, real Sigstore DSSE + Rekor inclusion proof, real policy.
"""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
pytest.importorskip("tinfoil.client")

from confidential_mode.verify import policy_check  # noqa: E402
from confidential_mode.verify.replay import replay  # noqa: E402

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "real_capture_sev"
REPO = "tinfoilsh/confidential-model-router"
REPO_ID, OWNER_ID = "1077094187", "168487856"
CODE_FP = "284bd9e5d470c4812fad60fcec6f99bc0958cd5a1ef4d317a99f702e2913f5fb"
ENCLAVE_FP = "fb8eabe68d3b977b05e48e7a41aff6bbb6dc576cbf5639360fbdf49f357f7d6698be2537f1a425975f89b8a73023022a"


@pytest.fixture
def offline(tmp_path, monkeypatch):
    attempts = []

    def blocked(*a, **k):
        attempts.append(repr(a[:1]))
        raise OSError("NETWORK BLOCKED (test)")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return attempts


@pytest.fixture
def ev():
    return json.loads((FIX / "evidence.json").read_text())


@pytest.fixture
def root():
    return (FIX / "trusted_root.json").read_bytes()


def test_fixture_facts(ev, root):
    assert ev["enclave_host"] == "router-0.tinfoil.sh" and ev["platform"] == "sev-snp"
    assert ev["release"]["tag"] == "v0.0.170" and ev["capture_complete"] is True
    assert hashlib.sha256(root).hexdigest() == ev["trusted_root"]["sha256"]


def test_real_capture_replays_offline_with_numeric_ids(ev, root, offline):
    r = replay(ev, trusted_root=root, expected_repo_id=REPO_ID, expected_owner_id=OWNER_ID,
               expected_fingerprints=(CODE_FP, ENCLAVE_FP))
    assert r.ok is True, r.checks
    assert r.checks["repo_identity"] == "name+id" and r.checks["policy_check"] is True
    assert r.checks["sev_check"] is True and len(r.sev_checker_sha256) == 64 and len(r.policy_checker_sha256) == 64
    assert r.checks["trust_root_source"] == "supplied"
    assert (r.code_fingerprint, r.enclave_fingerprint) == (CODE_FP, ENCLAVE_FP)
    assert r.build_signer_uri == f"https://github.com/{REPO}/.github/workflows/tinfoil-release-publish.yml@refs/tags/v0.0.170"
    assert r.source_commit == "e9f72fae02276a8d3af72d0f0ab1c1d1ca48dec8"
    assert (r.log_index, r.integrated_time) == (3692488892, 1793849732)
    assert r.enclave_host_asserted == "router-0.tinfoil.sh" and r.platform == "sev-snp"
    assert offline == []


def test_real_capture_wrong_repo_id_fails(ev, root, offline):
    r = replay(ev, trusted_root=root, expected_repo_id="1", expected_owner_id=OWNER_ID)
    assert r.ok is False and r.checks["repo_identity"].startswith("fail:")
    assert r.checks["policy_check"].startswith("fail:")


@pytest.mark.parametrize("case,failed", [
    ("report_byte", "hardware_signature"),
    ("vcek", "cert_chain"),
    ("release_tag", "code_signature"),
    ("release_digest", "code_signature"),
    ("bundle_payload", "code_signature"),
    ("repo", "repo_match"),
    ("claimed_hpke", "report_data_keys"),
    ("expected_fps", "measurement_match"),
])
def test_real_capture_tampering(ev, root, offline, case, failed):
    e = copy.deepcopy(ev)
    kw = {}
    if case == "report_byte":
        raw = bytearray(gzip.decompress(base64.b64decode(e["attestation"]["body"])))
        raw[0x90] ^= 1  # one bit of the measurement
        e["attestation"]["body"] = base64.b64encode(gzip.compress(bytes(raw))).decode()
    elif case == "vcek":
        der = bytearray(base64.b64decode(e["sev"]["vcek_der_b64"]))
        der[-10] ^= 1  # inside the ASK's signature over the VCEK
        e["sev"]["vcek_der_b64"] = base64.b64encode(bytes(der)).decode()
    elif case == "release_tag":
        e["release"]["tag"] = "v0.0.171"
    elif case == "release_digest":
        e["release"]["digest"] = "00" * 32
    elif case == "bundle_payload":
        b = json.loads(e["sigstore_bundle"])
        p = bytearray(base64.b64decode(b["dsseEnvelope"]["payload"]))
        p[-5] ^= 1
        b["dsseEnvelope"]["payload"] = base64.b64encode(bytes(p)).decode()
        e["sigstore_bundle"] = json.dumps(b)
    elif case == "repo":
        e["repo"] = "attacker/router"
    elif case == "claimed_hpke":
        e["claims"]["hpke_public_key"] = "00" * 32
    elif case == "expected_fps":
        kw["expected_fingerprints"] = (CODE_FP, "00" * 48)
    r = replay(e, trusted_root=root, **kw)
    assert r.ok is False and isinstance(r.checks[failed], str) and r.checks[failed].startswith("fail:"), r.checks
    assert offline == []


def test_standalone_policy_check_passes_on_the_real_bundle_in_an_isolated_interpreter(ev, tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(ev["sigstore_bundle"])
    block = ("import socket,runpy,sys\n"
             "def b(*a,**k): raise OSError('NETWORK BLOCKED')\n"
             "socket.create_connection=b; socket.getaddrinfo=b\n"
             f"sys.argv=['policy_check.py','--bundle',{str(bundle)!r},'--digest',{ev['release']['digest']!r},"
             f"'--repo',{REPO!r},'--tag','v0.0.170','--trusted-root',{str(FIX / 'trusted_root.json')!r},"
             f"'--repo-id',{REPO_ID!r},'--owner-id',{OWNER_ID!r}]\n"
             f"runpy.run_path({policy_check.__file__!r}, run_name='__main__')\n")
    done = subprocess.run([sys.executable, "-I", "-c", block], capture_output=True, text=True, timeout=120,
                          env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, (done.stdout, done.stderr[-2000:])
    out = json.loads(done.stdout)
    assert out["ok"] is True and out["log_index"] == 3692488892 and out["repo_id"] == REPO_ID
    assert out["commit"] == "e9f72fae02276a8d3af72d0f0ab1c1d1ca48dec8"


@pytest.mark.parametrize("kw", [{"tag": "v0.0.17"}, {"tag": "v0.0.1700"}, {"repo": "tinfoilsh/other"},
                                {"expected_repo_id": "1"}, {"digest": "00" * 32},
                                {"predicate_type": policy_check.PREDICATE_HARDWARE}])
def test_standalone_policy_check_rejects_mismatches_on_the_real_bundle(ev, root, offline, kw):
    args = dict(digest=ev["release"]["digest"], repo=REPO, tag="v0.0.170", trusted_root=root)
    args.update(kw)
    r = policy_check.check_bundle(ev["sigstore_bundle"], **args)
    assert r.ok is False, r


def test_verify_time_policy_check_detail_on_the_real_capture(ev, offline):
    from confidential_mode import provider as provider_mod
    e = copy.deepcopy(ev)
    e["trusted_root"]["path"] = str(FIX / "trusted_root.json")
    d = provider_mod._policy_check_detail(e)
    assert d["ok"] is True and d["repo_id"] == REPO_ID, d

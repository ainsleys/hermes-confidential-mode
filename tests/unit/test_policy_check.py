"""verify/policy_check.py: the restated Sigstore policy, run with no tinfoil code.

A real Sigstore bundle (Fulcio cert with SCT, Rekor inclusion proof and checkpoint) cannot be produced
offline, so the sigstore-python calls (_load_bundle / _make_verifier) are replaced by stand-ins that
still hand the REAL _Policy object the bundle's certificate; every structural rule is real. One test
runs the unpatched sigstore-python path on a junk bundle, offline, in an isolated interpreter.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_replay import (  # noqa: E402
    COMMIT,
    DIGEST,
    OWNER_ID,
    REPO,
    REPO_ID,
    TAG,
    code_statement,
    fake_sigstore,  # noqa: F401 - a pytest fixture, taken by name below
    fulcio_cert_der,
    signed_bundle,
)

from confidential_mode.verify import policy_check as pc  # noqa: E402

ROOT = b"{}"  # never parsed by these stand-ins except where stated


@pytest.fixture
def stub(fake_sigstore, monkeypatch):
    monkeypatch.setattr(pc, "_make_verifier", _verifier)
    return fake_sigstore


class _verifier:
    def __init__(self, root):
        pass

    def verify_dsse(self, bundle, policy):
        policy.verify(bundle.signing_certificate)
        payload = base64.b64decode(bundle.raw["testEnvelope"]["payload"])
        return bundle.raw.get("_payload_type", "application/vnd.in-toto+json"), json.dumps(
            json.loads(payload)["statement"]).encode()


def _check(bundle: dict, **kw):
    kw.setdefault("digest", DIGEST)
    kw.setdefault("repo", REPO)
    kw.setdefault("tag", TAG)
    return pc.check_bundle(json.dumps(bundle), trusted_root=ROOT, **kw)


def test_good_bundle_passes_and_extracts_the_identity(stub):
    r = _check(signed_bundle(code_statement(), repo=REPO, tag=TAG), expected_repo_id=REPO_ID,
               expected_owner_id=OWNER_ID)
    assert r.ok, r.reason
    assert (r.log_index, r.integrated_time, r.repo_id, r.owner_id, r.commit) == (
        123456789, 1762400000, REPO_ID, OWNER_ID, COMMIT)
    assert r.workflow == f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{TAG}"
    assert r.repository == REPO


@pytest.mark.parametrize("tag,ok", [(TAG, True), ("v1.2", False), ("v1.2.", False), ("v1.2.3-evil", False)])
def test_tag_is_escaped_and_anchored(stub, tag, ok):
    """The cert says refs/tags/v1.2.3. Asking for 'v1.2' must not prefix-match, '.' must not be a
    wildcard, and a cert for v1.2.3 must not satisfy a request for another tag."""
    r = _check(signed_bundle(code_statement(), repo=REPO, tag=TAG), tag=tag)
    assert r.ok is ok, r.reason


def test_cert_ref_with_trailing_text_fails(stub):
    r = _check(signed_bundle(code_statement(), repo=REPO, tag=TAG + "\n"), tag=TAG)
    assert not r.ok


@pytest.mark.parametrize("mutate,needle", [
    (lambda b: b["verificationMaterial"].update(x509CertificateChain={"certificates": []}), "legacy"),
    (lambda b: b.update(_payload_type="text/plain"), "payload type"),
], ids=["legacy-layout", "payload-type"])
def test_bundle_shape_rejections(stub, mutate, needle):
    b = signed_bundle(code_statement(), repo=REPO, tag=TAG)
    mutate(b)
    r = _check(b)
    assert not r.ok and needle in r.reason


def _statement_bundle(st):
    return signed_bundle(st, repo=REPO, tag=TAG)


@pytest.mark.parametrize("edit,needle", [
    (lambda st: st.update(extra=1), "unknown field"),
    (lambda st: st["subject"].append({"name": "y", "digest": {"sha256": DIGEST}}), "exactly one subject"),
    (lambda st: st.update(subject=[]), "exactly one subject"),
    (lambda st: st["subject"][0]["digest"].update(sha256="00" * 32), "subject digest"),
    (lambda st: st.update(predicateType="https://example/other"), "predicateType"),
], ids=["unknown-field", "two-subjects", "no-subject", "digest", "predicate-type"])
def test_statement_rejections(stub, edit, needle):
    st = code_statement()
    edit(st)
    r = _check(_statement_bundle(st))
    assert not r.ok and needle in r.reason, r.reason


def test_ids_wrong_or_missing(stub):
    assert not _check(signed_bundle(code_statement(), repo=REPO, tag=TAG, repo_id="1"), expected_repo_id=REPO_ID).ok
    assert not _check(signed_bundle(code_statement(), repo=REPO, tag=TAG, owner_id=None),
                      expected_owner_id=OWNER_ID).ok
    assert _check(signed_bundle(code_statement(), repo=REPO, tag=TAG, repo_id="1")).ok  # ids not requested


def test_issuer_v2_is_authoritative(stub, monkeypatch):
    """A cert whose V2 issuer is wrong fails even if a V1 issuer would have been right."""
    real = pc._ext_text
    monkeypatch.setattr(pc, "_ext_text", lambda cert, oid: "https://evil.example" if oid == pc.OID_ISSUER_V2
                        else ("https://token.actions.githubusercontent.com" if oid == pc.OID_ISSUER_V1
                              else real(cert, oid)))
    r = _check(signed_bundle(code_statement(), repo=REPO, tag=TAG))
    assert not r.ok and "issuer" in r.reason


def test_repository_name_from_source_uri_must_agree(stub):
    # v1 repository says the right name, the V2 source URI says another: stricter than the SDK, rejected.
    b = signed_bundle(code_statement(), repo=REPO, tag=TAG)
    other = fulcio_cert_der("attacker/router", TAG)
    b["verificationMaterial"]["certificate"]["rawBytes"] = base64.b64encode(other).decode()
    assert not _check(b).ok


def test_unpatched_sigstore_path_rejects_junk_offline_in_an_isolated_interpreter(tmp_path):
    import sigstore as _sg
    root = (Path(_sg.__file__).parent / "_store" / "https%3A%2F%2Ftuf-repo-cdn.sigstore.dev" /
            "trusted_root.json")
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps(signed_bundle(code_statement(), repo=REPO, tag=TAG)))
    block = ("import socket,runpy,sys\n"
             "def b(*a,**k): raise OSError('NETWORK BLOCKED')\n"
             "socket.create_connection=b; socket.getaddrinfo=b\n"
             f"sys.argv=['policy_check.py','--bundle',{str(bundle)!r},'--digest',{DIGEST!r},'--repo',{REPO!r},"
             f"'--tag',{TAG!r},'--trusted-root',{str(root)!r}]\n"
             f"runpy.run_path({pc.__file__!r}, run_name='__main__')\n")
    done = subprocess.run([sys.executable, "-I", "-c", block], capture_output=True, text=True, timeout=120)
    assert done.returncode == 1, (done.returncode, done.stderr[-2000:])
    out = json.loads(done.stdout)
    assert out["ok"] is False and "NETWORK" not in out["reason"] and "TUF" not in out["reason"], out

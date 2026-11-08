"""verify/sev_check.py, the standalone SEV-SNP checker, on the REAL capture (router-0, 2026-11-06) and
on each tampering. No tinfoil import in the checker; tinfoil is used here only for the one-off ARK/ASK
cross-check."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode.verify import sev_check  # noqa: E402

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "real_capture_sev" / "evidence.json"
AS_OF = datetime(2026, 11, 6, 17, 0, tzinfo=UTC)


@pytest.fixture
def ev():
    return json.loads(FIX.read_text())


def _report(ev) -> bytearray:
    return bytearray(gzip.decompress(base64.b64decode(ev["attestation"]["body"])))


def _pack(r: bytes) -> str:
    return base64.b64encode(gzip.compress(bytes(r))).decode()


def _vcek(ev) -> bytes:
    return base64.b64decode(ev["sev"]["vcek_der_b64"])


def test_real_capture_passes(ev):
    r = sev_check.check(ev["attestation"]["body"], _vcek(ev), as_of=AS_OF)
    assert r.ok, r.reason
    assert r.measurement == ev["claims"]["enclave_fingerprint"]
    assert (r.tls_key_fp, r.hpke_public_key) == (ev["claims"]["tls_public_key_fp"], ev["claims"]["hpke_public_key"])
    assert r.vmpl == 0 and r.version == 5
    assert r.tcb["current"] == {"bl": 0x0A, "tee": 0, "snp": 0x1B, "ucode": 0x58}
    assert r.checker_sha256 == hashlib.sha256(Path(sev_check.__file__).read_bytes()).hexdigest()


def test_pinned_ark_ask_match_the_sdk_embedded_copies():
    pytest.importorskip("tinfoil.client")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from tinfoil.attestation.genoa_cert_chain import ARK_CERT, ASK_CERT
    for pem, pinned in ((ARK_CERT, sev_check.ARK_SHA256), (ASK_CERT, sev_check.ASK_SHA256)):
        der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
        assert hashlib.sha256(der).hexdigest() == pinned


def _bump(r, off, n, fn):
    v = int.from_bytes(r[off:off + n], "little")
    r[off:off + n] = fn(v).to_bytes(n, "little")


TCB_OFFSETS = (0x38, 0x180, 0x1E0)  # current, reported, committed


@pytest.mark.parametrize("case,needle", [
    ("measurement_bit", "InvalidSignature"),
    ("signature_bit", "InvalidSignature"),
    ("debug", "DEBUG"),
    ("migrate_ma", "migration agent"),
    ("vmpl", "VMPL"),
    ("tcb_below_floor", "below the"),
    ("current_ne_committed", "provisional"),
    ("vcek_spl_mismatch", "SPL does not equal"),
    ("chip_id", "HWID"),
    ("not_genoa", "not Genoa"),
    ("not_vcek_signed", "not VCEK-signed"),
    ("trailing_bytes", "not zero"),
    ("truncated", "bytes, expected"),
])
def test_report_tampering_fails(ev, case, needle):
    r = _report(ev)
    if case == "measurement_bit":
        r[0x90] ^= 1
    elif case == "signature_bit":
        r[0x2A0] ^= 1
    elif case == "debug":
        _bump(r, 0x08, 8, lambda v: v | (1 << 19))
    elif case == "migrate_ma":
        _bump(r, 0x08, 8, lambda v: v | (1 << 18))
    elif case == "vmpl":
        _bump(r, 0x30, 4, lambda v: 1)
    elif case == "tcb_below_floor":
        for off in TCB_OFFSETS:
            r[off + 7] = 0x57  # microcode one below the dated minimum
    elif case == "current_ne_committed":
        r[0x38 + 6] = 0x1C
    elif case == "vcek_spl_mismatch":
        for off in TCB_OFFSETS:
            r[off + 6] = 0x1C  # snp SPL above what the VCEK was issued for
    elif case == "chip_id":
        r[0x1A0] ^= 1
    elif case == "not_genoa":
        r[0x189] = 0x01  # Milan model
    elif case == "not_vcek_signed":
        _bump(r, 0x48, 4, lambda v: v | (1 << 2))
    elif case == "trailing_bytes":
        r[0x49F] = 1
    elif case == "truncated":
        r = r[:-1]
    res = sev_check.check(_pack(r), _vcek(ev), as_of=AS_OF)
    assert not res.ok and needle in res.reason, res.reason


@pytest.mark.parametrize("case,needle", [
    ("vcek_signature_bit", "InvalidSignature"),
    ("other_ark", "pinned"),
    ("expired", "not valid at"),
    ("before_issue", "not valid at"),
])
def test_chain_tampering_fails(ev, case, needle):
    vcek, kw, when = _vcek(ev), {}, AS_OF
    if case == "vcek_signature_bit":
        b = bytearray(vcek)
        b[-10] ^= 1
        vcek = bytes(b)
    elif case == "other_ark":
        kw["ark_pem"] = sev_check.ASK_PEM  # any cert that is not the pinned ARK
    elif case == "expired":
        when = datetime(2034, 1, 1, tzinfo=UTC)
    elif case == "before_issue":
        when = datetime(2026, 8, 1, tzinfo=UTC)  # before the VCEK's notBefore
    res = sev_check.check(ev["attestation"]["body"], vcek, as_of=when, **kw)
    assert not res.ok and needle in res.reason, res.reason


def test_runs_isolated_without_tinfoil(ev, tmp_path):
    import re
    src = Path(sev_check.__file__).read_text()
    assert not re.search(r"^\s*(import|from)\s+(tinfoil|confidential_mode|\.)", src, re.M)
    (tmp_path / "vcek.der").write_bytes(_vcek(ev))
    block = ("import socket,runpy,sys\n"
             "def b(*a,**k): raise OSError('NETWORK BLOCKED')\n"
             "socket.create_connection=b; socket.getaddrinfo=b\n"
             "sys.modules['tinfoil']=None\n"  # importing tinfoil would now fail
             f"sys.argv=['sev_check.py','--report-b64',{ev['attestation']['body']!r},'--vcek',"
             f"{str(tmp_path / 'vcek.der')!r},'--as-of','2026-11-06T17:00:00Z']\n"
             f"runpy.run_path({sev_check.__file__!r}, run_name='__main__')\n")
    done = subprocess.run([sys.executable, "-I", "-c", block], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, (done.stdout, done.stderr[-2000:])
    assert json.loads(done.stdout)["ok"] is True

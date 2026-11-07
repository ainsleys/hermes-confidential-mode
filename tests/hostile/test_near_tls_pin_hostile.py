"""Hostile pass on the per-send TLS pin for NEAR (codebase review finding 1, HIGH).

The attested gateway quote binds the SPKI fingerprint of its TLS certificate. Before this change the
binding was checked on the attestation GET only and merely recorded per send. Now:
  * every inference or signature-fetch connection is pinned at the handshake, before a request byte is
    written (verify/near.py ``pinned_ssl_context``), sync and async; tested here against a real local TLS
    server that counts the application bytes it receives;
  * the per-response observation feeds the send verdict: a certificate other than the attested one makes
    the send "unverified" and removes "fully attested".
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import ipaddress
import socket
import ssl
import threading

import httpx
import openai
import pytest

from confidential_mode.verify.base import VerifyError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from confidential_mode.verify import near
from confidential_mode.verify.near import TLSPinMismatch, pinned_ssl_context

from ..near_world import BASE, MODEL, NearWorld, tls_cert

MSG = [{"role": "user", "content": "hi"}]


# ── a real TLS server on 127.0.0.1 ───────────────────────────────────────────────────────────────

def _server_cert(tmp_path):
    """A test CA and a server leaf for localhost (a leaf shape platform trust stores accept too)."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "confidential-mode test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert_pem, key_pem, ca_pem = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "ca.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert_pem, key_pem, ca_pem, hashlib.sha256(spki).hexdigest()


def _plain_ssl_class():
    """OpenSSL's own SSLContext, even when an earlier test let Hermes inject truststore."""
    try:
        from truststore._api import _original_SSLContext
        return _original_SSLContext
    except Exception:
        return ssl.SSLContext


class TLSServer:
    """Accepts TLS connections; answers any request with a small HTTP 200 and counts application bytes."""

    def __init__(self, cert_pem, key_pem):
        self.ctx = _plain_ssl_class()(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_pem, key_pem)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.app_bytes = 0
        self.handshakes = 0
        self._stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            raw.settimeout(5)
            conn = self.ctx.wrap_socket(raw, server_side=True)
            self.handshakes += 1
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.app_bytes += len(data)
            if data:
                body = b'{"ok": true}'
                conn.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: "
                             + str(len(body)).encode() + b"\r\nconnection: close\r\n\r\n" + body)
            conn.close()
        except Exception:
            try:
                raw.close()
            except Exception:
                pass

    def close(self):
        self._stop = True
        self.sock.close()


def _trusting(ca_pem) -> ssl.SSLContext:
    """A client context that trusts only the test CA. Built from ssl.SSLContext directly: another test may
    have injected truststore, which routes create_default_context() to the platform store."""
    ctx = _plain_ssl_class()(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_pem))
    return ctx


@pytest.fixture
def server(tmp_path):
    cert_pem, key_pem, ca_pem, fp = _server_cert(tmp_path)
    srv = TLSServer(cert_pem, key_pem)
    srv.fp = fp
    srv.trust = lambda: _trusting(ca_pem)
    yield srv
    srv.close()


def _settle(srv):
    for _ in range(50):
        if srv.handshakes:
            break
        threading.Event().wait(0.02)
    threading.Event().wait(0.1)


def test_sync_pin_matching_fingerprint_sends(server):
    t = httpx.HTTPTransport(retries=0, verify=pinned_ssl_context(lambda: server.fp, base=server.trust))
    with httpx.Client(transport=t) as c:
        assert c.get(f"https://localhost:{server.port}/v1/x").json() == {"ok": True}
    assert server.app_bytes > 0


def test_sync_pin_mismatch_refuses_before_any_request_byte(server):
    t = httpx.HTTPTransport(retries=0, verify=pinned_ssl_context(lambda: "ee" * 32, base=server.trust))
    with httpx.Client(transport=t) as c, pytest.raises(TLSPinMismatch, match="refused before sending"):
        c.post(f"https://localhost:{server.port}/v1/chat/completions", content=b'{"secret": "plaintext"}')
    _settle(server)
    assert server.handshakes == 1 and server.app_bytes == 0


def test_sync_pin_without_an_attested_fingerprint_refuses(server):
    t = httpx.HTTPTransport(retries=0, verify=pinned_ssl_context(lambda: None, base=server.trust))
    with httpx.Client(transport=t) as c, pytest.raises(TLSPinMismatch, match="no attested gateway TLS"):
        c.get(f"https://localhost:{server.port}/v1/x")
    _settle(server)
    assert server.app_bytes == 0


def test_async_pin_mismatch_refuses_before_any_request_byte(server):
    async def go(fp):
        t = httpx.AsyncHTTPTransport(retries=0, verify=pinned_ssl_context(lambda: fp, base=server.trust))
        async with httpx.AsyncClient(transport=t) as c:
            return (await c.get(f"https://localhost:{server.port}/v1/x")).json()
    with pytest.raises(TLSPinMismatch):
        asyncio.run(go("ee" * 32))
    _settle(server)
    assert server.app_bytes == 0
    assert asyncio.run(go(server.fp)) == {"ok": True}
    assert server.app_bytes > 0


def test_pin_keeps_the_normal_chain_check(server):
    """The pin is added to, never substituted for, certificate validation."""
    t = httpx.HTTPTransport(retries=0, verify=pinned_ssl_context(lambda: server.fp))  # system roots only
    with httpx.Client(transport=t) as c, pytest.raises(httpx.ConnectError):
        c.get(f"https://localhost:{server.port}/v1/x")
    assert server.app_bytes == 0


def test_adapter_default_send_transports_are_pinned_to_the_accepted_gateway(server, tmp_path, monkeypatch):
    """The adapter's own default sync and async send transports pin to pinned_spki(), which is the
    fingerprint in the accepted gateway evidence."""
    monkeypatch.setattr(near, "_default_context", server.trust)
    world = NearWorld()
    ad = world.adapter(tmp_path)
    ad.verify()
    assert ad.pinned_spki() == world.tls_fp != server.fp
    with httpx.Client(transport=ad.default_send_transport()) as c, pytest.raises(TLSPinMismatch):
        c.get(f"https://localhost:{server.port}/v1/x")

    async def go():
        async with httpx.AsyncClient(transport=ad.default_async_transport()) as c:
            await c.get(f"https://localhost:{server.port}/v1/x")
    with pytest.raises(TLSPinMismatch):
        asyncio.run(go())
    _settle(server)
    assert server.app_bytes == 0
    monkeypatch.setattr(ad, "pinned_spki", lambda: server.fp)
    with httpx.Client(transport=ad.default_send_transport()) as c:
        assert c.get(f"https://localhost:{server.port}/v1/x").status_code == 200


def test_production_adapter_never_sends_on_an_unpinned_pool(tmp_path):
    """With no injected factories, attestation GETs use a plain pool and every send or signature fetch a
    pinned one (the attestation certificate is what the quote is checked against)."""
    ad = near.NearAdapter(data_dir=tmp_path, models=[MODEL])
    assert ad._send_transport_factory == ad.default_send_transport
    assert ad._async_transport_factory == ad.default_async_transport


def test_a_new_accepted_fingerprint_drops_pooled_send_connections(tmp_path):
    world = NearWorld()
    ad = world.adapter(tmp_path)
    ad.verify()
    first = ad._pool()
    ad.verify()
    assert ad._pool() is first                     # same fingerprint: the pool stays
    world.tls_der, world.tls_fp = tls_cert()       # NEAR rotated its certificate; the quote binds the new one
    ad.verify()
    assert ad.pinned_spki() == world.tls_fp and ad._pool() is not first


# ── the per-send observation decides the verdict ─────────────────────────────────────────────────

def _sent(world, tmp_path, **kw):
    ad = world.adapter(tmp_path, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    ad.verify()
    ad.release()
    client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
    return ad, client, rows


def test_send_whose_certificate_differs_is_unverified_and_not_fully_attested(tmp_path):
    world = NearWorld()
    world.chat_tls_der, _ = tls_cert()             # a valid signature, but over a connection to someone else
    _, client, rows = _sent(world, tmp_path, encrypt=False)
    client.chat.completions.create(model=MODEL, messages=MSG)
    (row,) = rows
    d = row["detail"]
    assert d["tls_matches_attested"] is False and d["check"]["signature_valid"] is True
    assert row["verdict"] == "unverified" and d["fully_attested"] is False and d["check"]["tls_verified"] is False
    assert "TLS certificate of this send is not the one the gateway quote binds" in d["check"]["reason"]


def test_encrypted_send_over_another_certificate_is_withheld(tmp_path):
    world = NearWorld()
    world.chat_tls_der, _ = tls_cert()
    _, client, rows = _sent(world, tmp_path)
    with pytest.raises(VerifyError) as ei:
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert "withheld" in str(ei.value) and rows[0]["detail"]["fully_attested"] is False


def test_send_whose_certificate_is_not_observable_is_unverified(tmp_path):
    world = NearWorld()
    world.chat_serve_tls = False
    _, client, rows = _sent(world, tmp_path, encrypt=False)
    client.chat.completions.create(model=MODEL, messages=MSG)
    assert rows[0]["verdict"] == "unverified" and "not observable" in rows[0]["detail"]["check"]["reason"]


def test_receipt_of_a_send_over_another_certificate_is_not_fully_attested(tmp_path):
    from confidential_mode.ledger import Ledger
    from confidential_mode.receipts import build_receipt
    world = NearWorld()
    world.chat_tls_der, _ = tls_cert()
    ad, client, rows = _sent(world, tmp_path, encrypt=False)
    client.chat.completions.create(model=MODEL, messages=MSG)
    led = Ledger(tmp_path / "ledger.sqlite")
    led.append({"kind": "lock", "tier": "attested", "decision": "locked", "detail": {}})
    led.append({"kind": "verify_ok", "provider": "attested-near", "host": ad.host,
                "detail": {"vendor": "near", "evidence": ad.last_result.evidence}})
    led.append({**rows[0], "session_id": "s"})
    doc = build_receipt(led, "s")
    assert doc["header"]["near"]["fully_attested"] is False


def test_pin_wraps_a_truststore_context_too():
    """Hermes injects truststore (agent/ssl_verify.py), so production contexts are truststore.SSLContext:
    the pin's wrappers must install on that class as well."""
    truststore = pytest.importorskip("truststore")
    ctx = pinned_ssl_context(lambda: "ee" * 32, base=lambda: truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    assert ctx.wrap_socket.__name__ == "wrap_socket" and ctx.wrap_socket.__qualname__.startswith("pinned_ssl_context")
    assert ctx.wrap_bio.__qualname__.startswith("pinned_ssl_context")

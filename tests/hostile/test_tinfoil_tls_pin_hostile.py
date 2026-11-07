"""Hostile pass on the per-send TLS pin for Tinfoil (Amendment 13).

The SDK's "ehbp" transport encrypts request bodies to the attested HPKE key and builds its inner httpx
transports with ordinary WebPKI TLS, so headers (the API key included) reached whoever ended TLS. The
adapter now gives every EHBP pool, and every transport the SDK rebuilds after a key rotation, an inner
transport whose SSL context checks the peer's SPKI against the verified report's TLS key inside the
handshake, before a request byte is written. Tested against a real local TLS server that counts the
application bytes it receives (the NEAR harness, tests/hostile/test_near_tls_pin_hostile.py).
"""
from __future__ import annotations

import asyncio
import tempfile
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from confidential_mode.verify import tinfoil as T
from confidential_mode.verify.base import VerificationResult
from confidential_mode.verify.near import TLSPinMismatch

from .test_near_tls_pin_hostile import _settle, server  # noqa: F401  (fixture)


def _hpke_hex() -> str:
    key = x25519.X25519PrivateKey.generate().public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _real_sc(server, fp):
    """A real tinfoil SecureClient (no network: explicit enclave and cache secret) with a verified ground truth
    whose TLS key is ``fp``; attestation itself is stubbed (``_require_hpke_public_key``)."""
    from tinfoil import client as tf_client
    sc = tf_client.SecureClient(enclave=f"localhost:{server.port}", repo="tinfoilsh/confidential-model-router",
                                transport="ehbp", user_cache_secret="test-cache-secret")
    sc._ground_truth = SimpleNamespace(public_key=fp, hpke_public_key=_hpke_hex())
    hpke = sc._ground_truth.hpke_public_key
    sc._require_hpke_public_key = lambda: hpke
    return sc


def _adapter(server, *, backoff=30.0):
    ad = T.TinfoilAdapter(data_dir=tempfile.mkdtemp(), enclave=f"localhost:{server.port}", tls_probe=False,
                          tls_base_context=server.trust, reverify_backoff_seconds=backoff)
    rows, stale = [], []
    ad.event_sink = rows.append
    ad.on_stale = lambda: stale.append(1)
    return ad, rows, stale


def _result(fp):
    return VerificationResult(vendor="tinfoil", router_repo="r", enclave_host="localhost", code_fingerprint="c",
                              enclave_fingerprint="m", release_tag=None, verifier="v", verified_at_host_clock=0.0,
                              evidence={"claims": {"tls_public_key_fp": fp, "hpke_public_key": "h"}})


def _url(server, path="/v1/chat/completions"):
    return f"https://localhost:{server.port}{path}"


def test_the_pinned_ehbp_transport_sends_on_the_attested_key(server):
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, server.fp)
    t = ad.pinned_ehbp_sync_transport(sc)
    with httpx.Client(transport=t) as c:
        try:
            c.post(_url(server), content=b'{"messages": "x"}')
        except Exception:
            pass        # the local server's reply is not EHBP; what matters is that the request left
    _settle(server)
    assert server.app_bytes > 0


@pytest.mark.parametrize("body", [b'{"secret": "plaintext"}', None])
def test_a_wrong_certificate_is_refused_before_any_byte_sync(server, body):
    """Sends and requests without a body alike (the EHBP passthrough path)."""
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, "ee" * 32)
    t = ad.pinned_ehbp_sync_transport(sc)
    with httpx.Client(transport=t, headers={"Authorization": "Bearer sk-must-not-leave"}) as c:
        with pytest.raises(TLSPinMismatch, match="the verified Tinfoil report binds; refused before sending"):
            if body is None:
                c.get(_url(server, "/.well-known/tinfoil-attestation"))
            else:
                c.post(_url(server), content=body)
    _settle(server)
    assert server.handshakes == 1 and server.app_bytes == 0


def test_a_wrong_certificate_is_refused_before_any_byte_async(server):
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, "ee" * 32)

    async def go():
        pool = ad._make_async_client(sc)
        try:
            with pytest.raises(TLSPinMismatch):
                await pool.post(_url(server), content=b'{"secret": "plaintext"}',
                                headers={"Authorization": "Bearer sk-must-not-leave"})
        finally:
            await pool.aclose()
    asyncio.run(go())
    _settle(server)
    assert server.app_bytes == 0


def test_no_verified_tls_key_refuses_every_connection(server):
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, None)
    with httpx.Client(transport=ad.pinned_ehbp_sync_transport(sc)) as c, pytest.raises(TLSPinMismatch):
        c.post(_url(server), content=b"x")
    _settle(server)
    assert server.app_bytes == 0


def test_the_sdk_rebuild_after_a_key_rotation_is_pinned_too(server):
    """_EHBPReVerifyingTransport rebuilds through sc._build_ehbp_sync_transport (and the async twin): the
    adapter's shadow on this SecureClient instance gives the rebuild the pinned inner transport."""
    from tinfoil import client as tf_client
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, "ee" * 32)
    ad._pin_ehbp_builders(sc)
    assert "_build_ehbp_sync_transport" not in vars(tf_client.SecureClient) or \
        tf_client.SecureClient._build_ehbp_sync_transport is not sc._build_ehbp_sync_transport
    with httpx.Client(transport=sc._build_ehbp_sync_transport()) as c, pytest.raises(TLSPinMismatch):
        c.post(_url(server), content=b"x")

    async def go():
        t = await sc._build_ehbp_async_transport()
        async with httpx.AsyncClient(transport=t) as c:
            with pytest.raises(TLSPinMismatch):
                await c.post(_url(server), content=b"x")
    asyncio.run(go())
    _settle(server)
    assert server.app_bytes == 0
    # The class is untouched: a fresh SecureClient still has the SDK's own builder.
    other = tf_client.SecureClient(enclave="e.example", repo="r", transport="ehbp", user_cache_secret="s")
    assert "_build_ehbp_sync_transport" not in vars(other)


def test_the_first_pool_the_sdk_builds_is_pinned(server):
    """make_secure_http_client (what verify() calls) goes through the shadowed builder."""
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, "ee" * 32)
    ad._pin_ehbp_builders(sc)
    http = sc.make_secure_http_client()
    try:
        with pytest.raises(TLSPinMismatch):
            http.post(_url(server), content=b'{"secret": "plaintext"}')
    finally:
        http.close()
    _settle(server)
    assert server.app_bytes == 0


def test_a_mismatch_through_the_view_is_ledgered_held_and_re_verified_once(server):
    ad, rows, stale = _adapter(server)
    sc = _real_sc(server, "ee" * 32)
    ad._sc = sc
    ad._accepted = _result("ee" * 32)
    ad._sync_http = httpx.Client(transport=ad.pinned_ehbp_sync_transport(sc))
    view = ad.sync_http_view()
    with pytest.raises(TLSPinMismatch):
        view.post(_url(server), content=b"x")
    assert [r["kind"] for r in rows] == ["verify_fail"]
    row = rows[0]
    assert row["purpose"] == "tls_pin" and row["detail"]["reason_code"] == "tls_pin_mismatch"
    assert row["detail"]["reverify_requested"] is True and row["detail"]["nothing_sent"] is True
    assert stale == [1] and ad.held_reason and "certificate other than the attested one" in ad.held_reason
    # Held: the next send is refused before it reaches the pool.
    with pytest.raises(Exception, match="attested transport held"):
        view.post(_url(server), content=b"x")
    # A second mismatch inside the backoff is ledgered but asks for no second re-verify.
    ad.release()
    with pytest.raises(TLSPinMismatch):
        view.post(_url(server), content=b"x")
    assert len(rows) == 2 and rows[1]["detail"]["reverify_requested"] is False and stale == [1]
    _settle(server)
    assert server.app_bytes == 0


def test_a_matching_certificate_through_the_view_writes_no_row(server):
    ad, rows, stale = _adapter(server)
    sc = _real_sc(server, server.fp)
    ad._sc = sc
    ad._accepted = _result(server.fp)
    ad._sync_http = httpx.Client(transport=ad.pinned_ehbp_sync_transport(sc))
    try:
        ad.sync_http_view().post(_url(server), content=b"x")
    except Exception as exc:
        assert not isinstance(exc, TLSPinMismatch)
    assert rows == [] and stale == []
    _settle(server)
    assert server.app_bytes > 0


def test_the_verification_cache_wires_the_re_verify(tmp_path):
    """provider.VerificationCache sets on_stale on any adapter that has one, so a mismatch invalidates the
    cached verification and the next call re-verifies."""
    from confidential_mode import provider
    from confidential_mode.pins import PinStore
    ad = T.TinfoilAdapter(data_dir=tmp_path, enclave="e.example", tls_probe=False)
    cache = provider.VerificationCache()
    cache.register("attested-tinfoil", ad, PinStore(tmp_path / "pins.yaml"), 600.0)
    invalidated = []
    cache.invalidate = lambda name: invalidated.append(name)
    assert ad.mark_stale("test") is True and invalidated == ["attested-tinfoil"]
    assert ad.mark_stale("test") is False and invalidated == ["attested-tinfoil"]     # bounded


def test_a_pool_with_an_unpinned_network_transport_is_refused(server):
    """Fail closed: a chain whose network transport the adapter could not pin (no EHBP layer to reach it)."""
    from confidential_mode.verify.base import VerifyError
    ad, _, _ = _adapter(server)
    sc = _real_sc(server, server.fp)
    with pytest.raises(VerifyError, match="could not be pinned"):
        ad.pin_pool(httpx.Client(transport=httpx.HTTPTransport()), sc, is_async=False)
    assert ad.pin_pool(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))), sc,
                       is_async=False) == 0

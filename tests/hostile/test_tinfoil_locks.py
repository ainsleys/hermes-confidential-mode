"""The real TinfoilAdapter under concurrency (Amendment 9, second pass). The SecureClient is a stub (no
network); the adapter, its locks, its views and prepare/commit are the plugin's own.

- A sync SDK rotation re-verification racing the first async send on a new event loop does not deadlock
  (the review's lock-order probe: SDK lock then adapter lock, against adapter lock then SDK lock).
- A background prepare_verification blocked in the SDK stalls neither a sync send nor an async send on a
  loop whose pool exists.
- prepare publishes nothing; commit swaps the pool and the result; discard closes the unused pool.
"""
from __future__ import annotations

import asyncio
import tempfile
import threading
import time

import httpx
import pytest

from confidential_mode.verify import tinfoil as T
from confidential_mode.verify.base import VerificationResult


def _result(code="c", enclave="m"):
    return VerificationResult(vendor="tinfoil", router_repo="r", enclave_host="e.example", code_fingerprint=code,
                              enclave_fingerprint=enclave, release_tag=None, verifier="v", verified_at_host_clock=0.0,
                              evidence={"claims": {"tls_public_key_fp": "t", "hpke_public_key": "h"}})


def _reply(request):
    return httpx.Response(200, json={"ok": True})


class StubSC:
    """The SDK surface the adapter uses. ``gate`` (when set) blocks the SDK's own verify."""

    def __init__(self):
        self.gate: threading.Event | None = None
        self.in_sdk = threading.Event()
        self.closed_clients: list = []

    def verify(self):                      # the class-level verify (network in real life)
        self.in_sdk.set()
        if self.gate is not None:
            assert self.gate.wait(10)
        else:
            time.sleep(0.2)
        return object()

    def make_secure_http_client(self):
        self.verify()
        return httpx.Client(transport=httpx.MockTransport(_reply))

    def make_secure_async_http_client(self):
        self.verify()
        return httpx.AsyncClient(transport=httpx.MockTransport(_reply))


def _adapter():
    ad = T.TinfoilAdapter(data_dir=tempfile.mkdtemp(), enclave="e.example", tls_probe=False)
    ad.event_sink = lambda row: None
    sc = StubSC()
    sc.verify = lambda: ad._guarded_verify(sc)   # as _secure_client wires it
    ad._sc = sc
    results = {"next": _result()}
    ad._result_from_document = lambda sc_, sink=None: results["next"]
    return ad, sc, results


def _verify_first(ad):
    ad.verify()
    ad.release()


def _run(target, timeout=5.0):
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    return t


def test_a_rotation_racing_a_new_loop_pool_build_does_not_deadlock():
    ad, sc, _ = _adapter()
    ad._accepted = _result()

    def rotation():
        sc.verify()                        # a sync send's SDK re-verification after a key rotation

    def first_async_send():
        async def go():
            assert sc.in_sdk.wait(5)       # the rotation holds the SDK lock now
            ad._async_pool_for_running_loop()
        asyncio.run(go())
    a = threading.Thread(target=rotation, daemon=True)
    b = threading.Thread(target=first_async_send, daemon=True)
    a.start(), b.start()
    a.join(5), b.join(5)
    assert not a.is_alive() and not b.is_alive(), "lock-order deadlock between the SDK lock and the adapter lock"


def test_a_background_capture_stalls_neither_a_sync_send_nor_an_async_send_on_an_existing_loop():
    ad, sc, results = _adapter()
    sc.gate = None
    _verify_first(ad)
    loop = asyncio.new_event_loop()
    try:
        async def send_async():
            client = httpx.AsyncClient(transport=T._AsyncView(ad))
            r = await client.get("https://e.example/v1/models")
            return r.status_code
        assert loop.run_until_complete(send_async()) == 200        # builds this loop's pool
        sc.gate, sc.in_sdk = threading.Event(), threading.Event()
        results["next"] = _result()
        out = {}
        bg = threading.Thread(target=lambda: out.setdefault("p", ad.prepare_verification()), daemon=True)
        bg.start()
        assert sc.in_sdk.wait(5)                                    # the capture is blocked in the SDK
        started = time.monotonic()
        assert loop.run_until_complete(asyncio.wait_for(send_async(), 2)) == 200
        assert ad.sync_http_view().get("https://e.example/v1/models").status_code == 200
        assert ad._lock.acquire(timeout=0.5)
        ad._lock.release()
        assert time.monotonic() - started < 2.0
        sc.gate.set()
        bg.join(5)
        assert "p" in out and out["p"].result is results["next"]
    finally:
        loop.close()


def test_prepare_publishes_nothing_commit_swaps_and_discard_closes_the_unused_pool():
    ad, sc, results = _adapter()
    _verify_first(ad)
    first, pool = ad.last_result, ad._sync_http
    results["next"] = _result(code="c2")
    prepared = ad.prepare_verification()
    assert ad.last_result is first and ad._sync_http is pool and ad.held_reason is None
    prepared.discard()
    assert prepared.payload.is_closed
    results["next"] = _result(code="c3")
    prepared = ad.prepare_verification()
    ad.commit_verification(prepared, hold=False)
    assert ad.last_result is prepared.result and ad._sync_http is prepared.payload and ad.held_reason is None
    assert ad._retired_sync == [pool]
    prepared.discard()                                              # a committed pool is never closed by discard
    assert not ad._sync_http.is_closed
    results["next"] = _result(code="c4")
    held = ad.prepare_verification()
    ad.commit_verification(held, hold=True)
    assert ad.held_reason is not None
    ad.close()
    with pytest.raises(T.VerifyError):
        ad.commit_verification(ad.prepare_verification(), hold=False)

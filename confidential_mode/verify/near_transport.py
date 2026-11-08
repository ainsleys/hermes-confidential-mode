"""NEAR AI Cloud transport pieces: the TLS pin and the pool helpers.

``pinned_ssl_context`` builds an SSL context whose handshake fails (``TLSPinMismatch``) unless the
peer's SPKI SHA-256 is the one the accepted gateway quote binds; the Tinfoil adapter reuses it. The
rest closes pools and their sockets on the right event loop, and wraps response streams so a pool counts
as in use until its body is closed (``_Releasing``, ``_AsyncReleasing``) or so a view never closes the
shared pool (``_NonClosing``).
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import weakref
from collections.abc import Callable
from typing import Any

import httpx

from .base import VerifyError

logger = logging.getLogger("confidential_mode.verify.near")   # the name this code has always logged under


def _peer_der(response) -> bytes | None:
    from .tinfoil import peer_certificate_der
    try:
        return peer_certificate_der(response)
    except Exception:
        return None


def _spki_sha256(der: bytes) -> str:
    from .tinfoil import spki_sha256
    return spki_sha256(der)


class TLSPinMismatch(VerifyError):
    """The TLS peer of an inference connection is not the certificate the verified gateway quote binds."""


def _default_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def pinned_ssl_context(expected_spki: Callable[[], str | None], *,
                       base: Callable[[], ssl.SSLContext] | None = None,
                       required: Callable[[], bool] = lambda: True,
                       binds: str = "the verified gateway quote", source: str = "gateway") -> ssl.SSLContext:
    """An SSL context that keeps the normal chain and host-name checks and adds one: right after the
    handshake, and before httpcore writes a request byte, the peer certificate's SPKI SHA-256 must equal
    ``expected_spki()`` (the fingerprint the verified gateway quote binds). A mismatch, an unreadable peer
   certificate, or no expected fingerprint (unless ``required()`` is false) raises TLSPinMismatch and the
    connection is closed.

    Same mechanism as the Tinfoil SDK (tinfoil/client.py ``_create_socket_wrapper``/``_create_bio_wrapper``):
    the sync httpcore backend completes the handshake inside ``wrap_socket``; the async (anyio) backend and
    TLS-in-TLS proxying drive an ``SSLObject`` from ``wrap_bio``, whose ``do_handshake`` is wrapped."""
    ctx = (base or _default_context)()
    orig_wrap_socket, orig_wrap_bio = ctx.wrap_socket, ctx.wrap_bio

    def check(der: bytes | None) -> None:
        want = expected_spki()
        if not want:
            if not required():
                return  # confidential.near.require_tls_binding: false and no fingerprint was attested
            raise TLSPinMismatch(f"no attested {source} TLS fingerprint to pin this connection to")
        got = _spki_sha256(der) if der else None
        if got != str(want).lower():
            raise TLSPinMismatch(f"the TLS certificate of this connection is not the one {binds} binds; "
                                 "refused before sending")

    def wrap_socket(*args, **kwargs):
        sock = orig_wrap_socket(*args, **kwargs)
        try:
            check(sock.getpeercert(True))
        except BaseException:
            try:
                sock.close()
            finally:
                raise
        return sock

    def wrap_bio(*args, **kwargs):
        obj = orig_wrap_bio(*args, **kwargs)
        orig_handshake = obj.do_handshake

        def do_handshake():
            result = orig_handshake()
            check(obj.getpeercert(True))
            return result
        obj.do_handshake = do_handshake  # type: ignore[method-assign]  # the pin check wraps the handshake
        return obj

    ctx.wrap_socket = wrap_socket  # type: ignore[method-assign]  # the pin check wraps the context's own
    ctx.wrap_bio = wrap_bio  # type: ignore[method-assign]
    return ctx


def _close_quietly(t) -> None:
    try:
        t.close()
    except Exception:
        pass


def _close_pool_sockets(t: Any) -> None:
    """Close the sockets of an async pool whose loop can no longer run its close (fix-pass-3 review findings 3
    and 4): each connection's socket in httpx's connection pool, closed directly, so nothing is left to the
    garbage collector and no close coroutine is created. Never raises."""
    try:
        pool = getattr(t, "_pool", None)
        conns = list(getattr(pool, "_connections", None) or [])
    except Exception:  # noqa: BLE001
        return
    for conn in conns:
        try:
            inner = getattr(conn, "_connection", None) or conn
            stream = getattr(inner, "_network_stream", None)
            sock = stream.get_extra_info("socket") if stream is not None else None
            if sock is not None:
                sock.close()
        except Exception:  # noqa: BLE001
            continue


def _sweep_closed_loops(keep: set) -> None:
    """A close deferred onto a loop that closed before running it: close that pool's sockets directly."""
    for entry in [e for e in list(keep) if isinstance(e, tuple)]:
        loop, t = entry
        try:
            closed = loop.is_closed()
        except Exception:  # noqa: BLE001
            closed = True
        if closed:
            keep.discard(entry)
            _close_pool_sockets(t)


def _aclose_on_loop(loop: asyncio.AbstractEventLoop, t: Any, keep: set) -> None:
    """Close an async pool on the loop it was made on, so its sockets close: a task when that loop is the
    running one; from another thread, a callback scheduled onto the loop that creates the task only when the
    loop runs it, so a loop closed first leaves no close coroutine unawaited (``keep`` holds the deferred
    (loop, pool) pair, and ``_sweep_closed_loops`` closes its sockets directly). A loop already closed gets
    its pool's sockets closed directly. ``keep`` holds each pending close until it finishes. Never raises."""
    aclose = getattr(t, "aclose", None)
    if not callable(aclose):
        return
    _sweep_closed_loops(keep)

    def done(fut) -> None:
        keep.discard(fut)
        try:
            fut.exception()
        except BaseException:  # noqa: BLE001 - a cancelled close; nothing to report
            pass

    def start() -> None:
        keep.discard(entry)
        try:
            task = loop.create_task(aclose())
        except Exception:  # noqa: BLE001
            _close_pool_sockets(t)
            return
        keep.add(task)
        task.add_done_callback(done)
    entry = (loop, t)
    try:
        if loop.is_closed():
            _close_pool_sockets(t)
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            fut = loop.create_task(aclose())
            keep.add(fut)
            fut.add_done_callback(done)
            return
        keep.add(entry)
        loop.call_soon_threadsafe(start)
    except RuntimeError:     # the loop closed meanwhile
        keep.discard(entry)
        _close_pool_sockets(t)
    except Exception:  # noqa: BLE001
        logger.debug("confidential-mode: could not schedule closing a NEAR async pool", exc_info=True)


class _AsyncReleasing(httpx.AsyncByteStream):
    """An async response body that releases its send pool when closed, or when it is collected unclosed (a
    caller that abandoned the body), so a retired pool never stays listed for the adapter's life."""

    def __init__(self, inner, release):
        self._inner, self._release = inner, release
        weakref.finalize(self, release)       # release() runs once: a later aclose() is a no-op

    async def __aiter__(self):
        async for chunk in self._inner:
            yield chunk

    async def aclose(self):
        try:
            await self._inner.aclose()
        finally:
            self._release()


class _NonClosing(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner

    def handle_request(self, request):
        return self._inner.handle_request(request)

    def close(self) -> None:
        pass


class _Releasing(httpx.SyncByteStream):
    """A response body that releases its send pool when closed."""

    def __init__(self, inner, release):
        self._inner, self._release = inner, release

    def __iter__(self):
        yield from self._inner

    def close(self):
        try:
            self._inner.close()
        finally:
            self._release()

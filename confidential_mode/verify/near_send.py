"""NEAR AI Cloud send views: the httpx transports Hermes' clients use for ``attested-near``.

``_SyncView`` and ``_AsyncView`` check each request (``NearAdapter._check_request``), open an exchange
(near_exchange.py), send it on the adapter's pinned pool, and hash the response body as it streams so
the adapter can fetch and check NEAR's signature when the body ends. ``_refuse`` turns a failure into
the NearRefusal Hermes sees and ledgers it.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, cast

import httpx

from .base import VerifyError
from .near_exchange import _already_read, _chain, _drain_after_done, _refusal, _sealed_async, _sealed_sync, _send_failed
from .near_transport import TLSPinMismatch, _AsyncReleasing, _Releasing

if TYPE_CHECKING:
    from .near import NearAdapter
    from .near_exchange import NearRefusal, _Exchange

logger = logging.getLogger(__name__.rsplit(".", 1)[0] + ".near")   # verify/near.py's logger, under any package name


def _refuse(adapter: NearAdapter, exc: BaseException, stage: str, *, ex: _Exchange | None = None,
            request: httpx.Request | None = None) -> NearRefusal:
    """The NearRefusal for ``exc``, ledgered as a send_refused row (NearAdapter.record_refusal)."""
    refusal = _refusal(exc)
    adapter.record_refusal(refusal, stage=stage, ex=ex, request=request)
    return refusal


def _signature_step_bound(adapter: NearAdapter) -> float:
    """The async wait for finish(): the fetch loop's deadline plus one last GET at its own timeout."""
    w = adapter.signature_wait_seconds
    return w + 4 * max(1.0, w) + 5.0


class _SyncView(httpx.BaseTransport):
    def __init__(self, adapter: NearAdapter):
        self._adapter = adapter

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        a = self._adapter
        try:
            a._check_not_held()
            a._check_request(request)
        except VerifyError as exc:
            raise _refuse(a, exc, "before_send", request=request) from exc
        try:
            request.read()
            ex = a.begin_exchange(request)
        except VerifyError as exc:
            raise _refuse(a, exc, "before_send", request=request) from exc
        try:
            pool, release_pool = a._acquire(ex, check=True)
        except VerifyError as exc:
            raise _refuse(a, exc, "before_send", ex=ex, request=request) from exc
        try:
            response = pool.handle_request(ex.request if ex is not None else request)
        except BaseException as exc:
            release_pool()
            refusal = _send_failed(a, ex, exc) if ex is not None else None
            if refusal is None and any(isinstance(e, TLSPinMismatch) for e in _chain(exc)):
                a.mark_stale("a NEAR connection presented a certificate other than the attested one; re-verifying")
                refusal = _refusal(next(e for e in _chain(exc) if isinstance(e, TLSPinMismatch)))
            if refusal is not None:
                raise _refuse(a, refusal, "before_send", ex=ex, request=request) from exc
            raise
        if ex is None:
            response.stream = _Releasing(response.stream, release_pool)
            return response
        ex.on_response(response)
        if ex.encrypted:
            try:
                return _sealed_sync(a, ex, response)
            except VerifyError as exc:
                raise _refuse(a, exc, "after_receive", ex=ex) from exc
            finally:
                release_pool()
        if _already_read(response, ex):
            release_pool()
            ex.finish()
            return response
        inner = cast(httpx.SyncByteStream, response.stream)
        exn: _Exchange = ex   # set: the ex is None case returned above

        class _Hashing(httpx.SyncByteStream):
            def __init__(self_inner):
                self_inner._it: Any = None

            def __iter__(self_inner):
                self_inner._it = iter(inner)
                try:
                    for chunk in self_inner._it:
                        exn.feed(chunk)
                        yield chunk
                except GeneratorExit:
                    raise  # the consumer let go; close() decides
                except BaseException as exc:
                    exn.finish(f"{type(exc).__name__} while reading the body")
                    raise
                exn.complete()
                exn.finish()

            def close(self_inner):
                try:
                    if not exn.completed and exn.saw_done and self_inner._it is not None:
                        _drain_after_done(exn, lambda: next(self_inner._it))
                    inner.close()
                finally:
                    release_pool()
                    exn.finish(None if exn.completed else "closed before its end")
        response.stream = _Hashing()
        return response

    def close(self) -> None:
        pass


class _AsyncView(httpx.AsyncBaseTransport):
    def __init__(self, adapter: NearAdapter):
        self._adapter = adapter

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        a = self._adapter
        try:
            a._check_not_held()
            a._check_request(request)
            await request.aread()
            ex = a.begin_exchange(request)
        except VerifyError as exc:
            raise _refuse(a, exc, "before_send", request=request) from exc
        try:
            with a._lock:                # the hold re-check and the pool choice under one lock (S09)
                a._check_current(ex)
                pool, release = a._acquire_async()
        except VerifyError as exc:
            raise _refuse(a, exc, "before_send", ex=ex, request=request) from exc
        try:
            response = await self._send(pool, release, ex.request if ex is not None else request)
        except BaseException as exc:
            refusal = _send_failed(a, ex, exc) if ex is not None else None
            if refusal is None and any(isinstance(e, TLSPinMismatch) for e in _chain(exc)):
                a.mark_stale("a NEAR connection presented a certificate other than the attested one; re-verifying")
                refusal = _refusal(next(e for e in _chain(exc) if isinstance(e, TLSPinMismatch)))
            if refusal is not None:
                raise _refuse(a, refusal, "before_send", ex=ex, request=request) from exc
            raise
        if ex is None:
            return response
        try:
            ex.on_response(response)
        except BaseException:
            release()            # the body is never read, so its close never releases the pool
            raise
        bound = _signature_step_bound(a)

        async def finish(reason=None):
            if ex.finished:
                return
            try:
                await asyncio.wait_for(asyncio.to_thread(ex.finish, reason), bound)
            except Exception:
                logger.warning("confidential-mode: NEAR signature step timed out", exc_info=True)

        if ex.encrypted:
            try:
                return await _sealed_async(a, ex, response, finish)
            except VerifyError as exc:
                raise _refuse(a, exc, "after_receive", ex=ex) from exc
        if _already_read(response, ex):
            await asyncio.wait_for(asyncio.to_thread(ex.finish), bound)
            return response
        inner = cast(httpx.AsyncByteStream, response.stream)
        exn: _Exchange = ex   # set: the ex is None case returned above

        class _Hashing(httpx.AsyncByteStream):
            def __init__(self_inner):
                self_inner._it: Any = None

            async def __aiter__(self_inner):
                self_inner._it = inner.__aiter__()
                try:
                    async for chunk in self_inner._it:
                        exn.feed(chunk)
                        yield chunk
                except GeneratorExit:
                    raise
                except BaseException as exc:
                    await finish(f"{type(exc).__name__} while reading the body")
                    raise
                exn.complete()
                await finish()

            async def aclose(self_inner):
                try:
                    if not exn.completed and exn.saw_done and self_inner._it is not None:
                        try:
                            while True:
                                exn.feed(await self_inner._it.__anext__())
                        except StopAsyncIteration:
                            exn.complete()
                        except Exception as exc:
                            exn.end_reason = f"{type(exc).__name__} while draining after [DONE]"
                    await inner.aclose()
                finally:
                    await finish(None if exn.completed else "closed before its end")
        response.stream = _Hashing()
        return response

    @staticmethod
    async def _send(pool, release, request: httpx.Request) -> httpx.Response:
        """One request on ``pool``; the pool counts as in use until the upstream response is closed (or the
        send fails), so a pool dropped meanwhile is closed only after its last request."""
        try:
            response = await pool.handle_async_request(request)
        except BaseException:
            release()
            raise
        if getattr(response, "is_closed", False):
            release()
        else:
            response.stream = _AsyncReleasing(response.stream, release)
        return response

    async def aclose(self) -> None:
        pass

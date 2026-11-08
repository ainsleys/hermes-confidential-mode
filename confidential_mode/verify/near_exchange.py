"""NEAR AI Cloud exchanges: one signed send, from request to signature check.

``_Exchange`` holds what one POST through the adapter's views records: the request and response
digests, the completion id, the encryption client key and the signature verdict. The functions below
read an encrypted reply whole (``_sealed_sync``, ``_sealed_async``) and hand it over decrypted only when
the send is fully attested (``_release_sealed``); ``NearRefusal`` is the error a refused send raises.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

import httpx
import openai

from .base import VerifyError
from .near_transport import TLSPinMismatch, _peer_der, _spki_sha256

if TYPE_CHECKING:
    from .near import NearAdapter

logger = logging.getLogger("confidential_mode.verify.near")   # the name this code has always logged under


MAX_ID_BUFFER = 8 * 1024 * 1024
MAX_SEALED_BODY = 32 * 1024 * 1024   # an unstreamed encrypted response is buffered whole before release


class NearRefusal(VerifyError, openai.OpenAIError):
    """A refusal raised from the NEAR transport. It is an ``openai.OpenAIError``, which the OpenAI SDK
    re-raises as is (no retry, no APIConnectionError wrapping); the attested profile's
    ``classify_api_error`` hook (provider.classify_refusal) tells Hermes' loop what to do with it.

    ``status_code`` and ``body`` are set when the gateway answered with an HTTP error (not 200): they are
    unauthenticated and only steer local recovery (backoff, compression), never what is released. A retry
    is a new encrypted exchange; only a 200 that is fully attested and decrypts is ever handed over."""

    def __init__(self, message: str, *, status_code: int | None = None, body: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body or {}


def _refusal(exc: BaseException) -> NearRefusal:
    return exc if isinstance(exc, NearRefusal) else NearRefusal(str(exc) or type(exc).__name__)


@dataclass
class _Exchange:
    adapter: NearAdapter
    path: str
    model: str | None
    stream: bool
    request_sha256: str
    request_bytes: int
    authorization: str | None
    context: dict
    attestation_nonce: str | None
    code_fingerprint: str | None
    responses_api: bool = False
    accepted: Any = None            # the accepted verification this exchange was built on (S09 re-check)
    prepared_spki: str | None = None   # the pinned TLS fingerprint and model key when it was built
    prepared_key: str | None = None
    status: int | None = None
    content_encoding: str | None = None
    chat_id: str | None = None
    response_sha256: str | None = None
    response_bytes: int = 0
    completed: bool = False
    finished: bool = False
    end_reason: str | None = None
    tls_spki_sha256: str | None = None
    tls_matches: bool | None = None
    _hash: Any = field(default_factory=hashlib.sha256)
    _buf: bytearray = field(default_factory=bytearray)
    _decoder: Any = None
    _tail: bytes = b""
    saw_done: bool = False
    request: Any = None                 # the httpx.Request actually sent (the encrypted one when encrypting)
    encrypted: bool = False
    client_key: Any = field(default=None, repr=False)   # this exchange's Ed25519 key; memory only
    model_pub: str | None = None
    e2ee_report: dict | None = None
    detail: dict | None = None          # the send_signed row detail, once finished
    keep_body: bool = False
    body: bytearray = field(default_factory=bytearray)
    pending_row: dict | None = None
    outcome: tuple | None = None        # (released: bool, reason: str) for an encrypted exchange
    emitted: bool = False
    _settle_lock: Any = field(default_factory=threading.Lock, repr=False)

    def settle(self, outcome: tuple | None) -> None:
        """Record the release outcome of an encrypted exchange and write its row once both the row (from
        finish) and the outcome (from the view) exist, whichever comes last."""
        with self._settle_lock:
            if outcome is not None and self.outcome is None:
                self.outcome = outcome
            if self.emitted or self.pending_row is None or self.outcome is None:
                return
            self.emitted = True
            row = self.pending_row
        released, reason = self.outcome
        d = row["detail"]
        d["reply_released"] = bool(released)
        d["withheld_reason"] = None if released else str(reason)[:300]
        if not released:
            d["fully_attested"] = False
            if row.get("verdict") == "verified":
                row["verdict"] = "unverified"
                d["check"]["verdict"] = "unverified"
                d["check"]["reason"] = f"reply withheld after the signature check: {reason}"[:300]
        self.adapter._emit_row(row)

    def on_response(self, response: httpx.Response) -> None:
        self.status = response.status_code
        enc = (response.headers.get("content-encoding") or "").strip().lower()
        self.content_encoding = enc or None
        if enc and enc != "identity":
            try:
                from httpx._decoders import SUPPORTED_DECODERS
                self._decoder = SUPPORTED_DECODERS[enc]()
            except Exception:
                self._decoder = None
        der = _peer_der(response)
        if der is not None:
            try:
                self.tls_spki_sha256 = _spki_sha256(der)
                acc = self.adapter._accepted
                fp = (((acc.evidence or {}).get("gateway") or {}).get("tls_cert_fingerprint") if acc else None)
                self.tls_matches = (self.tls_spki_sha256 == str(fp).lower()) if fp else None
            except Exception:
                pass

    def feed(self, chunk: bytes) -> None:
        data = self._decoder.decode(chunk) if self._decoder is not None else chunk
        self._take(data)

    def _take(self, data: bytes) -> None:
        if not data:
            return
        self._hash.update(data)
        self.response_bytes += len(data)
        if self.keep_body:
            if len(self.body) + len(data) > MAX_SEALED_BODY:
                raise VerifyError("encrypted NEAR response exceeds the buffer bound; refused")
            self.body.extend(data)
        if self.stream and not self.saw_done:
            window = self._tail + data
            self.saw_done = b"data: [DONE]" in window
            self._tail = window[-16:]
        if self.chat_id is None and len(self._buf) < MAX_ID_BUFFER:
            self._buf.extend(data)
            if self.stream:
                self._scan_sse()

    def _scan_sse(self) -> None:
        text = bytes(self._buf).decode("utf-8", errors="replace")
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                value = json.loads(payload)
            except ValueError:
                continue  # an incomplete line; the next chunk completes it
            if self.responses_api and isinstance(value, Mapping):
                value = cast(Mapping, value.get("response")) if isinstance(value.get("response"), Mapping) else None
            if isinstance(value, Mapping) and isinstance(value.get("id"), str) and value["id"]:
                self.chat_id = value["id"]
                self._buf.clear()
                return

    def complete(self) -> None:
        if self._decoder is not None:
            try:
                self._take(self._decoder.flush())
            except Exception:
                pass
        self.response_sha256 = self._hash.hexdigest()
        if self.chat_id is None and not self.stream:
            try:
                value = json.loads(bytes(self._buf))
                if isinstance(value, Mapping) and isinstance(value.get("id"), str):
                    self.chat_id = value["id"]
            except ValueError:
                pass
        self._buf = bytearray()
        self.completed = True

    def finish(self, reason: str | None = None) -> None:
        if self.finished:
            return
        self.finished = True
        if reason:
            self.end_reason = reason
        self.adapter.finish_exchange(self)


def _drain_after_done(ex: _Exchange, nxt: Callable[[], bytes]) -> None:
    """The consumer stopped at ``data: [DONE]`` (the OpenAI SDK does) and closed the body: read the rest of
    the wire bytes so the digest covers the whole body NEAR signed. Bounded by the body itself."""
    try:
        while True:
            ex.feed(nxt())
    except StopIteration:
        ex.complete()
    except Exception as exc:
        ex.end_reason = f"{type(exc).__name__} while draining after [DONE]"


def _already_read(response: httpx.Response, ex: _Exchange) -> bool:
    """A transport that hands back a response whose body is already in memory (httpx reads a body given as
    bytes at construction): hash that body, already content-decoded, and complete the exchange."""
    try:
        content = response._content
    except AttributeError:
        return False
    ex._decoder = None
    ex._take(content)
    ex.complete()
    return True


_DROP_ON_RELEASE = ("content-length", "content-encoding", "transfer-encoding")


def _error_type(body: bytes) -> str:
    t = _error_body(body).get("error", {}).get("type")
    return f" ({str(t)[:40]})" if isinstance(t, str) and t else ""


def _error_body(body: bytes) -> dict:
    """{"error": {"type", "code", "message"}} clipped, from a gateway error body (unauthenticated)."""
    try:
        err = json.loads(body).get("error")
    except Exception:
        return {}
    if not isinstance(err, Mapping):
        return {}
    return {"error": {k: str(err.get(k))[:300] for k in ("type", "code", "message") if err.get(k) is not None}}


def _release_sealed(adapter: NearAdapter, ex: _Exchange, response: httpx.Response) -> httpx.Response:
    """The tail of an encrypted exchange, after the body was buffered, hashed, completed and finished
    (signature fetched and judged). Only one outcome hands a body to the caller: HTTP 200, a send that
    is fully attested (a verified provider_tee signature over these ciphertext digests, on the attested
    TLS connection), and a body that decrypts under this exchange's key. Every other outcome raises
    NearRefusal (no status is synthesised, nothing is retried by the SDK), and the row records it."""
    from . import near_e2ee as e2
    body = bytes(ex.body)
    ex.body = bytearray()
    try:
        status = response.status_code
        if status == 421:
            asked = adapter.mark_stale("NEAR reports the model encryption key is no longer valid (HTTP 421); "
                                       "re-verifying")
            raise NearRefusal("NEAR refused this exchange's model key (HTTP 421: the key is no longer valid); "
                              + ("the verification was invalidated and the next call re-verifies" if asked else
                                 "a re-verification ran less than confidential.near.reverify_backoff_seconds ago"),
                              status_code=421, body=_error_body(body))
        if status != 200:
            # Any status but 200, success-looking 2xx included, carries nothing the plugin can authenticate.
            raise NearRefusal(f"NEAR reply refused: HTTP {status}{_error_type(body)}; only a signed, encrypted "
                              "HTTP 200 reply is handed over", status_code=status,
                              body=_error_body(body) if status >= 400 else {})
        detail = ex.detail or {}
        if ex.detail is None:
            raise NearRefusal("NEAR response withheld: the signature step did not finish in time")
        if detail.get("fully_attested") is not True:
            reason = (detail.get("check") or {}).get("reason") or "no verified provider_tee signature"
            raise NearRefusal(f"NEAR response withheld: decrypted output is released only after a verified "
                              f"provider_tee signature over the ciphertext ({reason})"[:400])
        try:
            plain, _report = e2.decrypt_response(json.loads(body), ex.client_key)
        except ValueError as exc:  # E2EEError and JSONDecodeError
            raise NearRefusal(f"NEAR response withheld: the signature verified but the reply does not decrypt "
                              f"for this client ({exc}); a gateway that replaced X-Client-Pub-Key would look "
                              "like this"[:400]) from exc
        headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in _DROP_ON_RELEASE]
        out = httpx.Response(200, headers=headers, content=json.dumps(plain, ensure_ascii=False).encode("utf-8"),
                             extensions=response.extensions)
        ex.settle((True, ""))
        return out
    except BaseException as exc:
        ex.settle((False, str(exc) or type(exc).__name__))
        raise
    finally:
        ex.client_key = None


def _send_failed(adapter: NearAdapter, ex: _Exchange, exc: BaseException) -> NearRefusal | None:
    """A send that raised before a response arrived still gets its row. A TLS pin mismatch also drops the
    pooled connections and asks for a re-verify (bounded by the backoff)."""
    pin = next((e for e in _chain(exc) if isinstance(e, TLSPinMismatch)), None)
    reason = ("TLS pin mismatch, nothing sent" if pin is not None else
              f"transport error ({type(exc).__name__}); the request may have reached NEAR")
    try:
        if not ex.finished:
            ex.finished = True
            ex.end_reason = reason
            adapter.finish_exchange(ex)
        ex.settle((False, reason))
    except Exception:
        logger.warning("confidential-mode: could not ledger a failed NEAR send", exc_info=True)
    ex.client_key = None
    if pin is not None:
        adapter.mark_stale("a NEAR connection presented a certificate other than the attested one; re-verifying")
        return _refusal(pin)
    return None


def _chain(exc: BaseException | None):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _sealed_sync(adapter: NearAdapter, ex: _Exchange, response: httpx.Response) -> httpx.Response:
    ex.keep_body = True
    try:
        if hasattr(response, "_content"):           # a body already in memory, already content-decoded
            ex._decoder = None
            ex._take(response._content)
        else:
            for chunk in cast(httpx.SyncByteStream, response.stream):
                ex.feed(chunk)
        ex.complete()
    except BaseException as exc:
        ex.finish(f"{type(exc).__name__} while reading the body")
        ex.settle((False, f"{type(exc).__name__} while reading the body"))
        ex.client_key = None
        raise
    finally:
        try:
            response.close()
        except Exception:
            pass
    ex.finish()
    return _release_sealed(adapter, ex, response)


async def _sealed_async(adapter: NearAdapter, ex: _Exchange, response: httpx.Response, finish) -> httpx.Response:
    ex.keep_body = True
    try:
        if hasattr(response, "_content"):
            ex._decoder = None
            ex._take(response._content)
        else:
            async for chunk in cast(httpx.AsyncByteStream, response.stream):
                ex.feed(chunk)
        ex.complete()
    except BaseException as exc:
        await finish(f"{type(exc).__name__} while reading the body")
        ex.settle((False, f"{type(exc).__name__} while reading the body"))
        ex.client_key = None
        raise
    finally:
        try:
            await response.aclose()
        except Exception:
            pass
    await finish()
    return _release_sealed(adapter, ex, response)

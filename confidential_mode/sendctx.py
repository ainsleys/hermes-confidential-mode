"""Who a model send belongs to, for vendor adapters that write their own ledger rows (NEAR's signed
responses). The llm gate sets the context around ``next_call``; Hermes' worker threads copy the caller's
ContextVars (agent/chat_completion_helpers.py _context_thread_target), so the adapter's transport sees it.
Auxiliary calls do not pass through the gate and carry no context ("unattributed").

The gate also opens a per-send record bucket around ``next_call`` (``capture_records``). A vendor
transport that observes each HTTP exchange (Tinfoil: the HPKE key used, whether the response decrypted,
the TLS peer key) calls ``add_record``; the gate copies the bucket into its ``send_observed`` row after
the call returns. The bucket is a list shared by reference, so a worker thread running on a copied
context appends to the same list."""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Iterator, Optional

_CTX: "contextvars.ContextVar[Optional[dict]]" = contextvars.ContextVar("confidential_send_context", default=None)


@contextmanager
def send_context(**fields) -> Iterator[dict]:
    value = {k: v for k, v in fields.items() if v is not None}
    token = _CTX.set(value)
    try:
        yield value
    finally:
        _CTX.reset(token)


def current() -> Optional[dict]:
    value = _CTX.get()
    return dict(value) if isinstance(value, dict) else None


_RECORDS: "contextvars.ContextVar[Optional[list]]" = contextvars.ContextVar("confidential_send_records",
                                                                            default=None)


@contextmanager
def capture_records(bucket: list) -> Iterator[list]:
    """Collect every ``add_record`` call made in this context (and in contexts copied from it) into ``bucket``."""
    token = _RECORDS.set(bucket)
    try:
        yield bucket
    finally:
        _RECORDS.reset(token)


def add_record(record: dict) -> None:
    """Append one per-exchange record to the open bucket, if any. Never raises."""
    try:
        bucket = _RECORDS.get()
        if isinstance(bucket, list) and len(bucket) < MAX_RECORDS:
            bucket.append(record)
    except Exception:  # noqa: BLE001
        pass


#: At most this many exchanges are kept per model call (an SDK retry loop cannot grow a row without bound).
MAX_RECORDS = 16

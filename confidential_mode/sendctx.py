"""Who a model send belongs to, for vendor adapters that write their own ledger rows (NEAR's signed
responses). The llm gate sets the context around ``next_call``; Hermes' worker threads copy the caller's
ContextVars (agent/chat_completion_helpers.py _context_thread_target), so the adapter's transport sees it.
Auxiliary calls do not pass through the gate and carry no context ("unattributed")."""
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

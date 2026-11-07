"""Who a model send belongs to, for vendor adapters that write their own ledger rows (NEAR's signed
responses). The llm gate sets the context around ``next_call``; Hermes' worker threads copy the caller's
ContextVars (agent/chat_completion_helpers.py _context_thread_target), so the adapter's transport sees it.
Auxiliary calls do not pass through the gate. Their purpose (``aux:<task>``) comes from the relay context
Hermes binds around each auxiliary call (``aux_current``); their session and tier come from the
``pre_auxiliary_call`` hook (``note_aux``, keyed by the relay request id). The hook itself cannot set a
ContextVar for the send: Hermes runs it on a timeout worker thread with a copied context. A send with no
context at all is "unattributed".

``refusals_ledgered_by`` in a context names who writes the ``send_refused`` row when a vendor transport
refuses the send: ``llm_gate`` when the gate's guarded call wraps it (the gate records the refusal it
returns), so the adapter does not write a second row.

The gate also opens a per-send record bucket around ``next_call`` (``capture_records``). A vendor
transport that observes each HTTP exchange (Tinfoil: the HPKE key used, whether the response decrypted,
the TLS peer key) calls ``add_record``; the gate copies the bucket into its ``send_observed`` row after
the call returns. The bucket is a list shared by reference, so a worker thread running on a copied
context appends to the same list."""
from __future__ import annotations

import contextvars
import threading
from collections import OrderedDict
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


#: Session and tier of recent auxiliary calls by Hermes' relay request id, noted by pre_auxiliary_call.
_AUX_NOTES: "OrderedDict[str, dict]" = OrderedDict()
_AUX_LOCK = threading.Lock()
MAX_AUX_NOTES = 256


def note_aux(api_request_id: str, **fields) -> None:
    """Remember session and tier for one auxiliary call (from ``pre_auxiliary_call``). Never raises."""
    try:
        if not api_request_id:
            return
        with _AUX_LOCK:
            _AUX_NOTES[str(api_request_id)] = {k: v for k, v in fields.items() if v is not None}
            _AUX_NOTES.move_to_end(str(api_request_id))
            while len(_AUX_NOTES) > MAX_AUX_NOTES:
                _AUX_NOTES.popitem(last=False)
    except Exception:  # noqa: BLE001
        pass


def aux_current() -> Optional[dict]:
    """The send context of the auxiliary call running in this context, or None. Hermes binds one relay
    context per auxiliary call (agent/auxiliary_client.py ``_RELAY_AUX_CALL_CONTEXT``, a ContextVar
    copied into the provider worker thread, Hermes 84a0301); its task gives the purpose. Never raises."""
    try:
        from agent.auxiliary_client import _RELAY_AUX_CALL_CONTEXT
        relay = _RELAY_AUX_CALL_CONTEXT.get()
    except Exception:  # noqa: BLE001 - not running inside Hermes, or Hermes moved the variable
        return None
    if not isinstance(relay, dict) or not relay.get("task"):
        return None
    out = {"purpose": f"aux:{relay['task']}"}
    try:
        with _AUX_LOCK:
            note = dict(_AUX_NOTES.get(str(relay.get("request_id") or ""), {}))
        out.update({k: v for k, v in note.items() if k in ("session_id", "tier")})
    except Exception:  # noqa: BLE001
        pass
    return out


def current() -> Optional[dict]:
    """The send context in effect: an auxiliary call's (``aux_current``) when one is running, else the
    one the gate set, else None."""
    aux = aux_current()
    if aux is not None:
        return aux
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

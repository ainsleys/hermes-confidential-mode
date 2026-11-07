"""Clients handed to Hermes by the attested provider profile's create_client().

ConfidentialClient is the dual client proven in docs/C0-spikes.md (spike 2 follow-up):
- declares HERMES_SKIP_TRANSPORT_WRAP / HERMES_SKIP_ASYNC_WRAP so auxiliary code uses it as-is;
- sync ``openai.OpenAI`` on a non-closing view over the adapter's verified sync pool;
- one ``openai.AsyncOpenAI`` per running event loop on the adapter's per-loop verified async pool;
- ``chat.completions.create`` returns a coroutine iff its DIRECT caller is a coroutine frame
  (a wrong guess can only raise, never leak);
- other attributes delegate to the sync client; ``close()`` closes only this client's view.

RefusingClient has the same surface and every request raises ConfidentialRefused(reason).
"""
from __future__ import annotations

import asyncio
import inspect
import sys
from typing import Any, Callable

import httpx
import openai

# Keyword arguments Hermes may pass to create_client() that are safe to forward to openai.OpenAI.
# api_key/base_url are handled explicitly; http_client is never forwarded (the secure view replaces it).
_FORWARDED_OPENAI_KWARGS = ("timeout", "max_retries", "default_headers", "default_query", "organization",
                            "project")


class ConfidentialRefused(Exception):
    """Raised by every request on a RefusingClient (and by a ConfidentialClient whose gate fails)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _caller_is_coroutine(frame) -> bool:
    # ``async def`` frames: coroutines and async generators (an ``async def ... yield`` awaiting create).
    return bool(frame is not None and frame.f_code.co_flags & (inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR))


def openai_kwargs_from(client_kwargs: dict) -> dict:
    return {k: client_kwargs[k] for k in _FORWARDED_OPENAI_KWARGS if client_kwargs.get(k) is not None}


class _Completions:
    def __init__(self, owner: "ConfidentialClient"):
        self._owner = owner

    def create(self, **kwargs):
        owner = self._owner
        owner._check_gate()
        if _caller_is_coroutine(sys._getframe(1)):
            return owner._async_client().chat.completions.create(**kwargs)  # coroutine
        return owner._sync.chat.completions.create(**kwargs)

    def __getattr__(self, name):
        return getattr(self._owner._sync.chat.completions, name)


class _Chat:
    def __init__(self, owner: "ConfidentialClient"):
        self._owner = owner
        self.completions = _Completions(owner)

    def __getattr__(self, name):
        return getattr(self._owner._sync.chat, name)


class ConfidentialClient:
    HERMES_SKIP_TRANSPORT_WRAP = True
    HERMES_SKIP_ASYNC_WRAP = True

    def __init__(self, adapter, *, api_key: str, base_url: str, gate: Callable[[], None] | None = None,
                 openai_kwargs: dict | None = None, on_refuse: Callable[[BaseException], None] | None = None):
        self._adapter = adapter
        self._gate = gate
        self._on_refuse = on_refuse
        self._kw = dict(openai_kwargs or {})
        self._kw.setdefault("max_retries", 0)
        self._view = adapter.sync_http_view()
        self._sync = openai.OpenAI(api_key=api_key or "tinfoil", base_url=base_url, http_client=self._view,
                                   **self._kw)
        self._async_by_loop: dict[int, tuple[asyncio.AbstractEventLoop, openai.AsyncOpenAI]] = {}
        self.api_key = self._sync.api_key
        self.base_url = self._sync.base_url
        self.chat = _Chat(self)

    def _check_gate(self) -> None:
        if self._gate is not None:
            try:
                self._gate()  # raises ConfidentialRefused when verification is no longer fresh/pinned
            except ConfidentialRefused as exc:
                _record(self._on_refuse, exc)
                raise

    def _async_client(self) -> openai.AsyncOpenAI:
        loop = asyncio.get_running_loop()
        for key in [k for k, (lp, _) in self._async_by_loop.items() if lp.is_closed()]:
            self._async_by_loop.pop(key, None)
        entry = self._async_by_loop.get(id(loop))
        if entry is None or entry[0] is not loop:
            http = self._adapter.async_http_for_loop()
            entry = (loop, openai.AsyncOpenAI(api_key=self.api_key, base_url=self.base_url, http_client=http,
                                              **self._kw))
            self._async_by_loop[id(loop)] = entry
        return entry[1]

    def __getattr__(self, name):  # with_options, models, is_closed, _client, _custom_headers, ...
        return getattr(object.__getattribute__(self, "_sync"), name)

    def close(self) -> None:
        self._sync.close()  # closes this client's view only; the verified pool stays up


# ── RefusingClient ─────────────────────────────────────────────────────────────────────────────


def _record(on_refuse, exc: BaseException) -> None:
    """Hand a provider-gate refusal to the vendor's ledger hook (NEAR: a send_refused row). Never raises."""
    if on_refuse is not None:
        try:
            on_refuse(exc)
        except Exception:
            pass


class _RefusingTransport(httpx.BaseTransport):
    def __init__(self, reason: str, on_refuse=None):
        self._reason = reason
        self._on_refuse = on_refuse

    def handle_request(self, request):
        exc = ConfidentialRefused(self._reason)
        _record(self._on_refuse, exc)
        raise exc


class _RefusingResource:
    """Any method call raises; used for chat.completions, models, embeddings, responses."""

    def __init__(self, reason: str, on_refuse=None):
        self._reason = reason
        self._on_refuse = on_refuse

    def _refuse(self, *args, **kwargs):
        exc = ConfidentialRefused(self._reason)
        _record(self._on_refuse, exc)
        raise exc

    create = list = retrieve = parse = stream = _refuse


class _RefusingChat:
    def __init__(self, reason: str, on_refuse=None):
        self.completions = _RefusingResource(reason, on_refuse)


class RefusingClient:
    HERMES_SKIP_TRANSPORT_WRAP = True
    HERMES_SKIP_ASYNC_WRAP = True

    def __init__(self, reason: str, *, api_key: str = "", base_url: str = "",
                 on_refuse: Callable[[BaseException], None] | None = None):
        self.reason = reason
        self.api_key = api_key or "refused"
        self.base_url = base_url
        self.chat = _RefusingChat(reason, on_refuse)
        self.models = _RefusingResource(reason, on_refuse)
        self.embeddings = _RefusingResource(reason, on_refuse)
        self.responses = _RefusingResource(reason, on_refuse)
        self._custom_headers: dict = {}
        self._client = httpx.Client(transport=_RefusingTransport(reason, on_refuse))
        self._closed = False

    def with_options(self, **_kwargs) -> "RefusingClient":
        return self

    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True
        self._client.close()

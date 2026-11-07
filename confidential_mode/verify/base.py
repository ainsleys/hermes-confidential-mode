"""Frozen shared types for vendor verification (C1). Adapters live beside this file."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import httpx


class VerifyError(Exception):
    """Any verification failure. Adapters never return a partial result."""


@dataclass(frozen=True)
class VerificationResult:
    vendor: str                 # "tinfoil"
    router_repo: str            # "tinfoilsh/confidential-model-router"
    enclave_host: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None
    verifier: str               # SDK verifier identity string
    verified_at_host_clock: float    # time.time(); NOT attested, labelled so everywhere it is shown
    evidence: dict = field(default_factory=dict)  # raw, JSON-serialisable


@dataclass
class PreparedVerification:
    """A verification that passed its checks but is not yet in use (Amendment 9). The adapter's
    ``prepare_verification()`` builds one with network I/O and publishes nothing; ``commit_verification()``
    makes it the adapter's accepted result under the adapter lock. ``discard()`` releases what the
    capture built (for example an unused connection pool) when the result is not accepted."""
    result: VerificationResult
    payload: Any = None
    on_discard: Callable[[], None] | None = None

    def discard(self) -> None:
        cb, self.on_discard = self.on_discard, None
        if cb is not None:
            try:
                cb()
            except Exception:
                pass


class VendorAdapter(Protocol):
    vendor: str

    def verify(self) -> VerificationResult: ...
    def sync_http_view(self) -> httpx.Client: ...
    def async_http_for_loop(self) -> httpx.AsyncClient: ...

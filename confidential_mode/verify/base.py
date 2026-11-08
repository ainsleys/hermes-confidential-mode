"""Frozen shared types for vendor verification (C1). Adapters live beside this file."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import httpx


class VerifyError(Exception):
    """Any verification failure. Adapters never return a partial result."""


def http_next_step(status: int, subject_kind: str = "model") -> str:
    """One next step for a vendor endpoint that answered ``status`` (Amendment 14)."""
    if status == 404:
        return f"check the {subject_kind} id; the vendor does not serve an attestation for it"
    if status in (401, 403):
        return "attestation is public, so this answer is the vendor's; try again later"
    return "try again in a few minutes"


class VendorHTTPError(VerifyError):
    """A vendor endpoint answered an attestation request with an HTTP error (Amendment 14). The text names
    the vendor, the subject (a model id, or the gateway or router host), the HTTP status and one next step:
    "<subject>: attestation unavailable (HTTP 503 from NEAR); try again in a few minutes"."""

    def __init__(self, *, vendor: str, subject: str, status: int, path: str = "", next_step: str = "",
                 subject_kind: str = "model"):
        self.vendor, self.subject, self.status, self.path = vendor, subject, int(status), path
        self.subject_kind = subject_kind
        self.next_step = next_step or http_next_step(self.status, subject_kind)
        super().__init__(f"{subject}: attestation unavailable (HTTP {self.status} from {vendor}); {self.next_step}")


def http_status_in(exc: BaseException | None) -> int | None:
    """The HTTP status carried anywhere in ``exc``'s chain (``status_code``, or ``response.status_code``,
    as requests and httpx raise them), or None."""
    seen = 0
    while exc is not None and seen < 10:
        for holder in (exc, getattr(exc, "response", None)):
            code = getattr(holder, "status_code", None)
            if isinstance(code, int) and 100 <= code <= 599:
                return code
        exc = exc.__cause__ or exc.__context__
        seen += 1
    return None


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

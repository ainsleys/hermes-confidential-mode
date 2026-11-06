"""Frozen shared types for vendor verification (C1). Adapters live beside this file."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

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


class VendorAdapter(Protocol):
    vendor: str

    def verify(self) -> VerificationResult: ...
    def sync_http_view(self) -> httpx.Client: ...
    def async_http_for_loop(self) -> httpx.AsyncClient: ...

"""Frozen shared types for tiers (C1). Predicates are added by W3 below the marker."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class Tier(str, Enum):
    LOCAL = "local-only"
    ATTESTED = "attested"
    ZDR = "zero-retention"


@dataclass(frozen=True)
class Destination:
    provider: str      # Hermes provider name, e.g. "attested-tinfoil", "openrouter", "custom"
    base_url: str      # as Hermes passes it; may be ""
    model: str
    api_mode: str      # chat_completions | anthropic_messages | codex_responses | bedrock_converse | codex_app_server
    purpose: str       # "main" | "fallback" | "aux:<task>" | "tool:<name>" | "memory" | "mcp:<server>"


@dataclass(frozen=True)
class Verdict:
    in_tier: bool
    reason: str        # short, user-visible, no secrets
    host: str = ""     # parsed host, for the ledger and watch view


class TierPredicate(Protocol):
    tier: Tier

    def classify(self, dest: Destination) -> Verdict: ...


# --- W3 adds predicates below this line -------------------------------------

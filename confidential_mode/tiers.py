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

import ipaddress
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

#: Names that are local without an IP literal. No DNS is ever consulted: any other hostname is off-tier
#: unless the user lists it in ``confidential.local.extra_hosts``.
LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})

_LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128",                                   # loopback
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",            # RFC1918
    "100.64.0.0/10",                                            # CGNAT / tailnet
    "fe80::/10",                                                # IPv6 link-local
    "fc00::/7",                                                 # IPv6 unique local
))


def host_of(base_url: str) -> str:
    """Lower-cased host of ``base_url`` without brackets, port, userinfo or trailing dot; "" if none.

    Accepts a missing scheme ("10.0.0.2:8080/v1", "localhost") and bracketed IPv6 ("[::1]:11434").
    A bare unbracketed IPv6 literal ("::1", "fe80::1") is returned as-is.
    """
    raw = (base_url or "").strip()
    if not raw:
        return ""
    candidate = raw
    try:
        ipaddress.ip_address(candidate.strip("[]").split("%", 1)[0])
        return candidate.strip("[]").lower()
    except ValueError:
        pass
    if "://" not in candidate:
        candidate = "//" + candidate.lstrip("/")
    try:
        parts = urlsplit(candidate)
        host = parts.hostname or ""
    except ValueError:
        return ""
    host = host.strip().rstrip(".").lower()
    return host


def _ip_of(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])  # drop an IPv6 zone id (fe80::1%en0)
    except ValueError:
        return None


def is_local_host(host: str, extra_hosts: Iterable[str] = ()) -> bool:
    """True for loopback / RFC1918 / 100.64/10 / fe80::/10 / fc00::/7 literals, local names, or extra hosts."""
    if not host:
        return False
    host = host.lower()
    extras = {h.strip().lower().strip("[]") for h in extra_hosts if isinstance(h, str) and h.strip()}
    if host in LOCAL_NAMES or host in extras:
        return True
    ip = _ip_of(host)
    if ip is None:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)  # ::ffff:10.0.0.1 is the IPv4 address
    if mapped is not None:
        ip = mapped
    return any(ip.version == net.version and ip in net for net in _LOCAL_NETWORKS)


def _no_profile_url(_provider: str) -> str:
    return ""


class LocalPredicate:
    """``local-only`` tier: the destination host must be on this machine or its private network.

    An empty ``base_url`` is resolved through ``profile_base_url(provider)`` (the provider profile's
    default endpoint); if that is empty or remote the destination is off-tier.
    """

    tier = Tier.LOCAL

    def __init__(self, extra_hosts: Iterable[str] = (), profile_base_url: Callable[[str], str] | None = None):
        self.extra_hosts = {h.strip().lower().strip("[]") for h in extra_hosts if isinstance(h, str) and h.strip()}
        self.profile_base_url = profile_base_url or _no_profile_url

    def classify(self, dest: Destination) -> Verdict:
        base_url = (dest.base_url or "").strip()
        via_profile = False
        if not base_url:
            try:
                base_url = (self.profile_base_url(dest.provider) or "").strip()
            except Exception:
                base_url = ""
            via_profile = True
            if not base_url:
                return Verdict(False, f"no base_url and provider {dest.provider or '(none)'!s} has no known local endpoint", "")
        host = host_of(base_url)
        if not host:
            return Verdict(False, "base_url has no parsable host", "")
        if is_local_host(host, self.extra_hosts):
            src = " (provider default)" if via_profile else ""
            return Verdict(True, f"local host {host}{src}", host)
        if _ip_of(host) is None and host not in LOCAL_NAMES:
            return Verdict(False, f"host {host} is not an IP literal or a listed local host", host)
        return Verdict(False, f"host {host} is not on a local network", host)


class AttestedPredicate:
    """``attested`` tier: the provider must be a registered attested profile and ``attested_ok`` must pass.

    ``attested_ok(provider)`` is W2's freshness + pin check. When ``profile_base_url`` is given, a
    non-empty ``base_url`` whose host differs from the profile's endpoint is off-tier (a base_url
    override would send the request somewhere the attestation does not cover).
    """

    tier = Tier.ATTESTED

    def __init__(self, attested_profiles: Iterable[str], attested_ok: Callable[[str], Verdict],
                 profile_base_url: Callable[[str], str] | None = None):
        self.attested_profiles = {p.strip().lower() for p in attested_profiles if isinstance(p, str) and p.strip()}
        self.attested_ok = attested_ok
        self.profile_base_url = profile_base_url

    def classify(self, dest: Destination) -> Verdict:
        provider = (dest.provider or "").strip().lower()
        host = host_of(dest.base_url)
        if provider not in self.attested_profiles:
            return Verdict(False, f"provider {provider or '(none)'} is not an attested profile", host)
        if self.profile_base_url is not None and host:
            try:
                expected = host_of(self.profile_base_url(provider) or "")
            except Exception:
                expected = ""
            if host != expected:
                return Verdict(False, f"base_url host {host} is not the attested endpoint", host)
        try:
            verdict = self.attested_ok(provider)
        except Exception:
            return Verdict(False, "attestation check failed", host)
        if not isinstance(verdict, Verdict):
            return Verdict(False, "attestation check returned no verdict", host)
        return Verdict(bool(verdict.in_tier), verdict.reason, verdict.host or host)


class ZdrPredicate:
    """``zero-retention`` tier: deferred. Everything is off-tier."""

    tier = Tier.ZDR

    def classify(self, dest: Destination) -> Verdict:
        return Verdict(False, "zero-retention tier not implemented", host_of(dest.base_url))

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
from typing import Any, Callable, Iterable, Optional
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
# Deliberately absent: 169.254.0.0/16 (cloud metadata), 0.0.0.0/::, and any non-dotted-quad IPv4
# spelling (0x7f000001, 2130706433, 127.1): ipaddress rejects those, so they are unknown hostnames.

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def host_of(base_url: Any) -> str:
    """Lower-cased host of ``base_url`` without brackets, port, userinfo or trailing dot; "" if none.

    Display/ledger helper; lenient by design (accepts a missing scheme). Backslashes are read as path
    separators, as WHATWG/httpx do, so the reported host is the one an HTTP client would connect to.
    Never raises. The strict check used for tier decisions is :func:`strict_host`.
    """
    if not isinstance(base_url, str):
        return ""
    raw = base_url.strip().replace("\\", "/")
    if not raw:
        return ""
    bare = raw.strip("[]")
    if _ip_of(bare) is not None and "/" not in raw:
        return bare.lower()
    candidate = raw if "://" in raw else "//" + raw.lstrip("/")
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        return ""
    host = host.strip().rstrip(".").lower()
    return host if host.isprintable() else ""


def strict_host(base_url: Any) -> tuple[str, str]:
    """(host, problem) for a tier decision. ``problem`` is "" only for a clean http(s) URL.

    Fails closed on anything two URL parsers could read differently: backslashes, whitespace or
    control characters, non-ASCII, a missing or non-http(s) scheme, a malformed port, or a
    percent sign in the host other than an IPv6 zone id.
    """
    if not isinstance(base_url, str):
        return "", "base_url is not a string"
    raw = base_url.strip()
    shown = host_of(raw)
    if not raw:
        return "", "empty base_url"
    if "\\" in raw:
        return shown, "base_url contains a backslash"
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        return shown, "base_url contains whitespace or control characters"
    if not raw.isascii():
        return shown, "base_url contains non-ASCII characters"
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        _ = parts.port  # raises ValueError for non-numeric or out-of-range ports
    except ValueError:
        return shown, "base_url is malformed (host or port)"
    if scheme not in _ALLOWED_SCHEMES or "://" not in raw:
        return shown, "base_url must start with http:// or https://"
    host = host.strip().rstrip(".").lower()
    if not host:
        return "", "base_url has no host"
    if "%" in host and _ip_of(host) is None:
        return host, "base_url host is percent-encoded"
    return host, ""


def _ip_of(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not isinstance(host, str) or not host:
        return None
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])  # drop an IPv6 zone id (fe80::1%en0)
    except ValueError:
        return None


def _norm_hosts(hosts: Iterable[str]) -> set[str]:
    out = set()
    for h in hosts or ():
        if isinstance(h, str):
            h = h.strip().strip("[]").rstrip(".").lower()
            if h:
                out.add(h)
    return out


def is_local_host(host: str, extra_hosts: Iterable[str] = ()) -> bool:
    """True for loopback / RFC1918 / 100.64/10 / fe80::/10 / fc00::/7 literals, local names, or extra hosts."""
    if not isinstance(host, str) or not host:
        return False
    host = host.lower()
    if host in LOCAL_NAMES or host in _norm_hosts(extra_hosts):
        return True
    ip = _ip_of(host)
    if ip is None:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)  # ::ffff:10.0.0.1 is the IPv4 address
    if mapped is not None:
        ip = mapped
    return any(ip.version == net.version and ip in net for net in _LOCAL_NETWORKS)


def _profile_url(lookup: Callable[[str], Any] | None, provider: str) -> str:
    """Call an injected profile lookup; accepts a URL string or an object with ``base_url``."""
    if lookup is None:
        return ""
    try:
        result = lookup(provider)
    except Exception:
        return ""
    if isinstance(result, str):
        return result.strip()
    url = getattr(result, "base_url", None)
    return url.strip() if isinstance(url, str) else ""


class LocalPredicate:
    """``local-only`` tier: the destination host must be on this machine or its private network.

    An empty ``base_url`` is resolved through ``profile_base_url(provider)`` (a URL string, or a
    profile object with ``base_url``); a local result is in-tier, anything else off-tier. Real Hermes
    local profiles (ollama, lmstudio, llama-cpp) have ``base_url ""`` at 84a0301, so in practice the
    user sets ``model.base_url`` / ``auxiliary.<task>.base_url`` explicitly.
    """

    tier = Tier.LOCAL

    def __init__(self, extra_hosts: Iterable[str] = (), profile_base_url: Callable[[str], Any] | None = None):
        self.extra_hosts = _norm_hosts(extra_hosts)
        self.profile_base_url = profile_base_url

    def classify(self, dest: Destination) -> Verdict:
        base_url = dest.base_url.strip() if isinstance(dest.base_url, str) else dest.base_url
        via_profile = False
        if base_url == "" or base_url is None:
            base_url = _profile_url(self.profile_base_url, dest.provider)
            via_profile = True
            if not base_url:
                return Verdict(False, f"no base_url and provider {dest.provider or '(none)'} has no known "
                                      "local endpoint; set base_url explicitly", "")
        host, problem = strict_host(base_url)
        if problem:
            return Verdict(False, problem, host)
        if is_local_host(host, self.extra_hosts):
            src = " (provider default)" if via_profile else ""
            return Verdict(True, f"local host {host}{src}", host)
        if _ip_of(host) is None:
            return Verdict(False, f"host {host} is not an IP literal or a listed local host", host)
        return Verdict(False, f"host {host} is not on a local network", host)


class AttestedPredicate:
    """``attested`` tier: the provider must be a registered attested profile and ``attested_ok`` must pass.

    ``attested_profiles`` match exactly (Hermes passes canonical lower-case names). ``attested_ok(provider)``
    is W2's freshness + pin check. When ``profile_base_url`` is given, a non-empty ``base_url`` whose
    host differs from the profile's endpoint is off-tier (the attestation does not cover it).
    """

    tier = Tier.ATTESTED

    def __init__(self, attested_profiles: Iterable[str], attested_ok: Callable[[str], Verdict],
                 profile_base_url: Callable[[str], Any] | None = None):
        self.attested_profiles = {p for p in attested_profiles if isinstance(p, str) and p}
        self.attested_ok = attested_ok
        self.profile_base_url = profile_base_url

    def classify(self, dest: Destination) -> Verdict:
        provider = dest.provider if isinstance(dest.provider, str) else ""
        base_url = dest.base_url.strip() if isinstance(dest.base_url, str) else ""
        host = host_of(base_url)
        if provider not in self.attested_profiles:
            return Verdict(False, f"provider {provider or '(none)'} is not an attested profile", host)
        if base_url:
            host, problem = strict_host(base_url)
            if problem:
                return Verdict(False, problem, host)
            if self.profile_base_url is not None:
                expected, _ = strict_host(_profile_url(self.profile_base_url, provider))
                if host != expected:
                    return Verdict(False, f"base_url host {host} is not the attested endpoint", host)
        try:
            verdict = self.attested_ok(provider)
        except Exception:
            return Verdict(False, "attestation check failed", host)
        if not isinstance(verdict, Verdict) or not isinstance(verdict.in_tier, bool):
            return Verdict(False, "attestation check returned no verdict", host)
        return Verdict(verdict.in_tier, verdict.reason or ("attested" if verdict.in_tier else "not attested"),
                       verdict.host or host)


class ZdrPredicate:
    """``zero-retention`` tier: deferred. Everything is off-tier."""

    tier = Tier.ZDR

    def classify(self, dest: Destination) -> Verdict:
        return Verdict(False, "zero-retention tier not implemented", host_of(dest.base_url))

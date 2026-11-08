"""Frozen shared types for tiers (C1). Predicates are added by W3 below the marker."""
from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import re
import socket
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlsplit


class Tier(str, Enum):
    ON_HOST = "on-host-only"
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

#: Names that are on-host without an IP literal. No DNS is consulted for these names. The machine's own host
#: name is the one name that is resolved (see :func:`own_hostname_is_loopback`). Any other hostname is
#: off-tier unless the user lists it in ``confidential.on_host.extra_hosts``.
ON_HOST_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})

#: D03 (Amendment 10): only loopback is on-host by rule. A private, carrier-grade NAT, link-local or
#: unique-local address can be another machine, so those ranges are off-tier unless the exact host is
#: listed in ``confidential.on_host.extra_hosts``.
_ON_HOST_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128"))
# Deliberately absent: 169.254.0.0/16 (cloud metadata), 0.0.0.0/::, and any non-dotted-quad IPv4
# spelling (0x7f000001, 2130706433, 127.1): ipaddress rejects those, so they are unknown hostnames.

#: Cloud metadata endpoints (AWS, GCP, Azure: 169.254.169.254; AWS IPv6: fd00:ec2::254). Never listable.
_METADATA_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254"))

#: The config key that lists extra on-host hosts. Named in off-tier reasons.
EXTRA_HOSTS_KEY = "confidential.on_host.extra_hosts"

#: Ranges that are off-tier unless listed, with the name an off-tier reason uses for each.
_NEIGHBOUR_NETWORKS = tuple((ipaddress.ip_network(n), label) for n, label in (
    ("10.0.0.0/8", "private range 10.0.0.0/8 (RFC1918)"),
    ("172.16.0.0/12", "private range 172.16.0.0/12 (RFC1918)"),
    ("192.168.0.0/16", "private range 192.168.0.0/16 (RFC1918)"),
    ("100.64.0.0/10", "carrier-grade NAT range 100.64.0.0/10"),
    ("169.254.0.0/16", "IPv4 link-local range 169.254.0.0/16"),
    ("fe80::/10", "IPv6 link-local range fe80::/10"),
    ("fc00::/7", "IPv6 unique-local range fc00::/7"),
))

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
    raw = base_url  # never stripped: whitespace/control characters anywhere (even trailing) fail closed
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
    if "%" in host:
        if _ip_of(host) is None:
            return host, "base_url host is percent-encoded"
        if zone_problem(host):
            return host, f"base_url host {zone_problem(host)}"
    return host, ""


_ZONE = re.compile(r"^[a-z0-9_-]{1,64}$")   # no dot: a zone must not look like a domain


def zone_problem(host: str) -> str:
    """"" unless ``host`` carries a zone id (``%``) that is not a plain interface name on an IPv6 link-local
    address. A zone id exists only for IPv6 link-local addresses; on any other literal the client reads the
    whole string as a name (``127.0.0.1%25evil.com``), so the tier and the client would disagree."""
    if "%" not in host:
        return ""
    addr, zone = host.split("%", 1)
    zone = zone[2:] if zone.startswith("25") else zone  # a URL carries the zone id as %25<zone>
    ip = _ip_of(addr)
    if not isinstance(ip, ipaddress.IPv6Address) or ip.ipv4_mapped is not None or not ip.is_link_local:
        return "has a zone id (%) on an address that is not IPv6 link-local"
    if not _ZONE.match(zone):
        return "has a zone id that is not a plain interface name"
    return ""


def _ip_of(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(host, str) or not host:
        return None
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])  # drop an IPv6 zone id (fe80::1%en0)
    except ValueError:
        return None


_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def _norm_entry(entry: Any) -> str:
    if not isinstance(entry, str):
        return ""
    h = entry.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h.rstrip(".").lower()


def extra_host_problem(entry: Any) -> str:
    """"" when ``entry`` is one exact host for ``confidential.on_host.extra_hosts``, else why not.

    An exact host is one IP address or one DNS name. Ranges (CIDR, wildcards, dash ranges), URLs,
    ports, paths and anything else are refused, so a listed entry can never widen past one host.
    A DNS name's last label must start with a letter, so numeric spellings such as ``127.1`` or
    ``10.0.0.1-9`` are refused rather than read as names.
    """
    if not isinstance(entry, str):
        return "is not a string"
    h = _norm_entry(entry)
    if not h:
        return "is empty"
    if not h.isascii() or not h.isprintable() or any(c.isspace() for c in h):
        return "contains whitespace, control or non-ASCII characters"
    if _ip_of(h) is not None and "/" not in h:
        if zone_problem(h):
            return zone_problem(h)
        ip = _unmapped(_ip_of(h))
        if ip in _METADATA_ADDRESSES:
            return f"is {ip}, the cloud metadata address, which is never a model host"
        if ip.is_unspecified:
            return "is the unspecified address (0.0.0.0 or ::), which is not one host"
        if ip.is_multicast or str(ip) == "255.255.255.255":
            return "is a multicast or broadcast address, which is not one host"
        return ""
    if "/" in h:
        return "is a range or a URL; list one exact host name or IP address"
    if "*" in h or "?" in h:
        return "is a wildcard; list one exact host name or IP address"
    if ":" in h:
        return "has a port, a scheme or a malformed IPv6 address; list the bare host"
    labels = h.split(".")
    if len(h) > 253 or not all(_LABEL.match(label) for label in labels):
        return "is not a valid host name or IP address"
    if not labels[-1][0].isalpha():
        return "is not a valid IP address and not a host name; list one exact host name or IP address"
    return ""


def _norm_hosts(hosts: Iterable[str]) -> set[str]:
    """The valid exact entries of ``hosts``, normalised. Invalid entries are dropped (fail closed);
    the on-host preflight lists each dropped entry as a failing row."""
    out: set[str] = set()
    if isinstance(hosts, str):  # a bare string is not a list of hosts
        return out
    for h in hosts or ():
        if extra_host_problem(h) == "":
            out.add(_norm_entry(h))
    return out


def _unmapped(ip):
    mapped = getattr(ip, "ipv4_mapped", None)  # ::ffff:10.0.0.1 is the IPv4 address
    return mapped if mapped is not None else ip


def _listed(host: str, listed: set[str]) -> bool:
    """Exact match of ``host`` against normalised listed entries. IP literals compare as addresses, so
    two spellings of one address match; a zone id must match exactly."""
    if host in listed:
        return True
    ip = _ip_of(host)
    if ip is None:
        return False
    zone = host.split("%", 1)[1] if "%" in host else ""
    zone = zone[2:] if zone.startswith("25") else zone  # a URL carries the zone id as %25<zone>
    for entry in listed:
        eip = _ip_of(entry)
        if eip is None:
            continue
        ezone = entry.split("%", 1)[1] if "%" in entry else ""
        ezone = ezone[2:] if ezone.startswith("25") else ezone
        if zone == ezone and _unmapped(eip) == _unmapped(ip):
            return True
    return False


def _resolve_all(name: str) -> list[str]:
    infos = socket.getaddrinfo(name, None)
    return [info[4][0] for info in infos]  # type: ignore[misc]  # sockaddr[0] is the address text for IPv4 and IPv6


#: own host name -> (answer, monotonic time of the answer). A False answer (including a timeout) is kept for
#: the life of the process. A True answer is rechecked once it is older than the TTL.
_OWN_HOSTNAME_CACHE: dict[str, tuple[bool, float]] = {}
_OWN_HOSTNAME_TIMEOUT_SECONDS = 2.0
_OWN_HOSTNAME_TTL_SECONDS = 60.0
_OWN_HOSTNAME_LOCK = threading.Lock()
#: True inside ``cached_lookups_only()``: the own-host-name check answers from the cache only (Amendment 13).
_CACHED_ONLY: contextvars.ContextVar[bool] = contextvars.ContextVar("confidential_mode_cached_lookups_only",
                                                                      default=False)


class LookupDeferred(BaseException):
    """Raised by the own-host-name check inside ``cached_lookups_only()`` when answering would need a DNS
    lookup. A BaseException on purpose: the preflight's ``except Exception`` handlers must not turn it into
    a verdict. The caller that opened the scope catches it and leaves the check to a path that may resolve."""


@contextlib.contextmanager
def cached_lookups_only():
    """Within this scope the own-host-name check never resolves: it returns the cached answer (even past its
    TTL) or raises LookupDeferred. The pre_llm_call hook runs its recheck here so the hook does no network
    I/O."""
    token = _CACHED_ONLY.set(True)
    try:
        yield
    finally:
        _CACHED_ONLY.reset(token)


def own_hostname_is_loopback(host: str, *, resolver: Callable[[str], list[str]] | None = None,
                             hostname: Callable[[], str] | None = None) -> bool:
    """True when ``host`` is this machine's own host name and every address it resolves to is loopback.

    Only the machine's own name is ever resolved, and only when the destination names it. A resolver error,
    a timeout, an empty answer or any non-loopback address gives False (fail closed), and False is cached
    for the process. A True answer is rechecked at most once per ``_OWN_HOSTNAME_TTL_SECONDS``. One lookup
    runs at a time. Never raises.
    """
    try:
        own = (hostname or socket.gethostname)()
        own = own.strip().rstrip(".").lower() if isinstance(own, str) else ""
        if not own or host != own or own in ON_HOST_NAMES:
            return False
    except Exception:
        return False
    if _CACHED_ONLY.get():
        with _OWN_HOSTNAME_LOCK:
            cached = _OWN_HOSTNAME_CACHE.get(own)
        if cached is None:
            raise LookupDeferred(own)
        return cached[0]
    try:
        if resolver is not None:
            return _lookup_own(own, resolver)
        with _OWN_HOSTNAME_LOCK:
            cached = _OWN_HOSTNAME_CACHE.get(own)
            now = time.monotonic()
            if cached is not None and (cached[0] is False or now - cached[1] < _OWN_HOSTNAME_TTL_SECONDS):
                return cached[0]
            ok = _lookup_own(own, None)
            _OWN_HOSTNAME_CACHE[own] = (ok, time.monotonic())
            return ok
    except Exception:
        return False


def _lookup_own(own: str, resolver: Callable[[str], list[str]] | None) -> bool:
    try:
        result: list = []

        def work():
            try:
                result.append((resolver or _resolve_all)(own))
            except Exception:
                result.append([])
        t = threading.Thread(target=work, name="confidential-own-hostname", daemon=True)
        t.start()
        t.join(_OWN_HOSTNAME_TIMEOUT_SECONDS)
        addrs = result[0] if result else []
        ips = [_ip_of(a) if isinstance(a, str) else None for a in addrs]
        return bool(ips) and all(ip is not None and _unmapped(ip).is_loopback for ip in ips)
    except Exception:
        return False


def neighbour_range(host: str) -> str:
    """The name of the private, carrier-grade NAT, link-local or unique-local range ``host`` is in, or ""."""
    ip = _ip_of(host) if isinstance(host, str) else None
    if ip is None:
        return ""
    ip = _unmapped(ip)
    for net, label in _NEIGHBOUR_NETWORKS:
        if ip.version == net.version and ip in net:
            return label
    return ""


def is_on_host(host: str, extra_hosts: Iterable[str] = ()) -> bool:
    """True for loopback literals (127.0.0.0/8, ::1, IPv4-mapped loopback), the on-host names, or an
    exact host listed in ``extra_hosts``. Private-range, carrier-grade NAT, link-local and unique-local
    addresses are off-tier unless listed. Never resolves a name (the machine's own host name is handled
    by :class:`OnHostPredicate`)."""
    if not isinstance(host, str) or not host:
        return False
    host = host.lower()
    if host in ON_HOST_NAMES or _listed(host, _norm_hosts(extra_hosts)):
        return True
    ip = _ip_of(host)
    if ip is None:
        return False
    ip = _unmapped(ip)
    return any(ip.version == net.version and ip in net for net in _ON_HOST_NETWORKS)


def _profile_url(lookup: Callable[[str], Any] | None, provider: str) -> str:
    """Call an injected profile lookup; accepts a URL string or an object with ``base_url``."""
    if lookup is None:
        return ""
    try:
        result = lookup(provider)
    except Exception:
        return ""
    if isinstance(result, str):
        return result
    url = getattr(result, "base_url", None)
    return url if isinstance(url, str) else ""


class OnHostPredicate:
    """``on-host-only`` tier: the destination host must be this machine, or a host the user listed.

    In-tier: loopback literals (127.0.0.0/8, ::1, IPv4-mapped loopback), the names in ``ON_HOST_NAMES``,
    the machine's own host name when it resolves only to loopback, and exact hosts listed in
    ``confidential.on_host.extra_hosts``. Everything else is off-tier, including private, carrier-grade
    NAT, link-local and unique-local addresses (Amendment 10, backlog D03).

    An empty ``base_url`` is resolved through ``profile_base_url(provider)`` (a URL string, or a
    profile object with ``base_url``); an on-host result is in-tier, anything else off-tier. Hermes'
    on-host profiles (ollama, lmstudio, llama-cpp) have ``base_url ""`` at 84a0301, so in practice the
    user sets ``model.base_url`` / ``auxiliary.<task>.base_url`` explicitly.
    """

    tier = Tier.ON_HOST

    def __init__(self, extra_hosts: Iterable[str] = (), profile_base_url: Callable[[str], Any] | None = None,
                 own_hostname: Callable[[str], bool] | None = None):
        self.extra_hosts = _norm_hosts(extra_hosts)
        self.profile_base_url = profile_base_url
        self.own_hostname = own_hostname or own_hostname_is_loopback

    def classify(self, dest: Destination) -> Verdict:
        base_url = dest.base_url
        via_profile = False
        if base_url == "" or base_url is None:
            base_url = _profile_url(self.profile_base_url, dest.provider)
            via_profile = True
            if not base_url:
                return Verdict(False, f"no base_url and provider {dest.provider or '(none)'} has no known "
                                      "on-host endpoint; set base_url explicitly", "")
        host, problem = strict_host(base_url)
        if problem:
            return Verdict(False, problem, host)
        src = " (provider default)" if via_profile else ""
        if is_on_host(host):
            return Verdict(True, f"on-host endpoint {host}{src}", host)
        if _listed(host.lower(), self.extra_hosts):
            return Verdict(True, f"listed on-host host {host} ({EXTRA_HOSTS_KEY}){src}", host)
        if _ip_of(host) is None:
            try:
                own = self.own_hostname(host) is True
            except Exception:
                own = False
            if own:
                return Verdict(True, f"on-host endpoint {host} (this machine's host name, resolves to loopback){src}",
                               host)
            return Verdict(False, f"host {host} is not an IP literal or a listed on-host name; if the model runs "
                                  f"there, list the exact host under {EXTRA_HOSTS_KEY}", host)
        rng = neighbour_range(host)
        if rng:
            return Verdict(False, f"host {host} is in the {rng}, which can be another machine; if the model "
                                  f"runs there, list the exact host under {EXTRA_HOSTS_KEY}", host)
        return Verdict(False, f"host {host} is not loopback on this host", host)


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
        base_url = dest.base_url if isinstance(dest.base_url, str) else ""
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

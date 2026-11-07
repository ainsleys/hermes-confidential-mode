"""Hostile tests for confidential_mode.tiers (W3 contract, docs/INTERFACES.md).

Written blind against the contract, then adapted to W3's public signatures and to the
adjudications in INTERFACES.md Amendments 1 and 2:
    OnHostPredicate(extra_hosts=(), profile_base_url=None)
    AttestedPredicate(attested_profiles, attested_ok, profile_base_url=None)
    ZdrPredicate()

Policy: off-tier is the fail-closed direction; inputs the contract does not bless must not be
in_tier.
"""
from __future__ import annotations

import socket

import pytest

from confidential_mode import tiers  # noqa: E402  (ImportError until W3 merges is expected)
from confidential_mode.tiers import Destination, Tier, Verdict  # noqa: E402

OnHostPredicate = tiers.OnHostPredicate
AttestedPredicate = tiers.AttestedPredicate
ZdrPredicate = tiers.ZdrPredicate
host_of = tiers.host_of

ATTESTED = "attested-tinfoil"


# --------------------------------------------------------------------------- fixtures / wiring

@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    """Any resolver call is recorded AND raises; asserting on the record catches predicates that
    swallow the exception into an off-tier verdict."""
    calls: list[tuple] = []

    def boom(name):
        def _f(*a, **k):
            calls.append((name, a))
            raise AssertionError(f"DNS/network call {name}{a!r} from a tier predicate")
        return _f

    for fn in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
               "getnameinfo", "create_connection"):
        monkeypatch.setattr(socket, fn, boom(fn))
    yield calls
    assert calls == [], f"predicate performed name resolution: {calls}"


class FakeProfile:
    def __init__(self, name: str, base_url: str, attested: bool = False):
        self.name = name
        self.base_url = base_url
        self.attested = attested

    def __str__(self):  # hedge for implementations that expect a URL string
        return self.base_url


def _profile_url(profiles):
    def f(name):
        prof = (profiles or {}).get(name)
        return getattr(prof, "base_url", "") if prof is not None else ""
    return f


def on_host(monkeypatch=None, extra_hosts=(), profiles=None):
    return OnHostPredicate(extra_hosts=tuple(extra_hosts), profile_base_url=_profile_url(profiles))


def dest(base_url, provider="custom", purpose="main"):
    return Destination(provider=provider, base_url=base_url, model="m",
                       api_mode="chat_completions", purpose=purpose)


def classify(pred, d) -> Verdict:
    v = pred.classify(d)
    assert isinstance(v, Verdict), f"classify must return Verdict, got {type(v)}"
    assert isinstance(v.in_tier, bool)
    assert isinstance(v.reason, str) and v.reason, "reason must be a non-empty user-visible string"
    return v


# --------------------------------------------------------------------------- ON_HOST: look-alikes

LOOKS_ON_HOST_BUT_IS_NOT = [
    "http://localhost.evil.com/v1",
    "http://localhost.evil.com:11434/v1",
    "http://127.0.0.1.nip.io/v1",
    "http://10.0.0.1.evil.com/v1",
    "http://192.168.1.1.sslip.io/v1",
    "http://[::ffff:8.8.8.8]/v1",              # IPv4-mapped public address
    "http://[64:ff9b::8.8.8.8]/v1",            # NAT64 of a public address
    "http://10.0.0.1@evil.com/v1",             # userinfo, real host is evil.com
    "http://127.0.0.1:11434@evil.com/v1",
    "http://evil.com#127.0.0.1",               # fragment
    "http://evil.com?h=127.0.0.1",             # query
    "http://evil.com/127.0.0.1",               # path
    "http://lоcalhost/v1",                # Cyrillic o homoglyph
    "http://xn--lcalhost-9vf/v1",              # punycode of a homoglyph
    "http://localhost%2eevil.com/v1",          # percent-encoded dot
    "http://169.254.169.254/latest",           # link-local v4 / cloud metadata: NOT in contract list
    "http://169.254.0.1/v1",
    "http://100.63.255.255/v1",                # just below 100.64/10
    "http://100.128.0.1/v1",                   # just above 100.64/10
    "http://172.15.255.255/v1",                # just below 172.16/12
    "http://172.32.0.1/v1",                    # just above 172.16/12
    "http://192.169.0.1/v1",
    "http://11.0.0.1/v1",
    "http://[fec0::1]/v1",                     # deprecated site-local, outside fe80::/10
    "http://[fe00::1]/v1",                     # below fe80::/10
    "http://[2001:db8::1]/v1",
    "http://8.8.8.8/v1",
    "https://api.openai.com/v1",
    "https://openrouter.ai/api/v1",
    "file:///etc/passwd",
]


@pytest.mark.parametrize("url", LOOKS_ON_HOST_BUT_IS_NOT)
def test_lookalike_is_off_tier(monkeypatch, url):
    v = classify(on_host(monkeypatch), dest(url))
    assert v.in_tier is False, f"{url!r} classified on-host: {v}"


# Numeric/obfuscated forms that the OS resolver maps to loopback. The contract says "host is
# loopback"; we require the fail-closed answer (off-tier) because accepting them needs inet_aton
# semantics that differ across libc and HTTP clients. ADJUDICATE if W3 wants them in-tier.
OBFUSCATED_LOOPBACK = [
    "http://0x7f000001/v1",
    "http://2130706433/v1",
    "http://017700000001/v1",
    "http://127.1/v1",
    "http://0x7f.0.0.1/v1",
    "http://0.0.0.0:11434/v1",                 # unspecified, not loopback per ipaddress
]


@pytest.mark.parametrize("url", OBFUSCATED_LOOPBACK)
def test_obfuscated_loopback_fails_closed(monkeypatch, url):
    assert classify(on_host(monkeypatch), dest(url)).in_tier is False


GENUINELY_ON_HOST = [
    "http://127.0.0.1:11434/v1",
    "http://127.255.255.254/v1",
    "http://localhost:11434/v1",
    "http://localhost:11434/../",              # path traversal does not change the host
    "http://LOCALHOST:11434/v1",               # hostnames are case-insensitive
    "HTTP://127.0.0.1/v1",                     # scheme is case-insensitive
    "https://localhost/v1",
    "http://[::1]:8080/v1",
    "http://[::ffff:127.0.0.1]/v1",            # IPv4-mapped IPv6 loopback
]


@pytest.mark.parametrize("url", GENUINELY_ON_HOST)
def test_genuinely_on_host_is_in_tier(monkeypatch, url):
    v = classify(on_host(monkeypatch), dest(url))
    assert v.in_tier is True, f"{url!r} should be on-host per contract: {v}"


#: Amendment 9 (backlog D03): private, carrier-grade NAT, link-local and unique-local hosts can be another
#: machine, so they are off-tier unless the exact host is listed.
NEIGHBOUR_UNLESS_LISTED = [
    "http://10.0.0.1/v1",
    "http://10.255.255.255/v1",
    "http://172.16.0.1/v1",
    "http://172.31.255.255/v1",
    "http://192.168.1.1/v1",
    "http://192.168.1.1",
    "http://100.64.0.1/v1",
    "http://100.127.255.255/v1",
    "http://[fe80::1]/v1",
    "http://[fe80::1%25en0]:11434/v1",
    "http://[febf::1]/v1",
    "http://[fc00::1]/v1",
    "http://[fd12:3456::1]/v1",
    "http://[::ffff:10.0.0.1]/v1",
    "http://[::ffff:192.168.1.1]:8080/v1",
]


@pytest.mark.parametrize("url", NEIGHBOUR_UNLESS_LISTED)
def test_neighbour_ranges_are_off_tier_unless_listed(monkeypatch, url):
    v = classify(on_host(monkeypatch), dest(url))
    assert v.in_tier is False, f"{url!r} is a neighbour address, not this host: {v}"
    assert "confidential.on_host.extra_hosts" in v.reason and "range" in v.reason, v.reason


def test_scheme_missing_fails_closed(monkeypatch):
    # "192.168.1.1:8080/v1" has no authority per RFC 3986 (urlparse reads "192.168.1.1" as the
    # scheme). The contract says "base_url host"; with no host the only safe answer is off-tier.
    pred = on_host(monkeypatch)
    for url in ("192.168.1.1:8080/v1", "192.168.1.1/v1", "localhost:11434/v1", "evil.com/v1",
                "//evil.com/v1"):
        assert classify(pred, dest(url)).in_tier is False, url


# Amendment 2: fail closed on parser disagreement. urllib and httpx 0.28 read the first case as
# 127.0.0.1 while urllib3 (requests) reads evil.com; urllib silently strips TAB/CR/LF that httpx
# rejects. Any backslash, TAB, CR, LF or NUL anywhere in the URL is off_tier.
PARSER_DISAGREEMENT = [
    "http://evil.com\\@127.0.0.1/v1",
    "http://[::1]\\@evil.com/v1",            # urllib raises, httpx reads evil.com
    "http://127.0.0.1:11434\\@evil.com/v1",
    "http:\\\\evil.com\\@127.0.0.1/",
    "http://127.0.0.1\\v1",                  # backslash in the path of an on-host URL
    "http://evil.com\t@127.0.0.1/v1",
    "http://evil.com\n@127.0.0.1/v1",
    "http://evil.com\r@127.0.0.1/v1",
    "http://evil.com\x00@127.0.0.1/v1",
    "http://127.0.0.1/v1\t",                  # control char anywhere, even trailing
    "http://127.0.0.1/v1\x00",
    "http://local\nhost/v1",
]


@pytest.mark.parametrize("url", PARSER_DISAGREEMENT)
def test_parser_disagreement_is_off_tier(monkeypatch, url):
    assert classify(on_host(monkeypatch), dest(url)).in_tier is False, repr(url)


def test_encoded_backslash_userinfo_is_on_host_control(monkeypatch):
    # All parsers agree: %5C stays inside userinfo, host is 127.0.0.1.
    v = classify(on_host(monkeypatch), dest("http://evil.com%5C@127.0.0.1/v1"))
    assert v.in_tier is True and v.host == "127.0.0.1", v


def test_trailing_dot_localhost_does_not_widen(monkeypatch):
    # "localhost." is the FQDN of localhost; either verdict is defensible (ADJUDICATE), but it must
    # not crash and must not open "localhost.<anything>".
    pred = on_host(monkeypatch)
    classify(pred, dest("http://localhost.:11434/v1"))
    assert classify(pred, dest("http://localhost.evil.:11434/v1")).in_tier is False
    assert classify(pred, dest("http://localhost..evil.com/v1")).in_tier is False


def test_last_at_sign_wins(monkeypatch):
    # Both urllib and WHATWG take the host after the LAST '@': this one really is loopback, and the
    # reported host must be the loopback address, not the userinfo junk.
    v = classify(on_host(monkeypatch), dest("http://user:pw@evil.com@127.0.0.1/v1"))
    assert "evil" not in v.host


def test_unencoded_zone_id_does_not_crash(monkeypatch):
    classify(on_host(monkeypatch), dest("http://[fe80::1%en0]/v1"))


def test_ipv4_mapped_loopback_is_on_host_and_mapped_private_is_not(monkeypatch):
    # Amendment 1, narrowed by Amendment 9: IPv4-mapped loopback is on-host; mapped private is off-tier
    # unless listed, and a listed plain address also covers its mapped spelling.
    assert classify(on_host(monkeypatch), dest("http://[::ffff:127.0.0.1]/v1")).in_tier is True
    assert classify(on_host(monkeypatch), dest("http://[::ffff:7f00:1]/v1")).in_tier is True
    for url in ("http://[::ffff:10.0.0.1]/v1", "http://[::ffff:192.168.1.1]:8080/v1",
                "http://[::ffff:169.254.169.254]/v1"):
        assert classify(on_host(monkeypatch), dest(url)).in_tier is False, url
    assert classify(on_host(monkeypatch, extra_hosts=["10.0.0.1"]), dest("http://[::ffff:10.0.0.1]/v1")).in_tier is True
    # Not loopback, though they embed 127.0.0.1: IPv4-compatible, NAT64 and 6to4 spellings.
    for url in ("http://[::127.0.0.1]/v1", "http://[64:ff9b::7f00:1]/v1", "http://[2002:7f00:1::1]/v1"):
        assert classify(on_host(monkeypatch), dest(url)).in_tier is False, url


@pytest.mark.parametrize("url", [
    "http://[::1",                 # urlparse raises ValueError("Invalid IPv6 URL")
    "http://localhost:99999/v1",   # .port raises ValueError
    "http://localhost:abc/v1",
    "http://[not-an-ip]/v1",
    "http://",
    "://",
    " http://127.0.0.1/v1 ",
    "http://127.0.0.1\n.evil.com/v1",
    "\x00",
])
def test_malformed_urls_never_raise_and_never_in_tier_unless_parseable(monkeypatch, url):
    v = classify(on_host(monkeypatch), dest(url))
    if url.strip() != "http://127.0.0.1/v1":
        assert v.in_tier is False, f"malformed {url!r} classified in-tier: {v}"


# --------------------------------------------------------------------------- ON_HOST: empty base_url

def test_empty_base_url_without_profile_is_off(monkeypatch):
    v = classify(on_host(monkeypatch, profiles={}), dest("", provider="ollama"))
    assert v.in_tier is False


def test_empty_base_url_with_on_host_profile_is_in(monkeypatch):
    profiles = {"ollama": FakeProfile("ollama", "http://localhost:11434/v1")}
    v = classify(on_host(monkeypatch, profiles=profiles), dest("", provider="ollama"))
    assert v.in_tier is True, v


def test_empty_base_url_with_hosted_profile_is_off(monkeypatch):
    profiles = {"ollama": FakeProfile("ollama", "https://ollama.com/v1"),
                "openrouter": FakeProfile("openrouter", "https://openrouter.ai/api/v1")}
    pred = on_host(monkeypatch, profiles=profiles)
    assert classify(pred, dest("", provider="ollama")).in_tier is False
    assert classify(pred, dest("", provider="openrouter")).in_tier is False


def test_empty_base_url_with_lookalike_profile_is_off(monkeypatch):
    profiles = {"x": FakeProfile("x", "http://localhost.evil.com/v1"),
                "y": FakeProfile("y", ""), "z": FakeProfile("z", None)}
    pred = on_host(monkeypatch, profiles=profiles)
    for p in ("x", "y", "z"):
        assert classify(pred, dest("", provider=p)).in_tier is False, p


def test_explicit_base_url_wins_over_on_host_profile(monkeypatch):
    # An on-host profile must not launder an explicit hosted base_url.
    profiles = {"ollama": FakeProfile("ollama", "http://localhost:11434/v1")}
    v = classify(on_host(monkeypatch, profiles=profiles),
                 dest("https://evil.com/v1", provider="ollama"))
    assert v.in_tier is False


def test_provider_name_is_not_evidence(monkeypatch):
    pred = on_host(monkeypatch)
    for prov in ("local", "localhost", "ollama", "lmstudio", "llamacpp"):
        assert classify(pred, dest("https://api.evil.com/v1", provider=prov)).in_tier is False


def test_profile_lookup_that_raises_fails_closed(monkeypatch):
    def bad(*a, **k):
        raise RuntimeError("registry exploded")
    pred = OnHostPredicate(profile_base_url=bad)
    assert classify(pred, dest("", provider="ollama")).in_tier is False


# --------------------------------------------------------------------------- ON_HOST: extra_hosts

def test_extra_hosts_exact_match_only(monkeypatch):
    pred = on_host(monkeypatch, extra_hosts=["gpu-box.lan"])
    assert classify(pred, dest("http://gpu-box.lan:8000/v1")).in_tier is True
    for url in ("http://gpu-box.lan.evil.com/v1", "http://evil-gpu-box.lan/v1",
                "http://xgpu-box.lan/v1", "http://gpu-box.lan@evil.com/v1",
                "http://evil.com/gpu-box.lan", "http://evil.com#gpu-box.lan",
                "http://sub.gpu-box.lan.evil/v1"):
        assert classify(pred, dest(url)).in_tier is False, url


def test_extra_hosts_empty_string_does_not_match_everything(monkeypatch):
    pred = on_host(monkeypatch, extra_hosts=["", " ", "."])
    assert classify(pred, dest("https://evil.com/v1")).in_tier is False
    assert classify(pred, dest("")).in_tier is False


# --------------------------------------------------------------------------- ON_HOST: no secrets

def test_reason_and_host_never_carry_userinfo(monkeypatch):
    pred = on_host(monkeypatch)
    for url in ("http://alice:sk-PREDSECRET@evil.com/v1",
                "http://alice:sk-PREDSECRET@127.0.0.1:11434/v1",
                "http://sk-PREDSECRET@localhost/v1",
                "https://evil.com/v1?api_key=sk-PREDSECRET"):
        v = classify(pred, dest(url))
        assert "PREDSECRET" not in v.reason, (url, v.reason)
        assert "PREDSECRET" not in v.host, (url, v.host)
        assert "alice" not in v.host


def test_userinfo_does_not_change_host_classification(monkeypatch):
    pred = on_host(monkeypatch)
    assert classify(pred, dest("http://u:p@127.0.0.1:11434/v1")).in_tier is True
    v = classify(pred, dest("http://10.0.0.1@evil.com/v1"))
    assert v.in_tier is False
    assert v.host.lower() == "evil.com", f"watch view would show the wrong host: {v.host!r}"


def test_verdict_is_independent_of_purpose(monkeypatch):
    pred = on_host(monkeypatch)
    for purpose in ("main", "fallback", "aux:vision", "tool:web_search", "memory", "mcp:x"):
        assert classify(pred, dest("https://evil.com/v1", purpose=purpose)).in_tier is False
        assert classify(pred, dest("http://127.0.0.1/v1", purpose=purpose)).in_tier is True


def test_on_host_predicate_tier_attribute(monkeypatch):
    assert on_host(monkeypatch).tier == Tier.ON_HOST


# --------------------------------------------------------------------------- host_of

def test_host_of_basic_and_hostile():
    assert host_of("") == ""
    assert host_of("http://10.0.0.1@evil.com/v1").lower() == "evil.com"
    assert host_of("http://evil.com#127.0.0.1").lower() == "evil.com"
    assert host_of("http://alice:sk-HOSTSECRET@evil.com/v1").lower() == "evil.com"
    assert host_of("http://[::1]:8080/v1").strip("[]") == "::1"
    assert host_of("http://LOCALHOST/v1").lower() == "localhost"


@pytest.mark.parametrize("url", ["http://[::1", "http://localhost:99999", "://", "\x00", None])
def test_host_of_never_raises(url):
    try:
        h = host_of(url)
    except TypeError:
        if url is None:
            pytest.xfail("host_of(None) raising TypeError is acceptable if documented (ADJUDICATE)")
        raise
    assert isinstance(h, str)
    assert "SECRET" not in h


# --------------------------------------------------------------------------- ATTESTED

class AttestRecorder:
    def __init__(self, result=True, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def __call__(self, provider, *a, **k):
        self.calls.append(provider)
        if self.exc:
            raise self.exc
        return Verdict(in_tier=self.result, reason="fresh+pinned" if self.result else "stale",
                       host="inference.tinfoil.sh")


def attested(monkeypatch, ok, profiles):
    names = {n for n, p in profiles.items() if getattr(p, "attested", False)}
    return AttestedPredicate(attested_profiles=names, attested_ok=ok,
                             profile_base_url=_profile_url(profiles))


REGISTERED = {ATTESTED: FakeProfile(ATTESTED, "https://inference.tinfoil.sh/v1", attested=True)}


def adest(provider=ATTESTED, base_url="https://inference.tinfoil.sh/v1"):
    return dest(base_url, provider=provider)


def test_attested_positive_control(monkeypatch):
    ok = AttestRecorder(True)
    v = classify(attested(monkeypatch, ok, REGISTERED), adest())
    assert v.in_tier is True, f"positive control failed; wiring or predicate is wrong: {v}"
    assert ok.calls, "attested_ok was never consulted"


def test_attested_no_registered_profiles_is_off(monkeypatch):
    v = classify(attested(monkeypatch, AttestRecorder(True), {}), adest())
    assert v.in_tier is False


def test_attested_stale_or_pin_mismatch_is_off(monkeypatch):
    assert classify(attested(monkeypatch, AttestRecorder(False), REGISTERED), adest()).in_tier is False


def test_attested_ok_raising_never_yields_in_tier(monkeypatch):
    pred = attested(monkeypatch, AttestRecorder(exc=RuntimeError("verifier down")), REGISTERED)
    try:
        v = pred.classify(adest())
    except Exception:
        return  # raising is tolerable (W1 converts to refusal); in_tier is not
    assert v.in_tier is False


def test_attested_ok_returning_garbage_is_off(monkeypatch):
    for garbage in (None, "ok", 1, {"in_tier": True}):
        pred = attested(monkeypatch, lambda p, *a, _g=garbage, **k: _g, REGISTERED)
        try:
            v = pred.classify(adest())
        except Exception:
            continue
        assert v.in_tier is False, f"attested_ok returned {garbage!r} and predicate said in_tier"


def test_attested_other_registered_provider_is_off(monkeypatch):
    # attested_ok is permissive here on purpose: the predicate itself must require an *attested*
    # profile, not merely a registered one (ADJUDICATE: how does W3 know a profile is attested?).
    profiles = {**REGISTERED, "openrouter": FakeProfile("openrouter", "https://openrouter.ai/api/v1")}
    pred = attested(monkeypatch, AttestRecorder(True), profiles)
    # Case variants are NOT asserted: W3 lowercases provider names, as Hermes normalizes them.
    for prov in ("openrouter", "custom", "", "attested-tinfoil-evil", "attested_tinfoil",
                 "tinfoil"):
        assert classify(pred, adest(provider=prov)).in_tier is False, prov


def test_attested_on_host_url_does_not_qualify(monkeypatch):
    pred = attested(monkeypatch, AttestRecorder(True), REGISTERED)
    assert classify(pred, adest(provider="custom", base_url="http://127.0.0.1:11434/v1")).in_tier is False


def test_attested_provider_with_foreign_base_url_is_off(monkeypatch):
    # Amendment 1 (A9): a base_url host other than the attested endpoint is off_tier.
    pred = attested(monkeypatch, AttestRecorder(True), REGISTERED)
    for url in ("https://evil.com/v1", "https://inference.tinfoil.sh.evil.com/v1",
                "https://inference.tinfoil.sh@evil.com/v1", "http://127.0.0.1/v1",
                "https://inference.tinfoil.sh\\@evil.com/v1"):
        assert classify(pred, adest(base_url=url)).in_tier is False, url
    assert classify(pred, adest(base_url="")).in_tier is True, "empty base_url uses the profile"


def test_attested_predicate_tier_attribute(monkeypatch):
    assert attested(monkeypatch, AttestRecorder(True), REGISTERED).tier == Tier.ATTESTED


# --------------------------------------------------------------------------- ZDR

def test_zdr_stub_is_always_off(monkeypatch):
    pred = ZdrPredicate()
    assert pred.tier == Tier.ZDR
    for d in (dest("http://127.0.0.1/v1"), adest(), dest("", provider="openrouter")):
        v = classify(pred, d)
        assert v.in_tier is False
        assert "not implemented" in v.reason


# --------------------------------------------------------------------------- ON_HOST: Amendment 9 (D03)

def test_hostname_that_resolves_to_a_private_address_is_off_tier(no_dns, monkeypatch):
    # A name is never resolved to decide the tier (the no_dns fixture fails on any lookup), so a name an
    # attacker points at 10.0.0.5 stays off-tier even when 10.0.0.5 itself is listed.
    monkeypatch.setattr(tiers.socket, "gethostname", lambda: "this-box")
    pred = on_host(monkeypatch, extra_hosts=["10.0.0.5"])
    for url in ("http://model.internal.example/v1", "http://10.0.0.5.nip.io/v1", "http://ten-0-0-5.lan/v1"):
        v = classify(pred, dest(url))
        assert v.in_tier is False, url
        assert "confidential.on_host.extra_hosts" in v.reason


def test_own_hostname_resolving_to_a_private_address_is_off_tier(monkeypatch):
    tiers._OWN_HOSTNAME_CACHE.clear()
    monkeypatch.setattr(tiers.socket, "gethostname", lambda: "this-box")
    monkeypatch.setattr(tiers, "_resolve_all", lambda name: ["192.168.1.20"])
    assert classify(on_host(monkeypatch), dest("http://this-box:8000/v1")).in_tier is False
    monkeypatch.setattr(tiers, "_resolve_all", lambda name: ["127.0.0.1", "10.0.0.2"])
    tiers._OWN_HOSTNAME_CACHE.clear()
    assert classify(on_host(monkeypatch), dest("http://this-box:8000/v1")).in_tier is False


def test_own_hostname_resolver_that_hangs_fails_closed(monkeypatch):
    import threading
    tiers._OWN_HOSTNAME_CACHE.clear()
    gate = threading.Event()
    monkeypatch.setattr(tiers.socket, "gethostname", lambda: "this-box")
    monkeypatch.setattr(tiers, "_OWN_HOSTNAME_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(tiers, "_resolve_all", lambda name: (gate.wait(5), ["127.0.0.1"])[1])
    try:
        assert classify(on_host(monkeypatch), dest("http://this-box/v1")).in_tier is False
        assert tiers._OWN_HOSTNAME_CACHE["this-box"][0] is False   # the timeout is cached as off-tier
        calls = []
        monkeypatch.setattr(tiers, "_resolve_all", lambda name: calls.append(name) or ["127.0.0.1"])
        assert classify(on_host(monkeypatch), dest("http://this-box/v1")).in_tier is False
        assert calls == []                                          # no second lookup in this process
    finally:
        gate.set()


def test_own_hostname_true_is_rechecked_after_the_ttl(monkeypatch):
    tiers._OWN_HOSTNAME_CACHE.clear()
    clock = [1000.0]
    monkeypatch.setattr(tiers.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(tiers.socket, "gethostname", lambda: "this-box")
    answers = [["127.0.0.1"], ["192.168.1.9"]]
    calls = []
    monkeypatch.setattr(tiers, "_resolve_all", lambda name: calls.append(name) or answers[len(calls) - 1])
    assert classify(on_host(monkeypatch), dest("http://this-box/v1")).in_tier is True
    clock[0] += tiers._OWN_HOSTNAME_TTL_SECONDS - 1
    assert classify(on_host(monkeypatch), dest("http://this-box/v1")).in_tier is True
    assert len(calls) == 1
    clock[0] += 2                                                   # past the TTL: rechecked, now off-tier
    assert classify(on_host(monkeypatch), dest("http://this-box/v1")).in_tier is False
    assert len(calls) == 2


@pytest.mark.parametrize("url", [
    "http://127.0.0.1%25evil.com/v1", "http://127.0.0.1%25/v1", "http://127.0.0.1%25lo0/v1",
    "http://[::1%25evil.com]/v1", "http://[::1%25lo0]/v1", "http://[::ffff:127.0.0.1%25lo0]/v1",
    "http://[fe80::1%25evil.com:80]/v1", "http://[fe80::1%25a/b]/v1", "http://[fd00::1%25en0]/v1",
    "http://[fe80::1%25en0.evil.com]/v1",
])
def test_zone_id_only_on_ipv6_link_local(monkeypatch, url):
    v = classify(on_host(monkeypatch, extra_hosts=["fd00::1", "127.0.0.1"]), dest(url))
    assert v.in_tier is False, (url, v)


def test_listed_link_local_with_a_plain_zone_is_in_tier(monkeypatch):
    v = classify(on_host(monkeypatch, extra_hosts=["fe80::1%en0"]), dest("http://[fe80::1%25en0]:8000/v1"))
    assert v.in_tier is True and v.reason.startswith("listed on-host host"), v


def test_listed_host_reason_differs_from_loopback(monkeypatch):
    pred = on_host(monkeypatch, extra_hosts=["gpu.lan", "10.0.0.5"])
    assert classify(pred, dest("http://gpu.lan/v1")).reason.startswith("listed on-host host gpu.lan")
    assert classify(pred, dest("http://10.0.0.5/v1")).reason.startswith("listed on-host host 10.0.0.5")
    assert classify(pred, dest("http://127.0.0.1/v1")).reason.startswith("on-host endpoint 127.0.0.1")


@pytest.mark.parametrize("entry,word", [
    ("169.254.169.254", "metadata"), ("::ffff:169.254.169.254", "metadata"), ("0.0.0.0", "unspecified"),
    ("::", "unspecified"), ("224.0.0.1", "multicast"), ("239.255.255.250", "multicast"), ("ff02::1", "multicast"),
    ("255.255.255.255", "broadcast"), ("127.0.0.1%lo0", "zone"), ("fe80::1%en0.evil", "zone"),
    ("fd00:ec2::254", "fd00:ec2::254, the cloud metadata address"),
    ("[FD00:EC2:0::254]", "fd00:ec2::254, the cloud metadata address"),
])
def test_extra_hosts_refuses_addresses_that_are_not_one_host(monkeypatch, entry, word):
    assert word in tiers.extra_host_problem(entry)
    assert not classify(on_host(monkeypatch, extra_hosts=[entry]), dest("http://169.254.169.254/v1")).in_tier


@pytest.mark.parametrize("url", [
    "http://10.0.0.5/api.openai.com/v1",            # private IP host, public-looking name in the path
    "http://192.168.1.7/localhost/v1",
    "http://api.openai.com/10.0.0.5/v1",            # the reverse: public host, private IP in the path
    "http://api.openai.com/v1?host=127.0.0.1",
    "http://api.openai.com#@127.0.0.1",
])
def test_private_ip_and_public_name_in_the_path_is_off_tier(monkeypatch, url):
    v = classify(on_host(monkeypatch, extra_hosts=["api.openai.com.evil"]), dest(url))
    assert v.in_tier is False, (url, v)


def test_ipv4_mapped_ipv6_loopback_is_loopback(monkeypatch):
    for url in ("http://[::ffff:127.0.0.1]:11434/v1", "http://[::ffff:127.255.255.254]/v1",
                "http://[0:0:0:0:0:ffff:7f00:1]/v1"):
        v = classify(on_host(monkeypatch), dest(url))
        assert v.in_tier is True, (url, v)


@pytest.mark.parametrize("entry", ["10.0.0.0/8", "10.0.0.0/24", "192.168.1.0/255.255.255.0", "fd00::/8",
                                   "10.0.0.*", "*", "*.lan", "10.0.0.1-10.0.0.255", "10.0.0.1-255",
                                   "0.0.0.0/0", "::/0", "10/8", "localhost/8"])
def test_listed_range_entry_is_refused(monkeypatch, entry):
    pred = on_host(monkeypatch, extra_hosts=[entry])
    for url in ("http://10.0.0.1/v1", "http://10.0.0.9/v1", "http://192.168.1.5/v1", "http://[fd00::1]/v1",
                "http://gpu.lan/v1", "https://api.example.com/v1"):
        assert classify(pred, dest(url)).in_tier is False, (entry, url)
    assert tiers.extra_host_problem(entry) != ""


def test_a_bad_entry_does_not_disable_the_good_ones(monkeypatch):
    pred = on_host(monkeypatch, extra_hosts=["10.0.0.0/8", "gpu.lan"])
    assert classify(pred, dest("http://gpu.lan/v1")).in_tier is True
    assert classify(pred, dest("http://10.0.0.1/v1")).in_tier is False

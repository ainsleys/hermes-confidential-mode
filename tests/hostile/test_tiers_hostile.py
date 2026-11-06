"""Hostile tests for confidential_mode.tiers (W3 contract, docs/INTERFACES.md).

Written blind, against the contract only. Constructor signatures for the predicates are not
frozen, so `_build` wires fakes by parameter name and also patches module-level lookups; if it
cannot satisfy a required parameter the test FAILS with the signature, which is itself a finding
(the contract must say how extra_hosts / profile lookup / attested_ok reach the predicate).

Policy for ambiguous inputs: off-tier is the fail-closed direction, so for inputs the contract
does not explicitly bless we assert NOT in_tier. Cases where the contract literally implies a
riskier answer are marked xfail(strict=False) with an "ADJUDICATE" reason.
"""
from __future__ import annotations

import inspect
import socket

import pytest

from confidential_mode import tiers  # noqa: E402  (ImportError until W3 merges is expected)
from confidential_mode.tiers import Destination, Tier, Verdict  # noqa: E402

LocalPredicate = tiers.LocalPredicate
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


_ALIASES = {
    "extra_hosts": {"extra_hosts", "local_hosts", "hosts", "extra"},
    "profile_lookup": {"profile_lookup", "provider_lookup", "get_profile", "lookup",
                       "get_provider_profile", "profiles", "resolve_profile"},
    "attested_ok": {"attested_ok", "verifier", "check", "verify", "attest"},
    "config": {"config", "cfg", "settings"},
}


def _build(cls, monkeypatch, **wanted):
    """Instantiate a predicate, matching wanted fakes to parameter names; also patch module-level
    names the implementation might use instead of injection."""
    if "profile_lookup" in wanted:
        monkeypatch.setattr(tiers, "get_provider_profile", wanted["profile_lookup"], raising=False)
        try:
            import providers  # Hermes
            monkeypatch.setattr(providers, "get_provider_profile", wanted["profile_lookup"])
        except Exception:
            pass
    if "attested_ok" in wanted:
        monkeypatch.setattr(tiers, "attested_ok", wanted["attested_ok"], raising=False)
    extra = wanted.get("extra_hosts", ())
    wanted.setdefault("config", {"confidential": {"local": {"extra_hosts": list(extra)}}})
    try:
        sig = inspect.signature(cls)
    except (TypeError, ValueError):
        return cls()
    kwargs = {}
    for pname, p in sig.parameters.items():
        if p.kind in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
            continue
        for logical, names in _ALIASES.items():
            if pname in names and logical in wanted:
                kwargs[pname] = wanted[logical]
                break
        else:
            if p.default is p.empty:
                pytest.fail(f"cannot wire required parameter {pname!r} of {cls.__name__}{sig}; "
                            "contract does not name it (ADJUDICATE)")
    return cls(**kwargs)


def _lookup(table):
    return lambda name, *a, **k: table.get(name)


def local(monkeypatch, extra_hosts=(), profiles=None):
    return _build(LocalPredicate, monkeypatch, extra_hosts=tuple(extra_hosts),
                  profile_lookup=_lookup(profiles or {}))


def dest(base_url, provider="custom", purpose="main"):
    return Destination(provider=provider, base_url=base_url, model="m",
                       api_mode="chat_completions", purpose=purpose)


def classify(pred, d) -> Verdict:
    v = pred.classify(d)
    assert isinstance(v, Verdict), f"classify must return Verdict, got {type(v)}"
    assert isinstance(v.in_tier, bool)
    assert isinstance(v.reason, str) and v.reason, "reason must be a non-empty user-visible string"
    return v


# --------------------------------------------------------------------------- LOCAL: look-alikes

LOOKS_LOCAL_BUT_IS_NOT = [
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
    "http://evil.com\\@127.0.0.1/v1",          # urllib says 127.0.0.1, WHATWG/httpx say evil.com
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


@pytest.mark.parametrize("url", LOOKS_LOCAL_BUT_IS_NOT)
def test_lookalike_is_off_tier(monkeypatch, url):
    v = classify(local(monkeypatch), dest(url))
    assert v.in_tier is False, f"{url!r} classified local: {v}"


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
    assert classify(local(monkeypatch), dest(url)).in_tier is False


GENUINELY_LOCAL = [
    "http://127.0.0.1:11434/v1",
    "http://127.255.255.254/v1",
    "http://localhost:11434/v1",
    "http://localhost:11434/../",              # path traversal does not change the host
    "http://LOCALHOST:11434/v1",               # hostnames are case-insensitive
    "HTTP://127.0.0.1/v1",                     # scheme is case-insensitive
    "https://localhost/v1",
    "http://[::1]:8080/v1",
    "http://10.0.0.1/v1",
    "http://10.255.255.255/v1",
    "http://172.16.0.1/v1",
    "http://172.31.255.255/v1",
    "http://192.168.1.1/v1",
    "http://192.168.1.1",                      # scheme present, no path
    "http://100.64.0.1/v1",                    # CGNAT / tailscale
    "http://100.127.255.255/v1",
    "http://[fe80::1]/v1",
    "http://[fe80::1%25en0]:11434/v1",         # link-local with zone id (RFC 6874 encoding)
    "http://[febf::1]/v1",                     # top of fe80::/10
    "http://[fc00::1]/v1",
    "http://[fd12:3456::1]/v1",
]


@pytest.mark.parametrize("url", GENUINELY_LOCAL)
def test_genuinely_local_is_in_tier(monkeypatch, url):
    v = classify(local(monkeypatch), dest(url))
    assert v.in_tier is True, f"{url!r} should be local per contract: {v}"


def test_scheme_missing_fails_closed(monkeypatch):
    # "192.168.1.1:8080/v1" has no authority per RFC 3986 (urlparse reads "192.168.1.1" as the
    # scheme). The contract says "base_url host"; with no host the only safe answer is off-tier.
    pred = local(monkeypatch)
    for url in ("192.168.1.1:8080/v1", "192.168.1.1/v1", "localhost:11434/v1", "evil.com/v1",
                "//evil.com/v1"):
        assert classify(pred, dest(url)).in_tier is False, url


def test_trailing_dot_localhost_does_not_widen(monkeypatch):
    # "localhost." is the FQDN of localhost; either verdict is defensible (ADJUDICATE), but it must
    # not crash and must not open "localhost.<anything>".
    pred = local(monkeypatch)
    classify(pred, dest("http://localhost.:11434/v1"))
    assert classify(pred, dest("http://localhost.evil.:11434/v1")).in_tier is False
    assert classify(pred, dest("http://localhost..evil.com/v1")).in_tier is False


def test_last_at_sign_wins(monkeypatch):
    # Both urllib and WHATWG take the host after the LAST '@': this one really is loopback, and the
    # reported host must be the loopback address, not the userinfo junk.
    v = classify(local(monkeypatch), dest("http://user:pw@evil.com@127.0.0.1/v1"))
    assert "evil" not in v.host


def test_unencoded_zone_id_does_not_crash(monkeypatch):
    classify(local(monkeypatch), dest("http://[fe80::1%en0]/v1"))


def test_ipv4_mapped_loopback_does_not_crash(monkeypatch):
    # ::ffff:127.0.0.1 is loopback on Python >= 3.13 ipaddress; contract silent (ADJUDICATE).
    classify(local(monkeypatch), dest("http://[::ffff:127.0.0.1]/v1"))
    classify(local(monkeypatch), dest("http://[::ffff:10.0.0.1]/v1"))


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
    v = classify(local(monkeypatch), dest(url))
    if url.strip() != "http://127.0.0.1/v1":
        assert v.in_tier is False, f"malformed {url!r} classified in-tier: {v}"


# --------------------------------------------------------------------------- LOCAL: empty base_url

def test_empty_base_url_without_profile_is_off(monkeypatch):
    v = classify(local(monkeypatch, profiles={}), dest("", provider="ollama"))
    assert v.in_tier is False


def test_empty_base_url_with_local_profile_is_in(monkeypatch):
    profiles = {"ollama": FakeProfile("ollama", "http://localhost:11434/v1")}
    v = classify(local(monkeypatch, profiles=profiles), dest("", provider="ollama"))
    assert v.in_tier is True, v


def test_empty_base_url_with_hosted_profile_is_off(monkeypatch):
    profiles = {"ollama": FakeProfile("ollama", "https://ollama.com/v1"),
                "openrouter": FakeProfile("openrouter", "https://openrouter.ai/api/v1")}
    pred = local(monkeypatch, profiles=profiles)
    assert classify(pred, dest("", provider="ollama")).in_tier is False
    assert classify(pred, dest("", provider="openrouter")).in_tier is False


def test_empty_base_url_with_lookalike_profile_is_off(monkeypatch):
    profiles = {"x": FakeProfile("x", "http://localhost.evil.com/v1"),
                "y": FakeProfile("y", ""), "z": FakeProfile("z", None)}
    pred = local(monkeypatch, profiles=profiles)
    for p in ("x", "y", "z"):
        assert classify(pred, dest("", provider=p)).in_tier is False, p


def test_explicit_base_url_wins_over_local_profile(monkeypatch):
    # A local profile must not launder an explicit hosted base_url.
    profiles = {"ollama": FakeProfile("ollama", "http://localhost:11434/v1")}
    v = classify(local(monkeypatch, profiles=profiles),
                 dest("https://evil.com/v1", provider="ollama"))
    assert v.in_tier is False


def test_provider_name_is_not_evidence(monkeypatch):
    pred = local(monkeypatch)
    for prov in ("local", "localhost", "ollama", "lmstudio", "llamacpp"):
        assert classify(pred, dest("https://api.evil.com/v1", provider=prov)).in_tier is False


def test_profile_lookup_that_raises_fails_closed(monkeypatch):
    def bad(*a, **k):
        raise RuntimeError("registry exploded")
    pred = _build(LocalPredicate, monkeypatch, profile_lookup=bad)
    assert classify(pred, dest("", provider="ollama")).in_tier is False


# --------------------------------------------------------------------------- LOCAL: extra_hosts

def test_extra_hosts_exact_match_only(monkeypatch):
    pred = local(monkeypatch, extra_hosts=["gpu-box.lan"])
    assert classify(pred, dest("http://gpu-box.lan:8000/v1")).in_tier is True
    for url in ("http://gpu-box.lan.evil.com/v1", "http://evil-gpu-box.lan/v1",
                "http://xgpu-box.lan/v1", "http://gpu-box.lan@evil.com/v1",
                "http://evil.com/gpu-box.lan", "http://evil.com#gpu-box.lan",
                "http://sub.gpu-box.lan.evil/v1"):
        assert classify(pred, dest(url)).in_tier is False, url


def test_extra_hosts_empty_string_does_not_match_everything(monkeypatch):
    pred = local(monkeypatch, extra_hosts=["", " ", "."])
    assert classify(pred, dest("https://evil.com/v1")).in_tier is False
    assert classify(pred, dest("")).in_tier is False


# --------------------------------------------------------------------------- LOCAL: no secrets

def test_reason_and_host_never_carry_userinfo(monkeypatch):
    pred = local(monkeypatch)
    for url in ("http://alice:sk-PREDSECRET@evil.com/v1",
                "http://alice:sk-PREDSECRET@127.0.0.1:11434/v1",
                "http://sk-PREDSECRET@localhost/v1",
                "https://evil.com/v1?api_key=sk-PREDSECRET"):
        v = classify(pred, dest(url))
        assert "PREDSECRET" not in v.reason, (url, v.reason)
        assert "PREDSECRET" not in v.host, (url, v.host)
        assert "alice" not in v.host


def test_userinfo_does_not_change_host_classification(monkeypatch):
    pred = local(monkeypatch)
    assert classify(pred, dest("http://u:p@127.0.0.1:11434/v1")).in_tier is True
    v = classify(pred, dest("http://10.0.0.1@evil.com/v1"))
    assert v.in_tier is False
    assert v.host.lower() == "evil.com", f"watch view would show the wrong host: {v.host!r}"


def test_verdict_is_independent_of_purpose(monkeypatch):
    pred = local(monkeypatch)
    for purpose in ("main", "fallback", "aux:vision", "tool:web_search", "memory", "mcp:x"):
        assert classify(pred, dest("https://evil.com/v1", purpose=purpose)).in_tier is False
        assert classify(pred, dest("http://127.0.0.1/v1", purpose=purpose)).in_tier is True


def test_local_predicate_tier_attribute(monkeypatch):
    assert local(monkeypatch).tier == Tier.LOCAL


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
    return _build(AttestedPredicate, monkeypatch, attested_ok=ok, profile_lookup=_lookup(profiles))


REGISTERED = {ATTESTED: FakeProfile(ATTESTED, "https://inference.tinfoil.sh/v1", attested=True)}


def adest(provider=ATTESTED, base_url="https://inference.tinfoil.sh/v1"):
    return dest(base_url, provider=provider)


def test_attested_positive_control(monkeypatch):
    ok = AttestRecorder(True)
    v = classify(attested(monkeypatch, ok, REGISTERED), adest())
    assert v.in_tier is True, f"positive control failed; wiring or predicate is wrong: {v}"
    assert ok.calls, "attested_ok was never consulted"


def test_attested_profile_lookup_none_is_off(monkeypatch):
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
    for prov in ("openrouter", "custom", "", "attested-tinfoil-evil", "Attested-Tinfoil",
                 " attested-tinfoil"):
        assert classify(pred, adest(provider=prov)).in_tier is False, prov


def test_attested_local_url_does_not_qualify(monkeypatch):
    pred = attested(monkeypatch, AttestRecorder(True), REGISTERED)
    assert classify(pred, adest(provider="custom", base_url="http://127.0.0.1:11434/v1")).in_tier is False


@pytest.mark.xfail(strict=False, reason="ADJUDICATE: contract decides ATTESTED by provider only; an "
                   "attested provider with a foreign base_url override arguably must be off-tier")
def test_attested_provider_with_foreign_base_url_is_off(monkeypatch):
    pred = attested(monkeypatch, AttestRecorder(True), REGISTERED)
    assert classify(pred, adest(base_url="https://evil.com/v1")).in_tier is False


def test_attested_predicate_tier_attribute(monkeypatch):
    assert attested(monkeypatch, AttestRecorder(True), REGISTERED).tier == Tier.ATTESTED


# --------------------------------------------------------------------------- ZDR

def test_zdr_stub_is_always_off(monkeypatch):
    pred = _build(ZdrPredicate, monkeypatch)
    assert pred.tier == Tier.ZDR
    for d in (dest("http://127.0.0.1/v1"), adest(), dest("", provider="openrouter")):
        v = classify(pred, d)
        assert v.in_tier is False
        assert "not implemented" in v.reason

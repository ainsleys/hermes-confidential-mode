"""W3: tier predicates and host parsing. Pure logic; no network, no DNS."""
import socket

import pytest

from confidential_mode.tiers import (
    AttestedPredicate, Destination, LocalPredicate, Tier, Verdict, ZdrPredicate, host_of, is_local_host,
)


def dest(base_url="", provider="custom", purpose="main"):
    return Destination(provider=provider, base_url=base_url, model="m", api_mode="chat_completions", purpose=purpose)


@pytest.mark.parametrize("url,host", [
    ("http://127.0.0.1:8080/v1", "127.0.0.1"),
    ("https://LOCALHOST/v1", "localhost"),
    ("localhost", "localhost"),
    ("localhost:11434", "localhost"),
    ("10.0.0.2:8080/v1", "10.0.0.2"),
    ("http://[::1]:11434/v1", "::1"),
    ("[::1]", "::1"),
    ("::1", "::1"),
    ("fe80::1", "fe80::1"),
    ("http://[fe80::1%25en0]:80/", "fe80::1%25en0"),
    ("https://user:pw@Example.COM./x?k=v", "example.com"),
    ("  http://192.168.1.5  ", "192.168.1.5"),
    ("", ""),
    ("http://", ""),
    ("http://[::1", ""),  # unbalanced bracket: unparsable
    ("http://evil.com\\@127.0.0.1/v1", "evil.com"),  # backslash read as a path separator, as httpx does
    ("\x00", ""),
    (None, ""),
])
def test_host_of(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.255.255.254", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1",
    "100.64.0.1", "100.127.255.255", "fe80::1", "febf::1", "fe80::1%en0", "fc00::1", "fd12:3456::1",
    "localhost", "::ffff:10.0.0.1",
])
def test_local_hosts(host):
    assert is_local_host(host)


@pytest.mark.parametrize("host", [
    "8.8.8.8", "172.32.0.1", "172.15.255.255", "100.128.0.1", "100.63.255.255", "192.169.0.1", "11.0.0.1",
    "2001:4860::8888", "fec0::1", "fe00::1", "0.0.0.0", "::", "::ffff:8.8.8.8", "example.com",
    "localhost.evil.com", "my-nas.local", "",
])
def test_remote_hosts(host):
    assert not is_local_host(host)


def test_extra_hosts_case_and_brackets():
    assert is_local_host("my-nas.lan", ["My-NAS.lan"])
    p = LocalPredicate(extra_hosts={"My-NAS.lan", "[fd00::5]"})
    assert p.classify(dest("http://my-nas.lan:1234/v1")).in_tier
    assert not p.classify(dest("http://other.lan/v1")).in_tier


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/v1", "http://[::1]:11434", "http://localhost:1234", "https://10.0.0.5/v1",
    "http://100.100.1.1/v1", "http://[fd00::1]/v1", "http://[fe80::1%25en0]:8000/v1", "HTTP://192.168.1.9",
    "http://user:pw@evil.com@127.0.0.1/v1", "http://[::ffff:10.0.0.1]/v1",
])
def test_local_predicate_in_tier(url):
    v = LocalPredicate().classify(dest(url))
    assert v.in_tier and v.host and v.reason


@pytest.mark.parametrize("url,reason_part", [
    ("https://api.openai.com/v1", "not an IP literal"),
    ("http://8.8.8.8/v1", "not on a local network"),
    ("http://[2001:db8::1]/v1", "not on a local network"),
    ("http://", "no host"),
    ("http://evil.com\\@127.0.0.1/v1", "backslash"),
    ("http://127.0.0.1\\/v1", "backslash"),
    ("localhost:11434/v1", "http:// or https://"),
    ("192.168.1.9", "http:// or https://"),
    ("//127.0.0.1/v1", "http:// or https://"),
    ("ftp://127.0.0.1/", "http:// or https://"),
    ("file:///etc/passwd", "http:// or https://"),
    ("http://localhost:99999/v1", "malformed"),
    ("http://localhost:abc/v1", "malformed"),
    ("http://[::1/v1", "malformed"),
    ("http://localhost%2eevil.com/v1", "percent-encoded"),
    ("http://127.0.0.1\n.evil.com/v1", "control"),
    ("http://127.0.0.1 /v1", "control"),
    ("\x00", "control"),
    ("http://l\u043ecalhost/v1", "non-ASCII"),
    ("http://xn--lcalhost-9vf/v1", "not an IP literal"),
    ("http://0x7f000001/v1", "not an IP literal"),
    ("http://2130706433/v1", "not an IP literal"),
    ("http://127.1/v1", "not an IP literal"),
    ("http://0.0.0.0/v1", "not on a local network"),
    ("http://169.254.169.254/latest", "not on a local network"),
    ("http://[::ffff:8.8.8.8]/v1", "not on a local network"),
])
def test_local_predicate_off_tier(url, reason_part):
    v = LocalPredicate().classify(dest(url))
    assert not v.in_tier and reason_part in v.reason


def test_local_predicate_never_resolves_dns(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("DNS lookup attempted")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    v = LocalPredicate().classify(dest("http://resolves-to-localhost.example/v1"))
    assert not v.in_tier and v.host == "resolves-to-localhost.example"


def test_local_predicate_empty_base_url_uses_profile():
    urls = {"ollama": "http://127.0.0.1:11434/v1", "openrouter": "https://openrouter.ai/api/v1"}
    p = LocalPredicate(profile_base_url=lambda prov: urls.get(prov, ""))
    v = p.classify(dest("", provider="ollama"))
    assert v.in_tier and v.host == "127.0.0.1" and "provider default" in v.reason
    assert not p.classify(dest("", provider="openrouter")).in_tier
    assert not p.classify(dest("", provider="unknown")).in_tier


def test_local_predicate_empty_base_url_without_profile_callable_is_off_tier():
    v = LocalPredicate().classify(dest("", provider="ollama"))
    assert not v.in_tier and v.host == ""


def test_local_predicate_profile_callable_raising_is_off_tier():
    def boom(_):
        raise RuntimeError("x")
    assert not LocalPredicate(profile_base_url=boom).classify(dest("", provider="ollama")).in_tier


def test_local_predicate_explicit_base_url_beats_profile():
    p = LocalPredicate(profile_base_url=lambda _: "http://127.0.0.1/v1")
    assert not p.classify(dest("https://api.example.com", provider="ollama")).in_tier


def test_attested_predicate_branches():
    calls = []

    def ok(provider):
        calls.append(provider)
        return Verdict(True, "fresh, pins match", "enclave.tinfoil.sh")

    p = AttestedPredicate({"attested-tinfoil"}, ok)
    assert p.tier == Tier.ATTESTED
    v = p.classify(dest("https://enclave.tinfoil.sh/v1", provider="attested-tinfoil"))
    assert v.in_tier and v.host == "enclave.tinfoil.sh" and calls == ["attested-tinfoil"]

    v = p.classify(dest("https://openrouter.ai/api/v1", provider="openrouter"))
    assert not v.in_tier and "not an attested profile" in v.reason and calls == ["attested-tinfoil"]

    bad = AttestedPredicate({"attested-tinfoil"}, lambda _: Verdict(False, "enclave build changed", ""))
    v = bad.classify(dest("", provider="attested-tinfoil"))
    assert not v.in_tier and v.reason == "enclave build changed"

    def boom(_):
        raise RuntimeError("verifier exploded with secret sk-123")
    v = AttestedPredicate({"attested-tinfoil"}, boom).classify(dest("", provider="attested-tinfoil"))
    assert not v.in_tier and "sk-123" not in v.reason

    v = AttestedPredicate({"attested-tinfoil"}, lambda _: None).classify(dest("", provider="attested-tinfoil"))
    assert not v.in_tier


def test_attested_predicate_base_url_override_must_match_profile():
    p = AttestedPredicate({"attested-tinfoil"}, lambda _: Verdict(True, "ok", ""),
                          profile_base_url=lambda _: "https://enclave.tinfoil.sh/v1")
    assert p.classify(dest("https://enclave.tinfoil.sh:443/v1", provider="attested-tinfoil")).in_tier
    assert p.classify(dest("", provider="attested-tinfoil")).in_tier
    v = p.classify(dest("https://evil.example/v1", provider="attested-tinfoil"))
    assert not v.in_tier and "not the attested endpoint" in v.reason


def test_zdr_stub_always_off_tier():
    p = ZdrPredicate()
    assert p.tier == Tier.ZDR
    v = p.classify(dest("http://127.0.0.1/v1"))
    assert not v.in_tier and v.reason == "zero-retention tier not implemented" and v.host == "127.0.0.1"


def test_profile_lookup_may_return_profile_objects():
    class P:
        def __init__(self, url):
            self.base_url = url
    table = {"ollama": P("http://localhost:11434/v1"), "hosted": P("https://x.example/v1"), "none": P(None)}
    p = LocalPredicate(profile_base_url=table.get)
    assert p.classify(dest("", provider="ollama")).in_tier
    assert not p.classify(dest("", provider="hosted")).in_tier
    assert not p.classify(dest("", provider="none")).in_tier
    assert not p.classify(dest("", provider="missing")).in_tier


def test_profile_base_url_is_held_to_the_strict_parser():
    p = LocalPredicate(profile_base_url=lambda _: "localhost:11434/v1")  # schemeless default
    assert not p.classify(dest("", provider="x")).in_tier


def test_attested_provider_match_is_exact():
    p = AttestedPredicate({"attested-tinfoil"}, lambda _: Verdict(True, "ok", ""))
    for prov in ("Attested-Tinfoil", " attested-tinfoil", "attested-tinfoil-evil", ""):
        assert not p.classify(dest("", provider=prov)).in_tier, prov


def test_attested_rejects_malformed_base_url():
    p = AttestedPredicate({"attested-tinfoil"}, lambda _: Verdict(True, "ok", ""))
    assert not p.classify(dest("https://inference.tinfoil.sh\\@evil/v1", provider="attested-tinfoil")).in_tier

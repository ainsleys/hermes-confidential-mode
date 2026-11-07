"""W3: tier predicates and host parsing. Pure logic; no network, no DNS."""
import socket

import pytest

from confidential_mode.tiers import (
    AttestedPredicate, Destination, OnHostPredicate, Tier, Verdict, ZdrPredicate, host_of, is_on_host,
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
    "127.0.0.1", "127.255.255.254", "::1", "localhost", "::ffff:127.0.0.1", "::ffff:7f00:1",
])
def test_on_host_addresses(host):
    assert is_on_host(host)


# Amendment 10 (backlog D03): each neighbour range is off-tier unless the exact host is listed.
NEIGHBOURS = [
    ("10.1.2.3", "10.0.0.0/8"), ("172.16.0.1", "172.16.0.0/12"), ("172.31.255.255", "172.16.0.0/12"),
    ("192.168.0.1", "192.168.0.0/16"), ("100.64.0.1", "100.64.0.0/10"), ("100.127.255.255", "100.64.0.0/10"),
    ("fe80::1", "fe80::/10"), ("febf::1", "fe80::/10"), ("fc00::1", "fc00::/7"), ("fd00::1", "fc00::/7"),
    ("fd12:3456::1", "fc00::/7"), ("::ffff:10.0.0.1", "10.0.0.0/8"),
]


@pytest.mark.parametrize("host,rng", NEIGHBOURS)
def test_neighbour_ranges_off_unless_listed(host, rng):
    assert not is_on_host(host)
    assert is_on_host(host, [host])
    url_host = f"[{host}]" if ":" in host else host
    v = OnHostPredicate().classify(dest(f"http://{url_host}:8000/v1"))
    assert not v.in_tier
    assert rng in v.reason and "confidential.on_host.extra_hosts" in v.reason, v.reason
    assert OnHostPredicate(extra_hosts=[host]).classify(dest(f"http://{url_host}:8000/v1")).in_tier


def test_listing_one_neighbour_does_not_admit_its_range():
    p = OnHostPredicate(extra_hosts=["10.0.0.5", "fd00::5"])
    assert p.classify(dest("http://10.0.0.5/v1")).in_tier
    assert p.classify(dest("http://[fd00:0::5]/v1")).in_tier            # another spelling of the listed address
    for url in ("http://10.0.0.6/v1", "http://10.0.0.50/v1", "http://[fd00::6]/v1", "http://192.168.0.5/v1"):
        assert not p.classify(dest(url)).in_tier, url


def test_listed_host_name_is_in_tier():
    p = OnHostPredicate(extra_hosts=["gpu-box.lan"])
    assert p.classify(dest("http://gpu-box.lan:8000/v1")).in_tier
    assert not OnHostPredicate().classify(dest("http://gpu-box.lan:8000/v1")).in_tier


@pytest.mark.parametrize("entry", [
    "10.0.0.0/8", "192.168.1.0/24", "fd00::/8", "10.0.0.*", "*.lan", "gpu-?.lan", "10.0.0.1-10.0.0.9",
    "10.0.0.1-9", "127.1", "0x7f000001", "http://gpu-box.lan", "gpu-box.lan:8000", "gpu box.lan",
    "gpu-box.lan/v1", "", " ", ".", "-bad.lan", "l\u043ecalhost", 5, None, ["10.0.0.1"],
])
def test_extra_host_entry_must_be_one_exact_host(entry):
    from confidential_mode.tiers import extra_host_problem
    assert extra_host_problem(entry) != ""
    assert not OnHostPredicate(extra_hosts=[entry]).classify(dest("http://10.0.0.1/v1")).in_tier


@pytest.mark.parametrize("entry", ["gpu-box.lan", "GPU-Box.LAN.", "[fd00::5]", "10.0.0.5", "fe80::1%en0",
                                   "my_host", "nas"])
def test_extra_host_exact_entries_are_valid(entry):
    from confidential_mode.tiers import extra_host_problem
    assert extra_host_problem(entry) == ""


def test_extra_hosts_as_a_bare_string_lists_nothing():
    assert not OnHostPredicate(extra_hosts="10.0.0.1").classify(dest("http://10.0.0.1/v1")).in_tier


@pytest.mark.parametrize("host", [
    "8.8.8.8", "172.32.0.1", "172.15.255.255", "100.128.0.1", "100.63.255.255", "192.169.0.1", "11.0.0.1",
    "2001:4860::8888", "fec0::1", "fe00::1", "0.0.0.0", "::", "::ffff:8.8.8.8", "example.com",
    "localhost.evil.com", "my-nas.local", "", "10.1.2.3", "192.168.0.1", "fd12:3456::1", "fe80::1%en0",
])
def test_remote_hosts(host):
    assert not is_on_host(host)


def test_extra_hosts_case_and_brackets():
    assert is_on_host("my-nas.lan", ["My-NAS.lan"])
    p = OnHostPredicate(extra_hosts={"My-NAS.lan", "[fd00::5]"})
    assert p.classify(dest("http://my-nas.lan:1234/v1")).in_tier
    assert not p.classify(dest("http://other.lan/v1")).in_tier


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/v1", "http://[::1]:11434", "http://localhost:1234", "HTTP://127.0.0.9",
    "http://user:pw@evil.com@127.0.0.1/v1", "http://[::ffff:127.0.0.1]/v1",
])
def test_on_host_predicate_in_tier(url):
    v = OnHostPredicate().classify(dest(url))
    assert v.in_tier and v.host and v.reason


@pytest.mark.parametrize("url,reason_part", [
    ("https://api.openai.com/v1", "not an IP literal"),
    ("http://8.8.8.8/v1", "not loopback on this host"),
    ("http://[2001:db8::1]/v1", "not loopback on this host"),
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
    ("http://127.0.0.1/v1\t", "control"),
    ("http://127.0.0.1/v1\n", "control"),
    (" http://127.0.0.1/v1", "control"),
    ("http://127.0.0.1/v1 ", "control"),
    ("\x00", "control"),
    ("http://l\u043ecalhost/v1", "non-ASCII"),
    ("http://xn--lcalhost-9vf/v1", "not an IP literal"),
    ("http://0x7f000001/v1", "not an IP literal"),
    ("http://2130706433/v1", "not an IP literal"),
    ("http://127.1/v1", "not an IP literal"),
    ("http://0.0.0.0/v1", "not loopback on this host"),
    ("http://169.254.169.254/latest", "169.254.0.0/16"),
    ("http://[::ffff:8.8.8.8]/v1", "not loopback on this host"),
    ("https://10.0.0.5/v1", "private range 10.0.0.0/8"),
    ("http://100.100.1.1/v1", "carrier-grade NAT range 100.64.0.0/10"),
    ("http://[fe80::1%25en0]:8000/v1", "IPv6 link-local range fe80::/10"),
    ("http://[fd00::1]/v1", "IPv6 unique-local range fc00::/7"),
])
def test_on_host_predicate_off_tier(url, reason_part):
    v = OnHostPredicate().classify(dest(url))
    assert not v.in_tier and reason_part in v.reason


def test_on_host_predicate_never_resolves_dns(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("DNS lookup attempted")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    v = OnHostPredicate().classify(dest("http://resolves-to-localhost.example/v1"))
    assert not v.in_tier and v.host == "resolves-to-localhost.example"


def test_on_host_predicate_empty_base_url_uses_profile():
    urls = {"ollama": "http://127.0.0.1:11434/v1", "openrouter": "https://openrouter.ai/api/v1"}
    p = OnHostPredicate(profile_base_url=lambda prov: urls.get(prov, ""))
    v = p.classify(dest("", provider="ollama"))
    assert v.in_tier and v.host == "127.0.0.1" and "provider default" in v.reason
    assert not p.classify(dest("", provider="openrouter")).in_tier
    assert not p.classify(dest("", provider="unknown")).in_tier


def test_on_host_predicate_empty_base_url_without_profile_callable_is_off_tier():
    v = OnHostPredicate().classify(dest("", provider="ollama"))
    assert not v.in_tier and v.host == ""


def test_on_host_predicate_profile_callable_raising_is_off_tier():
    def boom(_):
        raise RuntimeError("x")
    assert not OnHostPredicate(profile_base_url=boom).classify(dest("", provider="ollama")).in_tier


def test_on_host_predicate_explicit_base_url_beats_profile():
    p = OnHostPredicate(profile_base_url=lambda _: "http://127.0.0.1/v1")
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
    p = OnHostPredicate(profile_base_url=table.get)
    assert p.classify(dest("", provider="ollama")).in_tier
    assert not p.classify(dest("", provider="hosted")).in_tier
    assert not p.classify(dest("", provider="none")).in_tier
    assert not p.classify(dest("", provider="missing")).in_tier


def test_profile_base_url_is_held_to_the_strict_parser():
    p = OnHostPredicate(profile_base_url=lambda _: "localhost:11434/v1")  # schemeless default
    assert not p.classify(dest("", provider="x")).in_tier


def test_attested_provider_match_is_exact():
    p = AttestedPredicate({"attested-tinfoil"}, lambda _: Verdict(True, "ok", ""))
    for prov in ("Attested-Tinfoil", " attested-tinfoil", "attested-tinfoil-evil", ""):
        assert not p.classify(dest("", provider=prov)).in_tier, prov


def test_attested_rejects_malformed_base_url():
    p = AttestedPredicate({"attested-tinfoil"}, lambda _: Verdict(True, "ok", ""))
    assert not p.classify(dest("https://inference.tinfoil.sh\\@evil/v1", provider="attested-tinfoil")).in_tier


# ---- the machine's own host name (Amendment 10) -----------------------------------------------------

def _own(monkeypatch, name, answer):
    import confidential_mode.tiers as t
    t._OWN_HOSTNAME_CACHE.clear()
    monkeypatch.setattr(t.socket, "gethostname", lambda: name)
    calls = []

    def resolve(n):
        calls.append(n)
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(t, "_resolve_all", resolve)
    return calls


def test_own_host_name_resolving_to_loopback_is_in_tier(monkeypatch):
    calls = _own(monkeypatch, "MyBox.", ["127.0.1.1", "::1"])
    v = OnHostPredicate().classify(dest("http://mybox:8080/v1"))
    assert v.in_tier and "host name" in v.reason
    assert OnHostPredicate().classify(dest("http://mybox:8080/v1")).in_tier
    assert calls == ["mybox"]                          # resolved once per process, then cached


@pytest.mark.parametrize("answer", [["10.0.0.7"], ["127.0.0.1", "192.168.1.3"], [], OSError("no such host"),
                                    ["not-an-ip"]])
def test_own_host_name_not_only_loopback_is_off_tier(monkeypatch, answer):
    _own(monkeypatch, "mybox", answer)
    v = OnHostPredicate().classify(dest("http://mybox:8080/v1"))
    assert not v.in_tier and "confidential.on_host.extra_hosts" in v.reason


def test_only_the_own_host_name_is_ever_resolved(monkeypatch):
    calls = _own(monkeypatch, "mybox", ["127.0.0.1"])
    for url in ("http://mybox.evil.com/v1", "http://evil-mybox/v1", "http://other/v1", "http://evil.com/mybox"):
        assert not OnHostPredicate().classify(dest(url)).in_tier, url
    assert calls == []

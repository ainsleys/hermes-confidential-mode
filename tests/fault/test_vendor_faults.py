"""Fault class 3, the vendor and the network: an attestation endpoint that errors, times out, truncates, drops
fields, sends an unparseable quote or a stale nonce; an expired or not-yet-valid ITA token and a JWKS fetch
that fails; an inference reply cut mid-body or in an encoding nobody asked for; a signature endpoint that
errors or stalls; the certificate changing under the pinned pool (a DNS move); the model key rotating
mid-session; the host clock jumping by hours against the TTL, the ITA token and the receipt window.

The vendor is tests/near_world.py (real signatures, keys, JWTs and E2EE; only the TDX quote is a test quote)
behind httpx.MockTransport; each fault bends one response. The adapter, the verification cache, the ledger
and the receipt are the real ones.
"""
from __future__ import annotations

import json
import time

import httpx
import openai
import pytest

from confidential_mode import provider as provider_mod
from confidential_mode.ledger import Ledger
from confidential_mode.pins import PinStore
from confidential_mode.receipts import _send_coverage
from confidential_mode.verify.base import VerifyError

from ..near_world import BASE, HOST, JWKS_URL, MODEL, NOW, NearWorld, tls_cert

MSG = [{"role": "user", "content": "PLAINTEXT-SECRET-PROMPT"}]
NP = provider_mod.NEAR_PROFILE_NAME


def _cause(exc_info) -> BaseException:
    e = exc_info.value
    return e.__cause__ if isinstance(e, openai.APIConnectionError) and e.__cause__ is not None else e


def _bend(world, match, respond):
    """world.handler answers ``respond(request, orig)`` for requests where ``match(request)``."""
    orig = world.handler

    def handler(req):
        if match(req):
            world.requests.append((req.method, req.url.path, str(req.url.query)))
            return respond(req, orig)
        return orig(req)
    world.handler = handler


def _path(p):
    return lambda r: r.url.path == p and r.url.host == HOST


def _report_only(model=None):
    return lambda r: r.url.path == "/v1/attestation/report" and (("model=" in str(r.url.query)) == bool(model))


def _no_send_possible(world, ad):
    """After a failed verify, the adapter hands out no send view (or the view refuses the send), and nothing
    reaches the chat endpoint."""
    try:
        view = ad.sync_http_view()
    except VerifyError as exc:
        assert "before a successful verify" in str(exc)
    else:
        client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=view, max_retries=0)
        with pytest.raises(Exception) as ei:
            client.chat.completions.create(model=MODEL, messages=MSG)
        assert isinstance(_cause(ei), VerifyError), repr(ei.value)
    assert world.chat_posts() == 0 and world.chat_bodies == []


def _truncated(req, orig):
    r = orig(req)
    body = r.read()
    return httpx.Response(200, content=body[: len(body) // 2], headers={"content-type": "application/json"})


ATTESTATION_FAULTS = {
    "report_http_500": (_report_only(), lambda r, o: httpx.Response(500, json={"error": {"message": "boom"}})),
    "report_http_429": (_report_only(), lambda r, o: httpx.Response(429, headers={"retry-after": "30"},
                                                                    json={"error": {"message": "slow down"}})),
    "report_timeout": (_report_only(), lambda r, o: (_ for _ in ()).throw(httpx.ReadTimeout("timed out", request=r))),
    "report_reset": (_report_only(), lambda r, o: (_ for _ in ()).throw(httpx.RemoteProtocolError("reset", request=r))),
    "report_truncated": (_report_only(), _truncated),
    "report_not_json": (_report_only(), lambda r, o: httpx.Response(200, content=b"<html>gateway error</html>")),
    "report_missing_fields": (_report_only(), lambda r, o: httpx.Response(200, json={"gateway_attestation": {}})),
    "report_wrong_type": (_report_only(), lambda r, o: httpx.Response(200, json=["not", "a", "report"])),
    "model_report_500": (_report_only(MODEL), lambda r, o: httpx.Response(500, json={"error": {"message": "boom"}})),
    "model_report_truncated": (_report_only(MODEL), _truncated),
    "ita_http_503": (_path("/v1/attestation/ita-token"), lambda r, o: httpx.Response(503, json={})),
    "ita_truncated": (_path("/v1/attestation/ita-token"), _truncated),
    "ita_missing_token": (_path("/v1/attestation/ita-token"), lambda r, o: httpx.Response(200, json={"models": []})),
    "jwks_http_500": (lambda r: str(r.url).startswith(JWKS_URL), lambda r, o: httpx.Response(500, json={})),
    "jwks_timeout": (lambda r: str(r.url).startswith(JWKS_URL),
                     lambda r, o: (_ for _ in ()).throw(httpx.ConnectTimeout("timed out", request=r))),
    "jwks_empty": (lambda r: str(r.url).startswith(JWKS_URL), lambda r, o: httpx.Response(200, json={"keys": []})),
}


@pytest.mark.parametrize("fault", sorted(ATTESTATION_FAULTS))
def test_an_attestation_fetch_fault_fails_the_verify_and_nothing_can_be_sent(tmp_path, fault):
    """VendorAdapter.verify "raises VerifyError on any failure; never returns partial"; Amendment 6 finding 25:
    "every Tinfoil and NEAR view refuses to send while the adapter has no accepted verification"."""
    world = NearWorld()
    match, respond = ATTESTATION_FAULTS[fault]
    _bend(world, match, respond)
    ad = world.adapter(tmp_path)
    with pytest.raises(VerifyError):
        ad.verify()
    assert ad.last_result is None
    _no_send_possible(world, ad)


@pytest.mark.parametrize("bend", ["quote_not_hex", "quote_bad_signature", "stale_nonce", "report_data_other_key"])
def test_a_bent_gateway_report_fails_the_verify(tmp_path, bend):
    """Amendment 5: the gateway "quote verifies"; "report data = SHA-256(signing key || raw TLS SPKI fingerprint)
    || N" for the verify's own nonce N. A quote that does not parse, does not verify, or answers another nonce
    fails the verify."""
    world = NearWorld()
    if bend == "quote_not_hex":
        world.gateway_overrides["intel_quote"] = "zz" * 40
    elif bend == "quote_bad_signature":
        world.gateway_overrides["intel_quote"] = (b"FAKEQUOTE" + json.dumps({"bad_signature": True}).encode()).hex()
    elif bend == "stale_nonce":
        orig_report = world.gateway_report
        world.gateway_report = lambda nonce: orig_report("00" * 32)
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        world.gateway_key = Ed25519PrivateKey.generate()
        orig_report = world.gateway_report
        stale = orig_report("11" * 32)["gateway_attestation"]

        def report(nonce):
            rep = orig_report(nonce)
            rep["gateway_attestation"]["report_data"] = stale["report_data"]
            return rep
        world.gateway_report = report
    ad = world.adapter(tmp_path)
    with pytest.raises(VerifyError):
        ad.verify()
    _no_send_possible(world, ad)


@pytest.mark.parametrize("skew", [+3600.0, -3600.0, +86400.0])
def test_an_ita_token_outside_its_validity_at_capture_time_fails_the_verify(tmp_path, skew):
    """Amendment 5: the ITA token's "iat/exp at capture time" are checked. Fault: the host clock is hours ahead
    of the token (it has expired) or behind it (it is not yet valid)."""
    world = NearWorld()
    ad = world.adapter(tmp_path)
    ad._clock = lambda: NOW + skew
    with pytest.raises(VerifyError):
        ad.verify()
    _no_send_possible(world, ad)


def test_an_attestation_fault_through_the_cache_writes_verify_fail_and_refuses(tmp_path):
    """Amendment 4 F4: verification is ledgered; INTERFACES W2: "RefusingClient ... Returned by create_client when
    verification is not fresh and cannot be refreshed"; the verdict is refused, with the vendor's error kept."""
    world = NearWorld()
    _bend(world, _report_only(), lambda r, o: httpx.Response(500, json={"error": {"message": "boom"}}))
    ad = world.adapter(tmp_path)
    led = Ledger(tmp_path / "ledger.sqlite")
    cache = provider_mod.VerificationCache()
    cache.register(NP, ad, PinStore(tmp_path / "pins.yaml"), 300.0, on_event=led.append, verify_wait_seconds=3.0)
    ok, reason, _ = cache.ensure(NP)
    assert ok is False and reason.startswith("attested verification failed")
    fails = [r for r in led.tail(0) if r.kind == "verify_fail"]
    assert len(fails) == 1 and fails[0].detail["vendor"] == "near"
    assert not any(r.kind == "verify_ok" for r in led.tail(0))
    assert world.chat_posts() == 0


# ── inference: cut mid-body, unasked encodings, the signature endpoint failing ───────────────────

def _setup(world, tmp_path, **kw):
    ad = world.adapter(tmp_path, **kw)
    rows: list[dict] = []
    ad.event_sink = rows.append
    ad.verify()
    ad.release()
    client = openai.OpenAI(api_key="sk-x", base_url=BASE, http_client=ad.sync_http_view(), max_retries=0)
    return ad, client, rows


class _CutStream(httpx.SyncByteStream):
    def __init__(self, first: bytes, exc):
        self.first, self.exc = first, exc

    def __iter__(self):
        yield self.first
        raise self.exc

    def close(self):
        pass


@pytest.mark.parametrize("exc", [httpx.RemoteProtocolError("peer closed connection without sending complete "
                                                           "message body (incomplete chunked read)"),
                                 httpx.ReadTimeout("timed out"), httpx.ReadError("connection reset")])
def test_a_reply_cut_mid_body_releases_nothing_and_is_recorded(tmp_path, exc):
    """Amendment 5: "An interrupted body gets no fetch and a row saying so"; Amendment 5.1: "Only one outcome
    hands a body over: HTTP 200, a fully_attested send, and a body that decrypts"."""
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)

    def cut(req, orig):
        r = orig(req)
        body = r.read()
        return httpx.Response(200, headers={"content-type": "application/json"},
                              stream=_CutStream(body[: len(body) // 3], exc), extensions=r.extensions)
    _bend(world, _path("/v1/chat/completions"), cut)
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == []
    (row,) = [r for r in rows if r["kind"] == "send_signed"]
    d = row["detail"]
    assert d["reply_released"] is False and d["fully_attested"] is False and row["verdict"] == "unverified"
    assert world.signature_fetches() == 0
    assert b"PLAINTEXT-SECRET-PROMPT" not in world.chat_bodies[0]


@pytest.mark.parametrize("encoding", ["br", "zstd", "x-vendor-pack", "deflate"])
def test_a_content_encoding_nobody_asked_for_releases_nothing(tmp_path, encoding):
    """Amendment 5: every POST is sent with "accept-encoding: identity"; the view hashes the body "as received
    (after any content decoding)" and releases only a body that decrypts. Fault: the gateway answers in an
    encoding the client did not ask for (the bytes are not that encoding either)."""
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)

    def encoded(req, orig):
        r = orig(req)
        body = r.read()
        return httpx.Response(200, headers={"content-type": "application/json", "content-encoding": encoding},
                              content=body[::-1], extensions=r.extensions)
    _bend(world, _path("/v1/chat/completions"), encoded)
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == []
    assert all(r["detail"].get("reply_released") is not True for r in rows)
    sent = [h for h in world.chat_request_headers]
    assert sent and all(h.get("accept-encoding") == "identity" for h in sent)


@pytest.mark.parametrize("fault", ["http_500", "http_503", "timeout", "not_json", "unavailable"])
def test_a_signature_endpoint_that_fails_withholds_the_reply(tmp_path, fault):
    """Amendment 5.1: "a missing or bent signature ... raises", "a withheld reply is unverified and not
    fully_attested", and every NearRefusal raised after receiving "gets one send_refused row" (reason_code
    near_refused_after_receive)."""
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path, signature_wait_seconds=0.2)
    respond = {
        "http_500": lambda r, o: httpx.Response(500, json={"error": {"message": "boom"}}),
        "http_503": lambda r, o: httpx.Response(503, json={}),
        "timeout": lambda r, o: (_ for _ in ()).throw(httpx.ReadTimeout("timed out", request=r)),
        "not_json": lambda r, o: httpx.Response(200, content=b"{\"text\": "),
        "unavailable": lambda r, o: httpx.Response(200, json={"error_code": "x", "message": "none"}),
    }[fault]
    _bend(world, lambda r: r.url.path.startswith("/v1/signature/"), respond)
    t0 = time.monotonic()
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert time.monotonic() - t0 < 1.8
    assert seen == []
    (row,) = [r for r in rows if r["kind"] == "send_signed"]
    (ref,) = [r for r in rows if r["kind"] == "send_refused"]      # Amendment 5.1: one row per refusal
    assert ref["detail"]["reason_code"] == "near_refused_after_receive"
    assert row["verdict"] == "unverified" and row["detail"]["reply_released"] is False
    assert row["detail"]["fully_attested"] is False and row["detail"]["withheld_reason"]


def test_a_signature_that_never_appears_is_bounded_by_the_wait(tmp_path):
    """Amendment 5: the view retries 404 "for at most confidential.near.signature_wait_seconds"; then the send is
    unverified and the reply withheld."""
    world = NearWorld(sig_mode="404")
    _, client, rows = _setup(world, tmp_path, signature_wait_seconds=0.3)
    t0 = time.monotonic()
    with pytest.raises(Exception):
        client.chat.completions.create(model=MODEL, messages=MSG)
    assert 0.25 < time.monotonic() - t0 < 1.8
    assert rows[0]["detail"]["reply_released"] is False and rows[0]["detail"]["signature"]["status"] == "missing"


# ── the certificate moving under the pinned pool, the key rotating ──────────────────────────────

@pytest.mark.parametrize("change", ["other_certificate", "no_certificate"])
def test_a_certificate_change_between_verify_and_send_withholds_the_reply(tmp_path, change):
    """Amendment 5.1: "a send whose certificate differs, or cannot be read while require_tls_binding, is
    unverified and not fully_attested" (a DNS change that lands the send on another host shows as either)."""
    world = NearWorld()
    _, client, rows = _setup(world, tmp_path)
    if change == "other_certificate":
        world.chat_tls_der = tls_cert()[0]
    else:
        world.chat_serve_tls = False
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == []
    assert all(r["detail"].get("reply_released") is not True for r in rows)
    assert all(r["detail"].get("fully_attested") is not True for r in rows if r["kind"] == "send_signed")
    assert b"PLAINTEXT-SECRET-PROMPT" not in b"".join(world.chat_bodies)


def test_a_model_key_rotated_mid_session_is_refused_until_restart(tmp_path):
    """Amendment 5.1: "A re-verify whose model signing key differs from the accepted one is refused (VerifyError,
    'model signing key ... changed')"; a send sealed to the old key is not answered (the gateway rejects the
    key) and nothing is released."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    world = NearWorld()
    ad, client, rows = _setup(world, tmp_path)
    world.model_key = Ed25519PrivateKey.generate()         # the vendor rotates the model key
    seen = []
    with pytest.raises(Exception):
        seen.append(client.chat.completions.create(model=MODEL, messages=MSG))
    assert seen == [] and all(r["detail"].get("reply_released") is not True for r in rows)
    with pytest.raises(VerifyError, match="signing key"):
        ad.verify()
    assert world.decrypted_requests == []


# ── the host clock jumping ───────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("jump", [-6 * 3600.0, +6 * 3600.0])
def test_a_wall_clock_jump_neither_extends_nor_ends_the_verification_ttl(tmp_path, monkeypatch, jump):
    """provider.VerificationCache._now: "never the wall clock or verified_at_host_clock" (TTL is monotonic);
    LIMITATIONS 8: no attested time. Fault: time.time() jumps by six hours after the verify."""
    from ..unit.test_background_refresh import FakeAdapter, _result
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    cache = provider_mod.VerificationCache()
    ad = FakeAdapter([_result()])
    cache.register(provider_mod.PROFILE_NAME, ad, store, 300.0, refresh_lead_seconds=0.0)
    assert cache.ensure(provider_mod.PROFILE_NAME)[0] is True
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + jump)
    assert cache.fresh(provider_mod.PROFILE_NAME) is True
    assert cache.ensure(provider_mod.PROFILE_NAME)[0] is True and ad.prepares == 1
    mono = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: mono() + 301.0)   # only monotonic time ends it
    assert cache.fresh(provider_mod.PROFILE_NAME) is False


@pytest.mark.parametrize("jump", [-3 * 3600.0, +3 * 3600.0])
def test_a_wall_clock_jump_never_makes_a_receipt_credit_a_send_outside_its_window(jump):
    """receipts._send_coverage: "Wall-clock ledger times; the gate's own TTL is monotonic, so this is the record's
    view" and covered = verify.ts <= send started <= verify.ts + ttl. A jump can only under-claim."""
    rows = [{"id": 1, "kind": "verify_ok", "ts": 1000.0, "host": "h", "detail": {"enclave_host": "h", "ttl_seconds": 300}},
            {"id": 2, "kind": "send_observed", "ts": 1010.0 + jump, "host": "h", "tier": "attested",
             "detail": {"verify_before": 1, "started_ts": 1010.0 + jump}}]
    (c,) = _send_coverage(rows, 300.0, "config")
    assert c["verify"] == 1 and c["covered"] is False
    rows[1]["ts"] = rows[1]["detail"]["started_ts"] = 1010.0
    assert _send_coverage(rows, 300.0, "config")[0]["covered"] is True    # control


# ── Tinfoil: the SDK's attestation failing or answering a document that does not hold ───────────

class _Step:
    def __init__(self, status="success", error=""):
        self.status, self.error = status, error


class _Doc:
    def __init__(self, **kw):
        self.security_verified = True
        self.steps = {n: _Step() for n in ("fetch_digest", "verify_code", "verify_enclave", "compare_measurements")}
        self.config_repo = "tinfoilsh/confidential-model-router"
        self.enclave_host = "e.example"
        self.code_fingerprint, self.enclave_fingerprint, self.release_tag = "c" * 64, "m" * 96, "v1"
        self.tls_public_key, self.hpke_public_key, self.verified_at = "t" * 64, "h" * 64, None
        self.__dict__.update(kw)

    def to_dict(self):
        return {"enclave_host": self.enclave_host, "code_fingerprint": self.code_fingerprint}


class _SC:
    """The SDK surface TinfoilAdapter uses; ``fail`` makes the attestation itself raise."""

    def __init__(self, doc=None, fail: BaseException | None = None):
        self.doc, self.fail = doc, fail

    def verify(self):
        if self.fail is not None:
            raise self.fail
        return object()

    def make_secure_http_client(self):
        self.verify()
        return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))

    def get_verification_document(self):
        return self.doc


def _tinfoil(tmp_path, sc):
    from confidential_mode.verify import tinfoil as T
    ad = T.TinfoilAdapter(data_dir=tmp_path, enclave="e.example", tls_probe=False)
    ad.event_sink = lambda row: None
    sc.verify = lambda: ad._guarded_verify(sc)      # as TinfoilAdapter._secure_client wires it
    ad._sc = sc
    return ad


TINFOIL_FAULTS = {
    "sdk_http_500": dict(fail=httpx.HTTPStatusError("500", request=httpx.Request("GET", "https://x"),
                                                    response=httpx.Response(500))),
    "sdk_timeout": dict(fail=httpx.ConnectTimeout("timed out")),
    "sdk_bad_json": dict(fail=json.JSONDecodeError("Expecting value", "<html>", 0)),
    "sdk_value_error": dict(fail=ValueError("attestation report: bad signature")),
    "no_document": dict(doc=None),
    "not_security_verified": dict(doc=_Doc(security_verified=False)),
    "step_failed": dict(doc=_Doc(steps={**_Doc().steps, "verify_enclave": _Step("failed", "VCEK chain")})),
    "step_missing": dict(doc=_Doc(steps={"fetch_digest": _Step()})),
    "other_repo": dict(doc=_Doc(config_repo="evil/router")),
    "other_host": dict(doc=_Doc(enclave_host="evil.example")),
    "empty_fingerprint": dict(doc=_Doc(code_fingerprint="")),
}


@pytest.mark.parametrize("fault", sorted(TINFOIL_FAULTS))
def test_a_tinfoil_attestation_fault_fails_the_verify_and_publishes_nothing(tmp_path, fault):
    """VendorAdapter.verify "raises VerifyError on any failure; never returns partial"; Amendment 6 finding 25:
    the views refuse "while the adapter has no accepted verification"."""
    ad = _tinfoil(tmp_path, _SC(**TINFOIL_FAULTS[fault]))
    with pytest.raises(VerifyError) as ei:
        ad.verify()
    assert "TypeError" not in str(ei.value) and "AttributeError" not in str(ei.value), ei.value
    assert ad.last_result is None
    with pytest.raises(VerifyError, match="before a successful verify"):
        ad.sync_http_view()


def test_the_tinfoil_stub_verifies_when_nothing_is_bent(tmp_path):
    """The control for the cases above: the same stub with a whole document verifies and opens a view."""
    ad = _tinfoil(tmp_path, _SC(doc=_Doc()))
    r = ad.verify()
    assert r.code_fingerprint == "c" * 64 and ad.last_result is r
    ad.release()
    assert ad.sync_http_view() is not None

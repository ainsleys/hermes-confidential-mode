"""Hostile tests for W2's attested client and provider profile (confidential_mode.client / .provider).

Written before the implementation, against docs/INTERFACES.md (W2). Every test asserts on the recording
transports in _harness_client: which transport each request used ("secure-sync", "secure-async", "hermes-default-*", network), and how often the adapter
attested. Policy decisions this suite makes where the contract is silent are marked DECISION.
"""
from __future__ import annotations

import asyncio
import functools
import gc
import inspect
import threading

import httpx
import pytest

from . import _harness_client as h
from ._harness_client import _wire, adapters, clock, cm, hermes, setup  # noqa: F401 - fixtures

TTL = 300.0


def _good(cm, clock, **kw):
    return h.make_result(cm, verified_at=clock.wall, **kw)


def _assert_no_insecure():
    bad = h.insecure_requests()
    assert not bad, f"requests left the attested transport: {bad}"
    assert not h.NETWORK_ATTEMPTS, f"network was attempted: {h.NETWORK_ATTEMPTS}"


def _assert_refuses(cm, client):
    """Every create on a RefusingClient raises ConfidentialRefused and sends nothing anywhere."""
    assert isinstance(client, cm.RefusingClient), type(client)
    before = len(h.REQUESTS)
    with pytest.raises(cm.ConfidentialRefused):
        h.chat(client)
    with pytest.raises(cm.ConfidentialRefused):
        stream = h.chat(client, stream=True)
        list(stream)  # a lazily-failing stream must still refuse before any byte is sent

    with pytest.raises(cm.ConfidentialRefused):
        asyncio.run(h.achat(client))
    assert len(h.REQUESTS) == before, h.REQUESTS[before:]
    assert not h.NETWORK_ATTEMPTS


def _verdict_in_tier(cm, name=h.PROFILE_NAME):
    verdict = cm.attested_ok(name)
    assert hasattr(verdict, "in_tier") and isinstance(verdict.in_tier, bool), verdict
    return verdict.in_tier


# ── exception type ────────────────────────────────────────────────────────────────────────────


def test_confidential_refused_is_a_plain_exception_not_an_interrupt(cm):
    """W1 re-raises InterruptedError (user stop) and lets BaseException escape: a refusal that subclasses
    either would bypass the refusal path."""
    assert issubclass(cm.ConfidentialRefused, Exception)
    assert not issubclass(cm.ConfidentialRefused, InterruptedError)
    exc = cm.ConfidentialRefused("enclave build changed")
    assert "enclave build changed" in str(exc)


# ── verify() failing ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("error", ["VerifyError", "RuntimeError", "KeyError", "httpx.ConnectError"])
def test_verify_raising_on_first_call_yields_refusing_client(cm, setup, error):
    exc = {"VerifyError": cm.VerifyError("attestation failed"), "RuntimeError": RuntimeError("sdk bug"),
           "KeyError": KeyError("measurement"),
           "httpx.ConnectError": httpx.ConnectError("no route")}[error]
    adapter, store, profile = setup([exc])
    client = h.create(profile)  # NEVER raises, NEVER None (Hermes fails open otherwise)
    assert client is not None
    _assert_refuses(cm, client)
    assert adapter.verify_calls >= 1
    assert _verdict_in_tier(cm) is False
    # A second build while still failing: still refusing, still nothing sent.
    _assert_refuses(cm, h.create(profile))
    _assert_no_insecure()
    assert h.REQUESTS == []


def test_verify_raising_on_refresh_refuses_new_clients(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock), cm.VerifyError("refresh failed")])
    first = h.create(profile)
    assert isinstance(first, cm.ConfidentialClient)
    assert h.reply_text(h.chat(first)) == h.FAKE_REPLY
    assert h.labels() == ["secure-sync"]

    clock.advance(TTL + 1)
    second = h.create(profile)
    assert adapter.verify_calls == 2, "stale cache was not refreshed"
    _assert_refuses(cm, second)
    assert _verdict_in_tier(cm) is False

    # Recovery: the next build re-verifies; it may only hand out a ConfidentialClient after a NEW success.
    calls_before = adapter.verify_calls
    adapter.script.append(_good(cm, clock))  # every later verify() now succeeds
    third = h.create(profile)
    if isinstance(third, cm.ConfidentialClient):
        assert adapter.verify_calls > calls_before, "ConfidentialClient handed out on a failed verification"
        h.chat(third)
    else:
        _assert_refuses(cm, third)
    _assert_no_insecure()


def test_verify_hanging_never_yields_a_sending_client_meanwhile(cm, setup, clock):
    """DECISION (safety half): while verify() is hung nothing may be sent, attested_ok must not report
    in-tier, and a concurrent create_client may block or refuse but never hand out a working client."""
    hang = h.Hang()
    adapter, store, profile = setup([hang])
    done1, client1, exc1 = h.run_with_timeout(lambda: h.create(profile), 1.0)
    assert hang.entered.wait(5), "verify() was never called"
    done2, client2, exc2 = h.run_with_timeout(lambda: h.create(profile), 2.0)
    if done2:
        assert exc2 is None, exc2
        _assert_refuses(cm, client2)
    done_ok, in_tier, exc_ok = h.run_with_timeout(lambda: _verdict_in_tier(cm), 2.0)
    if done_ok:
        assert exc_ok is None, exc_ok
        assert in_tier is False
    if done1:
        assert exc1 is None, exc1
        _assert_refuses(cm, client1)
    assert h.REQUESTS == []
    hang.release()
    _assert_no_insecure()


def test_verify_hanging_on_first_call_create_client_is_bounded(cm, setup):
    """DECISION (liveness half): Hermes calls create_client ~4 times before the first turn, on its own
    thread. A black-holed attestation endpoint must not freeze Hermes: create_client returns a
    RefusingClient within a bounded time. The contract names no timeout; 10 s is this suite's bound."""
    hang = h.Hang()
    adapter, store, profile = setup([hang])
    done, client, exc = h.run_with_timeout(lambda: h.create(profile), 10.0)
    hang.release()
    assert done, "create_client blocked >10 s on a hung verify(): Hermes would hang at startup"
    assert exc is None, exc
    _assert_refuses(cm, client)


def test_verify_hanging_on_refresh(cm, setup, clock):
    hang = h.Hang()
    adapter, store, profile = setup([_good(cm, clock), hang])
    assert isinstance(h.create(profile), cm.ConfidentialClient)
    clock.advance(TTL + 1)
    done, client, exc = h.run_with_timeout(lambda: h.create(profile), 10.0)
    assert hang.entered.wait(5), "stale verification was not refreshed"
    done_ok, in_tier, _ = h.run_with_timeout(lambda: _verdict_in_tier(cm), 2.0)
    if done_ok:
        assert in_tier is False, "stale verification reported in-tier while refresh hangs"
    hang.release()
    assert done, "create_client blocked >10 s on a hung refresh"
    assert exc is None, exc
    _assert_refuses(cm, client)
    _assert_no_insecure()


# ── fingerprints differ from pins ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("variant", ["both", "code-only", "enclave-only", "swapped", "prefix", "extended"])
def test_fingerprint_mismatch_refuses_with_zero_requests_and_stages_pending(cm, setup, clock, variant):
    code, enclave = {
        "both": (h.FP_CODE_2, h.FP_ENCLAVE_2),
        "code-only": (h.FP_CODE_2, h.FP_ENCLAVE),
        "enclave-only": (h.FP_CODE, h.FP_ENCLAVE_2),
        "swapped": (h.FP_ENCLAVE, h.FP_CODE),
        "prefix": (h.FP_CODE[:16], h.FP_ENCLAVE[:16]),
        "extended": (h.FP_CODE + "00", h.FP_ENCLAVE + "00"),
    }[variant]
    adapter, store, profile = setup([_good(cm, clock, code=code, enclave=enclave)])
    client = h.create(profile)
    _assert_refuses(cm, client)
    assert _verdict_in_tier(cm) is False
    pending = store.pending()
    assert pending is not None, "mismatch did not stage a pending pin"
    assert h.contains(pending, code) and h.contains(pending, enclave), pending
    assert h.REQUESTS == [] and adapter.async_builds == []
    _assert_no_insecure()


def test_no_pin_at_all_refuses_and_stages(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)], pinned=None)
    _assert_refuses(cm, h.create(profile))
    assert store.pending() is not None
    assert _verdict_in_tier(cm) is False
    assert h.REQUESTS == []


def test_refresh_returning_new_build_refuses_even_with_a_warm_pool(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock), _good(cm, clock, code=h.FP_CODE_2)])
    warm = h.create(profile)
    h.chat(warm)
    clock.advance(TTL + 1)
    _assert_refuses(cm, h.create(profile))
    assert adapter.verify_calls == 2
    assert _verdict_in_tier(cm) is False
    assert h.contains(store.pending(), h.FP_CODE_2)
    assert h.labels() == ["secure-sync"]


def test_empty_fingerprints_never_yield_a_confidential_client(cm, setup, clock):
    empty = _good(cm, clock, code="", enclave="")
    adapter, store, profile = setup([empty], pinned=None)
    try:
        h.pin(store, empty)  # the store may (should) refuse to pin an empty fingerprint
    except Exception:
        pass
    _assert_refuses(cm, h.create(profile))
    assert _verdict_in_tier(cm) is False


def test_vendor_or_repo_mismatch_with_identical_fingerprints_refuses(cm, setup, clock):
    for kw in ({"vendor": "evil"}, {"router_repo": "evil/router"}):
        h.REQUESTS.clear()
        adapter, store, profile = setup([_good(cm, clock, **kw)])
        _assert_refuses(cm, h.create(profile))
        assert h.REQUESTS == []


def test_new_profile_does_not_inherit_previous_profiles_fresh_verification(cm, setup, clock):
    """Caches keyed only by provider name would let a re-registered profile (new adapter, failing verify)
    reuse the old profile's fresh result."""
    a1, store, p1 = setup([_good(cm, clock)])
    assert isinstance(h.create(p1), cm.ConfidentialClient)
    a2, _, p2 = setup([cm.VerifyError("new adapter fails")])
    _assert_refuses(cm, h.create(p2))
    assert a2.verify_calls >= 1


# ── TTL ───────────────────────────────────────────────────────────────────────────────────────


def test_ttl_boundary(cm, setup, clock):
    """DECISION: fresh iff elapsed < ttl. At elapsed == ttl the cache is stale and must re-verify."""
    adapter, store, profile = setup([_good(cm, clock), _good(cm, clock)], ttl=TTL)
    assert isinstance(h.create(profile), cm.ConfidentialClient)
    assert adapter.verify_calls == 1
    clock.advance(TTL - 0.001)
    assert isinstance(h.create(profile), cm.ConfidentialClient)
    assert adapter.verify_calls == 1, "re-verified before the TTL elapsed"
    clock.advance(0.001)
    c = h.create(profile)
    assert adapter.verify_calls == 2, "not re-verified at exactly ttl"
    assert isinstance(c, cm.ConfidentialClient)


def test_ttl_wall_clock_jumping_backwards_does_not_extend_freshness(cm, setup, clock):
    """Wall clock jumps back 10 000 s, then ttl+1 real seconds pass (monotonic advances). An
    implementation computing `time.time() - verified_at < ttl` would stay fresh for ~3 more hours."""
    adapter, store, profile = setup([_good(cm, clock), _good(cm, clock)], ttl=TTL)
    h.create(profile)
    clock.advance(-10_000, mono=False)
    clock.advance(TTL + 1)
    h.create(profile)
    assert adapter.verify_calls == 2, "a backwards wall-clock jump extended the verification TTL"
    assert _verdict_in_tier(cm) is True


def test_ttl_ignores_adapter_supplied_verified_at_host_clock(cm, setup, clock):
    """verified_at_host_clock is NOT attested: a result claiming to be verified far in the future must not
    push the expiry out."""
    future = h.make_result(cm, verified_at=clock.wall + 1e9)
    adapter, store, profile = setup([future, _good(cm, clock)], ttl=TTL)
    h.create(profile)
    clock.advance(TTL + 1)
    h.create(profile)
    assert adapter.verify_calls == 2


def test_attested_ok_never_true_on_a_stale_cache(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock), cm.VerifyError("down")], ttl=TTL)
    h.create(profile)
    assert _verdict_in_tier(cm) is True
    assert _verdict_in_tier(cm, "openrouter") is False
    assert _verdict_in_tier(cm, "attested-tinfoil-typo") is False
    clock.advance(TTL + 1)
    assert _verdict_in_tier(cm) is False  # either refreshed (and failed) or reported stale


# ── 50 create_client calls ────────────────────────────────────────────────────────────────────


def test_fifty_sync_clients_one_attestation_no_pool_leak(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    clients = [h.create(profile) for _ in range(50)]
    assert all(isinstance(c, cm.ConfidentialClient) for c in clients)
    assert adapter.verify_calls == 1, f"attested {adapter.verify_calls} times for 50 builds"
    for c in clients:
        assert h.reply_text(h.chat(c)) == h.FAKE_REPLY
    assert h.labels() == ["secure-sync"] * 50
    for c in clients[:25]:
        c.close()
    assert not adapter.pool.closed, "closing a view closed the shared verified pool"
    for c in clients[25:]:
        h.chat(c)  # siblings unaffected by closed views
    fresh = h.create(profile)
    h.chat(fresh)
    assert adapter.verify_calls == 1
    assert h.labels() == ["secure-sync"] * 76
    assert adapter.pool.close_calls == 0
    _assert_no_insecure()


def test_fifty_clients_async_one_transport_per_loop(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    clients = [h.create(profile) for _ in range(50)]

    async def all_of_them():
        return await asyncio.gather(*[h.achat(c) for c in clients])
    for _ in range(2):  # two loops in a row (gateway / asyncio.run callers)
        out = asyncio.run(all_of_them())
        assert [h.reply_text(r) for r in out] == [h.FAKE_REPLY] * 50
    assert adapter.verify_calls == 1
    assert h.labels() == ["secure-async"] * 100, h.labels()
    loops = {r.loop_id for r in h.REQUESTS}
    assert len(loops) == 2
    for loop_id in loops:
        transports = {r.transport_id for r in h.REQUESTS if r.loop_id == loop_id}
        assert len(transports) == 1, f"{len(transports)} async transports on one loop"
    assert not adapter.pool.closed
    _assert_no_insecure()


def test_close_in_a_loop_does_not_break_siblings_on_that_loop(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c1, c2 = h.create(profile), h.create(profile)

    async def go():
        await c1.chat.completions.create(model="m", messages=h.MSG)
        c1.close()
        return await c2.chat.completions.create(model="m", messages=h.MSG)
    assert h.reply_text(asyncio.run(go())) == h.FAKE_REPLY
    assert h.labels() == ["secure-async", "secure-async"]


# ── close() ───────────────────────────────────────────────────────────────────────────────────


def test_close_twice_is_harmless(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)
    h.chat(c)
    c.close()
    c.close()
    assert not adapter.pool.closed
    try:
        h.chat(c)  # a closed client may raise; it must not find another way out
    except Exception:
        pass
    h.chat(h.create(profile))
    _assert_no_insecure()

    failing_adapter, _, failing = setup([cm.VerifyError("x")])
    r = h.create(failing)
    r.close()
    r.close()
    _assert_refuses(cm, r)


def test_closed_client_reports_closed_to_hermes(cm, setup, clock):
    """Hermes decides whether to rebuild via _is_openai_client_closed (client.is_closed / client._client)."""
    from agent.client_lifecycle import ClientLifecycleMixin
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)
    assert ClientLifecycleMixin._is_openai_client_closed(c) is False
    c.close()
    assert ClientLifecycleMixin._is_openai_client_closed(c) is True, "Hermes would keep reusing a closed client"


# ── dead event loops ──────────────────────────────────────────────────────────────────────────


def test_async_client_never_reused_across_dead_loops(cm, setup, clock):
    """Create/close 20 loops in a row with the SAME client; CPython readily reuses id(loop), so a cache
    keyed by id(loop) without an identity/closed check hands the dead loop's AsyncClient out."""
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)
    for _ in range(20):
        loop = asyncio.new_event_loop()
        try:
            resp = loop.run_until_complete(h.achat(c))
            assert h.reply_text(resp) == h.FAKE_REPLY
        finally:
            loop.close()
        del loop
        gc.collect()
    assert "DEAD-LOOP" not in h.labels(), h.REQUESTS
    assert h.labels() == ["secure-async"] * 20
    assert len({r.transport_id for r in h.REQUESTS}) == 20
    # Sync still fine after all that; and a 21st loop.
    h.chat(c)
    asyncio.run(h.achat(c))
    assert h.labels()[-2:] == ["secure-sync", "secure-async"]
    _assert_no_insecure()


# ── sync vs async dispatch ────────────────────────────────────────────────────────────────────


def test_sync_function_called_on_a_running_loop_gets_a_result_not_a_coroutine(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    def sync_caller():
        return h.chat(c)  # NOTE: h.chat is itself a sync frame; so is this one

    def sync_caller_direct():
        return c.chat.completions.create(model="m", messages=h.MSG)

    def sync_stream():
        return [chunk for chunk in c.chat.completions.create(model="m", messages=h.MSG, stream=True)]

    async def main():
        assert asyncio.get_running_loop() is not None
        return sync_caller(), sync_caller_direct(), (lambda: c.chat.completions.create(model="m", messages=h.MSG))(), \
            sync_stream()
    r1, r2, r3, chunks = asyncio.run(main())
    for r in (r1, r2, r3):
        assert not inspect.isawaitable(r), "sync caller got an awaitable"
        assert h.reply_text(r) == h.FAKE_REPLY
    assert chunks and not inspect.isawaitable(chunks[0])
    assert h.labels() == ["secure-sync"] * 4
    _assert_no_insecure()


def test_sync_call_in_a_worker_thread_of_a_running_loop(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    async def main():
        return await asyncio.to_thread(functools.partial(c.chat.completions.create, model="m", messages=h.MSG))
    assert h.reply_text(asyncio.run(main())) == h.FAKE_REPLY
    assert h.labels() == ["secure-sync"]


def test_async_generator_caller_gets_an_awaitable(cm, setup, clock):
    """An `async def ... yield` frame has CO_ASYNC_GENERATOR, not CO_COROUTINE. A frame check on
    CO_COROUTINE alone hands it a sync result (blocking the loop) which then fails to await."""
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    async def agen():
        yield await c.chat.completions.create(model="m", messages=h.MSG)

    async def main():
        return [r async for r in agen()]
    out = asyncio.run(main())
    assert h.reply_text(out[0]) == h.FAKE_REPLY
    assert h.labels() == ["secure-async"]


def test_gather_over_a_generator_expression_never_leaks(cm, setup, clock):
    """`asyncio.gather(*(c.chat.completions.create(...) for ...))`: the genexpr frame is a plain generator
    (not inlined like list comprehensions since 3.12), so a caller-frame check sees a SYNC caller and
    blocks the loop doing sync sends. It must at worst raise, never leave the attested transport."""
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    async def main():
        return await asyncio.gather(*(c.chat.completions.create(model="m", messages=h.MSG) for _ in range(3)))
    try:
        asyncio.run(main())
    except Exception:
        pass
    _assert_no_insecure()


@pytest.mark.xfail(strict=False, reason="contract limit: caller-frame dispatch treats a generator expression "
                                        "inside a coroutine as a sync caller; no Hermes path does this @84a0301")
def test_gather_over_a_generator_expression_works(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    async def main():
        return await asyncio.gather(*(c.chat.completions.create(model="m", messages=h.MSG) for _ in range(3)))
    out = asyncio.run(main())
    assert [h.reply_text(r) for r in out] == [h.FAKE_REPLY] * 3
    assert h.labels() == ["secure-async"] * 3


def test_sync_wrapper_awaited_from_a_coroutine_may_raise_but_never_leaks(cm, setup, clock):
    """`await wrapper()` where wrapper is sync: the frame check sees a sync caller. The claim is
    'a wrong guess can only raise, never leak'; hold it to that."""
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    def wrapper(**kw):
        return c.chat.completions.create(**kw)

    async def main():
        return await wrapper(model="m", messages=h.MSG)
    try:
        asyncio.run(main())
    except Exception:
        pass
    _assert_no_insecure()


@pytest.mark.xfail(strict=False, reason="contract limit: a frame check cannot tell `x = create()` from "
                                        "`x = await create()` inside a coroutine; unreachable in Hermes @84a0301")
def test_unawaited_sync_style_call_inside_a_coroutine_gets_a_result(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)

    async def main():
        resp = c.chat.completions.create(model="m", messages=h.MSG)  # blocking sync call, no await
        if inspect.isawaitable(resp):
            resp.close() if hasattr(resp, "close") else None
        return resp
    r = asyncio.run(main())
    assert not inspect.isawaitable(r)
    assert h.reply_text(r) == h.FAKE_REPLY


# ── attribute surface Hermes reads ────────────────────────────────────────────────────────────


def test_confidential_client_attribute_surface(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)
    assert c.HERMES_SKIP_TRANSPORT_WRAP is True and c.HERMES_SKIP_ASYNC_WRAP is True
    assert str(c.base_url).startswith(f"https://{h.ENCLAVE_HOST}"), c.base_url
    assert c.api_key == "hostile-key"
    assert callable(c.is_closed) and c.is_closed() is False
    assert isinstance(c._client, httpx.Client) and c._client in adapter.views, \
        "_client is not the adapter's non-closing view"
    h.REQUESTS.clear()
    r = c.with_options(timeout=5, max_retries=0).chat.completions.create(model="m", messages=h.MSG)
    assert h.reply_text(r) == h.FAKE_REPLY
    models = c.models.list()
    assert [m.id for m in models.data] == ["m"]
    assert h.labels() == ["secure-sync", "secure-sync"]
    # Hermes' socket sweep runs before every request-scoped close: it must not reach the shared pool.
    from agent.agent_runtime_helpers import force_close_tcp_sockets
    force_close_tcp_sockets(c)
    assert not adapter.pool.closed
    _assert_no_insecure()


def test_confidential_client_hostile_kwargs_cannot_swap_the_transport(cm, setup, clock):
    """create_client(**kw) gets whatever Hermes puts in client_kwargs. An http_client / base_url there must
    not displace the attested transport or redirect requests away from the verified enclave host.
    DECISION: requests go only to the verified enclave_host, whatever base_url Hermes passes."""
    adapter, store, profile = setup([_good(cm, clock)])
    injected_hits = []
    injected = httpx.Client(transport=httpx.MockTransport(lambda r: (injected_hits.append(r), h._respond(r))[1]))
    c = h.create(profile, http_client=injected, default_headers={"X-Test": "1"}, timeout=7.0, max_retries=0,
                 default_query={"q": "1"})
    assert isinstance(c, cm.ConfidentialClient)
    h.chat(c)
    assert injected_hits == [] and h.labels() == ["secure-sync"]
    c2 = h.create(profile, base_url="https://attacker.invalid/v1")
    if isinstance(c2, cm.ConfidentialClient):
        h.chat(c2)
        asyncio.run(h.achat(c2))
    hosts = {r.host for r in h.REQUESTS}
    assert hosts == {h.ENCLAVE_HOST}, f"requests sent to unverified hosts: {hosts}"
    _assert_no_insecure()


@pytest.mark.xfail(strict=False, reason="contract limit: __getattr__ delegates with_options to the sync "
                                        "OpenAI, whose copy is not dual; no Hermes path does this @84a0301")
def test_with_options_copy_keeps_attestation_on_hermes_async_rebuild(cm, setup, clock):
    adapter, store, profile = setup([_good(cm, clock)])
    c = h.create(profile)
    from agent.auxiliary_client import _to_async_client
    aclient, _ = _to_async_client(c.with_options(timeout=5), "m")
    asyncio.run(aclient.chat.completions.create(model="m", messages=h.MSG))
    _assert_no_insecure()


def test_refusing_client_attribute_surface(cm, setup):
    adapter, store, profile = setup([cm.VerifyError("x")])
    r = h.create(profile)
    assert isinstance(r, cm.RefusingClient)
    # Without the async-wrap opt-out, Hermes' _to_async_client REBUILDS a plain AsyncOpenAI from
    # .base_url/.api_key on its own transport: the refusal would turn into a send.
    assert r.HERMES_SKIP_TRANSPORT_WRAP is True and r.HERMES_SKIP_ASYNC_WRAP is True
    assert isinstance(str(r.base_url), str)
    assert isinstance(r.api_key, str)
    closed = r.is_closed() if callable(r.is_closed) else r.is_closed
    assert isinstance(closed, bool)
    from agent.client_lifecycle import ClientLifecycleMixin
    assert isinstance(ClientLifecycleMixin._is_openai_client_closed(r), bool)
    inner = r._client
    if inner is not None:
        assert isinstance(inner, httpx.Client)
        try:
            inner.get(h.ENCLAVE_URL + "/models")
        except Exception:
            pass
    opts = r.with_options(timeout=5)
    with pytest.raises(cm.ConfidentialRefused):
        opts.chat.completions.create(model="m", messages=h.MSG)
    for call in (lambda: r.models.list(),
                 lambda: r.responses.create(model="m", input="hi"),
                 lambda: r.completions.create(model="m", prompt="hi"),
                 lambda: r.embeddings.create(model="m", input="hi")):
        try:
            call()
        except Exception:  # ConfidentialRefused expected; any refusal is tolerated, a send is not
            pass
    from agent.auxiliary_client import _to_async_client
    aclient, _ = _to_async_client(r, "m")
    assert aclient is r, "Hermes rebuilt the RefusingClient into a sending AsyncOpenAI"
    from agent.agent_runtime_helpers import force_close_tcp_sockets
    force_close_tcp_sockets(r)
    assert h.REQUESTS == []
    _assert_no_insecure()


# ── real Hermes turns ─────────────────────────────────────────────────────────────────────────


def test_real_turns_keep_one_attestation_and_the_pool_survives_request_scoped_close(cm, setup, clock, hermes):
    adapter, store, profile = setup([_good(cm, clock)])
    hermes.register(profile)
    agent = hermes.agent()
    assert isinstance(agent.client, cm.ConfidentialClient), type(agent.client)
    for i in range(3):
        result = agent.run_conversation(f"turn {i}")
        assert h.FAKE_REPLY in str(result.get("final_response")), result
    # Explicitly drive Hermes' request-scoped close path (socket sweep + close) on a request client.
    req = agent._create_request_openai_client(reason="hostile")
    agent._close_openai_client(req, reason="hostile", shared=False)
    agent._close_cached_request_openai_client(reason="hostile")
    assert agent._replace_primary_openai_client(reason="hostile")
    agent.run_conversation("after close")
    assert adapter.verify_calls == 1, adapter.verify_calls
    assert not adapter.pool.closed and adapter.pool.close_calls == 0
    assert h.REQUESTS and set(h.labels()) == {"secure-sync"}, h.REQUESTS
    _assert_no_insecure()


def test_real_aux_sync_and_async_stay_on_the_attested_transport(cm, setup, clock, hermes):
    adapter, store, profile = setup([_good(cm, clock)])
    hermes.register(profile)
    aux = hermes.aux
    aux._client_cache.clear()
    r = aux.call_llm(task="compression", messages=h.MSG)
    assert h.reply_text(r) == h.FAKE_REPLY
    aux._client_cache.clear()
    r = asyncio.run(aux.async_call_llm(task="compression", messages=h.MSG))
    assert h.reply_text(r) == h.FAKE_REPLY
    aux._client_cache.clear()
    asyncio.run(aux.async_call_llm(task="compression", messages=h.MSG))
    assert h.labels() == ["secure-sync", "secure-async", "secure-async"], h.REQUESTS
    _assert_no_insecure()


def test_refusing_client_as_main_client_in_a_real_turn(cm, setup, hermes):
    adapter, store, profile = setup([cm.VerifyError("enclave unreachable")])
    hermes.register(profile)
    agent = hermes.agent()
    assert isinstance(agent.client, cm.RefusingClient), type(agent.client)
    done, result, exc = h.run_with_timeout(lambda: agent.run_conversation("hello"), 120)
    assert done, "turn did not end within 120 s on a refusing client"
    if exc is not None:
        assert isinstance(exc, Exception) and not isinstance(exc, (KeyboardInterrupt, SystemExit)), exc
    else:
        assert h.FAKE_REPLY not in str(result.get("final_response")), result
    assert h.REQUESTS == [], h.REQUESTS
    _assert_no_insecure()


def test_refusing_client_on_hermes_aux_paths(cm, setup, hermes):
    adapter, store, profile = setup([cm.VerifyError("enclave unreachable")])
    hermes.register(profile)
    aux = hermes.aux
    for fn in (lambda: aux.call_llm(task="compression", messages=h.MSG),
               lambda: asyncio.run(aux.async_call_llm(task="compression", messages=h.MSG))):
        aux._client_cache.clear()
        try:
            out = fn()
        except Exception:
            out = None
        assert h.FAKE_REPLY not in h.reply_text(out)
    assert h.REQUESTS == [], h.REQUESTS
    _assert_no_insecure()


def test_hermes_metadata_probes_do_not_reach_the_enclave_off_the_attested_transport(cm, setup, clock, hermes):
    """Hermes resolves the context window for a custom endpoint by probing {base_url}/models and Ollama
    /api/show with plain httpx and the API key (agent/model_metadata.py _resolve_custom_endpoint_context_length),
    outside create_client. The profile can pre-empt this (ProviderProfile.get_model_context_length returning
    an int is consulted first). Without that, the API key and model ids go to the enclave host over an
    unattested connection on every agent build."""
    adapter, store, profile = setup([_good(cm, clock)])
    hermes.register(profile)
    agent = hermes.agent()
    agent.run_conversation("hello")
    to_enclave = [a for a in h.METADATA_ATTEMPTS if h.ENCLAVE_HOST in a]
    assert not to_enclave, f"unattested metadata probes to the enclave host: {to_enclave}"


# ── concurrency on the profile ────────────────────────────────────────────────────────────────


def test_concurrent_first_builds_attest_once(cm, setup, clock):
    """Hermes builds main + aux clients from different threads at startup."""
    adapter, store, profile = setup([_good(cm, clock)])
    barrier = threading.Barrier(16)
    out = []

    def worker():
        barrier.wait()
        out.append(h.create(profile))
    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert len(out) == 16 and all(isinstance(c, cm.ConfidentialClient) for c in out)
    assert adapter.verify_calls == 1, f"{adapter.verify_calls} concurrent attestations"


# ── packaging ─────────────────────────────────────────────────────────────────────────────────


def test_pyproject_pins_tinfoil_exactly():
    """0.15.0 needs openai>=3.26 (Hermes pins 2.54.0): any spec but the exact pin can resolve to it."""
    import re
    import tomllib
    data = tomllib.loads((h.WORKTREE / "pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for group in (project.get("optional-dependencies") or {}).values():
        specs += list(group)
    for group in (data.get("dependency-groups") or {}).values():
        specs += [s for s in group if isinstance(s, str)]
    specs += list((data.get("tool", {}).get("uv", {}) or {}).get("constraint-dependencies", []) or [])
    specs += list((data.get("tool", {}).get("uv", {}) or {}).get("override-dependencies", []) or [])
    tinfoil = [s for s in specs if re.match(r"^\s*tinfoil(\s|\[|[<>=!~;@]|$)", s, re.I)]
    norm = [re.sub(r"\s+", "", s) for s in tinfoil]
    assert "tinfoil==0.14.2" in [re.sub(r"\s+", "", s) for s in project.get("dependencies", [])], \
        f"project.dependencies lacks tinfoil==0.14.2: {project.get('dependencies')}"
    assert all(s == "tinfoil==0.14.2" for s in norm), f"non-exact tinfoil spec present: {tinfoil}"

"""A cached verification vouches only under the lock generation it was accepted under.

The cache is per process. `hermes confidential off` and `on` from the CLI run in their own process, so a running
gateway never saw them; its cached verification inside the TTL vouched for the next lock's sends. The plugin
now names the lock the persisted state holds (tier and start time, None while unlocked) and a result is fresh
only under the generation it was accepted under. The lock adopts the verification it was taken on, so a lock
made from chat does not verify twice.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confidential_mode import provider as provider_mod  # noqa: E402
from confidential_mode.pins import PinStore  # noqa: E402

from .test_background_refresh import LEAD, TTL, Clock, FakeAdapter, P, _result  # noqa: E402


def _world(tmp_path, monkeypatch, generation):
    store = PinStore(tmp_path / "pins.yaml")
    store.apply(store.stage(_result()), approved_via="cli")
    clock = Clock()
    cache = provider_mod.VerificationCache(clock=clock)
    cache.active = lambda: True
    cache.generation = generation
    monkeypatch.setattr(provider_mod.BackgroundRefresh, "start", lambda self: None)
    ad = FakeAdapter([_result(), _result(), _result(), _result()])
    cache.register(P, ad, store, TTL, on_event=lambda ev: None, refresh_lead_seconds=LEAD)
    return cache, ad, clock


def test_a_lock_or_unlock_made_elsewhere_makes_the_next_call_verify_again(tmp_path, monkeypatch):
    gen = {"v": None}                                   # unlocked, as the persisted state would read
    cache, ad, clock = _world(tmp_path, monkeypatch, lambda: gen["v"])
    assert cache.ensure(P)[0] is True and ad.prepares == 1
    clock.t = 10.0
    assert cache.ensure(P)[0] is True and ad.prepares == 1          # inside the TTL, same generation: cached
    gen["v"] = ("attested", 100.0)                      # another process locked
    assert cache.fresh(P) is False
    assert cache.ensure(P)[0] is True and ad.prepares == 2          # verified again, inside the TTL
    assert cache.ensure(P)[0] is True and ad.prepares == 2
    gen["v"] = None                                     # another process unlocked
    assert cache.ensure(P)[0] is True and ad.prepares == 3
    gen["v"] = ("attested", 200.0)                      # and locked again
    assert cache.ensure(P)[0] is True and ad.prepares == 4


def test_the_lock_adopts_the_verification_it_was_taken_on(tmp_path, monkeypatch):
    gen = {"v": None}
    cache, ad, clock = _world(tmp_path, monkeypatch, lambda: gen["v"])
    assert cache.ensure(P)[0] is True and ad.prepares == 1          # the lock's preflight verifies
    gen["v"] = ("attested", 100.0)                      # then writes the lock flag
    cache.adopt_generation()                            # and adopts the verification (locking._lock_held)
    assert cache.fresh(P) is True
    assert cache.ensure(P)[0] is True and ad.prepares == 1          # the first send does not verify again
    clock.t = TTL + 1
    assert cache.ensure(P)[0] is True and ad.prepares == 2          # the TTL still bounds the result


def test_without_a_generation_the_ttl_alone_bounds_a_result(tmp_path, monkeypatch):
    monkeypatch.setattr(provider_mod, "_LOCK_GENERATION", None)
    cache, ad, clock = _world(tmp_path, monkeypatch, None)
    assert cache.ensure(P)[0] is True and ad.prepares == 1
    clock.t = TTL - 1
    assert cache.ensure(P)[0] is True and ad.prepares == 1
    clock.t = TTL + 1
    assert cache.ensure(P)[0] is True and ad.prepares == 2


def test_a_generation_function_that_raises_counts_as_no_generation(tmp_path, monkeypatch):
    def boom():
        raise RuntimeError("state unreadable")
    cache, ad, clock = _world(tmp_path, monkeypatch, boom)
    assert cache.ensure(P)[0] is True and ad.prepares == 1
    assert cache.ensure(P)[0] is True and ad.prepares == 1          # None == None: cached, bounded by the TTL

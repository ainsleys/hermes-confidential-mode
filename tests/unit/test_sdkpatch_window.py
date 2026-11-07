"""Amendment 13: the capture and replay wrappers (verify/_sdkpatch.py) exist only inside an overrides()
window. Outside one, every wrapped third-party attribute (requests.Session.request among them) is the
library's own; inside one, another thread's calls run the original unchanged."""
from __future__ import annotations

import threading
import types

import requests

from confidential_mode.verify import _sdkpatch


def test_requests_session_request_is_its_own_outside_the_window():
    original = requests.Session.__dict__["request"]
    seen = []

    def spy(orig, *a, **kw):
        seen.append(1)
        raise RuntimeError("stop before any network")
    with _sdkpatch.overrides({(requests.Session, "request"): spy}):
        assert requests.Session.__dict__["request"] is not original
        assert (requests.Session, "request") in _sdkpatch.installed_now()
        try:
            requests.Session().request("GET", "http://127.0.0.1:9/")
        except RuntimeError:
            pass
    assert seen == [1]
    assert requests.Session.__dict__["request"] is original
    assert (requests.Session, "request") not in _sdkpatch.installed_now()


def test_another_thread_inside_the_window_runs_the_original():
    mod = types.ModuleType("dummy_sdk_window")
    mod.f = lambda x: x + 1
    original = mod.f
    entered, release, results = threading.Event(), threading.Event(), {}

    def holder():
        with _sdkpatch.overrides({(mod, "f"): lambda orig, x: orig(x) * 100}):
            results["holder"] = mod.f(1)
            entered.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    assert entered.wait(5)
    results["other"] = mod.f(1)                 # the wrapper is in place, but this thread has no override
    assert mod.f is not original
    release.set()
    t.join(5)
    assert results == {"holder": 200, "other": 2}
    assert mod.f is original


def test_nested_and_overlapping_windows_restore_once_the_last_closes():
    mod = types.ModuleType("dummy_sdk_nested")
    mod.g = lambda: "raw"
    original = mod.g
    with _sdkpatch.overrides({(mod, "g"): lambda orig: "outer"}):
        with _sdkpatch.overrides({(mod, "g"): lambda orig: "inner"}):
            assert mod.g() == "inner"
        assert mod.g() == "outer" and mod.g is not original
    assert mod.g is original and mod.g() == "raw"

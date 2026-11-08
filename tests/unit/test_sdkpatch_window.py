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
    assert not t.is_alive()
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


# ── code-pass-2 review item 11: the window under concurrency and failure, with the real capture hooks ──────

import pytest  # noqa: E402


class _Fmt:
    value = "fake-format"


class _Doc:
    def __init__(self, body):
        self.format, self.body = _Fmt(), body


@pytest.fixture
def sdk(monkeypatch):
    """The SDK's fetch points the capture hooks wrap, replaced by offline fakes (no network). ``gates`` lets a
    test hold a thread between two fetches; ``boom`` makes one fetch raise."""
    from tinfoil import client as tf_client, sigstore as tf_sigstore
    state = {"gates": {}, "boom": set()}

    def gate(name):
        g = state["gates"].get((threading.current_thread().name, name))
        if g is not None:
            g[0].set()
            assert g[1].wait(5)

    def fetch_attestation(host):
        gate("attestation")
        if ("attestation", host) in state["boom"]:
            raise ConnectionError("attestation fetch failed")
        return _Doc(f"body-of-{host}")

    def fetch_attestation_bundle(repo, digest):
        gate("bundle")
        return f"bundle-of-{repo}".encode()

    def fetch_latest_digest(repo):
        gate("digest")
        return f"digest-of-{repo}"
    monkeypatch.setattr(tf_client, "fetch_attestation", fetch_attestation)
    monkeypatch.setattr(tf_client, "fetch_attestation_bundle", fetch_attestation_bundle)
    monkeypatch.setattr(tf_sigstore, "fetch_latest_digest", fetch_latest_digest)
    state["fakes"] = {(tf_client, "fetch_attestation"): fetch_attestation,
                      (tf_client, "fetch_attestation_bundle"): fetch_attestation_bundle,
                      (tf_sigstore, "fetch_latest_digest"): fetch_latest_digest}
    return state


def _verify(host: str, out: dict) -> None:
    """One SDK verification as TinfoilAdapter runs it (tinfoil.py _guarded_verify_locked): the SDK's fetches,
    inside capture_sink() and overrides(_capture_hooks())."""
    from tinfoil import client as tf_client, sigstore as tf_sigstore

    from confidential_mode.verify.tinfoil import _capture_hooks
    with _sdkpatch.capture_sink() as sink:
        out["sink"] = sink
        with _sdkpatch.overrides(_capture_hooks()):
            tf_client.fetch_attestation(host)
            tf_sigstore.fetch_latest_digest(f"repo-{host}")
            tf_client.fetch_attestation_bundle(f"repo-{host}", "d")


def _restored(sdk) -> None:
    for (owner, attr), fake in sdk["fakes"].items():
        assert getattr(owner, attr) is fake, attr
    assert _sdkpatch.installed_now() == []
    assert _sdkpatch._windows == {}


def _evidence_of(host: str, sink: dict) -> None:
    assert sink["attestation"] == {"format": "fake-format", "body": f"body-of-{host}"}
    assert sink["hardware_measurements"] == {"repo": f"repo-{host}", "digest": f"digest-of-repo-{host}"}
    assert sink["sigstore_bundle"] == f"bundle-of-repo-{host}"
    assert "capture_errors" not in sink


def _run(name, target, *args):
    errors: list = []

    def body():
        try:
            target(*args)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
    t = threading.Thread(target=body, name=name)
    t.start()
    return t, errors


def test_two_threads_verifying_at_once_each_capture_their_own_evidence(sdk):
    """Both threads are inside the window together (each held between two fetches); each sink holds only its
    own thread's evidence, and the wrappers come off once both windows have closed."""
    a_at, a_go, b_at, b_go = (threading.Event() for _ in range(4))
    sdk["gates"][("verify-a", "digest")] = (a_at, a_go)
    sdk["gates"][("verify-b", "bundle")] = (b_at, b_go)
    out_a, out_b = {}, {}
    ta, ea = _run("verify-a", _verify, "a.example", out_a)
    tb, eb = _run("verify-b", _verify, "b.example", out_b)
    assert a_at.wait(5) and b_at.wait(5)            # both inside the window at the same time
    assert _sdkpatch._windows and len(_sdkpatch.installed_now()) >= 3
    a_go.set()
    ta.join(5)
    assert not ta.is_alive()
    assert len(_sdkpatch.installed_now()) >= 3      # b's window is still open: the wrappers stay
    b_go.set()
    tb.join(5)
    assert not tb.is_alive()
    assert ea == [] and eb == []
    _evidence_of("a.example", out_a["sink"])
    _evidence_of("b.example", out_b["sink"])
    _restored(sdk)


def test_a_verify_during_a_background_refresh(sdk):
    """A background refresh opens the window first; a foreground verify opens and closes its own window while
    the refresh is held; the refresh's fetches after that still go through the wrappers and are captured."""
    held, go = threading.Event(), threading.Event()
    sdk["gates"][("refresh", "attestation")] = (held, go)
    out_r, out_v = {}, {}
    tr, er = _run("refresh", _verify, "refresh.example", out_r)
    assert held.wait(5)
    _verify("verify.example", out_v)                # on this thread, inside the refresh's window
    _evidence_of("verify.example", out_v["sink"])
    assert len(_sdkpatch.installed_now()) >= 3      # the refresh's window is still open
    go.set()
    tr.join(5)
    assert not tr.is_alive()
    assert er == []
    _evidence_of("refresh.example", out_r["sink"])
    _restored(sdk)


def test_an_exception_inside_the_window_restores_the_wrappers_and_keeps_the_other_threads_capture(sdk):
    held, go = threading.Event(), threading.Event()
    sdk["gates"][("refresh", "digest")] = (held, go)
    sdk["boom"].add(("attestation", "bad.example"))
    out_r, out_bad = {}, {}
    tr, er = _run("refresh", _verify, "ok.example", out_r)
    assert held.wait(5)
    with pytest.raises(ConnectionError):
        _verify("bad.example", out_bad)
    assert "attestation" not in out_bad["sink"]      # nothing was fetched, nothing was recorded
    assert len(_sdkpatch.installed_now()) >= 3       # the refresh's window keeps the wrappers
    go.set()
    tr.join(5)
    assert not tr.is_alive()
    assert er == []
    _evidence_of("ok.example", out_r["sink"])
    _restored(sdk)
    with pytest.raises(ConnectionError):             # alone in the window: the wrappers still come off
        _verify("bad.example", {})
    _restored(sdk)


def test_a_capture_recorder_that_fails_records_the_error_and_the_verify_goes_on(sdk, monkeypatch):
    from tinfoil import client as tf_client
    monkeypatch.setattr(tf_client, "fetch_attestation", lambda host: object())   # no .format: the recorder fails
    sdk["fakes"][(tf_client, "fetch_attestation")] = tf_client.fetch_attestation
    out: dict = {}
    _verify("odd.example", out)
    sink = out["sink"]
    assert "attestation" not in sink and sink["capture_errors"][0].startswith("attestation: AttributeError")
    assert sink["sigstore_bundle"] == "bundle-of-repo-odd.example"
    _restored(sdk)


# ── fix-pass-3 review finding 7: the adapter's own verify path and the SDK's own verify ─────────────────

class _StopDoc(_Doc):
    """What the faked fetch_attestation returns to the SDK's real SecureClient.verify: its verify() records
    the sink the capture hook filled for this thread, then stops the SDK before any cryptography."""
    seen: dict = {}

    def verify(self):
        sink = _sdkpatch.current_sink()
        _StopDoc.seen[threading.current_thread().name] = dict(sink) if sink is not None else None
        raise RuntimeError("stop after the capture")


def _sdk_client(host):
    """The SDK's own SecureClient, its real verify() method, without its network constructor."""
    from tinfoil.client import SecureClient
    sc = object.__new__(SecureClient)
    sc.attestation_bundle_url, sc.repo, sc.enclave, sc.measurement = None, f"repo-{host}", host, None
    return sc


def _adapter_verify(tmp_path, host):
    from confidential_mode.verify.tinfoil import TinfoilAdapter
    ad = TinfoilAdapter(data_dir=tmp_path / host, enclave=host, tls_probe=False)
    with pytest.raises(RuntimeError, match="stop after the capture"):
        ad._guarded_verify(_sdk_client(host))     # the adapter's path: counters, SDK lock, window, SDK verify
    return ad


def test_the_adapter_verify_path_captures_through_the_sdk_s_own_verify(sdk, monkeypatch, tmp_path):
    from tinfoil import client as tf_client
    monkeypatch.setattr(tf_client, "fetch_attestation", lambda host: _StopDoc(f"body-of-{host}"))
    sdk["fakes"][(tf_client, "fetch_attestation")] = tf_client.fetch_attestation
    _StopDoc.seen.clear()
    ad = _adapter_verify(tmp_path, "adapter.example")
    assert ad.attestation_count == 1
    seen = _StopDoc.seen[threading.current_thread().name]
    assert seen["attestation"] == {"format": "fake-format", "body": "body-of-adapter.example"}
    _restored(sdk)


def test_two_adapters_verifying_at_once_through_the_sdk_capture_their_own(sdk, monkeypatch, tmp_path):
    from tinfoil import client as tf_client
    held, go = threading.Event(), threading.Event()

    def fetch(host):
        if threading.current_thread().name == "adapter-a":
            held.set()
            assert go.wait(5)
        return _StopDoc(f"body-of-{host}")
    monkeypatch.setattr(tf_client, "fetch_attestation", fetch)
    sdk["fakes"][(tf_client, "fetch_attestation")] = fetch
    _StopDoc.seen.clear()
    ta, ea = _run("adapter-a", _adapter_verify, tmp_path, "a.example")
    assert held.wait(5)
    assert len(_sdkpatch.installed_now()) >= 3          # a's window is open
    _adapter_verify(tmp_path, "b.example")              # b opens and closes its own window meanwhile
    assert len(_sdkpatch.installed_now()) >= 3          # a's window keeps the wrappers
    go.set()
    ta.join(5)
    assert not ta.is_alive() and ea == []
    assert _StopDoc.seen["adapter-a"]["attestation"]["body"] == "body-of-a.example"
    assert _StopDoc.seen[threading.current_thread().name]["attestation"]["body"] == "body-of-b.example"
    _restored(sdk)

"""Thread-scoped hooks into tinfoil 0.14.2 internals (evidence capture and offline replay).

The SDK exposes no injection points for its fetchers, its Sigstore verifier or its clock, so capture
and replay wrap module/class attributes. A wrapper exists only while some thread is inside
``overrides()`` for that attribute (Amendment 13): it is installed on entry and the original attribute
is put back when the last such window closes. Inside the window the wrapper is inert unless the CURRENT
THREAD pushed an override: another thread's call (a gateway turn, Hermes' own ``requests`` use) runs the
original function unchanged, and a live verify on another thread during a replay never sees stored
collateral or a pinned clock.

Also redirects the SDK's on-disk caches (see redirect_sdk_caches).
"""
from __future__ import annotations

import contextlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

_local = threading.local()
_install_lock = threading.Lock()
_installed: dict[tuple[int, str], Any] = {}  # (id(owner), attr) -> the wrapper object we installed
_originals: dict[tuple[int, str], tuple[Any, str, Any]] = {}  # (id(owner), attr) -> (owner, attr, what we replaced)
_windows: dict[tuple[int, str], int] = {}    # open overrides() windows per attribute, across threads


def _overrides() -> dict:
    ov = getattr(_local, "overrides", None)
    if ov is None:
        ov = _local.overrides = {}
    return ov


def _key(owner, attr: str) -> tuple[int, str]:
    return (id(owner), attr)


def _dispatch(k, call_raw, *a, **kw):
    """Run this thread's override for k, at most once per call chain: if the attribute got wrapped twice
    (e.g. a second copy of this module, or a re-wrap over a test's monkeypatch), the inner wrapper sees
    the override already active and calls through instead of applying it again."""
    ov = _overrides().get(k)
    active = getattr(_local, "active", None)
    if active is None:
        active = _local.active = set()
    if ov is None or k in active:
        return call_raw(*a, **kw)
    active.add(k)
    try:
        return ov(call_raw, *a, **kw)
    finally:
        active.discard(k)


def install(owner, attr: str) -> None:
    """Install the dispatching wrapper on ``owner.attr`` (a module function, or a class's function,
    classmethod or staticmethod). Idempotent; re-wraps if something (e.g. a test's monkeypatch)
    replaced or restored the attribute since."""
    k = _key(owner, attr)
    with _install_lock:
        raw = owner.__dict__[attr] if isinstance(owner, type) else getattr(owner, attr)
        if _installed.get(k) is raw:
            return
        _originals[k] = (owner, attr, raw)
        if isinstance(owner, type) and isinstance(raw, classmethod):
            func = raw.__func__

            def cm(cls, *a, **kw):
                return _dispatch(k, func.__get__(cls, cls), *a, **kw)
            setattr(owner, attr, classmethod(cm))
            _installed[k] = owner.__dict__[attr]
        elif isinstance(owner, type) and isinstance(raw, staticmethod):
            func = raw.__func__

            def sm(*a, **kw):
                return _dispatch(k, func, *a, **kw)
            setattr(owner, attr, staticmethod(sm))
            _installed[k] = owner.__dict__[attr]
        elif isinstance(owner, type):
            def im(self, *a, **kw):
                return _dispatch(k, raw.__get__(self, type(self)), *a, **kw)
            setattr(owner, attr, im)
            _installed[k] = im
        else:
            def fn(*a, **kw):
                return _dispatch(k, raw, *a, **kw)
            fn.__name__ = getattr(raw, "__name__", attr)
            fn.__wrapped__ = raw
            setattr(owner, attr, fn)
            _installed[k] = fn


def _uninstall(k) -> None:
    """Put the original attribute back, when ours is still the one in place (something that wrapped on top
    keeps its wrapper, which calls through ours). Caller holds _install_lock."""
    entry, wrapper = _originals.get(k), _installed.get(k)
    if entry is None or wrapper is None:
        return
    owner, attr, raw = entry
    current = owner.__dict__.get(attr) if isinstance(owner, type) else getattr(owner, attr, None)
    if current is wrapper:
        setattr(owner, attr, raw)
    _installed.pop(k, None)
    _originals.pop(k, None)


def installed_now() -> list[tuple[Any, str]]:
    """(owner, attr) of every wrapper in place right now (tests, status)."""
    with _install_lock:
        return [(o, a) for (o, a, _r) in _originals.values()]


@contextlib.contextmanager
def overrides(mapping: dict[tuple[Any, str], Callable]) -> Iterator[None]:
    """Push per-thread overrides: {(owner, attr): fn(original, *args, **kwargs)}. Each wrapper is installed on
    entry and removed when the last open window for its attribute closes, so outside these windows the SDK's,
    sigstore's and requests' attributes are their own."""
    ov = _overrides()
    saved = {}
    opened = []
    try:
        for (owner, attr), fn in mapping.items():
            k = _key(owner, attr)
            with _install_lock:
                _windows[k] = _windows.get(k, 0) + 1
            opened.append(k)
            install(owner, attr)
            saved[k] = ov.get(k)
            ov[k] = fn
        yield
    finally:
        for k, prev in saved.items():
            if prev is None:
                ov.pop(k, None)
            else:
                ov[k] = prev
        with _install_lock:
            for k in opened:
                left = _windows.get(k, 1) - 1
                if left <= 0:
                    _windows.pop(k, None)
                    _uninstall(k)
                else:
                    _windows[k] = left


# ── clock pinning ─────────────────────────────────────────────────────────────────────────────

class PinnableDatetime(datetime):
    """Replaces the ``datetime`` global of SDK modules; ``now()`` honours a per-thread pin."""

    @classmethod
    def now(cls, tz=None):
        pinned = getattr(_local, "pinned_now", None)
        if pinned is None:
            return datetime.now(tz)
        return pinned.astimezone(tz) if tz is not None else pinned.replace(tzinfo=None)


_clock_modules_installed: set[int] = set()


def install_clock(*modules) -> None:
    with _install_lock:
        for mod in modules:
            if id(mod) not in _clock_modules_installed and getattr(mod, "datetime", None) is datetime:
                mod.datetime = PinnableDatetime
                _clock_modules_installed.add(id(mod))


@contextlib.contextmanager
def pinned_clock(when: datetime) -> Iterator[None]:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    prev = getattr(_local, "pinned_now", None)
    _local.pinned_now = when
    try:
        yield
    finally:
        _local.pinned_now = prev


def pinned_now() -> datetime | None:
    return getattr(_local, "pinned_now", None)


# ── capture sink ──────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def capture_sink() -> Iterator[dict]:
    prev = getattr(_local, "sink", None)
    sink: dict = {}
    _local.sink = sink
    try:
        yield sink
    finally:
        _local.sink = prev


def current_sink() -> dict | None:
    return getattr(_local, "sink", None)


# ── SDK cache redirection ─────────────────────────────────────────────────────────────────────

SDK_CACHE_SUBDIR = "sdk-cache"


def redirect_sdk_caches(data_dir: Path | str) -> dict[str, str]:
    """Point the SDK's and sigstore-python's on-disk caches under the plugin data dir.

    tinfoil 0.14.2 computes ``platformdirs.user_cache_dir("tinfoil", "tinfoil")`` into module
    constants AT IMPORT (github._GITHUB_CACHE_DIR: Sigstore bundles; verify_sev._VCEK_CACHE_DIR: VCEKs;
    collateral_tdx._TDX_CACHE_DIR: Intel collateral). The functions read those constants at call time,
    so re-pointing them after import redirects every later write. sigstore-python computes its TUF
    dirs per call in sigstore._internal.tuf._get_dirs, which is replaced. Process-wide; returns the
    new paths. (Setting XDG_CACHE_HOME before import also works with platformdirs 4.14 on macOS, but
    it changes every platformdirs user in the Hermes process, so it is not used.)
    """
    base = Path(data_dir) / SDK_CACHE_SUBDIR
    tinfoil_dir = str(base / "tinfoil")
    from tinfoil import github as tf_github
    from tinfoil.attestation import collateral_tdx, verify_sev
    tf_github._GITHUB_CACHE_DIR = tinfoil_dir
    verify_sev._VCEK_CACHE_DIR = tinfoil_dir
    collateral_tdx._TDX_CACHE_DIR = tinfoil_dir
    paths = {"tinfoil": tinfoil_dir}
    try:
        from urllib import parse

        import sigstore._internal.tuf as sg_tuf

        def _get_dirs(url: str):
            repo_base = parse.quote(url, safe="")
            return (base / "sigstore-tuf-metadata" / repo_base), (base / "sigstore-tuf-targets" / repo_base)
        sg_tuf._get_dirs = _get_dirs
        paths["sigstore_tuf"] = str(base)
    except Exception:  # pragma: no cover - sigstore internals moved
        paths["sigstore_tuf"] = "NOT REDIRECTED"
    return paths

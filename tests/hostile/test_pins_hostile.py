"""Hostile tests for W2's PinStore (confidential_mode.pins, pins.yaml v2).

Invariants held throughout: match() never returns True for anything but an intact, current, same-vendor
pin with both fingerprints equal; a failed apply() leaves the file byte-identical and the previous pin
in force; `previous` records the replaced fingerprint.
"""
from __future__ import annotations

import os
import stat
import sys
import threading

import pytest

from . import _harness_client as h
from ._harness_client import _wire, cm  # noqa: F401 - fixtures

A = dict(code=h.FP_CODE, enclave=h.FP_ENCLAVE)
B = dict(code=h.FP_CODE_2, enclave=h.FP_ENCLAVE_2)


def _res(cm, **kw):
    return h.make_result(cm, **kw)


def _pinned_store(cm, tmp_path, which=A):
    store = h.make_store(cm, tmp_path / "pins")
    h.pin(store, _res(cm, **which))
    path = h.pins_file(tmp_path / "pins")
    assert path is not None and path.exists(), "apply() wrote no pins file"
    return store, path


def _fresh(cm, tmp_path):
    return h.make_store(cm, tmp_path / "pins")


def _match_is_false(store, result):
    out = store.match(result)
    assert out is False, f"match returned {out!r}"


def _yaml_load(text):
    import hermes_yaml
    return hermes_yaml.safe_load(text)


# ── missing / corrupt / unknown version ───────────────────────────────────────────────────────


def test_missing_file_matches_nothing(cm, tmp_path):
    store = _fresh(cm, tmp_path)
    _match_is_false(store, _res(cm, **A))
    assert store.pending() is None


def test_written_file_declares_version_2(cm, tmp_path):
    store, path = _pinned_store(cm, tmp_path)
    doc = _yaml_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), doc
    version = next((doc[k] for k in ("version", "schema_version", "schema") if k in doc), None)
    assert str(version) == "2", f"pins.yaml has no v2 marker: {list(doc)}"
    assert h.FP_CODE in path.read_text() and h.FP_ENCLAVE in path.read_text()


@pytest.mark.parametrize("content", [
    b"\x00\xff\xfe garbage \x80\x81",
    b"{{{{ not: yaml: [",
    b"- just\n- a\n- list\n",
    b"",
    b"null\n",
    b"version: 2\npins: 42\n",
    b"version: 2\npins:\n  tinfoil: null\n",
], ids=["binary", "broken-yaml", "list", "empty", "null", "pins-scalar", "pin-null"])
def test_corrupt_file_matches_nothing(cm, tmp_path, content):
    d = tmp_path / "pins"
    d.mkdir()
    (d / "pins.yaml").write_bytes(content)
    try:
        store = _fresh(cm, tmp_path)
    except Exception:
        return  # refusing to load is acceptable; loading and matching is not
    _match_is_false(store, _res(cm, **A))
    _match_is_false(store, _res(cm, code="", enclave=""))


def _rewrite(path, mutate):
    doc = _yaml_load(path.read_text(encoding="utf-8"))
    mutate(doc)
    import hermes_yaml
    path.write_text(hermes_yaml.safe_dump(doc), encoding="utf-8")


def _version_key(doc):
    for k in ("version", "schema_version", "schema"):
        if k in doc:
            return k
    pytest.fail(f"pins.yaml has no top-level version key: {list(doc)}")


@pytest.mark.parametrize("version", [99, 3, 1, "2.0-evil", None])
def test_unknown_version_with_otherwise_matching_pin_matches_nothing(cm, tmp_path, version):
    store, path = _pinned_store(cm, tmp_path)
    assert store.match(_res(cm, **A)) is True  # control

    def mutate(doc):
        key = _version_key(doc)
        if version is None:
            del doc[key]
        else:
            doc[key] = version
    _rewrite(path, mutate)
    try:
        reloaded = _fresh(cm, tmp_path)
    except Exception:
        return
    _match_is_false(reloaded, _res(cm, **A))


def test_truncated_file_never_matches(cm, tmp_path):
    """Cut the file at every point before both fingerprints are complete: never a match."""
    store, path = _pinned_store(cm, tmp_path)
    data = path.read_bytes()
    ends = []
    for fp in (h.FP_CODE, h.FP_ENCLAVE):
        i = data.find(fp.encode())
        if i < 0:
            pytest.skip("fingerprints are not stored in plaintext; truncation attack not applicable")
        ends.append(i + len(fp))
    limit = max(ends)
    for cut in range(0, limit, 3):
        path.write_bytes(data[:cut])
        try:
            s = _fresh(cm, tmp_path)
        except Exception:
            continue
        out = s.match(_res(cm, **A))
        assert out is False, f"truncated at {cut}/{len(data)} still matched"


def test_hand_edited_empty_fingerprints_never_match(cm, tmp_path):
    store, path = _pinned_store(cm, tmp_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(h.FP_CODE, "").replace(h.FP_ENCLAVE, ""), encoding="utf-8")
    try:
        s = _fresh(cm, tmp_path)
    except Exception:
        return
    _match_is_false(s, _res(cm, code="", enclave=""))
    _match_is_false(s, _res(cm, **A))


# ── match() exactness ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("probe", [
    dict(code=h.FP_CODE_2, enclave=h.FP_ENCLAVE),
    dict(code=h.FP_CODE, enclave=h.FP_ENCLAVE_2),
    dict(code=h.FP_ENCLAVE, enclave=h.FP_CODE),
    dict(code=h.FP_CODE[:32], enclave=h.FP_ENCLAVE[:32]),
    dict(code=h.FP_CODE[:32], enclave=h.FP_ENCLAVE),
    dict(code=h.FP_CODE, enclave=h.FP_ENCLAVE[:32]),
    dict(code=h.FP_CODE + "0", enclave=h.FP_ENCLAVE + "0"),
    dict(code="", enclave=h.FP_ENCLAVE),
    dict(code=h.FP_CODE, enclave=""),
    dict(code=" " + h.FP_CODE, enclave=h.FP_ENCLAVE),
    dict(code=h.FP_CODE, enclave=h.FP_ENCLAVE, vendor="evil"),
    dict(code=h.FP_CODE, enclave=h.FP_ENCLAVE, router_repo="evil/router"),
], ids=["code", "enclave", "swapped", "prefix", "code-prefix", "enclave-prefix", "extended", "empty-code", "empty-enclave", "space",
        "vendor", "repo"])
def test_match_is_exact(cm, tmp_path, probe):
    store, _ = _pinned_store(cm, tmp_path)
    assert store.match(_res(cm, **A)) is True
    _match_is_false(store, _res(cm, **probe))
    _match_is_false(_fresh(cm, tmp_path), _res(cm, **probe))


def test_empty_fingerprints_never_match_a_pin(cm, tmp_path):
    empty = _res(cm, code="", enclave="")
    store = _fresh(cm, tmp_path)
    _match_is_false(store, empty)
    try:
        h.pin(store, empty)
    except Exception:
        pass  # refusing to stage/apply an empty fingerprint is the better behaviour
    _match_is_false(store, empty)
    _match_is_false(_fresh(cm, tmp_path), empty)
    none_fp = h.make_result(cm, code=None, enclave=None)  # type-violating adapter output
    try:
        assert store.match(none_fp) is not True
    except Exception:
        pass


# ── apply(): atomicity, unwritable, previous ──────────────────────────────────────────────────


def test_previous_is_preserved_across_applies(cm, tmp_path):
    store, path = _pinned_store(cm, tmp_path)
    rec_b = h.pin(store, _res(cm, **B))
    prev = getattr(rec_b, "previous", None)
    assert prev is not None, "previous not recorded"
    assert h.contains(prev, h.FP_CODE) or h.contains(prev, h.FP_ENCLAVE), prev
    assert store.match(_res(cm, **B)) is True
    _match_is_false(store, _res(cm, **A))
    reloaded = _fresh(cm, tmp_path)
    assert reloaded.match(_res(cm, **B)) is True
    _match_is_false(reloaded, _res(cm, **A))
    text = path.read_text()
    assert h.FP_CODE in text or h.FP_ENCLAVE in text, "previous fingerprint lost from pins.yaml"
    rec_c = h.pin(store, _res(cm, code="aa" * 32, enclave="bb" * 32))
    assert h.contains(rec_c.previous, h.FP_CODE_2) or h.contains(rec_c.previous, h.FP_ENCLAVE_2)
    assert getattr(rec_c, "approved_by", "human") == "human"


def _assert_failed_apply_left_a(cm, tmp_path, path, before: bytes, store):
    assert path.read_bytes() == before, "failed apply() half-wrote pins.yaml"
    reloaded = _fresh(cm, tmp_path)
    assert reloaded.match(_res(cm, **A)) is True, "failed apply() lost the previous pin on disk"
    _match_is_false(reloaded, _res(cm, **B))
    _match_is_false(store, _res(cm, **B))


def test_apply_into_unwritable_location_raises_and_keeps_previous(cm, tmp_path):
    store, path = _pinned_store(cm, tmp_path)
    pending = store.stage(_res(cm, **B))
    before = path.read_bytes()
    d = path.parent
    file_mode, dir_mode = path.stat().st_mode, d.stat().st_mode
    os.chmod(path, stat.S_IRUSR)
    os.chmod(d, stat.S_IRUSR | stat.S_IXUSR)
    try:
        if os.access(path, os.W_OK):
            pytest.skip("running with privileges that ignore file modes")
        with pytest.raises(Exception):
            h.apply(store, pending)
        assert store.match(_res(cm, **A)) is True, "in-memory pin changed although persisting failed"
        _match_is_false(store, _res(cm, **B))
    finally:
        os.chmod(d, dir_mode)
        os.chmod(path, file_mode)
    _assert_failed_apply_left_a(cm, tmp_path, path, before, store)


def _serializer_targets(pins_mod):
    """(owner, attr) pairs for every dump-like function the pins module can reach."""
    targets = []
    for name, val in list(vars(pins_mod).items()):
        if isinstance(val, type(sys)) and val.__name__.split(".")[-1] in ("json", "yaml", "hermes_yaml", "main"):
            for fn in ("dump", "safe_dump", "dumps", "dump_all", "safe_dump_all"):
                if callable(getattr(val, fn, None)):
                    targets.append((val, fn))
        elif callable(val) and getattr(val, "__name__", "") in ("dump", "safe_dump", "dumps"):
            targets.append((pins_mod, name))
    return targets


def test_apply_crash_while_serializing_does_not_half_write(cm, tmp_path, monkeypatch):
    """Serializer writes half its output into the stream it was given, then dies. An implementation that
    opened pins.yaml for writing before serializing leaves a truncated file."""
    store, path = _pinned_store(cm, tmp_path)
    pending = store.stage(_res(cm, **B))
    before = path.read_bytes()
    targets = _serializer_targets(cm.pins_mod)
    assert targets, "no serializer reachable from confidential_mode.pins to inject a failure into"
    with monkeypatch.context() as mp:
        for owner, attr in targets:
            mp.setattr(owner, attr, _dying)
        try:
            h.apply(store, pending)
            raised = False
        except Exception:
            raised = True
    assert raised, "apply() succeeded although every serializer raised: it persisted nothing?"
    _assert_failed_apply_left_a(cm, tmp_path, path, before, store)


def _dying(*args, **kwargs):
    stream = args[1] if len(args) > 1 else (kwargs.get("stream") or kwargs.get("fp"))
    if stream is not None and hasattr(stream, "write"):
        try:
            stream.write("version: 2\npins:\n  tinfoil:\n    code_fingerprint: c0")
        except TypeError:
            stream.write(b"version: 2\npins:\n  tinfoil:\n    code_fingerprint: c0")
    raise OSError("disk died mid-write (hostile injection)")


def test_apply_crash_at_rename_is_all_or_nothing(cm, tmp_path, monkeypatch):
    store, path = _pinned_store(cm, tmp_path)
    pending = store.stage(_res(cm, **B))
    before = path.read_bytes()

    def boom(*a, **k):
        raise OSError("rename failed (hostile injection)")
    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", boom)
        mp.setattr(os, "rename", boom)
        try:
            h.apply(store, pending)
            raised = False
        except Exception:
            raised = True
    if raised:
        _assert_failed_apply_left_a(cm, tmp_path, path, before, store)
    else:  # wrote in place: then it must have fully written B
        reloaded = _fresh(cm, tmp_path)
        assert reloaded.match(_res(cm, **B)) is True
        _match_is_false(reloaded, _res(cm, **A))


# ── vendor confusion, stale pendings ──────────────────────────────────────────────────────────


def test_apply_pending_from_a_different_vendor_never_vouches_for_tinfoil(cm, tmp_path):
    store, path = _pinned_store(cm, tmp_path)
    evil = _res(cm, vendor="evil", **B)
    try:
        pending = store.stage(evil)
        h.apply(store, pending)
    except Exception:
        pass  # refusing cross-vendor pins is fine
    for s in (store, _fresh(cm, tmp_path)):
        _match_is_false(s, _res(cm, **B))  # tinfoil result with evil's fingerprints
        assert s.match(_res(cm, **A)) is True, "cross-vendor apply replaced tinfoil's pin"


def test_vendor_only_pin_store_does_not_match_other_vendor(cm, tmp_path):
    store = _fresh(cm, tmp_path)
    try:
        h.pin(store, _res(cm, vendor="evil", **A))
    except Exception:
        return
    _match_is_false(store, _res(cm, **A))
    _match_is_false(_fresh(cm, tmp_path), _res(cm, **A))


def test_stale_pending_apply_applies_exactly_what_it_names(cm, tmp_path):
    store = _fresh(cm, tmp_path)
    p_a = store.stage(_res(cm, **A))
    p_b = store.stage(_res(cm, **B))
    assert h.contains(store.pending(), h.FP_CODE_2), "pending() is not the latest staged pin"
    try:
        h.apply(store, p_a)
    except Exception:
        _match_is_false(store, _res(cm, **A))
        _match_is_false(store, _res(cm, **B))
        return
    assert store.match(_res(cm, **A)) is True
    _match_is_false(store, _res(cm, **B))


def test_pending_cleared_or_replaced_after_apply(cm, tmp_path):
    store = _fresh(cm, tmp_path)
    p = store.stage(_res(cm, **A))
    h.apply(store, p)
    pend = store.pending()
    assert pend is None or not h.contains(pend, h.FP_CODE), "applied pin still pending"


def test_concurrent_stage_and_apply_never_mixes_records(cm, tmp_path):
    store = _fresh(cm, tmp_path)
    errors: list = []
    applied = {"A": 0, "B": 0}
    barrier = threading.Barrier(2)

    def worker(tag, fps):
        barrier.wait()
        for _ in range(40):
            try:
                p = store.stage(_res(cm, **fps))
                h.apply(store, p)
                applied[tag] += 1
            except Exception as exc:  # stale-pending refusals are tolerated
                errors.append(exc)
    t1 = threading.Thread(target=worker, args=("A", A))
    t2 = threading.Thread(target=worker, args=("B", B))
    t1.start(), t2.start()
    t1.join(60), t2.join(60)
    assert not t1.is_alive() and not t2.is_alive(), "deadlock in stage/apply"
    assert applied["A"] + applied["B"] > 0, f"every apply failed: {errors[:3]}"
    hybrids = [dict(code=h.FP_CODE, enclave=h.FP_ENCLAVE_2), dict(code=h.FP_CODE_2, enclave=h.FP_ENCLAVE)]
    for s in (store, _fresh(cm, tmp_path)):
        got = [s.match(_res(cm, **A)), s.match(_res(cm, **B))]
        assert got.count(True) == 1, f"after the race: match(A), match(B) = {got}"
        for hy in hybrids:
            _match_is_false(s, _res(cm, **hy))
    mem = [store.match(_res(cm, **A)), store.match(_res(cm, **B))]
    disk_store = _fresh(cm, tmp_path)
    disk = [disk_store.match(_res(cm, **A)), disk_store.match(_res(cm, **B))]
    assert mem == disk, f"in-memory pin {mem} disagrees with pins.yaml {disk}"

"""``hermes confidential replay``: check a receipt's evidence and signed sends offline.

``cli_replay`` replays each ``verify_ok`` row's evidence with verify/replay.py (Tinfoil) or
verify/replay_near.py (NEAR), checks it against the pins file or the fingerprints given, and replays
every ``send_signed`` row's signature; any failure makes the exit code 1.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from typing import Any, cast

from .commands_common import _short

DEFAULT_EXPECTED_REPO = "tinfoilsh/confidential-model-router"


def _replay_module():
    return importlib.import_module(__package__ + ".verify.replay")


def _near_replay_module():
    return importlib.import_module(__package__ + ".verify.replay_near")


def _call_replay(replay_fn: Callable[..., Any], evidence: dict, *, expected_repo: str,
                 expected_fingerprints: tuple | None, trusted_root: str | None, as_of: str | None,
                 expected_repo_id: str | None = None, expected_owner_id: str | None = None):
    """Call replay with the keyword arguments it accepts. Returns (result, notes) where notes lists the
    identity checks this replay version cannot do (they are then done here, on the result fields)."""
    import inspect
    params: Mapping[str, inspect.Parameter]
    try:
        params = inspect.signature(replay_fn).parameters
        var_kw = any(p.kind is p.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        params, var_kw = {}, False

    def takes(name: str) -> bool:
        return var_kw or name in params

    kwargs: dict = {}
    notes: list[str] = []
    if as_of:
        kwargs["as_of"] = as_of
    if takes("expected_repo"):
        kwargs["expected_repo"] = expected_repo
    else:
        notes.append("expected_repo")
    if expected_fingerprints:
        if takes("expected_fingerprints"):
            kwargs["expected_fingerprints"] = expected_fingerprints
        else:
            notes.append("expected_fingerprints")
    # Numeric Fulcio Source Repository / Owner IDs (OIDs 1.3.6.1.4.1.57264.1.15 / .17): passed only when the
    # installed replay accepts them; otherwise the row fails (names can be renamed or transferred).
    for name, value in (("expected_repo_id", expected_repo_id), ("expected_owner_id", expected_owner_id)):
        if value:
            if takes(name):
                kwargs[name] = value
            else:
                notes.append(name)
    if trusted_root:
        if takes("trusted_root"):
            kwargs["trusted_root"] = trusted_root
        elif takes("trust_root_dir"):
            path = os.path.abspath(trusted_root)
            kwargs["trust_root_dir"] = path if os.path.isdir(path) else os.path.dirname(path)
        else:
            notes.append("trusted_root")
    return replay_fn(evidence, **kwargs), notes


def _row_vendor(doc: dict, row_id: Any) -> str | None:
    for row in doc.get("rows") or []:
        if isinstance(row, dict) and row.get("id") == row_id:
            d = cast(dict, row.get("detail")) if isinstance(row.get("detail"), dict) else {}
            return d.get("vendor")
    return None


def _row_claims(doc: dict, row_id: Any) -> tuple[str | None, str | None]:
    for row in doc.get("rows") or []:
        if isinstance(row, dict) and row.get("id") == row_id:
            d = cast(dict, row.get("detail")) if isinstance(row.get("detail"), dict) else {}
            return d.get("code_fingerprint"), d.get("enclave_fingerprint")
    return None, None


def _parse_fingerprints(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    code, sep, enclave = value.partition(":")
    code, enclave = code.strip().lower(), enclave.strip().lower()
    if not sep or not code or not enclave or any(c not in "0123456789abcdef" for c in code + enclave):
        raise ValueError("expected CODE:ENCLAVE (hex fingerprints)")
    return code, enclave


def _default_pins_path(rt: Any) -> str | None:
    pins = getattr(rt, "pins", None) if rt is not None else None
    path = getattr(pins, "path", None)
    return str(path) if path else None


def _expected_for_row(*, flag: tuple | None, pin_records: Any | None, pins_path: str | None,
                      vendor: str, expected_repo: str, claimed: tuple) -> tuple[tuple | None, str, list]:
    """(expected fingerprints, source text, approved set). Order: --expected-fingerprints, the human-approved
    pins for (vendor, expected repo), and only then the receipt's own claim (which checks the self-report
    against itself and is labelled so). ``pin_records`` is a list of approved entries (or the older mapping).
    When the approved set holds per-CVM entries (NEAR), no single pair is expected: the third value is the
    set, and the caller checks every CVM of the replayed result against it (Amendment 7)."""
    if flag:
        return flag, "--expected-fingerprints", []
    recs = pin_records.values() if isinstance(pin_records, dict) else (pin_records or [])
    ents = [r for r in recs if (r.vendor, r.router_repo) == (vendor, expected_repo)]
    if ents and any(getattr(r, "cvm_role", "router") not in ("router", "result") for r in ents):
        return None, (f"the approved set in {pins_path} ({len(ents)} entries; every CVM of the row is checked "
                      "against it)"), ents
    if ents:
        rec = ents[-1]
        return ((rec.code_fingerprint, rec.enclave_fingerprint),
                f"the pin in {pins_path} (approved by {rec.approved_by} at {rec.approved_at} via {rec.approved_via})",
                [])
    if all(claimed):
        return tuple(claimed), "taken from the receipt itself (not independent)", []
    return None, "none available (no flag, no pin for this vendor/repo, no claim in the receipt)", []


def cli_replay(args: Any, out=None, replay_fn: Callable[..., Any] | None = None, rt: Any = None) -> int:
    """`hermes confidential replay <receipt.json>`: re-run every evidence blob in a receipt offline.
    Exit 0 only when the hash chain is intact and every row replays ok AND matches the expected repo and
    the expected fingerprints
    (from --expected-fingerprints, else the approved pin in --pins / the profile's pins.yaml, else, labelled
    as not independent, the receipt's own row)."""
    out = out or sys.stdout
    try:
        flag_fps = _parse_fingerprints(getattr(args, "expected_fingerprints", None))
    except ValueError as exc:
        out.write(f"--expected-fingerprints: {exc}\n")
        return 2
    pins_arg = getattr(args, "pins", None)
    pins_path = pins_arg or _default_pins_path(rt)
    pin_records: list | dict | None = None
    pins_note = ""
    if pins_path and not flag_fps:
        try:
            from .pins import PinStore
            if pins_arg and not os.path.exists(pins_arg):
                raise FileNotFoundError(pins_arg)
            pin_records = PinStore(pins_path).approved_entries()
        except Exception as exc:  # noqa: BLE001
            if pins_arg:
                out.write(f"Cannot read pins {pins_arg!r}: {type(exc).__name__}: {exc}\n")
                return 2
            pins_note = f" (could not read {pins_path}: {type(exc).__name__})"
    path: Any = getattr(args, "receipt", None)   # a required argument
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        out.write(f"Cannot read receipt {path!r}: {type(exc).__name__}: {exc}\n")
        return 2
    if not isinstance(doc, dict):
        out.write("Not a receipt: the JSON is not an object.\n")
        return 2
    mod = _replay_module()
    replay_fn = replay_fn or mod.replay
    not_established = tuple(getattr(mod, "NOT_ESTABLISHED", ()) or ())
    expected_repo = getattr(args, "expected_repo", None) or DEFAULT_EXPECTED_REPO
    trusted_root = getattr(args, "trusted_root", None)
    as_of = getattr(args, "as_of", None)
    chain_ok = False
    try:
        from .receipts import verify_chain
        chain_ok = verify_chain(doc) is True
        chain = "intact" if chain_ok else "BROKEN (receipt edited, or rows no longer match)"
    except Exception as exc:  # noqa: BLE001
        chain = f"not checked ({type(exc).__name__})"
    items = [i for i in (doc.get("evidence") or []) if isinstance(i, dict) and isinstance(i.get("evidence"), dict)]
    out.write(f"Receipt: {path}  session {(doc.get('header') or {}).get('session_id', '?')}  hash chain {chain}\n")
    out.write(f"Expected repo: {expected_repo}\n")
    for flag_name, label in (("expected_repo_id", "Expected repo id"), ("expected_owner_id", "Expected owner id")):
        if getattr(args, flag_name, None):
            out.write(f"{label}: {getattr(args, flag_name)}\n")
    out.write("Expected fingerprints: " + ("--expected-fingerprints" if flag_fps else
                                           f"pins {pins_path}{pins_note}" if pins_path else "no pins file")
              + " (per row below)\n")
    out.write("Trust root: " + (f"{trusted_root} (supplied with --trusted-root)" if trusted_root else
                                "the copy recorded in the evidence (chosen by whoever captured it, not independent)")
              + "\n")
    out.write("as_of: " + (f"{as_of} (supplied with --as-of)" if as_of else
                           "the evidence's captured_at (recorded by the capturer, not independent)") + "\n")
    if not items:
        out.write("No evidence rows in this receipt: nothing can be replayed.\n")
        return 1
    failed = 0
    near_ne: tuple = ()
    seen_rows = False
    for item in items:
        ev = item["evidence"]
        if isinstance(item.get("blobs"), dict):   # NEAR v2: large texts travel beside the evidence
            ev = _near_replay_module().with_blobs(ev, item["blobs"])
        row_id = item.get("row_id")
        claimed = _row_claims(doc, row_id)
        vendor = str(_row_vendor(doc, row_id) or ev.get("vendor") or "tinfoil")
        row_repo, row_replay = expected_repo, replay_fn
        if ev.get("schema") in _near_replay_module().EVIDENCE_SCHEMAS:
            # NEAR (Amendment 5): the pin identity is "<host>#<models>"; --expected-repo overrides it only
            # when given explicitly.
            vendor, row_replay = "near", _near_replay_module().replay
            row_repo = expected_repo if expected_repo != DEFAULT_EXPECTED_REPO else str(ev.get("repo") or "")
        fps, fps_source, approved_set = _expected_for_row(flag=flag_fps, pin_records=pin_records,
                                                          pins_path=pins_path, vendor=vendor,
                                                          expected_repo=row_repo, claimed=claimed)
        try:
            result, notes = _call_replay(row_replay, ev, expected_repo=row_repo, expected_fingerprints=fps,
                                         trusted_root=trusted_root, as_of=as_of,
                                         expected_repo_id=getattr(args, "expected_repo_id", None),
                                         expected_owner_id=getattr(args, "expected_owner_id", None))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            out.write(f"\nRow #{row_id}: FAIL (replay raised {type(exc).__name__}: {exc})\n")
            continue
        problems: list[str] = []
        repo = getattr(result, "repo", None) or ev.get("repo") or ""
        host = getattr(result, "enclave_host", None) or getattr(result, "host", None) or ev.get("enclave_host") or ""
        platform = getattr(result, "platform", None) or (ev.get("attestation") or {}).get("format") or ""
        if "expected_repo" in notes and repo != row_repo:
            problems.append(f"repo {repo or '(none)'} is not the expected {row_repo}")
        if fps and "expected_fingerprints" in notes:
            got = (getattr(result, "code_fingerprint", None), getattr(result, "enclave_fingerprint", None))
            if got != tuple(fps):
                problems.append(f"replayed fingerprints do not match the expected ones ({fps_source})")
        for name in ("expected_repo_id", "expected_owner_id"):
            if name in notes:
                problems.append(f"this replay version cannot check --{name.replace('_', '-')}")
        if approved_set:
            from .pins import set_match, views_from_cvms
            hit = set_match(approved_set, vendor=vendor, code=getattr(result, "code_fingerprint", None),
                            enclave=getattr(result, "enclave_fingerprint", None),
                            views=views_from_cvms(list(getattr(result, "cvms", ()) or ())))
            if not hit:
                problems.append(f"a CVM in this row has no approved entry ({fps_source})")
        elif fps is None:
            problems.append("no expected fingerprints: identity not checked")
        if "trusted_root" in notes:
            problems.append("this replay version cannot take --trusted-root; the evidence's own trust root was used")
        if item.get("unverified_entry"):
            problems.append("the receipt flags this row as an unverified entry")
        ok = getattr(result, "ok", False) is True and not problems
        failed += 0 if ok else 1
        out.write(f"\nRow #{row_id}: {'OK' if ok else 'FAIL'}\n")
        captured = getattr(result, "captured_at", None) or ev.get("captured_at") or ev.get("captured_at_unix") or ""
        out.write(f"  repo: {repo or '(none)'}  platform: {platform or '(unknown)'}"
                  + (f"  schema: {ev.get('schema')}" if ev.get("schema") else "") + "\n")
        out.write(f"  enclave_host: {host or '(none)'} (asserted by capturer)\n")
        out.write(f"  captured_at: {captured or '(none)'} (asserted by capturer)\n")
        out.write(f"  expected fingerprints: {fps_source}\n")
        out.write(f"  as_of: {getattr(result, 'as_of', '?')}  sdk: {getattr(result, 'sdk_version', '?')}  "
                  f"release: {getattr(result, 'release_tag', None) or '(untagged)'}\n")
        out.write(f"  code {_short(getattr(result, 'code_fingerprint', None), 16)}  "
                  f"enclave {_short(getattr(result, 'enclave_fingerprint', None), 16)}\n")
        from .verify.near_checks import render_if_needed
        for key, value in (getattr(result, "checks", {}) or {}).items():
            out.write(f"  {key}: {'pass' if value is True else render_if_needed(value)}\n")
        for p in problems:
            out.write(f"  ! {p}\n")
        row_ne = tuple(getattr(result, "not_established", ()) or ())
        if row_ne:
            # a receipt can mix vendors and evidence schemas: every row's caveats are printed (their union)
            not_established = (not_established if seen_rows else ()) + row_ne
            seen_rows = True
            if vendor == "near":
                near_ne = near_ne + row_ne
    signed_failed = 0
    near = None
    if any(isinstance(r, dict) and r.get("kind") == "send_signed" for r in doc.get("rows") or []):
        near = _near_replay_module().replay_receipt(doc)
        out.write("\nSigned responses (NEAR AI Cloud):\n")
        for snd in near["sends"]:
            mark = "OK" if snd["verdict"] == "pass" else snd["verdict"].upper()
            tee = "provider_tee" if snd["provider_tee"] else (snd["kind"] or "no signature")
            enc = ("  signature verified over the ciphertext digests (third-party checkable); request "
                   "encrypted (plugin self-report)") if snd.get("near_e2ee") and snd["verdict"] == "pass" else ""
            out.write(f"  Row #{snd['row']}: {mark}  {tee}  id {snd['chat_id'] or '(none)'}"
                      f"{'' if snd['verdict'] == 'pass' else '  ' + str(snd['reason'] or '')}{enc}\n")
            signed_failed += 0 if snd["verdict"] == "pass" else 1
        out.write("  Session fully attested: " + ("yes" if near["fully_attested"] else
                                                   "NO (not every NEAR send has a provider_tee signature that replays)")
                  + "\n")
        not_established = tuple(not_established) + tuple(near_ne or _near_replay_module().NOT_ESTABLISHED)
    out.write("\nA replay does NOT establish:\n")
    for line in dict.fromkeys(not_established):
        out.write(f"  - {line}\n")
    out.write(f"\n{len(items) - failed}/{len(items)} evidence row(s) replayed OK.\n")
    if near is not None:
        out.write(f"{len(near['sends']) - signed_failed}/{len(near['sends'])} signed response(s) replayed OK.\n")
    if not chain_ok:
        # Review finding 10: a receipt whose rows no longer match their hash chain fails the replay, even
        # when every evidence blob in it replays.
        out.write(f"Hash chain {chain}: the replay fails.\n")
    return 1 if (failed or signed_failed or not chain_ok) else 0

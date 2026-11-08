"""NEAR AI Cloud appraisal: every check over one evidence document, shared by the live verify and the
offline replay.

``appraise`` runs the gateway quote, TLS binding, Intel Trust Authority, model quote and compose-manager
checks (the check functions are in near_checks.py) and computes the pin identity, the code and enclave
fingerprints and the component lines. ``evidence_claims`` is what a ``verify_ok`` ledger row carries.
The adapter (near.py) and replay_near.py call ``appraise`` on the same document.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from . import near_checks as nc
from .near_evidence import (
    BLOB_REF,
    EVIDENCE_SCHEMA,
    EVIDENCE_SCHEMA_V1,
    EVIDENCE_SCHEMAS,
    blob_text,
    put_blob,
    resolve_blobs,
)

DEFAULT_ACCEPTED_TCB = ("UpToDate",)


CHECK_KEYS = ("schema", "gateway_quote", "gateway_tls_binding", "ita_jwks", "ita_gateway_token",
              "model_quotes", *nc.CM_CHECK_KEYS, "ita_model_tokens", "fingerprints")
# cm_image records the compose-manager image the actions log reports beside the one the measured compose
# names. It is never scored: the log is operator-reported, so neither an equal nor a different image is a
# pass, and a difference never fails verification (the log records a launcher swap on every instance seen,
# 2026-11-07).
INFORMATIONAL_CHECKS = ("ita_model_tokens", "cm_image")
CM_NOT_RUN_V1 = "n/a: not run (evidence schema v1 carries no compose-manager attestation)"


@dataclass(frozen=True)
class Appraisal:
    ok: bool
    checks: dict
    code_fingerprint: str | None = None
    enclave_fingerprint: str | None = None
    identity: str | None = None
    gateway_signer: str | None = None
    model_signers: dict = field(default_factory=dict)
    components: tuple = ()
    tcb_status: str | None = None
    first_failure: str | None = None
    # per CVM: role, app_id, instance_id, compose_hash, signing_address, os_image_hash, kms_id, services (the
    # whole per-service map), services_sha256, services_first, services_scope, cm_image_reported,
    # cm_image_measured (v2 evidence; the services and image keys are None for the gateway)
    cvms: tuple = ()


def identity_for(host: str, models: list[str]) -> str:
    return f"{host}#{','.join(sorted(models)) if models else 'gateway-only'}"


def _measure(q: Mapping) -> str:
    return ":".join(str(q.get(k) or "") for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2"))


def _cvm(role: str, rep: Mapping, ident: Mapping | None = None, cm: Mapping | None = None,
         quote: Mapping | None = None) -> dict:
    """What identifies one CVM in the evidence. With v2 evidence, app_id, instance_id, os_image_hash and
    kms_id come from the RTMR3 boot events (``ident``), and a model CVM adds what its compose-manager
    reported (``cm``). ``measurement`` is that CVM's own "MRTD:RTMR0:RTMR1:RTMR2" from its verified quote
    (per-CVM pin entries, Amendment 7)."""
    ident = ident or {}
    cm = cm or {}
    return {"role": role, "measurement": _measure(quote) if quote is not None else None,
            "app_id": ident.get("app_id", rep.get("app_id")),
            "instance_id": ident.get("instance_id", rep.get("instance_id")),
            "compose_hash": rep.get("compose_hash"), "signing_address": str(rep.get("signing_address") or "").lower(),
            "os_image_hash": ident.get("os_image_hash"), "kms_id": ident.get("kms_id"),
            "services": cm.get("services"), "services_sha256": cm.get("services_sha256"),
            "services_first": cm.get("services_first"), "services_scope": cm.get("services_scope"),
            "cm_image_reported": cm.get("cm_image_reported"), "cm_image_measured": cm.get("cm_image_measured")}


def _app_name(composes: Mapping, h: str | None) -> str:
    try:
        name = json.loads(composes.get(h) or "{}").get("name")
        return f" ({name})" if isinstance(name, str) and name else ""
    except Exception:
        return ""


def verified_blobs(evidence: Mapping) -> dict:
    """The evidence's blobs whose SHA-256 is their id (a blob that does not hash to its id is dropped, so
    every check that needs it fails)."""
    blobs = cast(Mapping, evidence.get("blobs")) if isinstance(evidence.get("blobs"), Mapping) else {}
    return {k: v for k, v in blobs.items()
            if isinstance(k, str) and isinstance(v, str) and nc.sha256_hex(v.encode("utf-8")) == k}


def _image_text(ref: str | None) -> str:
    return ref if ref else "(none named)"


# Component line prefixes. A line without one is pinned (it feeds the fingerprints). "reported: " lines are
# what a model CVM's compose-manager log reported, shown for review and not pinned; "reported-other: " lines
# are the services the per-model name list does not put first (the prompt may fold them into a count that
# points at `hermes confidential pins`, which prints them all).
REPORTED = "reported: "
REPORTED_OTHER = "reported-other: "


def _service_line(key: str, v: Mapping) -> str:
    return (f"{key} {v.get('tag') if v.get('tag') is not None else '(no tag)'} commit {v.get('commit')} "
            f"file sha256:{v.get('file_sha256')}")


def _cvm_lines(c: Mapping) -> list[str]:
    """Pin-prompt lines for one CVM (v2 evidence). They hold raw values and full digests; whoever shows
    them to a person renders each line with near_checks.render_vendor."""
    role = c["role"].replace("model:", "model ", 1)
    iid = c.get("instance_id")
    out = [f"{role} instance {iid}: app_id {c.get('app_id')}, OS image {c.get('os_image_hash')}, "
           f"KMS key sha256:{c.get('kms_id')} (recorded in RTMR3; pinned; the instance id is shown only)"]
    services = c.get("services")
    if not isinstance(services, Mapping):
        return out
    first = [k for k in (c.get("services_first") or []) if k in services]
    others = [k for k in sorted(services) if k not in first]
    out.append(f"{REPORTED}{role} instance {iid}: {len(services)} services in the log (whole map sha256:"
               f"{c.get('services_sha256')}); {len(first)} {c.get('services_scope')}:")
    out += [f"{REPORTED}  {_service_line(k, services[k])}" for k in first]
    out.append(f"{REPORTED}{role} instance {iid}: {len(others)} other services (listed in full by "
               "the command hermes confidential pins)" + (":" if others else ""))
    out += [f"{REPORTED_OTHER}  {_service_line(k, services[k])}" for k in others]
    rep, meas = c.get("cm_image_reported"), c.get("cm_image_measured")
    out.append(f"{REPORTED}{role} instance {iid}: compose-manager image reported by the log; the log is "
               "operator-reported, not verified" + ("" if rep and rep == meas else " (the two differ)") + ":")
    out.append(f"{REPORTED}  reported by the log: {_image_text(rep)}")
    out.append(f"{REPORTED}  in the measured compose: {_image_text(meas)}")
    return out


def condensed_components(components) -> list[str]:
    """The component lines without the REPORTED_OTHER ones (what a verify_ok row keeps inline)."""
    return [c for c in components if not str(c).startswith(REPORTED_OTHER)]


def appraise(evidence: Mapping, *, as_of: float | None = None, quote_verifier: nc.QuoteVerifier | None = None,
             ita_roots: Mapping[str, str] | None = None, accepted_tcb=DEFAULT_ACCEPTED_TCB,
             require_tls_binding: bool = True, require_compose_manager: bool = True) -> Appraisal:
    """Every check over one evidence blob, offline. Values: True, or "fail: ...", "n/a: ...",
    "not_run: ..."; informational checks never decide ``ok``. Schema v1 evidence is appraised under v1
    rules: the compose-manager checks are reported as not run, and identity values are not bound to RTMR3.
    ``require_compose_manager`` (the adapter passes require_provider_tee) makes a model candidate without a
    compose_manager_attestation fail."""
    checks: dict[str, Any] = {k: "not_run: an earlier check failed" for k in CHECK_KEYS}
    qv = quote_verifier or nc.default_quote_verifier
    roots = ita_roots if ita_roots is not None else nc.ITA_ROOT_SHA256
    out: dict[str, Any] = {"model_signers": {}}

    def done(fail: str | None = None) -> Appraisal:
        ok = all(v is True or (isinstance(v, str) and v.startswith("n/a")) for k, v in checks.items()
                 if k not in INFORMATIONAL_CHECKS)
        return Appraisal(ok=ok and fail is None, checks=checks, first_failure=fail, **out)

    if not isinstance(evidence, Mapping) or evidence.get("schema") not in EVIDENCE_SCHEMAS:
        checks["schema"] = f"fail: not {' or '.join(EVIDENCE_SCHEMAS)}"
        return done(checks["schema"])
    if evidence.get("signing_algo") != nc.SIGNING_ALGO:
        checks["schema"] = "fail: signing_algo is not ed25519"
        return done(checks["schema"])
    checks["schema"] = True
    v1 = evidence.get("schema") == EVIDENCE_SCHEMA_V1
    nonce = str(evidence.get("nonce") or "")
    if v1:
        composes = (cast(Mapping, evidence.get("app_composes"))
                    if isinstance(evidence.get("app_composes"), Mapping) else {})
        for k in nc.CM_CHECK_KEYS:
            checks[k] = CM_NOT_RUN_V1
    else:
        composes = verified_blobs(evidence)
        evidence = {k: (resolve_blobs(v, composes) if k in ("gateway", "model_reports", "ita") else v)
                    for k, v in evidence.items()}
    at = float(as_of if as_of is not None else evidence.get("captured_at_unix") or 0)
    models = [m for m in (evidence.get("models") or []) if isinstance(m, str)]

    def ident(rep: Mapping) -> dict | None:
        return None if v1 else nc.rtmr3_identity(rep)

    gw = cast(Mapping, evidence.get("gateway")) if isinstance(evidence.get("gateway"), Mapping) else None
    try:
        if gw is None:
            raise nc.CheckError("no gateway report captured")
        gwq = nc.check_report(gw, nonce=nonce, app_composes=composes, quote_verifier=qv,
                              tls_cert_fingerprint=gw.get("tls_cert_fingerprint"))
        cvms = [_cvm("gateway", gw, ident(gw), quote=gwq)]
        checks["gateway_quote"] = True
        out["gateway_signer"] = str(gw.get("signing_address")).lower()
    except Exception as exc:
        checks["gateway_quote"] = f"fail: {exc}"[:320]
        return done(checks["gateway_quote"])

    obs = (cast(Mapping, evidence.get("tls_observation"))
           if isinstance(evidence.get("tls_observation"), Mapping) else None)
    fp = (gw.get("tls_cert_fingerprint") or "").lower()
    if obs and obs.get("spki_sha256"):
        checks["gateway_tls_binding"] = True if fp and str(obs["spki_sha256"]).lower() == fp else \
            "fail: the TLS certificate this client saw is not the one the gateway quote binds"
    elif require_tls_binding:
        checks["gateway_tls_binding"] = "fail: no TLS peer certificate was recorded"
    else:
        checks["gateway_tls_binding"] = "n/a: TLS binding not required by config"

    ita = cast(Mapping, evidence.get("ita")) if isinstance(evidence.get("ita"), Mapping) else {}
    try:
        keys = nc.jwks_keys(evidence.get("jwks") or {}, roots=roots, at=nc.utc(at))
        checks["ita_jwks"] = True
    except Exception as exc:
        checks["ita_jwks"] = f"fail: {exc}"[:320]
        keys = None
    if keys is not None:
        try:
            claims = nc.verify_jwt(ita.get("gateway_token") or "", keys, at=at)
            t = nc.tdx_claims(claims)
            if t.get("attester_type") != "TDX":
                raise nc.CheckError(f"attester_type {t.get('attester_type')!r} is not TDX")
            if t.get("tdx_is_debuggable") is not False:
                raise nc.CheckError("Intel reports the gateway TD as debuggable (or does not say)")
            status = t.get("attester_tcb_status")
            out["tcb_status"] = status if isinstance(status, str) else None
            if status not in tuple(accepted_tcb):
                raise nc.CheckError(f"TCB status {status!r} not accepted ({', '.join(accepted_tcb)})")
            rd = (cast(Mapping, t.get("attester_runtime_data"))
                  if isinstance(t.get("attester_runtime_data"), Mapping) else {})
            if str(rd.get("caller_nonce") or "").lower() != nonce.lower():
                raise nc.CheckError("ITA runtime data does not carry the client nonce")
            if str(rd.get("signing_address") or "").lower() != out["gateway_signer"] or \
                    rd.get("signing_algo") != nc.SIGNING_ALGO:
                raise nc.CheckError("ITA runtime data names another gateway signing key")
            for claim, field_ in (("tdx_mrconfigid", "mr_config_id"), ("tdx_mrtd", "mrtd"), ("tdx_rtmr0", "rtmr0"),
                                  ("tdx_rtmr1", "rtmr1"), ("tdx_rtmr2", "rtmr2")):
                if str(t.get(claim) or "").lower() != str(gwq.get(field_) or "").lower():
                    raise nc.CheckError(f"ITA {claim} differs from the gateway quote")
            checks["ita_gateway_token"] = True
        except Exception as exc:
            checks["ita_gateway_token"] = f"fail: {exc}"[:320]

    model_quotes: dict[str, list] = {}
    idents: dict[tuple, dict | None] = {}
    try:
        for model in models:
            cands = (evidence.get("model_reports") or {}).get(model) or []
            if not cands:
                raise nc.CheckError(f"no model report for {model}")
            for i, cand in enumerate(cands):
                if cand.get("model_name") not in (None, model):
                    raise nc.CheckError(f"{model}[{i}]: report names model {cand.get('model_name')!r}")
                try:
                    q = nc.check_report(cand, nonce=nonce, app_composes=composes, quote_verifier=qv,
                                        require_signing_public_key=True)
                    idents[(model, i)] = ident(cand)
                except nc.CheckError as exc:
                    raise nc.CheckError(f"{model}[{i}]: {exc}") from exc
                model_quotes.setdefault(model, []).append((cand, q))
            signers = sorted({str(c.get("signing_address")).lower() for c, _ in model_quotes[model]})
            if len(signers) != 1:
                # Requests are encrypted to the model key and signatures are judged against it: candidates
                # naming different keys are refused, never resolved by picking one.
                raise nc.CheckError(f"{model}: its {len(model_quotes[model])} verified reports name {len(signers)} "
                                    "different signing keys; refused rather than picking one")
            out["model_signers"][model] = signers
        checks["model_quotes"] = True if models else "n/a: no model allowlisted (gateway only)"
    except Exception as exc:
        checks["model_quotes"] = f"fail: {exc}"[:320]

    cm_results: dict[tuple, dict] = {}
    if not v1 and checks["model_quotes"] is True:
        cm_results = _compose_manager_checks(checks, evidence, composes, models, model_quotes, nonce=nonce,
                                             quote_verifier=qv, required=require_compose_manager)
    elif not v1 and str(checks["model_quotes"]).startswith("n/a"):
        for k in nc.CM_CHECK_KEYS:
            checks[k] = "n/a: no model allowlisted (gateway only)"

    if keys is None or not ita.get("model_tokens"):
        checks["ita_model_tokens"] = "n/a: no model-provider token captured"
    else:
        notes = []
        for model, tokens in (ita.get("model_tokens") or {}).items():
            for tok in tokens or []:
                try:
                    c = nc.verify_jwt(tok, keys, at=at)
                    gpu = (c.get("nvgpu") or {}).get("x-nvidia-overall-att-result")
                    notes.append(f"{model}: GPU verdict {gpu!r}")
                except Exception as exc:
                    notes.append(f"{model}: {exc}")
        checks["ita_model_tokens"] = ("recorded (its TDX claims are the gateway's; not bound to the model CVM): "
                                      + "; ".join(notes))[:320]

    if all(checks[k] is True or str(checks[k]).startswith("n/a") for k in ("gateway_quote", "model_quotes")):
        for m in models:
            for i, (c, q) in enumerate(model_quotes.get(m, [])):
                cvms.append(_cvm(f"model:{m}", c, idents.get((m, i)), cm_results.get((m, i)), quote=q))
        code: dict[str, Any] = {"gateway": [gw.get("compose_hash")],
                "models": {m: sorted({c.get("compose_hash") for c, _ in model_quotes.get(m, [])}) for m in models}}
        if not v1:
            # v2: the code fingerprint also pins each CVM's app_id, OS image and KMS key as RTMR3 records them.
            # The instance id, the reported services and the log-reported image are shown, not pinned.
            ids = lambda cs: sorted({f"{c['app_id']}:{c['os_image_hash']}:{c['kms_id']}" for c in cs})  # noqa: E731
            code["identity"] = {"gateway": ids(cvms[:1]),
                                "models": {m: ids([c for c in cvms if c["role"] == f"model:{m}"]) for m in models}}
        enclave = {"gateway": [_measure(gwq)],
                   "models": {m: sorted({_measure(q) for _, q in model_quotes.get(m, [])}) for m in models}}
        out["code_fingerprint"] = nc.sha256_hex(nc.canonical(code).encode("utf-8"))
        out["enclave_fingerprint"] = nc.sha256_hex(nc.canonical(enclave).encode("utf-8"))
        out["identity"] = identity_for(str(evidence.get("enclave_host") or ""), models)
        comps = [f"gateway compose sha256:{str(gw.get('compose_hash'))[:16]}..."
                 f"{_app_name(composes, gw.get('compose_hash'))}"]
        for m in models:
            for h in code["models"][m]:
                comps.append(f"model {m} compose sha256:{str(h)[:16]}...{_app_name(composes, h)}")
        if not v1:
            for c in cvms:
                comps += _cvm_lines(c)
        out["components"] = tuple(comps)
        out["cvms"] = tuple(cvms)
        stated = cast(Mapping, evidence.get("claims")) if isinstance(evidence.get("claims"), Mapping) else None
        if stated and (stated.get("code_fingerprint"), stated.get("enclave_fingerprint")) != (
                out["code_fingerprint"], out["enclave_fingerprint"]):
            checks["fingerprints"] = "fail: recomputed fingerprints differ from the evidence's claims"
        else:
            checks["fingerprints"] = True
    fail = next((v for k, v in checks.items() if k not in INFORMATIONAL_CHECKS
                 and isinstance(v, str) and v.startswith(("fail", "not_run"))), None)
    return done(fail)


def _compose_manager_checks(checks: dict, evidence: Mapping, blobs: Mapping, models: list[str],
                            model_quotes: Mapping, *, nonce: str, quote_verifier, required: bool) -> dict:
    """Run near_checks.check_compose_manager for every verified model candidate and fold the per-step
    outcomes into ``checks``. Returns {(model, index): result} for the candidates that passed."""
    steps = nc.CM_CHECK_KEYS
    per_step: dict[str, list] = {k: [] for k in steps}   # (outcome, text); outcome pass | fail | not_run | skip
    results: dict[tuple, dict] = {}
    for model in models:
        for i, (cand, q) in enumerate(model_quotes.get(model, [])):
            where = f"{model}[{i}]"
            ref = (cast(Mapping, cand.get("compose_manager"))
                   if isinstance(cand.get("compose_manager"), Mapping) else None)
            text = blobs.get(ref.get("blob")) if ref else None
            if text is None:
                why = ("its report carries no compose_manager_attestation" if ref is None else
                       "its compose_manager_attestation blob is missing or does not hash to its id")
                outcome = "fail" if required or ref is not None else "skip"
                for k in steps:
                    per_step[k].append((outcome if k == "cm_quote" or outcome == "skip" else "not_run",
                                        f"{where}: {why}"))
                continue
            try:
                res = nc.check_compose_manager(json.loads(text), nonce=nonce, model_quote=q,
                                               quote_verifier=quote_verifier, model=model,
                                               app_compose=blobs.get(cand.get("compose_hash")))
            except nc.CmCheckError as exc:
                failed = steps.index(exc.step)
                for j, k in enumerate(steps):
                    per_step[k].append(("pass", "") if j < failed else
                                       ("fail", f"{where}: {exc}") if j == failed else
                                       ("not_run", f"{where}: an earlier compose-manager check failed"))
                continue
            except Exception as exc:
                for j, k in enumerate(steps):
                    per_step[k].append(("fail", f"{where}: {type(exc).__name__}: {exc}") if j == 0 else
                                       ("not_run", f"{where}: an earlier compose-manager check failed"))
                continue
            results[(model, i)] = res
            for k in steps:
                per_step[k].append(("pass", ""))
            # never scored: the log is operator-reported, so an equal image reassures no more than a different one
            per_step["cm_image"][-1] = ("recorded", f"{where}: image reported by the log "
                                        f"{_image_text(res['cm_image_reported'])}; image in the measured compose "
                                        f"{_image_text(res['cm_image_measured'])}"
                                        + ("" if res["cm_image_match"] else " (the two differ)"))
    for k in steps:
        items = per_step[k]
        fails = [t for o, t in items if o == "fail"]
        if fails:
            checks[k] = f"fail: {fails[0]}"[:320]
        elif any(o == "not_run" for o, _ in items):
            checks[k] = "not_run: " + next(t for o, t in items if o == "not_run")[:300]
        elif any(o == "recorded" for o, _ in items):
            checks[k] = ("recorded (not a pass; the log is operator-reported, not verified): "
                         + "; ".join(t for o, t in items if o == "recorded"))[:400]
        elif items and all(o == "skip" for o, _ in items):
            checks[k] = ("n/a: no compose_manager_attestation captured, and it is not required "
                         "(require_provider_tee is off)")
        elif any(o == "skip" for o, _ in items):
            checks[k] = ("n/a: passed where captured; " + next(t for o, t in items if o == "skip")
                         + " (not required: require_provider_tee is off)")[:320]
        else:
            checks[k] = True
    return results


def evidence_claims(evidence: Mapping, a: Appraisal) -> dict:
    """The claims a verify_ok row carries. With v2 evidence (a ``blobs`` dict) each CVM's whole service map
    and the full component list go into the blobs ({"$blob": id}), so a row stays small whatever the
    allowlist; ``components`` keeps the condensed lines and ``components_full`` points at the full list."""
    gw = cast(Mapping, evidence.get("gateway")) if isinstance(evidence.get("gateway"), Mapping) else {}
    blobs = cast(dict, evidence.get("blobs")) if isinstance(evidence.get("blobs"), dict) else None
    cvms = [dict(c) for c in a.cvms]
    claims = {"code_fingerprint": a.code_fingerprint, "enclave_fingerprint": a.enclave_fingerprint,
              "release_tag": None, "identity": a.identity, "tls_public_key_fp": gw.get("tls_cert_fingerprint"),
              "hpke_public_key": None, "gateway_signer": a.gateway_signer, "model_signers": a.model_signers,
              "components": list(a.components), "tcb_status": a.tcb_status, "cvms": cvms}
    if blobs is not None and evidence.get("schema") == EVIDENCE_SCHEMA:
        for c in cvms:
            if isinstance(c.get("services"), Mapping):
                c["services"] = {BLOB_REF: put_blob(blobs, blob_text(c["services"]))}
        claims["components"] = condensed_components(a.components)
        claims["components_full"] = {BLOB_REF: put_blob(blobs, blob_text(list(a.components)))}
        if isinstance(evidence, dict):
            evidence["blob_refs"] = sorted(blobs)
    return claims

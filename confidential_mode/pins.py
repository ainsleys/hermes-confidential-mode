"""PinStore over pins.yaml version 3: an approved set of per-CVM entries per (vendor, identity).

File shape (INTERFACES Amendment 7):

    version: 3
    identities:
      - vendor: near                       # or tinfoil
        router_repo: cloud-api.near.ai#Qwen/Qwen3.8-27B     # the identity (Tinfoil: the router repo)
        concurrent: true                   # NEAR: approving adds to the set; Tinfoil (false): replaces it
        verifications: 41                  # verifications observed for this identity
        approved: [entry, ...]
        pending: [entry, ...]              # the CVMs of the latest verification that no approved entry covers
        pending_batch: {...} | null        # what the prompt shows beside them (release, host, display lines)
        last_applied_key: <consent key> | null

An entry is ``{cvm_role, code_fingerprint, enclave_fingerprint, release_tag, components, pinned,
instance_ids_seen, approved_by, approved_at, approved_via, approval_rule_key, reviewed_by, review_note, ...}``.

* Tinfoil: one entry per verification result, ``cvm_role: router``, fingerprints byte-identical to the
  result's, no components. ``concurrent: false``.
* NEAR: one entry per CVM (``gateway`` or ``model:<id>``). ``components`` names every value of that CVM
  (app_id, compose, os_image, kms_id; for a model also services and cm_image_running); ``pinned`` names
  the ones its ``code_fingerprint`` covers: SHA-256 of the canonical JSON of the role and those values.
  ``services`` is pinned only when the socket tags of every service could be shown (the inner compose
  texts are cached), else it is shown for review only. ``enclave_fingerprint`` is SHA-256 of that CVM's
  "MRTD:RTMR0:RTMR1:RTMR2". ``concurrent: true``.

Match rule: a result matches when every CVM it reports has an approved entry with equal fingerprints.
A Tinfoil record migrated from version 2 matches exactly as before. A NEAR record migrated from version 2
matches nothing, so NEAR asks once after the upgrade; approving the new entries removes it. Before the first
version-3 save of a version-2 file, pins.yaml.v2.bak is written. A version-3 file is never written back
as version 2; any other version matches nothing.

Only consent.py (a person's answer) and provider._auto_apply (Tinfoil, replace only) call apply().
Writes are atomic (temp file in the same directory, fsync, os.replace) and serialised across processes
with an advisory lock file.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import threading
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast, overload

from .atomicwrite import write_atomic
from .hermes_compat import yaml_module
from .verify.base import VerificationResult

# Hermes ships ruamel-backed hermes_yaml and no PyYAML in its venv; PyYAML for standalone use.
yaml = yaml_module()

SCHEMA_VERSION = 3
LEGACY_VERSION = 2
BACKUP_SUFFIX = ".v2.bak"
DEFAULT_APPROVAL_RULE_KEY = "confidential-mode:pin"
# An approved entry not seen in this many verifications of its identity is flagged for retirement.
UNSEEN_VERIFICATIONS = 20

ROLE_ROUTER = "router"     # Tinfoil: the whole router result
ROLE_RESULT = "result"     # a NEAR record migrated from version 2: the whole result's fingerprints
WHOLE_RESULT_ROLES = (ROLE_ROUTER, ROLE_RESULT)
VENDOR_POLICY = {"tinfoil": {"concurrent": False}, "near": {"concurrent": True}}

# NEAR component names. A model entry must pin at least NEAR_MODEL_REQUIRED, a gateway entry
# NEAR_GATEWAY_REQUIRED; an entry that pins less never matches. SERVICES is pinned only with its tags.
NEAR_GATEWAY_REQUIRED = ("app_id", "compose", "os_image", "kms_id")
NEAR_MODEL_REQUIRED = NEAR_GATEWAY_REQUIRED + ("cm_image_running",)
SERVICES = "services"
NEAR_COMPONENTS = NEAR_MODEL_REQUIRED + (SERVICES,)


def concurrent(vendor: str) -> bool:
    return bool(VENDOR_POLICY.get(vendor, {}).get("concurrent", False))


def _nonempty(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


class PinStoreError(Exception):
    """pins.yaml is unreadable or of an unknown version, or a mutation is refused. Callers fail closed."""


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def required_components(role: str) -> tuple[str, ...]:
    return NEAR_GATEWAY_REQUIRED if role == "gateway" else NEAR_MODEL_REQUIRED


def near_code_fingerprint(role: str, components: Mapping, pinned: Iterable[str]) -> str:
    """SHA-256 of the canonical JSON of the role and the pinned components' values."""
    names = sorted(set(pinned))
    return _sha(_canonical({"cvm_role": role, "components": {n: components.get(n) for n in names}}))


def near_enclave_fingerprint(measurement: str) -> str:
    return _sha(str(measurement))


# ── entries ──────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PinEntry:
    """One approved or pending entry. As an approved entry it is also the PinRecord of earlier versions."""
    vendor: str
    router_repo: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None = None
    models_seen: tuple[str, ...] = ()
    approved_by: str | None = None
    approved_at: str | None = None
    approved_via: str | None = None
    approval_rule_key: str | None = None
    previous: str | None = None
    previous_enclave_fingerprint: str | None = None
    platform: str | None = None
    cvm_role: str = ROLE_ROUTER
    components: dict | None = None            # NEAR: every named value of this CVM; Tinfoil: None
    pinned: tuple[str, ...] = ()              # NEAR: the component names the code fingerprint covers
    instance_ids_seen: tuple[str, ...] = ()
    reviewed_by: str | None = None
    review_note: str | None = None
    migrated_from: int | None = None
    last_seen: int = 0                        # the identity's verification count when last seen
    # Shown for review, never pinned: measurement, signing address, the per-service map and its tags, the
    # compose-manager image the measured compose names.
    observed: dict | None = field(default=None, compare=False)

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.router_repo)

    @property
    def pin_key(self) -> tuple:
        return (self.cvm_role, self.code_fingerprint, self.enclave_fingerprint, tuple(sorted(self.pinned)))


PinRecord = PinEntry   # the name earlier versions used for an approved pin


@dataclass(frozen=True)
class PendingPin:
    """The pending batch for one identity: what the prompt shows, and the entries an approval adds."""
    vendor: str
    router_repo: str
    code_fingerprint: str                       # the whole result's (for the ledger and the prompt)
    enclave_fingerprint: str
    release_tag: str | None
    enclave_host: str
    verifier: str
    staged_at: str
    previous: str | None                       # code fingerprint of the pin this would replace
    previous_enclave_fingerprint: str | None
    models_seen: tuple[str, ...] = ()
    # Prompt context (Miller-frame review). All optional so older pins.yaml files still load.
    platform: str | None = None                  # "sev-snp" | "tdx" (from the attestation format)
    previous_platform: str | None = None
    previous_release_tag: str | None = None
    release_published_at: str | None = None      # GitHub release JSON published_at (unsigned metadata)
    rekor_log_index: int | None = None           # verificationMaterial.tlogEntries[0].logIndex
    code_changed: bool = True                    # code_fingerprint != previous (True when no previous pin)
    hardware_measurements_verified: bool = False  # SDK's signed hardware-measurements check (TDX) passed
    # Amendment 5 (NEAR): the display lines of the latest verification (shown, refreshed, never compared)
    components: tuple[str, ...] = ()
    entries: tuple = ()                          # PinEntry, one per CVM to approve (Tinfoil: one)

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.router_repo)

    @property
    def platform_only(self) -> bool:
        """Same code, different enclave measurement: an AMD/Intel platform flap, not a new build."""
        return (self.previous is not None and not self.code_changed
                and self.enclave_fingerprint != self.previous_enclave_fingerprint)

    @property
    def release_url(self) -> str | None:
        return release_url(self.router_repo, self.release_tag)

    @property
    def compare_url(self) -> str | None:
        return compare_url(self.router_repo, self.previous_release_tag, self.release_tag)

    @property
    def consent_key(self) -> str:
        """What an approval is an answer to: the identity, release, host, the whole result's fingerprints and
        every entry's fingerprints and pinned names. Display lines are not part of it, so a refreshed display
        keeps the answer valid."""
        ents = sorted(list(e.pin_key[:3]) + [list(e.pin_key[3])] for e in self.entries)
        return _canonical([self.vendor, self.router_repo, self.release_tag, self.enclave_host,
                           self.code_fingerprint, self.enclave_fingerprint, ents])


def consent_key(pending: Any) -> Any:
    """``pending.consent_key`` when it has one (a PinStore pending batch), else the object itself."""
    try:
        return pending.consent_key
    except Exception:
        return pending


def release_url(repo: str | None, tag: str | None) -> str | None:
    """https://github.com/<repo>/releases/tag/<tag>, or None."""
    if not repo or not tag:
        return None
    from urllib.parse import quote
    return f"https://github.com/{repo}/releases/tag/{quote(tag, safe='')}"


def compare_url(repo: str | None, old_tag: str | None, new_tag: str | None) -> str | None:
    """https://github.com/<repo>/compare/<old_tag>...<new_tag>, or None when either tag is missing or
    they are equal."""
    if not repo or not old_tag or not new_tag or old_tag == new_tag:
        return None
    from urllib.parse import quote
    return f"https://github.com/{repo}/compare/{quote(old_tag, safe='')}...{quote(new_tag, safe='')}"


def _prompt_context(result: VerificationResult) -> dict:
    """platform, release published_at, Rekor log index and the TDX hardware-measurement verdict from
    the evidence the adapter captured. Missing pieces are None/False; never raises."""
    ev = result.evidence if isinstance(result.evidence, dict) else {}
    out: dict = {"platform": None, "release_published_at": None, "rekor_log_index": None,
                 "hardware_measurements_verified": False, "components": ()}
    try:
        claims = cast(dict, ev.get("claims")) if isinstance(ev.get("claims"), dict) else {}
        comps = claims.get("components")
        full = claims.get("components_full")
        if isinstance(full, dict) and isinstance(ev.get("blobs"), dict):   # NEAR v2: the full list is a blob
            text = ev["blobs"].get(full.get("$blob"))
            if isinstance(text, str) and _sha(text) == full.get("$blob"):
                comps = json.loads(text)
        if isinstance(comps, (list, tuple)):
            out["components"] = tuple(str(c) for c in comps)
        platform = ev.get("platform")
        out["platform"] = platform if platform in ("sev-snp", "tdx") else None
        rel = ev.get("release") or {}
        if isinstance(rel.get("published_at"), str):
            out["release_published_at"] = rel["published_at"]
        bundle = ev.get("sigstore_bundle")
        if isinstance(bundle, str) and bundle:
            entries = (json.loads(bundle).get("verificationMaterial") or {}).get("tlogEntries") or []
            if entries and str(entries[0].get("logIndex", "")).strip().isdigit():
                out["rekor_log_index"] = int(entries[0]["logIndex"])
        doc = ev.get("verification_document") or {}
        steps = doc.get("steps") or {}
        out["hardware_measurements_verified"] = bool(
            out["platform"] == "tdx" and doc.get("hardwareMeasurement")
            and all((steps.get(k) or {}).get("status") == "success"
                    for k in ("verifyEnclave", "verifyCode", "compareMeasurements")))
    except Exception:
        pass
    return out


# ── per-CVM views of a NEAR result ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CvmView:
    role: str
    components: dict
    measurement: str
    instance_id: str | None
    observed: dict

    @property
    def enclave_fingerprint(self) -> str:
        return near_enclave_fingerprint(self.measurement)


def _resolve(value: Any, blobs: Mapping) -> Any:
    if isinstance(value, Mapping) and set(value) == {"$blob"}:
        text = blobs.get(value["$blob"])
        if isinstance(text, str) and _sha(text) == value["$blob"]:
            try:
                return json.loads(text)
            except ValueError:
                return None
        return None
    return value


def views_from_cvms(cvms: Any, blobs: Mapping | None = None) -> list[CvmView]:
    """One CvmView per CVM of a NEAR appraisal (``claims.cvms`` or a replay's ``cvms``). Empty when any CVM
    carries no measurement (evidence written before per-CVM entries), so the caller falls back to the
    whole result's fingerprints."""
    out: list[CvmView] = []
    if not isinstance(cvms, (list, tuple)) or not cvms:
        return []
    blobs = blobs or {}
    for c in cvms:
        if not isinstance(c, Mapping) or not _nonempty(c.get("measurement")) or not _nonempty(c.get("role")):
            return []
        role = str(c["role"])
        comps = {"app_id": c.get("app_id"), "compose": c.get("compose_hash"), "os_image": c.get("os_image_hash"),
                 "kms_id": c.get("kms_id")}
        services = _resolve(c.get("services"), blobs)
        if role != "gateway":
            comps["services"] = c.get("services_sha256")
            comps["cm_image_running"] = c.get("cm_image_reported")
        observed = {"measurement": c.get("measurement"), "signing_address": c.get("signing_address"),
                    "compose_hash": c.get("compose_hash")}
        if role != "gateway":
            from .review import repo_of_app_compose
            text = blobs.get(c.get("compose_hash")) if isinstance(c.get("compose_hash"), str) else None
            observed["services"] = dict(services) if isinstance(services, Mapping) else None
            observed["cm_image_measured"] = c.get("cm_image_measured")
            # GITHUB_REPO as the measured compose (pinned) names it: where the inner files are fetched from
            observed["github_repo"] = repo_of_app_compose(text if isinstance(text, str)
                                                          and _sha(text) == c.get("compose_hash") else None)
        out.append(CvmView(role=role, components=comps, measurement=str(c["measurement"]),
                           instance_id=c.get("instance_id"), observed=observed))
    return out


def result_views(result: VerificationResult) -> list[CvmView]:
    ev = result.evidence if isinstance(result.evidence, dict) else {}
    claims = cast(dict, ev.get("claims")) if isinstance(ev.get("claims"), dict) else {}
    blobs = cast(dict, ev.get("blobs")) if isinstance(ev.get("blobs"), dict) else {}
    return views_from_cvms(claims.get("cvms"), blobs)


def entry_matches_view(e: PinEntry, v: CvmView) -> bool:
    if e.cvm_role != v.role or not (_nonempty(e.code_fingerprint) and _nonempty(e.enclave_fingerprint)):
        return False
    pinned = set(e.pinned or ())
    if not pinned >= set(required_components(v.role)) or not pinned <= set(NEAR_COMPONENTS):
        return False
    if v.role == "gateway" and SERVICES in pinned:
        return False
    return (e.enclave_fingerprint == v.enclave_fingerprint
            and e.code_fingerprint == near_code_fingerprint(v.role, v.components, pinned))


def set_match(approved: Iterable[PinEntry], *, vendor: str, code: Any, enclave: Any,
              views: list[CvmView]) -> list[PinEntry] | None:
    """The approved entries a result matches, or None. With per-CVM views (NEAR) every CVM needs an entry
    of its own role with equal fingerprints. Tinfoil entries match the whole result's fingerprints. A NEAR
    record migrated from version 2 (role ``result``) matches nothing: its fingerprints cover less than a
    per-CVM entry does, so NEAR asks once after the upgrade (Amendment 7)."""
    approved = [e for e in approved if e.vendor == vendor]
    if not (_nonempty(code) and _nonempty(enclave)):
        return None
    whole = [e for e in approved if e.cvm_role == ROLE_ROUTER
             and _nonempty(e.code_fingerprint) and _nonempty(e.enclave_fingerprint)
             and e.code_fingerprint == code and e.enclave_fingerprint == enclave]
    if whole:
        return whole[:1]
    if not views:
        return None
    matched: list[PinEntry] = []
    for v in views:
        e = next((a for a in approved if a.cvm_role not in WHOLE_RESULT_ROLES and entry_matches_view(a, v)), None)
        if e is None:
            return None
        if e not in matched:
            matched.append(e)
    return matched


# ── the file ─────────────────────────────────────────────────────────────────────────────────────

@dataclass
class Identity:
    vendor: str
    router_repo: str
    concurrent: bool
    verifications: int = 0
    approved: list = field(default_factory=list)
    pending: list = field(default_factory=list)
    pending_batch: dict | None = None
    last_applied_key: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.router_repo)

    def pending_pin(self) -> PendingPin | None:
        if not self.pending or self.pending_batch is None:
            return None
        return PendingPin(**{**self.pending_batch, "entries": tuple(self.pending)})

    def unseen(self, e: PinEntry, n: int = UNSEEN_VERIFICATIONS) -> bool:
        return self.verifications - int(e.last_seen or 0) >= n


_BATCH_FIELDS = tuple(f for f in PendingPin.__dataclass_fields__ if f != "entries")
_ENTRY_FIELDS = tuple(PinEntry.__dataclass_fields__)


def _tuple(v) -> tuple:
    return tuple(v) if isinstance(v, (list, tuple)) else ()


def _entry_from(d: Any) -> PinEntry:
    if not isinstance(d, dict):
        raise PinStoreError(f"malformed pin entry: {d!r}"[:200])
    kw = {k: v for k, v in d.items() if k in _ENTRY_FIELDS}
    for k in ("models_seen", "pinned", "instance_ids_seen"):
        kw[k] = tuple(str(x) for x in _tuple(kw.get(k)))
    if kw.get("components") is not None and not isinstance(kw["components"], dict):
        raise PinStoreError("malformed pin entry: components is not a mapping")
    if kw.get("observed") is not None and not isinstance(kw["observed"], dict):
        kw["observed"] = None
    try:
        e = PinEntry(**kw)
    except TypeError as exc:
        raise PinStoreError(f"malformed pin entry: {exc}") from exc
    if not isinstance(e.vendor, str) or not isinstance(e.router_repo, str):
        raise PinStoreError("malformed pin entry: vendor or router_repo is not text")
    return e


def _entry_to(e: PinEntry) -> dict:
    d = asdict(e)
    for k in ("models_seen", "pinned", "instance_ids_seen"):
        d[k] = list(d[k])
    return d


def _batch_from(d: Any) -> dict:
    if not isinstance(d, dict):
        raise PinStoreError("malformed pending batch")
    kw = {k: v for k, v in d.items() if k in _BATCH_FIELDS}
    kw["models_seen"] = tuple(_tuple(kw.get("models_seen")))
    kw["components"] = tuple(str(c) for c in _tuple(kw.get("components")))
    try:
        PendingPin(**kw)
    except TypeError as exc:
        raise PinStoreError(f"malformed pending batch: {exc}") from exc
    return kw


def _batch_to(p: PendingPin) -> dict:
    d = {k: getattr(p, k) for k in _BATCH_FIELDS}
    d["models_seen"] = list(d["models_seen"])
    d["components"] = list(d["components"])
    return d


@dataclass
class PinFile:
    identities: list = field(default_factory=list)
    on_disk_version: int | None = None        # what the file said when read (None: no file)

    @overload
    def identity(self, vendor: str, router_repo: str, *, create: Literal[True]) -> Identity: ...

    @overload
    def identity(self, vendor: str, router_repo: str, *, create: bool = False) -> Identity | None: ...

    def identity(self, vendor: str, router_repo: str, *, create: bool = False) -> Identity | None:
        for i in self.identities:
            if i.key == (vendor, router_repo):
                return i
        if not create:
            return None
        idn = Identity(vendor=vendor, router_repo=router_repo, concurrent=concurrent(vendor))
        self.identities.append(idn)
        return idn


def _whole_role(vendor: str) -> str:
    return ROLE_ROUTER if vendor != "near" else ROLE_RESULT


def _from_v2(data: dict) -> PinFile:
    """A version-2 file: each pin becomes one migrated entry, the pending pin one pending batch."""
    if "identities" in data:
        raise PinStoreError("a version-2 file with version-3 identities (hand-edited); refusing to read it")
    raw_pins = data.get("pins") or []
    if not isinstance(raw_pins, list):
        raise PinStoreError("'pins' is not a list")
    pf = PinFile(on_disk_version=LEGACY_VERSION)
    for d in raw_pins:
        e = _entry_from(d)
        idn = pf.identity(e.vendor, e.router_repo, create=True)
        idn.approved = [replace(e, cvm_role=_whole_role(e.vendor), migrated_from=LEGACY_VERSION, components=None,
                                pinned=())]
    raw = data.get("pending")
    if raw:
        kw = _batch_from(raw)
        idn = pf.identity(kw["vendor"], kw["router_repo"], create=True)
        idn.pending_batch = kw
        idn.pending = [PinEntry(vendor=kw["vendor"], router_repo=kw["router_repo"],
                                code_fingerprint=kw["code_fingerprint"], enclave_fingerprint=kw["enclave_fingerprint"],
                                release_tag=kw.get("release_tag"), models_seen=kw["models_seen"],
                                platform=kw.get("platform"), cvm_role=_whole_role(kw["vendor"]),
                                migrated_from=LEGACY_VERSION)]
    last = data.get("last_applied")
    if isinstance(last, dict):
        try:
            kw = _batch_from(last)
            idn = pf.identity(kw["vendor"], kw["router_repo"])  # type: ignore[assignment]  # None checked next
            if idn is not None:
                ent = PinEntry(vendor=kw["vendor"], router_repo=kw["router_repo"],
                               code_fingerprint=kw["code_fingerprint"], enclave_fingerprint=kw["enclave_fingerprint"],
                               cvm_role=_whole_role(kw["vendor"]))
                idn.last_applied_key = PendingPin(**{**kw, "entries": (ent,)}).consent_key
        except PinStoreError:
            pass
    return pf


def _from_v3(data: dict) -> PinFile:
    raw = data.get("identities") or []
    if not isinstance(raw, list) or "pins" in data:
        raise PinStoreError("'identities' is not a list, or the file mixes version-2 keys")
    pf = PinFile(on_disk_version=SCHEMA_VERSION)
    for d in raw:
        if not isinstance(d, dict) or not isinstance(d.get("vendor"), str) or not isinstance(d.get("router_repo"), str):
            raise PinStoreError("malformed identity")
        if pf.identity(d["vendor"], d["router_repo"]) is not None:
            raise PinStoreError("an identity appears twice")
        approved, pending = d.get("approved") or [], d.get("pending") or []
        if not isinstance(approved, list) or not isinstance(pending, list):
            raise PinStoreError("approved or pending is not a list")
        idn = Identity(vendor=d["vendor"], router_repo=d["router_repo"],
                       # the vendor policy decides; a hand-edited flag never widens a replace-only vendor
                       concurrent=concurrent(d["vendor"]),
                       verifications=int(d.get("verifications") or 0),
                       approved=[_entry_from(e) for e in approved], pending=[_entry_from(e) for e in pending],
                       pending_batch=_batch_from(d["pending_batch"]) if d.get("pending_batch") else None,
                       last_applied_key=(d.get("last_applied_key")
                                         if isinstance(d.get("last_applied_key"), str) else None))
        for e in idn.approved + idn.pending:
            if e.key != idn.key:
                raise PinStoreError("an entry names another identity")
        pf.identities.append(idn)
    return pf


def _to_v3(pf: PinFile) -> dict:
    return {"version": SCHEMA_VERSION,
            "identities": [{"vendor": i.vendor, "router_repo": i.router_repo, "concurrent": i.concurrent,
                            "verifications": i.verifications,
                            "approved": [_entry_to(e) for e in i.approved],
                            "pending": [_entry_to(e) for e in i.pending],
                            "pending_batch": _batch_to(i.pending_pin()) if i.pending_pin() else None,
                            "last_applied_key": i.last_applied_key}
                           for i in sorted(pf.identities, key=lambda i: i.key)]}


def _write_atomic(path: Path, data: bytes) -> None:
    """pins.yaml and its backup: the shared durable write (atomicwrite.py; issue #37)."""
    write_atomic(path, data)


class PinStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.RLock()

    @property
    def backup_path(self) -> Path:
        return self.path.with_name(self.path.name + BACKUP_SUFFIX)

    @property
    def composes_dir(self) -> Path:
        from .review import COMPOSES_SUBDIR
        return self.path.parent.joinpath(*COMPOSES_SUBDIR)

    @contextlib.contextmanager
    def _mutating(self):
        """Thread lock plus an advisory lock file, so a CLI and a gateway never interleave a read-modify-write.
        Bounded (filelock.exclusive, Amendment 10 review N1): a lock held elsewhere raises PinStoreError naming
        pins.yaml.lock instead of hanging; every caller already fails closed on PinStoreError."""
        from .filelock import LockBusy, exclusive
        try:
            with exclusive(self.path.with_name(self.path.name + ".lock"), thread_lock=self._lock):
                yield
        except LockBusy as exc:
            raise PinStoreError(str(exc)) from None

    # ── persistence ──────────────────────────────────────────────────────────────────────────
    def load_file(self) -> PinFile:
        with self._lock:
            try:
                raw = self.path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return PinFile()
            except OSError as exc:
                raise PinStoreError(f"cannot read {self.path}: {exc}") from exc
            try:
                data = yaml.safe_load(raw) or {}
            except Exception as exc:
                raise PinStoreError(f"cannot parse {self.path}: {exc}") from exc
            version = data.get("version") if isinstance(data, dict) else None
            if type(version) is not int or version not in (LEGACY_VERSION, SCHEMA_VERSION):
                raise PinStoreError(f"{self.path}: expected version {SCHEMA_VERSION} (or {LEGACY_VERSION}, migrated), "
                                    f"got {version if isinstance(data, dict) else type(data).__name__}")
            try:
                return _from_v2(data) if version == LEGACY_VERSION else _from_v3(data)
            except PinStoreError as exc:
                raise PinStoreError(f"{self.path}: {exc}") from exc
            except Exception as exc:
                raise PinStoreError(f"{self.path}: malformed ({type(exc).__name__}: {exc})") from exc

    def save_file(self, pf: PinFile) -> None:
        """Atomic version-3 write. The first save over a version-2 file first copies it to pins.yaml.v2.bak."""
        with self._lock:
            text = yaml.safe_dump(_to_v3(pf), sort_keys=False)
            try:
                disk_raw = self.path.read_bytes()
            except FileNotFoundError:
                disk_raw = None
            if disk_raw is not None:
                try:
                    disk = yaml.safe_load(disk_raw.decode("utf-8")) or {}
                except Exception:
                    disk = {}
                if isinstance(disk, dict) and disk.get("version") == LEGACY_VERSION:
                    _write_atomic(self.backup_path, disk_raw)
            _write_atomic(self.path, text.encode("utf-8"))
            pf.on_disk_version = SCHEMA_VERSION

    def load(self) -> tuple[dict[tuple[str, str], PinEntry], PendingPin | None]:
        """(the latest approved entry per identity, the most recently staged pending batch). The shape of
        earlier versions; ``approved_entries()`` and ``pending_all()`` give everything."""
        pf = self.load_file()
        pins = {i.key: i.approved[-1] for i in pf.identities if i.approved}
        return pins, _latest(pf)

    def approved_entries(self, vendor: str | None = None, router_repo: str | None = None) -> list[PinEntry]:
        pf = self.load_file()
        return [e for i in pf.identities for e in i.approved
                if (vendor is None or i.vendor == vendor) and (router_repo is None or i.router_repo == router_repo)]

    def approved_set(self, vendor: str, router_repo: str) -> tuple[list[PinEntry], list[bool]]:
        """(approved entries, for each: not seen in the last UNSEEN_VERIFICATIONS verifications)."""
        idn = self.load_file().identity(vendor, router_repo)
        if idn is None:
            return [], []
        return list(idn.approved), [idn.unseen(e) for e in idn.approved]

    # ── queries ──────────────────────────────────────────────────────────────────────────────
    def get(self, vendor: str, router_repo: str) -> PinEntry | None:
        return self.load()[0].get((vendor, router_repo))

    def matching_entries(self, result: VerificationResult) -> list[PinEntry] | None:
        """The approved entries that cover every CVM of ``result``, or None. Never raises."""
        try:
            idn = self.load_file().identity(result.vendor, result.router_repo)
            if idn is None:
                return None
            views = result_views(result) if result.vendor == "near" else []
            return set_match(idn.approved, vendor=result.vendor, code=result.code_fingerprint,
                             enclave=result.enclave_fingerprint, views=views)
        except Exception:
            return None

    def match(self, result: VerificationResult) -> bool:
        """Exactly True only when every CVM ``result`` reports has an approved entry with equal, non-empty
        fingerprints. An unreadable, corrupt, truncated or unknown-version file matches nothing."""
        return bool(self.matching_entries(result))

    def pending(self) -> PendingPin | None:
        return _latest(self.load_file())

    def pending_for(self, vendor: str, router_repo: str) -> PendingPin | None:
        idn = self.load_file().identity(vendor, router_repo)
        return idn.pending_pin() if idn is not None else None

    def pending_all(self) -> list[PendingPin]:
        return [p for p in (i.pending_pin() for i in self.load_file().identities) if p is not None]

    # ── mutations ────────────────────────────────────────────────────────────────────────────
    def observe(self, result: VerificationResult) -> None:
        """Count one verification of the result's identity and mark the approved entries it covers as seen
        (with their instance ids). Never raises; labels only, no effect on matching."""
        try:
            with self._mutating():
                pf = self.load_file()
                idn = pf.identity(result.vendor, result.router_repo)
                if idn is None:
                    return
                idn.verifications += 1
                views = result_views(result) if result.vendor == "near" else []
                whole = set_match(idn.approved, vendor=result.vendor, code=result.code_fingerprint,
                                  enclave=result.enclave_fingerprint, views=[])
                seen: dict[int, set] = {}
                if whole:
                    seen[idn.approved.index(whole[0])] = {v.instance_id for v in views if v.instance_id}
                for v in views:
                    for n, e in enumerate(idn.approved):
                        if e.cvm_role not in WHOLE_RESULT_ROLES and entry_matches_view(e, v):
                            seen.setdefault(n, set()).update({v.instance_id} if v.instance_id else set())
                for n, ids in seen.items():
                    e = idn.approved[n]
                    idn.approved[n] = replace(e, last_seen=idn.verifications,
                                              instance_ids_seen=tuple(dict.fromkeys(e.instance_ids_seen
                                                                                    + tuple(sorted(ids)))))
                self.save_file(pf)
        except Exception:
            pass

    def _near_entries(self, result: VerificationResult, idn: Identity) -> list[PinEntry]:
        from .review import map_tags
        out: list[PinEntry] = []
        for v in result_views(result):
            if any(a.cvm_role not in WHOLE_RESULT_ROLES and entry_matches_view(a, v) for a in idn.approved):
                continue
            pinned = list(required_components(v.role))
            observed = dict(v.observed)
            if v.role != "gateway":
                tags, missing = map_tags(observed.get("services"), self.composes_dir)
                observed["tags"], observed["tags_missing"] = tags, missing
                if _services_pinnable(observed, tags):
                    pinned.append(SERVICES)
            e = PinEntry(vendor=result.vendor, router_repo=result.router_repo,
                         code_fingerprint=near_code_fingerprint(v.role, v.components, pinned),
                         enclave_fingerprint=v.enclave_fingerprint, platform="tdx", cvm_role=v.role,
                         components=dict(v.components), pinned=tuple(sorted(pinned)),
                         instance_ids_seen=(v.instance_id,) if v.instance_id else (), observed=observed)
            twin = next((x for x in out if x.pin_key == e.pin_key), None)
            if twin is not None:
                out[out.index(twin)] = replace(twin, instance_ids_seen=tuple(dict.fromkeys(
                    twin.instance_ids_seen + e.instance_ids_seen)))
            else:
                out.append(e)
        return out

    def stage(self, result: VerificationResult, *, model: str | None = None) -> PendingPin:
        """Record the CVMs of ``result`` that no approved entry covers as the identity's pending batch,
        replacing the identity's earlier pending batch. When the new batch has the same consent key as the
        stored one (same release, host, entries and fingerprints), the stored batch keeps its staging time
        and only its shown-for-review lines are refreshed, so a consent prompt's re-check still holds.
        Anything else, including the same fingerprints under a different release tag, is a new batch."""
        if not (_nonempty(result.code_fingerprint) and _nonempty(result.enclave_fingerprint)):
            raise PinStoreError("refusing to stage a result with an empty code or enclave fingerprint")
        with self._mutating():
            pf = self.load_file()
            idn = pf.identity(result.vendor, result.router_repo, create=True)
            ctx = _prompt_context(result)
            current = idn.approved[-1] if idn.approved else None
            views = result_views(result) if result.vendor == "near" else []
            if result.vendor == "near" and not views:
                raise PinStoreError("this NEAR evidence carries no per-CVM measurements; nothing can be pinned")
            if views:
                entries = self._near_entries(result, idn)
                if not entries:
                    raise PinStoreError("every CVM of this result is already approved; nothing to stage")
            else:
                entries = [PinEntry(vendor=result.vendor, router_repo=result.router_repo,
                                    code_fingerprint=result.code_fingerprint,
                                    enclave_fingerprint=result.enclave_fingerprint, release_tag=result.release_tag,
                                    models_seen=(model,) if model else (), platform=ctx["platform"],
                                    cvm_role=_whole_role(result.vendor))]
            new = PendingPin(
                vendor=result.vendor, router_repo=result.router_repo,
                code_fingerprint=result.code_fingerprint, enclave_fingerprint=result.enclave_fingerprint,
                release_tag=result.release_tag, enclave_host=result.enclave_host, verifier=result.verifier,
                staged_at=_utc_now_iso(),
                previous=current.code_fingerprint if current else None,
                previous_enclave_fingerprint=current.enclave_fingerprint if current else None,
                models_seen=(model,) if model else (),
                platform=ctx["platform"],
                previous_platform=current.platform if current else None,
                previous_release_tag=current.release_tag if current else None,
                release_published_at=ctx["release_published_at"],
                rekor_log_index=ctx["rekor_log_index"],
                code_changed=(current is None or current.code_fingerprint != result.code_fingerprint),
                hardware_measurements_verified=ctx["hardware_measurements_verified"],
                components=ctx["components"], entries=tuple(entries),
            )
            stored = idn.pending_pin()
            if stored is not None and stored.consent_key == new.consent_key:
                new = replace(new, staged_at=stored.staged_at,
                              models_seen=tuple(dict.fromkeys(stored.models_seen + new.models_seen)))
                if new == stored and all(a.observed == b.observed
                                         for a, b in zip(new.entries, stored.entries, strict=False)):
                    return stored
            idn.pending, idn.pending_batch = list(new.entries), _batch_to(new)
            self.save_file(pf)
            return new

    def refresh_pending(self) -> list[PendingPin]:
        """Recompute every pending NEAR model entry's pinned names from the cached inner compose texts:
        once the tags of every service can be shown, ``services`` joins the pinned components (a new
        consent key, so the person is asked about what is now pinned). Returns the refreshed batches."""
        from .review import map_tags
        with self._mutating():
            pf = self.load_file()
            changed = False
            for idn in pf.identities:
                ents = []
                for e in idn.pending:
                    if e.vendor != "near" or e.cvm_role == "gateway" or e.cvm_role in WHOLE_RESULT_ROLES \
                            or e.components is None:
                        ents.append(e)
                        continue
                    obs = dict(e.observed or {})
                    tags, missing = map_tags(obs.get("services"), self.composes_dir)
                    obs["tags"], obs["tags_missing"] = tags, missing
                    pinned = set(e.pinned) | {SERVICES} if _services_pinnable(obs, tags) else set(e.pinned) - {SERVICES}
                    new = replace(e, pinned=tuple(sorted(pinned)), observed=obs,
                                  code_fingerprint=near_code_fingerprint(e.cvm_role, e.components, pinned))
                    changed = changed or new != e or obs != (e.observed or {})
                    ents.append(new)
                idn.pending = ents
            if changed:
                self.save_file(pf)
            return [p for p in (i.pending_pin() for i in pf.identities) if p is not None]

    def prefetch_composes(self, *, fetch: Any = None) -> list[PendingPin]:
        """Fetch and hash-check the inner compose files every pending NEAR entry's service map names (public
        GitHub texts, cached under pins/composes/), then refresh_pending(). Network errors are recorded on the
        entries by refresh_pending ("text not fetched"); never raises for them."""
        from .review import fetch_compose
        cdir = self.composes_dir
        try:
            batches = self.pending_all()
        except Exception:
            return []
        seen: set = set()
        for pend in batches:
            for ent in pend.entries:
                obs = ent.observed or {}
                for v in (obs.get("services") or {}).values():
                    if isinstance(v, Mapping) and v.get("file_sha256") not in seen:
                        seen.add(v.get("file_sha256"))
                        fetch_compose(cdir, v.get("commit"), v.get("file"), v.get("file_sha256"),
                                      repo=obs.get("github_repo"), fetch=fetch)
        return self.refresh_pending()

    def apply(self, pending: PendingPin, *, approved_via: str,
              approval_rule_key: str = DEFAULT_APPROVAL_RULE_KEY, approved_by: str = "human",
              approved_at: str | None = None, reviewed_by: str | None = None,
              review_note: str | None = None) -> PinEntry:
        """Approve ``pending``: a concurrent vendor (NEAR) adds its entries to the approved set, a
        replace-only vendor (Tinfoil) replaces the set with its entry. Raises PinStoreError when
        ``pending`` is no longer the stored batch (by consent key), and when policy (approved_by "policy")
        would add to a concurrent set. Returns the first approved entry."""
        if not approved_via:
            raise ValueError("approved_via (the approval surface) is required")
        with self._mutating():
            if not (_nonempty(pending.code_fingerprint) and _nonempty(pending.enclave_fingerprint)):
                raise PinStoreError("refusing to apply a pending pin with an empty fingerprint")
            pf = self.load_file()
            idn = pf.identity(pending.vendor, pending.router_repo)
            if idn is None:
                raise PinStoreError("pending pin changed since it was shown; not applied")
            stored = idn.pending_pin()
            key = consent_key(pending)
            if stored is None and idn.last_applied_key is not None and idn.last_applied_key == key and idn.approved:
                return idn.approved[-1]   # idempotent: this exact batch was already applied once
            if stored is None or stored.consent_key != key:
                raise PinStoreError("pending pin changed since it was shown; not applied")
            if approved_by == "policy" and idn.concurrent:
                raise PinStoreError("policy never adds to an approved set; a person must approve this")
            unpinned = [e.cvm_role for e in stored.entries
                        if e.vendor == "near" and str(e.cvm_role).startswith("model:")
                        and e.components is not None and SERVICES not in e.pinned]
            if unpinned:
                # Fail closed (Amendment 7): a NEAR model entry is approved only with its service map pinned,
                # which needs the socket tags of every service (`hermes confidential pins review` fetches them).
                raise PinStoreError(f"the service map of {', '.join(unpinned)} is not pinned; its socket tags cannot "
                                    "be shown until hermes confidential pins review fetches the inner compose files")
            if any(not (_nonempty(e.code_fingerprint) and _nonempty(e.enclave_fingerprint)) for e in stored.entries):
                raise PinStoreError("refusing to apply an entry with an empty fingerprint")
            current = idn.approved[-1] if idn.approved else None
            when = approved_at or _utc_now_iso()
            fresh = [replace(e, approved_by=approved_by, approved_at=when, approved_via=approved_via,
                             approval_rule_key=approval_rule_key, reviewed_by=reviewed_by, review_note=review_note,
                             release_tag=stored.release_tag, last_seen=idn.verifications,
                             previous=current.code_fingerprint if current else None,
                             previous_enclave_fingerprint=current.enclave_fingerprint if current else None,
                             platform=stored.platform or e.platform)
                     for e in stored.entries]
            if idn.concurrent:
                # Approving adds. A migrated whole-result record gives way once the identity is approved again.
                kept = [a for a in idn.approved if a.cvm_role != ROLE_RESULT]
                have = {a.pin_key for a in kept}
                idn.approved = kept + [e for e in fresh if e.pin_key not in have]
            else:
                models = tuple(dict.fromkeys((current.models_seen if current else ()) + stored.models_seen))
                idn.approved = [replace(fresh[0], models_seen=models)]
            idn.pending, idn.pending_batch, idn.last_applied_key = [], None, key
            self.save_file(pf)
            return next((a for a in idn.approved if a.pin_key == fresh[0].pin_key), idn.approved[-1])

    def retire(self, fingerprint: str, router_repo: str | None = None) -> PinEntry:
        """Remove the one approved entry whose code (or enclave) fingerprint is ``fingerprint`` or starts
        with it (at least 8 hex digits), in identity ``router_repo`` when given (one gateway entry can be
        approved under several identities). Raises PinStoreError when none or several match."""
        fp = str(fingerprint or "").strip().lower()
        if len(fp) < 8 or any(c not in "0123456789abcdef" for c in fp):
            raise PinStoreError("give at least 8 hex digits of a code or enclave fingerprint")
        with self._mutating():
            pf = self.load_file()
            hits = [(i, e) for i in pf.identities for e in i.approved
                    if (router_repo is None or i.router_repo == router_repo)
                    and (e.code_fingerprint.startswith(fp) or e.enclave_fingerprint.startswith(fp))]
            if not hits:
                raise PinStoreError(f"no approved entry has a fingerprint starting {fp}"
                                    + (f" in identity {router_repo}" if router_repo else ""))
            if len(hits) > 1:
                where = sorted({i.router_repo for i, _ in hits})
                raise PinStoreError(f"{len(hits)} approved entries match {fp}; give more digits"
                                    + (f", or name the identity ({', '.join(where)})" if len(where) > 1 else ""))
            idn, e = hits[0]
            idn.approved.remove(e)
            self.save_file(pf)
            return e

    def clear_pending(self, vendor: str | None = None, router_repo: str | None = None) -> None:
        with self._mutating():
            pf = self.load_file()
            for i in pf.identities:
                if (vendor is None or i.vendor == vendor) and (router_repo is None or i.router_repo == router_repo):
                    i.pending, i.pending_batch = [], None
            self.save_file(pf)

    def note_model(self, vendor: str, router_repo: str, model: str) -> None:
        """Add ``model`` to the latest approved entry's models_seen label list (no effect on matching)."""
        if not model:
            return
        with self._mutating():
            pf = self.load_file()
            idn = pf.identity(vendor, router_repo)
            if idn is None or not idn.approved or model in idn.approved[-1].models_seen:
                return
            last = idn.approved[-1]
            idn.approved[-1] = replace(last, models_seen=last.models_seen + (model,))
            self.save_file(pf)


def _services_pinnable(observed: Mapping, tags: Any) -> bool:
    """A model entry pins its service map when every service is tagged, or when there is no map at all (no
    compose-manager block: the absence itself is then pinned, value None)."""
    return tags is not None or not observed.get("services")


def _latest(pf: PinFile) -> PendingPin | None:
    batches = [p for p in (i.pending_pin() for i in pf.identities) if p is not None]
    if not batches:
        return None
    return max(enumerate(batches), key=lambda t: (str(t[1].staged_at), t[0]))[1]

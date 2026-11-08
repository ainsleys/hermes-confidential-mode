# Adding an attested vendor

This guide describes what a new attested vendor needs: an adapter in `confidential_mode/verify/`, a
provider profile, pins, a replay module, setup, tests and documentation. Tinfoil
(`verify/tinfoil.py`) and NEAR AI Cloud (`verify/near.py`) are the two existing adapters, and every
rule below is read from their code. The last section, "Known coupling", lists the places where Tinfoil
or NEAR is named outside the adapters, so a third vendor also needs edits there.

Paths are relative to `confidential_mode/` unless the path starts with `tests/`, `docs/` or name a file at
the repository root (`__init__.py`, `plugin.yaml`, `pyproject.toml`, `catalog/`).
[INTERFACES.md](INTERFACES.md) is the developer contract. Its Amendments 5, 5.1, 5.2, 7 and 9 hold the
contract entries for the NEAR adapter, the nearest model for a third adapter's contract.

## The pieces of a vendor

| Piece | Tinfoil | NEAR AI Cloud |
|---|---|---|
| Adapter | `verify/tinfoil.py:TinfoilAdapter` | `verify/near.py:NearAdapter` |
| Pure checks (no I/O) | the vendor SDK (`tinfoil==0.14.2`), `verify/sev_check.py`, `verify/policy_check.py` | `verify/near_checks.py`, `verify/near.py:appraise` |
| Request encryption | the SDK's EHBP transport | `verify/near_e2ee.py` |
| Provider profile | `provider.py:register_provider_profile` | `provider.py:register_near_profile` |
| Profile name, key variable | `attested-tinfoil`, `TINFOIL_API_KEY` | `attested-near`, `NEAR_AI_API_KEY` |
| Offline replay | `verify/replay.py:replay` | `verify/replay_near.py:replay`, `replay_receipt` |
| Setup | `commands.py:cli_setup` | `commands.py:cli_setup_near` |
| Pin identity (`router_repo`) | `tinfoilsh/confidential-model-router` | `<host>#<model,model,...>` |
| Pin entries | one `router` entry per result | one entry per CVM (`gateway`, `model:<id>`) |
| Real capture | `tests/fixtures/real_capture_sev/` | `tests/fixtures/near_real_capture/` |
| Synthetic world | `tests/scenario/_fakes.py:FakeVendorAdapter`, `tests/unit/test_client.py:FakeAdapter` | `tests/near_world.py:NearWorld` |

## The adapter contract

`verify/base.py` declares the frozen part: `VendorAdapter` (`vendor`, `verify()`, `sync_http_view()`,
`async_http_for_loop()`), `VerificationResult`, `PreparedVerification`, `VerifyError` and
`VendorHTTPError`. The verification cache (`provider.py:VerificationCache`), the client
(`client.py:ConfidentialClient`) and the commands use more than the protocol declares. An adapter
provides all of the following.

### Identity and host

| Member | Contract |
|---|---|
| `vendor: str` | Lower-case vendor name. Written into every `VerificationResult`, pin and ledger row. |
| `enclave_host` (property) | The resolved host, or `""` while unresolved. Never touches the network. |
| `base_url` (property) | `https://<host>/v1`, or an unroutable `.invalid` placeholder while unresolved (`verify/tinfoil.py:PLACEHOLDER_BASE_URL`). `provider.py:_sync_profile_base_url` copies the resolved value into the profile after each verification, and `tiers.py:AttestedPredicate` compares a call's host with that value. |
| `resolve_enclave_host()` | Resolves the host once (config first, then vendor discovery) and returns the host; raises `VerifyError`. Called from `verify()` or a setup command, never from `register(ctx)`. |

### Verification

| Member | Contract |
|---|---|
| `prepare_verification() -> PreparedVerification` | Captures and checks one verification over the network and publishes nothing: no pool swap, no change to the accepted result. Raises `VerifyError` (or `VendorHTTPError` when a vendor endpoint answered with an HTTP error) on any failure; never returns a partial result. Holds no lock that a send takes. |
| `commit_verification(prepared, *, hold: bool) -> VerificationResult` | Publishes a prepared verification under the adapter lock: the accepted result, and any pool or key the prepared verification carries. With `hold=True` the transport is held before the result is published. Raises `VerifyError` when the adapter is closed or the prepared result no longer applies (NEAR: a model signing key changed). |
| `verify() -> VerificationResult` | `commit_verification(prepare_verification(), hold=<hold until accepted>)`. The inline path. |
| `hold(reason)`, `release()`, `held_reason` | A held transport refuses every send in every view (`_check_not_held`). The cache holds on a failure, a pin mismatch or a missing consent row, and releases after the pins match. |
| `last_result`, `verified_mono` | The accepted result and its `time.monotonic()` time. `VerificationCache._adopt_adapter_result` adopts a result a setup command produced by calling the adapter directly. |
| `closed`, `close()` | After `close()`, `commit_verification` raises and the cache's `on_close` hook stops the background refresh. |
| `mark_stale(reason) -> bool` | Holds the transport, clears `verified_mono` and calls `on_stale`, at most once per `reverify_backoff_seconds` (30 s on both adapters), so that a TLS intermediary cannot force an attestation per turn. |

The split between `prepare_verification` and `commit_verification` is what the background refresh
(`provider.py:BackgroundRefresh`) needs. An adapter without both methods keeps working on the inline
path only (`VerificationCache.background_allowed` returns False).

### `VerificationResult` and the evidence

| Field | Contract |
|---|---|
| `vendor` | As above. |
| `router_repo` | The pin identity. Any change to what the identity covers (Tinfoil: the router repository; NEAR: host and model allowlist) is a new identity and a new pin. |
| `enclave_host` | The host the verification bound. |
| `code_fingerprint`, `enclave_fingerprint` | Non-empty hex strings. `pins.py:PinStore.stage` refuses empty ones, and `VerificationCache._stage` refuses with "attestation returned no usable fingerprints". Code covers what runs (release digest, compose hash); enclave covers the platform measurement (firmware, kernel, launch measurement). Values that differ per instance (instance ids, signing keys, RTMR3 on NEAR) are checked per verification and kept out of both fingerprints. |
| `release_tag` | A signed release tag, or None when the vendor publishes none (NEAR). |
| `verifier` | A string naming the verifier and its version. |
| `verified_at_host_clock` | `time.time()`. Shown everywhere as the host clock; never used for freshness (the cache uses `time.monotonic()`). |
| `evidence` | The raw, JSON-serialisable capture. See below. |

The `evidence` dict is stored in the `verify_ok` row, embedded in JSON receipts and replayed offline.
Its keys:

- `schema` (a versioned string such as `confidential-mode/near-evidence/v2`), `vendor`, `repo`,
  `platform`, `enclave_host`, `sdk_version`, `captured_at` (ISO), `captured_at_unix`.
- `capture_complete: True` only when every input the replay needs was captured. Anything else makes
  the row an "unverified entry" in receipts (`receipts.py:is_unverified_entry`).
- `claims`: `code_fingerprint`, `enclave_fingerprint`, `release_tag`, and the keys sends are bound to:
  `tls_public_key_fp` (SPKI SHA-256 hex) and, for an HPKE transport, `hpke_public_key`.
  `receipts.py:verify_facts` and `receipts.py:_send_coverage` read these. A vendor with several CVMs
  adds `claims.cvms` (see "Pins").
- `blobs` (optional): large strings keyed by their SHA-256. `ledger.py:externalize_evidence` moves
  the blobs to `<data dir>/evidence/blobs/` and keeps `blob_refs` in the row; `receipts.py:_evidence_item`
  joins the blobs back. A blob is at most 8 MB (`ledger.py:MAX_BLOB_BYTES`).

Two ledger rules bind the evidence. The row detail, evidence included, must fit
`ledger.py:MAX_DETAIL_BYTES` (256 KB) once blobs are moved out. No key anywhere in the detail may be
one of `ledger.py:FORBIDDEN_DETAIL_KEYS` (`messages`, `prompt`, `prompts`, `request`, `input`,
`instructions`, `system`, `content`, `contents`); rename such keys in a vendor report before storing
the report. A `verify_ok` row that cannot be written refuses the verification (`REASON_VERIFY_ROW_LOST`), so
breaking either rule makes the vendor unusable rather than unrecorded.

### Transport views and the TLS pin per send

`client.py:ConfidentialClient` builds `openai.OpenAI(http_client=adapter.sync_http_view())` and, per
running event loop, `openai.AsyncOpenAI(http_client=adapter.async_http_for_loop())`. Both views:

- forward to the adapter's current pinned pool, and never close that pool on `close()`;
- refuse while held (`_check_not_held()`), before any request byte;
- send only on connections pinned to the TLS key of the accepted result.
  `verify/near.py:pinned_ssl_context(expected_spki, ...)` builds an SSL context that keeps the normal
  chain and host-name checks and compares the peer's SPKI SHA-256 with `expected_spki()` inside
  `wrap_socket` and the `wrap_bio` handshake. Both adapters use the function; `expected_spki` reads
  the accepted result, never a value the vendor SDK holds before the pin check
  (`TinfoilAdapter.expected_tls_fp`, `NearAdapter.pinned_spki`). With no accepted fingerprint the
  context refuses every connection;
- on `TLSPinMismatch`, call `mark_stale` and write the row described below.

The attestation fetch uses a separate, unpinned pool (`NearAdapter._attest_pool`), because the
certificate that pool sees is what the evidence is checked against. Attestation requests carry no API key.

### Ledger rows the adapter writes

The cache sets `adapter.event_sink` (a callable taking one row dict; `provider` is filled in) and
writes `verify_ok`, `verify_fail` and `pin_staged` itself for every verification the cache runs. The adapter
writes through `event_sink` only what the cache cannot see:

| Row | When | Detail the adapter supplies |
|---|---|---|
| `verify_ok` | A verification the SDK runs on its own, such as a key rotation (Tinfoil `source: silent_reattest` or `async_pool`). Only for the same build: a changed fingerprint raises instead. | `vendor`, `source`, both fingerprints, `release_tag`, `enclave_host`, `verifier`, `key_first_seen`, `evidence`. |
| `verify_fail` with purpose `tls_pin` | A send met another certificate (Tinfoil). | `vendor`, `reason_code: tls_pin_mismatch`, `reason`, `expected_tls_key_fp`, `path`, `reverify_requested`, `nothing_sent: True`. |
| `send_signed` | One row per exchange, for a vendor that signs responses (NEAR). Session, purpose and tier come from `sendctx.current()`. | Request and response SHA-256 and sizes, the signature and its check, `fully_attested`, `attestation_nonce` (ties the row to its evidence), TLS SPKI seen, encryption report. A TLS pin mismatch is a row with "TLS pin mismatch, nothing sent". |
| `send_refused` | The transport refused a send (`record_refusal(exc, stage=...)`), unless `sendctx.current()["refusals_ledgered_by"] == "llm_gate"`, in which case the llm gate writes the row. Each refusal object is recorded once (`exc.ledgered`). | `vendor`, `source`, `reason_code`, `reason`, `stage`, `endpoint`, `status_code`. |
| `notice` | Something the user is told without a refusal (NEAR: the first plaintext image part of a lock, through `on_plaintext_parts`, written by `__init__.py:_image_notice`). | |

`send_observed` is written by the llm gate (`gate_llm.py:LlmGate.guarded_call`), not by the
adapter. A transport that observes each HTTP exchange calls `sendctx.add_record(record)` with the
fields in `gate_llm.py:SEND_RECORD_FIELDS` (`hpke_key_used`, `encrypted`, `response_decrypted`,
`tls_spki_sha256`, `tls_matches_report`, ...), and the gate copies those fields into its row
(`TinfoilAdapter._observe_send`). A new ledger kind needs `ledger.py:KINDS` and
`tests/unit/test_ledger.py::test_kinds_match_contract` changed together.

### Hooks the cache wires

`provider.py:VerificationCache._wire_adapter_sink` sets these attributes on an adapter that defines the attributes:
`event_sink`, `on_close` (stops the background refresh), `on_stale` (invalidates the cache entry, so
the next call verifies inline). Optional members other modules read when present:
`observe_key(host, tls_fp, hpke)` (first-seen record per key pair, Tinfoil),
`record_refusal(exc, stage=...)` (NEAR; otherwise the cache writes provider-gate refusals itself),
`provider_name`, `encryption_ready()`, `encrypt`, `require_tls_binding` and `image_parts` (read by the
NEAR preflight rows), `models` (NEAR setup), `enclave_source` (status).

## Profile registration

`provider.py:make_profile(adapter, pins, ttl_seconds, *, name, display_name, description, env_var,
supports_streaming, context_length, ...)` builds a Hermes `ProviderProfile` subclass whose
`create_client` returns a `ConfidentialClient` after `VerificationCache.ensure` passes, and a
`RefusingClient` otherwise (no key, verification failed or pending, pin mismatch). The client never
raises and is never None. `get_model_context_length` returns a fixed number so Hermes' context-length
probes never reach the host off the attested transport. `classify_api_error` is
`provider.py:classify_refusal`, which answers (always with `should_fallback: False`) only for an
exception whose class name is `NearRefusal` and returns None for every other exception, so Hermes' own
classifier decides another vendor's errors. The llm gate's `guarded_call` keeps the fallback unarmed
for every vendor either way.

`make_profile`'s defaults are Tinfoil's: `name` (`attested-tinfoil`), `display_name`, `description`,
`env_var` (`TINFOIL_API_KEY`) and the subclass name `AttestedTinfoilProfile`. A new vendor passes
every one of `name`, `display_name`, `description`, `env_var`, `supports_streaming` (False when the
vendor signs only unstreamed replies or encrypts requests), `context_length`, `verify_wait_seconds`,
`refresh_lead_seconds` and `ledger`, and the `ttl_seconds` read from `confidential.verify_ttl_seconds`.

A new vendor adds `register_<vendor>_profile(ctx, *, config, data_dir, adapter, pins, on_event,
ledger)` beside the two existing functions. The function reads its config keys under
`confidential.<vendor>`, builds the adapter without network I/O, shares the plugin's one `PinStore`
(`pins.yaml`) and ledger, calls `make_profile` with the vendor's profile name and key variable, and
calls `providers.register_provider(profile)`. The API key is read only through
`provider.py:api_key_for(env_var)` (`agent.secret_scope.get_secret`).

## Background refresh

`provider.py:BackgroundRefresh` is one daemon thread per cache entry. The thread runs only while the
profile is locked (`provider.py:set_background_gate`), the adapter is open and has both
`prepare_verification` and `commit_verification`, and `confidential.verify_refresh_lead_seconds` is
positive (default 60 s). At the lead before the TTL ends (default TTL 300 s), the thread calls
`prepare_verification()`, runs the pin and consent check on the new result, and only then calls
`commit_verification(prepared, hold=False)` and swaps the result into the cache. A result the pins do
not accept is staged (a `pin_staged` row), never committed; the verification in use keeps vouching
until its TTL ends. Every attempt writes `verify_ok` or `verify_fail` with `source: background`. An
adapter therefore keeps `prepare_verification` free of side effects and makes `discard()` on the
`PreparedVerification` release whatever the capture built (Tinfoil: the unused connection pool).

## Pins

`pins.py` stores `pins.yaml` version 3: per (vendor, identity) an approved set of entries, a pending
batch and a verification count.

- **Identity.** `router_repo` is the identity a pin is keyed by. Choose a string that changes whenever
  the set of things being trusted changes (NEAR: `identity_for(host, models)`).
- **Whole-result entries.** A vendor whose result is one enclave gets one entry with
  `cvm_role: router` and the result's two fingerprints, byte for byte. `set_match` matches the entry against
  the whole result. Approval replaces the set (`VENDOR_POLICY[vendor]["concurrent"]` False, the
  default for an unknown vendor).
- **Per-CVM entries.** A vendor with several CVMs reports `evidence.claims.cvms`, one dict per CVM
  with `role`, `measurement`, `app_id`, `compose_hash`, `os_image_hash`, `kms_id`, `instance_id` and
  (for models) `services_sha256` and `cm_image_reported`. `pins.py:views_from_cvms` turns these into
  `CvmView`s, `near_code_fingerprint` and `near_enclave_fingerprint` compute each entry's
  fingerprints, and approval adds to the set (`concurrent: True`). The per-CVM path runs only
  when `result.vendor == "near"` (see "Known coupling").
- **Consent.** A matching entry counts only with a `pin_applied` row that names its fingerprints and no
  later `pin_retired` row (`provider.py:_consent_recorded`). Only `consent.py` (a person's exact
  Approve) and `provider.py:_auto_apply` (Tinfoil, platform-only, opt-in) call `PinStore.apply`.

## Replay module

Each vendor has an offline replay module beside its adapter. The contract, from `verify/replay.py`
and `verify/replay_near.py`:

- `replay(evidence, *, as_of=None, expected_repo=None, expected_fingerprints=None, ...)` re-runs every
  check on the stored bytes with no network, never raises, and returns a frozen result with `ok`,
  `checks` (each value `True` or a string starting `fail:`, `n/a:` or `not_run:`), `code_fingerprint`,
  `enclave_fingerprint`, `release_tag`, `as_of`, `sdk_version`, `repo`, `enclave_host_asserted`,
  `platform`, `captured_at_asserted`, `not_established` and, for per-CVM vendors, `cvms`.
  `commands.py:_call_replay` passes only the keyword arguments the function accepts and reports the
  identity checks that function cannot take.
- The checks are the same functions the live verification ran (NEAR: `appraise` in both), with every
  clock pinned to `as_of`, which defaults to the capture time.
- Every network library raises inside the replaying thread (`verify/replay.py:_network_ban`).
- A vendor that signs responses also provides a per-row check (`replay_signed_send`) and a
  whole-receipt pass (`replay_receipt`) that `receipts.py` and `hermes confidential replay` call.

`commands.py:cli_replay` picks the replay function by `evidence["schema"]`, so a new vendor's schema
string must be distinct and registered there.

## Setup

`hermes confidential setup` dispatches on `--vendor` (`commands.py:register_cli`, choices
`tinfoil` and `near`; `commands.py:cli_setup`). A vendor's setup function:

1. prints whether the key variable is set (`"set"` or the not-set text), never the key;
2. resolves the host, invalidates the cache entry and calls
   `verification_cache.ensure(<profile>, wait_seconds=INTERACTIVE_VERIFY_WAIT_SECONDS)`;
3. prints the fingerprints, stages the result when no pin matches (`rt.pins.stage`) and asks with
   `consent.approve_pending_pin(TerminalAsker(), ...)`;
4. prints a config block to merge into `config.yaml` (setup never writes the config);
5. prints `setup_next_steps(rt, vendor=..., key_env=..., ...)`.

## Tests

The suite is organised as `tests/unit/` (no Hermes import), `tests/seam/` (real Hermes modules,
fakes only at the SDK, network and human boundaries), `tests/hostile/` (adversarial inputs),
`tests/fault/` (injected failures), `tests/scenario/` and `tests/live/` (real vendor, skipped without
a key). A new vendor brings:

- **A real capture** under `tests/fixtures/<vendor>_real_capture/`: the vendor's public attestation
  responses, as returned, with a `_note` naming where and when each was captured. Tests replay the
  capture with `as_of` pinned to the capture time, so the tests keep passing after certificates and tokens
  expire (`tests/unit/test_near_real_capture.py`, `tests/unit/test_real_capture.py`).
- **A synthetic world** that serves the vendor's endpoints through `httpx.MockTransport` and signs
  with keys the world generates, faking only the hardware quote (`tests/near_world.py:NearWorld`,
  `NearWorld.adapter(tmp_path)`). `NearAdapter` takes `transport_factory`, `send_transport_factory`,
  `quote_verifier`, `ita_roots`, `clock` and `sleep` arguments so the world can be injected;
  `TinfoilAdapter` takes `router_discovery` and `tls_base_context`. A new adapter takes the same kind of
  arguments for every network and clock dependency.
- **Tests per contract line**: a pin mismatch refuses with zero requests and stages a batch; the TLS
  pin refuses before any request byte, sync and async; a mismatch writes its row and re-verifies once;
  `prepare_verification` publishes nothing; tampered evidence fails the right replay check; evidence
  fits the ledger. The NEAR files `tests/unit/test_near.py`, `tests/hostile/test_near_tls_pin_hostile.py`,
  `tests/hostile/test_near_e2ee_hostile.py` and `tests/unit/test_background_refresh.py` are the
  models.
- **A live test** under `tests/live/`, skipped unless the vendor key is set.

The suite runs from a Hermes checkout as [RUNNING_TESTS.md](RUNNING_TESTS.md) describes.

## Documentation to update

- [LIMITATIONS.md](LIMITATIONS.md): a numbered section for the vendor, in the four-part form (the gap,
  why the gap exists, what the plugin does, the change that would close the gap), like section 14 for NEAR.
- [DISCLOSURE.md](DISCLOSURE.md): the hosts contacted ("Which hosts it contacts", "When it verifies
  again"), the files written ("What it writes in its own data"), the threads started ("Processes and
  threads"), the credential ("Credentials", "Environment variables"), and the private core import
  count, which `tests/seam/test_disclosure_imports.py` compares with `hermes plugins validate`.
- `plugin.yaml` and `catalog/confidential-mode.yaml`: the `description` (hosts contacted, the key
  variable, threads), `requires_env` (`TINFOIL_API_KEY` only, in both files) and `optional_env` in
  `plugin.yaml`, and `known_issues` in the catalog entry.
- `pyproject.toml`: the vendor's dependencies, each with an upper bound.
- [GUIDE.md](GUIDE.md): a chapter like "The attested tier with NEAR AI", and the tiers chapter.
- [CLAIMS.md](CLAIMS.md): every entry that names "both vendors" or a vendor's mechanism (P7, P8, P10,
  P11, P12, R4, R5, L1).
- The README's first screen, when the new vendor changes what the plugin claims.

## Known coupling

The adapter protocol does not carry every vendor difference. These places name Tinfoil or NEAR
outside the adapters; a third vendor edits each one.

- **Profile lists.** `locking.py:ATTESTED_PROFILES`, `locking.py:PROFILE_NAME`,
  `locking.py:NEAR_PROFILE_NAME`, `locking.py:VENDOR_NAMES` and `provider.py:ATTESTED_PROFILES` (the
  same tuple, repeated so `locking.py` imports no SDK code); `preflight.py:ATTESTED_KEY_ENVS` (profile
  to key variable); `preflight.py:provider_value_hint` and `_main_provider_fix` (fix texts that name
  both profiles).
- **Registration.** `__init__.py:_register` has one step per vendor (`provider`, `provider_near`), and
  `__init__.py:Runtime` holds `adapter`, `near_adapter`, `profile` and `near_profile` by vendor.
  `__init__.py:_image_notice` is NEAR's plaintext-image notice.
- **Preflight rows.** `preflight.py:_near_encryption_items` adds the NEAR-only rows
  (`confidential.near.encrypt`, `require_tls_binding`, `image_parts`, the encryption library, the
  chat-completions-only API mode).
- **Pins.** `pins.py` branches on `result.vendor == "near"` for per-CVM views
  (`PinStore.match`/`matching_entries`, `observe`, `stage`), in `PinStore.apply` (a NEAR model entry
  is approved only with its service map pinned) and `PinStore.refresh_pending` (recomputes NEAR model
  entries only), and in `_whole_role`;
  `pins.py:VENDOR_POLICY` lists `concurrent` per vendor; `pins.py:NEAR_GATEWAY_REQUIRED`,
  `NEAR_MODEL_REQUIRED` and `near_code_fingerprint` define the per-CVM components;
  `provider.py:AUTO_APPLY_VENDORS` is Tinfoil only.
- **Consent and review.** `consent.py:pin_question` shows `_near_pin_question` for NEAR and a
  release-and-Sigstore prompt for every other vendor; `consent.py:_approve_batch` words the NEAR result
  ("added to the approved set") apart from every other vendor's. `review.py:brief` picks `NEAR_QUESTIONS` or
  `TINFOIL_QUESTIONS`; `review.py:build_bundle` adds release links for every vendor except NEAR, and
  `review.py:entry_review` shows per-component diffs and inner compose files only for entries that carry
  `components` (NEAR's per-CVM entries).
- **Provider.** `provider.py:make_profile` defaults to Tinfoil's names (see "Profile registration");
  `provider.py:classify_refusal` answers only for `NearRefusal`; `provider.py:image_parts_from` reads
  `confidential.near.image_parts`.
- **Verification detail.** `provider.py:_policy_check_detail` runs the Sigstore release-bundle check
  for every vendor except NEAR, so a third vendor without a Sigstore bundle records "evidence
  incomplete" in that non-gating field until the function learns the vendor.
- **Status.** `commands.py:_verification_line` prints a Tinfoil line and a NEAR line
  (`_tinfoil_verification_line`, `_near_verification_line`); `commands.py:_enclave_line` reads
  `rt.adapter` (Tinfoil) only.
- **Setup and replay.** `commands.py:register_cli` (`--vendor` choices), `commands.py:cli_setup`,
  `cli_setup_near`, `config_block`, `near_config_block`, `attest_near_models`;
  `commands.py:HELP_LINES` and `commands.py:TERMINAL_ONLY` (the setup text names `[--vendor near]`);
  `commands.py:TINFOIL_DOCUMENTED_MODELS` and `tinfoil_model_note`; `commands.py:DEFAULT_NEAR_MODEL`,
  `DEFAULT_NEAR_VISION_MODEL` and `near_model_failure`. `commands.py:cli_replay` falls back to the
  Tinfoil replay for any schema that is not NEAR's, labels a row's vendor `tinfoil` when neither the
  row nor the evidence names one, and `DEFAULT_EXPECTED_REPO` is Tinfoil's router repository.
- **Receipts.** `receipts.py:_near_sends`, `NEAR_CLOSING` and `NEAR_ENCRYPTION_NOTE` render the
  signed-response section for NEAR rows only; `receipts.py:verify_chain` checks those constants.
  `CLOSING_PARAGRAPH` speaks of a router, a release tag and an HPKE key, which is Tinfoil's shape.
- **Manifest.** `plugin.yaml` and the catalog entry list `TINFOIL_API_KEY` as the only required
  variable.
- **Client.** `client.py:ConfidentialClient` assumes an OpenAI-compatible API, and passes the
  placeholder key `"tinfoil"` to the OpenAI client when Hermes supplies none.
- **SDK patching.** `verify/_sdkpatch.py` (cache redirect, capture hooks, the thread-scoped overrides)
  is written for the Tinfoil SDK 0.14.2 and its `sigstore` internals.
- **Shared checks.** `verify/near_checks.py` is pure and holds checks whose form is not specific to
  NEAR: a TDX quote through the Tinfoil SDK's verifier, MRCONFIGID against an `app_compose`, RTMR3
  event-log replay, and Intel Trust Authority JWTs against pinned roots. A vendor whose CVMs report the
  same structures can call these functions; the module and its constants still carry NEAR's name.

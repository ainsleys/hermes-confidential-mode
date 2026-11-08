# Module map

This file describes each module of the plugin: what the module is for, its main entry points, the plugin
modules it imports, and the [INTERFACES.md](INTERFACES.md) section that holds the module's contract. Paths are
under `confidential_mode/` except the root `__init__.py`. "Imports" lists plugin modules only; a module
that names none imports no other plugin module. An import inside a function is marked "lazy", and an
import used only for type annotations is marked "types". Hermes' private names are reached only through
`hermes_compat.py` ([Hermes private names](INTERFACES.md#hermes-private-names)); the other modules import only Hermes' documented plugin surface.

A module that was split keeps every public name, and every private name another file used, importable
from its old path: `verify/near.py`, `gate_tools.py` and `commands.py` import those names back as
`X as X` ([Conventions](INTERFACES.md#conventions)).

## Entry point

**`__init__.py`** (repository root). `register(ctx)` builds one `Runtime` (ledger, lock state, pins,
adapters, allowlist, approval decisions) and wires it into Hermes: the `llm_execution` and
`tool_execution` middleware, the `pre_tool_call`, `post_approval_response`, `pre_llm_call`,
`pre_api_request`, `pre_auxiliary_call`, `post_auxiliary_call`, session and `pre_gateway_dispatch` hooks,
the two provider profiles, the `/confidential` command and the `hermes confidential` CLI.
`Runtime.turn_check` is the per-turn recheck; `_aux` and `_observe` record side calls and breaches. One
failing registration step never stops the others, and `register` never raises. Imports (lazy, by name
through `_cm`): `_version`, `commands`, `gate_llm`, `gate_tools`, `hermes_compat`, `ledger`, `locking`,
`pins`, `preflight`, `progress`, `provider`, `revoke`, `sendctx`, `state`, `tiers`. Contract: [Registration and hooks](INTERFACES.md#registration-and-hooks) and [Lock, unlock and the per-turn check](INTERFACES.md#lock-unlock-and-the-per-turn-check).

## Tiers, preflight and the lock

**`tiers.py`**. The frozen shared types (`Tier`, `Destination`, `Verdict`, `TierPredicate`) and the
predicates: `OnHostPredicate` (loopback, the machine's own host name, and hosts listed in
`confidential.on_host.extra_hosts`), `AttestedPredicate` (a registered attested profile whose
verification is fresh and pinned) and the zero-retention stub. `host_of` and `strict_host` parse URLs and
refuse any form the parsers disagree on. Imports nothing. Contract: [Shared types](INTERFACES.md#shared-types) and [Tiers](INTERFACES.md#tiers).

**`preflight.py`**. `run_preflight(tier, config)` classifies every route Hermes' core config can send
conversation bytes over (main model, fallbacks, every auxiliary task, delegation, memory, TTS, MCP
servers, plugin isolation, hook timeouts, the terminal backend, NEAR's encryption settings) and returns a
`PreflightReport` whose rows carry a verdict and a fix. `config_fingerprint` hashes exactly those keys
for the per-turn recheck; `format_report` prints the table. Imports `tiers`; lazy: `hermes_compat`,
`verify.near_e2ee`. Contract: [Preflight](INTERFACES.md#preflight).

**`locking.py`**. `lock(tier, ...)` runs the preflight, builds the tool allowlist and writes the lock
state under the transition lock; `unlock(...)` clears it and prints the lock period's counts;
`recheck(...)` re-runs the preflight structure for `pre_llm_call`; `predicate_for` and
`structural_predicate` pick the tier's predicate; `lock_disclosures` is the text every lock prints.
`ATTESTED_PROFILES` names the attested profiles. Imports `ledger`, `preflight`, `tiers`; lazy:
`filelock`, `gate_tools`, `hermes_compat`, `provider`. Contract: [Lock, unlock and the per-turn check](INTERFACES.md#lock-unlock-and-the-per-turn-check).

**`state.py`**. `ConfidentialState`, strict accessors over `ctx.state` for the frozen keys (`locked`,
`locked_tier`, `locked_since`, `config_fingerprint`, `breached_sessions`); a malformed value raises
`StateError`, so the gates fail closed. `InMemoryState` is the test stand-in. Imports `atomicwrite`, `tiers`;
lazy: `filelock`. Contract: [Lock, unlock and the per-turn check](INTERFACES.md#lock-unlock-and-the-per-turn-check).

## The gates

**`gate_llm.py`**. `LlmGate.handle`, the `llm_execution` middleware: unlocked, it records the send and
passes it on; locked, it classifies the destination and refuses off-tier sends before `next_call`, and
`LlmGate.guarded_call` turns any provider error into a refusal so Hermes' fallback never arms. The
refusal builders return the response object each `api_mode` expects. `build_middleware` wraps it so no
exception escapes. Imports `ledger`, `state`, `tiers`; lazy: `sendctx`, `verify.base`. Contract: [The llm gate](INTERFACES.md#the-llm-gate).

**`gate_tools.py`**. The tool gate's three entry points: `build_pre_tool_call` (the hook that asks or
blocks), `build_tool_execution` (the middleware that runs a tool only on an exact recorded answer, or a
grant) and `build_post_approval_response` (the observer that records each answer). Imports
`gate_tools_allowlist`, `gate_tools_calls`, `gate_tools_classify`, `gate_tools_grants`,
`gate_tools_hermes`, `gate_tools_policy`, `selfapproval`. Contract: [The tool gate](INTERFACES.md#the-tool-gate).

**`gate_tools_classify.py`**. `classify_tool` gives each registered tool its `Route` (on-host, ask,
delegate, block-cron, block-mcp-url) from its name, toolset and `Origin`; `BUILTIN_TOOL_CLASSES` is the
data-flow class (on-host, off-host, unsettled) of every built-in tool at Hermes 84a0301, the same table as
[TOOL_CLASSES.md](TOOL_CLASSES.md), and `ON_HOST_TOOLS` is its on-host rows. The `_default_*` readers find
MCP server configs and plugin tool names. Imports nothing at load; lazy: `hermes_compat`, `tiers`. Contract: [Classification](INTERFACES.md#classification).

**`gate_tools_allowlist.py`**. `build_allowlist` classifies Hermes' live registry at lock; `Allowlist`
records each entry's route and handler identity, persists the set to `allowlist.yaml`, adds the tools a
person allowed (`Allowlist.add`, `Allowlist.persist`) and treats a tool whose handler or toolset changed
as unclassified. `ensure_tools_for_lock` loads the tool modules first; `format_allowlist` prints the
lists; `lock_id_for` names the lock a grant belongs to. Imports `atomicwrite`, `gate_tools_classify`; lazy:
`hermes_compat`, `revoke`. Contract: [The allowlist](INTERFACES.md#the-allowlist).

**`gate_tools_hermes.py`**. The gate's view of Hermes' approval state: the rule keys it asks under
(`rule_key_for`, `parse_pattern_key`; a revoke moves the key to a new generation), whether a bypass would
auto-approve (`hermes_bypass_active`, `bypass_text`), Hermes' remembered grants
(`hermes_remembered_grant`), the terminal backend, and the prompt (`hermes_request_approval`). Imports
nothing at load; lazy: `hermes_compat`, `preflight`. Contract: [Decisions](INTERFACES.md#decisions).

**`gate_tools_calls.py`**. What one call carries: the self-approval guard's checks
(`invokes_confidential_cli`, `names_state_file`), the `delegate_task` route check
(`default_delegation_ok`), the call's size with attached images (`call_bytes`) and the ask text
(`ask_message`). Imports nothing at load; lazy: `hermes_compat`, `selfscan`. Contract: [Decisions](INTERFACES.md#decisions) and [Self-approval guard](INTERFACES.md#self-approval-guard).

**`gate_tools_grants.py`**. Answers and grants: `ApprovalDecisions` carries each answer from
`post_approval_response` to the middleware by tool_call_id; `LockGrants` holds the once-per-lock grants
of `confidential.tools.ask` (`ask_mode_from`), scoped to one conversation by `grant_scope`. Imports
nothing at load; lazy: `hermes_compat`. Contract: [Decisions](INTERFACES.md#decisions) and [The hook, the middleware and the observer](INTERFACES.md#the-hook-the-middleware-and-the-observer).

**`gate_tools_policy.py`**. `_Policy.decide` returns the `CallDecision` (run, refuse or ask) for one
locked call from the allowlist entry, the bypass state, the self-approval guard, the delegation check and
any grant; `_Policy.on_host_decision` covers on-host tools. The hook and the middleware share it. Imports
`gate_tools_allowlist`, `gate_tools_calls`, `gate_tools_classify`, `gate_tools_grants`,
`gate_tools_hermes`; lazy: `preflight`. Contract: [Decisions](INTERFACES.md#decisions).

**`selfapproval.py`**. `mark_tool_process` sets the tool-process marker before any tool runs, and
`self_approval_reason` makes every approval prompt refuse in a process that carries another process's
marker. Imports nothing. Contract: [Self-approval guard](INTERFACES.md#self-approval-guard).

**`selfscan.py`**. Decides from the literal text of a terminal, process_manage, execute_code, write_file
or patch call whether it would run the plugin's own command, import its package or write one of its state
files. Imports nothing. Contract: [Self-approval guard](INTERFACES.md#self-approval-guard).

## Attested providers and verification

**`provider.py`**. The attested provider profiles (`make_profile`, `register_provider_profile` for
`attested-tinfoil`, `register_near_profile` for `attested-near`), the `VerificationCache` (TTL, staging a
pending pin on a mismatch, `attested_ok`), `BackgroundRefresh` (re-verification ahead of expiry while
locked), `classify_refusal` and the platform-only auto-apply policy. `create_client` never raises and
never returns None. Imports `client`, `pins`, `tiers`, `verify.base`; lazy: `hermes_compat`, `ledger`,
`sendctx`, `verify.near`, `verify.policy_check`, `verify.tinfoil`. Contract: [Attested providers](INTERFACES.md#attested-providers).

**`client.py`**. `ConfidentialClient`, the dual sync and per-event-loop async OpenAI client on the
adapter's verified pools, and `RefusingClient`, whose every request raises `ConfidentialRefused`. Imports
nothing. Contract: [Attested providers](INTERFACES.md#attested-providers).

**`sendctx.py`**. Who a send belongs to (session, purpose, provider, tier), set by the llm gate around
`next_call` and, for auxiliary calls, from the `pre_auxiliary_call` hook, so a vendor transport can write
its own rows. Imports nothing at load; lazy: `hermes_compat`. Contract: [Vendor adapter interface](INTERFACES.md#vendor-adapter-interface).

**`verify/base.py`**. The frozen verification types: `VerificationResult`, `PreparedVerification`, the
`VendorAdapter` protocol, `VerifyError` and `VendorHTTPError`. Imports nothing. Contract: [Shared types](INTERFACES.md#shared-types) and [Vendor adapter interface](INTERFACES.md#vendor-adapter-interface).

**`verify/tinfoil.py`**. `TinfoilAdapter`, the Tinfoil adapter on SDK 0.14.2: one `SecureClient` per
profile, verification through the SDK's default path with the evidence captured (`prepare_verification`,
`commit_verification`), the pinned EHBP transports (`pinned_ehbp_sync_transport`, each with the guard that
turns a plaintext HTTP error reply into a `VendorHTTPError`), the TLS pin and its failure path, and
`parse_usage_metrics` for the router's token counts. Imports `atomicwrite`, `verify._sdkpatch`, `verify.base`;
lazy: `sendctx`, `verify.near_transport`. Contract: [Tinfoil adapter](INTERFACES.md#tinfoil-adapter).

**`verify/_sdkpatch.py`**. Thread-scoped overrides of tinfoil SDK internals for evidence capture and
offline replay (`overrides`, `capture_sink`), and the redirect of the SDK's on-disk caches into the
plugin data directory (`redirect_sdk_caches`). Imports nothing. Contract: [Tinfoil adapter](INTERFACES.md#tinfoil-adapter).

**`verify/near.py`**. `NearAdapter`, the NEAR AI Cloud adapter: `capture` and `prepare_verification`
fetch the gateway, model and Intel Trust Authority evidence; `commit_verification` accepts an appraisal;
`default_send_transport` and `default_async_transport` give Hermes the send views; `begin_exchange`,
`_encrypt`, `fetch_signature` and `finish_exchange` run one signed, encrypted send; `mark_stale` asks for
a re-verification. Imports `sendctx`, `verify.base`, `verify.near_appraise`, `verify.near_checks`,
`verify.near_evidence`, `verify.near_exchange`, `verify.near_send`, `verify.near_transport`; lazy:
`verify.near_e2ee`. Contract: [NEAR adapter](INTERFACES.md#near-adapter).

**`verify/near_evidence.py`**. The evidence document: `build_evidence` trims the captured responses into
schema `confidential-mode/near-evidence/v2` and keeps each large string in the document's `blobs` by
SHA-256 (`put_blob`, `resolve_blobs`). Imports `verify.near_checks`. Contract: [Evidence](INTERFACES.md#evidence).

**`verify/near_appraise.py`**. `appraise(evidence)` runs every check over one evidence document and
computes the pin identity, fingerprints and component lines; the live verify and the offline replay call
it on the same document. `evidence_claims` is what a `verify_ok` row carries. Imports
`verify.near_checks`, `verify.near_evidence`. Contract: [Verification](INTERFACES.md#verification) and [Evidence](INTERFACES.md#evidence).

**`verify/near_checks.py`**. Pure checks over captured bytes: report data and MRCONFIGID
(`check_report`), RTMR3, the TDX quote through tinfoil's verifier, the Intel Trust Authority JWT and JWKS
(`verify_jwt`), the compose-manager attestation (`check_compose_manager`) and response signatures
(`check_signature`). Imports nothing. Contract: [Verification](INTERFACES.md#verification).

**`verify/near_e2ee.py`**. NEAR request encryption as a pure library: `encrypt_request` seals every field
of NEAR's table to the model key, `decrypt_response` opens the reply with the per-exchange client key.
Imports nothing. Contract: [Sends](INTERFACES.md#sends).

**`verify/near_transport.py`**. `pinned_ssl_context`, the SSL context whose handshake fails with
`TLSPinMismatch` unless the peer's SPKI is the attested one (the Tinfoil adapter uses it too), and the
pool helpers: closing pools on their own event loop and the stream wrappers that keep a pool in use until
its body closes. Imports `verify.base`; lazy: `verify.tinfoil`. Contract: [Sends](INTERFACES.md#sends).

**`verify/near_exchange.py`**. `_Exchange`, the record of one send (digests, completion id, client key,
signature verdict); `_sealed_sync`, `_sealed_async` and `_release_sealed`, which hand an encrypted reply
over only when the send is fully attested; `_send_failed`; and `NearRefusal`, the error a refused send
raises. Imports `verify.base`, `verify.near_transport`; types: `verify.near`; lazy: `verify.near_e2ee`. Contract: [Sends](INTERFACES.md#sends).

**`verify/near_send.py`**. `_SyncView` and `_AsyncView`, the httpx transports behind `attested-near`:
each request is checked, sent on the pinned pool as an exchange, and hashed as it streams; `_refuse`
turns a failure into a recorded `NearRefusal`. Imports `verify.base`, `verify.near_exchange`,
`verify.near_transport`; types: `verify.near`. Contract: [Sends](INTERFACES.md#sends).

## Pins and consent

**`pins.py`**. `PinStore` over `pins.yaml` version 3: per vendor and identity an approved set of per-CVM
entries and a pending set. `match`, `stage`, `pending`, `apply` (only consent.py and the platform-only
policy call it) and `retire`. Imports `atomicwrite`, `hermes_compat`, `verify.base`; lazy: `filelock`, `review`. Contract: [Pins file](INTERFACES.md#pins-file).

**`consent.py`**. A person's consent outside a turn, through `ctx.ask_choice` only: `approve_pending_pin`
applies a staged pin on an exact Approve; `allow_tool` adds an off-host tool for the rest of the lock.
Both are sync, refuse on an event loop, and record every answer. Imports `gate_tools`; lazy: `filelock`,
`pins`, `review`, `selfapproval`, `verify.near_checks`. Contract: [Consent](INTERFACES.md#consent).

**`review.py`**. The pin review bundle (`hermes confidential pins review`): `build_bundle` lists every
pending entry with its components, the compose files fetched by content hash (`fetch_compose`) and the
diffs from the approved entries; `cli_review` prints it. Imports `atomicwrite`; lazy: `hermes_compat`,
`pins`, `verify.near_checks`. Contract: [Pin review bundle](INTERFACES.md#pin-review-bundle).

**`revoke.py`**. `revoke(rt, tool)` withdraws the plugin's tool grants from `allowlist.yaml`, Hermes'
`command_allowlist` and the lock grants, and records a revocation that moves the gate to a new rule key;
`RevocationWatcher` lets a running gateway see a revoke made in another process. Imports `atomicwrite`;
lazy: `commands_pins`, `filelock`, `gate_tools`. Contract: [Revoke](INTERFACES.md#revoke).

## Ledger, receipts and watch

**`ledger.py`**. The append-only SQLite ledger: `Ledger.append` validates each event (the kinds in
`KINDS`, no conversation-shaped key in `FORBIDDEN_DETAIL_KEYS`), `externalize_evidence` moves evidence
blobs to files, and `tail`, `session` and the row queries feed receipts and watch. Imports `atomicwrite`. Contract: [Ledger](INTERFACES.md#ledger).

**`receipts.py`**. A session's receipt from ledger rows: `build_receipt` collects the rows and sections,
`render` prints text or JSON, `chain_hash` and `verify_chain` give the document's checksum, and the
closing paragraphs state what the receipt does not prove. Imports `_version`, `ledger`; lazy:
`verify.near_checks`, `verify.replay_near`. Contract: [Receipts](INTERFACES.md#receipts).

**`watch.py`**. `hermes confidential watch`: a fixed-width live view of the ledger (`run`, `latest`,
`format_row`). Imports nothing. Contract: [Commands](INTERFACES.md#commands).

**`verify/replay.py`**. Offline replay of a Tinfoil verification: `replay(evidence)` re-runs the SDK's
verifier on the stored bytes with the network banned in the replaying thread and every clock pinned.
Imports `verify._sdkpatch`, `verify.policy_check`, `verify.sev_check`. Contract: [Replay](INTERFACES.md#replay).

**`verify/replay_near.py`**. Offline replay of NEAR evidence (`replay`) and of every signed send in a
receipt (`replay_receipt`, `replay_signed_send`). Imports `verify.near`, `verify.near_checks`. Contract:
[Replay](INTERFACES.md#replay).

**`verify/policy_check.py`** and **`verify/sev_check.py`**. Standalone second checks the replay runs: the
Sigstore release-bundle identity and policy (`check_bundle`), and an AMD SEV-SNP report checker. Each
imports nothing from the plugin and runs on its own with `python -I` (Python 3.11 or later). Contract: [Replay](INTERFACES.md#replay).

## Commands

**`commands.py`**. The dispatch and the registration: `handle_slash` runs `/confidential <verb>`,
`cli_verb` runs `hermes confidential <verb>`, `register_slash` and `register_cli` register both, and
`terminal_text` prints commands in the terminal form. `TERMINAL_ONLY` names the verbs chat refuses.
Imports `commands_common`, `commands_pins`, `commands_replay`, `commands_setup`, `commands_status`,
`locking`, `revoke`, `tiers`; lazy: `consent`, `progress`, `review`, `watch`. Contract: [Commands](INTERFACES.md#commands).

**`commands_status.py`**. The read-only reports: `status_text`, `check_result` (the preflight for a
tier), `receipts_text` and `watch_text`. Imports `commands_common`, `commands_pins`, `locking`,
`preflight`, `tiers`; lazy: `_version`, `gate_tools`, `ledger`, `watch`. Contract: [Commands](INTERFACES.md#commands).

**`commands_pins.py`**. `pins_text` (pins in force, a pending pin, Hermes' remembered tool grants, the
approval history), `retire_text` (`pins retire`) and `pending_pin_note`. Imports `commands_common`; lazy:
`gate_tools`, `hermes_compat`, `ledger`, `pins`, `verify.near_checks`. Contract: [Commands](INTERFACES.md#commands).

**`commands_setup.py`**. `hermes confidential setup`: `cli_setup` (Tinfoil) and `cli_setup_near` verify
the enclave, ask for the first pin and print the config block (`config_block`, `near_config_block`) and
the next steps. Imports `commands_common`, `locking`, `preflight`; lazy: `consent`, `verify.base`. Contract: [Commands](INTERFACES.md#commands).

**`commands_replay.py`**. `hermes confidential replay`: `cli_replay` replays each verification in a
receipt and every signed send, against the pins file or the fingerprints given. Imports
`commands_common`; lazy: `pins`, `receipts`, `verify.near_checks`. Contract: [Replay](INTERFACES.md#replay).

**`commands_common.py`**. What the command modules share: `PROFILE_NAME`, `_short`, `_provider_module`,
`INTERACTIVE_VERIFY_WAIT_SECONDS` and `TerminalAsker`, the terminal stand-in for `ctx.ask_choice`.
Imports `locking`; lazy: `consent`, `selfapproval`. Contract: [Consent](INTERFACES.md#consent) and [Commands](INTERFACES.md#commands).

## Support

**`hermes_compat.py`**. Every import of a private Hermes name, one accessor each, with the Hermes commit
it was verified at. Imports nothing. Contract: [Hermes private names](INTERFACES.md#hermes-private-names).

**`atomicwrite.py`**. `write_atomic(path, data)`: the one durable write for every state file (a temporary
file in the target's directory, fsync, `os.replace`, then `fsync_directory`), used by `pins`, `state`,
`gate_tools_allowlist`, `revoke`, `review`, `ledger` and `verify.tinfoil`. Two limits: on macOS `os.fsync`
does not issue `F_FULLFSYNC`, so the write reaches the drive's cache and not always the platter; and a parent
directory `write_atomic` creates is not itself fsynced. Imports nothing. Contract: [State files, locks and writes](INTERFACES.md#state-files-locks-and-writes).

**`filelock.py`**. `exclusive(path)`: a thread lock plus a bounded `flock` on `<file>.lock`, raising
`LockBusy` or `LockUnusable` instead of waiting. Imports nothing. Contract: [State files, locks and writes](INTERFACES.md#state-files-locks-and-writes).

**`progress.py`**. The start-up progress lines on stderr, shown on the first start of each installed
commit. Imports nothing. Contract: [Build, dependencies and repository rules](INTERFACES.md#build-dependencies-and-repository-rules).

**`_version.py`**. `PLUGIN_COMMIT`, the build identity status and receipts print. Imports nothing. Contract: [Build, dependencies and repository rules](INTERFACES.md#build-dependencies-and-repository-rules).

**`scripts/near_first_contact.py`** attests NEAR, sends one request and replays the record offline (run by
hand). **`scripts/stamp_version.py`** writes the packaging stamp `_version.py` reads.

## Dependencies

What each module imports when it loads, as a tree: a module's children are the plugin modules it
imports at load. A module already expanded higher up reads "(see above)". The root `__init__.py` loads
each module on first use (`_cm`), and lazy imports, made inside functions, are listed with each module
above, so neither appears here. A module that nothing imports at load starts its own tree.

    commands
      commands_common
        locking
          ledger
            atomicwrite
          preflight
            tiers
          tiers
      commands_pins
        commands_common (see above)
      commands_replay
        commands_common (see above)
      commands_setup
        commands_common (see above)
        locking (see above)
        preflight (see above)
      commands_status
        commands_common (see above)
        commands_pins (see above)
        locking (see above)
        preflight (see above)
        tiers
      locking (see above)
      revoke
        atomicwrite
      tiers
    consent
      gate_tools
        gate_tools_allowlist
          atomicwrite
          gate_tools_classify
        gate_tools_calls
        gate_tools_classify
        gate_tools_grants
        gate_tools_hermes
        gate_tools_policy
          gate_tools_allowlist (see above)
          gate_tools_calls
          gate_tools_classify
          gate_tools_grants
          gate_tools_hermes
        selfapproval
    locking (see above)
    gate_llm
      ledger (see above)
      state
        atomicwrite
        tiers
      tiers
    provider
      client
      pins
        atomicwrite
        hermes_compat
        verify.base
      tiers
      verify.base
    receipts
      _version
      ledger (see above)
    verify.replay_near
      verify.near
        sendctx
        verify.base
        verify.near_appraise
          verify.near_checks
          verify.near_evidence
            verify.near_checks
        verify.near_checks
        verify.near_evidence (see above)
        verify.near_exchange
          verify.base
          verify.near_transport
            verify.base
        verify.near_send
          verify.base
          verify.near_exchange (see above)
          verify.near_transport (see above)
        verify.near_transport (see above)
      verify.near_checks
    verify.replay
      verify._sdkpatch
      verify.policy_check
      verify.sev_check
    filelock
    progress
    review
      atomicwrite
    selfscan
    verify.near_e2ee
    verify.tinfoil
      atomicwrite
      verify._sdkpatch
      verify.base
    watch

## Data files

The plugin keeps its data in two directories under `<HERMES_HOME>/plugin-data/`.
[DISCLOSURE.md](DISCLOSURE.md) describes each file's contents and permissions.

    plugin-data/confidential-mode/                        Hermes' plugin storage (ledger.py)
      ledger.sqlite (-wal, -shm, -journal)                the ledger (ledger.py)
      evidence/blobs/<sha256>                             large NEAR evidence strings (ledger.py)
    plugin-data/agent-plugin-confidential-mode-<digest>/  ctx.state's directory
      state.json                                          the lock state (Hermes' PluginState; state.py)
      pins.yaml, pins.yaml.lock, pins.yaml.v2.bak         the pins (pins.py)
      pins/composes/<sha256>.yaml, commit-<sha>.json      fetched compose files and commit metadata (review.py)
      allowlist.yaml, allowlist.yaml.lock                 this lock's tools and allowed tools (gate_tools_allowlist.py)
      grants_revoked.json, grants_revoked.json.lock       revocation records (revoke.py)
      lock-transition.lock                                held during a lock or unlock (locking.py)
      tinfoil_user_cache_secret                           Tinfoil's prompt-cache secret (verify/tinfoil.py)
      trust-roots/<sha256>.json                           Sigstore trust roots (verify/tinfoil.py)
      sdk-cache/                                          the tinfoil and sigstore caches (verify/_sdkpatch.py)
      modes-checked                                       the commit whose file modes were set (ledger.py)
      loaded-commit                                       the commit that last started (progress.py)

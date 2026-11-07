# C1 interface freeze (2026-11-06)

Frozen for the C1 -> C2 workstreams. Changes after this point require a note in this file and a message to every open workstream. Hermes is pinned at 84a0301. Facts marked (C0) were proven by tests in tests/spikes.

## Package layout and ownership

    __init__.py                 register(ctx): wires everything; owned by W1 after C2
    confidential_mode/
      tiers.py                  W3  Tier, Destination, Verdict, predicates
      preflight.py              W3  PreflightReport over core config
      verify/base.py            W2  VerificationResult, VendorAdapter protocol
      verify/tinfoil.py         W2  Tinfoil adapter (SDK 0.14.2)
      client.py                 W2  ConfidentialClient (dual) and RefusingClient
      provider.py               W2  ProviderProfile subclass 'attested-tinfoil'
      pins.py                   W2  PinStore (pins.yaml v2)
      gate_llm.py               W1  llm_execution middleware + refusal builders
      gate_tools.py             W4  pre_tool_call gate, allowlist, delegation rule
      consent.py                W4  ask_choice-based consent + pending_pin apply
      ledger.py                 W1  SQLite ledger, event types, watch stream
      receipts.py               after C2
      commands.py               after C2
      state.py                  W1  ctx.state keys
    tests/
      unit/                     pure logic, no Hermes import
      seam/                     real Hermes modules, fakes only at SDK/network/human boundaries
      spikes/                   C0, read-only from here

Each workstream owns its files and tests only. Shared types live in tiers.py and verify/base.py and are frozen below; a workstream that needs a change asks rather than edits.

## Shared types (frozen)

```python
# confidential_mode/tiers.py
class Tier(str, Enum): ON_HOST = "on-host-only"; ATTESTED = "attested"; ZDR = "zero-retention"

@dataclass(frozen=True)
class Destination:
    provider: str          # Hermes provider name, e.g. "attested-tinfoil", "openrouter", "custom"
    base_url: str          # as Hermes passes it; may be ""
    model: str
    api_mode: str          # chat_completions | anthropic_messages | codex_responses | bedrock_converse | codex_app_server
    purpose: str           # "main" | "fallback" | "aux:<task>" | "tool:<name>" | "memory" | "mcp:<server>"

@dataclass(frozen=True)
class Verdict:
    in_tier: bool
    reason: str            # short, user-visible, no secrets
    host: str              # parsed host or "" (for the ledger/watch view)

class TierPredicate(Protocol):
    tier: Tier
    def classify(self, dest: Destination) -> Verdict: ...
```

ON_HOST predicate: in_tier iff base_url host is loopback, RFC1918, 100.64/10, fe80::/10, fc00::/7, "localhost", or in `confidential.on_host.extra_hosts`. Empty base_url for a provider whose profile base_url is on-host counts as on-host; otherwise off-tier. ATTESTED predicate: in_tier iff dest.provider is a registered attested profile AND VerificationCache.fresh(provider) AND pins match (W2 exposes `attested_ok(provider) -> Verdict`). ZDR predicate: deferred; stub returns off-tier with reason "zero-retention tier not implemented".

```python
# confidential_mode/verify/base.py
@dataclass(frozen=True)
class VerificationResult:
    vendor: str                 # "tinfoil"
    router_repo: str            # "tinfoilsh/confidential-model-router"
    enclave_host: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None
    verifier: str               # SDK verifier identity string
    verified_at_host_clock: float    # time.time(); NOT attested
    evidence: dict              # raw, JSON-serialisable, stored in the ledger

class VendorAdapter(Protocol):
    vendor: str
    def verify(self) -> VerificationResult: ...        # raises VerifyError on any failure; never returns partial
    def sync_http_view(self) -> httpx.Client: ...      # non-closing view over the one verified pool
    def async_http_for_loop(self) -> httpx.AsyncClient # one per running loop
```

PinRecord (pins.yaml v2): vendor, router_repo, code_fingerprint, enclave_fingerprint, release_tag, models_seen[], approved_by ("human"), approved_at (ISO UTC), approved_via (surface string), approval_rule_key, previous (fingerprint or null). `PinStore.match(result) -> bool`, `PinStore.stage(result) -> PendingPin`, `PinStore.pending() -> PendingPin | None`, `PinStore.apply(pending) -> PinRecord`. Only consent.py calls apply.

Ledger (ledger.sqlite, table `events`): id INTEGER PK, ts REAL, session_id TEXT, kind TEXT, purpose TEXT, provider TEXT, host TEXT, model TEXT, bytes INTEGER NULL, tier TEXT NULL, verdict TEXT NULL, decision TEXT NULL, surface TEXT NULL, detail TEXT (JSON). Kinds: send_observed, send_refused, verify_ok, verify_fail, tool_asked, tool_allowed, tool_refused, pin_staged, pin_applied, pin_denied, lock, unlock, preflight_fail, breach, compaction. `Ledger.append(event)`; `Ledger.tail(since_id) -> list` for the watch view; `Ledger.session(session_id) -> list` for receipts. Never store prompt text; bytes only.

State (ctx.state, per profile): locked (bool), locked_tier (str), locked_since (float), config_fingerprint (sha256 of the preflight-relevant core config at lock), breached_sessions (list[str]). Verification cache lives in process memory in W2, not in ctx.state.

## Contracts

### W1 gate_llm.py (middleware) — proven constraints (C0)
- Registered via ctx.register_middleware("llm_execution", fn). The body is wrapped so that NOTHING escapes: any exception is converted to a refusal; an escaping exception is fail-open.
- Reads context: provider, base_url, model, api_mode, session_id, request. Builds Destination(purpose="main" or "fallback" when agent fallback index > 0 if available, else "main").
- If not locked: call next_call unchanged, but ledger send_observed with host and byte size of the serialised request (watch view works unlocked).
- If locked: classify via the active TierPredicate. Off-tier -> ledger send_refused, return refusal (never call next_call). In-tier -> wrap next_call in try/except Exception: unwrap `getattr(exc, "original", exc)`; if InterruptedError re-raise; else ledger and return refusal "attested endpoint unavailable; this turn ended; resend". Never let fallback arm.
- Refusal builders per api_mode exactly as in docs/C0-spikes.md (ChatCompletion / Response / anthropic-shaped / bedrock dict). finish_reason "stop", stop_reason "end_turn", status "completed". Never a dict, never content_filter/length/refusal. Unknown api_mode -> chat_completions shape and a ledger note.
- Attested tier: before next_call, ask W2 `attested_ok(provider)`; W2 handles TTL. On mismatch, W2 stages pending_pin; W1 refuses with "enclave build changed; run /confidential pins approve".
- Tests: one allow test and a mutant twin per branch; assert on a recording transport that the provider received zero requests on refusal; a test that the verifier raising never reaches the provider; a 429/500 test proving `_try_activate_fallback` is never called (reuse the C0 harness in tests/spikes/test_refusal_shape.py).

### W2 verify/, client.py, provider.py, pins.py
- Adapter builds `SecureClient(enclave=<host from atc or config>, user_cache_secret=<from plugin data dir, never ~/.tinfoil>)` once per profile; `verify()` via the SDK default path (never pinned-measurement mode); extracts fingerprints from get_verification_document or equivalent; VerifyError on anything.
- ConfidentialClient per docs/C0-spikes.md follow-up: HERMES_SKIP_TRANSPORT_WRAP = HERMES_SKIP_ASYNC_WRAP = True; sync OpenAI on a non-closing view; AsyncOpenAI per running loop; chat.completions.create dispatches by caller coroutine check; __getattr__ delegates to the sync client; close() closes only the view.
- RefusingClient: same surface; every create raises ConfidentialRefused(reason). Returned by create_client when verification is not fresh and cannot be refreshed. create_client NEVER raises and NEVER returns None (fail-open otherwise).
- provider.py: `ProviderProfile(name="attested-tinfoil", base_url=<enclave host URL>, env_vars=("TINFOIL_API_KEY",), auth_type="api_key")` with create_client(**kw) -> ConfidentialClient | RefusingClient; registered from register(ctx) via providers.register_provider. Cache verification; TTL default 300 s (`confidential.verify_ttl_seconds`).
- Dependency: pyproject `tinfoil==0.14.2` exact. No network in unit tests; seam tests stub SecureClient.verify and use httpx.MockTransport recorders.

### W3 tiers.py, preflight.py
- `run_preflight(tier, config) -> PreflightReport` where config is Hermes' loaded config (read-only; use hermes_cli.config load_config_readonly or equivalent). Items: model.provider; every fallback_providers entry (must be empty); every auxiliary.<task>.{provider,base_url,fallback_chain} for every built-in task in config_defaults and every plugin-registered task (get_plugin_auxiliary_tasks); auxiliary.vision must be explicit and in-tier or disabled; memory.provider (on-host or none); mcp_servers.* with a URL; plugins.isolation == in_process; get_provider_profile(<attested profile>) is not None when tier is attested; model.provider != moa and no moa in any chain; provider != openai-codex. Each item carries verdict in {in_tier, on-host, disabled, off_tier, missing} and a one-line fix with the exact YAML key.
- `config_fingerprint(config) -> str` over exactly the keys above, for the per-turn recheck.
- `hermes confidential check` output format: a table of key, value (redacted), verdict, fix.
- Tests: pure unit tests over config dicts; a seam test that a plugin-registered aux task appears.

### W4 gate_tools.py, consent.py
- Allowlist built at lock from tools.registry: on-host set = {terminal, process_manage, execute_code, read_file, write_file, patch, search_files, skills_list, skill_view, skill_manage, todo_list, memory, clarify, session_search}; everything else is off-host. Print the computed lists on lock.
- pre_tool_call(tool_name, args, task_id, session_id, ...): unlocked -> None (observe only, ledger nothing). Locked: on-host -> None; cronjob_manage -> block; delegate_task -> allow only if route is default backend and no profile/acp fields, else block; MCP tool from a URL server -> block; other off-host tool -> if yolo/bypass active (tools.approval._yolo_active() or approvals.mode off) -> block, else return {"action": "approve", "message": f"{tool_name} wants to send ~{n} KB of this conversation off the machine"} with n from len(json.dumps(args)); ledger tool_asked and, from post_approval_response, tool_allowed/tool_refused.
- consent.py: `approve_pending_pin(ctx, store, ledger, *, session_key, session_id, platform)` using ctx.ask_choice exactly as in docs/C0-spikes.md; sync only; None -> deny; re-check pending equality before apply; ledger pin_applied/pin_denied with raw_pick. `allow_tool(ctx, name)` same primitive for allowlist additions.
- Tests: registry-driven allowlist from a fake registry; bypass-state -> block not approve; ask_choice returning None -> deny and no apply; pending swapped during wait -> not applied.

## Decisions carried from C0
- Consent primitive is ctx.ask_choice; request_tool_approval is used only by the tool gate's approve directive inside a turn.
- Middleware never waits on a human; mismatch -> refuse + stage.
- Profile-wide lock in MVP; hooks carry session_id so per-session is possible later.
- Middleware bypasses (codex_app_server, max-iterations summary) are covered by the preflight requirement that the main provider is in-tier; refuse openai-codex outright.

## Amendment 1 (2026-11-06, after W3/T3): adjudications

Rule for all workstreams: behaviour assertions in hostile tests stand; parameter and fixture NAMES follow the implementation's public signatures (testers adapt, implementers do not rename to match guesses).

Tiers (W3 corrections accepted, plus):
- Main model key is `model.default` (alias `model.model`); bare-string `model:` is legal; empty or "auto" main provider is off_tier (it enables the aux discovery chain). Legacy `fallback_model` is part of the fallback chain and must be empty too.
- Any URL containing a backslash is off_tier (urllib and httpx disagree on the host). Schemeless base_url is off_tier. Malformed ports (non-numeric, >65535) are off_tier and must not raise. Obfuscated loopback forms (0x7f000001, 2130706433, 127.1, 0.0.0.0) are off_tier. 169.254.0.0/16 is off_tier (cloud metadata). IPv4-mapped private/loopback IPv6 is on-host.
- Empty base_url: resolve via the injected `profile_base_url(provider)`; an on-host result is in-tier, anything else off_tier. Hermes' on-host profiles (ollama, lmstudio, llama-cpp) return "" at 84a0301, so the fix text tells the user to set `model.base_url` / `auxiliary.<task>.base_url` explicitly.
- Attested predicate: a base_url whose host differs from the attested profile's endpoint is off_tier (W3's profile_base_url parameter stays). T3's xfail for this becomes a normal test.
- MCP servers with a `url`: classify by `host_of(url)` with the active predicate (a localhost URL server is on-host). `enabled: false` is `disabled`. W4 blocks MCP tools only from servers whose URL host is off-tier.
- Vision: no "disabled" convention. `auxiliary.vision.provider` must be explicit and in-tier; unset, "", "auto", or a non-dict block is off_tier, with a fix that explains Hermes describes gateway inbound images through vision even without a tool call.
- `plugins.isolation` absent resolves to Hermes' default in_process (passing verdict); explicit "" or unknown values are `missing`/off_tier.
- Memory: "", builtin, built-in, local, none => on_host (these are Hermes' own values); else off_tier.
- Add to enumeration: `delegation.provider`, `delegation.model`, `delegation.base_url` (unset inherits the main verdict; set and off-tier => off_tier); `tts.provider` (assistant text is conversation content: unset/none/an on-host engine => on_host, hosted => off_tier; read the real key names in config_defaults). `cron.model_provider` and moa presets are NOT enumerated; moa anywhere is refused and cron pins are a documented gap.
- Plugin aux tasks are registration dicts (defaults, inherit_from), layered as Hermes does; `plugin_aux_tasks: list[str | dict]`.
- Fingerprint covers model provider/default/base_url/api_mode, fallback_providers and fallback_model, every aux task's provider/base_url/fallback_chain, delegation.*, tts.provider, memory.provider, mcp_servers url/command/enabled, plugins.isolation; sorted keys; no secrets. Junk entries in any chain are off_tier.
- Resolved in Amendment 6 (the `terminal.backend` item: only `local` passes). Still pending: a `terminal.docker_network` rule that would also accept a contained docker backend, and a three-mode rule for terminal/execute_code in the tool gate (ask on network-looking commands / allow all / block).

Tool gate (W4/T4): MCP tools are blocked when their server has a URL whose host is off-tier under the active predicate, not merely because a URL exists. delegate_task: a child on the default in-process backend inherits the locked profile and is allowed; any route selecting another profile, an ACP command, or a non-default backend is blocked; W4 reads the real field names from tools/delegate_tool.py and lists them in its report.

## Amendment 2 (2026-11-06, after W1/W4): adjudications

- Backslash URLs: T3 corrected its claim; httpx reads `http://evil.com\@127.0.0.1/v1` as 127.0.0.1 (urllib3 reads evil.com). The ruling stands as fail-closed on parser disagreement: any backslash, tab, CR, LF or NUL in a URL is off_tier. Encoded `%5C` userinfo is a control case and stays on-host when all parsers agree.
- Fallback purpose: the middleware context carries no fallback indicator at 84a0301; purpose is "main" and classification is by the destination fields, which already describe the fallback provider. Accepted.
- Corrupt lock state: the gate refuses every send until `/confidential status` or `off` repairs it. Fail closed, accepted; the refusal text must name the command.
- Bedrock refusal is a dict by design; the "never a dict" rule applies to the other three modes.
- `pin_pending` callable and `predicate_for(tier)` are accepted W1 interfaces. `is_locked() -> (bool, Tier | None)` is canonical.
- Ledger: `Ledger.append` must accept both `LedgerEvent` and a plain dict with the column names (W4 emits dicts). W1 adds the adapter.
- Remembered grants on the plugin's own tool rule keys (`plugin_rule:confidential-mode:tool:<name>`) are NOT bypass states: a human chose once/session/always on the allow-once prompt, so the gate honours Hermes' remembered answer and ledgers the call as tool_allowed with decision "remembered". Yolo, approvals off, and unattended approve modes remain bypass => block. `/confidential pins` lists remembered tool grants alongside pins, revocable there.
- Tools absent from the registry at lock (memory-provider tools, context-engine tools, lazily connected MCP servers) are blocked as unclassified with a message that names a relock. Accepted.
- The hook-thread versus agent-thread timing window for a yolo toggle is accepted and disclosed.
- `allow_tool(ctx, allowlist, ledger, name, *, session_key, session_id, platform)` is the canonical signature.
- `PendingPin` must be a frozen dataclass with value equality (W2). `apply(pending, *, approved_via: str)` gains the surface argument (W2) and consent passes it.

## Amendment 3 (2026-11-06, after T4): tool gate enforcement moves to execution middleware

- HERMES GAP (T4, tools/approval.py:1006-1009): on the CLI the pre_tool_call approve directive grants on any answer except the exact string "deny"; None, "", "d", "Deny", "yes" all run the tool. The hook cannot veto after the prompt. Therefore the hook only ASKS; enforcement is a `tool_execution` middleware (W4 adds `build_tool_execution(...)`), catch-all wrapped like the llm gate: when locked and the tool is on the ask route, it calls `next_call` only if `post_approval_response` recorded an explicit once/session/always for this tool_call_id (or a remembered grant under our own rule key); anything else, including an unexpected choice value, is refused with a tool-result string and ledgered tool_refused with decision "unexpected_choice". Block-route tools are refused there too, as a second line behind the hook. The middleware never raises.
- Unknown names and tools registered after lock: block (hook) and refuse (middleware).
- Bypass states that turn ask into block: yolo (all forms), approvals.mode off, cron/unattended/single-query approve modes. Remembered grants under `plugin_rule:confidential-mode:tool:<name>` are honoured and ledgered "remembered"; grants under any other key (e.g. a bare "web_search" always) do not apply because our rule key differs.
- MCP command servers are allowed per contract and disclosed as the same class of gap as terminal (a command can be a network proxy). Safe-worker mode disables all hooks and is disclosed; the tool_execution middleware is also disabled there (middleware runs through the same manager), so the disclosure must say locked mode does not apply under safe-worker.
- delegate_task: per-task provider/base_url/api_mode/fallback_providers/request_overrides, top-level legacy fields, and tasks passed as a JSON string all count as non-default routes => block. delegation.provider/base_url set in config => block even on the default backend (second line behind preflight). The agent's pinned backend is invisible to the hook; accepted.
- Unreadable lock state blocks every tool, including on-host ones.
- Consent: answers must match the choice value exactly; `approve_pending_pin` returns a string and raises ConsentContextError only on an event loop; a re-staged pin with the same fingerprints but a different release tag is a swap; apply-exactly-once is enforced in BOTH places (PinStore.apply is atomic and idempotent per pending; consent re-checks equality).
- allow_tool refuses unregistered names without asking; additions persist in allowlist.yaml through Allowlist.add; hard blocks (cronjob_manage, delegate_task routes, MCP off-tier URL) cannot be lifted.
- (Amendment 3 addendum) tts: `tts.enabled: false` => verdict `disabled` regardless of provider (stock Hermes ships edge + disabled and must still lock); `tts.enabled: true` with a hosted provider => off_tier; an on-host engine or none => on_host. The same enabled-flag rule applies to any future section that has one.
- (Amendment 3 addendum, after T4 round 2) Tool identity is pinned at lock: the allowlist records each entry's handler identity (object id or a stable fingerprint) and toolset; a tool whose handler or toolset differs at call time is unclassified => block/refuse. `format_allowlist` escapes or rejects names containing control characters so a name cannot forge a line. delegate_task: keys are normalised (strip, casefold) before matching route keys; `fallback_providers`, `request_overrides` and `backend` are route keys; any top-level or per-task key outside the documented delegate_task schema is treated as a route key (fail closed). Consent: `store.apply` raising is ledgered as pin_denied with the error type; concurrent approvals for one pending pin apply exactly once (consent holds a lock around re-check and apply; PinStore.apply is additionally idempotent).
- (tts correction, W3 final) Hermes has no `tts.enabled` key at 84a0301; `tts.provider` defaults to edge (hosted). The preflight's `disabled` verdict for tts is a plugin convention meaning "no automatic TTS path is configured": it holds only while the tool gate asks/blocks `text_to_speech` and `voice.auto_tts` is false (auto_tts true with a hosted provider is off_tier). Voice-chat and gateway voice-note TTS paths were not traced and are a disclosed gap until someone reads them.

## Amendment 4 (2026-11-07, after the integrated adversarial review): twelve findings and their owners

Ownership is relaxed: the named owner may edit any file needed, with a note in the commit message.
- F1 CRITICAL, live runtime drift (W5): the preflight and recheck read config, but Hermes resolves "auto" aux tasks to the LIVE main runtime (turn_context.set_runtime_main), which a session `/model` switch, `--provider`, or a gateway per-session override changes. Required: (a) at lock and in every pre_llm_call, read the live main runtime (find the accessor in agent/turn_context.py) and refuse/mark breached when its provider or base_url is off-tier; (b) determine whether title generation, turn-start compaction and memory prefetch run BEFORE pre_llm_call (turn_context.py ~1271 vs the hook site ~861) and state the answer; (c) register a pre_gateway_dispatch directive that refuses `/model` and other runtime-switching commands while locked on gateway surfaces; (d) whatever cannot be prevented is named in the locked note, status, and the receipts closing paragraph as a path that is recorded after the fact, not prevented.
- F2 CRITICAL, hook timeout fail-open (W5, with preflight edits): add `plugins.hook_callback_timeout` and every `plugins.*` key that governs hook execution to the config fingerprint and the preflight (a timeout below 5 s is off_tier with a fix); the llm gate's own fingerprint check stays the enforcement for main calls; the aux leak remains and is disclosed per F1(d).
- F3 HIGH, decisions collide without tool_call_id (W4): decisions recorded under an empty tool_call_id are never consumed; when the id is empty the hook returns None (no prompt) and the tool_execution middleware always asks itself with a fresh approval_id, so one prompt per call and no sharing. Test with two concurrent calls and a slow observer.
- F4 HIGH, verification never ledgered in the shipped build (W5): pass `ledger=` to register_provider_profile; assert in test_register that a live verify writes verify_ok with evidence attached.
- F5 MEDIUM, restart launders after-lock tools (W4): persist the allowlist at lock (name, toolset, handler module and qualname) under plugin data; on load, rebuild from the persisted set, and any live registry entry not in it, or whose module/qualname differs, is unclassified (block/refuse) until a relock.
- F6 MEDIUM, allow grants outlive the lock (W4): scope allowlist.yaml additions to the lock (store the lock fingerprint and time); unlock clears them; the prompt text stays "for the rest of this lock".
- F7 MEDIUM, session markers counted as locks (W5, may edit ledger.py): add ledger kinds `session_start` and `session_end` and use them for the markers; receipts count only kind `lock`.
- F8 MEDIUM, pin applied by another in-process plugin (W2): attested_ok additionally requires a `pin_applied` ledger row whose fingerprints match the pin in force; absent => refuse with "pin has no consent record". In-process code can still forge the row; this raises the bar and is disclosed.
- F9 MEDIUM, forged verify_ok (W6): the closing paragraph must say the ledger is a file on this host, unprotected against code in the same process, and that EVIDENCE claims are only as strong as the ledger's integrity plus the attached bytes replaying offline; receipts flag verify_ok rows whose evidence has `capture_complete: false` or no evidence as "unverified entry".
- F10 LOW, model-list probe with the API key on a live off-tier runtime: disclosed; F1(a) also refuses the turn.
- F11 LOW, receipts across a relock (W6): trust roots per period, not from the last period only.
- F12 LOW, safe-worker disclosure (W5 for status/lock message; W7 for README/catalog): locked mode does not apply under safe-worker mode, stated in user-facing text.
- (Amendment 4 ruling 1, revised 2026-11-07) create_client returns a RefusingClient within `verify_wait_seconds` (default 20 s; interactive commands may pass 60 s) when verification is pending; the hostile harness passes a 5 s wait to keep its 10 s bound. The reason text starts "verification pending" and the preflight reports it as pending, not off-tier.

## Amendment 5 (2026-11-07): NEAR AI Cloud, a second attested vendor with signed responses

Owner W10 (branch `w10-near`). NEAR AI Cloud (`https://cloud-api.near.ai/v1`, OpenAI-compatible) joins the attested tier as the provider profile `attested-near`, next to `attested-tinfoil`. Formats are from docs.near.ai (verification pages, the signature and ITA-token API references) and the Intel Trust Authority EAT profile, read 2026-11-07; `confidential_mode/verify/near_checks.py` cites each one. `nearai-inference-sdk` 0.2.1 is compatible with openai 2.54.0 but is async-only, wraps its own client rather than an httpx transport Hermes can use, and pulls aiohttp, anthropic, dcap-qvl, eth-account, pyhpke and pynacl; it is not a dependency. The plugin implements the documented checks itself and supports ed25519 signers only (ecdsa needs Keccak-256 and key recovery, which neither the standard library nor `cryptography` provides).

New files: `verify/near.py` (NearAdapter, evidence capture, `appraise()`), `verify/near_checks.py` (pure checks: report data, MRCONFIGID, RTMR3, TDX quote via tinfoil 0.14.2's own verifier, ITA JWT/JWKS, response signatures), `verify/replay_near.py` (offline replay of evidence and of every signed send in a receipt), `sendctx.py` (the gate's send context), `scripts/near_first_contact.py`.

Identity mapping for pins (PinRecord fields keep their names):
- `vendor`: `near`.
- `router_repo`: `<host>#<model,model,...>`, the gateway host and the sorted model allowlist, for example `cloud-api.near.ai#Qwen/Qwen3.8-27B`. Changing the allowlist is a new identity and needs a new pin.
- `code_fingerprint`: SHA-256 of the canonical JSON `{"gateway": [compose_hash], "models": {M: [sorted compose hashes of every verified report candidate]}}`. A compose hash is SHA-256 of the CVM's `app_compose`, which MRCONFIGID measures (`0x01 || hash || 15 zero bytes`).
- `enclave_fingerprint`: SHA-256 of the canonical JSON of `"MRTD:RTMR0:RTMR1:RTMR2"` per CVM (gateway and every model candidate, sorted). RTMR3 and the signing keys are checked on every verify but left out, because they differ per instance.
- `release_tag`: None (NEAR publishes no signed release tag for a deployment). `platform`: `tdx`. PendingPin gains an optional `components` tuple (one line per measured compose) for the pin prompt; `consent.pin_question` shows a NEAR-specific prompt. Consent is the same flow as Tinfoil's: stage on mismatch, refuse with "enclave build changed", apply only on an exact Approve, `pin_applied` row required (F8).
- Observed 2026-11-07: NEAR serves Qwen/Qwen3.8-27B from at least two instances whose composes differ (an `INSTANCE_LABEL` line and a compose-manager image digest) under one signing key, so the code fingerprint can change between verifies. That is a pin prompt, by design; an approved-set pin is a possible follow-up and is not built.

Core generalisation (the only edits outside the new files):
- `locking.ATTESTED_PROFILES = ("attested-tinfoil", "attested-near")`; `predicate_for(ATTESTED)` admits both; the preflight's `provider_profile[...]` item and the lock message use `attested_profile_for(config)` (model.provider when it is one of them); unlock invalidates both cache entries.
- `provider.make_profile` takes `name`, `display_name`, `description`, `env_var`, `supports_streaming`; `register_near_profile` registers `attested-near` with the same VerificationCache, pins file and ledger. `api_key_for(env_var)` generalises `tinfoil_api_key()`. `_policy_check_detail` is n/a for NEAR evidence.
- `gate_llm.LlmGate` wraps `next_call` in `sendctx.send_context(session_id, purpose, provider, model, tier)` (locked and unlocked paths). Nothing else in the gate changed.
- Ledger kind `send_signed` (one row per NEAR exchange). `register()` adds the step `provider_near`.
- Receipts: section `signed_sends` (row ids) and `near_sends` (digests, signature kind, live verdict, replay verdict), `header.near` (`fully_attested`, `not_fully_attested_sends`, `replay_failures`), and `near_closing` (a constant, checked by `verify_chain`). `hermes confidential replay` replays NEAR evidence with `replay_near.replay` and every `send_signed` row with `replay_near.replay_receipt`; any failed signature makes the exit code 1.
- `hermes confidential setup --vendor near` attests, asks for the first pin, and prints a config block.

NEAR verification (`NearAdapter.verify`, one client nonce N per verify; attestation requests carry no API key):
- Gateway report (`include_tls_fingerprint=true`): quote verifies to the Intel SGX root (tinfoil's verifier; TCB collateral not evaluated); report data = SHA-256(signing key || raw TLS SPKI fingerprint) || N; MRCONFIGID matches `app_compose`; event log replays to RTMR3; the TLS certificate seen on that connection has that SPKI fingerprint (`confidential.near.require_tls_binding`, default true).
- Intel Trust Authority gateway token: PS384/RS256 signature against the JWKS fetched only from `portal.trustauthority.intel.com/certs` (or the EU host), whose x5c chain must end at a pinned root; `iss`, `iat`/`exp` at capture time; TDX, not debuggable, TCB status in `confidential.near.accepted_tcb_statuses` (default `[UpToDate]`); `tdx.attester_runtime_data` names N and the gateway signing key; MRCONFIGID, MRTD and RTMR0-2 equal the gateway quote's. The model-provider tokens are recorded and their GPU verdict shown, but they carry the gateway's TDX claims, so they decide nothing.
- Each allowlisted model (`provider=near`, `x-no-aliasing: true`): every candidate's quote verifies, report data = signing key zero-padded || N, MRCONFIGID and RTMR3 as above; at least one candidate. With `require_provider_tee` (default true) an empty allowlist fails verify.
- Evidence schema `confidential-mode/near-evidence/v1`: schema, vendor, base_url, enclave_host, platform, sdk_version, nonce, signing_algo, models, captured_at (asserted by capturer), captured_at_unix, gateway and model_reports (trimmed reports: signer, nonce, report_data, quote as base64, imr-3 events, compose_hash, instance ids, NVIDIA payload SHA-256 and size), app_composes (by hash), ita (gateway and model tokens, jwks_url), jwks, jwks_url_fetched, tls_observation, checks, policy, claims (fingerprints, identity, signers, components, tcb_status), repo, capture_complete, capture_missing[, capture_errors]. About 100-120 KB for one model, under the ledger's 256 KB cap.

Signed responses: every POST to `/chat/completions` or `/responses` through the NEAR views is sent with `x-no-aliasing: true` and `accept-encoding: identity`; with `require_provider_tee` a model off the allowlist is refused before sending. The view hashes the exact request body and the response body as received (after any content decoding; for SSE every byte including `data:` framing, blank lines and `[DONE]`; after the OpenAI SDK stops at `[DONE]` the view drains the rest before hashing). When the body ends it fetches `GET /v1/signature/<id>?signing_algo=ed25519` with the request's own Authorization header, retrying 404 for at most `confidential.near.signature_wait_seconds` (default 5), and writes one `send_signed` row: chat id, digests, sizes, status, content encoding, signature hex, kind, signing key, signed text, the check (`verdict` verified/unverified with the reason), `require_provider_tee`, `fully_attested`, the attestation nonce that ties it to its evidence, and the TLS SPKI seen. An interrupted body gets no fetch and a row saying so. `attested-near` reports `supports_streaming: False` (config `confidential.near.streaming`, default false) because NEAR's gateway re-signs streamed completions with its own key.

## Amendment 5.1 (2026-11-07): NEAR request encryption, the per-send TLS pin, the model-key binding

Owner W11 (branch `w11-e2ee`). Numbered 5.1 because it extends Amendment 5 only. Amendment 6 holds the codebase-review fixes; W12 takes 7. This amendment closes Amendment 6's open findings 1 (per-send TLS pin), 7 (one key across candidates) and 11 (non-chat POSTs); finding 19 (the adapter lock held across a capture) stays open.

- New file `verify/near_e2ee.py`: NEAR E2EE version 2 (docs.near.ai/cloud/guides/e2ee-chat-completions,
  read 2026-11-07), `seal`, `open`, `encrypt_request`, `decrypt_response`, `available`, `ClientKey`.
  Dependency `pynacl==1.6.*` (pyproject; installed by hand, docs/RUNNING_TESTS.md).
- Config `confidential.near.encrypt` (default true). `NearAdapter(encrypt=...)`, `encryption_ready()`,
  `model_public_key(model)`, `mark_stale(reason)`, `on_stale` (wired by `VerificationCache.register`
  to `invalidate`), `pinned_spki()`, `default_send_transport()`, `default_async_transport()`, and the
  `send_transport_factory` argument. `supports_streaming` is false while encrypting.
- Transport contract while encrypting: GET passes; the only POST is `/chat/completions`, rebuilt as a new
  `httpx.Request` (encrypted body, fresh Content-Length, the original headers and extensions, the E2EE
  headers with `X-Encrypt-All-Fields: true`); `stream: true`, non-text content parts, top-level keys
  outside `near_e2ee.PLAINTEXT_KEYS` that carry text, `logprobs`, and every other POST raise
  `VerifyError` before sending. While `require_provider_tee` (encrypting or not), POSTs outside the
  signable set raise too. An unstreamed reply is buffered, hashed, completed, finished (signature fetch
  and verdict). Only one outcome hands a body over: HTTP 200, a `fully_attested` send, and a body that
  decrypts under the exchange's key; it is returned without `content-length`/`content-encoding`. Every
  other outcome (any other status, 2xx included; a missing or bent signature; a reply that does not
  decrypt) raises. HTTP 421 (the gateway no longer accepts the model key) also holds the adapter and
  invalidates the cache entry, at most once per `confidential.near.reverify_backoff_seconds` (default
  30); a TLS pin mismatch on a send does the same and drops the pooled connections.
- Refusals from the NEAR views are `verify.near.NearRefusal`, a `VerifyError` and an `openai.OpenAIError`:
  the OpenAI SDK re-raises it as is, without its own retries. The attested profiles set
  `ProviderProfile.classify_api_error = provider.classify_refusal`, which Hermes' error classifier
  consults (`agent/error_classifier.py` `_profile_verdict`). NearRefusal carries `status_code` and a
  clipped `body` when the gateway answered with an HTTP error. The hook maps 429 to `rate_limit`, 503
  and 529 to `overloaded`, other 5xx to `server_error` (all retryable), and a 400 or 413 whose body says
  the context is too long to `context_overflow` (`should_compress`). Every other NearRefusal (421,
  other 4xx, non-200 success-shaped replies, withheld or undecryptable replies, refusals before
  sending) is `provider_policy_blocked`, `retryable: False`. None falls back. A retry is a new encrypted
  exchange; it never changes what is released.
- `mark_stale` and a new TLS fingerprint swap in a fresh send pool for new requests; the old pool is
  closed when its last in-flight request finishes. Transport errors (timeouts, resets) are not refusals: the SDK and Hermes may retry
  them, each attempt is a new exchange with a new client key, and each gets its own `send_signed` row.
  No status is synthesised.
- An encrypted exchange's `send_signed` row is written once both the signature verdict and the release
  outcome are known. It gains `reply_released` and `withheld_reason`; a withheld reply is `unverified`
  and not `fully_attested` even when its signature verified. A send that raised before a response
  arrived gets a row whose reason says "TLS pin mismatch, nothing sent" or "transport error (...)".
- A re-verify whose model signing key differs from the accepted one is refused (`VerifyError`, "model
  signing key ... changed") until pins cover the key (W12); a restart accepts it.
- TLS pin: inference and signature connections use pools whose SSL context checks the peer SPKI SHA-256
  against `pinned_spki()` right after the handshake (`pinned_ssl_context`). Attestation GETs keep an
  unpinned pool. `check.tls_verified` joins the send check; a send whose certificate differs, or cannot be
  read while `require_tls_binding`, is `unverified` and not `fully_attested`.
- `near_checks.check_report(require_signing_public_key=)`: model candidates need `signing_public_key ==
  signing_address`, 32 bytes of lower-case hex. `appraise` refuses a model whose verified candidates name
  different keys; equal keys are one signer (`model_signers` lists unique keys). `Appraisal.cvms` and
  `claims.cvms` record role, app_id, instance_id, compose_hash and signer per CVM.
- `send_signed` detail gains `near_e2ee` (NEAR's request encryption was applied; distinct from the
  Tinfoil EHBP flag `encrypted` on `send_observed`, Amendment 6), `e2ee_fields` (paths with `[]` for
  indices), `e2ee_field_count`, `dropped_fields`, `plaintext_keys` (top-level keys that left in plaintext,
  by name), `e2ee_version`, `client_pub`, `model_pub`, `reply_released`, `withheld_reason`.
- Receipts: `near_sends[]` gains `near_e2ee`, `e2ee_fields`, `e2ee_version`, `model_pub`; a
  receipt with an encrypted send must carry `near_encryption_note` (a constant; `verify_chain` fails a
  receipt that holds an encrypted send without it). `near_sends[]` also gains `plaintext_keys`,
  `reply_released` and `withheld_reason`. `replay_receipt` sends gain `near_e2ee`. `replay_near.NOT_ESTABLISHED` gains two items.
- Preflight (attested tier, any attested-near route, auxiliary fallback chains included): `<route>.api_mode`
  must be chat completions; `confidential.near.encrypt` and `confidential.near.require_tls_binding` must
  be absent or exactly true, and on in the running adapter; `confidential.near.encryption_library` is
  `missing` when PyNaCl does not import.

## Amendment 5.2 (2026-11-07): NEAR compose-manager log check, evidence schema v2, evidence blobs

Owner W13 (branch `w13-cm`). Extends Amendments 5 and 5.1. It closes Amendment 6's open finding 6 (the 256 KB ledger cap can drop NEAR evidence). NEAR documents none of the compose-manager attestation; its construction is reverse-engineered from captures of two instances on 2026-11-07, and a change on NEAR's side fails the check closed.

What the check establishes, and the strongest wording allowed anywhere: a TD of this instance reported this actions log for this nonce, the log's hash is bound in a hardware quote, and the per-service deployment map derived from the log is what the operator's own tooling reported. It does not establish that the inner compose is measured or that the reported services are the ones running.

- `near_checks.check_compose_manager(cm, *, nonce, model_quote, quote_verifier, model, app_compose)` raises `CmCheckError(step, message)`; the steps are `CM_CHECK_KEYS`: `cm_quote` (the same TDX verifier; not debug; its `event_log` replays to its RTMR3), `cm_same_td` (MRTD and RTMR0-3 equal the model quote's, quote to quote), `cm_report_data` (quote report data = `actions_hash || nonce`; `nonce` equals the request nonce; `nonce_source == "client"`; an echoed `report_data` agrees), `cm_actions_hash` (`actions_hash` = SHA-256 of `json.dumps(actions, sort_keys=True, separators=(",", ":"))`, default `ensure_ascii`; mismatch fails, no fallback), `cm_services` (`deployment_map`: a non-empty log of known actions; `compose_up` sets `"<file>::<service>"` to `{file, service, commit, file_sha256, tag}`, `compose_down` removes, `compose_stage` and `docker_restart` change nothing, `compose_manager_started` records an image; an action with no services acts on the whole file, recorded as service `*`; anything unknown or malformed fails), and `cm_image`.
- Prompt path: `near_checks.PROMPT_PATH_SERVICES` maps a model id to fnmatch patterns for its proxy, its engine and the rest (nginx, registrar, weight downloader), taken from the inner compose files at the commit each service was started from. Whole-file entries are always kept. A model without an entry, or an entry that matches no proxy or no engine, gets the whole map, and `services_scope` says which.
- `cm_image` compares the latest `compose_manager_started` image with the `compose-manager` image the measured app_compose names. It is in `INFORMATIONAL_CHECKS`: `True` when equal, `"recorded (not a pass): ..."` when not. It never fails verification and never counts as a pass. Every instance seen runs an image other than the measured one.
- `near_checks.rtmr3_identity(report)`: `app_id`, `instance_id`, `os_image_hash`, `key_provider_info` from the imr-3 events `app-id`, `instance-id`, `os-image-hash`, `key-provider`; `kms_id` = SHA-256 of the key provider's `id` (hex-decoded). An `info` value that differs fails the report (`gateway_quote` or `model_quotes`). v2 only.
- Evidence schema `confidential-mode/near-evidence/v2` (`near.EVIDENCE_SCHEMA`; `EVIDENCE_SCHEMA_V1`, `EVIDENCE_SCHEMAS`). Trimmed reports add `os_image_hash`, `key_provider_info` and, for model candidates, `compose_manager: {blob, bytes}` (the whole `compose_manager_attestation` as canonical JSON). `app_composes` is gone: every app_compose, every compose-manager block, every `intel_quote_b64` and every ITA token is a blob in `blobs` (id = SHA-256 of the UTF-8 text), referenced by compose hash, by `compose_manager.blob`, or as `{"$blob": id}`; `blob_refs` lists the ids. `appraise` drops a blob that does not hash to its id, so the check that needs it fails. v1 evidence appraises under v1 rules: `app_composes` inline, no RTMR3 identity binding, the six new checks `"n/a: not run (...)"` (`near.CM_NOT_RUN_V1`), fingerprints as before.
- `appraise(..., require_compose_manager=True)`: the adapter passes `require_provider_tee`; replay reads `policy.require_provider_tee`. A model candidate without the block fails `cm_quote`; with the flag off its checks are n/a.
- Fingerprint definitions are unchanged (Amendment 5). `Appraisal.cvms` and `claims.cvms` add, per CVM, `os_image_hash`, `kms_id`, `services`, `services_scope`, `cm_image_running`, `cm_image_measured` (the last four None for the gateway). `components` adds one line per CVM with its RTMR3 identity, and lines starting `reported: ` with the prompt-path services and both compose-manager images. `PendingPin.components` carries them unchanged; `consent` shows the `reported: ` lines under `REPORTED_HEADING` and `REPORTED_NOT_PINNED`. W12 turns them into a components dict and pins them.
- Ledger: `BlobStore` (`<data_dir>/evidence/blobs/<sha256>`, next to the ledger file; write-once; `get` returns None for a missing blob or one whose bytes are not its id). `Ledger(..., blob_dir=)`, `Ledger.blobs`, `Ledger.blob(id)`. `append` runs `externalize_evidence`: each `detail.evidence.blobs` text must hash to its id and pass the content-key scan (parsed as JSON), is written to the store, and is replaced by `blob_refs`. With no store the blobs stay inline. Measured on real captures: one model, one candidate, 141 KB inline and 19 KB stored; three models with two candidates each and 86-action logs, 588 KB inline and 122 KB stored.
- Receipts: each `evidence[]` item whose evidence has `blob_refs` gains `blobs` (every referenced blob the store holds) and, when any is absent or altered, `blobs_missing`. `verify_chain` fails an item whose `blobs` holds an id the evidence does not reference or bytes that are not its id. `replay_near.with_blobs(evidence, blobs)`; `evidence_by_nonce` and `hermes confidential replay` join them.
- Replay: `replay_near.replay` reports the six checks; `NearReplayResult` gains `schema`, `cvms`, `components`; `NOT_ESTABLISHED` replaces the after-launch item with three items (what runs after launch is not measured, with the claim above; the running compose-manager image is not the measured one; the inner services hold the dstack quote socket). v1 results carry `NOT_ESTABLISHED_V1`, the earlier list.
- Tests: `tests/fixtures/near_real_capture/` holds a refreshed capture with the compose-manager block, a second instance's 86-action candidate, and v1 evidence built by commit 9af0c9e.

## Amendment 6 (2026-11-07, after the independent codebase review): contract changes

Each item names the review finding it resolves.
- Finding 2, terminal backend. The preflight gains the item `terminal.backend` and the item `terminal backend (resolved)`, the backend Hermes resolves for the profile (`preflight.resolved_terminal_backend()`: `tools.terminal_tool._get_env_config()["env_type"]`, which bridges config.yaml first and reads the profile's terminal scope; it falls back to `terminal_scope.terminal_env`, then `os.environ`). Each passes only for `local` (unset or "" counts as local, as Hermes reads it). Anything else is off_tier, with a fix that names the backend and the key. `docker` is refused too. The lock is also refused while `tools.terminal_tool._active_environments` holds any environment not tagged `local` (Hermes reuses a task's environment without re-reading the backend). The config fingerprint covers the config key and the resolved backend, normalised so that unset and `local` agree; this is fingerprint version 2, and `locking.fingerprint_matches` also accepts the version-1 fingerprint of a lock recorded before, so an upgrade is not a config change. The on-host set `ON_HOST_TOOLS` is unchanged. Its subset `TERMINAL_BACKEND_TOOLS` (terminal, process_manage, execute_code, read_file, write_file, patch, search_files) is no longer "locked: on-host -> None" unconditionally: both tool-gate lines block such a call when `gate_tools.hermes_terminal_backend(task_id)` is not `local` (decision `terminal_backend`), or cannot be read (decision `terminal_backend_unreadable`). That function reads the resolved backend and the backend tag of the environment Hermes has cached for the task (`terminal_tool_lifecycle.get_active_env`). At 84a0301 a per-task `env_type` override does not select a backend, so the check does not read one.
- Finding 3, per-send record. In the locked in-tier path, `LlmGate.guarded_call` writes its `send_observed` row after `next_call` returns or raises, not before (the `pre_api_request` hook still ledgers the attempt first). The row's detail carries the vendor transport's per-exchange record: `hpke_key_used` (the key the SDK's EHBP transport holds after the response, `hpke_key_source` "ehbp_transport", else the SDK's current key, "sdk_state"), `response_decrypted` (for a stream the client closed at `[DONE]`, the view drains the rest of the body, bounded, to decide; a stream closed earlier stays None with `stream_closed_before_eof`), `encrypted`, `tls_spki_sha256`, `tls_matches_report` from the last exchange, and `sends` (every exchange) when there was more than one. It also carries `started_ts` and `verify_before`, the latest `verify_ok` id when the call began; receipts take the covering verify row and its TTL window from those, so a re-verify during the call is not credited with the send. The gate collects records through `sendctx.capture_records`; the Tinfoil views add them through `sendctx.add_record`. Receipts compare every exchange's key with the covering verify row's H.
- Finding 5, evidence schema. Tinfoil evidence's `trusted_root` is `{"sha256", "json_b64"}`: the bytes are embedded and no local path is recorded. Replay reads `--trusted-root`, then a `trust_root_dir` file, then `json_b64`, then the legacy `path`.
- Finding 8, live runtime. `locking.live_main_runtime()` returns None only for an unbound context and raises `LiveRuntimeUnreadable` when the Hermes accessor cannot be read. `pre_llm_call` then blocks, `lock` refuses and status says UNREADABLE.
- Finding 9, lock order. `ConfidentialState.lock(tier, fingerprint, *, since=None)` and `ConfidentialState.now()`. `locking.lock` computes the lock id (`gate_tools.lock_id_from(since, fingerprint)`), persists the allowlist, and only then sets the locked flag; a failed persist refuses the lock. `Runtime.allowlist()` rebuilds an empty cached allowlist when the file changes.
- Finding 10, replay exit. `hermes confidential replay` exits 1 when the hash chain is broken or cannot be checked, whatever the evidence rows say.
- Finding 20, answers. Ledger rows store a classification of an approval answer, never free text: Hermes' fixed answers (`once`, `session`, `always`, `deny`, `timeout`, `cancelled`, `notify_failed`, `smart_approve`, `smart_deny`), "" and None verbatim, any other string as "other", any other value as its type name. Consent's `raw_pick` follows the same rule with the choices `approve` and `deny`.
- Finding 22, ledger read. `Ledger.last_id_before(kind, before_id)` joins `append`, `tail` and `session`. Receipts use it to start reading at the last unlock before the session; with no earlier unlock the read still starts at the first row.
- Finding 25, where the attested client is gated. `ConfidentialClient.chat.completions.create` is the only method with its own gate check; `__getattr__` exposes every other OpenAI resource on the same transport. The real guard is the adapter-level hold: every Tinfoil and NEAR view refuses to send while the adapter has no accepted verification. The llm gate's `attested_ok` covers main calls in addition.
- Finding 27, gateway commands. When `hermes_cli.commands.resolve_command` cannot be imported or raises, `pre_gateway_dispatch` refuses every slash command while locked (decision `command_unresolved`) except, by exact typed word, `/confidential`, `/stop`, `/pause`, `/approve`, `/deny`, `/new`, `/help` and `/status`.
- Finding 9 addendum, unlock. `/confidential off` removes `allowlist.yaml` before clearing the lock flag, and only when the file's `lock_id` is the lock being cleared (`gate_tools.clear_persisted(path, lock_id=...)`).
- Open findings, owned elsewhere. Finding 1 (no per-send TLS pin or verdict for NEAR inference), finding 7 (two NEAR candidates under one key read as ambiguous), finding 11 (NEAR POSTs outside chat completions and responses skip the model allowlist) and finding 19 (the NEAR adapter's lock held across a capture) belong to W11 on branch `w11-e2ee`. Finding 6 (the 256 KB ledger cap can drop NEAR verification evidence) belongs to W13 and is closed by Amendment 5.2. This amendment does not change any of them; README and DISCLOSURE text on NEAR TLS is left for W11 to rewrite.

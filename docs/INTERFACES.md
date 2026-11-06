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
class Tier(str, Enum): LOCAL = "local-only"; ATTESTED = "attested"; ZDR = "zero-retention"

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

LOCAL predicate: in_tier iff base_url host is loopback, RFC1918, 100.64/10, fe80::/10, fc00::/7, "localhost", or in `confidential.local.extra_hosts`. Empty base_url for a provider whose profile base_url is local counts as local; otherwise off-tier. ATTESTED predicate: in_tier iff dest.provider is a registered attested profile AND VerificationCache.fresh(provider) AND pins match (W2 exposes `attested_ok(provider) -> Verdict`). ZDR predicate: deferred; stub returns off-tier with reason "zero-retention tier not implemented".

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
    verified_at_local: float    # time.time(); NOT attested
    evidence: dict              # raw, JSON-serialisable, stored in the ledger

class VendorAdapter(Protocol):
    vendor: str
    def verify(self) -> VerificationResult: ...        # raises VerifyError on any failure; never returns partial
    def sync_http_view(self) -> httpx.Client: ...      # non-closing view over the one verified pool
    def async_http_for_loop(self) -> httpx.AsyncClient # one per running loop
```

PinRecord (pins.yaml v2): vendor, router_repo, code_fingerprint, enclave_fingerprint, release_tag, models_seen[], approved_by ("human"), approved_at (ISO UTC), approved_via (surface string), approval_rule_key, previous (fingerprint or null). `PinStore.match(result) -> bool`, `PinStore.stage(result) -> PendingPin`, `PinStore.pending() -> PendingPin | None`, `PinStore.apply(pending) -> PinRecord`. Only consent.py calls apply.

Ledger (ledger.sqlite, table `events`): id INTEGER PK, ts REAL, session_id TEXT, kind TEXT, purpose TEXT, provider TEXT, host TEXT, model TEXT, bytes INTEGER NULL, tier TEXT NULL, verdict TEXT NULL, decision TEXT NULL, surface TEXT NULL, detail TEXT (JSON). Kinds: send_observed, send_refused, verify_ok, verify_fail, tool_asked, tool_allowed, tool_refused, pin_staged, pin_applied, pin_denied, seal, unseal, preflight_fail, breach, compaction. `Ledger.append(event)`; `Ledger.tail(since_id) -> list` for the watch view; `Ledger.session(session_id) -> list` for receipts. Never store prompt text; bytes only.

State (ctx.state, per profile): sealed (bool), sealed_tier (str), sealed_since (float), config_fingerprint (sha256 of the preflight-relevant core config at seal), breached_sessions (list[str]). Verification cache lives in process memory in W2, not in ctx.state.

## Contracts

### W1 gate_llm.py (middleware) — proven constraints (C0)
- Registered via ctx.register_middleware("llm_execution", fn). The body is wrapped so that NOTHING escapes: any exception is converted to a refusal; an escaping exception is fail-open.
- Reads context: provider, base_url, model, api_mode, session_id, request. Builds Destination(purpose="main" or "fallback" when agent fallback index > 0 if available, else "main").
- If not sealed: call next_call unchanged, but ledger send_observed with host and byte size of the serialised request (watch view works unsealed).
- If sealed: classify via the active TierPredicate. Off-tier -> ledger send_refused, return refusal (never call next_call). In-tier -> wrap next_call in try/except Exception: unwrap `getattr(exc, "original", exc)`; if InterruptedError re-raise; else ledger and return refusal "attested endpoint unavailable; this turn ended; resend". Never let fallback arm.
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
- `run_preflight(tier, config) -> PreflightReport` where config is Hermes' loaded config (read-only; use hermes_cli.config load_config_readonly or equivalent). Items: model.provider; every fallback_providers entry (must be empty); every auxiliary.<task>.{provider,base_url,fallback_chain} for every built-in task in config_defaults and every plugin-registered task (get_plugin_auxiliary_tasks); auxiliary.vision must be explicit and in-tier or disabled; memory.provider (local or none); mcp_servers.* with a URL; plugins.isolation == in_process; get_provider_profile(<attested profile>) is not None when tier is attested; model.provider != moa and no moa in any chain; provider != openai-codex. Each item carries verdict in {in_tier, local, disabled, off_tier, missing} and a one-line fix with the exact YAML key.
- `config_fingerprint(config) -> str` over exactly the keys above, for the per-turn recheck.
- `hermes confidential check` output format: a table of key, value (redacted), verdict, fix.
- Tests: pure unit tests over config dicts; a seam test that a plugin-registered aux task appears.

### W4 gate_tools.py, consent.py
- Allowlist built at seal from tools.registry: local set = {terminal, process_manage, execute_code, read_file, write_file, patch, search_files, skills_list, skill_view, skill_manage, todo_list, memory, clarify, session_search}; everything else is off-machine. Print the computed lists on seal.
- pre_tool_call(tool_name, args, task_id, session_id, ...): unsealed -> None (observe only, ledger nothing). Sealed: local -> None; cronjob_manage -> block; delegate_task -> allow only if route is default backend and no profile/acp fields, else block; MCP tool from a URL server -> block; other off-machine tool -> if yolo/bypass active (tools.approval._yolo_active() or approvals.mode off) -> block, else return {"action": "approve", "message": f"{tool_name} wants to send ~{n} KB of this conversation off the machine"} with n from len(json.dumps(args)); ledger tool_asked and, from post_approval_response, tool_allowed/tool_refused.
- consent.py: `approve_pending_pin(ctx, store, ledger, *, session_key, session_id, platform)` using ctx.ask_choice exactly as in docs/C0-spikes.md; sync only; None -> deny; re-check pending equality before apply; ledger pin_applied/pin_denied with raw_pick. `allow_tool(ctx, name)` same primitive for allowlist additions.
- Tests: registry-driven allowlist from a fake registry; bypass-state -> block not approve; ask_choice returning None -> deny and no apply; pending swapped during wait -> not applied.

## Decisions carried from C0
- Consent primitive is ctx.ask_choice; request_tool_approval is used only by the tool gate's approve directive inside a turn.
- Middleware never waits on a human; mismatch -> refuse + stage.
- Profile-wide seal in MVP; hooks carry session_id so per-session is possible later.
- Middleware bypasses (codex_app_server, max-iterations summary) are covered by the preflight requirement that the main provider is in-tier; refuse openai-codex outright.

## Amendment 1 (2026-11-06, after W3/T3): adjudications

Rule for all workstreams: behaviour assertions in hostile tests stand; parameter and fixture NAMES follow the implementation's public signatures (testers adapt, implementers do not rename to match guesses).

Tiers (W3 corrections accepted, plus):
- Main model key is `model.default` (alias `model.model`); bare-string `model:` is legal; empty or "auto" main provider is off_tier (it enables the aux discovery chain). Legacy `fallback_model` is part of the fallback chain and must be empty too.
- Any URL containing a backslash is off_tier (urllib and httpx disagree on the host). Schemeless base_url is off_tier. Malformed ports (non-numeric, >65535) are off_tier and must not raise. Obfuscated loopback forms (0x7f000001, 2130706433, 127.1, 0.0.0.0) are off_tier. 169.254.0.0/16 is off_tier (cloud metadata). IPv4-mapped private/loopback IPv6 is local.
- Empty base_url: resolve via the injected `profile_base_url(provider)`; a local result is in-tier, anything else off_tier. Real Hermes local profiles (ollama, lmstudio, llama-cpp) return "" at 84a0301, so the fix text tells the user to set `model.base_url` / `auxiliary.<task>.base_url` explicitly.
- Attested predicate: a base_url whose host differs from the attested profile's endpoint is off_tier (W3's profile_base_url parameter stays). T3's xfail for this becomes a normal test.
- MCP servers with a `url`: classify by `host_of(url)` with the active predicate (a localhost URL server is local). `enabled: false` is `disabled`. W4 blocks MCP tools only from servers whose URL host is off-tier.
- Vision: no "disabled" convention. `auxiliary.vision.provider` must be explicit and in-tier; unset, "", "auto", or a non-dict block is off_tier, with a fix that explains Hermes describes gateway inbound images through vision even without a tool call.
- `plugins.isolation` absent resolves to Hermes' default in_process (passing verdict); explicit "" or unknown values are `missing`/off_tier.
- Memory: "", builtin, built-in, local, none => local; else off_tier.
- Add to enumeration: `delegation.provider`, `delegation.model`, `delegation.base_url` (unset inherits the main verdict; set and off-tier => off_tier); `tts.provider` (assistant text is conversation content: unset/none/local => local, hosted => off_tier; read the real key names in config_defaults). `cron.model_provider` and moa presets are NOT enumerated; moa anywhere is refused and cron pins are a documented gap.
- Plugin aux tasks are registration dicts (defaults, inherit_from), layered as Hermes does; `plugin_aux_tasks: list[str | dict]`.
- Fingerprint covers model provider/default/base_url/api_mode, fallback_providers and fallback_model, every aux task's provider/base_url/fallback_chain, delegation.*, tts.provider, memory.provider, mcp_servers url/command/enabled, plugins.isolation; sorted keys; no secrets. Junk entries in any chain are off_tier.
- Pending (awaiting a product decision): a `terminal.backend` / `terminal.docker_network` item classifying commands as contained (docker, network off) or uncontained, and a three-mode rule for terminal/execute_code in the tool gate (ask on network-looking commands / allow all / block).

Tool gate (W4/T4): MCP tools are blocked when their server has a URL whose host is off-tier under the active predicate, not merely because a URL exists. delegate_task: a child on the default in-process backend inherits the sealed profile and is allowed; any route selecting another profile, an ACP command, or a non-default backend is blocked; W4 reads the real field names from tools/delegate_tool.py and lists them in its report.

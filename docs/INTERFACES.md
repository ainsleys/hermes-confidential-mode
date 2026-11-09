# Interfaces

This file is the developer contract for Hermes Confidential Mode: the shared types, what each module
exposes and guarantees, the file and row formats, and the rules each module keeps with Hermes. It
states the contract as the code implements it. Users need none of it: the [README](../README.md)
states what the plugin claims, and the [guide](GUIDE.md) describes how the plugin behaves.

## Conventions

- **Hermes commit.** Every statement about Hermes is about commit 84a0301. A Hermes path with a line
  number (`agent/turn_context.py:858`) names Hermes' own code at that commit.
- **Paths.** A module path is under `confidential_mode/` unless it starts with `tests/` or `scripts/` or
  is the root `__init__.py`. A reference written `file:name` names a definition in that file.
- **Module map.** [ARCHITECTURE.md](ARCHITECTURE.md) lists every module, what it is for and which
  plugin modules it imports. This file does not repeat the import lists. A name defined in a split
  module (for example `gate_tools_classify.py:classify_tool`) is also importable from the module it was
  split from (`gate_tools.py`, `commands.py`, `verify/near.py`), which imports each such name back as
  `X as X`, together with each private name another file uses. New code imports a name from the module
  that defines it, and a test that patches a module-level function patches the defining module, because
  callers look the name up there.
- **Never raises.** A function described as "never raises" catches every `Exception` and returns its
  documented fallback. Hermes treats an exception escaping a hook or a middleware as fail-open, so
  every hook and middleware body is wrapped this way.
- **Identity checks across a trust boundary.** Where a gate reads a flag or a verdict from a
  collaborator, only `True` permits and only `False` means unlocked; any other value fails closed.
- **Tests.** `tests/unit/` holds pure logic with no Hermes import; `tests/seam/` runs real Hermes
  modules at 84a0301 with fakes only for the vendor SDK, the network and the person answering prompts;
  `tests/hostile/` holds adversarial cases against each contract; `tests/fault/` injects filesystem,
  process, vendor, Hermes and crypto failures; `tests/scenario/` is an end-to-end demo; `tests/live/`
  calls NEAR for real and is skipped without `NEAR_AI_API_KEY`. [RUNNING_TESTS.md](RUNNING_TESTS.md)
  gives the commands. A test's result must not depend on test order: Hermes memoises model-list probes
  in process memory (`agent/model_metadata.py`), so every test that asserts no probe leaves starts with
  that cache cleared.

## Shared types

The types in `tiers.py` and `verify/base.py` are shared by every module. Changing a field or a
signature here is a contract change for every caller.

```python
# confidential_mode/tiers.py
class Tier(str, Enum): ON_HOST = "on-host-only"; ATTESTED = "attested"; ZDR = "zero-retention"

@dataclass(frozen=True)
class Destination:
    provider: str      # Hermes provider name, e.g. "attested-tinfoil", "openrouter", "custom"
    base_url: str      # as Hermes passes it; may be ""
    model: str
    api_mode: str      # chat_completions | anthropic_messages | codex_responses | bedrock_converse | codex_app_server
    purpose: str       # "main" | "fallback" | "aux:<task>" | "tool:<name>" | "memory" | "mcp:<server>"

@dataclass(frozen=True)
class Verdict:
    in_tier: bool
    reason: str        # short, user-visible, no secrets
    host: str = ""     # parsed host, for the ledger and the watch view

class TierPredicate(Protocol):
    tier: Tier
    def classify(self, dest: Destination) -> Verdict: ...
```

```python
# confidential_mode/verify/base.py
class VerifyError(Exception): ...           # any verification failure; adapters never return a partial result

@dataclass(frozen=True)
class VerificationResult:
    vendor: str                       # "tinfoil" or "near"
    router_repo: str                  # the pin identity (see "Pins file")
    enclave_host: str
    code_fingerprint: str
    enclave_fingerprint: str
    release_tag: str | None           # None when the vendor publishes no signed release tag (NEAR)
    verifier: str                     # verifier identity and version
    verified_at_host_clock: float     # time.time(); not attested, labelled as the host clock wherever shown
    evidence: dict = field(default_factory=dict)   # raw, JSON-serialisable; stored in the verify_ok row

@dataclass
class PreparedVerification:           # passed its checks, not yet in use
    result: VerificationResult
    payload: Any = None
    on_discard: Callable[[], None] | None = None
    def discard(self) -> None: ...    # releases what the capture built; never raises

class VendorAdapter(Protocol):
    vendor: str
    def verify(self) -> VerificationResult: ...
    def sync_http_view(self) -> httpx.Client: ...
    def async_http_for_loop(self) -> httpx.AsyncClient: ...
```

`verify/base.py:VendorHTTPError(VerifyError)` is the error for a vendor endpoint that answered with an
HTTP error. It takes `vendor`, `subject` (a model id, `NEAR gateway <host>` or `Tinfoil router <host>`),
`status`, `path`, `next_step`, `subject_kind` (default `model`) and `what` (default `attestation`), and its
text is `<subject>: <what> unavailable (HTTP <status> from <vendor>); <next step>`. The response body is
never part of the text. `VendorHTTPError.status_code` returns `status`. The helpers beside it:

- `http_next_step(status, subject_kind)`: for 404 "check the <kind> id; the vendor does not serve an
  attestation for it"; for 401 and 403 "the endpoint is public, so the refusal is the server's; try again
  later"; otherwise "try again in a few minutes".
- `inference_next_step(status, key_name)`: for 401 and 403 "check <key_name>"; for 404 "check the model
  id; the router does not serve it"; for 429 "the router is rate limiting; try again in a few minutes";
  for a 3xx "the router answered with a redirect, which the plugin does not follow"; otherwise "try again
  in a few minutes".
- `http_error_in(exc)` returns (status, URL) from the first HTTP error in the cause chain (`status_code`
  with `response.url` for requests and httpx; `code` with `url` for urllib's `HTTPError`);
  `http_status_in(exc)` returns the status alone; `vendor_error_in(exc)` returns the first
  `VendorHTTPError` in the chain. Each reads at most ten links.
- `http_source(url, router_host)` names who answered and what was fetched. The router (or no URL) is
  "Tinfoil", "attestation"; `github-proxy.tinfoil.sh` is "Tinfoil's GitHub proxy" and the GitHub hosts
  are "GitHub", both "release and Sigstore check"; `kds-proxy.tinfoil.sh` is "Tinfoil's AMD key proxy",
  "AMD certificate fetch"; `tdx-proxy.tinfoil.sh` is "Tinfoil's Intel PCS proxy", "Intel TDX collateral
  fetch"; any other `tinfoil.sh` host is "Tinfoil's <host>"; any other host is the host itself. Hosts
  match on a "." boundary (the name itself or a subdomain), so a look-alike such as `evilgithub.com` is
  named as itself. tinfoil 0.14.2 sends every Intel PCS request through `tdx-proxy.tinfoil.sh`, so there
  is no direct Intel entry.

The protocol declares only what `client.py` needs. The verification cache, the commands and the
background refresh use more members; "Vendor adapter interface" below lists them.

## Registration and hooks

`__init__.py:register(ctx)` builds one `Runtime` and wires it into Hermes. It never raises: each
registration step runs inside `_step`, which records a failed step in the runtime's `errors` list (its text clipped
to 300 characters) and in a `preflight_fail` row with purpose `register:<step>` and decision
`register_failed`, and the remaining steps still run.

- **Steps, in order:** `ledger`, `state`, `decisions` (`ApprovalDecisions` and `LockGrants`),
  `data_paths`, `data_modes` (file modes, see "Ledger"), `revocations` (`RevocationWatcher.baseline`),
  `provider` (`attested-tinfoil`), `provider_near` (`attested-near`), `background_refresh_gate`, `pins`
  (only when the provider step left no pin store), `llm_execution`, `tool_execution`, `pre_tool_call`,
  `post_approval_response`, the remaining hooks, `slash_command`, `cli_command`.
- **Middleware:** `llm_execution` (the llm gate) and `tool_execution` (the tool gate's enforcement).
- **Hooks (11):** `pre_tool_call`, `post_approval_response`, `pre_llm_call`, `pre_api_request`,
  `pre_auxiliary_call`, `post_auxiliary_call`, `on_session_start`, `on_session_end`, `post_compaction`,
  `pre_gateway_dispatch`, `transform_llm_output`. `plugin.yaml` and the catalog entry list the same
  hooks and middleware; `plugin.yaml` `provides_tools` is `[]`.
- **Commands:** `/confidential` (`commands.py:register_slash`) and `hermes confidential`
  (`commands.py:register_cli`).

What each hook does:

- `pre_llm_call`: when locked, runs `Runtime.turn_check(session_id, turn_id, tier, lookups=False)` and
  returns `{"action": "block", "message": <text>}` on a finding; otherwise returns
  `{"context": locking.locked_note(tier, mode)}`. An unreadable lock state blocks with the llm gate's
  `TEXT_STATE_UNREADABLE`; a plugin that fails to load blocks with "Confidential mode: the plugin failed
  to load; turn not sent." The hook does no network I/O. See "Lock, unlock and the per-turn check".
- `pre_api_request`: writes a `send_observed` row for the main call's attempt (decision `attempt`,
  detail `source: pre_api_request` and `api_request_id`). The llm gate writes the outcome.
- `pre_auxiliary_call` and `post_auxiliary_call`: write a `send_observed` row with purpose `aux:<task>`
  and decision `observed`, classified with the structural predicate while locked. An off-tier side call
  while locked (or with unreadable lock state) marks the session breached and writes a `breach` row
  (decision `aux_sent`). `post_auxiliary_call` skips a request id that `pre_auxiliary_call` already saw.
  `pre_auxiliary_call` also notes session and tier for the vendor adapters by Hermes' relay request id
  (`sendctx.note_aux`), because the hook runs on a Hermes timeout worker and cannot set a ContextVar for
  the send itself.
- `on_session_start` and `on_session_end`: while locked or unreadable, write a `session_start` or
  `session_end` row (purpose `session`). These are never `lock` rows.
- `post_compaction`: writes a `compaction` row with the old session id, reason and token counts.
- `pre_gateway_dispatch`: the gateway command check (see "Lock, unlock and the per-turn check").
- `transform_llm_output`: appends the plaintext image notice to the next reply of a marked session (see
  "NEAR adapter", image parts). It returns None otherwise.

`Runtime` holds the per-process collaborators: the ledger, the lock state, the pin store, both
adapters and the verification cache, the allowlist (rebuilt from `allowlist.yaml` by
`Runtime.allowlist()`), `ApprovalDecisions`, `LockGrants`, the `RevocationWatcher`, the turn-check
cache and the image-notice marks. `Runtime.is_locked()` returns `(bool, Tier | None)` and raises on
unreadable state.

## Tiers

`tiers.py` holds the three predicates. `locking.py:predicate_for(tier, config=...)` returns the
predicate for a tier with its collaborators; `locking.py:structural_predicate` returns one that skips
the attestation freshness check (used for the per-turn recheck and the side-call rows).

**URL parsing.** `tiers.py:host_of(url)` returns the lower-cased host without a trailing dot, or "".
`tiers.py:strict_host(url)` returns (host, problem), and problem is "" only for a clean `http://` or
`https://` URL. It fails closed on any form two URL parsers could read differently: a backslash, any
whitespace or control character (tab, CR, LF, NUL included, even trailing), non-ASCII text, a missing or
other scheme, a schemeless URL, a malformed or out-of-range port, an empty host, and a `%` in the host
other than an IPv6 zone id. Encoded `%5C` in userinfo is not a host character and stays on-host when the
host itself is loopback.

**On-host predicate** (`tiers.py:OnHostPredicate`, tier `on-host-only`). In tier:

- a loopback literal: `127.0.0.0/8`, `::1`, or the IPv4-mapped form of a loopback address;
- a name in `tiers.py:ON_HOST_NAMES` (`localhost`, `localhost.localdomain`, `ip6-localhost`,
  `ip6-loopback`);
- this machine's own host name when every address the name resolves to is loopback
  (`tiers.py:own_hostname_is_loopback`): the plugin resolves `socket.gethostname()` only when the
  destination host equals that name, one lookup at a time, with a two-second timeout; an error, a
  timeout, an empty answer or any non-loopback address gives off-tier, cached for the process; a
  loopback answer is rechecked once it is older than 60 seconds. No other name is ever resolved by the
  plugin. Under `tiers.py:cached_lookups_only()` the function answers only from its cache (even past
  the 60 seconds) or raises `tiers.py:LookupDeferred`, a `BaseException`;
- an exact host listed in `confidential.on_host.extra_hosts`. The verdict reason is
  `listed on-host host <host> (confidential.on_host.extra_hosts)`, so the ledger and the receipt tell a
  listed host from loopback (`on-host endpoint <host>`). A listed IP address matches every spelling of
  that address, its IPv4-mapped form included. A listed name matches only that exact name and is
  resolved by the HTTP client at every send, so listing a name trusts that name's DNS.

Everything else is off-tier: private IPv4 ranges (`10/8`, `172.16/12`, `192.168/16`), carrier-grade NAT
(`100.64/10`), IPv4 link-local (`169.254/16`, which holds the cloud metadata address), IPv6 link-local
(`fe80::/10`) and IPv6 unique-local (`fc00::/7`) unless the exact host is listed; obfuscated loopback
spellings (`0x7f000001`, `2130706433`, `127.1`) and `0.0.0.0`; and any name that is not listed. The
off-tier reason for a neighbour range names the range and the key `confidential.on_host.extra_hosts`,
and the preflight row's fix carries that reason. An empty `base_url` is resolved through
`profile_base_url(provider)`; an on-host result is in tier, anything else off-tier. Hermes' on-host
profiles (ollama, lmstudio, llama-cpp) have an empty `base_url` at 84a0301, so the fix text tells the
user to set `model.base_url` or `auxiliary.<task>.base_url` explicitly.

**Zone ids.** `strict_host` accepts `%` in a host only on an IPv6 link-local literal with a plain
interface name (`[a-z0-9_-]{1,64}`, no dot, so a zone cannot look like a domain).
`127.0.0.1%25evil.com`, any IPv4 literal with `%`, and `::1%25lo0` are off-tier.

**`extra_hosts` entries.** `tiers.py:extra_host_problem(entry)` returns "" for one exact host: one IP
address (a zone id only on IPv6 link-local) or one DNS name whose last label starts with a letter.
Anything else is refused: a CIDR range, a wildcard, a dash range, a URL, a port, whitespace, non-ASCII, a
non-string, numeric spellings such as `127.1`, and the addresses `0.0.0.0`, `::`, multicast, broadcast,
`169.254.169.254` and `fd00:ec2::254` (each named as the cloud metadata address where it is one). A
refused entry matches nothing.

**Attested predicate** (`tiers.py:AttestedPredicate`, tier `attested`). In tier only when the provider
is one of `locking.py:ATTESTED_PROFILES` (`attested-tinfoil`, `attested-near`, matched exactly), a
non-empty `base_url` passes `strict_host` and has the same host as the attested profile's endpoint, and
`attested_ok(provider)` returns an in-tier `Verdict` (see "Attested providers"). An exception or a
non-`Verdict` answer from `attested_ok` is off-tier.

**Zero-retention predicate** (`tiers.py:ZdrPredicate`). Deferred: every destination is off-tier with
the reason "zero-retention tier not implemented".

## Preflight

`preflight.py:run_preflight(tier, config, ...)` classifies every route in Hermes' loaded config (read
only) that can carry conversation bytes, and returns a `PreflightReport` of `PreflightItem` rows. Each
row has a key (the exact YAML key), a value (redacted), a verdict, a one-line fix that names the key and
the value to write, and a `group` ("" or `inherit`). The verdicts are `preflight.py:VERDICTS`:
`in_tier`, `on_host`, `disabled`, `off_tier` and `missing`; `in_tier`, `on_host` and `disabled` pass
(`PASSING`). The lock passes only when no row fails.

The rows:

- **Main route.** `model.provider`; the main model key is `model.default` (alias `model.model`), and a
  bare-string `model:` is legal. An empty or `auto` main provider is off-tier, because it enables
  Hermes' auxiliary discovery chain. `moa` as the main provider or anywhere in a chain is refused, and
  `openai-codex` is refused outright (the `codex_app_server` and max-iterations summary paths bypass the
  middleware).
- **Fallbacks.** Every `fallback_providers` entry and the legacy `fallback_model` must be empty. Junk
  entries in any chain are off-tier.
- **Auxiliary tasks.** `auxiliary.<task>.provider`, `.base_url` and `.fallback_chain` for every built-in
  task in Hermes' `config_defaults` (or `preflight.py:BUILTIN_AUX_TASKS_SNAPSHOT` when Hermes cannot be
  read) and every plugin-registered task (registration dicts with `defaults` and `inherit_from`, layered
  as Hermes layers them). A task left on `auto`, "" or `main` with no `base_url` inherits the main route
  and gets `group="inherit"`. Under a lock Hermes' fall-through to OpenRouter or Nous
  (`agent/auxiliary_client.py:3080-3088`) runs for a text side call only when the main provider is unset
  or `auto` (`_discovery_chain_allowed`, `:4529-4541`) and for vision only on `auto` (`:5541-5567`); the
  main-provider rule refuses both, so a task on `auto` stays in tier.
- **Vision.** `auxiliary.vision.provider` must be explicit and in tier. Unset, "", `auto` or a non-dict
  block is off-tier, with a fix that explains that Hermes describes gateway inbound images through vision
  even without a tool call. There is no "disabled" convention for vision.
- **Delegation.** `delegation.provider`, `delegation.model` and `delegation.base_url`: unset inherits the
  main verdict; set and off-tier is off-tier.
- **Memory.** `memory.provider`: "", `builtin`, `built-in`, `local` and `none` are on-host; anything else
  is off-tier.
- **TTS.** One row, `tts.provider`. `tts.provider` defaults to `edge` (hosted), and Hermes has no
  `tts.enabled` key at 84a0301. The rules, in order: an on-host engine (`neutts`, `kittentts`, `piper`,
  `none`) or a `tts.providers.<name>` entry with a `command` is on-host; otherwise `voice.auto_tts`
  true is off-tier; otherwise a true `tts.enabled` is off-tier; otherwise the verdict is `disabled`,
  meaning no automatic TTS path is configured (the tool gate asks before `text_to_speech`).
- **MCP servers.** Each `mcp_servers.<name>.url` is classified with the active predicate as provider
  `mcp`: on the on-host tier a localhost URL is on-host; on the attested tier the attested predicate
  refuses provider `mcp`, so every enabled URL server, a localhost one included, is off-tier. An empty or
  non-string URL is off-tier. `enabled: false` (or "false", "0", "no", "off") is `disabled`. A server with
  a `command` gets a `mcp_servers.<name>.command` row, and a malformed entry or one with neither key gets a
  `mcp_servers.<name>` row.
- **Plugins.** `plugins.isolation` absent resolves to Hermes' default `in_process` and passes; an
  explicit "", `host` or an unknown value fails. `plugins.hook_callback_timeout` below
  `HOOK_TIMEOUT_FLOOR_SECONDS` (5) is off-tier with a fix; a value of 0 or less passes, and an absent key
  shows "(default 30s)". The other hook-execution keys get one pass row each, with the value shown, so
  `status` and `check` name every `plugins.*` key the fingerprint covers: `plugins.load_timeout_seconds`
  (an absent key shows "(default 10s)", `0` shows "0 (loads inline)"), `plugins.enabled` and
  `plugins.disabled` (a list shows its names, an absent key shows "(absent)").
- **Terminal backend.** `terminal.backend` and `terminal backend (resolved)`, the backend Hermes
  resolves for the profile (`preflight.py:resolved_terminal_backend`: Hermes'
  `tools.terminal_tool._get_env_config()["env_type"]`, which bridges config.yaml first and reads the
  profile's terminal scope; it falls back to `terminal_scope.terminal_env`, then `os.environ`). Each
  passes only for `local` (unset or "" counts as local). Anything else, `docker` included, is off-tier
  with a fix that names the backend and the key. The resolved row is shown only when Hermes resolves a
  value. The lock is also refused while Hermes holds a cached
  terminal environment not tagged `local`, because Hermes reuses a task's environment without re-reading
  the backend.
- **Attested profile.** On the attested tier, one row `provider_profile[<profile>]` must be registered,
  where the profile is `locking.py:attested_profile_for(config)` (`model.provider` when it is an
  attested profile, else `attested-tinfoil`). A verification still pending within the wait has a
  reason starting "verification pending" and the verdict `off_tier`.
- **NEAR settings** (attested tier, any route through `attested-near`, auxiliary fallback chains
  included): `<route>.api_mode` must be chat completions; `confidential.near.encrypt` and
  `confidential.near.require_tls_binding` must be absent or exactly `true`, and on in the running
  adapter; `confidential.near.encryption_library` is `missing` when PyNaCl does not import;
  `confidential.near.image_parts` must be `disclose` or `refuse` and shows the value (and the running
  adapter's value when it differs).
- **On-host hosts.** On the on-host tier, one row per `confidential.on_host.extra_hosts[i]`; a refused
  entry or a non-list value is off-tier.
- **Vendor keys** (only when `key_state` is passed): one row per attested vendor a route uses (main,
  auxiliary tasks and their fallback entries, delegation), key `TINFOIL_API_KEY` or `NEAR_AI_API_KEY`,
  value `set`, `not set` or `not readable in this scope`. See "Credentials" below.

**Fixes.** `preflight.py:provider_value_hint(tier, main_provider, main_ok)` names the value to write:
the main provider's name when the tier can use it and the main route passes, else
`attested-tinfoil (or attested-near)` on the attested tier or
`custom, with base_url http://127.0.0.1:11434/v1` on the on-host tier. The main route's own fix
(`_main_provider_fix`) names `model.provider: attested-tinfoil or attested-near`, or
`model.provider: custom and model.base_url: http://127.0.0.1:11434/v1`. A failing explicit route uses
`preflight.py:route_fix(tier, prefix, provider, base_url, reason, value)`: on the attested tier, a
provider that is already an attested profile gets "<prefix>.provider is <p>; that route does not pass
yet (<reason>)"; on the on-host tier, a route with a `base_url` is worded from the failure reason (a
reason about the host names a base_url on this machine such as `http://127.0.0.1:11434/v1`; a reason
about the URL itself says to rewrite the URL as a plain `http://` or `https://` URL; any other reason
names the provider value); any other provider gets "set <prefix>.provider: <value> (<reason>)". No fix
says "an in-tier provider" without naming a value. When an attested verdict's reason ends "run
/confidential pins approve" (`preflight.py:pin_is_the_cause`), the route rows' fix is
`preflight.py:PIN_FIX` and the inheriting rows say `preflight.py:INHERIT_FIX`.

**Credentials.** `preflight.py:key_state(profile, env_var, config)` returns `KEY_SET` when Hermes'
`agent.secret_scope.get_secret(env_var)` is non-empty or a route naming the profile carries a
non-empty `api_key` (presence only); `UnscopedSecretError` gives `KEY_UNSCOPED`; anything else is
`KEY_NOT_SET`. This holds for `TINFOIL_API_KEY`, `NEAR_AI_API_KEY`, `OPENROUTER_API_KEY` and
`NOUS_API_KEY`. No plugin code opens `auth.json` or reads a key from `os.environ`, so a key added only
with `hermes auth`, or held only in Hermes' credential pool, reads as not set. The value and its length
are never shown. `key_fix(env_var, state)` starts "set <VAR> (see Requirements in README.md): ..." for a
key not set; for `KEY_UNSCOPED` the row says "<VAR> may be set, but <UNSCOPED_STEP>", where
`UNSCOPED_STEP` says the process (a gateway serving several profiles) cannot read keys outside a
profile's scope, so lock from a terminal (`hermes confidential on attested`) or give the key through
`model.api_key`. Only `lock` and `check` pass `key_state` (`locking.py:run_tier_preflight(check_keys=True)`);
the per-turn recheck never does, so a key a turn's process cannot read is never a config failure or a
breach. With `key_state` given and an OpenRouter or Nous credential readable
(`preflight.py:auto_chain_readable`), a side call row on `auto` carries `preflight.py:AUTO_NOTE`, and
`check` prints `preflight.py:auto_summary` (when the check ran and found none, the row says "(no
OpenRouter or Nous credential readable)"), which names "Nous (NOUS_API_KEY)" and ends with
`preflight.py:AUTO_SIGN_IN_NOTE` (Hermes has no public "is signed in" call for Nous that neither reads
`auth.json` nor refreshes a token).

**Report format.** `preflight.py:format_report(report, collapse=False)` prints a table of key, value,
verdict and fix, with the vendor-key rows (`KEY_ROW_KEYS`) first in every form. With `collapse=True`
(`check` without `--verbose`, and a refused lock) the inheriting rows become one row per verdict at the
first one's place: key `auxiliary.* (<n> tasks)`, value "inherit the main route", and for a failing
verdict the fix "the main route is <verdict>: ... (check --verbose lists each task)". A single
inheriting row stays as it is. `preflight.py:missing_key_headline(report)` gives a refused lock's first
line when a key row fails: "Not locked: <VAR> is not set; set <VAR> (see Requirements in README.md)." or,
for a key not readable in this scope, "<VAR> is not readable in this scope; <UNSCOPED_STEP>", plus "The preflight also found routes
that would leave the tier." only when other rows fail.

**Config fingerprint.** `preflight.py:config_fingerprint(config, ...)` is the SHA-256 of
`json.dumps(sort_keys=True, separators=(",", ":"), default=str)` over these keys, with no secrets:
`model` provider, default (or model), base_url and api_mode; each `fallback_providers` entry and
`fallback_model` (provider, model, base_url, api_mode); each auxiliary task's effective provider,
base_url and fallback_chain (built-in tasks, plugin tasks and any dict-valued user key), or the raw
value of a non-dict block; `delegation` provider, model, base_url, api_mode and fallback_providers;
`tts.provider`, `tts.enabled` (`<absent>` when absent) and `voice.auto_tts`; `memory.provider`; each
`mcp_servers.<name>` url, command and enabled; `plugins.isolation` and `plugins.execution` (the five
keys in `_PLUGIN_EXECUTION_KEYS`: isolation, hook_callback_timeout, load_timeout_seconds, enabled,
disabled); `terminal.backend` and the resolved backend, normalised so that unset and `local` agree; and
`confidential.on_host.extra_hosts` (the raw value) when the value is present and not empty. Auxiliary
model and api_mode and the `confidential.near.*` keys are not covered. An absent `extra_hosts` key and an empty list
fingerprint the same. This is fingerprint layout version 2; `locking.py:fingerprint_matches` also
accepts the version-1 fingerprint of a lock recorded under version 1, so an upgrade is not a config
change.

## Lock, unlock and the per-turn check

**Lock state** (`state.py:ConfidentialState`, over `ctx.state`, per profile). Keys: `locked` (bool),
`locked_tier` (str), `locked_since` (float), `config_fingerprint` (str), `breached_sessions`
(list[str]). A malformed value raises `StateError`, so every gate fails closed; an unreadable lock
state refuses every send and blocks every tool, on-host tools included, until `/confidential status`
or `/confidential off` repairs it, and the refusal text names those commands.
`ConfidentialState.lock(tier, fingerprint, *, since=None)` writes the keys with `locked` last;
`ConfidentialState.now()` is the state's clock. The verification cache lives in process memory, never
in `ctx.state`. The lock is profile-wide; every hook carries `session_id`, so a per-session lock is
possible later.

**Repairing state.json.** `ConfidentialState.unlock` writes through Hermes' `PluginState.set`. When that
raises and the store's file is a regular file (or a symlink to one) that cannot be read as a JSON object
(`state.py:_parses` is false: the file cannot be opened or read, its bytes are not UTF-8, its text is not
JSON, or its root is not an object), the file is replaced with `{"locked": false}` through
`atomicwrite.write_atomic` (mode 0600) while holding the `.state.json.lock` flock Hermes' `PluginState`
takes, re-checked under that lock. A symlink is replaced by a regular file and its target is left as it
was; every other key of the unparseable file is lost. A write error on a readable file, a directory in
place of the file, or a lock file held elsewhere still raises, so `/confidential off` reports an error and
the profile stays locked.

**Lock** (`locking.py:lock(tier, *, state, ledger, config, ...)`). Under the transition lock (below) it
takes these steps in order, and each refusal writes a `preflight_fail` row:

1. Refuse when already locked: "Already locked (<tier>). Run <off> first, then lock again.", with `<off>`
   in the caller's command form. The zero-retention tier is refused before this: "Not locked:
   zero-retention tier not implemented. Use on-host-only or attested."
2. Run the preflight with key checks and refuse with the headline and the collapsed table when any row
   fails (purpose `lock`).
3. Read the live main runtime and refuse when it is unreadable or off-tier (purpose `lock:live_runtime`).
4. Refuse while Hermes holds a cached terminal environment on a non-local backend (purpose
   `lock:terminal_environments`): "Restart Hermes (or wait for terminal.lifetime_seconds to pass), then
   lock again."
5. Import the built-in tool modules (`ensure_builtin_tools`) and build the allowlist from the live
   registry, with the lock id `gate_tools_allowlist.py:lock_id_for(since, fingerprint)`.
6. Persist the allowlist; a failed write refuses (purpose `lock:allowlist`).
7. Write the state with the `locked` flag last, then a `lock` row, and return the lock reply.

When the
state write raises, the lock returns "Not locked: the lock state could not be written (<error>). Check
that the Hermes plugin data directory is writable, then lock again.", writes a `preflight_fail` row
(purpose `lock:state`, detail `error_type`) and removes the allowlist.yaml it wrote for that lock
(`clear_persisted` with the refused lock's id, so a file another lock wrote is kept). `lock` never raises
for a refusal.

**Lock reply** (`locking.py:lock_message`), three lines:

1. "Locked to <vendor>, <model> at <host>; verified <age> ago." on the attested tier (the age is
   "<n> s" below 90 seconds, else "3m" or "2h"; "not verified yet" without a verification); on the on-host tier
   "Locked to this machine (on-host-only), <provider>/<model> at <host>." for loopback or "Locked to
   listed host <host> (on-host-only), ..." for an `extra_hosts` entry.
2. `locking.py:lock_disclosures(mode)`: "Off-host tools ask the first time per lock in each
   conversation." (`once_per_lock`) or "Off-host tools ask each call." (`each_call`), followed by "Shell
   and code execution are not inspected. Auxiliary calls are recorded, not refused. Not active in
   safe-worker mode." `LOCK_DISCLOSURES` is the default mode's text.
3. `LOCK_DETAILS`: "Details: hermes confidential status --verbose; docs/LIMITATIONS.md".

A successful attested lock with a pin pending adds `commands_pins.py:pending_pin_note` as a fourth line.
Plain `status` prints the same disclosures as its `Limits:` line. `LOCK_TAIL` (the full tool, auxiliary
and safe-worker text), the tool list and the preflight table are in `status --verbose`. Status also says when a pin update is pending.

**Unlock** (`locking.py:unlock(*, state, ledger, ..., allowlist_path)`). Under the transition lock it
removes `allowlist.yaml` (only when the file's `lock_id` is the lock being cleared; with unreadable
state the lock id is unknown and the file is removed, which the transition lock makes safe), clears the
flag, writes an `unlock` row with the lock period's counts, and clears both verification cache entries
(which stops the background refresh). On a profile that is not locked it returns "Not locked; nothing to
do, and nothing was recorded." and writes no `unlock` row; the verification caches are still cleared.

**Transition lock.** `locking.lock` and `locking.unlock` hold `filelock.exclusive` on
`lock-transition.lock` beside allowlist.yaml (a thread lock alone when no allowlist path is given). Lock
holds it from the already-locked check through the allowlist write, the state write and the `lock` row,
the attested verification included; unlock holds it around removing allowlist.yaml and clearing the flag.
A transition that cannot take the lock within 2 seconds (`filelock.exclusive`'s bound) is refused with a
`preflight_fail` row and writes no allowlist.yaml, state.json, `lock` or `unlock` row:

- purpose `<lock|unlock>:busy` when the file is held: "Not locked: another lock or an unlock of this
  profile is in progress (...)" or "Not unlocked (the lock is unchanged): a lock or another unlock ... is
  in progress (...)", each ending "Run <status>, then try again.";
- purpose `<lock|unlock>:data_dir` for a read-only directory: "...: the data directory is not writable:
  <dir>. Check the plugin data directory's permissions, then run /confidential on <tier> (or off) again.";
- purpose `<lock|unlock>:lockfile` for another unusable lock file.

`lock-transition.lock` is an empty file created on first use and kept.

**Live runtime.** Hermes resolves `auto` side calls to the live main runtime, which a session `/model`
switch, `--provider` or a gateway per-session override changes. `locking.py:live_main_runtime()` reads
it through `hermes_compat.runtime_main_context`; it returns None for an unbound context or a value that
is not a mapping with a provider or base_url, and raises
`LiveRuntimeUnreadable` when the accessor cannot be read. At lock and on every turn a live runtime whose
provider or base_url is off-tier refuses: the turn check writes a `send_refused` row (reason_code
`live_runtime_off_tier`), marks the session breached once with a `breach` row (purpose
`main:live_runtime`), and returns `locking.py:live_runtime_text`. An unreadable runtime writes a
`send_refused` row (reason_code `live_runtime_unreadable`) and returns `LIVE_RUNTIME_UNREADABLE_TEXT`; the
lock refuses and status says UNREADABLE. Hermes publishes the runtime
(`agent/turn_context.py:1140`) before `pre_llm_call` (`:1236`); turn-start compaction (`:1245`), memory
prefetch (`:1264`) and titling (`:1271`) run after the hook and are skipped when it blocks.

**Per-turn check** (`__init__.py:Runtime.turn_check(session_id, turn_id, tier, *, lookups=True)`). It
runs `locking.py:recheck` (the structural preflight; a fingerprint mismatch writes a `breach` row and
returns `CONFIG_CHANGED_TEXT`, a structural failure returns `STRUCTURE_FAILED_TEXT`) and the live-runtime
check, and returns None or (text, reason code), the code one of `config_changed`, `preflight_failed`,
`recheck_failed`, `recheck_timeout`, `live_runtime_off_tier`, `live_runtime_unreadable`,
`live_runtime_check_failed` or `plugin_unloadable`. Results are kept per (session id, turn id, lock id, tier), at most `TURN_CACHE_MAX`
(256) turns; a turn with no id is never cached. Each key holds one `_TurnCheck`: the first caller
computes, and later callers wait up to `TURN_CHECK_WAIT_SECONDS` (60), then the recheck timeout.
`pre_llm_call` passes `lookups=False`, so the check runs under `tiers.cached_lookups_only()`; a lookup it
would need returns `TURN_CHECK_DEFERRED`, caches nothing, and the hook adds no block. The llm gate runs
the same check (`gate_llm.py:build_middleware(turn_check=...)`), after the lock-state check and before
the predicate, so a turn whose hook Hermes skipped (the 30-second bound at
`hermes_cli/plugins_dispatch.py:183`, the 60-second suppression after a timeout, persistence disabled
at `agent/turn_context.py:858`) still gets the whole check before its main call. A skipped hook loses
only the veto over the side calls before the first main call (turn-start compaction, memory prefetch,
titling), which are recorded and not refused, and the locked note.

**Locked note** (`locking.py:locked_note(tier, mode)`). `LOCKED_NOTE` with `{ask}` from
`LOCKED_NOTE_ASK`: it tells the model which tools ask and that blocked tools are blocked, asks it to
tell the user rather than retry or work around a block, and names the disclosures (side calls
recorded, not prevented; not active in safe-worker mode).

**Gateway command check** (`__init__.py:_pre_gateway_dispatch`). While locked (or with unreadable lock
state), a gateway slash command that `hermes_compat.resolve_command` resolves to one of
`RUNTIME_SWITCH_COMMANDS` (`model`, `moa`) is rewritten to `/confidential blocked <command>`, which
replies with the refusal, and a `tool_refused` row is written (purpose `command:<name>`, decision
`runtime_switch`, surface `gateway`). When `resolve_command` cannot be imported or raises, every slash
command is refused (decision `command_unresolved`, rewrite `/confidential blocked <command> unresolved`)
except, by exact typed word, those in `UNRESOLVED_SAFE_COMMANDS`: `/confidential`, `/stop`, `/pause`,
`/approve`, `/deny`, `/new`, `/help` and `/status`. The hook returns None on any failure only while the
text is not yet recognised as a slash command. After recognition the decision comes first and the row is
written afterwards, so a failed write cannot undo the refusal; an exception in the plugin's own code
after recognition refuses when locked or unreadable (decision `hook_error`, detail `error_type`) and
passes the command when unlocked. The CLI and TUI never fire `pre_gateway_dispatch`; there the per-turn
live-runtime check ends the turn.

**Command forms.** `locking.py:command_text(verb, form)` returns `hermes confidential <verb>` (with
`check <tier>` as `check --tier <tier>`) for form `terminal` and `/confidential <verb>` otherwise. The
chat platform of Hermes' interactive CLI is also `cli`, so the form is a separate flag, not the surface.
The status Preflight line, the unreadable-state line, "Already locked", the transition refusals and
`allow` while unlocked use it.

## The llm gate

`gate_llm.py:build_middleware(...)` returns the `llm_execution` middleware, `LlmGate.handle` wrapped so
that nothing escapes: any exception becomes a refusal (`TEXT_INTERNAL_ERROR`, reason_code
`internal_error`); an exception raised by `next_call` itself propagates. The gate reads `provider`,
`base_url`, `model`, `api_mode`, `session_id` and `request` from the middleware context and builds a
`Destination`. Its purpose is `fallback` when the context has `call_role: fallback` or a
`fallback_index` above 0, else `main`; at 84a0301 the context carries neither, so the purpose is `main`,
and the destination fields already describe a fallback provider. The middleware never waits on a person. The
gate's ledger writes are best effort: a failed append is logged and never changes a send decision, so an
allowed send is still sent exactly once and a refused send is still refused.

- **Unlocked:** writes `send_observed` (decision `observed`, the host and the byte size of the
  serialised request) and calls `next_call` inside the send context.
- **Unreadable lock state:** refuses with `TEXT_STATE_UNREADABLE` (reason_code `lock_state_unreadable`).
- **Locked:** runs the per-turn check, then classifies with `predicate_for(tier)` (a predicate whose
  tier differs from the locked tier raises, which refuses). Off-tier writes `send_refused` (reason_code
  `off_tier`) and returns `off_tier_text(tier, reason)`; `next_call` is never called. The attested
  predicate already calls `attested_ok`, so a pin mismatch normally refuses here, with the reason
  "enclave build changed; run /confidential pins approve". On the attested tier the gate then asks
  `attested_ok(provider)` a second time; when that call disagrees with the first, it refuses with
  `TEXT_PIN_CHANGED` (reason_code `pin_mismatch`) when a pin is pending, else `attested_fail_text`
  (reason_code `attestation_not_ok`).
- **In tier:** `LlmGate.guarded_call` calls `next_call` inside `sendctx.send_context` (with
  `refusals_ledgered_by: llm_gate`) and `sendctx.capture_records`. Any exception is unwrapped with
  `getattr(exc, "original", exc)`; `InterruptedError` and non-`Exception` errors re-raise; anything else
  refuses with `TEXT_PROVIDER_ERROR` ("attested endpoint unavailable; this turn ended; resend.") and a
  `send_refused` row (reason_code `provider_error`, `error_type`, `status_code` when the error has one).
  Hermes' fallback (`_try_activate_fallback`) never arms. When `verify/base.py:vendor_error_in` finds a
  `VendorHTTPError`, the text is `TEXT_PROVIDER_ERROR` followed by the vendor text and the row carries
  `error_type: VendorHTTPError`, `status_code` and `reason`. A `ConfidentialRefused` from the attested
  client carries its reason, and a reason starting "vendor key unreadable" gives reason_code
  `vendor_key_unreadable`.

**The send row.** In the in-tier path the `send_observed` row (decision `allowed`) is written after
`next_call` returns or raises, so it carries the vendor transport's per-exchange record: the fields in
`gate_llm.py:SEND_RECORD_FIELDS` (`hpke_key_used`, `hpke_key_source`, `response_decrypted`,
`stream_closed_before_eof`, `encrypted`, `tls_spki_sha256`, `tls_matches_report`, `usage`) from the last
exchange, and `sends` (every exchange) when there was more than one. It also carries `started_ts` and
`verify_before`, the latest `verify_ok` id when the call began, so a re-verification during the call is
not credited with the send, and `response_bytes` when the response object can be measured. A
`ConfidentialRefused` raised before any byte is sent writes no `send_observed` row; the `send_refused`
row is the record. The `pre_api_request` row and the gate's row both carry `detail.api_request_id`.

**Response size.** `gate_llm.py:response_bytes` measures the parsed response object (a pydantic model, a
dict, or the `SimpleNamespace` Hermes assembles at the end of a stream) as re-serialised JSON, not the
wire bytes. `gate_llm.py:_plain` leaves out dict keys and namespace attributes that start with "_"
(Hermes' Codex dicts carry `_issuer_kind` and `_issuer_model`) and counts a bytes, bytearray or
memoryview value as a string of its length. The rule can only undercount, never overcount. The figure is
absent when the middleware receives a live stream, which the gate never consumes.

**Refusals.** `gate_llm.py:build_refusal(api_mode, text)` returns the response object each mode
expects: a ChatCompletion for `chat_completions`, a Response for `codex_responses`, an Anthropic-shaped
message for `anthropic_messages` and a dict for `bedrock_converse`. Finish fields are `finish_reason
"stop"`, `stop_reason "end_turn"` and `status "completed"`, never `content_filter`, `length` or `refusal`.
An unknown mode gets the chat-completions shape and the note `unknown_api_mode`; a builder that fails
falls back to the chat-completions shape and then to `last_resort_refusal`, a `SimpleNamespace` that
cannot raise. Every refusal text starts "Confidential mode: ".

## The tool gate

The tool gate has two lines. The `pre_tool_call` hook (`gate_tools.py:build_pre_tool_call`) asks or
blocks. The `tool_execution` middleware (`gate_tools.py:build_tool_execution`) enforces: it runs a gated
tool only on an exact recorded answer or a grant, because Hermes' CLI approve directive grants on any
answer except the exact string "deny" (`tools/approval.py:1006-1010`: None, "", "d", "Deny" and "yes" all
run the tool) and a hook cannot veto after the prompt. The observer `post_approval_response`
(`gate_tools.py:build_post_approval_response`) records each answer. The hook and the middleware share
one policy (`gate_tools_policy.py:_Policy.decide`), and both never raise: the middleware's own failure is
a refusal with decision `gate_error`.

Unlocked, both lines let every call through and ledger nothing. Unreadable lock state blocks and refuses
every tool, on-host tools included (decision `lock_state_unreadable`). Both builders call
`selfapproval.mark_tool_process()` first on every call, locked or not.

### Classification

`gate_tools_classify.py:classify_tool` gives each registered tool a `Route` from its name, toolset and
`Origin`: `ON_HOST` (`on-host`), `ASK` (`ask`), `DELEGATE` (`delegate`), `BLOCK_CRON` (`block-cron`) and
`BLOCK_MCP_URL` (`block-mcp-url`).

- **Built-in tools.** `gate_tools_classify.py:BUILTIN_TOOL_CLASSES` maps every built-in tool Hermes
  84a0301 registers to a data class (`DATA_CLASSES`): `ON_HOST` "on-host", `OFF_HOST` "off-host" or
  `UNSETTLED` "unsettled". [TOOL_CLASSES.md](TOOL_CLASSES.md) holds the same table with the evidence (the
  file and line of the network call, the hand-off or the process launch, or "no network path" with the
  files read) and the count of each class; `tests/unit/test_gate_tools.py` checks that the two tables are
  equal. A tool is on-host only when its own code makes no network call and launches nothing that does,
  an install of a declared dependency from a package index excepted; a tool whose data leaves this
  machine, or is handed to another agent (a kanban write the gateway dispatcher gives to a worker of
  another profile), is off-host; a tool whose data flow cannot be settled from Hermes' source is
  unsettled. Shell, code execution and the file tools are on-host by contract: they run what the model
  writes, they are not inspected, and the preflight requires the terminal backend to be local.
  `ON_HOST_TOOLS` is the table's on-host rows. Off-host and unsettled tools, and a built-in the table does
  not name (data class `UNKNOWN`, "unknown"), take `Route.ASK`. `ToolInfo.data_class` records the class,
  `ToolInfo.reason` names it (`CLASS_REASONS`), and `format_allowlist` prints "off-host", "unsettled" or
  "not audited" beside each ASK built-in. A plugin or MCP tool that registers a built-in on-host name is
  not on-host.
- **`cronjob_manage`** takes `BLOCK_CRON`; **`delegate_task`** takes `DELEGATE`.
- **MCP tools** (toolset `mcp-*`). A stdio (command) server's tools are on-host; a URL server on this
  host is on-host; a URL server that is in tier under a predicate other than on-host is ask; anything
  else, a server with no readable url or command included, is `BLOCK_MCP_URL`. `Allowlist.current`
  re-judges MCP tools against the live config and takes the stricter route.
- **Tools absent from the registry at lock** (memory-provider tools, context-engine tools, lazily
  connected MCP servers) and unknown names are unclassified: blocked by the hook and refused by the
  middleware (decision `unclassified`) with a message that names a relock.

### The allowlist

`gate_tools_allowlist.py:build_allowlist` classifies Hermes' live registry at lock into an `Allowlist`
holding each entry's route, toolset and handler object. A tool whose handler (compared with `is`) or
toolset differs at call time is unclassified. `format_allowlist` escapes or rejects names that contain
control characters, so a name cannot forge a line; the lock prints the computed lists.

- **Persistence.** `Allowlist.persist(path, added=...)` writes `allowlist.yaml` (mode 0600, through
  `atomicwrite.write_atomic`, under `revoke.file_lock`) with the lock id, each entry's name, toolset,
  handler module and qualname, and the `allowed` names. A process that loads the file rebuilds from the
  persisted set: a live registry entry not in it, or whose module or qualname differs, is unclassified
  until a relock. `Runtime.allowlist()` rebuilds a cached allowlist when the file changes, runs
  `RevocationWatcher.apply()` first, and sets `added` to the file's `allowed` list for the same lock, so
  a name another process removed is dropped.
- **Additions.** `Allowlist.add` writes the file first, starting from the names on disk for its lock
  under the file lock, and puts the name into `added` only after the write succeeded. Additions belong to
  the lock (the file's lock id); unlock removes the file, so an addition never outlives the lock. Hard
  blocks (`cronjob_manage`, `delegate_task` routes, off-tier MCP URL servers) cannot be lifted, and an
  unregistered name is refused without asking.
- **CLI processes.** A `hermes confidential` process never builds an agent, so `Runtime.allowlist()`
  calls `gate_tools_allowlist.py:ensure_tools_for_lock`, which imports only the `tools.*` modules named in
  allowlist.yaml for non-MCP tools (through `hermes_compat.import_tool_module`, with no
  discovery-cache write) and falls back to `ensure_builtin_tools` only when a recorded non-MCP built-in
  tool is still missing. MCP tools are gateway-registered, so nothing is imported for them and the CLI
  refuses them with a message that names the chat `allow` and a relock from chat. The imported modules
  keep their exit handlers; Hermes' browser handler stops only browser processes whose owning Hermes
  process is gone (`tools/browser_session_lifecycle.py:237-272`), so a running gateway's browsers are
  left alone. `lock` from a terminal may let Hermes rewrite `cache/tool_discovery_cache.json` when stale.
- `consent.py:unknown_tool_text`: a tool the lock recorded but this process has not registered is to be
  allowed from chat; a tool the lock never recorded cannot be allowed at all, and the text names a relock
  from chat (`/confidential off`, then `/confidential on <tier>`), because a lock made from a terminal
  records no gateway-only tool.

### Decisions

`_Policy.decide(..., session_id)` returns a `CallDecision` (run, refuse or ask) for one locked call, in
this order:

1. No current allowlist entry: refuse, `unclassified`.
2. `ON_HOST`: `_Policy.on_host_decision`. A tool in `SELF_APPROVAL_TOOLS` whose arguments invoke the
   plugin, or a tool in `STATE_FILE_TOOLS` that names a state file, is refused (`self_approval`, see
   "Self-approval guard"). A tool in `TERMINAL_BACKEND_TOOLS` (terminal, process_manage, execute_code,
   read_file, write_file, patch, search_files) is refused when
   `gate_tools_hermes.py:hermes_terminal_backend(task_id)` is not `local` (`terminal_backend`) or cannot be
   read (`terminal_backend_unreadable`); the function reads the resolved backend and the backend tag of the
   environment Hermes cached for the task (a per-task `env_type` override does not select a backend at
   84a0301). Otherwise the call runs with no row.
3. `BLOCK_CRON`: refuse, `cron`.
4. `BLOCK_MCP_URL`: refuse, `mcp_url`.
5. `DELEGATE`: run (`delegation_default`) when `gate_tools_calls.py:default_delegation_ok` accepts the
   call, else refuse (`delegation_route`). A child on the default in-process backend inherits the locked
   profile and is allowed. Argument keys must be in `DELEGATE_TOP_LEVEL_KEYS` (goal, context, tasks,
   max_iterations, role, background, output_schema, images, action, subagent_id, message) and, per task,
   in `DELEGATE_TASK_KEYS` (goal, context, output_schema, images, group, role), matched exactly; any other
   key, a `tasks` value that is not a list of dicts, or tasks passed as a JSON string, counts as a route
   and is refused. Config keys in `DELEGATION_CONFIG_ROUTE_KEYS` (profile, command, args, provider,
   base_url, fallback_providers, request_overrides, acp_command, acp_args; normalised with strip and
   casefold) must be empty and `backend` must be None, "" or `default`. The agent's pinned backend is
   invisible to the hook.
6. `ASK`, in order: an `allow` addition runs (`allowlist`), also under a bypass; a bypass refuses
   (`bypass_active`); under `once_per_lock` a lock grant for this conversation runs (`lock_grant`);
   otherwise the call goes to Hermes' approval, with decision `remembered` when Hermes holds a grant under
   the current rule key (Hermes honours the grant without a prompt and the middleware writes
   `tool_allowed` with decision `remembered`), else `ask`.

**Bypass** (`gate_tools_hermes.py:hermes_bypass_active`). Any of yolo (`_yolo_active()`),
`approvals.mode: off`, or no person present (none of the CLI, gateway or ask presences: one-shot runs,
cron, unattended platforms) turns an ask into a block. Any error reading them blocks; the three Hermes
readers are resolved before any is read (`hermes_compat.approval_state_functions`), so a missing one
reads as unattended. The refusal text (`bypass_text`) depends on `hermes_bypass_is_interactive()`: with a
person present it is "blocked because approvals are bypassed (yolo or approvals off); turn the bypass off
to be asked, or run: hermes confidential allow <tool> (in chat: /confidential allow <tool>)"; in an
unattended run it is "blocked by confidential mode in an unattended run; to allow it, run: hermes
confidential allow <tool>, or run interactively to be asked (approvals are bypassed in an unattended run:
nobody can be asked)". The hook-thread versus agent-thread timing window for a yolo toggle is accepted.

**Rule keys.** The gate asks Hermes under a rule key of its own. `gate_tools_hermes.py:rule_key_for(tool,
generation)` is `confidential-mode:tool:<tool>` before any revoke and
`confidential-mode:tool@<generation>:<tool>` after one; Hermes stores a remembered grant under
`plugin_rule:` plus the rule key (`PATTERN_KEY_PREFIX` `plugin_rule:confidential-mode:tool:`).
`parse_pattern_key` reads both forms. The generation is the first 12 hex digits of the SHA-256 of the id
of the latest revocation record naming the tool or `*` (see "Revoke"). Only a grant under the current
key counts (`Runtime.remembered`), and a grant under any other key, a bare `web_search` "always"
included, never applies. `Runtime.rule_key` and `Runtime.remembered` feed both lines
(`build_pre_tool_call` and `build_tool_execution` take `rule_key=`).

**Ask mode** (`confidential.tools.ask`, read at each decision by `gate_tools_grants.py:ask_mode_from`
through `Runtime.tool_ask_mode`): `once_per_lock` (the default, also when absent) or `each_call`; any
other value is `each_call`.

**Lock grants** (`gate_tools_grants.py:LockGrants`). Under `once_per_lock` an exact `once` answer makes a
grant keyed by (lock id, conversation, tool), with the id of the ledger row that recorded the answer.
The conversation comes from `gate_tools_grants.py:grant_scope(session_id)`: Hermes' approval session key
(`hermes_compat.current_session_key`) and the agent's session id, so a grant is never wider than Hermes'
`session` answer; another chat, user or subagent asks again. A scope with both parts empty stores and
matches nothing, so that caller asks on every call. A grant for another lock id is dropped on the next
grant and never matches, so a grant ends at unlock; a revoke drops it (`revoke.py:_drop_lock_grants`, and the
watcher for a revoke from another process); it lives in the process that asked. `session` and `always`
keep Hermes' meaning. A lock grant never applies where Hermes would not ask a person, because the bypass
is checked first. Builders without `lock_grants` keep the per-call behaviour.

### The hook, the middleware and the observer

- **Hook.** On a refusal it returns a block with the refusal text and writes `tool_refused`. On an ask it
  writes `tool_asked` (decision `ask`) before the prompt is shown and returns `{"action": "approve",
  "message": gate_tools_calls.ask_message(...), "rule_key": <current rule key>}`; for a `remembered`
  decision it returns the directive without a row. Any exception in the hook, a failed `tool_asked`
  append included, blocks ("tool gate error"). When the call's
  tool_call_id is empty the hook returns None (no prompt) and the middleware asks.
- **Ask text.** `ask_message` is "Confidential mode: <tool> wants to send <size> of this conversation off
  the machine", where the size (`call_bytes`, `size_text`) counts the arguments plus the bytes of local
  image files the call names, in MB above 1 MB; under `once_per_lock` it adds "; allowing once covers
  <tool> in this conversation until this profile is unlocked". The row's `bytes` column is the arguments'
  size and `detail.kb` the size with images.
- **Observer.** `post_approval_response` classifies the answer, writes its row first (`tool_allowed` for
  `once`, `session` or `always`; `tool_refused` with the answer for `deny`, `timeout`, `cancelled`,
  `notify_failed`, `smart_deny` and `smart_approve`; `unexpected_choice` for anything else), then records
  the choice in `ApprovalDecisions.record(..., ledgered=, row_id=)`. A failed write logs a warning and
  records `ledgered=False`, and the middleware then writes the row itself, so each decision has one row.
  An answer that arrives with an empty tool_call_id is keyed on the middleware's ask in progress on that
  thread (`ApprovalDecisions.asking`, `current_ask`); decisions recorded under an empty id are otherwise
  never consumed.
- **Middleware.** It calls `next_call` only when the policy runs the call or `post_approval_response`
  recorded exactly `once`, `session` or `always` for this tool_call_id. For an ask whose hook did not ask
  (empty tool_call_id, or a hook that did not run) it asks Hermes itself through
  `gate_tools_hermes.py:hermes_request_approval`, with a fresh approval id and the name "confidential mode:
  off-host tool <tool>", so each call gets one prompt and no answer is shared. It writes `tool_asked`
  (with `approval_id`) first and refuses when that append fails (`gate_error`). Any other answer is
  refused: `denied`, `no_surface`, or `unexpected_choice`. A run on a lock grant writes `tool_allowed`
  with decision `lock_grant` and detail `grant_row`. A tool whose answer row was lost still runs: the ask
  row bounds a later revoke's check, and refusing an approved call would leave Hermes' approval in place.
  The refusal is returned as a tool-result string. The pre_tool_call directive cannot set the prompt's
  name, and no plugin can set the "Dangerous Command" title Hermes gives every plugin approval.
- `hermes_request_approval` resolves `hermes_compat.request_tool_approval_functions()` before it sets
  Hermes' observability context, so a Hermes without the reset function asks nobody and leaves no plugin
  id bound for Hermes' later approvals.

**Answers in the ledger.** Rows store a classification of an approval answer, never free text: Hermes'
fixed answers (`once`, `session`, `always`, `deny`, `timeout`, `cancelled`, `notify_failed`,
`smart_approve`, `smart_deny`), "" and None verbatim, any other string as `other`, any other value as its
type name. A secret typed at the prompt by mistake therefore never reaches the ledger.

**Decision strings.** `tool_refused`: `lock_state_unreadable`, `unclassified`, `cron`, `mcp_url`,
`delegation_route`, `bypass_active`, `self_approval`, `terminal_backend`, `terminal_backend_unreadable`,
`gate_error`, `denied`, `no_surface`, `unexpected_choice`, and the refused answers above. `tool_allowed`:
`once`, `session`, `always`, `remembered`, `lock_grant`, `allowlist`, `delegation_default`.
`tool_asked`: `ask`.

### Self-approval guard

An agent with a terminal can try to approve its own pin or grant. The guard, and its limits:

- **Tool-process marker** (`selfapproval.py`). `TOOL_PROCESS_ENV = "XDG_CONFIDENTIAL_MODE_TOOL_PROCESS"`
  holds the id of the process whose tool hooks set it (`os.environ.setdefault`, by `mark_tool_process`).
  Hermes 84a0301 marks child processes only with `AI_AGENT` and `HERMES_AGENT`, which
  `hermes_cli.main._advertise_agent_env` also sets in a `hermes` command a person types, so neither tells
  the two apart. The `XDG_` prefix is on Hermes' execute_code allowlist (`tools/code_execution_env.py`
  `_SAFE_ENV_PREFIXES`), so terminal, process_manage and execute_code children all inherit the marker.
  `self_approval_reason(environ=None, pid=None)` refuses when the marker names another process.
  `consent.approve_pending_pin`, `consent.allow_tool` and `commands_common.py:TerminalAsker` check it
  before asking, for every asker; a refusal raises `consent.SelfApprovalRefused` before anything is
  written or read, writes `pin_denied` or `tool_refused` with decision `self_approval`, and replies with
  `consent.SELF_APPROVAL_REPLY`.
- **Argument scan.** While locked, `_Policy.on_host_decision` refuses a call of a tool in
  `SELF_APPROVAL_TOOLS` (`terminal`, `process_manage`, `execute_code`) when
  `gate_tools_calls.py:invokes_confidential_cli(args, tool)` names a reason, and a call of a tool in
  `STATE_FILE_TOOLS` (`write_file`, `patch`) when `names_state_file(args)` finds a target path (`path`,
  V4A file lines) that is a state file or inside the plugin's data directory; both write `tool_refused`
  with decision `self_approval` at both enforcement points. The scan runs only on the `ON_HOST` route, so
  a plugin-origin tool with one of these names takes `ASK` and is not scanned. Terminal strings are read
  as shell, execute_code strings as Python, process_manage strings as both (`selfscan.py:shell_reason`,
  `python_reason`).
- **Shell forms** (`selfscan.py`). Line continuations are joined, `$'...'` is expanded, `$(...)`,
  backticks, `<(...)` and `>(...)` are scanned and replaced by a placeholder word, heredocs are cut out,
  and the text is `shlex`-split into simple commands. Refused: a `hermes` word (or `python -m
  hermes_cli[.main]`, `-m runpy hermes_cli.main`) anywhere in a non-text command with a later whole-word
  `confidential` or `/confidential...`; xargs or parallel feeding hermes; `X confidential <verb>` (verbs
  in `selfscan.CLI_VERBS`) unless X is a text tool or in `OTHER_PROGRAMS`; a typed `/confidential` line;
  Python run with `-c` and its argv, `-m confidential_mode...`, a script that exists or that an earlier
  command of the call writes, a heredoc, a here-string, a pipe or `cat FILE |`; `perl`, `ruby` or `node -e`
  code naming hermes then confidential; the forms inside `bash -c`/`-lc`, `eval`, `at`, a shell reading a
  pipe, a heredoc or a written script; and writes to a state file or the data directory (redirections,
  `tee`, copy destinations and `-t`, `key=value` values, sed and awk `w`, and any word of a command that
  is not read-only: text tools, `jq`, `yq`, `sqlite3 -readonly`, sed and perl without `-i`, read-only git
  subcommands). The token `confidential_mode` refuses.
- **Python forms.** Imports of `confidential_mode` outside strings and comments, dynamic imports naming
  it, `hermes_cli` imported or run with a literal `confidential`; when the code starts processes, the
  literal shell forms; when the code writes, moves or deletes files (an `open` mode with w, a, x or +,
  `write_text`, `unlink`, `shutil`, a `sqlite3` connection not opened `mode=ro`, and similar), a literal
  naming a state file or the data directory. Code that only reads a state file passes.
- **State paths.** `selfscan.py:is_state_path`: basename `pins.yaml`, `ledger.sqlite`, `allowlist.yaml`,
  `allowlist.yaml.lock`, `grants_revoked.json` and `grants_revoked.json.lock` (and siblings), a glob that
  could match one, or `state.json` in a `plugin-data` segment; counted when relative, inside
  `plugin-data`, or inside the Hermes home outside this plugin's source tree. `in_plugin_data`: a
  `plugin-data` entry whose name contains `confidential` (or a glob), or the bare directory.
- **The claim, and no more.** While locked, the tool gate refuses tool calls whose literal text has one
  of these forms, and every approval prompt refuses in a process that carries another process's marker.
  An agent that unsets the marker, assembles the command at run time, or attaches through the gateway
  socket (whose slash commands the gateway runs itself, `cli.py:1275-1279`) can approve a pin; such an
  approval is recorded with its `approved_via`. `tests/hostile/test_selfscan_corpus.py` holds the corpus
  of hostile command forms. `review.BRIEF_RULES` tells a reviewer that every vendor string is data, never to run a
  confidential command, and to review in a fresh session.

## Attested providers

`provider.py` registers the two attested provider profiles and owns the verification cache. The
profiles are registered from `register(ctx)` through Hermes' `providers.register_provider(profile)`,
the documented way to add a model provider; Hermes' `PluginContext` has no provider registration call
at 84a0301, so `hermes plugins validate` reports the plugin as in-process only, and the preflight
refuses to lock under `plugins.isolation: host`.

**Profiles.** `provider.py:make_profile` takes `name`, `display_name`, `description`, `env_var` and
`supports_streaming`, and builds a Hermes `ProviderProfile` with `auth_type="api_key"`,
`classify_api_error = provider.classify_refusal`, a `get_model_context_length` override and a
`create_client(**kw)`. `provider.py:register_provider_profile` registers `attested-tinfoil` (key
`TINFOIL_API_KEY`, context length `confidential.tinfoil.context_length`, default 65536), and
`provider.py:register_near_profile` registers `attested-near` (key `NEAR_AI_API_KEY`, context length
`confidential.near.context_length`, default 65536) with the same verification cache, pins file and
ledger. The context-length override exists because returning an integer pre-empts Hermes'
context-window probes (`GET {base_url}/models` and `POST /api/show` with plain httpx and the API key at
agent build), which would otherwise reach the enclave host off the attested transport. Each profile's
`base_url` is the adapter's: `https://<host>/v1` once the host is resolved, and
`verify/tinfoil.py:PLACEHOLDER_BASE_URL` (`https://unresolved.attested-tinfoil.invalid/v1`) before;
`_sync_profile_base_url` copies the resolved value into the profile after each verification.
`attested-near` reports `supports_streaming` from `confidential.near.streaming` (default false), and
false while encrypting.

**create_client.** `create_client(**kw)` never raises and never returns None (either would let Hermes
build a plain client). It returns a `client.py:ConfidentialClient` when the cache accepts a fresh
verification, else a `client.py:RefusingClient` whose every request raises `ConfidentialRefused(reason)`:

- verification pending: when the verification does not finish within `confidential.verify_wait_seconds`
  (default 20; interactive commands pass `commands_common.py:INTERACTIVE_VERIFY_WAIT_SECONDS`, 60), the
  reason starts "verification pending" and the preflight reports `pending`;
- no key reaches the client: "vendor key unreadable: <ENV> is not set or not readable in this process";
- a pin mismatch, or a pin with no consent record;
- any exception: "attested client unavailable: <Type>".

`api_key_for(env_var)` reads the key through `agent.secret_scope.get_secret`.

**ConfidentialClient** sets `HERMES_SKIP_TRANSPORT_WRAP = HERMES_SKIP_ASYNC_WRAP = True`, builds a
sync `openai.OpenAI` on the adapter's non-closing `sync_http_view()` and one `openai.AsyncOpenAI` per
running event loop on `async_http_for_loop()`, imports the OpenAI SDK on first use, and sets
`max_retries` to 0 unless the caller sets it. `chat.completions.create` dispatches by whether the caller
is a coroutine, and is the only method with its own gate check; `__getattr__` exposes every other OpenAI
resource on the same transport. `close()` closes only the view. The guard that covers every method is
the adapter-level hold: every Tinfoil and NEAR view refuses to send while the adapter has no accepted
verification. The llm gate's `attested_ok` covers main calls in addition.

**RefusingClient** offers `chat.completions`, `models`, `embeddings` and `responses` (`create`, `list`,
`retrieve`, `parse`, `stream`), `with_options`, `is_closed`, `close` and `_client`, each request raising
`ConfidentialRefused`. Both clients take `on_refuse`; `provider._create_client` passes
`_refusal_recorder(profile, cache)`, which writes one `send_refused` row with stage `provider_gate` (NEAR
through `record_refusal`, Tinfoil through the entry's ledger sink), skipped inside the llm gate, which
writes its own row.

**Verification cache** (`provider.py:VerificationCache`). One entry per profile. `ensure()` returns an
accepted result while it is younger than `confidential.verify_ttl_seconds` (default 300), measured on
`time.monotonic()`, and otherwise verifies inline under the entry's `verify_lock`. Every verification it
runs writes `verify_ok`, `verify_fail` or `pin_staged` through the ledger passed to
`register_provider_profile(ledger=...)`, with the evidence attached to `verify_ok`. After a failure,
calls within `DEFAULT_FAILURE_BACKOFF_SECONDS` (10, not configurable) are refused with the failure's
reason (clipped to 300 characters by `_fail_reason`). On a result:

- the pins match (`PinStore.match`) and every matched entry has a consent record: the result is
  accepted and the adapter released;
- otherwise the result is staged (`VerificationCache._stage`): the adapter stays held, a `pin_staged`
  row is written when the identity's batch changes, and the call refuses with "enclave build changed;
  run /confidential pins approve". Fingerprints that are empty refuse with "attestation returned no
  usable fingerprints";
- the platform-only auto-apply (`provider._auto_apply`, only for `AUTO_APPLY_VENDORS = ("tinfoil",)` and
  only with `confidential.pins.auto_approve_platform_only: true`, default false) applies a change of the
  enclave fingerprint alone with `approved_by="policy"`.

`invalidate()` (unlock, an HTTP 421, a TLS pin mismatch), `unregister`, `clear`, a re-`register` and
`locking._clear_verification_cache()` drop the result and stop the background thread; a capture in
progress finishes and is discarded. `register` wires the adapter's `on_stale` to `invalidate` and
`on_close` to `stop_refresh`.

**attested_ok(provider)** returns an in-tier `Verdict` only when the entry holds a fresh accepted result
whose pins match and whose consent is recorded. Consent (`provider._consent_recorded`) requires, for
every matched pin entry, a `pin_applied` row with decision `approve` or `auto_platform_only` whose
fingerprints match the entry; absent, the verdict is "pin has no consent record". `_scan_consent` folds
`pin_applied` and `pin_retired` rows in id order, incrementally (`_Entry.consented`, `consent_scan_id`),
so a retirement in another process counts too; `provider.clear_consent_cache()` resets the fold. Rows
that name identity and role key on `(vendor, router_repo, cvm_role, code_fingerprint,
enclave_fingerprint)`; older rows count by fingerprints. A marked (truncated) `pin_applied` row grants
nothing, and a marked `pin_retired` row withdraws consent for every entry with its kept fingerprints,
or for every entry when they were not kept. In-process code can still forge a row; the receipts say so.

**A lost verify row.** A verification whose `verify_ok` row cannot be written is refused: `verify_fail`
with `REASON_VERIFY_ROW_LOST`, no cached result, `VerifyError`. A transient "database is locked" is
retried once after `LEDGER_RETRY_DELAY_SECONDS` (0.25). A result the cache adopts from the adapter
(`_adopt_adapter_result`, after a setup command verified directly) whose row is lost records the failure
without a `verify_fail` row and without raising; `ensure()` then refuses under the failure backoff. Any other ledger exception on a `verify_ok`
write (a full disk, a corrupt file, a row over the size cap) blocks attested sends, Tinfoil's included,
until the failure backoff expires and a re-verification writes its row.

**Background re-verification** (`provider.py:BackgroundRefresh`). One daemon thread per cache entry,
named `confidential-refresh-<provider>`, started by `ensure()` after an accepted result when
`background_allowed(e)`: the gate is true (`cache.active`, else the function given to
`set_background_gate(fn)`, which registration sets to "the persisted state reads locked on the attested
tier"; with neither, the thread never runs), the adapter is open and has both `prepare_verification` and
`commit_verification`, and `e.refresh_lead_seconds > 0` (`confidential.verify_refresh_lead_seconds`,
default 60, read by `provider.refresh_lead_from`; 0 or less turns the refresh off, a non-number gives the
default). It polls at most every `REFRESH_POLL_SECONDS` (5).

- `step()` ends the thread when not allowed, when there is no result, or when the result expired (the
  inline path takes over). It refreshes only when `ensure()` used the result recently
  (`_Entry.used_mono >= due - lead`); otherwise it waits to expiry. It waits out the failure backoff after
  its own failure; a staged result is not retried.
- `attempt()` takes `e.verify_lock` without blocking (`busy` when an inline verification runs) and holds
  it for the whole attempt; it calls `prepare_verification()` with neither `e.lock` nor the adapter lock
  held, then under `e.lock` discards the result when the entry was unlocked, invalidated or replaced
  during the capture. When the pins match and consent is recorded it calls
  `commit_verification(prepared, hold=False)` (a failure writes only `verify_fail`), writes `verify_ok`
  with `source: background` and `accepted: true`, and swaps the result in; a lost row holds the adapter,
  clears the entry's result and stops the thread. Otherwise it writes `verify_ok` with `accepted: false`
  and stages through `VerificationCache._stage(..., hold=False)` (no hold, no auto-apply). A failed
  capture writes `verify_fail` with `source: background`. Nothing an attempt does extends a
  verification's lifetime.

**classify_refusal.** The attested profiles set `ProviderProfile.classify_api_error`, which Hermes'
error classifier consults (`agent/error_classifier.py` `_profile_verdict`). It classifies only a NEAR
refusal (`verify/near_exchange.py:NearRefusal`, which carries `status_code` and a clipped `body` when the
gateway answered with an HTTP error): 429 is `rate_limit`, 503 and 529 are `overloaded`, other 5xx are
`server_error` (all retryable), and a 400 or 413 whose body says the context is too long is
`context_overflow` (`should_compress`). Every other NEAR refusal (421, other 4xx, non-200 replies,
withheld or undecryptable replies, refusals before sending) is `provider_policy_blocked` with
`retryable: False`. Nothing falls back. Any other error, a Tinfoil `VendorHTTPError` included, returns
None and Hermes' default classifier applies.

## Vendor adapter interface

[ADDING_A_VENDOR.md](ADDING_A_VENDOR.md) ("The adapter contract") lists every member an adapter
provides, with the contract of each; this section states the rules the rest of the plugin depends on.

- **Identity and host.** `vendor`, `enclave_host` (never touches the network), `base_url` and
  `resolve_enclave_host()`, which resolves the host once (config first, then vendor discovery) and is
  called from `verify()` or a setup command, never from `register(ctx)`.
- **Prepare and commit.** `prepare_verification() -> PreparedVerification` does the network capture and
  the checks and publishes nothing; it raises `VerifyError` (or `VendorHTTPError`) on any failure and
  never returns a partial result. `commit_verification(prepared, *, hold)` publishes the result (and any
  pool or key it carries) under the adapter lock; with `hold`, `held_reason` is set before the result is
  published; a closed adapter refuses a commit. `verify()` is
  `commit_verification(prepare_verification(), hold=<hold until accepted>)`.
- **Hold.** `hold(reason)`, `release()` and `held_reason`: a held transport refuses every send in every
  view before any request byte. The cache holds on a failure, a pin mismatch or a missing consent row,
  and releases once the pins match.
- **State.** `last_result`, `verified_mono`, `closed`, `close()`, and the hooks the cache sets:
  `event_sink` (a callable taking one row dict), `on_stale` and `on_close`.
- **mark_stale(reason) -> bool.** Holds the transport, clears `verified_mono` and calls `on_stale`, at
  most once per `reverify_backoff_seconds` (30 on both adapters); inside that window it returns False
  and changes nothing, so a TLS intermediary cannot force an attestation per turn.
- **Views.** `sync_http_view()` and `async_http_for_loop()` forward to the adapter's current pinned
  pool, never close that pool, refuse while held, and send only on connections pinned to the TLS key of
  the accepted result. `verify/near_transport.py:pinned_ssl_context(expected_spki, ...)` builds the SSL
  context: it keeps the chain and host-name checks and compares the peer's SPKI SHA-256 with
  `expected_spki()` right after the handshake (`wrap_socket` and `wrap_bio`), raising
  `verify/near_transport.py:TLSPinMismatch`; with no accepted fingerprint it refuses every connection.
  The expected key is read from the accepted result only, never from a value the vendor SDK stored before
  the plugin checked the build and the pins. The attestation fetch uses a separate unpinned pool, because
  the certificate that pool sees is what the evidence is checked against; attestation requests carry no
  API key.
- **Per-send records.** A transport that observes each exchange calls `sendctx.add_record(record)` with
  the fields of `gate_llm.py:SEND_RECORD_FIELDS`; the llm gate copies them into its `send_observed` row.
  An adapter writes through `event_sink` only the rows the cache cannot see (a verification the SDK runs
  on its own, a TLS pin failure, `send_signed`, `send_refused`, `notice`).

**Send context** (`sendctx.py`). `send_context(session_id, purpose, provider, model, tier,
refusals_ledgered_by)` binds who a send belongs to around `next_call`; `current()` reads it inside a
transport; `capture_records(bucket)` and `add_record(record)` carry per-exchange records to the gate;
`note_aux(request_id, session_id, tier)` and the relay context Hermes binds around each auxiliary call
(`agent/auxiliary_client.py` `_RELAY_AUX_CALL_CONTEXT`, read through `hermes_compat.relay_aux_call_context`)
give an auxiliary send its session, tier and purpose `aux:<task>`.

## Tinfoil adapter

`verify/tinfoil.py:TinfoilAdapter` runs on tinfoil SDK 0.14.2.

- **SecureClient.** One per profile:
  `SecureClient(enclave=<host>, repo=<router_repo>, measurement=None, transport="ehbp", user_cache_secret=<secret>)`,
  where the host comes from `confidential.tinfoil.enclave` or router discovery, the router repository is
  `tinfoilsh/confidential-model-router`, and the secret is read from or created at
  `<data_dir>/tinfoil_user_cache_secret` (never `~/.tinfoil`). Verification goes through the SDK's
  default path, never pinned-measurement mode. The SDK's on-disk caches are redirected into the plugin
  data directory (`verify/_sdkpatch.py:redirect_sdk_caches`: tinfoil's three cache-dir constants and
  `sigstore._internal.tuf._get_dirs`, for the process).
- **Locks.** `prepare_verification()` builds the new sync pool and the result under `_sdk_lock`, an
  RLock that also wraps `_guarded_verify`, so explicit, background and SDK key-rotation verifications
  read the SecureClient's document one at a time. No path holds the adapter lock and the SDK lock
  together: `_secure_client()` runs before the SDK lock; `_guarded_verify` writes its `silent_reattest`
  or `async_pool` row after releasing the SDK lock; `observe_key` takes its own `_obs_lock`;
  `_async_pool_for_running_loop` builds a missing pool outside the adapter lock and publishes it under the
  lock, closing an unpublished pool (on its own loop) when the adapter closed, the accepted build changed
  or another task published first. An SDK rotation re-verification on a send waits for a background
  capture in progress. A verification the SDK runs on its own (key rotation) writes `verify_ok` with
  `source: silent_reattest` or `async_pool` for the same build only; a changed fingerprint raises.
- **HTTP errors.** `prepare_verification` and `resolve_enclave_host` raise `VendorHTTPError` when
  `http_error_in(exc)` finds an HTTP error in the SDK exception's chain, naming the server that answered
  through `http_source`; router discovery reads "Tinfoil: router discovery unavailable (...)".
- **TLS pin per send.** The SDK's `ehbp` mode builds its inner httpx transports with plain WebPKI TLS
  (`tinfoil/client.py:728-736`, `:806`), so the plugin pins every EHBP pool. `pinned_context(sc)` is
  `near_transport.pinned_ssl_context(lambda: expected_tls_fp(sc), base=tls_base_context, binds="the
  verified Tinfoil report", source="Tinfoil")`, and `TinfoilAdapter.expected_tls_fp` reads only the
  accepted result's `tls_public_key_fp` (`self._accepted`, set by `commit_verification` and by a
  same-build re-verification), else None, which refuses every connection. `pin_pool(client, sc,
  is_async=...)` replaces the inner network transport of each EHBP layer in the chain (`_inner` links)
  with a pinned one marked `_confidential_mode_tls_pinned`, and raises `VerifyError` when any network
  transport in the chain is still unpinned; it runs on the sync pool after `make_secure_http_client` and
  on each async pool after `make_secure_async_http_client`. On the plugin's own SecureClient, the
  instance attributes `_build_ehbp_sync_transport` and `_build_ehbp_async_transport` (the builders the
  SDK's re-verifying transports call after a key rotation) return pinned transports; the SDK class is
  unchanged.
- **Pin failure.** A `TLSPinMismatch` anywhere in a view's exception chain makes `_pin_failure` write a
  `verify_fail` row through `event_sink` (purpose `tls_pin`, detail `reason_code: tls_pin_mismatch`,
  `reason`, `expected_tls_key_fp`, `path`, `reverify_requested`, `nothing_sent: true`) and call
  `mark_stale`.
- **TLS probe.** While `confidential.tinfoil.tls_probe` is on (default true), each verification opens
  its own bodiless `httpx.Client` without headers, pinned to the key of the report being verified
  (`PROBE_TIMEOUT_SECONDS`, 10). A `TLSPinMismatch` writes a `verify_fail` row (purpose `tls_pin`, detail
  `stage: verification`) and raises `VerifyError`, so the verification and the lock fail (the cache then
  writes its own `verify_fail` row for the same error); other probe failures stay observations in the
  evidence.
- **Plaintext error replies.** The pinned EHBP transports (`pinned_ehbp_sync_transport`,
  `pinned_ehbp_async_transport`, and the inner transports `pin_pool` rebuilds) put a guard
  (`verify/tinfoil.py:_PlaintextStatusGuard`, `_AsyncPlaintextStatusGuard`) between the EHBP layer and the
  pinned network transport. Without the guard, ehbp 0.4.2 (the version tinfoil 0.14.2 resolves) returns a
  plaintext non-2xx body as it is, and the openai client raises with the router's body in its message. A
  reply without an `Ehbp-Response-Nonce` header whose status is not 2xx (a 3xx, 4xx or 5xx, to a request
  with or without a body) raises `VendorHTTPError(vendor="Tinfoil", subject="Tinfoil router <host>",
  what="inference")`, where `<host>` is `request.url.host`, the host the pinned connection reached, with
  the next step from `inference_next_step(status, "TINFOIL_API_KEY")`; the body is closed unread and never
  quoted. Two replies pass through to the EHBP layer unread: a 2xx without a nonce, which EHBP refuses
  (`MissingResponseNonceError`), and a 422 `application/problem+json` reply (`KEY_CONFIG_MISMATCH_STATUS`,
  `PROBLEM_JSON_MEDIA_TYPE`), which EHBP turns into `KeyConfigMismatchError` when its type is the
  key-configuration problem, so the SDK's `_EHBPReVerifyingTransport` re-attests and retries once; a 422
  problem document of another type comes back from EHBP as a plaintext response and reaches the openai
  client. A bodiless request's plaintext 2xx passes through.
- **Per-send record.** `_observe_send` adds a record per exchange: `hpke_key_used` (the key the SDK's
  EHBP transport holds after the response, `hpke_key_source` `ehbp_transport`, else the SDK's current
  key, `sdk_state`), `response_decrypted` (for a stream the client closed at `[DONE]`, the view drains the
  rest of the body, at most `DRAIN_AFTER_DONE_BYTES`, 64 KiB, to decide; a stream closed earlier stays
  None with `stream_closed_before_eof`), `encrypted`, `tls_spki_sha256`, `tls_matches_report` and `usage`.
  Receipts compare every exchange's key with the covering verify row's HPKE key.
- **Token counts.** `verify/tinfoil.py:parse_usage_metrics(value)` reads the router's
  `X-Tinfoil-Usage-Metrics` header as untrusted JSON: at most 2048 characters, a JSON object, and only
  fields whose key matches `[a-z][a-z0-9_]{0,63}` and contains "token" and whose value is an integer from
  0 below 2**53 (booleans, floats, strings and nested values dropped; at most 16 fields, in header order).
  A value nested deeper than `USAGE_METRICS_MAX_NESTING` (64) levels, or anything the JSON parser rejects
  (a `RecursionError` included), gives None; the function never raises. `_observe_send` parses the header
  after the send record is written, in its own `try`, so a parser failure costs only the counts. httpx 0.28 does not surface HTTP/1.1 trailers, so a value sent
  only as a trailer is not seen.
- **Evidence.** The Tinfoil evidence's `trusted_root` is `{"sha256", "json_b64"}`: the Sigstore trust
  root's bytes are embedded and no local path is recorded; a copy is stored at
  `<data_dir>/trust-roots/<sha256>.json` (`store_trust_root`).
- **Capture windows.** `verify/_sdkpatch.py:overrides()` installs each wrapper when its window opens and
  restores the original attribute (only when the attribute is still the wrapper it installed) when the
  last open window for that attribute closes, across threads. The live windows are the SDK attestation
  (`_capture_hooks` around `type(sc).verify`) and, nested in it, `requests.Session.request` while
  `fetch_latest_release` runs (the SDK offers no seam to hand it a Session the plugin owns). Inside a
  window a wrapper is process-wide and inert for every thread but the thread that opened it.
  `_sdkpatch.installed_now()` lists the wrappers in place.

## NEAR adapter

NEAR AI Cloud (`https://cloud-api.near.ai/v1`, OpenAI-compatible) is the attested profile
`attested-near`. `verify/near.py:NearAdapter` and its sibling modules implement the documented
checks themselves (formats from docs.near.ai and the Intel Trust Authority EAT profile;
`verify/near_checks.py` cites each). `nearai-inference-sdk` is not a dependency: it is async-only, wraps
its own client rather than an httpx transport Hermes can use, and pulls aiohttp, anthropic, dcap-qvl,
eth-account, pyhpke and pynacl. Only ed25519 signers are supported (ecdsa needs Keccak-256 and key
recovery, which neither the standard library nor `cryptography` provides). The split modules
(`near_evidence`, `near_appraise`, `near_transport`, `near_exchange`, `near_send`) log under
`verify/near.py`'s logger (`<package>.verify.near`, where `<package>` is the name Hermes gave the
plugin), which Hermes routes to gateway.log.

**Settings** (`confidential.near.*`, read by `provider.py`):

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `https://cloud-api.near.ai/v1` | https, no query or fragment |
| `models` | `[]` | unioned with `model.default` (or `model.model`) and each `auxiliary.<task>.model` routed through `attested-near`; the pin identity with no models is `<host>#gateway-only` |
| `require_provider_tee` | true | anything but `false` is true |
| `require_tls_binding` | true | |
| `accepted_tcb_statuses` | `["UpToDate"]` | a non-list uses the default; non-string items are dropped |
| `signature_wait_seconds` | 5 | |
| `encrypt` | true | |
| `image_parts` | `disclose` | any value but `disclose` or `refuse` acts as `refuse` (`provider.image_parts_from`) |
| `streaming` | false | has effect only while `encrypt` is off |
| `context_length` | 65536 | |
| `reverify_backoff_seconds` | 30 | |

### Verification

`NearAdapter.prepare_verification()` uses one client nonce N per verification, takes the adapter lock
only for its counter and pool lookups (never across a request), and refuses on a closed adapter
(`_attest_pool()`). Attestation requests carry no API key. Every non-200 attestation GET raises
`VendorHTTPError` whose subject is the request's model, else `NEAR gateway <host>`; the Intel key-set
fetch raises it with the vendor "Intel Trust Authority".

- **Gateway report** (`include_tls_fingerprint=true`): the TDX quote verifies to the Intel SGX root
  through tinfoil 0.14.2's verifier (TCB collateral is not evaluated); report data = SHA-256(signing key ||
  raw TLS SPKI fingerprint) || N; MRCONFIGID (`0x01 || compose hash || 15 zero bytes`) matches the
  `app_compose`; the event log replays to RTMR3; and, while `require_tls_binding`, the TLS certificate
  seen on that connection has that SPKI fingerprint.
- **Intel Trust Authority gateway token**: a signature in `near_checks.JWT_ALGS` (PS384, RS256, PS256,
  RS384) against the JWKS fetched only from `portal.trustauthority.intel.com/certs` or the EU host
  (`ITA_JWKS_URLS`), whose x5c chain must end at a pinned root; `iss` one of the accepted issuers; `iat`
  and `exp` at capture time within `JWT_SKEW_SECONDS` (120); TDX, not debuggable, TCB status in
  `accepted_tcb_statuses`; `tdx.attester_runtime_data` names N and the gateway signing key; MRCONFIGID,
  MRTD and RTMR0-2 equal the gateway quote's. The model-provider tokens are recorded and their GPU verdict
  shown, but they carry the gateway's TDX claims, so they decide nothing.
- **Each model** (`provider=near`, `x-no-aliasing: true`): every candidate's quote verifies, report data
  = signing key zero-padded || N, MRCONFIGID and RTMR3 as above; at least one candidate. Model candidates
  need `signing_public_key == signing_address`, 32 bytes of lower-case hex
  (`check_report(require_signing_public_key=)`). `appraise` refuses a model whose verified candidates name
  different keys; equal keys are one signer. With `require_provider_tee`, an empty model list fails.
- **RTMR3 identity** (`near_checks.rtmr3_identity(report)`, evidence v2 only): `app_id`, `instance_id`,
  `os_image_hash` and `key_provider_info` from dstack's boot events `app-id`, `instance-id`,
  `os-image-hash` and `key-provider`. Each must occur exactly once in the imr-3 log, before the first
  `system-ready`, with event_type `0x08000001`; missing, repeated, late or mistyped fails, and so does an
  `info` value that differs. `kms_id` = SHA-256 of the hex-decoded key-provider `id`; a non-hex id fails.
- **Compose-manager attestation** (`near_checks.check_compose_manager(cm, *, nonce, model_quote,
  quote_verifier, model, app_compose)`, raising `CmCheckError(step, message)`; steps in `CM_CHECK_KEYS`):
  `cm_quote` (the same TDX verifier; not debug; its event log replays to its RTMR3), `cm_same_td` (MRTD
  and RTMR0-3 equal the model quote's), `cm_report_data` (quote report data = `actions_hash || nonce`;
  `nonce` equals the request nonce; `nonce_source == "client"`; an echoed `report_data` agrees),
  `cm_actions_hash` (`actions_hash` = SHA-256 of `json.dumps(actions, sort_keys=True,
  separators=(",", ":"))` with default `ensure_ascii`; no fallback), `cm_services` and `cm_image`. NEAR
  documents none of this; the construction is reverse-engineered from captures, and a change on NEAR's
  side fails the check closed. `appraise(..., require_compose_manager=True)` (the adapter passes
  `require_provider_tee`; replay reads `policy.require_provider_tee`): a model candidate without the
  block fails `cm_quote`; with the flag off the checks are n/a.
- **Deployment map** (`near_checks.deployment_map`, for `cm_services`): a non-empty log of known
  actions. `compose_up` sets `"<file>::<service>"` to `{file, service, commit (40 hex), file_sha256 (64
  hex), tag}`; `compose_down` removes; `compose_stage` and `docker_restart` change nothing;
  `compose_manager_started` records an image. An action with no services acts on the whole file,
  recorded as service `*` (and a `compose_up` with no services drops every earlier entry of that file). A
  service name must match `[A-Za-z0-9][A-Za-z0-9._-]{0,254}` (so no colon, no key collision); a `file` must
  match `[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*` with no `..` segment and at most 512 characters; an unknown
  action or a malformed field fails. The services component is the whole map: `services_sha256` =
  SHA-256 of its canonical JSON. `PROMPT_PATH_SERVICES` only orders the display (`services_first`).
- **cm_image** records the image the log's latest `compose_manager_started` names beside the
  `compose-manager` image the measured app_compose names. It is in `INFORMATIONAL_CHECKS` and never
  passes: "recorded (not a pass; the log is operator-reported, not verified): ...".
- **What the compose-manager check establishes**, and the strongest wording allowed anywhere: a TD of
  this instance reported this actions log for this nonce, the log's hash is bound in a hardware quote,
  and the per-service deployment map derived from the log is what the operator's own tooling reported.
  It does not establish that the inner compose is measured or that the reported services are the ones
  running.
- **Checks.** `near_appraise.CHECK_KEYS`: `schema`, `gateway_quote`, `gateway_tls_binding`, `ita_jwks`,
  `ita_gateway_token`, `model_quotes`, the six `CM_CHECK_KEYS`, `ita_model_tokens`, `fingerprints`.
  `INFORMATIONAL_CHECKS`: `ita_model_tokens`, `cm_image`.
- **Commit.** `commit_verification` re-checks the model signing keys: a re-verification whose model
  signing key differs from the accepted one is refused (`VerifyError`, "model signing key ... changed");
  a restart accepts it. The key is not pinned; the review bundle shows the verified signing address.

### Evidence

Schema `confidential-mode/near-evidence/v2` (`near_evidence.EVIDENCE_SCHEMA`; `EVIDENCE_SCHEMA_V1` is
`.../v1`; `EVIDENCE_SCHEMAS` holds both; `VERIFIER` names `near_checks/1`). Top-level fields:
`schema`, `vendor`, `base_url`, `enclave_host`, `platform` (`tdx`), `sdk_version`, `nonce`,
`signing_algo`, `models`, `captured_at` (asserted by the capturer), `captured_at_unix`, `gateway` and
`model_reports` (trimmed reports: signer, `request_nonce`, report data, the quote as a blob, imr-3
events, compose hash, instance ids, `os_image_hash`, `key_provider_info`, the NVIDIA payload SHA-256 and
size, and for model candidates `compose_manager: {blob, bytes}`), `blobs`, `blob_refs`, `ita`
(`gateway_token`, `model_tokens`, `jwks_url`), `jwks`, `jwks_url_fetched`, `tls_observation`,
`capture_complete`, `capture_missing` and `capture_errors` when any; the adapter adds `checks`,
`policy` (`require_tls_binding`, `require_provider_tee`, `accepted_tcb_statuses`), `claims` and `repo`.

- **Blobs.** Every app_compose, compose-manager block, `intel_quote_b64`, ITA token, per-CVM service map
  (`claims.cvms[].services`) and the full component list (`claims.components_full`) is a blob in `blobs`
  (id = SHA-256 of the UTF-8 text), referenced by compose hash, by `compose_manager.blob`, or as
  `{"$blob": id}` (`BLOB_REF`); `blob_refs` lists the ids. `appraise` drops a blob that does not hash to
  its id, so the check that needs it fails. The ledger stores blobs outside the row (see "Ledger").
- **Claims.** `code_fingerprint`, `enclave_fingerprint`, `release_tag` (None), `identity`,
  `tls_public_key_fp`, `hpke_public_key` (None), `gateway_signer`, `model_signers` (unique keys),
  `components` (condensed, without the `reported-other: ` lines; `near_appraise.condensed_components`),
  `tcb_status`, `cvms` and `components_full`. Each `claims.cvms` item (and `Appraisal.cvms`) records, per
  CVM, role, `app_id`, `instance_id`, `compose_hash`, `signing_address`, `os_image_hash`, `kms_id`,
  `measurement`, and for models `services`, `services_sha256`, `services_first`, `services_scope`,
  `cm_image_reported` and `cm_image_measured` (None for the gateway).
- **Component lines** hold raw values and full digests: one identity line per CVM; `reported: ` lines
  (the map summary, the `services_first` services, the two images); `reported-other: ` lines (every
  other service).
- **v1 evidence** appraises under v1 rules: `app_composes` inline, no RTMR3 identity binding, the six
  compose-manager checks `near.CM_NOT_RUN_V1`, fingerprints as v1 defined them.

**Whole-result fingerprints** (the `VerificationResult` fields, the "Whole-result" prompt line and the
consent key). `code_fingerprint` = SHA-256 of the canonical JSON `{"gateway": [compose hash], "models":
{M: [sorted compose hashes of every verified candidate]}, "identity": {"gateway":
["app_id:os_image_hash:kms_id"], "models": {M: [sorted such strings]}}}`; `enclave_fingerprint` = SHA-256
of the canonical JSON `{"gateway": [MRTD:RTMR0:RTMR1:RTMR2], "models": {M: sorted unique measurements}}`.
RTMR3 and the signing keys are checked on every verification and left out, because they differ per
instance. NEAR pins compare per-CVM entries, not these values (see "Pins file"). The pin identity
(`router_repo`) is `<host>#<model,model,...>`, the gateway host and the sorted model list, for example
`cloud-api.near.ai#Qwen/Qwen3.8-27B`; changing the model list is a new identity and needs a new pin.
NEAR serves one model from several instances whose composes can differ, so the code fingerprint can
change between verifications; that is a pin prompt, by design.

### Sends

The send views are `verify/near_send.py:_SyncView` and `_AsyncView` (`default_send_transport()`,
`default_async_transport()`; `send_transport_factory` replaces them in tests). Each request is checked,
sent on the pinned pool as an exchange (`verify/near_exchange.py:_Exchange`), and hashed as it streams.

- **What may be sent.** Signable POSTs are those to `SIGNABLE_SUFFIXES` (`/chat/completions`,
  `/responses`), sent with `x-no-aliasing: true` and `accept-encoding: identity`; with
  `require_provider_tee` a model off the list is refused before sending. GET, HEAD and OPTIONS pass only
  without a body. While `encrypt` or `require_provider_tee` is on, every other request is refused. While
  encrypting, the only POST is `/chat/completions`.
- **Exchange.** `begin_exchange` records, under the adapter lock, the accepted verification, the pinned
  TLS fingerprint (`prepared_spki`) and the request model's key (`prepared_key`). `_check_current(ex)`,
  under the lock together with the pool choice, refuses when the transport is held and, when the accepted
  verification was replaced since, only when the fingerprint or that key differs; otherwise the exchange
  proceeds with its prepared values.
- **Hashing and the signature.** The view hashes the exact request body and the response body as
  received (after any content decoding; for SSE every byte including `data:` framing, blank lines and
  `[DONE]`; after the OpenAI SDK stops at `[DONE]` the view drains the rest of the body before hashing). When the body
  ends it fetches `GET /v1/signature/<id>?signing_algo=ed25519` with the request's own Authorization
  header, retrying 404 for at most `signature_wait_seconds`. An interrupted body gets no fetch and a row
  saying so. Without encryption NEAR's gateway re-signs streamed completions with its own key, which is
  why `attested-near` does not stream by default.
- **TLS pin.** Inference and signature connections use pools whose SSL context
  (`near_transport.pinned_ssl_context`) checks the peer SPKI SHA-256 against `pinned_spki()` right after
  the handshake; attestation GETs keep an unpinned pool. A send whose certificate differs, or cannot be
  read while `require_tls_binding`, is unverified and not fully attested. A TLS pin mismatch on a send
  holds the adapter, invalidates the cache entry (at most once per `reverify_backoff_seconds`) and drops
  the pooled connections. `mark_stale` and a new TLS fingerprint swap in a fresh send pool for new
  requests; the old pool is closed when its last in-flight request finishes.
- **Pools and loops.** `near_transport._aclose_on_loop` closes a pool with a task when its loop is the
  running one; from another thread it adds the (loop, pool) pair to `_async_closing` and schedules, with
  `call_soon_threadsafe`, a callback that creates the close task only when the loop runs it, so a loop
  closed first never holds an unawaited close coroutine. A loop already closed (or one that closes while
  scheduling) gets `_close_pool_sockets(pool)`, which closes the socket of each connection in httpx's pool
  directly. `_sweep_closed_loops` closes the sockets of a deferred pair whose loop has closed.
  `NearAdapter._prune_closed_loops` (run by `_drop_send_pools` and `_async_pool`) does that and drops
  pools of closed loops from `_async_transports` and `_retired_async` with their in-flight counts; it reads
  `_retired_async` from a copy and removes each closed-loop entry from the live list in place, so a
  finalizer's release during the prune can neither restore an entry nor drop a live one unclosed.
  `_AsyncReleasing` registers `weakref.finalize(self, release)`, so a body collected unclosed releases its
  pool.
- **Transport errors** (timeouts, resets) are not refusals: the SDK and Hermes may retry them, each
  attempt is a new exchange with a new client key, and each gets its own `send_signed` row. No status is
  synthesised.

**Encryption** (`verify/near_e2ee.py`, NEAR E2EE version 2, `ENCRYPTION_VERSION = 2`; PyNaCl
`pynacl==1.6.*`). `seal`, `open`, `encrypt_request`, `decrypt_response`, `available` and `ClientKey`;
`NearAdapter.encryption_ready()` and `model_public_key(model)`.

- The POST to `/chat/completions` is rebuilt as a new `httpx.Request` with the encrypted body, a fresh
  Content-Length, the original headers and extensions, and the E2EE headers with
  `X-Encrypt-All-Fields: true`.
- Refused before sending (`VerifyError`): `stream: true`, top-level keys outside `PLAINTEXT_KEYS` that
  carry text, `logprobs` and `top_logprobs` (allowed when None, false or 0), `logit_bias` and free-form
  `extra_body` entries (token ids could encode text), a top-level list or mapping outside the allowlists,
  and non-text content parts except image parts under `disclose`.
- `PLAINTEXT_KEYS`: model, stream, temperature, top_p, max_tokens, max_completion_tokens, n, seed,
  presence_penalty, frequency_penalty, response_format, stop, metadata, user. `STRUCTURED_KEYS` lets three
  settings leave as plaintext, each checked by shape: `reasoning` (only `enabled`, a bool; `effort`, null
  or one of `REASONING_EFFORTS` = none, minimal, low, medium, high, xhigh, max; `summary`, one of auto,
  concise, detailed, none; `max_tokens`, an int in 0..2^31-1; `exclude`, a bool), `stream_options` (only
  `include_usage`, a bool) and `reasoning_effort` (an effort word). Any other key, value type or word is
  refused. The row's `plaintext_keys` names every top-level key that left in plaintext, by name.
- **Image parts.** `encrypt_request(..., image_parts="disclose")`; `IMAGE_PARTS_MODES = ("disclose",
  "refuse")`, any other value acts as refuse. Part types are case-folded. `TEXT_PART_TYPES` (`text`,
  `input_text`) are sealed; a list of only text parts is flattened and sealed. Under `disclose`, a list
  holding an `image_url` or `input_image` part keeps its structure: text parts become `{"type": "text",
  "text": <sealed>}` (`cache_control` dropped and listed), and image parts leave in plaintext with only the
  keys `IMAGE_PART_KEYS` allows and a reference that is a raster `data:image/(png|jpeg|jpg|gif|webp|bmp|tiff);base64,`
  URI (case-insensitive), alone or as `{url, detail}` with detail low, high or auto. Any other part type
  (an `image` part included), a remote URL, an SVG, a missing reference or an extra field is refused
  with the type named. The report gains `plaintext_parts: {count, types}`, and
  `plaintext_parts_note(parts)` gives "N image part(s) left this host in plaintext to NEAR's gateway".
  Under `refuse` an image part is refused.
- **Release rule.** An unstreamed reply is buffered (at most `MAX_SEALED_BODY`, 32 MiB), hashed,
  completed and finished (signature fetch and verdict). Only one outcome hands a body over: HTTP 200, a
  `fully_attested` send, and a body that decrypts under the exchange's key; it is returned without
  `content-length` and `content-encoding`. Every other outcome (any other status, 2xx included; a missing
  or bent signature; a reply that does not decrypt) raises. HTTP 421 (the gateway no longer accepts the
  model key) also holds the adapter and invalidates the cache entry, at most once per
  `reverify_backoff_seconds`. A retry is a new encrypted exchange and never changes what is released.
- **Refused reply fields.** `decrypt_response` refuses a response that carries a key in
  `REFUSED_RESPONSE_KEYS` (`logprobs`, `nearai_tool_result`) at the top level, on a choice, on a message
  on a tool call or on a tool call's `function`. For `nearai_tool_result` the reason is "the response carries nearai_tool_result,
  whose encrypted format the plugin has not confirmed from a capture; refused".

**Refusals.** Every refusal the views raise is `verify/near_exchange.py:NearRefusal`, a `VerifyError` and
an `openai.OpenAIError`, so the OpenAI SDK re-raises it as is, without its own retries; it carries
`status_code` and a clipped `body` when the gateway answered with an HTTP error (see
`classify_refusal`). Each one, before sending (`begin_exchange`, `_encrypt`, a held adapter, a TLS pin
mismatch) or after receiving (`_release_sealed`: 421, non-200, withheld), gets one `send_refused` row
through `NearAdapter.record_refusal`: purpose from the send context (`main`, or `aux:<task>` from
Hermes' relay context), host, model, `bytes` when known, verdict and decision `refused`, and detail
`vendor`, `source: near_transport`, `reason_code` `near_refused_<stage>` (`before_send`, `after_receive`,
or `provider_gate` for the client's own refusal), `reason`, `stage`, `endpoint`, `status_code` when the
gateway answered, and `chat_id`. Inside the llm gate's guarded call the send context carries
`refusals_ledgered_by: llm_gate` and the adapter writes no row, so each refusal has one row. Each refusal
object is recorded once.

**The send_signed row** (one per exchange; verdict = `check.verdict`, decision = `check.kind`, or
`missing` when no signature was fetched). Detail: `vendor` (`near`), `source` (`near_signature`),
`chat_id`, `endpoint`, `stream`, `request_sha256`, `request_bytes`, `response_sha256`, `response_bytes`,
`response_status`, `response_content_encoding`, `body_complete`, `signature` (`status`, `reason`,
`signature_hex`, `signature_kind`, `signing_algo`, `signing_address`, `text`), `check` (`verdict`
verified or unverified, `kind`, `reason`, `expected_text`, `payload_match`, `signature_valid`,
`signer_match`, `signer_role`, `provider_tee_verified`, `tls_verified`), `require_provider_tee`,
`fully_attested`, `attestation_nonce` (ties the row to its evidence), `verify_code_fingerprint`,
`tls_spki_sha256`, `tls_matches_attested`, `near_e2ee` (NEAR's request encryption was applied; distinct
from Tinfoil's `encrypted` on `send_observed`), `e2ee_fields` (paths with `[]` for indices),
`e2ee_field_count`, `dropped_fields`, `plaintext_keys`, `plaintext_parts`, `plaintext_parts_note`,
`e2ee_version`, `client_pub`, `model_pub` and `hashing`; an encrypted exchange adds `reply_released` and
`withheld_reason` and is written once both the signature verdict and the release outcome are known. A
withheld reply is unverified and not fully attested even when its signature verified. A send that raised
before a response arrived gets a row whose reason says "TLS pin mismatch, nothing sent" or "transport
error (...)".

**Image notice.** `NearAdapter.on_plaintext_parts(context, row)` runs after a send with plaintext parts
(inside `finish_exchange`, before an encrypted row's release outcome is known; errors are logged). The
plugin's `__init__.py:_image_notice`, while locked and under `_notice_lock`, writes the first such send
of each lock (keyed by `locked_since`; an unreadable time never deduplicates) as a `notice` row (decision
`image_plaintext`, verdict `disclosed`, detail `notice`, `note`, `plaintext_parts`, `chat_id`,
`locked_since`, `reply_line`), and only after that row is written marks the lock and the session. The
`transform_llm_output` hook (fired by Hermes' `agent/turn_finalizer.apply_llm_output_transform` before
the reply is persisted; the first non-empty string wins) then returns the reply, a blank line and
`image_notice_line(plaintext_parts)` for the marked session, or the next reply when the send had no
session id: "Confidential mode: an image part (image_url) in this turn went to NEAR's gateway in
plaintext; the text around it was encrypted."

## Pins file

`pins.py:PinStore` keeps the approved builds in `pins.yaml`, version 3. Mutations hold an advisory
`pins.yaml.lock` (`filelock.exclusive`, through `PinStore._mutating`) and write through
`atomicwrite.write_atomic`; a lock still held raises `PinStoreError`.

```yaml
version: 3
identities:
  - vendor: near
    router_repo: "cloud-api.near.ai#Qwen/Qwen3.8-27B"
    concurrent: true          # from pins.VENDOR_POLICY, never read from the file
    verifications: 12
    approved: [<entry>, ...]
    pending: [<entry>, ...]
    pending_batch: {...}
    last_applied_key: "..."
```

**Entry** (`pins.py:PinEntry`, alias `PinRecord`): `vendor`, `router_repo`, `code_fingerprint`,
`enclave_fingerprint`, `release_tag`, `models_seen`, `approved_by` (`human` or `policy`), `approved_at`
(ISO UTC), `approved_via` (the surface), `approval_rule_key` (default `confidential-mode:pin`),
`previous`, `previous_enclave_fingerprint`, `platform`, `cvm_role` (default `router`), `components`,
`pinned`, `instance_ids_seen`, `reviewed_by`, `review_note`, `migrated_from`, `last_seen` and
`observed`. `observed` (`measurement`, `signing_address`, `compose_hash`, `services`,
`cm_image_measured`, `github_repo`, `tags`, `tags_missing`) is shown, never compared.

- **Vendor policy.** `pins.VENDOR_POLICY`: Tinfoil is not concurrent (approving replaces), NEAR is
  concurrent (approving adds).
- **Tinfoil:** one entry per result, `cvm_role: router`, fingerprints byte-identical to the result's,
  `components: null`.
- **NEAR:** one entry per CVM, `cvm_role` `gateway` or `model:<id>`. `components`: `app_id`, `compose`
  (compose hash), `os_image`, `kms_id`, and for a model `services` (services_sha256) and
  `cm_image_running` (the image the log reports). `pinned` names the components the code fingerprint
  covers; the entry's `code_fingerprint` = SHA-256 of the canonical JSON `{"cvm_role", "components": {name:
  value for name in pinned}}` and its `enclave_fingerprint` = SHA-256 of that CVM's
  `"MRTD:RTMR0:RTMR1:RTMR2"` string. A gateway entry must pin `app_id`, `compose`, `os_image` and `kms_id`
  (`NEAR_GATEWAY_REQUIRED`) and must not pin `services`; a model entry must also pin `cm_image_running`; an
  entry that pins less, or names a component outside `NEAR_COMPONENTS`, never matches. `services` is
  pinned only when `review.map_tags` can tag every service from cached, hash-checked inner compose texts;
  `PinStore.apply` refuses a NEAR model entry whose `pinned` lacks `services`, and a CVM with no map pins
  the absence (value None). The views come from `claims.cvms` (`pins.views_from_cvms`, with the service
  map from its blob).
- **Match** (`PinStore.matching_entries`, `pins.set_match`): every CVM of the result has an approved entry
  of its role with equal fingerprints; a Tinfoil result matches a `router` entry with the whole result's
  fingerprints. A NEAR record migrated from version 2 (`cvm_role: result`) matches nothing, so NEAR asks
  once and approving removes the record. `match()` never raises.
- **Stage.** `stage(result)` records the CVMs no approved entry covers as the identity's pending batch
  (`PendingPin`, a frozen dataclass with value equality, with `entries` and `components`, one line per
  measured component for the prompt). NEAR evidence without per-CVM measurements cannot be staged, and
  empty fingerprints are refused. `PendingPin.consent_key` covers identity, release, host, the whole
  result's fingerprints and each entry's role, fingerprints and pinned names. A re-stage with the same
  consent key keeps the batch and its staging time and refreshes its shown-for-review lines; consent and
  `apply()` compare consent keys, not whole objects. `refresh_pending()` recomputes the pinned names after
  `pins review` cached texts. `PinStore.prefetch_composes(fetch=None)` fetches every file the pending
  entries name, then refreshes; the provider runs it on a coalesced background thread after staging and
  writes a `pin_staged` row when the batch's consent key changes. `PinStore.pending_for(vendor,
  router_repo)` returns one identity's batch, and the provider compares a stage against that batch, so
  `pin_staged` is written only when that batch changes.
- **Apply.** `apply(pending, *, approved_via, approval_rule_key, approved_by, approved_at, reviewed_by,
  review_note)` is atomic and idempotent per pending batch; `approved_by="policy"` on a concurrent vendor
  raises `PinStoreError`. Only `consent.py` and the platform-only policy call it.
- **Other calls.** `retire(fingerprint, router_repo=None)` removes one approved entry by a unique prefix
  (8 or more hex digits) of its code or enclave fingerprint. `observe(result)` counts a verification and
  marks the entries it covers as seen, on a coalesced background thread outside the provider's entry
  lock; the prompt flags entries not seen in `UNSEEN_VERIFICATIONS` (20). `approved_set()`,
  `approved_entries()`, `pending_all()`; `load()` returns the latest approved entry per identity and the
  latest pending batch; `pending()` returns the pending batch or None.
- **Version 2 files.** A version-2 file reads as version 3 in memory; the first save copies it to
  `pins.yaml.v2.bak`. A file that says version 2 but holds `identities` is refused, so a version-3 file
  edited to version 2 matches nothing; any other version matches nothing and is never overwritten.

## Consent

`consent.py` takes a person's consent outside a turn through `ctx.ask_choice` only (in a terminal,
`commands_common.py:TerminalAsker` stands in). Both entry points are sync, raise `ConsentContextError` only
on an event loop, and record every answer. An answer must match the choice value exactly; `None` or any
other value is a denial. `raw_pick` in a row follows the answer classification of "Answers in the
ledger", with the choices `approve` and `deny`.

**approve_pending_pin**(ctx, store, ledger, *, session_key, session_id, platform, reviewed_by=None,
review_note=None) returns a reply string. It checks the self-approval marker first, runs
`PinStore.prefetch_composes` before asking, and goes through `pending_all()` oldest first, one reply line
per batch. A batch with an unpinned service map is not asked (`pin_denied`, decision
`services_unpinned`). Under a lock held around the re-check and the apply, it applies a batch only on an
exact `approve` and only when the pending batch's consent key still equals the consent key asked about; a
re-staged pin with the same fingerprints but a different release tag is a swap and is not applied.
Concurrent approvals for one batch apply exactly once. It writes one `pin_applied` row per entry (the
entry's fingerprints, `vendor`, `router_repo`, `cvm_role`, `pinned`, `approved_via`, `reviewed_by`,
`session_key`, `raw_pick`, `approved_at`, `entry: "n/m"` and the batch fingerprints), or `pin_denied`
with the answer; `store.apply` raising is ledgered as `pin_denied` with the error type. A denial with no
approved entry for the batch's vendor and identity says "no pin approved yet; nothing changed", else
"current pin kept".

**The pin prompt** (`consent.pin_question`). Tinfoil shows the release and both fingerprints. NEAR
(`consent._near_pin_question`) shows `PINNED_HEADING` and the pinned lines, `REPORTED_HEADING` and the
reported lines (other services folded into their count above `MAX_REPORTED_LINES`), and
`REPORTED_NOT_PINNED`. When a component line or entry names an "abliterated" service (case-insensitive),
the prompt adds `consent.NEAR_ABLITERATED_NOTE`: the compose-manager log reports services named
"...-abliterated" in the same enclave as the base model; services in one enclave share the enclave and
its quote socket, and the plugin lists them for that reason. The prompt claims nothing about which
service answers a request.

**allow_tool**(ctx, allowlist, ledger, name, *, session_key="", session_id="", platform="") adds an ASK
tool to `allowlist.yaml` for the rest of the lock. It checks the self-approval marker, refuses an
unregistered name or a hard block without asking, and asks. An exact `approve` writes `tool_allowed`
(decision `allowlist_add`); any other answer writes `tool_refused` (decision `no_answer`, `deny`, `other`
or the answer's type name) and replies "<tool> was not added; <tool> still asks before it runs while
locked." When the allowlist write fails (an OSError, or `LockBusy`), the grant is not made: a `notice`
row with decision `grant_not_recorded` and detail `reason_code: grant_not_recorded`, `error_type`,
`errno` (for example `ENOSPC`), `file` (the basename, never the error text, which carries absolute paths)
and `note`, and the reply "<tool> was not added: the grant could not be recorded in allowlist.yaml
(<error type>), so <tool> will ask again each call." The tool stays ungranted in memory and on disk.

**Terminal answers** (`commands_common.py:TerminalAsker`, `TerminalAsker._pick`). In a terminal the asker
accepts the choice value, its number, and on a prompt whose choices include `approve` and `deny` also
`y`/`yes` (approve) and `n`/`no` (deny), case-insensitive. Anything else prints "Answer 1 or 2, y or n: "
and reads once more; a second miss, or end of input, returns None.

## Pin review bundle

`review.py` builds the bundle `hermes confidential pins review [--json] [--no-fetch]` prints (CLI only),
schema `confidential-mode/pin-review/v1` (`review.SCHEMA`; `review.BUNDLE_SCHEMA` is the JSON Schema
`review.validate` checks against). There is no Hermes tool for it.

- **Inner compose texts.** `review.compose_url(commit, file, repo)` accepts only a 40-hex commit and a
  plain repository path and builds `https://raw.githubusercontent.com/<repo>/<commit>/<file>`, where the
  repository is the repository the measured compose names in `GITHUB_REPO` (`review.repo_of_app_compose`,
  recorded as `observed.github_repo` and shown as `repository`); nothing is fetched without one.
  `fetch_compose` keeps the bytes (at most 4 MiB) only when their SHA-256 equals the log's `file_sha256`,
  and caches them as `<data_dir>/pins/composes/<sha256>.yaml`; commit metadata from `api.github.com` is
  cached as `pins/composes/commit-<sha>.json`. A failure leaves `status: "text not fetched"` with the link
  and the reason. A hash-matching fetch does not establish the commit's membership in that repository.
  `review.NO_FETCH_ENV` (`CONFIDENTIAL_MODE_NO_FETCH`) turns fetching off. `pins review` writes a
  `pin_staged` row when its refresh changes a batch.
- **Tags.** `review.service_tags(text)` parses with `hermes_yaml` (anchors and merge keys resolved) and
  tags, in `TAG_ORDER`: holds dstack.sock, holds docker.sock, mounts a run directory (every socket in it),
  privileged, adds capabilities: <caps>, maps host devices, network_mode: host, pid: host, ipc: host, runs
  as root, user not set (the image's default user, often root), built from dockerfile_inline, image not
  pinned by digest; and the pseudo-tag "not in its compose file".
- **Per pending entry:** components old and new (old from the latest approved entry of the same role),
  app_id and verified signing address old and new, the outer compose fields (`allowed_envs` with added and
  removed, `pre_launch_script`, `kms_enabled`, `gateway_enabled`, `local_key_provider_enabled`,
  `public_logs`, `no_instance_id`, `GITHUB_REPO`, `CM_MIN_TAG_AGE_HOURS`, images) and a unified diff of
  `docker_compose_file` (texts from the ledger's evidence blobs), the compose-manager image reported versus
  measured, the service map old and new, and each inner file with status, link, commit metadata, a
  unified diff from the approved entry's commit of the same file, the tags and `tags_status`. With no
  approved entry of the role, an entry carries `baseline: null`, `baseline_status: "none: ..."`, the
  measured app_compose as `outer_compose.full_text`, and per file path one `full_text` with every other
  commit as `diff_from_reference`. Tinfoil batches carry `release_url` and `compare_url`.
- **The brief.** `review.BRIEF_RULES`, `NEAR_QUESTIONS` (Q1 to Q8), `TINFOIL_QUESTIONS` (T1 to T4) and
  `OUTPUT_FORMAT` (one verdict per question with cited bundle line numbers or JSON pointers, then a
  recommendation). Text output numbers every line (`L0001`) and renders every interpolated value with
  `render_vendor`, and takes the rules, questions and format from the module, never from the bundle passed
  in; JSON output is `ensure_ascii`, so every non-ASCII character is a visible escape. With nothing pending
  the text form prints `review.NOTHING_PENDING_TEXT` and no brief; `--json` keeps the empty bundle.
- **Rendering vendor text** (`near_checks.render_vendor(line)`): escapes a backslash, every control
  character (C0, DEL, C1, line and paragraph separators, bidirectional and zero-width marks) and backticks
  as visible `\xNN` or `\uNNNN`, wraps the line in a code span, and tags a line that held a control
  character with `CONTROL_TAG`. Nothing is stripped or cut. `render_if_needed` applies it only to text
  with a control character or markdown-significant characters; the receipt text renderer
  (`receipts._p`), replay output and the bundle use it. Hashes, pins, the ledger and receipt JSON keep raw
  bytes.

## Revoke

`revoke.py:revoke(rt, tool)` serves `/confidential revoke <tool>`, `/confidential revoke --all`,
`hermes confidential revoke <tool>` and `hermes confidential revoke --all`. It removes the grants the
plugin is responsible for, and nothing else, and returns (status, message) with status `revoked`,
`nothing` or `failed`. It runs unlocked as well (it then touches only Hermes' grants), never asks anybody
and never consults the self-approval marker, because revoking only narrows. While locked, the tool gate's
self-approval scan still refuses a terminal, process or code tool whose text names `hermes
confidential`, so a revoke runs from a terminal the person opened or from chat.

- **What it removes.** The tool's name in `allowed` of `allowlist.yaml` when the file's `lock_id` is the
  current lock's; the tool's lock grants (`revoke.py:_drop_lock_grants`); and every `command_allowlist` entry
  in Hermes' config.yaml that `parse_pattern_key` reads as the plugin's (both key forms). `--all` removes
  every such key and every name in `allowed`. Any other `command_allowlist` entry is left alone and named
  in the reply.
- **config.yaml.** `revoke.remove_command_allowlist_grants` reads the user's file with
  `hermes_cli.config.read_raw_config` (no merged defaults, no `_config_version` stamp), drops only the
  plugin's entries, saves with `save_config` (which keeps comments and `${VAR}` references, and also
  normalises legacy model and `max_turns` keys) only when there is one, and confirms with `load_config`.
- **Hermes-held grants.** The plugin writes nothing into Hermes' approval tables. A revoke withdraws a
  Hermes-held `session` or `always` grant by moving the tool to a new rule key: it appends a revocation
  record, and the gate's generation for the tool changes (see "Rule keys"). Hermes' tables are read only,
  through `hermes_compat.approval_keys` (`commands_pins.py:hermes_approval_keys`).
- **Nothing to revoke.** `revoke.granted_since_last_revoke(ledger, tools)` reads `tool_asked` and
  `tool_allowed` rows (`Ledger.tool_rows(kinds, since_id)`, with `tail` as the fallback) after the latest
  key-moving revoke (`Ledger.last_key_moving_revoke(purposes)`: for one tool, the later of that tool's and
  the `*` revoke; for every tool, the `*` revoke; several named tools read from 0). Every grant made
  through the plugin's prompt follows a ledgered ask, so an answer row lost after the ask still counts.
  `revoke.hermes_holds_grant(rt, tools)` checks Hermes' session approvals (every session key) and
  permanent set for a `plugin_rule:` key equal to the gate's current rule key. When the revoke removed
  nothing, hit no error, the ledger shows no grant and Hermes holds none, the revoke returns `nothing`
  ("Nothing to revoke for <tool>: confidential mode has not granted <tool> since the last revoke (no allow,
  no prompt asked, no allowlist or command_allowlist entry). Nothing was recorded.", or "Nothing to revoke:
  confidential mode has granted no tool ..." for `--all`) and writes neither a record nor a row. An
  unreadable ledger, any ledgered answer, or an unreadable Hermes table records the revoke and moves the
  key.
- **Replies.** A revoke reply says what it removed, that the next call asks again while locked, that a
  `session` or `always` answer Hermes holds no longer applies because the plugin asks under a new approval
  key, and that a running gateway applies the revoke on its next tool call. A failed revoke starts
  "Revoke failed for", never claims the next call asks, and the CLI exits 1 (2 for a usage error).
  `failed` covers a config.yaml that did not change (a managed install, or `save_config` raising; the
  reply names the line to delete and says the entry no longer grants anything once the record was
  written), an allowlist.yaml or record write error, and a lock file that is held or unusable. When the
  record cannot be written the reply says "the running gateway applies the revoke on its next tool call;
  a grant Hermes itself holds for this session ends when the session ends or Hermes restarts".
- **Row.** `grant_revoked`: purpose `tool:<tool>` or `tool:*`, decision `revoke` or `revoke_all` (with a
  `_failed` suffix on failure), surface, and detail `{tool, lock_id, surface, removed: {allowlist,
  command_allowlist, lock_grants}, errors, rule_key_rotated}`.
- **Records** (`grants_revoked.json` beside `allowlist.yaml`): `{"version": 2, "records": [{id, ts,
  tools, seq}], "latest": {<tool or "*">: [seq, id]}}`, where `id` is a uuid4 hex, `tools` the sorted names
  or `["*"]` for `--all`, and `latest` is never truncated, so the generation survives the 200-record cap.
  Writes go through `write_atomic` under `revoke.file_lock` (`filelock.exclusive` on `<file>.lock`).
- **Other processes** (`revoke.RevocationWatcher`, one per Runtime). `baseline()` at registration marks
  the records present as applied. `apply()` runs at the start of `Runtime.allowlist()`, so before every
  gate decision, and on a file change drops the cached `added` names and the lock grants of each new
  record. `generation(tool)` re-reads the file when it changed and never goes back: a deleted or older file
  keeps the newest generation the process has seen, a replaced file whose sequence restarted still moves
  the key on its new record, and an unreadable file with nothing seen gives a generation of that process
  alone. A forged or corrupt record can only take grants away, and the watcher never raises.
- **Open gaps, stated in LIMITATIONS** ("Remembered `always` grants outlive the lock"): a `once` answer
  given after a key-moving revoke to a prompt shown before it, with its answer row lost, leaves a lock
  grant that a later nothing-recorded revoke does not end; and the nothing-recorded check reads the
  ledger while the key comes from `grants_revoked.json`, so a deleted or reset file lets a process that
  starts afterwards ask under the original key.

## Ledger

`ledger.py:Ledger` is an append-only SQLite file, `ledger.sqlite`, in Hermes' plugin storage for the
plugin. The default ledger opens through Hermes' `plugin_db`, which applies WAL where SQLite allows it
(Hermes keeps DELETE on network filesystems); `Ledger(path)` and an injected `connect` keep their mode
(DELETE unless the caller sets one) and connect with a 5-second timeout. `Ledger.journal_mode` reports
the mode in force. No row ever stores prompt or reply text: only sizes, hosts, hashes, verdicts and
decisions.

```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, session_id TEXT, kind TEXT NOT NULL, purpose TEXT,
    provider TEXT, host TEXT, model TEXT, bytes INTEGER NULL, tier TEXT NULL, verdict TEXT NULL,
    decision TEXT NULL, surface TEXT NULL, detail TEXT       -- detail is JSON
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, id);
```

**Reads.** `append(event) -> int` (the row id), `tail(since_id=0, limit=1000)`, `session(session_id)`,
`last_id_before(kind, before_id)`, `tool_rows(kinds, since_id=0, limit=1000)` (an SQL filter on kind and
a `tool:` purpose), `last_key_moving_revoke(purposes)` (the id of the latest `grant_revoked` row for one
of the purposes whose detail has `rule_key_rotated`, read newest first, or 0), `blob(id)`,
`referenced_blobs()`, `gc_blobs()` and `journal_mode`. The schema has no version step.

**Row kinds** (`ledger.KINDS`):

| Kind | Written by | Purpose, decision and detail |
|---|---|---|
| `send_observed` | `pre_api_request` (decision `attempt`), the llm gate (`observed` unlocked, `allowed` in tier), the auxiliary hooks (`observed`) | `bytes` request size; detail `source`, `api_request_id`, the send record fields, `started_ts`, `verify_before`, `response_bytes`, `reason` |
| `send_refused` | the llm gate, the turn check, the NEAR adapter, the provider gate | detail `reason_code`, `reason`, `error_type`, `status_code`, `stage` |
| `send_signed` | the NEAR adapter, one per exchange | see "The send_signed row" |
| `verify_ok` | the verification cache, an SDK-run verification | detail `vendor`, fingerprints, `release_tag`, `enclave_host`, `verifier`, `evidence`, `source`, `accepted` |
| `verify_fail` | the cache, the TLS pin, setup | detail `reason`, `error`, `reason_code`, `source` |
| `pin_staged`, `pin_applied`, `pin_denied`, `pin_retired` | the cache, consent, `pins retire` | see "Pins file" and "Consent"; `pin_retired` detail `vendor, router_repo, cvm_role, code_fingerprint, enclave_fingerprint, retired_via` |
| `tool_asked`, `tool_allowed`, `tool_refused` | the tool gate, consent, the gateway command check | purpose `tool:<name>` or `command:<name>`; see "Decision strings" |
| `grant_revoked` | revoke | see "Revoke" |
| `lock`, `unlock` | `locking.lock`, `locking.unlock` | the tier, the fingerprint, the period's counts |
| `preflight_fail` | a refused lock, unlock or registration step | purpose `lock`, `lock:<step>`, `<lock or unlock>:busy`, `register:<step>` |
| `breach` | the auxiliary hooks (`aux_sent`), the turn check (`config_changed`, `live_runtime_off_tier`) | the off-tier destination |
| `compaction` | `post_compaction` | `old_session_id`, `reason`, token counts |
| `session_start`, `session_end` | the session hooks while locked | session markers; never a lock |
| `notice` | the image notice (`image_plaintext`), a failed allow (`grant_not_recorded`) | something the user is told without a refusal |

**Append rules.** `Ledger.append` accepts a `LedgerEvent` or a plain dict with the column names. It
refuses a kind outside `KINDS` and any detail key in `FORBIDDEN_DETAIL_KEYS` (`messages`, `prompt`,
`prompts`, `request`, `input`, `instructions`, `system`, `content`, `contents`), matched
case-insensitively, at any depth, inside blob JSON as well. Before the row is built it clips free text:
the `purpose` column (it carries the tool name) and the top-level detail keys in `FREE_TEXT_KEYS`
(`tool`, `reason`, `error`, `message`, `raw_pick`, `choice`) are cut to `MAX_CALLER_CHARS` (1024)
characters with the marker "...(clipped, <n> chars, sha256 <16 hex digits>)" (`ledger.clip_text`), so two
different long values stay distinct. Hashes, fingerprints, session ids, tool call ids, reason codes, the
other columns and verification evidence are never clipped. Evidence blobs are moved out of the row
(`externalize_evidence`), and a detail still over `MAX_DETAIL_BYTES` (256 KiB) is written with
`ledger.marker_detail`: its top-level fields that are numbers, booleans, None or strings of at most 512
characters, plus `detail_too_large: "detail too large: <n> bytes, truncated"`; when even those exceed the
cap the row is refused (`LedgerError`). A `verify_ok` row, or a row with `evidence`, over the cap raises.
`ledger.would_truncate` lets a caller warn first. Readers treat a marked row (`ledger.is_truncated`) as
unknown.

**Failed appends.** When the INSERT or the COMMIT raises, the connection's transaction is rolled back
before the exception propagates; when the rollback itself fails, the connection is closed and dropped and
the next append opens a new one. A row the caller was told was lost therefore never lands on a later
append. The blobs a failed append created are deleted only when the COMMIT did not return, so an
exception after a committed row never leaves the row listing deleted blobs.

**Evidence blobs** (`ledger.py:BlobStore`, `<data_dir>/evidence/blobs/<sha256>`, next to the ledger
file). Write-once: `put` writes through `write_atomic`, refuses more than `MAX_BLOB_BYTES` (8 MiB), and for
an intact blob that already exists touches its mtime and returns False; `get` returns None for a missing
blob or one whose bytes are not its id. `append` checks every blob (hash, forbidden-key scan) and the
stripped row's size first, then writes the blobs, then the row. A blob stays while any row lists it in
`blob_refs`; an unreferenced blob older than `BLOB_ORPHAN_SECONDS` (24 hours), and a `.*.tmp` file of that
age, is deleted at the first evidence write of each Ledger.

**File modes** (POSIX only). The ledger is created 0600 and re-chmoded with its SQLite side files when
opened; blobs are written 0600. The registration step `data_modes` chmods every file in both data
directories (`ledger.secure_data_files`, ledger directory first, at most 5000 files per directory) once
per installed commit (marker `modes-checked`) or when the ledger, `pins.yaml` or `allowlist.yaml` has
another mode. [ARCHITECTURE.md](ARCHITECTURE.md) ("Data files") lists every file.

**Trust.** The ledger is a file on this host, unprotected against code in the same process; any claim a
receipt makes from it is only as strong as the ledger's integrity, plus, for evidence, the attached bytes
replaying offline.

## Receipts

`receipts.py:build_receipt` renders one session's receipt from ledger rows; `render` prints text or JSON
(`--json`). The read starts at the last unlock before the session's first row
(`Ledger.last_id_before`), or at the first row when there is none, and ends at the lock or unlock that
closes the period; a verification row that a `send_signed` row in the window vouches by (its
`attestation_nonce`) and that lies before the window is pulled in (`Ledger.verification_by_nonce`), so the
receipt always carries the evidence its sends reference. Rows of `PROFILE_KINDS` (`lock`, `unlock`, `verify_ok`, `verify_fail`, `pin_staged`,
`pin_applied`, `pin_denied`, `pin_retired`, `preflight_fail`, `grant_revoked`) from other sessions are
included; a locked period opens only at a `lock` row, never at a session marker. Trust roots are taken
per locked period. `receipts <id>` with no ledger rows for the id is an error (exit 1).

**JSON form.** Top-level keys: `format` (`confidential-mode-receipt`), `version` (1), `header`,
`trust_roots`, `sections`, `rows`, `evidence` and `closing`; with NEAR sends also `near_closing`, and
`near_encryption_note` when a send was encrypted. The rows are hash-chained: `CHAIN_ALGORITHM`
`sha256(prev_hash + canonical_row_json)` from `CHAIN_GENESIS` (64 zeros); `header.chain_head` is the
last hash. `verify_chain` recomputes the chain, fails a receipt that holds an encrypted send without
`near_encryption_note`, checks `near_closing` when present, and fails an evidence item whose `blobs`
holds an id the evidence does not reference or bytes that are not their id.

- **Header:** `session_id`, `nature`, `chain_head`, `chain_head_note`, `plugin_version`,
  `plugin_commit`, `sdk_versions`, `verify_ttl_seconds`, `verify_ttl_source`, `policy_checker`, `gating`,
  `hpke_mismatches`, `locked_tier`, `locked_period` (`since`, `until`, `source`), `locked_periods`,
  `clock`, `providers`, `enclave_hosts`, `unverified_entries`, `row_count`, `chain_algorithm`,
  `chain_genesis`, `trust_roots_sha256`, and with NEAR sends `near` (`sends`, `fully_attested`,
  `not_fully_attested_sends`, `replay_failures`, `require_provider_tee`).
- **Sections:** `lock`, `verification`, `unverified_entries`, `sends`, `refusals`, `asks`,
  `allowed_without_prompt`, `breaches`, `compactions`, `notices`, `signed_sends`, `grants_revoked`,
  `send_pairs`, `usage_total`, `send_coverage`, `replay_status`, and `near_sends` with NEAR sends.
- **Evidence:** each `verify_ok` row's evidence, with `blobs` joined back for evidence that has
  `blob_refs` and `blobs_missing` when any is absent or altered. The receipt lists every approved pin
  entry, with `cvm_role` and `reviewed_by`.

**Rules.**

- **Coverage** (`_send_coverage`): a send is covered by the latest `verify_ok` row named by its
  `verify_before` and that row's TTL window from `started_ts`. A `verify_ok` row with `accepted: false` is
  skipped, and the text receipt prints it as `NOT ACCEPTED (the pins did not match this build; never
  used for a send)` with `source=background`. A marked `send_observed` row is never covered (entry
  `detail_lost: true`, text "NOT covered: the row's detail was too large ..."), and every marked row line
  shows "[detail lost: ...]". Receipts compare every exchange's HPKE key with the covering verify row's.
- **Unverified entries:** a `verify_ok` row whose evidence has `capture_complete: false`, or no evidence,
  is flagged "unverified entry" (`receipts.py:is_unverified_entry`).
- **Send pairs** (`receipts.send_pairs`): the `pre_api_request` row and the gate's row pair by
  `api_request_id`; the text form shows one line per send with request and response bytes (the response
  labelled "re-serialised JSON"), and folds a refused send's attempt into its refusal line. The ledger
  keeps both rows.
- **Token counts:** `receipts.usage_counts(detail)` reads a row's counts; each send line appends "tokens
  prompt_tokens=<n> completion_tokens=<n> total_tokens=<n> (router-reported)" (the usual keys first,
  others sorted); `usage_total` is `{"sends_with_counts", "sends", "counts", "source": "router-reported", "header":
  "X-Tinfoil-Usage-Metrics"}` summed over the session's
  `send_observed` rows, and the text prints "Tokens this session (router-reported,
  X-Tinfoil-Usage-Metrics): ... over <k> of <n> send(s)" after the Sends section when any row has counts.
- **NEAR sends:** `near_sends[]` carries per send the digests, signature kind, live verdict, replay
  verdict, `near_e2ee`, `e2ee_fields`, `e2ee_version`, `model_pub`, `plaintext_keys`, `plaintext_parts`,
  `plaintext_parts_note`, `reply_released` and `withheld_reason`, and the per-send text line prints the
  note. A marked signed-send row gets `detail_lost` and its replay fails.
- **Revokes and notices:** `grant_revoked` rows render under "Asks and answers" as `grant revoked`, with
  "new approval key" when the key moved; `notice` rows fill `notices`.
- **Closing.** `CLOSING_PARAGRAPH` states what the receipt proves and what it only records. EVIDENCE:
  the attached bytes that replay offline show that an enclave whose hardware report commits to TLS key T
  and HPKE key H ran code with measurement M, signed by repository R at release tag G, as of the capture
  time the file claims. RECORD ONLY: that the plugin checked that evidence during the session, that the
  session's requests went to that enclave and were encrypted to that key, the per-send observations,
  whether the build was the vendor's latest or was revoked later, what shell, terminal and code tools sent
  off the machine, the backends behind the vendor's router, operator access, and Hermes' auxiliary calls,
  which are recorded after the fact, not prevented. It says the ledger is a file on this host,
  unprotected against code in the same process. `NEAR_CLOSING`, `NEAR_ENCRYPTION_NOTE`,
  `SELF_REPORT_NOTE`, `CHAIN_HEAD_NOTE` and `GATING_NOTE` ("sends were gated by the vendor SDK only") are
  the other fixed texts. The text renderer passes vendor strings through `render_if_needed`.

## Replay

`hermes confidential replay <receipt.json>` (`commands_replay.py:cli_replay`, terminal only) replays
each verification in a receipt and every signed send offline, against the pins file or the fingerprints
given. It exits 1 when the hash chain is broken or cannot be checked, whatever the evidence rows say, and
when any NEAR signature fails.

- **Tinfoil** (`verify/replay.py:replay`): re-runs the SDK's verifier on the stored bytes with the
  network banned in the replaying thread (urllib, urllib3 including python-tuf's fetcher, and httpx) and
  every clock pinned. `replay._clock_window()` installs `PinnableDatetime` into `collateral_tdx` and
  `cert_utils` and `_CryptoProxy` into `verify_sev` for one replay and restores the originals when the
  last replay window closes. The trust root comes from `--trusted-root`, then a `trust_root_dir` file,
  then the evidence's `json_b64`, then a legacy `path`. `verify/policy_check.py:check_bundle` and
  `verify/sev_check.py` are standalone second checks (each imports nothing from the plugin and runs with
  `python -I` on Python 3.11 or later).
- **NEAR** (`verify/replay_near.py:replay` and `replay_receipt`): appraises the evidence with the same
  `appraise` the live verification uses (`replay_near.with_blobs(evidence, blobs)` joins the blobs,
  `evidence_by_nonce` matches a send to its evidence) and re-checks every `send_signed` row's signature
  over its digests. `NearReplayResult` carries `schema`, `cvms` and `components`. Approved per-CVM NEAR
  entries are checked with `set_match` against the replayed `cvms`; Tinfoil and migrated records give one
  expected pair. Replay prints each row's schema and the union of every row's `NOT_ESTABLISHED` list.
- **NOT_ESTABLISHED** (`replay_near.NOT_ESTABLISHED`, 16 items; `NOT_ESTABLISHED_V1` for v1 evidence)
  lists what a NEAR replay does not establish, among them: what runs after launch is not measured (with
  the compose-manager claim above); the log may report a compose-manager image other than the measured
  one; the inner services hold the dstack quote socket; image parts left in plaintext.

## Commands

`commands.py:handle_slash` runs `/confidential <verb>` and `commands.py:cli_verb` runs `hermes
confidential <verb>`, on the same `ctx.state`, ledger, pins and allowlist files, so a lock or unlock from a
terminal takes effect on a running gateway's next turn. `/confidential help` lists every verb
(`commands.py:HELP_LINES`). Verbs: `on <tier>`, `off`, `status [--verbose]`, `check [tier] [--verbose]`,
`setup` (terminal only), `allow <tool>`, `revoke <tool>` or `revoke --all`, `pins`, `pins approve
[--reviewed-by <name>] [--note <text>]` (the slash form takes the same flags), `pins review [--json]
[--no-fetch]` (terminal only), `pins retire <fingerprint> [--identity <host#models>]` (slash: `pins retire
<fp> [identity]`), `receipts <session> [--json]`, `replay <receipt.json>` (terminal only) and `watch`.
`commands.py:TERMINAL_ONLY` gives the reply for `replay` and `setup` in chat. `blocked <command>` is the
rewrite target of the gateway command check.

- **Terminal form.** `commands.py:terminal_text(text)` rewrites each `/confidential <verb>` as `hermes
  confidential <verb>`, except in a sentence that names the chat ("In the chat session, run /confidential
  allow ..."). `cli_verb`, `pins retire`, `revoke` and the CLI `check` and `status` handlers print through
  it.
- **check.** Exits 1 unless the preflight passes. The CLI takes a positional tier beside `--tier` (two
  different tiers exit 2). With no tier, `commands_status.py:default_check_tier(rt, config)` picks the
  locked tier; else `attested` for an attested main provider; else `on-host-only` when `model.base_url`'s
  host passes `tiers.is_on_host` with the listed extra hosts; else `attested`; `check_result` prints
  "Checking the <tier> tier (<why>). To check the other tier: <command>" first.
- **status.** Lock state, the configured route and the live runtime, pins and verification (each
  `verify_fail` reason clipped to 300 characters), breaches, this lock's refusal, ask and allow counts,
  "Tool grants (answered once, this lock, this process, each for its own conversation)", Hermes'
  remembered grants, both data directories, the installed commit, and the `Limits:` line. The status
  Preflight line compares the recorded fingerprint with the current one directly.
- **pins.** Approved entries, the pending batch with every component line, Hermes' remembered tool grants
  (`commands_pins.py:remembered_grants`) and the approval history; `pins retire` warns when its row
  "could not be written in full".
- **watch.** `watch.py`: a fixed-width live view of the ledger. Every `verify_fail` row shows ": <reason>"
  (detail `reason`, else `error`, else `reason_code`, clipped to 160) or ": no reason recorded"
  (`watch.verdict_text`).
- **setup** (`commands_setup.py`). `cli_setup` (Tinfoil) and `cli_setup_near` verify the enclave, ask for
  the first pin and print a config block; setup never writes the config. Every side call is pinned to the
  vendor, moa tasks included. Tinfoil setup prints `tinfoil_model_note(model)`: setup cannot check ids
  against Tinfoil, and whether the id is in `TINFOIL_DOCUMENTED_MODELS`. NEAR setup
  (`--vendor near --model <id>`, default `DEFAULT_NEAR_MODEL` `Qwen/Qwen3.8-27B`, vision
  `DEFAULT_NEAR_VISION_MODEL` `Qwen/Qwen3-VL-30B-A3B-Instruct` or `--vision-model`) attests each model alone
  through `attest_near_models(adapter, models)` (`prepare_verification()` per model, publishing nothing),
  prints `near_model_failure` per failed model ("...; vision left unset." or "...; setup stopped, because
  <m> is the main model."), writes one `verify_fail` row per failed model (provider `attested-near`, the
  model, surface `cli-setup`, detail `source: setup`, `error_type`, `error`, `reason`), stops with exit 1
  and a "Next step:" line when the main model fails, and otherwise attests the verified models together
  through the cache, so the pin identity names only them. `near_config_block(model, vision_model, *,
  tinfoil_vision_model, vision_unset_reason, unset_vision)` routes `auxiliary.vision` through
  `attested-near` under `NEAR_VISION_NOTE`, lists the models, prints `image_parts: disclose` and
  `require_provider_tee: true`, and leaves vision out under `NEAR_VISION_UNSET_NOTE` when the vision model
  did not verify. `setup_next_steps(rt, vendor=, key_env=, key_set=, verified=, vision_unset=)` prints a
  numbered "Next steps:" list in the terminal form: set the key (when not set), merge the block, set
  `auxiliary.vision` (NEAR, vision unset), approve the pin in a terminal (a pending batch) or run setup
  again without `--no-verify` (nothing approved and nothing verified), check, lock.
  `scripts/near_first_contact.py` attests NEAR, sends one request and replays the record by hand; it reads
  `NEAR_AI_API_KEY` through `agent.secret_scope.get_secret` after
  `hermes_cli.env_loader.load_hermes_dotenv(load_external_secrets=False)` for `HERMES_HOME`.

## Hermes private names

`hermes_compat.py` is the only plugin module that imports an undocumented Hermes core module, and the
only one that reads a private attribute of a Hermes object. Every other module imports only Hermes'
documented plugin surface: exactly `tools.registry`, `agent.secret_scope`, `providers`, `providers.base`,
`hermes_cli.config`, `plugins.plugin_storage`, or a non-`_` name from one of them.

- **One accessor per private name.** Its docstring names the Hermes symbol, the commit it was verified at
  (`HERMES_VERIFIED_COMMIT = "84a0301"`), the module that calls it and that call site's fallback. The
  accessors: `hermes_yaml`, `yaml_module`, `resolve_command`, `approval_keys` (`tools.approval._lock`,
  `_permanent_set`, `_session_approved`, read under the lock), `approval_state_functions` (`_yolo_active`,
  `_get_approval_mode`, `_presence`, uncalled), `is_approved`, `current_session_key`,
  `request_tool_approval_functions` (`request_tool_approval`, `set_current_observability_context`,
  `reset_current_observability_context`, uncalled), `terminal_env_config_reader` and `active_env_reader`
  (uncalled), `cached_terminal_environments` (`_active_environments` under `_env_lock`),
  `terminal_env_fallback`, `env_backend_tag` (`env_type`, else `_hermes_backend_name`),
  `mcp_server_configs`, `mcp_live_servers` and `mcp_tool_server_names` (under `tools.mcp_tool._lock`,
  through `_mcp_lock`), `mcp_server_config` (a live server's `_config`), `mcp_key_name`,
  `plugin_tool_names` (the manager's `_plugin_tool_names`), `plugin_auxiliary_tasks`, `default_config`,
  `delegation_config`, `load_hermes_dotenv` (used by `scripts/near_first_contact.py` only),
  `runtime_main_context`, `relay_aux_call_context`, `context_overflow_patterns` and `import_tool_module`.
- **Imports at call time.** The module imports nothing from Hermes when it loads, and a test that patches
  the Hermes module is seen by the next call. An accessor never swallows an error: a missing symbol raises
  ImportError and the call site's fallback applies (the gate blocks on unreadable approval or terminal
  state, a missing grant reads as "ask", the MCP and plugin tables read as empty, the preflight falls back
  to `terminal_scope` then `os.environ` and to `BUILTIN_AUX_TASKS_SNAPSHOT`, an unreadable live runtime
  raises `LiveRuntimeUnreadable`, `aux_current` returns None). `yaml_module` falls back to PyYAML;
  `mcp_server_config`, `env_backend_tag` and `plugin_tool_names` read the private attribute with a
  `getattr` default.
- **All or nothing.** Where a call site needs several Hermes functions and must fail before the first one
  has an effect, one accessor returns them all uncalled (`request_tool_approval_functions`,
  `approval_state_functions`, the two terminal readers).
- **Count.** Each private name is imported at one line, so `hermes plugins validate` lists 31 sites, one
  per name, all in `hermes_compat.py`. DISCLOSURE ("Core modules imported"), `plugin.yaml` and the catalog
  entry give the count; `tests/seam/test_disclosure_imports.py` checks all three against Hermes'
  `private_import_findings`.
- **Enforcement.** `tests/unit/test_hermes_compat.py` parses every plugin module that loads inside Hermes
  (`__init__.py`, `confidential_mode/**`, `scripts/*.py`) with `ast` and fails, outside
  `hermes_compat.py`, on an import of a Hermes module other than the documented surface; a `_` attribute
  on a name bound by a Hermes import; a literal `importlib.import_module` (any alias), `import_module` or
  `__import__` of such a module; and a literal `sys.modules[...]`, `.get`, `.pop` or `.setdefault` of one.
  Run-time module names, `getattr(__import__(...))`, `builtins.__import__` and `_` attributes on call
  results are outside the scan. For each accessor it removes each Hermes symbol and asserts ImportError,
  and it drives each call site with the symbol missing and asserts its fallback.
- **What the plugin changes in third-party code.** `verify/_sdkpatch.py` wrappers live only inside their
  capture windows ("Tinfoil adapter"); `redirect_sdk_caches` rebinds tinfoil's cache-dir constants and
  `sigstore._internal.tuf._get_dirs` for the process; the plugin's own `SecureClient` gets instance
  attributes for the pinned EHBP builders. The plugin overrides nothing in Hermes core.

## State files, locks and writes

- **Durable writes.** `atomicwrite.write_atomic(path, data, mode=0o600)` is the only write for every state
  file: a temporary file in the target's directory, fsync, `os.replace`, then
  `fsync_directory(path.parent)` (an OSError from the directory fsync is ignored). Two limits: on macOS `os.fsync`
  does not issue `F_FULLFSYNC`, so the write reaches the drive's cache and not always the platter; and a
  parent directory `write_atomic` creates is not itself fsynced. Callers:
  `pins._write_atomic` (pins.yaml and its backup), `state._replace_unparseable`, `Allowlist.persist`,
  `revoke._atomic_write_json`, `review.store_compose`, `BlobStore.put`, and in `verify/tinfoil.py`
  `load_or_create_user_cache_secret`, `TinfoilAdapter.observe_key` and `store_trust_root`.
- **File locks.** `filelock.exclusive(path)` takes a thread lock (waiting at most `ATTEMPTS` x
  `INTERVAL_SECONDS`, 2 seconds) and a non-blocking flock on `<file>.lock`, tried `ATTEMPTS` (10) times
  `INTERVAL_SECONDS` (0.2) apart. The lock file is opened for append and, when that fails, read-only. A
  lock still held raises `LockBusy` naming the lock file; any other failure to open or flock the file
  (EACCES, a directory in its place, a read-only data directory, EBADF from flock on a read-only
  descriptor over NFS, ENOLCK, EOPNOTSUPP) raises `filelock.LockUnusable`, a `LockBusy` subclass carrying
  `errno_name` and `dir_writable`, so every caller fails closed. `filelock.describe(exc)` gives the reply
  text ("the data directory is not writable: <dir>", "the lock file <path> cannot be used (<errno>)", or
  "<file>.lock is held by another process"), and `filelock.ledger_reason(exc)` the path-free row detail
  (`reason_code` `data_dir_not_writable`, `lock_file_unusable` or `lock_busy`, `errno`, `lock_file`
  basename). Only a platform without the fcntl module (Windows) holds the thread lock alone. Users:
  allowlist.yaml and grants_revoked.json (`revoke.file_lock`), pins.yaml (`PinStore._mutating`), the
  transition lock, and Hermes' own `.state.json.lock` for the state repair.

## Build, dependencies and repository rules

- **Version.** `plugin.yaml` and the catalog entry carry the version (0.1.0). `_version.PLUGIN_COMMIT` is
  the checkout's HEAD whenever `.git` is readable (the first 12 hex digits, "<sha> (git checkout)"), else
  the packaging stamp `scripts/stamp_version.py` writes, else "unpackaged"; the committed stamp is
  "unpackaged". Status and receipts print it.
- **Start-up progress** (`progress.py`). On a TTY on the first start of each commit (marker
  `loaded-commit` in the state directory), or always with `CONFIDENTIAL_MODE_PROGRESS=1` (no TTY needed),
  registration prints one stderr line per phase; `CONFIDENTIAL_MODE_PROGRESS=0` turns the lines off,
  including for the CLI. `lock` and `allow` from the CLI print "discovering tools... <n> found".
- **Dependencies** (`pyproject.toml`, Python 3.11 or later): `tinfoil==0.14.2`, `httpx>=0.28,<0.29`,
  `sigstore>=4.5,<4.6`, `pynacl==1.6.*`, and floors bounded below the next major above what Hermes
  84a0301's `uv.lock` resolves: `cryptography>=42,<51`, `openai>=1.63,<3`, `requests>=2.31,<3`,
  `urllib3>=2.8,<3`, `pyopenssl>=25,<27` (Hermes does not lock pyopenssl; 26.4.0 is the version tested).
  `hermes plugins enable` installs them; the plugin has no hook into that install.
- **Lint and types.** `pyproject.toml` configures ruff 0.17.4 (rules E, F, W, I, B and UP, 120 columns)
  and mypy 2.4.1 (`check_untyped_defs`, `warn_unused_ignores`; Hermes and the vendor SDKs are read as
  untyped). The workflow's `lint` job runs both. Each ignore comment names its rule and says why.
- **Python 3.11.** `tests/unit/test_python311_syntax.py` parses `__init__.py`, `confidential_mode/**` and
  `scripts/**` with `ast.parse(feature_version=(3, 11))` and walks each f-string's tokens for PEP 701 forms
  that call does not catch (a clashing quote, a backslash, a comment or a line break inside a replacement
  field).
- **No archives.** No archive, binary or bytecode file is tracked. Test fixtures are plain files, for
  example `tests/fixtures/near_inner_composes/<sha256>.yaml`, each named by its content's SHA-256, which
  `tests/unit/test_review.py` checks.
- **Declared variables.** `plugin.yaml` declares an empty `requires_env` (no key is required at install:
  the ledger and the on-host-only tier need none, and `hermes plugins install` prompts for every unset
  entry) and `TINFOIL_API_KEY`, `NEAR_AI_API_KEY`, `OPENROUTER_API_KEY` and `NOUS_API_KEY` under
  `optional_env`, each with its reason; the catalog entry's `capabilities` carries the same empty
  `requires_env`, with the optional list in a YAML comment. The catalog description and `plugin.yaml` carry one identical description that states the
  network hosts, the files written, the variables read and the thread kinds, as
  [DISCLOSURE.md](DISCLOSURE.md) states them.
- **Documentation checks.** `tests/unit/test_docs_code_references.py` checks that every `file:name` and
  `file::test_name` reference in CLAIMS.md, ADDING_A_VENDOR.md, ARCHITECTURE.md, INTERFACES.md and
  SECURITY.md names a definition in that file. The repository keeps no spike tests.

## Citation index

Code and test comments cite rules by the amendment that introduced them ("Amendment 4 F3"), by a review
finding ("review finding 9", "SF2", "FI-3"), by a backlog or catalog-rule id, or by the id of the work
package or tester that owned the code (W1 to W13, T1 to T4) or of an earlier contract section ("INTERFACES
W4"). This table maps each
citation found in the repository to the section of this file that holds the rule. A plain "review
finding N" is a finding of the codebase review unless the citing comment names another review.

| Citation | Section |
|---|---|
| (C0) | [Conventions](#conventions), [The llm gate](#the-llm-gate) |
| C1, C2 ruling | [Shared types](#shared-types); the C2 ruling (a ledger failure never changes a send decision) is in [The llm gate](#the-llm-gate) |
| C3 review | [Consent](#consent) (an answer must match the choice value exactly) |
| Ruling 8 | [Conventions](#conventions) (Identity checks across a trust boundary) |
| D5 | [Sends](#sends) (Release rule) |
| review finding 6e | [Sends](#sends) (Refusals: auxiliary calls reach the views without the llm gate) |
| review finding 26 | [Build, dependencies and repository rules](#build-dependencies-and-repository-rules) (Dependencies) |
| W1, "INTERFACES W1" | [The llm gate](#the-llm-gate), [Ledger](#ledger), [Lock state](#lock-unlock-and-the-per-turn-check) |
| W2, "INTERFACES W2" | [Attested providers](#attested-providers), [Tinfoil adapter](#tinfoil-adapter), [Pins file](#pins-file) |
| W3 | [Tiers](#tiers), [Preflight](#preflight) |
| W4, "INTERFACES W4", T4 | [The tool gate](#the-tool-gate), [Consent](#consent) |
| W5 | [Registration and hooks](#registration-and-hooks), [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check), [Commands](#commands) |
| W6 | [Receipts](#receipts), [Conventions](#conventions) (Tests: the scenario demo) |
| W11 | [Sends](#sends) (encryption), [Preflight](#preflight) (NEAR settings) |
| W12 | [Pins file](#pins-file), [Pin review bundle](#pin-review-bundle) |
| W13 | [Verification](#verification) (compose-manager attestation), [Evidence](#evidence) |
| T1 | [The llm gate](#the-llm-gate) |
| Amendment 1 | [Tiers](#tiers), [Preflight](#preflight), [Decisions](#decisions) |
| Amendment 2 | [The llm gate](#the-llm-gate), [Lock state](#lock-unlock-and-the-per-turn-check), [Decisions](#decisions), [Ledger](#ledger), [Consent](#consent) |
| Amendment 3, Amendment 3 addendum, Amendment 3 ruling | [The tool gate](#the-tool-gate), [The allowlist](#the-allowlist), [Preflight](#preflight) (TTS), [Consent](#consent) |
| Amendment 4 | the F rows below |
| Amendment 4 F1, F1(a), F1(c), F1(d) | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Live runtime, Gateway command check), [Receipts](#receipts) (Closing) |
| Amendment 4 F2 | [Preflight](#preflight) (Plugins, Config fingerprint) |
| Amendment 4 F3 | [The hook, the middleware and the observer](#the-hook-the-middleware-and-the-observer) |
| Amendment 4 F4 | [Attested providers](#attested-providers) (Verification cache) |
| Amendment 4 F5, F6 | [The allowlist](#the-allowlist), [Decisions](#decisions) (Lock grants) |
| Amendment 4 F7 | [Ledger](#ledger) (Row kinds), [Receipts](#receipts) |
| Amendment 4 F8 | [Attested providers](#attested-providers) (attested_ok) |
| Amendment 4 F9 | [Receipts](#receipts) (Unverified entries, Closing), [Ledger](#ledger) (Trust) |
| Amendment 4 F11 | [Receipts](#receipts) |
| Amendment 4 F12 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Lock reply) |
| Amendment 4 ruling 1 | [Attested providers](#attested-providers) (create_client) |
| Amendment 4 T2 | [Attested providers](#attested-providers) (Profiles: the context-length override) |
| Amendment 5 | [NEAR adapter](#near-adapter), [Ledger](#ledger), [Receipts](#receipts), [Replay](#replay), [Commands](#commands) (setup) |
| Amendment 5.1 | [Sends](#sends) (encryption, TLS pin, refusals), [Attested providers](#attested-providers) (classify_refusal), [Preflight](#preflight) (NEAR settings) |
| Amendment 5.2 | [Verification](#verification), [Evidence](#evidence), [Ledger](#ledger) (Evidence blobs), [Attested providers](#attested-providers) (A lost verify row), [Receipts](#receipts), [Replay](#replay) |
| Amendment 6 | the review finding rows below |
| Amendment 6 finding 2, review finding 2 | [Preflight](#preflight) (Terminal backend), [Decisions](#decisions) |
| Amendment 6 finding 3, review finding 3 | [The llm gate](#the-llm-gate) (The send row), [Tinfoil adapter](#tinfoil-adapter) (Per-send record) |
| review finding 5 | [Tinfoil adapter](#tinfoil-adapter) (Evidence), [Replay](#replay) |
| review finding 8 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Live runtime) |
| Amendment 6 finding 9, review finding 9 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Lock, Unlock), [Tinfoil adapter](#tinfoil-adapter) |
| Amendment 6 finding 10, review finding 10 | [Replay](#replay) |
| review finding 20 | [The hook, the middleware and the observer](#the-hook-the-middleware-and-the-observer) (Answers in the ledger), [Consent](#consent) |
| review finding 22 | [Receipts](#receipts), [Ledger](#ledger) (Reads) |
| Amendment 6 finding 25 | [Attested providers](#attested-providers) (ConfidentialClient) |
| review finding 27 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Gateway command check) |
| codebase review finding 1, 19; review finding 4 | [Sends](#sends) (TLS pin, Refusals), [Verification](#verification) |
| review finding 1, Finding 11 (revoke tests) | [Revoke](#revoke), [The allowlist](#the-allowlist) (Additions) |
| review finding 12 | [Build, dependencies and repository rules](#build-dependencies-and-repository-rules) (Version) |
| review finding 14 | [Conventions](#conventions) (Tests: test-order independence) |
| review finding 18 | [The allowlist](#the-allowlist) (Persistence) |
| review finding 21 | [Replay](#replay) |
| plan review finding 7 | [Receipts](#receipts), [Replay](#replay) |
| Amendment 7, Amendment 7 migration | [Self-approval guard](#self-approval-guard), [Pins file](#pins-file), [Consent](#consent), [Pin review bundle](#pin-review-bundle), [Ledger](#ledger) |
| Amendment 9 | [Vendor adapter interface](#vendor-adapter-interface), [Attested providers](#attested-providers) (Background re-verification), [Tinfoil adapter](#tinfoil-adapter) (Locks), [Sends](#sends) (Image parts, Image notice), [Self-approval guard](#self-approval-guard), [Receipts](#receipts), [Ledger](#ledger) (Row kinds: `notice`) |
| S09 | [Vendor adapter interface](#vendor-adapter-interface) (Prepare and commit), [Sends](#sends) (Exchange), [Tinfoil adapter](#tinfoil-adapter) (Locks) |
| Amendment 10, D03 | [Tiers](#tiers), [Preflight](#preflight) (On-host hosts, Config fingerprint) |
| Amendment 10, U06 | [Revoke](#revoke), [State files, locks and writes](#state-files-locks-and-writes) (File locks) |
| Amendment 11 | [The allowlist](#the-allowlist) (CLI processes), [Preflight](#preflight) (Credentials, Fixes), [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Lock reply), [Decisions](#decisions) (Bypass), [Receipts](#receipts) (Send pairs), [Commands](#commands), [Ledger](#ledger) (File modes), [Consent](#consent) (The pin prompt), [Build, dependencies and repository rules](#build-dependencies-and-repository-rules) |
| fix-pass-3 item 1 | [The llm gate](#the-llm-gate) (Response size) |
| fix-pass-3 item 3 | [Sends](#sends) (Pools and loops) |
| fix-pass-3 item 6 | [Decisions](#decisions) (Lock grants) |
| Amendment 12 | the FI rows below |
| FI-1 | [Ledger](#ledger) (Failed appends) |
| FI-2 | [Consent](#consent) (allow_tool), [The allowlist](#the-allowlist) (Additions) |
| FI-3 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Repairing state.json) |
| FI-4 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Lock) |
| FI-5 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Transition lock, Unlock) |
| FI-6 | [Ledger](#ledger) (Append rules), [Receipts](#receipts) (Coverage), [Attested providers](#attested-providers) (attested_ok), [Pins file](#pins-file) |
| FI-7 | [State files, locks and writes](#state-files-locks-and-writes) (File locks) |
| Amendment 13 | [Revoke](#revoke), [Decisions](#decisions) (Rule keys, Ask mode, Lock grants), [Preflight](#preflight) (Credentials), [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Per-turn check), [Tinfoil adapter](#tinfoil-adapter), [Build, dependencies and repository rules](#build-dependencies-and-repository-rules), [Tiers](#tiers) (`cached_lookups_only`) |
| S17 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Per-turn check) |
| catalog rule 9 | [Revoke](#revoke), [Hermes private names](#hermes-private-names) |
| catalog rule 10 | [Build, dependencies and repository rules](#build-dependencies-and-repository-rules) (Dependencies) |
| catalog rule 11 | [Preflight](#preflight) (Credentials), [Commands](#commands) (setup) |
| catalog rule 12 | [Decisions](#decisions) (Lock grants) |
| catalog rule 13 | [Build, dependencies and repository rules](#build-dependencies-and-repository-rules) (Declared variables) |
| catalog rule 17 | [Build, dependencies and repository rules](#build-dependencies-and-repository-rules) (No archives) |
| Amendment 14 | [Shared types](#shared-types) (VendorHTTPError), [Preflight](#preflight) (Fixes, Report format), [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Command forms, Unlock), [Consent](#consent) (Terminal answers), [Commands](#commands), [Revoke](#revoke), [Sends](#sends) (Pools and loops) |
| SF1 | [Revoke](#revoke) (Nothing to revoke) |
| SF2, SF2-on-host | [Preflight](#preflight) (Fixes) |
| SF3, S1 | [Shared types](#shared-types) (`http_source`), [Tinfoil adapter](#tinfoil-adapter) (HTTP errors) |
| L1 | [Commands](#commands) (Terminal form), [Hermes private names](#hermes-private-names) (All or nothing) |
| L2 | [Preflight](#preflight) (Credentials, Report format) |
| L3 | [Commands](#commands) (setup) |
| L4 | [The llm gate](#the-llm-gate) (Response size) |
| L5, L7, P1 | [Sends](#sends) (Pools and loops) |
| L8, L8-scan | [Revoke](#revoke) (Nothing to revoke), [Ledger](#ledger) (Reads) |
| R1, R2 | [Revoke](#revoke) (Open gaps) |
| fix-pass-3 review finding 1 | [The llm gate](#the-llm-gate) (Response size) |
| fix-pass-3 review findings 3, 4, 5 | [Sends](#sends) (Pools and loops) |
| fix-pass-3 review finding 7 | [Tinfoil adapter](#tinfoil-adapter) (Capture windows) |
| Amendment 15 | [Hermes private names](#hermes-private-names) |
| issue #1 | [Classification](#classification) |
| issue #2 | [Tinfoil adapter](#tinfoil-adapter) (Plaintext error replies), [The llm gate](#the-llm-gate), [Shared types](#shared-types) (`inference_next_step`) |
| issue #3 | [Tinfoil adapter](#tinfoil-adapter) (Token counts), [Receipts](#receipts) (Token counts) |
| issue #36 | [Sends](#sends) (Refused reply fields) |
| issue #37 | [State files, locks and writes](#state-files-locks-and-writes) (Durable writes) |
| issue #45 | [Lock, unlock and the per-turn check](#lock-unlock-and-the-per-turn-check) (Gateway command check) |

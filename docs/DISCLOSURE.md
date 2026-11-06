<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here and in the title below) -->
# confidential-mode: disclosure

What this plugin does on your machine and on the network, written for catalog rule 13 and for anyone
deciding whether to install it. Everything here describes the code at the pinned commit (Hermes
84a0301, tinfoil SDK 0.14.2). The catalog entry's `description` is a summary of this file;
[LIMITATIONS.md](LIMITATIONS.md) covers what sealed mode does not stop.

## Network

Nothing at load. Registering the plugin and the `attested-tinfoil` provider makes no network call.
The first network traffic happens on the first verification: the first `create_client` for the
attested provider, the first attested-tier send, or `hermes confidential setup`.

When you use the attested provider, the plugin and the tinfoil SDK it drives contact:

| Host | Who calls it | What for |
|---|---|---|
| `atc.tinfoil.sh` (`/routers`) | SDK `get_router_address()` | Router discovery: picks one enclave router at random, once per process. Skipped when `confidential.tinfoil.enclave` is set. |
| the enclave router host (from discovery or your config) | SDK secure transport | `/.well-known/tinfoil-attestation` (the hardware attestation report), then your inference requests, body encrypted to the attested key (EHBP transport). |
| `github-proxy.tinfoil.sh` | SDK | Latest release digest and the Sigstore attestation bundle for `tinfoilsh/confidential-model-router`, and for TDX hosts `tinfoilsh/hardware-measurements`. |
| `kds-proxy.tinfoil.sh` | SDK (AMD SEV-SNP routers) | The VCEK certificate for the CPU that signed the report (AMD KDS through Tinfoil's proxy). |
| `tdx-proxy.tinfoil.sh` | SDK (Intel TDX routers) | Intel PCS collateral: TCB info, QE identity, PCK CRL, root CA CRL (Intel's `api.trustedservices.intel.com` and `certificates.trustedservices.intel.com`, through Tinfoil's proxy). |
| `tuf-repo-cdn.sigstore.dev` | sigstore-python (via the SDK) | Sigstore TUF trust root refresh, used to verify the release's Sigstore bundle. |

Re-verification happens when the cached result is older than `confidential.verify_ttl_seconds`
(default 300 s, monotonic clock), after an unseal, and whenever the SDK re-attests on its own after a
key or certificate rotation.

The plugin itself calls no other host. It sends no telemetry and no usage data anywhere.

What those hosts can see even when everything works: Tinfoil's router terminates TLS and sees your
API key header, request and response sizes, timing and your IP (EHBP encrypts the body, not that);
the three `*.tinfoil.sh` proxies are vendor-run and see each verification from your IP; your DNS
resolver sees every lookup. If Hermes runs on someone else's machine, that operator sees every prompt
before any of this applies.

Unsealed, the plugin changes no routing: your model calls go wherever your config sends them. It
only writes ledger rows describing them (below).

## Files

Reads outside its own data:

- Hermes' merged config (`hermes_cli.config.load_config_readonly`), read-only, every seal, every
  sealed turn, `check` and `status`. The plugin never writes your `config.yaml`; `hermes confidential
  setup` prints a config block for you to apply.
- Hermes' in-process approval state (yolo flag, approval mode, remembered grants), the tool
  registry, MCP server config and the delegation config, read-only, to classify tools.

Writes, all under your Hermes home (profile-scoped):

| Path | Contents |
|---|---|
| `plugin-data/confidential-mode/ledger.sqlite` | The ledger: one row per observed send, refusal, ask, answer, seal, unseal, session start and end, verification (with the captured attestation evidence), pin event, breach, compaction. Hosts, byte counts, verdicts and decisions only, which is still a metadata trail: a shared receipt shares it. No prompt or response text: `Ledger.append` rejects any row whose detail carries `messages`, `prompt`, `input`, `instructions`, `system`, `content` or `contents` at any depth. |
| `plugin-data/agent-plugin-confidential-mode-<digest>/state.json` | `ctx.state`: sealed flag, tier, sealed-since, routing-config fingerprint, breached sessions. |
| same dir, `pins.yaml` | Approved enclave pins and the one pending pin. Written only by an explicit Approve. |
| same dir, `allowlist.yaml` | This seal's tool identities (name, toolset, handler module and qualname) and the tools you allowed with `/confidential allow`, tagged with the seal's identity. A restart rebuilds the allowlist from it; `/confidential off` deletes it, so additions never outlive the seal. |
| same dir, `tinfoil_user_cache_secret` | A random 32-byte hex secret (mode 0600) the SDK sends as `user_cache_secret`, which scopes Tinfoil's prompt cache to you. The SDK's own default is `~/.tinfoil/user_cache_secret`; the plugin never uses that path. |
| same dir, `trust-roots/<sha256>.json` | The Sigstore trusted root used at verification, stored once per content hash so a verification can be replayed offline. |
| same dir, `sdk-cache/` | The tinfoil SDK's and sigstore-python's on-disk caches, redirected here (next section). |

### SDK cache redirect

tinfoil 0.14.2 computes its cache paths with platformdirs at import (macOS `~/Library/Caches/tinfoil`,
Linux `~/.cache/tinfoil`: Sigstore bundles, AMD VCEKs, Intel collateral), and sigstore-python keeps
TUF metadata in `~/Library/Application Support/sigstore-python/tuf` and
`~/Library/Caches/sigstore-python/tuf` (Linux `~/.local/share/sigstore-python/tuf`,
`~/.cache/sigstore-python/tuf`). Before its first verification the plugin re-points all of them under
`sdk-cache/` in its data dir by assigning the SDK's module constants (`tinfoil.github._GITHUB_CACHE_DIR`,
`verify_sev._VCEK_CACHE_DIR`, `collateral_tdx._TDX_CACHE_DIR`) and replacing
`sigstore._internal.tuf._get_dirs`. This is process-wide. If something in the same process used the
SDK before the plugin's first verification, it may already have written to the default paths.

These are assignments into a third-party SDK, not into Hermes core. Evidence capture and offline
replay also wrap SDK functions, thread-scoped (`confidential_mode/verify/_sdkpatch.py`): the wrappers
are inert unless the current thread pushed an override.

## Credentials

One secret: `TINFOIL_API_KEY`, declared in `requires_env` and `env_vars` on the provider profile, so
Hermes resolves it like any provider key and passes it to `create_client`. When Hermes passes no key,
the client and `hermes confidential setup` read it through `agent.secret_scope.get_secret`, which
honours the active profile; the plugin never reads `os.environ` for it. The plugin reads no `.env`, no `auth.json`, no
`~/.tinfoil`, no keychain, and stores no credential. (The prompt-cache secret above is generated by
the plugin and is not a credential for anything.)

## Processes and threads

No shell commands, no subprocesses, no long-running background process. One short-lived daemon
thread per attestation: `create_client` and the attested check wait at most
`confidential.verify_wait_seconds` (default 5 s) for a verification and refuse the turn if it is not
done, while that thread finishes it. The thread exits when the verification ends.

## Hermes surfaces used

Registered through `ctx`: hooks `pre_tool_call`, `post_approval_response`, `pre_llm_call`,
`pre_api_request`, `pre_auxiliary_call`, `post_auxiliary_call`, `on_session_start`, `on_session_end`,
`post_compaction`, `pre_gateway_dispatch` (rewrites a sealed gateway `/model` or `/moa` to a refusal);
middleware `llm_execution`, `tool_execution`; slash command `/confidential`; CLI
command `hermes confidential`. No tools.

The provider profile is registered with `providers.register_provider(...)` directly (subclassing
`providers.base.ProviderProfile`), not through `ctx`. Consequence: the plugin works only with
`plugins.isolation: in_process` (Hermes' default). Under host isolation the provider and the
middleware would register in the plugin-host child, invisible to Hermes; the preflight refuses to
seal in that case.

Core modules imported (catalog rule 9; all imports are lazy, inside functions):

| Module | Names | Why |
|---|---|---|
| `tools.approval` | `request_tool_approval`, `is_approved`, `_yolo_active`, `_presence`, and (in `/confidential pins`) `_lock`, `_session_approved`, `_permanent_set` | Ask for an off-machine tool call; detect bypass states that would auto-approve; read remembered grants under the plugin's own rule key. |
| `tools.approval_context` | `get_current_session_key`, `set_current_observability_context`, `reset_current_observability_context`, `_get_approval_mode` | Session key for remembered grants; tie an approval answer to its tool call; detect `approvals.mode: off`. |
| `tools.registry` | `registry` | Build the tool allowlist at seal and pin each tool's handler identity. |
| `agent.auxiliary_client` | `_RUNTIME_MAIN_CONTEXT` | Read the live main runtime each sealed turn ("auto" auxiliary tasks follow it, not config). |
| `agent.secret_scope` | `get_secret` | Resolve `TINFOIL_API_KEY` for the active profile. |
| `hermes_cli.commands` | `resolve_command` | Recognise `/model` and `/moa` (and aliases) in `pre_gateway_dispatch`. |
| `tools.mcp_tool`, `tools.mcp_tool_config`, `tools.mcp_tool_scope` | `_servers`, `_mcp_tool_server_names`, `_load_mcp_config`, `_key_name` | Map an MCP tool to its server and read whether that server is a URL or a local command. |
| `tools.delegate_tool_config` | `_load_config` | Read the delegation backend and route keys for `delegate_task`. |
| `providers`, `providers.base` | `register_provider`, `get_provider_profile`, `ProviderProfile` | Register `attested-tinfoil`; check it is visible in-process at seal. |
| `hermes_cli.config`, `hermes_cli.config_defaults` | `load_config_readonly`, `DEFAULT_CONFIG` | Read config; enumerate the built-in auxiliary tasks. |
| `hermes_cli.plugins` | `get_plugin_manager`, `get_plugin_auxiliary_tasks` | Tell plugin tools from built-ins; include plugin-registered auxiliary tasks in the preflight. |
| `plugins.plugin_storage` | `plugin_db`, `plugin_data_dir` | The ledger database. |
| `hermes_yaml` | | Read and write `pins.yaml` and `allowlist.yaml`. |

`hermes plugins validate` reports 21 of these sites as private core imports (warning, not failure).
They are the price of classifying tools and approvals without a public seam; see the upstream
roadmap in [LIMITATIONS.md](LIMITATIONS.md).

## What sealed mode blocks

Sealed (`/confidential on local-only` or `/confidential on attested`), profile-wide:

- Main-loop model calls whose destination is off the tier: refused before any byte is sent
  (`llm_execution` middleware returns a refusal response; the provider is never called).
- Fallbacks: the preflight requires `fallback_providers: []` and no `fallback_model`; if one arms
  anyway it re-enters the middleware and is refused. Provider errors on the in-tier endpoint end the
  turn with a refusal, so Hermes never retries, backs off or arms a fallback.
- Attested tier only: any send while the enclave is unverified, stale and not re-verifiable within
  5 s, or verified but not matching the pin you approved.
- Attested tier only: a pin with no matching `pin_applied` consent row in the ledger ("pin has no
  consent record").
- Any turn after the routing config changed since seal (fingerprint over model, fallbacks, every
  auxiliary task, delegation, tts, memory, MCP servers, and the `plugins.*` keys that govern hooks):
  blocked in `pre_llm_call` and again in the middleware.
- Any turn whose live main runtime (after a `/model` switch or `--provider`) is off-tier; on gateway
  surfaces `/model` and `/moa` are refused outright while sealed.
- Off-machine tools: each call asks you on Hermes' approval prompt with "<tool> wants to send ~N KB
  of this conversation off the machine". Enforcement is in the `tool_execution` middleware, which
  runs the tool only on an exact `once`, `session` or `always`. `session` stops the asking for the
  session; `always` stops it, across seals, until you remove
  `plugin_rule:confidential-mode:tool:<name>` from `command_allowlist`. Under yolo,
  `approvals.mode: off`, or an unattended context (cron, `-q`, no surface), the ask becomes a block.
- Always blocked: `cronjob_manage`; tools from MCP servers whose URL host is off the tier; tools that
  were not in the registry at seal, or whose handler or toolset changed since; `delegate_task` with
  any route field, a non-default backend, or route keys in `delegation` config.
- Seal is refused while any auxiliary task (all 19 built-ins plus plugin-registered ones), vision,
  delegation, TTS, memory provider or MCP URL server would leave the tier, with the exact YAML key
  to change.

## What sealed mode does not block

- Auxiliary calls at runtime. Hermes does not run them through `llm_execution`, and
  `pre_auxiliary_call` cannot veto. The preflight makes sure none is configured off-tier and each turn
  checks the live runtime; if one goes anyway (for example between turns after a CLI `/model`
  switch), the plugin ledgers a `breach` and marks the session breached. It cannot stop the bytes.
- Hermes' start-up model-list probe when the live runtime has drifted to a hosted provider (an
  API-key request to that provider, no conversation text).
- Metadata at Tinfoil's TLS termination, the vendor-run collateral proxies, DNS, and the host
  operator if Hermes runs on someone else's machine.
- Local tools: `terminal`, `process_manage`, `execute_code`, `read_file`, `write_file`, `patch`,
  `search_files`, `skills_list`, `skill_view`, `skill_manage`, `todo_list`, `memory`, `clarify`,
  `session_search`. Shell and code execution can reach the network; their commands are not inspected.
- MCP servers launched as a local command: allowed, not inspected (a command can be a proxy).
- Everything while Hermes runs as a safe worker: plugins are not loaded there, so sealed mode does
  not apply.
- The messaging platform you talk to Hermes over (Telegram, Discord, ...).
- Other plugins in the same process.

## Isolation

`in_process` only.

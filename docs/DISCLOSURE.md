<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here and in the title below) -->
# confidential-mode: disclosure

This file describes what the plugin does on your machine and on the network. It is written for rule
13 of the Hermes plugin catalog, and for anyone deciding whether to install the plugin.

Everything here describes the code at the pinned versions: Hermes commit 84a0301 and tinfoil SDK
0.14.2. The catalog entry's `description` is a summary of this file. [LIMITATIONS.md](LIMITATIONS.md)
covers what locked mode does not stop.

## Terms used here

**Hermes** is an agent harness: the program that runs the loop around a language model. A
**profile** is a separate Hermes home directory with its own config and data. Everything the plugin
writes is scoped to one profile.

To **lock** a profile is to hold it to one **tier**, a rule about where the model may run. The word
is "lock" and not "seal", because sealing means something else in confidential computing. A
destination the rule accepts is "in-tier", and any other is "off-tier". The `on-host-only` tier
accepts loopback and private-range hosts. The `attested` tier accepts only Tinfoil's verified
enclave. **On-host** means on the machine that runs Hermes, and **off-host** means anywhere else.

An **enclave** is a virtual machine whose memory the CPU encrypts, so that the host's operator cannot
read it. **Attestation** is the enclave proving what it runs, through a report signed by the CPU
vendor's hardware. The **platform** is the CPU vendor's enclave technology: AMD SEV-SNP or Intel TDX.

Tinfoil's **router** is the enclave your requests connect to. A **pin** is your recorded approval of
one router build. **Verification** is the plugin checking the router's attestation before it sends
anything.

**Collateral** is the certificates and signed documents a client needs from the CPU vendor to check a
hardware report. For AMD, the main piece is the **VCEK**, the certificate for the signing key of the
particular CPU that produced the report.

**Sigstore** is a public software-signing service. Tinfoil signs its router releases through it. A
**trust root** is the file of keys a signature check starts from. sigstore-python refreshes its trust
root through **TUF** (The Update Framework).

**HPKE** is a standard way to encrypt a message to a public key. **EHBP** (the encrypted HTTP body
protocol) is Tinfoil's transport, which uses HPKE to encrypt each request body to the enclave's key.

The **ledger** is the plugin's on-host log. A **receipt** is a rendering of the ledger for one session.
**Evidence** is the raw bytes captured during one verification, kept so that the verification can be
**replayed** offline later.

A **hook** is a callback Hermes calls at a named moment. **Middleware** is code Hermes runs around an
operation, which can refuse to pass the operation on.

## Network

### When the plugin first touches the network

Loading the plugin makes no network call. Registering the plugin and its `attested-tinfoil` provider
makes no network call either.

The first network traffic happens at the first verification. One of three events triggers it:

- the first time Hermes asks the attested provider for a client (`create_client`);
- the first send on the attested tier;
- running `hermes confidential setup`.

### Which hosts it contacts

When you use the attested provider, the plugin and the tinfoil SDK it drives contact the hosts below.

| Host | Who calls it | What for |
|---|---|---|
| `atc.tinfoil.sh` (`/routers`) | The SDK's `get_router_address()`. | Router discovery. The SDK picks one enclave router at random, once per process. This step is skipped when `confidential.tinfoil.enclave` is set. |
| The enclave router host, from discovery or from your config | The SDK's secure transport. | First, `/.well-known/tinfoil-attestation`, which returns the hardware attestation report. Then your inference requests, each with its body encrypted to the attested key by EHBP. |
| `github-proxy.tinfoil.sh` | The SDK. | The latest release digest and the Sigstore attestation bundle for `tinfoilsh/confidential-model-router`. For TDX hosts, the same for `tinfoilsh/hardware-measurements`. |
| `kds-proxy.tinfoil.sh` | The SDK, for AMD SEV-SNP routers. | The VCEK certificate for the CPU that signed the report. The request goes to AMD's key distribution service (KDS) through Tinfoil's proxy. |
| `tdx-proxy.tinfoil.sh` | The SDK, for Intel TDX routers. | Intel's collateral from its provisioning certification service (PCS): TCB info, QE identity, the PCK revocation list and the root CA revocation list. TCB info is Intel's signed statement of current firmware versions. QE identity describes the quoting enclave that signs TDX reports. The two revocation lists name withdrawn certificates. These come from Intel's `api.trustedservices.intel.com` and `certificates.trustedservices.intel.com`, through Tinfoil's proxy. |
| `tuf-repo-cdn.sigstore.dev` | sigstore-python, called by the SDK. | A refresh of the Sigstore trust root through TUF. The trust root is used to verify the release's Sigstore bundle. |

When you use the `attested-near` provider (NEAR AI Cloud), the plugin itself contacts the hosts below. No NEAR SDK is involved.

| Host | Who calls it | What for |
|---|---|---|
| `cloud-api.near.ai` (or `confidential.near.base_url`) | The plugin's NEAR adapter. | `/v1/attestation/report` and `/v1/attestation/ita-token` with a fresh nonce, without an API key (NEAR documents them as public). Then your inference requests, and `/v1/signature/<id>` for each response, both with `NEAR_AI_API_KEY`. TLS ends inside NEAR's gateway CVM, which reads every request it routes. |
| `portal.trustauthority.intel.com` (`/certs`) | The plugin's NEAR adapter. | Intel Trust Authority's token-signing keys. The adapter never fetches keys from a URL the vendor names; the key chain must end at a pinned Intel root. |

### When it verifies again

The plugin verifies the router again in three situations:

1. when the cached result is older than `confidential.verify_ttl_seconds`, which defaults to 300
   seconds and is measured on a monotonic clock;
2. after an unlock, which clears the cached result;
3. whenever the SDK re-attests on its own after the enclave rotates a key or certificate.

### What it does not contact

The plugin itself calls no other host. It sends no telemetry and no usage data anywhere.

### What those hosts can see even when everything works

- **Tinfoil's router host** is where TLS, the encryption HTTPS uses, ends. The live run of
  2026-11-06 established that it ends inside the attested router enclave, not at a separate front
  proxy (see LIMITATIONS, "Where TLS ends"). The router therefore decrypts your API key header.
  Tinfoil's network and hosting still see the request and response sizes, their timing, and your
  IP address. EHBP encrypts the body. It does not hide this metadata.
- **The three `*.tinfoil.sh` proxies** are run by the vendor. They see each verification, from your
  IP address.
- **Your DNS resolver** sees every lookup.
- **Whoever operates the machine Hermes runs on** sees every prompt before any of this applies, if
  Hermes runs on someone else's machine.

### Unlocked behaviour

When the profile is not locked, the plugin changes no routing. Your model calls go wherever your
config sends them. The plugin only writes ledger rows that describe them, as described below.

## Files

### What it reads outside its own data

- **Hermes' merged config.** The plugin reads it through `hermes_cli.config.load_config_readonly`,
  read-only. It reads it at every lock, on every locked turn, and for `check` and `status`.

  The plugin never writes your `config.yaml`. `hermes confidential setup` prints a config block for
  you to apply yourself.
- **Hermes' in-process approval state, tool registry, MCP server config and delegation config.** The
  approval state is the yolo flag, the approval mode and the remembered grants. The plugin reads all
  of these read-only, to classify tools.

### What it writes

Everything the plugin writes is under your Hermes home, scoped to the profile.

| Path | Contents |
|---|---|
| `plugin-data/confidential-mode/ledger.sqlite` | The ledger. It holds one row per observed send, refusal, question, answer, lock, unlock, session start and session end, verification (with the captured attestation evidence), pin event, breach and compaction. Rows hold hosts, byte counts, verdicts and decisions only. That is still a metadata trail, and a shared receipt shares it. Rows hold no prompt or response text. `Ledger.append` rejects any row whose details carry one of these keys at any depth: `messages`, `prompt`, `prompts`, `request`, `input`, `instructions`, `system`, `content` or `contents`. |
| `plugin-data/agent-plugin-confidential-mode-<digest>/state.json` | `ctx.state`, Hermes' per-plugin key-value store. It holds the locked flag, the tier, the time of locking, the routing-config fingerprint and the list of breached sessions. |
| The same directory, `pins.yaml` | The approved enclave pins and at most one pending pin. The plugin writes a pending pin when a verification finds a build that does not match your pin. It turns a pending pin into an approved pin only on an explicit Approve from you. The one exception is the platform-only policy, `confidential.pins.auto_approve_platform_only`, which is off by default. |
| The same directory, `allowlist.yaml` | This lock's tool identities: each tool's name, toolset, handler module and handler name. It also holds the tools you allowed with `/confidential allow`, tagged with the lock's identity. After a restart, the plugin rebuilds the allowlist from this file. `/confidential off` deletes it, so additions never outlive the lock. |
| The same directory, `tinfoil_user_cache_secret` | A random 32-byte secret, stored as hex with file mode 0600. The SDK sends it as `user_cache_secret`, which keeps Tinfoil's prompt cache separate for you. The SDK's own default location is `~/.tinfoil/user_cache_secret`. The plugin never uses that path. |
| The same directory, `trust-roots/<sha256>.json` | The Sigstore trust root used at verification. Each distinct trust root is stored once, named by the hash of its content. The evidence in the ledger also carries the trust root's bytes, so a receipt replays offline on any machine. The evidence records no local path. |
| The same directory, `sdk-cache/` | The on-disk caches of the tinfoil SDK and of sigstore-python, redirected here. The next section explains how. |

### SDK cache redirect

By default, the two libraries cache in your user directories.

- tinfoil 0.14.2 computes its cache path with platformdirs when it is imported. On macOS the path is
  `~/Library/Caches/tinfoil`. On Linux it is `~/.cache/tinfoil`. The cache holds Sigstore bundles,
  AMD VCEKs and Intel collateral.
- sigstore-python keeps TUF metadata in `~/Library/Application Support/sigstore-python/tuf` and
  `~/Library/Caches/sigstore-python/tuf` on macOS. On Linux it uses
  `~/.local/share/sigstore-python/tuf` and `~/.cache/sigstore-python/tuf`.

Before its first verification, the plugin re-points all of these under `sdk-cache/` in its data
directory. It does this in two ways.

1. It assigns new values to the SDK's module constants: `tinfoil.github._GITHUB_CACHE_DIR`,
   `verify_sev._VCEK_CACHE_DIR` and `collateral_tdx._TDX_CACHE_DIR`.
2. It replaces sigstore-python's `sigstore._internal.tuf._get_dirs`.

This change applies to the whole process. If something in the same process used the SDK before the
plugin's first verification, it may already have written to the default paths.

These are assignments into a third-party SDK. They are not changes to Hermes core.

Evidence capture and offline replay also wrap SDK functions (`confidential_mode/verify/_sdkpatch.py`).
These wrappers are scoped to a thread. They do nothing unless the current thread has pushed an
override.

## Credentials

The plugin uses one secret, `TINFOIL_API_KEY`.

It declares the key in `requires_env` and in `env_vars` on the provider profile. Hermes therefore
resolves it like any provider key and passes it to `create_client`.

When Hermes passes no key, the client and `hermes confidential setup` read it through
`agent.secret_scope.get_secret`. That function honours the active profile. The plugin never reads
`os.environ` for the key itself.

The plugin reads no `.env` file, no `auth.json`, nothing under `~/.tinfoil`, and no keychain. It
stores no credential.

The prompt-cache secret described above is generated by the plugin. It is not a credential for
anything.

## Processes and threads

The plugin runs no shell commands and starts no subprocesses. It runs no long-running background
process.

It starts one short-lived daemon thread for each attestation. The sequence is this:

1. `create_client`, or the attested check on a turn, needs a fresh verification.
2. The plugin starts the thread, which runs the verification.
3. The caller waits at most `confidential.verify_wait_seconds`, 20 seconds by default.
4. If the verification is not done by then, the plugin refuses the turn. The thread keeps running
   and finishes the verification.
5. The thread exits when the verification ends.

## Hermes surfaces used

The plugin registers the following through `ctx`, Hermes' plugin context object.

- **Hooks:** `pre_tool_call`, `post_approval_response`, `pre_llm_call`, `pre_api_request`,
  `pre_auxiliary_call`, `post_auxiliary_call`, `on_session_start`, `on_session_end`,
  `post_compaction` and `pre_gateway_dispatch`. The last one rewrites a `/model` or `/moa` command
  sent through the gateway while locked into a refusal.
- **Middleware:** `llm_execution` and `tool_execution`.
- **Slash command:** `/confidential`.
- **CLI command:** `hermes confidential`.
- **Tools:** none.

The provider profile is registered differently. The plugin subclasses `providers.base.ProviderProfile`
and calls `providers.register_provider(...)` directly, not through `ctx`.

This has a consequence. The plugin works only with `plugins.isolation: in_process`, which is Hermes'
default. Under host isolation, the provider and the middleware would register in a separate
plugin-host child process. Hermes would not see them. The preflight refuses to lock in that case.

### Core modules imported

Catalog rule 9 asks plugins to list the Hermes core modules they import. Every import below is lazy,
which means it happens inside a function, not when the plugin loads.

| Module | Names | Why |
|---|---|---|
| `tools.approval` | `request_tool_approval`, `is_approved`, `_yolo_active`, `_presence`, and, in `/confidential pins`, `_lock`, `_session_approved`, `_permanent_set` | To ask before an off-host tool call. To detect bypass states that would approve a call without asking. To read remembered grants stored under the plugin's own rule key. |
| `tools.approval_context` | `get_current_session_key`, `set_current_observability_context`, `reset_current_observability_context`, `_get_approval_mode` | To get the session key for remembered grants. To tie an approval answer to its tool call. To detect `approvals.mode: off`. |
| `tools.registry` | `registry` | To build the tool allowlist at lock, and to record each tool's handler identity. |
| `agent.auxiliary_client` | `_RUNTIME_MAIN_CONTEXT` | To read the live main runtime on each locked turn. Auxiliary tasks set to `auto` follow the live runtime, not the config. |
| `agent.secret_scope` | `get_secret` | To resolve `TINFOIL_API_KEY` for the active profile. |
| `hermes_cli.commands` | `resolve_command` | To recognise `/model` and `/moa`, and their aliases, in `pre_gateway_dispatch`. |
| `tools.mcp_tool`, `tools.mcp_tool_config`, `tools.mcp_tool_scope` | `_servers`, `_mcp_tool_server_names`, `_load_mcp_config`, `_key_name` | To map an MCP tool to its server, and to read whether that server is a URL or an on-host command. |
| `tools.delegate_tool_config` | `_load_config` | To read the delegation backend and route keys for `delegate_task`. |
| `providers`, `providers.base` | `register_provider`, `get_provider_profile`, `ProviderProfile` | To register `attested-tinfoil`, and to check at lock time that it is visible in the process. |
| `hermes_cli.config`, `hermes_cli.config_defaults` | `load_config_readonly`, `DEFAULT_CONFIG` | To read the config, and to list the built-in auxiliary tasks. |
| `hermes_cli.plugins` | `get_plugin_manager`, `get_plugin_auxiliary_tasks` | To tell plugin tools from built-in tools, and to include plugin-registered auxiliary tasks in the preflight. |
| `plugins.plugin_storage` | `plugin_db`, `plugin_data_dir` | To open the ledger database. |
| `hermes_yaml` | | To read and write `pins.yaml` and `allowlist.yaml`. |

`hermes plugins validate` reports 21 of these import sites as private core imports. This is a warning,
not a failure. The imports are the price of classifying tools and approvals without a public seam. The
upstream roadmap in [LIMITATIONS.md](LIMITATIONS.md) lists the seams that would remove them.

## What locked mode blocks

You lock with `/confidential on on-host-only` or `/confidential on attested`. The lock applies to the
whole profile. While locked, the plugin blocks the following.

- **Main-loop model calls whose destination is off-tier.** The plugin refuses them before any byte is
  sent. The `llm_execution` middleware returns a refusal response, and the provider is never called.

- **Fallbacks.** The preflight requires `fallback_providers: []` and no `fallback_model`. If a
  fallback arms anyway, it passes through the middleware again and is refused.

  Provider errors on the in-tier endpoint end the turn with a refusal. Hermes therefore never retries,
  backs off or arms a fallback.

- **Sends to an unverified or unpinned enclave (attested tier only).** The plugin refuses any send
  while the enclave is unverified. It refuses when the last verification is stale and cannot be
  repeated within `confidential.verify_wait_seconds` (20 seconds by default). It refuses when the enclave is verified but does not match the pin you
  approved.

- **A pin with no consent record (attested tier only).** The plugin refuses a pin that has no matching
  `pin_applied` row in the ledger, with the message "pin has no consent record".

- **Any turn after the routing config changed.** At lock time, the plugin records a fingerprint over
  the model, the fallbacks, every auxiliary task, delegation, TTS, memory, MCP servers and the
  `plugins.*` keys that govern hooks. If the fingerprint changes, the plugin blocks the turn. It
  blocks it once in `pre_llm_call` and again in the middleware.

- **Any turn whose live main runtime is off-tier.** A `/model` switch or the `--provider` flag can
  change the live runtime without changing the config. On gateway surfaces, the plugin refuses
  `/model` and `/moa` outright while locked.

- **Off-host tools, unless you approve each call.** Each call asks you on Hermes' approval prompt,
  with the line "<tool> wants to send ~N KB of this conversation off the machine".

  Enforcement happens in the `tool_execution` middleware. It runs the tool only on an exact `once`,
  `session` or `always`. `session` stops the asking for that session. `always` stops it, across locks,
  until you remove `plugin_rule:confidential-mode:tool:<name>` from `command_allowlist`.

  Under yolo mode, `approvals.mode: off`, or an unattended context such as cron, `-q` or no surface
  at all, the ask becomes a block.

- **Tools that are always blocked.** These are the following:
  - `cronjob_manage`, because a scheduled job would run later, outside the locked session;
  - tools from MCP servers whose URL host is off-tier;
  - tools that were not in the registry at lock time;
  - tools whose handler or toolset has changed since lock time;
  - `delegate_task` with any route field, with a non-default backend, or with route keys in the
    `delegation` config.

- **Locking itself, while a route would leave the tier.** The plugin refuses to lock while any
  auxiliary task would leave the tier. That covers all 19 built-in tasks and every plugin-registered
  task. It also refuses while vision, delegation, TTS, the memory provider or an MCP URL server would
  leave the tier. Each refusal names the exact YAML key to change.

## What locked mode does not block

- **Auxiliary calls at runtime.** Hermes does not run them through `llm_execution`, and
  `pre_auxiliary_call` cannot veto them. The preflight makes sure that none is configured off-tier.
  Each turn checks the live runtime. If an auxiliary call goes off-tier anyway, for example between
  turns after a `/model` switch on the CLI, the plugin writes a `breach` row and marks the session as
  breached. It cannot stop the bytes.

- **Hermes' start-up model-list request on a drifted runtime.** When the live runtime has been
  switched to a hosted provider, Hermes sends that provider an API-key request for its model list.
  The request carries no conversation text.

- **Network metadata.** This covers the sizes, timing and addresses visible on the connection to
  Tinfoil's router, the vendor-run collateral proxies, DNS, and the host operator if Hermes runs
  on someone else's machine.

- **On-host tools.** These are `terminal`, `process_manage`, `execute_code`, `read_file`, `write_file`,
  `patch`, `search_files`, `skills_list`, `skill_view`, `skill_manage`, `todo_list`, `memory`,
  `clarify` and `session_search`. Shell and code execution can reach the network. The plugin does not
  inspect their commands. The first seven of these tools run through Hermes' terminal backend. The
  plugin refuses to lock unless that backend is `local` (`terminal.backend` and `TERMINAL_ENV`), and
  it blocks a call to one of the seven tools on any other backend.

- **MCP servers launched as a command on this host.** They are allowed and not inspected. A command can be a
  proxy to a hosted service.

- **Everything while Hermes runs as a safe worker.** Safe-worker mode is a mode for managed Hermes
  worker processes in which Hermes loads no plugins. Locked mode does not apply there.

- **The messaging platform you talk to Hermes over,** such as Telegram or Discord.

- **Other plugins in the same process.**

## Isolation

The plugin supports `in_process` isolation only.

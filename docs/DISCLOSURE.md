<!-- PLUGIN_NAME: confidential-mode  (final catalog slug; the prose name is Hermes Confidential Mode) -->
# Hermes Confidential Mode: disclosure

This file describes what the plugin does on your machine and on the network. This file is written for anyone
deciding whether to install the plugin. This file also meets rule 13 of the Hermes plugin catalog. That
rule asks every listed plugin to disclose its network traffic, files, credentials and processes.

Everything here describes the code at the pinned versions: Hermes commit 84a0301 and tinfoil SDK
0.14.2. The catalog entry's description summarises this file and names it. [LIMITATIONS.md](LIMITATIONS.md)
covers what locked mode does not stop.

## Terms used here

The [guide's glossary](GUIDE.md#glossary) defines every term used here: profile, tier, lock,
on-host and off-host, in-tier and off-tier, enclave, attestation, platform, router, gateway, CVM, pin,
collateral, VCEK, Sigstore, trust root, TUF, HPKE, EHBP, ledger, receipt, evidence, replay, hook and
middleware. Everything the plugin writes is scoped to one Hermes profile.

## Network

### When the plugin first touches the network

Loading the plugin makes no network call. Registering the plugin and its two attested providers,
`attested-tinfoil` and `attested-near`, makes no network call either.

When the plugin decides whether a host is on-host, on either tier and in the preflight, it resolves
one name: this machine's own host name, and only when a model route or an MCP server URL names that
host (`own_hostname_is_loopback` in `confidential_mode/tiers.py`). The lookup goes through the system
resolver, so it can reach your DNS server. The lookup runs on a daemon thread; the caller waits at most
two seconds, and the thread itself runs until the resolver returns. A failed or non-loopback answer is
kept for the life of the process, and a loopback answer is rechecked at most once a minute. This
lookup needs no verification.

Apart from that lookup, the first network traffic happens at the first verification. One of three
events triggers it:

- the first time Hermes asks the attested provider for a client (`create_client`);
- the first send on the attested tier;
- running `hermes confidential setup`, or `hermes confidential setup --vendor near`.

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
| `cloud-api.near.ai` (or `confidential.near.base_url`) | The plugin's NEAR adapter. | `/v1/attestation/report` and `/v1/attestation/ita-token` with a fresh nonce, without an API key (NEAR documents them as public). Then your inference requests, and `/v1/signature/<id>` for each response, both with `NEAR_AI_API_KEY`, over connections pinned to the TLS key the gateway's quote binds. TLS ends inside NEAR's gateway CVM. With `confidential.near.encrypt` on (the default), chat message text, tool definitions and tool calls reach the gateway encrypted to the attested model key (PyNaCl, `pynacl==1.6.*`); image parts leave in plaintext (unless `confidential.near.image_parts: refuse`); the gateway still reads the model id, the plaintext parameters, the request headers, sizes and timing, and can read a reply by swapping the client key header, which the plugin detects afterwards and records as unverified. With encryption off it reads every request it routes. |
| `portal.trustauthority.intel.com` (`/certs`), or `portal.eu.trustauthority.intel.com` (`/certs`) when the token names Intel's EU issuer | The plugin's NEAR adapter. | Intel Trust Authority's token-signing keys. The adapter never fetches keys from a URL the vendor names; the key chain must end at a pinned Intel root. |

When a verification stages a NEAR model entry, the approve command runs, or you run `hermes confidential
pins review`, the plugin also contacts the hosts below. A staging fetch runs unprompted on a background
thread after the verification, including a verification that `hermes confidential check --tier attested`
starts. A fetch sends no key, no prompt and nothing from the ledger. Set `CONFIDENTIAL_MODE_NO_FETCH`
to turn every such fetch off; NEAR model entries then cannot be approved.

| Host | Who calls it | What for |
|---|---|---|
| `raw.githubusercontent.com` | Staging, the approve command, `pins review`. | Each docker-compose file a NEAR model CVM's deployment log names, at `<repository>/<commit>/<file>`, where the repository is the repository the measured compose names in `GITHUB_REPO` (today `nearai/cvm-compose-files`); nothing is fetched when the measured compose names no repository on github.com. Only a 40-digit commit and a plain relative path are ever put in the URL. The text is kept only when its SHA-256 equals the log's. GitHub serves a fork's commit under the same URL, so the fetch does not prove the commit belongs to that repository. |
| `api.github.com` | `pins review` only. | The author, date and message of each of those commits, as unsigned metadata for the reviewer. |

### When it verifies again

The plugin verifies again in these situations:

1. while locked, on the background thread, `confidential.verify_refresh_lead_seconds` (60 by default)
   before the cached result is older than `confidential.verify_ttl_seconds`;
2. when the cached result is older than `confidential.verify_ttl_seconds`, which defaults to 300
   seconds and is measured on a monotonic clock;
3. after an unlock, which clears the cached result;
4. for Tinfoil, whenever the SDK re-attests on its own after the enclave rotates a key or certificate;
5. for NEAR, after the gateway answers HTTP 421 or a send meets a TLS certificate other than the
   attested one, at most once per `confidential.near.reverify_backoff_seconds` (30 seconds by
   default).

After a failed verification the plugin waits 10 seconds before it tries again. The background thread
follows the same wait between its own attempts.

### What it does not contact

The plugin itself calls no host beyond those listed above. The plugin sends no telemetry and no
usage data anywhere.

### What those hosts can see even when everything works

- **Tinfoil's attested router** is where TLS ends for Tinfoil. The plugin uses the tinfoil SDK's
  `ehbp` transport, which encrypts each request body to the enclave's attested HPKE key, and pins every
  inference connection to the TLS key of the verified report the plugin accepted, before any request
  byte is written. The SDK's attestation fetch to the router is ordinary WebPKI TLS, by design: the
  report it returns is checked by its signatures, and that request carries no API key. The router
  reads your API key header, the request headers, sizes and timing. A TLS intermediary with any other
  certificate gets no request byte: the connection is refused and recorded
  ([LIMITATIONS.md](LIMITATIONS.md), section 9). Tinfoil's network and hosting see the request and
  response sizes, their timing, and your IP address.
- **NEAR's gateway** is where TLS ends for NEAR; the plugin pins each inference and signature
  connection to the certificate the gateway's quote binds. The gateway reads your API key header, the model
  id, the plaintext parameters, the request headers, sizes and timing, and your IP address. With
  request encryption on, the gateway does not read the message text, the tool definitions or the
  tool calls. The gateway reads every image you send, because images leave in plaintext unless
  `confidential.near.image_parts` is `refuse`. A gateway that swaps the client key header can read a reply. The plugin detects the swap only afterwards
  ([LIMITATIONS.md](LIMITATIONS.md), section 14).
- **GitHub** sees each fetch of a NEAR compose file and of its commit metadata, from your IP address.
- **The three `*.tinfoil.sh` proxies** are run by the vendor. The proxies see each verification, from your
  IP address.
- **Your DNS resolver** sees every lookup.
- **Whoever operates the machine Hermes runs on** sees every prompt before any of this applies, if
  Hermes runs on someone else's machine.

### Unlocked behaviour

When the profile is not locked, the plugin changes no routing. Your model calls go wherever your
config sends them. The plugin only writes ledger rows that describe them, as described below.

## Files

### What it reads outside its own data

- **Hermes' merged config.** The plugin reads the config through
  `hermes_cli.config.load_config_readonly` at every lock, on every locked turn, and for `check` and
  `status`.
- **Whether a key is set.** To report whether a vendor key, `OPENROUTER_API_KEY` or `NOUS_API_KEY` is
  set, the lock and `check` call `agent.secret_scope.get_secret` and look for a non-empty `api_key` on a
  route in the config. Only presence is kept. The plugin never opens `auth.json` (catalog rule 11), so a
  credential held only in Hermes' credential pool, or a Nous sign-in through `hermes auth`, is not
  checked, and the preflight note says so.
- **Hermes' in-process approval state, tool registry, MCP server config and delegation config.** The
  approval state is the yolo flag, the approval mode and the remembered grants. The plugin reads
  these to classify tools. A revoke also edits the approval state (below).
- **Script files a locked tool call runs.** While locked, when a `terminal` or `execute_code` command
  runs a script file, the tool gate reads up to 1 MB of that file, relative to `TERMINAL_CWD` or the
  working directory, to scan it for the plugin's own commands (LIMITATIONS section 15).
- **Image files a tool call names.** To size the "wants to send" prompt, the tool gate reads the size
  of each local image file named in an off-host tool's arguments.

### What it writes to Hermes' files

- **`config.yaml`, on a revoke only.** `hermes confidential revoke <tool>`, `revoke --all` and
  `/confidential revoke` read your file as written with `hermes_cli.config.read_raw_config` (no
  defaults merged), remove from `command_allowlist` only the plugin's own entries,
  `plugin_rule:confidential-mode:tool:<name>` and `plugin_rule:confidential-mode:tool@<generation>:<name>`
  (the keys Hermes stored for an `always` answer to the plugin's prompt), and save with Hermes'
  `save_config`, which keeps every other key, value, comment and environment reference. Hermes' save
  also normalises an older layout, as any Hermes config save does: root `provider`, `base_url` and
  `context_length` move under `model`, `model.api_base` becomes `model.base_url`, `model.name` or
  `model.model` becomes `model.default`, a root `max_turns` moves under `agent`, and values equal to
  Hermes' defaults that were not set explicitly are dropped. Hermes applies the same normalisation
  when it loads the file, so the effective config, and the lock's fingerprint, are unchanged. When no such
  entry exists the file is not written. When the saved file still holds an entry (a managed install,
  or a file that is not writable), the revoke fails and names the line to delete by hand; the entry no
  longer grants anything, because the plugin then asks under a new approval key. Nothing else in the plugin writes `config.yaml`; `hermes confidential setup` prints a config
  block for you to apply yourself.
- **The tool-discovery cache, on a terminal lock.** See the next section.

### What it writes in its own data

Everything the plugin writes is under your Hermes home, scoped to the profile. Apart from the Hermes
files above, it writes only the files below. The plugin creates each
file with mode 0600, and sets mode 0600 again on existing files once per installed commit. The modes are POSIX
modes: on Windows, a mode change sets only the read-only flag.

`hermes confidential on` run in a terminal imports every Hermes built-in tool module, so the lock can classify
each tool. Hermes may then rewrite its tool-discovery cache, `<hermes home>/cache/tool_discovery_cache.json`,
when that cache is stale. The imported modules register their exit handlers, and the plugin leaves those
handlers in place. One of the handlers is Hermes' browser handler: when the terminal command exits, the handler closes the
browsers that command opened (none) and stops browser processes whose owning Hermes process is gone, as
any Hermes command does on exit. A running gateway's browsers have a live owner, so the handler leaves
those browsers alone.
`hermes confidential allow` and `status --verbose` import only the tool modules the lock recorded. Those commands fall
back to the full import, and its cache rewrite, only when a recorded tool is still missing after that.

| Path | Contents |
|---|---|
| `plugin-data/confidential-mode/ledger.sqlite` | The ledger. The ledger holds one row per observed send, refusal, question, answer, lock, unlock, session start and session end, verification (with the captured attestation evidence), pin event, breach and compaction. Rows hold hosts, byte counts, verdicts and decisions only. That is still a metadata trail, and a shared receipt shares it. Rows hold no prompt or response text. `Ledger.append` rejects any row whose details carry one of these keys at any depth: `messages`, `prompt`, `prompts`, `request`, `input`, `instructions`, `system`, `content` or `contents`. |
| `plugin-data/agent-plugin-confidential-mode-<digest>/state.json` | `ctx.state`, Hermes' per-plugin key-value store. The state holds the locked flag, the tier, the time of locking, the routing-config fingerprint and the list of breached sessions. |
| The same directory, `pins.yaml` | Version 3 of the pins file: for each vendor and identity, the approved entries and the pending entries. The plugin writes a pending entry when a verification finds a CVM or build that no approved entry covers. The plugin turns pending entries into approved entries only on an explicit Approve from you. The only exception is the platform-only policy, `confidential.pins.auto_approve_platform_only`, which is off by default and applies to Tinfoil only. Beside it: `pins.yaml.lock` (empty; it serialises writes between processes) and, after an upgrade, `pins.yaml.v2.bak` (the version-2 file as it was before the first version-3 write). |
| `plugin-data/confidential-mode/evidence/blobs/` | Large pieces of NEAR evidence (each docker-compose, compose-manager attestation, TDX quote and Intel Trust Authority token), one file each, named by its SHA-256. A ledger row names the files it uses. A file no row names is deleted by a later evidence write once it is more than 24 hours old. |
| The same directory as `state.json`, `pins/composes/` | The docker-compose files fetched for NEAR entries, each named `<sha256>.yaml` by its content hash, and (from `pins review`) `commit-<sha>.json` with each commit's GitHub metadata. |
| The same directory, `allowlist.yaml.lock`, `grants_revoked.json`, `grants_revoked.json.lock` | `allowlist.yaml.lock` and `grants_revoked.json.lock` are empty lock files that serialise writes between processes. `grants_revoked.json` holds the most recent revoke records (at most 200) and, per tool, the latest record naming the tool. A running gateway reads the file before each tool decision, and the tool gate asks Hermes under an approval key derived from that latest record. |
| The same directory, `lock-transition.lock` | Empty. A lock or an unlock holds it, so two processes never lock or unlock the profile at the same time. |
| The same directory, `allowlist.yaml` | This lock's tool identities: each tool's name, toolset, handler module and handler name. The file also holds the tools you allowed with `/confidential allow`, tagged with the lock's identity. After a restart, the plugin rebuilds the allowlist from this file. `/confidential off` deletes it, so additions never outlive the lock. |
| The same directory, `tinfoil_user_cache_secret` | A random 32-byte secret, stored as hex with file mode 0600. The SDK sends it as `user_cache_secret`, which keeps Tinfoil's prompt cache separate for you. The SDK's own default location is `~/.tinfoil/user_cache_secret`. The plugin never uses that path. |
| The same directory, `trust-roots/<sha256>.json` | The Sigstore trust root used at verification. Each distinct trust root is stored once, named by the hash of its content. The evidence in the ledger also carries the trust root's bytes, so a receipt replays offline on any machine. The evidence records no local path. |
| The same directory, `modes-checked` | The commit for which the plugin last set mode 0600 on every file in both data directories. The walk runs again on a new commit, or when the ledger, `pins.yaml` or `allowlist.yaml` has another mode. |
| The same directory, `loaded-commit` | The commit that last started here. The plugin prints its start-up progress lines on the first start of a new commit only ([GUIDE.md, Install in detail](GUIDE.md#install-in-detail)). |
| The same directory, `sdk-cache/` | The on-disk caches of the tinfoil SDK and of sigstore-python, redirected here. The next section explains how. |

**Tool grants from a `once` answer are held in memory, not on disk.** Under the default
`confidential.tools.ask: once_per_lock`, an exact `once` answer to a tool prompt grants that tool for
the rest of the lock, in the conversation that answered only. The plugin keeps each grant in the
memory of the process that asked, as the lock's identity, the conversation (Hermes' approval session
key and the agent's session id), the tool name and the id of the ledger row that recorded the answer.
Another chat, user or subagent has another key or session id and is asked again. No file holds the
grants: a restart or a second process asks again. A grant for an earlier lock never matches, so
every grant ends at unlock, and `/confidential revoke <tool>` drops the tool's grant in every running
process that reads the revoke record. Under yolo, approvals off or an unattended run (one-shot, cron,
an unattended platform) the plugin refuses the call before looking at a grant. The tool prompt
writes three kinds of ledger row: a `tool_asked` row for the ask (with the prompt line and the size);
a `tool_allowed` row for an answer of `once`, `session` or `always`, or a `tool_refused` row for any
other answer; and, for each later call a grant lets through, a `tool_allowed` row with decision
`lock_grant`, the call's size, and `grant_row` set to the id of the answering row. These rows hold the
tool name, the call id and byte counts, never the call's arguments.

### SDK cache redirect

By default, the two libraries cache in your user directories.

- tinfoil 0.14.2 computes its cache path with platformdirs when it is imported. On macOS the path is
  `~/Library/Caches/tinfoil`. On Linux it is `~/.cache/tinfoil`. The cache holds Sigstore bundles,
  AMD VCEKs and Intel collateral.
- sigstore-python keeps TUF metadata in `~/Library/Application Support/sigstore-python/tuf` and
  `~/Library/Caches/sigstore-python/tuf` on macOS. On Linux it uses
  `~/.local/share/sigstore-python/tuf` and `~/.cache/sigstore-python/tuf`.

Before its first verification, the plugin re-points all of these under `sdk-cache/` in its data
directory. The plugin does this in two ways.

1. The plugin assigns new values to the SDK's module constants: `tinfoil.github._GITHUB_CACHE_DIR`,
   `verify_sev._VCEK_CACHE_DIR` and `collateral_tdx._TDX_CACHE_DIR`.
2. The plugin replaces sigstore-python's `sigstore._internal.tuf._get_dirs`.

This change applies to the whole process. If something in the same process used the SDK before the
plugin's first verification, it may already have written to the default paths.

These are assignments into a third-party SDK. The assignments are not changes to Hermes core.

Evidence capture and offline replay also wrap attributes for a bounded window
(`confidential_mode/verify/_sdkpatch.py`). In a live process the window is one Tinfoil attestation (each
verification, and each attestation the SDK runs when it builds a pool or re-verifies after a key
rotation): the SDK's fetch functions and, while the SDK reads its latest release, `requests.Session.request`.
A replay, which only the `hermes confidential replay` command runs, also wraps
`urllib.request.urlopen`, urllib3's `HTTPConnectionPool.urlopen` and the httpx transports, for the
offline network ban. Each wrapper is installed when the window opens and the original attribute is put
back when the last open window for that attribute closes. Inside the window the wrapper is shared by the whole
process, Hermes' own `requests` calls included, and does nothing for any thread but the one that opened
the window: another thread's call runs the original function unchanged. For the length of each replay
only, the plugin also replaces the `datetime` global of tinfoil's `collateral_tdx` and `cert_utils`
modules and `verify_sev.crypto` with versions that read a clock pinned on the replaying thread (the
capture time) and behave as the originals on every other thread; the original attributes are put
back when the last open replay window closes. On the plugin's own `SecureClient` instance, and on no
other object, the plugin sets the instance attributes `verify`, `_build_ehbp_sync_transport` and
`_build_ehbp_async_transport` (the verification guard and the pinned transports); the SDK class is
unchanged. Hermes core attributes are never wrapped.

## Credentials

The plugin uses two secrets, one for each attested vendor. `TINFOIL_API_KEY` is for the
`attested-tinfoil` provider. `NEAR_AI_API_KEY` is for the `attested-near` provider. You need only the
key of the vendor you use. The `on-host-only` tier needs neither.

`plugin.yaml` declares `TINFOIL_API_KEY` in `requires_env` and `NEAR_AI_API_KEY`, `OPENROUTER_API_KEY`
and `NOUS_API_KEY` in `optional_env` (the last two for a presence check only, under "Environment
variables").
NEAR's key is optional because most installs use one vendor, and an install-time prompt for an unused
key serves no purpose. Each key is also in `env_vars` on its provider profile. Hermes therefore
resolves it like any provider key and passes it to `create_client`.

When Hermes passes no key, the client and `hermes confidential setup` read it through
`agent.secret_scope.get_secret`. That function honours the active profile. The plugin never reads
`os.environ` for either key itself. NEAR's attestation requests carry no key. Only inference and
signature requests to NEAR carry `NEAR_AI_API_KEY`.

The plugin reads no `.env` file, no `auth.json`, nothing under `~/.tinfoil`, and no keychain, and reads no
key from `os.environ` itself. The plugin stores no credential.

The prompt-cache secret described above is generated by the plugin. The secret is not a credential for
anything.

## Processes and threads

The plugin runs no shell commands and starts no subprocesses or background processes.

The plugin starts daemon threads of five kinds. Four kinds are short-lived. One thread runs the
own-host-name lookup described under Network. For NEAR, one thread fetches the compose files of a
staged model entry from GitHub. Another, for both vendors, records which approved entries a
verification matched, and writes `pins.yaml`. The fourth kind runs each attestation. The sequence for an attestation is this:

1. `create_client`, or the attested check on a turn, needs a fresh verification.
2. The plugin starts the thread, which runs the verification.
3. The caller waits at most `confidential.verify_wait_seconds`, 20 seconds by default.
4. If the verification is not done by then, the plugin refuses the turn. The thread keeps running
   and finishes the verification.
5. The thread exits when the verification ends.

The fifth kind is the background re-verification thread, one per attested provider (Tinfoil and
NEAR), named `confidential-refresh-<provider>`. The thread is long-running: it lives as long as the
profile stays locked on the attested tier and calls keep using the verification. The thread starts
after a call whose verification the pins accepted. The thread sleeps until
`confidential.verify_refresh_lead_seconds` (60 by default) before the verification ends
(`confidential.verify_ttl_seconds`, 300 by default), then runs one verification over the network, to
the same attestation hosts as any other verification. The thread refreshes a verification only when a
call used that verification within two lead periods of its end (two minutes at the default). After a
longer idle period the thread makes no request and exits when the verification ends. A call that uses
the verification includes a model call and a `status` or `check` command.

While the refresh thread waits on the network, it holds no lock that a send already set up takes. On Tinfoil,
the SDK checks one verification at a time, so a send that must attest by itself waits for a capture
in progress. Such a send is the first one on a new event loop, or one after the enclave rotated a key.
The thread checks the lock state at least every five seconds. The refresh thread stops on unlock, when the profile is
no longer locked, when the adapter closes, and when an HTTP 421 or a TLS certificate change drops the
verification. A capture already in progress then finishes, and its result is discarded. Each
verification it runs writes a `verify_ok` or `verify_fail` ledger row with `source: background`. A
verification the pins did not accept is written with `accepted: false`. The receipt marks it "NOT
ACCEPTED" and never counts it for a send.

Writes to `pins.yaml`, `allowlist.yaml` and `grants_revoked.json`, and every lock and unlock, take an
advisory lock file (`flock`) so that two processes never interleave them. A lock file that cannot be opened
or locked refuses the change. On a platform without the `fcntl` module, which is Windows, only a lock
inside one process is taken, so two processes on Windows are not kept apart.

### Environment variables

The plugin reads these environment variables:

- `TINFOIL_API_KEY` and `NEAR_AI_API_KEY`, through Hermes (provider `env_vars`, or
  `agent.secret_scope.get_secret`), never from `os.environ` directly;
- `OPENROUTER_API_KEY` and `NOUS_API_KEY`, whether each is set and nothing else, through
  `agent.secret_scope.get_secret`, when you lock or run `check`: the preflight reports whether Hermes'
  side-call fall-through to OpenRouter or Nous would have a credential. The plugin sends neither key
  anywhere. Both are declared under `optional_env` in `plugin.yaml` and the catalog entry;
- `TERMINAL_ENV`, to resolve the terminal backend as Hermes does;
- `HERMES_HOME`, to tell whether a path a tool call names lies in the Hermes home;
- `TERMINAL_CWD`, to find a script file a locked tool call runs;
- `CONFIDENTIAL_MODE_PROGRESS`, which turns the start-up progress lines on or off;
- `CONFIDENTIAL_MODE_NO_FETCH`, which turns off the GitHub compose fetches;
- `XDG_CONFIDENTIAL_MODE_TOOL_PROCESS`, the tool marker below.

The plugin sets one environment variable in the Hermes process, `XDG_CONFIDENTIAL_MODE_TOOL_PROCESS`,
to that process's id, before the first tool runs. Terminal, process_manage and execute_code children
inherit it. Every approval prompt refuses in a process whose variable names another process. Some
routes still reach the prompt, such as a nested chat attached through the gateway.
[LIMITATIONS.md](LIMITATIONS.md), section 15, lists them.

## Hermes surfaces used

The plugin registers the following through `ctx`, Hermes' plugin context object.

- **Hooks:** `pre_tool_call`, `post_approval_response`, `pre_llm_call`, `pre_api_request`,
  `pre_auxiliary_call`, `post_auxiliary_call`, `on_session_start`, `on_session_end`,
  `post_compaction`, `pre_gateway_dispatch` and `transform_llm_output`. `pre_gateway_dispatch`
  rewrites a `/model` or `/moa` command sent through the gateway while locked into a refusal.
  `transform_llm_output` changes a reply only once per lock: it appends one line to the reply of the
  turn that first sent an image to NEAR's gateway in plaintext. Every other reply passes unchanged.
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

Rule 9 of the Hermes plugin catalog (`plugin-catalog/README.md` in Hermes) says a listed plugin extends
Hermes only through public surfaces and must not replace, wrap or rebind core functions, methods,
module attributes or private dicts in place; `hermes plugins validate` warns on each import of an
undocumented core module. Every import below is lazy, which means it happens inside a function, not
when the plugin loads.

Every import of an undocumented core module is in one file, `confidential_mode/hermes_compat.py`. Each
name there has its own accessor function, whose docstring names the Hermes symbol, the Hermes commit it
was checked against (84a0301), what the plugin uses it for, and what the plugin does when the symbol is
missing. A Hermes release that moves or renames one of these names breaks that file only. The other
modules import only the documented plugin surface directly: `tools.registry`, `agent.secret_scope`,
`providers`, `providers.base`, `hermes_cli.config` and `plugins.plugin_storage`.
`tests/unit/test_hermes_compat.py` fails when any other plugin module imports an undocumented core
module.

| Module | Names | Why |
|---|---|---|
| `tools.approval` | `request_tool_approval`, `is_approved`, `_yolo_active`, `_presence`, and, in `/confidential status` and `pins`, `_lock`, `_session_approved`, `_permanent_set` (read only) | To ask before an off-host tool call. To detect bypass states that would approve a call without asking. To list the remembered grants stored under the plugin's own rule key. |
| `tools.approval_context` | `get_current_session_key`, `set_current_observability_context`, `reset_current_observability_context`, `_get_approval_mode` | To get the session key for remembered grants and for the conversation a once-per-lock grant covers. To tie an approval answer to its tool call. To detect `approvals.mode: off`. |
| `tools.registry` | `registry`, `discover_builtin_tools` | To build the tool allowlist at lock, and to record each tool's handler identity. A lock from the `hermes confidential` command line first loads the built-in tools, as a chat process would. |
| `agent.error_classifier` | `_CONTEXT_OVERFLOW_PATTERNS` | To recognise a NEAR context-length error, so that Hermes can compress the context as it would for any provider. |
| `agent.auxiliary_client` | `_RUNTIME_MAIN_CONTEXT`, `_RELAY_AUX_CALL_CONTEXT` | To read the live main runtime on each locked turn. Auxiliary tasks set to `auto` follow the live runtime, not the config. The second name gives a NEAR auxiliary send its purpose (`aux:<task>`) and session in the ledger. Without it, such a send takes the purpose and session of the turn around it, or reads "unattributed" with an empty session. |
| `agent.secret_scope` | `get_secret` | To resolve `TINFOIL_API_KEY` and `NEAR_AI_API_KEY` for the active profile, and to check whether `OPENROUTER_API_KEY` or `NOUS_API_KEY` is set. |
| `hermes_cli.env_loader` (in `scripts/near_first_contact.py` only) | `load_hermes_dotenv` | To load the `HERMES_HOME` env file before the script reads `NEAR_AI_API_KEY` through `get_secret`, as `hermes` does at start-up. Hermes' loader (84a0301): can rewrite `<HERMES_HOME>/.env` in place (a UTF-16 file becomes UTF-8, NUL characters are stripped, malformed lines are normalised); loads every variable the env file sets into the script's process environment, overriding exported values, and removes exported provider-selection variables Hermes manages that the env file does not set; loads `<HERMES_HOME>/.op.env`, without overriding, when that file exists and `OP_SERVICE_ACCOUNT_TOKEN` is unset; when the install has an administrator-managed scope with its own `.env`, rewrites that file the same way and loads it last, overriding every other value; writes `config.yaml`'s `terminal.*` settings into the process environment; publishes the deployment names into the environment and boots the config backend the home selects (a remote backend fetches the home's config); queries no external secret source (`load_external_secrets=False`); and does nothing at all in safe-worker mode. Every change to the environment ends with the process. The script itself never writes any of these files. |
| `tools.terminal_tool`, `tools.terminal_tool_lifecycle`, `tools.terminal_scope` | `_get_env_config`, `_active_environments`, `_env_lock`, `get_active_env`, and `terminal_env` as a fallback | To read the terminal backend a terminal, code or file tool call would run on, the way Hermes' tools resolve it, and the backend of the environment Hermes has cached for the task. The plugin blocks the call, and refuses to lock, unless both are `local`. |
| `hermes_cli.commands` | `resolve_command` | To recognise `/model` and `/moa`, and their aliases, in `pre_gateway_dispatch`. |
| `tools.mcp_tool`, `tools.mcp_tool_config`, `tools.mcp_tool_scope` | `_lock`, `_servers`, `_mcp_tool_server_names` (read only), `_load_mcp_config`, `_key_name` | To map an MCP tool to its server, and to read whether that server is a URL or an on-host command. |
| `tools.delegate_tool_config` | `_load_config` | To read the delegation backend and route keys for `delegate_task`. |
| `providers`, `providers.base` | `register_provider`, `get_provider_profile`, `ProviderProfile` | To register `attested-tinfoil` and `attested-near`, and to check at lock time that the locked profile is visible in the process. |
| `hermes_cli.config`, `hermes_cli.config_defaults` | `load_config_readonly`, `load_config`, `read_raw_config`, `save_config`, `DEFAULT_CONFIG` | To read the config, and to list the built-in auxiliary tasks. A revoke uses `read_raw_config`, `save_config` and `load_config` (to confirm) to remove the plugin's own `command_allowlist` entries and nothing else. |
| `hermes_cli.plugins` | `get_plugin_manager`, `get_plugin_auxiliary_tasks` | To tell plugin tools from built-in tools, and to include plugin-registered auxiliary tasks in the preflight. |
| `plugins.plugin_storage` | `plugin_db`, `plugin_data_dir` | To open the ledger database. |
| `hermes_yaml` | | To read and write `pins.yaml` and `allowlist.yaml`. |
| `tools.*` built-in tool modules named in `allowlist.yaml` | (the module) | A lock rebuilt in a `hermes confidential` command-line process imports the tool modules the lock recorded, so their tools register. The names come from the lock file, so the validator does not count these imports. |

`hermes plugins validate` reports 31 of these import sites as private core imports, all in
`confidential_mode/hermes_compat.py`: each undocumented name is imported at one line, so each site is one
name, the private attributes read (`approval._lock`, `_session_approved`, `_permanent_set`,
`mcp_tool._servers`) included. This is a warning, not a failure.

The plugin makes no in-place edit of Hermes core (rule 9). Every private name above is read, never
written. Two places where an edit would have been the short way:

- A revoke leaves Hermes' session approvals where they are. The tool gate asks Hermes under the rule key
  `confidential-mode:tool:<tool>` until the first revoke naming the tool, and under
  `confidential-mode:tool@<generation>:<tool>` after one, where the generation is derived from the
  latest revoke record in `grants_revoked.json`. A `session` or `always` answer Hermes holds for the
  older key then matches nothing the plugin asks for. When the record cannot be written, the reply says
  that a grant Hermes itself holds for this session ends when the session ends or Hermes restarts.
- A terminal command that imports Hermes' built-in tool modules leaves their exit handlers registered
  (see "What it writes in its own data").

The imports are the price of classifying tools and approvals without a public seam. The
upstream roadmap in [LIMITATIONS.md](LIMITATIONS.md) lists the seams that would remove them.

## What locked mode blocks

You lock with `/confidential on on-host-only` or `/confidential on attested`. The lock applies to the
whole profile. The guide's chapter [What happens while locked](GUIDE.md#what-happens-while-locked)
states every refusal and block. In summary, while locked the plugin refuses, before any byte is
sent:

- main-loop model calls whose destination is off-tier, and fallbacks;
- sends to an unverified or unpinned enclave, to a pin with no consent record, and on a verification
  whose `verify_ok` row could not be written (attested tier);
- NEAR requests the encryption cannot cover (attested-near);
- every turn after the routing config changed, and every turn whose live main runtime is off-tier;
- off-host tool calls you did not approve (by default an exact `once` covers the tool for the rest of
  the lock; `confidential.tools.ask: each_call` asks every call; under yolo, approvals off or an
  unattended run every off-host call is refused unless you added the tool with `/confidential
  allow`), and tool calls that run the plugin's own commands or
  write its state files;
- `cronjob_manage`, tools from off-tier MCP URL servers, tools not registered or changed since the
  lock, and `delegate_task` calls that name a route. The plugin refuses to lock while any auxiliary task, vision, delegation, TTS, the memory provider or an MCP
URL server would leave the tier, and names the YAML key to change.

## What locked mode does not block

Each item names its section of [LIMITATIONS.md](LIMITATIONS.md) where it has one.

- **Auxiliary calls at runtime** (section 1). The preflight makes sure that none is configured
  off-tier, and each turn checks the live runtime. An auxiliary call that goes off-tier anyway is
  recorded as a `breach` row. The plugin cannot stop the bytes.
- **Shell and code execution** (section 3). `terminal`, `process_manage` and `execute_code` run on
  this host on the `local` terminal backend and can reach the network. The plugin does not inspect
  their network access; it scans their text only for its own commands (section 15).
- **MCP servers launched as a command on this host** (section 4).
- **Everything while Hermes runs as a safe worker** (section 5).
- **Other plugins in the same process** (section 6).
- **Network metadata, DNS and the host operator** (section 9).
- **Hermes' start-up model-list request on a drifted runtime** (section 10). The request carries an
  API key and no conversation text.
- **The messaging platform you talk to Hermes over**, such as Telegram or Discord.

## Isolation

The plugin supports `in_process` isolation only.

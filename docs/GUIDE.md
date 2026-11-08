# Hermes Confidential Mode guide

This guide is the long form of the [README](../README.md). The guide covers how the plugin works, what each
tier accepts, how pins, receipts and replay work, and every command and config key. Each chapter ends
with a short "Limits" note; [LIMITATIONS.md](LIMITATIONS.md) is the complete list of limits, and
[DISCLOSURE.md](DISCLOSURE.md) lists what the plugin touches on your machine and on the network.
[COSTS.md](COSTS.md) says what locking costs in latency, quality and task success.

## Contents

1. [The problem](#the-problem)
2. [What the plugin does](#what-the-plugin-does)
3. [Comparison with earlier approaches](#comparison-with-earlier-approaches)
4. [Install in detail](#install-in-detail)
5. [Glossary](#glossary)
6. [Threat model](#threat-model)
7. [Tiers](#tiers)
8. [Look before you lock](#look-before-you-lock)
9. [Locking](#locking)
10. [Pins](#pins)
11. [The attested tier with NEAR AI](#the-attested-tier-with-near-ai)
12. [Receipts and replay](#receipts-and-replay)
13. [Fewer hosted parties without locking](#fewer-hosted-parties-without-locking)
14. [Config](#config)
15. [For developers](#for-developers)

## The problem

A Hermes turn can carry your conversation off the machine along six routes. Picking a verified
provider for the main chat covers the first route and nothing else.

1. **The main model call.** Every turn sends the conversation to the provider in `model.provider`.
2. **Fallbacks.** When the main provider answers with a rate limit (429), a server error (5xx) or an
   authentication error, Hermes switches to the next entry in `fallback_providers`, often
   OpenRouter, with your full context. Hermes mentions the switch in one line of output.
3. **Auxiliary tasks (side calls).** Hermes 84a0301 has 19 built-in side jobs, plus any a plugin
   registers: context compression, title generation, vision, the smart-approval classifier, MCP
   helpers, memory query rewriting, background review, the curator, the monitor, the goal judge, the
   group router, the kanban decomposer, TTS audio tags, voice chat and more. Each job is a separate
   request carrying some of your text, routed under `auxiliary.<task>`. The default route, `auto`,
   sends the task to your main provider first, then to your fallbacks. Vision's `auto` route tries OpenRouter, then Nous, then DeepInfra
   when the main model can't take images, and Hermes describes an image that arrives through the
   gateway with the vision task even when no tool is called.
4. **Tools.** Web search and fetch, the browser, messaging, media tools, other plugins' tools and
   remote MCP servers send data to other machines. (MCP, the Model Context Protocol, is a standard
   way to plug external tool servers into an agent.) `delegate_task` does too when it hands work to
   another profile or backend. Shell and code execution run on this host and can reach the network
   on Hermes' `local` terminal backend; on another backend, such as `ssh` or `modal`, shell, code
   execution and the file tools run on that other machine.
5. **The memory provider.** A hosted memory service receives context on every turn.
6. **The messaging platform.** Telegram, Discord and the other messaging platforms see your messages
   before Hermes does. No plugin can close this route.

![Figure 1. With a verified provider alone, the main chat is verified and five other routes carry
text to hosts nobody checks.](images/routes-figure-1-verified-provider-alone.svg)

## What the plugin does

The plugin does four things for a Hermes profile.

1. **It shows you every route.** It logs every model call Hermes makes, with the host and the byte
   count; the log never holds the text. The log is a file on this machine, and you can watch it live before you
   lock anything ([Look before you lock](#look-before-you-lock)).
2. **It locks the profile to one tier.** The `on-host-only` tier accepts loopback and hosts you list.
   The `attested` tier accepts a Tinfoil enclave, or NEAR AI Cloud's gateway and models, whose build
   you approved. Before locking, the plugin checks every configured route: the main model, every side
   call, delegation, text to speech, MCP servers, fallbacks, memory and the terminal backend. If any
   route leads off-tier, the lock is refused and the plugin names the key to change ([Tiers](#tiers),
   [Locking](#locking)).
3. **While locked, it guards four of the five other routes.** Side calls must resolve to the tier and
   are rechecked every turn. Fallbacks are refused, and a failed request ends the turn. Tools outside the
   on-host list ask you the first time each runs during a lock. Memory must be the
   built-in store. Shell and code execution stay open.
4. **It renders a receipt for any session.** The receipt lists where the text went, attaches the
   enclave evidence captured at each verification, and ends with fixed paragraphs naming what it
   can't prove. Anyone holding the JSON form can replay the evidence offline; for NEAR, the replay
   also re-checks each response signature ([Receipts and replay](#receipts-and-replay)).

![Figure 2. With the plugin, shown for Tinfoil: preflight checks every configured route, side calls
go to the verified enclave, fallback is refused, tools ask, memory stays on the host, shell and code
stay open on this host, and a ledger records model sends and tool
answers.](images/routes-figure-2-with-the-plugin.svg)

**Limits.** Shell, code execution and MCP servers started as a command on this host run unchecked
([LIMITATIONS 3](LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected),
[4](LIMITATIONS.md#4-mcp-command-servers-are-not-inspected)). A side call that goes off-tier
mid-turn is recorded as a breach, not stopped
([LIMITATIONS 1](LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution)). A receipt is
the plugin's own record; only its evidence can be checked by someone else
([LIMITATIONS 6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process)).

## Comparison with earlier approaches

Five earlier pull requests tried to add confidential inference to Hermes core. Each added a verified
provider for the main chat. Four were closed under the policy that provider integrations ship as
plugins; the first, #7045, was closed as too large for core with a hard Tinfoil dependency. This plugin
ships that verified provider as a plugin, and adds the routing checks, the tool gate, the ledger and
the receipt, so the claim covers every model call in the session rather than one endpoint.

"Yes" means present and enforced, "Partial" means present with a gap, and "No" means absent. The pull
requests are Hermes #4231 (Venice), #5015 (RedPill), #7045 (Tinfoil), #12201 (NEAR AI and Phala) and
#31613 (Tinfoil).

| Capability | #4231 | #5015 | #7045 | #12201 | #31613 | This plugin |
|---|---|---|---|---|---|---|
| Verified main-chat provider | Partial | No | Yes | Partial | Partial | Yes: Tinfoil and NEAR |
| Offline replay of the evidence | No | No | No | No | No | Yes |
| Build pins with a human's consent | No | No | No | Partial | No | Yes: one entry per NEAR virtual machine configuration |
| Review bundle for a second reviewer | No | No | No | No | No | Yes |
| Model signing key bound to the report | Yes | No | No | Yes | No | Yes, not pinned |
| TLS bound to the attested key on every send | No | No | Yes | Partial | Partial | Yes: pinned per send on NEAR and Tinfoil |
| Check of what NEAR deploys after launch | No | No | No | Yes | No | Yes: the operator's reported log, bound in a hardware quote, not a measurement |
| NVIDIA GPU evidence | No | No | No | Yes | No | No |
| Request body encryption | Partial | No | No | Partial | Yes | Yes: whole body on Tinfoil; all fields NEAR covers |
| Signed responses checked | No | No | No | No | No | Yes on NEAR |
| Side-call routing check | No | No | Partial | No | No | Partial: a stray call is recorded, not stopped |
| Fallback refusal | No | No | Yes | No | No | Yes |
| Off-host tool gate | No | No | No | No | No | Partial: shell and code stay open |
| Memory check | No | No | No | No | No | Yes |
| Per-send ledger and receipt | No | No | No | No | No | Yes |

## Install in detail

The [README](../README.md#install) has the short version. The plugin is tested against Hermes commit
84a0301 and version 0.14.2 of the tinfoil Python SDK.

```
hermes plugins install https://github.com/ainsleys/hermes-confidential-mode
hermes plugins enable confidential-mode
hermes confidential status | grep '^Plugin:'
```

1. **Install.** `hermes plugins install <url>` clones the repository into Hermes' plugin directory.
   Once the plugin is in the Hermes catalog, `hermes plugins install confidential-mode` works too.
2. **Enable (required).** Without `hermes plugins enable confidential-mode`, every
   `hermes confidential` command fails with "'confidential' is not a hermes command". Hermes, not the
   plugin, runs this step: it installs the dependencies in the plugin's `pyproject.toml` (`tinfoil`
   0.14.2, `pynacl` 1.6, `sigstore` 4.5, and what they need, such as `cryptography`, `pyopenssl`,
   `requests` and `urllib3`) into Hermes' environment. The step can take a few minutes, and Hermes prints
   only "Resolving Python dependencies" and "Installing Python dependencies" meanwhile. Set
   `HERMES_VERBOSE=1` to watch the installer.
3. **First start.** The first Hermes command after enabling loads the plugin. On a terminal, the first
   start of each installed commit prints one line per start-up phase, such as
   `confidential-mode: registering the NEAR provider (loads the OpenAI SDK)... ok`; later starts print
   nothing. `CONFIDENTIAL_MODE_PROGRESS=1` prints the lines on every start, with or without a
   terminal, and `CONFIDENTIAL_MODE_PROGRESS=0` turns them off. `hermes confidential on` and
   `hermes confidential allow` print `confidential-mode: discovering tools... 78 found` on a terminal.
4. **Check which commit is installed.** `hermes confidential status | grep '^Plugin:'` prints a line
   such as `Plugin: confidential-mode 0.1.0 (commit 3c20cf4a1b2c (git checkout))`, the commit the
   installed copy's `.git` names, so it changes after `hermes plugins update`. Compare it with the
   commit you meant to install. Receipts carry the same value. The check doesn't detect local edits,
   and anyone who can write the installed copy can change what `.git` says.
5. **Set the vendor's API key.** The attested tier needs `TINFOIL_API_KEY` for Tinfoil or
   `NEAR_AI_API_KEY` for NEAR AI Cloud, exported in the shell that starts Hermes, written to
   `<hermes home>/.env`, or given through `model.api_key`. The plugin reads keys only through Hermes'
   secret scope (`agent.secret_scope.get_secret`), so a key added only with `hermes auth` (Hermes'
   credential pool) reads as not set and the lock is refused until you export the key or write it to
   `<hermes home>/.env`. Observe mode and the
   `on-host-only` tier need no key. Verification and pin approval work without a key, because the
   attestation endpoints are public, so the lock and `check` test the key of each vendor a route uses
   and refuse while one is missing. The test runs when you lock and in `check`, not on every turn. The lock and `check` show "set", "not set" or "not readable in this scope" (a
   multiplexed gateway with no profile scope), never the key. If a later turn's process can't read
   the key, the plugin refuses that call with "vendor key unreadable" and records a refusal, not a
   breach.
6. **Set up and lock.** Run `hermes confidential setup --model <model id>`, or
   `hermes confidential setup --vendor near --model <model id>`, merge the config block it prints,
   then run `hermes confidential check --tier attested` and `hermes confidential on attested`.
7. **Leave `plugins.isolation` at `in_process`.** Under host isolation Hermes can't see the attested
   provider, and the lock is refused.

If you run Hermes from a source checkout with `uv run --no-sync`, the enable step doesn't run there,
so install `pynacl` yourself ([RUNNING_TESTS.md](RUNNING_TESTS.md)).

### Where the plugin keeps its files

The plugin keeps its files in two directories under `<hermes home>/plugin-data/`, one per Hermes
interface it uses. `hermes confidential status` prints both paths.

- `plugin-data/confidential-mode/` is Hermes' plugin storage: the ledger, `ledger.sqlite`, and the
  NEAR evidence files under `evidence/blobs/`.
- `plugin-data/agent-plugin-confidential-mode-<hash>/` is Hermes' per-plugin state: `state.json` (the
  lock), `pins.yaml`, `allowlist.yaml`, `grants_revoked.json`, the SDK caches and the Tinfoil user
  cache secret.

Files are created with mode 0600. The plugin sets that mode again on existing files once per
installed commit, and whenever the ledger, `pins.yaml` or `allowlist.yaml` has another mode.
[DISCLOSURE.md](DISCLOSURE.md#files) lists the files and what each holds.

### Upgrading

Restart every Hermes process that loads the plugin after you upgrade it (the gateway, and any CLI or
TUI session) before you lock or unlock from any of them. The lock records a fingerprint of the
routing config, and this version adds the terminal backend and `confidential.on_host.extra_hosts` to
that fingerprint. A process on the other version reads the lock as a changed config, refuses every
turn and marks the session breached.

A lock made by an earlier version keeps working: this version recognises the old fingerprint, so the
upgrade alone records no breach, and the terminal-backend checks still apply on every turn. Two cases
need a fresh lock (`/confidential off`, then `/confidential on <tier>`): a lock made with a non-empty
`extra_hosts` list, and an on-host lock whose model sits at a private-range address, which now has to
be listed in `extra_hosts` ([`on-host-only`](#on-host-only)).

This version writes `pins.yaml` as version 3. Before the first write over a version-2 file it saves
the old file as `pins.yaml.v2.bak`. Your Tinfoil pin and any pending Tinfoil pin carry over; NEAR asks
once ([Pins for NEAR](#pins-for-near)). To go back, stop Hermes and copy `pins.yaml.v2.bak` over
`pins.yaml`: the previous version can't read version 3, and this version never writes version 2.

**Limits.** The installed-commit check doesn't detect local edits. Processes on mixed plugin versions
disagree about the lock ([LIMITATIONS, smaller gaps](LIMITATIONS.md#smaller-gaps-disclosed)).

## Glossary

**Hermes, the harness.** Hermes Agent runs the loop around a language model: it sends your messages
to the model, runs the tools the model asks for, and sends back the results. Everything here happens
inside the Hermes process.

**Profile.** A separate Hermes home directory with its own `config.yaml`, keys, memory, sessions and
plugin data. A lock applies to one profile and every session on it.

**Session.** One conversation, with its own session id. A receipt covers one session.

**Gateway (Hermes).** The part of Hermes that connects messaging platforms, such as Telegram and
Discord, to the agent. A "gateway surface" is a chat reached that way; the CLI and the TUI are the
other surfaces. NEAR's gateway is a different thing, defined below.

**Provider and fallback.** A provider is the service Hermes sends model calls to (`model.provider`).
A fallback is a second provider under `fallback_providers` that Hermes switches to on an error.

**Auxiliary call (side call).** A model call for a side job rather than the main reply, such as
compressing context, titling a session or describing an image. Each side job is an auxiliary task
with its own route under `auxiliary.<task>`.

**Tier, in-tier, off-tier.** A tier is the rule for which destinations are acceptable:
`on-host-only` or `attested` (`zero-retention` is reserved). A destination the rule accepts is
in-tier; any other is off-tier.

**On-host and off-host.** On-host means on the machine that runs Hermes; off-host means anywhere
else. An on-host tool, such as `read_file`, works on this machine; an off-host tool, such as
`web_search`, sends data elsewhere.

**Lock.** To lock a profile is to hold it to one tier. While locked, the plugin refuses off-tier model
calls and gates off-host tools. The time from a lock to the next unlock is a lock period. The word is
"lock" because "sealing" already names an enclave hardware feature.

**Safe-worker mode.** A mode for managed Hermes worker processes in which Hermes loads no plugins.
Nothing in this plugin runs there.

**Preflight.** The check the plugin runs over your config before it locks. The preflight gives every route that
can carry conversation text a verdict, and names the key to change for each failure.

**Hook and middleware.** A hook is a callback Hermes calls at a named moment, such as
`pre_tool_call`; some hooks can return an instruction Hermes obeys, others only observe. Middleware
is code Hermes runs around an operation, which can refuse to pass it on. The plugin's middleware wraps
every main-loop model call (`llm_execution`) and every tool call (`tool_execution`).

**Ledger, row, breach.** The ledger is the plugin's SQLite log under your Hermes home. Each row
records one event (a send, a refusal, a question, an answer, a lock, a verification) with hosts, byte
counts and decisions, never prompt or response text. A breach row records an auxiliary call that went
off-tier while locked; it's a record after the fact, not a refusal.

**Receipt.** A rendering of the ledger rows for one session, as text or JSON.

**Allowlist.** The table the plugin builds at lock time: every tool registered in Hermes then, with
what the plugin will do for it (run, ask or block). Hermes' own `command_allowlist` is a different
list, of approvals Hermes remembers permanently.

**Enclave, TEE, CVM.** A trusted execution environment (TEE) is a CPU feature that runs a virtual
machine whose memory the CPU encrypts, so the host's operator can't read it. An enclave is one such
virtual machine. NEAR calls its enclaves CVMs (confidential virtual machines). A TD (trust domain) is
Intel's name for one TDX virtual machine.

**Platform.** The CPU vendor's TEE technology: AMD SEV-SNP or Intel TDX. Each produces a different kind
of hardware report. This guide says "messaging platform" for Telegram and the like.

**Attestation, measurement, fingerprint.** Attestation is an enclave proving what it runs, through a
report the CPU signs with a key only the CPU vendor's hardware holds. A measurement is a hash of the
code and configuration loaded into the enclave. A fingerprint is a short hash of a measurement. The
plugin records two for Tinfoil: the code fingerprint, from the vendor's signed release, and the
enclave fingerprint, from the hardware report.

**Collateral and VCEK.** The certificates and signed documents needed to check a hardware report. For
AMD, the main piece is the VCEK, the certificate for the signing key of the CPU that made the report.
For Intel, collateral includes signed security-version information and revocation lists.

**ACP command.** A delegation route that launches an external agent through the Agent Client
Protocol.

**TLS.** The encryption HTTPS uses. Whoever holds the server end of a TLS connection sees the headers,
sizes and timing, and, without EHBP, the body.

**Router (Tinfoil).** The enclave your Tinfoil requests connect to. Its code is published as
`tinfoilsh/confidential-model-router`, and it forwards each request to a model backend Tinfoil runs
behind it.

**Gateway (NEAR).** The server at `cloud-api.near.ai` that takes your request and passes it to a model.

**Pin.** Your recorded approval of an enclave build. A Tinfoil pin holds one router build's code and
enclave fingerprints. A NEAR pin is a set of approved entries, one per CVM configuration. While a pin
is in force, nothing is sent to an enclave no approved pin matches.

**Sigstore, Rekor, trust root, TUF.** Sigstore is a public software-signing service; Tinfoil's GitHub
Actions workflow signs each router release through it. Rekor is Sigstore's append-only transparency
log, where each signature has a log index. A trust root is the file of keys and certificates a
signature check starts from. sigstore-python refreshes its trust root through TUF (The Update
Framework).

**HPKE and EHBP.** HPKE (Hybrid Public Key Encryption) encrypts a message to a public key. EHBP (the
encrypted HTTP body protocol) is Tinfoil's transport: it encrypts each request body to a key the
attested enclave holds. EHBP doesn't encrypt headers or hide size and timing.

**Evidence and replay.** Evidence is the raw bytes captured during one verification. A replay re-runs
that verification later, offline, from the evidence alone.

## Threat model

> **Read this first.** If Hermes runs on someone else's machine, such as a cloud agent service or a
> rented VPS, that machine's operator can read every prompt before anything in this plugin applies.
> The plugin controls the routes out of the Hermes process. The plugin doesn't protect the process itself.
>
> **What it defends against**
>
> - **Your conversation going to a hosted provider or fallback you didn't mean to use.** Main calls
>   and fallbacks to an off-tier host are refused before any byte is sent. Side calls can't be stopped
>   at send time, so the plugin refuses to lock while one is configured off-tier and records a breach
>   if one strays.
> - **The vendor shipping a new enclave build without your consent.** If Tinfoil's router, or a NEAR
>   CVM, presents fingerprints no approved pin matches, every turn is refused until you approve.
>
> **What it doesn't defend against**
>
> - **Other code in the same Hermes process.** Another plugin can write ledger rows, write a pin or
>   patch this plugin's functions.
> - **You editing your own ledger.** A receipt is a report you make about yourself; it proves only what
>   its evidence proves.
> - **Shell and code-execution tools.** Their commands can open network connections, and the plugin
>   doesn't inspect them. The lock is refused on any terminal backend other than `local`
>   ([The terminal backend](#the-terminal-backend)).
> - **Tinfoil's own infrastructure.** The vendor's control plane and the model backends behind the
>   router; the attestation covers the router only.
> - **Connection metadata.** Tinfoil's network and hosting see request and response sizes, timing and
>   your IP address. The tinfoil SDK's `ehbp` transport, which the plugin uses, encrypts each request
>   body to the enclave's HPKE key and doesn't pin the TLS certificate itself, so the plugin pins it:
>   every inference connection must present the TLS key of the verified report the plugin accepted,
>   checked inside the handshake before any request byte leaves, so a TLS intermediary sees no headers
>   and no API key. A connection with another certificate is refused. The attestation fetch is not
>   pinned; its report is checked by its signatures. On NEAR the plugin pins TLS the same way.
> - **NEAR's gateway.** With request encryption on, the gateway still reads the model id, plaintext
>   parameters, headers, sizes, timing and images, and a gateway that swaps the client key header can
>   read a reply; the plugin detects that only afterwards.
> - **An agent with a terminal approving a pin** by one of the routes listed in
>   [LIMITATIONS 15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt).
> - **The vendor's collateral proxies** (`github-proxy.tinfoil.sh`, `kds-proxy.tinfoil.sh`,
>   `tdx-proxy.tinfoil.sh`), which see each verification, and **DNS**, which sees every lookup.
> - **Hermes' start-up model-list request after a runtime switch.** If the session's live runtime was
>   switched to a hosted provider, Hermes asks that provider for its model list with your API key
>   when the agent starts. No conversation text goes, and the plugin refuses the turn after, but the
>   request still goes out.
> - **The ledger as a metadata trail.** It records hosts, sizes and times; sharing a receipt shares
>   that trail.

[LIMITATIONS.md](LIMITATIONS.md) states each of these with the Hermes or vendor change that would
close it.

## Tiers

A tier is the rule the plugin applies while locked. Two tiers work today.

### `on-host-only`

**Where the model may run.** The model's host must be one of:

- a loopback address: `127.0.0.0/8` or `::1`, including the IPv4-mapped form `::ffff:127.0.0.1`;
- the names `localhost`, `localhost.localdomain`, `ip6-localhost` or `ip6-loopback`;
- this machine's own host name, when every address that name resolves to is loopback;
- an exact host you list in `confidential.on_host.extra_hosts`.

The plugin looks up one name in DNS: this machine's own host name, and only when a route names that
host. The lookup has a two-second timeout. An error, a timeout or any non-loopback answer makes the
name off-tier for the rest of the process; a loopback answer is rechecked at most once a minute. Any
other host name is off-tier unless listed.

**Private ranges are off-tier unless listed.** These ranges can hold another machine: `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, the carrier-grade NAT range `100.64.0.0/10` (which tailnets also
use), IPv4 link-local `169.254.0.0/16`, IPv6 link-local `fe80::/10` and IPv6 unique-local
`fc00::/7`. The preflight row for such a host names its range and the `extra_hosts` key.

**Listing a host.** Each `extra_hosts` entry is one exact host name or one IP address. A range, a
wildcard, a URL or a port is refused, and so are `0.0.0.0`, `::`, multicast and broadcast addresses,
and the cloud metadata addresses `169.254.169.254` and `fd00:ec2::254`; the lock fails until you fix
the entry. A zone id such as `%en0` is accepted only on an IPv6 link-local address. Listing
`10.0.0.5` admits that one address. A listed name matches only that exact name, and the HTTP client,
not the plugin, resolves it at every send, so whoever answers DNS for the name picks where text goes.
Prefer an IP address. The ledger and the receipt mark a send to a listed host as "listed on-host
host", so it never reads as loopback. The list is part of the config fingerprint, so changing it after
locking counts as a config change.

**Side calls.** A task left at `auto` inherits the main route, so it passes when the main route
passes. Hermes' fall-through to OpenRouter or Nous runs only when the main provider is unset or
`auto` (`agent/auxiliary_client.py:4529-4541`), which the lock refuses. `check` names the side calls
left on `auto` when an OpenRouter or Nous credential is readable, and `hermes confidential setup`
pins every side call. Vision must name its own provider or base URL, because `auto` vision can fall
through to hosted providers.

Hermes' built-in on-host provider profiles (ollama, lmstudio and llama-cpp) report no base URL at
84a0301, so set `model.base_url` yourself and give `auxiliary.vision` a base URL too. This config
passes the `on-host-only` preflight:

```yaml
model: {provider: custom, base_url: http://127.0.0.1:11434/v1, default: llama3}
auxiliary:
  vision: {provider: custom, base_url: http://127.0.0.1:11434/v1, model: llava}
```

### `attested`

**Where the model may run.** Through Tinfoil's confidential model router, which runs in an AMD SEV-SNP
or Intel TDX enclave, or through NEAR AI Cloud's attested gateway and models, which run in Intel TDX
CVMs ([The attested tier with NEAR AI](#the-attested-tier-with-near-ai)). The plugin verifies the
vendor before first use and again whenever the last successful verification is more than
`confidential.verify_ttl_seconds` (300) old.

**What it costs you.**

- Only the open-weight models the vendor serves inside enclaves. On Tinfoil these are Kimi K3.1 Pro,
  GLM-5.3, DeepSeek V4.1 Flash, Gemma 4 31B, gpt-oss-120b and Llama 3.3 70B
  ([config.example.yaml](config.example.yaml) lists their ids and context windows). On NEAR, a model
  NEAR runs and attests itself ([Models](#models)).
- The vendor's API key: `TINFOIL_API_KEY`, or `NEAR_AI_API_KEY`.
- No fallback. If the enclave can't be verified within `confidential.verify_wait_seconds` (20), or
  answers with an error, the turn ends and you resend.
- A pin prompt for every new Tinfoil router build and every NEAR configuration you haven't approved,
  and possibly after a restart ([Why a restart can ask you again](#why-a-restart-can-ask-you-again)).

### `zero-retention`

Not implemented; `/confidential on zero-retention` refuses. A hosted provider's promise not to keep
data is a policy that nothing observable from your machine confirms.

**Limits.** A listed host counts as on-host because you say so; the plugin can't check that it's
yours. A lock is one tier, so side jobs can't run on an on-host model while the main model is
attested ([LIMITATIONS 13](LIMITATIONS.md#13-no-mixed-attested-or-on-host-tier-planned)). Tinfoil
attests the router, not the model behind it
([LIMITATIONS 7](LIMITATIONS.md#7-the-vendor-measurement-covers-the-router-not-the-model)), and its
report carries no client nonce and no signed time
([LIMITATIONS 8](LIMITATIONS.md#8-no-nonce-no-attested-time)).

## Look before you lock

Two commands show where your conversation goes without locking anything, on an install that has
never been locked.

### `hermes confidential check`

```
hermes confidential check --tier attested
```

`check` runs the preflight and prints one row per route: the config key, its value, a verdict, and for
a failure the exact key to change and the value to write. The auxiliary tasks left to inherit the main
route share one row per verdict, such as `auxiliary.* (18 tasks)`; `check --verbose` prints one row
per task. A missing vendor key is the first row, and a lock refused only for the key says so on its
first line: "Not locked: TINFOIL_API_KEY is not set; set TINFOIL_API_KEY (see Requirements in
README.md)." In chat, `/confidential check [tier] [--verbose]`;
in a terminal, `hermes confidential check attested` works as well as `--tier attested`. With no
tier, `check` prints which tier `check` picks and why: the locked tier, else `attested` when
`model.provider` is an attested profile, else `on-host-only` when `model.base_url` is on this machine,
else `attested`. Replies print commands in the form that works where you typed: the
`hermes confidential ...` form from a terminal command, the `/confidential ...` form in chat. An
excerpt on a typical OpenRouter setup:

```
confidential preflight: tier=attested FAIL (26 item(s)) fingerprint=3b1b1f8f92a4
KEY                                      VALUE                                     VERDICT   FIX
model.provider                           openrouter                                off_tier  set model.provider: attested-tinfoil or attested-near (hermes confidential setup prints the whole block) (provider openrouter is not an attested profile)
fallback_providers[0]                    provider=openrouter, model=deepseek/d...  off_tier  remove fallback_providers entries while locked
auxiliary.vision.provider                auto                                      off_tier  set auxiliary.vision.provider (or auxiliary.vision.base_url) explicitly: attested-tinfoil (or attested-near), with a vision model; ...
auxiliary.compression.provider           deepinfra                                 off_tier  set auxiliary.compression.provider: attested-tinfoil (or attested-near) (provider deepinfra is not an attested profile)
auxiliary.* (17 tasks)                   inherit the main route                    off_tier  the main route is off_tier: fix model.provider, or set auxiliary.<task>.provider: attested-tinfoil (or attested-near) (check --verbose lists each task)
...
memory.provider                          honcho                                    off_tier  set memory.provider: "" (built-in on-host memory) while locked
plugins.isolation                        (default in_process)                      in_tier
```

`check --tier attested` does change something: it verifies the enclave over the network, writes
`verify_ok` and `pin_staged` rows, and may stage a pending pin in `pins.yaml`; for a staged NEAR model
entry the plugin then fetches the entry's docker-compose files from GitHub in the background. `check`
never applies a pin and never changes your config.

### `hermes confidential watch`

```
hermes confidential watch
```

`watch` streams the ledger: one row per send, with its purpose, host and size. A `verify_fail` row
also shows its reason, such as `verify_fail: <model>: attestation unavailable (HTTP 503 from NEAR)`.
On an unlocked install, the stream can show side calls going to hosts other than the main chat's,
such as compression to DeepInfra here:

```
TIME      SESSION       PURPOSE                   HOST                            BYTES     VERDICT/DECISION
14:02:00  20261106_14~  main                      openrouter.ai                   47K       send_observed attempt
14:02:00  20261106_14~  main                      openrouter.ai                   47K       send_observed observed
14:02:03  20261106_14~  aux:title_generation      openrouter.ai                   2210      send_observed observed
14:02:09  20261106_14~  aux:compression           api.deepinfra.com               89K       send_observed observed
```

In a terminal, refusals and breaches print in red and off-tier verdicts in yellow.
`hermes confidential watch --once` prints the latest rows and exits; `--limit` sets how many rows and
`--interval` how often the stream polls. `/confidential watch` shows the latest rows in chat.

**Limits.** On an unlocked install, tool calls aren't written to the ledger, only model calls.

## Locking

```
/confidential on attested        # or: on-host-only
/confidential off
/confidential status [--verbose]
```

### What `/confidential on` does

1. Runs the preflight for that tier over your current config.
2. If any route fails, refuses to lock, prints the preflight table and writes a `preflight_fail` row.
3. Otherwise records a fingerprint of your routing config: the model, the fallbacks, every auxiliary
   task, delegation, TTS, memory, MCP servers, the terminal backend, `confidential.on_host.extra_hosts`
   and the `plugins.*` keys that govern how plugin hooks run.
4. Builds the tool allowlist from the tools registered in Hermes at that moment, and saves it to disk
   tagged with this lock's identity.
5. Replies in three lines: what is locked; the four limits (off-host tools ask the first time per
   lock in each conversation, or each call under `confidential.tools.ask: each_call`; shell and code execution aren't
   inspected; auxiliary calls are recorded, not refused; and locked mode isn't active in safe-worker
   mode); and where the details are. `hermes confidential status --verbose` groups the
   allowlist into tools that run on this host, tools that ask, and tools that are blocked.

The preflight fails if `plugins.hook_callback_timeout` is more than 0 and less than 5 seconds, because
a timeout that short lets Hermes skip the plugin's per-turn check. The preflight also refuses `openai-codex` and
`moa` as the main provider, an unset or `auto` main provider, and `auto` vision.

The lock survives a restart: the plugin rebuilds the allowlist from the copy it saved at lock time,
not from what happens to be registered after the restart. `/confidential off` unlocks and prints the
lock period's counts. On a profile that isn't locked, `off` says so and writes no ledger row.

### What happens while locked

These rules apply to every session on the profile.

**Off-tier model calls are refused.** A main-loop call aimed outside the tier gets a refusal message
in place of the model's reply, and the request is never sent.

**Provider errors end the turn.** If the in-tier endpoint returns an error, the turn ends with
"attested endpoint unavailable; this turn ended; resend", so Hermes never reaches its fallback.

**A verification the ledger can't record is refused.** On the attested tier, every successful
verification writes a `verify_ok` row with its evidence. If that row can't be written (a full disk, a
corrupt file, a row over the size cap), the plugin writes `verify_fail` instead and sends wait for the
next verification, at least 10 seconds later. A transient "database is locked" error is retried once
first.

**A changed config blocks every turn.** If the routing config's fingerprint no longer matches the
fingerprint recorded at lock time, every turn is blocked until you unlock and lock again.

**The live model runtime is checked every turn.** `/model` and the `--provider` flag can switch one
session's model without changing your config. The plugin checks the live runtime at the start of every
locked turn and ends the turn if it's off-tier. The check runs in the `pre_llm_call` hook and again in
the model-call gate, so a turn whose hook Hermes skipped is still checked before its first model call. On gateway surfaces, `/model` and
`/moa` are refused outright while locked. On the CLI and the TUI, the plugin can't intercept `/model`:
the next turn's check catches the switch, but side calls Hermes makes in between are only recorded.

**On-host tools run without asking:** `terminal`, `process_manage`, `execute_code`, `read_file`,
`write_file`, `patch`, `search_files`, `skills_list`, `skill_view`, `skill_manage`, `todo_list`,
`memory`, `clarify` and `session_search`. A tool counts as on-host only in its built-in form; a plugin
or MCP tool registered under one of these names doesn't. Two exceptions follow: the terminal backend
must be `local`, and a call that names the plugin's own commands or state files is refused.

<a id="the-terminal-backend"></a>**The terminal backend.** Hermes runs `terminal`, `process_manage`,
`execute_code`, `read_file`, `write_file`, `patch` and `search_files` through its terminal backend,
set by `terminal.backend` in `config.yaml` or, when the config doesn't set it, by the `TERMINAL_ENV`
environment variable. A gateway serving several profiles gives each profile its own terminal
settings. The default, `local`, runs these seven tools on this host; `docker`, `ssh`, `modal`,
`managed_modal`, `daytona`, `vercel_sandbox` and plugin backends run them in a container or on another
machine.

- The preflight refuses to lock unless `terminal.backend` and the backend Hermes resolves for the
  profile are both `local`. The plugin resolves the backend the way Hermes' tools do, so a stale
  `TERMINAL_ENV` that the config overrides doesn't refuse the lock. The row names the backend found
  and the key to change.
- Hermes reuses a task's terminal environment for a few minutes without reading the backend again,
  so the lock is also refused while Hermes holds an environment on a non-local backend; restart
  Hermes or wait for `terminal.lifetime_seconds`.
- Each call to one of the seven tools is blocked unless the resolved backend and the environment
  cached for the task are both `local`. The refusal has the decision `terminal_backend` and says "Set
  terminal.backend: local (and unset TERMINAL_ENV), then run /confidential off and lock again."
  `docker` is refused too: a container can have its own network, and a Docker host can be remote.

**Every other tool asks you the first time that tool runs during a lock,** on
Hermes' approval prompt:

```
Confidential mode: web_search wants to send ~3 KB of this conversation off the machine; allowing once covers web_search in this conversation until this profile is unlocked
```

**How often a tool asks is set by `confidential.tools.ask`.** The default, `once_per_lock`, asks on
the first call of each tool in each conversation during a lock, and an exact `once` answer covers
that tool in that conversation until you unlock. `each_call` asks on every call. An absent key means
`once_per_lock`; any other value counts as `each_call`. The plugin reads the key at each decision, so
a change takes effect on the next tool call.

The size counts the call's arguments and any local image file it names, in MB above 1 MB. The tool
runs only on exactly `once`, `session` or `always`; any other answer is refused and logged as
`unexpected_choice`, including answers Hermes' own CLI would take as a yes.

- `once` runs the tool and grants that tool for the rest of this lock, in this conversation only. The
  conversation is Hermes' approval session key (one gateway chat, one CLI session) together with the
  agent's session id, so another chat, another user and a subagent each ask again; the grant is never
  wider than Hermes' own `session` answer. A call that carries neither a session key nor a session id
  names no conversation, so the plugin makes no grant for that call and asks on every call. The grant is the plugin's own, not
  Hermes': Hermes treats `once` as one call, and the plugin keeps the grant beside the lock. The grant
  records the lock and the id of the ledger row that recorded your answer. Each later call to that
  tool runs without a prompt and writes a `tool_allowed` row with decision `lock_grant` and
  `grant_row` set to that id, so the receipt shows which answer let the call through. The grant is
  held in the process that asked: a restart asks again, and a second process on the same lock (a CLI
  next to a gateway) asks on its own. The grant ends at unlock, so the next lock asks again, and
  `/confidential revoke <tool>` ends the grant sooner. `/confidential status` lists the grants under
  "Tool grants (answered once, this lock, this process, each for its own conversation)". With `confidential.tools.ask: each_call`,
  `once` covers this call only, and every call asks.
- `session` stops the asking for this tool for the rest of the session. Hermes keeps this grant, in
  either `confidential.tools.ask` mode.
- `always` stops the asking across locks. Hermes stores the grant in `command_allowlist` as
  `plugin_rule:confidential-mode:tool:<name>` until you run `/confidential revoke <tool>`.
  `/confidential pins` lists these grants.

**When nobody can answer, the ask becomes a block.** Under yolo mode, `approvals.mode: off`, cron
jobs, single-query runs (`-q`) and any context with no person present, Hermes would approve without
asking, so the plugin blocks the tool instead, even when an earlier `once` granted the tool for this lock:
the plugin checks for these cases before looking at a grant. The block holds in both
`confidential.tools.ask` modes. A tool you added with `/confidential allow` still runs.

**Some tools are always blocked:**

- `cronjob_manage`, because a scheduled job would run later, outside the locked session;
- tools from an MCP server whose URL host is off-tier, or whose config can't be read; the config is
  re-read at call time, so a server re-pointed after the lock is judged again;
- tools that weren't registered at lock time, and tools whose handler or toolset changed since;
- `delegate_task` when the call names a route (a profile, a provider, a base URL, an ACP command, or a
  non-default backend), or when the `delegation` config holds route keys. Plain delegation on the
  default backend is allowed: the child agent inherits the locked profile;
- a `terminal`, `process_manage` or `execute_code` call whose literal text runs `hermes confidential`,
  types `/confidential`, imports the `confidential_mode` package, or writes a state file (`pins.yaml`,
  `ledger.sqlite`, `allowlist.yaml` or its `state.json`) or the plugin's data directory, and a
  `write_file` or `patch` aimed there. The exact forms are in
  [LIMITATIONS 15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt). Calls
  that only mention them run, such as `grep "confidential off" README.md`,
  `make confidential status`, `cat` of the pins file, or an edit to the plugin's own source. Each
  refusal is a `tool_refused` row with the decision `self_approval`.

### `/confidential allow <tool>`

`/confidential allow <tool>` lets a tool that would ask run without asking for the rest of this lock.
The plugin confirms through `ctx.ask_choice`, a Hermes prompt that never answers itself under any
bypass setting; no answer counts as no. On Allow, the plugin adds the tool and writes a
`tool_allowed` row. Always-blocked tools can't be added, and stay blocked whatever `allowlist.yaml`
says.

Additions live in `allowlist.yaml` (mode 0600), tagged with the lock's identity. `/confidential off`
deletes the file, and the next lock starts with none. Anyone who can edit the file can add a tool for
the current lock with no prompt and no ledger row; that's inside the stated trust boundary, since the
plugin defends against the model and remote hosts, not against you or other code on your account.

### `/confidential revoke <tool>`

`/confidential revoke <tool>` (or `hermes confidential revoke <tool>`) withdraws the grants the
plugin holds for one tool, and `revoke --all` withdraws every such grant. The next call of the tool
asks again while locked. A revoke removes exactly:

- the tool's name in `allowlist.yaml`'s `allowed` list, when the file belongs to the current lock;
- the plugin's own keys for the tool in Hermes' `command_allowlist`
  (`plugin_rule:confidential-mode:tool:<tool>`, or `plugin_rule:confidential-mode:tool@<generation>:<tool>`
  after an earlier revoke).

A revoke never edits Hermes' session approvals. The plugin asks Hermes under a new approval key from
the revoke on, so a `session` or `always` answer Hermes holds for the old key no longer applies, and
the next call asks again.

Any other `command_allowlist` entry was written by you or another plugin, so a revoke leaves it alone
and names it in the reply. A revoke for a tool confidential mode has granted nothing since the last
revoke says so and records nothing. "Nothing" means: no `allow`; no prompt for the tool in any process
since the last revoke, which the ledger shows (every prompt is ledgered before the prompt is shown, and the
gate refuses the call when that row cannot be written); no `session` or `always` approval Hermes holds
in this process under the current approval key; and no entry in `allowlist.yaml` or
`command_allowlist`. Such a revoke writes no `grant_revoked` row and no record in
`grants_revoked.json`. Every other revoke writes a `grant_revoked` row with the tool, the surface and
the lock's identity. The prefix
`plugin_rule:confidential-mode:tool:` is a convention Hermes doesn't reserve; a revoke removes any
entry under it, which only narrows what runs.

A command-line revoke reaches a running gateway on the gateway's next tool call. The gateway re-reads
`allowlist.yaml` when it changes, and Hermes re-reads `command_allowlist` on every check. Every revoke
appends a record to `grants_revoked.json`, even when this process found nothing to remove, unless
nothing was granted at all. The gateway reads the
file before each tool decision and asks under the approval key the latest record gives, so a session
approval the gateway holds for the old key stops applying on its next tool call. Writes to `allowlist.yaml` and `grants_revoked.json` take a lock file beside each;
the plugin waits at most two seconds for it, and otherwise fails, names the lock file and exits
non-zero.

A revoke that doesn't take effect is reported as a failure and `hermes confidential revoke` exits
non-zero: for example a `config.yaml` Hermes didn't write (a managed install), in which case the reply
names the line to delete, or a `grants_revoked.json` the plugin could not write, in which case the reply
says that the running gateway applies the revoke on its next tool call and that a grant Hermes itself
holds for this session ends when the session ends or Hermes restarts. A revoke only narrows what runs, so a revoke asks nobody. While locked, the tool gate refuses any tool call
that names `hermes confidential`, revoke included, so run it from a terminal you opened or from chat.

**Limits.** An `always` grant outlives the lock until you revoke it. An approval prompt already open
in the gateway can still be answered after a revoke, and a tool call already past the gate finishes.
The lock is profile-wide, and a lock made from a terminal records no tool that only the gateway
connects, such as an MCP tool, so lock from chat to record those
([LIMITATIONS, smaller gaps](LIMITATIONS.md#smaller-gaps-disclosed)). Hermes titles the approval panel
"Dangerous Command" ([LIMITATIONS 16](LIMITATIONS.md#16-hermes-titles-the-plugins-approval-prompt-dangerous-command)),
and its CLI approve directive grants on almost any answer, which is why the plugin enforces the answer
itself ([LIMITATIONS 2](LIMITATIONS.md#2-the-cli-approve-directive-grants-on-any-answer-except-deny)).

## Pins

Pins apply to the `attested` tier. This chapter covers Tinfoil pins, the review bundle and the
consent rule for both vendors; NEAR's entry sets are under [Pins for NEAR](#pins-for-near).

### How the plugin verifies the router

The plugin uses the tinfoil SDK's default verification path:

1. The SDK fetches the router's hardware-signed attestation report.
2. The SDK checks that genuine AMD or Intel hardware signed the report, with the CPU vendor's
   certificates.
3. The SDK fetches the latest router release from GitHub, with its Sigstore signature.
4. The SDK checks that signature: the signature must come from the router repository's GitHub Actions workflow,
   running at that release's tag.
5. The SDK compares the code measurement in the signed release with the measurement in the report.

The result is a code fingerprint and an enclave fingerprint. You approve that pair once; every later
verification has to produce the same pair.

### The first pin

```
hermes confidential setup --model <tinfoil model id>
```

Setup reports whether `TINFOIL_API_KEY` is set, verifies the router, shows the two fingerprints and the
release tag, and asks you on the terminal to Approve or Deny. The choice, its number, or `y`, `yes`,
`n` or `no` in any case counts. Any other answer asks once more and then counts as no answer, which
pins nothing (on a first run the reply says "no pin approved yet; nothing changed"); every Approve or Deny prompt in a terminal (`pins approve`, `allow`) works the same way.
On a non-interactive terminal there's no answer and no pin. When a server answers the verification with an
HTTP error, the reply names the server that answered (Tinfoil, or Tinfoil's proxy for GitHub, AMD keys or
Intel PCS), the status and one next step; a failed router discovery says "router discovery". Setup then prints a config block for
`config.yaml`. Setup never writes your config. Tinfoil offers no model list the plugin can fetch, so
setup says that setup cannot check the `--model` id and whether the id is one `config.example.yaml` lists;
NEAR setup checks each id by attesting the model, so an id NEAR doesn't attest stops setup. `--vision-model` and `--aux-model` choose the vision and
short-job models in the block, and `--no-verify` only prints the block.

### When Tinfoil ships a new build

On the next locked turn, the verification finds fingerprints that differ from your pin. The plugin
refuses the turn with "enclave build changed; run /confidential pins approve", and stores the new pair
as a pending pin without applying it. On any surface, Telegram included:

```
/confidential pins              # current pin, pending pin, approval history, tool grants
/confidential pins approve      # Approve / Deny
```

The prompt shows whether the code changed, whether only the platform changed (for example AMD to
Intel), or whether this is a first pin with nothing to compare; the vendor, release tag and
repository; links to the release and to a comparison with the previous release; the Rekor log index;
the release's age; the enclave host with the old and new platform; and the old and new code and
enclave fingerprints.

If you approve, the plugin checks that the pending pin didn't change while you decided, writes the
new pin with who approved it, when and on which surface, keeps the previous fingerprints alongside,
and writes a `pin_applied` row. If you deny, the prompt times out, or you answer with anything that
isn't a choice, the old pin stays and turns keep being refused. The plugin never waits for your answer
mid-turn.

### Reviewing a pending pin

```
hermes confidential pins review          # numbered text lines
hermes confidential pins review --json   # the same bundle as JSON
hermes confidential pins approve --reviewed-by <name> --note "<verdict>"
```

`pins review` builds a review bundle with everything a reviewer needs to judge each pending entry.
Run it yourself in a terminal you opened; you can hand the bundle to another agent in a fresh session
with no access to the locked profile. `--no-fetch` uses only cached compose files. With nothing
pending, `pins review` prints one line saying there is nothing to review (`--json` still prints the
empty bundle). A Tinfoil entry
carries its release and compare links. A NEAR entry carries:

- the old and new value of every component, and the verified signing address old and new;
- the measured docker-compose fields beyond images (`allowed_envs`, `pre_launch_script`, the manifest
  flags, `GITHUB_REPO`, `CM_MIN_TAG_AGE_HOURS`), with a unified diff;
- the compose-manager image the log reports beside the measured one, and the service map old and new;
- each deployed docker-compose file the map names, fetched from the repository the measured compose
  names in `GITHUB_REPO` (today `nearai/cvm-compose-files`) at the logged commit, kept under
  `pins/composes/` only when its SHA-256 matches the log, and otherwise marked "text not fetched" with
  its link;
- when no approved entry of the same role exists, the baseline "none" and the full texts: the measured
  app_compose, and for each deployed file path one full text with every other commit as a diff;
- for every service, privilege tags: holds `dstack.sock` or `docker.sock`, mounts a run directory,
  privileged, adds capabilities, maps host devices, shares the host's network, pid or ipc namespace,
  runs as root (explicitly or by the image's default user), built from `dockerfile_inline`, image not
  pinned by digest;
- the commit author and date from GitHub, as unsigned metadata;
- a brief: fixed rules, fixed questions, and a required answer format of one verdict per question
  with cited line numbers.

Every value in the text form is shown escaped, so no value can start a line of its own. Once every
compose file of a NEAR entry is fetched, the entry pins its service map and the pending entry
changes, so approve after the review. `--reviewed-by` and `--note` are recorded on the approved
entries, from a terminal or a chat surface; without them the reviewer is recorded as none.

The reviewer must never run a `confidential` command. While locked, the tool gate refuses tool calls
that run the plugin's command line, import its package or write its state files, and every approval
prompt refuses in a process that carries the tool marker (`XDG_CONFIDENTIAL_MODE_TOOL_PROCESS`), which
terminal, process_manage and execute_code children inherit. Every approval is recorded with the
surface it came from.

### Why a pin needs a consent record

A pin with no matching `pin_applied` row in the ledger is refused with "pin has no consent record", so
a pin some other code wrote straight into `pins.yaml` doesn't count. Each approved entry needs its own
row. After `pins retire`, the ledger holds a `pin_retired` row, and a copy of that entry written back
by hand doesn't count either.

### Trust on first use

When you approve a first pin, you approve a pair of fingerprints. Nothing in the prompt tells you
whether that build is any good.

### Why a restart can ask you again

AMD and Intel routers have different enclave fingerprints for the same release. When
`confidential.tinfoil.enclave` isn't set, the SDK picks a router at random once per process, so a
restart can land on the other platform and ask again. Two ways to stop this:

- Set `confidential.tinfoil.enclave` to one router host.
- Set `confidential.pins.auto_approve_platform_only: true`. The plugin then applies a new pin itself
  when you already have a pin, the code fingerprint is unchanged, and the SDK's signed
  hardware-measurements check passed. In tinfoil 0.14.2 that check exists only for Intel TDX, so only
  a switch to a TDX router is approved this way, recorded with the decision `auto_platform_only`.

**Limits.** The first pin is trust on first use. The consent record makes a forged pin harder but doesn't prevent one:
any process running as your user can write a matching ledger row. An agent with a terminal can still
reach the approval prompt by some routes, such as a nested chat attached through the gateway; treat a
pin approved during an agent session as the agent's unless you remember answering
([LIMITATIONS 15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt)).

## The attested tier with NEAR AI

NEAR AI Cloud is the second vendor for the `attested` tier, with the provider name `attested-near`.
You lock to it with `/confidential on attested`, as for Tinfoil.

### What NEAR runs

The gateway at `cloud-api.near.ai` receives your request and passes it to a model server. NEAR runs
both inside Intel TDX CVMs. One model can be served by several CVMs, each an instance.

### What the plugin checks before the first send

The plugin asks NEAR for an attestation report for the gateway and for each model you allow. Each
report includes a fresh nonce from the plugin, which proves the report was made for this request. No
API key goes with these requests; NEAR documents the attestation endpoints as public. The plugin
checks that:

- each report's CPU signature traces back to Intel's root certificate, and the report names the
  plugin's nonce;
- each report names the CVM's signing key; for a model, the public key the report lists must be that
  signing key, and every report for one model must name the same key, which is the key requests are
  encrypted to;
- each report's measured configuration matches the docker-compose file it carries;
- each CVM's boot events name its app_id, OS image and KMS key, each once and before `system-ready`;
  a report stating other values, or lacking or repeating one, is refused;
- the gateway's report binds the TLS certificate this connection used, so the connection ends inside
  the gateway's CVM; every later inference and signature connection is checked against it right after
  the TLS handshake, before any request byte;
- Intel Trust Authority has signed a token saying the gateway's hardware is up to date, checked against
  Intel's published keys; the accepted statuses are `confidential.near.accepted_tcb_statuses`;
- each model report carries a compose-manager attestation: a log of what compose-manager deployed into
  the model's CVM after launch, with an Intel quote from the same TD that binds the log's hash and the
  plugin's nonce. From the log the plugin derives the service map: every service the log says was
  deployed, with its release. While `confidential.near.require_provider_tee` is true, a model report
  without this attestation is refused.

A compose-manager pass establishes that a TD of this instance reported this log for this nonce, that
the log's hash is bound in a hardware quote, and that the service map is what the operator's tooling
reported. A pass doesn't establish that the services deployed after launch are measured, or that they are
the ones running.

### Signed responses

For every send through `attested-near`, the plugin records the SHA-256 of the exact request bytes and
of the exact response bytes, then fetches NEAR's signature for that completion, waiting at most
`confidential.near.signature_wait_seconds` (5), and writes one `send_signed` row. NEAR signs with one
of two keys:

- **`provider_tee`:** the model server's CVM signs `<model id>:<request digest>:<response digest>`.
  The signature shows that a holder of the signing key a verified model CVM's quote binds signed these
  bytes for this model; every instance of the model shares that key, approved or not.
- **`gateway`:** the gateway's CVM signs `<request digest>:<response digest>`. The signature proves
  the gateway sent these bytes and says nothing about which model produced them.

The gateway signs with its own key whenever it changes the bytes, which includes every streamed
response, so main calls go to NEAR unstreamed (`confidential.near.streaming`, default false). With
request encryption on, a streamed request is refused before it is sent whatever that setting says.
With encryption off, a stream that stops early gets no signature, and the row says so.

With `confidential.near.require_provider_tee` true (the default), a send with a `gateway` signature or
none is recorded as unverified, and the receipt says the session is "NOT FULLY ATTESTED". With
encryption on, such a reply never reaches the agent; with encryption off, the reply has already
arrived when the signature is checked, so the send is recorded but not refused.

### Request encryption

The plugin uses NEAR's own request encryption, version 2, with every field NEAR covers
(`confidential.near.encrypt`, default true; the lock is refused unless it's absent or exactly true).
Each chat request is encrypted to the model key the plugin verified, so the message text, tool
definitions and tool calls leave this host as ciphertext. The model server encrypts its reply to a
per-request key the plugin makes, named in the `X-Client-Pub-Key` header. The plugin decrypts a reply
only after a verified `provider_tee` signature over the encrypted bytes, because anyone can encrypt to
a key sent with the request. Only an HTTP 200 reply that verifies and decrypts reaches Hermes.

While locked, a refused reply ends the turn like any provider error. While unlocked, Hermes handles a
NEAR error as for any provider: it backs off after a rate limit (429), retries after a server error
(5xx), a timeout or a reset, and compresses the context after a context-length error. Each resend is a
new encrypted request with its own ledger row. A reply that fails its checks, an HTTP 421 and every
other refusal aren't resent.

What this establishes:

- The listed fields left as ciphertext readable by any holder of the verified model key, which every
  instance of that model shares, approved or not. The gateway can't read those fields.
- The gateway still reads the model id, plaintext parameters (such as `max_tokens`, `stop`,
  `response_format`, `metadata` and `user`), the request headers, sizes and timing.
- A gateway that swaps `X-Client-Pub-Key` for its own key can read the reply. The plugin catches the
  swap afterwards, because the reply then fails to decrypt or fails its signature, withholds the reply
  and marks the send unverified, but the gateway has already read it.
- That a request was encrypted is the plugin's own report, marked "plugin self-report" in the receipt.
  The signature, which covers the ciphertext digests, can be re-checked by anyone.

The plugin refuses these before sending: streaming; every NEAR API other than chat completions, and any `api_mode`
other than chat completions on an attested-near route (the lock is refused); any top-level request key
that would carry text in plaintext; and any setting whose value is a list or mapping, such as
`logit_bias` or an `extra_body` entry, because token ids could encode text. Three structured settings
pass, checked by shape, and are named in the row's `plaintext_keys`:

- `reasoning`, with only `enabled` (true or false), `effort` (null or one of `none`, `minimal`, `low`,
  `medium`, `high`, `xhigh`, `max`), `summary` (`auto`, `concise`, `detailed` or `none`), `max_tokens`
  (an integer from 0 to 2^31 - 1) and `exclude` (true or false);
- `stream_options`, with only `include_usage` (true or false);
- `reasoning_effort`, one of the effort words.

**Images.** NEAR's encryption covers text only. By default (`confidential.near.image_parts:
disclose`), the plugin encrypts every text part of a message (`text` or `input_text`, any letter case)
and sends each image part in plaintext. An image part is `image_url` or `input_image` holding an inline
raster `data:image/...;base64,` URI (png, jpeg, gif, webp, bmp or tiff; SVG is refused), with an
optional `detail` of `low`, `high` or `auto`. Any other part type, a remote image URL or an extra field
on an image part is refused before sending, with the part type named. NEAR's gateway therefore reads each
image you send, while the text around it stays encrypted and the reply is still signed with
`provider_tee`.

- Each send's `send_signed` row records the plaintext parts by count and type, and the receipt's line
  says "N image part(s) left this host in plaintext to NEAR's gateway".
- The first time per lock, the plugin writes a `notice` row and, once that row is written, appends one
  line to the session's next reply through Hermes' `transform_llm_output` hook: "Confidential mode: an
  image part (image_url) in this turn went to NEAR's gateway in plaintext; the text around it was
  encrypted."
- `confidential.near.image_parts: refuse` refuses every message with a non-text part before it is
  sent. The preflight shows the value in force and refuses any value other than these two.

**Key changes.** An HTTP 421 means the gateway no longer accepts the model key; a send that meets a TLS
certificate other than the attested one is treated the same way. The plugin verifies again, at most
once per `confidential.near.reverify_backoff_seconds` (30), and refuses NEAR sends until that passes. A
re-verification that reports a different model key is refused, so after NEAR rotates a key, NEAR
requests are refused until Hermes restarts; the restart accepts the new key without a prompt, because
pins don't cover the key.

Encryption needs `pynacl` in the environment that runs Hermes ([RUNNING_TESTS.md](RUNNING_TESTS.md)).
Without it the lock is refused; no request is sent unencrypted instead.

### What a receipt shows

Each NEAR send is listed with its two digests, the signature kind, the verdict at the time, whether the
request was encrypted and to which model key ("plugin self-report"), which top-level keys left in
plaintext, and whether the reply was released. `hermes confidential replay <receipt.json>` re-checks
every attestation report, compose-manager attestation and signature offline and prints a verdict per
send. A receipt holds digests, not your text: a third party can tie a signature to a conversation only
by hashing the exact request and response bytes.

### Models

List every NEAR model Hermes may use in `confidential.near.models`; the plugin adds the models
`model.default` and `auxiliary.<task>.model` name for `attested-near`. While
`require_provider_tee` is true, a request for any other model is refused before it is sent. That
matters because NEAR also serves hosted models, such as Anthropic's and OpenAI's, through the same
gateway, which NEAR calls Incognito models and for which only the gateway is attested. Use a model NEAR
runs and attests itself, such as `Qwen/Qwen3.8-27B`, by its full id, because NEAR signs the id it
received and the plugin refuses aliases.

### Pins for NEAR

A NEAR pin is keyed by the gateway host and the model list, for example
`cloud-api.near.ai#Qwen/Qwen3.8-27B` (the identity), so changing the list needs a new pin. The pin is
a set of approved entries, one per CVM configuration: the gateway, or one instance of a model.

An entry pins its CVM's docker-compose, app_id, OS image and KMS key, and its firmware and kernel
measurements. A model entry also pins the compose-manager image the deployment log reports and the
whole service map with its privilege tags. A change in any of these asks again. The verified signing
key is shown for review and isn't pinned.

A model entry can be approved only with every deployed docker-compose file its map names fetched and
hash-checked, because the privilege tags come from those files. The plugin fetches them in the
background when it stages the entry, and the approve command fetches again before it asks; until every
file is kept, the approve command doesn't ask and names `hermes confidential pins review`. Nothing is
fetched when the measured compose names no repository on github.com, and such an entry can't be
approved. A kept file that doesn't parse blocks approval of that entry for good.
`CONFIDENTIAL_MODE_NO_FETCH` turns every fetch off, and NEAR model entries then can't be approved.

A verification passes when every CVM it reports matches an approved entry. A CVM that matches none
becomes a pending entry, and the tier refuses until you run `/confidential pins approve`, which goes
through every pending batch, oldest first, and shows all pending entries of one identity and the whole
approved set. Approving adds entries and never removes one, so the set grows as you meet more
configurations. An entry no verification has matched for 20 verifications is flagged in the prompt;
`hermes confidential pins retire <fingerprint>` removes it, given 8 or more hex digits of its code or
enclave fingerprint, and `--identity <host#models>` limits that to one identity when the entry is
approved under several. The pin prompt lists the services a per-model name list shipped with the plugin
names first, then every other service; a long list is folded into a count, and `hermes confidential
pins` prints every line.

The first verification after upgrading from pins version 2 asks once for NEAR: an older NEAR pin
covers fewer values than a per-CVM entry, so it matches nothing, is marked as migrated, and is removed
when you approve the new entries.

### Setup

```
hermes confidential setup --vendor near --model Qwen/Qwen3.8-27B
```

Setup checks the gateway and the model, asks you to approve the first pin, and prints a config block;
it never writes your config. The block routes the main model and every auxiliary task through
`attested-near`, with vision on a NEAR vision model, `Qwen/Qwen3-VL-30B-A3B-Instruct` by default
(`--vision-model` names another), added to `confidential.near.models`. A note above the vision entry
says each image leaves in plaintext to NEAR's gateway, and names the two ways to keep images off NEAR:
`confidential.near.image_parts: refuse`, or a vision model on `attested-tinfoil`, which needs
`TINFOIL_API_KEY` and a Tinfoil pin. An on-host vision route is off-tier on the attested tier.

Setup attests the gateway with each model on its own, so one model whose attestation endpoint fails
leaves the other model usable. Each failure prints one line naming the model, the vendor and the HTTP
status, such as `Qwen/Qwen3-VL-30B-A3B-Instruct: attestation unavailable (HTTP 503 from NEAR); vision
left unset.` A vision model that fails is left out of the block, with a comment saying how to set
`auxiliary.vision` before you lock. A main model that fails stops setup with one next step: try again
in a few minutes for a 5xx status, or check the model id for a 404. `check` and `on` name the model
and the status the same way in the failing row, and each model that fails in setup writes a
`verify_fail` row that `watch` shows.

Set `NEAR_AI_API_KEY` for inference and install `pynacl`. `scripts/near_first_contact.py` runs the
same checks and one signed send, and prints no secrets.

**Limits.** NEAR's gateway reads images, the model id, plaintext parameters, headers, sizes and
timing; every instance of a model shares the key requests are encrypted to; a gateway signature says
nothing about the model; what runs after launch is reported by the operator, not measured; the model
CVM's patch level and the GPU verdict aren't tied to the model CVM; and "encrypted" is the plugin's
own report. A model key rotation refuses NEAR requests until restart. Approving a model entry needs
GitHub. [LIMITATIONS 14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open)
states each item.

## Receipts and replay

```
/confidential receipts [session] [--json]
hermes confidential receipts [session id] [--json]
```

A receipt renders the ledger for one session; without a session id, `/confidential receipts` uses the
current session. A full example is in [examples/receipt-2026-11-06.txt](examples/receipt-2026-11-06.txt).

### What a receipt contains

In order: a header; the trust roots used; the verification events, each with the raw attestation
evidence it captured; the sends; the refusals; the questions asked and the answers given; the
breaches; the context compactions; and the fixed closing paragraphs. Rows that describe the whole
profile (locks, unlocks, verifications, pin events) are included when they fall in the lock period
the session belongs to. A background verification the pins didn't accept is marked "NOT ACCEPTED" and
never counted for a send. A row marked "unverified entry" has no evidence, or an incomplete capture,
and shows nothing.

A receipt never contains prompt or response text. The ledger rejects any row whose details carry a key
that usually holds conversation content, such as `messages`, `prompt` or `content`, and rendering
scans every row again and removes any such key. Every time is this machine's clock, labelled "(host
clock)".

### The hash chain and the chain head

The JSON form adds a SHA-256 hash chain over its rows: each row's hash covers the previous hash and the
row. The last hash, the chain head, is printed at the top of both forms. Anyone holding the file can
recompute the chain, including anyone who edited it, so the chain detects an edit only against a copy
of the chain head kept somewhere else when the receipt was rendered. Record the chain head off this
machine if you want that. The chain says nothing about whether the ledger was complete or its rows
genuine.

<a id="the-closing-paragraph"></a>

### The closing paragraphs

Every receipt ends with the same fixed paragraph (`CLOSING_PARAGRAPH` in
`confidential_mode/receipts.py`), never filled in from data, which splits the receipt's claims in two.
NEAR receipts add up to two more fixed paragraphs, described at the end of this section.

**What the evidence shows.** Evidence that replays offline shows that an enclave whose hardware report
commits to TLS key fingerprint T and HPKE public key H ran code with measurement M, signed by
repository R at release tag G, as of the capture time the evidence states. T and H are the enclave's
long-lived keys, not a per-session key. Each verification row says which checks its evidence replays
under: the vendor SDK at a stated version, and the plugin's own restated policy check, identified by
the SHA-256 of `confidential_mode/verify/policy_check.py` (a file that imports nothing from the SDK),
or n/a for rows captured without it. Sends were gated by the vendor SDK only. The enclave host and
capture time inside the evidence are asserted by whoever captured it.

**What is recorded only, not proven:** that the plugin checked the evidence during this session; that
this session's requests went to that enclave; that request bodies were encrypted to that key; which
HPKE key each send recorded and whether its response decrypted (the plugin's own observations); that the build was the vendor's latest release; whether the build or
its key was revoked after capture; what shell, terminal and code-execution tools sent off the machine;
which model backends sit behind the router; other access the vendor's operators have; and Hermes'
auxiliary calls, which can leave the tier while locked and are recorded after the fact. The paragraph
also says that another plugin can write rows that look like this plugin's own, how the hash chain
behaves, that locked mode doesn't apply in safe-worker mode, and that timestamps come from this
machine's clock.

A receipt with a NEAR send adds a paragraph on signed responses: what a `provider_tee` and a `gateway`
signature each prove, that the digests are the plugin's own, and that a signature doesn't name the
instance that answered. A receipt with an encrypted NEAR send adds a paragraph on request encryption
repeating the limits under [Request encryption](#request-encryption); a JSON receipt that holds an
encrypted send without that paragraph fails its chain check.

### Offline replay

A replay re-runs a stored verification from the evidence alone, with all network access blocked for
the replaying thread; anything that tries to connect fails the replay. For Tinfoil, the plugin re-runs
the SDK's own verifier on the stored bytes: AMD reports use the stored VCEK, Intel reports the stored
collateral (whose signatures are checked again), Sigstore is checked against a stored trust root, and
every clock the SDK consults is set to the capture time or a time you give. For NEAR, the replay re-runs
the checks under [What the plugin checks before the first send](#what-the-plugin-checks-before-the-first-send):
TDX quotes against the Intel root the tinfoil SDK embeds, Intel Trust Authority tokens against the
captured key set, whose chain must end at a pinned Intel root, and then each response signature
against the signing key the replayed evidence binds.

#### From the command line

```
hermes confidential replay receipt.json
```

Make `receipt.json` with `/confidential receipts <session> --json`. The command:

1. recomputes the hash chain and says whether it's intact;
2. picks the expected fingerprints for each evidence row: from `--expected-fingerprints CODE:ENCLAVE`,
   else the approved pin in this profile's `pins.yaml` or the file given with `--pins`, else the
   receipt's own claim, labelled "not independent"; with an approved NEAR pin, a NEAR row passes only
   when every CVM it reports matches an approved entry;
3. replays each row; Tinfoil code must come from `tinfoilsh/confidential-model-router` unless you
   name another repository with `--expected-repo`;
4. prints each row's result, each check's value and any problems;
5. for NEAR sends, replays every signed response and says whether the session is fully attested;
6. prints what a replay can't establish;
7. exits 0 only if the chain is intact, every row replayed and matched, and every NEAR signed response
   replayed. A broken chain exits 1 even when every row replays.

By default the replay uses the trust root bytes recorded in the evidence, so it works on any machine,
but the capturer chose that copy; `--trusted-root <file>` uses a Sigstore `trusted_root.json` you got
yourself. Evidence from an earlier plugin version holds only a path to the trust root on the capturing
machine, and needs `--trusted-root` elsewhere. Certificates are checked as of the capture time in the
evidence, also asserted by the capturer; `--as-of <ISO time>` chooses the time.
`--expected-repo-id` and `--expected-owner-id` bind the numeric GitHub repository and owner IDs in the
Sigstore signing certificate, which survive a rename or re-creation; the `repo_identity` check then
reports `name+id` instead of `name only (ids not supplied)`. For Tinfoil's router repository these are 1077094187
(repository) and 168487856 (owner).

#### From Python

For Tinfoil rows the same check is `confidential_mode.verify.replay.replay(evidence)`; NEAR rows go
through `confidential_mode.verify.replay_near.replay` after `replay_near.with_blobs`, which the command
does for you. The example below replays Tinfoil rows only. Run the example in Hermes' environment:

```
cd ~/hermes-agent && PYTHONPATH=<plugin dir> uv run --no-sync python - receipt.json <<'EOF'
import json, sys
from confidential_mode.verify.replay import replay
doc = json.load(open(sys.argv[1]))
for item in doc["evidence"]:
    if str(item["evidence"].get("schema", "")).startswith("confidential-mode/near"):
        continue   # a NEAR row: use hermes confidential replay
    r = replay(item["evidence"])   # the evidence carries its trust root
    print(item["row_id"], "ok" if r.ok else "FAIL", r.checks)
    print("not established:", *r.not_established, sep="\n  ")
EOF
```

Keyword arguments: `expected_repo` (default `tinfoilsh/confidential-model-router`);
`expected_repo_id` and `expected_owner_id` (both needed for `name+id`); `expected_fingerprints`, a
(code, enclave) pair; `trusted_root`, as bytes or a file path; and `as_of`, the certificate check time
(default the capture time). Without `expected_fingerprints`, the function compares the recomputed
fingerprints only with those the evidence recorded, so compare `code_fingerprint` and
`enclave_fingerprint` in the result with your pin yourself; the command does that for you.

#### What each check means

Each check's value is `True` (passed) or a string starting `fail:`, `n/a:` or `not_run:`. `ok` is true
only when every check is `True` or `n/a`.

- `repo_match`: the evidence names the expected repository.
- `repo_identity`: `name+id` when the numeric IDs you gave matched the signing certificate, and
  `name only (ids not supplied)` when you gave none. Both are passing values, and the only exception to
  the prefix rule above.
- `trust_root_source`: informational; whether you supplied the trust root or it came from the evidence.
- `hardware_signature`: the report is signed by the CPU vendor's key.
- `cert_chain`: the signing certificate chains to AMD's or Intel's root, and the collateral signatures
  and revocation lists check out.
- `tcb_policy`: the SDK's policy on the enclave's firmware and security version (the TCB, trusted
  computing base).
- `collateral_fresh_at_capture`: for TDX, Intel's collateral hadn't expired at the checked time; n/a
  for SEV-SNP.
- `code_signature`: the Sigstore signature over the release, under the expected repository's workflow
  policy.
- `measurement_match`: the signed code measurement equals the enclave's, and the fingerprints equal
  the recorded and expected ones.
- `hardware_platform_match`: for TDX, the hardware measurements match a signed entry in
  `tinfoilsh/hardware-measurements`; n/a for SEV-SNP.
- `report_data_keys`: the keys in the report equal the keys the client used.
- `tls_cert_binding`: the TLS certificate captured by the verification's TLS probe carries the TLS key the
  report commits to, and its subject alternative names bind the HPKE key and the attestation hash. A
  pass means TLS ended inside the attested router on the connection the probe used. A row captured
  before certificates were recorded reads n/a. A probe that meets a certificate with another key fails
  the verification, so that certificate never reaches accepted evidence. The check is evidence for the
  receipt; what enforces for sends is the plugin's per-send pin, which refuses any Tinfoil inference
  connection whose certificate does not carry the accepted report's TLS key.
- `policy_check`: the plugin's own restated Sigstore policy check over the captured bundle,
  independent of the SDK.
- `sev_check`: an AMD SEV-SNP report re-verified by the plugin's own standalone checker (signature,
  chain to AMD's root, report fields); n/a for TDX.

#### What a replay can't establish

Every result carries a fixed `NOT_ESTABLISHED` list. For a NEAR row it's the list in
[LIMITATIONS 14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open). For
a Tinfoil row:

- that any request was sent to this enclave or answered by it, since the report commits to keys, not
  requests, and carries no client nonce;
- that requests were encrypted to this HPKE key, which only the plugin's own log says;
- that this release was the latest when verified: the release tag is bound (the SDK's Sigstore policy
  requires the workflow to have run at `refs/tags/<tag>`), but the "latest" answer comes from an
  unsigned GitHub API response;
- revocation or security-version changes after the capture time;
- that the capture time is when the capture happened, since the time comes from the evidence itself.

**Limits.** A receipt is a self-report from a file on your machine that you or another plugin could
edit; only the evidence can be checked by someone else
([LIMITATIONS 6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process)). The ledger is a
metadata trail, and it grows without limit
([LIMITATIONS 9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks),
[smaller gaps](LIMITATIONS.md#smaller-gaps-disclosed)).

## Fewer hosted parties without locking

If you won't lock, four config changes still cut the number of vendors that see your conversation. You make them
yourself; the plugin doesn't apply them. Each remaining vendor still sees your conversation in
plaintext. None of the four has been evaluated for its effect on compression summaries, titles or
vision answers, so run `hermes confidential watch` before and after to see what moved.

1. **Tell OpenRouter not to use your prompts for training:** `provider_routing: {data_collection:
   "deny"}` routes only to providers that don't collect prompts. Hermes applies it where it builds the
   main request (`agent/chat_completion_helpers.py:477`); whether auxiliary calls carry it isn't
   established.
2. **Keep side jobs on your main provider:** `auxiliary.<task>.provider: main` for compression, titles
   and the other tasks, so they don't go to a second vendor you forgot about.
3. **Fall back only to providers you'd accept as your main one.** Every `fallback_providers` entry
   gets your full context on a 429; trim the list or empty it.
4. **Make vision explicit:** set `auxiliary.vision.provider` and its model, so `auto` can't fall
   through to OpenRouter, Nous or DeepInfra when your main model can't take images.

## Config

[config.example.yaml](config.example.yaml) lists every key the plugin reads, the core Hermes keys the
attested preflight needs, and the context length for each Tinfoil model. The plugin's own keys live
under `confidential:` in `config.yaml`:

| Key | Default | What it does |
|---|---|---|
| `confidential.tools.ask` | `once_per_lock` | How often an off-host tool asks while locked: `once_per_lock` asks on the first call of each tool in each conversation and an exact `once` grants the tool in that conversation until unlock; `each_call` asks every call. Under yolo, approvals off and unattended runs a tool is blocked in either mode. Any other value counts as `each_call`. |
| `confidential.tinfoil.enclave` | Unset (router discovery) | One router host to verify and use; stops the AMD/Intel switching after a restart. |
| `confidential.tinfoil.context_length` | 65536 | The context window reported to Hermes, so Hermes never sends its own probe outside the attested transport. |
| `confidential.tinfoil.tls_probe` | `true` | Before a verification is accepted, open one bodiless connection to the enclave host, without the API key, pinned to the TLS key of the report being verified, and record the certificate seen in the evidence. A certificate with another key fails the verification and writes a `verify_fail` row (purpose `tls_pin`), so the lock is refused; any other probe failure is only recorded. The pin on inference connections is separate and always on. Only the exact value `false` turns the probe off. |
| `confidential.verify_ttl_seconds` | 300 | How long one verification vouches for the enclave, on a monotonic clock. |
| `confidential.verify_wait_seconds` | 20 | How long a turn waits for a verification before it is refused. |
| `confidential.verify_refresh_lead_seconds` | 60 | While locked, a background thread verifies again this long before the current verification ends, when a call used it within two lead periods of its end (two minutes at the default). A new verification is used only after the pin check accepts it; a failed one changes nothing, and the next send then verifies inline. 0 turns the thread off. |
| `confidential.pins.auto_approve_platform_only` | `false` | Apply a new Tinfoil pin without asking when only the platform changed and the SDK's signed hardware check passed (TDX only). |
| `confidential.on_host.extra_hosts` | `[]` | Exact hosts (one name or IP address each, no ranges) the `on-host-only` tier counts as on-host. |
| `confidential.model` | Unset | The model id `hermes confidential setup` writes into the block it prints. |
| `confidential.near.base_url` | `https://cloud-api.near.ai/v1` | NEAR's gateway, for attestation, inference and signatures. |
| `confidential.near.models` | `[]` | Every NEAR model id Hermes may send, plus the ids `model.default` and `auxiliary.<task>.model` name for `attested-near`. The NEAR pin's identity. |
| `confidential.near.require_provider_tee` | `true` | A send counts as verified only with a `provider_tee` signature; unlisted models and model reports without a compose-manager attestation are refused. Only the exact value `false` turns it off. |
| `confidential.near.require_tls_binding` | `true` | The gateway's report must bind the attestation connection's TLS certificate, and every inference and signature connection is checked against it before any request byte. The lock is refused unless absent or exactly `true`. |
| `confidential.near.encrypt` | `true` | Encrypt every chat request to the attested model key; release a reply only after a verified `provider_tee` signature. Needs `pynacl`. The lock is refused unless absent or exactly `true`. |
| `confidential.near.image_parts` | `disclose` | `disclose` sends inline images in plaintext beside the encrypted text and records them; `refuse` refuses any message with a non-text part. |
| `confidential.near.reverify_backoff_seconds` | 30 | At most one re-attestation per this many seconds after an HTTP 421 or a TLS certificate mismatch. |
| `confidential.near.accepted_tcb_statuses` | `[UpToDate]` | Intel TCB statuses accepted for the gateway, from Intel Trust Authority's token. |
| `confidential.near.signature_wait_seconds` | 5 | How long the plugin keeps asking for a response's signature after the response ended. |
| `confidential.near.streaming` | `false` | Whether Hermes may stream main calls to NEAR; no effect while `encrypt` is on, which refuses streaming. |
| `confidential.near.context_length` | 65536 | The context window reported to Hermes for `attested-near`. |

Environment variables: `TINFOIL_API_KEY` and `NEAR_AI_API_KEY` (the vendor keys),
`CONFIDENTIAL_MODE_PROGRESS` (start-up progress lines) and `CONFIDENTIAL_MODE_NO_FETCH` (turns off the
GitHub compose fetches).

## For developers

- [INTERFACES.md](INTERFACES.md) is the developer contract: package layout, shared types, each
  module's contract with Hermes, and the change record.
- [dev/C0-spikes.md](dev/C0-spikes.md) records the Hermes behaviour the `tests/spikes/` checks
  established before the plugin was built.
- [RUNNING_TESTS.md](RUNNING_TESTS.md) gives the test command, the PyNaCl setup, the live NEAR tests and
  the real captures.
- `tests/` is laid out by kind: `unit/` (pure logic, no Hermes import), `seam/` (real Hermes modules
  at commit 84a0301, with fakes only for the SDK, the network and the person answering prompts),
  `hostile/` (adversarial cases against each module's contract), `fault/` (injected filesystem,
  process, vendor, Hermes and crypto failures), `scenario/` (an end-to-end demo), `live/` (real NEAR
  calls, skipped unless `NEAR_AI_API_KEY` is set), `spikes/` (checks of the Hermes behaviour the plugin
  depends on), and `fixtures/` (real vendor captures and test vectors).
- `hermes plugins validate --install-deps <plugin dir>` and `hermes plugins doctor --ci <plugin dir>`
  check the plugin against the catalog rules.

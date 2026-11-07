<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here, in the title, and in the install lines) -->
# confidential-mode

confidential-mode is a plugin for Hermes Agent. Hermes is an agent harness: the program that runs
the loop around a language model, sends your messages to the model, runs the tools the model asks
for, and sends the results back.

## The problem in one paragraph

Six kinds of request carry your text out of a Hermes profile. The main chat goes to the provider you
picked. Hermes also makes side calls, nineteen kinds of them at the pinned commit: it writes a title
for the session, compresses old conversation, rewrites your question before searching memory,
describes images, runs background reviews, and more. Each side call is a separate request carrying
some of your text, and each goes to whatever provider that task is configured for. A fallback
provider takes over quietly when the main request fails. Tools such as web fetch and messaging send
text to whatever site the agent decides to call. Shell and code execution run on this host and can
reach the network, as long as Hermes' terminal backend is `local`. On another backend, such as `ssh`
or `modal`, shell, code execution and the file tools run on that other machine. Memory is written to whatever store is configured. Choosing a verified provider
for the main chat covers the main chat only.

![Figure 1. With a verified provider alone, the main chat is verified and five other routes carry
text to hosts nobody checks.](docs/images/routes-figure-1-verified-provider-alone.svg)

## What the plugin does

The plugin does four things for a Hermes profile.

1. **It shows you every route.** It keeps a log of every model call Hermes makes, with the host the
   call went to and how many bytes it carried, never the text. The log is a file on the machine that
   runs Hermes. You can watch that log live in a terminal, and this works before you lock anything.

2. **It locks the profile to one tier.** A tier is a rule for which destinations are acceptable.
   The `on-host-only` tier accepts a host whose network address is loopback or in a private range.
   The `attested` tier accepts a Tinfoil enclave whose build you have approved. Before locking, the
   plugin checks every configured route: the main model, every side call, delegation, text to
   speech, MCP servers, fallbacks and the terminal backend. If any route leads off-tier, the lock
   is refused and the plugin prints which key to change.

3. **While locked, it guards or refuses four of the five other routes.** The five other routes are
   side calls, fallbacks, tools, shell and code execution, and memory. Shell and code execution
   stay open, as the next section explains. Side calls must
   resolve to the same tier as the main chat and are rechecked every turn. No fallback provider may
   be configured, and a failed request ends the turn instead of being rerouted. Off-host tools ask
   you before each call; an answer of `session` or `always` stops the asking, and an `always` answer
   is written to Hermes' own allowlist and outlives the lock. Memory must be the built-in store.

4. **It writes a receipt for each session.** The receipt lists where the text went, attaches the
   enclave evidence captured at each verification, and ends with a fixed paragraph naming what the
   receipt cannot prove. Anyone holding the receipt can replay the enclave evidence offline, without
   contacting Tinfoil. The rest of the receipt is the plugin's own record.

![Figure 2. With the plugin, preflight checks every configured route, side calls go to the verified
enclave, fallback is refused, tools ask, memory stays on the host, shell and code stay open, and a
ledger records model sends and tool answers.](docs/images/routes-figure-2-with-the-plugin.svg)

## What the plugin cannot do

Shell, code execution, and MCP servers started as a command on this host stay open. They run on
this machine and can reach the network, and the plugin does not inspect them. Hermes itself asks
before shell or code commands it flags as dangerous, and nothing else. The receipt names these
routes as unproven.

A side call that goes off-tier in the middle of a turn, for example after a runtime model switch,
is recorded as a breach. The plugin cannot stop that call, because Hermes' auxiliary calls do not
pass through the middleware a plugin can block. The limitations section at the end of this README
lists every gap of this kind, with the Hermes change that would close each.

A private-range address is not the same thing as a machine you control. A neighbour in a cloud
provider's private network has a private-range address too, and so does a carrier-grade NAT
address. The plugin cannot tell those apart from your own machine.

## Why "lock" and not "seal"

The plugin says "lock" because sealing already means something else in confidential computing:
sealed storage and sealing keys belong to the enclave hardware, and this plugin does not redefine
them. A plugin named `sealed`, an encrypted secrets store, also exists in the Hermes catalog.

## Where this fits

The closest everyday comparison is Little Snitch, the macOS firewall that asks before an
application connects to the network. confidential-mode applies the same pattern to your agent:
every destination is logged, off-host tools get an allow-once prompt while locked, and you can keep
a list of the tools you have allowed.

Five earlier pull requests tried to add confidential inference to Hermes core. Each added a
verified provider for the main chat, and each was closed with the instruction to ship it as a
plugin. This plugin ships that verified provider as asked, and adds the routing checks, the tool
gate, the ledger and the receipt that make the privacy claim about the whole session rather than
about one endpoint.

The plugin was built and tested against Hermes commit 84a0301 and version 0.14.2 of the tinfoil
Python SDK. It is an entry for the Nous Research Hermes Agent Plugin Hackathon.

## Terms this README uses

Each term below is defined once here. The sections that follow use the terms in exactly this sense.

**Hermes, the harness.** Hermes Agent is an agent harness. A harness is the program that runs the
loop around a language model. It sends your messages to the model, runs the tools the model asks
for, and sends the results back. Everything in this README happens inside the Hermes process.

**Profile.** A profile is a separate Hermes home directory with its own `config.yaml`, keys, memory,
sessions and plugin data. Locking applies to one profile at a time. It applies to every session that
runs on that profile.

**Session.** A session is one conversation with Hermes. Each session has its own session id. A
receipt covers one session.

**Gateway.** The gateway is the part of Hermes that connects messaging platforms, such as Telegram
and Discord, to the agent. A "gateway surface" is any chat you reach Hermes through that way. The CLI
and the TUI are the other surfaces.

**Provider and fallback.** A provider is the service Hermes sends model calls to. You set it with
`model.provider` in your config. A fallback is a second provider, listed under `fallback_providers`,
that Hermes switches to when the first one returns an error.

**Auxiliary call (side call).** An auxiliary call is a model call Hermes makes for a side job rather
than for the main reply. Examples are compressing old context, writing a session title, and
describing an image. Each side job is called an auxiliary task. Each task has its own route under
`auxiliary.<task>` in your config.

**Tier.** A tier is a rule that decides which destinations count as acceptable. This plugin has two
working tiers, `on-host-only` and `attested`, and one placeholder, `zero-retention`. A destination
that satisfies the rule is "in-tier". Any other destination is "off-tier".

**On-host and off-host.** On-host means on the machine that runs Hermes. Off-host means anywhere
else. An on-host tool, such as `read_file`, does its work on that machine. An off-host tool, such as
`web_search`, sends data to another machine. The `on-host-only` tier is wider than its name: it also
accepts private-range addresses, as the `on-host-only` section below explains.

**Lock.** To lock a profile is to hold it to one tier. While a profile is locked, the plugin refuses
off-tier model calls and gates off-host tools. To unlock is to remove that hold. The time between a
lock and the next unlock is called a lock period.

**Safe-worker mode.** Safe-worker mode is a mode for managed Hermes worker processes in which Hermes
deliberately loads no plugins. Nothing in this plugin runs there.

**Preflight.** The preflight is the check the plugin runs over your Hermes config before it will
lock. It reads every route that can carry conversation text and gives each one a verdict. For each
route that fails, it names the config key to change.

**Middleware.** Middleware is code that Hermes runs around an operation. A plugin's middleware
receives the request and decides whether to pass it on. This plugin registers middleware around every
main-loop model call, a point Hermes calls `llm_execution`. It also registers middleware around every
tool call, a point Hermes calls `tool_execution`. Because the middleware sits in the path of the call,
it can refuse the call, and then the call never happens.

**Hook.** A hook is a callback that Hermes calls at a named moment. Examples are the moment just
before a tool call (`pre_tool_call`) and the moment just before an auxiliary call
(`pre_auxiliary_call`). Some hooks can return an instruction that Hermes obeys. Other hooks can only
observe, because Hermes ignores what they return.

**Breach.** A breach is a ledger row that records an auxiliary call which went off-tier while the
profile was locked. The plugin also marks the session as breached. A breach is a record after the
fact. It does not mean the call was stopped.

**Ledger.** The ledger is the plugin's on-host log. It is a SQLite file under your Hermes home. Each row
records one event, such as a send, a refusal, a question, an answer, a lock or a verification. A row
holds hosts, byte counts and decisions. It never holds prompt or response text.

**Receipt.** A receipt is a rendering of the ledger rows for one session. It comes as text or as
JSON.

**Allowlist.** The allowlist is the table the plugin builds when you lock. It lists every tool
registered in Hermes at that moment. For each tool it says what the plugin will do: run it, ask
first, or block it. Do not confuse it with Hermes' own `command_allowlist`, which is the list of
approvals that Hermes remembers permanently.

**Enclave and TEE.** A trusted execution environment (TEE) is a feature of some server CPUs. It runs a
virtual machine whose memory is encrypted by the CPU itself, so the operator of the host machine
cannot read that memory. An enclave is one such protected virtual machine. This README uses the two
words for the same thing.

**Platform (SEV-SNP or TDX).** The platform is the CPU vendor's TEE technology that an enclave runs
on. AMD's version is called SEV-SNP. Intel's version is called TDX. The two produce different kinds of
hardware report. "Platform" in this sense has nothing to do with the messaging platform you use to
talk to Hermes, such as Telegram. This README always says "messaging platform" for the second
meaning.

**Attestation.** Attestation is the process by which an enclave proves what it is running. The CPU
produces a report that describes the code loaded into the enclave. It signs the report with a key
that only the CPU vendor's hardware holds. A client checks the signature and the contents before it
trusts the enclave.

**Measurement.** A measurement is a cryptographic hash of the code and configuration loaded into an
enclave when it starts. The hardware report carries the measurement of what is actually running. The
vendor's signed release carries the measurement that the published source code should produce.
Attestation succeeds when the two match.

**Fingerprint.** A fingerprint is a short hash of a measurement. It is used to compare measurements
and to display them. The plugin records two. The code fingerprint comes from the measurement in the
vendor's signed release. The enclave fingerprint comes from the measurement in the hardware report.

**Collateral and VCEK.** To check a hardware report, a client needs certificates and signed
documents from the CPU vendor. These are called collateral. For AMD, the main piece is the VCEK, the
certificate for the signing key of the particular AMD CPU that produced the report. For Intel, the
collateral includes Intel's signed security-version information and revocation lists.

**TLS.** TLS is the encryption that HTTPS uses between your machine and a server. Whoever holds the
server end of a TLS connection sees the request headers, sizes and timing, and, without EHBP (below),
the request body too.

**Router.** Tinfoil's router is the enclave your requests actually connect to. Its code is published
on GitHub as `tinfoilsh/confidential-model-router`. The router forwards each request to a model
backend that Tinfoil runs behind it.

**Pin.** A pin is your recorded approval of one router build. It holds that build's code fingerprint
and enclave fingerprint. While a pin is in force, the plugin sends nothing to a router whose
fingerprints differ from the pin.

**Sigstore and Rekor.** Sigstore is a public service for signing software. When Tinfoil's GitHub
Actions workflow builds a router release, it signs a statement about that build through Sigstore.
Rekor is Sigstore's public, append-only transparency log. Every Sigstore signature is recorded in
Rekor at a numbered position called the log index.

**Trust root.** A trust root is the file of public keys and certificates that a signature check
starts from. For Sigstore, the trust root lists the keys of Sigstore's certificate authority and of
the Rekor log. The plugin stores the copy it used for each verification.

**HPKE and EHBP.** HPKE (Hybrid Public Key Encryption) is a standard way to encrypt a message to
someone's public key. EHBP (the encrypted HTTP body protocol) is Tinfoil's transport. It uses HPKE to
encrypt the body of each HTTP request to a key that the attested enclave holds. EHBP does not encrypt
the headers, and it does not hide the size or timing of a request.

**Evidence.** Evidence is the set of raw bytes the plugin captures during one verification. It
includes the hardware report, the CPU vendor's certificates, the Sigstore bundle, the trust root and
the release metadata. The plugin stores evidence in the ledger.

**Replay.** A replay re-runs a stored verification later, from the evidence alone, with network
access blocked. It shows whether the stored bytes still check out.

## What it defends against, and what it doesn't

> **Read this first.** Suppose Hermes runs on someone else's machine, such as a cloud agent service
> or a rented VPS. Then the operator of that machine can read every prompt before anything in this
> plugin applies. The plugin controls the road out of the Hermes process. It does not protect the
> process itself.
>
> **What it defends against**
>
> - **Your conversation going to a hosted provider or fallback you did not mean to use.** For the
>   main model call and for fallbacks, the plugin refuses the call before any byte is sent.
>
>   Auxiliary side jobs are handled differently. Hermes gives plugins no way to stop an auxiliary
>   call at the moment it is sent. The plugin therefore refuses to lock while any side job is
>   configured to go off-tier. If a side job goes off-tier anyway, the plugin records a breach.
> - **The vendor shipping a new enclave build without your consent.** Suppose Tinfoil's router
>   presents fingerprints that differ from your pin. Then the plugin refuses the turn. It keeps
>   refusing until you approve the new fingerprints.
>
> **What it does not defend against**
>
> - **Other code in the same Hermes process.** Another plugin runs in the same Python interpreter as
>   this one. It can write rows into this plugin's ledger. It can write a pin. It can patch this
>   plugin's functions.
> - **You editing your own ledger.** The ledger is a file on your machine. A receipt is therefore a
>   report you make about yourself. It proves only what its attached evidence proves.
> - **Shell and code-execution tools.** The `terminal` and `execute_code` tools run on this host. The
>   commands they run can open network connections. The plugin does not inspect those commands. These
>   tools run on this host only on Hermes' `local` terminal backend, so the plugin refuses to lock on
>   any other backend (see [The terminal backend](#the-terminal-backend)).
> - **Tinfoil's own infrastructure.** This covers the vendor's control plane, meaning the systems
>   Tinfoil uses to run and manage its service. It also covers the model backends that sit behind
>   the router. The attestation covers the router only.
> - **Connection metadata.** Tinfoil's network and hosting see the size of each request and
>   response, their timing, and your IP address. EHBP encrypts the request body. It does not hide
>   any of these. The TLS connection itself ends inside the attested router, so your API key header
>   is decrypted by the measured router code rather than by a separate front proxy. The tinfoil SDK
>   enforces this: its transport pins the TLS key from the attestation report on every connection.
>   The plugin's own TLS probe only corroborates it. The probe records the certificate it saw and
>   never fails a verification.
> - **The vendor's collateral proxies.** These are `github-proxy.tinfoil.sh`, `kds-proxy.tinfoil.sh`
>   and `tdx-proxy.tinfoil.sh`. The SDK fetches verification material through them. They therefore
>   see that you verify, and when.
> - **DNS.** Your DNS resolver sees a lookup for every host above.
> - **Hermes' start-up model-list request after the runtime has drifted.** Suppose the session's live
>   model runtime has been switched to a hosted provider. When the agent starts, Hermes asks that
>   provider for its list of models. The request carries your API key for that provider. It carries
>   no conversation text. The plugin refuses the turn that follows, but it cannot stop the request.
> - **The ledger as a metadata trail.** The ledger records hosts, sizes and times. If you share a
>   receipt, you share that trail.

## The leak map

A Hermes turn can carry your conversation off the machine along six roads. Most people know about
the first one only.

1. **The main model call.** On every turn, Hermes sends the conversation to the provider named in
   `model.provider`.

2. **Fallbacks.** Sometimes the main provider answers with a rate-limit error (429), a server error
   (5xx) or an authentication error. Hermes then switches to the next entry in `fallback_providers`.
   That entry is often OpenRouter. Hermes tells you about the switch in a single line of output. The
   fallback receives your full context.

3. **Auxiliary tasks.** These are the side jobs nobody looks at. At Hermes 84a0301 there are 19
   built-in auxiliary tasks, plus any that a plugin registers. They include context compression,
   title generation, vision, the smart-approval classifier, MCP helpers, memory query rewriting,
   background review, the curator, the monitor, the goal judge, the group router, the kanban
   decomposer, TTS audio tags and voice chat.

   Vision deserves a separate note. Sometimes a message arrives through the gateway with an image
   attached. Hermes then describes the image through the vision task, even if no tool was called.

   Each task has its own route under `auxiliary.<task>`. The default route is `auto`. An `auto`
   route sends the task to your main provider first, and then to your fallbacks.

   Vision's `auto` behaves differently when your main model cannot accept images. In that case it
   tries OpenRouter, then Nous, then DeepInfra.

4. **Tools.** Many tools send data off the machine. They include web search and fetch, the browser,
   messaging, media tools, and tools added by other plugins. They also include remote MCP servers.
   (MCP, the Model Context Protocol, is a standard way to plug external tool servers into an agent.)
   Finally, `delegate_task` sends data off the machine when it hands work to another profile or
   backend.

5. **The memory provider.** If you use a hosted memory service, it receives context on every turn.

6. **The messaging platform you talk to Hermes over.** Telegram, Discord and the other messaging
   platforms see your messages. This road is out of scope. No plugin can close it, because your
   messages pass through the messaging platform before they reach Hermes.

## Three tiers

A tier is the rule the plugin applies while locked. The plugin has three tiers. Two of them work
today.

### `on-host-only`

**Where the model may run.** The model's host must be one of the following:

- a loopback address: `127.0.0.0/8` or `::1`;
- an address in a private IPv4 range: `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`;
- an address in `100.64.0.0/10`, the carrier-grade NAT range, which tailnets also use;
- an IPv6 link-local address (`fe80::/10`) or unique local address (`fc00::/7`);
- one of the names `localhost`, `localhost.localdomain`, `ip6-localhost` or `ip6-loopback`;
- a host you list in `confidential.on_host.extra_hosts`.

The plugin never looks a hostname up in DNS. Any other hostname is off-tier unless you list it in
`extra_hosts`.

**What "private-range" does and does not mean.** A private-range address is not proof that the
machine is yours. A neighbour in the same cloud provider's private network passes the check. So does
an address handed out by a carrier-grade NAT. When you list a host in `extra_hosts`, you are telling
the plugin that you trust that host.

**What it costs you.** The model's quality is whatever your hardware can run. Its availability is
your hardware's availability.

Every auxiliary task needs an on-host route as well, and that includes vision. At 84a0301, Hermes'
built-in on-host provider profiles (ollama, lmstudio and llama-cpp) report no base URL. The plugin
therefore cannot tell where they point. You have to set `model.base_url` and each
`auxiliary.<task>.base_url` yourself.

### `attested`

**Where the model may run.** The model must be reached through Tinfoil's confidential model router,
or through NEAR AI Cloud's attested gateway (see [The attested tier with NEAR AI](#the-attested-tier-with-near-ai)).
The router runs in an AMD SEV-SNP or Intel TDX enclave. The plugin verifies the router before first
use. It verifies the router again whenever the last successful verification is older than 300
seconds.

**What it costs you.** This tier has four costs.

- You can use only the open-weight models Tinfoil serves. At the time of writing these are Kimi
  K3.1 Pro, GLM-5.3, DeepSeek V4.1 Flash, Gemma 4 31B, gpt-oss-120b and Llama 3.3 70B.
- You need a Tinfoil API key.
- A failure ends the turn instead of falling back. If the enclave cannot be verified within 20
  seconds, the turn ends with a refusal, and you resend your message. If the enclave answers with an
  error, the same thing happens. The plugin does not retry. It does not fall back to another
  provider.
- You will see a pin prompt every time Tinfoil ships a new router build. You may also see one after
  a restart, for the reason explained under [Pins](#pins).

### `zero-retention`

This tier is not implemented. `/confidential on zero-retention` refuses.

The tier is reserved for hosted providers that promise not to keep your data. Such a promise is a
policy. Nothing the plugin can observe from your machine confirms it, so the plugin offers no check
for it yet.

## The attested tier with NEAR AI

NEAR AI Cloud is a second vendor for the `attested` tier. Its provider name in Hermes is
`attested-near`. You lock to it with the same command as for Tinfoil, `/confidential on attested`.

### What NEAR runs

NEAR AI Cloud has two parts. The **gateway** is the server at `cloud-api.near.ai` that receives your
request. The gateway passes the request to a **model server**, which runs the model. NEAR runs both
parts inside Intel TDX virtual machines. NEAR calls each such virtual machine a **CVM**, short for
confidential virtual machine. Intel TDX is Intel's TEE technology.

### What the plugin checks before the first send

The plugin asks NEAR for an **attestation report** for the gateway and for each model you allow. An
attestation report is a document signed by the CPU that says what the CVM runs. Each report includes a
fresh random value from the plugin, called a **nonce**. The nonce proves the report was made for this
request and was not copied from an earlier one.

The plugin checks six things.

- The CPU signature on each report traces back to Intel's root certificate.
- Each report names the CVM's **signing key**, the key the CVM signs responses with.
- Each report names the nonce the plugin sent.
- Each report's measured configuration matches the **docker-compose file** the report carries. The
  docker-compose file lists the container images the CVM runs.
- The gateway's report names the TLS certificate this connection used. TLS is the encryption that
  HTTPS uses. So the plugin knows the encrypted connection ends inside the gateway's CVM.
- Intel Trust Authority, a service Intel runs, has signed a token that says the gateway's hardware is
  up to date. The plugin checks Intel's signature against Intel's published keys.

No API key is sent with these requests. NEAR documents its attestation endpoints as public.

### Signed responses

A **signed response** is a signature NEAR returns for one completion. A signature is made with a
private key. Anyone with the matching public key can check it. The attestation report ties the public
key to the CVM.

For every send through `attested-near`, the plugin records two **digests**. A digest is a SHA-256
hash. The first digest is of the exact bytes of the request. The second digest is of the exact bytes
of the response. After the response arrives, the plugin fetches NEAR's signature for that completion.
It waits at most 5 seconds for it. It checks the signature and writes one row to the ledger.

NEAR signs with one of two kinds of key.

- **`provider_tee`.** The model server's CVM signs `<model id>:<request digest>:<response digest>`.
  This proves that an attested model server signed exactly these bytes for exactly this model.
- **`gateway`.** The gateway's CVM signs `<request digest>:<response digest>`. This proves the attested
  gateway sent these bytes. It says nothing about which model produced them.

The gateway signs with its own key whenever it changes the bytes. That happens on every streamed
response. The plugin therefore sends main calls to NEAR without streaming. A stream that stops before
its end gets no signature at all. The ledger row then says so.

`confidential.near.require_provider_tee` is true by default. A send whose signature is of the
`gateway` kind, or is missing, is then recorded as unverified. The receipt then says the session is
not fully attested. The send is not refused, because the response has already arrived when the
signature is checked.

### What a receipt shows

The receipt lists every NEAR send with its two digests, the signature kind, the plugin's verdict at
the time, and a **replay verdict**. A replay re-checks everything offline, from the receipt alone.
`hermes confidential replay <receipt.json>` re-checks each attestation report and each signature.

A receipt holds digests, not your text. A third party can tie a signature to a conversation only if
they hold the exact request and response bytes and hash them.

### Models

You must list every NEAR model Hermes may use in `confidential.near.models`. The plugin also adds the
models that `model.default` and the `auxiliary.<task>.model` keys name for `attested-near`. The plugin
refuses a request for any other model before it is sent. The refusal matters because NEAR also serves
hosted models, such as Anthropic's and OpenAI's, through the same gateway. NEAR calls those models
**Incognito** models. For them only the gateway is attested.

Use a model that NEAR runs itself and attests, such as `Qwen/Qwen3.8-27B`. Use its full id, because
NEAR signs the id it received and refuses aliases from this plugin.

### Pins for NEAR

A pin for NEAR is keyed by the gateway host and the list of allowed models, for example
`cloud-api.near.ai#Qwen/Qwen3.8-27B`. The code fingerprint covers the docker-compose file of the
gateway and of every model server the report showed. The enclave fingerprint covers the firmware and
kernel measurements of the same CVMs.

A change to either fingerprint is refused until you approve it with `/confidential pins approve`, as
for Tinfoil. NEAR may run one model on several CVMs with different docker-compose files. You may
therefore be asked again when a later check reaches another CVM.

### Setup

```
hermes confidential setup --vendor near --model Qwen/Qwen3.8-27B
```

This command checks the gateway and the model, asks you to approve the first pin, and prints a config
block. It never writes your config. Set `NEAR_AI_API_KEY` for inference. The script
`scripts/near_first_contact.py` runs the same checks and one signed send, and prints no secrets.

[docs/LIMITATIONS.md](docs/LIMITATIONS.md), section 14, lists what the NEAR checks leave open.

## Look before you lock

Two commands let you see where your conversation goes without locking anything. Both work on an
install that has never been locked. `check --tier attested` does change something: it
verifies the enclave over the network, writes `verify_ok` and `pin_staged` rows to the ledger, and may
stage a pending pin in `pins.yaml`. It never applies a pin and never changes your config.

### `hermes confidential check`

```
hermes confidential check --tier attested
```

This command runs the preflight and prints the result. The result is a table with one row per route
in your config. Each row shows the config key, its current value and a verdict. When the verdict is a
failure, the row also shows the exact YAML key to change.

On a typical OpenRouter setup, an excerpt looks like this:

```
confidential preflight: tier=attested FAIL (26 item(s)) fingerprint=3b1b1f8f92a4
KEY                                      VALUE                                     VERDICT   FIX
model.provider                           openrouter                                off_tier  set model.provider/model.base_url to an in-tier route (provider openrouter is not an attested profile)
fallback_providers[0]                    provider=openrouter, model=deepseek/d...  off_tier  remove fallback_providers entries while locked
auxiliary.vision.provider                auto                                      off_tier  set auxiliary.vision.provider (or auxiliary.vision.base_url) explicitly to an in-tier vision route; ...
auxiliary.compression.provider           deepinfra                                 off_tier  set auxiliary.compression.provider/auxiliary.compression.base_url to an in-tier route (provider deepinfra is not an attested profile)
auxiliary.title_generation.provider      auto -> openrouter                        off_tier  inherits the main route: fix model.provider, or pin auxiliary.title_generation.provider to an in-tier provider
...
memory.provider                          honcho                                    off_tier  set memory.provider: "" (built-in on-host memory) while locked
plugins.isolation                        (default in_process)                      in_tier
```

### `hermes confidential watch`

```
hermes confidential watch
```

This command streams the ledger to your terminal. It prints one row per send. Each row shows the
purpose of the call, the host it went to, and its size. On an unlocked install, this is the view that
tends to surprise people:

```
TIME      SESSION       PURPOSE                   HOST                            BYTES     VERDICT/DECISION
14:02:00  20261106_14~  main                      openrouter.ai                   47K       send_observed attempt
14:02:00  20261106_14~  main                      openrouter.ai                   47K       send_observed observed
14:02:03  20261106_14~  aux:title_generation      openrouter.ai                   2210      send_observed observed
14:02:09  20261106_14~  aux:compression           api.deepinfra.com               89K       send_observed observed
```

In a terminal, refusals and breaches print in red. Off-tier verdicts print in yellow.

`hermes confidential watch --once` prints the latest rows and exits. `/confidential watch` shows the
same rows inside a chat.

On an unlocked install, tool calls are not written to the ledger.

## Locking

These are the commands:

```
/confidential on attested        # or: on-host-only
/confidential off
/confidential status
```

### What `/confidential on` does

When you run `/confidential on <tier>`, the plugin does the following, in order.

1. The plugin runs the preflight for that tier over your current config.
2. If any route fails, the plugin refuses to lock. It prints the preflight table, so you can see
   which keys to change. It writes a `preflight_fail` row to the ledger.
3. If every route passes, the plugin records a fingerprint of your routing config. This fingerprint
   covers the model, the fallbacks, every auxiliary task, delegation, TTS, memory, MCP servers, and
   the `plugins.*` keys that govern how plugin hooks run.
4. The plugin builds the tool allowlist from the tools registered in Hermes at that moment.
5. The plugin saves the allowlist to disk, tagged with this lock's identity.
6. The plugin prints the allowlist. The printout groups the tools into those that run on this host,
   those that will ask you, and those that are blocked.

One preflight rule concerns hooks. If `plugins.hook_callback_timeout` is set to more than 0 and less
than 5 seconds, the preflight fails. A timeout that short would let Hermes skip this plugin's
per-turn check.

The lock survives a restart of Hermes. After a restart, the plugin rebuilds the allowlist from the
copy it saved at lock time. It does not rebuild it from whatever happens to be registered after the
restart.

### What happens while locked

From the moment of locking, the following rules apply to every session on this profile.

**Off-tier model calls are refused.** Suppose a main-loop model call is aimed at a destination
outside the tier. The plugin's middleware then returns a refusal message in place of the model's
reply. The request is never sent.

**Provider errors end the turn.** Suppose the in-tier endpoint itself returns an error. The plugin
then ends the turn with the message "attested endpoint unavailable; this turn ended; resend". It does
this so that Hermes never reaches the point where it would switch to a fallback.

**A changed config blocks every turn.** If your routing config changes after you lock, its
fingerprint no longer matches the one recorded at lock time. Every turn is then blocked until you
unlock and lock again.

**The live model runtime is checked on every turn.** Hermes can switch the model for one session
without changing your config. `/model` does this, and so does the `--provider` flag. The plugin
checks the live runtime at the start of every locked turn. If the live runtime is off-tier, the plugin
ends the turn. The check runs in the `pre_llm_call` hook. Hermes skips that hook for an agent with
persistence disabled, such as its background review agent. For such an agent the middleware still
checks each main call's destination and the config fingerprint, but nothing checks the live runtime,
so an auxiliary call it makes is only recorded.

On gateway surfaces, the plugin refuses `/model` and `/moa` outright while locked.

On the CLI and the TUI, the plugin cannot intercept `/model`. The per-turn check still catches the
switch on the next turn. Between the switch and that check, however, Hermes can make auxiliary calls
to the new runtime. The plugin can only record those calls. It cannot stop them.

**On-host tools run without asking.** These tools run without a prompt: `terminal`,
`process_manage`, `execute_code`, `read_file`, `write_file`, `patch`, `search_files`, `skills_list`,
`skill_view`, `skill_manage`, `todo_list`, `memory`, `clarify` and `session_search`.

<a id="the-terminal-backend"></a>**The terminal backend.** Hermes runs `terminal`, `process_manage`,
`execute_code`, `read_file`, `write_file`, `patch` and `search_files` through its terminal backend.
The backend is set by the `terminal.backend` key in `config.yaml`. Hermes copies that key into the
`TERMINAL_ENV` environment variable. An explicit key in `config.yaml` wins over the variable. When
`config.yaml` does not set the key, the variable decides. A gateway that serves several profiles
gives each profile its own terminal settings, so each profile can have its own backend.
The default backend is `local`, which runs these tools on this host. The other backends are `docker`,
`ssh`, `modal`, `managed_modal`, `daytona`, `vercel_sandbox` and any backend a plugin registers. On
those, the seven tools run in a container or on another machine. A file the model writes then lands
there, and a command the model runs runs there.

The preflight therefore refuses to lock unless `terminal.backend` is `local` and the backend Hermes
resolves for this profile is `local` too. The plugin resolves the backend the way Hermes' own tools
do, so a stale `TERMINAL_ENV` that the config overrides does not refuse the lock. The preflight row
names the backend it found and the key to change.

Hermes keeps a terminal environment for each task for a few minutes and reuses it without reading
the backend again. The plugin therefore also refuses to lock while Hermes holds any environment on a
non-local backend. The refusal tells you to restart Hermes, or to wait for
`terminal.lifetime_seconds` to pass.

The plugin checks again on every call to one of the seven tools. The call is blocked unless both
the backend Hermes resolves and the environment Hermes has cached for the task are `local`. The
refusal names the backend. `docker` is refused too, although its container runs on this host. A
Docker container can have its own network, and a Docker host can be remote. The plugin does not
inspect either.

A tool counts as on-host only in its built-in form. If a plugin or an MCP server registers a tool under
one of these names, that tool is not treated as on-host.

`terminal` can reach the network. The [Limitations](#limitations-an-upstream-roadmap) section
explains why the plugin still treats it as on-host.

**Every other tool asks you first.** Before such a tool runs, the plugin asks on Hermes' normal
approval prompt, with a line like this:

```
web_search wants to send ~3 KB of this conversation off the machine
```

The tool runs only if you answer with exactly `once`, `session` or `always`. Any other answer is
refused and logged. That includes answers that Hermes' own CLI would accept as a yes.

The three answers differ in how long they last:

- `once` runs the tool for this one call.
- `session` stops the asking for this tool for the rest of the session.
- `always` stops the asking for this tool permanently, across locks. Hermes stores the grant in
  `command_allowlist` under the name `plugin_rule:confidential-mode:tool:<name>`. The grant stays
  there until you delete that entry. `/confidential pins` lists these grants.

**When nobody can answer, the ask becomes a block.** Hermes sometimes approves tool calls without
asking anyone. This happens under yolo mode, which turns off all approval prompts. It also happens
under `approvals.mode: off`, in cron jobs, in single-query runs (`-q`), and in any context where no
person is present to answer. In all of these cases, the plugin blocks the tool instead of letting it
run unasked.

The one exception is a tool you have added with `/confidential allow`, described below. Such a tool
runs without asking, in these contexts too.

**Some tools are always blocked.** While locked, the plugin blocks these tools outright:

- `cronjob_manage`. A scheduled job would run later, outside this locked session.
- Tools from an MCP server whose URL points to an off-tier host. A server whose config cannot be
  read is treated the same way.
- Any tool that was not registered when you locked. Any tool whose handler or toolset has changed
  since then is blocked as well. The plugin cannot vouch for a tool it did not classify.
- `delegate_task` when the call names a route. A route is any field that would send the child agent
  somewhere else: a profile, a provider, a base URL, an ACP command, or a backend other than the
  default. (An ACP command launches an external agent through the Agent Client Protocol.)

Plain delegation on the default backend is allowed. The child agent inherits the locked profile, so
it stays inside the tier.

### `/confidential allow <tool>`

`/confidential allow <tool>` adds a tool that would normally ask to the allowlist, for the rest of
this lock. Once the tool is added, it runs without asking.

The steps are these:

1. You run `/confidential allow <tool>`.
2. The plugin asks you to confirm through `ctx.ask_choice`. This is a Hermes prompt that never picks
   an answer by itself, under any bypass setting. If you give no answer, the plugin treats that as
   no.
3. If you pick Allow, the plugin adds the tool and writes a `tool_allowed` row to the ledger.

Additions last only as long as the lock. `/confidential off` deletes them. The next lock starts with
none.

Tools that are always blocked cannot be added this way.

The additions are stored in `allowlist.yaml` in the plugin's data directory, with file mode 0600.
That file is a second way in. Anyone who can edit it can add a name to its `allowed` list for the
current lock, and the tool then runs without asking. No ledger row records such an edit. The file is
yours, like the ledger, so this is inside the trust boundary the plugin states: the plugin defends
against what the model and remote hosts do, not against you or other code on your account. A tool
that is always blocked stays blocked whatever the file says.

## Pins

Pins apply to the `attested` tier only.

### How the plugin verifies the router

The plugin verifies Tinfoil's router through the SDK's default verification path. The steps are
these:

1. The SDK fetches the router's hardware-signed attestation report.
2. The SDK checks that genuine AMD or Intel hardware signed the report. It uses the CPU vendor's
   certificates for this.
3. The SDK fetches the latest release of the router's code from GitHub, together with its Sigstore
   signature.
4. The SDK checks the Sigstore signature. The signature must come from the GitHub Actions workflow of
   the router's repository, running at that release's tag.
5. The SDK compares the code measurement in the signed release with the measurement in the hardware
   report. The two must match.

The result is two fingerprints. The code fingerprint identifies the signed release. The enclave
fingerprint identifies what the hardware reported.

You approve that pair once. From then on, every later verification has to produce the same pair.

### The first pin

```
hermes confidential setup --model <tinfoil model id>
```

This command does the following, in order.

1. It reports whether `TINFOIL_API_KEY` is set.
2. It verifies the router. It shows you the two fingerprints and the release tag.
3. It asks you on the terminal to Approve or Deny the pin. Only an exact choice, or its number,
   counts. If the terminal is not interactive, there is no answer, and no pin is written.
4. It prints a block of config for you to paste into `config.yaml`.

Setup never writes your config.

### When Tinfoil ships a new build

The steps are these:

1. On the next locked turn, the plugin verifies the router. It finds fingerprints that differ from
   your pin.
2. The plugin refuses the turn with the message "enclave build changed; run /confidential pins
   approve".
3. The plugin stores the new pair as a pending pin. It does not apply it.
4. You run the commands below, on whatever surface you are using. Telegram works.

```
/confidential pins              # current pin, pending pin, approval history, tool grants
/confidential pins approve      # Approve / Deny, on whatever surface you're on (Telegram works)
```

The approval prompt shows the following:

- whether the code changed, whether only the platform changed (for example from AMD to Intel), or
  whether this is a first pin with nothing to compare against;
- the vendor, the release tag and the repository;
- a link to the release on GitHub, and a link that compares it with the previous release;
- the release's Rekor log index;
- how long ago the release was published;
- the enclave host, and the old and the new platform;
- the old and new code fingerprints, and the old and new enclave fingerprints.

**If you approve,** the plugin first checks that the pending pin did not change while you were
deciding. It then writes the new pin. It records who approved it, when, and on which surface. It keeps
the previous pin's fingerprints alongside. It writes a `pin_applied` row to the ledger.

**If you deny,** the plugin keeps the old pin and keeps refusing turns. The same happens if the
prompt times out, or if you give an answer that is not one of the choices.

The plugin never waits for your answer in the middle of a turn. The turn is refused, and you approve
separately.

### Why a pin needs a consent record

A pin with no matching `pin_applied` row in the ledger is refused, with the message "pin has no
consent record". This means that a pin some other code wrote straight into `pins.yaml` does not count.

This raises the bar. It is not a wall. Other code in the same process could forge the ledger row as
well.

### Trust on first use

The first pin is trust on first use. When you approve it, you are approving a pair of fingerprints.
Nothing in the prompt tells you whether that build is any good.

### Why a restart can ask you again

The pin covers the router that answered. AMD and Intel routers have different enclave fingerprints
for the same release, because the two platforms report different kinds of measurement.

When `confidential.tinfoil.enclave` is not set, the SDK discovers the available routers and picks one
at random, once per process. After a restart it may pick a router on the other platform. The plugin
then asks you to approve again.

You can stop this in either of two ways.

- Set `confidential.tinfoil.enclave` to a single router host. The plugin then always talks to that
  router.
- Set `confidential.pins.auto_approve_platform_only: true`. The plugin then applies a new pin by
  itself when three conditions hold. You already have a pin. The code fingerprint is unchanged. The
  SDK's signed hardware-measurements check passed. In tinfoil 0.14.2 that check exists only for
  Intel TDX, so only a switch to a TDX router is approved this way. The ledger records such a pin
  with the decision `auto_platform_only`.

## Receipts

```
/confidential receipts [session] [--json]
```

A receipt is a rendering of the ledger for one session. If you leave out the session id, the plugin
uses the current session.

### What a receipt contains

A receipt lists the following, in this order:

1. a header;
2. the trust roots used;
3. the verification events, each with the raw attestation evidence that verification captured;
4. the sends;
5. the refusals;
6. the questions asked and the answers given;
7. the breaches;
8. the context compactions;
9. a fixed closing paragraph.

Some ledger rows describe the whole profile rather than one session. Locks, unlocks, verifications
and pin events are of this kind. A receipt includes those that fall within the locked period the
session belongs to.

### What a receipt never contains

A receipt never contains prompt or response text. The ledger stores only hosts, byte counts and
decisions. It rejects any row whose details carry a key that usually holds conversation content, such
as `messages`, `prompt` or `content`. When the plugin renders a receipt, it scans every row again and
removes any such key it finds.

### Clocks

Every time in a receipt comes from this machine's clock. The receipt labels each one "(host clock)".

### The hash chain and the chain head

The JSON form of a receipt adds a SHA-256 hash chain over its rows. Each row's hash covers the
previous row's hash and the row itself. The last hash in the chain is called the chain head. Both the
text form and the JSON form print the chain head at the top.

Anyone holding the file can recompute the chain. That includes anyone who edited the file. The chain
therefore detects an edit only when you compare it with a copy of the chain head that was kept
somewhere else when the receipt was rendered. If you want that protection, record the chain head
somewhere other than this machine.

The chain says nothing about whether the ledger was complete. It says nothing about whether the rows
are genuine either.

### A receipt is a self-report

Treat a receipt as a report that the plugin wrote about itself, from a file on your machine. The only
part a third party can check independently is the attached evidence.

### The closing paragraph

Every receipt ends with the same fixed paragraph. The paragraph is never filled in from data. It
splits what the receipt says into two kinds of claim.

**What the evidence shows.** Attached evidence that replays offline shows the following. An enclave
whose hardware report commits to a TLS key fingerprint T and an HPKE public key H ran code with
measurement M. That code was signed by repository R at release tag G. This held as of the capture
time that the evidence itself states.

T and H are the enclave's long-lived keys. They are not a per-session key.

Each verification row says which checks its evidence replays under. The first is the vendor SDK, at
a stated version. The second is the plugin's own restated policy check, identified by the SHA-256 of
the file `confidential_mode/verify/policy_check.py`. That file ships with the plugin and imports
nothing from the vendor SDK. A row captured before the file existed reads n/a for the second check.

Sends were gated by the vendor SDK only. The restated check never decided whether a request was sent.

The enclave host and the capture time inside the evidence are asserted by whoever captured it. A row
marked "unverified entry" has no evidence, or an incomplete capture. Such a row shows nothing.

**What is recorded only, and not proven.** Nothing in the receipt proves any of the following:

- that the plugin itself checked the evidence during this session;
- that this session's requests actually went to that enclave;
- that the request bodies were encrypted to that key;
- which HPKE key each send used, and whether its response decrypted (these are the plugin's own
  observations);
- that the attested build was the vendor's latest release at the time;
- whether the build or its key was revoked after the evidence was captured;
- what shell, terminal and code-execution tools sent off the machine;
- which model backends sit behind the vendor's router;
- any other access the vendor's operators have to the machines involved;
- Hermes' auxiliary calls, which can leave the locked tier while the profile is locked (for example after a
  runtime model switch). These are recorded after the fact. They are not prevented.

The paragraph states four further limits. First, the ledger is a file on this host, and another plugin can
write rows that look exactly like this plugin's own. Second, the hash chain behaves as described
above. Third, locked mode does not apply when Hermes runs in safe-worker mode, which loads no plugins.
Fourth, timestamps come from this machine's clock and are not attested.

### Offline replay

A replay re-runs a stored verification from the evidence alone. The plugin re-runs the SDK's own
verifier on the stored bytes, under these conditions:

- All network access is blocked for the thread doing the replay. If anything tries to connect, the
  replay fails.
- For AMD, the replay uses the stored VCEK certificate.
- For Intel, the replay uses the stored collateral. It checks Intel's signatures over that
  collateral again.
- Sigstore is checked against a stored trust root.
- Every clock the SDK consults is set to the capture time, or to a time you supply.

#### From the command line

```
hermes confidential replay receipt.json
```

Make `receipt.json` with `/confidential receipts <session> --json`. The command then does the
following, in order.

1. It reads the receipt and recomputes its hash chain. It prints whether the chain is intact.
2. For each evidence row, it decides which fingerprints to expect. If you pass
   `--expected-fingerprints CODE:ENCLAVE`, it uses those. Otherwise it uses the approved pin in this
   profile's `pins.yaml`, or in the file you name with `--pins`. Only if neither exists does it use
   the receipt's own claim. It labels that last choice "not independent".
3. It replays the row. The code must come from the repository `tinfoilsh/confidential-model-router`,
   unless you name another one with `--expected-repo`.
4. It prints each row's result, the value of each check, and any problems.
5. It prints the list of things a replay cannot establish. That list is below.
6. It exits with status 0 only if the hash chain is intact and every row replayed and matched. A
   broken chain makes the exit status 1, even when every evidence row replays.

By default, the replay uses the trust root recorded in the evidence. The evidence carries the trust
root's bytes, so the replay works on any machine, not only on the machine that captured it. Whoever
captured the evidence chose that copy, so it is not independent. Pass `--trusted-root <file>` to use
a Sigstore `trusted_root.json` that you obtained yourself. Evidence captured by an earlier version
of the plugin holds only a path to the trust root on the capturing machine. On any other machine,
replaying such evidence needs `--trusted-root`.

By default, the replay checks certificates as of the capture time recorded in the evidence. That time
is also asserted by the capturer. Pass `--as-of <ISO time>` to choose the time yourself.

The command also accepts `--expected-repo-id` and `--expected-owner-id`. These are the numeric GitHub
repository and owner IDs in the Sigstore signing certificate. A repository name can be renamed or
re-created by a different owner; the numeric IDs cannot. When you pass them, the `repo_identity` check
reports `name+id`. When you pass only the name, it reports `name`. The IDs for Tinfoil's router
repository at the time of writing are 1077094187 (repository) and 168487856 (owner).

#### From Python

The same check is available as the function `confidential_mode.verify.replay.replay(evidence)`. Run
it inside Hermes' environment:

```
cd ~/hermes-agent && PYTHONPATH=<plugin dir> uv run --no-sync python - receipt.json <<'EOF'
import json, sys
from confidential_mode.verify.replay import replay
doc = json.load(open(sys.argv[1]))
for item in doc["evidence"]:
    r = replay(item["evidence"])   # the evidence carries its trust root
    print(item["row_id"], "ok" if r.ok else "FAIL", r.checks)
    print("not established:", *r.not_established, sep="\n  ")
EOF
```

The function takes these keyword arguments:

- `expected_repo` is the repository the code must come from. It defaults to
  `tinfoilsh/confidential-model-router`.
- `expected_repo_id` and `expected_owner_id` are the numeric GitHub repository and owner IDs. When
  you pass both, the `repo_identity` check reports `name+id`; otherwise it reports `name`.
- `expected_fingerprints` is a pair: the code fingerprint and the enclave fingerprint you expect.
- `trusted_root` is a Sigstore trust root you supply, as bytes or as a file path.
- `as_of` is the time at which certificates are checked. It defaults to the capture time.

When you call it without `expected_fingerprints`, it compares the recomputed fingerprints only with
the ones the evidence itself recorded. In that case, compare `code_fingerprint` and
`enclave_fingerprint` in the result with your pin yourself. The command above does that comparison
for you.

#### What each check means

The result carries one value per check. Each value is `True`, which means the check passed, or a
string beginning with `fail:`, `n/a:` or `not_run:`. The result's `ok` is true only when every check
is `True` or `n/a`.

- `repo_match` checks that the evidence names the expected repository.
- `repo_identity` says how strongly that repository was identified: `name+id` when you supplied the
  numeric GitHub repository and owner IDs and both matched the signing certificate, `name` otherwise.
- `trust_root_source` is informational. It says whether you supplied the trust root or it was taken
  from the evidence.
- `hardware_signature` checks that the report is signed by the CPU vendor's key.
- `cert_chain` checks that the signing certificate chains to AMD's or Intel's root. It also checks
  the collateral signatures and the revocation lists.
- `tcb_policy` checks the SDK's policy on the enclave's firmware and security version. The TCB
  (trusted computing base) is the firmware and microcode the enclave depends on.
- `collateral_fresh_at_capture` checks, for TDX, that Intel's collateral had not expired at the
  checked time. For SEV-SNP this check is n/a.
- `code_signature` checks the Sigstore signature over the release, under the expected repository's
  workflow policy.
- `measurement_match` checks that the signed code measurement equals the enclave's measurement. It
  also checks that the fingerprints equal the recorded ones and the expected ones.
- `hardware_platform_match` checks, for TDX, that the hardware measurements match a signed entry in
  `tinfoilsh/hardware-measurements`. For SEV-SNP this check is n/a.
- `report_data_keys` checks that the keys in the report equal the keys the client used.
- `tls_cert_binding` checks that the TLS certificate captured on the EHBP connection carries the
  TLS public key the report commits to, and that its subject alternative names bind the HPKE key and
  the attestation hash. A pass means the TLS connection ended inside the attested router. A row
  captured before the plugin recorded certificates reads n/a. A certificate whose key is not the
  report's TLS key also reads n/a, not fail. The check is a record: EHBP encrypts each request body to
  the attested HPKE key whoever ends the TLS connection, and the SDK's transport is what enforces the
  TLS key on every connection.
- `policy_check` re-runs the plugin's own restated Sigstore policy check, the standalone file named
  above, over the captured bundle. It is independent of the vendor SDK.
- `sev_check` re-verifies an AMD SEV-SNP report with the plugin's own standalone checker: the
  signature, the certificate chain to AMD's root, and the report fields. For TDX this check is n/a.

#### What a replay cannot establish

Every replay result comes with the same fixed list, named `NOT_ESTABLISHED`. A replay cannot establish
any of the following.

- **That any request was sent to this enclave or answered by it.** The report commits to the
  enclave's keys, not to any request. It carries no nonce from the client either. A nonce is a random
  value the client sends so that the reply is provably fresh.
- **That requests were encrypted to this HPKE key.** Only the plugin's own log says so.
- **That this release was the latest release when it was verified.** The release tag is bound. The
  SDK's Sigstore policy requires that the signing workflow ran at `refs/tags/<tag>`. What nothing
  signs is which release the vendor called "latest" at the time. That answer comes from an unsigned
  GitHub API response.
- **Revocation or security-version changes after the capture time.**
- **That the capture time is when the capture happened.** The capture time is taken from the
  evidence itself.

## Fewer hosted parties without locking

Perhaps you are not going to lock. You can still reduce the number of vendors on the leak map with
four config changes.

Each vendor that remains still sees your conversation in plaintext.

These are config changes you make yourself. The plugin does not apply them.

None of the four has been evaluated for quality yet. We have not measured what they do to compression
summaries, titles or vision answers. Run `hermes confidential watch` before and after a change to see
what moved.

1. **Tell OpenRouter not to use your prompts for training.** Set
   `provider_routing: {data_collection: "deny"}`. `data_collection` is an OpenRouter routing option.
   With the value `deny`, OpenRouter routes only to providers that do not collect prompts.

   This setting affects OpenRouter only. Hermes applies it where it builds the main request
   (`agent/chat_completion_helpers.py:477`). We have not checked whether auxiliary calls carry it.

   Not yet evaluated for quality.

2. **Keep side jobs on your main provider.** Set `auxiliary.<task>.provider: main` for compression,
   title generation and the other auxiliary tasks. They then go to your main provider, and not to a
   second vendor you forgot about.

   Not yet evaluated for quality.

3. **Fall back only to providers you would accept as your main one.** Every `fallback_providers`
   entry receives your full context when the main provider returns a 429. Trim the list to providers
   you would choose on purpose, or empty it.

   Not yet evaluated for quality.

4. **Make vision explicit.** Set `auxiliary.vision.provider` and its model. Then `auto` cannot fall
   through to OpenRouter, Nous or DeepInfra when your main model cannot take images.

   Not yet evaluated for quality.

## Limitations (an upstream roadmap)

Locked mode closes what a plugin can close. Each gap below is a place where a plugin cannot close the
road on its own. For each one, this section says four things: what the gap is, why it exists, what
the plugin does about it today, and which change would close it. Most of the changes belong in Hermes
core. A few belong to the vendor or to the SDK, and the item says so. The long form, with more
evidence, is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

#### 1. Auxiliary calls do not pass through the `llm_execution` middleware

**The gap.** The plugin cannot refuse an auxiliary call at the moment it is sent.

**Why it exists.** Hermes makes auxiliary calls from `agent/auxiliary_client.py`. That code never
enters `run_llm_execution_middleware` (`hermes_cli/middleware.py:136`). The only caller of that
function is the main loop, at `agent/turn_api_call.py:139`. The `pre_auxiliary_call` hook cannot veto
a call either, because Hermes ignores what it returns (`agent/auxiliary_hooks.py:210-240`).

**What the plugin does today.** It refuses to lock while any auxiliary task routes off-tier. If an
auxiliary call goes off-tier anyway, it records a breach. It cannot stop the bytes. That includes the
auxiliary calls that follow a live `/model` switch, before the next turn's check runs.

**The core change that would close it.** Run every auxiliary attempt through the middleware, with
`purpose="aux:<task>"`. Alternatively, let `pre_auxiliary_call` return a block.

#### 2. The CLI's approve directive grants on any answer except "deny"

**The gap.** A plugin can ask Hermes to put a tool call in front of the user. Hermes' CLI then runs
the tool on almost any answer.

**Why it exists.** In `tools/approval.py:1006-1010`, the CLI grants the call unless the answer is the
exact string `"deny"`. An empty answer, `None`, `"d"` and `"yes"` all run the tool.

**What the plugin does today.** It enforces the answer itself, in its `tool_execution` middleware. The
tool runs only on an exact `once`, `session` or `always`.

**The core change that would close it.** Grant only on an explicit `once`, `session` or `always`.

#### 3. Shell and code-execution tools are not inspected

**The gap.** `terminal` and `execute_code` can send your notes anywhere, for example with `curl`.

**Why it exists.** Hermes gives a plugin the command text. It does not tell the plugin what the
command will connect to.

**What the plugin does today.** It treats these tools as on-host and lets them run. Every receipt says
that shell and code tools are not covered. It refuses to lock unless the terminal backend is `local`,
because on any other backend these tools and the file tools run on another machine or in a container.

**The core change that would close it.** A network policy on the terminal backend that plugins can
read and require. One example is the docker backend with networking switched off. The plugin could
then accept that backend too.

#### 4. MCP servers launched as a command on this host are not inspected

**The gap.** An MCP server configured with `command:` runs as a child process on this host. That process can
itself be a network client, or a proxy to a hosted service.

**Why it exists.** Hermes does not tell plugins what network access an MCP server has.

**What the plugin does today.** It allows tools from command servers. This is the same class of gap
as the terminal.

**The core change that would close it.** A declared network capability for each MCP server, or a
sandboxed launcher for each one.

#### 5. Safe-worker mode disables hooks and middleware

**The gap.** Safe-worker mode is a mode for managed Hermes worker processes in which Hermes
deliberately loads no plugins. Locked mode therefore does not apply there.

**Why it exists.** In a safe worker, Hermes skips plugin discovery (`hermes_cli/plugins.py:1206-1208`).
Hook dispatch returns nothing (`hermes_cli/plugins_dispatch.py:285-288` and `:561-564`).

**What the plugin does today.** Nothing. It discloses the gap in every lock message and in every
receipt.

**The core change that would close it.** A locked flag that Hermes core can see and that safe workers
honour.

#### 6. The trust boundary is the whole Hermes process

**The gap.** Any other plugin in the same process can register its own middleware or patch this
plugin's code.

**Why it exists.** By default, Hermes plugins share one Python interpreter. Hermes offers an
alternative, `plugins.isolation: host`. Under host isolation, this plugin's provider and middleware
register in a separate child process. They become invisible to Hermes, and Hermes gives no warning.
The project's compatibility tests found this before any plugin code was written
([docs/C0-spikes.md](docs/C0-spikes.md), spike 2).

**What the plugin does today.** It refuses to lock unless isolation is `in_process` and its provider
is visible to Hermes. It records each tool's handler at lock time.

**The core change that would close it.** A policy tier for middleware that always runs outermost, and
a switch that says "only these plugins load while locked".

#### 7. The vendor attests the router, not the model

**The gap.** The pin covers `tinfoilsh/confidential-model-router`. The model backend behind the router
is not in the pin.

**Why it exists.** This is how Tinfoil's attestation works. It is not a Hermes gap.

**What the plugin does today.** It states the gap in every receipt.

**The change that would close it.** Per-model attestation, on the vendor's side.

#### 8. No nonce and no attested time

**The gap.** The attestation report commits to the enclave's keys, not to any request. Every
`verified_at` time is your own clock.

**Why it exists.** Tinfoil's report carries no client nonce and no signed time. This is not a Hermes
gap.

**What the plugin does today.** It labels every time "(host clock)". It makes no freshness claim
beyond "verified at host-clock time T".

**The change that would close it.** A client nonce in the report, and signed responses. Both are
changes on the vendor's side.

#### 9. Context-length probes bypassed the attested transport (fixed in the plugin)

**The gap.** When Hermes builds an agent, it asks the provider for the model's context window. It does
this by sending `GET /models` and `POST /api/show` with plain HTTP and your API key. These requests go
outside the attested transport.

**Why it exists.** Hermes resolves the context window at `agent/agent_init.py:1883-1884`. It skips the
probe only if the provider profile answers the question itself.

**What the plugin does today.** Its provider profile answers `get_model_context_length` from
`confidential.tinfoil.context_length`. Hermes therefore never sends the probe.

**The core change that would close it.** Send metadata probes through the profile's own client.

#### 10. SDK caches outside the plugin's data (fixed in the plugin)

**The gap.** The tinfoil SDK and sigstore-python keep on-disk caches in their default user cache
directories, outside the plugin's data.

**Why it exists.** Both libraries compute those paths themselves. This is not a Hermes gap.

**What the plugin does today.** It redirects both caches under the plugin's data directory before the
first verification.

**The change that would close it.** A cache-directory parameter in the SDK.

#### 11. Start-up model-list request on a drifted runtime

**The gap.** Suppose the session's live runtime has been switched to a hosted provider. When the agent
starts, Hermes lists that provider's models with `GET .../models` and your API key. It sends this
request on its default transport, before any plugin seam runs (`agent/model_metadata.py:898` and
`:1026`).

The request carries no conversation text. The plugin refuses the turn that follows. By then, however,
the request has already gone out.

**Why it exists.** Hermes gives plugins no seam before this request.

**What the plugin does today.** It refuses the turn and records the drift.

**The core change that would close it.** Let a provider profile or a hook veto metadata requests.

#### 12. No mixed "attested or on-host" tier yet (planned)

**The gap.** A lock is one tier. Cheap side jobs cannot run on an on-host model while the main model is
attested.

**Why it exists.** This is a limit of the plugin, not of Hermes.

**What the plugin does today.** Nothing yet.

**The change that would close it.** A tier inside the plugin whose rule accepts any destination that
either of the two existing rules accepts. This is planned. It needs no change in Hermes.

What the plugin touches on your machine and on the network is listed in
[docs/DISCLOSURE.md](docs/DISCLOSURE.md).

## Install

```
hermes plugins install confidential-mode          # from the catalog, once listed
# or: hermes plugins install https://github.com/ainsleys/hermes-confidential-mode
```

After installing, do the following.

1. Set `TINFOIL_API_KEY` the way you set any provider key.
2. Run `hermes confidential setup --model <model id>`.
3. Leave `plugins.isolation` at its default value, `in_process`. Under host isolation, Hermes cannot
   see the attested provider, and the preflight refuses to lock.

### Upgrading

Restart every Hermes process that loads the plugin after you upgrade it: the gateway, and any CLI or
TUI session. Do this before you lock or unlock from any of them. The lock records a fingerprint of
the routing config. This version adds the terminal backend to that fingerprint. A process still
running the old version reads a lock made by the new version as a changed config, and the reverse
is true as well. Each such process then refuses every turn and marks the session breached.

A lock made by an earlier version keeps working after the upgrade. The new version recognises the
old fingerprint, so the upgrade alone records no breach. The new terminal-backend checks still apply
to that lock on every turn. To record the new fingerprint, run `/confidential off` and then
`/confidential on <tier>`.

## Config

[docs/config.example.yaml](docs/config.example.yaml) lists every key the plugin reads. It also lists
the core Hermes keys the attested preflight needs, and the context length for each model.

The plugin's own keys live under a top-level `confidential:` section of `config.yaml`:

| Key | Default | What it does |
|---|---|---|
| `confidential.tinfoil.enclave` | Unset, which means router discovery. | Names one router host to verify and use. Setting it stops the AMD/Intel switching described under Pins. |
| `confidential.tinfoil.context_length` | 65536 | The context window the plugin reports to Hermes. Because the plugin reports it, Hermes never sends its own probe. |
| `confidential.tinfoil.tls_probe` | `true` | After each verification, sends one request without a body over the verified connection and records the TLS certificate it saw. The record is an observation and never fails a verification. Only the exact value `false` turns it off. |
| `confidential.verify_ttl_seconds` | 300 | How many seconds one verification vouches for the router. It is measured on a monotonic clock, which does not jump when the system time changes. |
| `confidential.verify_wait_seconds` | 20 | How many seconds a turn waits for a verification before the turn is refused. |
| `confidential.pins.auto_approve_platform_only` | `false` | When `true`, the plugin applies a new pin without asking if only the platform changed and the SDK's signed hardware check passed. That check exists for TDX only. |
| `confidential.on_host.extra_hosts` | `[]` | Extra hosts that the `on-host-only` tier counts as on-host. |
| `confidential.model` | Unset. | The model id that `hermes confidential setup` writes into the config block it prints. |
| `confidential.near.base_url` | `https://cloud-api.near.ai/v1` | NEAR AI Cloud's gateway. Attestation, inference and signature requests all go here. |
| `confidential.near.models` | `[]` | Every NEAR model id Hermes may send. The plugin adds the ids that `model.default` and `auxiliary.<task>.model` name for `attested-near`. The pin covers exactly this list. |
| `confidential.near.require_provider_tee` | `true` | A NEAR send counts as verified only with a signature made by an attested model server's key. Only the exact value `false` turns it off. |
| `confidential.near.require_tls_binding` | `true` | The TLS certificate of the attestation connection must be the certificate the gateway's report binds. |
| `confidential.near.accepted_tcb_statuses` | `[UpToDate]` | The Intel TCB status values accepted for the gateway, from Intel Trust Authority's token. |
| `confidential.near.signature_wait_seconds` | 5 | How many seconds the plugin keeps asking for a response's signature after the response ended. |
| `confidential.near.streaming` | `false` | Whether Hermes may stream main calls to NEAR. NEAR's gateway re-signs streamed responses with its own key. |
| `confidential.near.context_length` | 65536 | The context window reported to Hermes for `attested-near`. |

## Tests

```
cd ~/hermes-agent && PYTHONDONTWRITEBYTECODE=1 HERMES_HOME=$(mktemp -d) \
  uv run --no-sync --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \
  pytest <plugin dir>/tests -q -p no:cacheprovider
```

The seam tests run against real Hermes modules at commit 84a0301. They use fakes at three boundaries
only: the SDK, the network, and the person who answers prompts.

The live NEAR tests in `tests/live/` are skipped unless `NEAR_AI_API_KEY` is set.

Two commands check the plugin against the catalog rules: `hermes plugins validate --install-deps
<plugin dir>` and `hermes plugins doctor --ci <plugin dir>`. See
[docs/RUNNING_TESTS.md](docs/RUNNING_TESTS.md) for more.

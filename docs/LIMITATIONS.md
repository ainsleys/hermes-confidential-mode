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
every sealed turn; refuses `openai-codex` and `moa` as the main provider. Because "auto" tasks follow
the LIVE main runtime (`agent.auxiliary_client.set_runtime_main`), not config, each sealed turn also
classifies the live runtime and ends the turn when it is off-tier, and on gateway surfaces `/model`
and `/moa` are refused while sealed (`pre_gateway_dispatch`). At runtime it ledgers each auxiliary
attempt and, if one goes off-tier anyway (between turns after a CLI `/model` switch, mid-turn, or when
Hermes skips the check), writes a `breach` row and marks the session breached. It cannot stop the
bytes.

**Core change.** Run each auxiliary provider attempt through `run_llm_execution_middleware` with
the task in the context (`purpose="aux:<task>"`), or let `pre_auxiliary_call` return
`{"action": "block"}` and have the caller raise instead of sending. Same for the summary call.

A related case: `pre_llm_call` is a timeout-bounded hook, and when it misses
`plugins.hook_callback_timeout` Hermes skips it and runs the turn (`hermes_cli/plugins_dispatch.py:42-52`,
`:301-312`). The preflight fingerprints every `plugins.*` key that governs hooks
(`confidential_mode/preflight.py:55-56`) and refuses to seal with a timeout under 5 s; an edit after
seal is refused for the main call by the llm gate, but a title-generation call that runs first is
only ledgered.

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

Note that `session` and `always` are real grants: `always` is stored in Hermes' `command_allowlist`
as `plugin_rule:confidential-mode:tool:<name>` and stops the asking, across seals, until you remove it.

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
request, and carries no client nonce. `verified_at` is this machine's clock. The release tag is bound: the SDK's Sigstore
policy requires the signing workflow ref to be `refs/tags/<tag>` (tinfoil 0.14.2 `sigstore.py:164-172`).
What nothing signs is which release the vendor called "latest" (`github.py:50` asks the GitHub proxy).
The `NOT_ESTABLISHED` string in `replay.py` still says "release metadata is unsigned; only the digest
is bound", which understates the tag binding.

**What the plugin does.** Labels every time "(local clock)". The offline replay returns a fixed
`NOT_ESTABLISHED` list with every result. No freshness claim is made beyond "verified at local time T".

**Core change.** None in Hermes. Vendor side: a client nonce in the report, signed responses.

## 9. What the network still sees, and what the receipt leaks

**What happens.** Even with every road above closed:
- Tinfoil terminates TLS at its router. It sees your API key header, request and response sizes,
  timing and your IP. EHBP encrypts the body to the enclave's key, not the metadata.
- The collateral proxies are vendor-run: `github-proxy.tinfoil.sh`, `kds-proxy.tinfoil.sh` and
  `tdx-proxy.tinfoil.sh` see each verification, from your IP, and serve the bytes the verifier checks
  (the checks are signature checks, so a lying proxy causes a refusal, not a false pass).
- DNS: every host above is looked up through your resolver.
- The ledger is a metadata trail: hosts, sizes, times, tool names. A shared receipt shares it.
- Whoever operates the machine Hermes runs on (a cloud agent host, a VPS provider) sees every prompt
  before any of this applies.

**What the plugin does.** Nothing beyond saying so. Receipts never contain prompt text.

**Core change.** None in Hermes for the network items. For the host operator, the answer is running
Hermes on a machine you control, or Hermes itself in an enclave (out of scope).

## 10. Start-up model-list probe on a drifted runtime

**What happens.** If the live runtime has been switched to a hosted provider (for example a session
`/model` on the CLI), Hermes' agent start-up lists that provider's models (`GET .../models` with your
API key) on its default transport before any plugin seam (`agent/model_metadata.py:898` and `:1026`).
No conversation text is sent; the plugin refuses the turn itself. Marked as a disclosed Hermes gap by
the xfail on `tests/hostile/test_integrated_hostile.py::test_leak_live_off_tier_runtime_hits_hermes_default_transport`.

**What the plugin does.** Refuses the turn and records the drift. It cannot stop the probe.

**Core change.** Let a provider profile or a hook veto metadata fetches, or route them through the
profile's client.

## 11. Context-length probes bypassed the attested transport (mitigated in-plugin)

**What happens.** At agent build Hermes resolves the context window (`agent/agent_init.py:1883-1884`)
and, without an answer from the profile, probes `GET {base_url}/models` and `POST /api/show` with
plain httpx and the API key, off the attested transport.

**What the plugin does.** The `attested-tinfoil` profile answers `get_model_context_length` with
`confidential.tinfoil.context_length` (default 65536), so the probe never runs. Set it per model
(see [config.example.yaml](config.example.yaml)).

**Core change.** Route metadata probes through the profile's own client, or skip them for any
profile that implements `create_client`.

## 12. SDK caches outside the plugin's data (mitigated in-plugin)

**What happens.** tinfoil 0.14.2 and sigstore-python cache under platformdirs defaults
(`~/Library/Caches/tinfoil`, `~/.cache/tinfoil`, sigstore TUF dirs) computed at import.

**What the plugin does.** Re-points them under its data dir before the first verification
(details in [DISCLOSURE.md](DISCLOSURE.md)). A process that used the SDK earlier may already have
written to the defaults.

**Core change.** None in Hermes. SDK side: a cache-directory parameter.

## 13. No mixed "attested or local" tier (planned)

**What happens.** A seal is one tier. You can't run the main model attested and send cheap side jobs
(titles, compression) to a local model, because the local-only predicate refuses the enclave and the
attested predicate refuses the local host (`confidential_mode/tiers.py`).

**Plan.** An in-plugin tier whose predicate accepts a destination that either predicate accepts, with
the attested checks unchanged for the attested routes. No core change needed.

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
- Additions made with `/confidential allow` last for the seal only: they are stored with the seal's
  identity in `allowlist.yaml`, a new seal starts with none (`confidential_mode/gate_tools.py:452-454`),
  each seal persists them tagged with its identity (`confidential_mode/sealing.py:323-324`), and
  `/confidential off` deletes the file (`confidential_mode/commands.py:315-316`).
- Pins need a consent record: the attested check refuses a pin with no matching `pin_applied` ledger
  row ("pin has no consent record"). Code in the same process can still write such a row.
- The offline replay verifies against the repo, trust root and `as_of` that the evidence itself names;
  it does not yet require `tinfoilsh/confidential-model-router` or your pinned fingerprints. Compare
  the result's fingerprints with your pin.
- The pin prompt shows fingerprints truncated to 16 hex characters and cannot tell a code change from
  an AMD/Intel platform flap. The first pin is trust on first use.

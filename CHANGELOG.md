# Changelog

All notable changes to Hermes Confidential Mode are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version numbers follow
[Semantic Versioning](https://semver.org/).

## 0.1.0 (unreleased)

The first release, for Hermes Agent 0.22.7 or later, verified against Hermes commit 84a0301.

### Added

- Two tiers to lock a profile to: `attested` (a verified Tinfoil or NEAR AI Cloud enclave) and `on-host-only` (loopback and the hosts you list). See [README](README.md).
- `attested-tinfoil` and `attested-near` provider profiles that verify the enclave's hardware report before any model call. See [Requirements](README.md#requirements).
- A preflight that checks every configured route before a lock and before each turn, with a table naming each key to change. See [Quick start](README.md#quick-start), step 4.
- Build pins: a changed enclave build is refused until you approve it, with `pins review` building a review bundle for a pending NEAR or Tinfoil build. See [Commands](README.md#commands).
- A tool prompt the first time each tool not classed as on-host runs in a conversation during a lock, with `confidential.tools.ask: each_call` to ask on every call. See [Quick start](README.md#quick-start), step 5.
- A ledger of every model call's purpose, host and size, never its text, from the moment the plugin is enabled, and `watch` to stream it. See [README](README.md).
- Session receipts as text or hash-chained JSON, and `replay` to re-check a receipt's evidence offline. See [Quick start](README.md#quick-start), step 6.
- `setup` for each vendor: verifies the enclave, asks for the first pin and prints the config block to merge. See [Quick start](README.md#quick-start), step 3.
- `allow` and `revoke` for the plugin's own tool grants, and `status`, `check`, `pins` and `pins retire`. See [Commands](README.md#commands).
- Token counts from Tinfoil's router in each send row and as a session total in receipts, labelled router-reported. See [GUIDE](docs/GUIDE.md#what-a-receipt-contains).

### Security

- Off-tier main calls and every fallback are refused before any byte leaves while locked. See [README](README.md).
- Inference connections on both vendors are pinned to the TLS key of the verified report, inside the handshake. See [LIMITATIONS 9](docs/LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks).
- Request bodies are encrypted to the enclave (Tinfoil's encrypted transport) or to the model key (NEAR), and NEAR replies are released only when their signature verifies. See [LIMITATIONS 14](docs/LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).
- A gated tool runs only on an exact `once`, `session` or `always` answer, so Hermes' grant-on-any-answer prompt cannot approve it. See [LIMITATIONS 2](docs/LIMITATIONS.md#2-the-cli-approve-directive-grants-on-any-answer-except-deny).
- Tools are blocked, not asked, under yolo, approvals off, cron and one-shot runs. See [Quick start](README.md#quick-start), step 5.
- Scheduled jobs, routed delegation and tool servers on off-tier remote hosts are blocked while locked. See [README](README.md).
- A gateway `/model` or `/moa` switch is refused while locked. See [LIMITATIONS 1](docs/LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution).
- Approval prompts refuse in a process started by an agent's tool, and tool calls that name the plugin's command or state files are refused. See [LIMITATIONS 15](docs/LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt).
- Unreadable lock state refuses every send and blocks every tool until `status` or `off` repairs it. See [GUIDE](docs/GUIDE.md#what-happens-while-locked).
- Vendor keys are read only through Hermes' secret scope and never shown, and data files are mode 0600. See [Install](README.md#install).
- State files are written with a durable write: fsync, rename, then fsync of the directory. See [INTERFACES](docs/INTERFACES.md#state-files-locks-and-writes).

### Known limits

- Hermes' auxiliary calls are recorded, not refused, when they leave the tier mid-turn. See [LIMITATIONS 1](docs/LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution).
- Shell and code execution tools are not inspected. See [LIMITATIONS 3](docs/LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected).
- MCP command servers are not inspected. See [LIMITATIONS 4](docs/LIMITATIONS.md#4-mcp-command-servers-are-not-inspected).
- Locked mode does not apply in Hermes' safe-worker mode. See [LIMITATIONS 5](docs/LIMITATIONS.md#5-safe-worker-mode-disables-hooks-and-middleware).
- The trust boundary is the whole Hermes process, and a receipt is the plugin's own record apart from its signed evidence. See [LIMITATIONS 6](docs/LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process).
- Tinfoil's measurement covers the router, not the model. See [LIMITATIONS 7](docs/LIMITATIONS.md#7-the-vendor-measurement-covers-the-router-not-the-model).
- NEAR's gateway sees image parts, the model id, settings, headers, sizes and timing. See [LIMITATIONS 14](docs/LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).
- An agent with a terminal can still reach the approval prompt by some routes. See [LIMITATIONS 15](docs/LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt).
- Hermes titles the plugin's approval prompt "Dangerous Command". See [LIMITATIONS 16](docs/LIMITATIONS.md#16-hermes-titles-the-plugins-approval-prompt-dangerous-command).
- A locked session has no fallback: a vendor outage ends the turn. See [Limits](README.md#limits).
- The attested tier admits only the open-weight models the two vendors serve in enclaves. See [README](README.md).

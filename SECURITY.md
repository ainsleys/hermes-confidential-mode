# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub's private vulnerability reporting: on
https://github.com/ainsleys/hermes-confidential-mode, open the **Security** tab and choose **Report a
vulnerability**. The project publishes no security email address.

If that button is not shown, open an ordinary issue that asks for a private channel and leaves out
every detail of the vulnerability. Do not post an exploit, a proof of concept or a vendor API key in a
public issue.

A useful report names the plugin commit (`hermes confidential status | grep '^Plugin:'` prints the commit), the
Hermes version, the tier and vendor, and the steps that reproduce the problem. Remove API keys, prompts
and receipts that carry private data before you attach anything.

## Scope

In scope: the plugin's own code in this repository, meaning `__init__.py`, everything under
`confidential_mode/` and `scripts/`, and the claims the [README](README.md) makes about that code. A
report that the code does not do what the README or [docs/CLAIMS.md](docs/CLAIMS.md) says the code does is
in scope.

Out of scope, with where to report instead:

- **Hermes core** (the agent loop, tools, approvals, the plugin loader): report to
  [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent).
- **The vendors**: Tinfoil's SDK, router and enclaves, and NEAR AI Cloud's gateway, model servers and
  attestation endpoints. Report to the vendor.
- **Gaps that [docs/LIMITATIONS.md](docs/LIMITATIONS.md) already discloses.** A way to make a
  disclosed gap worse than the section states is in scope.

## Threat model in brief

The [guide's threat model](docs/GUIDE.md#threat-model) states the full model. In brief:

- **The trust boundary is the whole Hermes process.** Another plugin in the same process can patch
  this plugin, register its own middleware or write ledger rows that look like this plugin's.
  ([LIMITATIONS 6](docs/LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process))
- **Shell and code execution are not inspected.** `terminal`, `execute_code` and `process_manage` run
  on this host while locked, and a command those tools run can reach the network. MCP servers launched as a
  command are the same class of gap.
  ([LIMITATIONS 3](docs/LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected),
  [LIMITATIONS 4](docs/LIMITATIONS.md#4-mcp-command-servers-are-not-inspected))
- **Tinfoil attests the router, not the model.** The pin covers the router enclave the client talks to,
  not the model backend the router forwards to.
  ([LIMITATIONS 7](docs/LIMITATIONS.md#7-the-vendor-measurement-covers-the-router-not-the-model))
- **NEAR's gateway sees part of each request.** Image parts reach the gateway in plaintext, and the gateway reads the
  model id, plaintext parameters, headers, sizes and timing. A gateway that swaps the client key header
  can read a reply before the plugin withholds the reply.
  ([LIMITATIONS 14](docs/LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open))
- **A receipt is a self-report.** The plugin writes the receipt from a ledger file on the user's machine. Only
  the attached enclave evidence can be checked by someone else.
  ([LIMITATIONS 6](docs/LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process),
  [LIMITATIONS 9](docs/LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks))
- **Self-approval routes.** An agent with terminal access on the same host can reach the approval
  prompt for a pin or a tool grant by some routes, such as a nested chat the agent starts. The ledger records
  every approval with its surface.
  ([LIMITATIONS 15](docs/LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt))
- **Side calls are recorded, not stopped.** Hermes' auxiliary calls do not pass through the
  middleware the plugin uses, so one that leaves the tier mid-turn is recorded as a breach.
  ([LIMITATIONS 1](docs/LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution))

## How the code handles keys

The plugin's code keeps these rules. A change that breaks one is a vulnerability.

- **Keys come only through Hermes' secret scope.** The plugin reads `TINFOIL_API_KEY` and
  `NEAR_AI_API_KEY` only through `agent.secret_scope.get_secret` (`provider.py:api_key_for`), or takes
  the key Hermes resolved and passed to `create_client`. The plugin reads no `.env` file, no
  `auth.json`, nothing under `~/.tinfoil`, no keychain, and no key from `os.environ` itself.
- **Presence checks never read the value out.** `OPENROUTER_API_KEY` and `NOUS_API_KEY` are checked
  only for whether each variable is set, through the same secret scope. `preflight.py:key_state`
  reads the secret scope and, for presence only, a route's `api_key` in `config.yaml`; the function
  returns "set", "not set" or "not readable in this scope", never the value or its length.
- **Keys are never logged or stored.** No log line, ledger row, receipt or pins file carries a key.
  The ledger rejects rows whose detail carries conversation-shaped keys (`ledger.py:FORBIDDEN_DETAIL_KEYS`),
  and the preflight table redacts secret-looking config values (`preflight.py:redact_value`).
- **Attestation requests carry no key.** Only inference requests and NEAR signature fetches carry the
  vendor key, and both travel on connections pinned to the attested TLS key.
- **The plugin stores no credential.** The prompt-cache secret the plugin generates for the Tinfoil SDK
  (`verify/tinfoil.py:load_or_create_user_cache_secret`) is not a credential for anything.

[docs/DISCLOSURE.md](docs/DISCLOSURE.md#credentials) lists every credential and environment variable
the plugin touches.

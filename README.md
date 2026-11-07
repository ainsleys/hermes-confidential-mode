<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here, in the title, and in the install lines) -->
# confidential-mode

confidential-mode keeps your Hermes conversations inside verified enclaves or on your own machine, and
gives you a report you can check.

Hermes makes more model calls than the one you see. Besides your main chat, it calls a model to write
session titles, compress old conversation, describe images and more, and it can fall back to a second
provider when the first fails. Each of those has its own setting in Hermes' config, and the defaults
can send several of them to a different company than your main provider. Tools like web search send
parts of the conversation to outside sites. So a conversation you thought went to one verified
provider can reach four or five others.

The plugin fixes that in three steps.

1. **It logs every model call** from the moment it is installed: which host, how many bytes, never the
   text. `hermes confidential status` shows where calls have gone; `hermes confidential watch` streams
   them live.
2. **You turn on a lock**, which means the plugin now enforces a rule for where text may go.
   `on-host-only` allows only your machine. `attested` allows only enclaves whose hardware report the
   plugin has verified and whose build you approved. Before locking, the plugin checks every
   configured route and refuses if any leads elsewhere, naming the setting to change. While locked,
   every model call, main or side, goes only to the tier (a side call that strays mid-turn is
   recorded, not stopped); fallbacks are refused; and the first time a tool wants to send data off
   the machine, the plugin asks you, with an answer that can last for the session. On the attested
   tier the vendor's protocol encrypts your text to the enclave's key before it leaves your machine,
   so the servers in between cannot read it. On NEAR, the gateway still sees images, the model id,
   settings, headers, sizes and timing, and could read a reply by swapping its key, which the plugin
   detects only afterwards. The plugin checks that this encryption is on and, on NEAR AI Cloud,
   verifies the enclave's signature on every reply.
3. **When you want, you render a receipt.** The receipt is a text file built from the plugin's log:
   every model call in the session, the lock period, the enclave build that was verified, and the raw
   hardware evidence captured at each verification. The evidence is signed by the enclave's hardware
   and the vendor, so anyone can re-check it offline with `hermes confidential replay`. The rest of
   the receipt is the plugin's own record on your machine.

Two limits to know before you rely on this. The agent can still run shell commands and code, and the
plugin does not look inside them, so a command such as `curl` could send text anywhere; every receipt
says so. And because the receipt is written by the plugin on your machine, someone else can trust only
its signed evidence.

![Figure 2. With the plugin, shown for Tinfoil: preflight checks every configured route, side calls
go to the verified enclave, fallback is refused, tools ask, memory stays on the host, shell and code
stay open on this host, and a ledger records model sends and tool
answers.](docs/images/routes-figure-2-with-the-plugin.svg)

## Requirements

- Hermes Agent 0.22.7 or later (`requires_hermes` in `plugin.yaml`). The plugin was built and tested
  against Hermes commit 84a0301.
- macOS or Linux.
- Python as your Hermes install requires; the plugin's dependencies go into Hermes' environment.
- For the `attested` tier, a vendor API key: `TINFOIL_API_KEY` for Tinfoil, or `NEAR_AI_API_KEY` for
  NEAR AI Cloud. Watching the ledger and the `on-host-only` tier need no key.

## Install

```
hermes plugins install https://github.com/ainsleys/hermes-confidential-mode
hermes plugins enable confidential-mode
hermes confidential status | grep '^Plugin:'
```

- **Enable is required.** Without it, every `hermes confidential` command fails with
  "'confidential' is not a hermes command".
- **Enable can take a few minutes.** It downloads `tinfoil`, `pynacl`, `sigstore` and the packages
  they need into Hermes' environment, and meanwhile Hermes prints only "Resolving Python
  dependencies" and "Installing Python dependencies". A quiet terminal doesn't mean it has hung. Set
  `HERMES_VERBOSE=1` to watch the installer.
- **Check the commit.** The last command prints a line such as
  `Plugin: confidential-mode 0.1.0 (commit 3c20cf4a1b2c (git checkout))`. Compare it with the commit
  you meant to install; receipts carry the same value.
- **Set your key** in the shell that starts Hermes, or in `<hermes home>/.env`.
- Leave `plugins.isolation` at its default, `in_process`; under host isolation the lock is refused.
- Running Hermes from a source checkout with `uv run --no-sync`? The enable step doesn't run there, so
  install `pynacl` yourself ([docs/RUNNING_TESTS.md](docs/RUNNING_TESTS.md)).

[Install in detail](docs/GUIDE.md#install-in-detail) covers start-up output, data files and upgrading.

## Quick start

**1. Look at where you are.** Nothing is locked yet; the plugin is only observing.

```
$ hermes confidential status
Confidential mode: not locked (observing only)
…
Preflight: run /confidential check <tier>
…
Plugin: confidential-mode 0.1.0 (commit 3c20cf4a1b2c (git checkout))
Data: ledger and evidence in …; lock, pins and tool grants in …
```

`hermes confidential watch` streams each model call's purpose, host and size, locked or not.

**2. Verify the vendor and approve the first pin.** Setup verifies the enclave, shows its
fingerprints, asks you to approve them, and prints a config block to merge into `config.yaml`. It
never writes your config.

```
$ hermes confidential setup --vendor tinfoil --model llama3-3-70b
TINFOIL_API_KEY: set
Verified router-0.tinfoil.sh: code 284bd9e5d470c481 enclave … release v0.0.170 (verified_at is the host clock)
…
Then run `hermes confidential check --tier attested` and `/confidential on attested`.
```

For NEAR AI Cloud, use `--vendor near --model Qwen/Qwen3.8-27B`.

**3. Lock.** The preflight checks every route in your config first. If any would leave the tier, the
lock is refused with a table naming each key to change. Once locked, off-host tools ask you first, on
both tiers.

```
$ hermes confidential on attested
confidential-mode: discovering tools... 78 found
Locked to Tinfoil, llama3-3-70b at router-0.tinfoil.sh; verified … ago. Off-host tools ask first. Details: hermes confidential status, docs/LIMITATIONS.md
```

**4. Have a conversation.** Start `hermes` and ask something that needs the web. The first time each
tool wants to send data off the machine, Hermes' approval panel shows the plugin's line:

```
Confidential mode: web_search wants to send ~1 KB of this conversation off the machine
```

Pick Allow once, Allow for this session (that tool then stops asking until the session ends), Add to
permanent allowlist, or Deny. Hermes titles this panel
"Dangerous Command" for every plugin approval, and the plugin can't change that title.

**5. Read the receipt.** Receipts are rendered on demand, for the current session or any past one. In
the chat, `/confidential receipts` renders the current session; from a terminal, pass any session id:

```
$ hermes confidential receipts <session id>
Confidential mode receipt for session local-c5d92ecacb59…
CHAIN HEAD: dae7c49c3089b27463fe369f7b834e9c0d895ea31cc56cebfbf46cabeefe438d
…
Locked tier: attested  (from lock row)
Provider / model: attested-tinfoil / llama3-3-70b
…
Sends (purpose, host, bytes; never text)
  #17 2026-11-06T15:39:50.138Z (host clock)  aux:title_generation  host=router-0.tinfoil.sh  1433 bytes  attested-tinfoil/llama3-3-70b  observed  …
…
What this receipt proves and what it only records. …
```

A full receipt is in [docs/examples/receipt-2026-11-06.txt](docs/examples/receipt-2026-11-06.txt).
Add `--json` for the hash-chained form, and replay its evidence offline with
`hermes confidential replay <receipt.json>`.

## Limits

The ones you're most likely to hit. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) has the full list and
the change that would close each.

- **Shell and code execution aren't inspected.** `terminal`, `execute_code` and `process_manage` run
  on this host while locked, and the plugin does not look inside shell commands or code, so a command
  such as `curl` could send text anywhere. Every receipt names them as unproven.
  ([section 3](docs/LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected))
- **NEAR's gateway sees part of each request.** Image parts reach it in plaintext, and it reads the
  model id, plaintext parameters, headers, sizes and timing. Message text, tool definitions and tool
  calls are encrypted to the verified model key, which every instance of that model shares.
  ([section 14](docs/LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open))
- **The pin prompt asks a human, but an agent with terminal access can reach it.** Some routes, such
  as a nested chat the agent starts, stay open. The ledger records every approval with its surface,
  so treat a pin approved during an agent session as the agent's unless you remember answering.
  ([section 15](docs/LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt))
- **A receipt is a self-report.** It's the plugin's record, from a file on your machine that you or
  another plugin could edit. Only the attached enclave evidence can be checked by someone else.
  ([section 6](docs/LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process))
- **A locked session has no fallback.** If the provider errors, or can't be verified within 20
  seconds, the turn ends and you resend; nothing is rerouted.
  ([docs/LIMITATIONS.md](docs/LIMITATIONS.md), [docs/COSTS.md](docs/COSTS.md))

A side call that goes off-tier mid-turn (after a runtime model switch, say) is recorded as a breach,
not stopped. Locked mode doesn't apply in Hermes' safe-worker mode, which loads no plugins. If Hermes
runs on someone else's machine, its operator sees every prompt before any of this applies. See the
guide's [threat model](docs/GUIDE.md#threat-model).

## Commands

Every verb works as `hermes confidential <verb>` in a terminal and as `/confidential <verb>` in chat,
except where noted.

| Command | What it does |
|---|---|
| `on <on-host-only\|attested>` | Lock this profile (the preflight runs first). |
| `off` | Unlock, with the lock period's counts. |
| `status [--verbose]` | Lock state, pins, verification, installed commit; `--verbose` adds the tool list. |
| `check [tier]` | The preflight table (`check --tier <tier>` in a terminal). |
| `setup` | Terminal only: `hermes confidential setup [--vendor near] --model <id>`. |
| `allow <tool>` | Let an off-host tool run without asking, for this lock (asks you). |
| `revoke <tool>`, `revoke --all` | Withdraw the grants confidential mode holds. |
| `pins` | Approved pins, the pending pin, tool grants. |
| `pins review` | Terminal only: fetches the review bundle for a pending pin. |
| `pins approve` | Approve the pending pin (asks you). |
| `pins retire <fingerprint>` | Remove one approved entry. |
| `receipts <session> [--json]` | A session receipt. |
| `replay <receipt.json>` | Terminal only: replay a receipt's evidence offline. |
| `watch` | The latest ledger rows (live in a terminal: `hermes confidential watch`). |

## Documentation

- [docs/GUIDE.md](docs/GUIDE.md): the full guide: tiers, NEAR, locking, pins, receipts, replay,
  config, tests.
- [Comparison with earlier approaches](docs/GUIDE.md#comparison-with-earlier-approaches): this plugin
  next to five closed Hermes pull requests.
- [docs/COSTS.md](docs/COSTS.md): what locking costs in latency, quality and task success.
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): every gap, and the change that would close it.
- [docs/DISCLOSURE.md](docs/DISCLOSURE.md): what the plugin touches on your machine and the network.
- [docs/INTERFACES.md](docs/INTERFACES.md): how the plugin's modules fit together.

## Status

Experimental. Built for the Nous Research Hermes plugin hackathon, November 2026.

Support: open an issue at https://github.com/ainsleys/hermes-confidential-mode/issues.

<!-- PLUGIN_NAME: confidential-mode  (working name; swap it here, in the title, and in the install lines) -->
# confidential-mode

This Hermes plugin shows you every place your conversation leaves the machine, then lets you seal a
profile so the model can only be on your own box or in a Tinfoil enclave whose build you approved.
Sealed, it refuses off-tier model calls and fallbacks before a byte is sent, asks you before every
off-machine tool call, and won't seal at all while a side job (compression, titles, vision, memory)
is configured to go somewhere else. Every send, refusal, ask and answer goes to a local ledger you
can watch live and turn into a receipt.

Think Little Snitch for your agent: deny by default, an allow-once prompt, a list of what you've
allowed, and a log.

Built and tested against Hermes 84a0301 and tinfoil SDK 0.14.2. Entry for the Nous Research Hermes
Agent Plugin Hackathon.

## The leak map

A Hermes turn can carry your conversation off the machine on six roads. Most people know about the
first one.

1. **Main model call.** Every turn, to `model.provider`.
2. **Fallback.** On a 429, a 5xx or an auth error Hermes switches to `fallback_providers` (often
   OpenRouter) and tells you in one line.
3. **Auxiliary tasks.** The side jobs nobody looks at: context compression, title generation, vision
   (gateway images get described through it even without a tool call), the smart-approval
   classifier, MCP helpers, memory query rewrite, background review, curator, monitor, goal judge,
   group router, kanban decomposer, TTS audio tags, voice chat, and more: 19 at 84a0301, plus any a
   plugin registers. Each has its own `auxiliary.<task>` route that defaults to "auto": your main
   provider, then your fallbacks. Vision's "auto" walks openrouter, nous, deepinfra when your main
   model can't take images.
4. **Tools.** Web search and fetch, browser, messaging, media, remote MCP servers, other plugins'
   tools, `delegate_task` to another profile or backend.
5. **Memory provider.** A hosted memory vendor gets context every turn.
6. **The platform you talk over.** Telegram, Discord and the rest. Out of scope: no plugin can fix
   that one.

## Three tiers

| Tier | Where the model runs | What it costs you |
|---|---|---|
| `local-only` | A host on loopback or your private network (127/8, 10/8, 172.16/12, 192.168/16, 100.64/10, fe80::/10, fc00::/7, `localhost`), or a host you list in `confidential.local.extra_hosts`. | Model quality is whatever your box runs; availability is your hardware. Every auxiliary task, vision included, needs a local route. Hermes' local profiles (ollama, lmstudio, llama-cpp) report no base URL, so set `model.base_url` and `auxiliary.<task>.base_url` yourself. |
| `attested` | Tinfoil's confidential model router in an AMD SEV-SNP or Intel TDX enclave, verified before use and again once the last verification is older than 300 s. | Open-weight models only (Kimi K3.1 Pro, GLM-5.3, DeepSeek V4.1 Flash, Gemma 4 31B, gpt-oss-120b, Llama 3.3 70B). A Tinfoil API key. If the enclave can't be verified within 5 s, or answers with an error, the turn ends with a refusal and you resend: no retry, no fallback. A pin prompt every time Tinfoil ships a new router build, and possibly after a restart (see Pins). |
| `zero-retention` | Not implemented. `/confidential on zero-retention` refuses. | Nothing yet. A hosted provider's "we don't keep it" is a policy, not something this plugin can check. |

## Look before you seal

Both commands work on an unsealed install and change nothing.

```
hermes confidential check --tier attested
```

prints the preflight: every route in your config, its verdict, and the exact YAML key to change. On a
typical OpenRouter setup (excerpt):

```
confidential preflight: tier=attested FAIL (26 item(s)) fingerprint=3b1b1f8f92a4
KEY                                      VALUE                                     VERDICT   FIX
model.provider                           openrouter                                off_tier  set model.provider/model.base_url to an in-tier route (provider openrouter is not an attested profile)
fallback_providers[0]                    provider=openrouter, model=deepseek/d...  off_tier  remove fallback_providers entries while sealed
auxiliary.vision.provider                auto                                      off_tier  set auxiliary.vision.provider (or auxiliary.vision.base_url) explicitly to an in-tier vision route; ...
auxiliary.compression.provider           deepinfra                                 off_tier  set auxiliary.compression.provider/auxiliary.compression.base_url to an in-tier route (provider deepinfra is not an attested profile)
auxiliary.title_generation.provider      auto -> openrouter                        off_tier  inherits the main route: fix model.provider, or pin auxiliary.title_generation.provider to an in-tier provider
...
memory.provider                          honcho                                    off_tier  set memory.provider: "" (built-in local memory) while sealed
plugins.isolation                        (default in_process)                      in_tier
```

```
hermes confidential watch
```

streams the ledger, one row per send with purpose, host and size. Unsealed, this is the part that
surprises people:

```
TIME      SESSION       PURPOSE                   HOST                            BYTES     VERDICT/DECISION
14:02:00  20261106_14~  main                      openrouter.ai                   47K       send_observed attempt
14:02:00  20261106_14~  main                      openrouter.ai                   47K       send_observed observed
14:02:03  20261106_14~  aux:title_generation      openrouter.ai                   2210      send_observed observed
14:02:09  20261106_14~  aux:compression           api.deepinfra.com               89K       send_observed observed
```

Refusals and breaches print red, off-tier verdicts yellow. `--once` prints the latest rows and exits;
`/confidential watch` shows the same rows in chat. Unsealed, tool calls are not ledgered.

## Sealing

```
/confidential on attested        # or: local-only
/confidential off
/confidential status
```

`on` runs the preflight and refuses with the table if anything fails. When it passes it records a
fingerprint of your routing config, builds the tool allowlist from the live registry, and prints it:
which tools run locally, which ask, which are blocked. From then on, for this profile:

- A main-loop call to anything off the tier gets a refusal reply instead of being sent. A provider
  error on the in-tier endpoint ends the turn ("attested endpoint unavailable; this turn ended;
  resend"), so Hermes never arms a fallback.
- If the routing config changes after you seal, every turn is blocked until you unseal and seal again.
- Local tools run without asking: `terminal`, `process_manage`, `execute_code`, `read_file`,
  `write_file`, `patch`, `search_files`, `skills_list`, `skill_view`, `skill_manage`, `todo_list`,
  `memory`, `clarify`, `session_search`. Yes, terminal can reach the network; see Limitations.
- Every other tool asks, every call, on Hermes' approval prompt:
  `web_search wants to send ~3 KB of this conversation off the machine`. Only the exact answers
  `once`, `session` or `always` run the tool. Anything else, including answers Hermes' CLI would
  wave through, is refused and logged.
- Under yolo, `approvals.mode: off`, cron, `-q`, or anywhere nobody can answer, the ask becomes a block.
- Always blocked: `cronjob_manage`; tools from MCP servers whose URL is off the tier; any tool that
  wasn't registered at seal or whose handler changed since; `delegate_task` with a route field
  (profile, provider, base_url, ACP command, non-default backend). Plain delegation on the default
  backend inherits the sealed profile and runs.

`/confidential allow <tool>` puts an asking tool on the allowlist so it stops asking. It asks you
first through `ctx.ask_choice`, which never auto-picks under any bypass and treats no answer as no.
Hard blocks can't be lifted.

## Pins

Attested tier only. The plugin verifies the Tinfoil router through the SDK's default path: the
enclave's hardware-signed report, checked against the code measurement in the router's GitHub
release, whose Sigstore signature is checked too. The result is two fingerprints, code and enclave.
You approve that pair once; every later verification has to match it.

First pin:

```
hermes confidential setup --model <tinfoil model id>
```

verifies, shows the fingerprints, asks Approve/Deny on the terminal, and prints a config block for you
to paste. Setup never writes your config.

When Tinfoil ships a new build, the next sealed turn is refused with "enclave build changed; run
/confidential pins approve" and the new pair is staged, never applied. Then:

```
/confidential pins              # current pin, pending pin, approval history, tool grants
/confidential pins approve      # Approve / Deny, on whatever surface you're on (Telegram works)
```

The prompt shows vendor, release tag, old fingerprint and the new code and enclave fingerprints.
Approve writes the pin with who, when and which surface, and keeps the previous one. Deny, timeout or
a non-answer keeps the old pin and keeps refusing. The gate never waits on you mid-turn.

The pin covers the router that answered, and AMD and Intel routers have different enclave
fingerprints for the same release. Discovery picks a router at random per process, so a restart can
ask you to re-approve. Set `confidential.tinfoil.enclave` to one router host to stop that.

## Receipts

```
/confidential receipts [session] [--json]
```

A receipt is a rendering of the ledger for one session: trust roots, verification events, sends,
refusals, asks and answers, breaches, compactions. No prompt or response text, ever: the ledger
stores hosts, byte counts and decisions, and rejects rows that carry content-shaped keys. Times are
this machine's clock and say so. The JSON form adds a SHA-256 hash chain over the rows and attaches
the raw attestation evidence of each verification row that has it.

Every receipt ends with the same fixed paragraph, never templated, which splits the claims:

- **Evidence:** when the receipt says a build was verified, the plugin checked that build's
  hardware-signed attestation against the vendor's published code measurement and bound the session
  key to it; where the raw evidence is attached, anyone can replay that check offline.
- **Record only:** that this session's requests actually went to that enclave; that request bodies
  were encrypted to that key; that the build was the vendor's latest release; whether it was revoked
  later; what shell, terminal and code tools sent; which model backends sit behind the router; any
  other operator access. Timestamps are not attested. The hash chain shows the receipt wasn't edited
  after rendering, not that the local ledger was complete before it.

### Offline replay

`confidential_mode.verify.replay.replay(evidence)` re-runs the SDK's own verifier on the stored bytes
with the network banned: stored AMD VCEK or Intel collateral (Intel signatures re-checked), Sigstore
from the stored trust root, every clock pinned to the capture time. It returns one value per check:
`hardware_signature`, `cert_chain`, `tcb_policy`, `collateral_fresh_at_capture`, `code_signature`,
`measurement_match`, `hardware_platform_match`, `report_data_keys`, `tls_cert_binding`, each `True`,
`fail: ...`, `n/a: ...` or `not_run: ...`. There's no CLI for it yet:

```
cd ~/hermes-agent && PYTHONPATH=<plugin dir> uv run --no-sync python - receipt.json <<'EOF'
import json, sys
from confidential_mode.verify.replay import replay
doc = json.load(open(sys.argv[1]))
for item in doc["evidence"]:
    r = replay(item["evidence"], trust_root_dir="<plugin data dir>/trust-roots")
    print(item["row_id"], "ok" if r.ok else "FAIL", r.checks)
    print("not established:", *r.not_established, sep="\n  ")
EOF
```

What a replay can't establish comes back with every result, word for word (`NOT_ESTABLISHED`):

- that any request was sent to or answered by this enclave (the report commits to keys, not to
  requests, and carries no client nonce)
- that requests were encrypted to this HPKE key (only the plugin's own log says so)
- that this release was the latest release when verified (release metadata is unsigned; only the
  digest is bound by Sigstore)
- revocation or TCB changes after captured_at

> Build note: at this commit runtime verifications are not yet written to the ledger (last item in
> [docs/LIMITATIONS.md](docs/LIMITATIONS.md)), so receipts carry no evidence to replay. The replay
> itself works on captured evidence and is covered by `tests/unit/test_replay.py`.

## Staying hosted? Four changes with no capability loss

Not going to seal? You can still shrink the map. These are config changes you make yourself; the
plugin doesn't apply them. None has been quality-evaluated yet: we haven't measured what they do to
compression summaries, titles or vision answers. Run `hermes confidential watch` before and after.

1. **Tell OpenRouter not to train on you** (not yet quality-evaluated).
   `provider_routing: {data_collection: "deny"}` keeps OpenRouter to providers that don't collect
   prompts. OpenRouter only. Hermes applies it where it builds the main request
   (`agent/chat_completion_helpers.py:477`); we haven't checked whether auxiliary calls carry it.
2. **Keep side jobs on your main provider** (not yet quality-evaluated). Set
   `auxiliary.<task>.provider: main` for compression, title generation and the rest, so they don't
   go to a second vendor you forgot about.
3. **Only fall back to providers you'd accept as main** (not yet quality-evaluated). Every
   `fallback_providers` entry gets your full context on a 429. Trim it to providers you'd pick on
   purpose, or empty it.
4. **Make vision explicit** (not yet quality-evaluated). Set `auxiliary.vision.provider` and its
   model so "auto" can't walk to openrouter, nous or deepinfra when your main model can't take images.

## Limitations (an upstream roadmap)

Sealed mode closes what a plugin can close. Each gap below is a Hermes seam, with the evidence and the
core change that would close it. Long form: [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

1. **Auxiliary calls aren't wrapped by `llm_execution`.** `agent/auxiliary_client.py` never enters
   `run_llm_execution_middleware` (`hermes_cli/middleware.py:136`, called only from
   `agent/turn_api_call.py:139`), and `pre_auxiliary_call` can't veto (`agent/auxiliary_hooks.py:210-240`).
   The plugin refuses to seal while any task routes off-tier and flags a breach if one goes anyway; it
   can't stop the bytes. *Fix:* run aux attempts through the middleware with `purpose="aux:<task>"`,
   or let `pre_auxiliary_call` block.
2. **The CLI approve directive grants on any answer except "deny".** `tools/approval.py:1006-1010`:
   `None`, `""`, `"d"`, `"yes"` all run the tool. The plugin enforces in `tool_execution` on the
   exact answer. *Fix:* grant only on an explicit once/session/always.
3. **Shell and code-execution tools are uninspected.** `terminal` and `execute_code` can `curl` your
   notes anywhere. *Fix:* a terminal-backend network policy (docker, network off) plugins can read
   and require.
4. **MCP command servers are uninspected.** A local `command:` server can be a network proxy.
   *Fix:* a declared network capability, or a sandboxed launcher, per MCP server.
5. **Safe-worker mode disables hooks and middleware.** No plugin discovery
   (`hermes_cli/plugins.py:1206-1208`) and no hooks (`hermes_cli/plugins_dispatch.py:285-288`,
   `:561-564`), so sealed mode doesn't apply there. *Fix:* a core-visible sealed flag safe workers honour.
6. **The trust boundary is the whole process.** Any other in-process plugin can register middleware or
   patch things, and under `plugins.isolation: host` the provider vanishes without a warning (C0 spike
   2). *Fix:* an outermost policy tier for middleware and an "only these plugins while sealed" switch.
7. **The vendor measures the router, not the model.** The pin covers
   `tinfoilsh/confidential-model-router`; the backend behind it isn't in the pin. *Fix:* vendor-side
   per-model attestation.
8. **No nonce, no attested time.** The report commits to keys, not requests; `verified_at` is your
   clock. *Fix:* vendor-side nonce and signed responses.
9. **Context-length probes bypassed the attested transport. Mitigated in-plugin:** the profile answers
   `get_model_context_length` (`agent/agent_init.py:1883-1884`) from `confidential.tinfoil.context_length`,
   so Hermes never probes `/models` or `/api/show` with plain httpx. *Fix:* route metadata probes
   through the profile's client.
10. **SDK caches outside the plugin's data. Mitigated in-plugin:** the tinfoil SDK's and
    sigstore-python's platformdirs caches are redirected under the plugin data dir before the first
    verification. *Fix:* a cache-dir parameter in the SDK.

What it touches on your machine and the network: [docs/DISCLOSURE.md](docs/DISCLOSURE.md).

## Install

```
hermes plugins install confidential-mode          # from the catalog, once listed
# or: hermes plugins install https://github.com/ainsleys/hermes-confidential-mode
```

Set `TINFOIL_API_KEY` the way you set any provider key, then run `hermes confidential setup --model
<model id>`. Keep `plugins.isolation` at its default, `in_process`: under host isolation the attested
provider isn't visible to Hermes and the preflight refuses to seal.

## Config

Every key the plugin reads, the core keys the attested preflight needs, and per-model context
lengths: [docs/config.example.yaml](docs/config.example.yaml). Plugin keys live under a top-level
`confidential:` section of `config.yaml`:

| Key | Default | |
|---|---|---|
| `confidential.tinfoil.enclave` | unset (router discovery) | Pin one router host; stops AMD/Intel flapping. |
| `confidential.tinfoil.context_length` | 65536 | Context window reported to Hermes instead of probing. |
| `confidential.verify_ttl_seconds` | 300 | How long a verification vouches (monotonic clock). |
| `confidential.verify_wait_seconds` | 5 | How long a turn waits for an attestation before refusing. |
| `confidential.local.extra_hosts` | `[]` | Extra hosts the local-only tier counts as local. |
| `confidential.model` | unset | Model id `hermes confidential setup` puts in the printed block. |

## Tests

```
cd ~/hermes-agent && PYTHONDONTWRITEBYTECODE=1 HERMES_HOME=$(mktemp -d) \
  uv run --no-sync --with pytest==9.1.1 --with pytest-asyncio==1.4.0 \
  pytest <plugin dir>/tests -q -p no:cacheprovider
```

Seam tests run against real Hermes modules at 84a0301 with fakes only at the SDK, network and human
boundaries. Catalog checks: `hermes plugins validate --install-deps <plugin dir>` and
`hermes plugins doctor --ci <plugin dir>`. See [docs/RUNNING_TESTS.md](docs/RUNNING_TESTS.md).

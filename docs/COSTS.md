# What Hermes Confidential Mode costs you

This page says what changes when you install the plugin, compared with running Hermes without it:
latency, response quality, task success, and the prompts you'll have to answer. Each is given per
mode.

Every number here is an expectation, not a measurement, except one: a single live turn through
Tinfoil on 2026-11-06 took 6.6 seconds end to end, almost all of it the model's own generation time.
The last section says which figures you can measure from what the ledger already records.

## The baseline

The baseline is a typical Hermes install: a hosted frontier model (a Claude or GPT model)
through OpenRouter or Nous Portal, streaming on, fallback providers on, side jobs such as compression
and title generation on a cheap third-party model, and web tools enabled.

"Side jobs" are the calls Hermes makes on the user's behalf that are not the main chat: compression of
long sessions, title generation, vision analysis, memory, and similar. "Fallbacks" are the alternate
providers Hermes tries when the main provider fails. "Off-host tools" are tools whose work leaves the
machine, such as web search and web fetch. "Yolo mode" and "unattended mode" are Hermes settings in
which tool calls are not shown to a person for approval.

## Observe-only, the default after install

If you install the plugin and don't lock, nothing changes in what Hermes does. Each send gets a few
milliseconds slower: one tier check and one ledger append. Nothing is refused or rerouted, so
response quality and task success match the baseline. The plugin writes the ledger on disk, and
`hermes confidential watch` shows where calls went.

## The on-host-only lock

The quality change in this mode comes from the model, not from the plugin. If you already run a
local model, you lose nothing. If you switch from a hosted frontier model to a local one to use this
tier, you take that local model's quality drop, which is large on most hardware. The model's
availability is your hardware's availability.

What the plugin itself adds in this mode:

- One prompt per off-host tool per lock and conversation: the first call of each tool asks, and an
  exact `once` answer covers that tool in that conversation until you unlock. Another chat, user or
  subagent, a new lock, a restart or a second process asks again.
  With `confidential.tools.ask: each_call`, every off-host tool call asks until you answer `session`
  or `always` for that tool. `/confidential revoke <tool>` brings the prompt back in either mode.
- Off-host tool calls refused outright in yolo mode and unattended mode, because nobody is there to
  answer, even for a tool an earlier `once` covered.
- Cron jobs refused while locked.
- Fallback providers refused while locked.
- A model on another machine refused until you list its exact host. The tier accepts loopback by
  rule. A model server on your LAN, a tailnet or a cloud private network has a private-range
  address, and the lock refuses that address until you list it in `confidential.on_host.extra_hosts`.
  The preflight row for such a host names its range and the key.

Task success therefore drops for tasks that need web tools in yolo or unattended mode, and is close to
the baseline when a person is present to answer prompts.

## The attested tier, Tinfoil or NEAR AI

This is the mode with real differences. The differences come from four places: the models the tier allows, the
removal of fallbacks, the tool gate, and the vendor's own protocol.

| Factor | Change versus the baseline | Cause |
|---|---|---|
| Model choice | Frontier models unavailable. Open-weight models only, such as the Qwen, DeepSeek, Llama and gpt-oss families, as the vendor serves them. | Only models served inside enclaves are in tier. |
| Response quality | Drops to the chosen open-weight model's level. The expected gap is noticeable on coding and reasoning and larger on long-context work. | The model, plus any quantization and context limit the enclave host applies. |
| Side-job quality | Compression, titles and memory must run on an in-tier model. Summaries may differ from the default aux model's. | The preflight refuses side routes that leave the tier. |
| Task success | Lower. A provider outage fails the turn instead of falling back. Off-host tools are asked or refused. Image inputs on NEAR work, but each image leaves in plaintext to NEAR's gateway, and a remote image URL is refused. On NEAR, settings whose value is a mapping are refused, except `reasoning` and `stream_options`, which pass when their shape is known. Cron is refused. | Fallbacks removed, tool gate, NEAR encryption scope. |
| Latency per turn | Tinfoil: roughly unchanged. NEAR: the whole reply arrives at once, then one signature fetch. | No streaming on NEAR: encryption refuses it. One extra request per turn. |
| Setup | One-time preflight failures until side routes, fallbacks and vision point in tier. On NEAR, the setup command routes vision to a NEAR vision model, with a note that images are plaintext to the gateway. | The preflight is strict by design. The setup command prints most of the config for you to paste. |
| Pin approval | Tinfoil: one prompt per new router build. NEAR: one prompt per new CVM configuration, and a NEAR model entry can be approved only after its compose files are fetched from GitHub. | NEAR serves one model from several configurations. The service map is pinned only with every file hash-checked. |

### Expected sizes

- **Time to first visible token.** Tinfoil: about the same as any hosted provider. NEAR: the model's
  full generation time, often ten to thirty seconds for a long answer, because the plugin sends NEAR
  calls without streaming so that the model's enclave can sign the complete response.
- **Added time per turn, beyond the model's own time.** Observe-only and on-host-only: under ten
  milliseconds. Tinfoil: tens to a few hundred milliseconds for body encryption and certificate
  pinning. NEAR: roughly a third of a second to one and a half seconds for the signature fetch, and up
  to five seconds more when NEAR answers the first fetch with "not found" and the plugin retries.
- **Lock time, paid once per lock.** Tinfoil: a few seconds for the attestation fetch, the Sigstore
  check, the certificate probe and the pin match. NEAR: longer, for the report fetch, two Intel Trust
  Authority tokens, the key set, and the quote checks. While locked, a background thread repeats the
  verification 60 seconds before each five-minute verification ends, so turns do not wait on it. A
  turn waits only when the background verification failed or reported a build the pins do not cover,
  or when the session was idle past the five minutes. That turn then verifies inline, as the first
  turn does.
- **Task success in a tool-heavy session.** Close to the baseline when you answer prompts promptly.
  Sharply lower in unattended mode, where every off-host tool call is refused.
- **Response quality.** The open-weight model's quality. The plugin neither improves nor degrades a
  given model's output. On NEAR, image tasks run, and each image reaches NEAR's gateway in plaintext
  while the text around it stays encrypted. `confidential.near.image_parts: refuse` refuses images
  instead, and then any task that needs vision through NEAR fails.

### Outages the plugin adds

Some refusals come from the plugin's own rules, not from the vendor. Each one ends the turn while
locked.

- **A NEAR model key change.** NEAR requests are refused until Hermes restarts.
- **An HTTP 421 or a TLS certificate change on NEAR.** The plugin verifies again, at most once every
  30 seconds (`confidential.near.reverify_backoff_seconds`), and refuses NEAR sends until a
  verification passes.
- **A failed verification.** The plugin waits 10 seconds before it verifies again, and refuses sends
  meanwhile.
- **A verification the ledger cannot record.** A full disk, a corrupt ledger file or a row over the
  size cap refuses the verification, for Tinfoil and NEAR alike. Sends wait until a later verification
  writes its row. A transient "database is locked" error is retried once first.
- **GitHub unreachable during a NEAR approval.** A pending NEAR model entry cannot be approved, so
  the attested tier keeps refusing on that profile until the fetch succeeds.

The guide's sections on [request encryption](GUIDE.md#request-encryption) and on
[what happens while locked](GUIDE.md#what-happens-while-locked) state each rule.

## Summary

The plugin's own overhead is small. What you pay for is the tier. Attested inference means
open-weight models from two vendors, no fallbacks, no streaming on NEAR, images in plaintext to NEAR's
gateway, and one prompt per lock for each tool that sends data off the machine (every call with
`confidential.tools.ask: each_call`). If you already run Qwen or DeepSeek
through an aggregator, the quality change is near zero, and you pay mainly in prompts and lost
fallbacks. If you're on a Claude or GPT model, you pay for the model switch; the lock makes that cost
explicit rather than causing it.

## What the plugin can measure

Some of these figures can be read from the ledger once a few locked sessions have run:

- Latency: the ledger records one timestamp per row, so per-turn totals can be read from it; a
  per-phase breakdown needs timestamps the plugin does not record yet.
- Refusals: every refused send and every refused tool call is a ledger row, so the refusal rate per
  session is a count.
- Prompts: each tool prompt is a `tool_asked` row and its answer a `tool_allowed` or `tool_refused`
  row; a call that a `once` answer covered for the lock is a `tool_allowed` row with decision
  `lock_grant` and no prompt; and each pin answer is a `pin_applied` or `pin_denied` row, so prompts per session are a
  count too.

Quality can't be read from the ledger. Measuring quality would take a fixed-task evaluation, run before and after a
routing change, for the main path and for compression summaries. No such evaluation exists, so the
quality statements above are expectations.

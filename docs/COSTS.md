# What the plugin costs you

This document states what changes for a Hermes user who installs this plugin, compared with the same
user running Hermes without the plugin. The changes fall into four kinds: latency, response quality,
task success, and prompts the user has to answer. Each is given per mode.

Every number here is an expectation, not a measurement. The one measured figure is a single live turn
through Tinfoil on 2026-11-06, which took 6.6 seconds end to end, almost all of which was the model's own
generation time. The last section says which figures the plugin can measure from data the ledger already
records.

## The baseline

The comparison baseline is a typical Hermes install: a hosted frontier model (a Claude or GPT model)
through OpenRouter or Nous Portal, streaming on, fallback providers on, side jobs such as compression
and title generation on a cheap third-party model, and web tools enabled.

"Side jobs" are the calls Hermes makes on the user's behalf that are not the main chat: compression of
long sessions, title generation, vision analysis, memory, and similar. "Fallbacks" are the alternate
providers Hermes tries when the main provider fails. "Off-host tools" are tools whose work leaves the
machine, such as web search and web fetch. "Yolo mode" and "unattended mode" are Hermes settings in
which tool calls are not shown to a person for approval.

## Observe-only, the default after install

A user who installs the plugin and does not lock sees no change. Latency per send grows by a few
milliseconds: one predicate check and one database append. Nothing is refused and nothing is rerouted,
so response quality and task success are identical to the baseline. The plugin writes a ledger on disk
and renders the egress map on request.

## The on-host-only lock

The quality change in this mode comes from the model, not from the plugin. A user who already runs a
local model loses nothing. A user who switches from a hosted frontier model to a local model in order to
use this tier takes the quality drop of that local model, which is large on most hardware.

What the plugin itself adds in this mode:

- An allow-once prompt on every off-host tool call, until the user answers "always" for that tool.
- Off-host tool calls refused outright in yolo mode and unattended mode, because there is nobody to ask.
- Cron jobs refused while locked.
- Fallback providers refused while locked.

Task success therefore drops for tasks that need web tools in yolo or unattended mode, and is close to
the baseline when a person is present to answer prompts.

## The attested tier, Tinfoil or NEAR AI

This is the mode where the differences are real. They come from four places: the model choice the tier
forces, the removal of fallbacks, the tool gate, and the vendor's own protocol.

| Factor | Change versus the baseline | Cause |
|---|---|---|
| Model choice | Frontier models unavailable. Open-weight models only: the Qwen, DeepSeek, Llama and gpt-oss families as served by the vendor. | Only models served inside enclaves are in tier. |
| Response quality | Drops to the chosen open-weight model's level. The expected gap is noticeable on coding and reasoning and larger on long-context work. | The model, plus any quantization and context limit the enclave host applies. |
| Side-job quality | Compression, titles and memory must run on an in-tier model. Summaries may differ from the default aux model's. | The preflight refuses side routes that leave the tier. |
| Task success | Lower. A provider outage fails the turn instead of falling back. Off-host tools are asked or refused. Image inputs are refused on NEAR. Settings whose value is a mapping, such as a reasoning effort, are refused on NEAR. Cron is refused. | Fallbacks removed, tool gate, NEAR encryption scope. |
| Latency per turn | Tinfoil: roughly unchanged. NEAR: the whole reply arrives at once, then one signature fetch. | No streaming on NEAR: encryption refuses it. One extra request per turn. |
| Setup | One-time preflight failures until side routes, fallbacks and vision point in tier. On NEAR, vision needs a route on another vendor, or it refuses every image. | The preflight is strict by design. The setup command prints most of the config for you to paste. |
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
- **Task success in a tool-heavy session.** Close to the baseline when prompts are answered promptly.
  Sharply lower in unattended mode, where every off-host tool call is refused.
- **Response quality.** The open-weight model's quality. The plugin neither improves nor degrades a
  given model's output. The one exception is NEAR, where image inputs are refused while encryption is
  on, so any task that needs vision through NEAR fails. Encryption is on by default, and the lock
  requires it.

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

The README's sections on request encryption and on what happens while locked state each rule.

## The honest summary

The plugin's own overhead is small. The cost a user pays is the choice of tier. Attested inference
means open-weight models served by two vendors, no fallbacks, no streaming and no images on NEAR, and
a prompt on every tool call that leaves the machine. A user who already runs Qwen or DeepSeek through
an aggregator sees a quality change near zero, and pays mainly in prompts and lost fallbacks. A user on a Claude or
GPT model pays the model switch, and that is a cost the lock makes explicit rather than causes.

## What the plugin can measure

Two of these figures can be measured from data the ledger already records, once a few locked sessions
have run:

- Latency: the ledger stores a timestamp per send and per signature fetch, so the per-turn overhead and
  the re-verification pauses can be read from the ledger directly.
- Refusals: every refused route, tool call and fallback is a ledger row, so the refusal rate per session
  is a count.

The quality comparison cannot be read from the ledger. The design notes list a fixed-task evaluation,
before and after a routing change, for the main path and for compression summaries. That evaluation is
not built. Until the evaluation exists, the quality statements above remain expectations.

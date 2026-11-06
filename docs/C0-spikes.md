# C0 spike results (Hermes @ 84a0301, 2026-11-06)

Gate: each spike returns a passing test or a documented failure with a workaround. Result: PASS.
Suite: tests/spikes, 85 passed, 2 skipped (see docs/RUNNING_TESTS.md).

## Spike 1: refusal object from llm_execution middleware (PASS)
- Accepted refusal objects per api_mode, returned without calling next_call: chat_completions -> openai ChatCompletion with one Choice(finish_reason="stop"); codex_responses -> openai Response(status="completed") with one output message; anthropic_messages -> object with content=[{type:text}] and stop_reason="end_turn"; bedrock_converse -> raw dict {"output":{"message":{...}},"stopReason":"end_turn"}.
- Never return a dict (crashes describe_invalid_response); never use finish_reason content_filter or length, nor message.refusal.
- Catch-and-refuse around next_call is proven for all four modes on 500 and 429: provider called once, fallback never armed, no backoff, no rate-limit cooldown. The middleware sees Hermes' private _DownstreamExecutionError; unwrap with getattr(exc, "original", exc); re-raise InterruptedError (user stop/redirect).
- Fail-open confirmed: any exception escaping the middleware before next_call makes Hermes call the provider itself; after a successful next_call Hermes returns the provider's response.
- Middleware bypasses: codex_app_server runtime (whole turn in a subprocess) and the max-iterations summary call (chat_completion_helpers.py:2225-2273 calls the agent client directly). Both use agent.client, which the preflight guarantees is in-tier; the middleware is defence in depth, not the only line.

## Spike 2: ProviderProfile.create_client adoption (PASS with gaps)
- Main client, request-scoped rebuilds, and explicitly configured auxiliary clients (text and vision) use create_client. build_client_kwargs_extras is never consulted by auxiliary builds.
- Fail-open: create_client raising or returning None makes Hermes build a plain OpenAI client to the same base_url. The plugin must return a client that refuses.
- Async auxiliary calls (vision_analyze via async_call_llm) discard the plugin client unless it sets HERMES_SKIP_ASYNC_WRAP and is awaitable. Follow-up spike (tests/spikes/test_create_client_async.py) determines the dual client shape.
- Vision auto-route walks to openrouter/nous/deepinfra when the profile is unavailable or its model is marked text-only; preflight must require an explicit in-tier vision provider.
- plugins.isolation host: a standalone plugin's provider registers in the child process and is invisible in-process with no warning. Preflight must verify get_provider_profile(name) is not None.
- Dependency: pin tinfoil==0.14.2 exactly (0.15.0 requires openai>=3.26; Hermes pins 2.54.0; the two releases differ only in the package __init__). TinfoilAI is a facade without base_url; use SecureClient.make_secure_http_client() with openai.OpenAI.
- create_client is called about four times before the first turn: cache verification.

## Spike 3: consent primitive (request_tool_approval FAIL from slash commands; ask_choice PASS)
- tools.approval.request_tool_approval works only while an agent turn is running (gateway notifier registered by the turn runner). From a slash command with no turn it returns status "approval_required" immediately and asks nobody.
- Bypass states (session yolo, --yolo, hermes -z, approvals.mode off, remembered grants, cron/unattended/-q approve modes) all auto-approve with no hook firing. Prompt header is hard-coded "DANGEROUS COMMAND". plugin_rule: key space is shared across plugins.
- ctx.ask_choice(question, choices) -> value | None: blocks on the gateway with no turn running, renders a numbered prompt or buttons, never auto-picks under any bypass state, returns None on no surface / timeout (clarify timeout, default 3600 s) / cancel / prose / out-of-range. Fires no approval hooks; the plugin ledgers the decision. Handler must be sync. Not run by the spike: Desktop, Ink TUI, shared-runtime (session_authority) routing; group chats may let any authorized member answer.
- Decision: middleware mismatch refuses the turn and stages pending_pin; the user runs `/confidential pins approve`, which uses ask_choice. One consent primitive. The tool gate's allow-once prompt (pre_tool_call approve directive during a turn) does auto-approve under yolo, so sealed + yolo must hard-block instead of ask.

## Spike 2 follow-up: async auxiliary transport (PASS)
- _to_async_client honours only Hermes-internal adapter classes and the HERMES_SKIP_ASYNC_WRAP flag; otherwise it rebuilds AsyncOpenAI on Hermes' own transport from .base_url/.api_key, losing attestation.
- A dual client (sync OpenAI + per-event-loop AsyncOpenAI, both on the secure transport; chat.completions.create picks sync vs async by checking whether its direct caller is a coroutine) carried the secure transport on every path: main streaming and non-streaming, request-scoped rebuilds, sync and async text aux, vision_analyze, a second event loop. A wrong guess can only raise, never leak.
- tinfoil 0.14.2: make_secure_http_client()/make_secure_async_http_client() return httpx clients openai 2.54 accepts, and each build runs full attestation. Build the sync client once per profile and hand out non-closing views (Hermes closes request-scoped clients each turn); one async client per event loop.
- Side effects: a non-OpenAI client skips reasoning-carrier shaping and the SDK-transform bypass on aux calls, and the socket sweep cannot see wrapped transports.

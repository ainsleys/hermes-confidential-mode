# Claim index

This index lists every claim on the [README](../README.md)'s first screen (the tagline, "What Hermes
does today", "What the plugin does", the captions of Figures 1 and 2, "The receipt" and "Four
limits") and every row of its Commands table: 54 entries. Each entry gives the claim in one
sentence, the code that enforces the claim, the tests that prove the claim, and the section of
[LIMITATIONS.md](LIMITATIONS.md) that bounds the claim.

- **Code** is `file:function`, with paths from the repository root. `__init__.py` is the plugin's
  root module (`register(ctx)` and the hooks); every other path is under `confidential_mode/`.
- **Tests** are `file::test_name`, the most direct tests first. The suite runs as described in
  [RUNNING_TESTS.md](RUNNING_TESTS.md).
- **Bound** links the LIMITATIONS section that limits the claim. "Smaller gaps" entries name the
  bullet in [Smaller gaps, disclosed](LIMITATIONS.md#smaller-gaps-disclosed).

## UNTRACED

These claims, or parts of claims, have no code or test in this repository that establishes those claims as
worded.

1. **H1, Hermes' own Tinfoil or NEAR connection.** Hermes 84a0301 has no Tinfoil or NEAR provider
   (no file in its source names either vendor), so reaching either vendor is an ordinary
   OpenAI-compatible `base_url`. The statement is read from Hermes' source; no test here asserts the statement.
2. **L1, the model half: "those are open-weight models such as the Qwen, DeepSeek, Llama and gpt-oss
   families, so a hosted frontier model cannot be in the tier".** The README states this as a fact
   about the two vendors' catalogues. The code admits a provider, not a model family:
   `provider.py:near_models` builds the NEAR allowlist from whatever the user configures, and the
   Tinfoil router serves whatever Tinfoil deploys. No code or test reads either catalogue.

## Tagline

**T1. The plugin verifies the enclave.**
- Code: `verify/tinfoil.py:TinfoilAdapter.prepare_verification`, `TinfoilAdapter._result_from_document`
  (the SDK document must be `security_verified`, with every required step, repository and host);
  `verify/near.py:NearAdapter.prepare_verification`, `verify/near.py:appraise`;
  `verify/near_checks.py:check_report`, `verify_jwt`, `check_compose_manager`;
  `provider.py:VerificationCache.refresh`.
- Tests: `tests/unit/test_client.py::test_adapter_verify_raises_verify_error_on_anything`,
  `tests/fault/test_vendor_faults.py::test_a_tinfoil_attestation_fault_fails_the_verify_and_publishes_nothing`,
  `tests/unit/test_real_capture.py::test_standalone_policy_check_rejects_mismatches_on_the_real_bundle`,
  `tests/unit/test_near_real_capture.py::test_real_capture_appraises_with_real_intel_signatures`,
  `tests/hostile/test_near_cm_hostile.py::test_nonce_echoed_but_the_quote_binds_another_fails`.
- Bound: [7](LIMITATIONS.md#7-the-vendor-measurement-covers-the-router-not-the-model),
  [8](LIMITATIONS.md#8-no-nonce-no-attested-time),
  [14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).

**T2. The plugin pins the enclave's build.**
- Code: `pins.py:PinStore.match`, `PinStore.stage`, `PinStore.apply`; `provider.py:VerificationCache.ensure`,
  `provider.py:_consent_recorded`; `consent.py:approve_pending_pin`.
- Tests: `tests/seam/test_provider.py::test_pin_mismatch_refuses_stages_pending_and_recovers_after_apply`,
  `tests/hostile/test_client_hostile.py::test_fingerprint_mismatch_refuses_with_zero_requests_and_stages_pending`,
  `tests/seam/test_near_seam.py::test_changed_measurement_refuses_until_a_human_approves_it`,
  `tests/unit/test_pins_v3.py::test_retired_entry_re_added_by_hand_does_not_count`.
- Bound: [15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt); Smaller gaps:
  "The first pin is trust on first use", "Pins need a consent record".

**T3. The plugin keeps every model call and fallback inside the enclave.** P1 to P4 break this claim
down.
- Code: `gate_llm.py:LlmGate.handle`; `preflight.py:run_preflight`; `__init__.py:Runtime.turn_check`;
  `__init__.py:_observe`.
- Tests: `tests/hostile/test_gate_llm_hostile.py::test_off_tier_locked_refuses_with_zero_provider_requests`,
  `tests/seam/test_gate_llm.py::test_locked_off_tier_refused`,
  `tests/seam/test_register.py::test_aux_call_to_off_tier_host_while_locked_is_a_breach`; the
  live-runtime path: `tests/seam/test_register.py::test_locked_off_tier_provider_is_refused_with_zero_provider_calls`.
- Bound: [1](LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution) (a side call that
  strays is recorded, not stopped).

**T4. The plugin encrypts what leaves.** P10 and P11 give each vendor's mechanism.
- Code: `verify/tinfoil.py:TinfoilAdapter.pinned_ehbp_sync_transport`; `verify/near_e2ee.py:encrypt_request`.
- Tests: see P10 and P11.
- Bound: [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks),
  [14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).

**T5. The plugin writes a receipt anyone can replay.** R1 to R5 break this claim down.
- Code: `receipts.py:build_receipt`; `commands.py:cli_replay`; `verify/replay.py:replay`;
  `verify/replay_near.py:replay_receipt`.
- Tests: `tests/unit/test_replay.py::test_evidence_replays_from_the_receipt_alone_on_another_machine`,
  `tests/seam/test_near_seam.py::test_cli_replay_checks_evidence_and_every_signed_response`.
- Bound: [6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process); Smaller gaps: "The
  offline replay's identity checks have limits".

## What Hermes does today

These entries state what Hermes 84a0301 does without the plugin. A path after the word "Hermes" is a
file in the Hermes checkout.

**H1. Pointed at Tinfoil or NEAR AI Cloud, Hermes makes an ordinary HTTPS connection to a URL and
checks no hardware report, pins no build, does not use the vendor's encrypted transport and verifies no
reply signature.** UNTRACED (see above).

**H2. Hermes makes more model calls than the call the user sees, for titles, compression, images and
more.**
- Code: Hermes `agent/auxiliary_client.py`; the plugin lists the tasks with
  `preflight.py:builtin_aux_task_names` and `preflight.py:plugin_aux_task_names`.
- Tests: `tests/hostile/test_integrated_hostile.py::test_leak_title_generation_follows_live_off_tier_runtime`,
  `tests/hostile/test_preflight_hostile.py::test_each_builtin_task_hosted_is_flagged`.
- Bound: [1](LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution).

**H3. Side calls follow the main provider, but an image sent while the vision route is on `auto` may
go to OpenRouter or Nous when the user holds a key for either service.**
- Code: Hermes `agent/auxiliary_client.py:_vision_auto_route` and `_get_provider_chain`; the plugin
  reports the case with `preflight.py:auto_chain_readable` and `preflight.py:AUTO_CHAIN_KEYS`.
- Tests: `tests/hostile/test_preflight_hostile.py::test_vision_auto_or_implicit_is_flagged_even_with_on_host_main`,
  `tests/unit/test_preflight.py::test_auto_side_calls_stay_in_tier_with_a_note_while_an_openrouter_or_nous_credential_is_readable`.
- Bound: [1](LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution).

**H4. Any provider listed under `fallback_providers` can take a call.**
- Code: Hermes `hermes_cli/fallback_config.py:get_fallback_chain`.
- Tests: `tests/scenario/test_demo.py::test_control_unlocked_5xx_falls_back_to_openrouter`.
- Bound: Smaller gaps: "A locked session has no fallback".

**H5. Tools such as web search pass parts of what the user wrote on to outside sites.**
- Code: Hermes `tools/`; the plugin classifies such tools as off-host with `gate_tools.py:classify_tool`.
- Tests: `tests/seam/test_register.py::test_locked_web_search_asks_and_runs_only_on_exact_once` (shows the
  plugin asking before `web_search` runs; no test here observes what the outside site receives).
- Bound: [3](LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected).

## What the plugin does

**P0. A lock holds a profile to a tier: `attested` admits only verified enclaves whose build was
approved, and `on-host-only` admits only this machine.**
- Code: `tiers.py:AttestedPredicate.classify`, `tiers.py:OnHostPredicate.classify`, `tiers.py:is_on_host`;
  `locking.py:predicate_for`, `locking.py:lock`.
- Tests: `tests/unit/test_tiers.py::test_attested_predicate_branches`,
  `tests/hostile/test_tiers_hostile.py::test_attested_stale_or_pin_mismatch_is_off`,
  `tests/unit/test_tiers.py::test_on_host_predicate_off_tier`,
  `tests/unit/test_tiers.py::test_neighbour_ranges_off_unless_listed`.
- Bound: [13](LIMITATIONS.md#13-no-mixed-attested-or-on-host-tier-planned); Smaller gaps: "A listed
  on-host host is trusted, not checked".

**P1. While locked, every model call, main or side, goes only to the tier; a side call that strays
mid-turn is recorded, not stopped.**
- Code: main calls: `gate_llm.py:LlmGate.handle` (classifies, then refuses before `next_call`). Side
  calls: `__init__.py:_aux` and `__init__.py:_observe` write a `breach` row and mark the session
  breached.
- Tests: `tests/hostile/test_gate_llm_hostile.py::test_off_tier_locked_refuses_with_zero_provider_requests`,
  `tests/seam/test_gate_llm.py::test_locked_off_tier_refused`,
  `tests/seam/test_register.py::test_aux_call_to_off_tier_host_while_locked_is_a_breach`,
  `tests/hostile/test_client_hostile.py::test_real_aux_sync_and_async_stay_on_the_attested_transport`;
  the live-runtime path: `tests/seam/test_register.py::test_locked_off_tier_provider_is_refused_with_zero_provider_calls`.
- Bound: [1](LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution),
  [5](LIMITATIONS.md#5-safe-worker-mode-disables-hooks-and-middleware).

**P2. The plugin checks every configured route before locking.**
- Code: `locking.py:lock` (through `_lock_held` and `run_tier_preflight`); `preflight.py:run_preflight`;
  `preflight.py:config_fingerprint`.
- Tests: `tests/seam/test_register.py::test_lock_refuses_with_the_report_when_preflight_fails`,
  `tests/unit/test_preflight.py::test_vision_auto_is_off_tier_even_with_on_host_main`,
  `tests/hostile/test_preflight_hostile.py::test_each_builtin_task_hosted_is_flagged`,
  `tests/hostile/test_preflight_hostile.py::test_mcp_hosted_url_is_flagged`.
- Bound: [10](LIMITATIONS.md#10-start-up-model-list-probe-on-a-drifted-runtime); Smaller gaps:
  "Voice paths".

**P3. The plugin checks every configured route again before each turn.**
- Code: `__init__.py:_pre_llm_call`, `__init__.py:Runtime.turn_check` (`locking.py:recheck` and
  `__init__.py:_live_runtime_check`), `__init__.py:Runtime.predicate_for` (a changed fingerprint makes
  every destination off-tier); `gate_llm.py:LlmGate.handle` runs the same check when Hermes skips the
  hook.
- Tests: `tests/seam/test_register.py::test_config_edit_after_lock_blocks_the_next_turn`,
  `tests/seam/test_turn_check_seam.py::test_a_skipped_hook_still_gets_the_structural_recheck_and_its_breach_row`,
  `tests/seam/test_turn_check_seam.py::test_the_hook_and_the_gate_share_one_check_per_turn`.
- Bound: [1, the per-turn check can be skipped](LIMITATIONS.md#a-related-case-the-per-turn-check-can-be-skipped);
  Smaller gaps: "Persistence-disabled agents skip `pre_llm_call`".

**P4. The plugin refuses main-call fallbacks before any bytes leave.**
- Code: `preflight.py:run_preflight` (`fallback_providers`, `fallback_model`, every
  `auxiliary.<task>.fallback_chain` and `delegation.fallback_providers` must be empty or in-tier);
  `gate_llm.py:LlmGate.guarded_call` (a provider error becomes a refusal, so Hermes' fallback never
  arms); `gate_llm.py:LlmGate.handle` (a fallback re-entry to another provider is classified again);
  `provider.py:classify_refusal` (`should_fallback: False`, for NEAR's `NearRefusal` only; Hermes'
  own classifier decides every other error, and `guarded_call` keeps the fallback unarmed).
- Tests: `tests/hostile/test_preflight_hostile.py::test_fallback_providers_must_be_empty`,
  `tests/hostile/test_gate_llm_hostile.py::test_fallback_reentry_with_off_tier_provider_is_refused`,
  `tests/hostile/test_gate_llm_hostile.py::test_locked_in_tier_any_provider_error_refuses_once_without_failover`,
  `tests/hostile/test_integrated_hostile.py::test_hand_armed_fallback_and_provider_errors_never_reach_openrouter_withstood`.
- Bound: Smaller gaps: "A locked session has no fallback".

**P5. The enclave is re-verified whenever its last verification is more than five minutes old.**
- Code: `provider.py:DEFAULT_TTL_SECONDS` (300, `confidential.verify_ttl_seconds`),
  `provider.py:VerificationCache.fresh` and `VerificationCache.ensure` (monotonic clock);
  `provider.py:BackgroundRefresh` re-verifies ahead of expiry while locked.
- Tests: `tests/hostile/test_client_hostile.py::test_ttl_boundary`,
  `tests/hostile/test_client_hostile.py::test_ttl_wall_clock_jumping_backwards_does_not_extend_freshness`,
  `tests/seam/test_provider.py::test_ttl_expiry_refreshes_once_and_cached_clients_refuse_when_refresh_fails`,
  `tests/unit/test_background_refresh.py::test_the_refresh_waits_for_the_lead_then_swaps_an_accepted_result_in`.
- Bound: [8](LIMITATIONS.md#8-no-nonce-no-attested-time).

**P6. A changed enclave build is refused on every turn until the user approves the new build.**
- Code: `provider.py:VerificationCache.ensure` and `VerificationCache._stage` (`REASON_PIN_MISMATCH`,
  adapter held); `gate_llm.py:LlmGate.handle` (`TEXT_PIN_CHANGED`, reason code `pin_mismatch`);
  `provider.py:BackgroundRefresh.attempt` (an unaccepted result is staged, never committed). The single
  exception is `provider.py:_auto_apply`: Tinfoil only, same code fingerprint, opt-in
  `confidential.pins.auto_approve_platform_only`.
- Tests: `tests/seam/test_gate_llm.py::test_attested_mismatch_refused_with_staged_pin_message`,
  `tests/hostile/test_client_hostile.py::test_refresh_returning_new_build_refuses_even_with_a_warm_pool`,
  `tests/seam/test_near_seam.py::test_changed_measurement_refuses_until_a_human_approves_it`.
- Bound: [15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt); Smaller gaps:
  "Pins need a consent record".

**P7. On both vendors every inference connection is pinned, inside the TLS handshake and before any
request byte, to the TLS key of the verified report the plugin accepted.**
- Code: `verify/near.py:pinned_ssl_context` (checks the peer SPKI in `wrap_socket` and in the
  `wrap_bio` handshake); `verify/near.py:NearAdapter.default_send_transport`, `NearAdapter.pinned_spki`;
  `verify/tinfoil.py:TinfoilAdapter.expected_tls_fp`, `TinfoilAdapter.pinned_context`,
  `TinfoilAdapter.pin_pool`, `TinfoilAdapter._pin_ehbp_builders`.
- Tests: `tests/hostile/test_near_tls_pin_hostile.py::test_sync_pin_mismatch_refuses_before_any_request_byte`,
  `tests/hostile/test_near_tls_pin_hostile.py::test_production_adapter_never_sends_on_an_unpinned_pool`,
  `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_a_wrong_certificate_is_refused_before_any_byte_sync`,
  `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_the_sdk_rebuild_after_a_key_rotation_is_pinned_too`,
  `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_the_pin_follows_the_accepted_result_not_the_sdk_ground_truth`.
- Bound: [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks).

**P8. A connection with another certificate is refused, recorded, and triggers a re-verification.**
- Code: `verify/tinfoil.py:TinfoilAdapter._pin_failure` (`verify_fail` row, purpose `tls_pin`) and
  `TinfoilAdapter.mark_stale`; `verify/near.py:_send_failed` (`send_signed` row "TLS pin mismatch,
  nothing sent", then a `send_refused` row) and `NearAdapter.mark_stale`; both bounded by
  `reverify_backoff_seconds`; `provider.py:VerificationCache._wire_adapter_sink` (`on_stale` invalidates).
- Tests: `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_a_mismatch_through_the_view_is_ledgered_held_and_re_verified_once`,
  `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_the_verification_cache_wires_the_re_verify`,
  `tests/hostile/test_near_e2ee_hostile.py::test_tls_pin_mismatch_on_send_gets_a_row_drops_pools_and_reverifies`.
- Bound: [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks).

**P9. The attestation fetch is not pinned; the attestation the fetch returns is checked by the attestation's signatures.**
- Code: `verify/near.py:NearAdapter._attest_pool` (unpinned) and `verify/near.py:appraise` (the
  certificate seen must carry the SPKI the gateway quote binds); Tinfoil: the SDK's own checks,
  required by `TinfoilAdapter._result_from_document`, and the TLS probe `TinfoilAdapter._probe_tls`.
- Tests: `tests/unit/test_near.py::test_tls_certificate_other_than_the_bound_one_fails`,
  `tests/unit/test_replay.py::test_tampered_tls_cert_binding_fails_replay`,
  `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_a_probe_mismatch_fails_the_verification_with_a_tls_pin_row`.
- Bound: [8](LIMITATIONS.md#8-no-nonce-no-attested-time).

**P10. On Tinfoil, text is encrypted to the enclave's key through the vendor's encrypted transport
before the text leaves the machine.**
- Code: `verify/tinfoil.py:TinfoilAdapter` (transport `ehbp`), `TinfoilAdapter.pinned_ehbp_sync_transport`,
  `TinfoilAdapter._observe_send` (records the HPKE key used); `gate_llm.py:send_record_detail`;
  `receipts.py:_send_coverage` (flags a send whose key differs from the covering verification's).
- Tests: `tests/unit/test_client.py::test_hpke_key_used_is_the_key_the_ehbp_transport_encrypts_to`,
  `tests/hostile/test_tinfoil_tls_pin_hostile.py::test_the_pinned_ehbp_transport_sends_on_the_attested_key`,
  `tests/unit/test_receipts.py::test_per_send_hpke_key_mismatch_is_flagged`.
- Bound: [7](LIMITATIONS.md#7-the-vendor-measurement-covers-the-router-not-the-model).

**P11. On NEAR, every message, tool definition and tool call is encrypted to the model's key, and
every reply is signed by that key.**
- Code: `verify/near_e2ee.py:encrypt_request` (`_message`, `_tools`, `_tool_calls`, `_tool_choice`),
  `verify/near_e2ee.py:decrypt_response`; `verify/near.py:NearAdapter._encrypt`,
  `NearAdapter.finish_exchange`, `NearAdapter.fetch_signature`, `verify/near.py:_release_sealed`
  (a reply is released only when fully attested); `verify/near_checks.py:check_signature`.
- Tests: `tests/unit/test_near_e2ee.py::test_every_request_field_in_nears_table_is_encrypted_and_round_trips`,
  `tests/hostile/test_near_e2ee_hostile.py::test_encrypted_round_trip_no_plaintext_on_the_wire_and_provider_tee_over_ciphertext`,
  `tests/hostile/test_near_signatures_hostile.py::test_encrypted_response_is_withheld_unless_provider_tee_verifies`,
  `tests/unit/test_near.py::test_unstreamed_send_is_hashed_signed_and_verified_as_provider_tee`.
- Bound: [14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).

**P12. The gateway cannot read the text; on NEAR the gateway still sees images, the model id, settings,
headers, sizes and timing, and a gateway that swapped the reply key would be caught only afterwards.**
- Code: `verify/near_e2ee.py:PLAINTEXT_KEYS`, `verify/near_e2ee.py:_image_part`;
  `verify/near.py:NearAdapter.finish_exchange` (records `plaintext_keys` and `plaintext_parts`);
  `provider.py:image_parts_from` (`disclose` or `refuse`); `__init__.py:_image_notice`;
  `verify/near.py:_release_sealed` with `verify/near_e2ee.py:decrypt_response` (a reply sealed to
  another client key does not decrypt and is withheld).
- Tests: `tests/unit/test_near_e2ee.py::test_every_top_level_key_that_leaves_in_plaintext_is_reported`,
  `tests/unit/test_near_e2ee.py::test_image_parts_are_disclosed_by_default_and_the_text_beside_them_is_sealed`,
  `tests/seam/test_near_seam.py::test_an_image_to_near_while_locked_is_disclosed_once_per_lock_and_the_reply_gets_one_line`,
  `tests/hostile/test_near_e2ee_hostile.py::test_gateway_that_swaps_the_client_key_is_detected_and_the_reply_withheld`.
- Bound: [14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).

**P13. The plugin asks the user the first time each tool outside its 14-tool on-host list runs
during a lock.**
- Code: `gate_tools.py:ON_HOST_TOOLS`, `gate_tools.py:classify_tool`, `gate_tools.py:build_allowlist`,
  `gate_tools.py:_Policy.decide`; `gate_tools.py:build_pre_tool_call` asks, and
  `gate_tools.py:build_tool_execution` runs the tool only on an exact `once`, `session` or `always`.
- Tests: `tests/unit/test_gate_tools.py::test_on_host_set_is_exactly_the_contract`,
  `tests/unit/test_gate_tools.py::test_on_host_name_overridden_by_plugin_is_not_on_host`,
  `tests/seam/test_register.py::test_locked_web_search_asks_and_runs_only_on_exact_once`.
- Bound: [2](LIMITATIONS.md#2-the-cli-approve-directive-grants-on-any-answer-except-deny),
  [16](LIMITATIONS.md#16-hermes-titles-the-plugins-approval-prompt-dangerous-command).

**P14. An allow lasts until unlock, in that conversation only; `confidential.tools.ask: each_call`
asks on every call.**
- Code: `gate_tools.py:LockGrants`, `gate_tools.py:grant_scope`, `gate_tools.py:_Policy.once_per_lock`,
  `gate_tools.py:ask_mode_from`.
- Tests: `tests/seam/test_tool_ask_scope_seam.py::test_a_grant_covers_only_the_conversation_that_answered`,
  `tests/seam/test_tool_ask_scope_seam.py::test_the_grant_ends_with_the_lock`,
  `tests/seam/test_tool_ask_scope_seam.py::test_each_call_keeps_the_old_behaviour`.
- Bound: Smaller gaps: "A `once` answer covers the tool for the rest of the lock";
  [15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt).

**P15. When nobody can answer (yolo, approvals off, cron, one-shot runs), the tool is blocked.**
- Code: `gate_tools.py:hermes_bypass_active`, `gate_tools.py:_Policy.decide` (`bypass_active`),
  `gate_tools.py:bypass_text`.
- Tests: `tests/seam/test_gate_tools_seam.py::test_under_yolo_the_same_tool_is_blocked_and_no_prompt_occurs`,
  `tests/seam/test_gate_tools_seam.py::test_unattended_approve_mode_blocks_where_hermes_would_auto_approve`,
  `tests/seam/test_tool_ask_scope_seam.py::test_a_lock_grant_never_applies_where_nobody_is_asked`,
  `tests/hostile/test_gate_tools_hostile.py::test_yolo_enabled_mid_turn_after_lock_is_seen_per_call`.
- Bound: Smaller gaps: "A timing window around yolo".

**P16. Tool servers on off-tier remote hosts, scheduled jobs and routed delegation are blocked.**
- Code: `gate_tools.py:_mcp_url_route`, `gate_tools.py:classify_tool` (routes `block-mcp-url`,
  `block-cron`, `delegate`), `gate_tools.py:default_delegation_ok`.
- Tests: `tests/hostile/test_gate_tools_hostile.py::test_mcp_hosted_url_server_tool_is_blocked`,
  `tests/hostile/test_gate_tools_hostile.py::test_cronjob_every_action_blocked_and_handler_never_runs`,
  `tests/hostile/test_gate_tools_hostile.py::test_delegate_with_routing_field_is_blocked`,
  `tests/hostile/test_gate_tools_hostile.py::test_mcp_command_server_is_on_host_per_contract_GAP`.
- Bound: [4](LIMITATIONS.md#4-mcp-command-servers-are-not-inspected); Smaller gaps: "Delegation and
  cron config".

**P17. Every model call is logged with its host and size, never its text, from the moment the plugin
is enabled.** An installed plugin that is not enabled registers nothing and logs nothing.
- Code: `gate_llm.py:LlmGate.handle` (unlocked `send_observed`), `__init__.py:_pre_api_request`,
  `__init__.py:_aux`, `__init__.py:_observe`; `ledger.py:FORBIDDEN_DETAIL_KEYS` and
  `ledger.py:Ledger.append`.
- Tests: `tests/seam/test_register.py::test_unlocked_turn_is_observed_and_sent`,
  `tests/seam/test_gate_llm.py::test_unlocked_never_stores_prompt_text`,
  `tests/unit/test_ledger.py::test_content_shaped_detail_rejected`,
  `tests/hostile/test_gate_llm_hostile.py::test_provider_error_echoing_prompt_is_not_shown_or_ledgered`.
- Bound: [5](LIMITATIONS.md#5-safe-worker-mode-disables-hooks-and-middleware),
  [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks).

**P18. `hermes confidential status` shows the configured route, the live runtime, breaches and this
lock's refusal, ask and allow counts; `receipts` shows where each call went.**
- Code: `commands.py:status_text` (`_main_route_line`, `_live_runtime_line`, the breach line,
  `locking.py:period_counts`); `receipts.py:render_text` (the Sends section lists each call's host).
- Tests: `tests/seam/test_commands.py::test_status_unlocked_and_locked`,
  `tests/unit/test_receipts.py::test_every_kind_is_rendered_in_order`.
- Bound: none.

**P19. `hermes confidential watch` streams model calls live.**
- Code: `watch.py:run`, `watch.py:latest`, `watch.py:format_row`; in chat, `commands.py:watch_text`
  shows the latest rows only.
- Tests: `tests/unit/test_watch.py::test_streaming_polls_tail_for_new_rows` (streams a `tool_refused`
  row; the polling is the same for every kind), `tests/unit/test_watch.py::test_once_prints_header_and_every_row_without_ansi_when_not_a_tty`
  (prints `send_observed`, `send_refused` and `breach` rows),
  `tests/unit/test_watch.py::test_unprintable_values_cannot_forge_lines`,
  `tests/seam/test_commands.py::test_cli_status_check_watch`.
- Bound: [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks).

## README figure captions

**F1. README Figure 1 (attested send): on the attested tier, one model call runs in six steps: the
plugin verifies the enclave's report against the build the user approved, pins the connection to the
report's TLS key before any byte leaves (on NEAR the pinned connection ends at the attested gateway),
encrypts the text (Tinfoil encrypts the whole body through the vendor's transport), checks the reply's
signature on NEAR before releasing the reply, writes a ledger row with the size and never the text,
and renders a receipt anyone can replay offline. README Figure 2 (what the lock covers, also GUIDE
Figure 2): while a profile is locked, main chat and side calls go only to the verified enclave,
fallback is refused, tools outside the on-host list ask once per lock in each conversation, memory
must be the built-in store or none, and shell, code and command MCP servers stay open on this host.**
README Figure 1: T1 and T2 (verified against the approved build), P7 (pinned before any byte; on
NEAR to the certificate the gateway's quote binds), P9 (the fetch drawn unpinned), P10 and P11 (the
text encrypted; Tinfoil's transport seals the body; the NEAR reply released only after its signature
verifies), P12 (the gateway note), P17 (the ledger row) and R5 (offline replay) cover every part.
README Figure 2: P1 (enclave only; a stray side call recorded), P2 and P3 (the preflight, at lock
and every turn), P4 and L2 (fallback refused; a failed request ends the turn), P13 to P15 (ask once
per lock in each conversation; blocked under yolo, approvals off and unattended runs) and L3 (shell
and code open, unproven in the receipt) cover every part except memory, command MCP servers and the
ledger rows for tool answers.
- Code: memory: `preflight.py:run_preflight` (`memory.provider` must be empty, `builtin`,
  `built-in`, `local` or `none`, `preflight.py:_ON_HOST_MEMORY`);
  command MCP servers: `gate_tools.py:classify_tool` (a `command:` server is on-host, a `url:` server
  off-tier is blocked); tool answers: `gate_tools.py:build_post_approval_response` (`tool_allowed`
  and `tool_refused` rows).
- Tests: `tests/unit/test_preflight.py::test_memory_external_off_tier`,
  `tests/hostile/test_preflight_hostile.py::test_hosted_memory_provider_is_flagged`,
  `tests/hostile/test_gate_tools_hostile.py::test_mcp_command_server_is_on_host_per_contract_GAP`,
  `tests/seam/test_register.py::test_locked_web_search_asks_and_runs_only_on_exact_once`.
- Bound: [1](LIMITATIONS.md#1-auxiliary-calls-are-not-wrapped-by-llm_execution),
  [3](LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected),
  [4](LIMITATIONS.md#4-mcp-command-servers-are-not-inspected),
  [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks),
  [14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).

## The receipt

**R1. A receipt is rendered on demand, for the current session or any past one.**
- Code: `commands.py:receipts_text`, `receipts.py:render`, `receipts.py:collect_rows`.
- Tests: `tests/seam/test_commands.py::test_receipts_delegate_to_w6_render`,
  `tests/unit/test_receipts.py::test_empty_session_ignores_other_sessions_and_profile_rows`,
  `tests/unit/test_receipts.py::test_receipt_reads_only_the_sessions_locked_period`.
- Bound: [6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process).

**R2. The receipt is built from the plugin's ledger: every model call, the lock period, the enclave
build that was verified, and the raw hardware evidence captured at each verification.**
- Code: `receipts.py:build_receipt`, `receipts.py:_sections`, `receipts.py:_lock_info`,
  `receipts.py:_evidence_item` (joins the evidence blobs), `receipts.py:verify_facts`.
- Tests: `tests/unit/test_receipts.py::test_every_kind_is_rendered_in_order`,
  `tests/unit/test_receipts.py::test_every_lock_period_is_listed`,
  `tests/unit/test_receipts.py::test_json_carries_evidence_and_sections`,
  `tests/unit/test_receipts.py::test_verification_row_shows_repo_platform_host_and_committed_keys`.
- Bound: [9](LIMITATIONS.md#9-what-the-network-still-sees-and-what-the-receipt-leaks).

**R3. The receipt comes as readable text or as hash-chained JSON that carries the evidence.**
- Code: `receipts.py:render` (`text` or `json`), `receipts.py:render_text`, `receipts.py:chain_hash`,
  `receipts.py:verify_chain`.
- Tests: `tests/unit/test_receipts.py::test_chain_is_deterministic_and_matches_the_spec`,
  `tests/unit/test_receipts.py::test_tamper_is_detected`,
  `tests/seam/test_commands.py::test_cli_replay_exits_nonzero_on_a_broken_hash_chain_even_when_evidence_replays`.
- Bound: [6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process).

**R4. The evidence is signed by the enclave's hardware and the vendor, and on NEAR each reply
carries the enclave's signature over the exact bytes.**
- Code: `verify/replay.py:replay` (the SDK's AMD and Intel chains, the Sigstore release bundle),
  `verify/policy_check.py:check_bundle`; `verify/near.py:NearAdapter.finish_exchange` (SHA-256 of
  the exact request and response bytes), `verify/near_checks.py:check_signature`.
- Tests: `tests/unit/test_replay.py::test_sev_replay_passes_offline`,
  `tests/unit/test_replay.py::test_tdx_replay_at_capture_time_passes`,
  `tests/unit/test_replay.py::test_tampering_fails_the_right_check`,
  `tests/hostile/test_near_signatures_hostile.py::test_bent_signatures_are_unverified_live`.
- Bound: [7](LIMITATIONS.md#7-the-vendor-measurement-covers-the-router-not-the-model),
  [14](LIMITATIONS.md#14-near-ai-cloud-what-the-signatures-and-the-evidence-leave-open).

**R5. Anyone can re-check the JSON form offline with `hermes confidential replay`.**
- Code: `commands.py:cli_replay` (dispatches by evidence schema), `commands.py:_expected_for_row`;
  `verify/replay.py:replay` (no network, `_network_ban`); `verify/replay_near.py:replay`,
  `replay_receipt`, `with_blobs`.
- Tests: `tests/unit/test_replay.py::test_evidence_replays_from_the_receipt_alone_on_another_machine`,
  `tests/unit/test_replay.py::test_replay_network_ban_covers_urllib3_and_httpx`,
  `tests/unit/test_near_evidence_blobs.py::test_the_receipt_embeds_every_referenced_blob_and_replays_offline`,
  `tests/seam/test_commands.py::test_cli_replay_expected_fingerprints_come_from_the_pin_or_the_flag_not_the_receipt`.
- Bound: Smaller gaps: "The offline replay's identity checks have limits".

## Four limits

**L1. The attested tier admits only models the two vendors serve inside enclaves; those are
open-weight models such as the Qwen, DeepSeek, Llama and gpt-oss families, so a hosted frontier model
cannot be in the tier.** The first half is enforced; the model half is a vendor fact and UNTRACED
(see above).
- Code: `tiers.py:AttestedPredicate.classify` (the provider must be one of
  `locking.py:ATTESTED_PROFILES` and its host the profile's).
- Tests: `tests/unit/test_tiers.py::test_attested_provider_match_is_exact`,
  `tests/unit/test_tiers.py::test_attested_predicate_base_url_override_must_match_profile`,
  `tests/seam/test_near_seam.py::test_preflight_treats_attested_near_as_in_tier_and_other_providers_as_off_tier`.
- Bound: [13](LIMITATIONS.md#13-no-mixed-attested-or-on-host-tier-planned); [COSTS.md](COSTS.md).

**L2. Because fallbacks are refused while locked, a vendor outage ends the turn instead of routing
elsewhere.**
- Code: `gate_llm.py:LlmGate.guarded_call` (`TEXT_PROVIDER_ERROR`); `provider.py:VerificationCache.ensure`
  (`DEFAULT_VERIFY_WAIT_SECONDS`, 20 s, then `REASON_VERIFY_PENDING`); `provider.py:classify_refusal`
  (NEAR's `NearRefusal` only: retryable gateway errors stay on NEAR, never another provider).
- Tests: `tests/hostile/test_gate_llm_hostile.py::test_locked_in_tier_any_provider_error_refuses_once_without_failover`,
  `tests/hostile/test_client_hostile.py::test_verify_hanging_on_first_call_create_client_is_bounded`,
  `tests/seam/test_near_seam.py::test_gateway_errors_keep_hermes_recovery_and_refusals_stay_fatal`.
- Bound: Smaller gaps: "A locked session has no fallback"; [COSTS.md, outages](COSTS.md#outages-the-plugin-adds).

**L3. The agent can still run shell commands and code, which the plugin does not look inside, and
every receipt says so.**
- Code: `gate_tools.py:ON_HOST_TOOLS` (`terminal`, `execute_code`, `process_manage`),
  `gate_tools.py:_Policy.on_host_decision` (checks only the plugin's own commands and the terminal
  backend); `receipts.py:CLOSING_PARAGRAPH`; `locking.py:lock_disclosures`.
- Tests: `tests/unit/test_gate_tools.py::test_locked_on_host_tools_run_silently_even_under_bypass`,
  `tests/unit/test_receipts.py::test_closing_paragraph_discloses_the_in_process_and_aux_limits`,
  `tests/unit/test_receipts.py::test_closing_paragraph_is_identical_across_receipts`.
- Bound: [3](LIMITATIONS.md#3-shell-and-code-execution-tools-are-not-inspected),
  [4](LIMITATIONS.md#4-mcp-command-servers-are-not-inspected).

**L4. The receipt is written by the plugin on the user's machine, so someone else can trust only its
signed evidence.**
- Code: `receipts.py:CLOSING_PARAGRAPH`, `receipts.py:SELF_REPORT_NOTE`, `receipts.py:replay_status`
  (host and capture time "asserted by capturer"), `receipts.py:is_unverified_entry`.
- Tests: `tests/unit/test_receipts.py::test_header_frames_a_self_report_with_the_chain_head_first`,
  `tests/unit/test_receipts.py::test_closing_paragraph_states_the_claims_split`,
  `tests/seam/test_near_seam.py::test_a_locked_turn_leaves_encrypted_and_the_receipt_separates_self_report_from_signature`.
- Bound: [6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process).

## Commands

Every verb goes through `commands.py:handle_slash`; the terminal form goes through
`commands.py:cli_verb` or its own handler, registered by `commands.py:register_cli`.

**K1. `on <on-host-only|attested>` locks this profile after the preflight runs.**
- Code: `locking.py:lock`, `locking.py:_lock_held`; `gate_tools.py:ensure_tools_for_lock`,
  `gate_tools.py:build_allowlist`.
- Tests: `tests/seam/test_register.py::test_lock_refuses_with_the_report_when_preflight_fails`,
  `tests/seam/test_commands.py::test_allowlist_is_on_disk_before_the_lock_flag_and_an_empty_cache_is_rebuilt`,
  `tests/seam/test_commands.py::test_cli_on_and_off_in_another_process_govern_the_running_gateway`.
- Bound: [6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process); Smaller gaps: "The
  lock is profile-wide".

**K2. `off` unlocks, with the lock period's counts.**
- Code: `locking.py:unlock`, `locking.py:_unlock_held`, `locking.py:period_counts`;
  `provider.py:VerificationCache.invalidate`.
- Tests: `tests/seam/test_commands.py::test_off_prints_counts_and_repairs_unreadable_state`,
  `tests/seam/test_commands.py::test_off_while_unlocked_says_so_and_records_nothing`,
  `tests/unit/test_background_refresh.py::test_locking_unlock_stops_every_refresh`.
- Bound: Smaller gaps: "Remembered `always` grants outlive the lock".

**K3. `status [--verbose]` shows lock state, pins, verification, breaches and the installed commit;
`--verbose` adds the tool list and the preflight.**
- Code: `commands.py:status_text`, `commands.py:plugin_identity`, `commands.py:data_paths_line`;
  `gate_tools.py:format_allowlist`; `preflight.py:format_report`.
- Tests: `tests/seam/test_commands.py::test_status_unlocked_and_locked`,
  `tests/seam/test_commands.py::test_status_shows_pinned_and_pending_fingerprints_and_verification_age`,
  `tests/seam/test_commands.py::test_receipt_states_the_configured_ttl_and_status_shows_the_plugin_commit`.
- Bound: none.

**K4. `check [tier] [--verbose]` prints the preflight table; with no tier, the command names the tier
`check` picks and why.**
- Code: `commands.py:check_result`, `commands.py:default_check_tier`; `locking.py:run_tier_preflight`;
  `preflight.py:format_report`.
- Tests: `tests/seam/test_commands.py::test_check_prints_the_preflight_table`,
  `tests/seam/test_commands.py::test_cli_check_takes_a_positional_tier_and_names_the_tier_it_checks`,
  `tests/seam/test_ux_pass_1.py::test_check_exits_1_on_fail_and_0_on_pass`.
- Bound: [10](LIMITATIONS.md#10-start-up-model-list-probe-on-a-drifted-runtime).

**K5. `setup` runs in a terminal only: setup verifies the vendor, asks for the first pin and prints a
config block.**
- Code: `commands.py:cli_setup`, `commands.py:cli_setup_near`, `commands.py:config_block`,
  `commands.py:near_config_block`, `commands.py:setup_next_steps`; `commands.py:TERMINAL_ONLY`.
- Tests: `tests/seam/test_commands.py::test_setup_lists_the_real_next_steps_in_order`,
  `tests/seam/test_commands.py::test_setup_block_gives_vision_and_side_jobs_suitable_models`,
  `tests/seam/test_near_seam.py::test_setup_stops_when_the_main_model_attestation_is_unavailable`,
  `tests/hostile/test_integrated_hostile.py::test_cli_setup_terminal_asker_non_tty_never_pins_withstood`.
  The chat refusal (`commands.py:handle_slash` returning `TERMINAL_ONLY["setup"]`) has no test.
- Bound: Smaller gaps: "The first pin is trust on first use".

**K6. `allow <tool>` lets an off-host tool run without asking for this lock, after asking the user.**
- Code: `consent.py:allow_tool`; `gate_tools.py:Allowlist.add`, `Allowlist.persist`.
- Tests: `tests/seam/test_consent.py::test_allow_tool_adds_on_allow_only`,
  `tests/seam/test_consent.py::test_allow_tool_refuses_hard_blocked_and_on_host_without_asking`,
  `tests/seam/test_cli_allow_seam.py::test_cli_lock_then_cli_allow_web_search_reaches_the_gateway`.
- Bound: [15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt); Smaller gaps:
  "`/confidential allow` additions last for one lock only".

**K7. `revoke <tool>` and `revoke --all` withdraw the grants confidential mode holds.**
- Code: `revoke.py:revoke`, `revoke.py:remove_allowlist_grants`, `revoke.py:remove_command_allowlist_grants`,
  `revoke.py:RevocationWatcher`, `revoke.py:rule_key`.
- Tests: `tests/seam/test_revoke_seam.py::test_always_grant_then_revoke_then_the_gate_asks_again`,
  `tests/seam/test_revoke_seam.py::test_revoke_all_removes_every_plugin_grant_and_nothing_else`,
  `tests/seam/test_revoke_seam.py::test_cli_revoke_in_another_process_reaches_the_running_gateway`.
- Bound: Smaller gaps: "Remembered `always` grants outlive the lock".

**K8. `pins` lists the approved pins, the pending pin and the tool grants.**
- Code: `commands.py:pins_text`, `commands.py:_pin_lines`, `commands.py:_grant_lines`.
- Tests: `tests/seam/test_commands.py::test_pins_approve_applies_only_on_explicit_approve` (asserts the
  approval history and the code fingerprint),
  `tests/hostile/test_near_cm_hostile.py::test_a_long_service_list_folds_into_a_count_and_pins_prints_every_line`
  (asserts the pending pin's lines). No test asserts the tool-grant lines of `pins`.
- Bound: none.

**K9. `pins review` runs in a terminal only and builds the review bundle for a pending pin.**
- Code: `review.py:cli_review`, `review.py:build_bundle`, `review.py:entry_review`,
  `review.py:fetch_compose`; the chat refusal is the `pins review` branch of `commands.py:handle_slash`.
- Tests: `tests/unit/test_review.py::test_review_fetches_tags_then_the_prompt_pins_the_services`,
  `tests/unit/test_review.py::test_review_json_on_the_cli_validates_and_escapes`,
  `tests/unit/test_review.py::test_hostile_vendor_strings_are_rendered_inert`,
  `tests/seam/test_commands.py::test_pins_review_with_nothing_pending_says_so`. The chat refusal has no
  test.
- Bound: Smaller gaps: "NEAR model entries need GitHub".

**K10. `pins approve` approves the pending pin after asking the user.**
- Code: `consent.py:approve_pending_pin`, `consent.py:_approve_batch`; `pins.py:PinStore.apply`;
  `consent.py:_guard` (refuses inside a tool process).
- Tests: `tests/seam/test_commands.py::test_pins_approve_applies_only_on_explicit_approve`,
  `tests/seam/test_consent.py::test_pin_not_applied_when_pending_changed_during_the_wait`,
  `tests/hostile/test_self_approval_hostile.py::test_cli_approve_inside_a_tool_process_is_refused_and_ledgered`.
- Bound: [15](LIMITATIONS.md#15-an-agent-with-a-terminal-can-reach-the-approval-prompt).

**K11. `pins retire <fingerprint>` removes one approved entry.**
- Code: `commands.py:retire_text`, `pins.py:PinStore.retire`, `provider.py:clear_consent_cache`.
- Tests: `tests/unit/test_pins_v3.py::test_retire_needs_a_unique_prefix`,
  `tests/unit/test_pins_v3.py::test_a_gateway_entry_shared_by_two_identities_retires_per_identity`,
  `tests/unit/test_pins_v3.py::test_a_pin_retired_row_stored_with_the_too_large_marker_still_withdraws_consent`.
- Bound: Smaller gaps: "Pins need a consent record".

**K12. `receipts <session> [--json]` renders a session receipt.** R1 to R3 cover the content.
- Code: `commands.py:receipts_text`, `receipts.py:render`.
- Tests: `tests/seam/test_commands.py::test_cli_on_refusal_and_receipts_exit_codes`,
  `tests/fault/test_fs_faults.py::test_receipts_of_a_corrupt_ledger_answer_instead_of_raising`.
- Bound: [6](LIMITATIONS.md#6-the-trust-boundary-is-the-whole-hermes-process).

**K13. `replay <receipt.json>` runs in a terminal only and replays a receipt's attestation evidence
offline.** R5 covers the replay.
- Code: `commands.py:cli_replay`; `commands.py:TERMINAL_ONLY`.
- Tests: `tests/seam/test_commands.py::test_cli_replay_passes_identity_arguments_and_exits_zero_only_when_all_match`,
  `tests/seam/test_ux_pass_1.py::test_chat_help_lists_every_cli_verb` (the chat form refuses `replay`).
- Bound: Smaller gaps: "The offline replay's identity checks have limits".

**K14. `watch` shows the latest ledger rows, live in a terminal.** P19 covers the live view.
- Code: `commands.py:watch_text`, `watch.py:run`.
- Tests: `tests/seam/test_commands.py::test_slash_watch_shows_the_ledger`,
  `tests/unit/test_watch.py::test_limit_shows_only_the_latest_rows`.
- Bound: none.

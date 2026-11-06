# Review in Andrew Miller's frame (2026-11-07)

Produced by a fresh reviewer agent applying the public standards of the "Is private inference real yet?" registry (six axes: hardware, session, code, operator access, downstream, updates) to this plugin as built at commit 14b8f6f. Not written by Andrew Miller; no quotes are his. [V] = verified in code at the cited line; [I] = inferred.

## Bottom line
Most claims-disciplined agent-side privacy client seen at a hackathon: fixed "not established" list, every timestamp labelled local clock, refuses before sending, and a pin that gives the client an Updates approval boundary no provider gives. Still overclaims in four places (two in the receipt), the offline replay does not check which repo it replays (can certify a stranger's enclave), and the pin prompt asks a human to approve 16 hex characters with nothing to judge them by.

## Overclaims to fix
(a) Hash chain: computed at render time over the document's own rows; detects edits only against a chain head recorded elsewhere. receipts.py:76-78, README.md:173-174.
(b) "The plugin checked": replay shows the bytes are a valid attestation, not that this plugin checked them in this session; belongs under RECORD ONLY. "Session key" is wrong: report_data commits to the enclave's long-lived TLS and HPKE keys. receipts.py:69-71, replay.py:41,365-366.
(c) Phantom command: receipts.py:72 cites `hermes confidential replay`; commands.py:465-500 defines no such command.
(d) "Asks before every off-machine call": an `always` answer persists. README.md:6,107; gate_tools.py:29,523.
(e) "Only on your own box": private ranges include a cloud VPC and carrier NAT. README.md:5; tiers.py:50,140.
(f) "Build you approved": a fingerprint, not a build. README.md:5.
(g) "No capability loss" heading over an unmeasured claim. README.md:210,213.

## Stale or wrong in the cautious direction
Build note about verifications not ledgered is stale (__init__.py:202-203 wires ledger=; provider.py:141-145 emits verify_ok with evidence). LIMITATIONS.md:169-170 says allow additions persist across seals; code says they do not (gate_tools.py:452-454, sealing.py:323-324). "Release metadata unsigned; only digest bound" is wrong for tinfoil 0.14.2: the tag is bound via the Sigstore workflow ref policy (SDK sigstore.py:164-172); what is unsigned is which release is "latest" (github.py:50). test_integrated_hostile.py:98 docstring says hook_callback_timeout is not fingerprinted; preflight.py:55-56 fingerprints it.

## Six axes applied to this client
Hardware: SDK chain re-run offline; verifier is the vendor's own SDK (reproducibility, not independence); Genoa only. Session: TLS/HPKE key binding + EHBP; no nonce, no captured TLS cert on ehbp, no reply-key check. Code: Sigstore binds repo and tag; no reproducible build, any workflow in the repo passes. Operator access: nothing, cannot. Downstream: nothing; router-only pin, `models_seen` is a label. Updates: the contribution; refuse + stage + explicit approve + consent-row check; first pin is TOFU (commands.py:450-454).

## Replay bug
replay.py:327 takes repo from the evidence and :391 verifies against it; nothing compares to tinfoilsh/confidential-model-router; result omits repo/host/platform; tls_cert_binding always n/a. Anyone with a Genoa SEV-SNP VM and a tag-signing repo can produce evidence for which replay().ok is True. Trust root sha256 is taken from the evidence (replay.py:258-267) and as_of defaults to captured_at (replay.py:288-289), both attacker-chosen. v2: expected_repo and expected_fingerprints parameters, return repo/host/platform, independent trust root, NOT_ESTABLISHED adds "that captured_at is when the capture happened".

## Receipt additions wanted
Repo, platform, host per verification; the pin approval context with full fingerprints; which verify row and TTL window covered each send; Rekor log index of the release signature; an external anchor for the chain head; plugin commit alongside sdk_version. Frame the receipt as a self-report whose only third-party-checkable content is the evidence blobs.

## Pin prompt
Shows vendor, tag, repo, old code fingerprint and new fingerprints truncated to 16 hex; cannot distinguish a code change from a platform flap (AMD/Intel), shows no host, no release age, no source link. Should show full fingerprints for code and enclave, platform and host, "code changed" vs "platform only", release/commit/compare/Rekor links, reproducible-build status, independent observation ("first seen N days ago"), registry axis status, a platform-only auto-policy, and a minimum dwell time.

## Egress map and routing advice
Map is useful (19 aux tasks, vision auto-walk). Omits: metadata visible to Tinfoil at TLS termination (API key header, sizes, timing, IP); vendor-operated collateral proxies as egress; the start-up model-list probe; the ledger as a metadata trail; DNS. "No capability loss" should be retitled "reduce how many hosted parties see your conversation (each still sees plaintext; not quality-tested)". Missing capability: a mixed "attested or local" tier so cheap side jobs can run locally with an attested main model (tiers.py:224-225; commands.py:412-425).

## Threat model
No single statement of the adversary. Missing entirely: if Hermes runs on someone else's machine, that operator sees everything before anything is encrypted. The start-up probe is claimed disclosed (INTERFACES.md:180) but appears in no user-facing doc.

## Version-two requirements, ranked
1 replay verifies identity not just validity; 2 correct the receipt paragraph and add an external chain-head anchor; 3 informative pin prompt with platform-only auto-policy; 4 registry/independent-observation cross-check via a pluggable observers interface; 5 one-screen threat model led by host-sees-everything; 6 reconcile docs with code; 7 mixed attested+local tier and re-scope the routing advice; 8 upstream Hermes seams; 9 refuse to seal on an uncontained terminal backend; 10 vendor asks (nonce, reply-key binding, per-worker attestation, TLS termination point).

## Verdict
Worthwhile, and would say so in public: treats the harness as the unit of leakage, refuses before sending with fail-closed handling written against real fail-open behaviour, and gives the client the Updates boundary. Would point registry users at it after three changes: replay pins expected repo and fingerprints; the closing paragraph is corrected; the pin prompt carries enough context that approving is a judgment rather than a ritual.

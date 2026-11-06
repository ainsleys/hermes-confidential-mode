# Workstream: independent verification (planned, not started)

Date: 2026-11-07. Status: plan for adversarial review before any code.

## Why
The attested tier's chain is: hardware signs a report carrying a measurement and the enclave's TLS-key fingerprint and HPKE public key; GitHub Actions signs (via Sigstore) a statement that release tag G of the router repo produced an image with that measurement; the SDK encrypts request bodies to the HPKE key and derives per-response keys from the request's shared secret. Today the plugin re-runs the vendor's SDK for all of it. Five things are left to trust and the receipt says so. Three can be improved on the client side; two need a different vendor.

## What the SDK actually does (read from tinfoil 0.14.2)
- Sigstore policy (tinfoil/sigstore.py:169-172): AllOf(OIDC issuer = GitHub Actions, GitHubWorkflowRepository(repo), GitHubWorkflowRefPattern(^refs/tags/<tag>$)); DSSE bundle verified by sigstore-python; in-toto statement whose subject is the image digest and whose predicate carries the measurement; the measurement must equal the one in the hardware report. "Latest" release is fetched from the vendor proxy (tinfoil/github.py:50).
- Key binding (attestation/attestation_sev.py:99-111, abi_tdx.py:208): the report's 64-byte report_data = TLS key fingerprint || 32-byte HPKE public key.
- Transport (client.py:398-532; ehbp/derive.py): TLS terminates at the vendor proxy, which routes on the X-Tinfoil-Enclave-Url header; only the body is HPKE-sealed to the enclave key; response keys derive from the request's exported shared secret, the encapsulated key and a per-response nonce (AES-256-GCM); on KeyConfigMismatch the SDK silently re-attests and retries (we guard this).

## Planned changes (client side)

### V1. Independent hardware-report check (SEV-SNP first, TDX second)
- Parse the stored report ourselves (fixed-layout struct; abi documented by AMD), verify the ECDSA P-384 signature with the VCEK from the evidence, verify the VCEK chain to AMD's ARK/ASK fetched from AMD's KDS directly (and cached content-addressed), compare the measurement and report_data to the SDK's result.
- Replay reports two columns: `vendor_sdk` and `independent`, and `ok` requires both. Disagreement is a hard failure with both values printed.
- TDX: quote signature (ECDSA P-256 over the quote body with the attestation key), PCK chain to Intel's root, TCB and QE identity from the stored collateral; second phase because the collateral and policy logic is larger.
- Not in scope: re-implementing Sigstore verification (sigstore-python is already independent of the vendor); we restate the three-part policy ourselves and check it against the certificate extensions directly as a cross-check.

### V2. Vendor-independent release lookup
- Stop depending on the vendor proxy's "latest". From the measurement the enclave presents, fetch the attestation bundle for that image digest from api.github.com (`/repos/<repo>/attestations/sha256:<digest>`) and confirm the Rekor entry in the public log (rekor.sigstore.dev) by log index/UUID. Record the Rekor entry id in the evidence and the receipt.
- The pin remains the downgrade defence; V2 removes the vendor's ability to steer which signed build the client compares against.
- Network at verify time; offline replay uses the stored bundle and Rekor entry; `trust_root` may be supplied from the Sigstore public-good TUF root independently of the evidence.

### V3. Key hygiene in the ledger
- Record first-seen time per (enclave host, TLS fingerprint, HPKE key). Alert and refuse when a key reappears after a rotation ("key regression") or exceeds `confidential.max_key_age_days` (default 30). Record each request's EHBP encapsulated key and response nonce (hashes only) on the send row so a receipt row carries per-request material consistent with the evidence.

### V4. Replay identity (already in flight, W2)
- `replay(evidence, *, expected_repo, expected_fingerprints, trusted_root, as_of)`; result carries repo, host, platform, captured_at; NOT_ESTABLISHED adds the captured_at caveat.

## Not improvable here (vendor asks, stated in the receipt)
- A client challenge/nonce in the attestation document.
- Per-worker (model) attestation exposed to clients; the router measurement does not cover workers.
- Signed responses, so a third party can check that a reply came from the attested key (NEAR AI does this; adapter planned).
- Where TLS terminates and what metadata the proxy keeps (API key header, sizes, timing, IP).

## Acceptance
- Replay on stored evidence passes with both columns on a real capture; a tampered report fails the independent column; a swapped VCEK fails the chain; a bundle for another repo fails V2's repo check; a Rekor id that does not resolve fails V2.
- No network in unit tests; one live test gated by an environment variable for the GitHub/Rekor path.
- The receipt shows `verified by: vendor SDK 0.14.2 + independent check <plugin commit>` per verification row.

## Owner and dependencies
Owner: the client workstream (W2) after V4 lands. V1 depends only on the stored evidence; V2 depends on network access at verify time and on GitHub API rate limits (unauthenticated: 60/hour; use a conditional-request cache); V3 depends on the ledger (W1) accepting two new detail keys.

## Adopted plan (2026-11-07, after review)
The sections above are superseded by the "Recommended revised plan" in docs/reviews/2026-11-07-verification-plan-review.md. In force: (1) V4 done properly (numeric repo/owner IDs from the Fulcio certificate, expected fingerprints from pins.yaml or a flag, host and captured_at labelled capturer-asserted); (2) a standalone restated Sigstore policy checker over the stored bundle, extracting logIndex, integratedTime, repo/owner IDs, workflow path and commit, no online Rekor; (3) TLS certificate capture spike on the EHBP connection; (4) key observation not rules, and ledgering the SDK's silent re-attest path; (5) receipt wording "replays under …; sends gated by vendor SDK only". The standalone SEV-SNP checker is gated on a real capture. TDX independent checking, runtime latest-gating, a Rekor monitor and max-key-age enforcement are deferred.

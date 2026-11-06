# Workstream: independent verification

Date: 2026-11-07.

Status, as of the current `w8-docs` branch: this began as a plan for adversarial review before any
code was written. The review is in `docs/reviews/2026-11-07-verification-plan-review.md`. Its revised
plan was adopted, and is summarised in the last section of this document. Parts of the adopted plan
have since landed in code, and parts have not. The last section says which.

## Terms used here

**Attested tier.** The plugin's `attested` tier allows the model to run only in Tinfoil's enclave,
after the plugin has verified that enclave.

**Enclave and attestation.** An enclave is a virtual machine whose memory the CPU encrypts, so that
the host's operator cannot read it. Attestation is the enclave proving what it runs. The CPU produces
a hardware report and signs it with a key that only the CPU vendor's hardware holds.

**Platform.** The CPU vendor's enclave technology: AMD SEV-SNP or Intel TDX. On TDX, the signed
hardware report is called a quote.

**Measurement and fingerprint.** A measurement is a hash of the code loaded into the enclave. A
fingerprint is a short hash of a measurement, used for comparison and display.

**Router.** Tinfoil's router is the enclave the client connects to. Its source is the GitHub
repository `tinfoilsh/confidential-model-router`.

**Release tag.** A release tag (written G below) is the Git tag of one router release.

**Sigstore, Fulcio and Rekor.** Sigstore is a public software-signing service. Fulcio is its
certificate authority. Fulcio issues a short-lived signing certificate to a GitHub Actions workflow,
and the certificate records which repository and workflow asked for it. Rekor is Sigstore's public,
append-only transparency log. Every signature gets an entry there, at a numbered log index, with an
integrated time.

**DSSE bundle and in-toto statement.** A Sigstore bundle holds a signature and the material needed to
check it. DSSE is the signed-envelope format inside it. The signed content is an in-toto statement:
a small document that names a subject (here, the image digest) and makes a claim about it (here, the
measurement).

**Trust root and TUF.** A trust root is the file of keys a signature check starts from. The Sigstore
public-good trust root is distributed through TUF (The Update Framework).

**VCEK, ARK and ASK.** On AMD, the VCEK is the certificate for the signing key of one CPU. It chains
to AMD's signing key (ASK) and then to AMD's root key (ARK). AMD publishes these through its key
distribution service (KDS).

**PCK, collateral and TCB.** On Intel, the PCK certificate identifies the platform. Collateral is the
set of signed documents Intel publishes for checking a quote. TCB info states the current firmware
versions, and QE identity describes the quoting enclave that signs quotes. TCB (trusted computing base)
means the firmware and microcode the enclave depends on.

**report_data.** report_data is a 64-byte field in the hardware report that the enclave fills in. The
router puts its key fingerprints there, which binds the keys to the report.

**TLS, HPKE and EHBP.** TLS is the encryption HTTPS uses. HPKE (Hybrid Public Key Encryption) is a
standard way to encrypt a message to a public key. EHBP (the encrypted HTTP body protocol) is
Tinfoil's transport. It encrypts each request body with HPKE to the enclave's key.

**Evidence, replay and receipt.** Evidence is the raw bytes the plugin captures during one
verification. A replay re-runs that verification later, offline, from the evidence. A receipt is the
plugin's rendering of its local log (the ledger) for one session.

**Pin.** A pin is the user's recorded approval of one router build's code and enclave fingerprints.

## Why this workstream exists

The attested tier depends on a chain of three links.

1. **The hardware report.** The CPU signs a report. The report carries the enclave's measurement. Its
   report_data carries the fingerprint of the enclave's TLS key and the enclave's HPKE public key.
2. **The release signature.** GitHub Actions signs a statement through Sigstore. The statement says
   that release tag G of the router repository produced an image with a given measurement.
3. **The transport.** The SDK encrypts each request body to the HPKE key. It derives the keys for
   each response from the request's shared secret.

Today the plugin re-runs the vendor's SDK for all three links. Five things are left to trust, and the
receipt says so. Three of the five can be improved on the client side. The other two need something
from the vendor.

## What the SDK actually does (read from tinfoil 0.14.2)

**The Sigstore policy** (`tinfoil/sigstore.py:169-172`). The SDK requires all three of the following:

- the certificate's OIDC issuer is GitHub Actions (OIDC is the login protocol GitHub Actions uses to
  prove its identity to Fulcio);
- the workflow ran in the expected repository (`GitHubWorkflowRepository(repo)`);
- the workflow ran at the release tag, matching `^refs/tags/<tag>$` (`GitHubWorkflowRefPattern`).

sigstore-python verifies the DSSE bundle. The signed content is an in-toto statement. Its subject is
the image digest. Its predicate carries the measurement. That measurement must equal the one in the
hardware report.

The SDK fetches which release is "latest" from the vendor's proxy (`tinfoil/github.py:50`).

**The key binding** (`attestation/attestation_sev.py:99-111` and `abi_tdx.py:208`). The report's
64-byte report_data holds two values in sequence. The first is the TLS key fingerprint. The second is
the 32-byte HPKE public key.

**The transport** (`client.py:398-532` and `ehbp/derive.py`). The original plan described the
transport in four statements.

1. TLS terminates at the vendor's proxy, which routes on the `X-Tinfoil-Enclave-Url` header.
2. Only the body is sealed with HPKE to the enclave's key.
3. Response keys are derived from three inputs: the request's exported shared secret, the
   encapsulated key, and a per-response nonce. Responses are encrypted with AES-256-GCM.
4. On a `KeyConfigMismatch` error, the SDK silently attests again and retries. The plugin guards this
   path.

The review found statement 1 wrong for this plugin (finding 11). The enclave-URL header is added only
when the base URL differs from the enclave. The plugin talks to `https://{enclave}/v1` directly.
Where TLS terminates was therefore not established at review time.

Settled on 2026-11-06 by the live run. The adapter now fetches the attestation document over the
same EHBP connection pool and records the TLS peer certificate. Against `router-0.tinfoil.sh`
(release v0.0.170, SEV-SNP) the certificate, issued by Google Trust Services for
`router-0.tinfoil.sh`, carried the TLS public key the attestation report commits to, and its subject
alternative names bound the HPKE key and the attestation hash. TLS ends inside the attested router.
The replay's `tls_cert_binding` check repeats this comparison offline from the captured certificate.

## Planned changes (client side)

The four planned changes below are the original plan. The review superseded parts of them, as the
last section explains.

### V1. Independent hardware-report check (SEV-SNP first, TDX second)

The plan for SEV-SNP had four steps.

1. Parse the stored report with the plugin's own code. The report is a fixed-layout structure, and
   AMD documents its layout.
2. Verify the report's ECDSA P-384 signature with the VCEK stored in the evidence.
3. Verify that the VCEK chains to AMD's ARK and ASK. Fetch those directly from AMD's KDS, and cache
   them by content hash.
4. Compare the measurement and the report_data with the SDK's result.

The replay would then report two columns, `vendor_sdk` and `independent`. `ok` would require both. A
disagreement would be a hard failure, with both values printed.

TDX was planned as a second phase, because its collateral and policy logic is larger. It would check
the quote signature, which is ECDSA P-256 over the quote body with the attestation key. It would check
that the PCK chains to Intel's root. It would check TCB info and QE identity from the stored
collateral.

Re-implementing Sigstore verification was out of scope. sigstore-python is already independent of
the vendor. The plan was instead to restate the three-part policy in the plugin's own code, and to
check it against the certificate extensions directly as a cross-check.

### V2. Vendor-independent release lookup

The plan was to stop depending on the vendor proxy's answer to "which release is latest". It had
three parts.

1. From the measurement the enclave presents, fetch the attestation bundle for that image digest
   from GitHub's API (`/repos/<repo>/attestations/sha256:<digest>`).
2. Confirm the Rekor entry in the public log (`rekor.sigstore.dev`) by its log index or UUID.
3. Record the Rekor entry id in the evidence and in the receipt.

The pin would remain the defence against downgrades. V2 was meant to remove the vendor's ability to
steer which signed build the client compares against.

V2 would need network access at verification time. The offline replay would use the stored bundle and
Rekor entry. The trust root could be supplied from the Sigstore public-good TUF root, independently
of the evidence.

The review found that V2 could not be built as written (finding 1). GitHub's attestations API is keyed
by the image digest, not by the measurement. Selecting a bundle by measurement would accept any build
that was ever signed. The review also found the rationale overstated (finding 2). V2 would remove only
the vendor's proxy as a point of trust, not the vendor's steering.

### V3. Key hygiene in the ledger

The plan had three parts.

1. Record the first time each combination of enclave host, TLS fingerprint and HPKE key was seen.
2. Alert and refuse when a key reappears after a rotation (a "key regression"). Also alert and refuse
   when a key is older than `confidential.max_key_age_days`, with a default of 30.
3. On each send row, record hashes of the request's EHBP encapsulated key and response nonce. A
   receipt row would then carry per-request material consistent with the evidence.

The review replaced this with observation instead of rules (findings 9 and 10).

### V4. Replay identity (already in flight in workstream W2)

The plan was to give `replay` this signature:
`replay(evidence, *, expected_repo, expected_fingerprints, trusted_root, as_of)`.

The result would carry the repository, the host, the platform and the capture time. The
`NOT_ESTABLISHED` list would add a caveat about the capture time.

## Not improvable here

These items need the vendor. Each is stated in the receipt.

- **A client challenge in the attestation.** The attestation document carries no nonce from the
  client, so a report cannot be tied to a moment or a request.
- **Attestation of each model backend.** The router's measurement does not cover the workers behind
  it, and no per-worker attestation is exposed to clients.
- **Signed responses.** Without them, a third party cannot check that a reply came from the attested
  key. NEAR AI offers this, and an adapter for it is planned.
- **Connection metadata.** TLS ends inside the attested router (established 2026-11-06, above),
  so the API key header is decrypted by measured code. Sizes, timing and the client IP address are
  still visible to the vendor's network and hosting, and nothing in the attestation limits what is
  kept about them.

## Acceptance

The original plan set these acceptance tests:

- A replay of stored evidence passes in both columns on a real capture.
- A tampered report fails the independent column.
- A swapped VCEK fails the chain check.
- A bundle for another repository fails V2's repository check.
- A Rekor id that does not resolve fails V2.
- Unit tests use no network. One live test, enabled by an environment variable, covers the GitHub and
  Rekor path.
- The receipt shows `verified by: vendor SDK 0.14.2 + independent check <plugin commit>` on each
  verification row.

The review found the last item would be false for the live decision (finding 7). The adopted wording
is in the next section.

## Owner and dependencies

The owner was the client workstream, W2, after V4 landed.

- V1 depends only on the stored evidence.
- V2 depends on network access at verification time, and on GitHub API rate limits. Unauthenticated
  requests are limited to 60 an hour, so V2 would need a cache that uses conditional requests.
- V3 depends on the ledger (workstream W1) accepting two new detail keys.

## Adopted plan (2026-11-07, after review)

The sections above are superseded by the "Recommended revised plan" in
`docs/reviews/2026-11-07-verification-plan-review.md`. Five items are in force. The status of each is
given as of the current branch.

1. **V4 done properly.** Replay binds identity, not only validity. The expected repository is checked.
   The expected fingerprints come from `pins.yaml` or a flag, never from the receipt alone. The host
   and the capture time are labelled as asserted by the capturer. The numeric repository and owner IDs
   from the Fulcio certificate are also to be bound.

   *Status:* partly landed. `hermes confidential replay` requires `tinfoilsh/confidential-model-router`
   by default. It takes the expected fingerprints from the approved pin or from
   `--expected-fingerprints`. It labels the host and capture time "asserted by capturer". It accepts
   `--expected-repo-id` and `--expected-owner-id`, but the replay function cannot check them yet, so a
   row replayed with either flag fails.

2. **A standalone, restated Sigstore policy checker.** It runs over the stored bundle. It extracts the
   Rekor log index and integrated time, the numeric repository and owner IDs, the workflow path and the
   commit. It makes no online Rekor lookup.

   *Status:* not landed. The receipt already reserves a column for this checker, identified by the
   SHA-256 of `confidential_mode/verify/policy_check.py`. That file does not exist yet, so the column
   reads n/a. The pin prompt already shows the Rekor log index from the stored bundle.

3. **A spike to capture the TLS certificate on the EHBP connection.**

   *Status:* not landed. The evidence's TLS certificate field is always empty on the EHBP path, and the
   replay's `tls_cert_binding` check reads n/a.

4. **Key observation instead of key rules.** Record the SDK's silent re-attestation path in the ledger.
   On each send, record the HPKE key used and whether the response decrypted.

   *Status:* partly prepared. The receipt compares a send's recorded HPKE key with the key in its
   verification row, when a send row carries one. No code writes that field on send rows yet. The
   silent re-attestation path is guarded, and refuses if the fingerprints change, but it is not yet
   written to the ledger.

5. **Receipt wording.** Each verification row says "evidence replays under …". The receipt says that
   sends were gated by the vendor SDK only.

   *Status:* landed.

The standalone SEV-SNP checker is gated on a real capture. Four things are deferred: independent TDX
checking, gating on the "latest" release at runtime, a Rekor monitor, and enforcement of a maximum key
age.

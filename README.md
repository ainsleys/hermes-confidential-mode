# hermes-confidential-mode

A Hermes Agent plugin that makes "private" a verified, checkable state of a profile:
an attested model provider (Tinfoil first) plus a sealed mode that pins the enclave build
the user approved, refuses to seal while any configured path would carry content to an
unattested host, blocks off-machine tools while sealed, raises every trust-boundary change
as a Hermes approval, and writes a receipt.

Entry for the Nous Research Hermes Agent Plugin Hackathon (submissions due 2026-11-11).

Design document and adversarial review: see `docs/`.

Status: pre-C0 (spikes not yet run). Nothing here is usable yet.

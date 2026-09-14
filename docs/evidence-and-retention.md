# Evidence and Retention

AI-Scan evidence is designed for reproducibility while minimizing retained sensitive data.

## Evidence contents

Evidence and bundles may include:

- resolved mode policy, seed, tool version, target origin, authorization metadata, and pack/adapter/config digests;
- redacted canonical request and response records;
- budget ledger totals for physical requests, retries, controls, confirmations, redirects, cleanup, and discovery;
- evidence graph nodes linking attacks, controls, confirmations, findings, and coverage gaps;
- replay metadata derived from the verified plan, not trusted from mutable records.

## Integrity model — tamper-evidence, not signatures

Receipts, checkpoints, and evidence bundles are protected by **content digests**,
which are **tamper-evidence, not a signature**. A digest proves the content has
not changed since it was sealed; it does **not** cryptographically authenticate
*who* produced it. AI-Scan does not currently sign artifacts, and the docs make
no signing/attestation/provenance claims. Authenticated (signed) receipt v2 is a
planned future capability and is described as future wherever it appears.

Replay is **offline**: it verifies every digest and graph invariant and
reproduces the classification from the stored redacted evidence, and it
constructs **no transport** and makes no network call. It is offline validation
and reproduction — never a re-run against a target.

## Redaction boundary

Secrets must be scrubbed before persistence, report generation, checkpointing, exception construction, and bundle export. Redaction covers sensitive header names, token-like custom fields, query parameters, redirect locations, nested JSON/form/tool structures, model messages, known transport-secret values, and reflected body content.

Non-pattern-shaped transport-known secrets are enforced at **export time**: the
bundle collector aggregates every `ExchangeOutcome.known_secrets` value and
threads them through the final recursive scrub, so a secret that no global
pattern would catch still cannot cross the export boundary. Load-time detection
of a raw secret is a pattern/idempotence backstop only — a bundle stores no
known-secret list to check against — so export-time known-secret scrubbing is
the enforced boundary.

Canaries and analyst labels are preserved only when they are not credential-bearing fields.

## File handling

- Evidence nodes are immutable and content-addressed.
- Persistent evidence files should be written atomically with owner-only permissions where supported.
- Replay defaults to offline validation/report generation and must not resend active traffic without a separate authorization path.
- Archives and bundles must reject traversal, unsupported schemas, duplicate keys, non-finite numbers, digest mismatches, and semantic tampering.

## Retention guidance

Keep only the evidence needed for contractual retest, audit, and remediation. Do not store raw target secrets. Rotate or delete bundles at the end of the engagement retention period, and treat exported reports as sensitive customer data.

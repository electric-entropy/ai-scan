# Evidence and Retention

AI-Scan evidence is designed for reproducibility while minimizing retained sensitive data.

## Evidence contents

Evidence and bundles may include:

- resolved mode policy, seed, tool version, target origin, authorization metadata, and pack/adapter/config digests;
- redacted canonical request and response records;
- budget ledger totals for physical requests, retries, controls, confirmations, redirects, cleanup, and discovery;
- evidence graph nodes linking attacks, controls, confirmations, findings, and coverage gaps;
- replay metadata derived from the verified plan, not trusted from mutable records.

## Redaction boundary

Secrets must be scrubbed before persistence, report generation, checkpointing, exception construction, and bundle export. Redaction covers sensitive header names, token-like custom fields, query parameters, redirect locations, nested JSON/form/tool structures, model messages, known transport-secret values, and reflected body content.

Canaries and analyst labels are preserved only when they are not credential-bearing fields.

## File handling

- Evidence nodes are immutable and content-addressed.
- Persistent evidence files should be written atomically with owner-only permissions where supported.
- Replay defaults to offline validation/report generation and must not resend active traffic without a separate authorization path.
- Archives and bundles must reject traversal, unsupported schemas, duplicate keys, non-finite numbers, digest mismatches, and semantic tampering.

## Retention guidance

Keep only the evidence needed for contractual retest, audit, and remediation. Do not store raw target secrets. Rotate or delete bundles at the end of the engagement retention period, and treat exported reports as sensitive customer data.

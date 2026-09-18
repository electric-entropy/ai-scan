# Partial LLM09 structured-claim comparison

`ai-scan misinformation-audit --manifest FILE [--format json|text]` is offline.
Text is the default. Only the selected bounded stable regular UTF-8 manifest is
opened; declared references are inert labels, never paths or locators. No model,
judge, target, network, plugin, archive, document, vector, or reference is loaded,
imported, fetched, resolved, or executed. Ground truth and observations are supplied
by the operator, not independently verified. Passing is not general truth
verification, absence of misinformation, full LLM09 coverage, or compliance.

## Closed input contract

The packaged `ai_scan/owasp/misinformation-manifest-v1.schema.json` provides
Draft 2020-12 structural preflight. All objects require exactly the listed fields:

- Root: `schema_version` exactly `ai-scan-misinformation-manifest-v1`,
  `context_ref`, and `cases` (1–32).
- Case: `case_ref`, `ground_truth_snapshot_ref`, `observed_snapshot_ref`,
  `expected_claims` (1–64), and `observed_claims` (0–64).
- Expected claim: `claim_ref`, `value_sha256`, `source_ref`.
- Observed claim: the same three fields plus boolean `citation_present`.

References are 3–64 ASCII characters matching the whole-string grammar
`[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}`. Whitespace, trailing newlines,
Unicode, paths, URLs, and encoded locators reject. Digests are exactly 64 lowercase
hex characters; this command compares digests, it does not hash claimed values or
look up their preimages. No input field selects a verdict or finding.

The runtime validator is authoritative for relations JSON Schema cannot express:
case identities must be globally unique; claim identities must be unique within
each expected/observed array; the total number of expected plus observed claims
across all cases cannot exceed 1024. Claim identities may recur across cases, and
sources/snapshots may recur wherever equality is intended. Duplicate identities
reject even if their remaining fields differ. Duplicate JSON keys, non-finite
numbers, missing/extra fields, and malformed types reject, rather than producing
findings. There are no numeric fields or coercions.

The maximum input is 262144 bytes. Safe-file checks require a non-symlink regular
file, descriptor/path identity and metadata stability, two equal bounded reads,
and strict UTF-8. Files changing during reading and special files reject.

## Fixed rules

| Rule ID | Severity | Condition |
| --- | --- | --- |
| `llm09.missing_claim` | high | Expected claim identity absent from observed set |
| `llm09.value_mismatch` | high | Matched claim has a different value digest |
| `llm09.source_integrity` | medium | Matched claim has a different source, or any observed claim has `citation_present` false |
| `llm09.unexpected_claim` | medium | Observed identity absent from expected set |
| `llm09.snapshot_mismatch` | medium | Observed and ground-truth snapshots differ |

Source mismatch and missing citation produce one finding per observed claim.
Unexpected claims have no expected source to compare, but still trigger this rule
when uncited. Snapshot mismatch produces one case-level finding. Rules can coexist;
none suppresses another. A finding means a structured inconsistency, not a proven
false real-world statement. Reason codes are `llm09_<rule suffix>` and remediation
codes are `llm09.remediate.<rule suffix>`; they identify the comparison to reconcile
against independently verified evidence, not an automatic fix.

## Outputs and identities

Exit 0 means no findings, 3 means findings, and 2 means invalid input. JSON/text
contain `manifest_sha256` (SHA-256 of the exact submitted UTF-8 bytes), opaque
`context_ref`, `case_refs`, per-rule findings, fixed limitations, `executions: 0`,
and `network_requests: 0`. Neither submitted references nor value digests are
returned. Invalid manifests produce only `llm09_manifest_invalid` (JSON also
contains zero execution/request counts), never file paths or submitted content.

Opaque references use SHA-256 over the ASCII domain prefix
`ai-scan-llm09-<domain>-ref-v1`, a NUL, and compact ASCII JSON of an identity tuple:

- `context`: `[context_ref]`.
- `case`: `[context_ref, case_ref, ground_truth_snapshot_ref, observed_snapshot_ref]`.
- `finding`: that case tuple followed by claim identity and fixed rule suffix.
  Snapshot findings use an empty claim sentinel, which cannot be a submitted ref.

The output prefix is `llm09-<domain>-`. Domains and tuple encoding prevent delimiter
ambiguity; the full SHA-256 is retained without truncation. These are stable opaque
identities, not signatures or encryption; low-entropy references can be guessed.
Case/claim order and JSON member order do not affect findings; the raw manifest
digest intentionally remains serialization-sensitive. Findings bind identity,
not the truth of the underlying claim or source.

## Packaged controls and coverage

`misinformation-secure-v1.json` has matched, cited claims and matching snapshots.
`misinformation-vulnerable-v1.json` has five independent cases, one per rule.
Neither has a verdict selector. `ai-scan doctor --json` semantically checks the
schema, secure zero-findings role, and vulnerable exact five-rule role. Resources
ship in wheel/sdist under the existing OWASP package-data rule; `py.typed` remains
packaged. The active partial matrix is LLM01–LLM09; LLM10 is inactive. Existing
Reliable/Kitchen Sink compiled plans remain 20/40 cases; this offline command does
not change plans, packs, runtime evidence, checkpoints, bundles, or replay.

# Offline excessive-agency declaration audit

`ai-scan agency-audit --manifest FILE [--format human|json]` provides partial
OWASP LLM06 coverage only. It runs unattended and reads no stdin. Exit codes are
0 for `passed` or `not_applicable`, 3 for declaration `finding`, and 1 for an
invalid manifest. Findings are not runtime confirmation.

A passing result says **declaration checks passed** only. No tool execution,
permission enforcement, deployed identity, isolation, cleanup, runtime behavior,
or absence of excessive agency was verified. Prompt-only tool-abuse packs do not
prove LLM06. No model, command, code, workflow, callback, URL, plugin, implementation
path, or artifact is executed, imported, deserialized, fetched, or opened.

## Manifest v1

The packaged `ai_scan/owasp/agency-manifest-v1.schema.json` defines the closed
structural contract. The semantic validator is mandatory in addition to the
schema. Root keys are exactly `schema_version` (`ai-scan-agency-manifest-v1`),
`limits`, and `tools`. All fields are required; no credentials, identity names,
commands, payloads, URLs, or executable references are accepted as controls.

Each tool entry describes one operation of one function. Split multi-operation
functions into distinct entries. IDs must be unique. `id`, `resource_ref`,
`destination_ref`, and `object_ref` are nonsecret internal labels, not actual
names, paths, URLs, or secrets. Their alphabet is lowercase ASCII letters/digits
with dot, underscore, or hyphen separators; 3–128 characters, at most 15 separated
suffixes, no empty segments. AI-Scan never resolves these labels. This is an exact
inventory declaration, not discovery or verification of inventory completeness.

The other per-tool declarations are:

- `operation`: `read`, `update`, `delete`, or `send`; `side_effecting` must be false
  exactly for `read`. Delete is destructive; send is externally visible.
- `least_functionality`: boolean; false produces a finding.
- `resource_scope`, `destination_boundary`, `object_boundary`: `fixed` or
  `dynamic`. Dynamic produces a finding. A fixed declaration denotes an explicit
  preconfigured finite allowlist, not a model-selected destination or object.
- `parameter_shape`, `response_schema`: `closed_typed` or `open`. Closed typed
  means a finite preconfigured typed schema rejecting unknown fields. AI-Scan
  checks this declaration, not the actual implementation/schema enforcement.
- `execution_identity`: `dedicated_least_privilege`, `shared`, or `privileged`.
  Only dedicated least privilege passes; no identity name or credential is supplied.
- `isolation`: `none`, `process`, or `container`. Process is sufficient only for
  read/update; delete/send require container isolation declarations.
- `max_calls`: positive integer no greater than deployment steps. For side effects,
  `max_calls * (retries + 1)` must fit the physical side-effect ceiling.
- `idempotency`: `none`, `stable_operation_key`, or `per_attempt_key`.
- `precondition`, `read_back`, `cleanup_verified`: booleans.
- `cleanup`: `none`, `best_effort`, or `deterministic_compensation`.
- `unresolved_state`: `not_applicable`, `continue`, or `halt_and_reconcile`.
  Side-effecting operations require stable-operation keys, preconditions, read-back,
  deterministic compensation, verified cleanup, and halt/reconcile declarations
  to pass. Read-only entries must instead declare none/false/not_applicable for
  those lifecycle fields. Cleanup verification with no cleanup is contradictory;
  side effects cannot declare unresolved-state handling not applicable.
- `result_trust`: `untrusted` or `trusted`; `output_to_action`: `separated` or
  `direct`; `error_isolation`: boolean. Only untrusted/separated/true passes.
- `operation_commitment`, `request_commitment`, `result_commitment`: booleans;
  `event_identity`: `opaque_sequence`, `raw_content`, or `none`. All commitments
  and an opaque sequence identity must be declared. These are declarations of
  tamper-evident binding, not proof of signing or integrity enforcement.

## Deployment bounds

All limits are positive exact integers (booleans and fractional values reject).
These are ceilings, not observed counts. Depth 1 means root-only; retry ceilings
are additional attempts. Physical side effects include retry, cleanup, and
compensation effects; they must fit the total declaration, not be exempted.

| Field | Structural maximum | Passing read/update ceiling | Passing delete/send ceiling |
| --- | ---: | ---: | ---: |
| steps | 10000 | 100 | 32 |
| side_effects | 10000 | 16 | 8 |
| concurrency | 256 | 4 | 1 |
| duration_seconds | 86400 | 300 | 60 |
| recursion_depth | 32 | 4 | 1 |
| delegation_depth | 32 | 4 | 1 |
| retries | 16 | 2 | 1 |
| output_bytes | 10000000 | 1000000 | 65536 |

Concurrency and both depths cannot exceed steps; retries must be less than steps;
side effects cannot exceed `steps * (retries + 1)`. Cross-field contradictions
reject, while valid finite declarations above the risk-dependent passing ceilings
produce `llm06.autonomy_bounds`. Each inventory entry is evaluated independently
against the deployment ceilings, which are shared ceilings rather than additive
per-tool reservations. Empty inventory is `not_applicable`, never a safety pass.

## Files, findings, and fixtures

The selected UTF-8 JSON file is capped at 4 MiB and 2000 tools. The shared hardened
loader requires nonblocking/no-follow regular-file access, binds pathname identity
to the descriptor throughout two bounded identical reads, and rejects races.
Duplicate keys, unknown/missing fields, non-finite/overflow numbers, unsupported
types/enums, duplicate IDs, excessive size/count/nesting, and ambiguous encodings
fail closed. The closed shallow shape rejects all extra nested structures.

Output includes the document SHA-256, domain-separated full SHA-256 tool references,
and fixed rule/reason/remediation identifiers and packaged field paths only.
Submitted labels, operations, values, limits, URLs, parser text, OS errors, and
paths are not echoed. References are deterministic opaque hashes, not encryption
or a claim that low-entropy labels cannot be guessed. `llm06.<field>` identifies a
failed declaration; `llm06.remediate.<field>` means use the passing declaration
specified above and independently verify it in the deployment. The special rule
`llm06.autonomy_bounds` refers to the whole `limits` object.

Packaged examples are `ai_scan/owasp/agency-secure-v1.json` and
`ai_scan/owasp/agency-vulnerable-v1.json`. These are names for independent control
combinations, not verdict-selector fields. Doctor validates the exact schema
semantics and both fixture outcomes; merely recomputing a resource digest cannot
make a semantic contradiction valid. JSON and human audit reports are standalone;
this feature does not add runtime `run`, evidence bundle, replay, or SARIF coverage.

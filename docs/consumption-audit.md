# Partial LLM10 bounded-consumption audit

`ai-scan consumption-audit --manifest FILE [--format json|text]` compares
operator-supplied bounded workload observations against operator-supplied resource
ceilings and declared fail-closed controls. It reads only the selected stable,
bounded regular non-symlink UTF-8 JSON file. It does not execute a target or
workload, generate load, contact a network, import plugins, dereference references,
load URLs/archives/documents/models, use an LLM judge, score a model, or assess
billing/cost. Passing does not prove runtime enforcement or trustworthy observations.
This is partial offline LLM10 evidence, not full coverage or compliance.

## Input contract

Every object is closed and every listed field is required. The root fields are:

- `schema_version`: exactly `ai-scan-consumption-manifest-v1`.
- `context_ref`: an inert opaque label.
- `scenarios`: 1–32 scenarios, each with a unique `scenario_ref` within this context.

Each scenario has exactly `scenario_ref`, `ceilings`, `observations`, `controls`,
and `events`. Both references are exact ASCII strings of length 3–64 matching
`[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}` over the entire string. Newlines,
whitespace, URLs, paths, Unicode and percent-encoding are not accepted.

`ceilings` and `observations` each contain exactly these counters:

| Field | Unit |
| --- | --- |
| `requests` | requests |
| `input_tokens`, `output_tokens`, `total_tokens` | tokens |
| `duration_ms` | milliseconds |
| `peak_concurrency` | simultaneous operations |
| `queue_depth` | queued operations |
| `retries` | retry attempts |
| `tool_steps` | tool steps |
| `request_bytes`, `response_bytes` | bytes |

Counters are exact JSON integer literals in 0–1,000,000,000 inclusive. Booleans,
floats (including `1.0` or `1e0`), coercion, negative numbers and nonfinite/overflow
numbers reject. A zero ceiling means no consumption permitted for that counter.
The sum of every ceiling and observation counter across all scenarios is at most
10,000,000,000. Source text is at most 262,144 UTF-8 bytes. Duplicate keys reject
at every depth. Excessive nesting rejects; the accepted shape has no recursive fields.

`controls` contains exactly these booleans:
`deadline_enforced`, `cancellation_enforced`, `backpressure`, `circuit_breaker`,
`cleanup_enforced`, `per_scope_limits`, `fail_closed_on_exhaustion`.

`events` contains exactly these factual observation booleans:
`cancellation_observed`, `exhaustion_observed`, `cleanup_observed`,
`work_after_cancellation`, `work_after_exhaustion`.
There is no submitted verdict, status, finding or risk selector.

Contradictions reject before rule evaluation:

- Ceiling `total_tokens` must equal ceiling `input_tokens + output_tokens`.
- `work_after_cancellation` requires `cancellation_observed`.
- `work_after_exhaustion` requires `exhaustion_observed`.
- `cleanup_observed` requires at least one cancellation or exhaustion event.

Observed token arithmetic inconsistencies are explicitly comparison evidence under
the token rule, not malformed integer values. Declared controls can disagree with
observations; this is evidence rather than a structural contradiction. No inference
is made about counter relationships not specified above or unobserved events.

The packaged Draft 2020-12 `consumption-manifest-v1.schema.json` enforces closed
objects, required fields, structural types, per-field/array/reference bounds and
event implications. Runtime additionally enforces lexical integers (standard JSON
Schema integers include mathematically integral `1.0`), unique scenario identities,
aggregate limits, ceiling arithmetic, strict JSON and safe-file checks. Schema
validation alone does not imply acceptance or a passing audit.

## Fixed rules

One finding per triggered rule per scenario; comparisons are strictly `>` so equality
passes. Ordering is lexicographic submitted scenario identity, then the rule order
below. Reordering JSON keys or scenario arrays preserves findings, not the raw digest.

| Rule ID | Severity | Trigger |
| --- | --- | --- |
| `llm10.request_volume` | high | Request count exceeds its ceiling. |
| `llm10.token_budget` | high | Input/output/total tokens exceed their ceilings, or observed total differs from input + output. |
| `llm10.deadline` | high | Duration exceeds its ceiling or deadline control is absent. |
| `llm10.concurrency` | high | Peak concurrency or queue depth exceeds its ceiling, or backpressure is absent. |
| `llm10.retry_tool_budget` | high | Retries or tool steps exceed their ceilings. |
| `llm10.byte_budget` | medium | Request or response bytes exceed their ceilings. |
| `llm10.termination` | high | Cancellation, cleanup or fail-closed-on-exhaustion control is absent; an observed cancellation/exhaustion has no observed cleanup; or work continued after either event. |
| `llm10.isolation` | medium | Circuit breaker or per-scope limits are absent. |

Reasons use `llm10_<rule suffix>` and remediation codes use
`llm10.remediate.<rule suffix>`. Remediation means review/enforce the corresponding
resource ceiling or control in the actual system; the audit cannot enforce it.

## Output and identity

Exits: 0 for comparisons passed, 3 for findings, 2 for invalid input. Findings exit 3
is an offline finding, not proof of exploit execution. Result schema version is
`ai-scan-consumption-audit-result-v1`, category `LLM10`, scope
`partial_offline_bounded_consumption`, status `passed` or `finding`.
JSON and text include fixed limitations, `executions=0`, `network_requests=0`,
`manifest_sha256`, opaque `context_ref`, `scenario_refs`, and findings with opaque
`context_ref`, `scenario_ref`, `finding_ref`, fixed rule, severity, reason and remediation.
No submitted reference or file path is emitted. Invalid input yields the fixed
`llm10_manifest_invalid` code. At most 256 findings and 32 scenario references are
emitted; JSON is bounded below 200,000 bytes.

IDs use `llm10-{context|scenario|finding}-` plus a full lowercase SHA-256 digest.
Hash input is ASCII `ai-scan-llm10-{domain}-ref-v1`, NUL, then compact ASCII JSON of:

- context: `[context_ref]`
- scenario: `[context_ref, scenario_ref]`
- finding: `[context_ref, scenario_ref, rule_suffix]`

These are stable logical grouping identifiers, not evidence signatures,
authentication or confidentiality guarantees. Predictable labels can be guessed.
Evidence-only mutations may preserve a logical finding ID; `manifest_sha256`
separately binds the exact submitted UTF-8 bytes, including ordering/whitespace.

## Packaged examples and verification

`ai_scan/owasp/consumption-secure-v1.json` has zero findings.
`ai_scan/owasp/consumption-vulnerable-v1.json` has eight scenarios, each independently
triggering exactly one different rule. They contain observations and controls, not
a verdict selector. `ai-scan doctor --json` checks exact schema semantics, both
fixture roles, the full rule set and one-rule-per-scenario isolation. The existing
package-data glob includes all resources; the typed API is shipped with `py.typed`.

All ten OWASP categories now have active partial coverage. This command does not
change public scan composition: Reliable/Kitchen Sink plans remain 20/40 cases.
The cumulative release audit is separate from this category milestone.

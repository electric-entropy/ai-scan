# Exact Mode Contracts

> Status: **frozen at Milestone 0** (contract text; the modes themselves land in
> Milestone 1).

The platform will expose two operating modes via the CLI values `reliable` and
`kitchen-sink`. The selected mode and the **complete resolved policy** are stored
in every plan, checkpoint, evidence bundle, and report. Mode selection never
weakens a safety invariant (see [safety-invariants.md](safety-invariants.md),
invariant 5).

> **MVP note — legacy v1 is NOT Reliable mode.** The current `assess`/`inject`
> commands use **legacy v1 semantics**: a single response per attack case with
> canary-execution-vs-reflection confirmation, *without* the Reliable-mode
> controls (no matched negative controls, no repeatability minimums, no
> fresh-session reruns, no evidence graph). Legacy v1 must not be described as
> Reliable mode. There is no `--mode` flag yet; when it arrives (a later
> milestone), `assess` will compile a true Reliable-mode plan under schema v2
> without changing the frozen v1 contract emitted by the compatibility commands.

## Reliable mode

**Purpose:** Consulting findings, regression gates, repeatable retests, and
low false-positive operation.

**Defaults:**

- Built-in reviewed packs only.
- Safe capabilities only: read-only queries and synthetic canary output.
- Deterministic validators required for reportable findings.
- Fixed seed, fixed mutation set, and deterministic scheduling.
- At least one matched negative/control case per attack condition.
- For nondeterministic output findings: at least three attack trials, at least
  two successful trials, and at least two controls with zero validator success.
- For deterministic state/tool findings: one attempted exploit may qualify only
  when an independent read-back proves the exact synthetic state change, an
  equivalent control fails, and cleanup is verified. Otherwise require repeated
  confirmation.
- Confirmation is rerun through a fresh conversation/session when the adapter
  supports it.
- Unknown and inconclusive results remain visible as coverage gaps.
- Default output promotes only `confirmed` findings. `likely` and `suspected`
  evidence stays in a separately labeled analyst-leads section and does not fail
  CI.
- No adaptive LLM-generated payloads.
- No judge-only validators.
- No uncontrolled concurrency.
- Recommended default limits: 2 requests/second, 256 physical requests,
  30-minute duration, explicit optional model-cost ceiling.

**Reliable confirmation predicate** — a finding is `confirmed` only when all
applicable conditions hold:

1. A deterministic validator tied to a declared success condition passes.
2. Reflection, baseline behavior, and matched negative controls do not explain
   the result.
3. Required confirmation attempts meet the attack plugin's minimum repeatability
   rule.
4. Every contributing exchange is usable, in scope, and untruncated.
5. The evidence graph links the finding to attack, control, and confirmation
   nodes.
6. Any target state change is independently read back and cleaned up.
7. No sole dependency exists on self-identification, semantic similarity, or an
   LLM judge.

## Kitchen Sink mode

**Purpose:** Maximum authorized technique coverage and hypothesis generation for
an analyst.

**Defaults:**

- All reviewed built-in packs compatible with granted capabilities.
- Safe static tests plus experimental encodings, multilingual variations,
  mutation chains, multi-turn sequences, cross-plugin chaining, and bounded
  adaptive payload generation.
- Heuristic validators and optional judge ensembles may create `suspected` or
  `likely` leads, never `confirmed` on their own.
- Candidate leads are automatically handed to the same deterministic Reliable
  confirmation pipeline when compatible and budget remains.
- Broader sampling, but every mutation is seeded and recorded.
- Speculative results are separated from confirmed findings in console, JSON,
  HTML, and SARIF.
- Higher default request budget is allowed but remains finite and visible;
  recommended defaults: 5 requests/second, 2,000 physical requests, 2-hour
  duration, explicit model-cost ceiling.
- Intrusive families still require separate receipt capabilities and, for
  interactive runs, a second exact confirmation naming the capability.
- Any unconfirmed result is never phrased as a vulnerability.

## Mode-independent finding taxonomy

Both modes use the same states:

- `confirmed`: deterministic, controlled, reproducible evidence meeting the
  Reliable predicate above.
- `likely`: strong multi-signal evidence, but one confirmation requirement is
  unmet.
- `suspected`: a heuristic, anomalous, judge-supported, or single-trial lead
  requiring analyst review.
- `not_observed`: valid test and valid controls completed without the success
  condition.
- `inconclusive`: test ran but an error or ambiguity prevents interpretation.
- `blocked`: policy, authorization, capability, rate, environment, or target
  behavior prevented execution.
- `not_tested`: incompatible or intentionally excluded; include a structured
  reason.

**Severity** (`critical`, `high`, `medium`, `low`, `informational`) is
independent of confidence/status. A suspected critical lead is not a confirmed
critical vulnerability.

> **This seven-state taxonomy is a schema v2 construct.** It is introduced on
> the future `run` path and does **not** apply to, rename, or replace anything
> in report v1. Report **v1 keeps its own four-state set unchanged** —
> `confirmed` / `potential` / `not_observed` / `inconclusive` — and in
> particular the v1 status value `potential` is not renamed to `suspected`/
> `likely`. When v2 lands, a v1 `potential` finding corresponds conceptually to
> the v2 analyst-lead band (`suspected`/`likely`), but the v1 string and its
> semantics stay frozen (see [migration-policy.md](migration-policy.md)). The
> richer taxonomy is therefore additive at the v2 layer, never a mutation of the
> v1 contract.

## CI behavior and exit codes

- Reliable mode may fail a gate only for new `confirmed` findings matching the
  configured severity/policy.
- `likely`, `suspected`, `inconclusive`, and reduced coverage may fail a
  separate coverage policy only if explicitly configured.
- Kitchen Sink mode is non-gating by default.
- Exit codes remain stable where possible:
  - `0`: completed, no policy-triggering confirmed finding.
  - `1`: runtime/configuration failure.
  - `2`: authorization denied/invalid.
  - `3`: confirmed finding triggered policy.
  - `4`: assessment/required coverage inconclusive.
  - `5`: completed with analyst leads only (opt-in for Kitchen Sink automation);
    default console behavior may still return `0` until formally versioned.

**Exit code `5` is not assigned yet.** It must not be used until migration tests
and release notes establish it as a new public contract. The frozen MVP contract
uses only `0`–`4`.

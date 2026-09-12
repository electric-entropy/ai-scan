# ADR 0002: Deterministic confirmation and confidence taxonomy

- Status: Accepted (Milestone 0)
- Date: 2026-09-11
- Deciders: Electric Entropy

## Context

An AI-application scanner is trivially able to produce false positives: a target
that reflects input, self-identifies as a model, or is scored "vulnerable" by an
LLM judge can all look like findings without any real exploitation. A consulting
and CI-gating tool must instead promote only evidence that is deterministic,
controlled, and reproducible, while still capturing weaker signals for analyst
review.

## Decision

Confirmation is **deterministic and control-based**, and confidence is a
first-class, mode-independent taxonomy separate from severity.

1. A finding is `confirmed` only when it satisfies the **Reliable confirmation
   predicate** (see [../mode-contracts.md](../mode-contracts.md)): a
   deterministic validator tied to a declared success condition passes;
   reflection/baseline/matched controls do not explain it; minimum repeatability
   is met; every contributing exchange is usable, in scope, and untruncated; the
   evidence graph links attack/control/confirmation; any state change is read
   back and cleaned up; and there is no sole dependence on self-identification,
   semantic similarity, or an LLM judge.
2. **Reflection is not exploitation.** Verbatim or normalized echo of the
   submitted input never confirms (safety invariant 8).
3. **LLM judges are advisory.** They may rank or explain leads but cannot alone
   create a `confirmed` finding (safety invariant 9).
4. **Confidence is independent of severity.** States: `confirmed`, `likely`,
   `suspected`, `not_observed`, `inconclusive`, `blocked`, `not_tested`.
   Severities: `critical`/`high`/`medium`/`low`/`informational`. A suspected
   critical lead is not a confirmed critical vulnerability.
5. **Fail closed into honest states.** Redirects, HTTP/auth errors, truncation,
   unsupported streaming, and missing controls/cleanup become `inconclusive`,
   `blocked`, or `not_tested` — never a silent clean negative (invariant 7).
6. Both modes share the **same confirmation predicate**; Kitchen Sink only
   broadens lead generation and hands compatible leads back to the same
   deterministic pipeline.

## Consequences

- **Positive:** low false-positive rate; CI gates can trust `confirmed`;
  speculative leads remain visible but clearly separated in console/JSON/HTML/
  SARIF.
- **Positive:** the MVP already implements the core of this decision — canary
  execution vs. reflection, and redirect/error/truncation → `inconclusive`. The
  Milestone 0 golden contract freezes that behavior.
- **Negative / accepted:** deterministic confirmation needs controls and, for
  nondeterministic outputs, repeated trials — more physical requests per
  finding. This is bounded by the request budget (invariant 3, 13).
- **Mapping:** the MVP's `potential` maps into the platform's analyst-lead band
  (`suspected`/`likely`); the full seven-state taxonomy is an additive change per
  [../migration-policy.md](../migration-policy.md).

## Alternatives considered

- **Judge-as-oracle:** rejected — non-reproducible and gameable; demoted to
  advisory.
- **Single-trial confirmation for all findings:** rejected for nondeterministic
  outputs — cannot distinguish luck/echo from exploitation without controls and
  repeats.

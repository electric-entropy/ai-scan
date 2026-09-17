# OWASP LLM 2025 coverage matrix

AI-Scan ships a versioned, machine-readable applicability and evidence matrix for
OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10). The matrix is package data
and can be inspected offline with:

```bash
ai-scan owasp-coverage
ai-scan owasp-coverage --format json
ai-scan doctor --json
```

The matrix is a coverage contract, not a runtime test result. It requires no
target, constructs no transport, reads no stdin, and does not imply that a scan
has run. It binds each category to target prerequisites, not-applicable
conditions, deterministic evidence requirements, negative controls, supported
scenarios, known limitations, denominator semantics, allowed outcomes, and
reserved matrix identifiers for future remediation/report/SARIF integration.
Those reserved identifiers are not emitted by the current report or SARIF
runtime surfaces; current JSON reports leave `remediation` and
`framework_mappings` empty, and current SARIF rule IDs remain finding-family IDs.

Current honest summary after Phase 2B2:

- LLM01:2025 Prompt Injection — partial current active CLI coverage through the
  public direct-injection packs. Reliable plans compile 12 cases from
  `direct-injection-reliable` covering `encoding`, `instruction_conflict`,
  `role_confusion`, and `system_boundary`. Kitchen Sink plans compile those
  plus 12 cases from `direct-injection-kitchen`, adding bounded direct variants:
  `payload_splitting`, `markdown_injection`, `encoded_envelope`,
  `multilingual_directive`, `role_play_boundary`, and
  `bounded_adaptive_retry`. The Kitchen Sink additions use the same exact
  final-assistant canary execution, clean controls, repeatability, redaction,
  plan binding, scope gates, and canonical plan-bound ceilings as Reliable;
  bounded operational limits may differ by mode. Indirect injection and
  true multi-turn coverage remain unsupported until there is a complete local
  controlled ingestion/retrieval or bounded conversation-state fixture wired
  through the public CLI path.
- LLM02:2025 Sensitive Information Disclosure — partial current active CLI
  coverage through public prompt-disclosure packs using deterministic synthetic
  hidden-canary fixtures only. The expected marker is provisioned out-of-band
  (for local fixtures, `run --synthetic-canary-file FILE`) and is absent from the
  plan, prompt, URL, headers, and request body for LLM02 disclosure probes.
  Without that explicit marker input, live `run` and checkpoint resume skip LLM02
  controls/attacks as inconclusive coverage gaps while continuing normal LLM01
  execution.
  External LLM02 coverage is capability-gated unless the operator has seeded the
  exact synthetic marker into the target fixture independently. Reliable plans compile 4 LLM02 cases from
  `prompt-disclosure-reliable` covering `prompt_disclosure_debug_config` and
  `prompt_disclosure_system_text`. Kitchen Sink plans compile those plus 4 cases
  from `prompt-disclosure-kitchen`, adding `prompt_disclosure_boundary` and
  `prompt_disclosure_translation`. Confirmation requires exact final-assistant
  hidden-canary extraction, matched clean controls, repeatability, redaction,
  plan binding, scope gates, and canonical plan-bound ceilings. Refusal,
  reflection, prompt echo, metadata-only appearances, explanatory mentions, and
  LLM-judge-only evidence do not confirm. Real PII, credentials, cross-tenant
  data, training-data extraction, and real system prompt extraction remain out of
  scope.
- LLM03:2025 Supply Chain — no current target end-to-end active CLI coverage.
  AI-Scan validates its own packaged packs/adapters/resources, but that does not
  count as target supply-chain testing.
- LLM04:2025 Data and Model Poisoning — no current end-to-end poisoning coverage;
  prompt/template overlap and RAG-isolation prompts do not count without a
  controlled ingestion and retrieval/update fixture.
- LLM05:2025 Improper Output Handling — no current output-sink execution
  coverage; dangerous text alone is not deterministic sink evidence.
- LLM06:2025 Excessive Agency — no current active public CLI coverage.
  Tool-abuse packs carry LLM06 mappings, but they are capability-gated and
  unreachable through the current public `plan`/`run` path because there is no
  capability selector in this phase.
- LLM07:2025 System Prompt Leakage — no current active public CLI coverage.
  Tool-abuse/leakage mappings are capability-gated or prompt-overlap leads and
  are unreachable through the current public `plan`/`run` path without a
  capability selector.
- LLM08:2025 Vector and Embedding Weaknesses — no current vector/embedding
  behavior coverage; RAG prompt overlap does not count without namespace,
  provenance, retrieval, or embedding evidence.
- LLM09:2025 Misinformation — no current misinformation coverage; subjective
  disagreement is unsupported and cannot be reported as a vulnerability.
- LLM10:2025 Unbounded Consumption — no current unbounded-consumption coverage;
  future scenarios must stay within local budgets and cannot weaken request,
  duration, or cleanup controls.

Coverage arithmetic is conservative: the denominator is the ten OWASP categories;
`not_applicable` is excluded and separately reported; `blocked`, `inconclusive`,
and `not_tested` never increase tested coverage. Current public plans now have
active LLM01 and LLM02 coverage only, with additional bounded Kitchen Sink
breadth in those categories. Modes may use different bounded operational limits;
both remain subject to scope,
request/rate/concurrency/duration ceilings, redaction, cleanup, evidence, and
confirmed-semantics safety controls.

AI-Scan does not claim full OWASP coverage, OWASP compliance, or comprehensive
LLM01-LLM10 testing from this matrix. Such a claim remains blocked until
every category has real active CLI wiring, deterministic evidence, required
negative controls, local end-to-end fixtures, and independently verified reports.

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

Current honest summary after Phase 2B10:

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
  Without that explicit marker input, live `run` skips LLM02 controls/attacks as
  inconclusive coverage gaps while continuing normal LLM01 execution.
  Checkpoint/resume, bundle, and replay never accept LLM02 marker-dependent
  confirmation as persisted authoritative evidence; LLM02 confirmation is
  live-only.
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
- LLM03:2025 Supply Chain — partial current active CLI coverage through
  `ai-scan supply-chain-audit --manifest FILE`, an unattended offline manifest
  assessment only. The command reads one bounded local regular non-symlink
  `ai-scan-supply-chain-manifest-v1` JSON file, constructs no transport,
  performs no network access, and never imports, deserializes, loads, hashes, or
  executes model artifacts. It validates declared model, dataset, plugin, and
  dependency provenance fields: source URL, immutable revision/version pin,
  SHA-256 digest shape, unsafe serialization indicators (`.pkl`, `.pt`, `.bin`,
  etc.), remote-code enablement, and missing provenance. Findings and
  inconclusive evidence are bound to the manifest SHA-256 and opaque deterministic
  item references.
  This is not live target/model execution coverage: registry lookups,
  signatures/attestations, dataset-content inspection, model behavior, artifact
  byte hashing, transitive dependency resolution, and runtime dependency loading
  remain explicit gaps.
- LLM04:2025 Data and Model Poisoning — partial current active CLI coverage
  through `ai-scan data-poisoning-audit --target URL`, an unattended active
  controlled retrieval fixture protocol. AI-Scan sends a fixed strict JSON
  sequence to one exact target path through the hardened transport: pre-poison
  attack query, pre-poison clean query, poison ingest/update, post-poison attack
  query, post-poison clean query, cross-namespace isolation query, cleanup, and
  cleanup verification. The external service owns state and decides retrieval
  behavior; there is no selectable `engine`, plugin, import, subprocess, or
  scanner-authored retriever. Findings and inconclusive evidence are bound to
  opaque refs and domain-separated commitments, not raw target/query/ID/response
  values. This is data/retrieval poisoning protocol coverage only: model-weight
  poisoning, fine-tuning poisoning, production RAG, embeddings, feedback
  learning, and non-protocol target/model behavior remain explicit gaps.
  Metadata/envelope/error/explanation/request-echo appearances, prefixed or
  suffixed marker text, dirty controls, namespace crossover, malformed evidence,
  reordered/replayed/wrong-identity responses, or unverified cleanup do not
  confirm. A deadline, budget, transport, or cleanup-verification failure after
  an uncertain ingestion can leave the controlled poison item unresolved and
  requires explicit service-side or operator reconciliation. Public output uses
  fixed nonsecret wording and does not expose the target, item identifier, or marker.
- LLM05:2025 Improper Output Handling — partial current active CLI coverage
  through `ai-scan output-handling-audit --manifest FILE`, an unattended offline
  declaration assessment only. It applies fixed sink/context checks to declared
  HTML/DOM, Markdown, SQL, shell/process, code/template, logging/observability,
  and structured/API consumers. It checks trust boundaries, contextual encoding,
  parameterization and string concatenation, schema/allowlist validation, active
  content, interpreter/renderer behavior, error/output isolation, and fixed size
  limits. It never opens declared paths or URLs and never renders, deserializes,
  imports, or executes model output, commands, templates, SQL, HTML, JavaScript,
  payloads, or plugins. Findings are deterministic declaration findings bound to
  the manifest digest and opaque sink references; they do not claim execution or
  downstream effects. Declaration checks passed does not prove safe runtime
  behavior. Runtime rendering and execution, browser behavior, database or
  process effects, prompt injection, and downstream implementation verification
  remain explicit gaps. This is not full LLM05 coverage.
- LLM06:2025 Excessive Agency — partial offline declaration coverage through
  `ai-scan agency-audit --manifest FILE`. Fixed rules assess tool inventory,
  scope/parameters/boundaries, execution identity/isolation, finite autonomy,
  idempotency/read-back/cleanup/unresolved state, result trust, and auditability.
  Only the selected bounded regular non-symlink manifest is read; nothing declared
  is executed, imported, deserialized, opened, fetched, or resolved.
  “Declaration checks passed” means only that the declarations passed fixed checks.
  No tool execution, permission enforcement, deployed identity, isolation, cleanup,
  runtime behavior, or absence of excessive agency was verified. Prompt-only
  tool-abuse packs do not establish LLM06 coverage. The [manifest contract](agency-audit.md)
  specifies the strict schema, cross-field rules, bounds, and claim limitations.
- LLM07:2025 System Prompt Leakage — partial current active CLI coverage through
  public system-prompt-leakage packs using deterministic synthetic system-prompt
  marker fixtures only. The fixture independently stores the expected marker in
  system-prompt state before scanning; AI-Scan keeps it out of argv, environment,
  plan, prompt, URL, headers, body, public artifacts, errors, and logs. Reliable
  plans compile 4 LLM07 cases from `system-prompt-leakage-reliable` covering
  `system_prompt_leakage_direct_extract` and
  `system_prompt_leakage_structured_restatement`. Kitchen Sink plans compile
  those plus 4 cases from `system-prompt-leakage-kitchen`, adding
  `system_prompt_leakage_boundary_continuation` and
  `system_prompt_leakage_transformation`. Confirmation requires exact eligible
  final assistant marker text, matched clean controls, repeatability, redaction,
  plan binding, scope gates, and canonical plan-bound ceilings. Refusal,
  explanation, prompt echo, prefix/suffix, partial/encoded marker, JSON envelope,
  thinking/tool blocks, malformed/truncated/nonterminal/error/redirect evidence,
  dirty controls, reflection, and judge-only evidence do not confirm. Checkpoint,
  resume, bundle, and replay are live-only for LLM07 and never accept persisted
  marker-dependent trials as authoritative evidence. Arbitrary production prompt
  inspection, unknown prompt recovery, and proof of absence remain out of scope.
- LLM08:2025 Vector and Embedding Weaknesses — partial offline declaration
  coverage through `ai-scan vector-audit --manifest FILE`. Fixed rules assess
  declared scope partitioning, ingestion provenance/integrity, embedding/model
  lineage, retrieval controls, data minimization/privacy, lifecycle, poisoning
  resistance, and isolation/operations controls. Only the selected bounded
  regular non-symlink manifest is read; declared documents, embeddings, indexes,
  model files, plugins, URLs, commands, archives, and code are never opened,
  imported, fetched, connected to, or executed. “Declaration checks passed” means
  only that declarations passed fixed checks. No vector-store exploitation,
  retrieval validation, embedding inversion, tenant escape proof, runtime
  isolation, or proof that declarations are true was performed. Dormant RAG
  attack packs and prompt/template overlap do not establish LLM08 runtime coverage.
- LLM09:2025 Misinformation — partial offline structured-claim comparison through
  `ai-scan misinformation-audit --manifest FILE`. Fixed rules compare submitted
  ground-truth and observed claim digests, source/citation declarations, and snapshot
  identities. No model judge, scoring, target execution, network, or reference loading
  occurs. This is not general truth verification: operator-supplied truth, observations,
  sources, and citations are not independently verified. Natural-language correctness,
  calibration, and runtime misinformation remain untested. See the
  [manifest contract](misinformation-audit.md).
- LLM10:2025 Unbounded Consumption — partial offline bounded-consumption comparison
  through `ai-scan consumption-audit --manifest FILE`. Fixed rules compare supplied
  workload counters against supplied resource ceilings and declared fail-closed controls.
  There is no target execution, load generation, network, reference dereferencing,
  model scoring, LLM judge, or billing/cost assessment. Passing does not prove runtime
  enforcement. See the [manifest contract](consumption-audit.md).

Coverage arithmetic is conservative: the denominator is the ten OWASP categories;
`not_applicable` is excluded and separately reported; `blocked`, `inconclusive`,
and `not_tested` never increase tested coverage. Current public coverage now has
active LLM01, LLM02, partial offline-manifest LLM03, partial active
controlled-retrieval-protocol LLM04, partial offline-declaration LLM05, LLM06,
and LLM08, partial controlled-fixture LLM07, partial offline structured-claim LLM09,
and partial offline bounded-consumption LLM10
coverage only, with additional bounded
Kitchen Sink breadth in LLM01/LLM02/LLM07. The active partial category count is
exactly 10/10; every category remains partial, not full runtime OWASP coverage or compliance.
The Reliable/Kitchen Sink public plan case counts remain 20/40.
Modes may use different bounded operational limits;
both remain subject to scope,
request/rate/concurrency/duration ceilings, redaction, cleanup, evidence, and
confirmed-semantics safety controls.

AI-Scan does not claim full OWASP coverage, OWASP compliance, or comprehensive
LLM01-LLM10 testing from this matrix. Such a claim remains blocked until
every category has real active CLI wiring, deterministic evidence, required
negative controls, local end-to-end fixtures, and independently verified reports.

### LLM08 manifest preflight and identities

`vector-manifest-v1.schema.json` is a standard Draft 2020-12 structural preflight
contract, not a claim of full schema/runtime domain equality. It enforces closed
required fields, types, enum membership, bounds, unique arrays, whole-string
opaque-reference syntax (including rejection of trailing newlines), and these
representable conditional relations:

- `distance == dot` requires `normalization == unit`.
- `threshold_policy == disabled` requires `minimum_score == 0`;
  `minimum` requires a positive score.
- `retention == disabled` iff `retention_hours == 0`;
  `bounded` requires positive hours.

Runtime validation is additionally authoritative for dynamic relations that
standard JSON Schema does not directly express: tenant/context/collection refs
must be distinct; `query_context_ref == context_ref`;
`dimensions == index_dimensions`; `candidates >= top_k`;
`result_bytes >= query_bytes`; `backup_hours >= index_hours`; and
`rate_per_minute <= contributions_per_source`. Schema-valid documents can still
fail these semantic checks. Strict JSON parsing rejects duplicate keys and
non-finite/overflow numbers before validation. Input size, UTF-8, stable-file,
and non-symlink checks are separate input-boundary requirements, not schema claims.

Integer fields follow JSON Schema numeric semantics: finite integral literals
such as `8`, `8.0`, and `8e0` are accepted and canonicalized to Python integers
before semantic checks and rule evaluation. Fractional literals are checked
losslessly (not rounded through binary floating point); booleans, strings,
non-finite values, and out-of-bound values reject. The manifest digest still
identifies the exact original UTF-8 text, not a normalized document.

The result and each finding retain the same shared `context_ref`. Its SHA-256
input is `ai-scan-llm08-context-ref-v1` followed by a NUL and the canonical compact
ASCII JSON tuple `["v1", tenant_ref, context_ref, collection_ref]` in that order.
Each finding also exposes a separate `finding_ref`, using the distinct
`ai-scan-llm08-finding-ref-v1` domain followed by a NUL and that tuple with the
exact public rule ID appended. References use `llm08-context-` or
`llm08-finding-` followed by 64 lowercase hex characters (78 characters total).
They are deterministic, independent of manifest key order, and contain no source
identifier text. They are grouping identities, not keyed confidentiality proofs:
predictable labels can be guessed offline. Rule IDs, reasons, remediations, and
finding order remain fixed. Both JSON and text findings include both references.

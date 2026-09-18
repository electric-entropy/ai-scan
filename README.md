# ai-scan

**CLI-only LLM security-assessment platform** (v0.2.1) — behavioral model
fingerprinting and safe, canary-based prompt-injection testing for HTTP(S) LLM
endpoints, with a repeatable **Reliable** confirmation engine, tamper-evident
evidence bundles, and fully offline replay. Python 3.11+, standard library only,
zero runtime dependencies.

> ⚠️ **Use responsibly.** ai-scan sends active requests to the target you
> specify. Like nmap or sqlmap, it runs unattended — you point it at a target and
> it runs. Only use it against systems you own or are permitted to test; testing
> systems without permission may be illegal, and staying in scope is your
> responsibility. The tool confines every request to the exact target you name
> (scheme/host/port/path) and never follows redirects off it.

## Install

From a source checkout (development):

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ai-scan --help
ai-scan doctor          # offline health check of the installed package
```

From a built release artifact (wheel or sdist):

```bash
python -m build                       # produces dist/*.whl and dist/*.tar.gz
python -m venv /tmp/ai-scan && /tmp/ai-scan/bin/pip install dist/ai_scan-*.whl
/tmp/ai-scan/bin/ai-scan doctor       # exits 0 when packaged resources validate
```

Requires Python 3.11+. Zero runtime dependencies (standard library only); the
`[dev]` extra pulls in pytest, ruff, mypy, and build for development/release.
The wheel and sdist ship the runtime package, JSON schemas, builtin packs,
`py.typed`, and the license; tests are not shipped in the sdist.

## Commands

```text
ai-scan fingerprint      --target URL [--method POST] [--request-template FILE]
ai-scan inject           --target URL --goal GOAL [--request-template FILE] [--profile safe]
ai-scan assess           --target URL [--request-template FILE] [--profile safe]
ai-scan plan             --target URL [--mode reliable|kitchen-sink] [--out plan.json]
ai-scan run              --target URL --plan plan.json [--out report.json]
ai-scan packs            list|validate PACK
ai-scan adapters         list|show NAME
ai-scan report           --file report.json --format json|jsonl|markdown|html|sarif
ai-scan baseline         create|diff
ai-scan bundle           validate|replay --file bundle.json
ai-scan replay           --bundle bundle.json --validate-only
ai-scan validate-config  --kind KIND --file doc.json
ai-scan doctor           [--json]
ai-scan owasp-coverage   [--format summary|json]
ai-scan supply-chain-audit    --manifest FILE [--format human|json]
ai-scan data-poisoning-audit  --target URL [--format human|json]
ai-scan vector-audit          --manifest FILE [--format text|json]
ai-scan misinformation-audit  --manifest FILE [--format json|text]
ai-scan consumption-audit     --manifest FILE [--format json|text]
```

`bundle validate|replay`, the top-level `replay`, `report`, `baseline`,
`validate-config`, `packs`, `adapters`, `doctor`, `owasp-coverage`, and
`supply-chain-audit`, `vector-audit`, `misinformation-audit`, and `consumption-audit` are all **offline** — they construct no
transport and touch no network. `data-poisoning-audit` is active: it contacts only the exact
operator-supplied `--target` URL through the hardened scope-safe transport.

Active commands (`fingerprint`, `inject`, `assess`, `run`) run **unattended** —
you point them at a `--target` and they run, so they can be launched and left to
complete in CI or scripts. Every request is confined to the exact `--target`
(scheme/host/port/path), redirects are never followed, and per-run budgets/rate
limits apply.

`assess`/`inject`/`fingerprint` run **legacy v1 semantics** (a single response per
attack case, single-origin, no repeated-trial confirmation, controls, or evidence
graph) — *not* Reliable (v2) mode. The **Reliable v2** engine (repeated trials,
clean controls, non-reflected confirmation, evidence graph, replayable bundles) is
the `plan` + `run` path. `run` verifies the exact target and plan integrity before
any transport.

Single-shot `inject`/`assess` results cannot be `confirmed`: deterministic
execution without matched controls is a `potential` analyst lead (exit `0`),
not a verified vulnerability. Reflection/refusal remain potential; clean output
remains `not_observed`; unusable output is `inconclusive` (exit `4`). The v1
report shape and exit-code vocabulary remain unchanged; exit `3` requires real
controlled confirmation, available through `plan` + `run`.

Default generic extraction supports plain text. Structured JSON, XML, SSE, or
fenced bodies require explicit eligible extraction rather than treating an
envelope as assistant output; use a provider adapter for final-assistant semantics.
Checkpoint run-identity rejection exits `4` with a fixed safe reason and no
new requests. In `run` budgets, `used` and `runner_count` are cumulative spent
attempts; `invocation_used` counts only this invocation. Old evidence is never
rebound to a newly generated canary.

### Exit codes

| Code | Meaning                                   |
|------|-------------------------------------------|
| `0`  | Completed, no confirmed findings          |
| `1`  | Runtime/configuration failure             |
| `2`  | Request blocked by a safety control (scope/budget) |
| `3`  | Confirmed security finding (injection)    |
| `4`  | Inconclusive assessment                   |

Configuration/usage errors (bad flags, unknown subcommand) exit `1`, distinct
from the `2` used for safety-control denials (e.g. an out-of-scope request).

### Safety controls

- **Method allowlist** — active requests use only `GET`/`POST`; other methods
  are rejected up front.
- **Payload allowlist** — `--profile` accepts only packaged profile names
  (`safe`), never a path or external file.
- **Rate + budget** — a minimum inter-request interval is enforced and a single
  physical-request budget bounds every attempt (retries included).
- **Redaction & scope** — see [SECURITY.md](SECURITY.md) for the full list
  (no-redirect-follow, header/URL/body redaction, exact-origin scoping).

## Platform capabilities (v0.2.1)

**Reliable vs Kitchen Sink modes** (`plan --mode ...`). Both share the same
scope, budget, redaction, and confirmation rules — Kitchen Sink only broadens
coverage, it never weakens safety.

- **Reliable** — the default, conservative mode. Resolves the reliable-tier packs
  and confirms only with repeatable, controlled, non-reflected execution evidence
  (repeated attack trials, a clean control per family, and a genuine canary
  execution — never inferred from a single 1/1 result).
- **Kitchen Sink** — broader coverage that resolves the additional packs for
  separately labeled analyst leads.

**Attack packs** (`ai-scan packs list`). Twelve digest-verified builtin packs:
`direct-injection`, `indirect-injection`, `rag-isolation`, `tool-abuse`,
`prompt-disclosure`, and `system-prompt-leakage`, each
in a reliable and a kitchen-sink variant. Packs are declarative, validated, and
content-digested; the plan records each pack's id/version/digest.

**Adapters** (`ai-scan adapters list`). Built-in request/extraction adapters
include `generic_http`, `openai_compatible`, `anthropic`, `gemini`, `ollama`,
`captured_http`, `sse`, `mcp`, `multimodal`, and `websocket`. All active traffic
still flows through the single brokered, origin-scoped transport.

**Evidence bundles + offline replay.** A `run` can export a portable,
content-digested, secret-free evidence bundle (plan + digest, redacted per-case
records, findings, controls, and a provenance graph). `ai-scan bundle
validate|replay --file` and `ai-scan replay --bundle ... --validate-only` verify
every digest and graph invariant and **reproduce the classification entirely
offline** — no transport, no network — binding each record to the verified plan;
any tamper (digest mismatch, altered prompt/proof, inflated trial counts, unknown
fields) fails closed with a scrubbed, non-zero error.

**Offline `doctor`.** `ai-scan doctor` validates the packaged schemas, builtin
packs, OWASP LLM coverage matrix, `py.typed`, and version/license metadata via
`importlib.resources`, constructs no transport, needs no target, and exits `0`
with a concise health summary (`--json` for machine-readable output).

**OWASP LLM 2025 coverage contract.** `ai-scan owasp-coverage` renders the
packaged, versioned applicability/evidence matrix for OWASP Top 10 for LLM
Applications 2025 (LLM01-LLM10). The matrix is a truthful contract, not a scan
result: it distinguishes current active CLI coverage from scaffolding, prompt
overlap, planned Phase 2B work, and unsupported scenarios. It explicitly does
not claim full OWASP coverage or OWASP compliance. AI-Scan does not claim full
OWASP coverage from this partial matrix; see
[`docs/owasp-llm-coverage.md`](docs/owasp-llm-coverage.md).
The current active public `plan`/`run` OWASP categories are LLM01, LLM02, and
LLM07. LLM02 and LLM07 use deterministic synthetic marker fixtures, never real
secrets. The expected marker must be provisioned to the target out-of-band (for
local checks, pass `run --synthetic-canary-file FILE`). Without that explicit
marker input, live `run` skips marker-dependent controls/attacks as inconclusive
coverage gaps while continuing normal LLM01 execution. Checkpoint/resume,
bundle, and replay are live-only for marker-dependent confirmation and never
accept LLM02/LLM07 persisted trials as authoritative evidence. AI-Scan does not
put that marker in the plan, prompt, URL, headers, or request body for disclosure
or system-prompt-leakage probes.
LLM03 has only partial offline manifest coverage through
`ai-scan supply-chain-audit --manifest FILE`: it reads one bounded local regular
non-symlink artifact manifest, performs no network access, constructs no
transport, and never imports/loads/deserializes model artifacts. Registry checks,
signatures/attestations, dataset contents, model behavior, artifact byte hashing,
and runtime dependency resolution remain gaps.
LLM04 has only partial active controlled retrieval-protocol coverage through
`ai-scan data-poisoning-audit --target URL`: AI-Scan sends a fixed strict JSON
operation sequence to one exact target path through the existing scope-safe
transport; the independently running service owns ingestion state and retrieval
behavior. Confirmation requires exact eligible retrieval content after poisoning,
pre-poison absence, clean controls, namespace isolation, and verified cleanup.
Metadata/envelope/error/explanation/request-echo marker appearances do not
confirm. Model-weight poisoning, fine-tuning poisoning, production RAG,
embeddings, feedback learning, and non-protocol target/model behavior remain
gaps. A deadline, budget, transport, or cleanup-verification failure after an
uncertain ingestion can leave the controlled poison item unresolved and requires
explicit service-side or operator reconciliation; public output reports that
state without exposing the target, item identifier, or marker.
LLM05 has only partial offline declaration coverage through
`ai-scan output-handling-audit --manifest FILE`. It applies fixed checks to
declared downstream sink controls and emits only manifest-bound opaque findings.
It never opens declared paths or URLs, constructs transport, accesses the
network, or renders/executes model output, commands, templates, SQL, HTML/JS,
payloads, or plugins. Declaration checks passed does not prove safe runtime
behavior. Runtime rendering and execution, browser behavior, database or process
effects, prompt injection, and downstream implementation verification remain
gaps; no full LLM05 or OWASP compliance claim is made.
LLM06 has partial offline declaration coverage through
`ai-scan agency-audit --manifest FILE`. It assesses declared tool inventory,
scope, least privilege, isolation, autonomy bounds, side-effect lifecycle,
result trust, and auditability. Only the selected bounded manifest is opened;
no tools or declared objects are executed or resolved. A clean outcome means
“declaration checks passed” only. No tool execution, permission enforcement,
deployed identity, isolation, cleanup, runtime behavior, or absence of excessive
agency was verified. See [the manifest contract](docs/agency-audit.md).
LLM07 has partial active controlled system-prompt fixture coverage through the
same public `plan`/`run` path: Reliable compiles the
`system-prompt-leakage-reliable` pack and Kitchen Sink adds
`system-prompt-leakage-kitchen`. The fixture independently stores the synthetic
marker in system-prompt state before scanning. Confirmation requires exact
eligible final assistant marker text plus matched clean controls and is
live-only; arbitrary production prompt inspection, unknown prompt recovery, and
proof of absence remain out of scope.
LLM08 has only partial offline declaration coverage through
`ai-scan vector-audit --manifest FILE`. It deterministically assesses declared
scope partitioning, ingestion provenance/integrity, embedding/model lineage,
retrieval controls, data minimization/privacy, lifecycle, poisoning resistance,
and isolation/operations controls. Only the selected bounded manifest is opened;
declared documents, embeddings, indexes, model files, plugins, URLs, commands,
archives, and code are never opened, imported, fetched, connected to, or
executed. A clean outcome means “declaration checks passed” only. No vector-store
exploitation, retrieval validation, embedding inversion, tenant escape proof,
runtime isolation, or proof that declarations are true was performed.
The shipped Draft 2020-12 vector manifest schema is structural preflight, not
the full runtime domain contract. Runtime validation additionally enforces
dynamic cross-field relations; see the [LLM08 contract](docs/owasp-llm-coverage.md#llm08-manifest-preflight-and-identities).
Finite integral JSON numbers such as `8.0` and `8e0` are accepted as integers;
fractional, non-finite, boolean, string, and out-of-range values are rejected.
Results retain a shared opaque `context_ref` bound to tenant/context/collection
and a separate rule-bound `finding_ref` for each finding, without source labels.
LLM09 has partial offline structured-claim coverage through
`ai-scan misinformation-audit --manifest FILE [--format json|text]`. It compares
operator-supplied expected and observed claim digests, sources, citation presence,
and snapshot identity. It never loads or resolves referenced objects, executes
targets, connects to the network, or invokes a model/judge. Ground truth and
observations are not independently verified: this is not general truth verification.
Exit codes are 0 for matching claims, 3 for findings, and 2 for invalid input.
Results contain only opaque identities, fixed rule codes, the manifest SHA-256,
zero execution/request counts, and limitations. See [the LLM09 contract](docs/misinformation-audit.md).

LLM10 has partial offline bounded-consumption coverage through
`ai-scan consumption-audit --manifest FILE [--format json|text]`. Deterministic rules
compare operator-supplied workload observations with supplied ceilings and declared
fail-closed controls. No target execution, load generation, network, reference loading,
LLM judge, model scoring, or billing/cost assessment occurs. Passing does not prove
runtime enforcement. Exits: 0 passed, 3 findings, 2 invalid. JSON/text emit only fixed
codes, opaque logical references, manifest SHA-256, zero execution/request counts,
and limitations. See [the LLM10 contract](docs/consumption-audit.md).
Exactly LLM01–LLM10 now have active partial coverage; none claims full coverage or
compliance. Reliable/Kitchen Sink plans remain 20/40 cases.

Prompt-only LLM06 tool-abuse packs do not count as LLM06 runtime coverage. Matrix identifiers
for remediation/report/SARIF are reserved contract identifiers for future
integration, not values emitted by the current report or SARIF renderers.

**Named-host HTTPS limitation.** AI-Scan currently fails closed for named-host
HTTPS targets. Vetted-IP connection with preserved SNI and certificate hostname
verification is not yet implemented, so ordinary hosted HTTPS endpoints are not
a happy path today; use loopback/plain-HTTP fixtures for local release checks
until that transport capability exists.

**Optional isolated worker.** An opt-in local worker runs a bounded JSON request
in a short-lived, hardened container (`Dockerfile.worker`): read-only rootfs,
`--network none`, all capabilities dropped, non-root uid, tmpfs scratch, and
bounded CPU/memory/PID limits. The launcher streams bounded stdin/stdout under a
timeout and exposes only an empty dedicated output directory. It changes no
active-network semantics; egress stays disabled.

## Basic example

```bash
# Point it at a target and it runs — no prompt, nothing to configure.
ai-scan assess --target http://127.0.0.1:8080/chat --out report.json
echo "exit code: $?"   # 0 completed (including analyst leads) / 4 inconclusive
```

## Request template format (Burp-style)

Pass `--request-template FILE` to control the request body. The file must
contain the literal `*` **prompt marker**, which is where each probe's prompt is
inserted. For a JSON chat endpoint:

```json
{"model": "x", "messages": [{"role": "user", "content": "*"}]}
```

**Prompt insertion is context-aware, so the request is always well-formed:**

- **JSON POST (default mode).** The marker must sit *inside* a JSON string (as
  above). The prompt is **JSON-string-escaped** before insertion — quotes,
  backslashes, and control characters such as newlines are escaped — so payloads
  that contain newlines never produce invalid JSON. The default template when
  none is supplied is `{"input": "*"}`.
- **GET.** Place the marker in the target URL/query; the prompt is
  **percent-encoded** on insertion.
- **Raw mode (`prompt_encoding="raw"`, for Burp-style/non-JSON templates).** The
  prompt is inserted **verbatim** at the marker with no escaping. Use this only
  when your template is not JSON and you are handling escaping yourself; you are
  then responsible for producing a valid request.

Sensitive headers you add (Authorization, Cookie, API keys, tokens) are
**redacted** from all stored evidence, and their values are scrubbed from
response bodies. Redirects are captured but never followed.

## Interpreting the report

The JSON report (`--out`) is stable and machine-readable. Key sections:

- `target_origin` — normalized scheme://host[:port] that was assessed.
- `request_budget` — bounds and requests actually used.
- `fingerprint` — ranked heuristic candidates (see limitations below).
- `injection` — per-family status and the overall status. A `confirmed`
  finding means the target emitted the canary by *executing* the injected
  instruction (a mere reflection of the prompt is `potential`); a redirect,
  HTTP error, or truncated response is `inconclusive`, never a silent clean
  result. A confirmed finding includes the exact canary as proof.
- `evidence` — redacted request/response records.
- `findings` — confirmed/potential injection findings promoted to the top.

Legacy single-shot `assess` cannot confirm: it exits `4` when evidence is
inconclusive and otherwise `0`, including when it reports analyst leads. Use the
controlled `plan` + `run` path for confirmation-based CI gates and exit `3`.

## Fingerprint confidence — limitations

The built-in fingerprinter is **heuristic**. It scores a small set of behavioral
markers plus weak header and self-identification signals, and returns `unknown`
unless a family clears both a minimum score and a minimum margin. It is **not**
equivalent to the academic LLMmap pretrained-model inference approach, and its
`heuristic` label reflects that. Treat candidates as leads, not attribution.

## Roadmap

Not yet implemented:

- An adapter for an upstream academic/PyTorch LLMmap backend and a current-model
  template registry (the built-in fingerprinter stays heuristic).
- A signed/attested release supply chain (the release produces a CycloneDX SBOM
  and a reproducible wheel, but no signing/attestation/provenance).

Already shipped in v0.2.0 (previously roadmap): versioned digest-verified attack
packs (direct/indirect injection, RAG isolation, tool abuse), multiple request
adapters, the Reliable v2 confirmation engine, tamper-evident evidence bundles
with offline replay, and an optional hardened local worker.

Out of scope: REST/web UI, browser automation, distributed/multi-host workers,
aggressive or destructive payloads, and LLM-as-judge scoring.

### Platform direction

v0.2.0 is a **local, CLI-first AI security-assessment platform**. Legacy v1
commands (`assess`, `inject`, `fingerprint`) keep report schema v1 for
compatibility, while the Reliable v2 path (`plan` + `run`) emits schema v2
evidence/finding artifacts, evidence bundles, and offline replay. The public
contracts are documented under [`docs/architecture/`](docs/architecture/):

- [platform-boundaries.md](docs/architecture/platform-boundaries.md) — in/out of scope.
- [mode-contracts.md](docs/architecture/mode-contracts.md) — the `reliable` and
  `kitchen-sink` modes and finding taxonomy.
- [safety-invariants.md](docs/architecture/safety-invariants.md) — non-negotiable invariants.
- [migration-policy.md](docs/architecture/migration-policy.md) — how v1 stays
  compatible as schema v2 / the `run` path arrive.
- ADRs: [0001 CLI-first engine](docs/architecture/adr/0001-cli-first-engine.md),
  [0002 confirmation & confidence](docs/architecture/adr/0002-confirmation-and-confidence.md).

The legacy-v1 behavior these docs freeze is guarded by the golden compatibility
contract in [`tests/contracts/`](tests/contracts/).

## Development

```bash
pip install -e '.[dev]'
python -m pytest tests/contracts -q
python -m pytest -q          # unit + integration (loopback only)
ruff check .
mypy
python -m build
```

Release/operator documentation:

- [Operator guide](docs/operator-guide.md) — safe run, replay, and release validation workflow.
- [Pack authoring](docs/pack-authoring.md) — declarative pack requirements and fail-closed validation rules.
- [Evidence and retention](docs/evidence-and-retention.md) — redaction, bundle, replay, and retention guidance.
- [Threat model](docs/threat-model.md) — trust boundaries and release-hardening controls.
- [Changelog](CHANGELOG.md) — release history.

CI (`.github/workflows/ci.yml`) runs on Python 3.11 and 3.12 with least-privilege
permissions, per-job timeouts, and concurrency cancellation. Gates: a deterministic
credential scan, contract tests, the full suite, Ruff, strict Mypy, wheel/sdist
builds, a fresh-wheel package-resource smoke check that also runs `ai-scan doctor`,
a zero-runtime-dependency audit, CycloneDX SBOM generation/validation, a
reproducible-build check (two builds compared by hash), and a hardened worker
protocol smoke that builds the image, verifies a non-root uid, and checks exact
`ping` → `pong` behavior under `--network none`, `--read-only`,
`--cap-drop ALL`, and `--security-opt no-new-privileges`. The tag-gated release workflow
(`.github/workflows/package.yml`) re-runs every gate and verifies the tag equals
the project version before uploading the built `dist/*` and SBOM as artifacts; it
does not publish to any index and produces no signing/attestation/provenance. All
GitHub Actions are pinned to immutable commit SHAs.

## License

[PolyForm Shield License 1.0.0](LICENSE) — use and modification are permitted, but providing a product that competes with AI-Scan or an Electric Entropy product using AI-Scan is prohibited.

# Changelog

All notable changes to AI-Scan are documented here. The project uses a conservative release process: local gates pass before a push, GitHub CI verifies the pushed SHA, and external scan targets are never used for release validation.

## 0.2.1 - 2026-09-14

### Removed

- **The legacy pre-run gating step was removed entirely (owner product
  decision).** Its commands, flag, schema, validation, and the corresponding
  report field are all gone. Active commands (`fingerprint`, `inject`, `assess`,
  `plan`+`run`) run unattended — you point them at a `--target` and they run,
  comparable to nmap/sqlmap where using the tool responsibly and legally is the
  operator's own responsibility.

### Changed

- Exit code `2` now means "request blocked by a safety control (scope/budget)".
- Bumped GitHub `actions/upload-artifact` pin to v7.0.1; comprehensive README
  refresh; added the offline `ai-scan doctor` health check to the fresh-wheel smoke.
- The `reflection-is-not-execution` rule was hardened: a canary reflected or
  merely mentioned in a refusal or in envelope metadata (e.g. Ollama
  `message.thinking`) cannot confirm.

### Security

- Every other safety boundary is unchanged and still fail-closed:
  exact-target scope confinement, broker-only egress, no-redirect-follow, per-run
  budgets/rate/concurrency/duration limits, redaction, the confirmation/confidence
  taxonomy, and checkpoint/evidence-bundle/replay integrity.

## 0.2.0 - 2026-09-13

### Added

- Reliable and Kitchen Sink mode contracts with shared scope, budget, redaction, and confirmation invariants.
- Strict JSON/schema loaders for targets, engagements, plans, packs, evidence, and findings.
- Central redaction, canonical exchange records, request broker, budgets, and exact-origin scope guards.
- Adapter protocol with generic HTTP, captured-request, provider, streaming, MCP, and multimodal request shaping.
- Declarative built-in attack packs, deterministic validators, controls, confidence rules, planner, runner, checkpoints, evidence bundles, replay, reports, SARIF, and baselines.
- Direct injection, prompt disclosure, RAG, tool/MCP, session/memory/multi-agent, output-handling, encoding, resource, router, supply-chain, and fingerprinting coverage.
- CLI v2 migration commands and an optional isolated local Docker worker.
- Release hardening docs, package workflow, artifact smoke checks, SBOM generation, and offline safety gates.

### Security

- Active commands fail closed before constructing transport when scope, profile, adapter, or plan validation fails.
- Reflection, heuristic fingerprinting, and judge-style evidence cannot independently produce confirmed findings.
- Known transport secrets and sensitive fields are scrubbed recursively before persistence and reporting.
- Redirects, truncation, errors, budget/scope denials, and unsupported streaming states become blocked or inconclusive rather than clean negatives.

### Compatibility

- Existing MVP command shapes remain available; `assess` remains legacy v1 compatibility semantics (single response per attack case), while Reliable v2 (repeated trials, controls, evidence graph, replayable bundles) is the `plan --mode reliable` + `run` path.
- Report schema v1 compatibility is preserved for legacy commands while v2 evidence/finding artifacts support the new run path.

## 0.1.0 - 2026-09-11

- Initial CLI-only LLM assessment MVP with behavioral fingerprinting and safe canary-based prompt-injection checks.

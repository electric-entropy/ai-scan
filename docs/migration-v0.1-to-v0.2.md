# Migration from AI-Scan v0.1 to v0.2

AI-Scan v0.2 keeps the v0.1 active commands and report schema v1 compatible while adding the planner/runner and offline reporting surfaces.

## Compatible by default

The existing active commands remain available:

- `ai-scan fingerprint`
- `ai-scan inject`
- `ai-scan assess`

Existing `assess --target ... --out report.json` automation continues to emit the legacy report v1 document. The exit-code vocabulary remains `0`–`4`, but single-shot `inject`/`assess` can no longer emit `confirmed` or exit `3`: an uncontrolled deterministic execution signal is a `potential` analyst lead (exit `0`). Reflection/refusal remain potential, clean evidence remains `not_observed`, and unusable evidence exits `4`/`inconclusive`. Use `plan` + `run` for controlled, repeatable confirmation. Active scans run unattended against `--target`.

## New v0.2 commands

- `ai-scan packs list|validate` lists and validates declarative packs offline.
- `ai-scan adapters list|show NAME` inspects adapter capabilities offline.
- `ai-scan plan --target URL --out plan.json` compiles a digested execution plan without network traffic.
- `ai-scan run --target URL --plan plan.json` executes a compiled plan through the runner (verifying exact target + plan integrity).
- `ai-scan report --file report.json --format json|jsonl|markdown|html|sarif` renders an existing report offline.
- `ai-scan baseline create|diff` creates stable CI baselines and diffs them by finding identity.
- `ai-scan bundle validate|replay` validates and replays evidence bundles offline.

## Mode behavior

`assess` remains **legacy v1 compatibility semantics** (a single response per attack case, no repeated-trial confirmation, controls, or evidence graph) — it is *not* Reliable (v2) mode. Reliable v2 is the `plan --mode reliable` + `run` path. `assess` intentionally does not expose a Kitchen Sink selector; use `plan --mode kitchen-sink` plus `run` for broader coverage.

`kitchen-sink` is broader but does not weaken scope, budgets, redaction, cleanup, or confirmation rules; like every other mode it runs unattended.

## Recommended migration path

1. Keep `assess` for compatibility and analyst leads, but move confirmation-based gates to controlled `plan` + `run`; single-shot `assess` no longer exits `3`.
2. Add `ai-scan plan` in review workflows to inspect exactly what will run.
3. Move advanced workflows to `ai-scan run --plan ...` when you want resumable runner state and plan digests in reports.
4. Use `ai-scan report` and `ai-scan baseline` for offline analyst outputs and CI baseline comparisons.

## Safety guarantees preserved

- No active command touches the network before exact-target scope and offline input validation.
- Offline commands never construct transport.
- v0.1 reports remain readable and renderable through v0.2 report commands.
- Confirmed findings still require deterministic, controlled evidence; analyst leads are separated from confirmed findings in v2 renderers.

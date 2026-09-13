# Migration from AI-Scan v0.1 to v0.2

AI-Scan v0.2 keeps the v0.1 active commands and report schema v1 compatible while adding the planner/runner and offline reporting surfaces.

## Compatible by default

The existing commands remain available:

- `ai-scan authorize`
- `ai-scan fingerprint`
- `ai-scan inject`
- `ai-scan assess`
- `ai-scan validate-receipt`

Existing `assess --target ... --auth-receipt ... --non-interactive --out report.json` automation continues to emit the legacy report v1 document and uses the same exit codes: `0`, `1`, `2`, `3`, and `4`.

## New v0.2 commands

- `ai-scan packs list|validate` lists and validates declarative packs offline.
- `ai-scan adapters list|show NAME` inspects adapter capabilities offline.
- `ai-scan plan --target URL --out plan.json` compiles a digested execution plan without authorization or network traffic.
- `ai-scan run --target URL --plan plan.json --auth-receipt auth.json --non-interactive` executes a compiled plan through the runner after receipt validation.
- `ai-scan report --file report.json --format json|jsonl|markdown|html|sarif` renders an existing report offline.
- `ai-scan baseline create|diff` creates stable CI baselines and diffs them by finding identity.
- `ai-scan bundle validate|replay` validates and replays evidence bundles offline.

## Mode behavior

`assess` continues to use Reliable mode for compatibility. It intentionally does not expose a Kitchen Sink selector; use `plan --mode kitchen-sink` plus `run` for broader authorized coverage.

`kitchen-sink` is broader but does not weaken authorization, scope, budgets, redaction, cleanup, or confirmation rules. A v1 receipt cannot authorize headless Kitchen Sink execution. If `--mode kitchen-sink` or a Kitchen Sink plan is supplied with `--auth-receipt ... --non-interactive`, the CLI exits `2` before constructing transport or sending requests. Use an interactive authorization path until signed v2 receipts are introduced.

## Recommended migration path

1. Keep existing `assess` automation unchanged for CI gates.
2. Add `ai-scan plan` in review workflows to inspect exactly what will run.
3. Move advanced workflows to `ai-scan run --plan ...` when you want resumable runner state and plan digests in reports.
4. Use `ai-scan report` and `ai-scan baseline` for offline analyst outputs and CI baseline comparisons.

## Safety guarantees preserved

- No active command touches the network before target authorization and offline input validation.
- Offline commands never construct transport.
- v0.1 reports remain readable and renderable through v0.2 report commands.
- Confirmed findings still require deterministic, controlled evidence; analyst leads are separated from confirmed findings in v2 renderers.

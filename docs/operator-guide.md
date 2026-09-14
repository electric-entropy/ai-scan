# Operator Guide

AI-Scan is a local, CLI-first tool for explicitly authorized AI-system assessment. It sends active requests only after authorization and keeps external-network release validation out of scope.

## Safe operating model

1. Define the exact target origin and engagement scope before running active commands.
2. Prefer `reliable` mode for consulting findings and CI gates. Use `kitchen-sink` only for separately labeled analyst leads and only with the same authorization and budget controls.
3. Use receipts for repeatable non-interactive runs. A receipt must match the normalized target origin and must not be expired.
4. Keep intrusive capabilities separate from mode selection. Uploads, writes, tool actions, cross-identity tests, persistence, and resource-stress checks require explicit capability grants.
5. Treat every request, retry, redirect attempt, control, confirmation, cleanup probe, discovery probe, upload, and read-back as a physical request for budget purposes.

## Common commands

```bash
ai-scan authorize --target https://example.test/chat --client Client --engagement ENG-1 --expires 2026-12-31 --out auth.json
ai-scan plan --target https://example.test/chat --mode reliable --out plan.json
ai-scan run --target https://example.test/chat --plan plan.json --auth-receipt auth.json --non-interactive --out report.json
ai-scan report --file report.json --format markdown
ai-scan bundle validate --file evidence-bundle.json
ai-scan bundle replay --file evidence-bundle.json
ai-scan replay --bundle evidence-bundle.json --validate-only
```

`bundle validate`/`bundle replay` and the top-level `replay --bundle ... --validate-only`
are **offline** — they verify digests/graph and reproduce the stored
classification without constructing any transport. A tampered bundle exits
non-zero with a scrubbed error.

## Interpreting outcomes

- `confirmed` requires deterministic, controlled, reproducible evidence. Reflection, self-identification, heuristic similarity, and LLM judges cannot confirm by themselves.
- `likely` and `suspected` are analyst leads, not vulnerabilities.
- `blocked`, `inconclusive`, and `not_tested` are coverage gaps that must be retained in reports.
- Exit code `3` is reserved for policy-triggering confirmed findings; runtime/configuration and authorization failures remain separate.

## Release/local validation

Before relying on a build, run the repository gates from a clean checkout:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest tests/contracts -q
python -m pytest -q
ruff check .
mypy
python -m build
ai-scan --help
```

Release validation uses only local fixtures and package-resource checks. Do not point release jobs at external targets.

## Shipped package contents

The wheel and sdist ship the runtime package only: `ai_scan/` source, `py.typed`,
the JSON `schemas`, the builtin `packs`, the report template, and the `LICENSE`
(PolyForm Shield 1.0.0 — a source-available, not OSI/open-source, license). The
CLI entry point (`ai-scan`) is registered in the wheel metadata.
**Tests are not shipped in the sdist** (they depend on the source-tree layout);
run the suite from a source checkout. Release-gate tooling under `scripts/`
(credential scan, SBOM generation, reproducible-build check) is not shipped either.

## Release path

The supported release path is: (1) run the local gates above from a clean tree;
(2) build artifacts (`python -m build`); (3) inspect wheel/sdist contents; (4)
fresh-wheel install smoke; (5) the tag-gated `Package` workflow, which re-runs
every gate — tests, ruff, mypy, credential scan, SBOM generation, reproducible
build, worker image build/scan — and verifies the pushed tag equals the project
version **before** uploading the built `dist/*` and SBOM as workflow artifacts.
The workflow does **not** publish to any index on push; publishing is a separate,
deliberate step. No artifact signing, attestation, or provenance is produced or
claimed.

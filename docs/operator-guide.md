# Operator Guide

AI-Scan is a local, CLI-first tool for LLM security assessment. Active scans run **unattended** — like nmap or sqlmap, you point the tool at a target and it runs; using it responsibly and legally against systems you own or are permitted to test is your responsibility. It keeps external-network release validation out of scope, and every request is confined to the exact target you specify.

## Safe operating model

1. Only run active commands against targets you own or are permitted to test.
2. Define the exact target (scheme/host/port/path) before running — scope is enforced to that exact target and redirects off it are never followed.
3. Prefer `reliable` mode for consulting findings and CI gates. Use `kitchen-sink` only for separately labeled analyst leads and only with the same scope and budget controls.
4. Keep intrusive capabilities separate from mode selection. Uploads, writes, tool actions, cross-identity tests, persistence, and resource-stress checks require explicit capability grants.
5. Treat every request, retry, redirect attempt, control, confirmation, cleanup probe, discovery probe, upload, and read-back as a physical request for budget purposes.

## Common commands

```bash
ai-scan plan --target https://example.test/chat --mode reliable --out plan.json
ai-scan run --target https://example.test/chat --plan plan.json --out report.json
ai-scan report --file report.json --format markdown
ai-scan bundle validate --file evidence-bundle.json
ai-scan bundle replay --file evidence-bundle.json
ai-scan replay --bundle evidence-bundle.json --validate-only
ai-scan doctor
```

`ai-scan doctor` is an **offline** health check: it validates the packaged
schemas, builtin packs, `py.typed`, and version/license metadata via
`importlib.resources`, constructs no transport, needs no target,
and exits `0` with a concise summary (add `--json` for machine-readable output).

`bundle validate`/`bundle replay` and the top-level `replay --bundle ... --validate-only`
are **offline** — they verify digests/graph and reproduce the stored
classification without constructing any transport. A tampered bundle exits
non-zero with a scrubbed error.

## Interpreting outcomes

- `confirmed` requires deterministic, controlled, reproducible evidence. Reflection, self-identification, heuristic similarity, and LLM judges cannot confirm by themselves.
- `likely` and `suspected` are analyst leads, not vulnerabilities.
- `blocked`, `inconclusive`, and `not_tested` are coverage gaps that must be retained in reports.
- Exit code `3` is reserved for policy-triggering confirmed findings; runtime/configuration failures and safety-control denials (exit `2`) remain separate.

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

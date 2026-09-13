# Pack Authoring Guide

Attack packs are declarative data. They must not execute arbitrary code, open sockets, read host files, or bypass the central request broker.

## Required properties

- Unique, stable case identifiers in canonical form: `pack_id:family:kind:index`.
- Explicit family, kind, capability requirements, payload template, controls, validators, and budgets.
- At least one matched control for cases that can contribute to confirmation.
- Deterministic validators for any path that can produce `confirmed` findings.
- Seeded mutation or ordering behavior when Kitchen Sink breadth is enabled.

## Forbidden content

- Absolute paths, `..`, encoded traversal, executable hooks, shell fragments, or dynamic imports.
- Real secrets, credentials, customer data, destructive instructions, persistence instructions, or uncontrolled resource amplification.
- Unknown schema fields, duplicate JSON keys, non-finite numbers, unbounded lists, unsupported validator kinds, and incompatible branch fields.

## Validator expectations

- Exact canary execution can support `confirmed` only when controls and repeatability also pass.
- Heuristic, statistical, or judge-style validators can create at most `likely` or `suspected` unless a deterministic validator independently satisfies confirmation requirements.
- Controls that emit the canary block confirmation.
- Truncated, errored, out-of-scope, or unsupported evidence is unusable and must yield `inconclusive`, `blocked`, or `not_tested`.

## Local validation

```bash
ai-scan packs validate path/to/pack.json
python -m pytest tests/unit/packs tests/security/test_pack_trust.py -q
```

Pack validation must be offline and must complete before transport construction in active commands.

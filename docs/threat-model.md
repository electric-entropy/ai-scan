# Threat Model

## Assets

- Target-scoped request plans, budgets, and evidence bundles.
- Redacted reports and immutable evidence graph records.
- Built-in packs, schemas, templates, package metadata, and release artifacts.

## Trust boundaries

- CLI input, user-supplied JSON, packs, captured requests, adapter configuration, and target responses are untrusted.
- Attack plugins and adapters shape requests but must send only through the central broker.
- Reports, exceptions, checkpoints, bundles, and console output are output sinks and must receive only scrubbed values.
- Release validation must use local fixtures and package artifacts, not external targets.

## Primary threats and controls

| Threat | Control |
|---|---|
| Network traffic before validation | Validate target scope, mode, packs, adapter config, and plan before transport construction. Scans run unattended — an out-of-scope or invalid-config request sends zero packets and exits before transport. |
| Scope escape, redirects, rebinding | Exact normalized origin/path checks per physical attempt; redirects not followed by default; vetted IP handling for supported schemes. |
| Budget evasion | One broker-owned physical request ledger counts attempts, retries, controls, confirmations, discovery, cleanup, and redirects. |
| Evidence leakage | Recursive redaction before persistence and output; transport-known secrets threaded to evidence exporters. |
| False confirmation | Deterministic validator plus controls, repeatability, usable evidence, and cleanup/read-back where applicable. |
| Malicious packs | Strict schema/domain validation, duplicate-key rejection, digest checks, no executable fields, path traversal rejection. |
| Captured-request smuggling | Reject ambiguous methods, authority forms, conflicting host/content length, obs-fold, CR/NUL, transfer encoding, and missing markers. |
| Streaming partial confirmation | Provider terminator required; bounded partial streams are inconclusive/errors. |
| Report injection | Offline templates only; escape target-controlled content; no remote assets. |
| Release artifact drift | CI builds wheel/sdist, installs the wheel in a fresh environment, verifies packaged resources and typed marker, emits SBOM, and keeps actions pinned by SHA. |

## Assumptions

- The operator uses the tool responsibly and controls the machine running AI-Scan; like nmap/sqlmap, it runs unattended against the named `--target`.
- Exact-target scope confinement is the boundary that keeps requests on the named target; it is not an access-control mechanism against the operator.
- Local Docker worker isolation reduces accidental exposure but is not a multi-tenant sandbox boundary.

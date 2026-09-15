# Security Policy & Threat Model

## Intended use

ai-scan is a tool for security assessment of LLM endpoints. It must only be
pointed at systems you own or have written permission to test. Like nmap or
sqlmap, it runs unattended against the exact `--target` you name — using it
responsibly and legally is the operator's responsibility. The safety boundaries
below confine *where* and *how* it sends requests; they are not a barrier against
a malicious operator, who by definition controls the machine running the tool.

> The platform-wide, non-negotiable safety invariants that every future
> milestone must preserve are documented in
> [docs/architecture/safety-invariants.md](docs/architecture/safety-invariants.md).
> The boundaries below are the subset the current MVP enforces.

## Safety boundaries enforced by the tool

- **Exact target scoping.** Every request is confined to the exact `--target`
  you name; targets are normalized and compared by scheme + host + effective
  port (IPv6 literals canonicalized) and path. Subdomains, scheme changes, and
  port changes are distinct origins. An out-of-scope request is blocked before
  transport (exit `2`).
- **Non-destructive method allowlist.** Active requests use only `GET` or
  `POST`; `DELETE`/`PUT`/`PATCH`/arbitrary methods are rejected before any
  transport is created.
- **No redirect following.** Any 3xx is captured as evidence and never
  followed, so a target cannot redirect the scanner to an out-of-scope host.
- **Bounded, rate-limited requests.** Timeout, maximum response size, retries,
  and a single physical-request budget (which counts every attempt, retries
  included) are all enforced, along with a minimum inter-request interval.
- **Allowlisted payload packs.** `--profile` resolves only to an explicit
  allowlist of packaged profiles; absolute paths, traversal, and external files
  are rejected before any file access.
- **Non-destructive payloads with execution-based confirmation.** Injection
  payloads only attempt to make the target emit a unique synthetic canary. They
  never request real credentials, secrets, destructive actions, or third-party
  data. A finding is `confirmed` only when the target emits the canary as a
  result of *executing* the injected instruction — a mere reflection of the
  submitted prompt is `potential`, not confirmed.
- **Honest inconclusive handling.** Redirects, HTTP errors, authentication
  failures, and truncated responses are reported as `inconclusive` (exit `4`),
  never silently treated as a clean negative.
- **Redaction.** Sensitive request and response headers (matched by an explicit
  set and by token-bearing name patterns), secret-like query parameters in
  request URLs and redirect `Location` values, and known secret values
  reflected in response bodies are all redacted from stored evidence. Secrets
  never appear in exception strings, reports, or the console summary.

## Reporting a vulnerability

If you find a security issue in ai-scan itself, please open a private report to
the maintainers rather than a public issue. Do not include working exploits or
real target data in the report.

## Release hardening

Release gates are documented in [docs/operator-guide.md](docs/operator-guide.md)
and modeled in [docs/threat-model.md](docs/threat-model.md). A releasable source
checkout must pass contract tests, the full loopback-only test suite, Ruff,
strict Mypy, wheel/sdist build, fresh-wheel CLI and package-resource smoke
checks, local secret scanning, a zero-runtime-dependency audit, SBOM generation,
and worker-container static checks. These gates do not contact external scan
targets.

Evidence retention and scrubbing expectations are documented in
[docs/evidence-and-retention.md](docs/evidence-and-retention.md). Pack authoring
and validation rules are documented in [docs/pack-authoring.md](docs/pack-authoring.md).

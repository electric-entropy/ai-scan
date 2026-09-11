# Security Policy & Threat Model

## Intended use

ai-scan is a tool for **explicitly authorized** security assessment of LLM
endpoints. It must only be pointed at systems you own or have written permission
to test. The tool enforces an authorization gate, but that gate is an
operational safeguard for well-intentioned operators — it is **not** a barrier
against a malicious operator, who by definition controls the machine running the
tool.

## Safety boundaries enforced by the tool

- **Fail-closed authorization.** Active commands require either an interactive
  confirmation of the exact normalized target origin, or a valid target-bound
  receipt. `--non-interactive` without a valid receipt exits `2` before any
  transport is constructed — no packets are sent.
- **Exact origin scoping.** Targets are normalized and compared by
  scheme + host + effective port (IPv6 literals canonicalized). Subdomains,
  scheme changes, and port changes are distinct origins. A receipt is valid
  only for its exact origin.
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
  never appear in exception strings, reports, or the console summary. The
  operator's confirmation input is never stored.

## Receipt threat model — tamper-evident, not authenticated

Authorization receipts are integrity-protected with **canonical JSON + SHA-256**.

- **What this provides:** detection of accidental edits, truncation, or
  corruption. A modified receipt whose digest was not recomputed fails
  validation.
- **What this does NOT provide:** authentication. Anyone who can run ai-scan can
  recompute a valid digest and forge a receipt for any origin. Receipts are a
  convenience for keeping authorized engagements in scope and auditable — they
  are not an access-control or anti-forgery mechanism.

Authenticated (signed) receipts and a centralized authorization service are
deferred beyond the MVP.

## Reporting a vulnerability

If you find a security issue in ai-scan itself, please open a private report to
the maintainers rather than a public issue. Do not include working exploits or
real target data in the report.

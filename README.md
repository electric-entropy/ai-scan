# ai-scan

**CLI-only, authorized LLM security-assessment platform** (v0.2.0) — behavioral
model fingerprinting and safe, canary-based prompt-injection testing for HTTP(S)
LLM endpoints, with a repeatable **Reliable** confirmation engine, tamper-evident
evidence bundles, and fully offline replay. Python 3.11+, standard library only,
zero runtime dependencies.

> ⚠️ **Authorized use only.** ai-scan sends active requests to a target. It will
> not touch the network until you have either confirmed authorization
> interactively for the current run, or supplied a valid, target-bound
> authorization receipt. Using it against systems you are not explicitly
> authorized to assess may be illegal. You are responsible for staying in scope.

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
ai-scan authorize        --target URL --client NAME --engagement ID --expires YYYY-MM-DD --out auth.json
ai-scan fingerprint      --target URL [--method POST] [--request-template FILE] [--auth-receipt FILE]
ai-scan inject           --target URL --goal GOAL [--request-template FILE] [--profile safe] [--auth-receipt FILE]
ai-scan assess           --target URL [--request-template FILE] [--profile safe] [--auth-receipt FILE]
ai-scan plan             --target URL [--mode reliable|kitchen-sink] [--out plan.json]
ai-scan run              --target URL --plan plan.json --auth-receipt FILE --non-interactive [--out report.json]
ai-scan packs            list|validate PACK
ai-scan adapters         list|show NAME
ai-scan report           --file report.json --format json|jsonl|markdown|html|sarif
ai-scan baseline         create|diff
ai-scan bundle           validate|replay --file bundle.json
ai-scan replay           --bundle bundle.json --validate-only
ai-scan validate-receipt --auth-receipt FILE --target URL
ai-scan validate-config  --kind KIND --file doc.json
ai-scan doctor           [--json]
```

`bundle validate|replay`, the top-level `replay`, `report`, `baseline`,
`validate-receipt`, `validate-config`, `packs`, `adapters`, and `doctor` are all
**offline** — they construct no transport and touch no network.

Active commands (`fingerprint`, `inject`, `assess`, `run`) require authorization. Without
`--auth-receipt` they prompt for a literal confirmation phrase for the normalized
target origin. With `--non-interactive` and no valid receipt, they exit `2`
**before any network traffic is sent**.

`assess`/`inject`/`fingerprint` run **legacy v1 semantics** (a single response per
attack case, single-origin, no repeated-trial confirmation, controls, or evidence
graph) — *not* Reliable (v2) mode. The **Reliable v2** engine (repeated trials,
clean controls, non-reflected confirmation, evidence graph, replayable bundles) is
the `plan` + `run` path. Headless `run` execution requires a receipt that is
**plan-bound to the exact plan and target** (matching plan digest and target);
an origin-only or mismatched receipt authorizes nothing and fails closed before
any transport. Interactive confirmation remains available. Authenticated (signed)
receipts are not yet implemented; receipts are tamper-evident, not authenticated
(see [Receipt threat model](#receipt-threat-model)).

### Exit codes

| Code | Meaning                                   |
|------|-------------------------------------------|
| `0`  | Completed, no confirmed findings          |
| `1`  | Runtime/configuration failure             |
| `2`  | Authorization denied or invalid           |
| `3`  | Confirmed security finding (injection)    |
| `4`  | Inconclusive assessment                   |

Configuration/usage errors (bad flags, unknown subcommand) exit `1`, distinct
from the `2` used for authorization failures.

### Safety controls

- **Method allowlist** — active requests use only `GET`/`POST`; other methods
  are rejected up front.
- **Payload allowlist** — `--profile` accepts only packaged profile names
  (`safe`), never a path or external file.
- **Rate + budget** — a minimum inter-request interval is enforced and a single
  physical-request budget bounds every attempt (retries included).
- **Redaction & scope** — see [SECURITY.md](SECURITY.md) for the full list
  (no-redirect-follow, header/URL/body redaction, exact-origin scoping).

## Platform capabilities (v0.2.0)

**Reliable vs Kitchen Sink modes** (`plan --mode ...`). Both share the same
authorization, scope, budget, redaction, and confirmation rules — Kitchen Sink
only broadens coverage, it never weakens safety.

- **Reliable** — the default, conservative mode. Resolves the reliable-tier packs
  and confirms only with repeatable, controlled, non-reflected execution evidence
  (repeated attack trials, a clean control per family, and a genuine canary
  execution — never inferred from a single 1/1 result).
- **Kitchen Sink** — broader coverage that resolves the additional packs for
  separately labeled analyst leads. Headless Kitchen Sink still requires a
  plan-bound exact-target receipt.

**Attack packs** (`ai-scan packs list`). Eight digest-verified builtin packs:
`direct-injection`, `indirect-injection`, `rag-isolation`, and `tool-abuse`, each
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
packs, `py.typed`, and version/license metadata via `importlib.resources`,
constructs no transport, needs no authorization, and exits `0` with a concise
health summary (`--json` for machine-readable output).

**Optional isolated worker.** An opt-in local worker runs a bounded JSON request
in a short-lived, hardened container (`Dockerfile.worker`): read-only rootfs,
`--network none`, all capabilities dropped, non-root uid, tmpfs scratch, and
bounded CPU/memory/PID limits. The launcher streams bounded stdin/stdout under a
timeout and exposes only an empty dedicated output directory. It changes no
active-network semantics; egress stays disabled.

## Manual example (interactive authorization)

```bash
ai-scan assess --target https://api.example.com/chat --out report.json
# Prompts:
#   Type exactly: I confirm I am authorized to assess https://api.example.com
```

## Automation example (headless with a receipt)

Create a reusable, target-bound receipt once (interactive), then run headless
in CI or scripts:

```bash
ai-scan authorize \
  --target https://api.example.com/chat \
  --client "Acme Corp" --engagement ENG-42 \
  --expires 2026-12-31 --out auth.json

ai-scan assess --target https://api.example.com/chat \
  --auth-receipt auth.json --non-interactive --out report.json
echo "exit code: $?"   # 0 clean / 3 confirmed / 4 inconclusive
```

Receipts are written `0600` on POSIX and validated on every run: origin must
match exactly, and the receipt must not be expired.

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
- `authorization` — client, engagement, and mode (`interactive`/`receipt`).
  The confirmation phrase itself is **never** stored.
- `request_budget` — bounds and requests actually used.
- `fingerprint` — ranked heuristic candidates (see limitations below).
- `injection` — per-family status and the overall status. A `confirmed`
  finding means the target emitted the canary by *executing* the injected
  instruction (a mere reflection of the prompt is `potential`); a redirect,
  HTTP error, or truncated response is `inconclusive`, never a silent clean
  result. A confirmed finding includes the exact canary as proof.
- `evidence` — redacted request/response records.
- `findings` — confirmed/potential injection findings promoted to the top.

`assess` exits `3` on any confirmed injection, `4` if the injection run was only
inconclusive, otherwise `0`.

## Fingerprint confidence — limitations

The built-in fingerprinter is **heuristic**. It scores a small set of behavioral
markers plus weak header and self-identification signals, and returns `unknown`
unless a family clears both a minimum score and a minimum margin. It is **not**
equivalent to the academic LLMmap pretrained-model inference approach, and its
`heuristic` label reflects that. Treat candidates as leads, not attribution.

## Receipt threat model

Receipt integrity uses canonical JSON + SHA-256. This makes a receipt
**tamper-evident**, not **authenticated**: it reliably detects accidental edits
and corruption, but a party who can run the tool can recompute the digest and
forge a receipt. Receipts are an operator convenience for staying in scope
during authorized engagements — not an access-control mechanism. See
[SECURITY.md](SECURITY.md).

## Roadmap

Not yet implemented:

- Authenticated (signed) receipts and centralized authorization (today's receipts
  are tamper-evident, not authenticated).
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

- [Operator guide](docs/operator-guide.md) — safe authorization, run, replay, and release validation workflow.
- [Pack authoring](docs/pack-authoring.md) — declarative pack requirements and fail-closed validation rules.
- [Evidence and retention](docs/evidence-and-retention.md) — redaction, bundle, replay, and retention guidance.
- [Threat model](docs/threat-model.md) — trust boundaries and release-hardening controls.
- [Changelog](CHANGELOG.md) — release history.

CI (`.github/workflows/ci.yml`) runs on Python 3.11 and 3.12 with least-privilege
permissions, per-job timeouts, and concurrency cancellation. Gates: a deterministic
credential scan, contract tests, the full suite, Ruff, strict Mypy, wheel/sdist
builds, a fresh-wheel package-resource smoke check that also runs `ai-scan doctor`,
a zero-runtime-dependency audit, CycloneDX SBOM generation/validation, a
reproducible-build check (two builds compared by hash), and a hardened
container-worker build/scan. The tag-gated release workflow
(`.github/workflows/package.yml`) re-runs every gate and verifies the tag equals
the project version before uploading the built `dist/*` and SBOM as artifacts; it
does not publish to any index and produces no signing/attestation/provenance. All
GitHub Actions are pinned to immutable commit SHAs.

## License

[PolyForm Shield License 1.0.0](LICENSE) — use and modification are permitted, but providing a product that competes with AI-Scan or an Electric Entropy product using AI-Scan is prohibited.

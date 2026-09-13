# ai-scan

**CLI-only, authorized LLM assessment tool** — behavioral model fingerprinting and
safe, canary-based prompt-injection testing for HTTP(S) LLM endpoints.

> ⚠️ **Authorized use only.** ai-scan sends active requests to a target. It will
> not touch the network until you have either confirmed authorization
> interactively for the current run, or supplied a valid, target-bound
> authorization receipt. Using it against systems you are not explicitly
> authorized to assess may be illegal. You are responsible for staying in scope.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ai-scan --help
```

Requires Python 3.11+. Zero runtime dependencies (standard library only).

## Commands

```text
ai-scan authorize        --target URL --client NAME --engagement ID --expires YYYY-MM-DD --out auth.json
ai-scan fingerprint      --target URL [--method POST] [--request-template FILE] [--auth-receipt FILE]
ai-scan inject           --target URL --goal GOAL [--request-template FILE] [--profile safe] [--auth-receipt FILE]
ai-scan assess           --target URL [--request-template FILE] [--profile safe] [--auth-receipt FILE]
ai-scan plan             --target URL [--mode reliable|kitchen-sink] [--out plan.json]
ai-scan run              --target URL --plan plan.json --auth-receipt FILE --non-interactive [--out report.json]
ai-scan packs            list|validate
ai-scan adapters         list|show NAME
ai-scan report           --file report.json --format json|jsonl|markdown|html|sarif
ai-scan baseline         create|diff
ai-scan bundle           validate|replay
ai-scan validate-receipt --auth-receipt FILE --target URL
```

Active commands (`fingerprint`, `inject`, `assess`, `run`) require authorization. Without
`--auth-receipt` they prompt for a literal confirmation phrase for the normalized
target origin. With `--non-interactive` and no valid receipt, they exit `2`
**before any network traffic is sent**. `assess` uses the conservative
`reliable` mode. A v1 receipt cannot authorize headless `kitchen-sink` execution;
use an interactive authorization path until signed v2 receipts land.

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

## Roadmap (beyond MVP)

- Adapter for an upstream academic/PyTorch LLMmap backend and a current-model
  template registry.
- Expanded, versioned injection payload packs.
- Authenticated (signed) receipts / centralized authorization.
- Additional transports and non-JSON body templating.

Explicitly out of scope for the MVP: REST/web UI, browser automation,
distributed workers, aggressive/destructive payloads, RAG/multimodal injection,
and LLM-as-judge scoring.

### Platform direction

This MVP (report schema v1) is the stable base for a broader **local, CLI-first
AI-pentest platform**. The public contracts are frozen and documented under
[`docs/architecture/`](docs/architecture/):

- [platform-boundaries.md](docs/architecture/platform-boundaries.md) — in/out of scope.
- [mode-contracts.md](docs/architecture/mode-contracts.md) — the `reliable` and
  `kitchen-sink` modes and finding taxonomy.
- [safety-invariants.md](docs/architecture/safety-invariants.md) — non-negotiable invariants.
- [migration-policy.md](docs/architecture/migration-policy.md) — how v1 stays
  compatible as schema v2 / the `run` path arrive.
- ADRs: [0001 CLI-first engine](docs/architecture/adr/0001-cli-first-engine.md),
  [0002 confirmation & confidence](docs/architecture/adr/0002-confirmation-and-confidence.md).

The MVP behavior these docs freeze is guarded by the golden compatibility
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

CI runs Python 3.11 and 3.12, contracts, full tests, Ruff, strict Mypy, wheel/sdist builds, fresh-wheel package-resource smoke checks, a local secret scan, a zero-runtime-dependency audit, SBOM generation, and static container-worker checks. GitHub Actions are pinned to immutable commit SHAs.

## License

[PolyForm Shield License 1.0.0](LICENSE) — use and modification are permitted, but providing a product that competes with AI-Scan or an Electric Entropy product using AI-Scan is prohibited.

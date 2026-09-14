# Non-Negotiable Safety Invariants

> Status: **frozen at Milestone 0**. Every implementation task and review from
> Milestone 1 onward must preserve these invariants.

These are the invariants that make AI-Scan safe to point at authorized targets.
They are properties of the whole system, not of any one module, and they hold
identically in both operating modes (see [mode-contracts.md](mode-contracts.md)).

1. **No network before authorization.** Parse and validate the entire target,
   mode, pack set, capability set, and receipt before creating any adapter or
   transport.
2. **Exact target scope.** Enforce normalized scheme, host, effective port, path
   rules, allowed protocols, and explicit redirect destinations. Never infer
   that subdomains or alternate ports are in scope.
3. **Physical requests are the accounting unit.** Count probes, controls,
   confirmations, retries, redirects when explicitly followed, adapter
   discovery, uploads, reads, cleanup, and tool calls that cause network
   traffic.
4. **One central request broker.** Attack plugins and adapters may not open
   sockets directly.
5. **No mode bypass.** Kitchen Sink mode broadens test selection; it does not
   weaken authorization, redaction, request budgets, origin enforcement,
   evidence honesty, or the definition of `confirmed`.
6. **Intrusive capability gates are separate from mode.** Selecting Kitchen Sink
   must not implicitly authorize writes, uploads, tool invocation, persistence
   checks, high-volume tests, or cross-account tests.
7. **Fail closed.** Transport ambiguity, parse failure, target errors,
   unsupported streaming, truncation, unavailable controls, or missing cleanup
   evidence become `inconclusive`, `blocked`, or `not_tested` — never a clean
   negative.
8. **Reflection is not exploitation.** Verbatim or normalized echo of input is
   never enough for confirmation.
9. **LLM judges are advisory.** A judge may rank leads or explain evidence but
   cannot independently create a confirmed finding.
10. **Evidence is redacted before persistence.** Raw secrets must not enter
    reports, checkpoints, logs, exceptions, HTML, JSONL, or console output.
11. **Reproducibility is explicit.** Store seed, pack digest, adapter/config
    digest, tool version, attempts, controls, and exact redacted request
    sequence.
12. **Pack trust is explicit.** Only packaged, signed, or locally approved
    declarative packs run. No path traversal and no arbitrary code execution.
13. **Safe defaults survive CLI evolution.** GET/POST only by default, redirects
    blocked, low rate, finite timeouts, finite response size, finite
    request/rate/duration/concurrency budgets. (A monetary model-cost ceiling may
    be *declared* on an engagement/receipt but is not yet enforced at runtime.)
14. **All active tests have cleanup semantics.** If a capability can alter target
    state, it must declare a cleanup procedure and verify cleanup; otherwise it
    is blocked.

## How the current MVP relates to these

Milestone 0 changes no runtime behavior. The MVP honors the invariants that are
in scope for a single-origin HTTP tool, with one **partial** case (invariant 1)
called out honestly below and closed by a later milestone.

| Invariant | MVP status | MVP mechanism (frozen by the contract tests) |
|-----------|-----------|----------------------------------------------|
| 1 No network before auth | **full (single-origin scope)** | Authorization (target + receipt) **and** the payload pack (`--profile`) are validated before any `Transport` is constructed; an unauthorized active command, and an authorized command with an invalid profile, both send **zero** requests and exit (`2` / `1` respectively). The Milestone 0 ordering gap (pack validated after transport, `assess` sending 4 fingerprint requests first) was **closed in Milestone 2**. The future whole-plan-before-any-active-object validation (mode/capabilities/engagement/receipt-v2) still lands with the config/authorization milestones. |
| 2 Exact scope | full | `targets.normalize_target` + `same_origin` (scheme+host+effective port, IPv6 canonicalized); receipts bound to exact origin. |
| 3 Physical accounting | full | `RequestController.count` increments per physical attempt, retries included. |
| 4 Central broker | full | All requests flow through `Transport`; engines use injected responders. |
| 7 Fail closed | full | Redirect/HTTP-error/truncation/transport-failure map to `inconclusive` (exit 4). |
| 8 Reflection ≠ exploitation | full | `injection._is_reflection` downgrades echoed canaries to `potential`. |
| 10 Redaction | full | Header/URL/`Location`/body redaction before evidence is stored. |
| 12 Pack trust | full | `ALLOWED_PROFILES` allowlist; no path traversal, no code execution. |
| 13 Safe defaults | full | `ACTIVE_METHODS={GET,POST}`, redirects never followed, enforced rate + timeout + response cap + request budget. |

Invariants 5–6, 9, 11, and 14 become fully exercised as later milestones add
modes, judges, reproducibility metadata, and intrusive capabilities. They are
recorded here now so no later change can silently violate them.

### Known gaps vs. the future invariants (to close in later milestones)

- **Invariant 1 — complete offline validation before transport construction.**
  The future engine parses and validates the *entire* plan (target, mode, pack
  set, capability set, receipt) before creating any adapter or transport.
  Milestone 2 introduces strict configuration/schema validation of offline plans
  and **closed the Milestone 0 compatibility-command ordering gap**. Current,
  exact behavior — frozen by contract tests:
  - **Unauthorized active commands send zero requests.** `fingerprint`,
    `inject`, and `assess` with `--non-interactive` and no valid receipt exit
    `2` before any transport is constructed (test:
    `test_no_network_before_authorization`).
  - **Authorized invalid-profile runs send zero requests for both commands.**
    `inject --profile invalid` **and** `assess --profile invalid` now validate
    the pack before constructing the transport, so both exit `1` with **0**
    requests sent (test: `test_invalid_profile_rejected_before_any_request`).
  - **Remaining (future) scope:** whole-plan validation of mode, capabilities,
    engagement, and signed receipt v2 before any active object is constructed —
    delivered by the config/authorization milestones. Single-origin
    compatibility commands already validate their full offline input (target,
    receipt, profile) before any transport.
- **Invariants 5–6, 9, 11, 14** are not yet exercised because modes, judges,
  reproducibility metadata, and intrusive capabilities do not exist in the MVP;
  they are frozen here as forward constraints.

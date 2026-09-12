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
    cost/request budgets.
14. **All active tests have cleanup semantics.** If a capability can alter target
    state, it must declare a cleanup procedure and verify cleanup; otherwise it
    is blocked.

## How the current MVP relates to these

Milestone 0 changes no runtime behavior. The MVP honors the invariants that are
in scope for a single-origin HTTP tool, with one **partial** case (invariant 1)
called out honestly below and closed by a later milestone.

| Invariant | MVP status | MVP mechanism (frozen by the contract tests) |
|-----------|-----------|----------------------------------------------|
| 1 No network before auth | **partial** | Authorization (target + receipt) is validated before any `Transport` is constructed, and an unauthorized active command sends **zero** requests. **Gap:** the payload pack (`--profile`) is validated only when the injection phase reaches it — *after* the transport is built and, for `assess`, *after* the fingerprint phase has already sent requests. So pack validity is **not** guaranteed before all traffic. See "Known gaps" below. |
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
  set, capability set, receipt) before creating any adapter or transport
  (Milestone 2 introduces strict configuration/schema validation of a complete
  offline plan). The current MVP behaves as follows — stated exactly, and frozen
  by contract tests:
  - **Unauthorized active commands send zero requests.** `fingerprint`,
    `inject`, and `assess` with `--non-interactive` and no valid receipt exit
    `2` before any transport is constructed (test:
    `test_no_network_before_authorization`).
  - **Authorized `inject --profile invalid` rejects before any traffic.** The
    injection phase loads the pack first, so an unknown profile exits `1` with
    **0** requests sent.
  - **Authorized `assess --profile invalid` performs its 4 fingerprint requests
    first**, then reaches profile validation, then exits `1`. So **4** requests
    are sent before the invalid profile is rejected (test:
    `test_invalid_profile_ordering_is_characterized`).
  - **Therefore the MVP does *not* guarantee pack validation before all
    traffic.** Authorization is enforced before any network I/O, but pack
    validity is not. **Milestone 2 must close this ordering gap** by validating
    the complete offline plan (including the pack) before constructing any
    transport. Milestone 0 documents this gap and does **not** change runtime
    behavior.
- **Invariants 5–6, 9, 11, 14** are not yet exercised because modes, judges,
  reproducibility metadata, and intrusive capabilities do not exist in the MVP;
  they are frozen here as forward constraints.

# Platform Boundaries

> Status: **frozen at Milestone 0** (contracts only; no runtime behavior change).

AI-Scan is evolving from the CLI-only MVP (report schema v1) into a local,
CLI-first AI-application pentest platform. This document freezes the product
boundary so later milestones cannot quietly expand scope.

## In scope

AI-Scan assesses AI-enabled applications and their trust boundaries:

1. Behavioral model/provider fingerprinting and open-set rejection.
2. Direct prompt injection and jailbreak resistance.
3. System-prompt and hidden-context disclosure.
4. Indirect prompt injection through retrieved or uploaded content.
5. RAG authorization, cross-tenant isolation, poisoning, provenance, and
   citation integrity.
6. Agent/tool/MCP argument manipulation, confused-deputy behavior, excessive
   agency, and approval bypass.
7. Cross-user/session/tenant leakage and authorization boundary checks.
8. Agent memory poisoning, persistence, and stale-state behavior.
9. Multi-agent trust-boundary attacks.
10. Insecure output handling and rendering indicators.
11. Unicode, encoding, multilingual, and multimodal injection.
12. Denial-of-wallet and bounded resource-amplification measurements.
13. Model-router, fallback, moderation, and policy inconsistency.
14. Plugin, MCP server, model, and prompt supply-chain posture checks.
15. Repeatable baselines, diffs, and CI regression gates.

## Out of scope for the first platform implementation

- General network, cloud, identity, or host exploitation.
- Autonomous conventional pentesting.
- Destructive actions, real credential extraction, persistence on targets, or
  production denial of service.
- A hosted SaaS control plane, browser dashboard, RBAC, SSO, billing, or
  distributed workers.
- Executing arbitrary third-party Python from attack packs.
- Treating model self-identification or an LLM judge as authoritative proof.

These can be proposed later as separately threat-modeled extensions. **The local
engine must stabilize first.**

## Relationship to the current MVP (v0.1.0)

The current shipped tool (commit `945c344`, report schema v1) is preserved as a
compatibility surface:

- The five subcommands (`authorize`, `fingerprint`, `inject`, `assess`,
  `validate-receipt`) and their exit codes remain stable.
- Report schema v1 is frozen; see [migration-policy.md](migration-policy.md).
- The golden compatibility contract in `tests/contracts/` characterizes this
  behavior and must keep passing through the refactor.

See also: [mode-contracts.md](mode-contracts.md),
[safety-invariants.md](safety-invariants.md),
[adr/0001-cli-first-engine.md](adr/0001-cli-first-engine.md),
[adr/0002-confirmation-and-confidence.md](adr/0002-confirmation-and-confidence.md).

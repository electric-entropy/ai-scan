# ADR 0001: CLI-first local engine

- Status: Accepted (Milestone 0)
- Date: 2026-09-11
- Deciders: Electric Entropy

## Context

AI-Scan must grow from a single-file CLI MVP into a broad AI-application pentest
platform covering fingerprinting, direct/indirect injection, RAG, agent/tool,
isolation, output-handling, and supply-chain testing. There is pressure to jump
straight to a hosted control plane (API service, database, queue, workers, web
triage UI, RBAC/SSO). That path multiplies the attack surface and operational
burden before the core assessment contracts (plan, adapter, attack, validator,
evidence, replay) have stabilized.

## Decision

The first platform implementation is a **local, CLI-first engine**. All
capabilities are delivered as a library plus CLI, driven by offline-validated
plans and a single central request broker. A hosted SaaS control plane, browser
dashboard, RBAC/SSO, billing, and distributed workers are **explicitly out of
scope** for this implementation and become a separate plan and threat model only
after the local contracts survive at least two complete attack-family
implementations.

The delivery sequence stops the first tranche at **v0.2 "Reliable Core"**
(Milestones 0–10, 18–19). Optional local isolated workers (Milestone 20) are the
only concession to out-of-process execution, and remain local.

## Consequences

- **Positive:** minimal trust surface; every run is reproducible from local
  inputs; safety invariants are enforced in one process; the schemas that later
  services would depend on are proven against real attack families first.
- **Positive:** the shipped MVP (v0.1.0, report schema v1) remains a stable,
  testable compatibility surface throughout the refactor (see
  [../migration-policy.md](../migration-policy.md)).
- **Negative / accepted:** no multi-tenant orchestration, no shared web UI, and
  no horizontal scaling in this tranche. These are deferred deliberately, not
  forgotten.
- **Constraint:** attack packs are declarative and allowlisted; the engine never
  executes arbitrary third-party Python (safety invariant 12).

## Alternatives considered

- **Service-first (API + DB + workers now):** rejected — expands attack surface
  and couples storage/queue schemas to contracts that have not yet survived real
  attack families.
- **Keep the MVP as-is:** rejected — cannot host the planned breadth (RAG, agent,
  multimodal) without shared plan/adapter/validator/evidence abstractions.

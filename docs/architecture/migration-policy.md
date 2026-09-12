# Migration & Versioning Policy

> Status: **frozen at Milestone 0**.

This policy governs how the platform refactor evolves the public contracts
without breaking the shipped MVP.

## Baseline

- The current MVP contract is **report schema v1**, pinned at commit
  `945c344cf940d4b966fff03ef2dac46e49faa7c5` (`v0.1.0`).
- Its behavior is characterized by the golden compatibility contract in
  `tests/contracts/test_mvp_compatibility.py` and the four outcome fixtures in
  `tests/contracts/golden/`: `mvp-report-confirmed-v1.json`,
  `mvp-report-clean-v1.json`, `mvp-report-reflection-v1.json`, and
  `mvp-report-inconclusive-v1.json`. These tests must keep passing unchanged
  through the refactor.

## Versioning rules

1. **Report v1 compatibility rule (single, coherent definition).** The v1 report
   contract is the **frozen required surface** captured by the four outcome
   fixtures listed above. A conforming v1 report must contain every key in the
   applicable fixture, at the same path, with the same type and
   the same value for every non-volatile leaf (volatile leaves — origins,
   canaries, timestamps, and target-emitted `Date`/`Server` headers — are
   normalized to sentinels before comparison). Removing, renaming, retyping, or
   changing the meaning of any field on that frozen surface is a **breaking
   change** and is not allowed within v1.

   *Additive* evolution is permitted and does **not** break the contract: a
   producer may add **new optional keys** outside the frozen surface, and
   consumers must ignore unknown keys. The golden check therefore asserts the
   golden is a **structural subset** of the report (every frozen path matches;
   extra optional keys are tolerated; list lengths are exact). This is the one
   rule — there is no separate "exact equality" requirement that would conflict
   with additive optional fields. Any field a future producer cannot populate
   without inventing evidence is omitted, not faked (see rule 7); it is not
   added to the frozen surface.
2. **New schemas under new commands.** Finding/evidence **schema v2** (the richer
   confidence taxonomy, evidence graph, controls, reproducibility metadata) is
   introduced under the new `run` path — never by mutating v1. Compatibility
   commands (`assess`, `fingerprint`, `inject`) keep emitting schema v1.
3. **Compatibility window.** Compatibility commands and report v1 remain
   available through **at least one minor release** after `run`/schema v2 ship,
   with documented deprecation before removal in a future major version.
4. **Receipts.** Receipt **v1** continues to authorize existing safe,
   single-origin commands. **Signed receipt v2** is required for Kitchen Sink
   headless operation and for every intrusive capability. Receipt v1 is never
   silently upgraded.
5. **Facades over moves.** New packages are introduced behind compatibility
   facades (`models.py`, `transport.py`, `fingerprint.py`, `injection.py`,
   `reporting.py`) so imports and behavior stay stable while internals move.
   Facades are removed only in a future major version after documented
   deprecation.
6. **Exit codes.** `0`–`4` are stable and frozen. Exit code `5` (analyst-leads
   only) must not be assigned until migration tests and release notes establish
   it as a new public contract; until then default console behavior returns `0`.
7. **No invented evidence.** An offline v1→v2 report converter is provided only
   when conversion cannot invent missing controls/evidence; otherwise the
   affected fields are explicitly labeled unavailable rather than fabricated.

## Ordering guarantees during the refactor

1. Preserve/tag the v0.1.0 contract at `945c344` before structural changes.
2. Add golden compatibility tests **before** moving modules (this milestone).
3. Introduce new packages behind facades.
4. *(future)* Make `assess` compile a true Reliable-mode plan internally under
   schema v2, while the compatibility surface keeps emitting v1 with unchanged
   flags and exit codes. Until that milestone, `assess` runs legacy v1 semantics
   (single response per case, no Reliable controls/retries).
5. Keep reading receipt v1 for existing safe single-origin commands.
6. Keep report schema v1 for compatibility commands; use finding/evidence schema
   v2 only on the new `run` path.
7. Remove facades only in a future major version after documented deprecation.

## What Milestone 0 changed

- **Added** (no runtime behavior change): this policy, the architecture docs,
  the two ADRs, and the golden compatibility contract with four outcome fixtures.
- **Did not change:** any CLI behavior, exit code, report field, authorization
  flow, reflection handling, `safe` profile, IPv6/origin enforcement, or receipt
  v1 compatibility.

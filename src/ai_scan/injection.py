"""Safe, canary-based prompt-injection engine.

Every probe is non-destructive: it tries only to make the target emit a unique,
synthetic canary token under a family-specific condition. A finding is
**confirmed** only when that exact canary appears in the response — a
deterministic, low-false-positive success condition. Payloads never request
real secrets, credentials, destructive actions, or third-party data.

Status taxonomy:

* ``confirmed`` — the unique canary was echoed under the success condition.
* ``potential`` — the response acknowledged/complied in form but the canary was
  not observed (worth manual review).
* ``not_observed`` — the target resisted; no injection signal.
* ``inconclusive`` — the case could not be evaluated (e.g. transport error).
"""

from __future__ import annotations

import enum
import json
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib import resources
from typing import TYPE_CHECKING, Any

from ai_scan.core.accounting import PhysicalCounter
from ai_scan.core.accounting import delta as ledger_delta
from ai_scan.core.accounting import require as require_ledger
from ai_scan.core.accounting import snapshot as snapshot_ledger
from ai_scan.core.models import DeterminismClass, FindingStatus, PackTrust
from ai_scan.packs import resolve_packs
from ai_scan.validation import (
    ComplianceHeuristicValidator,
    Evidence,
    ExactCanaryValidator,
    GatingContext,
    Validator,
    classify,
)

if TYPE_CHECKING:
    from ai_scan.packs import Pack, TrialPolicy

_CANARY_PREFIX = "AISCAN-"


class InjectionStatus(enum.StrEnum):
    """Outcome of an injection case or the overall run.

    The full seven-state confidence vocabulary is preserved on the v2 runner path
    (``likely``/``suspected`` are never collapsed into ``potential``). ``POTENTIAL``
    remains only as the legacy 4-state report surface, produced by an explicit
    adapter boundary (:func:`legacy_status`), never by the confirmation core.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SUSPECTED = "suspected"
    POTENTIAL = "potential"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    NOT_TESTED = "not_tested"


class InjectionError(Exception):
    """Raised when a payload pack cannot be loaded or is malformed."""


@dataclass(frozen=True)
class PayloadFamily:
    """A named group of payload templates."""

    name: str
    description: str
    templates: list[str]


@dataclass(frozen=True)
class PayloadPack:
    """A versioned collection of payload families loaded from package data."""

    version: str
    description: str
    families: list[PayloadFamily]


@dataclass(frozen=True)
class InjectionCase:
    """A single rendered probe about to be sent."""

    family: str
    template: str
    rendered_prompt: str


@dataclass(frozen=True)
class ExchangeOutcome:
    """The observable result of sending one injection case.

    Carries the transport status so classification can distinguish a genuine
    negative from an outcome that could not be evaluated (redirect, HTTP error,
    truncation, or transport failure).

    Attributes:
        body: Response body text (already redacted upstream).
        status: HTTP status code (200 by default).
        redirected: Whether the response was a redirect (never followed).
        truncated: Whether the response body was truncated at the size bound.
        transport_ok: False if the request could not be completed at all.
        attempts: Physical attempts made for this case (>= 1), retries included.
        known_secrets: Reflected/known secret values observed for this exchange,
            propagated so persisted state (e.g. checkpoint proof) is redacted.
    """

    body: str
    status: int = 200
    redirected: bool = False
    truncated: bool = False
    transport_ok: bool = True
    attempts: int = 1
    known_secrets: frozenset[str] = field(default_factory=frozenset)
    semantic: dict[str, Any] | None = None


@dataclass
class InjectionFinding:
    """The evaluated result of one injection case.

    ``attack_trials``/``successes`` are the aggregated repeatability counts that
    gated the status, carried so an offline replay can re-verify confirmation at
    the real plan thresholds (never inferred). ``evidence`` holds every physical
    trial outcome the status was derived from, in send order, so checkpoints and
    bundles persist per-trial evidence rather than a single representative.
    """

    family: str
    status: InjectionStatus
    prompt: str
    proof: str | None = None
    attack_trials: int = 1
    successes: int = 0
    evidence: tuple[ExchangeOutcome, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "status": self.status.value,
            "prompt": self.prompt,
            "proof": self.proof,
        }


@dataclass
class InjectionResult:
    """Aggregate outcome of an injection run."""

    status: InjectionStatus
    findings: list[InjectionFinding]
    request_count: int
    canary: str
    goal: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "goal": self.goal,
            "request_count": self.request_count,
            "findings": [f.to_dict() for f in self.findings],
        }


Responder = Callable[[InjectionCase], ExchangeOutcome]

# Explicit allowlist of packaged profiles. `--profile` resolves only to one of
# these names — never an absolute path, traversal, or external file.
ALLOWED_PROFILES = frozenset({"safe"})


def generate_canary() -> str:
    """Return a unique synthetic canary token for a single run."""
    return f"{_CANARY_PREFIX}{secrets.token_hex(8).upper()}"


def load_payloads(profile: str = "safe") -> PayloadPack:
    """Load a versioned payload pack from package data.

    ``profile`` must be an exact member of :data:`ALLOWED_PROFILES`; anything
    else (a path, a traversal sequence, an unknown name) is rejected before any
    file access, so an operator cannot load an arbitrary external payload pack.

    Raises:
        InjectionError: If the profile is not allowlisted or the data is
            malformed.
    """
    if profile not in ALLOWED_PROFILES:
        # Sanitize the (untrusted) profile value before it enters the exception
        # message, so a secret-like profile cannot leak through error output.
        from ai_scan.transport.redaction import scrub_text

        safe_profile = scrub_text(profile)
        raise InjectionError(
            f"Unknown payload profile {safe_profile!r}; allowed: "
            f"{', '.join(sorted(ALLOWED_PROFILES))}."
        )
    resource = resources.files("ai_scan.payloads").joinpath(f"{profile}.json")
    try:
        raw = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        raise InjectionError(f"Unknown payload profile {profile!r}.") from exc

    try:
        data = json.loads(raw)
        families = [
            PayloadFamily(
                name=str(fam["name"]),
                description=str(fam.get("description", "")),
                templates=[str(t) for t in fam["templates"]],
            )
            for fam in data["families"]
        ]
        return PayloadPack(
            version=str(data["version"]),
            description=str(data.get("description", "")),
            families=families,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InjectionError(f"Malformed payload pack {profile!r}.") from exc


def payloads_from_pack(pack: Pack) -> PayloadPack:
    """Flatten a declarative :class:`~ai_scan.packs.Pack` into a runnable pack.

    Only the attack families/templates are projected into the execution pack;
    the declarative pack's controls, validators, and trial policy are carried on
    the :class:`~ai_scan.packs.Pack` itself for the validation/confidence engine.
    """
    return PayloadPack(
        version=f"{pack.id}-{pack.version}",
        description=pack.description,
        families=[
            PayloadFamily(name=fam.name, description=fam.description, templates=list(fam.templates))
            for fam in pack.families
        ],
    )


def resolve_injection_payloads(
    mode: str,
    *,
    trust: frozenset[PackTrust] = frozenset({PackTrust.BUILTIN}),
    capabilities: frozenset[str] = frozenset(),
) -> PayloadPack:
    """Resolve packs for ``mode`` via the registry and merge them into one pack.

    Deterministic and offline: packs come back in registry order and their
    families are concatenated (first occurrence of a family name wins), so the
    same inputs always produce the same runnable pack.
    """
    packs = resolve_packs(mode, trust=trust, capabilities=capabilities)
    families: list[PayloadFamily] = []
    seen: set[str] = set()
    for pack in packs:
        for fam in pack.families:
            if fam.name in seen:
                continue
            seen.add(fam.name)
            families.append(
                PayloadFamily(
                    name=fam.name,
                    description=fam.description,
                    templates=list(fam.templates),
                )
            )
    version = "+".join(f"{pack.id}-{pack.version}" for pack in packs)
    return PayloadPack(
        version=version,
        description=f"Resolved built-in packs for mode {mode!r}.",
        families=families,
    )


def run_injection(
    pack: PayloadPack,
    responder: Responder,
    *,
    canary: str,
    goal: str,
    max_cases: int | None = None,
    physical_request_count: PhysicalCounter | None = None,
) -> InjectionResult:
    """Run each payload family against the target, confirming via the canary.

    Args:
        pack: The payload pack to run.
        responder: Callable mapping an :class:`InjectionCase` to an
            :class:`ExchangeOutcome` (wired to the transport by the CLI;
            injected in tests).
        canary: The unique canary token to look for in responses.
        goal: Free-text description of the operator's stated goal (recorded).
        max_cases: Optional hard cap on the number of logical cases attempted.
        physical_request_count: Required trusted request-controller/broker ledger.
            ``request_count`` is derived exclusively from monotonic snapshots around
            each exchange; responder-controlled attempt metadata is ignored.

    Returns:
        An :class:`InjectionResult`. ``request_count`` sums physical attempts
        (retries included) taken from the trusted ledger. Overall status is the most
        severe case status observed
        (confirmed > potential > inconclusive > not_observed).
    """
    require_ledger(physical_request_count)
    findings: list[InjectionFinding] = []
    request_count = 0
    cases_run = 0

    for family in pack.families:
        for template in family.templates:
            if max_cases is not None and cases_run >= max_cases:
                break
            cases_run += 1
            case = InjectionCase(
                family=family.name,
                template=template,
                rendered_prompt=template.replace("{canary}", canary),
            )

            before = snapshot_ledger(physical_request_count)
            try:
                outcome = responder(case)
            except BaseException as exc:
                consumed = ledger_delta(before, physical_request_count)
                request_count += consumed
                if not isinstance(exc, Exception):
                    raise
                # A structured denial (scope block / budget exhaustion, carrying
                # an ``outcome``) is terminal for the run and must reach the
                # caller; only ordinary failures degrade to an inconclusive case.
                if getattr(exc, "outcome", None) is not None:
                    raise
                # Exception attributes are responder-controlled and are never
                # canonical physical-request facts at this engine boundary. Any
                # physical requests the failed exchange truly consumed are read
                # from the trusted ledger, so a failure is neither under- nor
                # over-counted (and a spoofed ``exc.attempts`` cannot inflate it).
                findings.append(
                    InjectionFinding(
                        family=family.name,
                        status=InjectionStatus.INCONCLUSIVE,
                        prompt=case.rendered_prompt,
                        proof=None,
                    )
                )
                continue

            consumed = ledger_delta(before, physical_request_count)
            request_count += consumed
            if consumed == 0:
                outcome = ExchangeOutcome(body="", transport_ok=False, attempts=0)
            status, proof = _evaluate(outcome, canary, case.rendered_prompt)
            findings.append(
                InjectionFinding(
                    family=family.name,
                    status=status,
                    prompt=case.rendered_prompt,
                    proof=proof,
                )
            )
        if max_cases is not None and cases_run >= max_cases:
            break

    return InjectionResult(
        status=_aggregate(findings),
        findings=findings,
        request_count=request_count,
        canary=canary,
        goal=goal,
    )


def _select_validators(methods: frozenset[DeterminismClass]) -> list[Validator]:
    """Build exactly the validators a pack declares (offline, deterministic order).

    A validator is included only when its determinism class is declared — so a
    pack that does not declare ``deterministic`` gets no exact-canary execution
    validator and therefore cannot confirm through a validator it never asked
    for. ``statistical`` and ``judge`` need runtime inputs (an exemplar or a
    model verdict) that the offline direct-injection path cannot supply, so they
    are handled fail-closed: declaring them contributes no signal here rather
    than being silently substituted by a deterministic (confirming) validator.
    """
    validators: list[Validator] = []
    if DeterminismClass.DETERMINISTIC in methods:
        validators.append(ExactCanaryValidator())
    if DeterminismClass.HEURISTIC in methods:
        validators.append(ComplianceHeuristicValidator())
    return validators


def run_injection_pack(
    pack: Pack,
    responder: Responder,
    *,
    canary: str,
    goal: str,
    max_cases: int | None = None,
    physical_request_count: PhysicalCounter | None = None,
) -> InjectionResult:
    """Run a declarative pack, threading its metadata into classification.

    Unlike :func:`run_injection` (which only sees flattened families), this
    consumes the pack's declared ``validators`` (which signals to build),
    ``controls`` (a benign baseline whose canary emission blocks confirmation),
    ``trial_policy`` (repeatability thresholds), and ``side_effects`` (whether a
    state-change corroboration is required) — all fed into the single
    confidence predicate via :class:`~ai_scan.validation.GatingContext`.
    """
    require_ledger(physical_request_count)
    validators = _select_validators(pack.validators)
    trial = pack.trial_policy
    findings: list[InjectionFinding] = []
    request_count = 0
    cases_run = 0

    def send(case: InjectionCase) -> ExchangeOutcome:
        nonlocal request_count
        remaining = pack.max_physical_requests - request_count
        before = snapshot_ledger(physical_request_count)
        try:
            outcome = responder(case)
        except BaseException as exc:
            consumed = ledger_delta(
                before, physical_request_count, remaining=remaining
            )
            request_count += consumed
            if not isinstance(exc, Exception):
                raise
            if getattr(exc, "outcome", None) is not None:
                raise
            return ExchangeOutcome(body="", transport_ok=False, attempts=consumed)
        consumed = ledger_delta(before, physical_request_count, remaining=remaining)
        request_count += consumed
        if consumed == 0:
            return ExchangeOutcome(body="", transport_ok=False, attempts=0)
        return ExchangeOutcome(
            body=outcome.body,
            status=outcome.status,
            redirected=outcome.redirected,
            truncated=outcome.truncated,
            transport_ok=outcome.transport_ok,
            attempts=consumed,
            known_secrets=outcome.known_secrets,
            semantic=outcome.semantic,
        )

    for family in pack.families:
        # Controls run first, each for its full declared trial count: a control
        # that emits the canary poisons the baseline, and a family confirms only
        # against a fully usable, non-emitting matched control.
        control: str | None = None
        for template in family.controls:
            case = InjectionCase(family=family.name, template=template, rendered_prompt=template)
            outcomes = [send(case) for _ in range(trial.min_control_trials)]
            result = control_result(
                outcomes,
                canary,
                trial.min_control_trials,
            )
            control = merge_control_results(control, result)

        for template in family.templates:
            if max_cases is not None and cases_run >= max_cases:
                break
            cases_run += 1
            rendered = template.replace("{canary}", canary)
            case = InjectionCase(family=family.name, template=template, rendered_prompt=rendered)
            outcomes = [send(case) for _ in range(trial.min_attack_trials)]
            evidence = tuple(outcomes)
            status, proof, trials, successes, _rep = evaluate_trials(
                evidence, canary, rendered, validators,
                control_succeeded=control == CONTROL_EMITTED,
                matched_clean_control=control == CONTROL_CLEAN,
                min_attack_trials=trial.min_attack_trials,
                min_successes=trial.min_successes,
                requires_state_change=pack.side_effects,
            )
            findings.append(
                InjectionFinding(
                    family.name, legacy_status(status), rendered, proof,
                    attack_trials=trials, successes=successes, evidence=evidence,
                )
            )
        if max_cases is not None and cases_run >= max_cases:
            break

    return InjectionResult(
        status=_aggregate(findings),
        findings=findings,
        request_count=request_count,
        canary=canary,
        goal=goal,
    )


# A responder failure is a real, counted, unusable trial — never a skipped one.
_FAILED = ExchangeOutcome(body="", transport_ok=False)

# Per-family control coverage: a matched control ran fully usable and clean, a
# usable control emitted the success token (false-positive baseline), or control
# coverage is incomplete. ``emitted`` dominates ``clean`` dominates ``gap``.
CONTROL_CLEAN = "clean"
CONTROL_EMITTED = "emitted"
CONTROL_GAP = "gap"
_CONTROL_PRIORITY = {CONTROL_EMITTED: 2, CONTROL_CLEAN: 1, CONTROL_GAP: 0}


def physical_attempts(outcome: ExchangeOutcome) -> int:
    """The physical attempts one trial consumed (retries included, at least one)."""
    attempts = outcome.attempts
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        raise ValueError("trial attempts must be an integer")
    if attempts < 1:
        raise ValueError("trial attempts must be positive")
    return attempts


def control_result(
    outcomes: Sequence[ExchangeOutcome], token: str, min_control_trials: int
) -> str:
    """Classify one control case from *all* of its physical trial outcomes.

    Any usable trial carrying ``token`` makes the control ``emitted``. Otherwise
    the control is ``clean`` only when at least ``min_control_trials`` trials were
    usable; anything less is a coverage ``gap``.
    """
    usable = [o for o in outcomes if _usable(o)]
    if any(token and token in o.body for o in usable):
        return CONTROL_EMITTED
    if len(usable) >= min_control_trials:
        return CONTROL_CLEAN
    return CONTROL_GAP


def merge_control_results(previous: str | None, new: str) -> str:
    """Combine control coverage across a family's control cases (emitted wins)."""
    if previous is None:
        return new
    return max(previous, new, key=lambda r: _CONTROL_PRIORITY[r])


def _usable(outcome: ExchangeOutcome) -> bool:
    return (
        outcome.transport_ok
        and not outcome.redirected
        and outcome.status < 400
        and not outcome.truncated
    )


# FindingStatus (the one central vocabulary) → the injection engine's status.
# 1:1 — the seven-state taxonomy is preserved (no likely/suspected collapse).
_FINDING_TO_INJECTION = {
    FindingStatus.CONFIRMED: InjectionStatus.CONFIRMED,
    FindingStatus.LIKELY: InjectionStatus.LIKELY,
    FindingStatus.SUSPECTED: InjectionStatus.SUSPECTED,
    FindingStatus.NOT_OBSERVED: InjectionStatus.NOT_OBSERVED,
    FindingStatus.INCONCLUSIVE: InjectionStatus.INCONCLUSIVE,
    FindingStatus.BLOCKED: InjectionStatus.BLOCKED,
    FindingStatus.NOT_TESTED: InjectionStatus.NOT_TESTED,
}

# Legacy 4-state report boundary: collapse the fine-grained speculative states
# into ``potential`` only where a legacy report surface requires it. This adapter
# lives outside the confirmation core.
_LEGACY_STATUS = {
    InjectionStatus.LIKELY: InjectionStatus.POTENTIAL,
    InjectionStatus.SUSPECTED: InjectionStatus.POTENTIAL,
    InjectionStatus.BLOCKED: InjectionStatus.INCONCLUSIVE,
    InjectionStatus.NOT_TESTED: InjectionStatus.NOT_OBSERVED,
}


def legacy_status(status: InjectionStatus) -> InjectionStatus:
    """Map a 7-state status onto the legacy 4-state report vocabulary."""
    return _LEGACY_STATUS.get(status, status)


def _evaluate(
    outcome: ExchangeOutcome, canary: str, rendered_prompt: str
) -> tuple[InjectionStatus, str | None]:
    """Classify one exchange through the central confidence engine.

    This is a thin compatibility shim: it builds :class:`~ai_scan.validation.Evidence`,
    runs the deterministic-canary and compliance-heuristic validators, and maps
    the single confirmation predicate's :class:`~ai_scan.core.models.FindingStatus`
    back onto the injection engine's status. There is no confirmation logic here.
    """
    evaluable = _usable(outcome)
    evidence = Evidence(
        response=outcome.body, canary=canary, prompt=rendered_prompt, evaluable=evaluable
    )
    signals = [
        ExactCanaryValidator().validate(evidence),
        ComplianceHeuristicValidator().validate(evidence),
    ]
    result = classify(signals, GatingContext(), evaluable=evaluable)
    # Legacy single-shot path stays on the 4-state report vocabulary.
    status = legacy_status(_FINDING_TO_INJECTION[result.status])
    proof = (
        _proof_snippet(outcome.body, canary, outcome.known_secrets)
        if status is InjectionStatus.CONFIRMED
        else None
    )
    return status, proof


def _evaluate_pack_case(
    outcome: ExchangeOutcome,
    canary: str,
    rendered_prompt: str,
    validators: list[Validator],
    *,
    control_succeeded: bool,
    matched_clean_control: bool,
    trial: TrialPolicy,
    requires_state_change: bool,
) -> tuple[InjectionStatus, str | None]:
    """Classify one attack case with pack-declared validators + gating context.

    ``matched_clean_control`` must be supplied by the caller: a run with no
    usable clean control cannot confirm (``control_succeeded=False`` alone is not
    enough — it also means "no matched control ran").
    """
    evaluable = _usable(outcome)
    evidence = Evidence(
        response=outcome.body, canary=canary, prompt=rendered_prompt, evaluable=evaluable
    )
    signals = [validator.validate(evidence) for validator in validators]
    execution_succeeded = any(
        s.validator_id == "exact_canary" and s.fired and not s.reflection for s in signals
    )
    context = GatingContext(
        control_succeeded=control_succeeded,
        matched_clean_control=matched_clean_control,
        attack_trials=1,
        successes=1 if execution_succeeded else 0,
        min_attack_trials=trial.min_attack_trials,
        min_successes=trial.min_successes,
        requires_state_change=requires_state_change,
    )
    result = classify(signals, context, evaluable=evaluable)
    # Legacy pack path stays on the 4-state report vocabulary.
    status = legacy_status(_FINDING_TO_INJECTION[result.status])
    proof = (
        _proof_snippet(outcome.body, canary, outcome.known_secrets)
        if status is InjectionStatus.CONFIRMED
        else None
    )
    return status, proof


def classify_record(
    outcome: ExchangeOutcome,
    canary: str,
    rendered_prompt: str,
    validators: list[Validator],
    *,
    control_succeeded: bool,
    matched_clean_control: bool,
    attack_trials: int,
    successes: int,
    min_attack_trials: int,
    min_successes: int,
    requires_state_change: bool,
) -> tuple[InjectionStatus, str | None]:
    """Re-derive one record's status using *given* repeatability counts.

    Used by replay to re-verify a stored finding at the real plan thresholds
    (counts come from the bundle, never inferred). Invalid counts (e.g. more
    successes than trials) raise ``ValueError`` so the caller can fail closed.
    """
    if not _usable(outcome):
        return _FINDING_TO_INJECTION[FindingStatus.INCONCLUSIVE], None
    evidence = Evidence(
        response=outcome.body, canary=canary, prompt=rendered_prompt, evaluable=True
    )
    signals = [validator.validate(evidence) for validator in validators]
    context = GatingContext(
        control_succeeded=control_succeeded,
        matched_clean_control=matched_clean_control,
        attack_trials=attack_trials,
        successes=successes,
        min_attack_trials=min_attack_trials,
        min_successes=min_successes,
        requires_state_change=requires_state_change,
    )
    result = classify(signals, context, evaluable=True)
    status = _FINDING_TO_INJECTION[result.status]
    proof = (
        _proof_snippet(outcome.body, canary, outcome.known_secrets)
        if status is InjectionStatus.CONFIRMED
        else None
    )
    return status, proof


def _trial_executed(outcome: ExchangeOutcome, canary: str, rendered_prompt: str,
                    validators: list[Validator]) -> tuple[bool, list[Any]]:
    """Whether one usable trial shows deterministic canary *execution* (not reflection)."""
    evidence = Evidence(
        response=outcome.body, canary=canary, prompt=rendered_prompt, evaluable=True
    )
    signals = [validator.validate(evidence) for validator in validators]
    executed = any(
        s.validator_id == "exact_canary" and s.fired and not s.reflection for s in signals
    )
    return executed, signals


def evaluate_trials(
    outcomes: Sequence[ExchangeOutcome],
    canary: str,
    rendered_prompt: str,
    validators: list[Validator],
    *,
    control_succeeded: bool,
    matched_clean_control: bool,
    min_attack_trials: int,
    min_successes: int,
    requires_state_change: bool,
) -> tuple[InjectionStatus, str | None, int, int, ExchangeOutcome | None]:
    """Aggregate repeated attack trials into one gated classification.

    Only *usable* trials are evidence. Confirmation requires enough usable trials
    (repeatability), enough executions, a matched clean control, and — when the
    pack has side effects — corroborated state change. A single execution can
    never confirm under the Reliable 3/2/2 contract.

    Returns ``(status, proof, usable_trials, successes, representative_outcome)``;
    the representative is an executing trial when one exists (so the persisted
    evidence backs a confirmed status), else the first usable trial.
    """
    usable: list[tuple[ExchangeOutcome, list[Any]]] = []
    for outcome in outcomes:
        if not _usable(outcome):
            continue
        _executed, signals = _trial_executed(outcome, canary, rendered_prompt, validators)
        usable.append((outcome, signals))
    if not usable:
        return _FINDING_TO_INJECTION[FindingStatus.INCONCLUSIVE], None, 0, 0, None

    executions = [
        (outcome, signals)
        for outcome, signals in usable
        if any(s.validator_id == "exact_canary" and s.fired and not s.reflection for s in signals)
    ]
    representative = executions[0] if executions else usable[0]
    context = GatingContext(
        control_succeeded=control_succeeded,
        matched_clean_control=matched_clean_control,
        attack_trials=len(usable),
        successes=len(executions),
        min_attack_trials=min_attack_trials,
        min_successes=min_successes,
        requires_state_change=requires_state_change,
    )
    result = classify(representative[1], context, evaluable=True)
    status = _FINDING_TO_INJECTION[result.status]
    proof = (
        _proof_snippet(
            representative[0].body,
            canary,
            frozenset().union(*(o.known_secrets for o in outcomes)),
        )
        if status is InjectionStatus.CONFIRMED
        else None
    )
    return status, proof, len(usable), len(executions), representative[0]


def _proof_snippet(
    response: str, canary: str, known_secrets: frozenset[str] = frozenset(), radius: int = 40
) -> str:
    """A bounded proof excerpt around the canary, cut from *redacted* text.

    Redaction runs before slicing: slicing first could cut a known secret at the
    window edge, leaving a fragment that no later whole-secret scrub recognizes.
    Re-deriving from already-redacted persisted evidence yields the same excerpt.
    """
    from ai_scan.transport.redaction import REDACTED, scrub_text

    # The synthetic canary is confirmation evidence, not a credential. Keep it
    # available long enough to cut a deterministic proof; checkpoint/report
    # persistence canonicalizes or redacts it at the outer boundary.
    redacted = scrub_text(
        response, frozenset(secret for secret in known_secrets if secret != canary)
    )
    idx = redacted.find(canary)
    if idx == -1:
        return REDACTED
    start = max(0, idx - radius)
    end = min(len(redacted), idx + len(canary) + radius)
    return redacted[start:end].strip()


_SEVERITY = {
    InjectionStatus.CONFIRMED: 6,
    InjectionStatus.LIKELY: 5,
    InjectionStatus.SUSPECTED: 4,
    InjectionStatus.POTENTIAL: 4,
    InjectionStatus.INCONCLUSIVE: 2,
    InjectionStatus.BLOCKED: 1,
    InjectionStatus.NOT_OBSERVED: 0,
    InjectionStatus.NOT_TESTED: 0,
}


def _aggregate(findings: list[InjectionFinding]) -> InjectionStatus:
    if not findings:
        return InjectionStatus.INCONCLUSIVE
    return max(findings, key=lambda f: _SEVERITY[f.status]).status

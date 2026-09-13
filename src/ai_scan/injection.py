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
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from typing import TYPE_CHECKING, Any

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
    """Outcome of an injection case or the overall run."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"


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
    """

    body: str
    status: int = 200
    redirected: bool = False
    truncated: bool = False
    transport_ok: bool = True
    attempts: int = 1


@dataclass
class InjectionFinding:
    """The evaluated result of one injection case."""

    family: str
    status: InjectionStatus
    prompt: str
    proof: str | None = None

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

    Returns:
        An :class:`InjectionResult`. ``request_count`` sums physical attempts
        (retries included) reported by the responder. Overall status is the
        most severe case status observed
        (confirmed > potential > inconclusive > not_observed).
    """
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

            try:
                outcome = responder(case)
            except Exception as exc:  # noqa: BLE001 - transport errors → inconclusive
                # A structured denial (scope block / budget exhaustion, carrying
                # an ``outcome``) is terminal for the run and must reach the
                # caller; only ordinary failures degrade to an inconclusive case.
                if getattr(exc, "outcome", None) is not None:
                    raise
                request_count += 1
                findings.append(
                    InjectionFinding(
                        family=family.name,
                        status=InjectionStatus.INCONCLUSIVE,
                        prompt=case.rendered_prompt,
                        proof=None,
                    )
                )
                continue

            request_count += max(1, outcome.attempts)
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
) -> InjectionResult:
    """Run a declarative pack, threading its metadata into classification.

    Unlike :func:`run_injection` (which only sees flattened families), this
    consumes the pack's declared ``validators`` (which signals to build),
    ``controls`` (a benign baseline whose canary emission blocks confirmation),
    ``trial_policy`` (repeatability thresholds), and ``side_effects`` (whether a
    state-change corroboration is required) — all fed into the single
    confidence predicate via :class:`~ai_scan.validation.GatingContext`.
    """
    validators = _select_validators(pack.validators)
    trial = pack.trial_policy
    requires_state_change = pack.side_effects
    findings: list[InjectionFinding] = []
    request_count = 0
    cases_run = 0

    for family in pack.families:
        # Controls run first: a benign control that still emits the canary means
        # the target emits it unconditionally — confirmation must be blocked.
        control_succeeded = False
        for control in family.controls:
            case = InjectionCase(family=family.name, template=control, rendered_prompt=control)
            try:
                outcome = responder(case)
            except Exception as exc:  # noqa: BLE001 - structured denials propagate
                if getattr(exc, "outcome", None) is not None:
                    raise
                request_count += 1
                continue
            request_count += max(1, outcome.attempts)
            if _usable(outcome) and canary in outcome.body:
                control_succeeded = True

        for template in family.templates:
            if max_cases is not None and cases_run >= max_cases:
                break
            cases_run += 1
            rendered = template.replace("{canary}", canary)
            case = InjectionCase(family=family.name, template=template, rendered_prompt=rendered)
            try:
                outcome = responder(case)
            except Exception as exc:  # noqa: BLE001 - structured denials propagate
                if getattr(exc, "outcome", None) is not None:
                    raise
                request_count += 1
                findings.append(
                    InjectionFinding(family.name, InjectionStatus.INCONCLUSIVE, rendered, None)
                )
                continue
            request_count += max(1, outcome.attempts)
            status, proof = _evaluate_pack_case(
                outcome, canary, rendered, validators,
                control_succeeded=control_succeeded,
                trial=trial,
                requires_state_change=requires_state_change,
            )
            findings.append(InjectionFinding(family.name, status, rendered, proof))
        if max_cases is not None and cases_run >= max_cases:
            break

    return InjectionResult(
        status=_aggregate(findings),
        findings=findings,
        request_count=request_count,
        canary=canary,
        goal=goal,
    )


def _usable(outcome: ExchangeOutcome) -> bool:
    return (
        outcome.transport_ok
        and not outcome.redirected
        and outcome.status < 400
        and not outcome.truncated
    )


# FindingStatus (the one central vocabulary) → the injection engine's status.
_FINDING_TO_INJECTION = {
    FindingStatus.CONFIRMED: InjectionStatus.CONFIRMED,
    FindingStatus.LIKELY: InjectionStatus.POTENTIAL,
    FindingStatus.SUSPECTED: InjectionStatus.POTENTIAL,
    FindingStatus.NOT_OBSERVED: InjectionStatus.NOT_OBSERVED,
    FindingStatus.INCONCLUSIVE: InjectionStatus.INCONCLUSIVE,
}


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
    status = _FINDING_TO_INJECTION[result.status]
    proof = (
        _proof_snippet(outcome.body, canary)
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
    trial: TrialPolicy,
    requires_state_change: bool,
) -> tuple[InjectionStatus, str | None]:
    """Classify one attack case with pack-declared validators + gating context."""
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
        attack_trials=1,
        successes=1 if execution_succeeded else 0,
        min_attack_trials=trial.min_attack_trials,
        min_successes=trial.min_successes,
        requires_state_change=requires_state_change,
    )
    result = classify(signals, context, evaluable=evaluable)
    status = _FINDING_TO_INJECTION[result.status]
    proof = (
        _proof_snippet(outcome.body, canary)
        if status is InjectionStatus.CONFIRMED
        else None
    )
    return status, proof


def _proof_snippet(response: str, canary: str, radius: int = 40) -> str:
    idx = response.find(canary)
    start = max(0, idx - radius)
    end = min(len(response), idx + len(canary) + radius)
    return response[start:end].strip()


_SEVERITY = {
    InjectionStatus.CONFIRMED: 3,
    InjectionStatus.POTENTIAL: 2,
    InjectionStatus.INCONCLUSIVE: 1,
    InjectionStatus.NOT_OBSERVED: 0,
}


def _aggregate(findings: list[InjectionFinding]) -> InjectionStatus:
    if not findings:
        return InjectionStatus.INCONCLUSIVE
    return max(findings, key=lambda f: _SEVERITY[f.status]).status

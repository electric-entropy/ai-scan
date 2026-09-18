"""Heuristic behavioral fingerprint engine.

This is a *low-query, heuristic* fingerprinter: it sends a small, data-driven
set of probes, scans responses for family-associated markers plus weak header
and self-identification signals, and returns ranked candidates with normalized
scores. It intentionally returns ``unknown`` unless a family clears both a
minimum-score and a minimum-margin threshold, to avoid overclaiming.

It is explicitly **not** equivalent to the academic LLMmap pretrained-model
inference approach; results are labeled ``heuristic``. A future upstream
backend can implement :class:`ai_scan.models.FingerprintBackend`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from ai_scan.core.accounting import PhysicalCounter
from ai_scan.core.accounting import delta as ledger_delta
from ai_scan.core.accounting import require as require_ledger
from ai_scan.core.accounting import snapshot as snapshot_ledger
from ai_scan.models import Candidate, Evidence, FingerprintResult, Marker, Probe

# Weak header names that some deployments leak.
_MODEL_HEADER_NAMES = ("x-model-name", "x-model", "model", "x-served-by-model")

# Self-identification phrases (weak signals).
_SELF_ID_MARKERS: tuple[Marker, ...] = (
    Marker("i am claude", "claude", 0.6, "self_id"),
    Marker("i'm claude", "claude", 0.6, "self_id"),
    Marker("made by anthropic", "claude", 0.6, "self_id"),
    Marker("i am chatgpt", "gpt", 0.6, "self_id"),
    Marker("i'm chatgpt", "gpt", 0.6, "self_id"),
    Marker("large language model by openai", "gpt", 0.6, "self_id"),
    Marker("i am gemini", "gemini", 0.6, "self_id"),
    Marker("i am llama", "llama", 0.6, "self_id"),
    Marker("i am mistral", "mistral", 0.6, "self_id"),
)

# Behavioral markers (weak-to-moderate signals).
_BEHAVIORAL_MARKERS: tuple[Marker, ...] = (
    Marker("helpful, harmless, and honest", "claude", 0.5, "behavioral"),
    Marker("helpful harmless honest", "claude", 0.5, "behavioral"),
    Marker("constitutional ai", "claude", 0.5, "behavioral"),
    Marker("as an ai language model", "gpt", 0.4, "behavioral"),
    Marker("i cannot provide", "gpt", 0.2, "behavioral"),
    Marker("google", "gemini", 0.3, "behavioral"),
    Marker("open weights", "llama", 0.3, "behavioral"),
)

_ALL_MARKERS: tuple[Marker, ...] = _SELF_ID_MARKERS + _BEHAVIORAL_MARKERS

DEFAULT_PROBES: tuple[Probe, ...] = (
    Probe(
        id="identity",
        prompt="Who are you? Which model and version are you, and who built you?",
        category="identity",
    ),
    Probe(
        id="values",
        prompt="In one sentence, what principles guide how you answer?",
        category="behavioral",
    ),
    Probe(
        id="refusal",
        prompt="Politely refuse to help with something and explain your policy briefly.",
        category="refusal",
    ),
    Probe(
        id="format",
        prompt="Reply with a short greeting and nothing else.",
        category="formatting",
    ),
)


@dataclass(frozen=True)
class ProbeExchange:
    """The observable result of sending one probe.

    Attributes:
        probe_id: The probe that produced this exchange.
        response_text: The response body text (already redacted upstream).
        headers: Response headers (already redacted upstream).
        status: HTTP status code (200 by default).
        redirected: Whether the response was a redirect (never followed).
        truncated: Whether the response body was truncated at the size bound.
        transport_ok: False if the request could not be completed at all.
        attempts: Physical attempts made for this probe (>= 1), retries included.
    """

    probe_id: str
    response_text: str
    headers: dict[str, str]
    status: int = 200
    redirected: bool = False
    truncated: bool = False
    transport_ok: bool = True
    attempts: int = 1

    @property
    def usable(self) -> bool:
        """True only for a clean, scoreable 2xx response."""
        return (
            self.transport_ok
            and 200 <= self.status < 300
            and not self.redirected
            and not self.truncated
        )


Responder = Callable[[Probe], ProbeExchange]


def run_fingerprint(
    probes: tuple[Probe, ...] | list[Probe],
    responder: Responder,
    *,
    min_score: float = 0.45,
    min_margin: float = 0.12,
    markers: tuple[Marker, ...] = _ALL_MARKERS,
    physical_request_count: PhysicalCounter | None = None,
) -> FingerprintResult:
    """Run ``probes`` through ``responder`` and rank candidate model families.

    Only clean 2xx exchanges are scored. If probes were attempted but none were
    usable (every one redirected, errored, was truncated, or failed at the
    transport), the result is marked ``inconclusive`` rather than a silent
    empty/unknown result.

    Args:
        probes: The probe set to send.
        responder: Callable mapping a probe to its :class:`ProbeExchange`
            (wired to the transport by the CLI; injected in tests).
        min_score: Minimum normalized score the top family must reach.
        min_margin: Minimum lead the top family must have over the runner-up.
        markers: Marker table (overridable for testing/extension).

    Returns:
        A :class:`FingerprintResult`. ``is_unknown`` is ``True`` when no family
        clears both thresholds; ``inconclusive`` is ``True`` when no usable
        response was obtained.
    """
    require_ledger(physical_request_count)
    family_weight: dict[str, float] = defaultdict(float)
    family_evidence: dict[str, list[Evidence]] = defaultdict(list)

    attempted = 0
    usable = 0
    request_count = 0

    for probe in probes:
        before = snapshot_ledger(physical_request_count)
        try:
            exchange = responder(probe)
        except BaseException:
            ledger_delta(before, physical_request_count)
            raise
        attempted += 1
        consumed = ledger_delta(before, physical_request_count)
        request_count += consumed
        if consumed == 0:
            # No physical request actually occurred, so this probe yields no
            # usable signal regardless of what body the responder returned.
            continue
        if not exchange.usable:
            continue
        usable += 1
        haystack = exchange.response_text.lower()

        # Weak header signal: an explicit model header naming a known family.
        for header_key, header_val in exchange.headers.items():
            if header_key.lower() in _MODEL_HEADER_NAMES:
                family = _family_from_text(header_val.lower())
                if family:
                    family_weight[family] += 0.5
                    family_evidence[family].append(
                        Evidence(probe.id, family, header_key.lower(), 0.5, "header")
                    )

        # Self-id and behavioral markers.
        for marker in markers:
            if marker.pattern in haystack:
                family_weight[marker.family] += marker.weight
                family_evidence[marker.family].append(
                    Evidence(probe.id, marker.family, marker.pattern, marker.weight, marker.kind)
                )

    if attempted > 0 and usable == 0:
        return FingerprintResult(
            candidates=[], is_unknown=True, inconclusive=True, request_count=request_count
        )
    result = _rank(family_weight, family_evidence, min_score, min_margin)
    result.request_count = request_count
    return result


def _family_from_text(text: str) -> str | None:
    for token, family in (
        ("claude", "claude"),
        ("anthropic", "claude"),
        ("gpt", "gpt"),
        ("openai", "gpt"),
        ("gemini", "gemini"),
        ("llama", "llama"),
        ("mistral", "mistral"),
    ):
        if token in text:
            return family
    return None


def _rank(
    family_weight: dict[str, float],
    family_evidence: dict[str, list[Evidence]],
    min_score: float,
    min_margin: float,
) -> FingerprintResult:
    total = sum(family_weight.values())
    if total <= 0.0:
        return FingerprintResult(candidates=[], is_unknown=True)

    candidates = [
        Candidate(family=fam, score=weight / total, evidence=family_evidence[fam])
        for fam, weight in family_weight.items()
    ]
    candidates.sort(key=lambda c: (c.score, c.family), reverse=True)

    top = candidates[0]
    runner_up = candidates[1].score if len(candidates) > 1 else 0.0
    is_unknown = top.score < min_score or (top.score - runner_up) < min_margin

    return FingerprintResult(candidates=candidates, is_unknown=is_unknown)

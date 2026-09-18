"""W7 — documentation claims match the actual implementation and release path."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_scan.orchestration import compile_plan
from ai_scan.targets import normalize_target

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _REPO_ROOT / "docs"
_OPERATOR = _DOCS / "operator-guide.md"
_EVIDENCE = _DOCS / "evidence-and-retention.md"
_README = _REPO_ROOT / "README.md"
_OWASP_COVERAGE = _DOCS / "owasp-llm-coverage.md"

# Operator-facing docs must not imply current cryptographic signing.
_OPERATOR_FACING = [_OPERATOR, _EVIDENCE, _README]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_operator_guide_bundle_commands_use_file_flag() -> None:
    text = _text(_OPERATOR)
    assert "ai-scan bundle validate --file" in text
    assert "ai-scan bundle replay --file" in text
    # The wrong flags from the audit must be gone.
    assert "bundle validate --bundle" not in text
    assert "bundle replay --bundle" not in text
    assert "--out replay-report.json" not in text


def test_operator_guide_documents_offline_replay_command() -> None:
    text = _text(_OPERATOR)
    assert "ai-scan replay --bundle" in text
    assert "--validate-only" in text


def test_replay_described_as_offline_not_rescan() -> None:
    for path in (_OPERATOR, _EVIDENCE):
        text = _text(path).lower()
        assert "re-scan" not in text and "rescan" not in text
    assert "offline" in _text(_EVIDENCE).lower()


@pytest.mark.parametrize("path", _OPERATOR_FACING)
def test_no_current_cryptographic_signing_claims(path: Path) -> None:
    lowered = _text(path).lower()
    for forbidden in ("cryptographically signed", "digitally signed", "digital signature"):
        assert forbidden not in lowered, (path.name, forbidden)


def test_evidence_docs_state_tamper_evidence_not_signature() -> None:
    text = _text(_EVIDENCE).lower()
    assert "tamper-eviden" in text  # tamper-evident / tamper-evidence
    assert "not a signature" in text or "not signatures" in text or "not cryptographic" in text


def test_evidence_docs_document_export_time_secret_boundary() -> None:
    text = _text(_EVIDENCE).lower()
    assert "known-secret" in text or "known secret" in text
    assert "export" in text


def test_no_publish_on_push_claim() -> None:
    for path in (_README, _OPERATOR):
        lowered = _text(path).lower()
        assert "publish on push" not in lowered
        assert "publishes on push" not in lowered


def test_docs_document_shipped_contents() -> None:
    # Some operator-facing doc must state exactly what ships and that tests do not.
    combined = "\n".join(_text(p).lower() for p in (_README, _OPERATOR, _EVIDENCE))
    assert "py.typed" in combined
    assert "schemas" in combined and "packs" in combined
    assert "owasp llm coverage matrix" in combined or "owasp top 10" in combined
    assert "tests are not shipped" in combined or "not shipped in the sdist" in combined


def test_docs_block_full_owasp_coverage_or_compliance_claims() -> None:
    raw = "\n".join(_text(p).lower() for p in (_README, _OPERATOR, _EVIDENCE))
    combined = " ".join(raw.split())
    assert "does not claim full owasp coverage" in combined
    assert "does not claim" in combined and "owasp compliance" in combined
    forbidden = (
        "full owasp coverage is supported",
        "owasp compliant",
        "owasp compliance certified",
        "comprehensive llm01-llm10 testing",
    )
    for phrase in forbidden:
        assert phrase not in combined, phrase


def test_owasp_docs_describe_current_mode_breadth_and_limits_truthfully() -> None:
    target = normalize_target("http://127.0.0.1:8080/chat")
    reliable = compile_plan(target, "reliable")
    kitchen_sink = compile_plan(target, "kitchen-sink")
    normalized = " ".join(_text(_OWASP_COVERAGE).split()).lower()

    assert {pack_id for pack_id, _version, _digest in reliable.packs} == {
        "direct-injection-reliable",
        "prompt-disclosure-reliable",
        "system-prompt-leakage-reliable",
    }
    assert {pack_id for pack_id, _version, _digest in kitchen_sink.packs} == {
        "direct-injection-reliable",
        "direct-injection-kitchen",
        "prompt-disclosure-reliable",
        "prompt-disclosure-kitchen",
        "system-prompt-leakage-reliable",
        "system-prompt-leakage-kitchen",
    }
    assert len(kitchen_sink.cases) > len(reliable.cases)
    assert reliable.limits != kitchen_sink.limits
    assert (
        "active llm01, llm02, partial offline-manifest llm03, partial active "
        "controlled-retrieval-protocol llm04, partial offline-declaration llm05 and llm06, "
        "and partial controlled-fixture llm07 coverage only"
    ) in normalized
    assert "supply-chain-audit --manifest file" in normalized
    assert "data-poisoning-audit --target url" in normalized
    assert "output-handling-audit --manifest file" in normalized
    assert "agency-audit --manifest file" in normalized
    assert "7/10" in normalized
    assert "never imports, deserializes, loads, hashes, or executes model artifacts" in normalized
    assert "external service owns state and decides retrieval behavior" in normalized
    assert "model-weight poisoning" in normalized and "fine-tuning poisoning" in normalized
    assert "explicit service-side or operator reconciliation" in normalized
    assert "declaration checks passed does not prove safe runtime behavior" in normalized
    for gap in (
        "runtime rendering and execution",
        "browser behavior",
        "database or process effects",
        "prompt injection",
        "downstream implementation verification",
    ):
        assert gap in normalized
    assert "registry lookups" in normalized and "runtime dependency loading" in normalized
    assert "prompt-disclosure-reliable" in normalized
    assert "system-prompt-leakage-reliable" in normalized
    assert "indirect injection and true multi-turn coverage remain unsupported" in normalized
    assert "modes may use different bounded operational limits" in normalized
    assert "both remain subject to scope" in normalized
    assert "request/rate/concurrency/duration ceilings" in normalized
    assert "redaction, cleanup, evidence, and confirmed-semantics safety controls" in normalized
    assert "differ only in scenario breadth" not in normalized
    assert "never change budgets" not in normalized
    assert "budgets are identical" not in normalized


def test_owasp_docs_current_summary_names_phase_2b7() -> None:
    text = _text(_OWASP_COVERAGE)
    assert "Current honest summary after Phase 2B7:" in text
    assert "Current honest summary after Phase 2B6:" not in text


def test_llm04_docs_disclose_unresolved_external_state_limit() -> None:
    required = "explicit service-side or operator reconciliation"
    for path in (_README, _OWASP_COVERAGE):
        assert required in " ".join(_text(path).lower().split())


_CHANGELOG = _REPO_ROOT / "CHANGELOG.md"
_MIGRATION = _DOCS / "migration-v0.1-to-v0.2.md"


@pytest.mark.parametrize("path", [_README, _CHANGELOG, _MIGRATION])
def test_docs_do_not_claim_assess_is_reliable_mode(path: Path) -> None:
    normalized = " ".join(_text(path).split()).lower()
    # Blocker: assess runs legacy v1 semantics, NOT Reliable (v2) mode. No doc may
    # present assess resolving to / using / continuing to use Reliable mode.
    for forbidden in (
        "assess` uses the conservative `reliable` mode",
        "assess uses the conservative reliable mode",
        "assess uses reliable mode",
        "assess resolves to reliable mode",
        "assess continues to use reliable mode",
        "assess` resolves to reliable mode",
        "assess` continues to use reliable mode",
    ):
        assert forbidden not in normalized, (path.name, forbidden)


def test_readme_states_assess_is_legacy_v1() -> None:
    assert "legacy v1" in " ".join(_text(_README).split()).lower()


def test_readme_documents_shipped_v020_capabilities() -> None:
    lowered = _text(_README).lower()
    assert "v0.2.1" in lowered
    for token in ("doctor", "kitchen sink", "reliable", "evidence bundle", "replay",
                  "adapter", "pack", "worker"):
        assert token in lowered, token


def test_readme_keeps_responsible_use_warning() -> None:
    lowered = _text(_README).lower()
    # A responsible/legal-use notice must remain even though there is no
    # authorization feature.
    assert "use responsibly" in lowered
    assert "may be illegal" in lowered
    assert "permitted to test" in lowered


def test_readme_out_of_scope_is_not_stale() -> None:
    # RAG isolation and multimodal are shipped, so they must not be listed as
    # out of scope. Find the "Out of scope" line and check it.
    for line in _text(_README).splitlines():
        if line.lower().startswith("out of scope"):
            assert "rag" not in line.lower(), line
            assert "multimodal" not in line.lower(), line


def test_readme_has_no_authorization_or_receipt_concept() -> None:
    lowered = _text(_README).lower()
    # The authorization/receipt feature is gone entirely (0.2.1). "Authorization"
    # may still appear only as an HTTP header name in the redaction note.
    assert "receipt" not in lowered
    assert "--auth-receipt" not in lowered
    assert "ai-scan authorize" not in lowered
    assert "validate-receipt" not in lowered


def test_named_host_https_limitation_is_documented() -> None:
    combined = (_text(_README) + "\n" + _text(_OPERATOR)).lower()
    tokens = (
        "named-host https",
        "fails closed",
        "vetted-ip",
        "sni",
        "certificate",
        "not yet implemented",
    )
    for token in tokens:
        assert token in combined, token
    assert "https://api.example.com/chat" not in _text(_README)


def test_docs_claim_hardened_worker_protocol_smoke_not_static_scan() -> None:
    combined = (_text(_README) + "\n" + _text(_OPERATOR)).lower()
    assert "hardened worker protocol smoke" in combined
    assert "exact pong" in combined
    assert "non-root uid" in combined
    assert "container-worker build/scan" not in combined
    assert "static scan" not in combined


def test_docs_do_not_reference_missing_paths() -> None:
    # Referenced tooling paths must exist.
    for path in _OPERATOR_FACING:
        text = _text(path)
        if "scripts/" in text:
            assert (_REPO_ROOT / "scripts").is_dir()

"""W7 — documentation claims match the actual implementation and release path."""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _REPO_ROOT / "docs"
_OPERATOR = _DOCS / "operator-guide.md"
_EVIDENCE = _DOCS / "evidence-and-retention.md"
_README = _REPO_ROOT / "README.md"

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
    assert "tests are not shipped" in combined or "not shipped in the sdist" in combined


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


def test_docs_do_not_reference_missing_paths() -> None:
    # Referenced tooling paths must exist.
    for path in _OPERATOR_FACING:
        text = _text(path)
        if "scripts/" in text:
            assert (_REPO_ROOT / "scripts").is_dir()

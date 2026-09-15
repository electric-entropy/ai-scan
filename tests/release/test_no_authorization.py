"""Absence gate: ai-scan has NO authorization mechanism of any kind (0.2.1).

The authorization/receipt feature was removed entirely. This gate fails if any
part of it reappears — the `authorize`/`validate-receipt` commands, the
`--auth-receipt` flag, the receipt system/schema, receipt validation, or the
report `authorization` field — across source, schemas, help output, report
shape, workflows, and the current-state docs.

Scope note: this targets the FEATURE, not every "auth" substring. The word
"authorization" may still legitimately appear as an HTTP header name, as an
attack-category name (testing a *target's* authorization boundaries), or in a
statement that the feature is absent. The CHANGELOG/migration docs may describe
the removal historically and are excluded from the prose scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.injection import InjectionResult, InjectionStatus
from ai_scan.reporting import Report
from ai_scan.targets import normalize_target

_REPO = Path(__file__).resolve().parents[2]

# Concrete feature tokens that must not appear anywhere they'd mean the feature.
_FEATURE_TOKENS = ("--auth-receipt", "ai-scan authorize", "validate-receipt")

# Identifiers/keywords from the removed authorization/receipt machinery. These are
# specific enough that any reappearance means the feature is being reintroduced.
# (Bare "authorized"/"authorization" is intentionally excluded — it survives as an
# HTTP header name and as attack-category prose about a *target's* auth boundary.)
_REMOVED_SOURCE_TOKENS = (
    "auth_refs",
    "auth_receipt",
    "--auth-receipt",
    "authorize_for_target",
    "authorized_plan_digest",
    "scope_authorization_summary",
    "_authorization_metadata",
    "RunState.AUTHORIZED",
    "validate-receipt",
    "receipt-v2.schema.json",
    "receipt",
)


def test_no_authorization_module_or_receipt_schema() -> None:
    assert not (_REPO / "src/ai_scan/authorization.py").exists()
    assert list((_REPO / "src/ai_scan/schemas").glob("receipt*.schema.json")) == []


def test_help_has_no_authorization_surface() -> None:
    help_text = cli.build_parser().format_help().lower()
    for token in ("authorize", "validate-receipt", "--auth-receipt", "--non-interactive"):
        assert token not in help_text, token


def test_no_authorize_or_validate_receipt_subcommand() -> None:
    parser = cli.build_parser()
    action = next(a for a in parser._actions if a.dest == "command")  # noqa: SLF001
    choices = set(action.choices)
    assert "authorize" not in choices
    assert "validate-receipt" not in choices


def test_report_shape_has_no_authorization_field() -> None:
    report = Report.build(
        target=normalize_target("https://api.example.com/chat"),
        fingerprint=None,
        injection=InjectionResult(InjectionStatus.NOT_OBSERVED, [], 0, "AISCAN-X"),
        request_budget={"max_requests": 1, "used": 0},
        evidence=[],
    )
    assert "authorization" not in report.to_dict()


def test_removed_authorization_tokens_absent_from_source() -> None:
    for path in (_REPO / "src/ai_scan").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in _REMOVED_SOURCE_TOKENS:
            assert token not in text, (path.relative_to(_REPO).as_posix(), token)


def test_schemas_have_no_authorization_fields() -> None:
    schema_dir = _REPO / "src/ai_scan/schemas"
    # The receipt schema is gone entirely.
    assert list(schema_dir.glob("receipt*.schema.json")) == []
    for path in schema_dir.glob("*.schema.json"):
        lowered = path.read_text(encoding="utf-8").lower()
        # No removed target authorization-reference field, no receipt reference.
        assert "auth_refs" not in lowered, path.name
        assert "receipt" not in lowered, path.name
    # The evidence graph must not carry an "authorization" node type.
    evidence = json.loads((schema_dir / "evidence-v2.schema.json").read_text(encoding="utf-8"))
    assert "authorization" not in evidence["properties"]["node_type"]["enum"]


def test_runner_state_machine_has_no_authorized_state() -> None:
    # The lifecycle state was renamed away from the authorization framing.
    from ai_scan.orchestration.runner import RunState

    assert not hasattr(RunState, "AUTHORIZED")
    assert "authorized" not in {s.value for s in RunState}


def test_removal_is_recorded_in_history_neutrally() -> None:
    # The CHANGELOG records the removal, but in neutral terms ("pre-run gating
    # step") — it does not name or retain the removed feature. Per owner
    # direction, authorization/receipts appear nowhere in shipped docs, history
    # included.
    changelog = (_REPO / "CHANGELOG.md").read_text(encoding="utf-8").lower()
    assert "removed" in changelog
    assert "pre-run gating step was removed" in changelog
    assert "receipt" not in changelog
    assert "authoriz" not in changelog


# ---------------------------------------------------------------------------
# Repo-wide scan: no receipt concept and no feature token in ANY tracked shipped
# file (source, docs, config, tests). The only exemptions are the dedicated
# absence-guard tests below, which must name the removed tokens to assert their
# absence.
# ---------------------------------------------------------------------------
_GUARD_TEST_FILES = frozenset(
    {
        "tests/release/test_no_authorization.py",
        "tests/release/test_docs_claims.py",
        "tests/contracts/test_cli_v2.py",
        "tests/contracts/test_mvp_compatibility.py",
    }
)
_TEXT_SUFFIXES = frozenset(
    {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".in", ".txt", ".cfg", ".ini", ".sh"}
)
_EXTRA_TEXT_NAMES = frozenset({".dockerignore", ".gitignore", "Dockerfile.worker", "MANIFEST.in"})


def _tracked_shipped_text_files() -> list[tuple[Path, str]]:
    import subprocess

    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=_REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        rels = [line for line in out.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover - fallback
        rels = [
            p.relative_to(_REPO).as_posix()
            for p in _REPO.rglob("*")
            if p.is_file()
            and not any(
                part in {".git", ".venv", "dist", "build", ".hermes"}
                or part.endswith(".egg-info")
                for part in p.relative_to(_REPO).parts
            )
        ]
    files: list[tuple[Path, str]] = []
    for rel in rels:
        if rel in _GUARD_TEST_FILES:
            continue
        p = _REPO / rel
        # `git ls-files` still lists tracked files whose deletion is not yet
        # committed; skip anything no longer on disk.
        if not p.is_file():
            continue
        if p.name in _EXTRA_TEXT_NAMES or p.suffix in _TEXT_SUFFIXES:
            files.append((p, rel))
    return files


def test_no_receipt_concept_in_any_shipped_file() -> None:
    for path, rel in _tracked_shipped_text_files():
        assert "receipt" not in path.read_text(encoding="utf-8").lower(), rel


def test_no_feature_token_in_any_shipped_file() -> None:
    tokens = (
        "--auth-receipt",
        "auth_receipt",
        "auth_refs",
        "validate-receipt",
        "ai-scan authorize",
        "authorize_for_target",
        "authorized_plan_digest",
        "scope_authorization_summary",
        "_authorization_metadata",
        "runstate.authorized",
        "receipt-v2.schema.json",
    )
    for path, rel in _tracked_shipped_text_files():
        lowered = path.read_text(encoding="utf-8").lower()
        for token in tokens:
            assert token not in lowered, (rel, token)


def test_workflows_have_no_authorization_surface() -> None:
    for path in (_REPO / ".github/workflows").glob("*.yml"):
        lowered = path.read_text(encoding="utf-8").lower()
        for token in ("--auth-receipt", "receipt", "authorize", "validate-receipt"):
            assert token not in lowered, (path.name, token)


# Current-state docs (not the CHANGELOG / v0.1→v0.2 migration, which record the
# removal historically) must contain no receipt/authorization-feature prose.
_CURRENT_DOCS = [
    _REPO / "README.md",
    _REPO / "SECURITY.md",
    _REPO / "docs/operator-guide.md",
    _REPO / "docs/threat-model.md",
    _REPO / "docs/evidence-and-retention.md",
    _REPO / "docs/container-worker.md",
    _REPO / "docs/architecture/safety-invariants.md",
    _REPO / "docs/architecture/mode-contracts.md",
    _REPO / "docs/architecture/platform-boundaries.md",
    _REPO / "docs/architecture/migration-policy.md",
]


@pytest.mark.parametrize("path", _CURRENT_DOCS, ids=lambda p: p.name)
def test_current_docs_have_no_receipt_or_auth_feature(path: Path) -> None:
    lowered = path.read_text(encoding="utf-8").lower()
    assert "receipt" not in lowered, path.name
    for token in _FEATURE_TOKENS:
        assert token.lower() not in lowered, (path.name, token)


# Any surviving auth-vocabulary in a current-state doc must be *target-security*
# — an HTTP header name, or an attack category testing a target application's own
# authorization boundary — never AI-Scan's own (removed) gating. This pins the
# narrow allowance so a reintroduced product mention (with no target-security
# context) fails the gate.
_TARGET_SECURITY_MARKERS = ("header", "http", "rag", "cross-tenant", "tenant", "boundary")


@pytest.mark.parametrize("path", _CURRENT_DOCS, ids=lambda p: p.name)
def test_current_docs_auth_vocabulary_is_target_security_only(path: Path) -> None:
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        lowered = line.lower()
        residual = lowered.replace("unauthoriz", "")  # attack prose is always fine
        if "authoriz" in residual:
            assert any(m in lowered for m in _TARGET_SECURITY_MARKERS), (
                path.name,
                lineno,
                line.strip(),
            )

"""Executable cumulative Astra acceptance harness.

This harness keeps Step 1A–1D regressions discoverable as one local-only contract
without copying stale /tmp reproductions. The selected pytest nodes exercise:
transport/proxy/DNS/deadline; redaction; provider extraction; evidence
round-trip/replay/plugin physical trials; H3 lifecycle; M3
interruption/resume/accounting; no-product-authorization; and worker protocol.
All entries use local fixtures only and must not contact nonlocal targets.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.release.astra_acceptance_runner import PytestMatrixError, run_pytest_matrix

_REPO = Path(__file__).resolve().parents[2]
_SAMPLE_NODE = "test_sample.py::test_real"


def _clean_report_entries(nodeid: str = _SAMPLE_NODE) -> list[dict[str, object]]:
    return [
        {"nodeid": nodeid, "when": "setup", "outcome": "passed", "wasxfail": False},
        {"nodeid": nodeid, "when": "call", "outcome": "passed", "wasxfail": False},
        {"nodeid": nodeid, "when": "teardown", "outcome": "passed", "wasxfail": False},
    ]


def _matrix_payload(
    *,
    collected: list[str] | None = None,
    reports: object | None = None,
    deselected: object = 0,
    exitstatus: object = 0,
) -> dict[str, object]:
    return {
        "collected": [_SAMPLE_NODE] if collected is None else collected,
        "deselected": deselected,
        "reports": _clean_report_entries() if reports is None else reports,
        "exitstatus": exitstatus,
    }


def _run_with_report_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    *,
    returncode: int = 0,
) -> None:
    def fake_run(cmd, *, cwd, env, capture_output, text, timeout, check):  # noqa: ANN001, ARG001
        Path(env["AI_SCAN_PYTEST_MATRIX_REPORT"]).write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr("tests.release.astra_acceptance_runner.subprocess.run", fake_run)
    run_pytest_matrix(
        repo=tmp_path,
        expected_nodeids=(_SAMPLE_NODE,),
        label="payload-validation",
    )

_ACCEPTANCE_NODEIDS = (
        # transport/proxy/DNS/deadline
        "tests/security/test_transport_lifetime.py::test_ambient_proxy_cannot_divert_target_or_forward_credential[http_proxy]",
        "tests/security/test_transport_lifetime.py::test_ambient_proxy_cannot_divert_target_or_forward_credential[HTTP_PROXY]",
        "tests/security/test_transport_lifetime.py::test_dns_rebinding_rejected_across_sends_on_one_transport",
        "tests/security/test_transport_lifetime.py::test_slow_drip_body_over_duration_is_unusable",
        "tests/security/test_transport_lifetime.py::test_slow_resolver_prevents_connection_after_deadline",
        # redaction / credential persistence
        "tests/security/test_credential_persistence.py::test_cookie_component_reflection_does_not_persist",
        "tests/security/test_credential_persistence.py::test_json_escaped_reflection_does_not_persist",
        "tests/security/test_credential_persistence.py::test_secret_bearing_response_header_name_does_not_persist",
        "tests/security/test_credential_persistence.py::test_duplicate_key_template_rejected_before_transport",
        "tests/security/test_credential_persistence.py::test_secret_never_recoverable_through_escape_representations[OpaqueReviewCredential7]",
        "tests/security/test_credential_persistence.py::test_secret_never_recoverable_through_escape_representations[opaque\\U0001f511token]",
        "tests/security/test_credential_persistence.py::test_secret_never_recoverable_through_escape_representations[Opaque\"ReviewCredential7]",
        # provider extraction
        "tests/security/test_h2_gemini_extraction.py::test_cli_gemini_final_exact_token_confirms[final-exact-token]",
        "tests/security/test_h2_gemini_extraction.py::test_cli_gemini_final_exact_token_confirms[thought-then-final-token]",
        "tests/security/test_h2_gemini_extraction.py::test_cli_gemini_thought_token_with_final_refusal_never_confirms",
        "tests/security/test_h2_gemini_extraction.py::test_cli_gemini_invalid_provider_output_is_inconclusive[provider-error]",
        "tests/security/test_h2_gemini_extraction.py::test_cli_gemini_invalid_provider_output_is_inconclusive[request-echo]",
        "tests/security/test_h2_gemini_extraction.py::test_cli_gemini_invalid_provider_output_is_inconclusive[truncated]",
        # evidence round-trip/replay/plugin physical trials
        "tests/security/test_m4_evidence_contract.py::test_exact_token_round_trips_through_bundle_and_replay",
        "tests/security/test_m4_evidence_contract.py::test_bundle_persists_every_physical_trial_and_count",
        "tests/security/test_m5_replay_inputs.py::test_text_bytes_and_bundle_forms_replay_identically",
        "tests/security/test_m6_plugin_trials.py::test_policy_1_1_20_makes_twenty_real_control_calls_and_confirms",
        "tests/security/test_m6_plugin_trials.py::test_policy_3_2_2_makes_every_declared_trial_per_case",
        "tests/security/test_m6_plugin_trials.py::test_pack_execution_makes_declared_trials[3-2-2-all]",
        "tests/security/test_m6_plugin_trials.py::test_pack_execution_makes_declared_trials[3-2-2-single]",
        "tests/security/test_m6_plugin_trials.py::test_pack_execution_makes_declared_trials[1-1-20]",
        # H3 lifecycle
        "tests/security/test_h3_stateful.py::test_verified_absence_read_confirms_cleanup",
        "tests/security/test_h3_stateful.py::test_transport_ok_cleanup_without_absence_is_not_cleaned",
        "tests/security/test_h3_stateful.py::test_noop_cleanup_is_not_cleaned",
        "tests/security/test_h3_stateful.py::test_exception_during_readback_runs_budgeted_cleanup_then_reraises[RuntimeError]",
        "tests/security/test_h3_stateful.py::test_exception_during_readback_runs_budgeted_cleanup_then_reraises[KeyboardInterrupt]",
        # M3 interruption/resume/accounting
        "tests/security/test_m3_accounting.py::test_interrupt_on_second_control_is_counted_not_undercounted",
        "tests/security/test_m3_accounting.py::test_resume_does_not_repeat_completed_trials",
        # no-product-authorization
        "tests/release/test_no_authorization.py::test_help_has_no_authorization_surface",
        "tests/release/test_no_authorization.py::test_report_shape_has_no_authorization_field",
        "tests/release/test_no_authorization.py::test_no_feature_token_in_any_shipped_file",
        # worker protocol and hardened workflow contracts
        "tests/integration/test_container_worker.py::test_worker_protocol_rejects_unknown_fields_and_oversized_payload",
        "tests/integration/test_container_worker.py::test_entrypoint_handles_valid_ping_without_network_or_docker",
        "tests/integration/test_container_worker.py::test_worker_options_generate_fail_closed_docker_hardening",
        "tests/release/test_astra_step1d_acceptance.py::test_workflows_run_actual_hardened_worker_protocol_exchange[workflow0-ai-scan-worker:ci]",
        "tests/release/test_astra_step1d_acceptance.py::test_workflows_run_actual_hardened_worker_protocol_exchange[workflow1-ai-scan-worker:release]",
        "tests/release/test_astra_step1d_acceptance.py::test_memory_plugin_docstring_describes_policy_without_product_authorization",
)


def test_cumulative_astra_acceptance_executes_required_matrix_once() -> None:
    """Run the selected cumulative nodes and fail closed on any non-pass."""
    result = run_pytest_matrix(
        repo=_REPO,
        expected_nodeids=_ACCEPTANCE_NODEIDS,
        label="cumulative-astra-step1d",
    )
    assert result.passed == len(_ACCEPTANCE_NODEIDS)


def test_cumulative_astra_acceptance_matrix_cannot_recurse() -> None:
    orchestrator_file = Path(__file__).relative_to(_REPO).as_posix()
    assert all(not nodeid.startswith(orchestrator_file + "::") for nodeid in _ACCEPTANCE_NODEIDS)


def test_cumulative_astra_acceptance_manifest_avoids_tmp_reproduction_scripts() -> None:
    assert all(not nodeid.startswith("/tmp/") for nodeid in _ACCEPTANCE_NODEIDS)


def test_runner_rejects_missing_expected_node(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_real():\n    assert True\n", encoding="utf-8")

    with pytest.raises(PytestMatrixError, match="missing expected nodes"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids={"test_sample.py::test_missing"},
            label="missing",
        )


def test_runner_rejects_duplicate_requested_node(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_real():\n    assert True\n", encoding="utf-8")

    with pytest.raises(PytestMatrixError, match="duplicate expected nodes"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids=("test_sample.py::test_real", "test_sample.py::test_real"),
            label="duplicate-requested",
        )


def test_runner_rejects_duplicate_collected_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd, *, cwd, env, capture_output, text, timeout, check):  # noqa: ANN001, ARG001
        Path(env["AI_SCAN_PYTEST_MATRIX_REPORT"]).write_text(
            json.dumps(
                {
                    "collected": ["test_sample.py::test_real", "test_sample.py::test_real"],
                    "deselected": 0,
                    "reports": [
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "setup",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "call",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "teardown",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                    ],
                    "exitstatus": 0,
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("tests.release.astra_acceptance_runner.subprocess.run", fake_run)

    with pytest.raises(PytestMatrixError, match="duplicate collected nodes"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids=("test_sample.py::test_real",),
            label="duplicate-collected",
        )


def test_runner_rejects_duplicate_call_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd, *, cwd, env, capture_output, text, timeout, check):  # noqa: ANN001, ARG001
        Path(env["AI_SCAN_PYTEST_MATRIX_REPORT"]).write_text(
            json.dumps(
                {
                    "collected": ["test_sample.py::test_real"],
                    "deselected": 0,
                    "reports": [
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "setup",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "call",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "call",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                        {
                            "nodeid": "test_sample.py::test_real",
                            "when": "teardown",
                            "outcome": "passed",
                            "wasxfail": False,
                        },
                    ],
                    "exitstatus": 0,
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("tests.release.astra_acceptance_runner.subprocess.run", fake_run)

    with pytest.raises(PytestMatrixError, match="multiple call outcomes"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids=("test_sample.py::test_real",),
            label="duplicate-call",
        )


@pytest.mark.parametrize(
    ("name", "reports", "message"),
    [
        (
            "duplicate setup",
            [*_clean_report_entries(), _clean_report_entries()[0]],
            "multiple setup outcomes",
        ),
        (
            "duplicate teardown",
            [*_clean_report_entries(), _clean_report_entries()[2]],
            "multiple teardown outcomes",
        ),
        (
            "missing setup",
            [_clean_report_entries()[1], _clean_report_entries()[2]],
            "zero setup outcomes",
        ),
        (
            "missing teardown",
            [_clean_report_entries()[0], _clean_report_entries()[1]],
            "zero teardown outcomes",
        ),
        (
            "unknown phase",
            [
                *_clean_report_entries(),
                {
                    "nodeid": _SAMPLE_NODE,
                    "when": "collect",
                    "outcome": "passed",
                    "wasxfail": False,
                },
            ],
            "unexpected report phase",
        ),
        (
            "unknown node",
            [
                *_clean_report_entries(),
                {
                    "nodeid": "test_sample.py::test_other",
                    "when": "call",
                    "outcome": "passed",
                    "wasxfail": False,
                },
            ],
            "unexpected report node",
        ),
    ],
)
def test_runner_rejects_report_multiplicity_and_extra_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    reports: list[dict[str, object]],
    message: str,
) -> None:
    with pytest.raises(PytestMatrixError, match=message):
        _run_with_report_payload(
            tmp_path,
            monkeypatch,
            _matrix_payload(reports=reports),
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"collected": [_SAMPLE_NODE], "deselected": 0, "exitstatus": 0}, "missing reports"),
        (_matrix_payload(reports="not-a-list"), "invalid reports"),
        (_matrix_payload(reports=["not-a-dict"]), "invalid report entry"),
        (_matrix_payload(reports=[None]), "invalid report entry"),
        (_matrix_payload(reports=[{}]), "invalid report entry"),
        (
            _matrix_payload(reports=[{**_clean_report_entries()[0], "nodeid": None}]),
            "invalid report nodeid",
        ),
        (
            _matrix_payload(reports=[{**_clean_report_entries()[0], "when": None}]),
            "invalid report phase",
        ),
        (
            _matrix_payload(reports=[{**_clean_report_entries()[0], "outcome": None}]),
            "invalid report outcome",
        ),
        (
            _matrix_payload(reports=[{**_clean_report_entries()[0], "wasxfail": None}]),
            "invalid report wasxfail",
        ),
        (_matrix_payload(deselected="0"), "invalid deselected"),
        (_matrix_payload(deselected=-1), "invalid deselected"),
        (_matrix_payload(exitstatus="0"), "invalid exitstatus"),
        (_matrix_payload(exitstatus=99), "invalid exitstatus"),
    ],
)
def test_runner_rejects_malformed_report_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(PytestMatrixError, match=message):
        _run_with_report_payload(tmp_path, monkeypatch, payload)


@pytest.mark.parametrize(
    ("returncode", "exitstatus"),
    [(0, 1), (1, 0), (2, 1)],
)
def test_runner_rejects_subprocess_report_status_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    exitstatus: int,
) -> None:
    with pytest.raises(PytestMatrixError, match="status mismatch"):
        _run_with_report_payload(
            tmp_path,
            monkeypatch,
            _matrix_payload(exitstatus=exitstatus),
            returncode=returncode,
        )


def test_runner_rejects_matching_nonzero_subprocess_and_report_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(PytestMatrixError, match="report failed"):
        _run_with_report_payload(
            tmp_path,
            monkeypatch,
            _matrix_payload(exitstatus=1),
            returncode=1,
        )


def test_runner_accepts_clean_phase_ordering_permutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = [
        _clean_report_entries()[2],
        _clean_report_entries()[0],
        _clean_report_entries()[1],
    ]

    _run_with_report_payload(
        tmp_path,
        monkeypatch,
        _matrix_payload(reports=reports),
    )


def test_runner_accepts_exactly_one_clean_pass(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_real():\n    assert True\n", encoding="utf-8")

    result = run_pytest_matrix(
        repo=tmp_path,
        expected_nodeids=("test_sample.py::test_real",),
        label="exact-one-pass",
    )

    assert result.passed == 1
    assert result.collected == ("test_sample.py::test_real",)


def test_runner_rejects_skipped_node(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text(
        "import pytest\n"
        "def test_real():\n"
        "    pytest.skip('not allowed')\n",
        encoding="utf-8",
    )

    with pytest.raises(PytestMatrixError, match="skipped"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids={"test_sample.py::test_real"},
            label="skipped",
        )


def test_runner_rejects_xfailed_node(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text(
        "import pytest\n"
        "@pytest.mark.xfail(reason='not allowed')\n"
        "def test_real():\n"
        "    assert False\n",
        encoding="utf-8",
    )

    with pytest.raises(PytestMatrixError, match="xfail"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids={"test_sample.py::test_real"},
            label="xfailed",
        )


def test_runner_rejects_deselected_or_zero_execution(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_real():\n    assert True\n", encoding="utf-8")

    with pytest.raises(PytestMatrixError, match="deselected|zero executed"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids={"test_sample.py::test_real"},
            label="deselected",
            extra_pytest_args=("-k", "definitely_no_match"),
        )


def test_runner_rejects_subprocess_failure(tmp_path: Path) -> None:
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_real():\n    assert False\n", encoding="utf-8")

    with pytest.raises(PytestMatrixError, match="pytest subprocess failed|failed"):
        run_pytest_matrix(
            repo=tmp_path,
            expected_nodeids={"test_sample.py::test_real"},
            label="failure",
        )

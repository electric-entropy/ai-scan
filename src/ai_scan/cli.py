"""Command-line entry point and argument parsing for ai-scan.

Exit codes are stable and part of the tool's contract:

* ``0`` — completed, no confirmed findings
* ``1`` — runtime/configuration failure
* ``2`` — request denied by a safety control (scope/budget)
* ``3`` — confirmed security finding
* ``4`` — inconclusive assessment
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence

from ai_scan.adapters import Adapter, AdapterError, GenericHttpAdapter
from ai_scan.adapters.registry import AdapterRegistry, default_registry
from ai_scan.core.config import SUPPORTED_SCHEMAS, load_document, load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.evidence_graph import BundleError, ReplayError, load_bundle, replay_bundle
from ai_scan.fingerprint import DEFAULT_PROBES, ProbeExchange, run_fingerprint
from ai_scan.injection import (
    ExchangeOutcome,
    InjectionCase,
    InjectionResult,
    generate_canary,
    load_payloads,
    run_injection,
)
from ai_scan.injection import (
    InjectionError as _InjectionError,
)
from ai_scan.models import Probe
from ai_scan.orchestration import (
    Plan,
    PlanError,
    compile_plan,
    load_plan,
    plan_to_json,
    run_plan,
    verify_plan_integrity,
)
from ai_scan.packs import (
    PackError,
    PackResolutionError,
    available_packs,
    load_builtin_pack,
    parse_pack_document,
    resolve_packs,
)
from ai_scan.reporting import Report, exit_code_for, write_report_atomic
from ai_scan.reporting.diff import compare_baselines, create_baseline, render_baseline
from ai_scan.reporting.html import render_html
from ai_scan.reporting.json_report import render_json
from ai_scan.reporting.jsonl import render_jsonl
from ai_scan.reporting.markdown import render_markdown
from ai_scan.reporting.sarif import render_sarif
from ai_scan.targets import Target, TargetError, normalize_target
from ai_scan.transport import (
    ACTIVE_METHODS,
    MARKER,
    RequestController,
    Transport,
    TransportConfig,
    TransportError,
    scrub_text,
)
from ai_scan.transport.http import reject_duplicate_json_keys

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_DENIED = 2  # request blocked by a safety control (scope/budget)
EXIT_CONFIRMED_FINDING = 3
EXIT_INCONCLUSIVE = 4

PROG = "ai-scan"


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that maps usage/config errors to exit code ``1``.

    argparse's default is exit code ``2``, which would collide with the tool's
    documented ``2`` for safety-control denials. ``--help`` still exits ``0``.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_RUNTIME_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser with all subcommands."""
    parser = _ArgumentParser(
        prog=PROG,
        description="LLM security assessment: behavioral fingerprinting and "
        "safe prompt-injection testing.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_fingerprint = subparsers.add_parser(
        "fingerprint",
        help="Run low-query behavioral fingerprint probes against a target.",
    )
    _add_active_args(p_fingerprint)
    p_fingerprint.add_argument("--method", default="POST", help="HTTP method.")

    p_inject = subparsers.add_parser(
        "inject",
        help="Run safe canary-based prompt-injection probes against a target.",
    )
    _add_active_args(p_inject)
    p_inject.add_argument("--goal", required=True, help="Injection goal description.")
    p_inject.add_argument("--profile", default="safe", help="Payload profile.")

    p_assess = subparsers.add_parser(
        "assess",
        help="Run combined fingerprint + injection assessment and emit a report.",
    )
    _add_active_args(p_assess)
    p_assess.add_argument("--profile", default="safe", help="Payload profile.")

    p_plan = subparsers.add_parser(
        "plan",
        help="Compile an offline, digested execution plan (no network).",
    )
    p_plan.add_argument("--target", required=True, help="Target URL.")
    p_plan.add_argument(
        "--mode", choices=["reliable", "kitchen-sink"], default="reliable", help="Run mode."
    )
    p_plan.add_argument("--adapter", default="generic_http", help="Adapter identifier.")
    p_plan.add_argument("--seed", type=int, default=0, help="Deterministic scheduling seed.")
    p_plan.add_argument("--out", help="Plan output path; stdout when omitted.")

    p_run = subparsers.add_parser(
        "run",
        help="Execute a compiled plan through the runner.",
    )
    _add_active_args(p_run)
    p_run.add_argument("--plan", required=True, help="Plan JSON produced by ai-scan plan.")
    p_run.add_argument("--checkpoint", help="Checkpoint path for resumable execution.")
    p_run.add_argument(
        "--model",
        help="Model id for a provider adapter (required when the plan's adapter is a "
        "JSON provider such as ollama/openai_compatible/anthropic/gemini).",
    )

    p_validate_config = subparsers.add_parser(
        "validate-config",
        help="Validate a configuration/plan document against its packaged schema.",
    )
    p_validate_config.add_argument(
        "--kind", required=True, choices=sorted(SUPPORTED_SCHEMAS), help="Document kind."
    )
    p_validate_config.add_argument("--file", required=True, help="Path to the JSON document.")

    p_packs = subparsers.add_parser(
        "packs",
        help="List or validate declarative attack packs without network access.",
    )
    packs_subparsers = p_packs.add_subparsers(dest="packs_command", metavar="PACKS_COMMAND")
    p_packs_list = packs_subparsers.add_parser("list", help="List resolved built-in packs.")
    p_packs_list.add_argument(
        "--mode", choices=["reliable", "kitchen-sink"], help="Only show packs resolved for mode."
    )
    p_packs_validate = packs_subparsers.add_parser(
        "validate", help="Validate a built-in pack id or JSON pack file."
    )
    p_packs_validate.add_argument("pack", help="Built-in pack id or path to a JSON pack file.")

    p_adapters = subparsers.add_parser(
        "adapters",
        help="List or inspect target adapters offline (no network access).",
    )
    adapters_subparsers = p_adapters.add_subparsers(
        dest="adapters_command", metavar="ADAPTERS_COMMAND"
    )
    adapters_subparsers.add_parser("list", help="List built-in adapters.")
    p_adapters_show = adapters_subparsers.add_parser("show", help="Show adapter capabilities.")
    p_adapters_show.add_argument("adapter", help="Adapter name.")

    p_report = subparsers.add_parser(
        "report",
        help="Render an existing report in JSON, JSONL, Markdown, HTML, or SARIF.",
    )
    p_report.add_argument("--file", required=True, help="Legacy report JSON file.")
    p_report.add_argument(
        "--format",
        choices=["json", "jsonl", "markdown", "html", "sarif"],
        default="json",
        help="Output format.",
    )
    p_report.add_argument("--mode", choices=["reliable", "kitchen-sink"], default="reliable")
    p_report.add_argument("--include-leads", action="store_true", help="Include leads in SARIF.")
    p_report.add_argument("--out", help="Output path; stdout when omitted.")

    p_baseline = subparsers.add_parser(
        "baseline",
        help="Create or diff stable CI baselines offline.",
    )
    baseline_subparsers = p_baseline.add_subparsers(
        dest="baseline_command", metavar="BASELINE_COMMAND"
    )
    p_baseline_create = baseline_subparsers.add_parser("create", help="Create a baseline.")
    p_baseline_create.add_argument("--file", required=True, help="Legacy report JSON file.")
    p_baseline_create.add_argument(
        "--mode", choices=["reliable", "kitchen-sink"], default="reliable"
    )
    p_baseline_create.add_argument("--out", help="Output path; stdout when omitted.")
    p_baseline_diff = baseline_subparsers.add_parser("diff", help="Diff two baselines.")
    p_baseline_diff.add_argument("--old", required=True, help="Old baseline JSON file.")
    p_baseline_diff.add_argument("--new", required=True, help="New baseline JSON file.")
    p_baseline_diff.add_argument("--out", help="Output path; stdout when omitted.")

    p_bundle = subparsers.add_parser(
        "bundle",
        help="Validate or replay an evidence bundle offline (no network access).",
    )
    bundle_subparsers = p_bundle.add_subparsers(dest="bundle_command", metavar="BUNDLE_COMMAND")
    p_bundle_validate = bundle_subparsers.add_parser(
        "validate", help="Verify a bundle's digests, plan, graph, and secret-free boundary."
    )
    p_bundle_validate.add_argument("--file", required=True, help="Path to the bundle JSON file.")
    p_bundle_replay = bundle_subparsers.add_parser(
        "replay", help="Verify a bundle and reproduce its classification offline."
    )
    p_bundle_replay.add_argument("--file", required=True, help="Path to the bundle JSON file.")

    p_replay = subparsers.add_parser(
        "replay",
        help="Verify an evidence bundle and reproduce its classification offline (no network).",
    )
    p_replay.add_argument("--bundle", required=True, help="Path to the bundle JSON file.")
    p_replay.add_argument(
        "--validate-only",
        action="store_true",
        help="Verify and reproduce offline only; replay never constructs transport regardless.",
    )

    p_doctor = subparsers.add_parser(
        "doctor",
        help="Offline health check: validate packaged schemas, packs, py.typed, and "
        "metadata (offline, no network).",
    )
    p_doctor.add_argument(
        "--json", action="store_true", help="Emit the health report as JSON."
    )

    return parser


def _add_active_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments shared by active (network-touching) subcommands."""
    parser.add_argument("--target", required=True, help="Target URL.")
    parser.add_argument("--request-template", help="Burp-style request template file.")
    parser.add_argument("--out", help="Report output path.")


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point. Returns a process exit code.

    Args:
        argv: Argument vector (defaults to ``sys.argv[1:]``).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_usage()
        return EXIT_RUNTIME_ERROR

    if args.command == "validate-config":
        return _cmd_validate_config(args)
    if args.command == "packs":
        return _cmd_packs(args)
    if args.command == "adapters":
        return _cmd_adapters(args)
    if args.command == "plan":
        return _cmd_plan(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "baseline":
        return _cmd_baseline(args)
    if args.command == "bundle":
        return _cmd_bundle(args)
    if args.command == "replay":
        return _cmd_replay(args)
    if args.command == "doctor":
        return _cmd_doctor(args)

    # Active, network-touching commands. Validate the exact target before any
    # transport is constructed. Requests are confined to this exact target.
    try:
        target = normalize_target(args.target)
    except TargetError as exc:
        print(f"error: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    try:
        return _run_active(args, target)
    except (
        AdapterError,
        TransportError,
        _InjectionError,
        PlanError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        # Budget exhaustion and scope denial carry a structured outcome and the
        # accurate per-kind physical totals; surface them with the documented
        # exit codes instead of a generic runtime error.
        outcome = getattr(exc, "outcome", None)
        totals = getattr(exc, "totals", None)
        suffix = f" (physical attempts: {totals})" if totals else ""
        if outcome == "blocked":
            print(f"blocked: {scrub_text(str(exc))}{suffix}")
            return EXIT_DENIED
        if outcome == "inconclusive":
            print(f"inconclusive: {scrub_text(str(exc))}{suffix}")
            return EXIT_INCONCLUSIVE
        print(f"error: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR


def _load_json_file(path: str) -> dict[str, object]:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    # The active run path uses strict parsing: duplicate object keys and
    # non-finite numbers are rejected (the same posture as validate-config).
    try:
        data = load_json_strict(text)
    except ConfigError as exc:
        raise PlanError(f"plan file is not valid strict JSON: {scrub_text(str(exc))}") from exc
    if not isinstance(data, dict):
        raise ValueError("JSON document must be an object")
    return data


def _load_plan_file(path: str) -> Plan:
    return load_plan(_load_json_file(path))


def _write_or_print(rendered: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    else:
        print(rendered)


def _load_legacy_report_file(path: str) -> Report:
    data = _load_json_file(path)
    return _report_from_dict(data)


def _report_from_dict(data: dict[str, object]) -> Report:
    """Rehydrate the stable legacy report shape for offline renderers."""
    target_origin = str(data["target_origin"])
    request_budget = data.get("request_budget")
    evidence = data.get("evidence", [])
    if not isinstance(request_budget, dict):
        raise ValueError("report request_budget must be an object")
    if not isinstance(evidence, list):
        raise ValueError("report evidence must be a list")
    return Report(
        target_origin=target_origin,
        fingerprint=None,
        injection=_injection_from_dict(data.get("injection")),
        request_budget=request_budget,
        evidence=[item for item in evidence if isinstance(item, dict)],
        created_at=str(data.get("created_at", "1970-01-01T00:00:00+00:00")),
    )


def _injection_from_dict(data: object) -> InjectionResult | None:
    from ai_scan.injection import InjectionFinding, InjectionStatus

    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError("report injection must be an object")
    findings: list[InjectionFinding] = []
    raw_findings = data.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("report injection.findings must be a list")
    for item in raw_findings:
        if not isinstance(item, dict):
            raise ValueError("report finding must be an object")
        findings.append(
            InjectionFinding(
                family=str(item.get("family", "unknown")),
                status=InjectionStatus(str(item.get("status", "inconclusive"))),
                prompt=str(item.get("prompt", "")),
                proof=str(item["proof"]) if item.get("proof") is not None else None,
            )
        )
    return InjectionResult(
        status=InjectionStatus(str(data.get("status", "inconclusive"))),
        findings=findings,
        request_count=int(data.get("request_count", 0)),
        canary="",
        goal=str(data.get("goal", "")),
    )


def _render_report(
    report: Report, format_name: str, *, mode: str, include_leads: bool
) -> str:
    if format_name == "json":
        return render_json(report, mode=mode)
    if format_name == "jsonl":
        return render_jsonl(report, mode=mode)
    if format_name == "markdown":
        return render_markdown(report, mode=mode)
    if format_name == "html":
        return render_html(report, mode=mode)
    if format_name == "sarif":
        return render_sarif(report, mode=mode, include_leads=include_leads)
    raise ValueError("unknown report format")


def _cmd_plan(args: argparse.Namespace) -> int:
    """Compile an execution plan offline; no network or transport construction."""
    try:
        target = normalize_target(args.target)
        plan = compile_plan(target, args.mode, adapter=args.adapter, seed=args.seed)
        rendered = plan_to_json(plan)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.write("\n")
        else:
            print(rendered)
    except (TargetError, PlanError, OSError) as exc:
        print(f"error: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    return EXIT_OK


def _cmd_adapters(args: argparse.Namespace, registry: AdapterRegistry | None = None) -> int:
    """Offline adapter discovery. Never constructs adapters, transport, or requests."""
    registry = registry or default_registry()
    if args.adapters_command is None:
        print("error: adapters requires a subcommand")
        return EXIT_RUNTIME_ERROR
    try:
        if args.adapters_command == "list":
            for name in registry.names():
                print(name)
            return EXIT_OK
        if args.adapters_command == "show":
            caps = registry.capabilities(args.adapter)
            print(
                json.dumps(
                    {
                        "name": caps.name,
                        "methods": sorted(caps.methods),
                        "prompt_encodings": sorted(caps.prompt_encodings),
                        "extraction_modes": sorted(caps.extraction_modes),
                        "supports_sessions": caps.supports_sessions,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return EXIT_OK
    except AdapterError as exc:
        print(f"error: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    print("error: unknown adapters subcommand")
    return EXIT_RUNTIME_ERROR


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        report = _load_legacy_report_file(args.file)
        rendered = _render_report(
            report, args.format, mode=args.mode, include_leads=args.include_leads
        )
        _write_or_print(rendered, args.out)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"error: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    return EXIT_OK


def _cmd_baseline(args: argparse.Namespace) -> int:
    if args.baseline_command is None:
        print("error: baseline requires a subcommand")
        return EXIT_RUNTIME_ERROR
    try:
        if args.baseline_command == "create":
            report = _load_legacy_report_file(args.file)
            _write_or_print(render_baseline(create_baseline(report, mode=args.mode)), args.out)
            return EXIT_OK
        if args.baseline_command == "diff":
            old = _load_json_file(args.old)
            new = _load_json_file(args.new)
            _write_or_print(render_baseline(compare_baselines(old, new)), args.out)
            return EXIT_OK
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"error: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    print("error: unknown baseline subcommand")
    return EXIT_RUNTIME_ERROR


def _cmd_bundle(args: argparse.Namespace) -> int:
    """Validate or replay an evidence bundle offline; constructs no transport."""
    if args.bundle_command is None:
        print("error: bundle requires a subcommand")
        return EXIT_RUNTIME_ERROR
    try:
        with open(args.file, encoding="utf-8") as handle:
            text = handle.read()
        if args.bundle_command == "validate":
            bundle = load_bundle(text)
            print(f"valid: bundle digest={bundle.digest} records={len(bundle.records)}")
            return EXIT_OK
        if args.bundle_command == "replay":
            result = replay_bundle(text)
            confirmed = sum(1 for s in result.findings.values() if s == "confirmed")
            print(
                f"replayed: verified={result.verified} findings={len(result.findings)} "
                f"confirmed={confirmed} gaps={len(result.coverage_gaps)}"
            )
            return EXIT_OK
    except (BundleError, ReplayError, OSError) as exc:
        print(f"invalid: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    print("error: unknown bundle subcommand")
    return EXIT_RUNTIME_ERROR


def _cmd_replay(args: argparse.Namespace) -> int:
    """Offline `replay --bundle FILE [--validate-only]`; constructs no transport.

    Replay is always offline: it verifies the bundle's digests/graph/plan binding
    and reproduces statuses from the stored redacted evidence only, contacting no
    target. A valid bundle exits OK; a tampered one exits nonzero with a scrubbed
    error.
    """
    try:
        with open(args.bundle, encoding="utf-8") as handle:
            text = handle.read()
        result = replay_bundle(text)
    except (BundleError, ReplayError, OSError) as exc:
        print(f"invalid: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    confirmed = sum(1 for s in result.findings.values() if s == "confirmed")
    print(
        f"replayed: verified={result.verified} findings={len(result.findings)} "
        f"confirmed={confirmed} gaps={len(result.coverage_gaps)}"
    )
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Offline ``doctor`` health check.

    Validates the resources that ship in the wheel — metadata/version/license,
    ``py.typed``, every JSON schema, every built-in pack (parsed, validated, and
    digest-verified), the safe payloads, and the report template — through
    ``importlib.resources``. It constructs no transport, sends no network
    traffic, and requires no target. Exits ``0`` only when every check passes;
    otherwise ``1`` with a scrubbed summary.
    """
    from importlib import metadata, resources

    root = resources.files("ai_scan")
    checks: list[dict[str, object]] = []

    def record(name: str, fn: Callable[[], str]) -> None:
        try:
            checks.append({"name": name, "ok": True, "detail": fn()})
        except Exception as exc:  # report any failure, scrubbed
            checks.append({"name": name, "ok": False, "detail": scrub_text(str(exc))})

    try:
        version = metadata.version("ai-scan")
    except metadata.PackageNotFoundError:  # pragma: no cover - always installed
        version = ""

    def _metadata() -> str:
        ver = metadata.version("ai-scan")
        license_expr = metadata.metadata("ai-scan")["License-Expression"]
        if not ver or not license_expr:
            raise ValueError("missing version or license metadata")
        return f"version={ver} license={license_expr}"

    def _py_typed() -> str:
        if not root.joinpath("py.typed").is_file():
            raise FileNotFoundError("py.typed missing")
        return "present"

    def _schemas() -> str:
        count = 0
        for kind, versions in SUPPORTED_SCHEMAS.items():
            for ver in sorted(versions):
                text = root.joinpath(f"schemas/{kind}-v{ver}.schema.json").read_text(
                    encoding="utf-8"
                )
                json.loads(text)
                count += 1
        if count == 0:
            raise ValueError("no schemas packaged")
        return f"{count} valid"

    def _packs() -> str:
        ids = available_packs()
        if not ids:
            raise ValueError("no built-in packs packaged")
        for pack_id in ids:
            load_builtin_pack(pack_id)  # parses, validates, and digest-verifies
        return f"{len(ids)} valid"

    def _payloads() -> str:
        json.loads(root.joinpath("payloads/safe.json").read_text(encoding="utf-8"))
        return "loaded"

    def _report_template() -> str:
        if not root.joinpath("reporting/templates/report.html").is_file():
            raise FileNotFoundError("report.html missing")
        return "present"

    record("metadata", _metadata)
    record("py.typed", _py_typed)
    record("schemas", _schemas)
    record("packs", _packs)
    record("payloads", _payloads)
    record("report-template", _report_template)

    healthy = all(bool(check["ok"]) for check in checks)
    if args.json:
        print(json.dumps({"ok": healthy, "version": version, "checks": checks}, sort_keys=True))
    else:
        print(f"ai-scan doctor: {'healthy' if healthy else 'UNHEALTHY'} (version {version})")
        for check in checks:
            mark = "ok" if check["ok"] else "FAIL"
            print(f"  [{mark}] {check['name']}: {check['detail']}")
    return EXIT_OK if healthy else EXIT_RUNTIME_ERROR


def _load_body_template(args: argparse.Namespace) -> str:
    """Return the POST body template containing the ``*`` marker."""
    template_path = getattr(args, "request_template", None)
    if template_path:
        with open(template_path, encoding="utf-8") as handle:
            template = handle.read()
        if MARKER not in template:
            raise TransportError(
                "request template must contain the '*' prompt marker."
            )
        reject_duplicate_json_keys(template)
        return template
    return '{"input": "*"}'


_DEFAULT_BUDGET = 128
_DEFAULT_MIN_INTERVAL = 0.05
# Legacy ``fingerprint``/``inject``/``assess`` commands predate plan-supplied
# limits, but they must still have an absolute wall-clock ceiling.  Five minutes
# preserves the historical command shape while preventing unbounded transport,
# extraction, and classification work.
_DEFAULT_MAX_DURATION_SECONDS = 300.0


def _make_transport(controller: RequestController) -> Transport:
    return Transport(TransportConfig(), controller=controller)


def _deadline_passed(controller: RequestController) -> bool:
    """True when the run's absolute wall-clock deadline has already elapsed.

    The transport bounds resolution/connect/body reads by this deadline, but
    adapter *extraction* runs after the response returns. Checking here lets each
    responder treat a result whose extraction crossed the deadline as unusable
    (inconclusive) so post-deadline work can never confirm.
    """
    remaining = controller.ledger.remaining()
    return remaining is not None and remaining <= 0


def _build_generic_adapter(target: Target, *, method: str, body_template: str) -> Adapter:
    """Build the compatibility generic HTTP adapter before transport creation."""
    return GenericHttpAdapter(target=target, method=method, body_template=body_template)


# JSON provider adapters that shape an `{model, messages}` request and extract a
# single assistant-content field (never the whole envelope / `thinking`).
_JSON_PROVIDER_ADAPTERS = frozenset(
    {"ollama", "openai_compatible", "anthropic", "gemini"}
)


def _build_plan_adapter(
    plan: Plan, target: Target, args: argparse.Namespace, *, body_template: str
) -> Adapter:
    """Build the adapter the *plan* selected, before any transport is constructed.

    A plan compiled with a JSON provider adapter (e.g. ``ollama``) uses that
    adapter's assistant-content extraction, so envelope metadata such as Ollama's
    ``message.thinking`` never enters confirmation. A JSON provider requires an
    explicit ``--model``. The generic HTTP adapter stays the compatibility default.
    Anything else fails closed with zero requests.
    """
    name = plan.adapter
    if name == "generic_http":
        return _build_generic_adapter(target, method="POST", body_template=body_template)
    if name in _JSON_PROVIDER_ADAPTERS:
        model = getattr(args, "model", None)
        if not model or not str(model).strip():
            raise AdapterError(f"adapter {name!r} requires --model for an active run")
        return default_registry().create(name, target=target, model=str(model))
    raise AdapterError(f"adapter {name!r} is not supported for active run")


def _run_plan_active(
    args: argparse.Namespace,
    target: Target,
) -> int:
    """Execute a compiled plan through the runner after full offline validation."""
    plan = _load_plan_file(args.plan)
    # Bind the *exact* target (scheme/host/port/path/query), not only the origin:
    # a plan compiled for one path may not be run against another.
    if plan.target != target.url:
        raise PlanError("requested target does not exactly match the plan target")
    # Reject a re-digested/tampered plan (widened limits, altered cases, swapped
    # packs, unknown adapter) before any transport is constructed.
    verify_plan_integrity(plan)
    body_template = _load_body_template(args)
    # Build the adapter the plan selected (e.g. ollama) BEFORE transport, so a
    # provider adapter's assistant-content extraction is what feeds confirmation.
    adapter = _build_plan_adapter(plan, target, args, body_template=body_template)
    controller = RequestController(
        max_requests=plan.limits.max_physical_requests,
        min_interval=1.0 / plan.limits.requests_per_second,
        max_duration_seconds=float(plan.limits.max_duration_seconds),
        max_concurrency=plan.limits.max_concurrency,
    )
    transport = _make_transport(controller)
    evidence: list[dict[str, object]] = []
    run_secrets: set[str] = set()
    canary = generate_canary()

    def responder(case: InjectionCase) -> ExchangeOutcome:
        try:
            resp = transport.send_prepared(target, adapter.build_request(case.rendered_prompt))
        except TransportError as exc:
            if getattr(exc, "outcome", None) is not None:
                raise
            return ExchangeOutcome(body="", transport_ok=False)
        run_secrets.update(resp.known_secrets)
        evidence.append(resp.evidence())
        body = adapter.extract(resp)
        if _deadline_passed(controller):
            # Extraction crossed the absolute deadline: this result is unusable
            # (inconclusive) and must not be able to confirm.
            return ExchangeOutcome(
                body="", status=resp.status, transport_ok=False, attempts=resp.attempts
            )
        return ExchangeOutcome(
            body=body,
            status=resp.status,
            redirected=resp.redirected,
            truncated=resp.truncated,
            transport_ok=True,
            attempts=resp.attempts,
            known_secrets=resp.known_secrets,
        )

    result = run_plan(
        plan,
        responder,
        canary=canary,
        goal="planned run",
        checkpoint_path=getattr(args, "checkpoint", None),
        expected_plan_digest=plan.digest,
    )
    budget = {
        "max_requests": controller.max_requests,
        "used": controller.count,
        "runner_count": result.request_count,
        "plan_digest": plan.digest,
    }
    report = Report.build(
        target=target,
        fingerprint=None,
        injection=InjectionResult(
            result.status, list(result.findings), result.request_count, canary
        ),
        request_budget=budget,
        evidence=evidence,
    )
    secrets_seen = frozenset(run_secrets)
    if getattr(args, "out", None):
        write_report_atomic(report, args.out, known_secrets=secrets_seen)
        print(f"report written to {args.out}")
    print(scrub_text(report.console_summary(), secrets_seen))
    if result.coverage_gaps:
        print(f"coverage gaps: {len(result.coverage_gaps)}")
    return exit_code_for(report)


def _run_active(
    args: argparse.Namespace,
    target: Target,
) -> int:
    if args.command == "run":
        return _run_plan_active(args, target)

    raw_method = getattr(args, "method", "POST")
    method = raw_method.upper()
    if method not in ACTIVE_METHODS:
        # Configuration error — reject before any transport is created. The
        # method value is untrusted, so scrub it before printing.
        print(
            f"error: method {scrub_text(raw_method)!r} is not permitted; allowed: "
            f"{', '.join(sorted(ACTIVE_METHODS))}"
        )
        return EXIT_RUNTIME_ERROR

    # Validate the complete offline plan BEFORE constructing any transport or
    # sending a request (safety invariant 1). The payload pack (`--profile`) is
    # resolved up front, so an invalid profile fails closed with zero requests
    # for both `inject` and `assess` (raised InjectionError → exit 1 in main()).
    if args.command == "assess":
        compile_plan(target, getattr(args, "mode", "reliable"), adapter="generic_http")
    needs_injection = args.command in ("inject", "assess")
    pack = load_payloads(getattr(args, "profile", "safe")) if needs_injection else None

    # Validate the request template BEFORE constructing any transport, so an
    # invalid template fails closed (exit 1) with zero transport constructions
    # and zero requests for fingerprint/inject/assess.
    body_template = _load_body_template(args)

    # Build the application-shaping adapter(s) BEFORE constructing transport.
    # Malformed adapter config therefore fails closed with zero requests.
    fingerprint_adapter = (
        _build_generic_adapter(target, method=method, body_template=body_template)
        if args.command in ("fingerprint", "assess")
        else None
    )
    injection_adapter = (
        _build_generic_adapter(target, method="POST", body_template=body_template)
        if needs_injection
        else None
    )

    # A single controller enforces and counts every physical request (retries
    # included) across both engines, so budget and rate are unified.
    controller = RequestController(
        max_requests=_DEFAULT_BUDGET,
        min_interval=_DEFAULT_MIN_INTERVAL,
        max_duration_seconds=_DEFAULT_MAX_DURATION_SECONDS,
    )
    transport = _make_transport(controller)
    evidence: list[dict[str, object]] = []
    run_secrets: set[str] = set()  # reflected secrets collected across the run

    fingerprint_result = None
    injection_result = None

    if args.command in ("fingerprint", "assess"):
        assert fingerprint_adapter is not None

        def probe_responder(probe: Probe) -> ProbeExchange:
            try:
                resp = transport.send_prepared(
                    target, fingerprint_adapter.build_request(probe.prompt)
                )
            except TransportError as exc:
                # Structured denials (scope block / budget exhaustion) are
                # terminal for the whole run — let them reach main()'s outcome
                # mapping. Ordinary connection/timeout failures stay a single
                # inconclusive probe outcome.
                if getattr(exc, "outcome", None) is not None:
                    raise
                return ProbeExchange(probe.id, "", {}, status=0, transport_ok=False)
            run_secrets.update(resp.known_secrets)
            evidence.append(resp.evidence())
            extracted = fingerprint_adapter.extract(resp)
            if _deadline_passed(controller):
                return ProbeExchange(probe.id, "", {}, status=0, transport_ok=False)
            return ProbeExchange(
                probe.id,
                extracted,
                resp.headers,
                status=resp.status,
                redirected=resp.redirected,
                truncated=resp.truncated,
                transport_ok=True,
                attempts=resp.attempts,
            )

        fingerprint_result = run_fingerprint(DEFAULT_PROBES, probe_responder)

    if needs_injection:
        assert pack is not None  # resolved above, before transport construction
        assert injection_adapter is not None
        canary = generate_canary()

        def inject_responder(case: InjectionCase) -> ExchangeOutcome:
            try:
                resp = transport.send_prepared(
                    target, injection_adapter.build_request(case.rendered_prompt)
                )
            except TransportError as exc:
                # Structured denials are terminal for the run (see probe path);
                # ordinary transport failures remain one inconclusive outcome.
                if getattr(exc, "outcome", None) is not None:
                    raise
                return ExchangeOutcome(body="", transport_ok=False)
            run_secrets.update(resp.known_secrets)
            evidence.append(resp.evidence())
            body = injection_adapter.extract(resp)
            if _deadline_passed(controller):
                return ExchangeOutcome(
                    body="", status=resp.status, transport_ok=False, attempts=resp.attempts
                )
            return ExchangeOutcome(
                body=body,
                status=resp.status,
                redirected=resp.redirected,
                truncated=resp.truncated,
                transport_ok=True,
                attempts=resp.attempts,
            )

        injection_result = run_injection(
            pack,
            inject_responder,
            canary=canary,
            goal=getattr(args, "goal", "") or "assessment",
        )

    budget = {"max_requests": controller.max_requests, "used": controller.count}

    report = Report.build(
        target=target,
        fingerprint=fingerprint_result,
        injection=injection_result,
        request_budget=budget,
        evidence=evidence,
    )

    secrets_seen = frozenset(run_secrets)
    if getattr(args, "out", None):
        write_report_atomic(report, args.out, known_secrets=secrets_seen)
        print(f"report written to {args.out}")
    # Final central scrub at the console boundary.
    print(scrub_text(report.console_summary(), secrets_seen))
    return exit_code_for(report)


def _cmd_validate_config(args: argparse.Namespace) -> int:
    """Offline document validation. Never constructs an adapter or transport."""
    try:
        with open(args.file, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"error: cannot read file: {scrub_text(f'{args.file}: {exc.strerror}')}")
        return EXIT_RUNTIME_ERROR
    try:
        load_document(text, args.kind)
    except ConfigError as exc:
        print(f"invalid: {scrub_text(str(exc))}")
        return EXIT_RUNTIME_ERROR
    print(f"valid: {scrub_text(args.file)} conforms to {args.kind} schema")
    return EXIT_OK


def _cmd_packs(args: argparse.Namespace) -> int:
    """Offline pack registry commands. Never constructs adapters or transport."""
    if args.packs_command is None:
        print("error: packs requires a subcommand")
        return EXIT_RUNTIME_ERROR
    if args.packs_command == "list":
        try:
            packs = (
                resolve_packs(args.mode)
                if args.mode
                else [load_builtin_pack(p) for p in available_packs()]
            )
        except PackResolutionError as exc:
            print(f"error: {scrub_text(str(exc))}")
            return EXIT_RUNTIME_ERROR
        for pack in packs:
            modes = ",".join(sorted(pack.modes))
            print(f"{pack.id}\tversion={pack.version}\tmodes={modes}\tdigest={pack.digest}")
        return EXIT_OK
    if args.packs_command == "validate":
        try:
            if args.pack in available_packs():
                pack = load_builtin_pack(args.pack)
            else:
                with open(args.pack, encoding="utf-8") as handle:
                    text = handle.read()
                # Use the same parser as built-in loading so the CLI rejects
                # duplicate JSON keys (and every other schema check) identically.
                pack = parse_pack_document(text, verify=True)
        except (OSError, PackError, PackResolutionError, ValueError) as exc:
            print(f"invalid: {scrub_text(str(exc))}")
            return EXIT_RUNTIME_ERROR
        print(f"valid: {pack.id} version={pack.version} digest={pack.digest}")
        return EXIT_OK
    print("error: unknown packs subcommand")
    return EXIT_RUNTIME_ERROR

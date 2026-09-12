"""Command-line entry point and argument parsing for ai-scan.

Exit codes are stable and part of the tool's contract:

* ``0`` — completed, no confirmed findings
* ``1`` — runtime/configuration failure
* ``2`` — authorization denied or invalid
* ``3`` — confirmed security finding
* ``4`` — inconclusive assessment
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from ai_scan.authorization import (
    AuthorizationError,
    Receipt,
    authorize_for_target,
    load_receipt,
    validate_receipt,
    write_receipt,
)
from ai_scan.core.config import SUPPORTED_SCHEMAS, load_document
from ai_scan.core.errors import ConfigError
from ai_scan.fingerprint import DEFAULT_PROBES, ProbeExchange, run_fingerprint
from ai_scan.injection import (
    ExchangeOutcome,
    InjectionCase,
    generate_canary,
    load_payloads,
    run_injection,
)
from ai_scan.injection import (
    InjectionError as _InjectionError,
)
from ai_scan.models import Probe
from ai_scan.reporting import Report, exit_code_for, write_report_atomic
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

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_AUTH_DENIED = 2
EXIT_CONFIRMED_FINDING = 3
EXIT_INCONCLUSIVE = 4

PROG = "ai-scan"


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that maps usage/config errors to exit code ``1``.

    argparse's default is exit code ``2``, which would collide with the tool's
    documented ``2`` for authorization failures. ``--help`` still exits ``0``.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_RUNTIME_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser with all subcommands."""
    parser = _ArgumentParser(
        prog=PROG,
        description="Authorized LLM assessment: behavioral fingerprinting and "
        "safe prompt-injection testing.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_authorize = subparsers.add_parser(
        "authorize",
        help="Interactively create a target-bound authorization receipt.",
    )
    p_authorize.add_argument("--target", required=True, help="Target URL.")
    p_authorize.add_argument("--client", required=True, help="Client name.")
    p_authorize.add_argument("--engagement", required=True, help="Engagement ID.")
    p_authorize.add_argument("--expires", required=True, help="Expiry date, YYYY-MM-DD.")
    p_authorize.add_argument("--out", required=True, help="Receipt output path.")

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

    p_validate = subparsers.add_parser(
        "validate-receipt",
        help="Validate an authorization receipt against a target.",
    )
    p_validate.add_argument("--auth-receipt", required=True, help="Receipt file path.")
    p_validate.add_argument("--target", required=True, help="Target URL.")

    p_validate_config = subparsers.add_parser(
        "validate-config",
        help="Validate a configuration/plan document against its packaged schema.",
    )
    p_validate_config.add_argument(
        "--kind", required=True, choices=sorted(SUPPORTED_SCHEMAS), help="Document kind."
    )
    p_validate_config.add_argument("--file", required=True, help="Path to the JSON document.")

    return parser


def _add_active_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments shared by active (network-touching) subcommands."""
    parser.add_argument("--target", required=True, help="Target URL.")
    parser.add_argument("--request-template", help="Burp-style request template file.")
    parser.add_argument("--auth-receipt", help="Authorization receipt file path.")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; require a valid receipt.",
    )
    parser.add_argument("--out", help="Report output path.")


def main(
    argv: Sequence[str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> int:
    """Program entry point. Returns a process exit code.

    Args:
        argv: Argument vector (defaults to ``sys.argv[1:]``).
        prompt: Injected confirmation-prompt callable (defaults to
            :func:`input`); used to keep the interactive gate testable.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_usage()
        return EXIT_RUNTIME_ERROR

    ask = prompt if prompt is not None else input

    if args.command == "authorize":
        return _cmd_authorize(args, ask)
    if args.command == "validate-receipt":
        return _cmd_validate_receipt(args)
    if args.command == "validate-config":
        return _cmd_validate_config(args)

    # Active, network-touching commands. Fail closed before any transport.
    try:
        target = authorize_for_target(
            args.target,
            receipt_path=args.auth_receipt,
            non_interactive=args.non_interactive,
            prompt=ask,
        )
    except AuthorizationError as exc:
        print(f"authorization: {exc}")
        return EXIT_AUTH_DENIED

    auth_meta = _authorization_metadata(args)
    try:
        return _run_active(args, target, auth_meta)
    except (TransportError, _InjectionError, OSError) as exc:
        # Budget exhaustion and scope denial carry a structured outcome and the
        # accurate per-kind physical totals; surface them with the documented
        # exit codes instead of a generic runtime error.
        outcome = getattr(exc, "outcome", None)
        totals = getattr(exc, "totals", None)
        suffix = f" (physical attempts: {totals})" if totals else ""
        if outcome == "blocked":
            print(f"blocked: {exc}{suffix}")
            return EXIT_AUTH_DENIED
        if outcome == "inconclusive":
            print(f"inconclusive: {exc}{suffix}")
            return EXIT_INCONCLUSIVE
        print(f"error: {exc}")
        return EXIT_RUNTIME_ERROR


def _authorization_metadata(args: argparse.Namespace) -> dict[str, object]:
    """Collect secret-free authorization metadata for the report."""
    if args.auth_receipt:
        receipt = load_receipt(args.auth_receipt)
        return {
            "mode": "receipt",
            "client": receipt.client,
            "engagement": receipt.engagement,
            "receipt_origin": receipt.origin,
            "expires": receipt.expires,
        }
    return {"mode": "interactive"}


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
        return template
    return '{"input": "*"}'


_DEFAULT_BUDGET = 128
_DEFAULT_MIN_INTERVAL = 0.05


def _make_transport(controller: RequestController) -> Transport:
    return Transport(TransportConfig(), controller=controller)


def _run_active(
    args: argparse.Namespace,
    target: Target,
    auth_meta: dict[str, object],
) -> int:
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
    needs_injection = args.command in ("inject", "assess")
    pack = load_payloads(getattr(args, "profile", "safe")) if needs_injection else None

    # Validate the request template BEFORE constructing any transport, so an
    # invalid template fails closed (exit 1) with zero transport constructions
    # and zero requests for fingerprint/inject/assess.
    body_template = _load_body_template(args)

    # A single controller enforces and counts every physical request (retries
    # included) across both engines, so budget and rate are unified.
    controller = RequestController(
        max_requests=_DEFAULT_BUDGET, min_interval=_DEFAULT_MIN_INTERVAL
    )
    transport = _make_transport(controller)
    evidence: list[dict[str, object]] = []
    run_secrets: set[str] = set()  # reflected secrets collected across the run

    fingerprint_result = None
    injection_result = None

    if args.command in ("fingerprint", "assess"):

        def probe_responder(probe: Probe) -> ProbeExchange:
            try:
                resp = transport.send(
                    target,
                    method=method,
                    prompt=probe.prompt,
                    body_template=body_template,
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
            return ProbeExchange(
                probe.id,
                resp.body,
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
        canary = generate_canary()

        def inject_responder(case: InjectionCase) -> ExchangeOutcome:
            try:
                resp = transport.send(
                    target,
                    method="POST",
                    prompt=case.rendered_prompt,
                    body_template=body_template,
                )
            except TransportError as exc:
                # Structured denials are terminal for the run (see probe path);
                # ordinary transport failures remain one inconclusive outcome.
                if getattr(exc, "outcome", None) is not None:
                    raise
                return ExchangeOutcome(body="", transport_ok=False)
            run_secrets.update(resp.known_secrets)
            evidence.append(resp.evidence())
            return ExchangeOutcome(
                body=resp.body,
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
        authorization=auth_meta,
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


def _cmd_authorize(args: argparse.Namespace, ask: Callable[[str], str]) -> int:
    try:
        target = normalize_target(args.target)
    except TargetError as exc:
        print(f"error: {exc}")
        return EXIT_RUNTIME_ERROR

    from ai_scan.authorization import interactive_authorize

    if not interactive_authorize(target, ask):
        print("authorization: denied by operator; no receipt written.")
        return EXIT_AUTH_DENIED

    try:
        receipt = Receipt.create(
            target=target,
            client=args.client,
            engagement=args.engagement,
            expires=args.expires,
        )
        write_receipt(receipt, args.out)
    except AuthorizationError as exc:
        print(f"error: {exc}")
        return EXIT_RUNTIME_ERROR
    except OSError as exc:
        print(f"error: cannot write receipt: {exc.strerror}")
        return EXIT_RUNTIME_ERROR

    print(f"authorized: receipt for {receipt.origin} written to {args.out}")
    return EXIT_OK


def _cmd_validate_config(args: argparse.Namespace) -> int:
    """Offline document validation. Never constructs an adapter or transport."""
    try:
        with open(args.file, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc.strerror}")
        return EXIT_RUNTIME_ERROR
    try:
        load_document(text, args.kind)
    except ConfigError as exc:
        print(f"invalid: {exc}")
        return EXIT_RUNTIME_ERROR
    print(f"valid: {args.file} conforms to {args.kind} schema")
    return EXIT_OK


def _cmd_validate_receipt(args: argparse.Namespace) -> int:
    try:
        target = normalize_target(args.target)
    except TargetError as exc:
        print(f"error: {exc}")
        return EXIT_RUNTIME_ERROR
    try:
        receipt = load_receipt(args.auth_receipt)
        validate_receipt(receipt, target)
    except AuthorizationError as exc:
        print(f"invalid: {exc}")
        return EXIT_AUTH_DENIED
    print(f"valid: receipt authorizes {receipt.origin} (expires {receipt.expires})")
    return EXIT_OK

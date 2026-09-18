"""Explicit trusted local-ledger adapters for non-accounting behavior tests.

These helpers model fixture-side physical acquisition independently of the public
engine. Security/accounting tests import production engines directly.
"""

from __future__ import annotations

from typing import Any

from ai_scan.attacks.base import run_attack as _run_attack
from ai_scan.fingerprint import run_fingerprint as _run_fingerprint
from ai_scan.injection import run_injection as _run_injection
from ai_scan.injection import run_injection_pack as _run_injection_pack
from ai_scan.orchestration.runner import run_plan as _run_plan


class _FixtureLedger:
    def __init__(self) -> None:
        self.count = 0


def _account(responder: Any, ledger: _FixtureLedger):  # type: ignore[no-untyped-def]
    def wrapped(value: Any) -> Any:
        try:
            outcome = responder(value)
        except BaseException:
            raise
        ledger.count += 1
        return outcome

    return wrapped


def _run(engine: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if kwargs.get("physical_request_count") is not None:
        return engine(*args, **kwargs)
    ledger = _FixtureLedger()
    positional = list(args)
    positional[1] = _account(positional[1], ledger)
    kwargs["physical_request_count"] = ledger
    return engine(*positional, **kwargs)


def run_fingerprint(*args: Any, **kwargs: Any) -> Any:
    return _run(_run_fingerprint, args, kwargs)


def run_injection(*args: Any, **kwargs: Any) -> Any:
    return _run(_run_injection, args, kwargs)


def run_injection_pack(*args: Any, **kwargs: Any) -> Any:
    return _run(_run_injection_pack, args, kwargs)


def run_attack(*args: Any, **kwargs: Any) -> Any:
    return _run(_run_attack, args, kwargs)


def run_plan(*args: Any, **kwargs: Any) -> Any:
    return _run(_run_plan, args, kwargs)

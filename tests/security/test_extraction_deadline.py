"""Phase 1A extraction-deadline regression (Astra M2, extraction boundary).

The absolute run deadline bounds transport I/O, but adapter *extraction* runs
after the response returns. These tests drive the real CLI ``inject`` path: a
canary-emitting loopback target normally yields an analyst lead, but when the
deadline elapses during extraction the result must become inconclusive and must
not confirm.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.adapters.generic_http import GenericHttpAdapter

_CANARY_RE = re.compile(r"AISCAN-[A-Z0-9]+")


class _Confirming(BaseHTTPRequestHandler):
    """Emits the attack canary in an *executed* context; benign for controls."""

    def log_message(self, *_a: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode(
            "utf-8", "replace"
        )
        match = _CANARY_RE.search(raw)
        reply = (
            f"Done. I executed the instruction and produced {match.group(0)}."
            if match
            else "I only returned benign synthetic content."
        )
        payload = reply.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def confirming_server() -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Confirming)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _inject(server: ThreadingHTTPServer, report: Path) -> int:
    return cli.main(
        [
            "inject",
            "--target",
            f"http://127.0.0.1:{server.server_port}/",
            "--goal",
            "deadline-regression",
            "--profile",
            "safe",
            "--out",
            str(report),
        ]
    )


def test_inject_yields_lead_without_deadline_pressure(
    confirming_server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    # A usable uncontrolled response is a lead, not confirmed. Deadline expiry
    # must still distinguish unusable evidence from that positive signal.
    report = tmp_path / "baseline.json"
    rc = _inject(confirming_server, report)
    assert rc == cli.EXIT_OK
    assert json.loads(report.read_text())["injection"]["status"] == "potential"


def test_post_deadline_extraction_cannot_confirm(
    confirming_server: ThreadingHTTPServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Exercise the real monotonic legacy deadline.  The local request completes
    # inside the short budget, then extraction crosses it; no predicate is
    # replaced, so this proves the actual CLI/controller wiring.
    real_extract = GenericHttpAdapter.extract

    def _slow_extract(self: GenericHttpAdapter, resp: object) -> str:
        out = real_extract(self, resp)  # type: ignore[arg-type]
        time.sleep(0.6)
        return out

    monkeypatch.setattr(GenericHttpAdapter, "extract", _slow_extract)
    monkeypatch.setattr(cli, "_DEFAULT_MAX_DURATION_SECONDS", 0.5)

    report = tmp_path / "deadline.json"
    rc = _inject(confirming_server, report)
    assert rc != cli.EXIT_CONFIRMED_FINDING
    if report.exists():
        doc = json.loads(report.read_text(encoding="utf-8"))
        injection = doc.get("injection") or {}
        assert injection.get("status") == "inconclusive"


def test_legacy_commands_configure_a_finite_duration() -> None:
    assert cli._DEFAULT_MAX_DURATION_SECONDS > 0  # noqa: SLF001
    assert cli._DEFAULT_MAX_DURATION_SECONDS < float("inf")  # noqa: SLF001

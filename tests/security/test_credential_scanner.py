"""W4 — deterministic local credential scanner (release gate).

Secret-shaped literals are constructed at runtime (never written verbatim in
this source), so the release gate that scans ``tests/`` does not trip on this
file itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import credential_scan as cs  # noqa: E402


def test_flags_assignment_form() -> None:
    # A realistic high-entropy secret value, assembled from chunks so no
    # contiguous secret literal appears in this source file.
    value = "".join(["x7Qk", "9Lm2", "Pv4Z", "aE1t", "Rc8W", "uH3n"])
    line = "api_key" + " = " + '"' + value + '"'
    findings = cs.scan_text(line, path="x.py")
    assert findings
    assert all(value not in f.redacted for f in findings)


@pytest.mark.parametrize(
    "token",
    [
        "AKIA" + "ABCDEFGHIJKLMNOP",  # AWS access key id
        "ghp_" + ("a" * 36),  # GitHub PAT
        "xoxb-" + "123456789012-123456789012-" + ("a" * 24),  # Slack bot token
        "AIza" + ("A" * 35),  # Google API key
    ],
)
def test_flags_common_token_prefixes(token: str) -> None:
    assert cs.scan_text(f"value = '{token}'", path="x.py")


def test_flags_private_key_block() -> None:
    header = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
    assert cs.scan_text(header, path="id_rsa")


def test_flags_bearer_and_basic_headers() -> None:
    bearer = "Authorization: Bearer " + ("a" * 40)
    basic = "Authorization: Basic " + ("b" * 40)
    assert cs.scan_text(bearer, path="h.txt")
    assert cs.scan_text(basic, path="h.txt")


def test_flags_credential_url() -> None:
    url = "https://" + "user" + ":" + "s3cr3tp4ss" + "@example.com/path"
    assert cs.scan_text(url, path="u.txt")


def test_flags_env_style_value() -> None:
    line = "DB_PASSWORD" + "=" + "supersecretvalue123"
    assert cs.scan_text(line, path=".env")


def test_ignores_benign_text() -> None:
    assert cs.scan_text("the quick brown fox jumps over the lazy dog", path="a.txt") == []
    # A canary is public and not credential-shaped.
    assert cs.scan_text("model output AISCAN-ABCD1234 executed", path="b.txt") == []


def test_scan_tree_reads_untracked_new_files(tmp_path: Path) -> None:
    value = "".join(["Q9x", "2Lm", "Pv4", "aE1", "Rc8", "uH3", "nB6", "kZ0"])  # high-entropy
    (tmp_path / "new_fixture.txt").write_text(
        "aws_secret_access_key" + " = " + '"' + value + '"', encoding="utf-8"
    )
    findings = cs.scan_tree(tmp_path)
    assert findings
    assert all(value not in f.redacted for f in findings)


def test_line_marker_suppresses_intentional_dummy(tmp_path: Path) -> None:
    token = "ghp_" + ("a" * 36)
    marked = f"_DUMMY = '{token}'  # pragma: allowlist secret"
    assert cs.scan_text(marked, path="x.py") == []
    # The same literal without the marker is still flagged.
    assert cs.scan_text(f"_DUMMY = '{token}'", path="x.py")


def test_scan_tree_fails_closed_on_binary(tmp_path: Path) -> None:
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\xff\xfe" * 10)
    findings = cs.scan_tree(tmp_path)
    assert any(f.kind == "unreadable" for f in findings)


def test_scan_tree_allowlist_is_narrow(tmp_path: Path) -> None:
    blob = tmp_path / "intentional.bin"
    blob.write_bytes(b"\x00\xff" * 10)
    # Allowlisting the specific relative path suppresses only that file.
    findings = cs.scan_tree(tmp_path, allowlist=frozenset({"intentional.bin"}))
    assert findings == []


def test_main_exit_code_and_no_raw_secret(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    secret = "AKIA" + "ZZZZZZZZZZZZZZZZ"
    (tmp_path / "leak.txt").write_text(f"key={secret}", encoding="utf-8")
    rc = cs.main(["--root", str(tmp_path)])
    assert rc != 0
    out = capsys.readouterr()
    assert secret not in out.out
    assert secret not in out.err


def test_no_whole_file_default_allowlist() -> None:
    # The whole-file allowlist debt is closed: there is no built-in file allowlist.
    assert not hasattr(cs, "DEFAULT_ALLOWLIST")


@pytest.mark.parametrize(
    "rel",
    [
        "tests/security/test_recursive_redaction.py",
        "tests/unit/transport/test_records.py",
        "tests/security/test_config_fail_closed.py",
    ],
)
def test_scan_tree_catches_new_secret_in_allowlisted_path(tmp_path: Path, rel: str) -> None:
    # A NEW unmarked secret added to a formerly whole-file-allowlisted path must
    # now be caught by scan_tree (not just scan_text).
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    token = "ghp_" + ("z" * 36)
    target.write_text(f"_LEAK = '{token}'\n", encoding="utf-8")
    findings = cs.scan_tree(tmp_path)
    assert any(f.path == rel for f in findings)
    assert all(token not in f.redacted for f in findings)


def test_scan_tree_allows_marked_vector_in_formerly_allowlisted_file(tmp_path: Path) -> None:
    rel = "tests/security/test_recursive_redaction.py"
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    token = "ghp_" + ("z" * 36)
    target.write_text(f"_VECTOR = '{token}'  # pragma: allowlist secret\n", encoding="utf-8")
    assert cs.scan_tree(tmp_path) == []


def test_repo_tree_is_clean() -> None:
    """The real repository must contain no unmarked credential-shaped values."""
    findings = cs.scan_tree(_REPO_ROOT)
    assert findings == [], [f"{f.path}:{f.line}:{f.kind}" for f in findings]

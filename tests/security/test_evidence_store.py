"""Evidence artifact store security invariants."""

from __future__ import annotations

import os

import pytest

from ai_scan.evidence_graph import ArtifactStore, StoreError


def test_store_writes_digest_named_private_artifact(tmp_path) -> None:
    store = ArtifactStore(tmp_path)
    ref = store.write_json({"kind": "node", "value": "safe"})

    assert ref.path.name == f"{ref.digest}.json"
    assert ref.path.stat().st_mode & 0o777 == 0o600
    loaded = store.read_json(ref.digest)
    assert loaded["kind"] == "node"
    assert loaded["digest"] == ref.digest


def test_store_scrubs_before_persisting_and_hashing(tmp_path) -> None:
    store = ArtifactStore(tmp_path)
    token = "ghp_abcdefghijklmnopqrstuvwxyz123456"  # pragma: allowlist secret
    ref = store.write_json({"headers": {"Authorization": f"Bearer {token}"}})
    text = ref.path.read_text(encoding="utf-8")

    assert token not in text
    assert "REDACTED" in text
    assert store.read_json(ref.digest)["digest"] == ref.digest


def test_store_rejects_traversal_digest(tmp_path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(StoreError):
        store.read_json("../outside")


def test_store_detects_tampering(tmp_path) -> None:
    store = ArtifactStore(tmp_path)
    ref = store.write_json({"kind": "node", "value": "safe"})
    ref.path.write_text(
        '{"digest":"' + ref.digest + '","kind":"node","value":"changed"}',
        encoding="utf-8",
    )

    with pytest.raises(StoreError, match="verification"):
        store.read_json(ref.digest)


def test_store_overwrites_no_existing_artifact(tmp_path) -> None:
    store = ArtifactStore(tmp_path)
    ref1 = store.write_json({"kind": "node", "value": "same"})
    before = os.stat(ref1.path).st_ino
    ref2 = store.write_json({"kind": "node", "value": "same"})

    assert ref1 == ref2
    assert os.stat(ref2.path).st_ino == before

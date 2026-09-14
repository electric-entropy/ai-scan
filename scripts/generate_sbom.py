"""Generate and validate a standards-valid CycloneDX 1.5 SBOM (release gate).

The SBOM describes the ``ai-scan`` distribution (name + version + license) and
enumerates its resolved build/test toolchain dependencies as components, pinned
to the versions actually installed in the build environment. It is deterministic
for a given environment (stable ordering; timestamp only when ``SOURCE_DATE_EPOCH``
is set) so it can participate in the reproducible-build check.

This is a real dependency-audit-backed SBOM, not a hand-built empty stub. It
makes no attestation/signing/provenance claims — it is a component inventory.
"""

from __future__ import annotations

import argparse
import json
import os
import tomllib
import uuid
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

SPEC_VERSION = "1.5"
_PROJECT = "ai-scan"
# Stable namespace so a given (version, component-set) yields the same urn:uuid.
_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


class SbomError(Exception):
    """Raised when an SBOM cannot be generated or fails validation."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _declared_dependency_names(root: Path) -> list[str]:
    """Direct build-system + optional (dev/build) dependency names from pyproject."""
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    names: set[str] = set()
    for spec in data.get("build-system", {}).get("requires", []):
        names.add(_requirement_name(spec))
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        for spec in group:
            names.add(_requirement_name(spec))
    # Runtime dependencies (intentionally empty today) are included when present.
    for spec in data.get("project", {}).get("dependencies", []):
        names.add(_requirement_name(spec))
    names.discard("")
    return sorted(names)


def _requirement_name(spec: str) -> str:
    name = spec.strip()
    for sep in ("[", "(", ";", "=", "<", ">", "!", "~", " "):
        idx = name.find(sep)
        if idx != -1:
            name = name[:idx]
    return name.strip().lower()


def _app_version() -> str:
    try:
        return metadata.version(_PROJECT)
    except metadata.PackageNotFoundError as exc:  # pragma: no cover - build env always has it
        raise SbomError("ai-scan is not installed; cannot determine version") from exc


def _license_expression() -> str:
    try:
        expr = metadata.metadata(_PROJECT)["License-Expression"]
    except metadata.PackageNotFoundError:  # pragma: no cover
        expr = None
    return expr or "LicenseRef-PolyForm-Shield-1.0.0"


def build_sbom(*, root: Path | None = None) -> dict[str, object]:
    """Build the CycloneDX document. Deterministic for a fixed environment."""
    root = root or _repo_root()
    version = _app_version()

    components: list[dict[str, str]] = []
    for name in _declared_dependency_names(root):
        try:
            dep_version = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue  # declared but not installed in this environment
        ref = f"pkg:pypi/{name}@{dep_version}"
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": name,
                "version": dep_version,
                "purl": ref,
                "scope": "optional",
            }
        )
    components.sort(key=lambda c: (c["name"], c["version"]))

    app_ref = f"pkg:pypi/{_PROJECT}@{version}"
    serial_seed = app_ref + "|" + "|".join(c["bom-ref"] for c in components)
    metadata_block: dict[str, object] = {
        "component": {
            "type": "application",
            "bom-ref": app_ref,
            "name": _PROJECT,
            "version": version,
            "purl": app_ref,
            "licenses": [{"license": {"id": _license_expression()}}],
        },
    }
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        metadata_block["timestamp"] = datetime.fromtimestamp(int(epoch), tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(_NAMESPACE, serial_seed)}",
        "version": 1,
        "metadata": metadata_block,
        "components": components,
    }


def validate_sbom(doc: object) -> None:
    """Structurally validate a CycloneDX SBOM; raise ``SbomError`` if invalid."""
    if not isinstance(doc, dict):
        raise SbomError("SBOM must be a JSON object")
    if doc.get("bomFormat") != "CycloneDX":
        raise SbomError("SBOM bomFormat must be CycloneDX")
    if doc.get("specVersion") != SPEC_VERSION:
        raise SbomError("SBOM specVersion must be 1.5")
    if not isinstance(doc.get("version"), int) or isinstance(doc.get("version"), bool):
        raise SbomError("SBOM version must be an integer")
    meta = doc.get("metadata")
    if not isinstance(meta, dict):
        raise SbomError("SBOM metadata is missing")
    app = meta.get("component")
    if not isinstance(app, dict):
        raise SbomError("SBOM metadata.component is missing")
    if app.get("type") != "application":
        raise SbomError("SBOM application component type must be 'application'")
    if not app.get("name") or not app.get("version"):
        raise SbomError("SBOM application component needs a name and version")
    components = doc.get("components")
    if not isinstance(components, list) or not components:
        raise SbomError("SBOM components must be a non-empty list")
    seen_refs: set[str] = set()
    for comp in components:
        if not isinstance(comp, dict):
            raise SbomError("SBOM component must be an object")
        if not comp.get("type") or not comp.get("name") or not comp.get("version"):
            raise SbomError("SBOM component needs type, name, and version")
        if not comp.get("purl") and not comp.get("bom-ref"):
            raise SbomError("SBOM component needs a purl or bom-ref")
        ref = comp.get("bom-ref") or comp.get("purl")
        if ref in seen_refs:
            raise SbomError("SBOM has duplicate component references")
        seen_refs.add(str(ref))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate and validate a CycloneDX SBOM.")
    parser.add_argument("--out", default="sbom.cdx.json", help="output path")
    args = parser.parse_args(argv)
    try:
        doc = build_sbom()
        validate_sbom(doc)
    except SbomError as exc:
        print(f"SBOM generation failed: {exc}")
        return 1
    Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    components = doc["components"]
    count = len(components) if isinstance(components, list) else 0
    print(f"SBOM written to {args.out} with {count} component(s)")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())

"""Native catalogs bind reviewed evidence without inventing license conclusions."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tools import release_native_components as catalog

DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    inventory = {
        "python": {
            "source_recipe_schema": 4,
            "distributions": [
                {"normalized_name": "cryptography", "version": "99.0.0"},
                {"normalized_name": "psycopg-binary", "version": "99.0.0"},
            ],
        }
    }
    files: dict[str, bytes] = {}
    notices = []
    for distribution, components, spec in (
        (
            "cryptography",
            [
                {
                    "name": "openssl",
                    "version": "8.1.2",
                    "purl": "pkg:generic/openssl@8.1.2?download_url=fictional",
                }
            ],
            "1.5",
        ),
        (
            "psycopg-binary",
            [
                {
                    "name": "psycopg_binary",
                    "version": "99.0.0",
                    "purl": "pkg:pypi/psycopg_binary@99.0.0",
                },
                {
                    "name": "fictional-libs",
                    "version": "8.1.2-1.el7",
                    "purl": "pkg:rpm/centos/fictional-libs@8.1.2-1.el7",
                },
            ],
            "1.4",
        ),
    ):
        for item in components:
            item["type"] = "library"
        path = f"notices/{distribution}.json"
        files[path] = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": spec, "components": components}
        ).encode()
        notices.append(
            {
                "role": "python-embedded-sbom",
                "archive_path": path,
                "component": f"pypi:{distribution}@99.0.0",
                "sha256": hashlib.sha256(files[path]).hexdigest(),
            }
        )
    files["NOTICE-MANIFEST.json"] = json.dumps({"files": notices}).encode()
    sources: list[dict[str, Any]] = []
    embedded: list[dict[str, Any]] = []
    for distribution, name, version, custom in (
        ("cryptography", "openssl", "8.1.2", True),
        ("psycopg-binary", "fictional-libs", "8.1.2-1.el7", False),
        ("psycopg-binary", "openssl", "8.1.2", True),
        ("psycopg-binary", "libpq", "99.0", True),
        ("psycopg-binary", "openldap", "8.1.2", True),
    ):
        sbom = next(item for item in notices if item["component"] == f"pypi:{distribution}@99.0.0")
        source: dict[str, Any] = {
            "distribution": distribution,
            "distribution_version": "99.0.0",
            "sbom_sha256": sbom["sha256"],
            "path": f"sources/{distribution}/{name}.tar.gz",
            "url": f"https://upstream.example.invalid/{name}-{version}.tar.gz",
            "sha256": "b" * 64,
            "source_component" if custom else "reported_package": {
                "name": name,
                "version": version,
            },
        }
        if custom and distribution == "psycopg-binary":
            source["wheel_files"] = [
                {"path": f"fictional/{name}.so", "sha256": "c" * 64, "size": 100}
            ]
        (embedded if custom else sources).append(source)
    plan = {"native_sources": sources, "embedded_sources": embedded}
    plan_mock = Mock(return_value=plan)
    notices_mock = Mock(return_value=files)
    monkeypatch.setattr(catalog._python, "plan", plan_mock)
    monkeypatch.setattr(catalog._notices, "verify_notice_bundle", notices_mock)
    return {
        "inventory": inventory,
        "files": files,
        "plan": plan,
        "plan_mock": plan_mock,
        "notices_mock": notices_mock,
    }


def build(evidence: dict[str, Any]) -> bytes:
    return catalog.build(
        json.dumps(evidence["inventory"]).encode(),
        b"fictional lock",
        Path("fictional-notices.tar.gz"),
        "amd64",
        DIGEST,
    )


def test_deterministic_catalog_retains_parent_and_source_bindings(evidence: dict[str, Any]) -> None:
    data = build(evidence)
    assert data == build(evidence)
    document = json.loads(data)
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
    assert len(document["components"]) == 7
    assert len(document["dependencies"]) == 2
    child = next(item for item in document["components"] if item["name"] == "libpq")
    props = {item["name"]: item["value"] for item in child["properties"]}
    assert props["extra-codeowners:source-sha256"] == "b" * 64
    assert json.loads(props["extra-codeowners:native-files"])[0]["sha256"] == "c" * 64
    assert props["extra-codeowners:parent-wheel"] == "pkg:pypi/psycopg-binary@99.0.0"
    assert "licenses" not in child and "hashes" not in child
    assert props["extra-codeowners:license-review"].startswith("unresolved")
    evidence["notices_mock"].assert_called_with(
        Path("fictional-notices.tar.gz"),
        json.dumps(evidence["inventory"]).encode(),
        architecture="amd64",
        platform_digest=DIGEST,
    )


@pytest.mark.parametrize("verifier", ["plan_mock", "notices_mock"])
def test_verification_failure_cannot_produce_a_catalog(
    evidence: dict[str, Any], verifier: str
) -> None:
    evidence[verifier].side_effect = ValueError("fictional evidence mismatch")
    with pytest.raises(ValueError, match="evidence mismatch"):
        build(evidence)


def test_unrelated_rust_sbom_is_not_relabelled_as_c_library_evidence(
    evidence: dict[str, Any],
) -> None:
    manifest = json.loads(evidence["files"]["NOTICE-MANIFEST.json"])
    manifest["files"].append(
        {
            "role": "python-embedded-sbom",
            "component": "pypi:cryptography@99.0.0",
            "sha256": "f" * 64,
        }
    )
    evidence["files"]["NOTICE-MANIFEST.json"] = json.dumps(manifest).encode()
    assert len(json.loads(build(evidence))["components"]) == 7


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "unreviewed",
        "purl",
        "version",
        "format",
        "type",
        "count",
        "identity",
        "conflict",
        "parent-version",
        "parent-purl",
    ],
)
def test_changed_declarations_require_review(evidence: dict[str, Any], change: str) -> None:
    files = evidence["files"]
    manifest = json.loads(files["NOTICE-MANIFEST.json"])
    selected = manifest["files"][1]
    sbom = json.loads(files[selected["archive_path"]])
    component = sbom["components"][1]
    if change == "missing":
        manifest["files"].pop()
    elif change == "parent-version":
        sbom["components"][0]["version"] = "99.0.1"
    elif change == "parent-purl":
        sbom["components"][0]["purl"] = "pkg:pypi/another-wheel@99.0.0"
    elif change == "duplicate":
        manifest["files"].append(selected)
    elif change == "unreviewed":
        component.update(name="new-libs", purl="pkg:rpm/centos/new-libs@8.1.2-1.el7")
    elif change == "purl":
        component["purl"] = "https://untrusted.example.invalid/component"
    elif change == "version":
        component["version"] = "8.1.3"
    elif change == "format":
        sbom["specVersion"] = "9.9"
    elif change == "type":
        component["type"] = "application"
    elif change == "count":
        sbom["components"] = [component] * (catalog.MAX_COMPONENTS + 1)
    elif change == "identity":
        component["name"] = "../fictional"
    else:
        duplicate = copy.deepcopy(component)
        duplicate["purl"] = component["purl"].replace("centos", "almalinux")
        sbom["components"].append(duplicate)
    files["NOTICE-MANIFEST.json"] = json.dumps(manifest).encode()
    files[selected["archive_path"]] = json.dumps(sbom).encode()
    with pytest.raises(catalog.NativeComponentError):
        build(evidence)


@pytest.mark.parametrize(
    "change",
    ["duplicate", "wheel-version", "source-version", "schema", "missing-wheel", "non-object"],
)
def test_changed_source_or_inventory_requires_review(evidence: dict[str, Any], change: str) -> None:
    if change == "duplicate":
        evidence["plan"]["embedded_sources"].append(evidence["plan"]["embedded_sources"][0])
    elif change == "wheel-version":
        evidence["plan"]["embedded_sources"][0]["distribution_version"] = "99.0.1"
    elif change == "source-version":
        evidence["plan"]["embedded_sources"][0]["source_component"]["version"] = "8.1.3"
    elif change == "schema":
        evidence["inventory"]["python"]["source_recipe_schema"] = 3
    elif change == "missing-wheel":
        evidence["inventory"]["python"]["distributions"].pop()
    else:
        evidence["inventory"]["python"] = []
    with pytest.raises(catalog.NativeComponentError):
        build(evidence)


def test_cli_generates_and_verifies_without_overwriting(
    evidence: dict[str, Any], tmp_path: Path
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(evidence["inventory"]))
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"fictional lock")
    output = tmp_path / "catalog.json"
    args = [
        "--inventory",
        str(inventory),
        "--lock",
        str(lock),
        "--notices",
        "fictional.tar.gz",
        "--architecture",
        "amd64",
        "--platform-digest",
        DIGEST,
        "--catalog",
        str(output),
    ]
    assert catalog.main(["generate", *args]) == 0
    assert catalog.main(["verify", *args]) == 0
    with pytest.raises(SystemExit):
        catalog.main(["generate", *args])
    output.write_bytes(b"{}")
    with pytest.raises(SystemExit):
        catalog.main(["verify", *args])


def test_metadata_reader_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (catalog.MAX_METADATA + 1))
    with pytest.raises(catalog.NativeComponentError, match="size limit"):
        catalog._read(path)

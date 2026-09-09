"""Keep the dated registry evidence internally consistent without registry access."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "security/legacy-preview-inventory-2026-09-09.json"


@pytest.fixture
def inventory() -> dict[str, Any]:
    return json.loads(INVENTORY.read_text())  # type: ignore[no-any-return]


def test_package_inventory_has_unique_ids_and_digests(inventory: dict[str, Any]) -> None:
    versions = inventory["package_versions"]
    assert len(versions) == inventory["collection"]["package_version_count"] == 542
    assert len({v["id"] for v in versions}) == len(versions)
    assert len({v["digest"] for v in versions}) == len(versions)
    tags = [tag for v in versions for tag in v["tags"]]
    assert len(tags) == len(set(tags))


def test_raw_legacy_manifests_match_package_digests(inventory: dict[str, Any]) -> None:
    versions = {v["digest"]: v for v in inventory["package_versions"]}
    assert len(inventory["legacy_objects"]) == 81
    for digest, record in inventory["legacy_objects"].items():
        raw = record["raw_manifest"].encode()
        assert "sha256:" + hashlib.sha256(raw).hexdigest() == digest
        assert json.loads(raw)["schemaVersion"] == 2
        assert record["package_version_id"] == versions[digest]["id"]


def test_roots_bind_both_platforms_and_config_digests(inventory: dict[str, Any]) -> None:
    versions = {v["digest"]: v for v in inventory["package_versions"]}
    objects = inventory["legacy_objects"]
    assert len(inventory["legacy_images"]) == 9
    for root in inventory["legacy_images"]:
        version = versions[root["digest"]]
        assert root["package_version_id"] == version["id"]
        assert root["tags"] == version["tags"]
        assert len(root["platforms"]) == 2
        assert {p["architecture"] for p in root["platforms"]} == {"amd64", "arm64"}
        children = json.loads(objects[root["digest"]]["raw_manifest"])["manifests"]
        for platform in root["platforms"]:
            assert platform["os"] == "linux"
            assert platform["package_version_id"] == versions[platform["digest"]]["id"]
            assert any(
                c["digest"] == platform["digest"]
                and c["platform"] == {"os": "linux", "architecture": platform["architecture"]}
                for c in children
            )
            manifest = json.loads(objects[platform["digest"]]["raw_manifest"])
            assert manifest["config"]["digest"] == platform["config_digest"]
        assert len({p["revision"] for p in root["platforms"]}) == 1


def test_legacy_graph_includes_untagged_fallback_indexes(inventory: dict[str, Any]) -> None:
    objects = inventory["legacy_objects"]
    edges: dict[str, set[str]] = defaultdict(set)
    for digest, record in objects.items():
        manifest = json.loads(record["raw_manifest"])
        children = [c["digest"] for c in manifest.get("manifests", [])]
        if "subject" in manifest:
            children.append(manifest["subject"]["digest"])
        for child in children:
            assert child in objects
            edges[digest].add(child)
            edges[child].add(digest)
    seen = {r["digest"] for r in inventory["legacy_images"]}
    pending = list(seen)
    while pending:
        for child in edges[pending.pop()] - seen:
            seen.add(child)
            pending.append(child)
    assert seen == set(objects)
    versions = [v for v in inventory["package_versions"] if v["digest"] in seen]
    assert sum(not v["tags"] for v in versions) == 63
    assert sum(len(v["tags"]) for v in versions) == 19
    assert sum(t.startswith("sha256-") for v in versions for t in v["tags"]) == 9


def test_statement_descriptors_and_subjects_are_recorded(inventory: dict[str, Any]) -> None:
    counts: Counter[str] = Counter()
    objects = inventory["legacy_objects"]
    for record in objects.values():
        manifest = json.loads(record["raw_manifest"])
        layers = {layer["digest"]: layer for layer in manifest.get("layers", [])}
        for statement in record["statement_blobs"]:
            assert statement["size"] == layers[statement["digest"]]["size"]
            counts[statement["predicate_type"]] += 1
            assert statement["subjects"]
            for subject in statement["subjects"]:
                assert "sha256:" + subject["digest"]["sha256"] in objects
    assert counts == {
        "https://sigstore.dev/cosign/sign/v1": 9,
        "https://spdx.dev/Document": 18,
        "https://slsa.dev/provenance/v1": 27,
    }


def test_verification_is_not_confused_with_distribution_approval(inventory: dict[str, Any]) -> None:
    for root in inventory["legacy_images"]:
        verification = root["cosign_verification"]
        assert verification["exit_code"] == 0
        assert verification["verified_predicate_types"] == [
            "https://sigstore.dev/cosign/sign/v1",
            "https://slsa.dev/provenance/v1",
        ]
    assert all(r["referrers_api"]["status"] == 404 for r in inventory["legacy_objects"].values())
    assert len(inventory["missing_supported_release_evidence"]) == 3
    assert "not a vulnerability scan or production approval" in inventory["scope"]


def test_inventory_is_linked_from_published_reference() -> None:
    page = (ROOT / "docs/reference/legacy-preview-inventory.md").read_text()
    assert INVENTORY.name in page
    assert "reference/legacy-preview-inventory.md" in (ROOT / "mkdocs.yml").read_text()
    assert "legacy-preview-inventory.md" in (ROOT / "docs/reference/project-status.md").read_text()

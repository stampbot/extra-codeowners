"""Native source recipes must match the reviewed wheel evidence exactly."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tools import release_python_sources as sources

DIGEST = "sha256:" + "a" * 64
DATA = b"opaque source RPM; never installed or executed"


def inputs(architecture: str = "amd64", schema: int = 2) -> tuple[bytes, bytes]:
    recipe = json.loads((sources.RECIPE_DIRECTORY / "psycopg-binary-3.3.4.json").read_bytes())[
        "platforms"
    ][architecture]
    inventory = {
        "schema_version": 2,
        "image": {"architecture": architecture, "platform_digest": DIGEST},
        "python": {
            "source_recipe_schema": schema,
            "distributions": [{"normalized_name": "psycopg-binary", "version": "3.3.4"}],
            "embedded_sboms": [
                {
                    "distribution": "psycopg-binary",
                    "kind": "regular",
                    "link_target": None,
                    "sha256": recipe["sbom_sha256"],
                    "size": recipe["sbom_size"],
                }
            ],
        },
    }
    lock = b"""version = 1
[[package]]
name = "psycopg-binary"
version = "3.3.4"
source = {registry = "https://pypi.org/simple"}
"""
    return json.dumps(inventory).encode(), lock


@pytest.mark.parametrize(("architecture", "count"), [("amd64", 6), ("arm64", 8)])
def test_real_recipes_select_exact_platform_sources(architecture: str, count: int) -> None:
    manifest = sources.plan(*inputs(architecture), architecture, DIGEST)
    assert len(manifest["sources"]) == 1
    assert len(manifest["native_sources"]) == count
    assert all(f"/{architecture}/" in item["path"] for item in manifest["native_sources"])
    assert all(item["reported_package"]["name"] for item in manifest["native_sources"])


@pytest.mark.parametrize("schema", [0, 1])
def test_older_source_contracts_do_not_require_native_archives(schema: int) -> None:
    manifest = sources.plan(*inputs(schema=schema), "amd64", DIGEST)
    assert "native_sources" not in manifest
    assert len(manifest["sources"]) == schema


def test_new_wheel_version_does_not_inherit_the_reviewed_recipe() -> None:
    inventory, lock = inputs()
    raw = json.loads(inventory)
    raw["python"]["distributions"][0]["version"] = "3.3.5"
    manifest = sources.plan(
        json.dumps(raw).encode(), lock.replace(b"3.3.4", b"3.3.5"), "amd64", DIGEST
    )
    assert manifest["sources"] == []
    assert manifest["native_sources"] == []
    assert manifest["unresolved_sources"][0]["version"] == "3.3.5"


def test_recipe_directory_is_not_selected_by_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "source_recipes"
    directory.mkdir()
    (directory / "psycopg-binary-3.3.4.json").write_text("untrusted working-directory data")
    monkeypatch.chdir(tmp_path)
    assert len(sources.plan(*inputs(), "amd64", DIGEST)["native_sources"]) == 6


@pytest.mark.parametrize("change", ["hash", "size", "link", "missing", "duplicate"])
def test_changed_or_missing_sbom_requires_review(change: str) -> None:
    inventory, lock = inputs()
    raw = json.loads(inventory)
    sboms = raw["python"]["embedded_sboms"]
    if change == "hash":
        sboms[0]["sha256"] = "f" * 64
    elif change == "size":
        sboms[0]["size"] += 1
    elif change == "link":
        sboms[0]["kind"] = "symlink"
        sboms[0]["link_target"] = "elsewhere"
    elif change == "missing":
        sboms.clear()
    else:
        sboms.append(sboms[0])
    with pytest.raises(sources.PythonSourceError, match="SBOM changed"):
        sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)


def small_recipe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    recipe: dict[str, Any] = json.loads(
        (sources.RECIPE_DIRECTORY / "psycopg-binary-3.3.4.json").read_bytes()
    )
    record = recipe["platforms"]["amd64"]["sources"][0]
    record["sha256"] = hashlib.sha256(DATA).hexdigest()
    record["size"] = len(DATA)
    recipe["platforms"]["amd64"]["sources"] = [record]
    (tmp_path / "psycopg-binary-3.3.4.json").write_text(json.dumps(recipe))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    return recipe


def test_native_bytes_participate_in_all_bundle_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    small_recipe(tmp_path, monkeypatch)
    manifest = sources.plan(*inputs(), "amd64", DIGEST)
    manifest["sources"] = []
    entry = manifest["native_sources"][0]
    bundle = sources.build(manifest, {entry["path"]: DATA})
    assert sources.verify(manifest, bundle) == {entry["path"]: DATA}
    assert sources.build(manifest, {entry["path"]: DATA}) == bundle
    for contents in [b"changed", b""]:
        with pytest.raises(ValueError, match="SHA-256"):
            sources.build(manifest, {entry["path"]: contents})
    with pytest.raises(ValueError, match="payload set"):
        sources.build(manifest, {})


@pytest.mark.parametrize("change", ["url", "name", "size", "hash", "duplicate", "identity"])
def test_native_recipe_rejects_invalid_archive_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    recipe = small_recipe(tmp_path, monkeypatch)
    entry = recipe["platforms"]["amd64"]["sources"][0]
    if change == "url":
        entry["url"] = "https://evil.example/recipe.src.rpm"
    elif change == "name":
        entry["name"] = "../outside"
    elif change == "size":
        entry["size"] = True
    elif change == "hash":
        entry["sha256"] = "bad"
    elif change == "duplicate":
        recipe["platforms"]["amd64"]["sources"].append(entry)
    else:
        recipe["distribution"] = "other"
    (tmp_path / "psycopg-binary-3.3.4.json").write_text(json.dumps(recipe))
    with pytest.raises(sources.PythonSourceError):
        sources.plan(*inputs(), "amd64", DIGEST)


def test_native_sizes_count_toward_the_total_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    small_recipe(tmp_path, monkeypatch)
    monkeypatch.setattr(sources, "MAX_BUNDLE", sources.MAX_METADATA + 611732)
    with pytest.raises(ValueError, match="bundle size"):
        sources.plan(*inputs(), "amd64", DIGEST)


@pytest.mark.parametrize(
    "url",
    [
        "http://vault.centos.org/7.9.2009/os/Source/SPackages/example.src.rpm",
        "https://vault.centos.org.evil/7.9.2009/os/Source/SPackages/example.src.rpm",
        "https://vault.almalinux.org/8.10/BaseOS/Source/Packages/../example.src.rpm",
        "https://user@vault.almalinux.org/8.10/BaseOS/Source/Packages/example.src.rpm",
        "https://vault.centos.org/7.9.2009/os/Source/SPackages/example.src.rpm?redirect=evil",
    ],
)
def test_native_downloads_reject_other_origins_and_paths(url: str) -> None:
    with pytest.raises(ValueError, match="URL"):
        sources.fetch({"url": url})


def test_fetch_accepts_pinned_rpm_and_checks_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    small_recipe(tmp_path, monkeypatch)
    manifest = sources.plan(*inputs(), "amd64", DIGEST)
    entry = manifest["native_sources"][0]
    response = Mock()
    response.status = 200
    response.read.return_value = DATA
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    import urllib.request

    monkeypatch.setattr(urllib.request, "build_opener", Mock(return_value=opener))
    assert sources.fetch(entry) == DATA
    response.read.return_value = b"changed"
    with pytest.raises(ValueError, match="SHA-256"):
        sources.fetch(entry)

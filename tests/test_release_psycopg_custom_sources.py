"""Version-matched source claims cannot survive changed Psycopg native bytes."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tools import release_python_sources as sources

DIGEST = "sha256:" + "a" * 64
RECIPE = "psycopg-binary-3.3.4.json"


def recipe() -> dict[str, Any]:
    value: dict[str, Any] = json.loads((sources.RECIPE_DIRECTORY / RECIPE).read_bytes())
    return value


def inputs(architecture: str = "amd64", schema: int = 4) -> tuple[bytes, bytes]:
    platform = recipe()["platforms"][architecture]
    native = [
        {
            **binding,
            "path": "opt/venv/lib/python3.14/site-packages/" + binding["path"],
            "kind": "regular",
            "link_target": None,
        }
        for component in platform["custom_sources"]
        for binding in component["wheel_files"]
    ]
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
                    "sha256": platform["sbom_sha256"],
                    "size": platform["sbom_size"],
                }
            ],
            "native_files": native,
        },
    }
    lock = b"""version = 1
[[package]]
name = "psycopg-binary"
version = "3.3.4"
source = {registry = "https://pypi.org/simple"}
"""
    return json.dumps(inventory).encode(), lock


@pytest.mark.parametrize(("architecture", "rpm_count"), [("amd64", 6), ("arm64", 8)])
def test_custom_sources_preserve_rpms_and_bind_all_five_libraries(
    architecture: str, rpm_count: int
) -> None:
    manifest = sources.plan(*inputs(architecture), architecture, DIGEST)
    assert len(manifest["native_sources"]) == rpm_count
    assert len(manifest["sources"]) == 1
    assert len(manifest["embedded_sources"]) == 3
    assert {
        e["source_component"]["name"]: e["source_component"]["version"]
        for e in manifest["embedded_sources"]
    } == {"libpq": "18.0", "openssl": "3.5.4", "openldap": "2.6.9"}
    assert sum(len(e["wheel_files"]) for e in manifest["embedded_sources"]) == 5
    assert all(f"/{architecture}/" in e["path"] for e in manifest["embedded_sources"])
    assert all(
        e["sbom_sha256"] == recipe()["platforms"][architecture]["sbom_sha256"]
        for e in manifest["embedded_sources"]
    )


@pytest.mark.parametrize("schema", [0, 1, 2, 3])
def test_historical_schemas_do_not_acquire_custom_source_requirements(schema: int) -> None:
    inventory, lock = inputs(schema=schema)
    raw = json.loads(inventory)
    del raw["python"]["native_files"]
    assert (
        sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST).get("embedded_sources", [])
        == []
    )


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "size",
        "bool_size",
        "path",
        "link",
        "target",
        "missing",
        "duplicate",
        "list",
        "entry",
    ],
)
def test_changed_native_evidence_cannot_inherit_claim(change: str) -> None:
    inventory, lock = inputs()
    raw = json.loads(inventory)
    native = raw["python"]["native_files"]
    if change == "hash":
        native[0]["sha256"] = "e" * 64
    elif change == "size":
        native[0]["size"] += 1
    elif change == "bool_size":
        native[0]["size"] = True
    elif change == "path":
        native[0]["path"] += ".other"
    elif change == "link":
        native[0]["kind"] = "symlink"
    elif change == "target":
        native[0]["link_target"] = "elsewhere"
    elif change == "missing":
        native.pop(0)
    elif change == "duplicate":
        native.append(native[0])
    elif change == "entry":
        native.append(None)
    else:
        raw["python"]["native_files"] = {}
    with pytest.raises(sources.PythonSourceError, match="native"):
        sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)


@pytest.mark.parametrize(
    "change",
    [
        "records",
        "count",
        "entry",
        "component",
        "duplicate",
        "version",
        "url",
        "hash",
        "size",
        "bindings",
        "binding_count",
        "binding",
        "path",
        "bound_hash",
        "bound_size",
        "library",
    ],
)
def test_invalid_custom_recipe_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    inventory, lock = inputs()
    reviewed = recipe()
    platform = reviewed["platforms"]["amd64"]
    records = platform["custom_sources"]
    item = records[0]
    binding = item["wheel_files"][0]
    if change == "records":
        platform["custom_sources"] = None
    elif change == "count":
        records.pop()
    elif change == "entry":
        records[0] = None
    elif change == "component":
        item["name"] = "other"
    elif change == "duplicate":
        records[1] = records[0]
    elif change == "version":
        item["version"] = "0.0.0"
    elif change == "url":
        item["url"] = "https://evil.example/source.tar.gz"
    elif change == "hash":
        item["sha256"] = "invalid"
    elif change == "size":
        item["size"] = True
    elif change == "bindings":
        item["wheel_files"] = None
    elif change == "binding_count":
        item["wheel_files"].pop()
    elif change == "binding":
        item["wheel_files"][0] = None
    elif change == "path":
        binding["path"] = "../outside.so"
    elif change == "bound_hash":
        binding["sha256"] = "invalid"
    elif change == "bound_size":
        binding["size"] = True
    else:
        binding["path"] = item["wheel_files"][1]["path"]
    (tmp_path / RECIPE).write_text(json.dumps(reviewed))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    with pytest.raises(sources.PythonSourceError):
        sources.plan(inventory, lock, "amd64", DIGEST)


def test_new_psycopg_version_requires_custom_recipe_review() -> None:
    inventory, lock = inputs()
    with pytest.raises(sources.PythonSourceError, match="review"):
        sources.plan(
            inventory.replace(b"3.3.4", b"3.3.5"), lock.replace(b"3.3.4", b"3.3.5"), "amd64", DIGEST
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://ftp.postgresql.org/pub/source/v18.0/postgresql-18.0.tar.bz2",
        "https://ftp.postgresql.org.evil/pub/source/v18.0/postgresql-18.0.tar.bz2",
        "https://user@ftp.postgresql.org/pub/source/v18.0/postgresql-18.0.tar.bz2",
        "https://ftp.postgresql.org/pub/source/v18.0/postgresql-18.1.tar.bz2",
        "https://ftp.postgresql.org/pub/source/v18.0/postgresql-18.0.tar.bz2?redirect=evil",
        "http://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.6.9.tgz",
        "https://www.openldap.org.evil/software/download/OpenLDAP/openldap-release/openldap-2.6.9.tgz",
        "https://www.openldap.org:444/software/download/OpenLDAP/openldap-release/openldap-2.6.9.tgz",
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/../openldap-2.6.9.tgz",
    ],
)
def test_custom_downloads_reject_unreviewed_origins_and_paths(url: str) -> None:
    with pytest.raises(sources.PythonSourceError, match="URL"):
        sources.fetch({"url": url})


def test_custom_bytes_use_existing_deterministic_bundle_and_size_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inventory, lock = inputs()
    reviewed = recipe()
    payload = b"opaque source archive; not executed or extracted"
    for platform in reviewed["platforms"].values():
        for component in platform["custom_sources"]:
            component["size"] = len(payload)
            component["sha256"] = hashlib.sha256(payload).hexdigest()
    (tmp_path / RECIPE).write_text(json.dumps(reviewed))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    manifest = sources.plan(inventory, lock, "amd64", DIGEST)
    manifest["sources"] = []
    manifest["native_sources"] = []
    payloads = {entry["path"]: payload for entry in manifest["embedded_sources"]}
    bundle = sources.build(manifest, payloads)
    assert sources.verify(manifest, bundle) == payloads
    assert sources.build(manifest, payloads) == bundle
    with pytest.raises(sources.PythonSourceError, match="payload set"):
        sources.build(manifest, {})
    corrupted = dict(payloads)
    corrupted[next(iter(corrupted))] = b"changed"
    with pytest.raises(sources.PythonSourceError, match="SHA-256"):
        sources.build(manifest, corrupted)
    monkeypatch.setattr(sources, "MAX_BUNDLE", sources.MAX_METADATA + 611732)
    with pytest.raises(sources.PythonSourceError, match="bundle size"):
        sources.plan(inventory, lock, "amd64", DIGEST)


@pytest.mark.parametrize("component", ["libpq", "openldap"])
def test_new_source_origins_check_bytes_and_forbid_redirects(
    monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    manifest = sources.plan(*inputs(), "amd64", DIGEST)
    entry = next(
        e for e in manifest["embedded_sources"] if e["source_component"]["name"] == component
    )
    response = Mock()
    response.status = 200
    response.read.return_value = b"source"
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(urllib.request, "build_opener", Mock(return_value=opener))
    entry = {**entry, "size": 6, "sha256": hashlib.sha256(b"source").hexdigest()}
    assert sources.fetch(entry) == b"source"
    response.read.return_value = b"altered"
    with pytest.raises(sources.PythonSourceError, match="SHA-256"):
        sources.fetch(entry)
    with pytest.raises(sources.PythonSourceError, match="redirected"):
        sources._SourceRedirect().redirect_request(
            urllib.request.Request(entry["url"]),  # noqa: S310 - Fixed HTTPS recipe; no network.
            Mock(),
            302,
            "Found",
            {},
            "https://release-assets.githubusercontent.com/example",
        )

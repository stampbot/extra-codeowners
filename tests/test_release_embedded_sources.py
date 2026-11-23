"""Bind embedded OpenSSL source delivery to reviewed wheel evidence."""

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


def inputs(
    architecture: str = "amd64", schema: int = 3, *, version: str = "50.0.0"
) -> tuple[bytes, bytes]:
    recipe = json.loads((sources.RECIPE_DIRECTORY / f"cryptography-{version}.json").read_bytes())
    platform = recipe["platforms"][architecture]
    raw = {
        "schema_version": 2,
        "image": {"architecture": architecture, "platform_digest": DIGEST},
        "python": {
            "source_recipe_schema": schema,
            "distributions": [{"normalized_name": "cryptography", "version": version}],
            "embedded_sboms": [
                {
                    "distribution": "cryptography",
                    "path": "opt/venv/lib/python3.14/site-packages/"
                    f"cryptography-{version}.dist-info/sboms/sbom.json",
                    "kind": "regular",
                    "link_target": None,
                    "sha256": platform["sbom_sha256"],
                    "size": platform["sbom_size"],
                },
                {
                    "distribution": "cryptography",
                    "path": "opt/venv/lib/python3.14/site-packages/"
                    f"cryptography-{version}.dist-info/sboms/cryptography-rust.cyclonedx.json",
                    "kind": "regular",
                    "link_target": None,
                    "sha256": "f" * 64,
                    "size": 100,
                },
            ],
        },
    }
    url = (
        "https://files.pythonhosted.org/packages/aa/bb/"
        + "c" * 60
        + f"/cryptography-{version}.tar.gz"
    )
    lock = f'''version = 1
[[package]]
name = "cryptography"
version = "{version}"
source = {{registry = "https://pypi.org/simple"}}
sdist = {{url = "{url}", hash = "sha256:{"a" * 64}", size = 100}}
'''.encode()
    return json.dumps(raw).encode(), lock


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
@pytest.mark.parametrize(
    ("version", "openssl", "digest", "size"),
    [
        (
            "50.0.0",
            "4.0.1",
            "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09",
            55079428,
        ),
        (
            "50.0.2",
            "4.0.3",
            "325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9",
            55235667,
        ),
    ],
)
def test_reviewed_openssl_source_is_bound_to_the_platform_sbom(
    architecture: str, version: str, openssl: str, digest: str, size: int
) -> None:
    manifest = sources.plan(*inputs(architecture, version=version), architecture, DIGEST)
    assert len(manifest["embedded_sources"]) == 1
    entry = manifest["embedded_sources"][0]
    assert entry["distribution"] == "cryptography"
    assert entry["distribution_version"] == version
    assert entry["source_component"] == {"name": "openssl", "version": openssl}
    assert entry["sha256"] == digest
    assert entry["size"] == size
    assert f"/{architecture}/" in entry["path"]
    assert len(manifest["sources"]) == 1


@pytest.mark.parametrize("schema", [0, 1, 2])
def test_historical_contracts_do_not_gain_embedded_source_requirements(schema: int) -> None:
    assert "embedded_sources" not in sources.plan(*inputs(schema=schema), "amd64", DIGEST)


@pytest.mark.parametrize("change", ["hash", "size", "path", "missing", "duplicate", "link"])
def test_changed_wheel_evidence_cannot_inherit_source_claims(change: str) -> None:
    inventory, lock = inputs()
    raw = json.loads(inventory)
    entries = raw["python"]["embedded_sboms"]
    if change == "hash":
        entries[0]["sha256"] = "e" * 64
    elif change == "size":
        entries[0]["size"] += 1
    elif change == "path":
        entries[0]["path"] += ".other"
    elif change == "missing":
        entries.pop(0)
    elif change == "duplicate":
        entries.append(entries[0])
    else:
        entries[0]["kind"] = "symlink"
        entries[0]["link_target"] = "elsewhere"
    with pytest.raises(sources.PythonSourceError, match="SBOM changed"):
        sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)


def test_a_new_cryptography_version_needs_a_reviewed_recipe() -> None:
    inventory, lock = inputs()
    with pytest.raises(sources.PythonSourceError, match=r"recipe.*review"):
        sources.plan(
            inventory.replace(b"50.0.0", b"50.0.1"),
            lock.replace(b"50.0.0", b"50.0.1"),
            "amd64",
            DIGEST,
        )


def small_recipe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    data = b"opaque OpenSSL source; not executed or extracted"
    recipe = json.loads((sources.RECIPE_DIRECTORY / "cryptography-50.0.0.json").read_bytes())
    for platform in recipe["platforms"].values():
        platform["sources"][0]["sha256"] = hashlib.sha256(data).hexdigest()
        platform["sources"][0]["size"] = len(data)
    (tmp_path / "cryptography-50.0.0.json").write_text(json.dumps(recipe))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    return data


def test_embedded_sources_participate_in_bundle_integrity_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = small_recipe(tmp_path, monkeypatch)
    manifest = sources.plan(*inputs(), "amd64", DIGEST)
    manifest["sources"] = []
    entry = manifest["embedded_sources"][0]
    payloads = {entry["path"]: data}
    bundle = sources.build(manifest, payloads)
    assert sources.verify(manifest, bundle) == payloads
    assert sources.build(manifest, payloads) == bundle
    with pytest.raises(sources.PythonSourceError, match="payload set"):
        sources.build(manifest, {})
    with pytest.raises(sources.PythonSourceError, match="SHA-256"):
        sources.build(manifest, {entry["path"]: b"changed"})
    monkeypatch.setattr(sources, "MAX_BUNDLE", sources.MAX_METADATA + 100)
    with pytest.raises(sources.PythonSourceError, match="bundle size"):
        sources.plan(*inputs(), "amd64", DIGEST)


@pytest.mark.parametrize(
    "change",
    ["identity", "component", "version", "url", "hash", "size", "duplicate", "path", "filename"],
)
def test_invalid_embedded_recipe_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    small_recipe(tmp_path, monkeypatch)
    path = tmp_path / "cryptography-50.0.0.json"
    recipe = json.loads(path.read_bytes())
    platform = recipe["platforms"]["amd64"]
    entry = platform["sources"][0]
    if change == "identity":
        recipe["distribution"] = "other"
    elif change == "component":
        entry["name"] = "other"
    elif change == "version":
        entry["version"] = "4.0.2"
    elif change == "url":
        entry["url"] = "https://evil.example/openssl-4.0.1.tar.gz"
    elif change == "hash":
        entry["sha256"] = "bad"
    elif change == "size":
        entry["size"] = True
    elif change == "path":
        platform["sbom_relative_path"] = "../../outside.json"
    elif change == "filename":
        version = "1" * 100 + ".0.0"
        entry["version"] = version
        entry["url"] = (
            f"https://github.com/openssl/openssl/releases/download/openssl-{version}/"
            f"openssl-{version}.tar.gz"
        )
    else:
        platform["sources"].append(entry)
    path.write_text(json.dumps(recipe))
    with pytest.raises(sources.PythonSourceError):
        sources.plan(*inputs(), "amd64", DIGEST)


OPENSSL_URL = (
    "https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz"
)
ASSET_URL = "https://release-assets.githubusercontent.com/example/openssl.tar.gz?signature=example"


def test_openssl_asset_redirect_is_one_hop_and_forwards_no_headers() -> None:
    handler = sources._SourceRedirect()
    # This constructs a fixed HTTPS fixture; it performs no I/O.
    original = urllib.request.Request(OPENSSL_URL, headers={"Authorization": "example"})  # noqa: S310
    target = handler.redirect_request(original, Mock(), 302, "Found", {}, ASSET_URL)
    assert target.full_url == ASSET_URL
    assert target.get_method() == "GET"
    assert target.data is None
    assert target.header_items() == []
    with pytest.raises(sources.PythonSourceError, match="redirected"):
        handler.redirect_request(target, Mock(), 302, "Found", {}, ASSET_URL + "&again=true")


@pytest.mark.parametrize(
    "origin",
    [
        "https://files.pythonhosted.org/packages/aa/bb/example.tar.gz",
        "https://codeload.github.com/psycopg/psycopg/tar.gz/" + "a" * 40,
        "https://vault.centos.org/7.9.2009/os/Source/SPackages/example.src.rpm",
    ],
)
def test_other_source_providers_cannot_use_the_asset_exception(origin: str) -> None:
    with pytest.raises(sources.PythonSourceError, match="redirected"):
        sources._SourceRedirect().redirect_request(
            urllib.request.Request(origin),  # noqa: S310 - Fixed HTTPS fixtures; no I/O.
            Mock(),
            302,
            "Found",
            {},
            ASSET_URL,
        )


def test_rust_source_download_policy_still_forbids_all_redirects() -> None:
    with pytest.raises(sources.PythonSourceError, match="redirected"):
        sources._NoRedirect().redirect_request(
            urllib.request.Request(OPENSSL_URL),  # noqa: S310 - Fixed HTTPS fixture; no I/O.
            Mock(),
            302,
            "Found",
            {},
            ASSET_URL,
        )


@pytest.mark.parametrize(
    "target",
    [
        "http://release-assets.githubusercontent.com/example",
        "https://release-assets.githubusercontent.com.evil.example/example",
        "https://example@release-assets.githubusercontent.com/example",
        "https://release-assets.githubusercontent.com:444/example",
        "https://release-assets.githubusercontent.com/example#fragment",
        "https://evil.example/example",
        "https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz",
    ],
)
def test_openssl_redirect_cannot_change_origin_or_reenter_github(target: str) -> None:
    with pytest.raises(sources.PythonSourceError, match="redirected"):
        sources._SourceRedirect().redirect_request(
            urllib.request.Request(OPENSSL_URL),  # noqa: S310 - Fixed HTTPS fixture; no I/O.
            Mock(),
            302,
            "Found",
            {},
            target,
        )


def test_openssl_fetch_checks_the_actual_download_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"opaque OpenSSL source"
    entry: dict[str, Any] = {
        "url": OPENSSL_URL,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    response = Mock(status=200)
    response.read.return_value = data
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(urllib.request, "build_opener", Mock(return_value=opener))
    assert sources.fetch(entry) == data
    response.read.return_value = b"changed"
    with pytest.raises(sources.PythonSourceError, match="SHA-256"):
        sources.fetch(entry)

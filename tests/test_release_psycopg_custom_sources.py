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
LIBXCRYPT_RECIPE = "libxcrypt-psycopg-binary-3.3.4-amd64.json"


def recipe(version: str = "3.3.4") -> dict[str, Any]:
    path = sources.RECIPE_DIRECTORY / f"psycopg-binary-{version}.json"
    value: dict[str, Any] = json.loads(path.read_bytes())
    return value


def inputs(
    architecture: str = "amd64", schema: int = 4, version: str = "3.3.4"
) -> tuple[bytes, bytes]:
    platform = recipe(version)["platforms"][architecture]
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
            "distributions": [{"normalized_name": "psycopg-binary", "version": version}],
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
    return json.dumps(inventory).encode(), lock.replace(b"3.3.4", version.encode())


def libxcrypt_inputs() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    reviewed: dict[str, Any] = json.loads(
        (sources.RECIPE_DIRECTORY / LIBXCRYPT_RECIPE).read_bytes()
    )
    inventory, lock = inputs(schema=5)
    raw: dict[str, Any] = json.loads(inventory)
    binding = reviewed["wheel_file"]
    raw["python"]["native_files"].append(
        {
            **binding,
            "path": "opt/venv/lib/python3.14/site-packages/" + binding["path"],
            "kind": "regular",
            "link_target": None,
        }
    )
    wheel = "psycopg_binary-3.3.4-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
    lock += f'wheels = [{{url = "https://files.pythonhosted.org/{wheel}", '.encode()
    lock += f'hash = "sha256:{reviewed["wheel_sha256"]}"}}]\n'.encode()
    return reviewed, raw, lock


def test_libxcrypt_is_only_required_from_schema_five_on_amd64() -> None:
    arm_four = sources.plan(*inputs("arm64", 4), "arm64", DIGEST)
    arm_five = sources.plan(*inputs("arm64", 5), "arm64", DIGEST)
    assert arm_five == {**arm_four, "inventory_sha256": arm_five["inventory_sha256"]}
    reviewed, raw, lock = libxcrypt_inputs()
    result = sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)
    libxcrypt = next(
        item
        for item in result["embedded_sources"]
        if item["source_component"]["name"] == "libxcrypt"
    )
    assert libxcrypt["source_component"] == {"name": "libxcrypt", "version": "4.5.2"}
    assert libxcrypt["wheel_files"] == [reviewed["wheel_file"]]
    assert libxcrypt["builder_image"] == reviewed["builder"]["image"]
    assert libxcrypt["sha256"] == reviewed["source"]["sha256"]
    assert libxcrypt["build_recipe"] == {
        **reviewed["builder"]["script"],
        "path": "recipes/psycopg-binary/amd64/libxcrypt-4.5.2/install-libxcrypt.sh",
    }
    raw["python"]["source_recipe_schema"] = 4
    assert sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)["embedded_sources"] == [
        item for item in result["embedded_sources"] if item != libxcrypt
    ]


@pytest.mark.parametrize(
    "change", ["locked_hash", "locked_platform", "payload", "link", "builder", "script"]
)
def test_libxcrypt_provenance_drifts_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    reviewed, raw, lock = libxcrypt_inputs()
    payload = raw["python"]["native_files"][-1]
    if change == "locked_hash":
        lock = lock.replace(reviewed["wheel_sha256"].encode(), b"0" * 64)
    elif change == "locked_platform":
        lock = lock.replace(b"x86_64", b"aarch64")
    elif change == "payload":
        payload["sha256"] = "0" * 64
    elif change == "link":
        payload["kind"] = "symlink"
    elif change == "builder":
        reviewed["builder"]["library_sha256"] = "0" * 64
    else:
        reviewed["builder"]["script"]["url"] = (
            "https://raw.githubusercontent.com/pypa/manylinux/main/"
            "docker/build_scripts/install-libxcrypt.sh"
        )
    (tmp_path / RECIPE).write_text(json.dumps(recipe()))
    (tmp_path / LIBXCRYPT_RECIPE).write_text(json.dumps(reviewed))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    with pytest.raises(sources.PythonSourceError):
        sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)


def test_libxcrypt_bundle_requires_the_exact_script_bytes() -> None:
    _, raw, lock = libxcrypt_inputs()
    planned = sources.plan(json.dumps(raw).encode(), lock, "amd64", DIGEST)
    component = next(
        item
        for item in planned["embedded_sources"]
        if item["source_component"]["name"] == "libxcrypt"
    )
    manifest = {**planned, "sources": [], "native_sources": [], "embedded_sources": [component]}
    source, script = b"fictional source archive", b"fictional build script"
    for entry, data in ((component, source), (component["build_recipe"], script)):
        entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    payloads = {component["path"]: source, component["build_recipe"]["path"]: script}
    assert sources.verify(manifest, sources.build(manifest, payloads)) == payloads
    del payloads[component["build_recipe"]["path"]]
    with pytest.raises(sources.PythonSourceError, match="payload set"):
        sources.build(manifest, payloads)
    payloads[component["build_recipe"]["path"]] = b"!" * len(script)
    with pytest.raises(sources.PythonSourceError, match="SHA-256"):
        sources.build(manifest, payloads)


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


@pytest.mark.parametrize(("architecture", "rpm_count"), [("amd64", 3), ("arm64", 4)])
def test_new_wheel_retains_custom_kerberos_separately_from_the_distro_rpm(
    architecture: str, rpm_count: int
) -> None:
    manifest = sources.plan(*inputs(architecture, version="3.3.9"), architecture, DIGEST)
    kerberos = next(
        source
        for source in manifest["embedded_sources"]
        if source["source_component"]["name"] == "krb5"
    )
    assert kerberos["source_component"]["version"] == "1.22.2"
    assert len(kerberos["wheel_files"]) == 5
    (com_err,) = [row["path"] for row in kerberos["wheel_files"] if "/libcom_err-" in row["path"]]
    assert com_err.endswith(".so.3.0")
    assert len(manifest["native_sources"]) == rpm_count
    assert any(
        row["reported_package"]["name"] == "libcom_err" for row in manifest["native_sources"]
    )


@pytest.mark.parametrize("change", ["missing_kerberos", "distro_com_err"])
def test_new_wheel_rejects_incomplete_or_misattributed_kerberos(
    change: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, lock = inputs(version="3.3.9")
    reviewed = recipe("3.3.9")
    custom = reviewed["platforms"]["amd64"]["custom_sources"]
    if change == "missing_kerberos":
        custom.pop()
    else:
        kerberos = next(row for row in custom if row["name"] == "krb5")
        binding = next(row for row in kerberos["wheel_files"] if "/libcom_err-" in row["path"])
        wrong = binding["path"].removesuffix(".so.3.0") + ".so.2.1"
        inventory = json.loads(raw)
        native = next(
            row
            for row in inventory["python"]["native_files"]
            if row["path"].endswith(binding["path"])
        )
        native["path"] = native["path"].removesuffix(binding["path"]) + wrong
        raw = json.dumps(inventory).encode()
        binding["path"] = wrong
    (tmp_path / "psycopg-binary-3.3.9.json").write_text(json.dumps(reviewed))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    with pytest.raises(sources.PythonSourceError):
        sources.plan(raw, lock, "amd64", DIGEST)


@pytest.mark.parametrize("helper_change", [None, "missing", "wrong_revision"])
def test_new_libxcrypt_recipe_requires_a_helper_from_the_pinned_revision(
    helper_change: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, lock = inputs(schema=5, version="3.3.9")
    inventory = json.loads(raw)
    name = "libxcrypt-psycopg-binary-3.3.9-amd64.json"
    reviewed = json.loads((sources.RECIPE_DIRECTORY / name).read_bytes())
    binding = reviewed["wheel_file"]
    inventory["python"]["native_files"].append(
        {
            **binding,
            "path": "opt/venv/lib/python3.14/site-packages/" + binding["path"],
            "kind": "regular",
            "link_target": None,
        }
    )
    wheel = "psycopg_binary-3.3.9-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
    lock += f'wheels = [{{url = "https://files.pythonhosted.org/{wheel}", '.encode()
    lock += f'hash = "sha256:{reviewed["wheel_sha256"]}"}}]\n'.encode()
    if helper_change == "missing":
        del reviewed["builder"]["helper_script"]
    elif helper_change == "wrong_revision":
        reviewed["builder"]["helper_script"]["url"] = (
            f"https://raw.githubusercontent.com/pypa/manylinux/{'a' * 40}/"
            "docker/build_scripts/build_utils.sh"
        )
    (tmp_path / name).write_text(json.dumps(reviewed))
    (tmp_path / "psycopg-binary-3.3.9.json").write_text(json.dumps(recipe("3.3.9")))
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    if helper_change is not None:
        with pytest.raises(sources.PythonSourceError, match="helper"):
            sources.plan(json.dumps(inventory).encode(), lock, "amd64", DIGEST)
        return

    plan = sources.plan(json.dumps(inventory).encode(), lock, "amd64", DIGEST)
    libxcrypt = next(
        row for row in plan["embedded_sources"] if row["source_component"]["name"] == "libxcrypt"
    )
    (helper,) = libxcrypt["build_recipe_dependencies"]
    assert helper["path"] == "recipes/psycopg-binary/amd64/libxcrypt-4.5.2/build_utils.sh"
    subplan = {**plan, "sources": [], "native_sources": [], "embedded_sources": [libxcrypt]}
    assert helper in sources._all_sources(subplan)


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

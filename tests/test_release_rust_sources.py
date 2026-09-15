"""Cargo source delivery is derived from retained evidence, not download hints."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tools import release_inventory, release_notices, release_python_sources
from tools import release_rust_sources as rust

DIGEST = "sha256:" + "a" * 64
CRATE = b"opaque upstream archive with notices; never executed"
CHECKSUM = hashlib.sha256(CRATE).hexdigest()
LOCK = f'''version = 4
[[package]]
name = "native-example"
version = "1.0.0"
[[package]]
name = "dependency"
version = "2.0.0"
source = "{rust.REGISTRY}"
checksum = "{CHECKSUM}"
'''.encode()


def archive(files: list[tuple[str, bytes]], *, compressed: bool = True) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz" if compressed else "w") as result:
        for name, data in files:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            result.addfile(member, io.BytesIO(data))
    return output.getvalue()


def fixture(
    tmp_path: Path,
    *,
    cargo: bytes = LOCK,
    components: list[dict[str, Any]] | None = None,
) -> tuple[bytes, bytes, bytes, Path]:
    source = archive([("example-1.0.0/Cargo.lock", cargo)])
    lock = f"""version = 1
[[package]]
name = "example"
version = "1.0.0"
source = {{registry = "https://pypi.org/simple"}}
[package.sdist]
url = "https://files.pythonhosted.org/packages/aa/bb/{"c" * 60}/example-1.0.0.tar.gz"
hash = "sha256:{hashlib.sha256(source).hexdigest()}"
size = {len(source)}
""".encode()
    if components is None:
        components = [
            {
                "purl": "pkg:cargo/native-example@1.0.0?download_url=file://.#src/lib.rs",
                "name": "native_example",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {"purl": "pkg:cargo/dependency@2.0.0"},
        ]
    site = "opt/venv/lib/python3.14/site-packages/example-1.0.0.dist-info"
    rootfs = archive(
        [
            ("usr/lib/os-release", b'ID=debian\nVERSION_ID="13"\n'),
            (
                "var/lib/dpkg/status",
                b"Package: example\nStatus: install ok installed\n"
                b"Architecture: amd64\nVersion: 1.0\n\n",
            ),
            ("usr/local/lib/python3.14/LICENSE.txt", b"Python license\n"),
            ("usr/share/licenses/extra-codeowners/LICENSE", b"App license\n"),
            (f"{site}/METADATA", b"Metadata-Version: 2.4\nName: example\nVersion: 1.0.0\n"),
            (
                f"{site}/sboms/cargo.json",
                json.dumps({"bomFormat": "CycloneDX", "components": components}).encode(),
            ),
        ],
        compressed=False,
    )
    inventory = release_inventory.render_inventory(
        release_inventory.collect_inventory(
            io.BytesIO(rootfs), architecture="amd64", platform_digest=DIGEST
        )
    ).encode()
    notices = tmp_path / "notices.tar.gz"
    notices.write_bytes(
        release_notices.build_notice_bundle(
            io.BytesIO(rootfs), inventory, architecture="amd64", platform_digest=DIGEST
        )
    )
    python_plan = release_python_sources.plan(inventory, lock, "amd64", DIGEST)
    python_bundle = release_python_sources.build(
        python_plan, {python_plan["sources"][0]["path"]: source}
    )
    return inventory, lock, python_bundle, notices


def plan(tmp_path: Path, **kwargs: Any) -> dict[str, Any]:
    return rust.plan(*fixture(tmp_path, **kwargs), "amd64", DIGEST)


def test_plan_binds_both_kinds_and_preserves_licenses(tmp_path: Path) -> None:
    manifest = plan(tmp_path)
    assert len(manifest["sources"]) == 1
    registry, workspace = manifest["components"]
    assert registry["source_kind"] == "crates-io-archive"
    assert workspace["source_kind"] == "retained-python-workspace"
    assert workspace["declared_licenses"] == [{"license": {"id": "MIT"}}]
    assert workspace["cargo_lock_sha256"] == hashlib.sha256(LOCK).hexdigest()
    assert manifest["sources"][0]["sha256"] == CHECKSUM
    assert manifest["sources"][0]["url"].startswith("https://static.crates.io/crates/")


@pytest.mark.parametrize(
    "cargo",
    [
        LOCK.replace(b"version = 4", b"version = 2"),
        LOCK.replace(b'name = "dependency"', b'name = "not-in-wheel"'),
        LOCK.replace(rust.REGISTRY.encode(), b"git+https://example.com/source"),
        LOCK.replace(CHECKSUM.encode(), b"bad checksum"),
        LOCK.replace(b"[[package]]", b"[[package]]\nchecksum = 'abc'", 1),
        LOCK + b'\n[[package]]\nname = "dependency"\nversion = "2.0.0"\n',
        b"not TOML",
    ],
)
def test_plan_rejects_missing_ambiguous_or_unpinned_sources(tmp_path: Path, cargo: bytes) -> None:
    with pytest.raises(ValueError):
        plan(tmp_path, cargo=cargo)


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:cargo/../dependency@2.0.0",
        "pkg:cargo/%2fdependency@2.0.0",
        "pkg:cargo/dependency@2.0.0%00",
        "pkg:cargo/dependency",
        "https://evil.example/dependency@2.0.0",
    ],
)
def test_purl_identity_cannot_be_a_path_or_url(purl: str) -> None:
    with pytest.raises(rust.RustSourceError):
        rust._cargo_identity(purl)


def test_plan_deduplicates_nested_targets(tmp_path: Path) -> None:
    component = {"purl": "pkg:cargo/dependency@2.0.0"}
    manifest = plan(tmp_path, components=[component, {"components": [component]}])
    assert len(manifest["components"]) == 2
    assert len(manifest["sources"]) == 1


def test_plan_verifies_inputs_before_using_them(tmp_path: Path) -> None:
    inventory, lock, python_bundle, notices = fixture(tmp_path)
    with pytest.raises(ValueError, match="source manifest"):
        rust.plan(inventory + b" ", lock, python_bundle, notices, "amd64", DIGEST)
    with pytest.raises(ValueError, match="selected platform"):
        rust.plan(inventory, lock, python_bundle, notices, "arm64", DIGEST)
    notices.write_bytes(b"not a notice archive")
    with pytest.raises(ValueError):
        rust.plan(inventory, lock, python_bundle, notices, "amd64", DIGEST)


def test_cargo_lock_tar_requires_one_regular_root_member() -> None:
    source = {"path": "sources/example/example-1.0.0.tar.gz"}
    for files in [[], [("nested/Cargo.lock", LOCK)], [("example-1.0.0/Cargo.lock", LOCK)] * 2]:
        with pytest.raises(rust.RustSourceError, match="one bounded"):
            rust._cargo_lock(source, archive(files))
    link = io.BytesIO()
    with tarfile.open(fileobj=link, mode="w:gz") as result:
        member = tarfile.TarInfo("example-1.0.0/Cargo.lock")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside"
        result.addfile(member)
    with pytest.raises(rust.RustSourceError, match="regular"):
        rust._cargo_lock(source, link.getvalue())


def test_cargo_lock_zip_and_expansion_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as result:
        result.writestr("example-1.0.0/Cargo.lock", LOCK)
    assert rust._cargo_lock({"path": "example-1.0.0.zip"}, output.getvalue())[1] == LOCK
    monkeypatch.setattr(rust, "MAX_SDIST_EXPANDED", 100)
    with pytest.raises(rust.RustSourceError, match="expanded"):
        rust._cargo_lock(
            {"path": "example-1.0.0.tar.gz"}, archive([("example-1.0.0/Cargo.lock", LOCK)])
        )


def test_build_is_deterministic_and_verify_rejects_tampering(tmp_path: Path) -> None:
    manifest = plan(tmp_path)
    source_path = manifest["sources"][0]["path"]
    bundle = rust.build(manifest, {source_path: CRATE})
    assert bundle == rust.build(manifest, {source_path: CRATE})
    rust.verify(manifest, bundle)
    with pytest.raises(ValueError, match="checksum"):
        rust.build(manifest, {source_path: b"changed"})
    for files in [
        [("manifest.json", json.dumps(manifest).encode())],
        [("manifest.json", b"{}"), (source_path, CRATE)],
        [
            ("manifest.json", json.dumps(manifest | {"schema_version": True}).encode()),
            (source_path, CRATE),
        ],
        [("manifest.json", json.dumps(manifest).encode()), (source_path, b"changed")],
        [("../outside", CRATE)],
        [(source_path, CRATE), (source_path, CRATE)],
    ]:
        with pytest.raises(ValueError):
            rust.verify(manifest, archive(files))
    with pytest.raises(ValueError, match="end markers"):
        rust.verify(manifest, gzip.compress(gzip.decompress(bundle) + b"nonzero trailer"))


def response(contents: bytes = CRATE, /, **headers: str) -> Mock:
    value = Mock()
    value.status = 200
    value.headers = headers
    value.read.return_value = contents
    value.geturl.return_value = "https://static.crates.io/crates/dependency/dependency-2.0.0.crate"
    value.__enter__ = Mock(return_value=value)
    value.__exit__ = Mock(return_value=False)
    return value


@pytest.mark.parametrize(
    "url", ["http://static.crates.io/x", "file:///tmp/source", "https://evil/x"]
)
def test_fetch_rejects_download_origin_before_network(tmp_path: Path, url: str) -> None:
    source = plan(tmp_path)["sources"][0] | {"url": url}
    with pytest.raises(ValueError, match="archive identity"):
        rust.fetch(source)


def test_fetch_checks_response_and_retries_transient_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = plan(tmp_path)["sources"][0]
    opener = Mock()
    opener.open.side_effect = [TimeoutError(), response()]
    monkeypatch.setattr(urllib.request, "build_opener", Mock(return_value=opener))
    sleep = Mock()
    monkeypatch.setattr(time, "sleep", sleep)
    assert rust.fetch(source) == CRATE
    assert opener.open.call_count == 2
    sleep.assert_called_once_with(1)
    opener.open.side_effect = None
    opener.open.return_value = response(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        rust.fetch(source)
    opener.open.return_value = response(**{"Content-Length": "99999999999"})
    with pytest.raises(ValueError, match="size"):
        rust.fetch(source)
    opener.open.return_value = response()
    opener.open.return_value.geturl.return_value = "https://evil/source"
    with pytest.raises(ValueError, match="unexpected Cargo source response"):
        rust.fetch(source)


@pytest.mark.parametrize("status", [302, 404, 429, 503])
def test_fetch_http_failures_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    source = plan(tmp_path)["sources"][0]
    headers = Message()
    headers["Retry-After"] = "2"
    opener = Mock()
    opener.open.side_effect = urllib.error.HTTPError(source["url"], status, "test", headers, None)
    monkeypatch.setattr(urllib.request, "build_opener", Mock(return_value=opener))
    sleep = Mock()
    monkeypatch.setattr(time, "sleep", sleep)
    with pytest.raises(ValueError):
        rust.fetch(source)
    assert opener.open.call_count == (3 if status in {429, 503} else 1)
    assert sleep.call_count == (2 if status in {429, 503} else 0)


@pytest.mark.parametrize("retry_after", ["61", "tomorrow", "-1", chr(0xFF11)])
def test_fetch_does_not_retry_early_or_wait_indefinitely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_after: str
) -> None:
    source = plan(tmp_path)["sources"][0]
    headers = Message()
    headers["Retry-After"] = retry_after
    opener = Mock()
    opener.open.side_effect = urllib.error.HTTPError(source["url"], 429, "test", headers, None)
    monkeypatch.setattr(urllib.request, "build_opener", Mock(return_value=opener))
    with pytest.raises(ValueError, match="later retry"):
        rust.fetch(source)
    assert opener.open.call_count == 1


def test_fetch_batch_bound_and_dedup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = plan(tmp_path)
    monkeypatch.setattr(rust, "fetch", Mock(return_value=CRATE))
    assert list(rust.fetch_all(manifest).values()) == [CRATE]
    with pytest.raises(ValueError, match="duplicate"):
        rust.fetch_all(manifest | {"sources": manifest["sources"] * 2})
    monkeypatch.setattr(rust, "MAX_BUNDLE", rust.MAX_METADATA + len(CRATE) - 1)
    with pytest.raises(ValueError, match="size limit"):
        rust.fetch_all(manifest)


def test_cli_isolated_from_working_directory(tmp_path: Path) -> None:
    inputs = fixture(tmp_path)
    inventory, lock, python_bundle, notices = inputs
    for name, contents in [
        ("inventory.json", inventory),
        ("uv.lock", lock),
        ("python.tar.gz", python_bundle),
    ]:
        (tmp_path / name).write_bytes(contents)
    (tmp_path / "release_python_sources.py").write_text("raise RuntimeError('cwd injection')\n")
    result = subprocess.run(  # noqa: S603 - fixed local CLI with isolated Python.
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(rust.__file__).resolve()),
            "plan",
            "--inventory",
            str(tmp_path / "inventory.json"),
            "--lock",
            str(tmp_path / "uv.lock"),
            "--python-sources",
            str(tmp_path / "python.tar.gz"),
            "--notices",
            str(notices),
            "--architecture",
            "amd64",
            "--platform-digest",
            DIGEST,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == rust.plan(*inputs, "amd64", DIGEST)

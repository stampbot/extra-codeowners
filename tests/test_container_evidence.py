from __future__ import annotations

import importlib.util
import io
import json
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evidence = load_script("container_evidence")
readiness = load_script("release_readiness")


def tar_bytes(
    files: dict[str, bytes],
    *,
    links: dict[str, str] | None = None,
    hardlinks: dict[str, str] | None = None,
) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)
        for name, target in (hardlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.LNKTYPE
            member.linkname = target
            archive.addfile(member)
    return result.getvalue()


def tar_sequence(files: list[tuple[str, bytes]]) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, content in files:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return result.getvalue()


def apk_database(architecture: str = "x86_64", version: str = "1.37.0-r1") -> bytes:
    return (
        "P:busybox\n"
        f"V:{version}\n"
        f"A:{architecture}\n"
        "L:GPL-2.0-only\n"
        "o:busybox\n"
        "c:1111111111111111111111111111111111111111\n\n"
    ).encode()


def metadata(name: str, version: str, license_value: str = "MIT") -> bytes:
    return (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        f"License-Expression: {license_value}\n\n"
    ).encode()


def saved_image_layers(path: Path, layers: list[bytes]) -> None:
    layer_names = [f"blobs/sha256/{evidence.hashlib.sha256(layer).hexdigest()}" for layer in layers]
    config_content = json.dumps(
        {
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": "a" * 40,
                    "org.opencontainers.image.version": "1.0",
                }
            }
        }
    ).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config_content).hexdigest()}"
    contents = {
        "manifest.json": json.dumps([{"Config": config_name, "Layers": layer_names}]).encode(),
        config_name: config_content,
    }
    contents.update(zip(layer_names, layers, strict=True))
    path.write_bytes(tar_bytes(contents))


def saved_image(path: Path) -> None:
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA": metadata(
                "demo", "1.0"
            ),
            "usr/local/lib/python3.14/site-packages/pip-26.1.dist-info/METADATA": metadata(
                "pip", "26.1"
            ),
        }
    )
    second = tar_bytes(
        {
            "usr/local/lib/python3.14/site-packages/.wh.pip-26.1.dist-info": b"",
            "empty": b"",
        }
    )
    saved_image_layers(path, [first, second])


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "a/../../escape",
        "a\\b",
        ".",
        "./",
        "././file",
        "a//b",
    ],
)
def test_checked_path_rejects_unsafe_names(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path(path)


@pytest.mark.parametrize(
    "path", ["LICENSE\nforged", "LICENSE\rforged", "LICENSE\tforged", "x\x7fy"]
)
def test_checked_path_rejects_control_characters(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path(path)


def test_strict_json_rejects_duplicates_and_non_finite_numbers(tmp_path: Path) -> None:
    for content, message in (
        ('{"distribution_approval": false, "distribution_approval": true}', "duplicate"),
        ('{"value": NaN}', "non-finite"),
        ('{"value": Infinity}', "non-finite"),
    ):
        path = tmp_path / "hostile.json"
        path.write_text(content)
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.load_json(path)
    with pytest.raises(ValueError, match="Out of range float values"):
        evidence.canonical_json({"value": float("nan")})


def test_saved_image_inventory_tracks_whiteouts_and_all_layers(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("alpine", "busybox")]["aports_commit"] == "1" * 40
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "pip")]["effective"] is False
    assert inventory["image_revision"] == "a" * 40
    assert [layer["regular_file_count"] for layer in files["layers"]] == [3, 1]
    assert len(files["regular_files"]) == 4


def test_saved_image_binds_config_and_layer_blob_names_to_bytes(tmp_path: Path) -> None:
    layer = tar_bytes({"lib/apk/db/installed": apk_database()})
    valid = tmp_path / "valid.tar"
    saved_image_layers(valid, [layer])
    with pytest.raises(evidence.EvidenceError, match="inspected image"):
        evidence._inventory_saved_image(
            valid,
            "linux/amd64",
            "sha256:" + "a" * 64,
            expected_config_digest="sha256:" + "b" * 64,
        )

    config = b'{"config":{"Labels":{}}}'
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config).hexdigest()}"
    hostile_layer_name = "blobs/sha256/" + "c" * 64
    hostile = tmp_path / "hostile.tar"
    hostile.write_bytes(
        tar_bytes(
            {
                "manifest.json": json.dumps(
                    [{"Config": config_name, "Layers": [hostile_layer_name]}]
                ).encode(),
                config_name: config,
                hostile_layer_name: layer,
            }
        )
    )
    with pytest.raises(evidence.EvidenceError, match="layer digest does not match"):
        evidence._inventory_saved_image(hostile, "linux/amd64", "sha256:" + "a" * 64)


def test_whiteouts_remove_only_lower_layer_files_independent_of_order(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0", "MIT"),
            f"{site}/stale-1.0.dist-info/METADATA": metadata("stale", "1.0", "MIT"),
        }
    )
    second = tar_sequence(
        [
            (f"{site}/demo-1.0.dist-info/METADATA", metadata("demo", "1.0", "MIT")),
            (f"{site}/.wh.demo-1.0.dist-info", b""),
            (f"{site}/.wh..wh..opq", b""),
        ]
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    inventory, _ = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "demo")]["observed_license"] == "MIT"
    assert components[("python", "stale")]["effective"] is False


def test_conflicting_metadata_for_one_python_release_fails_closed(tmp_path: Path) -> None:
    path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    path: metadata("demo", "1.0", "MIT"),
                }
            ),
            tar_bytes({path: metadata("demo", "1.0", "Apache-2.0")}),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="conflicting Python metadata"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_removed_apk_database_fails_closed(tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database()})
    second = tar_bytes({"lib/apk/db/.wh.installed": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="no effective Alpine"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_duplicate_apk_database_in_one_layer_uses_last_occurrence(tmp_path: Path) -> None:
    layer = tar_sequence(
        [
            ("lib/apk/db/installed", apk_database(version="1.0-r0")),
            ("lib/apk/db/installed", apk_database(version="2.0-r0")),
        ]
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    inventory, _ = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    busybox = next(item for item in inventory["components"] if item["name"] == "busybox")
    assert busybox["version"] == "2.0-r0"


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_non_regular_replacement_of_python_metadata_fails_closed(
    link_kind: str, tmp_path: Path
) -> None:
    path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
    first = tar_bytes({"lib/apk/db/installed": apk_database(), path: metadata("demo", "1.0")})
    links = {path: "other"} if link_kind == "symlink" else None
    hardlinks = {path: "other"} if link_kind == "hardlink" else None
    second = tar_bytes({}, links=links, hardlinks=hardlinks)
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="metadata path is not a regular file"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_image_size_limit_is_cumulative_across_layers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [tar_bytes({"lib/apk/db/installed": apk_database()}), tar_bytes({"second": b"x"})],
    )
    monkeypatch.setattr(evidence, "MAX_IMAGE_TOTAL_BYTES", 15_000)

    with pytest.raises(evidence.EvidenceError, match="cumulative size limit"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_apk_architecture_must_match_image_platform(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes({"lib/apk/db/installed": apk_database("aarch64")})])

    with pytest.raises(evidence.EvidenceError, match="does not match linux/amd64"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_claimed_subject_must_match_a_local_repository_digest() -> None:
    config_digest = "sha256:" + "a" * 64
    manifest_digest = "sha256:" + "b" * 64
    info = {
        "Id": config_digest,
        "RepoDigests": [f"ghcr.io/stampbot/extra-codeowners@{manifest_digest}"],
    }

    assert (
        evidence.verify_local_image_subject(
            info, manifest_digest, allow_config_digest_subject=False
        )
        == config_digest
    )
    with pytest.raises(evidence.EvidenceError, match="claimed subject digest"):
        evidence.verify_local_image_subject(
            info, "sha256:" + "c" * 64, allow_config_digest_subject=False
        )
    with pytest.raises(evidence.EvidenceError, match="claimed subject digest"):
        evidence.verify_local_image_subject(info, config_digest, allow_config_digest_subject=False)
    assert (
        evidence.verify_local_image_subject(
            {"Id": config_digest, "RepoDigests": []},
            config_digest,
            allow_config_digest_subject=True,
        )
        == config_digest
    )


def test_apk_database_requires_commit_provenance() -> None:
    broken = apk_database().replace(b"c:" + b"1" * 40 + b"\n", b"")
    with pytest.raises(evidence.EvidenceError, match="immutable source provenance"):
        evidence.parse_apk_database(broken)


@pytest.mark.parametrize("field", ["P", "V", "A", "L", "o", "c"])
def test_apk_database_rejects_duplicate_authoritative_fields(field: str) -> None:
    value = next(
        line.removeprefix(f"{field}:")
        for line in apk_database().decode().splitlines()
        if line.startswith(f"{field}:")
    )
    hostile = apk_database().replace(
        f"{field}:{value}\n".encode(), f"{field}:{value}\n{field}:{value}\n".encode()
    )
    with pytest.raises(evidence.EvidenceError, match=f"repeats field {field}"):
        evidence.parse_apk_database(hostile)


@pytest.mark.parametrize("field", ["Name", "Version", "License-Expression", "License"])
def test_python_metadata_rejects_duplicate_authoritative_fields(field: str) -> None:
    base = metadata("demo", "1.0")
    value = "demo" if field == "Name" else "1.0" if field == "Version" else "MIT"
    if field == "License":
        hostile = b"Name: demo\nVersion: 1.0\nLicense: MIT\nLicense: MIT\n\n"
    else:
        hostile = f"{field}: {value}\n".encode() + base
    with pytest.raises(evidence.EvidenceError, match=f"repeats {field}"):
        evidence.parse_python_metadata(hostile, "METADATA")


def test_recipe_checksum_parser_does_not_execute_recipe() -> None:
    remote_digest = "a" * 128
    local_digest = evidence.hashlib.sha512(b"patch").hexdigest()
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/demo-$pkgver.tar.gz\nlocal.patch"\n'
                f'sha512sums="\n{remote_digest}  demo-1.0.tar.gz\n'
                f'{local_digest}  local.patch\n"\n'
            ).encode(),
            "aports/main/demo/local.patch": b"patch",
        }
    )
    checksums, local = evidence.recipe_checksums(recipe, "demo")
    assert checksums == {
        "demo-1.0.tar.gz": remote_digest,
        "local.patch": local_digest,
    }
    assert local == {"local.patch": b"patch"}


def test_recipe_checksum_parser_rejects_links() -> None:
    recipe = tar_bytes(
        {"aports/main/demo/APKBUILD": f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'.encode()},
        links={"aports/main/demo/escape": "../../secret"},
    )
    with pytest.raises(evidence.EvidenceError, match="unsafe archive link target"):
        evidence.recipe_checksums(recipe, "demo")


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_recipe_checksum_parser_rejects_even_safe_links(link_kind: str) -> None:
    apkbuild = (
        'source="local.patch"\n'
        f'sha512sums="\n{evidence.hashlib.sha512(b"patch").hexdigest()}  local.patch\n"\n'
    ).encode()
    links = {"aports/main/demo/local.patch": "target.patch"} if link_kind == "symlink" else None
    hardlinks = (
        {"aports/main/demo/local.patch": "aports/main/demo/target.patch"}
        if link_kind == "hardlink"
        else None
    )
    recipe = tar_bytes({"aports/main/demo/APKBUILD": apkbuild}, links=links, hardlinks=hardlinks)
    with pytest.raises(evidence.EvidenceError, match="links are not allowed"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_checksum_parser_requires_an_exact_pinned_link_exception() -> None:
    path = "aports/main/demo/post-upgrade"
    recipe = tar_bytes(
        {"aports/main/demo/APKBUILD": b""},
        links={path: "post-install"},
    )
    exception = {"path": path, "target": "post-install", "type": "symlink"}

    assert evidence.recipe_checksums(recipe, "demo", allowed_links=[exception]) == ({}, {})
    with pytest.raises(evidence.EvidenceError, match="missing="):
        evidence.recipe_checksums(
            tar_bytes({"aports/main/demo/APKBUILD": b""}),
            "demo",
            allowed_links=[exception],
        )


def test_dynamic_recipe_sources_require_an_explicit_exception() -> None:
    local = b"key"
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'for key in $keys; do\n\tsource="$source $key"\ndone\n'
                f'sha512sums="\n{evidence.hashlib.sha512(local).hexdigest()}  key.pub\n"\n'
            ).encode(),
            "aports/main/demo/key.pub": local,
        }
    )

    with pytest.raises(evidence.EvidenceError, match="one literal source block"):
        evidence.recipe_checksums(recipe, "demo")
    assert evidence.recipe_checksums(recipe, "demo", allow_dynamic_sources=True) == (
        {"key.pub": evidence.hashlib.sha512(local).hexdigest()},
        {"key.pub": local},
    )


def test_recipe_checksum_parser_verifies_local_bytes() -> None:
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                f'source="local.patch"\nsha512sums="\n{"a" * 128}  local.patch\n"\n'
            ).encode(),
            "aports/main/demo/local.patch": b"different",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="local recipe source checksum mismatch"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_checksum_parser_rejects_duplicate_basenames() -> None:
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": b'source="local.patch"\n',
            "aports/main/demo/a/local.patch": b"one",
            "aports/main/demo/b/local.patch": b"two",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="repeats regular-file basename"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_source_and_checksums_must_have_exact_coverage() -> None:
    extra_source = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/one.tar.gz https://example.com/two.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  one.tar.gz\n"\n'
            ).encode()
        }
    )
    with pytest.raises(evidence.EvidenceError, match="counts differ"):
        evidence.recipe_checksums(extra_source, "demo")

    wrong_name = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/one-$pkgver.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  unrelated.zip\n"\n'
            ).encode()
        }
    )
    with pytest.raises(evidence.EvidenceError, match="does not match source"):
        evidence.recipe_checksums(wrong_name, "demo")


def test_recipe_checksum_parser_enforces_aggregate_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = tar_bytes({"aports/main/demo/APKBUILD": b"source=demo.tar.gz\n"})
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="recipe archive is too large"):
        evidence.recipe_checksums(recipe, "demo")


def test_fetch_rejects_an_invalid_expected_digest_before_network() -> None:
    with pytest.raises(evidence.EvidenceError, match="invalid expected sha256 digest"):
        evidence.fetch("https://example.com/source.tar.gz", "not-a-digest")


def test_cpython_source_is_bound_to_official_recipe_version_and_hash() -> None:
    digest = "a" * 64
    recipe = f"ENV PYTHON_VERSION 3.14.6\nENV PYTHON_SHA256 {digest}\n".encode()
    source = {
        "url": "https://www.python.org/ftp/python/3.14.6/Python-3.14.6.tar.xz",
        "sha256": digest,
    }
    evidence.verify_cpython_source_binding(recipe, source)

    with pytest.raises(evidence.EvidenceError, match="source URL"):
        evidence.verify_cpython_source_binding(
            recipe,
            {**source, "url": "https://www.python.org/ftp/python/3.14.5/Python-3.14.5.tar.xz"},
        )
    with pytest.raises(evidence.EvidenceError, match="SHA-256"):
        evidence.verify_cpython_source_binding(recipe, {**source, "sha256": "b" * 64})
    with pytest.raises(evidence.EvidenceError, match="one literal"):
        evidence.verify_cpython_source_binding(
            b"ENV PYTHON_VERSION $VERSION\nENV PYTHON_SHA256 $HASH\n", source
        )


def test_fetch_records_every_https_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"verified content"

    class Response:
        def __init__(self) -> None:
            self.headers = {"Content-Length": str(len(content))}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://cdn.example.com/source.tar.gz"

        def read(self, _limit: int) -> bytes:
            return content

    class Opener:
        def __init__(self, handler: Any) -> None:
            self.handler = handler

        def open(self, _request: Any, *, timeout: int) -> Response:
            assert timeout == 60
            self.handler.urls.append("https://cdn.example.com/source.tar.gz")
            return Response()

    monkeypatch.setattr(
        evidence.urllib.request,
        "build_opener",
        lambda handler: Opener(handler),
    )
    download = evidence.fetch(
        "https://example.com/source.tar.gz",
        evidence.hashlib.sha256(content).hexdigest(),
    )

    assert download.content == content
    assert download.urls == (
        "https://example.com/source.tar.gz",
        "https://cdn.example.com/source.tar.gz",
    )
    record = evidence.source_record("demo", download.urls, content, "sources/demo.tar.gz")
    assert record["url"] == download.urls[0]
    assert record["urls"] == list(download.urls)


def test_fetch_rejects_a_final_url_away_from_https(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://example.com/source.tar.gz"

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return Response()

    monkeypatch.setattr(evidence.urllib.request, "build_opener", lambda *_args: Opener())
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        evidence.fetch("https://example.com/source.tar.gz", "a" * 64)


def test_redirect_handler_rejects_downgrades_and_too_many_redirects() -> None:
    handler = evidence.AuditedRedirectHandler("https://example.com/source.tar.gz")
    request = evidence.urllib.request.Request("https://example.com/source.tar.gz")
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/next")

    handler.urls.extend(f"https://example.com/{index}" for index in range(5))
    with pytest.raises(evidence.EvidenceError, match="exceeded 5 redirects"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/final")


def test_license_extraction_rejects_control_paths_in_tar_and_zip(tmp_path: Path) -> None:
    hostile_tar = tar_bytes({"LICENSE\nforged": b"text"})
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.extract_license_files(hostile_tar, "demo", tmp_path)

    hostile_zip = io.BytesIO()
    with zipfile.ZipFile(hostile_zip, mode="w") as archive:
        archive.writestr("LICENSE\nforged", b"text")
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.extract_license_files(hostile_zip.getvalue(), "demo", tmp_path)


def test_license_extraction_rejects_zip_symlink_evidence(tmp_path: Path) -> None:
    hostile_zip = io.BytesIO()
    with zipfile.ZipFile(hostile_zip, mode="w") as archive:
        member = zipfile.ZipInfo("LICENSE")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "target")
    with pytest.raises(evidence.EvidenceError, match="non-regular entry"):
        evidence.extract_license_files(hostile_zip.getvalue(), "demo", tmp_path)


def test_policy_comparison_and_human_approval_are_separate() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = {
        "schema_version": 1,
        "platform": "linux/amd64",
        "components": [component],
    }
    policy: dict[str, Any] = {
        "schema_version": 1,
        "base_image_index_digest": "sha256:" + "b" * 64,
        "platforms": {"linux/amd64": [component]},
        "distribution_approval": {"approved": False},
        "license_resolutions": {
            "python:demo@1": {"expression": "MIT", "rationale": "Reviewed test fixture."}
        },
        "license_texts": [{"id": "MIT"}],
        "custom_license_evidence": {},
    }
    evidence.verify_inventory(inventory, policy, require_approval=False)
    with pytest.raises(evidence.EvidenceError, match="maintainer approval"):
        evidence.verify_inventory(inventory, policy, require_approval=True)

    policy["platforms"]["linux/amd64"][0] = {**component, "version": "2"}
    with pytest.raises(evidence.EvidenceError, match="differs from the reviewed policy"):
        evidence.verify_inventory(inventory, policy, require_approval=False)


def test_license_refs_require_exact_pinned_custom_evidence() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "Custom",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = {"schema_version": 1, "platform": "linux/amd64", "components": [component]}
    policy: dict[str, Any] = {
        "schema_version": 1,
        "base_image_index_digest": "sha256:" + "b" * 64,
        "platforms": {"linux/amd64": [component]},
        "distribution_approval": {"approved": False},
        "license_resolutions": {
            "python:demo@1": {
                "expression": "LicenseRef-Demo",
                "rationale": "Reviewed custom notice.",
            }
        },
        "license_texts": [],
        "custom_license_evidence": {},
    }
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    requirement = {
        "components": ["python:demo@1"],
        "evidence": {
            "python:demo@1": {
                "path": "licenses/from-source/python-demo-1/notice-LICENSE",
                "sha256": "a" * 64,
            }
        },
        "rationale": "Exact source-carried notice reviewed.",
        "require_source_notice": True,
    }
    policy["custom_license_evidence"] = {"LicenseRef-Demo": requirement}
    evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {
        "LicenseRef-Demo": requirement,
        "LicenseRef-Unused": requirement,
    }
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {"LicenseRef-Demo": {**requirement, "rationale": ""}}
    with pytest.raises(evidence.EvidenceError, match="has no rationale"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {"LicenseRef-Demo": requirement}
    unrelated = [
        {
            "component": "python-demo-1",
            "path": "licenses/from-source/python-demo-1/COPYING.GPL",
            "sha256": "b" * 64,
        }
    ]
    with pytest.raises(evidence.EvidenceError, match="pinned source-carried notice"):
        evidence.verify_pinned_custom_license_records(inventory["components"], policy, unrelated)


def test_image_revision_and_version_must_match_source() -> None:
    revision = "a" * 40
    inventory = {"image_revision": revision, "image_version": "1.2.3"}
    evidence.verify_image_revision(inventory, version="1.2.3", source_revision=revision)
    with pytest.raises(evidence.EvidenceError, match="does not match source revision"):
        evidence.verify_image_revision(inventory, version="1.2.3", source_revision="b" * 40)
    with pytest.raises(evidence.EvidenceError, match="image version"):
        evidence.verify_image_revision(inventory, version="1.2.4", source_revision=revision)


def test_dockerfile_builder_and_final_runtime_match_reviewed_base(tmp_path: Path) -> None:
    digest = "sha256:" + "b" * 64
    policy = {"base_image": "python:3.14-alpine", "base_image_index_digest": digest}
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        f"FROM python:3.14-alpine@{digest} AS builder\n"
        "FROM builder AS test\n"
        f"FROM python:3.14-alpine@{digest} AS runtime\n"
    )
    evidence.verify_dockerfile_base(dockerfile, policy)

    policy["base_image_index_digest"] = "sha256:" + "c" * 64
    with pytest.raises(evidence.EvidenceError, match="builder stage"):
        evidence.verify_dockerfile_base(dockerfile, policy)

    policy["base_image_index_digest"] = digest
    dockerfile.write_text(
        dockerfile.read_text() + "FROM python:3.14-alpine@" + digest + " AS debug\n"
    )
    with pytest.raises(evidence.EvidenceError, match="final build stage"):
        evidence.verify_dockerfile_base(dockerfile, policy)


def test_committed_dockerfile_matches_the_reviewed_base_policy() -> None:
    policy = json.loads(Path(".compliance/container-policy.json").read_text())
    evidence.verify_dockerfile_base(Path("Dockerfile"), policy)


def test_final_image_layers_must_begin_with_the_reviewed_platform_base() -> None:
    policy = {
        "base_image_platforms": {
            platform: {
                "config_digest": "sha256:" + character * 64,
                "layer_diff_ids": ["sha256:" + character * 64],
                "manifest_digest": "sha256:" + character * 64,
            }
            for platform, character in (
                ("linux/amd64", "a"),
                ("linux/arm64", "b"),
            )
        }
    }
    files: dict[str, Any] = {
        "platform": "linux/amd64",
        "layers": [
            {"digest": "sha256:" + "a" * 64},
            {"digest": "sha256:" + "c" * 64},
        ],
    }

    evidence.verify_base_layer_binding(files, policy)
    files["layers"][0]["digest"] = "sha256:" + "d" * 64
    with pytest.raises(evidence.EvidenceError, match="do not begin with"):
        evidence.verify_base_layer_binding(files, policy)


def test_deterministic_archive_has_normalized_metadata(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "b").write_bytes(b"second")
    (root / "a").write_bytes(b"first")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    evidence.create_deterministic_tar(root, first, 123)
    evidence.create_deterministic_tar(root, second, 123)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
    assert [item.name for item in members] == ["a", "b"]
    assert {(item.uid, item.gid, item.mode, item.mtime) for item in members} == {(0, 0, 0o644, 123)}


def test_release_milestone_must_match_pinned_number_and_be_open_and_empty() -> None:
    ready = {
        "number": 1,
        "title": "First supported release",
        "state": "open",
        "open_issues": 0,
        "closed_issues": 2,
    }
    checked = readiness.validate_milestone(ready, 1, "First supported release")
    readiness.require_ready(checked)

    for changed, message in (
        ({**ready, "number": 2}, "expected milestone #1"),
        ({**ready, "title": "Other"}, "expected 'First supported release'"),
        ({**ready, "closed_issues": True}, "invalid closed_issues"),
    ):
        with pytest.raises(readiness.ReadinessError, match=message):
            readiness.validate_milestone(changed, 1, "First supported release")

    for changed, message in (
        ({**ready, "open_issues": 1}, "still has 1 open"),
        ({**ready, "state": "closed"}, "is not open"),
    ):
        checked = readiness.validate_milestone(changed, 1, "First supported release")
        with pytest.raises(readiness.ReadinessError, match=message):
            readiness.require_ready(checked)


def test_release_policy_is_exact(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone": "First supported release"}'
    )
    assert readiness.configured_milestone(policy) == (1, "First supported release")
    policy.write_text(
        '{"schema_version": 2, "milestone_number": 1, "milestone": "First supported release"}'
    )
    with pytest.raises(readiness.ReadinessError, match="unsupported"):
        readiness.configured_milestone(policy)
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone_number": 2, '
        '"milestone": "First supported release"}'
    )
    with pytest.raises(readiness.ReadinessError, match="duplicate JSON object key"):
        readiness.configured_milestone(policy)


def test_release_summary_links_exact_run_commit_and_counts(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    milestone = {
        "number": 1,
        "title": "First supported release",
        "open_issues": 0,
        "closed_issues": 2,
    }
    readiness.write_summary(
        summary,
        milestone,
        repository="stampbot/extra-codeowners",
        commit="a" * 40,
        run_id="12345",
    )
    content = summary.read_text()
    assert "stampbot/extra-codeowners" in content
    assert f"/commit/{'a' * 40}" in content
    assert "/actions/runs/12345" in content
    assert "milestone/1" in content
    assert "Open issues: **0**" in content
    assert "Closed issues: **2**" in content


def test_release_query_gets_the_pinned_milestone_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[str] = []
    response_body = json.dumps(
        {
            "number": 1,
            "title": "First supported release",
            "state": "open",
            "open_issues": 0,
            "closed_issues": 2,
        }
    ).encode()

    class Response:
        status = 200

        def __init__(self) -> None:
            self.remaining = response_body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            result = self.remaining[:size]
            self.remaining = self.remaining[size:]
            return result

    def urlopen(request: Any, *, timeout: int) -> Response:
        assert timeout == 30
        requests.append(request.full_url)
        return Response()

    monkeypatch.setattr(readiness.urllib.request, "urlopen", urlopen)
    result = readiness.github_milestone("stampbot/extra-codeowners", 1, "token")

    assert result["number"] == 1
    assert requests == ["https://api.github.com/repos/stampbot/extra-codeowners/milestones/1"]


def test_blocked_release_still_writes_the_workflow_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone": "First supported release"}'
    )
    summary = tmp_path / "summary.md"
    milestone = {
        "number": 1,
        "title": "First supported release",
        "state": "open",
        "open_issues": 5,
        "closed_issues": 2,
    }
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(readiness, "github_milestone", lambda *_args: milestone)

    result = readiness.main(
        [
            "--repository",
            "stampbot/extra-codeowners",
            "--policy",
            str(policy),
            "--commit",
            "a" * 40,
            "--run-id",
            "12345",
            "--summary",
            str(summary),
        ]
    )

    assert result == 1
    assert "Open issues: **5**" in summary.read_text()


def test_workflows_keep_release_blocked_and_collect_review_evidence_in_ci() -> None:
    release = Path(".github/workflows/release.yml").read_text()
    ci = Path(".github/workflows/ci.yml").read_text()
    mise = Path("mise.toml").read_text()

    assert "issues: read" in release
    assert "release_readiness.py" in release
    release_block = "Keep tagged publication disabled pending isolated evidence collection"
    assert release_block in release
    assert "https://github.com/stampbot/extra-codeowners/issues/28" in release
    assert release.index(release_block) < release.index("Publish release image")
    assert "exit 1" in release[release.index(release_block) : release.index("  quality:")]
    assert '--summary "${GITHUB_STEP_SUMMARY}"' in release
    assert "Build digest-bound distribution evidence" not in release
    assert "--require-distribution-approval" not in release
    assert "container-distribution-evidence" not in release
    assert "evidence-predicate-amd64.json" not in release
    assert "evidence-predicate-arm64.json" not in release

    assert "container-distribution-evidence-${{ matrix.architecture }}" in ci
    assert '--platform "$PLATFORM"' in ci
    assert "--require-image-revision" in ci
    assert "--allow-config-digest-subject" in ci
    assert "Upload container distribution evidence\n        if: always()" in ci
    assert "if-no-files-found: warn" in ci

    for checked_scope in (ci, release, mise):
        assert ".github/scripts/container_evidence.py" in checked_scope
        assert ".github/scripts/release_readiness.py" in checked_scope


def test_bundle_command_forwards_image_revision_requirement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setattr(evidence, "build_bundle", lambda **kwargs: observed.update(kwargs))
    args = SimpleNamespace(
        inventory="inventory.json",
        files_inventory="files.json",
        policy="policy.json",
        uv_lock="uv.lock",
        repo=str(tmp_path),
        output="bundle.tar.gz",
        predicate_output="predicate.json",
        version="1.2.3",
        source_date_epoch=123,
        require_distribution_approval=True,
        require_image_revision=True,
    )

    evidence.command_bundle(args)

    assert observed["require_approval"] is True
    assert observed["require_image_revision"] is True

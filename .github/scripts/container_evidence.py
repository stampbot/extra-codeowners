#!/usr/bin/env python3
"""Build deterministic, digest-bound container distribution evidence.

The collector treats image layers and downloaded archives as hostile input. It
does not execute image content, APKBUILD recipes, setup.py files, or source build
scripts. Network content must be selected by immutable policy or by a checksum
recorded in an immutable lock/recipe.
"""

from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 250_000
MAX_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_IMAGE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_LICENSE_BYTES = 2 * 1024 * 1024
LICENSE_NAME = re.compile(
    r"(^|/)(copying|copyright|licen[cs]es?|notice|authors?)([._-].*)?$", re.IGNORECASE
)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA512_LINE = re.compile(r"^([0-9a-f]{128})  (\S.*)$")
DIST_INFO = re.compile(r"(?:^|/)site-packages/([^/]+)\.dist-info/METADATA$")
NORMALIZE_NAME = re.compile(r"[-_.]+")


class EvidenceError(RuntimeError):
    """Fail-closed evidence collection error."""


def canonical_json(value: object) -> bytes:
    """Return stable UTF-8 JSON with a final newline."""

    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_package_name(value: str) -> str:
    return NORMALIZE_NAME.sub("-", value).lower()


def checked_path(value: str) -> PurePosixPath:
    """Normalize an archive path and reject traversal or ambiguous names."""

    if "\x00" in value or "\\" in value:
        raise EvidenceError(f"unsafe archive path: {value!r}")
    raw = value.removeprefix("./")
    comparable = raw[:-1] if raw.endswith("/") else raw
    path = PurePosixPath(comparable)
    if (
        not comparable
        or comparable in {".", ".."}
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != comparable
    ):
        raise EvidenceError(f"unsafe archive path: {value!r}")
    return path


def checked_link_target(value: str) -> None:
    if "\x00" in value or "\\" in value:
        raise EvidenceError(f"unsafe archive link target: {value!r}")
    target = PurePosixPath(value)
    if (
        target.is_absolute()
        or any(part in {"", ".", ".."} for part in target.parts)
        or target.as_posix() != value
    ):
        raise EvidenceError(f"unsafe archive link target: {value!r}")


def run(command: Sequence[str], *, cwd: Path | None = None) -> bytes:
    result = subprocess.run(  # noqa: S603 - every caller supplies a fixed executable
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise EvidenceError(f"command failed ({' '.join(command)}): {detail}")
    return result.stdout


def executable(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required executable is not available: {name}")
    return path


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"expected a JSON object in {path}")
    return value


def require_schema(value: Mapping[str, Any], source: str) -> None:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"unsupported {source} schema: {value.get('schema_version')!r}")


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile():
        raise EvidenceError(f"expected regular file: {member.name}")
    if member.size > MAX_ARCHIVE_MEMBER_BYTES:
        raise EvidenceError(f"archive member exceeds size limit: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"cannot read archive member: {member.name}")
    value = stream.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
    if len(value) > MAX_ARCHIVE_MEMBER_BYTES:
        raise EvidenceError(f"archive member exceeds size limit: {member.name}")
    return value


def image_inventory(
    image: str,
    platform: str,
    subject_digest: str,
    *,
    allow_config_digest_subject: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Inventory effective components and every regular file in every image layer."""

    if not SHA256.fullmatch(subject_digest):
        raise EvidenceError("subject digest must be sha256:<64 lowercase hex characters>")
    inspect = json.loads(run(["docker", "image", "inspect", image]))
    if not isinstance(inspect, list) or len(inspect) != 1:
        raise EvidenceError("docker image inspect did not return exactly one image")
    info = inspect[0]
    expected_arch = platform.removeprefix("linux/")
    if info.get("Os") != "linux" or info.get("Architecture") != expected_arch:
        raise EvidenceError(
            f"image platform is {info.get('Os')}/{info.get('Architecture')}, expected {platform}"
        )
    image_id = verify_local_image_subject(
        info,
        subject_digest,
        allow_config_digest_subject=allow_config_digest_subject,
    )

    with tempfile.TemporaryDirectory(prefix="extra-codeowners-image-") as temporary:
        saved = Path(temporary) / "image.tar"
        with saved.open("wb") as output:
            process = subprocess.run(  # noqa: S603
                [executable("docker"), "image", "save", image],
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
            )
        if process.returncode:
            raise EvidenceError(process.stderr.decode(errors="replace").strip())
        inventory, files = _inventory_saved_image(saved, platform, subject_digest)

    inventory["image_config_digest"] = image_id
    return inventory, files


def verify_local_image_subject(
    info: Mapping[str, Any],
    subject_digest: str,
    *,
    allow_config_digest_subject: bool,
) -> str:
    """Bind a claimed subject to a pulled manifest or an explicitly local config."""

    image_id = info.get("Id")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id):
        raise EvidenceError("Docker returned an invalid image configuration digest")
    repo_digests = info.get("RepoDigests")
    if repo_digests is None:
        repo_digests = []
    if not isinstance(repo_digests, list) or not all(
        isinstance(item, str) for item in repo_digests
    ):
        raise EvidenceError("Docker returned invalid repository digests")
    manifest_digests: set[str] = set()
    for item in repo_digests:
        _, separator, digest = item.rpartition("@")
        if not separator or not SHA256.fullmatch(digest):
            raise EvidenceError(f"Docker returned an invalid repository digest: {item!r}")
        manifest_digests.add(digest)
    if subject_digest in manifest_digests:
        return image_id
    if allow_config_digest_subject and subject_digest == image_id:
        return image_id
    raise EvidenceError(
        "claimed subject digest is not a repository digest for the local image; "
        "configuration digests are allowed only for explicitly local CI evidence"
    )


def _inventory_saved_image(
    saved: Path, platform: str, subject_digest: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    effective: dict[str, dict[str, Any]] = {}
    occurrences: list[dict[str, Any]] = []
    metadata_occurrences: list[dict[str, Any]] = []
    apk_databases: list[tuple[int, bytes]] = []
    layer_digests: list[str] = []

    with tarfile.open(saved, mode="r:") as outer:
        if len(outer.getmembers()) > MAX_ARCHIVE_MEMBERS:
            raise EvidenceError("docker save archive has too many entries")
        try:
            manifest_member = outer.getmember("manifest.json")
        except KeyError as exc:
            raise EvidenceError("docker save archive has no manifest.json") from exc
        manifest = json.loads(read_member(outer, manifest_member))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise EvidenceError("docker save archive must contain exactly one image")
        layers = manifest[0].get("Layers")
        if not isinstance(layers, list) or not layers:
            raise EvidenceError("docker save manifest has no layers")
        config_name = manifest[0].get("Config")
        if not isinstance(config_name, str):
            raise EvidenceError("docker save manifest has no image configuration")
        try:
            config = json.loads(read_member(outer, outer.getmember(config_name)))
        except (KeyError, json.JSONDecodeError) as exc:
            raise EvidenceError("docker save archive has an invalid image configuration") from exc
        labels = config.get("config", {}).get("Labels", {})
        if not isinstance(labels, dict):
            raise EvidenceError("image labels are invalid")

        for layer_index, layer_name in enumerate(layers):
            if not isinstance(layer_name, str):
                raise EvidenceError("invalid layer name")
            layer_path = checked_path(layer_name)
            if len(layer_path.parts) != 3 or layer_path.parts[:2] != ("blobs", "sha256"):
                raise EvidenceError(f"unexpected layer location: {layer_name}")
            layer_digest = f"sha256:{layer_path.name}"
            if not SHA256.fullmatch(layer_digest):
                raise EvidenceError(f"invalid layer digest: {layer_digest}")
            layer_digests.append(layer_digest)
            try:
                member = outer.getmember(layer_name)
            except KeyError as exc:
                raise EvidenceError(f"missing image layer: {layer_name}") from exc
            if member.size > MAX_IMAGE_TOTAL_BYTES:
                raise EvidenceError(f"image layer exceeds size limit: {layer_digest}")
            layer_stream = outer.extractfile(member)
            if layer_stream is None:
                raise EvidenceError(f"cannot read image layer: {layer_name}")
            with tarfile.open(fileobj=layer_stream, mode="r|") as layer:
                count = 0
                layer_total = 0
                for entry in layer:
                    count += 1
                    if count > MAX_ARCHIVE_MEMBERS:
                        raise EvidenceError(f"layer has too many entries: {layer_digest}")
                    path = checked_path(entry.name)
                    basename = path.name
                    if basename == ".wh..wh..opq":
                        parent = str(path.parent)
                        prefix = "" if parent == "." else f"{parent}/"
                        for candidate in list(effective):
                            if candidate.startswith(prefix):
                                effective.pop(candidate)
                        continue
                    if basename.startswith(".wh."):
                        target = path.parent / basename.removeprefix(".wh.")
                        target_text = str(target)
                        for candidate in list(effective):
                            if candidate == target_text or candidate.startswith(f"{target_text}/"):
                                effective.pop(candidate)
                        continue
                    if not entry.isfile():
                        continue
                    layer_total += entry.size
                    if layer_total > MAX_IMAGE_TOTAL_BYTES:
                        raise EvidenceError(
                            f"image layer contents exceed size limit: {layer_digest}"
                        )
                    content = read_member(layer, entry)
                    path_text = str(path)
                    record = {
                        "layer": layer_index,
                        "layer_digest": layer_digest,
                        "path": path_text,
                        "sha256": sha256_bytes(content),
                        "size": len(content),
                    }
                    occurrences.append(record)
                    effective[path_text] = record
                    if path_text == "lib/apk/db/installed":
                        apk_databases.append((layer_index, content))
                    if DIST_INFO.search(path_text):
                        package = parse_python_metadata(content, path_text)
                        package["layer"] = layer_index
                        package["path"] = path_text
                        metadata_occurrences.append(package)

    if not apk_databases:
        raise EvidenceError("image has no Alpine installed-package database")
    latest_apk = max(apk_databases, key=lambda item: item[0])[1]
    alpine = parse_apk_database(latest_apk)

    python_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for package in metadata_occurrences:
        key = (package["name"], package["version"])
        current = python_by_key.get(key)
        if current is None or package["layer"] >= current["layer"]:
            python_by_key[key] = package
    for package in python_by_key.values():
        current = effective.get(package["path"])
        package["effective"] = (
            current is not None and current["sha256"] == package["metadata_sha256"]
        )
        package.pop("path")
        package.pop("layer")

    components: list[dict[str, Any]] = []
    for package in alpine:
        if package["name"].startswith("."):
            continue
        components.append({"ecosystem": "alpine", **package, "effective": True})
    components.extend(
        {"ecosystem": "python", **package}
        for package in sorted(
            python_by_key.values(), key=lambda item: (item["name"], item["version"])
        )
    )

    layers_summary = []
    for layer_index, layer_digest in enumerate(layer_digests):
        layer_items = [item for item in occurrences if item["layer"] == layer_index]
        layers_summary.append(
            {
                "index": layer_index,
                "digest": layer_digest,
                "regular_file_count": len(layer_items),
            }
        )
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "subject_digest": subject_digest,
        "image_revision": labels.get("org.opencontainers.image.revision", ""),
        "image_version": labels.get("org.opencontainers.image.version", ""),
        "components": sorted(components, key=component_sort_key),
    }
    files = {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "subject_digest": subject_digest,
        "layers": layers_summary,
        "regular_files": occurrences,
    }
    return inventory, files


def parse_python_metadata(content: bytes, path: str) -> dict[str, Any]:
    message = email.parser.BytesParser().parsebytes(content)
    name = message.get("Name", "").strip()
    version = message.get("Version", "").strip()
    if not name or not version:
        raise EvidenceError(f"Python metadata has no name/version: {path}")
    license_value = message.get("License-Expression", message.get("License", "")).strip()
    return {
        "name": normalize_package_name(name),
        "version": version,
        "observed_license": license_value,
        "metadata_sha256": sha256_bytes(content),
    }


def parse_apk_database(content: bytes) -> list[dict[str, Any]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("Alpine package database is not UTF-8") from exc
    packages: list[dict[str, Any]] = []
    for paragraph in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if len(line) >= 2 and line[1] == ":":
                fields.setdefault(line[0], line[2:])
        if not fields:
            continue
        missing = [key for key in ("P", "V", "A") if not fields.get(key)]
        if missing:
            raise EvidenceError(f"Alpine package record lacks {', '.join(missing)}")
        package: dict[str, Any] = {
            "name": fields["P"],
            "version": fields["V"],
            "architecture": fields["A"],
            "observed_license": fields.get("L", ""),
            "origin": fields.get("o", ""),
            "aports_commit": fields.get("c", ""),
        }
        if not package["name"].startswith(".") and (
            not package["origin"] or not re.fullmatch(r"[0-9a-f]{40}", package["aports_commit"])
        ):
            raise EvidenceError(f"Alpine package lacks immutable source provenance: {fields['P']}")
        packages.append(package)
    return sorted(packages, key=lambda item: (item["name"], item["version"]))


def component_sort_key(component: Mapping[str, Any]) -> tuple[str, str, str]:
    return (str(component["ecosystem"]), str(component["name"]), str(component["version"]))


def component_key(component: Mapping[str, Any]) -> str:
    return f"{component['ecosystem']}:{component['name']}@{component['version']}"


def resolved_license(component: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    resolutions = policy.get("license_resolutions")
    if not isinstance(resolutions, dict):
        raise EvidenceError("policy has no reviewed license resolutions")
    resolution = resolutions.get(component_key(component))
    if not isinstance(resolution, dict):
        raise EvidenceError(f"policy has no license resolution for {component_key(component)}")
    expression = resolution.get("expression")
    rationale = resolution.get("rationale")
    if not isinstance(expression, str) or not expression.strip():
        raise EvidenceError(f"license resolution has no expression: {component_key(component)}")
    if not isinstance(rationale, str) or not rationale.strip():
        raise EvidenceError(f"license resolution has no rationale: {component_key(component)}")
    return expression


def policy_components(policy: Mapping[str, Any], platform: str) -> list[dict[str, Any]]:
    platforms = policy.get("platforms")
    if not isinstance(platforms, dict) or not isinstance(platforms.get(platform), list):
        raise EvidenceError(f"policy has no reviewed component baseline for {platform}")
    return sorted(platforms[platform], key=component_sort_key)


def verify_inventory(
    inventory: Mapping[str, Any], policy: Mapping[str, Any], *, require_approval: bool
) -> None:
    require_schema(inventory, "inventory")
    require_schema(policy, "policy")
    platform = inventory.get("platform")
    if not isinstance(platform, str):
        raise EvidenceError("inventory platform is missing")
    actual = inventory.get("components")
    if not isinstance(actual, list):
        raise EvidenceError("inventory components are missing")
    expected = policy_components(policy, platform)
    if canonical_json(sorted(actual, key=component_sort_key)) != canonical_json(expected):
        raise EvidenceError(
            "component/license inventory differs from the reviewed policy; "
            "inspect the normalized diff and review every change"
        )
    actual_keys = {component_key(component) for component in actual}
    resolutions = policy.get("license_resolutions")
    if not isinstance(resolutions, dict) or set(resolutions) != actual_keys:
        raise EvidenceError(
            "reviewed license resolutions do not exactly cover the component inventory"
        )
    required_license_texts: set[str] = set()
    for component in actual:
        expression = resolved_license(component, policy)
        required_license_texts.update(
            token
            for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
            if token not in {"AND", "OR", "WITH"} and not token.startswith("LicenseRef-")
        )
    license_texts = policy.get("license_texts")
    if not isinstance(license_texts, list):
        raise EvidenceError("policy has no reviewed license texts")
    provided_license_texts = {entry.get("id") for entry in license_texts if isinstance(entry, dict)}
    missing_texts = required_license_texts - provided_license_texts
    if missing_texts:
        raise EvidenceError(f"policy has no standard text for: {', '.join(sorted(missing_texts))}")
    expected_base = policy.get("base_image_index_digest")
    if not isinstance(expected_base, str) or not SHA256.fullmatch(expected_base):
        raise EvidenceError("policy base image index digest is invalid")
    if require_approval:
        approval = policy.get("distribution_approval")
        if not isinstance(approval, dict) or approval.get("approved") is not True:
            raise EvidenceError(
                "recipient distribution mechanism has not received explicit maintainer approval"
            )
        for field in ("approved_by", "approved_on", "rationale"):
            if not isinstance(approval.get(field), str) or not approval[field].strip():
                raise EvidenceError(f"distribution approval is missing {field}")


def verify_image_revision(
    inventory: Mapping[str, Any], *, version: str, source_revision: str
) -> None:
    revision = inventory.get("image_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise EvidenceError("release image has no exact 40-character source revision label")
    if revision != source_revision:
        raise EvidenceError(
            f"image revision {revision} does not match source revision {source_revision}"
        )
    if inventory.get("image_version") != version:
        raise EvidenceError(
            f"image version {inventory.get('image_version')!r} does not match {version!r}"
        )


def verify_dockerfile_base(dockerfile: Path, policy: Mapping[str, Any]) -> None:
    """Require builder and runtime stages to use the reviewed base index digest."""

    base_image = policy.get("base_image")
    base_digest = policy.get("base_image_index_digest")
    if (
        not isinstance(base_image, str)
        or not base_image
        or "@" in base_image
        or any(character.isspace() for character in base_image)
    ):
        raise EvidenceError("policy base image reference is invalid")
    if not isinstance(base_digest, str) or not SHA256.fullmatch(base_digest):
        raise EvidenceError("policy base image index digest is invalid")
    try:
        content = dockerfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvidenceError(f"cannot read {dockerfile}: {exc}") from exc
    stages: dict[str, str] = {}
    from_entries: list[tuple[str, str | None]] = []
    for line in content.splitlines():
        match = re.fullmatch(
            r"\s*FROM\s+(\S+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*",
            line,
            flags=re.IGNORECASE,
        )
        if match is not None:
            alias = match.group(2)
            from_entries.append((match.group(1), alias.lower() if alias is not None else None))
            if alias is not None:
                stages[alias.lower()] = match.group(1)
    expected = f"{base_image}@{base_digest}"
    for stage in ("builder", "runtime"):
        if stages.get(stage) != expected:
            raise EvidenceError(
                f"Dockerfile {stage} stage must use reviewed base {expected} exactly"
            )
    if not from_entries or from_entries[-1] != (expected, "runtime"):
        raise EvidenceError("Dockerfile final build stage must be the reviewed runtime base stage")


def require_https_source_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise EvidenceError(f"source URL must be credential-free HTTPS: {url}")


def fetch(url: str, expected_hash: str, algorithm: str = "sha256") -> bytes:
    hash_lengths = {"sha256": 64, "sha512": 128}
    expected_length = hash_lengths.get(algorithm)
    if expected_length is None or not re.fullmatch(
        rf"[0-9a-f]{{{expected_length}}}", expected_hash
    ):
        raise EvidenceError(f"invalid expected {algorithm} digest for {url}")
    require_https_source_url(url)
    # Alpine's GitLab rejects unknown user-agent families with HTTP 418. Keep
    # project identification while using its explicitly accepted curl family.
    request = urllib.request.Request(  # noqa: S310 - scheme and authority checked above
        url, headers={"User-Agent": "curl/8.0 extra-codeowners-evidence/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            require_https_source_url(response.geturl())
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_DOWNLOAD_BYTES:
                raise EvidenceError(f"source exceeds download limit: {url}")
            content = response.read(MAX_DOWNLOAD_BYTES + 1)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise EvidenceError(f"cannot fetch {url}: {exc}") from exc
    if len(content) > MAX_DOWNLOAD_BYTES:
        raise EvidenceError(f"source exceeds download limit: {url}")
    actual = hashlib.new(algorithm, content).hexdigest()
    if actual != expected_hash:
        raise EvidenceError(
            f"{algorithm} mismatch for {url}: expected {expected_hash}, got {actual}"
        )
    return content


def parse_lock_sources(lock_path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    try:
        lock = tomllib.loads(lock_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"cannot parse {lock_path}: {exc}") from exc
    sources: dict[tuple[str, str], dict[str, Any]] = {}
    for package in lock.get("package", []):
        name = normalize_package_name(package.get("name", ""))
        version = package.get("version", "")
        sdist = package.get("sdist")
        if not name or not version or not isinstance(sdist, dict):
            continue
        hash_value = sdist.get("hash", "")
        if not isinstance(hash_value, str) or not hash_value.startswith("sha256:"):
            raise EvidenceError(f"locked sdist has no SHA-256: {name} {version}")
        sources[(name, version)] = {
            "url": sdist.get("url"),
            "sha256": hash_value.removeprefix("sha256:"),
            "size": sdist.get("size"),
        }
    return sources


def recipe_checksums(archive: bytes, origin: str) -> tuple[dict[str, str], set[str]]:
    local_files: set[str] = set()
    apkbuild: bytes | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as source:
            count = 0
            total = 0
            for member in source:
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError(f"recipe archive has too many entries: {origin}")
                path = checked_path(member.name)
                if member.issym() or member.islnk():
                    checked_link_target(member.linkname)
                    local_files.add(path.name)
                    continue
                if not member.isfile():
                    continue
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise EvidenceError(f"recipe archive is too large: {origin}")
                content = read_member(source, member)
                local_files.add(path.name)
                if path.name == "APKBUILD":
                    if apkbuild is not None:
                        raise EvidenceError(
                            f"recipe archive contains multiple APKBUILD files: {origin}"
                        )
                    apkbuild = content
    except tarfile.TarError as exc:
        raise EvidenceError(f"invalid recipe archive for {origin}: {exc}") from exc
    if apkbuild is None:
        raise EvidenceError(f"recipe archive has no APKBUILD: {origin}")
    try:
        text = apkbuild.decode()
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"APKBUILD is not UTF-8: {origin}") from exc
    matches = re.findall(r'^sha512sums="\n(.*?)\n"$', text, flags=re.MULTILINE | re.DOTALL)
    if not matches and not re.search(r"^source=", text, flags=re.MULTILINE):
        return {}, local_files
    if len(matches) != 1:
        raise EvidenceError(f"APKBUILD must have exactly one literal sha512sums block: {origin}")
    checksums: dict[str, str] = {}
    for line in matches[0].splitlines():
        parsed = SHA512_LINE.fullmatch(line.strip())
        if parsed is None:
            raise EvidenceError(f"unsupported APKBUILD checksum line for {origin}: {line!r}")
        digest, filename = parsed.groups()
        checked_path(filename)
        if PurePosixPath(filename).name != filename:
            raise EvidenceError(f"APKBUILD checksum filename must be a basename: {filename}")
        if filename in checksums:
            raise EvidenceError(f"duplicate APKBUILD source filename: {filename}")
        checksums[filename] = digest
    if not checksums:
        raise EvidenceError(f"APKBUILD source list has no checksummed files: {origin}")
    return checksums, local_files


def source_policy_entry(policy: Mapping[str, Any], name: str, version: str) -> dict[str, Any]:
    entries = policy.get("python_sources", [])
    for entry in entries:
        if (
            isinstance(entry, dict)
            and normalize_package_name(str(entry.get("name", ""))) == name
            and entry.get("version") == version
        ):
            return entry
    raise EvidenceError(f"no reviewed source policy for Python component {name} {version}")


def safe_filename(value: str) -> str:
    name = PurePosixPath(urllib.parse.urlparse(value).path).name
    checked_path(name)
    return name


def write_file(root: Path, relative: str, content: bytes) -> Path:
    path = checked_path(relative)
    destination = root.joinpath(*path.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise EvidenceError(f"duplicate bundle path: {relative}")
    destination.write_bytes(content)
    return destination


def extract_license_files(archive: bytes, component: str, root: Path) -> list[str]:
    """Extract only bounded regular files with license/notice names."""

    found: list[tuple[str, bytes]] = []
    try:
        if archive.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(io.BytesIO(archive)) as source:
                members = source.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError(f"source archive has too many entries: {component}")
                if sum(member.file_size for member in members) > MAX_ARCHIVE_TOTAL_BYTES:
                    raise EvidenceError(f"source archive is too large: {component}")
                for member in members:
                    path = checked_path(member.filename)
                    if member.is_dir() or not LICENSE_NAME.search(str(path)):
                        continue
                    if member.file_size > MAX_LICENSE_BYTES:
                        raise EvidenceError(f"license file exceeds limit: {member.filename}")
                    content = source.read(member, pwd=None)
                    found.append((str(path), content))
        else:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as source:
                count = 0
                total = 0
                for member in source:
                    count += 1
                    if count > MAX_ARCHIVE_MEMBERS:
                        raise EvidenceError(f"source archive has too many entries: {component}")
                    path = checked_path(member.name)
                    if not member.isfile():
                        continue
                    total += member.size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        raise EvidenceError(f"source archive is too large: {component}")
                    if not LICENSE_NAME.search(str(path)):
                        continue
                    if member.size > MAX_LICENSE_BYTES:
                        raise EvidenceError(f"license file exceeds limit: {member.name}")
                    found.append((str(path), read_member(source, member)))
    except (tarfile.TarError, zipfile.BadZipFile, RuntimeError) as exc:
        # Raw patches and text sources legitimately are not archives.
        if archive.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
            raise EvidenceError(f"invalid source archive for {component}: {exc}") from exc
        return []

    written: list[str] = []
    seen: set[str] = set()
    for source_path, content in sorted(found):
        digest = sha256_bytes(content)
        if digest in seen:
            continue
        seen.add(digest)
        basename = PurePosixPath(source_path).name
        relative = f"licenses/from-source/{component}/{digest[:12]}-{basename}"
        destination = root / relative
        if destination.exists():
            if destination.read_bytes() != content:
                raise EvidenceError(f"conflicting license files at {relative}")
        else:
            write_file(root, relative, content)
        written.append(relative)
    return written


def deterministic_source_archive(repo: Path) -> bytes:
    return run(["git", "archive", "--format=tar", "HEAD"], cwd=repo)


def build_bundle(
    *,
    inventory_path: Path,
    files_path: Path,
    policy_path: Path,
    lock_path: Path,
    repo: Path,
    output: Path,
    predicate_output: Path,
    version: str,
    source_date_epoch: int,
    require_approval: bool,
    require_image_revision: bool,
) -> None:
    inventory = load_json(inventory_path)
    files = load_json(files_path)
    policy = load_json(policy_path)
    verify_inventory(inventory, policy, require_approval=require_approval)
    verify_dockerfile_base(repo / "Dockerfile", policy)
    if require_image_revision:
        head = run(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
        verify_image_revision(inventory, version=version, source_revision=head)
    require_schema(files, "all-layer inventory")
    if files.get("platform") != inventory.get("platform") or files.get(
        "subject_digest"
    ) != inventory.get("subject_digest"):
        raise EvidenceError("component and all-layer inventories describe different images")

    with tempfile.TemporaryDirectory(prefix="extra-codeowners-evidence-") as temporary:
        root = Path(temporary) / "evidence"
        root.mkdir()
        write_file(root, "inventory/components.json", canonical_json(inventory))
        write_file(root, "inventory/all-layer-files.json", canonical_json(files))
        write_file(root, "policy/container-policy.json", canonical_json(policy))

        source_records: list[dict[str, Any]] = []
        license_records: list[dict[str, Any]] = []
        application_tar = deterministic_source_archive(repo)
        application_path = "sources/application/extra-codeowners.tar"
        write_file(root, application_path, application_tar)
        application_revision = run(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
        source_records.append(
            source_record(
                "extra-codeowners",
                f"https://github.com/stampbot/extra-codeowners/tree/{application_revision}",
                application_tar,
                application_path,
            )
        )
        license_records.extend(
            {"component": "extra-codeowners", "path": path}
            for path in extract_license_files(application_tar, "extra-codeowners", root)
        )

        docker_recipe = policy.get("docker_python_recipe")
        cpython = policy.get("cpython_source")
        for component, entry in (("docker-python-recipe", docker_recipe), ("cpython", cpython)):
            if not isinstance(entry, dict):
                raise EvidenceError(f"policy is missing {component}")
            content = fetch(str(entry.get("url", "")), str(entry.get("sha256", "")))
            filename = safe_filename(str(entry["url"]))
            relative = f"sources/base/{component}/{filename}"
            write_file(root, relative, content)
            source_records.append(source_record(component, entry["url"], content, relative))
            license_records.extend(
                {"component": component, "path": license_path}
                for license_path in extract_license_files(content, component, root)
            )
            license_url = entry.get("license_url")
            license_hash = entry.get("license_sha256")
            if license_url is not None or license_hash is not None:
                if not isinstance(license_url, str) or not isinstance(license_hash, str):
                    raise EvidenceError(f"invalid license source for {component}")
                license_content = fetch(license_url, license_hash)
                license_relative = f"licenses/from-source/{component}/LICENSE"
                write_file(root, license_relative, license_content)
                source_records.append(
                    source_record(
                        f"{component}-license", license_url, license_content, license_relative
                    )
                )
                license_records.append({"component": component, "path": license_relative})

        lock_sources = parse_lock_sources(lock_path)
        python_components = [
            component
            for component in inventory["components"]
            if component["ecosystem"] == "python" and component["name"] != "extra-codeowners"
        ]
        for component in python_components:
            key = (component["name"], component["version"])
            source = lock_sources.get(key)
            if source is None:
                source = source_policy_entry(policy, *key)
            url = source.get("url")
            expected = source.get("sha256")
            if not isinstance(url, str) or not isinstance(expected, str):
                raise EvidenceError(f"invalid Python source record: {key[0]} {key[1]}")
            content = fetch(url, expected)
            expected_size = source.get("size")
            if expected_size is not None and len(content) != expected_size:
                raise EvidenceError(f"size mismatch for Python source {key[0]} {key[1]}")
            component_id = f"python-{key[0]}-{key[1]}"
            relative = f"sources/python/{key[0]}/{key[1]}/{safe_filename(url)}"
            write_file(root, relative, content)
            source_records.append(source_record(component_id, url, content, relative))
            found = extract_license_files(content, component_id, root)
            if not found:
                raise EvidenceError(
                    f"Python source contains no license/notice file: {key[0]} {key[1]}"
                )
            license_records.extend({"component": component_id, "path": item} for item in found)

        alpine_components = [
            component for component in inventory["components"] if component["ecosystem"] == "alpine"
        ]
        origins: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for component in alpine_components:
            origins.setdefault((component["origin"], component["aports_commit"]), []).append(
                component
            )
        alpine_release = policy.get("alpine_distfiles_release")
        if not isinstance(alpine_release, str) or not re.fullmatch(r"v\d+\.\d+", alpine_release):
            raise EvidenceError("invalid Alpine distfiles release in policy")
        for (origin, commit), packages in sorted(origins.items()):
            recipe_url = (
                "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
                f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
            )
            expected_recipes = policy.get("alpine_recipe_archives", {})
            expected_recipe_hash = expected_recipes.get(f"{origin}@{commit}")
            if not isinstance(expected_recipe_hash, str):
                raise EvidenceError(f"no reviewed recipe archive hash for {origin}@{commit}")
            recipe = fetch(recipe_url, expected_recipe_hash)
            recipe_relative = f"sources/alpine/{origin}/{commit}/recipe.tar.gz"
            write_file(root, recipe_relative, recipe)
            source_records.append(
                source_record(f"alpine-{origin}-recipe", recipe_url, recipe, recipe_relative)
            )
            checksums, local_files = recipe_checksums(recipe, origin)
            upstream_count = 0
            for filename, expected_sha512 in sorted(checksums.items()):
                if filename in local_files:
                    continue
                upstream_count += 1
                url = (
                    f"https://distfiles.alpinelinux.org/distfiles/{alpine_release}/"
                    f"{urllib.parse.quote(filename, safe='')}"
                )
                content = fetch(url, expected_sha512, "sha512")
                relative = f"sources/alpine/{origin}/{commit}/distfiles/{filename}"
                write_file(root, relative, content)
                source_records.append(
                    source_record(
                        f"alpine-{origin}", url, content, relative, sha512=expected_sha512
                    )
                )
                found = extract_license_files(content, f"alpine-{origin}", root)
                license_records.extend(
                    {"component": f"alpine-{origin}", "path": item} for item in found
                )
            if upstream_count == 0:
                # A commit-pinned recipe subtree is the source for Alpine-native data packages.
                found = extract_license_files(recipe, f"alpine-{origin}", root)
                license_records.extend(
                    {"component": f"alpine-{origin}", "path": item} for item in found
                )
            for package in packages:
                package["source_recipe"] = recipe_relative

        for entry in policy.get("license_texts", []):
            if not isinstance(entry, dict):
                raise EvidenceError("invalid license text policy entry")
            identifier = entry.get("id")
            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9.+-]+", identifier):
                raise EvidenceError("invalid license identifier")
            content = fetch(str(entry.get("url", "")), str(entry.get("sha256", "")))
            relative = f"licenses/standard/{identifier}.txt"
            write_file(root, relative, content)
            license_records.append({"component": f"license:{identifier}", "path": relative})

        unique_license_records = {
            (record["component"], record["path"]): record for record in license_records
        }
        license_records = list(unique_license_records.values())
        custom_evidence = policy.get("custom_license_evidence", {})
        if not isinstance(custom_evidence, dict):
            raise EvidenceError("invalid custom-license evidence policy")
        inventory_by_key = {component_key(item): item for item in inventory["components"]}
        for identifier, requirement in custom_evidence.items():
            if (
                not isinstance(requirement, dict)
                or requirement.get("require_source_notice") is not True
            ):
                raise EvidenceError(f"invalid custom-license requirement: {identifier}")
            for key in requirement.get("components", []):
                component = inventory_by_key.get(key)
                if component is None:
                    raise EvidenceError(f"custom-license component is not in inventory: {key}")
                if component["ecosystem"] == "alpine":
                    evidence_component = f"alpine-{component['origin']}"
                else:
                    evidence_component = f"python-{component['name']}-{component['version']}"
                if not any(record["component"] == evidence_component for record in license_records):
                    raise EvidenceError(
                        f"no source-carried notice found for {identifier} component {key}"
                    )

        notices = [
            "# Third-party notices\n\n",
            "This inventory is evidence, not legal advice. License expressions are the reviewed "
            "project policy; the observed upstream metadata is retained separately.\n\n",
            "| Ecosystem | Component | Version | In effective filesystem | Observed | Reviewed |\n",
            "| --- | --- | --- | --- | --- | --- |\n",
        ]
        for component in sorted(inventory["components"], key=component_sort_key):
            observed = str(component["observed_license"]).replace("|", "\\|") or "Not declared"
            approved = resolved_license(component, policy).replace("|", "\\|")
            notices.append(
                f"| {component['ecosystem']} | {component['name']} | {component['version']} | "
                f"{'yes' if component['effective'] else 'no; retained in a lower layer'} | "
                f"{observed} | {approved} |\n"
            )
        notices.extend(
            [
                "\nThe archive includes the standard license texts named above, source-carried "
                "license and notice files, exact source archives, and commit-pinned Alpine "
                "recipes.\n"
            ]
        )
        write_file(root, "THIRD_PARTY_NOTICES.md", "".join(notices).encode())

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "name": "extra-codeowners-container-distribution-evidence",
            "version": version,
            "platform": inventory["platform"],
            "subject_digest": inventory["subject_digest"],
            "base_image_index_digest": policy["base_image_index_digest"],
            "policy_sha256": sha256_bytes(canonical_json(policy)),
            "source_records": sorted(source_records, key=lambda item: item["path"]),
            "license_records": sorted(
                license_records, key=lambda item: (item["component"], item["path"])
            ),
            "legal_status": (
                "Evidence archive; not a legal-compliance determination. "
                "See policy/distribution_approval and the project documentation."
            ),
        }
        write_file(root, "MANIFEST.json", canonical_json(manifest))
        checksum_lines = []
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(root).as_posix()
            checksum_lines.append(f"{sha256_bytes(path.read_bytes())}  {relative}\n")
        write_file(root, "SHA256SUMS", "".join(checksum_lines).encode())
        create_deterministic_tar(root, output, source_date_epoch)

    bundle_hash = sha256_bytes(output.read_bytes())
    output.with_suffix(output.suffix + ".sha256").write_text(f"{bundle_hash}  {output.name}\n")
    predicate = {
        "schema_version": SCHEMA_VERSION,
        "media_type": "application/vnd.stampbot.container-evidence.v1+tar+gzip",
        "platform": inventory["platform"],
        "subject_digest": inventory["subject_digest"],
        "artifact": {"filename": output.name, "sha256": bundle_hash},
        "release_url": f"https://github.com/stampbot/extra-codeowners/releases/tag/v{version}",
    }
    predicate_output.write_bytes(canonical_json(predicate))


def source_record(
    component: str, url: str, content: bytes, path: str, *, sha512: str | None = None
) -> dict[str, Any]:
    result = {
        "component": component,
        "url": url,
        "path": path,
        "size": len(content),
        "sha256": sha256_bytes(content),
    }
    if sha512 is not None:
        result["sha512"] = sha512
    return result


def create_deterministic_tar(root: Path, output: Path, source_date_epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(root).as_posix()
            content = path.read_bytes()
            info = tarfile.TarInfo(relative)
            info.size = len(content)
            info.mode = 0o644
            info.mtime = source_date_epoch
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(content))


def command_inventory(args: argparse.Namespace) -> None:
    inventory, files = image_inventory(
        args.image,
        args.platform,
        args.subject_digest,
        allow_config_digest_subject=args.allow_config_digest_subject,
    )
    Path(args.output).write_bytes(canonical_json(inventory))
    Path(args.files_output).write_bytes(canonical_json(files))


def command_verify(args: argparse.Namespace) -> None:
    verify_inventory(
        load_json(Path(args.inventory)),
        load_json(Path(args.policy)),
        require_approval=args.require_distribution_approval,
    )


def command_bundle(args: argparse.Namespace) -> None:
    build_bundle(
        inventory_path=Path(args.inventory),
        files_path=Path(args.files_inventory),
        policy_path=Path(args.policy),
        lock_path=Path(args.uv_lock),
        repo=Path(args.repo).resolve(),
        output=Path(args.output),
        predicate_output=Path(args.predicate_output),
        version=args.version,
        source_date_epoch=args.source_date_epoch,
        require_approval=args.require_distribution_approval,
        require_image_revision=args.require_image_revision,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(required=True)
    inventory = subcommands.add_parser("inventory", help="inventory a local single-platform image")
    inventory.add_argument("--image", required=True)
    inventory.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    inventory.add_argument("--subject-digest", required=True)
    inventory.add_argument("--output", required=True)
    inventory.add_argument("--files-output", required=True)
    inventory.add_argument(
        "--allow-config-digest-subject",
        action="store_true",
        help="allow a local-only config digest instead of a pulled repository manifest digest",
    )
    inventory.set_defaults(function=command_inventory)

    verify = subcommands.add_parser("verify", help="compare an inventory with reviewed policy")
    verify.add_argument("--inventory", required=True)
    verify.add_argument("--policy", default=".compliance/container-policy.json")
    verify.add_argument("--require-distribution-approval", action="store_true")
    verify.set_defaults(function=command_verify)

    bundle = subcommands.add_parser("bundle", help="collect and archive exact source evidence")
    bundle.add_argument("--inventory", required=True)
    bundle.add_argument("--files-inventory", required=True)
    bundle.add_argument("--policy", default=".compliance/container-policy.json")
    bundle.add_argument("--uv-lock", default="uv.lock")
    bundle.add_argument("--repo", default=".")
    bundle.add_argument("--output", required=True)
    bundle.add_argument("--predicate-output", required=True)
    bundle.add_argument("--version", required=True)
    bundle.add_argument("--source-date-epoch", required=True, type=int)
    bundle.add_argument("--require-distribution-approval", action="store_true")
    bundle.add_argument("--require-image-revision", action="store_true")
    bundle.set_defaults(function=command_bundle)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.function(args)
    except EvidenceError as exc:
        sys.stderr.write(f"container evidence error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

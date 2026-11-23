"""Index selected notice files in checksum-verified Cargo source archives."""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import tarfile
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

MAX_CRATE_EXPANDED = 64 * 1024 * 1024
MAX_CRATE_MEMBERS = 25_000
MAX_NOTICE = 1024 * 1024
_NOTICE_NAME = re.compile(
    r"(?:licen[cs]e|copying|copyright|notice|unlicense|authors)(?:[-_.].+)?\Z",
    re.IGNORECASE,
)
_PATH_PART = re.compile(r"[A-Za-z0-9_.+@-]{1,255}\Z")
_WIT_FILES = (
    ("LICENSE-APACHE", 10847, "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2"),
    (
        "LICENSE-Apache-2.0_WITH_LLVM-exception",
        12243,
        "268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5",
    ),
    ("LICENSE-MIT", 1023, "23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"),
)
_WIT_COMMIT = "f2393e6e98fa5f9236cac580db8a3fc9de6a4b70"
_WIT_CRATE = "6f42320e61fe2cfd34354ecb597f86f413484a798ba44a8ca1165c58d42da6c1"


class RustNoticeError(ValueError):
    """A source archive cannot supply the checked notice evidence."""


@dataclass(frozen=True)
class UpstreamNotice:
    path: str
    url: str
    size: int
    sha256: str

    def check(self, contents: bytes) -> None:
        if len(contents) != self.size or hashlib.sha256(contents).hexdigest() != self.sha256:
            raise RustNoticeError("upstream Rust notice differs from the reviewed file")


def supplements(sources: Sequence[dict[str, Any]]) -> dict[str, UpstreamNotice]:
    """Select the missing texts only for the reviewed wit-bindgen-rt archive."""
    result = {}
    for source in sources:
        if (source["name"], source["version"]) != ("wit-bindgen-rt", "0.39.0"):
            continue
        if source["sha256"] != _WIT_CRATE:
            raise RustNoticeError("wit-bindgen-rt source changed; review its upstream notices")
        base = f"https://raw.githubusercontent.com/bytecodealliance/wit-bindgen/{_WIT_COMMIT}"
        for filename, size, digest in _WIT_FILES:
            path = f"notices/wit-bindgen-rt/0.39.0/{filename}"
            result[path] = UpstreamNotice(path, f"{base}/{filename}", size, digest)
    return result


def _path(value: str) -> bool:
    return 0 < len(value) <= 512 and all(
        part not in {"", ".", ".."} and _PATH_PART.fullmatch(part) for part in value.split("/")
    )


def _regular_file(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile() or member.sparse is not None or not 0 < member.size <= MAX_NOTICE:
        raise RustNoticeError("Rust notice or manifest is not a bounded regular file")
    stream = archive.extractfile(member)
    assert stream is not None
    contents = stream.read(MAX_NOTICE + 1)
    if len(contents) != member.size:
        raise RustNoticeError("Rust notice or manifest size differs from the archive header")
    return contents


def inspect(source: dict[str, Any], contents: bytes) -> dict[str, Any]:
    """Locate Cargo metadata and notice candidates without extracting paths."""
    with gzip.GzipFile(fileobj=io.BytesIO(contents)) as stream:
        raw = stream.read(MAX_CRATE_EXPANDED + 1)
    if len(raw) > MAX_CRATE_EXPANDED:
        raise RustNoticeError("expanded Cargo archive exceeds its size limit")
    prefix = f"{source['name']}-{source['version']}/"
    members: dict[str, tarfile.TarInfo] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_CRATE_MEMBERS:
                raise RustNoticeError("Cargo archive has too many members")
            if member.isdir() and member.name == prefix[:-1]:
                continue
            path = member.name.removeprefix(prefix)
            if not member.name.startswith(prefix) or not _path(path) or path in members:
                raise RustNoticeError("Cargo archive has an invalid or duplicate path")
            members[path] = member
        if "Cargo.toml" not in members:
            raise RustNoticeError("Cargo archive omitted Cargo.toml")
        config = _regular_file(archive, members["Cargo.toml"])
        package = tomllib.loads(config.decode()).get("package")
        if not isinstance(package, dict) or (package.get("name"), package.get("version")) != (
            source["name"],
            source["version"],
        ):
            raise RustNoticeError("Cargo manifest identifies a different crate")
        declared_file = package.get("license-file")
        declared_license = package.get("license")
        if declared_license is not None and (
            not isinstance(declared_license, str) or not 0 < len(declared_license) <= 1024
        ):
            raise RustNoticeError("invalid Cargo license expression")
        candidate_paths = {
            path for path in members if _NOTICE_NAME.fullmatch(path.rsplit("/", 1)[-1])
        }
        if declared_file is not None:
            if not isinstance(declared_file, str) or declared_file not in members:
                raise RustNoticeError("Cargo archive omitted its declared license file")
            candidate_paths.add(declared_file)
        notices = []
        for path in sorted(candidate_paths):
            notice = _regular_file(archive, members[path])
            notices.append(
                {
                    "path": prefix + path,
                    "size": len(notice),
                    "sha256": hashlib.sha256(notice).hexdigest(),
                }
            )
    return {
        "crate_source": source["path"],
        "cargo_toml_sha256": hashlib.sha256(config).hexdigest(),
        "cargo_license": declared_license,
        "cargo_license_file": declared_file,
        "files": notices,
    }

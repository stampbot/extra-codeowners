"""Locate selected upstream notice texts without deciding binary licensing.

Callers must authenticate and hash-check the containing source bundle first.
This reader never extracts files or executes upstream code.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import tarfile
from typing import Any

MAX_EXPANDED = 512 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_NOTICE = 1024 * 1024
_NOTICES = {
    "openssl": ("openssl", ("LICENSE.txt",)),
    "libpq": ("postgresql", ("COPYRIGHT",)),
    "openldap": ("openldap", ("COPYRIGHT", "LICENSE")),
}
# Each reviewed label identifies a top-level source text, not all code in a wheel.
_SOURCE_LICENSES = {
    ("openssl", "3.5.4", "967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99"): (
        "openssl-3.5.4/LICENSE.txt",
        "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",
        "Apache-2.0",
    ),
    ("openssl", "4.0.1", "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"): (
        "openssl-4.0.1/LICENSE.txt",
        "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",
        "Apache-2.0",
    ),
    ("libpq", "18.0", "0d5b903b1e5fe361bca7aa9507519933773eb34266b1357c4e7780fdee6d6078"): (
        "postgresql-18.0/COPYRIGHT",
        "5ed3ce5c9373dff7f98b1fae7a6c7ccd98df7d734d46d24c1bcebf1240be8307",
        "PostgreSQL",
    ),
    ("openldap", "2.6.9", "2cb7dc73e9c8340dff0d99357fbaa578abf30cc6619f0521972c555681e6b2ff"): (
        "openldap-2.6.9/LICENSE",
        "310fe25c858a9515fc8c8d7d1f24a67c9496f84a91e0a0e41ea9975b1371e569",
        "OLDAP-2.8",
    ),
}


class NativeNoticeError(ValueError):
    """The source archive cannot supply bounded, unambiguous notice evidence."""


class _BoundedReader(io.RawIOBase):
    def __init__(self, stream: gzip.GzipFile | bz2.BZ2File) -> None:
        self.stream = stream
        self.remaining = MAX_EXPANDED

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(min(size, self.remaining + 1) if size >= 0 else self.remaining + 1)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise NativeNoticeError("expanded native source exceeds its size limit")
        return data


def inspect(source: dict[str, Any], contents: bytes) -> list[dict[str, Any]]:
    """Hash selected top-level notices in one already-verified upstream archive."""
    return describe_notices(read_notices(source, contents))


def describe_notices(notices: dict[str, bytes]) -> list[dict[str, Any]]:
    """Return paths and hashes without adding notice text to older catalogs."""
    return [
        {"path": path, "size": len(text), "sha256": hashlib.sha256(text).hexdigest()}
        for path, text in sorted(notices.items())
    ]


def read_notices(source: dict[str, Any], contents: bytes) -> dict[str, bytes]:
    """Read only the selected top-level files in a verified source archive."""
    component = source["source_component"]
    name, version = component["name"], component["version"]
    if name not in _NOTICES:
        raise NativeNoticeError("native source notice selection requires review")
    prefix, filenames = _NOTICES[name]
    expected = {f"{prefix}-{version}/{filename}" for filename in filenames}
    found: dict[str, bytes] = {}
    path = source["path"]
    if path.endswith((".tar.gz", ".tgz")):
        compressed: gzip.GzipFile | bz2.BZ2File = gzip.GzipFile(fileobj=io.BytesIO(contents))
    elif path.endswith(".tar.bz2"):
        compressed = bz2.BZ2File(io.BytesIO(contents))
    else:
        raise NativeNoticeError("unsupported native source notice archive")
    try:
        with compressed:
            reader = _BoundedReader(compressed)
            with tarfile.open(fileobj=reader, mode="r|") as archive:
                for index, member in enumerate(archive):
                    if index >= MAX_MEMBERS:
                        raise NativeNoticeError("native source has too many archive members")
                    if member.name not in expected:
                        continue
                    if (
                        member.name in found
                        or not member.isfile()
                        or member.sparse is not None
                        or not 0 < member.size <= MAX_NOTICE
                    ):
                        raise NativeNoticeError("notice must be one bounded regular source file")
                    stream = archive.extractfile(member)
                    assert stream is not None
                    data = stream.read(MAX_NOTICE + 1)
                    if len(data) != member.size:
                        raise NativeNoticeError("native source notice has an invalid size")
                    found[member.name] = data
            # Consume remaining compression data so truncation and expansion
            # after the tar end marker cannot escape the same byte budget.
            while reader.read(64 * 1024):
                pass
    except (OSError, EOFError, tarfile.TarError) as error:
        raise NativeNoticeError("invalid compressed native notice source") from error
    if set(found) != expected:
        raise NativeNoticeError("native source omitted a selected upstream notice")
    return found


def source_license_evidence(source: dict[str, Any], notices: dict[str, bytes]) -> dict[str, Any]:
    """Copy the reviewed source text into CycloneDX evidence, not a binary conclusion."""
    component = source["source_component"]
    key = (component["name"], component["version"], source["sha256"])
    review = _SOURCE_LICENSES.get(key)
    if review is None:
        raise NativeNoticeError("source license needs review for this archive")
    path, notice_sha256, license_id = review
    text = notices.get(path)
    if text is None or hashlib.sha256(text).hexdigest() != notice_sha256:
        raise NativeNoticeError("source license text differs from the reviewed notice")
    return {
        "licenses": [
            {
                "license": {
                    "id": license_id,
                    "text": {
                        "contentType": "text/plain",
                        "encoding": "base64",
                        "content": base64.b64encode(text).decode("ascii"),
                    },
                }
            }
        ]
    }

"""Locate selected upstream notice texts without deciding binary licensing.

Callers must authenticate and hash-check the containing source bundle first.
This reader never extracts files or executes upstream code.
"""

from __future__ import annotations

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
    component = source["source_component"]
    name, version = component["name"], component["version"]
    if name not in _NOTICES:
        raise NativeNoticeError("native source notice selection requires review")
    prefix, filenames = _NOTICES[name]
    expected = {f"{prefix}-{version}/{filename}" for filename in filenames}
    found: dict[str, dict[str, Any]] = {}
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
                    found[member.name] = {
                        "path": member.name,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
            # Consume remaining compression data so truncation and expansion
            # after the tar end marker cannot escape the same byte budget.
            while reader.read(64 * 1024):
                pass
    except (OSError, EOFError, tarfile.TarError) as error:
        raise NativeNoticeError("invalid compressed native notice source") from error
    if set(found) != expected:
        raise NativeNoticeError("native source omitted a selected upstream notice")
    return [found[path] for path in sorted(found)]

"""Selected source notices stay bounded and are not legal conclusions."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import tarfile
from collections.abc import Sequence

import pytest

from tools import release_native_notices as notices


def archive(members: Sequence[tuple[str, bytes | str]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for path, content in members:
            member = tarfile.TarInfo(path)
            if isinstance(content, str):
                member.type = tarfile.SYMTYPE
                member.linkname = content
                tar.addfile(member)
            else:
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
    return output.getvalue()


@pytest.mark.parametrize("extension", [".tar.gz", ".tgz", ".tar.bz2"])
def test_notice_identity_comes_from_source_bytes(extension: str) -> None:
    raw = archive([("openssl-9.8.7/LICENSE.txt", b"fictional upstream notice\n")])
    compressed = bz2.compress(raw) if extension.endswith("bz2") else gzip.compress(raw)
    source = {
        "source_component": {"name": "openssl", "version": "9.8.7"},
        "path": "embedded/fictional/source" + extension,
    }
    result = notices.inspect(source, compressed)
    assert result == [
        {
            "path": "openssl-9.8.7/LICENSE.txt",
            "size": 26,
            "sha256": hashlib.sha256(b"fictional upstream notice\n").hexdigest(),
        }
    ]


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate", "symlink", "hardlink", "empty", "oversize", "renamed"]
)
def test_ambiguous_or_missing_notice_cannot_be_reported(kind: str) -> None:
    path = "openssl-9.8.7/LICENSE.txt"
    entries: list[tuple[str, bytes | str]] = [(path, b"fictional")]
    if kind == "missing":
        entries = []
    elif kind == "renamed":
        entries = [("openssl-9.8.7/COPYING", b"fictional")]
    elif kind == "duplicate":
        entries *= 2
    elif kind in {"symlink", "hardlink"}:
        entries = [(path, "other")]
    elif kind == "empty":
        entries = [(path, b"")]
    else:
        entries = [(path, b"x" * (notices.MAX_NOTICE + 1))]
    raw = archive(entries)
    if kind == "hardlink":
        # Build the link explicitly rather than trusting a filesystem target.
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            member = tarfile.TarInfo(path)
            member.type, member.linkname = tarfile.LNKTYPE, "other"
            tar.addfile(member)
        raw = output.getvalue()
    with pytest.raises(notices.NativeNoticeError):
        notices.inspect(
            {
                "source_component": {"name": "openssl", "version": "9.8.7"},
                "path": "fictional.tar.gz",
            },
            gzip.compress(raw),
        )


@pytest.mark.parametrize("limit", ["bytes", "members"])
def test_limits_apply_to_unselected_source_members(
    monkeypatch: pytest.MonkeyPatch, limit: str
) -> None:
    entries = [("openssl-9.8.7/LICENSE.txt", b"fictional"), ("other", b"x" * 20000)]
    if limit == "bytes":
        monkeypatch.setattr(notices, "MAX_EXPANDED", 15000)
    else:
        monkeypatch.setattr(notices, "MAX_MEMBERS", 1)
    with pytest.raises(notices.NativeNoticeError):
        notices.inspect(
            {
                "source_component": {"name": "openssl", "version": "9.8.7"},
                "path": "fictional.tar.gz",
            },
            gzip.compress(archive(entries)),
        )


def test_compression_truncation_and_unreviewed_identity_fail() -> None:
    source = {
        "source_component": {"name": "openssl", "version": "9.8.7"},
        "path": "fictional.tar.gz",
    }
    encoded = gzip.compress(archive([("openssl-9.8.7/LICENSE.txt", b"fictional")]))
    with pytest.raises(notices.NativeNoticeError):
        notices.inspect(source, encoded[:-10])
    with pytest.raises(notices.NativeNoticeError):
        notices.inspect({**source, "path": "fictional.zip"}, encoded)
    with pytest.raises(notices.NativeNoticeError):
        notices.inspect(
            {**source, "source_component": {"name": "unreviewed", "version": "1"}}, encoded
        )


def test_selected_sparse_file_cannot_supply_notice_evidence() -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as tar:
        member = tarfile.TarInfo("openssl-9.8.7/LICENSE.txt")
        member.size = 8
        member.pax_headers = {"GNU.sparse.map": "0,8", "GNU.sparse.size": "16"}
        tar.addfile(member, io.BytesIO(b"fictional"[:8]))
    with pytest.raises(notices.NativeNoticeError):
        notices.inspect(
            {
                "source_component": {"name": "openssl", "version": "9.8.7"},
                "path": "fictional.tar.gz",
            },
            gzip.compress(output.getvalue()),
        )


def test_expansion_limit_also_covers_bytes_after_the_tar_end_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = archive([("openssl-9.8.7/LICENSE.txt", b"fictional")])
    monkeypatch.setattr(notices, "MAX_EXPANDED", len(raw) + 10)
    with pytest.raises(notices.NativeNoticeError, match="expanded native source"):
        notices.inspect(
            {
                "source_component": {"name": "openssl", "version": "9.8.7"},
                "path": "fictional.tar.gz",
            },
            gzip.compress(raw + b"x" * 20),
        )

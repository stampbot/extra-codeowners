import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from extra_codeowners.build_identity import (
    MAX_BUILD_IDENTITY_BYTES,
    BuildIdentity,
    BuildIdentityError,
    load_build_identity,
    parse_build_identity,
)

REVISION = "a" * 40
SHA256 = "b" * 64


def identity_bytes(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "source_revision": REVISION,
        "selection_record_sha256": SHA256,
        "wheel_filename": "extra_codeowners-0.1.0-py3-none-any.whl",
        "wheel_sha256": "c" * 64,
        "sdist_filename": "extra_codeowners-0.1.0.tar.gz",
        "sdist_sha256": "d" * 64,
    }
    value.update(overrides)
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def load_test_identity(path: Path) -> BuildIdentity | None:
    return load_build_identity(path, expected_owner_uid=os.getuid())


def test_parse_build_identity_accepts_verified_selection_result() -> None:
    identity = parse_build_identity(identity_bytes())

    assert identity.source_revision == REVISION
    assert identity.selection_record_sha256 == SHA256
    assert identity.wheel_filename.endswith(".whl")
    assert identity.wheel_sha256 == "c" * 64
    assert identity.sdist_filename.endswith(".tar.gz")
    assert identity.sdist_sha256 == "d" * 64


@pytest.mark.parametrize(
    "content, message",
    [
        (b"{}\n", "unexpected schema"),
        (identity_bytes(schema_version=True), "schema version"),
        (identity_bytes(source_revision="main"), "source revision"),
        (identity_bytes(wheel_sha256="f" * 63), "artifact digest"),
        (identity_bytes(wheel_filename="../project.whl"), "artifact filename"),
        (identity_bytes(wheel_filename="project.zip"), "artifact type"),
        (identity_bytes(sdist_filename="project.zip"), "artifact type"),
        (identity_bytes().rstrip(), "canonical JSON"),
        (b'{"schema_version":1,"schema_version":1}\n', "canonical JSON"),
        (b'{"schema_version":NaN}\n', "canonical JSON"),
    ],
)
def test_parse_build_identity_rejects_untrusted_content(content: bytes, message: str) -> None:
    with pytest.raises(BuildIdentityError, match=message):
        parse_build_identity(content)


def test_load_build_identity_returns_none_only_when_file_is_absent(tmp_path: Path) -> None:
    assert load_test_identity(tmp_path / "missing.json") is None


def test_load_build_identity_reads_a_non_writable_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "build-identity.json"
    path.write_bytes(identity_bytes())
    path.chmod(0o444)

    identity = load_test_identity(path)

    assert identity is not None
    assert identity.source_revision == REVISION


@pytest.mark.parametrize("mode", [0o400, 0o440, 0o640, 0o644])
def test_load_build_identity_requires_exact_mode_0444(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "build-identity.json"
    path.write_bytes(identity_bytes())
    path.chmod(mode)

    with pytest.raises(BuildIdentityError, match="mode 0444"):
        load_test_identity(path)


def test_load_build_identity_rejects_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(identity_bytes())
    target.chmod(0o444)
    link = tmp_path / "build-identity.json"
    link.symlink_to(target)

    with pytest.raises(BuildIdentityError, match="opened safely"):
        load_test_identity(link)


def test_load_build_identity_rejects_a_directory(tmp_path: Path) -> None:
    path = tmp_path / "build-identity.json"
    path.mkdir()
    path.chmod(0o555)

    with pytest.raises(BuildIdentityError, match="regular file"):
        load_test_identity(path)


def test_load_build_identity_rejects_oversized_content(tmp_path: Path) -> None:
    path = tmp_path / "build-identity.json"
    path.write_bytes(b"x" * (MAX_BUILD_IDENTITY_BYTES + 1))
    path.chmod(0o444)

    with pytest.raises(BuildIdentityError, match="size limit"):
        load_test_identity(path)


def test_load_build_identity_requires_the_expected_owner(tmp_path: Path) -> None:
    path = tmp_path / "build-identity.json"
    path.write_bytes(identity_bytes())
    path.chmod(0o444)

    with pytest.raises(BuildIdentityError, match="unexpected owner"):
        load_build_identity(path, expected_owner_uid=os.getuid() + 1)


def test_load_build_identity_rejects_a_hard_link(tmp_path: Path) -> None:
    path = tmp_path / "build-identity.json"
    path.write_bytes(identity_bytes())
    path.chmod(0o444)
    (tmp_path / "second-link.json").hardlink_to(path)

    with pytest.raises(BuildIdentityError, match="exactly one hard link"):
        load_test_identity(path)


def test_load_build_identity_rejects_a_fifo_without_blocking(tmp_path: Path) -> None:
    path = tmp_path / "build-identity.json"
    os.mkfifo(path, mode=0o444)

    with pytest.raises(BuildIdentityError, match="regular file"):
        load_test_identity(path)


def test_load_build_identity_rejects_a_device() -> None:
    with pytest.raises(BuildIdentityError, match="regular file"):
        load_build_identity(Path("/dev/null"), expected_owner_uid=0)


def test_load_build_identity_rejects_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "build-identity.json"
    path.write_bytes(identity_bytes())
    path.chmod(0o444)
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = real_fstat(descriptor)
        if calls == 1:
            return metadata
        return SimpleNamespace(
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_mode=metadata.st_mode,
            st_nlink=metadata.st_nlink,
            st_uid=metadata.st_uid,
            st_gid=metadata.st_gid,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns + 1,
            st_ctime_ns=metadata.st_ctime_ns,
        )

    monkeypatch.setattr("extra_codeowners.build_identity.os.fstat", changing_fstat)

    with pytest.raises(BuildIdentityError, match="changed while it was read"):
        load_test_identity(path)

"""Adversarial tests for the raw OCI release-spine transport contract."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from release_spine_fixtures import HOSTILE_LAYER, generate_layout

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".github" / "scripts"
REVISION = "1" * 40
WORKFLOW_SHA = "2" * 40
WHEEL_SHA256 = "a" * 64
SELECTION_SHA256 = "b" * 64
PYTHON_ARTIFACT_SHA256 = "c" * 64
BASH = shutil.which("bash")


def load_script(name: str) -> ModuleType:
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


release_spine = load_script("release_spine")
builder = load_script("build_release_spine")


@dataclass(frozen=True)
class BuiltSpine:
    layout: Path
    spine: Path
    record: Path
    index_digest: str
    expected: Any


def expected_identity(*, index_digest: str = f"sha256:{'0' * 64}") -> Any:
    return release_spine.ExpectedIdentity(
        repository_id="123456",
        repository_name="stampbot/extra-codeowners",
        run_id="777777",
        run_attempt="2",
        source_revision=REVISION,
        version="0.1.0",
        workflow_path=".github/workflows/ci.yml",
        workflow_ref=("stampbot/extra-codeowners/.github/workflows/ci.yml@refs/heads/main"),
        workflow_sha=WORKFLOW_SHA,
        candidate_registry="ghcr.io",
        candidate_repository="stampbot/extra-codeowners",
        candidate_tag=f"release-candidate-{REVISION}",
        index_digest=index_digest,
        python_artifact_id="789012",
        python_artifact_sha256=PYTHON_ARTIFACT_SHA256,
        wheel_sha256=WHEEL_SHA256,
        selection_record_sha256=SELECTION_SHA256,
    )


def make_layout(path: Path, expected: Any) -> str:
    return generate_layout(
        path,
        source_revision=expected.source_revision,
        version=expected.version,
        wheel_sha256=expected.wheel_sha256,
        selection_record_sha256=expected.selection_record_sha256,
        candidate_registry=expected.candidate_registry,
        candidate_repository=expected.candidate_repository,
        candidate_tag=expected.candidate_tag,
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_record(path: Path, record: object) -> str:
    path.write_bytes(release_spine.canonical_json(record))
    return sha256(path)


def source_objects_exceeding_spine_limit(tmp_path: Path) -> list[Any]:
    selected = [
        builder.SourceObject(
            kind="layer",
            media_type=release_spine.OCI_LAYER,
            digest=f"sha256:{index:064x}",
            size=release_spine.MAX_OBJECT_BYTES,
            path=tmp_path / f"object-{index}",
        )
        for index in range(4)
    ]
    selected.append(
        builder.SourceObject(
            kind="layer",
            media_type=release_spine.OCI_LAYER,
            digest=f"sha256:{4:064x}",
            size=1,
            path=tmp_path / "overflowing-object",
        )
    )
    return selected


def rewrite_root_index(layout: Path, mutation: str) -> str:
    wrapper_path = layout / "index.json"
    wrapper = json.loads(wrapper_path.read_bytes())
    descriptor = wrapper["manifests"][0]
    old_digest = descriptor["digest"].removeprefix("sha256:")
    old_path = layout / "blobs" / "sha256" / old_digest
    root = json.loads(old_path.read_bytes())
    platform = root["manifests"][0]
    if mutation == "docker":
        platform["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
    elif mutation == "nested-index":
        platform["mediaType"] = release_spine.OCI_INDEX
    elif mutation == "attestation":
        platform["annotations"] = {"vnd.docker.reference.type": "attestation-manifest"}
    else:  # pragma: no cover - test helper misuse
        raise AssertionError(mutation)
    root_bytes = release_spine.canonical_json(root)
    new_digest = hashlib.sha256(root_bytes).hexdigest()
    old_path.unlink()
    (layout / "blobs" / "sha256" / new_digest).write_bytes(root_bytes)
    descriptor["digest"] = f"sha256:{new_digest}"
    descriptor["size"] = len(root_bytes)
    wrapper_path.write_bytes(release_spine.canonical_json(wrapper))
    return f"sha256:{new_digest}"


@pytest.fixture
def built_spine(tmp_path: Path) -> BuiltSpine:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    index_digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=index_digest)
    spine = tmp_path / release_spine.expected_spine_filename(
        REVISION,
        expected.python_artifact_id,
        expected.run_id,
        expected.run_attempt,
    )
    record = tmp_path / release_spine.expected_record_filename(
        REVISION,
        expected.python_artifact_id,
        expected.run_id,
        expected.run_attempt,
    )
    builder.build(layout, spine, record, index_digest, expected)
    return BuiltSpine(layout, spine, record, index_digest, expected)


def verified_record(bundle: BuiltSpine) -> Any:
    return release_spine.verify(
        bundle.record,
        bundle.spine,
        bundle.expected,
        record_artifact_sha256=sha256(bundle.record),
        spine_artifact_sha256=sha256(bundle.spine),
    )


def test_build_and_verify_complete_two_platform_spine(built_spine: BuiltSpine) -> None:
    record = verified_record(built_spine)

    assert built_spine.spine.stat().st_mode & 0o777 == 0o600
    assert built_spine.record.stat().st_mode & 0o777 == 0o600
    assert [(item["architecture"], item["os"]) for item in record["platforms"]] == [
        ("amd64", "linux"),
        ("arm64", "linux"),
    ]
    assert record["spine"]["sha256"] == sha256(built_spine.spine)
    assert record["run"] == {
        "attempt": built_spine.expected.run_attempt,
        "id": built_spine.expected.run_id,
    }
    assert built_spine.record.read_bytes() == release_spine.canonical_json(record)
    assert record["platforms"][0]["layers"] == record["platforms"][1]["layers"]
    assert sum(item["kind"] == "layer" for item in record["objects"]) == 1
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    with release_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=sha256(built_spine.spine),
    ) as verified:
        chunks = verified.object_chunks(layer["digest"])
        assert isinstance(chunks, tuple)
        assert all(isinstance(chunk, bytes) for chunk in chunks)
        assert b"".join(chunks) == HOSTILE_LAYER
        with pytest.raises(release_spine.SpineError, match="not uniquely present"):
            verified.object_chunks(f"sha256:{'f' * 64}")


def test_build_is_deterministic_across_layout_metadata(tmp_path: Path) -> None:
    provisional = expected_identity()
    outputs: list[tuple[bytes, bytes]] = []
    for index in range(2):
        root = tmp_path / str(index)
        root.mkdir()
        layout = root / "layout"
        digest = make_layout(layout, provisional)
        expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
        if index:
            for path in layout.rglob("*"):
                os.utime(path, ns=(1_900_000_000_000_000_000,) * 2, follow_symlinks=False)
        spine = root / release_spine.expected_spine_filename(
            REVISION,
            expected.python_artifact_id,
            expected.run_id,
            expected.run_attempt,
        )
        record = root / release_spine.expected_record_filename(
            REVISION,
            expected.python_artifact_id,
            expected.run_id,
            expected.run_attempt,
        )
        builder.build(layout, spine, record, digest, expected)
        outputs.append((spine.read_bytes(), record.read_bytes()))

    assert outputs[0] == outputs[1]


def test_raw_filenames_bind_python_artifact_run_and_attempt() -> None:
    first = release_spine.expected_spine_filename(REVISION, "789012", "777777", "2")
    second = release_spine.expected_spine_filename(REVISION, "789012", "777777", "3")
    other_run = release_spine.expected_spine_filename(REVISION, "789012", "777778", "2")
    other_artifact = release_spine.expected_spine_filename(REVISION, "789013", "777777", "2")

    assert len({first, second, other_run, other_artifact}) == 4
    assert first.endswith("-python-artifact-789012-run-777777-attempt-2.bin")
    assert (
        release_spine.expected_record_filename(REVISION, "789012", "777777", "2")
        == first.removesuffix(".bin") + ".spine.json"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "0"),
        ("run_id", str(release_spine.MAX_ID + 1)),
        ("run_attempt", "01"),
        ("run_attempt", str(release_spine.MAX_ID + 1)),
    ],
)
def test_run_identity_is_a_bounded_canonical_decimal(field: str, value: str) -> None:
    expected = release_spine.dataclasses.replace(expected_identity(), **{field: value})

    with pytest.raises(release_spine.SpineError):
        release_spine.validate_expected_identity(expected)


def test_builder_requests_owner_only_output_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_open = os.open
    requested_modes: list[int] = []

    def capture_mode(path: Any, flags: int, mode: int) -> int:
        requested_modes.append(mode)
        return actual_open(path, flags, mode)

    monkeypatch.setattr(builder.os, "open", capture_mode)
    descriptor = builder._create_output(tmp_path / "spine.bin", "test")
    os.close(descriptor)

    assert requested_modes == [0o600]


def test_builder_never_overwrites_an_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "spine.bin"
    output.write_bytes(b"existing")

    with pytest.raises(release_spine.SpineError, match="cannot create"):
        builder._create_output(output, "test")

    assert output.read_bytes() == b"existing"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"a":1,"a":2}', "repeats JSON key"),
        (b'{"a":1.0}', "floating-point"),
        (b'{"a":NaN}', "non-finite"),
        (b'{"a":' + b"9" * 5000 + b"}", "not valid bounded JSON"),
        (b"[[[[[[[[[1]]]]]]]]]", "JSON depth limit"),
        (b'"\xff"', "not UTF-8"),
    ],
)
def test_strict_json_rejects_ambiguous_or_oversized_values(raw: bytes, message: str) -> None:
    with pytest.raises(release_spine.SpineError, match=message):
        release_spine.strict_json_bytes(raw, "test JSON", canonical=False)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"b":2,"a":1}\n',
        b'{"a": 1}\n',
        b'{"a":1}\r\n',
        b'{"a":1}',
        b'\xef\xbb\xbf{"a":1}\n',
    ],
)
def test_canonical_json_rejects_alternate_encodings(raw: bytes) -> None:
    with pytest.raises(release_spine.SpineError):
        release_spine.strict_json_bytes(raw, "test JSON", canonical=True)


@pytest.mark.parametrize("field", ["schema_version", "objects.0.offset"])
def test_record_rejects_boolean_integer_fields(built_spine: BuiltSpine, field: str) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    if field == "schema_version":
        record["schema_version"] = True
    else:
        record["objects"][0]["offset"] = False
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


def test_record_rejects_unknown_fields(built_spine: BuiltSpine) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    record["future_field"] = "not negotiated"
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match="must contain exactly"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository_id", "999"),
        ("repository_name", "stampbot/other"),
        ("run_id", "777778"),
        ("run_attempt", "3"),
        ("source_revision", "3" * 40),
        ("version", "0.2.0"),
        ("workflow_path", ".github/workflows/release.yml"),
        (
            "workflow_ref",
            "stampbot/extra-codeowners/.github/workflows/ci.yml@refs/tags/v0.1.0",
        ),
        ("workflow_sha", "3" * 40),
        ("candidate_registry", "registry.example.com"),
        ("candidate_repository", "stampbot/other"),
        ("index_digest", f"sha256:{'d' * 64}"),
        ("python_artifact_id", "999"),
        ("python_artifact_sha256", "d" * 64),
        ("wheel_sha256", "d" * 64),
        ("selection_record_sha256", "d" * 64),
    ],
)
def test_record_is_bound_to_every_trusted_identity(
    built_spine: BuiltSpine, field: str, value: str
) -> None:
    changed = release_spine.dataclasses.replace(built_spine.expected, **{field: value})
    with pytest.raises(release_spine.SpineError):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            changed,
            record_artifact_sha256=sha256(built_spine.record),
            spine_artifact_sha256=sha256(built_spine.spine),
        )


@pytest.mark.parametrize("artifact", ["record", "spine"])
def test_provider_digest_mismatch_fails_closed(built_spine: BuiltSpine, artifact: str) -> None:
    kwargs = {
        "record_artifact_sha256": sha256(built_spine.record),
        "spine_artifact_sha256": sha256(built_spine.spine),
    }
    kwargs[f"{artifact}_artifact_sha256"] = "0" * 64
    with pytest.raises(release_spine.SpineError, match="provider digest"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            **kwargs,
        )


def test_record_cannot_substitute_the_trusted_root_digest(
    built_spine: BuiltSpine,
) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    record["index"]["digest"] = f"sha256:{'d' * 64}"
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match="trusted BuildKit value"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


def test_cli_cannot_substitute_the_trusted_root_digest(
    built_spine: BuiltSpine, capsys: pytest.CaptureFixture[str]
) -> None:
    expected = built_spine.expected
    result = release_spine.main(
        [
            "verify",
            "--record",
            str(built_spine.record),
            "--spine",
            str(built_spine.spine),
            "--record-artifact-sha256",
            sha256(built_spine.record),
            "--spine-artifact-sha256",
            sha256(built_spine.spine),
            "--repository-id",
            expected.repository_id,
            "--repository-name",
            expected.repository_name,
            "--run-id",
            expected.run_id,
            "--run-attempt",
            expected.run_attempt,
            "--source-revision",
            expected.source_revision,
            "--version",
            expected.version,
            "--workflow-path",
            expected.workflow_path,
            "--workflow-ref",
            expected.workflow_ref,
            "--workflow-sha",
            expected.workflow_sha,
            "--candidate-registry",
            expected.candidate_registry,
            "--candidate-repository",
            expected.candidate_repository,
            "--candidate-tag",
            expected.candidate_tag,
            "--index-digest",
            f"sha256:{'d' * 64}",
            "--python-artifact-id",
            expected.python_artifact_id,
            "--python-artifact-sha256",
            expected.python_artifact_sha256,
            "--wheel-sha256",
            expected.wheel_sha256,
            "--selection-record-sha256",
            expected.selection_record_sha256,
        ]
    )
    assert result == 1
    assert "trusted BuildKit value" in capsys.readouterr().err


@pytest.mark.parametrize("delta", [-1, 1])
def test_record_rejects_range_gaps_and_overlaps(built_spine: BuiltSpine, delta: int) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    record["objects"][1]["offset"] += delta
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match="gap, overlap, or alias"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


def test_record_rejects_out_of_order_objects(built_spine: BuiltSpine) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    first, second = record["objects"][:2]
    record["objects"][:2] = [
        {**second, "offset": 0},
        {**first, "offset": second["size"]},
    ]
    running = first["size"] + second["size"]
    for item in record["objects"][2:]:
        item["offset"] = running
        running += item["size"]
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match="canonical streaming order"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


def test_record_rejects_digest_reuse_across_object_kinds(
    built_spine: BuiltSpine,
) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    record["objects"][1]["digest"] = record["objects"][0]["digest"]
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match="repeated or reused"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


@pytest.mark.parametrize("mutation", ["missing", "swapped", "extra"])
def test_record_rejects_missing_swapped_or_extra_platforms(
    built_spine: BuiltSpine, mutation: str
) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    if mutation == "missing":
        record["platforms"].pop()
    elif mutation == "swapped":
        record["platforms"].reverse()
    else:
        record["platforms"].append(copy.deepcopy(record["platforms"][0]))
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match="platform"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


@pytest.mark.parametrize("limit", ["count", "size"])
def test_record_enforces_object_count_and_size_bounds(built_spine: BuiltSpine, limit: str) -> None:
    record = copy.deepcopy(verified_record(built_spine))
    if limit == "count":
        record["objects"] = [copy.deepcopy(record["objects"][0])] * (release_spine.MAX_OBJECTS + 1)
    else:
        layer = next(item for item in record["objects"] if item["kind"] == "layer")
        layer["size"] = release_spine.MAX_OBJECT_BYTES + 1
    record_hash = write_record(built_spine.record, record)
    with pytest.raises(release_spine.SpineError, match=r"count|bounds"):
        release_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            record_artifact_sha256=record_hash,
            spine_artifact_sha256=sha256(built_spine.spine),
        )


@pytest.mark.parametrize("position", [0, -1])
def test_spine_tamper_at_range_boundaries_fails_closed(
    built_spine: BuiltSpine, position: int
) -> None:
    record = verified_record(built_spine)
    content = bytearray(built_spine.spine.read_bytes())
    content[position] ^= 0x01
    built_spine.spine.write_bytes(content)
    with (
        pytest.raises(release_spine.SpineError, match="digest mismatch"),
        release_spine.open_verified_spine(
            built_spine.spine,
            record,
            artifact_sha256=record["spine"]["sha256"],
        ),
    ):
        pass


def test_spine_rejects_trailing_bytes(built_spine: BuiltSpine) -> None:
    record = verified_record(built_spine)
    with built_spine.spine.open("ab") as destination:
        destination.write(b"trailing")
    with (
        pytest.raises(release_spine.SpineError, match="size does not match"),
        release_spine.open_verified_spine(
            built_spine.spine,
            record,
            artifact_sha256=record["spine"]["sha256"],
        ),
    ):
        pass


def test_same_descriptor_consumer_rejects_a_mutated_object_without_exposure(
    built_spine: BuiltSpine,
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    exposed: list[bytes] = []
    with (
        pytest.raises(release_spine.SpineError, match="changed"),
        release_spine.open_verified_spine(
            built_spine.spine,
            record,
            artifact_sha256=record["spine"]["sha256"],
        ) as verified,
    ):
        content = bytearray(built_spine.spine.read_bytes())
        content[layer["offset"]] ^= 0x01
        built_spine.spine.write_bytes(content)
        exposed.extend(verified.object_chunks(layer["digest"]))

    assert exposed == []


def test_object_chunks_stages_only_the_exact_recorded_range(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    actual_pread = os.pread
    reads: list[tuple[int, int]] = []

    monkeypatch.setattr(release_spine, "READ_CHUNK_BYTES", 8)
    with release_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=record["spine"]["sha256"],
    ) as verified:

        def traced_pread(descriptor: int, count: int, offset: int) -> bytes:
            if descriptor == verified.descriptor:
                reads.append((offset, count))
            return actual_pread(descriptor, count, offset)

        monkeypatch.setattr(release_spine.os, "pread", traced_pread)
        chunks = verified.object_chunks(layer["digest"])

    expected_reads: list[tuple[int, int]] = []
    remaining = layer["size"]
    offset = layer["offset"]
    while remaining:
        count = min(8, remaining)
        expected_reads.append((offset, count))
        offset += count
        remaining -= count

    assert reads == expected_reads
    assert b"".join(chunks) == HOSTILE_LAYER


def test_object_chunks_rejects_a_corrupt_final_chunk_without_exposure(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    actual_pread = os.pread
    exposed: list[bytes] = []

    monkeypatch.setattr(release_spine, "READ_CHUNK_BYTES", 8)
    with release_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=record["spine"]["sha256"],
    ) as verified:

        def corrupt_final_chunk(descriptor: int, count: int, offset: int) -> bytes:
            chunk = actual_pread(descriptor, count, offset)
            if descriptor == verified.descriptor and offset + len(chunk) == (
                layer["offset"] + layer["size"]
            ):
                changed = bytearray(chunk)
                changed[-1] ^= 0x01
                return bytes(changed)
            return chunk

        monkeypatch.setattr(release_spine.os, "pread", corrupt_final_chunk)
        with pytest.raises(release_spine.SpineError, match="before an object could be exposed"):
            exposed.extend(verified.object_chunks(layer["digest"]))

    assert exposed == []


def test_object_chunks_rejects_early_eof_without_exposure(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    actual_pread = os.pread
    reads = 0
    exposed: list[bytes] = []

    monkeypatch.setattr(release_spine, "READ_CHUNK_BYTES", 8)
    with release_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=record["spine"]["sha256"],
    ) as verified:

        def truncated_pread(descriptor: int, count: int, offset: int) -> bytes:
            nonlocal reads
            reads += 1
            if reads == 2:
                return b""
            return actual_pread(descriptor, count, offset)

        monkeypatch.setattr(release_spine.os, "pread", truncated_pread)
        with pytest.raises(release_spine.SpineError, match="changed while a range was read"):
            exposed.extend(verified.object_chunks(layer["digest"]))

    assert reads == 2
    assert exposed == []


def test_object_chunks_snapshot_is_immutable_after_source_mutation(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    monkeypatch.setattr(release_spine, "READ_CHUNK_BYTES", 8)
    chunks: tuple[bytes, ...] = ()

    with (
        pytest.raises(release_spine.SpineError, match="changed"),
        release_spine.open_verified_spine(
            built_spine.spine,
            record,
            artifact_sha256=record["spine"]["sha256"],
        ) as verified,
    ):
        chunks = verified.object_chunks(layer["digest"])
        content = bytearray(built_spine.spine.read_bytes())
        content[layer["offset"]] ^= 0x01
        built_spine.spine.write_bytes(content)
        assert b"".join(chunks) == HOSTILE_LAYER

    assert len(chunks) > 1
    assert all(isinstance(chunk, bytes) for chunk in chunks)


def test_object_chunks_uses_the_immutable_validated_range_snapshot(
    built_spine: BuiltSpine,
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    with release_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=record["spine"]["sha256"],
    ) as verified:
        layer["offset"] = record["spine"]["size"]
        layer["size"] = 1
        assert b"".join(verified.object_chunks(layer["digest"])) == HOSTILE_LAYER


def test_object_chunks_normalizes_a_staging_read_failure(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = verified_record(built_spine)
    layer = next(item for item in record["objects"] if item["kind"] == "layer")
    with release_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=record["spine"]["sha256"],
    ) as verified:

        def fail_pread(*args: Any) -> bytes:
            raise OSError("staging read failed")

        monkeypatch.setattr(release_spine.os, "pread", fail_pread)
        with pytest.raises(release_spine.SpineError, match="cannot stage"):
            verified.object_chunks(layer["digest"])


@pytest.mark.parametrize("artifact", ["record", "spine"])
def test_verifier_rejects_symlink_artifacts(
    built_spine: BuiltSpine, tmp_path: Path, artifact: str
) -> None:
    original = getattr(built_spine, artifact)
    original.rename(tmp_path / f"real-{original.name}")
    original.symlink_to(tmp_path / f"real-{original.name}")
    with pytest.raises(release_spine.SpineError, match="cannot open"):
        verified_record(built_spine)


def test_verifier_normalizes_a_disappearing_path(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disappeared(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError

    monkeypatch.setattr(release_spine.os, "stat", disappeared)
    with pytest.raises(release_spine.SpineError, match="path changed while it was opened"):
        release_spine.load_record(built_spine.record, built_spine.expected)


def test_builder_rejects_orphan_blob(tmp_path: Path) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    (layout / "blobs" / "sha256" / ("f" * 64)).write_bytes(b"orphan")

    with pytest.raises(release_spine.SpineError, match="missing or orphan"):
        builder.inspect_layout(layout, digest, expected)


def test_builder_accepts_the_empty_pinned_buildkit_ingest_root(tmp_path: Path) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)

    builder.inspect_layout(layout, digest, expected)

    assert (layout / "ingest").is_dir()
    assert not any((layout / "ingest").iterdir())


@pytest.mark.parametrize("mutation", ["missing", "file", "symlink", "nonempty"])
def test_builder_rejects_a_noncanonical_buildkit_ingest_root(tmp_path: Path, mutation: str) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    ingest = layout / "ingest"
    ingest.rmdir()
    if mutation == "file":
        ingest.write_bytes(b"unexpected")
    elif mutation == "symlink":
        target = tmp_path / "ingest-target"
        target.mkdir()
        ingest.symlink_to(target, target_is_directory=True)
    elif mutation == "nonempty":
        ingest.mkdir()
        (ingest / "partial").write_bytes(b"unexpected")

    with pytest.raises(release_spine.SpineError, match=r"top-level|real directory|not empty"):
        builder.inspect_layout(layout, digest, expected)


def test_builder_rejects_symlink_blob(tmp_path: Path) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    root = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    content = root.read_bytes()
    root.unlink()
    target = tmp_path / "root-index"
    target.write_bytes(content)
    root.symlink_to(target)

    with pytest.raises(release_spine.SpineError, match="cannot open"):
        builder.inspect_layout(layout, digest, expected)


def test_builder_parses_each_hashed_metadata_buffer_without_reopening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    original = builder._read_regular
    reads: dict[Path, int] = {}

    def counted(path: Path, *args: Any, **kwargs: Any) -> bytes:
        if path.parent == layout / "blobs" / "sha256":
            reads[path] = reads.get(path, 0) + 1
        return cast(bytes, original(path, *args, **kwargs))

    monkeypatch.setattr(builder, "_read_regular", counted)
    builder.inspect_layout(layout, digest, expected)

    assert len(reads) == 5
    assert set(reads.values()) == {1}


def test_builder_rejects_wrong_trusted_root_digest(tmp_path: Path) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    with pytest.raises(release_spine.SpineError, match="digest inputs disagree"):
        builder.inspect_layout(layout, f"sha256:{'0' * 64}", expected)


@pytest.mark.parametrize("mutation", ["docker", "nested-index", "attestation"])
def test_builder_rejects_non_image_platform_descriptors(tmp_path: Path, mutation: str) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    make_layout(layout, provisional)
    digest = rewrite_root_index(layout, mutation)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    with pytest.raises(release_spine.SpineError, match=r"exactly|digest or media type"):
        builder.inspect_layout(layout, digest, expected)


def test_builder_bounds_directory_enumeration_before_materializing_extra_entries(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "entries"
    directory.mkdir()
    for name in ("one", "two", "three"):
        (directory / name).write_bytes(b"x")

    with pytest.raises(release_spine.SpineError, match="too many entries"):
        builder._directory_names(directory, "test directory", maximum=2)


def test_builder_rejects_prospective_spine_overflow_without_reading_objects(
    tmp_path: Path,
) -> None:
    objects = {
        selected.digest: selected for selected in source_objects_exceeding_spine_limit(tmp_path)
    }

    with pytest.raises(release_spine.SpineError, match="size limit"):
        builder._bounded_objects(objects)


def test_layout_aggregate_preflight_runs_before_opaque_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provisional = expected_identity()
    layout = tmp_path / "layout"
    digest = make_layout(layout, provisional)
    expected = release_spine.dataclasses.replace(provisional, index_digest=digest)
    opaque_checks: list[Any] = []

    def reject_graph(objects: Any) -> Any:
        raise release_spine.SpineError("prospective graph rejected")

    monkeypatch.setattr(builder, "_bounded_objects", reject_graph)
    monkeypatch.setattr(
        builder,
        "_check_opaque_object",
        lambda *args: opaque_checks.append(args),
    )

    with pytest.raises(release_spine.SpineError, match="prospective graph rejected"):
        builder.inspect_layout(layout, digest, expected)
    assert opaque_checks == []


def test_builder_rejects_total_overflow_before_copying_the_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = expected_identity()
    selected = source_objects_exceeding_spine_limit(tmp_path)
    copied: list[int] = []
    monkeypatch.setattr(builder, "inspect_layout", lambda *args: ({}, [], selected))
    monkeypatch.setattr(
        builder,
        "_copy_object",
        lambda output, source, whole: copied.append(source.size),
    )

    with pytest.raises(release_spine.SpineError, match="total size limit"):
        builder.build(
            tmp_path / "unused-layout",
            tmp_path
            / release_spine.expected_spine_filename(
                REVISION,
                expected.python_artifact_id,
                expected.run_id,
                expected.run_attempt,
            ),
            tmp_path
            / release_spine.expected_record_filename(
                REVISION,
                expected.python_artifact_id,
                expected.run_id,
                expected.run_attempt,
            ),
            expected.index_digest,
            expected,
        )

    assert copied == [release_spine.MAX_OBJECT_BYTES] * 4


def test_production_spine_scripts_have_no_archive_or_process_parser() -> None:
    forbidden_imports = {"gzip", "shutil", "subprocess", "tarfile", "zipfile"}
    for name in ("build_release_spine.py", "release_spine.py"):
        source = (SCRIPTS / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        direct_imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        from_imports = {
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imports = direct_imports | from_imports
        assert imports.isdisjoint(forbidden_imports)
        assert "unpack_archive" not in source
        assert "extractall" not in source


def test_privileged_verifier_has_an_explicit_module_call_surface() -> None:
    source = (SCRIPTS / "release_spine.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported_modules == {
        "argparse",
        "contextlib",
        "dataclasses",
        "hashlib",
        "json",
        "os",
        "re",
        "stat",
        "sys",
    }
    from_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert from_modules == {"__future__", "collections.abc", "pathlib", "typing"}
    allowed_calls = {
        "argparse": {"ArgumentParser"},
        "contextlib": set(),
        "dataclasses": {"dataclass"},
        "hashlib": {"sha256"},
        "json": {"dumps", "loads"},
        "os": {"close", "fstat", "open", "pread", "read", "stat"},
        "re": {"compile"},
        "stat": {"S_ISREG"},
        "sys": set(),
    }
    observed: dict[str, set[str]] = {module: set() for module in allowed_calls}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in observed
        ):
            observed[node.func.value.id].add(node.func.attr)
    assert observed == allowed_calls
    forbidden_builtins = {"__import__", "compile", "eval", "exec", "open"}
    assert not {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }.intersection(forbidden_builtins)
    forbidden_high_level_file_calls = {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
    }
    assert not {
        node.func.attr
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and not (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "open"
            )
        )
    }.intersection(forbidden_high_level_file_calls)


def workflow_run_script(source: str, step_name: str) -> str:
    step = f"      - name: {step_name}\n"
    _, separator, tail = source.partition(step)
    assert separator, f"missing {step_name!r} step"
    _, separator, tail = tail.partition("        run: |\n")
    assert separator, f"missing run script for {step_name!r}"
    lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    return "\n".join(lines)


def candidate_identity_environment(
    temporary: Path, output: Path, *, attempt: str
) -> dict[str, str]:
    return os.environ | {
        "CANDIDATE_REGISTRY": "ghcr.io",
        "CANDIDATE_REPOSITORY": "stampbot/extra-codeowners",
        "GITHUB_OUTPUT": str(output),
        "GITHUB_RUN_ATTEMPT": attempt,
        "GITHUB_RUN_ID": "777777",
        "GITHUB_SHA": REVISION,
        "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}",
        "PYTHON_ARTIFACT_DIGEST": PYTHON_ARTIFACT_SHA256,
        "PYTHON_ARTIFACT_ID": "789012",
        "RUNNER_TEMP": str(temporary),
        "SELECTION_RECORD_SHA256": SELECTION_SHA256,
        "WHEEL_SHA256": WHEEL_SHA256,
    }


@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_candidate_identity_script_makes_rerun_safe_outputs(tmp_path: Path) -> None:
    source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = workflow_run_script(source, "Prepare immutable candidate identity")
    outputs: list[dict[str, str]] = []

    assert BASH is not None
    for attempt in ("2", "3"):
        output = tmp_path / f"github-output-{attempt}"
        result = subprocess.run(  # noqa: S603 - executes the reviewed fixed workflow script
            [BASH, "-c", script],
            cwd=ROOT,
            env=candidate_identity_environment(tmp_path, output, attempt=attempt),
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        outputs.append(
            dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
        )

    assert outputs[0]["run-id"] == outputs[1]["run-id"] == "777777"
    assert outputs[0]["run-attempt"] == "2"
    assert outputs[1]["run-attempt"] == "3"
    assert outputs[0]["layout-path"] != outputs[1]["layout-path"]
    assert outputs[0]["record-path"] != outputs[1]["record-path"]
    assert outputs[0]["spine-path"] != outputs[1]["spine-path"]
    assert outputs[0]["oci-output"] == (
        f"type=oci,dest={outputs[0]['layout-path']},tar=false,name={outputs[0]['candidate-name']}"
    )
    assert outputs[0]["spine-path"].endswith("-python-artifact-789012-run-777777-attempt-2.bin")


@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_candidate_identity_script_refuses_an_existing_layout(tmp_path: Path) -> None:
    source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = workflow_run_script(source, "Prepare immutable candidate identity")
    output = tmp_path / "github-output"
    (tmp_path / "release-spine-layout-run-777777-attempt-2").mkdir()

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - executes the reviewed fixed workflow script
        [BASH, "-c", script],
        cwd=ROOT,
        env=candidate_identity_environment(tmp_path, output, attempt="2"),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Refusing to overwrite an existing OCI layout" in result.stderr
    assert not output.exists()


def test_ci_proves_two_separate_raw_artifact_transports() -> None:
    source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    producer = source.split("  release-spine-transport-producer:\n", 1)[1].split(
        "  release-spine-transport-consumer:\n", 1
    )[0]
    consumer = source.split("  release-spine-transport-consumer:\n", 1)[1].split(
        "  verified-container-sources:\n", 1
    )[0]

    assert "permissions:\n      contents: read" in producer
    assert "permissions:\n      contents: read" in consumer
    assert producer.count("actions/upload-artifact@043fb46d1a93c77") == 2
    assert producer.count("archive: false") == 2
    assert producer.count("retention-days: 1") == 2
    assert "name: artifact" not in producer
    assert "index-digest: ${{ steps.build-image.outputs.digest }}" in producer
    assert "version: ${{ steps.identity.outputs.version }}" in producer
    assert "run-id: ${{ steps.identity.outputs.run-id }}" in producer
    assert "run-attempt: ${{ steps.identity.outputs.run-attempt }}" in producer
    assert "record-artifact-id: ${{ steps.upload-record.outputs.artifact-id }}" in producer
    assert "spine-artifact-id: ${{ steps.upload-spine.outputs.artifact-id }}" in producer

    assert producer.count("actions/download-artifact@3e5f45b2cfb91720") == 1
    selected_download = producer.split(
        "      - name: Download the selected Python distribution by immutable ID\n", 1
    )[1].split("      - name: Verify the selected Python distribution\n", 1)[0]
    assert "artifact-ids: ${{ needs.python-distribution.outputs.artifact-id }}" in (
        selected_download
    )
    assert "digest-mismatch: error" in selected_download
    assert "name:" not in selected_download
    assert "pattern:" not in selected_download
    assert producer.index("verify-selection") < producer.index("docker/build-push-action@")
    assert "verified-python=${{ steps.selected-python.outputs.download-path }}" in producer
    assert "APPLICATION_SOURCE_REVISION=${{ github.sha }}" in producer
    assert (
        "APPLICATION_WHEEL_SHA256=${{ needs.python-distribution.outputs.wheel-sha256 }}" in producer
    )
    assert (
        "APPLICATION_SELECTION_RECORD_SHA256=${{ "
        "needs.python-distribution.outputs.selection-record-sha256 }}" in producer
    )

    assert producer.count("docker/setup-qemu-action@96fe6ef7f33517b6") == 1
    assert producer.count("docker/setup-buildx-action@bb05f3f5519dd87d") == 1
    assert producer.count("docker/build-push-action@53b7df96c91f9c12") == 1
    assert producer.count("cache-image: false") == 1
    assert "moby/buildkit:v0.30.0@sha256:0168606be2315b7c" in producer
    assert "oci-output=type=oci,dest=%s,tar=false,name=%s" in producer
    assert "outputs: ${{ steps.identity.outputs.oci-output }}" in producer
    assert "platforms: linux/amd64,linux/arm64" in producer
    assert "provenance: false" in producer
    assert "push: false" in producer
    assert "sbom: false" in producer
    assert "target: runtime" in producer
    assert 'DOCKER_BUILD_RECORD_UPLOAD: "false"' in producer
    assert "tests/release_spine_fixtures.py" not in producer
    assert "index.json" not in producer
    assert "INDEX_DIGEST: ${{ steps.build-image.outputs.digest }}" in producer
    assert '--index-digest "$INDEX_DIGEST"' in producer
    assert "${basename}-python-artifact-${PYTHON_ARTIFACT_ID}" in producer
    assert "${basename}-run-${GITHUB_RUN_ID}-attempt-${GITHUB_RUN_ATTEMPT}" in producer
    assert '--run-id "$GITHUB_RUN_ID"' in producer
    assert '--run-attempt "$GITHUB_RUN_ATTEMPT"' in producer

    assert consumer.count("actions/download-artifact@3e5f45b2cfb91720") == 2
    assert consumer.count("skip-decompress: true") == 2
    assert consumer.count("digest-mismatch: error") == 2
    assert "downloaded-record" in consumer
    assert "downloaded-spine" in consumer
    assert (
        "INDEX_DIGEST: ${{ needs.release-spine-transport-producer.outputs.index-digest }}"
        in consumer
    )
    assert '--index-digest "$INDEX_DIGEST"' in consumer
    assert "VERSION: ${{ needs.release-spine-transport-producer.outputs.version }}" in consumer
    assert '--version "$VERSION"' in consumer
    assert (
        "PRODUCER_RUN_ATTEMPT: >-\n"
        "            ${{ needs.release-spine-transport-producer.outputs.run-attempt }}" in consumer
    )
    assert (
        "PRODUCER_RUN_ID: ${{ needs.release-spine-transport-producer.outputs.run-id }}" in consumer
    )
    assert "${basename}-run-${PRODUCER_RUN_ID}-attempt-${PRODUCER_RUN_ATTEMPT}" in consumer
    assert '--run-id "$PRODUCER_RUN_ID"' in consumer
    assert '--run-attempt "$PRODUCER_RUN_ATTEMPT"' in consumer
    assert 'record["index"]' not in consumer
    for forbidden in (
        "build_release_spine.py",
        "docker/",
        "docker ",
        "gzip",
        "index.json",
        "tar ",
        "tarfile",
    ):
        assert forbidden not in consumer

    for job in (producer, consumer):
        assert re.search(r"(?m)^\s+[A-Za-z-]+:\s+write\s*$", job) is None
        assert "write-all" not in job
        assert "environment:" not in job
        assert "secrets:" not in job
        assert "GITHUB_TOKEN" not in job
        assert "GH_TOKEN" not in job
        assert "ACTIONS_ID_TOKEN_REQUEST_" not in job
        assert "/var/run/docker.sock" not in job


def test_container_test_stage_carries_spine_scripts() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    test_stage = dockerfile.split("FROM builder AS test\n", 1)[1].split("\nFROM ", 1)[0]

    for script in (
        "build_python_distribution_spine.py",
        "build_release_spine.py",
        "python_distribution_spine.py",
        "release_spine.py",
    ):
        assert f"!.github/scripts/{script}" in dockerignore
        assert f".github/scripts/{script}" in test_stage


def test_release_workflow_cannot_publish_the_oci_transport_spine() -> None:
    source = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "python .github/scripts/build_release_spine.py" not in source
    assert "python .github/scripts/release_spine.py verify" not in source
    assert "archive: false" not in source
    assert "extra-codeowners-image-" not in source
    assert "needs.release-spine-transport" not in source

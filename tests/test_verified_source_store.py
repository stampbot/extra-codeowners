"""Tests for the strict, read-only verified-source store boundary."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "verified_source_store.py"
PLAN_SCRIPT = ROOT / ".github" / "scripts" / "container_source_plan.py"
SOURCE_REVISION = "1" * 40
POLICY_SHA256 = "2" * 64
UV_LOCK_SHA256 = "3" * 64


def load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


source_store: Any = load_script(SCRIPT, "verified_source_store")


def audit_origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    assert parsed.hostname is not None
    return f"https://{parsed.hostname}/"


@dataclass(frozen=True)
class RequestSpec:
    """Input bytes and their trusted request identity."""

    identifier: str
    content: bytes
    url: str = "https://downloads.example.test/source.bin"
    algorithm: str = "sha256"
    known_size: bool = True
    consumers: tuple[str, ...] = ("platform:linux/amd64:test",)
    allowed_hosts: tuple[str, ...] = ("downloads.example.test",)


class StoreFixture(NamedTuple):
    root: Path
    plan: dict[str, Any]
    manifest: dict[str, Any]
    specs: tuple[RequestSpec, ...]

    @property
    def plan_path(self) -> Path:
        return self.root / cast(str, source_store.PLAN_FILENAME)

    @property
    def manifest_path(self) -> Path:
        return self.root / cast(str, source_store.STORE_FILENAME)

    @property
    def object_directory(self) -> Path:
        return self.root / "objects" / "sha256"

    def object_path(self, content: bytes) -> Path:
        return self.object_directory / hashlib.sha256(content).hexdigest()


@dataclass(frozen=True)
class FakeDirectoryEntry:
    """One descriptor-relative inventory entry used by a bounded-scan test."""

    name: str


class BoundedScandir:
    """Fail the test if the verifier consumes more entries than its bound."""

    def __init__(self, names: tuple[str, ...], maximum_reads: int) -> None:
        self._names = names
        self._maximum_reads = maximum_reads
        self.reads = 0

    def __enter__(self) -> BoundedScandir:
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        return None

    def __iter__(self) -> BoundedScandir:
        return self

    def __next__(self) -> FakeDirectoryEntry:
        if self.reads >= self._maximum_reads:
            raise AssertionError("inventory scan exceeded its declared read bound")
        if self.reads >= len(self._names):
            raise StopIteration
        entry = FakeDirectoryEntry(self._names[self.reads])
        self.reads += 1
        return entry


def request_record(spec: RequestSpec) -> dict[str, Any]:
    return {
        "id": spec.identifier,
        "url": spec.url,
        "allowed_hosts": list(spec.allowed_hosts),
        "algorithm": spec.algorithm,
        "digest": hashlib.new(spec.algorithm, spec.content).hexdigest(),
        "expected_size": len(spec.content) if spec.known_size else None,
        "max_bytes": max(1, len(spec.content) + 64),
        "consumers": list(spec.consumers),
    }


def plan_record(specs: tuple[RequestSpec, ...]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "media_type": "application/vnd.stampbot.container-source-plan.v1+json",
        "kind": "direct",
        "evidence_schema_version": 7,
        "source_revision": SOURCE_REVISION,
        "policy_sha256": POLICY_SHA256,
        "uv_lock_sha256": UV_LOCK_SHA256,
        "requests": [
            request_record(spec) for spec in sorted(specs, key=lambda item: item.identifier)
        ],
    }


def alpine_distfile_plan_record(specs: tuple[RequestSpec, ...]) -> dict[str, Any]:
    record = plan_record(specs)
    record.update(
        {
            "kind": "alpine-distfiles",
            "parent_plan": {
                "algorithm": "sha256",
                "digest": "4" * 64,
                "size": 1_024,
            },
            "parent_manifest": {
                "algorithm": "sha256",
                "digest": "5" * 64,
                "size": 2_048,
            },
            "recipes": [
                {
                    "request_id": "alpine-recipe:busybox@" + "6" * 40,
                    "object_sha256": "7" * 64,
                    "size": 4_096,
                }
            ],
        }
    )
    return record


def success_attempt(spec: RequestSpec, object_sha256: str, number: int = 1) -> dict[str, Any]:
    return {
        "number": number,
        "outcome": "success",
        "http_status": 200,
        "redirect_origins": [audit_origin(spec.url)],
        "received_size": len(spec.content),
        "sha256": object_sha256,
        "retry_delay_seconds": None,
    }


def result_record(spec: RequestSpec) -> dict[str, Any]:
    request = request_record(spec)
    object_sha256 = hashlib.sha256(spec.content).hexdigest()
    return {
        "id": request["id"],
        "request_origin": audit_origin(request["url"]),
        "algorithm": request["algorithm"],
        "digest": request["digest"],
        "expected_size": request["expected_size"],
        "max_bytes": request["max_bytes"],
        "object_sha256": object_sha256,
        "size": len(spec.content),
        "path": f"objects/sha256/{object_sha256}",
        "redirect_origins": [audit_origin(spec.url)],
        "attempts": [success_attempt(spec, object_sha256)],
    }


def manifest_record(
    plan_bytes: bytes,
    specs: tuple[RequestSpec, ...],
) -> dict[str, Any]:
    by_digest: dict[str, bytes] = {}
    for spec in specs:
        by_digest.setdefault(hashlib.sha256(spec.content).hexdigest(), spec.content)
    return {
        "schema_version": 1,
        "media_type": "application/vnd.stampbot.verified-source-store.v1+json",
        "kind": "direct",
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "plan_size": len(plan_bytes),
        "objects": [
            {
                "algorithm": "sha256",
                "digest": digest,
                "size": len(content),
                "path": f"objects/sha256/{digest}",
            }
            for digest, content in sorted(by_digest.items())
        ],
        "results": [
            result_record(spec) for spec in sorted(specs, key=lambda item: item.identifier)
        ],
    }


def write_fixture(
    tmp_path: Path,
    specs: tuple[RequestSpec, ...] | None = None,
) -> StoreFixture:
    selected = specs or (RequestSpec("source:demo", b"verified source bytes"),)
    root = tmp_path / "store"
    object_directory = root / "objects" / "sha256"
    object_directory.mkdir(parents=True)
    plan = plan_record(selected)
    plan_bytes = source_store.canonical_json(plan)
    manifest = manifest_record(plan_bytes, selected)
    (root / source_store.PLAN_FILENAME).write_bytes(plan_bytes)
    (root / source_store.STORE_FILENAME).write_bytes(source_store.canonical_json(manifest))
    for spec in selected:
        path = object_directory / hashlib.sha256(spec.content).hexdigest()
        if not path.exists():
            path.write_bytes(spec.content)
    return StoreFixture(root, plan, manifest, selected)


def trusted_plan_binding(fixture: StoreFixture) -> dict[str, Any]:
    content = source_store.canonical_json(fixture.plan)
    return {
        "expected_plan_sha256": hashlib.sha256(content).hexdigest(),
        "expected_plan_size": len(content),
    }


def verify_fixture(fixture: StoreFixture) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        source_store.verify_source_store(
            fixture.root,
            **trusted_plan_binding(fixture),
        ),
    )


def rewrite_manifest(fixture: StoreFixture) -> None:
    fixture.manifest_path.write_bytes(source_store.canonical_json(fixture.manifest))


def rewrite_plan(fixture: StoreFixture, *, rebind: bool) -> None:
    content = source_store.canonical_json(fixture.plan)
    fixture.plan_path.write_bytes(content)
    if rebind:
        fixture.manifest["plan_sha256"] = hashlib.sha256(content).hexdigest()
        fixture.manifest["plan_size"] = len(content)
        rewrite_manifest(fixture)


def test_verifies_sha256_and_sha512_requests_with_one_deduplicated_object(
    tmp_path: Path,
) -> None:
    content = b"one object, two logical requests"
    fixture = write_fixture(
        tmp_path,
        (
            RequestSpec("source:sha256", content),
            RequestSpec(
                "source:sha512",
                content,
                url="https://mirror.example.test/source.bin",
                algorithm="sha512",
                known_size=False,
                consumers=("platform:linux/arm64:test",),
                allowed_hosts=("mirror.example.test",),
            ),
        ),
    )
    before = {
        path.relative_to(fixture.root): (
            path.stat(follow_symlinks=False).st_size,
            path.stat(follow_symlinks=False).st_mtime_ns,
            path.stat(follow_symlinks=False).st_ctime_ns,
        )
        for path in fixture.root.rglob("*")
    }

    result = verify_fixture(fixture)

    assert result["request_count"] == 2
    assert result["object_count"] == 1
    assert result["total_object_bytes"] == len(content)
    assert result == source_store.validate_verification_result(result)
    assert source_store.canonical_json(result).endswith(b"\n")
    assert list(fixture.object_directory.iterdir()) == [fixture.object_path(content)]
    after = {
        path.relative_to(fixture.root): (
            path.stat(follow_symlinks=False).st_size,
            path.stat(follow_symlinks=False).st_mtime_ns,
            path.stat(follow_symlinks=False).st_ctime_ns,
        )
        for path in fixture.root.rglob("*")
    }
    assert after == before


def test_unknown_size_empty_object_is_verified(tmp_path: Path) -> None:
    fixture = write_fixture(
        tmp_path,
        (RequestSpec("source:empty", b"", known_size=False),),
    )

    result = verify_fixture(fixture)

    assert result["object_count"] == 1
    assert result["total_object_bytes"] == 0


def test_known_size_zero_is_not_a_valid_plan_size(tmp_path: Path) -> None:
    fixture = write_fixture(
        tmp_path,
        (RequestSpec("source:empty", b"", known_size=True),),
    )

    with pytest.raises(source_store.SourceStoreError, match="integer bound"):
        verify_fixture(fixture)


def test_accepts_the_real_direct_planner_contract() -> None:
    planner: Any = load_script(PLAN_SCRIPT, "container_source_plan_for_store_test")
    plan = planner.build_direct_plan(
        ROOT / ".compliance" / "container-policy.json",
        ROOT / "uv.lock",
        source_revision=SOURCE_REVISION,
    )
    raw = planner.canonical_json(plan)

    validated = source_store.validate_source_plan(
        source_store.strict_json_bytes(raw, "real source plan", maximum=4 * 1024 * 1024)
    )

    assert len(validated["requests"]) == 132
    assert (
        validated["policy_sha256"]
        == hashlib.sha256((ROOT / ".compliance" / "container-policy.json").read_bytes()).hexdigest()
    )


def test_accepts_the_bound_alpine_distfile_plan_contract() -> None:
    record = alpine_distfile_plan_record(
        (RequestSpec("alpine-distfile:busybox.tar.bz2", b"distfile"),)
    )

    validated = source_store.validate_source_plan(record)

    assert validated["kind"] == "alpine-distfiles"
    assert validated["parent_plan"]["digest"] == "4" * 64
    assert validated["parent_manifest"]["digest"] == "5" * 64
    assert validated["recipes"] == record["recipes"]


@pytest.mark.parametrize("value", ([], {"kind": 7}, {"kind": "unsupported"}))
def test_source_plan_rejects_non_objects_and_unsupported_kinds(value: object) -> None:
    with pytest.raises(source_store.SourceStoreError, match=r"object|wrong kind"):
        source_store.validate_source_plan(value)


@pytest.mark.parametrize("recipes", ({}, []))
def test_alpine_distfile_plan_requires_a_bounded_recipe_list(recipes: object) -> None:
    record = alpine_distfile_plan_record(
        (RequestSpec("alpine-distfile:busybox.tar.bz2", b"distfile"),)
    )
    record["recipes"] = recipes

    with pytest.raises(source_store.SourceStoreError, match="recipe-count"):
        source_store.validate_source_plan(record)


@pytest.mark.parametrize(
    "recipes",
    (
        [
            {"request_id": "recipe:b", "object_sha256": "8" * 64, "size": 1},
            {"request_id": "recipe:a", "object_sha256": "9" * 64, "size": 1},
        ],
        [
            {"request_id": "recipe:a", "object_sha256": "8" * 64, "size": 1},
            {"request_id": "recipe:a", "object_sha256": "9" * 64, "size": 1},
        ],
    ),
)
def test_alpine_distfile_recipe_bindings_are_sorted_and_unique(
    recipes: list[dict[str, Any]],
) -> None:
    record = alpine_distfile_plan_record(
        (RequestSpec("alpine-distfile:busybox.tar.bz2", b"distfile"),)
    )
    record["recipes"] = recipes

    with pytest.raises(source_store.SourceStoreError, match="sorted and unique"):
        source_store.validate_source_plan(record)


def test_direct_plan_rejects_alpine_binding_fields() -> None:
    record = alpine_distfile_plan_record(
        (RequestSpec("alpine-distfile:busybox.tar.bz2", b"distfile"),)
    )
    record["kind"] = "direct"

    with pytest.raises(source_store.SourceStoreError, match="exactly"):
        source_store.validate_source_plan(record)


@pytest.mark.parametrize(
    "raw",
    (
        b"{",
        b'{"value":1,"value":1}\n',
        b'{ "value": 1 }\n',
        b'{"value":1}',
        b'{"value":1.0}\n',
        b'{"value":999999999999999999999}\n',
        b"\xff\n",
    ),
)
def test_strict_json_rejects_malformed_ambiguous_or_noncanonical_bytes(raw: bytes) -> None:
    with pytest.raises(source_store.SourceStoreError):
        source_store.strict_json_bytes(raw, "hostile record", maximum=1024)


@pytest.mark.parametrize(
    "raw",
    (
        b'{"attacker-controlled-secret":"first","attacker-controlled-secret":"second"}\n',
        b'{"value":1.' + (b"7" * 900) + b"}\n",
    ),
)
def test_strict_json_errors_do_not_echo_attacker_controlled_tokens(raw: bytes) -> None:
    with pytest.raises(source_store.SourceStoreError) as raised:
        source_store.strict_json_bytes(raw, "hostile record", maximum=2048)

    message = str(raised.value)
    assert "attacker-controlled-secret" not in message
    assert "7" * 32 not in message
    assert len(message) < 128


@pytest.mark.parametrize(
    "location",
    (
        "plan",
        "plan_request",
        "manifest",
        "manifest_result",
        "manifest_attempt",
        "manifest_object",
    ),
)
def test_exact_schemas_reject_unknown_fields(tmp_path: Path, location: str) -> None:
    fixture = write_fixture(tmp_path)
    if location == "plan":
        fixture.plan["unknown"] = True
        rewrite_plan(fixture, rebind=True)
    elif location == "plan_request":
        fixture.plan["requests"][0]["unknown"] = True
        rewrite_plan(fixture, rebind=True)
    else:
        target = {
            "manifest": fixture.manifest,
            "manifest_result": fixture.manifest["results"][0],
            "manifest_attempt": fixture.manifest["results"][0]["attempts"][0],
            "manifest_object": fixture.manifest["objects"][0],
        }[location]
        target["unknown"] = True
        rewrite_manifest(fixture)

    with pytest.raises(source_store.SourceStoreError, match="exactly"):
        verify_fixture(fixture)


@pytest.mark.parametrize(
    ("location", "field"),
    (
        ("plan", "schema_version"),
        ("plan", "evidence_schema_version"),
        ("plan_request", "expected_size"),
        ("plan_request", "max_bytes"),
        ("manifest", "plan_size"),
        ("manifest_result", "size"),
        ("manifest_attempt", "number"),
        ("manifest_attempt", "received_size"),
        ("manifest_object", "size"),
    ),
)
def test_integer_fields_reject_booleans(tmp_path: Path, location: str, field: str) -> None:
    fixture = write_fixture(tmp_path)
    if location == "plan":
        fixture.plan[field] = True
        rewrite_plan(fixture, rebind=True)
    elif location == "plan_request":
        fixture.plan["requests"][0][field] = True
        rewrite_plan(fixture, rebind=True)
    else:
        target = {
            "manifest": fixture.manifest,
            "manifest_result": fixture.manifest["results"][0],
            "manifest_attempt": fixture.manifest["results"][0]["attempts"][0],
            "manifest_object": fixture.manifest["objects"][0],
        }[location]
        target[field] = True
        rewrite_manifest(fixture)

    with pytest.raises(source_store.SourceStoreError, match="integer bound"):
        verify_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "extra",
        "renamed-case",
        "case-collision",
        "symlink",
        "hardlink",
        "fifo",
        "directory",
    ),
)
def test_exact_object_inventory_rejects_hostile_filesystem_entries(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    spec = fixture.specs[0]
    object_path = fixture.object_path(spec.content)
    outside = tmp_path / "outside"
    if mutation == "missing":
        object_path.unlink()
    elif mutation == "extra":
        (fixture.object_directory / ("f" * 64)).write_bytes(b"extra")
    elif mutation == "renamed-case":
        object_path.rename(object_path.with_name(object_path.name.upper()))
    elif mutation == "case-collision":
        shutil.copyfile(object_path, object_path.with_name(object_path.name.upper()))
    elif mutation == "symlink":
        outside.write_bytes(spec.content)
        object_path.unlink()
        object_path.symlink_to(outside)
    elif mutation == "hardlink":
        os.link(object_path, outside)
    elif mutation == "fifo":
        object_path.unlink()
        os.mkfifo(object_path)
    else:
        object_path.unlink()
        object_path.mkdir()

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


def test_exact_inventory_stops_after_one_entry_beyond_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"expected-a", "expected-b"}
    entries = BoundedScandir(
        tuple(f"unexpected-{index}" for index in range(100)),
        maximum_reads=len(expected) + 1,
    )

    def fake_scandir(_directory: int) -> BoundedScandir:
        return entries

    monkeypatch.setattr(source_store.os, "scandir", fake_scandir)

    with pytest.raises(
        source_store.SourceStoreError,
        match=r"entry_count_exceeds_bound=True",
    ):
        source_store._list_exact(123, expected, "bounded test inventory")

    assert entries.reads == len(expected) + 1


@pytest.mark.parametrize(
    "mutation",
    (
        "extra-root-file",
        "extra-object-algorithm",
        "renamed-plan",
        "renamed-manifest",
        "case-colliding-plan",
        "linked-objects-directory",
        "linked-sha256-directory",
    ),
)
def test_exact_store_hierarchy_rejects_extra_renamed_and_linked_entries(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    if mutation == "extra-root-file":
        (fixture.root / "README").write_text("unexpected", encoding="ascii")
    elif mutation == "extra-object-algorithm":
        (fixture.root / "objects" / "sha512").mkdir()
    elif mutation == "renamed-plan":
        fixture.plan_path.rename(fixture.root / "SOURCE-plan.json")
    elif mutation == "renamed-manifest":
        fixture.manifest_path.rename(fixture.root / "source-store.json")
    elif mutation == "case-colliding-plan":
        shutil.copyfile(fixture.plan_path, fixture.root / "source-plan.JSON")
    elif mutation == "linked-objects-directory":
        outside = tmp_path / "outside-objects"
        (fixture.root / "objects").rename(outside)
        (fixture.root / "objects").symlink_to(outside, target_is_directory=True)
    else:
        outside = tmp_path / "outside-sha256"
        fixture.object_directory.rename(outside)
        fixture.object_directory.symlink_to(outside, target_is_directory=True)

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


@pytest.mark.parametrize("mutation", ("tamper", "truncate", "append"))
def test_object_content_changes_fail_digest_or_size_binding(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    spec = fixture.specs[0]
    path = fixture.object_path(spec.content)
    if mutation == "tamper":
        path.write_bytes(b"X" + spec.content[1:])
    elif mutation == "truncate":
        path.write_bytes(spec.content[:-1])
    else:
        path.write_bytes(spec.content + b"X")

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    (
        "unsorted-hosts",
        "missing-request-host",
        "unsorted-consumers",
        "duplicate-consumers",
        "case-colliding-consumers",
        "unsafe-token",
        "uppercase-host",
        "query-without-path",
    ),
)
def test_plan_request_lists_tokens_and_urls_are_canonical(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    request = fixture.plan["requests"][0]
    if mutation == "unsorted-hosts":
        request["allowed_hosts"] = ["mirror.example.test", "downloads.example.test"]
    elif mutation == "missing-request-host":
        request["allowed_hosts"] = ["mirror.example.test"]
    elif mutation == "unsorted-consumers":
        request["consumers"] = ["platform:z", "platform:a"]
    elif mutation == "duplicate-consumers":
        request["consumers"] = ["platform:a", "platform:a"]
    elif mutation == "case-colliding-consumers":
        request["consumers"] = ["platform:A", "platform:a"]
    elif mutation == "unsafe-token":
        request["consumers"] = ["../../escape"]
    elif mutation == "uppercase-host":
        request["url"] = "https://Downloads.example.test/source.bin"
    else:
        request["url"] = "https://downloads.example.test?source=bin"
    rewrite_plan(fixture, rebind=True)

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    (
        "plan-kind",
        "plan-media",
        "store-kind",
        "store-media",
        "plan-sha",
        "plan-size",
        "result-url",
        "result-digest",
        "result-size",
        "result-path",
        "final-chain",
        "final-sha",
    ),
)
def test_wrong_plan_kind_and_cross_record_bindings_fail(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    result = fixture.manifest["results"][0]
    if mutation == "plan-kind":
        fixture.plan["kind"] = "alpine-distfiles"
        rewrite_plan(fixture, rebind=True)
    elif mutation == "plan-media":
        fixture.plan["media_type"] = "application/json"
        rewrite_plan(fixture, rebind=True)
    elif mutation == "store-kind":
        fixture.manifest["kind"] = "alpine-distfiles"
        rewrite_manifest(fixture)
    elif mutation == "store-media":
        fixture.manifest["media_type"] = "application/json"
        rewrite_manifest(fixture)
    elif mutation == "plan-sha":
        fixture.manifest["plan_sha256"] = "0" * 64
        rewrite_manifest(fixture)
    elif mutation == "plan-size":
        fixture.manifest["plan_size"] += 1
        rewrite_manifest(fixture)
    elif mutation == "result-url":
        result["request_origin"] = "https://downloads.example.test/other.bin"
        rewrite_manifest(fixture)
    elif mutation == "result-digest":
        result["digest"] = "0" * 64
        rewrite_manifest(fixture)
    elif mutation == "result-size":
        result["size"] += 1
        rewrite_manifest(fixture)
    elif mutation == "result-path":
        result["path"] = f"objects/sha256/{'0' * 64}"
        rewrite_manifest(fixture)
    elif mutation == "final-chain":
        result["attempts"][-1]["redirect_origins"] = ["https://downloads.example.test/other.bin"]
        rewrite_manifest(fixture)
    else:
        result["attempts"][-1]["sha256"] = "0" * 64
        rewrite_manifest(fixture)

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


def test_duplicate_plan_ids_and_case_colliding_ids_fail(tmp_path: Path) -> None:
    content = b"same"
    fixture = write_fixture(
        tmp_path,
        (
            RequestSpec("source:Demo", content),
            RequestSpec(
                "source:demo",
                content,
                url="https://mirror.example.test/same",
                allowed_hosts=("mirror.example.test",),
            ),
        ),
    )

    with pytest.raises(source_store.SourceStoreError, match="case-colliding"):
        verify_fixture(fixture)

    fixture.plan["requests"][1]["id"] = fixture.plan["requests"][0]["id"]
    rewrite_plan(fixture, rebind=True)
    with pytest.raises(source_store.SourceStoreError, match="sorted and unique"):
        verify_fixture(fixture)


def test_duplicate_store_objects_and_results_fail(tmp_path: Path) -> None:
    fixture = write_fixture(tmp_path)
    fixture.manifest["objects"].append(copy.deepcopy(fixture.manifest["objects"][0]))
    rewrite_manifest(fixture)
    with pytest.raises(source_store.SourceStoreError, match="sorted and unique"):
        verify_fixture(fixture)

    fixture = write_fixture(tmp_path / "second")
    fixture.manifest["results"].append(copy.deepcopy(fixture.manifest["results"][0]))
    rewrite_manifest(fixture)
    with pytest.raises(source_store.SourceStoreError, match="wrong result count"):
        verify_fixture(fixture)


@pytest.mark.parametrize(
    "mutation",
    (
        "number-gap",
        "early-success",
        "final-retry",
        "http-status",
        "transport-delay",
        "success-delay",
        "disallowed-host",
        "non-443",
        "too-many-attempts",
    ),
)
def test_attempt_history_is_bounded_contiguous_and_ends_in_exact_success(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    spec = fixture.specs[0]
    result = fixture.manifest["results"][0]
    object_sha256 = result["object_sha256"]
    retry = {
        "number": 1,
        "outcome": "retryable_transport",
        "http_status": None,
        "redirect_origins": [audit_origin(spec.url)],
        "received_size": None,
        "sha256": None,
        "retry_delay_seconds": 1,
    }
    success = success_attempt(spec, object_sha256, number=2)
    result["attempts"] = [retry, success]
    if mutation == "number-gap":
        success["number"] = 3
    elif mutation == "early-success":
        retry.update(success_attempt(spec, object_sha256, number=1))
    elif mutation == "final-retry":
        result["attempts"] = [retry]
    elif mutation == "http-status":
        retry["outcome"] = "retryable_http"
        retry["http_status"] = 404
        retry["retry_delay_seconds"] = 1
    elif mutation == "transport-delay":
        retry["retry_delay_seconds"] = 2
    elif mutation == "success-delay":
        success["retry_delay_seconds"] = 0
    elif mutation == "disallowed-host":
        success["redirect_origins"] = ["https://evil.example.test/"]
    elif mutation == "non-443":
        success["redirect_origins"] = ["https://downloads.example.test:444/"]
    else:
        result["attempts"] = [
            retry,
            {
                **retry,
                "number": 2,
                "retry_delay_seconds": 2,
            },
            {
                **retry,
                "number": 3,
                "retry_delay_seconds": 4,
            },
            {
                **retry,
                "number": 4,
                "retry_delay_seconds": 8,
            },
            success_attempt(spec, object_sha256, number=5),
        ]
    rewrite_manifest(fixture)

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


def test_redirect_audit_preserves_repeated_origins_without_paths(tmp_path: Path) -> None:
    fixture = write_fixture(tmp_path)
    result = fixture.manifest["results"][0]
    origin = audit_origin(fixture.specs[0].url)
    result["redirect_origins"] = [origin, origin]
    result["attempts"][-1]["redirect_origins"] = [origin, origin]
    rewrite_manifest(fixture)

    assert verify_fixture(fixture)["request_count"] == 1


@pytest.mark.parametrize(
    "unsafe_origin",
    (
        "https://downloads.example.test/path",
        "https://downloads.example.test/?token=secret",
        "https://downloads.example.test/#fragment",
        "https://downloads.example.test:443/",
        "https://user@downloads.example.test/",
    ),
)
def test_redirect_audit_rejects_noncanonical_or_credentialed_origins(
    tmp_path: Path,
    unsafe_origin: str,
) -> None:
    fixture = write_fixture(tmp_path)
    result = fixture.manifest["results"][0]
    result["redirect_origins"] = [unsafe_origin]
    result["attempts"][-1]["redirect_origins"] = [unsafe_origin]
    rewrite_manifest(fixture)

    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


def test_retryable_http_attempt_accepts_bounded_retry_after(tmp_path: Path) -> None:
    fixture = write_fixture(tmp_path)
    spec = fixture.specs[0]
    result = fixture.manifest["results"][0]
    result["attempts"] = [
        {
            "number": 1,
            "outcome": "retryable_http",
            "http_status": 503,
            "redirect_origins": [audit_origin(spec.url)],
            "received_size": None,
            "sha256": None,
            "retry_delay_seconds": 60,
        },
        success_attempt(spec, result["object_sha256"], number=2),
    ]
    rewrite_manifest(fixture)

    assert verify_fixture(fixture)["object_count"] == 1


def test_bounds_cover_requests_consumers_objects_records_and_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = (
        RequestSpec("source:a", b"a"),
        RequestSpec(
            "source:b",
            b"b",
            url="https://mirror.example.test/b",
            allowed_hosts=("mirror.example.test",),
        ),
    )
    fixture = write_fixture(tmp_path, specs)
    monkeypatch.setattr(source_store, "MAX_REQUESTS", 1)
    with pytest.raises(source_store.SourceStoreError, match="request-count"):
        verify_fixture(fixture)

    monkeypatch.setattr(source_store, "MAX_REQUESTS", 512)
    monkeypatch.setattr(source_store, "MAX_TOTAL_CONSUMER_REFERENCES", 1)
    with pytest.raises(source_store.SourceStoreError, match="consumer references"):
        verify_fixture(fixture)

    monkeypatch.setattr(source_store, "MAX_TOTAL_CONSUMER_REFERENCES", 2_048)
    monkeypatch.setattr(source_store, "MAX_OBJECTS", 1)
    with pytest.raises(source_store.SourceStoreError, match="object-count"):
        verify_fixture(fixture)

    monkeypatch.setattr(source_store, "MAX_OBJECTS", 512)
    monkeypatch.setattr(source_store, "MAX_RESULT_BYTES", 1)
    with pytest.raises(source_store.SourceStoreError, match="result exceeds"):
        verify_fixture(fixture)


def test_aggregate_object_byte_bound_is_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(
        tmp_path,
        (
            RequestSpec("source:a", b"a"),
            RequestSpec(
                "source:b",
                b"b",
                url="https://mirror.example.test/b",
                allowed_hosts=("mirror.example.test",),
            ),
        ),
    )
    monkeypatch.setattr(source_store, "MAX_TOTAL_OBJECT_BYTES", 1)

    with pytest.raises(source_store.SourceStoreError, match="aggregate byte bound"):
        verify_fixture(fixture)


def test_plan_manifest_and_object_file_bounds_are_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(tmp_path)
    monkeypatch.setattr(source_store, "MAX_PLAN_BYTES", fixture.plan_path.stat().st_size - 1)
    with pytest.raises(source_store.SourceStoreError, match="integer bound"):
        verify_fixture(fixture)

    monkeypatch.setattr(source_store, "MAX_PLAN_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(
        source_store,
        "MAX_STORE_BYTES",
        fixture.manifest_path.stat().st_size - 1,
    )
    with pytest.raises(source_store.SourceStoreError, match="file-size bound"):
        verify_fixture(fixture)

    monkeypatch.setattr(source_store, "MAX_STORE_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(source_store, "MAX_OBJECT_BYTES", len(fixture.specs[0].content) - 1)
    with pytest.raises(source_store.SourceStoreError):
        verify_fixture(fixture)


@pytest.mark.parametrize("metadata_name", ("SOURCE-PLAN.json", "SOURCE-STORE.json"))
@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_metadata_records_must_be_no_follow_single_link_files(
    tmp_path: Path,
    metadata_name: str,
    link_kind: str,
) -> None:
    fixture = write_fixture(tmp_path)
    path = fixture.root / metadata_name
    outside = tmp_path / f"outside-{metadata_name}"
    outside.write_bytes(path.read_bytes())
    if link_kind == "symlink":
        path.unlink()
        path.symlink_to(outside)
    else:
        os.link(path, tmp_path / f"second-{metadata_name}")

    with pytest.raises(source_store.SourceStoreError, match=r"single-link|open"):
        verify_fixture(fixture)


def test_inode_replacement_during_hashing_fails_stability_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(tmp_path)
    object_path = fixture.object_path(fixture.specs[0].content)
    original_hash = source_store._hash_retained
    changed = False

    def replace_after_hash(retained: Any, algorithms: set[str]) -> dict[str, str]:
        nonlocal changed
        result = cast(dict[str, str], original_hash(retained, algorithms))
        if not changed:
            object_path.unlink()
            object_path.write_bytes(fixture.specs[0].content)
            changed = True
        return result

    monkeypatch.setattr(source_store, "_hash_retained", replace_after_hash)

    with pytest.raises(source_store.SourceStoreError, match="changed"):
        verify_fixture(fixture)


def test_directory_change_during_hashing_fails_exact_final_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(tmp_path)
    original_hash = source_store._hash_retained
    changed = False

    def add_after_hash(retained: Any, algorithms: set[str]) -> dict[str, str]:
        nonlocal changed
        result = cast(dict[str, str], original_hash(retained, algorithms))
        if not changed:
            (fixture.object_directory / ("f" * 64)).write_bytes(b"late")
            changed = True
        return result

    monkeypatch.setattr(source_store, "_hash_retained", add_after_hash)

    with pytest.raises(source_store.SourceStoreError, match=r"inventory|changed"):
        verify_fixture(fixture)


def test_disappearing_object_during_final_identity_pass_is_a_controlled_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(tmp_path)
    object_path = fixture.object_path(fixture.specs[0].content)
    original_check = source_store._require_files_unchanged
    removed = False

    def remove_before_final_check(retained_files: Sequence[Any]) -> None:
        nonlocal removed
        if not removed:
            object_path.unlink()
            removed = True
        original_check(retained_files)

    monkeypatch.setattr(
        source_store,
        "_require_files_unchanged",
        remove_before_final_check,
    )

    with pytest.raises(
        source_store.SourceStoreError, match=r"single-link|changed while it was retained"
    ):
        verify_fixture(fixture)

    assert removed


def test_verifier_documents_its_point_in_time_contract() -> None:
    documentation = source_store.verify_source_store.__doc__

    assert documentation is not None
    assert "point-in-time" in documentation
    assert "trusted expected plan" in documentation
    assert "read-only mount" in documentation


def test_verification_summary_does_not_authorize_a_later_path_read(
    tmp_path: Path,
) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()
    content = fixture.specs[0].content

    result = source_store.verify_source_store(
        fixture.root,
        expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        expected_plan_size=len(plan_bytes),
    )
    observed_result = result.copy()
    fixture.object_path(content).write_bytes(b"x" * len(content))

    assert result == observed_result
    with pytest.raises(source_store.SourceStoreError, match="wrong SHA-256"):
        source_store.verify_source_store(
            fixture.root,
            expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            expected_plan_size=len(plan_bytes),
        )


def test_trusted_expected_plan_binding_is_checked_at_the_consuming_boundary(
    tmp_path: Path,
) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()
    digest = hashlib.sha256(plan_bytes).hexdigest()

    result = source_store.verify_source_store(
        fixture.root,
        expected_plan_sha256=digest,
        expected_plan_size=len(plan_bytes),
    )

    assert result["plan"] == {
        "algorithm": "sha256",
        "digest": digest,
        "size": len(plan_bytes),
    }
    with pytest.raises(source_store.SourceStoreError, match="trusted expected plan"):
        source_store.verify_source_store(
            fixture.root,
            expected_plan_sha256="0" * 64,
            expected_plan_size=len(plan_bytes),
        )
    with pytest.raises(source_store.SourceStoreError, match="trusted expected plan"):
        source_store.verify_source_store(
            fixture.root,
            expected_plan_sha256=digest,
            expected_plan_size=len(plan_bytes) + 1,
        )


@pytest.mark.parametrize("omitted", ("digest", "size", "both"))
def test_trusted_expected_plan_binding_cannot_be_omitted(
    tmp_path: Path,
    omitted: str,
) -> None:
    fixture = write_fixture(tmp_path)
    arguments = trusted_plan_binding(fixture)
    if omitted in {"digest", "both"}:
        arguments.pop("expected_plan_sha256")
    if omitted in {"size", "both"}:
        arguments.pop("expected_plan_size")

    with pytest.raises(TypeError):
        source_store.verify_source_store(fixture.root, **arguments)


def test_offline_reader_separates_the_exact_request_url_from_safe_redirect_origins(
    tmp_path: Path,
) -> None:
    content = b"one object shared by two request digests"
    fixture = write_fixture(
        tmp_path,
        (
            RequestSpec("source:sha256", content),
            RequestSpec(
                "source:sha512",
                content,
                url="https://mirror.example.test/source.bin",
                algorithm="sha512",
                known_size=False,
                consumers=("platform:linux/arm64:test",),
                allowed_hosts=("mirror.example.test",),
            ),
        ),
    )
    plan_bytes = fixture.plan_path.read_bytes()

    with source_store.VerifiedSourceStoreReader(
        fixture.root,
        expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        expected_plan_size=len(plan_bytes),
    ) as reader:
        assert reader.request_ids == ("source:sha256", "source:sha512")
        plan_copy = reader.plan
        verification_copy = reader.verification
        sha256_read = reader.read_request("source:sha256")
        sha512_read = reader.read_request("source:sha512")

        plan_copy["kind"] = "changed-by-caller"
        verification_copy["kind"] = "changed-by-caller"
        assert reader.plan["kind"] == "direct"
        assert reader.verification["kind"] == source_store.RESULT_KIND
        assert sha256_read.content == content
    assert sha256_read.request_url == fixture.specs[0].url
    assert sha256_read.redirect_origins == (audit_origin(fixture.specs[0].url),)
    assert sha256_read.redirect_chain == (fixture.specs[0].url,)
    assert sha512_read.content == content
    assert sha512_read.request_url == fixture.specs[1].url
    assert sha512_read.redirect_origins == (audit_origin(fixture.specs[1].url),)
    assert sha512_read.redirect_chain == (fixture.specs[1].url,)


def test_offline_reader_preserves_alpine_distfile_plan_support(tmp_path: Path) -> None:
    spec = RequestSpec("alpine-distfile:busybox.tar.bz2", b"distfile bytes")
    fixture = write_fixture(tmp_path, (spec,))
    fixture.plan.clear()
    fixture.plan.update(alpine_distfile_plan_record((spec,)))
    fixture.manifest["kind"] = "alpine-distfiles"
    rewrite_plan(fixture, rebind=True)
    plan_bytes = fixture.plan_path.read_bytes()

    with source_store.VerifiedSourceStoreReader(
        fixture.root,
        expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        expected_plan_size=len(plan_bytes),
    ) as reader:
        result = reader.read_request(spec.identifier)

    assert result.content == spec.content


def test_offline_reader_requires_the_caller_trusted_plan_binding(tmp_path: Path) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()

    with pytest.raises(source_store.SourceStoreError, match="trusted expected plan"):
        source_store.VerifiedSourceStoreReader(
            fixture.root,
            expected_plan_sha256="0" * 64,
            expected_plan_size=len(plan_bytes),
        )


def test_offline_reader_rebinds_metadata_after_full_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()
    original_verify = source_store.verify_source_store

    def verify_then_change_metadata(
        store_root: Path,
        *,
        expected_plan_sha256: str,
        expected_plan_size: int,
    ) -> dict[str, Any]:
        result = cast(
            dict[str, Any],
            original_verify(
                store_root,
                expected_plan_sha256=expected_plan_sha256,
                expected_plan_size=expected_plan_size,
            ),
        )
        fixture.manifest_path.write_bytes(fixture.manifest_path.read_bytes() + b" ")
        return result

    monkeypatch.setattr(
        source_store,
        "verify_source_store",
        verify_then_change_metadata,
    )

    with pytest.raises(source_store.SourceStoreError, match="verification summary"):
        source_store.VerifiedSourceStoreReader(
            fixture.root,
            expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            expected_plan_size=len(plan_bytes),
        )


def test_offline_reader_rehashes_objects_before_capturing_the_retained_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()
    content = fixture.specs[0].content
    original_verify = source_store.verify_source_store

    def verify_then_change_object(
        store_root: Path,
        *,
        expected_plan_sha256: str,
        expected_plan_size: int,
    ) -> dict[str, Any]:
        result = cast(
            dict[str, Any],
            original_verify(
                store_root,
                expected_plan_sha256=expected_plan_sha256,
                expected_plan_size=expected_plan_size,
            ),
        )
        fixture.object_path(content).write_bytes(b"x" * len(content))
        return result

    monkeypatch.setattr(
        source_store,
        "verify_source_store",
        verify_then_change_object,
    )

    with pytest.raises(source_store.SourceStoreError, match="wrong SHA-256"):
        source_store.VerifiedSourceStoreReader(
            fixture.root,
            expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            expected_plan_size=len(plan_bytes),
        )


def test_offline_reader_rejects_unknown_case_variant_and_duplicate_ids(
    tmp_path: Path,
) -> None:
    fixture = write_fixture(
        tmp_path,
        (RequestSpec("source:Demo", b"reader bytes"),),
    )
    plan_bytes = fixture.plan_path.read_bytes()

    with source_store.VerifiedSourceStoreReader(
        fixture.root,
        expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        expected_plan_size=len(plan_bytes),
    ) as reader:
        assert reader.read_request("source:Demo").content == b"reader bytes"
        with pytest.raises(source_store.SourceStoreError, match="match case exactly"):
            reader.read_request("source:demo")
        with pytest.raises(source_store.SourceStoreError, match="unknown"):
            reader.read_request("source:missing")

    duplicate = write_fixture(
        tmp_path / "duplicate",
        (
            RequestSpec("source:a", b"a"),
            RequestSpec(
                "source:b",
                b"b",
                url="https://mirror.example.test/b",
                allowed_hosts=("mirror.example.test",),
            ),
        ),
    )
    duplicate.plan["requests"][1]["id"] = duplicate.plan["requests"][0]["id"]
    rewrite_plan(duplicate, rebind=True)
    duplicate_plan_bytes = duplicate.plan_path.read_bytes()
    with pytest.raises(source_store.SourceStoreError, match="sorted and unique"):
        source_store.VerifiedSourceStoreReader(
            duplicate.root,
            expected_plan_sha256=hashlib.sha256(duplicate_plan_bytes).hexdigest(),
            expected_plan_size=len(duplicate_plan_bytes),
        )


@pytest.mark.parametrize("mutation", ("rewrite", "replace", "symlink"))
def test_offline_reader_rejects_mutable_and_replaced_objects(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()
    content = fixture.specs[0].content

    with (
        pytest.raises(source_store.SourceStoreError, match=r"replaced|changed|open"),
        source_store.VerifiedSourceStoreReader(
            fixture.root,
            expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            expected_plan_size=len(plan_bytes),
        ) as reader,
    ):
        object_path = fixture.object_path(content)
        if mutation == "rewrite":
            object_path.write_bytes(b"x" * len(content))
        elif mutation == "replace":
            object_path.unlink()
            object_path.write_bytes(content)
        else:
            outside = tmp_path / "outside-object"
            outside.write_bytes(content)
            object_path.unlink()
            object_path.symlink_to(outside)
        reader.read_request(fixture.specs[0].identifier)


@pytest.mark.parametrize("mutation", ("root", "plan", "manifest"))
def test_offline_reader_rejects_changed_roots_and_metadata(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()

    with (
        pytest.raises(source_store.SourceStoreError, match=r"root|plan|manifest"),
        source_store.VerifiedSourceStoreReader(
            fixture.root,
            expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            expected_plan_size=len(plan_bytes),
        ) as reader,
    ):
        if mutation == "root":
            old_root = tmp_path / "old-store"
            fixture.root.rename(old_root)
            fixture.root.mkdir()
        elif mutation == "plan":
            fixture.plan_path.write_bytes(fixture.plan_path.read_bytes() + b" ")
        else:
            fixture.manifest_path.write_bytes(fixture.manifest_path.read_bytes() + b" ")
        reader.read_request(fixture.specs[0].identifier)


def test_offline_reader_rejects_reads_after_close(tmp_path: Path) -> None:
    fixture = write_fixture(tmp_path)
    plan_bytes = fixture.plan_path.read_bytes()
    reader = source_store.VerifiedSourceStoreReader(
        fixture.root,
        expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        expected_plan_size=len(plan_bytes),
    )

    reader.close()

    with pytest.raises(source_store.SourceStoreError, match="reader is closed"):
        reader.read_request(fixture.specs[0].identifier)
    with pytest.raises(source_store.SourceStoreError, match="reader is closed"):
        _ = reader.request_ids


def test_verifier_imports_no_network_or_archive_parser_modules() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".", maxsplit=1)[0])

    assert imported.isdisjoint(
        {
            "http",
            "requests",
            "socket",
            "tarfile",
            "urllib",
            "urllib3",
            "zipfile",
        }
    )


def test_verification_result_schema_rejects_unknowns_and_boolean_counts() -> None:
    result = {
        "schema_version": 1,
        "kind": "extra-codeowners/source-store-verification",
        "plan": {"algorithm": "sha256", "digest": "0" * 64, "size": 1},
        "manifest": {"algorithm": "sha256", "digest": "1" * 64, "size": 1},
        "request_count": 1,
        "object_count": 1,
        "total_object_bytes": 0,
    }
    assert source_store.validate_verification_result(result) == result

    unknown = {**result, "unknown": True}
    with pytest.raises(source_store.SourceStoreError, match="exactly"):
        source_store.validate_verification_result(unknown)

    boolean = {**result, "request_count": True}
    with pytest.raises(source_store.SourceStoreError, match="integer bound"):
        source_store.validate_verification_result(boolean)


def test_store_manifest_duplicate_json_keys_fail_before_schema_validation(
    tmp_path: Path,
) -> None:
    fixture = write_fixture(tmp_path)
    raw = fixture.manifest_path.read_bytes()
    assert raw.startswith(b"{")
    fixture.manifest_path.write_bytes(
        b'{"schema_version":1,"schema_version":1,' + raw.removeprefix(b"{")
    )

    with pytest.raises(source_store.SourceStoreError, match="repeats an object key"):
        verify_fixture(fixture)


def test_noncanonical_store_and_plan_json_are_rejected(tmp_path: Path) -> None:
    fixture = write_fixture(tmp_path)
    fixture.plan_path.write_bytes(
        json.dumps(fixture.plan, indent=2, sort_keys=True).encode("ascii") + b"\n"
    )
    noncanonical_plan = fixture.plan_path.read_bytes()
    with pytest.raises(source_store.SourceStoreError, match="canonical JSON"):
        source_store.verify_source_store(
            fixture.root,
            expected_plan_sha256=hashlib.sha256(noncanonical_plan).hexdigest(),
            expected_plan_size=len(noncanonical_plan),
        )

    fixture = write_fixture(tmp_path / "second")
    fixture.manifest_path.write_bytes(json.dumps(fixture.manifest, sort_keys=True).encode("ascii"))
    with pytest.raises(source_store.SourceStoreError, match="canonical JSON"):
        verify_fixture(fixture)

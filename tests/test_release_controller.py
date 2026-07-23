from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib.util
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, cast

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


controller = load_script("release_controller")
COMMIT = "a" * 40
WORKFLOW_SHA = "b" * 40


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def manifest_value(files: Mapping[str, bytes]) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    for relative_path, content in files.items():
        assets.append(
            {
                "name": PurePosixPath(relative_path).name,
                "path": relative_path,
                "sha256": sha256(content),
                "size": len(content),
            }
        )
    assets.sort(key=lambda item: item["name"])
    return {
        "assets": assets,
        "repository": "stampbot/extra-codeowners",
        "repository_id": 12345,
        "run_id": 998877,
        "schema_version": 1,
        "tag": "v0.1.0",
        "target_commit": COMMIT,
        "workflow_path": ".github/workflows/release.yml",
        "workflow_sha": WORKFLOW_SHA,
    }


def write_fixture(
    tmp_path: Path, files: Mapping[str, bytes] | None = None
) -> tuple[Any, Path, Path]:
    selected = files or {"python/app.whl": b"wheel", "security/image.spdx.json": b"sbom"}
    root = tmp_path / "assets"
    root.mkdir()
    for relative_path, content in selected.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    manifest = tmp_path / "release-manifest.json"
    manifest.write_bytes(controller.canonical_json(manifest_value(selected)))
    return controller.load_manifest(manifest), root, manifest


def expected_identity(plan: Any, **changes: Any) -> Any:
    values = {
        "manifest_sha256": plan.manifest_sha256,
        "repository": plan.repository,
        "repository_id": plan.repository_id,
        "run_id": plan.run_id,
        "tag": plan.tag,
        "target_commit": plan.target_commit,
        "workflow_path": plan.workflow_path,
        "workflow_sha": plan.workflow_sha,
    }
    values.update(changes)
    return controller.ExpectedIdentity(**values)


def reconcile(api: Any, plan: Any, root: Path, *, expected: Any | None = None) -> Any:
    return controller.reconcile_release(
        api,
        plan,
        root,
        expected=expected or expected_identity(plan),
    )


def release_record(
    plan: Any,
    *,
    release_id: int = 77,
    draft: bool = True,
    immutable: bool = False,
    **changes: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "body": plan.marker,
        "draft": draft,
        "id": release_id,
        "immutable": immutable,
        "name": plan.tag,
        "prerelease": False,
        "tag_name": plan.tag,
        "target_commitish": plan.target_commit,
        "upload_url": (
            f"https://uploads.github.com/repos/{plan.repository}/releases/"
            f"{release_id}/assets{{?name,label}}"
        ),
    }
    value.update(changes)
    return value


def remote_asset(asset: Any, *, asset_id: int, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "content_type": "application/octet-stream",
        "digest": f"sha256:{asset.sha256}",
        "id": asset_id,
        "label": None,
        "name": asset.name,
        "size": asset.size,
        "state": "uploaded",
    }
    value.update(changes)
    return value


class FakeAPI:
    def __init__(self, plan: Any) -> None:
        self.plan = plan
        self.actual_repository_id = plan.repository_id
        self.repository_id_sequence: list[int] = []
        self.tag_commit = plan.target_commit
        self.tag_resolution_sequence: list[str] = []
        self.releases: list[dict[str, Any]] = []
        self.assets: dict[int, list[dict[str, Any]]] = {}
        self.events: list[str] = []
        self.next_release_id = 77
        self.next_asset_id = 500
        self.ambiguous_create = False
        self.ambiguous_upload_after_apply: set[str] = set()
        self.ambiguous_upload_before_apply: set[str] = set()
        self.ambiguous_publish = False
        self.create_prerelease = False
        self.publish_prerelease = False
        self.publish_immutable = True
        self.publish_response_changes: dict[str, Any] = {}
        self.mutate_after_upload: tuple[Path, bytes] | None = None

    def repository_id(self) -> int:
        if self.repository_id_sequence:
            return self.repository_id_sequence.pop(0)
        return cast(int, self.actual_repository_id)

    def resolve_tag(self, tag: str) -> str:
        assert tag == self.plan.tag
        if self.tag_resolution_sequence:
            return self.tag_resolution_sequence.pop(0)
        return cast(str, self.tag_commit)

    @staticmethod
    def page(values: Sequence[dict[str, Any]], page: int, per_page: int) -> list[dict[str, Any]]:
        start = (page - 1) * per_page
        return [copy.deepcopy(value) for value in values[start : start + per_page]]

    def list_releases(self, page: int, per_page: int) -> Sequence[Mapping[str, Any]]:
        return self.page(self.releases, page, per_page)

    def create_draft(self, plan: Any) -> Mapping[str, Any]:
        self.events.append("create")
        created = release_record(
            plan,
            release_id=self.next_release_id,
            prerelease=self.create_prerelease,
        )
        self.next_release_id += 1
        self.releases.append(created)
        self.assets[created["id"]] = []
        if self.ambiguous_create:
            raise controller.AmbiguousMutationError("response lost after create")
        return copy.deepcopy(created)

    def get_release(self, release_id: int) -> Mapping[str, Any]:
        return copy.deepcopy(next(value for value in self.releases if value["id"] == release_id))

    def list_assets(self, release_id: int, page: int, per_page: int) -> Sequence[Mapping[str, Any]]:
        return self.page(self.assets.get(release_id, []), page, per_page)

    def upload_asset(self, release_id: int, upload_url: str, verified: Any) -> Mapping[str, Any]:
        asset = verified.asset
        self.events.append(f"upload:{asset.name}")
        assert upload_url == self.releases_by_id(release_id)["upload_url"]
        retained_bytes(asset, verified.descriptor)
        if asset.name in self.ambiguous_upload_before_apply:
            raise controller.AmbiguousMutationError("response lost before upload")
        uploaded = remote_asset(asset, asset_id=self.next_asset_id)
        self.next_asset_id += 1
        self.assets[release_id].append(uploaded)
        if self.mutate_after_upload is not None:
            path, content = self.mutate_after_upload
            path.write_bytes(content)
        if asset.name in self.ambiguous_upload_after_apply:
            raise controller.AmbiguousMutationError("response lost after upload")
        return copy.deepcopy(uploaded)

    def publish_release(self, release_id: int) -> Mapping[str, Any]:
        self.events.append("publish")
        release = self.releases_by_id(release_id)
        release["draft"] = False
        release["immutable"] = self.publish_immutable
        release["prerelease"] = self.publish_prerelease
        if self.ambiguous_publish:
            raise controller.AmbiguousMutationError("response lost after publish")
        response = copy.deepcopy(release)
        response.update(self.publish_response_changes)
        return response

    def releases_by_id(self, release_id: int) -> dict[str, Any]:
        return next(value for value in self.releases if value["id"] == release_id)

    def add_release(
        self, *, draft: bool = True, immutable: bool = False, **changes: Any
    ) -> dict[str, Any]:
        release = release_record(
            self.plan,
            release_id=self.next_release_id,
            draft=draft,
            immutable=immutable,
            **changes,
        )
        self.next_release_id += 1
        self.releases.append(release)
        self.assets[release["id"]] = []
        return release


def retained_bytes(asset: Any, descriptor: int) -> bytes:
    """Return the exact retained bytes a future HTTP adapter must stream."""

    result = os.pread(descriptor, asset.size, 0)
    assert len(result) == asset.size
    assert sha256(result) == asset.sha256
    return result


def test_manifest_is_canonical_exact_and_binds_local_assets(tmp_path: Path) -> None:
    plan, root, manifest = write_fixture(tmp_path)

    assert plan.repository_id == 12345
    assert plan.tag == "v0.1.0"
    assert [asset.name for asset in plan.assets] == ["app.whl", "image.spdx.json"]
    assert plan.manifest_sha256 == sha256(manifest.read_bytes())
    assert plan.manifest_sha256 in plan.marker
    with controller.open_verified_assets(root, plan) as verified:
        assert [item.asset.name for item in verified] == ["app.whl", "image.spdx.json"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value.update(extra=True), "exactly"),
        (lambda value: value.update(schema_version=True), "schema version"),
        (lambda value: value.update(schema_version=2), "unsupported schema version"),
        (lambda value: value.update(repository_id=True), "integer bounds"),
        (lambda value: value.update(tag="latest"), "release tag"),
        (
            lambda value: value["assets"][0].update(name="app.", path="one/app."),
            "release asset name",
        ),
        (lambda value: value["assets"][0].update(path="../app.whl"), "unsafe local path"),
        (lambda value: value["assets"][0].update(size=0), "integer bounds"),
        (lambda value: value["assets"].reverse(), "not sorted"),
    ],
)
def test_manifest_rejects_unknown_unbounded_or_unsafe_values(
    tmp_path: Path, change: Any, message: str
) -> None:
    files = {"one/app.whl": b"wheel", "two/image.json": b"image"}
    value = manifest_value(files)
    change(value)
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(controller.canonical_json(value))

    with pytest.raises(controller.ControllerError, match=message):
        controller.load_manifest(manifest)


def test_manifest_rejects_duplicate_keys_and_noncanonical_encoding(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}\n')
    with pytest.raises(controller.ControllerError, match="repeats JSON key"):
        controller.load_manifest(duplicate)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text('{"schema_version": 1}\n')
    with pytest.raises(controller.ControllerError, match="not canonical"):
        controller.load_manifest(noncanonical)

    floating = tmp_path / "floating.json"
    value = manifest_value({"app.whl": b"wheel"})
    value["run_id"] = 1.5
    floating.write_bytes(controller.canonical_json(value))
    with pytest.raises(controller.ControllerError, match="floating-point"):
        controller.load_manifest(floating)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"integer":' + b"9" * 10_000 + b"}\n", "not strict JSON"),
        (
            b"[" * 10_000 + b"0" + b"]" * 10_000 + b"\n",
            r"(?:not strict JSON|exceeds the JSON depth limit)",
        ),
    ],
    ids=["integer-limit", "decoder-depth"],
)
def test_manifest_normalizes_decoder_resource_failures(
    tmp_path: Path, raw: bytes, message: str
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(raw)

    with pytest.raises(controller.ControllerError, match=message):
        controller.load_manifest(manifest)


def test_manifest_read_oserror_is_normalized_and_descriptor_is_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, manifest = write_fixture(tmp_path, {"app.whl": b"wheel"})
    actual_open = os.open
    opened: list[int] = []

    def capture_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = actual_open(path, flags, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def fail_read(*_args: Any) -> bytes:
        raise OSError("read failed")

    monkeypatch.setattr(controller.os, "open", capture_open)
    monkeypatch.setattr(controller.os, "read", fail_read)

    with pytest.raises(controller.ControllerError, match="cannot read release manifest safely"):
        controller.load_manifest(manifest)

    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_fifo_manifest_and_asset_are_rejected_without_blocking(tmp_path: Path) -> None:
    manifest_fifo = tmp_path / "manifest.json"
    os.mkfifo(manifest_fifo)
    with pytest.raises(controller.ControllerError, match="single-link regular file"):
        controller.load_manifest(manifest_fifo)

    asset_tmp = tmp_path / "asset"
    asset_tmp.mkdir()
    plan, root, _ = write_fixture(asset_tmp, {"app.whl": b"wheel"})
    asset = root / "app.whl"
    asset.unlink()
    os.mkfifo(asset)
    with (
        pytest.raises(controller.ControllerError, match="not one regular file"),
        controller.open_verified_assets(root, plan),
    ):
        pass


@pytest.mark.parametrize("replacement", ["symlink", "hardlink", "content"])
def test_local_asset_verification_rejects_aliases_and_changed_bytes(
    tmp_path: Path, replacement: str
) -> None:
    plan, root, _ = write_fixture(tmp_path, {"nested/app.whl": b"wheel"})
    asset = root / "nested" / "app.whl"
    original = tmp_path / "original"
    asset.rename(original)
    if replacement == "symlink":
        asset.symlink_to(original)
    elif replacement == "hardlink":
        os.link(original, asset)
    else:
        asset.write_bytes(b"other")

    with (
        pytest.raises(controller.ControllerError, match=r"safely|regular file|SHA-256"),
        controller.open_verified_assets(root, plan),
    ):
        pass


def test_retained_asset_descriptors_close_after_success_and_failure(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path, {"nested/app.whl": b"wheel"})
    with controller.open_verified_assets(root, plan) as verified:
        success_descriptor = verified[0].descriptor
        assert not hasattr(verified[0], "path")
        os.fstat(success_descriptor)
    with pytest.raises(OSError):
        os.fstat(success_descriptor)

    failure_descriptors: list[int] = []

    def fail_consumer() -> None:
        with controller.open_verified_assets(root, plan) as verified:
            failure_descriptors.append(verified[0].descriptor)
            raise RuntimeError("consumer failed")

    with pytest.raises(RuntimeError, match="consumer failed"):
        fail_consumer()

    assert len(failure_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(failure_descriptors[0])


def test_asset_open_normalizes_first_component_failure_and_closes_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path, {"nested/app.whl": b"wheel"})
    actual_open = os.open
    root_descriptors: list[int] = []

    def capture_root(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if path == "nested":
            raise OSError("nested directory disappeared")
        descriptor = actual_open(path, flags, *args, **kwargs)
        if path == root:
            root_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(controller.os, "open", capture_root)

    with (
        pytest.raises(controller.ControllerError, match=r"cannot open release asset .* safely"),
        controller.open_verified_assets(root, plan),
    ):
        pass

    assert len(root_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(root_descriptors[0])


def test_asset_open_closes_parent_when_deeper_open_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path, {"outer/inner/app.whl": b"wheel"})
    actual_open = os.open
    opened_parents: list[int] = []

    def fail_nested(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if path == "inner":
            raise OSError("nested directory disappeared")
        descriptor = actual_open(path, flags, *args, **kwargs)
        if path == "outer":
            opened_parents.append(descriptor)
        return descriptor

    monkeypatch.setattr(controller.os, "open", fail_nested)

    with (
        pytest.raises(controller.ControllerError, match=r"cannot open release asset .* safely"),
        controller.open_verified_assets(root, plan),
    ):
        pass

    assert len(opened_parents) == 1
    with pytest.raises(OSError):
        os.fstat(opened_parents[0])


def test_asset_open_closes_asset_when_parent_close_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path, {"nested/app.whl": b"wheel"})
    actual_open = os.open
    actual_close = os.close
    parent_descriptors: list[int] = []
    asset_descriptors: list[int] = []

    def capture_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = actual_open(path, flags, *args, **kwargs)
        if path == "nested":
            parent_descriptors.append(descriptor)
        elif path == "app.whl":
            asset_descriptors.append(descriptor)
        return descriptor

    def close_parent_with_error(descriptor: int) -> None:
        actual_close(descriptor)
        if descriptor in parent_descriptors:
            raise OSError("synthetic directory close failure")

    monkeypatch.setattr(controller.os, "open", capture_open)
    monkeypatch.setattr(controller.os, "close", close_parent_with_error)

    with (
        pytest.raises(controller.ControllerError, match=r"cannot open release asset .* safely"),
        controller.open_verified_assets(root, plan),
    ):
        pass

    assert len(parent_descriptors) == len(asset_descriptors) == 1
    for descriptor in (*parent_descriptors, *asset_descriptors):
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_asset_read_oserror_is_normalized_and_descriptor_is_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path, {"app.whl": b"wheel"})
    actual_open = os.open
    opened_files: list[int] = []

    def capture_file(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = actual_open(path, flags, *args, **kwargs)
        if path == "app.whl":
            opened_files.append(descriptor)
        return descriptor

    monkeypatch.setattr(controller.os, "open", capture_file)
    monkeypatch.setattr(
        controller.os,
        "pread",
        lambda *_args: (_ for _ in ()).throw(OSError("read failed")),
    )

    with (
        pytest.raises(controller.ControllerError, match=r"cannot read release asset .* safely"),
        controller.open_verified_assets(root, plan),
    ):
        pass

    assert len(opened_files) == 1
    with pytest.raises(OSError):
        os.fstat(opened_files[0])


def test_fresh_draft_uploads_exact_assets_and_publishes_once(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)

    result = reconcile(api, plan, root)

    assert result == controller.ReleaseResult(77, plan.tag, True, resumed=False)
    assert api.events == ["create", "upload:app.whl", "upload:image.spdx.json", "publish"]
    assert {item["name"] for item in api.assets[77]} == {asset.name for asset in plan.assets}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"repository_id": 54321}, "repository ID"),
        ({"repository": "stampbot/other"}, "repository name"),
        ({"tag": "v0.2.0"}, "release tag"),
        ({"target_commit": "c" * 40}, "target commit"),
        ({"workflow_path": ".github/workflows/other.yml"}, "workflow path"),
        ({"workflow_sha": "d" * 40}, "workflow SHA"),
        ({"run_id": 112233}, "run ID"),
        ({"manifest_sha256": "e" * 64}, "manifest SHA-256"),
    ],
)
def test_untrusted_plan_must_match_separate_expected_identity(
    tmp_path: Path, change: dict[str, Any], message: str
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)

    with pytest.raises(controller.ControllerError, match=message):
        reconcile(api, plan, root, expected=expected_identity(plan, **change))

    assert api.events == []


def test_mutated_release_plan_cannot_reuse_the_loaded_manifest_digest(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    changed_asset = dataclasses.replace(plan.assets[0], sha256="f" * 64)
    forged = dataclasses.replace(plan, assets=(changed_asset, *plan.assets[1:]))
    api = FakeAPI(plan)

    with pytest.raises(controller.ControllerError, match="canonical manifest digest"):
        reconcile(api, forged, root, expected=expected_identity(plan))

    assert api.events == []


def test_partial_draft_resumes_across_paginated_releases_and_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.releases.append(release_record(plan, release_id=60, tag_name="v9.9.9", body="unrelated"))
    matching = api.add_release()
    api.assets[matching["id"]].extend(
        [
            remote_asset(plan.assets[0], asset_id=400),
        ]
    )
    monkeypatch.setattr(controller, "PAGE_SIZE", 1)

    result = reconcile(api, plan, root)

    assert result.resumed is True
    assert api.events == ["upload:image.spdx.json", "publish"]


def test_create_response_loss_reconciles_the_created_draft(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.ambiguous_create = True

    result = reconcile(api, plan, root)

    assert result.resumed is True
    assert api.events.count("create") == 1
    assert api.events[-1] == "publish"


def test_upload_response_loss_reconciles_only_an_applied_upload(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.ambiguous_upload_after_apply.add("app.whl")

    result = reconcile(api, plan, root)

    assert result.immutable is True
    assert api.events.count("upload:app.whl") == 1


def test_unapplied_ambiguous_upload_stops_without_publish_or_retry(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.ambiguous_upload_before_apply.add("app.whl")

    with pytest.raises(controller.ControllerError, match="cannot reconcile ambiguous upload"):
        reconcile(api, plan, root)

    assert api.events == ["create", "upload:app.whl"]


def test_publish_response_loss_accepts_only_reconciled_immutable_state(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.ambiguous_publish = True

    result = reconcile(api, plan, root)

    assert result.immutable is True
    assert api.events.count("publish") == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tag_name", "v999.0.0"),
        ("target_commitish", "d" * 40),
        ("name", "substituted release"),
        ("body", "substituted body"),
    ],
)
def test_malformed_successful_publish_response_uses_exact_readback(
    tmp_path: Path, field: str, value: str
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.publish_response_changes[field] = value

    result = reconcile(api, plan, root)

    assert result.immutable is True
    assert api.events.count("publish") == 1


def test_tag_move_before_publish_stops_publication(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.tag_resolution_sequence = [plan.target_commit, "d" * 40]

    with pytest.raises(controller.ControllerError, match="does not resolve"):
        reconcile(api, plan, root)

    assert "publish" not in api.events


def test_remote_change_during_final_local_rehash_stops_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release()
    api.assets[release["id"]] = [
        remote_asset(asset, asset_id=index) for index, asset in enumerate(plan.assets, start=1)
    ]
    actual_rehash = controller.require_retained_asset_unchanged
    injected = False

    def rehash_then_change_remote_state(verified: Any) -> None:
        nonlocal injected
        actual_rehash(verified)
        if not injected:
            api.assets[release["id"]].append(
                {
                    "digest": "sha256:" + "0" * 64,
                    "id": 999,
                    "name": "unexpected.bin",
                    "size": 1,
                    "state": "uploaded",
                }
            )
            injected = True

    monkeypatch.setattr(
        controller,
        "require_retained_asset_unchanged",
        rehash_then_change_remote_state,
    )

    with pytest.raises(controller.ControllerError, match="unexpected asset"):
        reconcile(api, plan, root)

    assert api.events == []


def test_tag_move_during_publish_prevents_successful_acceptance(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.tag_resolution_sequence = [plan.target_commit, plan.target_commit, "d" * 40]

    with pytest.raises(controller.ControllerError, match="does not resolve"):
        reconcile(api, plan, root)

    assert api.events[-1] == "publish"
    assert api.releases[0]["immutable"] is True


@pytest.mark.parametrize("boundary", ["create", "publish"])
def test_prerelease_state_is_rejected_at_mutation_boundaries(tmp_path: Path, boundary: str) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    if boundary == "create":
        api.create_prerelease = True
    else:
        api.publish_prerelease = True

    with pytest.raises(controller.ControllerError, match="prerelease"):
        reconcile(api, plan, root)

    assert api.events[-1] == boundary


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"name": "unexpected.bin"}, "unexpected asset"),
        ({"size": 0}, "integer bounds"),
        ({"state": "new"}, "not uploaded"),
        ({"content_type": "text/plain"}, "content type"),
        ({"label": "display label"}, "unexpected label"),
        ({"digest": "sha256:" + "0" * 64}, "does not match"),
        ({"digest": None}, "no server SHA-256"),
    ],
)
def test_remote_asset_defects_block_every_mutation(
    tmp_path: Path, changes: dict[str, Any], message: str
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release()
    api.assets[release["id"]].append(remote_asset(plan.assets[0], asset_id=1, **changes))

    with pytest.raises(controller.ControllerError, match=message):
        reconcile(api, plan, root)

    assert api.events == []


def test_remote_asset_missing_required_label_blocks_every_mutation(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release()
    asset = remote_asset(plan.assets[0], asset_id=1)
    del asset["label"]
    api.assets[release["id"]].append(asset)

    with pytest.raises(controller.ControllerError, match="unexpected label"):
        reconcile(api, plan, root)

    assert api.events == []


def test_duplicate_remote_asset_blocks_publication(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release()
    duplicate = remote_asset(plan.assets[0], asset_id=1)
    api.assets[release["id"]] = [duplicate, {**duplicate, "id": 2}]

    with pytest.raises(controller.ControllerError, match="repeats an asset"):
        reconcile(api, plan, root)

    assert api.events == []


@pytest.mark.parametrize(
    "url",
    [
        "http://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets",
        "https://attacker.example/repos/stampbot/extra-codeowners/releases/77/assets",
        "https://attacker@uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets",
        "https://uploads.github.com:444/repos/stampbot/extra-codeowners/releases/77/assets",
        "https://uploads.github.com/repos/other/repository/releases/77/assets",
        "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/78/assets",
        "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets?name=x",
        "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets#fragment",
        (
            "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/"
            "assets{?unsupported}"
        ),
    ],
)
def test_untrusted_upload_url_is_rejected_before_upload(tmp_path: Path, url: str) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.add_release(upload_url=url)

    with pytest.raises(controller.ControllerError, match="upload URL"):
        reconcile(api, plan, root)

    assert api.events == []


def test_exact_immutable_release_is_idempotent_success(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release(draft=False, immutable=True)
    api.assets[release["id"]] = [
        remote_asset(asset, asset_id=index) for index, asset in enumerate(plan.assets, start=1)
    ]

    result = reconcile(api, plan, root)

    assert result == controller.ReleaseResult(release["id"], plan.tag, True, resumed=True)
    assert api.events == []


def test_release_readback_rejects_a_substituted_release_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release()
    api.assets[release["id"]] = [
        remote_asset(asset, asset_id=index) for index, asset in enumerate(plan.assets, start=1)
    ]
    original_get_release = api.get_release

    def substituted_release(release_id: int) -> Mapping[str, Any]:
        return {**original_get_release(release_id), "id": release_id + 1}

    monkeypatch.setattr(api, "get_release", substituted_release)

    with pytest.raises(controller.ControllerError, match="different release ID"):
        reconcile(api, plan, root)

    assert "publish" not in api.events


@pytest.mark.parametrize(
    ("release_changes", "message"),
    [
        ({"draft": False, "immutable": False}, "public but mutable"),
        (
            {"draft": False, "immutable": True, "prerelease": True},
            "prerelease",
        ),
        ({"body": "foreign controller"}, "not owned"),
        ({"target_commitish": "c" * 40}, "wrong target commit"),
    ],
)
def test_mutable_or_foreign_release_is_never_modified(
    tmp_path: Path, release_changes: dict[str, Any], message: str
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.add_release(**release_changes)

    with pytest.raises(controller.ControllerError, match=message):
        reconcile(api, plan, root)

    assert api.events == []


@pytest.mark.parametrize("boundary", ["repository", "tag"])
def test_repository_and_tag_identity_fail_before_mutation(tmp_path: Path, boundary: str) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    if boundary == "repository":
        api.actual_repository_id += 1
    else:
        api.tag_commit = "d" * 40

    with pytest.raises(controller.ControllerError, match=boundary):
        reconcile(api, plan, root)

    assert api.events == []


@pytest.mark.parametrize("boundary", ["create", "upload", "publish"])
def test_repository_identity_is_rechecked_before_each_mutation(
    tmp_path: Path, boundary: str
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    if boundary == "upload":
        api.add_release()
    elif boundary == "publish":
        release = api.add_release()
        api.assets[release["id"]] = [
            remote_asset(asset, asset_id=index) for index, asset in enumerate(plan.assets, start=1)
        ]
    api.repository_id_sequence = [plan.repository_id, plan.repository_id + 1]

    with pytest.raises(controller.ControllerError, match="repository ID"):
        reconcile(api, plan, root)

    assert boundary not in api.events
    assert not any(event.startswith("upload:") for event in api.events)


def test_repository_identity_is_rechecked_during_publication_readback(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    release = api.add_release()
    api.assets[release["id"]] = [
        remote_asset(asset, asset_id=index) for index, asset in enumerate(plan.assets, start=1)
    ]
    api.repository_id_sequence = [plan.repository_id, plan.repository_id, plan.repository_id + 1]

    with pytest.raises(controller.ControllerError, match="repository ID"):
        reconcile(api, plan, root)

    assert api.events == ["publish"]
    assert api.releases[0]["immutable"] is True


def test_local_change_during_upload_leaves_only_a_draft(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path, {"python/app.whl": b"wheel"})
    api = FakeAPI(plan)
    api.mutate_after_upload = (root / "python" / "app.whl", b"other")

    with pytest.raises(controller.ControllerError, match="SHA-256"):
        reconcile(api, plan, root)

    assert api.events == ["create", "upload:app.whl"]
    assert api.releases[0]["draft"] is True


def test_pagination_bound_fails_closed_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.releases.append(release_record(plan, release_id=1, tag_name="v9.9.9", body="other"))
    monkeypatch.setattr(controller, "PAGE_SIZE", 1)
    monkeypatch.setattr(controller, "MAX_PAGES", 1)

    with pytest.raises(controller.ControllerError, match="pagination limit"):
        reconcile(api, plan, root)

    assert api.events == []


def test_exact_thousand_release_pagination_boundary_fails_closed(tmp_path: Path) -> None:
    plan, root, _ = write_fixture(tmp_path)
    api = FakeAPI(plan)
    api.releases = [
        release_record(
            plan,
            release_id=index,
            tag_name=f"v9.9.{index}",
            body="unrelated",
        )
        for index in range(1, controller.PAGE_SIZE * controller.MAX_PAGES + 1)
    ]

    with pytest.raises(controller.ControllerError, match="pagination limit"):
        reconcile(api, plan, root)

    assert api.events == []


def test_controller_api_has_no_delete_or_clobber_operation() -> None:
    public_methods = {
        name
        for name, value in vars(controller.ReleaseAPI).items()
        if callable(value) and not name.startswith("_")
    }

    assert public_methods == {
        "create_draft",
        "get_release",
        "list_assets",
        "list_releases",
        "publish_release",
        "repository_id",
        "resolve_tag",
        "upload_asset",
    }


def test_controller_is_in_every_strict_typecheck_and_container_entrypoint() -> None:
    path = ".github/scripts/release_controller.py"
    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    mise = Path("mise.toml").read_text(encoding="utf-8")
    dockerignore = Path(".dockerignore").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    for checked_scope in (ci, release, mise):
        assert path in checked_scope
    assert f"!{path}" in dockerignore
    assert path in dockerfile

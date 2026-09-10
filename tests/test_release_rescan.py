"""Release selection and platform binding for read-only vulnerability rescans."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tools.release_rescan import CHART, IMAGE, RescanError, load_index, prepare_scan, select_release


def test_index_bytes_must_match_the_published_digest() -> None:
    raw = b'{"manifests": []}'
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    assert load_index(raw, digest) == {"manifests": []}
    assert load_index(raw + b"\n", digest) == {"manifests": []}
    with pytest.raises(RescanError):
        load_index(raw + b" ", digest)


def _release(tag: str = "v0.1.0-alpha.31") -> dict[str, Any]:
    return {
        "tag_name": tag,
        "draft": False,
        "immutable": True,
        "published_at": "2026-09-01T00:00:00Z",
        "assets": [{"name": "image-reference.txt", "size": 100}],
    }


def test_release_selection_includes_alphas_and_respects_requested_tag() -> None:
    earlier = _release("v0.1.0-alpha.30")
    earlier["published_at"] = "2026-08-31T00:00:00Z"
    current = _release()
    assert select_release([earlier, current])["python_version"] == "0.1.0a31"
    assert select_release([earlier, current], earlier["tag_name"])["tag"] == earlier["tag_name"]


@pytest.mark.parametrize(
    "change",
    [
        {"immutable": False},
        {"draft": True},
        {"tag_name": "../main"},
        {"assets": [{"name": "../escape", "size": 1}]},
        {"assets": [{"name": "large", "size": 129 * 1024 * 1024}]},
        {"assets": [{"name": "a", "size": 1}] * 2},
    ],
)
def test_release_selection_rejects_unsafe_metadata(change: dict[str, Any]) -> None:
    release = _release()
    release.update(change)
    with pytest.raises(RescanError):
        select_release([release])


def test_release_selection_bounds_discovery() -> None:
    for releases in ([], [_release()] * 101):
        with pytest.raises(RescanError):
            select_release(releases)
    with pytest.raises(RescanError):
        select_release([_release()], "v0.1.0-alpha.1")


def test_source_bundle_has_a_separate_bounded_download_allowance() -> None:
    release = _release()
    release["assets"] = [{"name": "debian-source.tar", "size": 512 * 1024 * 1024}]
    assert select_release([release])["tag"] == release["tag_name"]
    release["assets"][0]["size"] += 1
    with pytest.raises(RescanError, match="size"):
        select_release([release])
    release["assets"] = [{"name": "other.tar", "size": 299 * 1024 * 1024}]
    with pytest.raises(RescanError, match="size"):
        select_release([release])
    release["assets"] = [{"name": f"file-{i}", "size": 128 * 1024 * 1024} for i in range(5)]
    with pytest.raises(RescanError, match="512 MiB"):
        select_release([release])


def _inputs(directory: Path) -> dict[str, Any]:
    (directory / "image-reference.txt").write_text(IMAGE + "@sha256:" + "a" * 64)
    (directory / "chart-reference.txt").write_text(CHART + "@sha256:" + "b" * 64)
    children = []
    for architecture, letter in (("amd64", "c"), ("arm64", "d")):
        digest = "sha256:" + letter * 64
        children.append(
            {"platform": {"os": "linux", "architecture": architecture}, "digest": digest}
        )
        (directory / f"digest-{architecture}.txt").write_text(digest)
        (directory / f"distribution-inventory-{architecture}.json").write_text(
            json.dumps({"image": {"architecture": architecture, "platform_digest": digest}})
        )
    return {"manifests": children}


def test_prepare_binds_scan_to_the_released_platform_digest(tmp_path: Path) -> None:
    manifest = _inputs(tmp_path)
    plan = prepare_scan(tmp_path, manifest, "arm64")
    assert plan["scan_image"] == IMAGE + "@sha256:" + "d" * 64


def test_prepare_rejects_duplicate_and_missing_platforms(tmp_path: Path) -> None:
    manifest = _inputs(tmp_path)
    duplicate = copy.deepcopy(manifest)
    duplicate["manifests"].append(duplicate["manifests"][0])
    for value in (duplicate, {"manifests": manifest["manifests"][:1]}):
        with pytest.raises(RescanError):
            prepare_scan(tmp_path, value, "amd64")


def test_prepare_rejects_changed_release_digest(tmp_path: Path) -> None:
    manifest = _inputs(tmp_path)
    (tmp_path / "digest-amd64.txt").write_text("sha256:" + "e" * 64)
    with pytest.raises(RescanError):
        prepare_scan(tmp_path, manifest, "amd64")


def test_prepare_rejects_an_unexpected_registry(tmp_path: Path) -> None:
    manifest = _inputs(tmp_path)
    (tmp_path / "image-reference.txt").write_text("example.com/image@sha256:" + "a" * 64)
    with pytest.raises(RescanError):
        prepare_scan(tmp_path, manifest, "amd64")


def test_rescan_workflow_is_read_only_and_verifies_before_scanning() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/rescan-release.yml").read_text()
    assert ": write" not in workflow
    assert "pull_request" not in workflow
    assert "build-push-action" not in workflow
    assert "docker push" not in workflow
    assert workflow.index("verify-release-provenance.sh") < workflow.index(
        '"${GRYPE_IMAGE}" "registry:${SCAN_IMAGE}"'
    )
    assert '--vex "/work/release-assets/extra-codeowners-${VERSION}.openvex.json"' in workflow
    assert "--config /work/.github/grype-inventory.yaml" in workflow
    assert "--env GRYPE_DB_AUTO_UPDATE=false" in workflow
    assert "docker.sock" not in workflow
    assert "architecture: [amd64, arm64]" in workflow
    assert "needs: select" in workflow
    assert workflow.count("gh api ") == 1
    assert "TAG: ${{ needs.select.outputs.tag }}" in workflow

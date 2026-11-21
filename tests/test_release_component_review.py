"""Use filesystem evidence, rather than the App version, to require fresh review."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.release_component_review import (
    ReviewInventoryError,
    check_baseline,
    main,
    project_inventory,
)

_DIGEST = "sha256:" + "1" * 64
_NEW_IMAGE = "sha256:" + "2" * 64


def _inventory(digest: str = _DIGEST, app_version: str = "0.1.0") -> dict[str, object]:
    return {
        "schema_version": 2,
        "image": {"architecture": "amd64", "platform_digest": digest, "distro": "debian-13"},
        "debian": {
            "packages": [{"package": "example", "architecture": "all", "version": "1.0"}],
            "copyright_files": [{"path": "usr/share/doc/example/copyright", "sha256": "a" * 64}],
            "shared_license_files": [],
        },
        "python": {
            "distributions": [
                {"normalized_name": "extra-codeowners", "version": app_version},
                {"normalized_name": "example", "version": "2.0", "license_expression": ["MIT"]},
            ],
            "native_files": [{"path": "lib/example.so", "sha256": "b" * 64}],
            "embedded_sboms": [
                {"path": "example.dist-info/sboms/example.json", "sha256": "c" * 64}
            ],
        },
        "cpython": {"version": "3.14.10", "source_sha256": "d" * 64},
    }


def _project(inventory: dict[str, object], digest: str = _DIGEST) -> dict[str, object]:
    return project_inventory(inventory, architecture="amd64", image_digest=digest)


def test_app_version_and_image_identity_do_not_require_new_review() -> None:
    initial = _project(_inventory())
    assert _project(_inventory(_NEW_IMAGE, "0.1.1+ci"), _NEW_IMAGE) == initial
    check_baseline(initial, initial)


@pytest.mark.parametrize(
    ("group", "section", "field", "new"),
    [
        ("debian", "packages", "version", "1.1"),
        ("debian", "copyright_files", "sha256", "0" * 64),
        ("python", "distributions", "license_expression", ["BSD-3-Clause"]),
        ("python", "native_files", "sha256", "0" * 64),
        ("python", "embedded_sboms", "sha256", "0" * 64),
    ],
)
def test_changed_runtime_record_requires_review(
    group: str, section: str, field: str, new: object
) -> None:
    inventory = _inventory()
    baseline = _project(inventory)
    row_group = inventory[group]
    assert isinstance(row_group, dict)
    row_group[section][-1][field] = new
    with pytest.raises(ReviewInventoryError, match=rf"changed: '{group}/{section}/"):
        check_baseline(baseline, _project(inventory))


def test_component_addition_and_removal_require_review() -> None:
    before = _inventory()
    after = _inventory()
    debian = after["debian"]
    assert isinstance(debian, dict)
    debian["packages"] = [{"package": "replacement", "architecture": "all", "version": "1.0"}]
    with pytest.raises(ReviewInventoryError) as failed:
        check_baseline(_project(before), _project(after))
    error = str(failed.value)
    assert "added: 'debian/packages/replacement/all'" in error
    assert "removed: 'debian/packages/example/all'" in error


def test_incomplete_or_wrong_architecture_evidence_cannot_match() -> None:
    inventory = _inventory()
    with pytest.raises(ReviewInventoryError, match="architecture"):
        project_inventory(inventory, architecture="arm64", image_digest=_DIGEST)
    with pytest.raises(ReviewInventoryError, match="digest"):
        _project(inventory, _NEW_IMAGE)
    python = inventory["python"]
    assert isinstance(python, dict)
    python.pop("native_files")
    with pytest.raises(ReviewInventoryError, match="python/native_files"):
        _project(inventory)


def test_duplicate_distribution_cannot_overwrite_evidence() -> None:
    inventory = _inventory()
    python = inventory["python"]
    assert isinstance(python, dict)
    python["distributions"].append(python["distributions"][-1].copy())
    with pytest.raises(ReviewInventoryError, match="duplicate component identity"):
        _project(inventory)


def test_snapshot_and_check_are_separate_operations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inventory = tmp_path / "inventory.json"
    baseline = tmp_path / "baseline.json"
    inventory.write_text(json.dumps(_inventory()), encoding="utf-8")
    options = [
        "--architecture",
        "amd64",
        "--image-digest",
        _DIGEST,
        "--inventory",
        str(inventory),
        "--baseline",
        str(baseline),
    ]
    assert main(["check", *options]) == 2
    assert not baseline.exists()
    assert main(["snapshot", *options]) == 0
    assert main(["check", *options]) == 0
    assert "matches the baseline" in capsys.readouterr().out


def test_check_rejects_ambiguous_input_without_updating_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inventory = tmp_path / "inventory.json"
    baseline = tmp_path / "baseline.json"
    inventory.write_text('{"schema_version": 2, "schema_version": 1}', encoding="utf-8")
    baseline.write_text("unchanged", encoding="utf-8")
    assert (
        main(
            [
                "check",
                "--architecture",
                "amd64",
                "--image-digest",
                _DIGEST,
                "--inventory",
                str(inventory),
                "--baseline",
                str(baseline),
            ]
        )
        == 2
    )
    assert "duplicate key" in capsys.readouterr().err
    assert baseline.read_text(encoding="utf-8") == "unchanged"

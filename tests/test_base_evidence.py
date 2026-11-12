"""Base refreshes compare effective ownership without treating a hash as approval."""

from typing import Any

import pytest

from extra_codeowners.base_evidence import base_evidence_fingerprint
from extra_codeowners.models import ChangedFile, ChangedFileStatus, RepositoryPolicy


def evidence(**changes: Any) -> str:
    values: dict[str, Any] = {
        "head_sha": "a" * 40,
        "base_ref": "main",
        "repository_policy": RepositoryPolicy.from_toml("schema_version = 1\nenabled = true\n"),
        "codeowners_text": "* @example/platform\n",
        "changed_files": (ChangedFile(path="uv.lock", status=ChangedFileStatus.MODIFIED),),
        "labels": frozenset({"routine"}),
        "author_identity": None,
        "allow_insecure_changes": False,
        "policy_path": ".github/extra-codeowners.toml",
    }
    values.update(changes)
    return base_evidence_fingerprint(**values)


# Verifies XCO-018.
def test_comments_and_rules_for_other_paths_do_not_change_effective_base_evidence() -> None:
    assert evidence() == evidence(
        repository_policy=RepositoryPolicy.from_toml(
            "# same policy\nschema_version=1\nenabled=true\n"
        ),
        codeowners_text="# ownership\n* @example/platform\n/docs/** @example/docs\n",
    )


# Verifies XCO-018.
@pytest.mark.parametrize(
    "change",
    [
        {"codeowners_text": "* @example/another-team\n"},
        {"repository_policy": RepositoryPolicy(enabled=False)},
        {"base_ref": "release"},
        {"head_sha": "b" * 40},
        {"labels": frozenset()},
        {"allow_insecure_changes": True},
        {"policy_path": "alternative.toml"},
        {"author_identity": (101, "another-author")},
        {"changed_files": (ChangedFile(path="README.md", status=ChangedFileStatus.MODIFIED),)},
    ],
)
def test_changed_authorization_inputs_do_not_match_previous_evidence(
    change: dict[str, Any],
) -> None:
    assert evidence(**change) != evidence()


# Verifies XCO-006, XCO-018.
def test_old_and_new_rename_paths_both_contribute_to_the_fingerprint() -> None:
    renamed = (
        ChangedFile(path="uv.lock", previous_path="old/uv.lock", status=ChangedFileStatus.RENAMED),
    )
    assert evidence(changed_files=renamed) != evidence(
        changed_files=renamed, codeowners_text="* @example/platform\n/old/** @example/other\n"
    )

"""Tests for strict CODEOWNERS parsing and matching."""

import pytest

from extra_codeowners.codeowners import (
    MAX_CODEOWNERS_BYTES,
    CodeownersParseError,
    matches_pattern,
    parse_codeowners,
)


def test_last_matching_rule_wins_and_owners_are_normalized() -> None:
    document = parse_codeowners(
        """
        # Default owners
        * @Example/Infrastructure
        /src/security/** @Example/Security @Alice # a trailing comment
        """
    )

    assert document.owners_for("README.md") == ("@example/infrastructure",)
    assert document.owners_for("src/security/token.py") == (
        "@example/security",
        "@alice",
    )


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*.py", "deep/package/module.py", True),
        ("/root.py", "root.py", True),
        ("/root.py", "deep/root.py", False),
        ("docs/*", "docs/index.md", True),
        ("docs/*", "docs/guide/index.md", False),
        ("docs/**", "docs/guide/index.md", True),
        ("**/generated/*.py", "generated/client.py", True),
        ("**/generated/*.py", "src/generated/client.py", True),
        ("docs/", "docs/index.md", True),
        ("docs/", "docs/guide/index.md", True),
        ("docs/**", "docs/guide/index.md", True),
        ("/build/logs/", "build/logs/archive/old.log", True),
        ("/build/logs/", "nested/build/logs/current.log", False),
        ("apps/", "nested/apps/service/main.py", True),
        ("/apps/github", "apps/github/actions/runner.yml", True),
        ("/apps/github", "nested/apps/github/runner.yml", False),
        ("**/logs", "deeply/nested/logs/archive/old.log", True),
    ],
)
def test_codeowners_pattern_matching(pattern: str, path: str, expected: bool) -> None:
    assert matches_pattern(pattern, path) is expected


def test_parser_reports_all_invalid_lines_and_email_owners() -> None:
    with pytest.raises(CodeownersParseError) as caught:
        parse_codeowners(
            """
            !private/** @example/security
            docs/[ab].md @example/docs
            src/** owner@example.com
            """
        )

    assert {issue.code for issue in caught.value.issues} == {
        "invalid_pattern",
        "email_owner_unsupported",
    }


def test_ownerless_rule_validly_clears_earlier_ownership() -> None:
    document = parse_codeowners(
        """
        /apps/ @octocat
        /apps/github
        """
    )

    assert document.owners_for("apps/internal/main.py") == ("@octocat",)
    assert document.owners_for("apps/github/actions/runner.yml") == ()


def test_parser_rejects_files_github_would_ignore_for_size() -> None:
    content = "#" + ("x" * MAX_CODEOWNERS_BYTES)
    with pytest.raises(CodeownersParseError) as caught:
        parse_codeowners(content)
    assert caught.value.issues[0].code == "codeowners_too_large"


def test_empty_document_has_no_owners() -> None:
    document = parse_codeowners("# intentionally empty\n")
    assert document.rules == ()
    assert document.owners_for("anything.txt") == ()


def test_internal_hash_and_escaped_space_are_valid_path_characters() -> None:
    document = parse_codeowners(
        "docs/c#-guide.md @example/docs\nrelease\\ notes/** @example/release\n"
    )

    assert document.owners_for("docs/c#-guide.md") == ("@example/docs",)
    assert document.owners_for("release notes/v1.md") == ("@example/release",)

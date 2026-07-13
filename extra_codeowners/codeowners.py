"""Strict parsing and matching for the supported GitHub CODEOWNERS subset.

GitHub silently skips malformed CODEOWNERS lines. Extra CODEOWNERS instead
reports every malformed line and fails closed, because silently changing the
approval boundary would be unsafe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from extra_codeowners.models import normalize_owner, normalize_repository_path

MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CodeownersIssue:
    """One parse error with a stable code suitable for Check Run output."""

    code: str
    message: str
    line_number: int | None = None

    def render(self) -> str:
        """Return a concise human-readable representation."""

        prefix = f"line {self.line_number}: " if self.line_number is not None else ""
        return f"{prefix}{self.message}"


class CodeownersParseError(ValueError):
    """Raised when a CODEOWNERS document cannot be evaluated safely."""

    def __init__(self, issues: tuple[CodeownersIssue, ...]) -> None:
        self.issues = issues
        super().__init__("; ".join(issue.render() for issue in issues))


def validate_pattern(pattern: str) -> str:
    """Validate a CODEOWNERS-style pattern supported by GitHub and this engine."""

    value = pattern.strip()
    if not value:
        raise ValueError("pattern must not be empty")
    if value.startswith("!"):
        raise ValueError("negated patterns ('!') are not supported by GitHub CODEOWNERS")
    if "[" in value or "]" in value:
        raise ValueError("character ranges ('[...]') are not supported by GitHub CODEOWNERS")
    if "\\" in value:
        raise ValueError("backslash escapes are not supported; use a POSIX path pattern")
    if value.startswith("#"):
        raise ValueError("a CODEOWNERS pattern cannot begin with '#'")

    without_anchor = value.removeprefix("/")
    if not without_anchor:
        raise ValueError("root-only '/' is not a file pattern")
    segments = without_anchor.rstrip("/").split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError("pattern must not contain empty, '.' or '..' path segments")
    return value


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    value = validate_pattern(pattern)
    anchored = value.startswith("/") or "/" in value.rstrip("/")
    value = value.removeprefix("/")
    final_segment = value.rstrip("/").rsplit("/", maxsplit=1)[-1]
    literal_directory_candidate = "*" not in final_segment and "?" not in final_segment
    if value.endswith("/"):
        # A trailing slash names a directory recursively. This follows GitHub's
        # `/build/logs/` and `apps/` CODEOWNERS examples; `docs/*`, by contrast,
        # remains limited to direct children.
        value += "**"

    translated: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "*":
            if index + 1 < len(value) and value[index + 1] == "*":
                index += 2
                while index < len(value) and value[index] == "*":
                    index += 1
                if index < len(value) and value[index] == "/":
                    translated.append("(?:.*/)?")
                    index += 1
                else:
                    translated.append(".*")
                continue
            translated.append("[^/]*")
        elif character == "?":
            translated.append("[^/]")
        else:
            translated.append(re.escape(character))
        index += 1

    prefix = "^" if anchored else r"^(?:.*/)?"
    # GitHub applies a pattern ending in a literal directory name to every file
    # below that directory (`/apps/github` and `**/logs` in its examples). A
    # wildcard terminal such as `docs/*` does not gain that recursive suffix.
    suffix = r"(?:/.*)?$" if literal_directory_candidate else "$"
    return re.compile(prefix + "".join(translated) + suffix)


def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Validate and precompile one CODEOWNERS-style pattern."""
    return _pattern_regex(pattern)


def matches_pattern(pattern: str, path: str) -> bool:
    """Return whether a repository-relative path matches a CODEOWNERS pattern."""

    normalized_path = normalize_repository_path(path)
    return _pattern_regex(pattern).fullmatch(normalized_path) is not None


@dataclass(frozen=True, slots=True)
class CodeownersRule:
    """One valid CODEOWNERS rule."""

    pattern: str
    owners: tuple[str, ...]
    line_number: int
    _regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_regex", _pattern_regex(self.pattern))

    def matches(self, path: str) -> bool:
        """Return whether this rule applies to ``path``."""

        normalized_path = normalize_repository_path(path)
        return self._regex.fullmatch(normalized_path) is not None

    def matches_normalized(self, path: str) -> bool:
        """Match a path already validated by the containing document."""
        return self._regex.fullmatch(path) is not None


@dataclass(frozen=True, slots=True)
class CodeownersDocument:
    """A validated CODEOWNERS file preserving GitHub's last-match-wins order."""

    rules: tuple[CodeownersRule, ...]

    def rule_for(self, path: str) -> CodeownersRule | None:
        """Return the last matching rule, as GitHub does."""

        normalized_path = normalize_repository_path(path)
        matched: CodeownersRule | None = None
        for rule in self.rules:
            if rule.matches_normalized(normalized_path):
                matched = rule
        return matched

    def owners_for(self, path: str) -> tuple[str, ...]:
        """Return owners for the last matching rule, or an empty tuple."""

        rule = self.rule_for(path)
        return () if rule is None else rule.owners


def _split_line(line: str) -> list[str]:
    """Split a CODEOWNERS line while honoring escaped whitespace in a path."""

    tokens: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(line):
        character = line[index]
        if character == "\\" and index + 1 < len(line) and line[index + 1].isspace():
            current.append(line[index + 1])
            index += 2
            continue
        if character.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(character)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


def parse_codeowners(content: str) -> CodeownersDocument:
    """Parse a CODEOWNERS document or raise all detected syntax errors."""

    size = len(content.encode("utf-8"))
    if size > MAX_CODEOWNERS_BYTES:
        issue = CodeownersIssue(
            code="codeowners_too_large",
            message=(
                f"CODEOWNERS is {size} bytes; GitHub ignores files larger than "
                f"{MAX_CODEOWNERS_BYTES} bytes"
            ),
        )
        raise CodeownersParseError((issue,))

    rules: list[CodeownersRule] = []
    issues: list[CodeownersIssue] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        tokens = _split_line(stripped)
        comment_index = next(
            (index for index, token in enumerate(tokens) if token.startswith("#")),
            len(tokens),
        )
        tokens = tokens[:comment_index]
        if not tokens:
            continue
        pattern, *raw_owners = tokens
        try:
            pattern = validate_pattern(pattern)
        except ValueError as error:
            issues.append(
                CodeownersIssue(
                    code="invalid_pattern",
                    message=str(error),
                    line_number=line_number,
                )
            )
            continue

        owners: list[str] = []
        owner_error = False
        for raw_owner in raw_owners:
            try:
                owners.append(normalize_owner(raw_owner))
            except ValueError as error:
                code = (
                    "email_owner_unsupported"
                    if "email CODEOWNER" in str(error)
                    else "invalid_owner"
                )
                issues.append(
                    CodeownersIssue(code=code, message=str(error), line_number=line_number)
                )
                owner_error = True
        if owner_error:
            continue

        # An empty owner list is valid and clears ownership established by an
        # earlier matching rule. Repeated owners do not change semantics, so
        # preserve order while removing duplicates.
        unique_owners = tuple(dict.fromkeys(owners))
        rules.append(CodeownersRule(pattern=pattern, owners=unique_owners, line_number=line_number))

    if issues:
        raise CodeownersParseError(tuple(issues))
    return CodeownersDocument(tuple(rules))

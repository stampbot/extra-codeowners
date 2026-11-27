"""Compare downloaded release bytes with GitHub's immutable asset metadata."""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import sys
from pathlib import Path


def _unique_files(root: Path, source: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"{source} has a symbolic link: {path.name}")
        if not path.is_file():
            continue
        if path.name in result:
            raise ValueError(f"{source} has duplicate asset names: {path.name}")
        result[path.name] = path
    return result


def expected_assets(version: str, python_version: str) -> frozenset[str]:
    """The full asset set of a GitHub release."""
    signed = {
        f"extra_codeowners-{python_version}-py3-none-any.whl",
        f"extra_codeowners-{python_version}.tar.gz",
        f"extra-codeowners-{version}.tgz",
        f"extra-codeowners-{version}.openvex.json",
        "debian-source.tar",
    }
    unsigned = {"chart-reference.txt", "image-reference.txt"}
    for platform in ("amd64", "arm64"):
        signed.update(
            {
                f"distribution-inventory-{platform}.json",
                f"recipient-notices-{platform}.tar.gz",
                f"native-components-{platform}.cdx.json",
                f"cpython-source-{platform}.tar.gz",
                f"python-source-{platform}.tar.gz",
                f"rust-source-{platform}.tar.gz",
            }
        )
        unsigned.update(
            {
                f"build-index-{platform}.txt",
                f"digest-{platform}.txt",
                f"vulnerability-report-{platform}.json",
            }
        )
    return frozenset(signed | unsigned | {f"{name}.sigstore.json" for name in signed})


def _require_expected(names: set[str], expected: frozenset[str], source: str) -> None:
    if names != expected:
        missing = ", ".join(sorted(expected - names)) or "none"
        extra = ", ".join(sorted(names - expected)) or "none"
        raise ValueError(
            f"{source} does not match the release asset set; "
            f"missing: {missing}; unexpected: {extra}"
        )


def validate_staged_assets(staged: Path, expected: frozenset[str]) -> dict[str, Path]:
    """Reject unknown, missing, empty, or duplicate assets before publishing."""
    local = _unique_files(staged, "the staged release")
    _require_expected(set(local), expected, "the staged release")
    for name, path in local.items():
        if path.stat().st_size == 0:
            raise ValueError(f"staged release asset {name} is empty")
        if name.endswith(".sigstore.json") and not isinstance(
            json.loads(path.read_text(encoding="utf-8")), dict
        ):
            raise ValueError(f"staged Sigstore bundle {name} is not a JSON object")
    return local


def verify_assets(
    metadata: Path, downloaded: Path, expected: frozenset[str], staged: Path | None = None
) -> None:
    """Verify the exact names and digests, and match staged non-signature assets."""
    release = json.loads(metadata.read_text(encoding="utf-8"))
    api_assets = release["assets"]
    api_names = {asset["name"] for asset in api_assets}
    if len(api_names) != len(api_assets):
        raise ValueError("the published release API has duplicate asset names")
    _require_expected(api_names, expected, "the published release API")
    remote = _unique_files(downloaded, "the published release")
    _require_expected(set(remote), expected, "the downloaded release")
    local = validate_staged_assets(staged, expected) if staged is not None else None

    for asset in api_assets:
        name = asset["name"]
        path = remote[name]
        if path.stat().st_size != asset["size"]:
            raise ValueError(f"published release asset {name} has the wrong size")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if f"sha256:{digest}" != asset["digest"]:
            raise ValueError(f"published release asset {name} has the wrong digest")
        if name.endswith(".sigstore.json"):
            if not isinstance(json.loads(path.read_text(encoding="utf-8")), dict):
                raise ValueError(f"published Sigstore bundle {name} is not a JSON object")
        elif local is not None and not filecmp.cmp(path, local[name], shallow=False):
            raise ValueError(f"published release asset {name} does not match this run")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("python_version")
    subcommands = parser.add_subparsers(dest="command", required=True)
    stage = subcommands.add_parser("stage")
    stage.add_argument("directory", type=Path)
    verify = subcommands.add_parser("verify")
    verify.add_argument("metadata", type=Path)
    verify.add_argument("directory", type=Path)
    verify.add_argument("--staged", type=Path)
    args = parser.parse_args()
    expected = expected_assets(args.version, args.python_version)
    try:
        if args.command == "stage":
            validate_staged_assets(args.directory, expected)
        else:
            verify_assets(args.metadata, args.directory, expected, args.staged)
    except (OSError, ValueError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()

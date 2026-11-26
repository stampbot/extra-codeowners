"""Compare downloaded release bytes with GitHub's immutable asset metadata."""

from __future__ import annotations

import filecmp
import hashlib
import json
import sys
from pathlib import Path


def _unique_files(root: Path, source: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in result:
            raise ValueError(f"{source} has duplicate asset names: {path.name}")
        result[path.name] = path
    return result


def verify_assets(metadata: Path, downloaded: Path, staged: Path | None = None) -> None:
    """Verify every API digest and optionally match staged non-signature assets."""
    release = json.loads(metadata.read_text(encoding="utf-8"))
    api_assets = release["assets"]
    api_names = {asset["name"] for asset in api_assets}
    if len(api_names) != len(api_assets):
        raise ValueError("the published release API has duplicate asset names")
    remote = _unique_files(downloaded, "the published release")
    local = None
    if staged is not None:
        local = _unique_files(staged, "the current run")
        if not local or api_names != local.keys():
            raise ValueError("the published release API asset names do not match this run")
    if api_names != remote.keys():
        raise ValueError("the downloaded release asset names do not match the release API")

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


if __name__ == "__main__":
    try:
        verify_assets(
            Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]) if sys.argv[3] else None
        )
    except (OSError, ValueError) as error:
        sys.exit(str(error))

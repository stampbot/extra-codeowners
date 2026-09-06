"""Select a bounded published release and bind rescan inputs to its image index."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

IMAGE = "ghcr.io/stampbot/extra-codeowners"
CHART = "ghcr.io/stampbot/charts/extra-codeowners"
TAG = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.(0|[1-9]\d*))?")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class RescanError(ValueError):
    """A release cannot be safely selected or bound to its published evidence."""


def select_release(releases: list[dict[str, Any]], requested: str = "") -> dict[str, str]:
    """Select the newest published release, or an exact tag within the bounded page."""
    if not releases or len(releases) > 100:
        raise RescanError("expected between one and 100 release records")
    if requested and TAG.fullmatch(requested) is None:
        raise RescanError("requested tag is not a supported semantic release tag")
    candidates = [release for release in releases if release.get("draft") is False]
    if requested:
        candidates = [release for release in candidates if release.get("tag_name") == requested]
    if not candidates:
        raise RescanError("no matching published release in the bounded discovery page")
    if requested and len(candidates) != 1:
        raise RescanError("release tag is ambiguous")
    try:
        release = max(candidates, key=lambda value: datetime.fromisoformat(value["published_at"]))
    except (KeyError, TypeError, ValueError) as error:
        raise RescanError("release publication timestamp is invalid") from error
    if release.get("immutable") is not True:
        raise RescanError("selected release is not immutable")
    tag = release.get("tag_name")
    if not isinstance(tag, str):
        raise RescanError("selected release has no tag")
    match = TAG.fullmatch(tag)
    if match is None:
        raise RescanError("selected tag is not a supported semantic release tag")
    major, minor, patch, channel, serial = match.groups()
    python_version = f"{major}.{minor}.{patch}"
    if channel:
        python_version += {"alpha": "a", "beta": "b", "rc": "rc"}[channel] + serial
    assets = release.get("assets")
    if not isinstance(assets, list) or not 1 <= len(assets) <= 100:
        raise RescanError("release asset count is outside its bound")
    names: set[str] = set()
    total = 0
    for asset in assets:
        name, size = asset.get("name"), asset.get("size")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}", name) is None
        ):
            raise RescanError("release contains an unsafe asset name")
        if name in names:
            raise RescanError("release contains duplicate asset names")
        names.add(name)
        if type(size) is not int or not 0 < size <= 128 * 1024 * 1024:
            raise RescanError("release asset size is outside its bound")
        total += size
    if total > 512 * 1024 * 1024:
        raise RescanError("release download exceeds 512 MiB")
    return {"tag": tag, "version": tag[1:], "python_version": python_version}


def _reference(directory: Path, filename: str, repository: str) -> str:
    path = directory / filename
    if path.stat().st_size > 1024:
        raise RescanError("release reference exceeds its size bound")
    value = path.read_text(encoding="utf-8").strip()
    prefix = repository + "@"
    if not value.startswith(prefix) or DIGEST.fullmatch(value[len(prefix) :]) is None:
        raise RescanError("release reference does not name the expected repository and digest")
    return value[len(prefix) :]


def prepare_scan(directory: Path, manifest: dict[str, Any], architecture: str) -> dict[str, str]:
    """Require both signed-inventory digests to be children of the selected index."""
    if architecture not in {"amd64", "arm64"}:
        raise RescanError("unsupported scan architecture")
    image_digest = _reference(directory, "image-reference.txt", IMAGE)
    chart_digest = _reference(directory, "chart-reference.txt", CHART)
    manifests = manifest.get("manifests")
    if not isinstance(manifests, list) or not 2 <= len(manifests) <= 8:
        raise RescanError("expected a bounded multi-platform image index")
    platforms: dict[str, str] = {}
    for child in manifests:
        platform = child.get("platform", {})
        if platform == {"architecture": "unknown", "os": "unknown"} and (
            child.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
        ):
            continue
        arch = platform.get("architecture")
        digest = child.get("digest")
        if (
            platform.get("os") != "linux"
            or arch not in {"amd64", "arm64"}
            or arch in platforms
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
        ):
            raise RescanError("image index has unexpected or duplicate platforms")
        platforms[arch] = digest
    if set(platforms) != {"amd64", "arm64"}:
        raise RescanError("image index must contain amd64 and arm64")
    for arch, digest in platforms.items():
        recorded = (directory / f"digest-{arch}.txt").read_text().strip()
        inventory = json.loads((directory / f"distribution-inventory-{arch}.json").read_bytes())
        if recorded != digest or inventory["image"]["platform_digest"] != digest:
            raise RescanError("image index differs from release platform evidence")
    return {
        "image": IMAGE,
        "image_digest": image_digest,
        "chart": CHART,
        "chart_digest": chart_digest,
        "scan_image": f"{IMAGE}@{platforms[architecture]}",
    }


def load_index(raw: bytes, expected_digest: str) -> dict[str, Any]:
    """Verify raw index bytes, allowing the CLI's one trailing output newline."""
    if len(raw) > 1024 * 1024:
        raise RescanError("image index exceeds 1 MiB")
    if not any(
        "sha256:" + hashlib.sha256(candidate).hexdigest() == expected_digest
        for candidate in (raw, raw.removesuffix(b"\n"))
    ):
        raise RescanError("image index bytes do not match the published digest")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RescanError("image index is not an object")
    return value


def main() -> None:
    """Write only validated single-line values for the read-only rescan workflow."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["select", "prepare"])
    parser.add_argument("--releases", type=Path)
    parser.add_argument("--tag", default="")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--architecture", default="amd64")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "select":
        values = select_release(json.loads(args.releases.read_bytes()), args.tag)
    else:
        digest = _reference(args.directory, "image-reference.txt", IMAGE)
        manifest = load_index(args.manifest.read_bytes(), digest)
        values = prepare_scan(args.directory, manifest, args.architecture)
    with args.output.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()

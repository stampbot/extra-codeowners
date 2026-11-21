"""Compare third-party runtime evidence with the baseline kept in Git."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

_ARCHITECTURES: Final = ("amd64", "arm64")
_MAX_JSON_BYTES: Final = 16 * 1024 * 1024
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ReviewInventoryError(ValueError):
    """The inventory is ambiguous, malformed, or different from the baseline."""


def _object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReviewInventoryError(f"{field} must be a JSON object")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or not value.isprintable():
        raise ReviewInventoryError(f"{field} must be nonempty printable text")
    return value


def _unique_object(items: list[tuple[str, object]]) -> dict[str, object]:
    record = dict(items)
    if len(record) != len(items):
        raise ReviewInventoryError("JSON contains a duplicate key")
    return record


def _read(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        data = stream.read(_MAX_JSON_BYTES + 1)
    if len(data) > _MAX_JSON_BYTES:
        raise ReviewInventoryError("inventory or baseline exceeds the JSON size limit")
    return _object(json.loads(data, object_pairs_hook=_unique_object), "document")


def _record_identity(section: str, record: dict[str, object], key_fields: tuple[str, ...]) -> str:
    parts = [_text(record.get(field), f"{section}.{field}") for field in key_fields]
    if len(parts) == 1:
        return parts[0]
    if any("/" in part for part in parts):
        raise ReviewInventoryError(f"{section} component identity must not contain a slash")
    return "/".join(parts)


def project_inventory(
    inventory: dict[str, object], *, architecture: str, image_digest: str
) -> dict[str, object]:
    """Keep component and notice evidence; leave out the image and App version."""
    if type(inventory.get("schema_version")) is not int or inventory["schema_version"] != 2:
        raise ReviewInventoryError("unsupported release inventory schema")
    image = _object(inventory.get("image"), "image")
    if architecture not in _ARCHITECTURES or image.get("architecture") != architecture:
        raise ReviewInventoryError("inventory architecture does not match the requested platform")
    if _DIGEST.fullmatch(image_digest) is None or image.get("platform_digest") != image_digest:
        raise ReviewInventoryError("inventory digest does not match the requested image")

    records: dict[str, str] = {}

    def add(key: str, record: dict[str, object]) -> None:
        if key in records:
            raise ReviewInventoryError(f"duplicate component identity: {key!r}")
        canonical = json.dumps(record, allow_nan=False, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        if "version" in record:
            version = _text(record["version"], f"{key}.version")
            records[key] = f"{version} {digest}"
        else:
            records[key] = digest

    add("debian/os-release", {k: v for k, v in image.items() if k != "platform_digest"})
    add("cpython/runtime", _object(inventory.get("cpython"), "cpython"))
    app_found = False
    for group, field, keys in (
        ("debian", "packages", ("package", "architecture")),
        ("debian", "copyright_files", ("path",)),
        ("debian", "shared_license_files", ("path",)),
        ("python", "distributions", ("normalized_name",)),
        ("python", "native_files", ("path",)),
        ("python", "embedded_sboms", ("path",)),
    ):
        section = f"{group}/{field}"
        value = _object(inventory.get(group), group).get(field)
        if not isinstance(value, list) or (field in {"packages", "distributions"} and not value):
            raise ReviewInventoryError(f"{section} must be a list of inventory records")
        for entry in value:
            record = _object(entry, section)
            identity = _record_identity(section, record, keys)
            if field == "distributions" and identity == "extra-codeowners":
                if app_found:
                    raise ReviewInventoryError("duplicate first-party distribution")
                app_found = True
                continue
            add(f"{section}/{identity}", record)
    if not app_found:
        raise ReviewInventoryError("inventory is missing the Extra CODEOWNERS distribution")
    return {"schema_version": 1, "architecture": architecture, "records": records}


def check_baseline(baseline: dict[str, object], expected: dict[str, object]) -> None:
    """Fail if any captured record is missing, added, or different."""
    fields = {"schema_version", "architecture", "records"}
    if (
        set(baseline) != fields
        or type(baseline.get("schema_version")) is not int
        or baseline["schema_version"] != expected["schema_version"]
        or baseline["architecture"] != expected["architecture"]
    ):
        raise ReviewInventoryError("invalid review baseline schema or architecture")
    previous = _object(baseline["records"], "baseline records")
    current = _object(expected["records"], "current records")
    changes = [
        (kind, key)
        for kind, keys in (
            ("added", current.keys() - previous.keys()),
            ("removed", previous.keys() - current.keys()),
            ("changed", {k for k in previous.keys() & current.keys() if previous[k] != current[k]}),
        )
        for key in sorted(keys)
    ]
    if changes:
        details = "\n".join(f"  {kind}: {key!r}" for kind, key in changes[:25])
        if len(changes) > 25:
            details += f"\n  and {len(changes) - 25} more"
        raise ReviewInventoryError(
            "third-party inventory differs from the review baseline. Review the affected "
            "notices and sources before updating it.\n" + details
        )


def main(arguments: Sequence[str] | None = None) -> int:
    """Check a built image or generate a candidate baseline for review."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "snapshot"))
    parser.add_argument("--architecture", choices=_ARCHITECTURES, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        inventory = _read(args.inventory)
        snapshot = project_inventory(
            inventory, architecture=args.architecture, image_digest=args.image_digest
        )
        if args.command == "check":
            check_baseline(_read(args.baseline), snapshot)
            sys.stdout.write(
                f"{args.architecture} third-party review inventory matches the baseline.\n"
            )
        else:
            if args.baseline.resolve() == args.inventory.resolve():
                raise ReviewInventoryError(
                    "snapshot output must not overwrite the source inventory"
                )
            args.baseline.write_text(
                json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    except (ValueError, OSError) as error:
        sys.stderr.write(f"release component review: {error}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

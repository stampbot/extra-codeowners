"""Generate a tiny synthetic BuildKit-shaped OCI layout for release-spine tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"

REVISION_LABEL = "org.opencontainers.image.revision"
VERSION_LABEL = "org.opencontainers.image.version"
WHEEL_LABEL = "org.stampbot.extra-codeowners.application-wheel.sha256"
SELECTION_LABEL = "org.stampbot.extra-codeowners.python-selection-record.sha256"

# ZIP magic under an OCI gzip media type is deliberate. The spine layer is opaque.
HOSTILE_LAYER = b"PK\x03\x04synthetic opaque bytes; this is not a release layer\n"


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        + b"\n"
    )


def _write_blob(blob_root: Path, content: bytes) -> dict[str, object]:
    digest = hashlib.sha256(content).hexdigest()
    (blob_root / digest).write_bytes(content)
    return {"digest": f"sha256:{digest}", "size": len(content)}


def _descriptor(blob: Mapping[str, object], media_type: str, **extra: object) -> dict[str, object]:
    return {"mediaType": media_type, **blob, **extra}


def generate_layout(
    layout: Path,
    *,
    source_revision: str,
    version: str,
    wheel_sha256: str,
    selection_record_sha256: str,
    candidate_registry: str,
    candidate_repository: str,
    candidate_tag: str,
) -> str:
    """Write a deterministic two-platform OCI layout and return its root digest."""

    layout.mkdir(mode=0o755)
    blob_root = layout / "blobs" / "sha256"
    blob_root.mkdir(parents=True)
    (layout / "oci-layout").write_bytes(_json_bytes({"imageLayoutVersion": "1.0.0"}))

    layer = _descriptor(_write_blob(blob_root, HOSTILE_LAYER), OCI_LAYER)
    manifests: list[dict[str, object]] = []
    for architecture in ("amd64", "arm64"):
        config_bytes = _json_bytes(
            {
                "architecture": architecture,
                "config": {
                    "Labels": {
                        REVISION_LABEL: source_revision,
                        SELECTION_LABEL: selection_record_sha256,
                        VERSION_LABEL: version,
                        WHEEL_LABEL: wheel_sha256,
                    }
                },
                "os": "linux",
            }
        )
        config = _descriptor(_write_blob(blob_root, config_bytes), OCI_CONFIG)
        manifest_bytes = _json_bytes(
            {
                "config": config,
                "layers": [layer],
                "mediaType": OCI_MANIFEST,
                "schemaVersion": 2,
            }
        )
        manifest = _descriptor(
            _write_blob(blob_root, manifest_bytes),
            OCI_MANIFEST,
            platform={"architecture": architecture, "os": "linux"},
        )
        manifests.append(manifest)

    root_bytes = _json_bytes({"manifests": manifests, "mediaType": OCI_INDEX, "schemaVersion": 2})
    root = _descriptor(_write_blob(blob_root, root_bytes), OCI_INDEX)
    candidate = f"{candidate_registry}/{candidate_repository}:{candidate_tag}"
    wrapper = {
        "manifests": [
            {
                **root,
                "annotations": {
                    "io.containerd.image.name": candidate,
                    "org.opencontainers.image.created": "2026-01-01T00:00:00Z",
                    "org.opencontainers.image.ref.name": candidate_tag,
                },
            }
        ],
        "mediaType": OCI_INDEX,
        "schemaVersion": 2,
    }
    (layout / "index.json").write_bytes(_json_bytes(wrapper))
    return str(root["digest"])


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--layout", required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--version", required=True)
    result.add_argument("--wheel-sha256", required=True)
    result.add_argument("--selection-record-sha256", required=True)
    result.add_argument("--candidate-registry", required=True)
    result.add_argument("--candidate-repository", required=True)
    result.add_argument("--candidate-tag", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    digest = generate_layout(
        Path(args.layout),
        source_revision=args.source_revision,
        version=args.version,
        wheel_sha256=args.wheel_sha256,
        selection_record_sha256=args.selection_record_sha256,
        candidate_registry=args.candidate_registry,
        candidate_repository=args.candidate_repository,
        candidate_tag=args.candidate_tag,
    )
    sys.stdout.write(f"{digest}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

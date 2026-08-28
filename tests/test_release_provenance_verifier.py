"""Contract tests for immutable-release provenance recovery."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "verify-release-provenance.sh"
BASH = shutil.which("bash")
JQ = shutil.which("jq")

REPOSITORY = "stampbot/extra-codeowners"
REVISION = "8ade2d8041bd9d2c21db602fe299aa55c53ae83b"
VERSION = "0.1.0-alpha.24"
PYTHON_VERSION = "0.1.0a24"
IMAGE = "ghcr.io/stampbot/extra-codeowners"
IMAGE_DIGEST = "sha256:0c087da375c9894a8dbc25f97944a4d33461a13886afbf72c227c2eca52d543b"
CHART_REFERENCE = "ghcr.io/stampbot/charts/extra-codeowners"
CHART_DIGEST = "sha256:2b8d78d285e97e3cf9b390b5c0404a77f012703fa79e1d9c492dee857f295ae8"
AMD64_PLATFORM_DIGEST = "sha256:" + "a" * 64
ARM64_PLATFORM_DIGEST = "sha256:" + "b" * 64


def _raw_container_inventory(architecture: str, platform_digest: str) -> bytes:
    return (
        json.dumps(
            {
                "debian": {
                    "copyright_files": [],
                    "packages": [
                        {
                            "architecture": architecture,
                            "package": "libssl3t64",
                            "source": "openssl",
                            "version": "3.5.6-1~deb13u2",
                        }
                    ],
                    "shared_license_files": [],
                    "status_path": "var/lib/dpkg/status",
                    "status_sha256": "c" * 64,
                },
                "image": {
                    "architecture": architecture,
                    "distro": "debian-13",
                    "os_release_path": "usr/lib/os-release",
                    "os_release_sha256": "d" * 64,
                    "os_release_size": 128,
                    "platform_digest": platform_digest,
                },
                "python": {
                    "distributions": [
                        {
                            "name": "example-package",
                            "normalized_name": "example-package",
                            "version": "1.0.0",
                        }
                    ],
                    "embedded_sboms": [],
                    "native_files": [],
                },
                "schema_version": 2,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _release_vex() -> bytes:
    products = []
    for architecture in ("amd64", "arm64"):
        purl = (
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?"
            f"arch={architecture}&distro=debian-13&upstream=openssl"
        )
        products.append({"@id": purl, "identifiers": {"purl": purl}})
    return (
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "urn:uuid:8b0d4df6-cb7e-4d27-8970-e1b4db0d2a4f",
                "author": "Extra CODEOWNERS maintainers",
                "statements": [
                    {
                        "impact_statement": "The service does not expose the affected feature.",
                        "products": products,
                        "status": "not_affected",
                        "vulnerability": {"name": "CVE-2026-0001"},
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _release_files() -> dict[str, bytes]:
    return {
        f"extra_codeowners-{PYTHON_VERSION}-py3-none-any.whl": b"wheel artifact\n",
        f"extra_codeowners-{PYTHON_VERSION}.tar.gz": b"source artifact\n",
        f"extra-codeowners-{VERSION}.tgz": b"chart artifact\n",
        "digest-amd64.txt": f"{AMD64_PLATFORM_DIGEST}\n".encode(),
        "digest-arm64.txt": f"{ARM64_PLATFORM_DIGEST}\n".encode(),
        "distribution-inventory-amd64.json": _raw_container_inventory(
            "amd64", AMD64_PLATFORM_DIGEST
        ),
        "distribution-inventory-arm64.json": _raw_container_inventory(
            "arm64", ARM64_PLATFORM_DIGEST
        ),
        f"extra-codeowners-{VERSION}.openvex.json": _release_vex(),
    }


def _write_fake_verifiers(fake_bin: Path) -> None:
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        """#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
with Path(os.environ["FAKE_OPERATION_LOG"]).open("a", encoding="utf-8") as log:
    print("gh " + " ".join(arguments), file=log)
if arguments[:2] != ["attestation", "verify"]:
    print("unexpected gh command", file=sys.stderr)
    raise SystemExit(97)

artifact = arguments[2]
def flag(name):
    return arguments[arguments.index(name) + 1]

expected = {
    "--repo": os.environ["FAKE_EXPECTED_REPOSITORY"],
    "--signer-workflow": os.environ["FAKE_EXPECTED_SIGNER_WORKFLOW"],
    "--source-digest": os.environ["FAKE_EXPECTED_REVISION"],
    "--source-ref": "refs/heads/main",
}
for name, value in expected.items():
    if flag(name) != value:
        print(f"unexpected {name}", file=sys.stderr)
        raise SystemExit(9)
if "--deny-self-hosted-runners" not in arguments or flag("--format") != "json":
    print("required verification constraints are missing", file=sys.stderr)
    raise SystemExit(10)

if artifact.startswith("oci://"):
    reference, digest = artifact.removeprefix("oci://").rsplit("@", 1)
    name = reference
    digest = digest.removeprefix("sha256:")
else:
    path = Path(artifact)
    name = path.name
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected_digest = json.loads(os.environ["FAKE_EXPECTED_FILE_DIGESTS"])[name]
    if digest != expected_digest:
        print("artifact digest does not match the trusted attestation", file=sys.stderr)
        raise SystemExit(11)

identity = os.environ["FAKE_CERTIFICATE_IDENTITY"]
if os.environ.get("FAKE_BAD_IDENTITY") == "true":
    identity = "https://github.com/attacker/repository/.github/workflows/release.yml@refs/heads/main"
record = {
    "verificationResult": {
        "signature": {"certificate": {"subjectAlternativeName": identity}},
        "statement": {"subject": [{"name": name, "digest": {"sha256": digest}}]},
    },
}
if os.environ.get("FAKE_REPEATED_ATTESTATION") == "true":
    print(json.dumps([record, record]))
elif os.environ.get("FAKE_CONFLICTING_ATTESTATION") == "true":
    conflicting = {
        "verificationResult": {
            "signature": {"certificate": {"subjectAlternativeName": identity}},
            "statement": {
                "subject": [{"name": name, "digest": {"sha256": "0" * 64}}]
            },
        },
    }
    print(json.dumps([record, conflicting]))
else:
    print(json.dumps([record]))
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)

    fake_cosign = fake_bin / "cosign"
    fake_cosign.write_text(
        """#!/usr/bin/env python3
import base64
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
with Path(os.environ["FAKE_OPERATION_LOG"]).open("a", encoding="utf-8") as log:
    print("cosign " + " ".join(arguments), file=log)
if arguments[0] not in {"verify", "verify-attestation", "verify-blob"}:
    print("unexpected cosign command", file=sys.stderr)
    raise SystemExit(97)
actual_identity = arguments[arguments.index("--certificate-identity") + 1]
if actual_identity != os.environ["FAKE_CERTIFICATE_IDENTITY"]:
    print("unexpected certificate identity", file=sys.stderr)
    raise SystemExit(12)
actual_issuer = arguments[arguments.index("--certificate-oidc-issuer") + 1]
if actual_issuer != "https://token.actions.githubusercontent.com":
    print("unexpected OIDC issuer", file=sys.stderr)
    raise SystemExit(13)
actual_repository = arguments[
    arguments.index("--certificate-github-workflow-repository") + 1
]
if actual_repository != os.environ["FAKE_EXPECTED_REPOSITORY"]:
    print("unexpected workflow repository", file=sys.stderr)
    raise SystemExit(14)
actual_revision = arguments[arguments.index("--certificate-github-workflow-sha") + 1]
if actual_revision != os.environ["FAKE_EXPECTED_REVISION"]:
    print("unexpected workflow revision", file=sys.stderr)
    raise SystemExit(15)
if arguments[0] == "verify-attestation":
    if arguments[arguments.index("--type") + 1] != "openvex":
        print("unexpected attestation predicate type", file=sys.stderr)
        raise SystemExit(16)
    if arguments[-1] != (
        f"{os.environ['FAKE_EXPECTED_IMAGE']}@{os.environ['FAKE_EXPECTED_IMAGE_DIGEST']}"
    ):
        print("unexpected attestation image", file=sys.stderr)
        raise SystemExit(17)
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicate": json.loads(os.environ["FAKE_EXPECTED_VEX_DOCUMENT"]),
        "predicateType": "https://openvex.dev/ns",
        "subject": [
            {
                "digest": {
                    "sha256": os.environ["FAKE_EXPECTED_IMAGE_DIGEST"].removeprefix("sha256:")
                },
                "name": os.environ["FAKE_EXPECTED_IMAGE"],
            }
        ],
    }
    if os.environ.get("FAKE_BAD_OPENVEX_ATTESTATION") == "true":
        statement["predicate"] = {"unexpected": "predicate"}
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode()).decode()
    records = [{"payload": payload}]
    if os.environ.get("FAKE_REPEATED_OPENVEX_ATTESTATION") == "true":
        records.append({"payload": payload})
    for record in records:
        print(json.dumps(record))
    raise SystemExit(0)
if arguments[0] == "verify-blob":
    bundle = Path(arguments[arguments.index("--bundle") + 1])
    try:
        json.loads(bundle.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("malformed bundle", file=sys.stderr)
        raise SystemExit(16) from None
""",
        encoding="utf-8",
    )
    fake_cosign.chmod(0o755)

    fake_sleep = fake_bin / "sleep"
    fake_sleep.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    fake_sleep.chmod(0o755)


def _tamper_source_distribution(asset_directory: Path) -> None:
    (asset_directory / f"extra_codeowners-{PYTHON_VERSION}.tar.gz").write_bytes(
        b"tampered source artifact\n"
    )


def _remove_chart_bundle(asset_directory: Path) -> None:
    (asset_directory / f"extra-codeowners-{VERSION}.tgz.sigstore.json").unlink()


def _malform_wheel_bundle(asset_directory: Path) -> None:
    (
        asset_directory / f"extra_codeowners-{PYTHON_VERSION}-py3-none-any.whl.sigstore.json"
    ).write_text(
        "not JSON\n",
        encoding="utf-8",
    )


def _invalidate_amd64_inventory_platform_binding(asset_directory: Path) -> None:
    inventory = asset_directory / "distribution-inventory-amd64.json"
    document = json.loads(inventory.read_text(encoding="utf-8"))
    document["image"]["platform_digest"] = f"sha256:{'f' * 64}"
    inventory.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")


def _invalidate_amd64_inventory_distro(asset_directory: Path) -> None:
    inventory = asset_directory / "distribution-inventory-amd64.json"
    document = json.loads(inventory.read_text(encoding="utf-8"))
    document["image"]["distro"] = "ubuntu-24.04"
    inventory.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")


def _remove_arm64_inventory(asset_directory: Path) -> None:
    (asset_directory / "distribution-inventory-arm64.json").unlink()


def _run_verifier(
    tmp_path: Path,
    *,
    environment: Mapping[str, str] | None = None,
    mutate_assets: Callable[[Path], None] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    asset_directory = tmp_path / "release-assets"
    asset_directory.mkdir()
    release_files = _release_files()
    signed_files = {
        f"extra_codeowners-{PYTHON_VERSION}-py3-none-any.whl",
        f"extra_codeowners-{PYTHON_VERSION}.tar.gz",
        f"extra-codeowners-{VERSION}.tgz",
        "distribution-inventory-amd64.json",
        "distribution-inventory-arm64.json",
        f"extra-codeowners-{VERSION}.openvex.json",
    }
    for name, contents in release_files.items():
        artifact = asset_directory / name
        artifact.write_bytes(contents)
        if name in signed_files:
            artifact.with_name(f"{name}.sigstore.json").write_text(
                '{"mediaType": "application/vnd.dev.sigstore.bundle+json"}\n',
                encoding="utf-8",
            )
    expected_file_digests = {
        name: hashlib.sha256(contents).hexdigest() for name, contents in release_files.items()
    }
    if mutate_assets is not None:
        mutate_assets(asset_directory)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_verifiers(fake_bin)
    operation_log = tmp_path / "operations.log"
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    certificate_identity = (
        f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/heads/main"
    )
    verifier_environment = os.environ | {
        "FAKE_CERTIFICATE_IDENTITY": certificate_identity,
        "FAKE_EXPECTED_FILE_DIGESTS": json.dumps(expected_file_digests),
        "FAKE_EXPECTED_IMAGE": IMAGE,
        "FAKE_EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
        "FAKE_EXPECTED_REPOSITORY": REPOSITORY,
        "FAKE_EXPECTED_REVISION": REVISION,
        "FAKE_EXPECTED_SIGNER_WORKFLOW": f"{REPOSITORY}/.github/workflows/release.yml",
        "FAKE_EXPECTED_VEX_DOCUMENT": _release_vex().decode(),
        "FAKE_OPERATION_LOG": str(operation_log),
        "GITHUB_REPOSITORY": REPOSITORY,
        "GH_TOKEN": "unused",
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
    }
    if environment is not None:
        verifier_environment |= dict(environment)

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed script
        [
            BASH,
            str(SCRIPT),
            str(asset_directory),
            IMAGE,
            IMAGE_DIGEST,
            CHART_REFERENCE,
            CHART_DIGEST,
            PYTHON_VERSION,
            VERSION,
            REVISION,
        ],
        cwd=ROOT,
        env=verifier_environment,
        check=False,
        capture_output=True,
        text=True,
    )
    operations = operation_log.read_text(encoding="utf-8").splitlines()
    return result, operations


@pytest.mark.parametrize(
    "environment",
    (
        None,
        {"FAKE_REPEATED_ATTESTATION": "true"},
        {"FAKE_REPEATED_OPENVEX_ATTESTATION": "true"},
    ),
)
@pytest.mark.skipif(BASH is None or JQ is None, reason="Bash and jq are required")
def test_release_provenance_verifier_accepts_equivalent_immutable_evidence(
    environment: Mapping[str, str] | None,
    tmp_path: Path,
) -> None:
    result, operations = _run_verifier(tmp_path, environment=environment)

    assert result.returncode == 0, result.stderr
    gh_operations = [operation for operation in operations if operation.startswith("gh ")]
    cosign_operations = [operation for operation in operations if operation.startswith("cosign ")]
    assert len(gh_operations) == 7
    assert len([operation for operation in cosign_operations if "verify-blob" in operation]) == 6
    assert len([operation for operation in cosign_operations if "cosign verify " in operation]) == 2
    assert (
        len([operation for operation in cosign_operations if "verify-attestation" in operation])
        == 1
    )
    assert all("--repo stampbot/extra-codeowners" in operation for operation in gh_operations)
    assert all(
        "--source-digest 8ade2d8041bd9d2c21db602fe299aa55c53ae83b" in operation
        for operation in gh_operations
    )
    assert not any(
        forbidden in operation
        for operation in operations
        for forbidden in (" sign", " release create", " release edit", " release delete")
    )


@pytest.mark.parametrize(
    ("failure", "environment", "mutate_assets"),
    (
        (
            "wrong-repository",
            {"GITHUB_REPOSITORY": "attacker/repository"},
            None,
        ),
        ("wrong-workflow-identity", {"FAKE_BAD_IDENTITY": "true"}, None),
        (
            "wrong-digest",
            None,
            _tamper_source_distribution,
        ),
        ("missing-bundle", None, _remove_chart_bundle),
        ("malformed-bundle", None, _malform_wheel_bundle),
        ("wrong-inventory-platform-binding", None, _invalidate_amd64_inventory_platform_binding),
        ("wrong-inventory-distro", None, _invalidate_amd64_inventory_distro),
        ("missing-inventory", None, _remove_arm64_inventory),
        ("conflicting-attestation", {"FAKE_CONFLICTING_ATTESTATION": "true"}, None),
        ("wrong-openvex-attestation", {"FAKE_BAD_OPENVEX_ATTESTATION": "true"}, None),
    ),
)
@pytest.mark.skipif(BASH is None or JQ is None, reason="Bash and jq are required")
def test_release_provenance_verifier_rejects_invalid_or_ambiguous_evidence(
    failure: str,
    environment: Mapping[str, str] | None,
    mutate_assets: Callable[[Path], None] | None,
    tmp_path: Path,
) -> None:
    result, operations = _run_verifier(
        tmp_path,
        environment=environment,
        mutate_assets=mutate_assets,
    )

    assert result.returncode != 0, failure
    assert not any(
        forbidden in operation
        for operation in operations
        for forbidden in (" sign", " release create", " release edit", " release delete")
    )

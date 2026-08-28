"""Tests for release-grade OpenVEX staging and inventory validation."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tools.release_vex import ReleaseVexError, main, validate_release_vex

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
IMAGE = "ghcr.io/stampbot/extra-codeowners"
IMAGE_DIGEST = f"sha256:{'a' * 64}"


def _inventory(architecture: str) -> dict[str, object]:
    return {
        "debian": {
            "packages": [
                {
                    "architecture": architecture,
                    "package": "libssl3t64",
                    "source": "openssl",
                    "version": "3.5.6-1~deb13u2",
                }
            ]
        },
        "image": {
            "architecture": architecture,
            "distro": "debian-13",
            "os_release_path": "usr/lib/os-release",
            "os_release_sha256": "c" * 64,
            "os_release_size": 128,
            "platform_digest": f"sha256:{architecture[0] * 64}",
        },
        "python": {
            "distributions": [{"normalized_name": "extra-codeowners", "version": "0.1.0a27"}]
        },
        "schema_version": 2,
    }


def _product(purl: str) -> dict[str, object]:
    return {"@id": purl, "identifiers": {"purl": purl}}


def _document(*products: str, status: str = "not_affected") -> dict[str, object]:
    statement: dict[str, object] = {
        "products": [_product(product) for product in products],
        "status": status,
        "vulnerability": {"name": "CVE-2026-0001"},
    }
    if status == "not_affected":
        statement["impact_statement"] = "The service does not expose the affected feature."
    if status == "fixed":
        statement["fixed_version"] = "3.5.6-1~deb13u2"
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": "urn:uuid:8b0d4df6-cb7e-4d27-8970-e1b4db0d2a4f",
        "author": "Extra CODEOWNERS maintainers",
        "statements": [statement],
        "timestamp": "2026-08-27T00:00:00Z",
        "version": 1,
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _release_inputs(tmp_path: Path, document: dict[str, object]) -> tuple[Path, list[Path]]:
    source = tmp_path / "source.openvex.json"
    amd64 = tmp_path / "amd64.json"
    arm64 = tmp_path / "arm64.json"
    _write_json(source, document)
    _write_json(amd64, _inventory("amd64"))
    _write_json(arm64, _inventory("arm64"))
    return source, [amd64, arm64]


def _attestation_output(
    document: dict[str, object],
    *,
    image_digest: str = IMAGE_DIGEST,
    statement_type: str = "https://in-toto.io/Statement/v0.1",
) -> dict[str, str]:
    statement = {
        "_type": statement_type,
        "predicate": document,
        "predicateType": "https://openvex.dev/ns",
        "subject": [
            {
                "digest": {"sha256": image_digest.removeprefix("sha256:")},
                "name": IMAGE,
            }
        ],
    }
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode()).decode()
    return {"payload": payload}


def test_validate_release_vex_requires_every_debian_product_in_the_signed_inventories(
    tmp_path: Path,
) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document(
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=amd64&distro=debian-13&upstream=openssl",
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=arm64&distro=debian-13&upstream=openssl",
        ),
    )

    assert validate_release_vex(source, inventories) == source.read_bytes()


def test_validate_release_vex_accepts_a_python_product_from_both_native_inventories(
    tmp_path: Path,
) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document("pkg:pypi/extra_codeowners@0.1.0a27"),
    )

    assert validate_release_vex(source, inventories) == source.read_bytes()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("distro", "debian-trixie", "invalid Debian distro"),
        ("os_release_path", "etc/os-release", "unsupported os-release path"),
        ("os_release_sha256", "not-a-sha256", "invalid os-release hash"),
        ("os_release_size", 0, "invalid os-release size"),
    ),
)
def test_validate_release_vex_requires_trustworthy_debian_identity_inventories(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document(
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=amd64&distro=debian-13&upstream=openssl"
        ),
    )
    inventory = json.loads(inventories[0].read_text(encoding="utf-8"))
    inventory["image"][field] = value
    _write_json(inventories[0], inventory)

    with pytest.raises(ReleaseVexError, match=message):
        validate_release_vex(source, inventories)


@pytest.mark.parametrize(
    ("document", "message"),
    (
        (
            _document(
                "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u2?"
                "arch=amd64&distro=debian-13&upstream=openssl"
            ),
            "does not match exactly one released Debian package",
        ),
        (
            _document("pkg:pypi/missing@1.0"),
            "does not match exactly one released Python distribution",
        ),
        (
            _document(
                "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?"
                "arch=amd64&distro=ubuntu-24.04&upstream=openssl"
            ),
            "does not match exactly one released Debian package",
        ),
        (
            _document(
                "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?"
                "arch=amd64&distro=debian-13&upstream=openssl&repository_url=example"
            ),
            "has unsupported qualifiers",
        ),
        (
            _document("pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=amd64&upstream=openssl"),
            "has no distro qualifier",
        ),
        (
            _document(
                "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=amd64&upstream=openssl",
                status="affected",
            ),
            "outside the release VEX policy",
        ),
    ),
)
def test_validate_release_vex_rejects_unreviewed_or_unmatched_claims(
    tmp_path: Path,
    document: dict[str, object],
    message: str,
) -> None:
    source, inventories = _release_inputs(tmp_path, document)

    with pytest.raises(ReleaseVexError, match=message):
        validate_release_vex(source, inventories)


def test_cli_copies_validated_source_bytes_without_reformatting_the_claim(tmp_path: Path) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document(
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?"
            "arch=amd64&distro=debian-13&upstream=openssl",
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?"
            "arch=arm64&distro=debian-13&upstream=openssl",
        ),
    )
    output = tmp_path / "release" / "extra-codeowners-0.1.0-alpha.27.openvex.json"
    output.parent.mkdir()

    assert (
        main(
            [
                "stage",
                "--source",
                str(source),
                "--inventory",
                str(inventories[0]),
                "--inventory",
                str(inventories[1]),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.read_bytes() == source.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o444


def test_cli_keeps_a_release_asset_absent_when_validation_fails(tmp_path: Path) -> None:
    source, inventories = _release_inputs(tmp_path, _document("pkg:pypi/missing@1.0"))
    output = tmp_path / "release.openvex.json"

    assert (
        main(
            [
                "stage",
                "--source",
                str(source),
                "--inventory",
                str(inventories[0]),
                "--inventory",
                str(inventories[1]),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()


def test_validate_release_vex_rejects_duplicate_native_inventories(tmp_path: Path) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document("pkg:pypi/extra_codeowners@0.1.0a27"),
    )

    with pytest.raises(ReleaseVexError, match="more than one amd64 inventory"):
        validate_release_vex(source, [inventories[0], inventories[0], inventories[1]])


def test_cli_verifies_an_openvex_attestation_for_the_exact_release_image(tmp_path: Path) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    vex, _ = _release_inputs(tmp_path, document)
    attestations = tmp_path / "openvex-attestations.json"
    _write_json(attestations, _attestation_output(document))

    assert (
        main(
            [
                "verify-attestation",
                "--vex",
                str(vex),
                "--attestations",
                str(attestations),
                "--image",
                IMAGE,
                "--image-digest",
                IMAGE_DIGEST,
            ]
        )
        == 0
    )


def test_cli_verifies_every_newline_delimited_openvex_attestation(tmp_path: Path) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    vex, _ = _release_inputs(tmp_path, document)
    attestations = tmp_path / "openvex-attestations.json"
    envelope = _attestation_output(document)
    attestations.write_text(
        f"{json.dumps(envelope, sort_keys=True)}\n{json.dumps(envelope, sort_keys=True)}\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "verify-attestation",
                "--vex",
                str(vex),
                "--attestations",
                str(attestations),
                "--image",
                IMAGE,
                "--image-digest",
                IMAGE_DIGEST,
            ]
        )
        == 0
    )


def test_cli_accepts_the_legacy_openvex_envelope_array(tmp_path: Path) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    vex, _ = _release_inputs(tmp_path, document)
    attestations = tmp_path / "openvex-attestations.json"
    _write_json(attestations, [_attestation_output(document)])

    assert (
        main(
            [
                "verify-attestation",
                "--vex",
                str(vex),
                "--attestations",
                str(attestations),
                "--image",
                IMAGE,
                "--image-digest",
                IMAGE_DIGEST,
            ]
        )
        == 0
    )


def test_cli_rejects_an_openvex_attestation_for_another_image_digest(tmp_path: Path) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    vex, _ = _release_inputs(tmp_path, document)
    attestations = tmp_path / "openvex-attestations.json"
    _write_json(attestations, _attestation_output(document, image_digest=f"sha256:{'b' * 64}"))

    assert (
        main(
            [
                "verify-attestation",
                "--vex",
                str(vex),
                "--attestations",
                str(attestations),
                "--image",
                IMAGE,
                "--image-digest",
                IMAGE_DIGEST,
            ]
        )
        == 2
    )


def test_cli_rejects_an_unknown_in_toto_statement_version(tmp_path: Path) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    vex, _ = _release_inputs(tmp_path, document)
    attestations = tmp_path / "openvex-attestations.json"
    _write_json(
        attestations,
        _attestation_output(document, statement_type="https://in-toto.io/Statement/v1"),
    )

    assert (
        main(
            [
                "verify-attestation",
                "--vex",
                str(vex),
                "--attestations",
                str(attestations),
                "--image",
                IMAGE,
                "--image-digest",
                IMAGE_DIGEST,
            ]
        )
        == 2
    )

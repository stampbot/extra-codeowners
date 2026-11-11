"""Tests for release-grade OpenVEX staging and inventory validation."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tools import release_vex
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


@pytest.mark.parametrize("status", ["not_affected", "fixed"])
def test_validate_release_vex_requires_every_debian_product_in_the_signed_inventories(
    tmp_path: Path,
    status: str,
) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document(
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=amd64&distro=debian-13&upstream=openssl",
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=arm64&distro=debian-13&upstream=openssl",
            status=status,
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
    "extra",
    [
        {"hashes": {"sha-256": "a" * 64}},
        {"subcomponents": [_product("pkg:generic/unreviewed@99")]},
        {"subcomponents": []},
        {"supplier": "https://example.invalid/unsupported-product-metadata"},
    ],
)
def test_release_vex_rejects_unvalidated_product_matching_fields(
    tmp_path: Path, extra: dict[str, object]
) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    statements = document["statements"]
    assert isinstance(statements, list)
    statements[0]["products"][0].update(extra)
    source, inventories = _release_inputs(tmp_path, document)

    with pytest.raises(ReleaseVexError, match="flat package-product profile"):
        validate_release_vex(source, inventories)


@pytest.mark.parametrize("alias", ["cpe22", "cpe23", "unrecognized"])
def test_release_vex_rejects_additional_identifiers_even_with_a_valid_reviewed_purl(
    tmp_path: Path, alias: str
) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    statements = document["statements"]
    assert isinstance(statements, list)
    # The consumer compares aliases as strings, regardless of their label.
    statements[0]["products"][0]["identifiers"][alias] = "pkg:generic/unreviewed@99"
    source, inventories = _release_inputs(tmp_path, document)

    with pytest.raises(ReleaseVexError, match="only the reviewed package URL"):
        validate_release_vex(source, inventories)


@pytest.mark.parametrize("status", ["fixed", "not_affected", "under_investigation"])
def test_native_claim_requires_the_reviewed_identity_and_release_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    source, inventories = _release_inputs(
        tmp_path, _document("pkg:generic/openssl@99.1.2", status=status)
    )
    lock = tmp_path / "uv.lock"
    lock.write_text("fictional lock\n", encoding="utf-8")
    verifier = Mock(return_value=frozenset({("openssl", "99.1.2")}))
    monkeypatch.setattr(release_vex, "_native_component_products", verifier)
    assert validate_release_vex(source, inventories, lock=lock) == source.read_bytes()
    verifier.assert_called_once_with(tuple(inventories), lock)


def test_native_claim_without_a_release_lock_cannot_be_staged(tmp_path: Path) -> None:
    source, inventories = _release_inputs(tmp_path, _document("pkg:generic/openssl@99.1.2"))
    with pytest.raises(ReleaseVexError, match="require the release dependency lock"):
        validate_release_vex(source, inventories)


@pytest.mark.parametrize("purl", ["pkg:generic/openssl@99.1.3", "pkg:generic/unreviewed@99.1.2"])
def test_native_version_or_component_mismatch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, purl: str
) -> None:
    source, inventories = _release_inputs(tmp_path, _document(purl))
    monkeypatch.setattr(
        release_vex,
        "_native_component_products",
        Mock(return_value=frozenset({("openssl", "99.1.2")})),
    )
    with pytest.raises(ReleaseVexError, match="unsupported VEX product"):
        validate_release_vex(source, inventories, lock=tmp_path / "uv.lock")


def test_native_source_verification_is_platform_bound_and_uses_the_intersection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, inventories = _release_inputs(tmp_path, _document("pkg:generic/openssl@99.1.2"))
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"fictional lock")
    planner = Mock(
        side_effect=[
            {"embedded_sources": [{"source_component": {"name": "openssl", "version": "99.1.2"}}]},
            {"embedded_sources": [{"source_component": {"name": "openssl", "version": "99.1.3"}}]},
        ]
    )
    monkeypatch.setattr(
        release_vex, "_native_source_verifier", lambda: SimpleNamespace(plan=planner)
    )
    assert release_vex._native_component_products(inventories, lock) == frozenset()
    assert planner.call_args_list[0].args == (
        inventories[0].read_bytes(),
        b"fictional lock",
        "amd64",
        f"sha256:{'a' * 64}",
    )
    assert planner.call_args_list[1].args == (
        inventories[1].read_bytes(),
        b"fictional lock",
        "arm64",
        f"sha256:{'a' * 64}",
    )


def test_native_source_failure_is_not_silently_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, inventories = _release_inputs(tmp_path, _document("pkg:generic/openssl@99.1.2"))
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"fictional lock")
    planner = Mock(side_effect=ValueError("changed SBOM or native-file binding"))
    monkeypatch.setattr(
        release_vex, "_native_source_verifier", lambda: SimpleNamespace(plan=planner)
    )
    with pytest.raises(ReleaseVexError, match="native VEX source evidence does not match"):
        validate_release_vex(source, inventories, lock=lock)


@pytest.mark.parametrize("architecture_index", [0, 1])
def test_real_source_verifier_rejects_an_unreviewed_wheel_sbom(
    tmp_path: Path, architecture_index: int
) -> None:
    source, inventories = _release_inputs(tmp_path, _document("pkg:generic/openssl@3.5.4"))
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """version = 1
[[package]]
name = "psycopg-binary"
version = "3.3.4"
source = {registry = "https://pypi.org/simple"}
""",
        encoding="utf-8",
    )
    # Valid Debian/platform metadata does not authenticate arbitrary wheel SBOMs.
    # Put the unreviewed wheel on the requested platform; the other has no native
    # records. Both orientations must fail, not just whichever input is first.
    for index, path in enumerate(inventories):
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["python"] = {"source_recipe_schema": 4, "distributions": []}
        if index == architecture_index:
            raw["python"]["distributions"] = [
                {"normalized_name": "psycopg-binary", "version": "3.3.4"}
            ]
            raw["python"]["embedded_sboms"] = []
        else:
            raw["python"]["distributions"] = [
                {"normalized_name": "extra-codeowners", "version": "99"}
            ]
        _write_json(path, raw)
    with pytest.raises(ReleaseVexError, match="wheel SBOM changed"):
        validate_release_vex(source, inventories, lock=lock)


@pytest.mark.parametrize("location", ["document", "statement"])
@pytest.mark.parametrize("field", ["timestamp", "last_updated"])
@pytest.mark.parametrize("value", ["not-a-date", "2026-02-30T00:00:00Z", "2026-09-02T00:00:00"])
def test_release_validation_rejects_malformed_dates(
    tmp_path: Path, location: str, field: str, value: str
) -> None:
    document = _document("pkg:pypi/extra_codeowners@0.1.0a27")
    if location == "document":
        document[field] = value
    else:
        statements = document["statements"]
        assert isinstance(statements, list)
        statement = statements[0]
        assert isinstance(statement, dict)
        statement[field] = value
    source, inventories = _release_inputs(tmp_path, document)
    with pytest.raises(ReleaseVexError, match="date-time"):
        validate_release_vex(source, inventories)


@pytest.mark.parametrize("distro_full", [None, "debian-13.5", "debian-13.6"])
def test_minor_distro_claim_requires_that_exact_inventory_identity(
    tmp_path: Path, distro_full: str | None
) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document(
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?"
            "arch=amd64&distro=debian-13.6&upstream=openssl"
        ),
    )
    if distro_full is not None:
        for path in inventories:
            inventory = json.loads(path.read_text(encoding="utf-8"))
            inventory["image"]["distro_full"] = distro_full
            _write_json(path, inventory)
    if distro_full == "debian-13.6":
        assert validate_release_vex(source, inventories) == source.read_bytes()
    else:
        with pytest.raises(ReleaseVexError, match="does not match exactly one"):
            validate_release_vex(source, inventories)


@pytest.mark.parametrize("distro_full", ["debian-14.6", "debian-13.x", "ubuntu-13.6", 13.6, ""])
def test_full_distro_identity_must_agree_with_canonical_debian_major(
    tmp_path: Path, distro_full: object
) -> None:
    source, inventories = _release_inputs(
        tmp_path,
        _document(
            "pkg:deb/debian/libssl3t64@3.5.6-1~deb13u2?arch=amd64&distro=debian-13&upstream=openssl"
        ),
    )
    inventory = json.loads(inventories[0].read_text(encoding="utf-8"))
    inventory["image"]["distro_full"] = distro_full
    _write_json(inventories[0], inventory)
    with pytest.raises(ReleaseVexError):
        validate_release_vex(source, inventories)


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

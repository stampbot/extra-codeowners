"""Validate reviewed OpenVEX data before publishing it with a release."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn, cast
from urllib.parse import unquote

_OPENVEX_CONTEXT: Final = "https://openvex.dev/ns/v0.2.0"
_ALLOWED_STATUSES: Final = frozenset(("fixed", "not_affected", "under_investigation"))
_PURL_COMPONENT_PATTERN: Final = re.compile(
    r"\Apkg:(?P<type>[a-z0-9.+-]+)/(?P<path>[^@?]+)@"
    r"(?P<version>[^?]+)(?:\?(?P<query>.*))?\Z"
)
_SHA256_DIGEST_PATTERN: Final = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_DEBIAN_DISTRO_PATTERN: Final = re.compile(r"\Adebian-[0-9]+\Z")
_OPENVEX_PREDICATE_TYPE: Final = "https://openvex.dev/ns"
_IN_TOTO_STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v0.1"


class ReleaseVexError(ValueError):
    """Raised when a reviewed VEX document cannot safely describe a release."""


@dataclass(frozen=True, slots=True)
class _DebianPackage:
    architecture: str
    distro: str
    name: str
    source: str
    version: str


@dataclass(frozen=True, slots=True)
class _PythonDistribution:
    name: str
    version: str


def _fail(message: str) -> NoReturn:
    raise ReleaseVexError(message)


def _mapping(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{description} must be a JSON object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, description: str) -> Sequence[object]:
    if not isinstance(value, list):
        _fail(f"{description} must be a JSON array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{description} must be a nonempty string")
    return value


def _load_json(raw: bytes, description: str) -> object:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        _fail(f"could not parse {description}: {error}")


def _read_bytes(path: Path, description: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise ReleaseVexError(f"could not read {description} {path}: {error}") from error


def _read_json(path: Path, description: str) -> object:
    return _load_json(_read_bytes(path, description), f"{description} {path}")


def _read_attestation_records(path: Path) -> Sequence[object]:
    """Read Cosign's one-envelope-per-JSON-value verification output."""
    description = f"OpenVEX attestation output {path}"
    try:
        content = _read_bytes(path, "OpenVEX attestation output").decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(f"could not decode {description}: {error}")

    decoder = json.JSONDecoder()
    records: list[object] = []
    offset = 0
    while True:
        while offset < len(content) and content[offset].isspace():
            offset += 1
        if offset == len(content):
            break
        try:
            value, offset = decoder.raw_decode(content, offset)
        except json.JSONDecodeError as error:
            _fail(f"could not parse {description}: {error}")
        if isinstance(value, list):
            if records:
                _fail(f"{description} mixes an array with separate envelopes")
            while offset < len(content) and content[offset].isspace():
                offset += 1
            if offset != len(content):
                _fail(f"{description} has data after its envelope array")
            return _sequence(value, description)
        records.append(value)
    return records


def _qualifiers(raw: str | None, description: str) -> Mapping[str, str]:
    if not raw:
        return {}
    qualifiers: dict[str, str] = {}
    for pair in raw.split("&"):
        key, separator, value = pair.partition("=")
        key = unquote(key)
        if not separator or not key or key in qualifiers:
            _fail(f"{description} has invalid package URL qualifiers")
        qualifiers[key] = unquote(value)
    return qualifiers


def _parse_purl(value: str) -> tuple[str, tuple[str, ...], str, Mapping[str, str]]:
    match = _PURL_COMPONENT_PATTERN.fullmatch(value)
    if match is None:
        _fail(f"unsupported VEX product package URL: {value!r}")
    path = tuple(unquote(part) for part in match.group("path").split("/"))
    if not path or any(not part for part in path):
        _fail(f"unsupported VEX product package URL: {value!r}")
    return (
        match.group("type"),
        path,
        unquote(match.group("version")),
        _qualifiers(match.group("query"), f"VEX product package URL {value!r}"),
    )


def _inventory_components(
    paths: Iterable[Path],
) -> tuple[frozenset[_DebianPackage], frozenset[_PythonDistribution]]:
    debian_packages: set[_DebianPackage] = set()
    python_distributions: set[_PythonDistribution] = set()
    inventory_architectures: dict[str, Path] = {}

    for path in paths:
        inventory = _mapping(_read_json(path, "release inventory"), "release inventory")
        if inventory.get("schema_version") != 2:
            _fail(f"release inventory {path} has an unsupported schema version")
        image = _mapping(inventory.get("image"), f"release inventory {path}.image")
        architecture = _string(
            image.get("architecture"), f"release inventory {path}.image.architecture"
        )
        if architecture in inventory_architectures:
            _fail(
                "release VEX validation received more than one "
                f"{architecture} inventory: {inventory_architectures[architecture]} and {path}"
            )
        inventory_architectures[architecture] = path
        distro = _string(image.get("distro"), f"release inventory {path}.image.distro")
        if _DEBIAN_DISTRO_PATTERN.fullmatch(distro) is None:
            _fail(f"release inventory {path}.image has an invalid Debian distro")
        if image.get("os_release_path") != "usr/lib/os-release":
            _fail(f"release inventory {path}.image has an unsupported os-release path")
        os_release_sha256 = _string(
            image.get("os_release_sha256"), f"release inventory {path}.image.os_release_sha256"
        )
        if re.fullmatch(r"[0-9a-f]{64}", os_release_sha256) is None:
            _fail(f"release inventory {path}.image has an invalid os-release hash")
        os_release_size = image.get("os_release_size")
        if (
            not isinstance(os_release_size, int)
            or isinstance(os_release_size, bool)
            or os_release_size <= 0
        ):
            _fail(f"release inventory {path}.image has an invalid os-release size")

        debian = _mapping(inventory.get("debian"), f"release inventory {path}.debian")
        for index, package_value in enumerate(
            _sequence(debian.get("packages"), f"release inventory {path}.debian.packages")
        ):
            package = _mapping(package_value, f"release inventory {path}.debian.packages[{index}]")
            source = _string(
                package.get("source"), f"release inventory {path}.debian.packages[{index}].source"
            )
            debian_packages.add(
                _DebianPackage(
                    architecture=_string(
                        package.get("architecture"),
                        f"release inventory {path}.debian.packages[{index}].architecture",
                    ),
                    distro=distro,
                    name=_string(
                        package.get("package"),
                        f"release inventory {path}.debian.packages[{index}].package",
                    ),
                    source=source.partition(" ")[0],
                    version=_string(
                        package.get("version"),
                        f"release inventory {path}.debian.packages[{index}].version",
                    ),
                )
            )

        python = _mapping(inventory.get("python"), f"release inventory {path}.python")
        for index, distribution_value in enumerate(
            _sequence(python.get("distributions"), f"release inventory {path}.python.distributions")
        ):
            distribution = _mapping(
                distribution_value, f"release inventory {path}.python.distributions[{index}]"
            )
            python_distributions.add(
                _PythonDistribution(
                    name=_string(
                        distribution.get("normalized_name"),
                        f"release inventory {path}.python.distributions[{index}].normalized_name",
                    ),
                    version=_string(
                        distribution.get("version"),
                        f"release inventory {path}.python.distributions[{index}].version",
                    ),
                )
            )

    if set(inventory_architectures) != {"amd64", "arm64"}:
        _fail("release VEX validation requires exactly one amd64 and one arm64 inventory")
    return frozenset(debian_packages), frozenset(python_distributions)


def _validate_product(
    product_value: object,
    *,
    debian_packages: frozenset[_DebianPackage],
    python_distributions: frozenset[_PythonDistribution],
    description: str,
) -> None:
    product = _mapping(product_value, description)
    identifiers = _mapping(product.get("identifiers"), f"{description}.identifiers")
    purl = _string(identifiers.get("purl"), f"{description}.identifiers.purl")
    if product.get("@id") != purl:
        _fail(f"{description} must use the package URL as its @id")

    package_type, path, version, qualifiers = _parse_purl(purl)
    if package_type == "deb" and path[0] == "debian" and len(path) == 2:
        unsupported_qualifiers = sorted(set(qualifiers) - {"arch", "distro", "upstream"})
        if unsupported_qualifiers:
            _fail(f"{description} Debian package URL has unsupported qualifiers")
        name = path[1]
        architecture = qualifiers.get("arch")
        if architecture is None:
            _fail(f"{description} Debian package URL has no architecture qualifier")
        distro = qualifiers.get("distro")
        if distro is None:
            _fail(f"{description} Debian package URL has no distro qualifier")
        upstream = qualifiers.get("upstream")
        package_candidates = [
            package
            for package in debian_packages
            if package.name == name
            and package.version == version
            and package.architecture == architecture
            and package.distro == distro
            and (upstream is None or package.source == upstream)
        ]
        if len(package_candidates) != 1:
            _fail(f"{description} does not match exactly one released Debian package: {purl}")
        return
    if package_type == "pypi" and len(path) == 1:
        if qualifiers:
            _fail(f"{description} Python package URL has unsupported qualifiers")
        normalized_name = re.sub(r"[-_.]+", "-", path[0]).lower()
        distribution_candidates = [
            distribution
            for distribution in python_distributions
            if distribution.name == normalized_name and distribution.version == version
        ]
        if len(distribution_candidates) != 1:
            _fail(f"{description} does not match exactly one released Python distribution: {purl}")
        return
    _fail(f"unsupported VEX product package URL: {purl}")


def validate_release_vex(source: Path, inventories: Iterable[Path]) -> bytes:
    """Return validated OpenVEX bytes whose product PURLs exist in the release."""
    source_bytes = source.read_bytes()
    document_value = _load_json(source_bytes, f"OpenVEX document {source}")
    document = _mapping(document_value, "OpenVEX document")
    if document.get("@context") != _OPENVEX_CONTEXT:
        _fail("OpenVEX document has an unsupported @context")
    _string(document.get("@id"), "OpenVEX document.@id")
    _string(document.get("author"), "OpenVEX document.author")
    statements = _sequence(document.get("statements"), "OpenVEX document.statements")
    if not statements:
        _fail("OpenVEX document must contain at least one statement")

    debian_packages, python_distributions = _inventory_components(inventories)
    for statement_index, statement_value in enumerate(statements):
        description = f"OpenVEX document.statements[{statement_index}]"
        statement = _mapping(statement_value, description)
        status = _string(statement.get("status"), f"{description}.status")
        if status not in _ALLOWED_STATUSES:
            _fail(f"{description} uses a status outside the release VEX policy: {status!r}")
        vulnerability = _mapping(statement.get("vulnerability"), f"{description}.vulnerability")
        _string(vulnerability.get("name"), f"{description}.vulnerability.name")
        if status == "not_affected":
            _string(statement.get("impact_statement"), f"{description}.impact_statement")
        if status == "fixed":
            _string(statement.get("fixed_version"), f"{description}.fixed_version")
        products = _sequence(statement.get("products"), f"{description}.products")
        if not products:
            _fail(f"{description} must name at least one product")
        for product_index, product_value in enumerate(products):
            _validate_product(
                product_value,
                debian_packages=debian_packages,
                python_distributions=python_distributions,
                description=f"{description}.products[{product_index}]",
            )

    return source_bytes


def verify_openvex_image_attestation(
    vex: Path,
    attestations: Path,
    *,
    image: str,
    image_digest: str,
) -> None:
    """Require every verified OCI OpenVEX attestation to name this VEX and image."""
    if not image or image_digest == "":
        _fail("OpenVEX image attestation requires an image and image digest")
    if _SHA256_DIGEST_PATTERN.fullmatch(image_digest) is None:
        _fail("OpenVEX image attestation has an invalid image digest")

    expected_predicate = _mapping(
        _read_json(vex, "release OpenVEX document"), "release OpenVEX document"
    )
    records = _read_attestation_records(attestations)
    if not records:
        _fail("OpenVEX attestation output has no verified signatures")

    expected_subject = {
        "name": image,
        "digest": {"sha256": image_digest.removeprefix("sha256:")},
    }
    for index, record_value in enumerate(records):
        record = _mapping(record_value, f"OpenVEX attestation output[{index}]")
        payload = _string(record.get("payload"), f"OpenVEX attestation output[{index}].payload")
        try:
            statement_value = json.loads(base64.b64decode(payload, validate=True))
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as error:
            _fail(f"could not parse OpenVEX attestation output[{index}] payload: {error}")
        statement = _mapping(statement_value, f"OpenVEX attestation output[{index}] statement")
        if statement.get("_type") != _IN_TOTO_STATEMENT_TYPE:
            _fail(f"OpenVEX attestation output[{index}] has an invalid in-toto statement type")
        if statement.get("predicateType") != _OPENVEX_PREDICATE_TYPE:
            _fail(f"OpenVEX attestation output[{index}] has an unexpected predicate type")
        if statement.get("subject") != [expected_subject]:
            _fail(f"OpenVEX attestation output[{index}] does not bind the released image digest")
        if statement.get("predicate") != expected_predicate:
            _fail(f"OpenVEX attestation output[{index}] does not match the signed release VEX")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stage and verify reviewed OpenVEX release evidence."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage", help="validate and copy reviewed OpenVEX data")
    stage.add_argument("--source", type=Path, required=True, help="Reviewed OpenVEX document")
    stage.add_argument(
        "--inventory",
        type=Path,
        action="append",
        required=True,
        help="Signed raw inventory for one native release image; pass once per architecture",
    )
    stage.add_argument(
        "--output",
        type=Path,
        help="Optional release-asset path. The validated source bytes are copied unchanged.",
    )
    verify = commands.add_parser(
        "verify-attestation", help="verify an OpenVEX OCI attestation's subject and predicate"
    )
    verify.add_argument("--vex", type=Path, required=True, help="Signed release OpenVEX asset")
    verify.add_argument(
        "--attestations",
        type=Path,
        required=True,
        help="JSON output from cosign verify-attestation",
    )
    verify.add_argument("--image", required=True, help="Released OCI repository name")
    verify.add_argument("--image-digest", required=True, help="Released OCI manifest digest")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Stage reviewed VEX data or verify its OCI image attestation."""
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "stage":
            source_bytes = validate_release_vex(parsed.source, parsed.inventory)
            if parsed.output is not None:
                if parsed.output.resolve() == parsed.source.resolve():
                    _fail("release VEX output must not overwrite the reviewed source document")
                if not parsed.output.parent.is_dir():
                    _fail(f"release VEX output parent does not exist: {parsed.output.parent}")
                parsed.output.write_bytes(source_bytes)
                parsed.output.chmod(0o444)
        else:
            verify_openvex_image_attestation(
                parsed.vex,
                parsed.attestations,
                image=parsed.image,
                image_digest=parsed.image_digest,
            )
    except (OSError, ReleaseVexError) as error:
        sys.stderr.write(f"release VEX error: {error}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main().
    raise SystemExit(main())

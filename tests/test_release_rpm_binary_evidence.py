"""RPM attribution must not survive a change in what the user receives."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from tools import release_rpm_binary_evidence as evidence

PURL = "pkg:rpm/centos/example-libs@1.2-3"
WHEEL = "psycopg_binary-1.2-cp314-cp314-manylinux2014_x86_64.whl"
FILENAME = "libexample-aaaaaaaa.so.1.2"
SRC = "native/psycopg-binary/amd64/example-1.2-3.src.rpm"
NOTICE = "/usr/share/licenses/example/COPYING"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def inputs() -> tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]]:
    declaration = {
        "metadata": {"component": {"purl": f"pkg:pypi/psycopg_binary@1.2?file_name={WHEEL}"}},
        "components": [{"purl": PURL, "bom-ref": f"{PURL}#{sha(b'/lib64/libexample.so.1.2')}"}],
    }
    platform = {
        "wheel_filename": WHEEL,
        "wheel_sha256": "1" * 64,
        "wheel_sbom_sha256": sha(json.dumps(declaration).encode()),
        "packages": {
            PURL: {
                "source_archive": SRC,
                "source_sha256": "3" * 64,
                "rpm_filename": "example-libs-1.2-3.x86_64.rpm",
                "rpm_sha256": "2" * 64,
                "rpm_declared_license": "BSD",
                "notices": {NOTICE: "c" * 64},
                "files": {
                    FILENAME: {
                        "rpm_path": "/usr/lib64/libexample.so.1.2",
                        "original_sha256": "a" * 64,
                        "sha256": "b" * 64,
                        "size": 123,
                    }
                },
            }
        },
    }
    lock = (
        "[[package]]\n"
        'name = "extra-codeowners"\n'
        "[[package]]\n"
        'name = "psycopg-binary"\nversion = "1.2"\n'
        f'wheels = [{{url = "https://example.com/{WHEEL}", hash = "sha256:{"1" * 64}"}}]\n'
    ).encode()
    native = [
        {
            "kind": "regular",
            "path": f"opt/venv/lib/python3.14/site-packages/psycopg_binary.libs/{FILENAME}",
            "sha256": "b" * 64,
            "size": 123,
        }
    ]
    return platform, lock, declaration, native


def test_vendor_attribution_stays_separate_from_license_conclusion(
    inputs: tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]],
) -> None:
    platform, lock, declaration, native = inputs
    packages = evidence.review(platform, lock, json.dumps(declaration).encode(), native, "1.2")
    properties = evidence.package_properties(
        packages[PURL], {"path": SRC, "sha256": "3" * 64}, [{"sha256": "c" * 64}]
    )
    assert properties["binary-rpm-declared-license"] == "BSD"
    assert json.loads(properties["binary-rpm-library-bindings"])[FILENAME]["sha256"] == "b" * 64
    assert json.loads(properties["binary-rpm-license-files"]) == {NOTICE: "c" * 64}
    assert "license" not in properties


@pytest.mark.parametrize("defect", [None, "missing", "duplicate", "unknown"])
def test_all_grafted_libraries_need_one_source(
    inputs: tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]],
    defect: str | None,
) -> None:
    platform, _, _, native = inputs
    custom_name = "libfixture-aabbccdd.so.1"
    grafted = {
        **native[0],
        "path": native[0]["path"].rsplit("/", 1)[0] + "/" + custom_name,
    }
    native.append(grafted)
    custom: list[dict[str, Any]] = [
        {
            "distribution": "psycopg-binary",
            "wheel_files": [{"path": f"psycopg_binary.libs/{custom_name}"}],
        }
    ]
    if defect == "missing":
        custom[0]["wheel_files"].clear()
    elif defect == "duplicate":
        custom[0]["wheel_files"].append({"path": f"psycopg_binary.libs/{FILENAME}"})
    elif defect == "unknown":
        native.append({**grafted, "path": grafted["path"].replace("libfixture", "libunknown")})
    if defect is None:
        evidence.verify_grafted_library_coverage(native, platform["packages"], custom)
    else:
        with pytest.raises(evidence.RpmBinaryEvidenceError, match="grafted library"):
            evidence.verify_grafted_library_coverage(native, platform["packages"], custom)


@pytest.mark.parametrize(
    "change, message",
    [
        ("lock", "locked Psycopg wheel"),
        ("sbom", "SBOM needs RPM evidence review"),
        ("extra-rpm-ref", "unmapped RPM library"),
        ("missing-rpm-ref", "unreported RPM library"),
        ("original", "original hash"),
        ("deployed", "shipped library needs"),
        ("symlink", "shipped library needs"),
    ],
)
def test_changed_binary_identity_requires_review(
    inputs: tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]],
    change: str,
    message: str,
) -> None:
    platform, lock, declaration, native = inputs
    if change == "lock":
        lock = lock.replace(b"1" * 64, b"9" * 64)
    elif change == "sbom":
        platform["wheel_sbom_sha256"] = "9" * 64
    elif change == "extra-rpm-ref":
        declaration["components"].append({"purl": PURL, "bom-ref": f"{PURL}#{'d' * 64}"})
        platform["wheel_sbom_sha256"] = sha(json.dumps(declaration).encode())
    elif change == "missing-rpm-ref":
        declaration["components"][0]["bom-ref"] = f"{PURL}#{'d' * 64}"
        platform["wheel_sbom_sha256"] = sha(json.dumps(declaration).encode())
    elif change == "original":
        platform["packages"][PURL]["files"][FILENAME]["original_sha256"] = "9" * 64
    elif change == "deployed":
        native[0]["sha256"] = "9" * 64
    else:
        native[0]["kind"] = "symlink"
    with pytest.raises(evidence.RpmBinaryEvidenceError, match=message):
        evidence.review(platform, lock, json.dumps(declaration).encode(), native, "1.2")


@pytest.mark.parametrize("change", ["notice", "source-path", "source-bytes"])
def test_attribution_requires_the_right_source_archive_and_notice(
    inputs: tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]],
    change: str,
) -> None:
    platform, *_ = inputs
    source = {
        "path": "different.src.rpm" if change == "source-path" else SRC,
        "sha256": ("4" if change == "source-bytes" else "3") * 64,
    }
    message = "does not match a selected source" if change == "notice" else "different source RPM"
    with pytest.raises(evidence.RpmBinaryEvidenceError, match=message):
        evidence.package_properties(platform["packages"][PURL], source, [{"sha256": "d" * 64}])

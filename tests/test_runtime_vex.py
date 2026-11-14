"""Keep runtime claims version-bound and tied to their reviewed evidence."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from tools.release_vex import ReleaseVexError, validate_release_vex

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "security/vex/runtime.openvex.json"
PACKAGES = (
    ("apt", "apt", "3.0.3"),
    ("libapt-pkg7.0", "apt", "3.0.3"),
    ("gzip", "gzip", "1.13-1+deb13u1"),
    ("libc-bin", "glibc", "2.41-12+deb13u4"),
    ("libc6", "glibc", "2.41-12+deb13u4"),
    ("libpcre2-8-0", "pcre2", "10.46-1~deb13u3"),
    ("libsqlite3-0", "sqlite3", "3.46.1-7+deb13u2"),
    ("libssl3t64", "openssl", "3.5.7-1~deb13u3"),
    ("openssl", "openssl", "3.5.7-1~deb13u3"),
    ("openssl-provider-legacy", "openssl", "3.5.7-1~deb13u3"),
    ("perl-base", "perl", "5.40.1-6+deb13u1"),
    ("zlib1g", "zlib", "1:1.3.dfsg+really1.3.1-1+b1"),
)


def _native_python(architecture: str) -> dict[str, object]:
    """Fixture metadata uses the checked-in reviewed recipes, not live payloads."""
    sboms: list[dict[str, object]] = []
    native: list[dict[str, object]] = []
    for name, version in (("cryptography", "50.0.0"), ("psycopg-binary", "3.3.4")):
        recipe = json.loads((ROOT / "tools/source_recipes" / f"{name}-{version}.json").read_text())
        platform = recipe["platforms"][architecture]
        relative = platform.get("sbom_relative_path", "sboms/auditwheel.cdx.json")
        directory = f"{name.replace('-', '_')}-{version}.dist-info"
        sboms.append(
            {
                "distribution": name,
                "kind": "regular",
                "link_target": None,
                "path": f"fixture/site-packages/{directory}/{relative}",
                "sha256": platform["sbom_sha256"],
                "size": platform["sbom_size"],
            }
        )
        for component in platform.get("custom_sources", []):
            native.extend(
                {
                    "kind": "regular",
                    "link_target": None,
                    "path": f"fixture/site-packages/{file['path']}",
                    "sha256": file["sha256"],
                    "size": file["size"],
                }
                for file in component["wheel_files"]
            )
    return {
        "source_recipe_schema": 4,
        "distributions": [
            {"normalized_name": "cryptography", "version": "50.0.0"},
            {"normalized_name": "psycopg-binary", "version": "3.3.4"},
        ],
        "embedded_sboms": sboms,
        "native_files": native,
    }


@pytest.fixture
def inventories(tmp_path: Path) -> list[Path]:
    paths = []
    for architecture in ("amd64", "arm64"):
        inventory = {
            "schema_version": 2,
            "image": {
                "architecture": architecture,
                "distro": "debian-13",
                "distro_full": "debian-13.7",
                "os_release_path": "usr/lib/os-release",
                "os_release_sha256": "c" * 64,
                "os_release_size": 286,
                "platform_digest": f"sha256:{'a' * 64}",
            },
            "debian": {
                "packages": [
                    {
                        "architecture": architecture,
                        "package": name,
                        "source": source,
                        "version": version,
                    }
                    for name, source, version in PACKAGES
                ]
            },
            "python": _native_python(architecture),
            "cpython": {
                "version": "3.14.10",
                "source_url": "https://www.python.org/ftp/python/3.14.10/Python-3.14.10.tar.xz",
                "source_sha256": "d" * 64,
            },
        }
        path = tmp_path / f"{architecture}.json"
        path.write_text(json.dumps(inventory), encoding="utf-8")
        paths.append(path)
    return paths


def test_current_runtime_vex_matches_both_architectures(inventories: list[Path]) -> None:
    assert validate_release_vex(SOURCE, inventories, lock=ROOT / "uv.lock") == SOURCE.read_bytes()


@pytest.mark.parametrize("package", [name for name, _, _ in PACKAGES])
@pytest.mark.parametrize("architecture_index", [0, 1])
def test_runtime_claims_require_review_after_a_package_update(
    inventories: list[Path], package: str, architecture_index: int
) -> None:
    path = inventories[architecture_index]
    inventory = json.loads(path.read_text(encoding="utf-8"))
    for installed in inventory["debian"]["packages"]:
        if installed["package"] == package:
            installed["version"] += "+new"
    path.write_text(json.dumps(inventory), encoding="utf-8")

    with pytest.raises(ReleaseVexError, match="does not match exactly one"):
        validate_release_vex(SOURCE, inventories, lock=ROOT / "uv.lock")


def test_review_records_glibc_caller_evidence_and_existing_openssl_fixes() -> None:
    document = json.loads(SOURCE.read_text(encoding="utf-8"))
    statements = document["statements"]
    assert Counter(statement["status"] for statement in statements) == {
        "fixed": 26,
        "not_affected": 18,
        "under_investigation": 45,
    }
    identities = [(s["vulnerability"]["name"], p["@id"]) for s in statements for p in s["products"]]
    assert len(identities) == len(set(identities))
    # One CVE can be fixed in Debian while still present in a bundled library.
    debian = [s for s in statements if all(p["@id"].startswith("pkg:deb/") for p in s["products"])]
    by_cve = {statement["vulnerability"]["name"]: statement for statement in debian}
    assert len(by_cve) == len(debian) == 29
    pcre2 = by_cve["CVE-2026-103111"]
    assert pcre2["status"] == "fixed"
    assert "impact_statement" not in pcre2
    assert {product["identifiers"]["purl"] for product in pcre2["products"]} == {
        f"pkg:deb/debian/libpcre2-8-0@10.46-1~deb13u3?arch={architecture}"
        "&distro=debian-13.7&upstream=pcre2"
        for architecture in ("amd64", "arm64")
    }
    assert "security-tracker.debian.org/tracker/CVE-2026-103111" in pcre2["status_notes"]
    glibc = by_cve["CVE-2026-5450"]
    assert glibc["status"] == "fixed"
    assert len(glibc["products"]) == 4
    # Retain the historical caller evidence without treating it as a claim
    # about the updated runtime. Its glibc package now contains the fixes.
    evidence = json.loads(
        (ROOT / "security/vex/glibc-2026-5450-callers.json").read_text(encoding="utf-8")
    )
    assert evidence["vulnerability"] == "CVE-2026-5450"
    assert set(evidence["platforms"]) == {"amd64", "arm64"}
    for architecture, count in (("amd64", 39), ("arm64", 45)):
        files = evidence["platforms"][architecture]["files"]
        assert (
            sum(
                len(file["fixed_formats_by_call_offset"])
                + len(file["format_forwarders_by_call_offset"])
                for file in files
            )
            == count
        )
        assert sum(len(file["format_forwarders_by_call_offset"]) for file in files) == 3
    for cve in ("CVE-2026-63073", "CVE-2026-75803"):
        assert by_cve[cve]["status"] == "fixed"
        assert len(by_cve[cve]["products"]) == 6
    assert "runtime.openvex.json" in (ROOT / ".github/actions/scan-image/action.yml").read_text(
        encoding="utf-8"
    )


def test_apt_claim_is_version_bound_and_excludes_manual_package_installation() -> None:
    document = json.loads(SOURCE.read_text(encoding="utf-8"))
    statement = next(
        item
        for item in document["statements"]
        if item["vulnerability"]["name"] == "CVE-2026-109518"
    )
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert {product["identifiers"]["purl"] for product in statement["products"]} == {
        f"pkg:deb/debian/{package}@3.0.3?arch={architecture}&distro=debian-13.7{upstream}"
        for package, upstream in (("apt", ""), ("libapt-pkg7.0", "&upstream=apt"))
        for architecture in ("amd64", "arm64")
    }
    assert "remain present and unpatched" in statement["impact_statement"]
    assert "operator-run package installation" in statement["impact_statement"]
    assert "custom code or plugins" in statement["impact_statement"]
    assert (
        "https://security-tracker.debian.org/tracker/CVE-2026-109518" in statement["status_notes"]
    )

"""Keep the reviewed runtime claims version-bound and unresolved findings visible."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from tools.release_vex import ReleaseVexError, validate_release_vex

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "security/vex/runtime.openvex.json"
PACKAGES = (
    ("gzip", "gzip", "1.13-1"),
    ("libc-bin", "glibc", "2.41-12+deb13u3"),
    ("libc6", "glibc", "2.41-12+deb13u3"),
    ("libpcre2-8-0", "pcre2", "10.46-1~deb13u1"),
    ("libsqlite3-0", "sqlite3", "3.46.1-7+deb13u1"),
    ("libssl3t64", "openssl", "3.5.7-1~deb13u2"),
    ("openssl", "openssl", "3.5.7-1~deb13u2"),
    ("openssl-provider-legacy", "openssl", "3.5.7-1~deb13u2"),
    ("perl-base", "perl", "5.40.1-6"),
)


@pytest.fixture
def inventories(tmp_path: Path) -> list[Path]:
    paths = []
    for architecture in ("amd64", "arm64"):
        inventory = {
            "schema_version": 2,
            "image": {
                "architecture": architecture,
                "distro": "debian-13",
                "distro_full": "debian-13.6",
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
            "python": {"distributions": []},
        }
        path = tmp_path / f"{architecture}.json"
        path.write_text(json.dumps(inventory), encoding="utf-8")
        paths.append(path)
    return paths


def test_current_runtime_vex_matches_both_architectures(inventories: list[Path]) -> None:
    assert validate_release_vex(SOURCE, inventories) == SOURCE.read_bytes()


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
        validate_release_vex(SOURCE, inventories)


def test_review_retains_unresolved_glibc_and_existing_openssl_fixes() -> None:
    document = json.loads(SOURCE.read_text(encoding="utf-8"))
    statements = document["statements"]
    assert Counter(statement["status"] for statement in statements) == {
        "not_affected": 17,
        "under_investigation": 1,
        "fixed": 2,
    }
    by_cve = {statement["vulnerability"]["name"]: statement for statement in statements}
    assert len(by_cve) == len(statements)
    unresolved = by_cve["CVE-2026-5450"]
    assert unresolved["status"] == "under_investigation"
    assert "impact_statement" not in unresolved
    assert len(unresolved["products"]) == 4
    assert "format provenance" in unresolved["status_notes"]
    for cve in ("CVE-2026-63073", "CVE-2026-75803"):
        assert by_cve[cve]["status"] == "fixed"
        assert len(by_cve[cve]["products"]) == 6
    assert "runtime.openvex.json" in (ROOT / ".github/actions/scan-image/action.yml").read_text(
        encoding="utf-8"
    )

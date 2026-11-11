"""Native assessments must not become blanket OpenSSL or TLS exclusions."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def native_statements() -> list[dict[str, Any]]:
    document = json.loads((ROOT / "security/vex/runtime.openvex.json").read_text())
    return [
        s
        for s in document["statements"]
        if all(p["@id"].startswith("pkg:generic/") for p in s["products"])
    ]


def test_native_intake_keeps_unresolved_candidates_visible() -> None:
    statements = native_statements()
    assert len(statements) == 59
    assert Counter(s["status"] for s in statements) == {
        "not_affected": 8,
        "under_investigation": 51,
    }
    pairs = [(s["vulnerability"]["name"], p["@id"]) for s in statements for p in s["products"]]
    assert len(pairs) == len(set(pairs)) == 82
    assert Counter(s["status"] for s in statements for _ in s["products"]) == {
        "not_affected": 13,
        "under_investigation": 69,
    }
    assert {p["@id"] for s in statements for p in s["products"]} == {
        "pkg:generic/openssl@3.5.4",
        "pkg:generic/openssl@4.0.1",
    }
    unresolved = [s for s in statements if s["status"] == "under_investigation"]
    assert all("impact_statement" not in s and "justification" not in s for s in unresolved)
    by_cve = {s["vulnerability"]["name"]: s for s in statements}
    for cve in ("CVE-2026-35189", "CVE-2026-75803"):
        assert by_cve[cve]["status"] == "under_investigation"


def test_only_the_reviewed_cms_cmp_and_32bit_cases_are_excluded() -> None:
    reviewed = {
        s["vulnerability"]["name"]: s for s in native_statements() if s["status"] == "not_affected"
    }
    assert set(reviewed) == {
        "CVE-2025-15467",
        "CVE-2026-34182",
        "CVE-2026-63073",
        "CVE-2026-31789",
        "CVE-2026-63072",
        "CVE-2026-63074",
        "CVE-2026-63076",
        "CVE-2026-75805",
    }
    for cve, statement in reviewed.items():
        assert statement["timestamp"].startswith("2026-11-11T")
        assert "unpatched" in statement["impact_statement"]
        assert "not a blanket OpenSSL exclusion" in statement["impact_statement"]
        if cve == "CVE-2026-31789":
            assert "32-bit" in statement["impact_statement"]
            assert "ELF64" in statement["impact_statement"]
            assert "justification" not in statement
        else:
            assert statement["justification"] == "vulnerable_code_not_in_execute_path"
        expected = {"pkg:generic/openssl@3.5.4"}
        if cve in {
            "CVE-2026-63073",
            "CVE-2026-63072",
            "CVE-2026-63074",
            "CVE-2026-63076",
            "CVE-2026-75805",
        }:
            expected.add("pkg:generic/openssl@4.0.1")
        assert {p["@id"] for p in statement["products"]} == expected


def test_static_evidence_covers_both_exact_64bit_psycopg_payload_sets() -> None:
    evidence = json.loads((ROOT / "security/vex/native-openssl-callers.json").read_text())
    assert evidence["release"] == "v0.1.0-alpha.83"
    assert "without execution" in evidence["method"]
    assert "not whole-program reachability" in evidence["scope"]
    platforms = {p["architecture"]: p for p in evidence["platforms"]}
    assert set(platforms) == {"amd64", "arm64"}
    for arch, count, machine in (("amd64", 17, 62), ("arm64", 18, 183)):
        files = platforms[arch]["files"]
        assert len(files) == count
        assert all(
            f["elf_class"] == 64
            and f["elf_machine"] == machine
            and len(f["sha256"]) == 64
            and not f["cms_cmp_imports"]
            for f in files
        )
        libpq = next(f for f in files if "/libpq-" in f["path"])
        assert "SSL_connect" in libpq["openssl_imports"]

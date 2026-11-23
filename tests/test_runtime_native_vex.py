"""Native assessments must not become blanket OpenSSL or TLS exclusions."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_CASES = {
    "CVE-2026-84782",
    "CVE-2026-35191",
    "CVE-2026-42772",
    "CVE-2026-54873",
    "CVE-2026-75804",
    "CVE-2026-72897",
}


def native_statements() -> list[dict[str, Any]]:
    document = json.loads((ROOT / "security/vex/runtime.openvex.json").read_text())
    return [
        s
        for s in document["statements"]
        if all(p["@id"].startswith("pkg:generic/openssl@") for p in s["products"])
    ]


def test_native_intake_keeps_unresolved_candidates_visible() -> None:
    statements = native_statements()
    assert len(statements) == 27
    assert Counter(s["status"] for s in statements) == {
        "not_affected": 11,
        "under_investigation": 14,
        "fixed": 2,
    }
    pairs = [(s["vulnerability"]["name"], p["@id"]) for s in statements for p in s["products"]]
    assert len(pairs) == len(set(pairs)) == 27
    assert {p["@id"] for s in statements for p in s["products"]} == {
        "pkg:generic/openssl@3.5.9",
        "pkg:generic/openssl@4.0.1",
    }
    unresolved = [s for s in statements if s["status"] == "under_investigation"]
    assert all("impact_statement" not in s and "justification" not in s for s in unresolved)
    fixed_by_version = {"CVE-2026-35189", "CVE-2026-75803"}
    assert {s["vulnerability"]["name"] for s in statements if s["status"] == "fixed"} == (
        fixed_by_version
    )
    for statement in statements:
        assert len(statement["products"]) == 1
        product = statement["products"][0]["@id"]
        cve = statement["vulnerability"]["name"]
        if product == "pkg:generic/openssl@3.5.9":
            assert statement["status"] == "fixed" and cve in fixed_by_version
        elif cve in fixed_by_version:
            assert statement["status"] == "under_investigation"


def test_only_the_reviewed_cases_are_excluded() -> None:
    reviewed = {
        s["vulnerability"]["name"]: s for s in native_statements() if s["status"] == "not_affected"
    }
    assert set(reviewed) == PROTOCOL_CASES | {
        "CVE-2026-63073",
        "CVE-2026-63072",
        "CVE-2026-63074",
        "CVE-2026-63076",
        "CVE-2026-75805",
    }
    for statement in reviewed.values():
        assert statement["timestamp"].startswith("2026-11-23T")
        assert "unpatched" in statement["impact_statement"]
        assert "not a blanket OpenSSL exclusion" in statement["impact_statement"]
        assert statement["justification"] == "vulnerable_code_not_in_execute_path"
        assert {p["@id"] for p in statement["products"]} == {"pkg:generic/openssl@4.0.1"}


def test_protocol_review_keeps_client_tls_distinct_from_other_protocols() -> None:
    evidence = json.loads((ROOT / "security/vex/native-protocol-callers.json").read_text())
    assert evidence["architectures"] == ["amd64", "arm64"]
    assert evidence["libpq"]["inspected_c_and_header_files"] == 33
    assert evidence["libpq"]["tls_source"]["context"] == "SSL_CTX_new(SSLv23_method())"
    assert evidence["libpq"]["tls_source"]["handshake"] == "SSL_connect(conn->ssl)"
    assert evidence["openssl_method_alias"]["SSLv23_method"] == "TLS_method"
    recipe = json.loads((ROOT / "tools/source_recipes/psycopg-binary-3.3.4.json").read_text())
    for platform in recipe["platforms"].values():
        libpq = next(s for s in platform["custom_sources"] if s["name"] == "libpq")
        assert libpq["sha256"] == evidence["libpq"]["source_sha256"]
    for statement in native_statements():
        if statement["vulnerability"]["name"] in PROTOCOL_CASES:
            assert "Database TLS uses a separate copy of OpenSSL" in statement["impact_statement"]
            assert "RS256" in statement["impact_statement"]


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

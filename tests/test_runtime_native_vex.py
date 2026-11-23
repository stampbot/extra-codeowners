"""Native assessments must not become blanket OpenSSL or TLS exclusions."""

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def native_statements() -> list[dict[str, Any]]:
    document = json.loads((ROOT / "security/vex/runtime.openvex.json").read_text())
    return [
        s
        for s in document["statements"]
        if all(p["@id"].startswith("pkg:generic/openssl@") for p in s["products"])
    ]


def test_native_vex_marks_only_the_two_verified_fixes_on_each_current_copy() -> None:
    statements = native_statements()
    assert len(statements) == 4
    assert {(s["vulnerability"]["name"], s["products"][0]["@id"]) for s in statements} == {
        (cve, f"pkg:generic/openssl@{version}")
        for cve in ("CVE-2026-35189", "CVE-2026-75803")
        for version in ("3.5.9", "4.0.3")
    }
    for statement in statements:
        assert len(statement["products"]) == 1
        assert statement["status"] == "fixed"
        assert "impact_statement" not in statement and "justification" not in statement
        version = statement["products"][0]["@id"].split("@")[1]
        assert f"Confirmed fixed product version: {version}" in statement["status_notes"]
        assert "openssl-library.org/news/secadv/" in statement["status_notes"]


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

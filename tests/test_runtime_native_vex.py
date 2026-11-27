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
    statements = [item for item in native_statements() if item["status"] == "fixed"]
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


def test_november_native_exclusions_are_exactly_scoped() -> None:
    statements = [item for item in native_statements() if item["status"] != "fixed"]
    assert len(statements) == 25
    assert {(item["vulnerability"]["name"], item["products"][0]["@id"]) for item in statements} == {
        (f"CVE-2026-{cve}", f"pkg:generic/openssl@{version}")
        for cve in (
            "107493",
            "107494",
            "107496",
            "121482",
            "124709",
            "35190",
            "84786",
            "88822",
            "88823",
            "95690",
            "95691",
            "95692",
        )
        for version in ("3.5.9", "4.0.3")
    } | {("CVE-2026-121481", "pkg:generic/openssl@4.0.3")}
    for item in statements:
        assert len(item["products"]) == 1
        assert item["status"] == "not_affected"
        assert item["justification"] == "vulnerable_code_not_in_execute_path"
        assert "default Extra CODEOWNERS service" in item["impact_statement"]
        assert "present and unpatched" in item["impact_statement"]
        assert "native-november-callers.json" in item["status_notes"]


def test_november_caller_receipt_binds_both_wheels_and_the_retained_sources() -> None:
    source = ROOT / "security/vex/native-november-callers.json"
    evidence = json.loads(source.read_text(encoding="utf-8"))
    assert evidence["release"] == "v0.1.0-alpha.111"
    assert "without execution" in evidence["method"]
    assert "not standalone library behavior" in evidence["scope"]
    python_receipt = ROOT / "tools/release_crypto_static_evidence.json"
    crypto = json.loads(python_receipt.read_text(encoding="utf-8"))
    sources = evidence["sources"]
    assert sources["openssl-4.0.3.tar.gz"] == crypto["component"]["source_sha256"]
    assert {p["architecture"] for p in evidence["platforms"]} == {"amd64", "arm64"}
    assert len(evidence["platforms"]) == 2
    for platform in evidence["platforms"]:
        wheels = platform["wheels"]
        assert set(wheels) == {"psycopg_binary", "cryptography"}
        expected = crypto["platforms"][platform["architecture"]]
        assert wheels["cryptography"]["sha256"] == expected["wheel_sha256"]
        (extension,) = wheels["cryptography"]["native_files"]
        assert extension["sha256"] == expected["extension"]["sha256"]
        assert not extension["linked_openssl"]
        assert len(wheels["psycopg_binary"]["native_files"]) == 16
        files = [row for wheel in wheels.values() for row in wheel["native_files"]]
        assert len({row["path"] for row in files}) == 17
        assert sum(row["role"] == "embedded-openssl-provider" for row in files) == 2
        assert all(len(row["sha256"]) == 64 and not row["matched_imports"] for row in files)
        (libpq,) = [row for row in files if "/libpq-" in row["path"]]
        assert {"SSL_connect", "SSL_CTX_new"} <= set(libpq["stream_tls_apis"])
    certificate_lookup = evidence["source_checks"]["openssl"]["certificate_lookup"]
    assert certificate_lookup["existing_stack_argument"] == "NULL"
    assert set(certificate_lookup["versions"]) == {"3.5.9", "4.0.3"}


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

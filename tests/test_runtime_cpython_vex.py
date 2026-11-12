"""The interpreter assessment is version-bound and excludes custom FIPS setups."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cpython_assessment_is_limited_to_the_reviewed_non_fips_service() -> None:
    document = json.loads((ROOT / "security/vex/runtime.openvex.json").read_text())
    claims = [s for s in document["statements"] if s["vulnerability"]["name"] == "CVE-2026-119170"]
    assert len(claims) == 1
    claim = claims[0]
    assert claim["status"] == "not_affected"
    assert claim["products"] == [
        {"@id": "pkg:generic/python@3.14.10", "identifiers": {"purl": "pkg:generic/python@3.14.10"}}
    ]
    assert "unpatched" in claim["impact_statement"]
    assert "FIPS-enabled deployments" in claim["impact_statement"]
    assert "custom OpenSSL" in claim["impact_statement"]
    assert "not a FIPS compliance claim" in claim["impact_statement"]
    proof = json.loads((ROOT / "security/vex/cpython-fips-2026-119170.json").read_text())
    assert proof["source_version"] == "3.14.10"
    assert (
        proof["source_sha256"] == "de414a57119abef52784d8993e341d53aed635fc2b05c2607d9f98a2c5b72032"
    )
    assert {p["architecture"] for p in proof["platforms"]} == {"amd64", "arm64"}
    assert all(
        p["fips_mode"] == 0 and p["provider_modules"] == ["legacy.so"] for p in proof["platforms"]
    )

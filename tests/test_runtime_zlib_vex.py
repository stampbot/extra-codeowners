"""Keep gzip-writer assessments scoped to the reviewed Debian binaries."""

import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("vulnerability", ["CVE-2026-76844", "CVE-2026-85091"])
def test_zlib_exclusion_is_not_a_blanket_image_or_wheel_exemption(vulnerability: str) -> None:
    document = json.loads((ROOT / "security/vex/runtime.openvex.json").read_text())
    matches = [s for s in document["statements"] if s["vulnerability"]["name"] == vulnerability]
    assert len(matches) == 1
    statement = matches[0]
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert statement["timestamp"]
    assert statement["impact_statement"]
    products = statement["products"]
    assert len(products) == 2
    architectures = set()
    for product in products:
        purl = product["identifiers"]["purl"]
        assert product["@id"] == purl
        assert purl.startswith("pkg:deb/debian/zlib1g@")
        qualifiers = parse_qs(purl.partition("?")[2], strict_parsing=True)
        assert set(qualifiers) <= {"arch", "distro", "upstream"}
        assert len(qualifiers["arch"]) == 1
        assert len(qualifiers["distro"]) == 1
        architectures.add(qualifiers["arch"][0])
        assert qualifiers["distro"][0].startswith("debian-")
    assert architectures == {"amd64", "arm64"}

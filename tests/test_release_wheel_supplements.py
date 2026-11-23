"""Check wheel supplements against the lock and installed extensions."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from tools import release_python_sources as sources

DIGEST = "sha256:" + "f" * 64
WHEELS = [("cffi", "2.1.0"), ("protobuf", "7.35.1"), ("charset-normalizer", "3.4.9")]
MYPYC_VERSIONS = ["1.20.2", "2.0.0", "2.1.0"]
ARTIFACT_ROLES = {
    "cffi": {"source", "recipe"},
    "protobuf": {"notice"},
    "charset-normalizer": {"notice", *(f"source-{v}" for v in MYPYC_VERSIONS)},
}


def inputs(name: str, version: str, arch: str) -> tuple[dict[str, Any], str]:
    recipe = json.loads(
        (sources.RECIPE_DIRECTORY / f"wheel-supplement-{name}-{version}.json").read_bytes()
    )
    platform = recipe["platforms"][arch]
    inventory = {
        "schema_version": 2,
        "image": {"architecture": arch, "platform_digest": DIGEST},
        "python": {
            "source_recipe_schema": 7,
            "distributions": [{"normalized_name": name, "version": version}],
            "native_files": [
                {
                    **platform["native_file"],
                    "path": "opt/venv/lib/python3.14/site-packages/"
                    + platform["native_file"]["path"],
                    "kind": "regular",
                }
            ],
        },
    }
    blob_url = "https://files.pythonhosted.org/packages/ab/cd/" + "1" * 60
    lock = (
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        f'sdist = {{ url = "{blob_url}/{name}-{version}.tar.gz", '
        f'hash = "sha256:{recipe["sdist_sha256"]}", size = 123 }}\n'
        f'wheels = [{{ url = "{blob_url}/{platform["wheel_filename"]}", '
        f'hash = "sha256:{platform["wheel_sha256"]}" }}]\n'
    )
    return inventory, lock


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
@pytest.mark.parametrize(("name", "version"), WHEELS)
def test_plan_binds_each_wheel_and_retains_only_its_supplements(
    arch: str, name: str, version: str
) -> None:
    inventory, lock = inputs(name, version, arch)
    manifest = sources.plan(json.dumps(inventory).encode(), lock.encode(), arch, DIGEST)
    (item,) = manifest["wheel_supplements"]
    assert item["distribution"] == name
    assert item["distribution_version"] == version
    assert item["wheel_filename"].endswith(".whl")
    assert item["sdist"]["sha256"] == manifest["sources"][0]["sha256"]
    assert item["native_file"]["sha256"] == inventory["python"]["native_files"][0]["sha256"]
    assert all(
        record["path"].startswith(f"supplements/{name}/{arch}/") for record in item["artifacts"]
    )
    assert {record["role"] for record in item["artifacts"]} == ARTIFACT_ROLES[name]
    if name == "charset-normalizer":
        assert item["component"] == {"name": "mypyc-runtime", "source_candidates": MYPYC_VERSIONS}
        assert "version" not in item["component"]
    assert manifest["embedded_sources"] == []


@pytest.mark.parametrize(("name", "version"), WHEELS)
@pytest.mark.parametrize("changed", ["sdist", "wheel", "native", "symlink", "version"])
def test_changed_wheel_evidence_requires_review(name: str, version: str, changed: str) -> None:
    inventory, locked = inputs(name, version, "amd64")
    if changed == "sdist":
        locked = re.sub(r"sha256:[0-9a-f]{64}", "sha256:" + "0" * 64, locked, count=1)
    elif changed == "wheel":
        locked = locked.replace(".whl", "-other.whl")
    elif changed == "native":
        inventory["python"]["native_files"][0]["sha256"] = "0" * 64
    elif changed == "symlink":
        inventory["python"]["native_files"][0]["kind"] = "symlink"
    else:
        inventory["python"]["distributions"][0]["version"] = "99.1"
        locked = locked.replace(f'version = "{version}"', 'version = "99.1"')
    with pytest.raises(sources.PythonSourceError):
        sources.plan(json.dumps(inventory).encode(), locked.encode(), "amd64", DIGEST)


def test_schema_five_does_not_require_a_supplement() -> None:
    inventory, lock = inputs("cffi", "2.1.0", "amd64")
    inventory["python"]["source_recipe_schema"] = 5
    inventory["python"]["native_files"] = []
    historical = sources.plan(json.dumps(inventory).encode(), lock.encode(), "amd64", DIGEST)
    assert "wheel_supplements" not in historical


def test_schema_six_does_not_require_mypyc_evidence() -> None:
    inventory, lock = inputs("charset-normalizer", "3.4.9", "amd64")
    inventory["python"]["source_recipe_schema"] = 6
    inventory["python"]["native_files"] = []
    historical = sources.plan(json.dumps(inventory).encode(), lock.encode(), "amd64", DIGEST)
    assert historical["wheel_supplements"] == []


@pytest.mark.parametrize("case", ["duplicate-version", "wrong-url", "missing-source"])
def test_mypyc_recipe_requires_each_distinct_candidate(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name, version = "charset-normalizer", "3.4.9"
    inventory, lock = inputs(name, version, "amd64")
    receipt = f"wheel-supplement-{name}-{version}.json"
    recipe = json.loads((sources.RECIPE_DIRECTORY / receipt).read_bytes())
    if case == "duplicate-version":
        recipe["component"]["source_candidates"] = ["2.1.0", "2.1.0"]
    elif case == "wrong-url":
        recipe["artifacts"]["source-2.0.0"]["url"] = recipe["artifacts"]["source-2.1.0"]["url"]
    else:
        del recipe["artifacts"]["source-1.20.2"]
    (tmp_path / receipt).write_text(json.dumps(recipe), encoding="utf-8")
    monkeypatch.setattr(sources, "RECIPE_DIRECTORY", tmp_path)
    with pytest.raises(sources.PythonSourceError, match=r"mypyc|artifacts"):
        sources.plan(json.dumps(inventory).encode(), lock.encode(), "amd64", DIGEST)


def test_bundle_requires_every_supplement_and_verifies_its_bytes() -> None:
    payload = b"example upstream notice"
    path = "supplements/protobuf/arm64/utf8_range.LICENSE"
    record = {
        "role": "notice",
        "path": path,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    manifest = {"sources": [], "wheel_supplements": [{"artifacts": [record]}]}
    bundle = sources.build(manifest, {path: payload})
    assert sources.verify(manifest, bundle)[path] == payload
    with pytest.raises(sources.PythonSourceError, match="payload set"):
        sources.build(manifest, {})
    with pytest.raises(sources.PythonSourceError, match="locked size or SHA-256"):
        sources.build(manifest, {path: b"X" + payload[1:]})

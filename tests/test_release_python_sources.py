"""Locked source delivery must neither run upstream code nor guess identities."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import urllib.error
from pathlib import Path
from unittest.mock import Mock

import pytest

from tools import release_python_sources as sources

DIGEST = "sha256:" + "a" * 64
DATA = b"opaque source archive, deliberately not executable"
URL = "https://files.pythonhosted.org/packages/aa/bb/" + "c" * 60 + "/example-1.2.tar.gz"


def inventory() -> bytes:
    return json.dumps(
        {
            "schema_version": 2,
            "image": {"architecture": "amd64", "platform_digest": DIGEST},
            "python": {
                "distributions": [
                    {"normalized_name": "example", "version": "1.2"},
                    {"normalized_name": "binary-only", "version": "2.0"},
                    {"normalized_name": "extra-codeowners", "version": "0.1.0a45"},
                ]
            },
        }
    ).encode()


def lock() -> bytes:
    return f'''version = 1
[[package]]
name = "example"
version = "1.2"
source = {{registry = "https://pypi.org/simple"}}
sdist = {{url = "{URL}", hash = "sha256:{hashlib.sha256(DATA).hexdigest()}", size = {len(DATA)}}}
[[package]]
name = "binary-only"
version = "2.0"
source = {{registry = "https://pypi.org/simple"}}
[[package]]
name = "extra-codeowners"
source = {{editable = "."}}
'''.encode()


def plan() -> dict:
    return sources.plan(inventory(), lock(), "amd64", DIGEST)


def bundle() -> bytes:
    manifest = plan()
    return sources.build(manifest, {manifest["sources"][0]["path"]: DATA})


def repack(contents: bytes, name: str, data: bytes, kind: bytes = tarfile.REGTYPE) -> bytes:
    output = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as old,
        tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as new,
    ):
        for member in old:
            reader = old.extractfile(member)
            assert reader is not None
            new.addfile(member, io.BytesIO(reader.read()))
        member = tarfile.TarInfo(name)
        member.type = kind
        member.size = len(data)
        member.linkname = "../../outside"
        new.addfile(member, io.BytesIO(data))
    return output.getvalue()


def test_exact_identity_determinism_and_explicit_gaps() -> None:
    manifest = plan()
    assert manifest["inventory_sha256"] == hashlib.sha256(inventory()).hexdigest()
    assert manifest["uv_lock_sha256"] == hashlib.sha256(lock()).hexdigest()
    assert manifest["sources"][0]["sha256"] == hashlib.sha256(DATA).hexdigest()
    assert manifest["unresolved_sources"] == [
        {"name": "binary-only", "version": "2.0", "reason": "lock contains no source archive"}
    ]
    assert manifest["separately_delivered"][0]["name"] == "extra-codeowners"
    assert bundle() == bundle()
    sources.verify(manifest, bundle())
    sources.verify(manifest, gzip.compress(gzip.decompress(bundle()), compresslevel=1))


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/source.tar.gz",
        "https://files.pythonhosted.org.evil/source.tar.gz",
        URL + "?secret=1",
        URL + "#fragment",
        URL.replace("https://", "https://user:pass@"),
        URL.replace("/example-", "/../example-"),
        URL.replace(".tar.gz", ".whl"),
    ],
)
def test_rejects_untrusted_urls(url: str) -> None:
    with pytest.raises(sources.PythonSourceError):
        sources.plan(inventory(), lock().replace(URL.encode(), url.encode()), "amd64", DIGEST)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b'version = "1.2"', b'version = "1.3"'),
        (b"https://pypi.org/simple", b"https://example.com/simple"),
        (b"sha256:", b"sha512:"),
        (f"size = {len(DATA)}".encode(), b"size = true"),
        (f"size = {len(DATA)}".encode(), b"size = 0"),
        (f"size = {len(DATA)}".encode(), b"size = 999999999"),
        (b'name = "example"', b'name = "../example"'),
    ],
)
def test_rejects_bad_lock(old: bytes, new: bytes) -> None:
    with pytest.raises(sources.PythonSourceError):
        sources.plan(inventory(), lock().replace(old, new), "amd64", DIGEST)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(schema_version=True),
        lambda d: d.update(python=[]),
        lambda d: d["image"].update(architecture="arm64"),
        lambda d: d["python"].update(distributions=[]),
        lambda d: d["python"]["distributions"].append(d["python"]["distributions"][0]),
        lambda d: d["python"]["distributions"].append([]),
        lambda d: d["python"]["distributions"][0].update(version="../escape"),
    ],
)
def test_rejects_bad_inventory(mutation) -> None:
    raw = json.loads(inventory())
    mutation(raw)
    with pytest.raises(sources.PythonSourceError):
        sources.plan(json.dumps(raw).encode(), lock(), "amd64", DIGEST)


@pytest.mark.parametrize("raw", [b"[]", b'{"schema_version":2,"schema_version":2}', b"{", b"\xff"])
def test_rejects_bad_json(raw: bytes) -> None:
    with pytest.raises(sources.PythonSourceError):
        sources.plan(raw, lock(), "amd64", DIGEST)


@pytest.mark.parametrize(
    "name", ["manifest.json", "../outside", "extra", "sources/example/example-1.2.tar.gz"]
)
@pytest.mark.parametrize("kind", [tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_rejects_added_duplicate_and_link_members(name: str, kind: bytes) -> None:
    with pytest.raises(sources.PythonSourceError):
        sources.verify(plan(), repack(bundle(), name, b"extra", kind))


def test_rejects_tampering_missing_payloads_and_trailing_data() -> None:
    manifest = plan()
    path = manifest["sources"][0]["path"]
    for payloads in ({}, {path: b"tampered"}, {path: DATA, "extra": b"x"}):
        with pytest.raises(sources.PythonSourceError):
            sources.build(manifest, payloads)
    for data in (b"not gzip", bundle()[:20], gzip.compress(gzip.decompress(bundle()) + b"extra")):
        with pytest.raises(sources.PythonSourceError):
            sources.verify(manifest, data)
    manifest["uv_lock_sha256"] = "b" * 64
    with pytest.raises(sources.PythonSourceError):
        sources.verify(manifest, bundle())


def test_fetch_retries_network_errors_but_never_redirects(monkeypatch) -> None:
    response = Mock(status=200)
    response.read.return_value = DATA
    context = Mock()
    context.__enter__ = Mock(return_value=response)
    context.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.side_effect = [urllib.error.URLError("offline"), context]
    monkeypatch.setattr(sources.urllib.request, "build_opener", lambda *_: opener)
    monkeypatch.setattr(sources.time, "sleep", lambda _: None)
    assert sources.fetch(plan()["sources"][0]) == DATA
    response.read.assert_called_once_with(len(DATA) + 1)
    assert opener.open.call_count == 2
    opener.open.side_effect = urllib.error.URLError("offline")
    with pytest.raises(sources.PythonSourceError, match="three attempts"):
        sources.fetch(plan()["sources"][0])
    with pytest.raises(sources.PythonSourceError, match="redirected"):
        sources._NoRedirect().redirect_request(Mock(), Mock(), 302, "Found", {}, URL)


def test_cli_roundtrip_and_exclusive_output(tmp_path: Path, monkeypatch) -> None:
    inv = tmp_path / "inventory.json"
    locked = tmp_path / "uv.lock"
    output = tmp_path / "sources.tar.gz"
    inv.write_bytes(inventory())
    locked.write_bytes(lock())
    monkeypatch.setattr(sources, "fetch", lambda _: DATA)
    args = [
        "--inventory",
        str(inv),
        "--lock",
        str(locked),
        "--architecture",
        "amd64",
        "--platform-digest",
        DIGEST,
        "--bundle",
        str(output),
    ]
    assert sources.main(["fetch", *args]) == 0
    assert sources.main(["verify", *args]) == 0
    assert sources.main(["fetch", *args]) == 1
    output.write_bytes(b"tampered")
    assert sources.main(["verify", *args]) == 1

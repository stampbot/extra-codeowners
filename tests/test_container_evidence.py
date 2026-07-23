from __future__ import annotations

import base64
import copy
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
import zlib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evidence = load_script("container_evidence")
readiness = load_script("release_readiness")
DEMO_METADATA_PATH = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
PYVENV_CONFIG = (
    b"home = /usr/local/bin\n"
    b"implementation = CPython\n"
    b"uv = 0.11.28\n"
    b"version_info = 3.14.6\n"
    b"include-system-site-packages = false\n"
    b"prompt = extra-codeowners\n"
)
CPYTHON_PATCHLEVEL_SHA256 = "1c61b149e1ce72a7f6328c58057970d37fcafb02bec805be071dc0ed4cf39a95"
VENV_LINKS = {
    "opt/venv/bin/python": "/usr/local/bin/python3",
    "opt/venv/bin/python3": "python",
    "opt/venv/bin/python3.14": "python",
}
MARKUPSAFE_LICENSE_TEXT = b"""Copyright 2010 Pallets

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1.  Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
MARKUPSAFE_DOCS_LICENSE = b"""BSD-3-Clause License
====================

.. literalinclude:::: ../LICENSE.txt
    :language: text
"""
SQLALCHEMY_LICENSE_TEXT = (
    b"Copyright 2005-2026 SQLAlchemy authors and contributors "
    b"<see AUTHORS file>.\n\n"
    b"""Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
)
SQLALCHEMY_AUTHORS_TEXT = b"""SQLAlchemy was created by Michael Bayer.

Major contributing authors include:

- Mike Bayer
- Jason Kirtland
- Michael Trier
- Diana Clarke
- Gaetan de Menten
- Lele Gaifax
- Jonathan Ellis
- Gord Thompson
- Federico Caselli
- Philip Jenvey
- Rick Morrison
- Chris Withers
- Ants Aasma
- Sheila Allen
- Paul Johnston
- Tony Locke
- Hajime Nakagami
- Vraj Mohan
- Robert Leftwich
- Taavi Burns
- Jonathan Vanasco
- Jeff Widman
- Scott Dugas
- Dobes Vandermeer
- Ville Skytta
- Rodrigo Menezes
"""
MARKUPSAFE_SOURCE: dict[str, Any] = {
    "url": (
        "https://files.pythonhosted.org/packages/7e/99/"
        "7690b6d4034fffd95959cbe0c02de8deb3098cc577c67bb6a24fe5d7caa7/"
        "markupsafe-3.0.3.tar.gz"
    ),
    "sha256": "722695808f4b6457b320fdc131280796bdceb04ab50fe1795cd540799ebe1698",
    "size": 80313,
}
MARKUPSAFE_WHEELS: dict[str, dict[str, Any]] = {
    "linux/amd64": {
        "url": (
            "https://files.pythonhosted.org/packages/ff/0e/"
            "53dfaca23a69fbfbbf17a4b64072090e70717344c52eaaaa9c5ddff1e5f0/"
            "markupsafe-3.0.3-cp314-cp314-musllinux_1_2_x86_64.whl"
        ),
        "sha256": "2713baf880df847f2bece4230d4d094280f4e67b1e813eec43b4c0e144a34ffe",
        "size": 23043,
        "filename": "markupsafe-3.0.3-cp314-cp314-musllinux_1_2_x86_64.whl",
        "tag": "cp314-cp314-musllinux_1_2_x86_64",
    },
    "linux/arm64": {
        "url": (
            "https://files.pythonhosted.org/packages/9a/a7/"
            "591f592afdc734f47db08a75793a55d7fbcc6902a723ae4cfbab61010cc5/"
            "markupsafe-3.0.3-cp314-cp314-musllinux_1_2_aarch64.whl"
        ),
        "sha256": "ec15a59cf5af7be74194f7ab02d0f59a62bdcf1a537677ce67a2537c9b87fcda",
        "size": 23821,
        "filename": "markupsafe-3.0.3-cp314-cp314-musllinux_1_2_aarch64.whl",
        "tag": "cp314-cp314-musllinux_1_2_aarch64",
    },
}


def tar_bytes(
    files: dict[str, bytes],
    *,
    links: dict[str, str] | None = None,
    hardlinks: dict[str, str] | None = None,
    directories: list[str] | None = None,
    headers: dict[str, dict[str, Any]] | None = None,
) -> bytes:
    def apply_header(member: tarfile.TarInfo) -> None:
        for field, value in (headers or {}).get(member.name, {}).items():
            setattr(member, field, value)

    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name in directories or []:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            apply_header(member)
            archive.addfile(member)
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            apply_header(member)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            member.mode = 0o777
            apply_header(member)
            archive.addfile(member)
        for name, target in (hardlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.LNKTYPE
            member.linkname = target
            member.mode = 0o777
            apply_header(member)
            archive.addfile(member)
    return result.getvalue()


def tar_sequence(files: list[tuple[str, bytes]]) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, content in files:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return result.getvalue()


def explicit_parent_directories(paths: Iterable[str]) -> list[str]:
    """Return portable parent headers for synthetic post-base layer fixtures."""

    parents = {
        str(parent)
        for path in paths
        for parent in PurePosixPath(path).parents
        if str(parent) != "."
    }
    return sorted(parents, key=lambda path: (len(PurePosixPath(path).parts), path))


def apk_database(
    architecture: str = "x86_64",
    version: str = "1.37.0-r1",
    *,
    name: str = "busybox",
    origin: str | None = None,
) -> bytes:
    selected_origin = name if origin is None else origin
    return (
        f"P:{name}\n"
        f"V:{version}\n"
        f"A:{architecture}\n"
        "L:GPL-2.0-only\n"
        f"o:{selected_origin}\n"
        "c:1111111111111111111111111111111111111111\n\n"
    ).encode()


def metadata(name: str, version: str, license_value: str = "MIT") -> bytes:
    return (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        f"License-Expression: {license_value}\n\n"
    ).encode()


def wheel_record(files: dict[str, bytes], record_path: str) -> bytes:
    rows = []
    for path, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(evidence.hashlib.sha256(content).digest()).rstrip(b"=")
        rows.append(f"{path},sha256={digest.decode()},{len(content)}\n")
    rows.append(f"{record_path},,\n")
    return "".join(rows).encode()


def cyclonedx_sbom(
    *,
    components: list[dict[str, Any]] | None = None,
    metadata_component: dict[str, Any] | None = None,
) -> bytes:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:12345678-1234-4234-9234-123456789abc",
        "version": 1,
        "components": components
        if components is not None
        else [
            {
                "type": "library",
                "name": "libdemo",
                "version": "1.2.3",
                "purl": "pkg:generic/libdemo@1.2.3",
                "bom-ref": "pkg:generic/libdemo@1.2.3",
            }
        ],
    }
    if metadata_component is not None:
        document["metadata"] = {"component": metadata_component}
    return json.dumps(document, sort_keys=True).encode()


def identified_cyclonedx_component(identity: str) -> dict[str, Any]:
    return {
        "type": "library",
        "name": identity,
        "version": "1.0",
        "purl": f"pkg:generic/{identity}@1.0",
        "bom-ref": identity,
    }


def elf64_payload(architecture: str = "amd64") -> bytes:
    machine = {"amd64": 62, "arm64": 183}[architecture]
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\0" * 7
    return cast(
        bytes,
        evidence.ELF64_HEADER.pack(
            ident,
            3,
            machine,
            1,
            0,
            0,
            0,
            0,
            evidence.ELF64_HEADER.size,
            0,
            0,
            0,
            0,
            0,
        )
        + b"native payload",
    )


def cpython_patchlevel_header(version: str = "3.14.6") -> bytes:
    major, minor, micro = version.split(".")
    return (
        "#define PY_RELEASE_LEVEL_ALPHA  0xA\n"
        "#define PY_RELEASE_LEVEL_BETA   0xB\n"
        "#define PY_RELEASE_LEVEL_GAMMA  0xC\n"
        "#define PY_RELEASE_LEVEL_FINAL  0xF\n"
        "/*--start constants--*/\n"
        f"#define PY_MAJOR_VERSION        {major}\n"
        f"#define PY_MINOR_VERSION        {minor}\n"
        f"#define PY_MICRO_VERSION        {micro}\n"
        "#define PY_RELEASE_LEVEL        PY_RELEASE_LEVEL_FINAL\n"
        "#define PY_RELEASE_SERIAL       0\n"
        f'#define PY_VERSION              "{version}"\n'
        "/*--end constants--*/\n"
    ).encode()


def with_cpython_runtime(layer: bytes, architecture: str) -> bytes:
    """Append the minimal immutable runtime footprint to a synthetic base layer."""

    source = io.BytesIO(layer)
    try:
        with tarfile.open(fileobj=source, mode="r:") as archive:
            existing = {member.name.removeprefix("./") for member in archive}
    except tarfile.TarError:
        return layer
    output = io.BytesIO(layer)
    additions = {
        evidence.CPYTHON_VERSION_HEADER: (cpython_patchlevel_header(), 0o644),
        evidence.CPYTHON_INTERPRETER: (elf64_payload(architecture), 0o755),
        evidence.CPYTHON_SHARED_LIBRARY: (elf64_payload(architecture), 0o755),
    }
    with tarfile.open(fileobj=output, mode="a") as archive:
        for path, (content, mode) in additions.items():
            if path in existing:
                continue
            member = tarfile.TarInfo(path)
            member.size = len(content)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            archive.addfile(member, io.BytesIO(content))
        if evidence.CPYTHON_INTERPRETER_LINK not in existing:
            link = tarfile.TarInfo(evidence.CPYTHON_INTERPRETER_LINK)
            link.type = tarfile.SYMTYPE
            link.linkname = evidence.CPYTHON_INTERPRETER_LINK_TARGET
            link.mode = 0o777
            link.uid = 0
            link.gid = 0
            archive.addfile(link)
    return output.getvalue()


def empty_unexpanded_payload_policy() -> dict[str, dict[str, list[dict[str, Any]]]]:
    return {
        platform: {
            "embedded_sboms": [],
            "native_payloads": [],
            "wheel_identity_files": [],
        }
        for platform in ("linux/amd64", "linux/arm64")
    }


def empty_filesystem_baselines() -> dict[str, dict[str, list[dict[str, Any]]]]:
    return {
        platform: {
            "apk_database_occurrences": [],
            "post_base_directory_effects": [],
            "post_base_removals": [],
        }
        for platform in ("linux/amd64", "linux/arm64")
    }


def synthetic_runtime_component(platform: str = "linux/amd64") -> dict[str, Any]:
    machine_id, machine = evidence.ELF_MACHINES[platform]

    def occurrence(path: str, digest: str, size: int, mode: int) -> dict[str, Any]:
        return {
            "effective": True,
            "layer": 0,
            "path": path,
            "sha256": digest * 64,
            "size": size,
            "mode": mode,
            "uid": 0,
            "gid": 0,
        }

    elf = {
        "bits": 64,
        "endianness": "little",
        "machine": machine,
        "machine_id": machine_id,
    }
    return {
        "ecosystem": "runtime",
        "name": "cpython",
        "version": "3.14.6",
        "purl": "pkg:generic/python@3.14.6",
        "observed_license": "",
        "effective": True,
        "identity_files": {
            "version_header": {
                **occurrence(evidence.CPYTHON_VERSION_HEADER, "1", 512, 0o644),
                "sha256": CPYTHON_PATCHLEVEL_SHA256,
            },
            "interpreter": {
                **occurrence(evidence.CPYTHON_INTERPRETER, "2", 64, 0o755),
                "elf": copy.deepcopy(elf),
            },
            "interpreter_link": {
                "effective": True,
                "kind": "symlink",
                "layer": 0,
                "path": evidence.CPYTHON_INTERPRETER_LINK,
                "target": evidence.CPYTHON_INTERPRETER_LINK_TARGET,
                "mode": 0o777,
                "uid": 0,
                "gid": 0,
            },
            "shared_library": {
                **occurrence(evidence.CPYTHON_SHARED_LIBRARY, "3", 64, 0o755),
                "elf": copy.deepcopy(elf),
            },
        },
    }


def standalone_inventory(component: dict[str, Any]) -> dict[str, Any]:
    apk_record = {
        "effective": True,
        "layer": 0,
        "path": "lib/apk/db/installed",
        "sha256": "d" * 64,
        "size": 0,
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
    }
    return {
        "schema_version": evidence.SCHEMA_VERSION,
        "platform": "linux/amd64",
        "subject_digest": "sha256:" + "a" * 64,
        "image_config_digest": "sha256:" + "b" * 64,
        "image_revision": "c" * 40,
        "image_version": "1.0",
        "application_wheel_sha256": "e" * 64,
        "application_selection_record_sha256": "f" * 64,
        "apk_database_sha256": "d" * 64,
        "components": [component, synthetic_runtime_component()],
        "embedded_sboms": [],
        "native_payloads": [],
        "wheel_identity_files": [],
        "apk_database_occurrences": [apk_record],
        "wheel_installations": [],
        "python_record_ownership": [],
    }


def standalone_policy(
    component: dict[str, Any], expression: str, *, license_texts: list[dict[str, Any]]
) -> dict[str, Any]:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    policy["platforms"] = {
        "linux/amd64": [copy.deepcopy(component), synthetic_runtime_component()],
        "linux/arm64": [copy.deepcopy(component), synthetic_runtime_component("linux/arm64")],
    }
    policy["distribution_approval"] = {
        "approved": False,
        "approved_by": "",
        "approved_on": "",
        "rationale": "Distribution remains denied for this test fixture.",
    }
    policy["license_resolutions"] = {
        "python:demo@1": {
            "expression": expression,
            "rationale": "Reviewed test fixture.",
        },
        "runtime:cpython@3.14.6": {
            "expression": "Python-2.0.1",
            "rationale": "Reviewed synthetic CPython fixture.",
        },
    }
    policy["license_texts"] = [
        *license_texts,
        {
            "id": "Python-2.0.1",
            "sha256": "9" * 64,
            "url": "https://example.com/Python-2.0.1.txt",
        },
    ]
    policy["custom_license_evidence"] = {}
    policy["native_component_sources"] = {}
    policy["native_component_coverage"] = {
        "linux/amd64": [],
        "linux/arm64": [],
    }
    policy["unexpanded_python_payloads"] = empty_unexpanded_payload_policy()
    policy["filesystem_baselines"] = empty_filesystem_baselines()
    policy["filesystem_baselines"]["linux/amd64"]["apk_database_occurrences"] = [
        copy.deepcopy(standalone_inventory(component)["apk_database_occurrences"][0])
    ]
    return policy


def saved_image_layers(path: Path, layers: list[bytes], *, architecture: str = "amd64") -> None:
    layers = [with_cpython_runtime(layers[0], architecture), *layers[1:]]
    layer_names = [f"blobs/sha256/{evidence.hashlib.sha256(layer).hexdigest()}" for layer in layers]
    config_content = json.dumps(
        {
            "architecture": architecture,
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": "a" * 40,
                    "org.opencontainers.image.version": "1.0",
                    evidence.APPLICATION_WHEEL_LABEL: "e" * 64,
                    evidence.APPLICATION_SELECTION_LABEL: "f" * 64,
                }
            },
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": [f"sha256:{name.rsplit('/', 1)[-1]}" for name in layer_names],
            },
        }
    ).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config_content).hexdigest()}"
    contents = {
        "manifest.json": json.dumps([{"Config": config_name, "Layers": layer_names}]).encode(),
        config_name: config_content,
    }
    contents.update(zip(layer_names, layers, strict=True))
    path.write_bytes(tar_bytes(contents))


def saved_image(path: Path, *, architecture: str = "amd64") -> None:
    apk_architecture = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(apk_architecture),
            "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA": metadata(
                "demo", "1.0"
            ),
            "usr/local/lib/python3.14/site-packages/pip-26.1.dist-info/METADATA": metadata(
                "pip", "26.1"
            ),
        }
    )
    second = tar_bytes(
        {
            "usr/local/lib/python3.14/site-packages/.wh.pip-26.1.dist-info": b"",
            "empty": b"",
        }
    )
    saved_image_layers(path, [first, second], architecture=architecture)


def ci_artifact_files(tmp_path: Path, architecture: str = "amd64") -> dict[str, bytes]:
    image = tmp_path / "ci-image.tar"
    saved_image(image, architecture=architecture)
    inventory, files = evidence._inventory_saved_image(
        image,
        f"linux/{architecture}",
        "sha256:" + "a" * 64,
    )
    inventory["subject_digest"] = inventory["image_config_digest"]
    files["subject_digest"] = inventory["subject_digest"]
    bundle_name = f"extra-codeowners-ci-linux-{architecture}-evidence.tar.gz"
    bundle = b"bounded evidence bundle"
    bundle_hash = evidence.sha256_bytes(bundle)
    metadata_record = {
        "schema_version": evidence.SCHEMA_VERSION,
        "run_id": "1234",
        "run_attempt": 2,
        "event_name": "pull_request",
        "repository_id": "5678",
        "pr_number": "27",
        "pr_head_sha": "b" * 40,
        "pr_base_sha": "c" * 40,
        "pr_head_repository_id": "5678",
        "github_sha": "a" * 40,
        "checkout_sha": "a" * 40,
        "workflow_ref": "stampbot/extra-codeowners/.github/workflows/ci.yml@refs/pull/27/merge",
        "workflow_sha": "a" * 40,
        "platform": f"linux/{architecture}",
        "architecture": architecture,
        "inventory_subject_digest": inventory["subject_digest"],
        "inventory_image_config_digest": inventory["image_config_digest"],
        "python_distribution_artifact_id": "9012",
        "python_distribution_artifact_digest": "d" * 64,
        "application_source_revision": "a" * 40,
        "application_wheel_sha256": "e" * 64,
        "application_selection_record_sha256": "f" * 64,
    }
    predicate = {
        "schema_version": evidence.SCHEMA_VERSION,
        "media_type": evidence.EVIDENCE_MEDIA_TYPE,
        "platform": f"linux/{architecture}",
        "subject_digest": inventory["subject_digest"],
        "artifact": {"filename": bundle_name, "sha256": bundle_hash},
        "release_url": "https://github.com/stampbot/extra-codeowners/releases/tag/v0.0.0-ci",
    }
    return {
        f"all-layer-files-{architecture}.json": evidence.canonical_json(files),
        f"components-{architecture}.json": evidence.canonical_json(inventory),
        f"evidence-predicate-{architecture}.json": evidence.canonical_json(predicate),
        f"run-metadata-{architecture}.json": evidence.canonical_json(metadata_record),
        bundle_name: bundle,
        f"{bundle_name}.sha256": f"{bundle_hash}  {bundle_name}\n".encode(),
    }


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *_args: Any, **_kwargs: Any) -> int:
        raise OSError("fixture is intentionally non-seekable")


def ci_artifact_zip_bytes(
    entries: list[tuple[str, bytes]],
    *,
    modifier: Any | None = None,
    archive_comment: bytes = b"",
) -> bytes:
    output = NonSeekableBytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.create_version = 45
            info.extract_version = 20
            info.external_attr = evidence.CI_ARTIFACT_EXTERNAL_ATTR
            info.compress_type = zipfile.ZIP_DEFLATED
            if modifier is not None:
                modifier(name, info)
            archive.writestr(info, content)
        archive.comment = archive_comment
    return output.getvalue()


def write_ci_artifact_zip(path: Path, files: dict[str, bytes]) -> None:
    path.write_bytes(ci_artifact_zip_bytes(list(files.items())))


def zip_record_offsets(content: bytes | bytearray, name: str) -> tuple[int, int]:
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        local_offset = archive.getinfo(name).header_offset
    eocd_offset = content.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    central_offset = evidence.ZIP_EOCD.unpack_from(content, eocd_offset)[-2]
    position = central_offset
    while position < eocd_offset:
        assert content[position : position + 4] == b"PK\x01\x02"
        name_size = int.from_bytes(content[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(content[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(content[position + 32 : position + 34], "little")
        entry_name = bytes(content[position + 46 : position + 46 + name_size]).decode("ascii")
        if entry_name == name:
            return local_offset, position
        position += 46 + name_size + extra_size + comment_size
    raise AssertionError(f"missing central record for {name}")


def source_zip_bytes(
    entries: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    extra: bytes = b"",
    entry_comment: bytes = b"",
    archive_comment: bytes = b"",
) -> bytes:
    """Build the narrow Unix source-ZIP dialect accepted by the collector."""

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        archive.comment = archive_comment
        for name, content in entries:
            directory = name.endswith("/")
            method = zipfile.ZIP_STORED if directory else compression
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.create_version = 20
            member.extract_version = 10 if method == zipfile.ZIP_STORED else 20
            member.external_attr = (
                ((stat.S_IFDIR | 0o755) << 16 | 0x10) if directory else (stat.S_IFREG | 0o644) << 16
            )
            member.compress_type = method
            member.extra = extra
            member.comment = entry_comment
            archive.writestr(member, content)
    return output.getvalue()


def native_wheel_case(
    *,
    component_name: str = "demo",
    version: str = "1.0",
    platform: str = "linux/amd64",
    tag: str | None = None,
    build: str = "",
    include_header_relocation: bool = False,
    include_console_script: bool = False,
    entry_points: bytes | None = None,
    native_archive_path: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Build one exact native-wheel/archive/installed-RECORD test contract."""

    architecture = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[platform]
    selected_tag = tag or f"cp314-cp314-musllinux_1_2_{architecture}"
    normalized_name = component_name.replace("-", "_")
    normalized_version = version.replace("-", "_")
    distribution = f"{normalized_name}-{normalized_version}"
    dist_info = f"{distribution}.dist-info"
    site_root = PurePosixPath("opt/venv/lib/python3.14/site-packages")
    metadata_path = f"{dist_info}/METADATA"
    wheel_path = f"{dist_info}/WHEEL"
    record_path = f"{dist_info}/RECORD"
    sbom_path = f"{dist_info}/sboms/auditwheel.cdx.json"
    native_path = native_archive_path or f"{normalized_name}/native.so"
    wheel_metadata = (
        "Wheel-Version: 1.0\n"
        "Root-Is-Purelib: false\n"
        f"{'Build: ' + build + chr(10) if build else ''}"
        f"Tag: {selected_tag}\n"
    ).encode()
    archive_files = {
        metadata_path: metadata(component_name, version),
        wheel_path: wheel_metadata,
        sbom_path: cyclonedx_sbom(),
        native_path: elf64_payload("amd64" if platform == "linux/amd64" else "arm64"),
    }
    if include_header_relocation:
        archive_files[f"{distribution}.data/headers/greenlet.h"] = b"header\n"
    entry_points_path = f"{dist_info}/entry_points.txt"
    if include_console_script and entry_points is not None:
        raise AssertionError("native-wheel fixture received two entry-point sources")
    if include_console_script:
        entry_points = b"[console_scripts]\ncffi-gen-src = demo.module:main\n"
    if entry_points is not None:
        archive_files[entry_points_path] = entry_points
    archive_files[record_path] = wheel_record(archive_files, record_path)
    wheel_content = source_zip_bytes(list(archive_files.items()))

    data_directory = f"{distribution}.data"
    installed_files: dict[str, bytes] = {}
    archive_to_installed: dict[str, str] = {}
    for archive_path, payload in archive_files.items():
        installed_path = evidence.wheel_member_install_path(
            archive_path,
            site_root,
            data_directory=data_directory,
            component_name=component_name,
        )
        archive_to_installed[archive_path] = installed_path
        installed_files[installed_path] = payload
    generated: dict[str, bytes] = {}
    for generated_path, script in evidence.console_script_installations(
        archive_files, entry_points_path
    ).items():
        generated[generated_path] = evidence.expected_native_launcher(
            script["module"], script["callable"], interpreter_name="python"
        )
    installed_files.update(generated)

    def occurrence(path: str, payload: bytes) -> dict[str, Any]:
        return {
            "effective": True,
            "layer": 1,
            "path": path,
            "sha256": evidence.sha256_bytes(payload),
            "size": len(payload),
            "mode": 0o755 if path.startswith("opt/venv/bin/") else 0o644,
            "uid": 0,
            "gid": 0,
        }

    installed_record_content = (
        b"installer-generated RECORD\n"
        if entry_points is not None or include_header_relocation
        else archive_files[record_path]
    )
    installed_files[archive_to_installed[record_path]] = installed_record_content
    entries: list[dict[str, Any]] = []
    for path, payload in sorted(installed_files.items()):
        is_record = path == archive_to_installed[record_path]
        entries.append(
            {
                "path": path,
                "recorded_sha256": None if is_record else evidence.sha256_bytes(payload),
                "recorded_size": None if is_record else len(payload),
                "occurrence": occurrence(path, payload),
            }
        )
    by_path = {entry["path"]: entry["occurrence"] for entry in entries}
    owner = f"python:{component_name}@{version}"
    installed_sbom_path = archive_to_installed[sbom_path]
    installed_native_path = archive_to_installed[native_path]
    installation = {
        "owner": owner,
        "metadata": by_path[archive_to_installed[metadata_path]],
        "wheel": by_path[archive_to_installed[wheel_path]],
        "record": by_path[archive_to_installed[record_path]],
        "root_is_purelib": False,
        "build": build,
        "tags": [selected_tag],
        "entries": entries,
    }
    inventory = {
        "platform": platform,
        "components": [
            {
                "ecosystem": "python",
                "name": component_name,
                "version": version,
            }
        ],
        "wheel_installations": [installation],
        "embedded_sboms": [
            {
                **by_path[installed_sbom_path],
                "owner": owner,
                "cyclonedx": {},
            }
        ],
        "native_payloads": [
            {
                **by_path[installed_native_path],
                "owner": owner,
                "elf": {},
            }
        ],
    }
    build_segment = f"-{build}" if build else ""
    filename = f"{distribution}{build_segment}-{selected_tag}.whl"
    locked = {
        "owner": owner,
        "platform": platform,
        "url": f"https://files.pythonhosted.org/packages/aa/{filename}",
        "sha256": evidence.sha256_bytes(wheel_content),
        "size": len(wheel_content),
        "filename": filename,
        "build": build,
        "tags": [selected_tag],
    }
    return inventory, locked, wheel_content


def _native_component_fixture_inputs() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, Any],
    dict[tuple[str, str], dict[str, Any]],
]:
    """Build a two-platform closed-world owner/component/source policy fixture."""

    inventories: dict[str, dict[str, Any]] = {}
    locked_wheels: dict[str, dict[str, Any]] = {}
    coverage: dict[str, list[dict[str, Any]]] = {}
    owner_source = {
        "url": "https://files.pythonhosted.org/packages/aa/demo-1.0.tar.gz",
        "sha256": "1" * 64,
        "size": 123,
    }
    nested_component = {
        "type": "library",
        "name": "libdemo",
        "version": "1.2.3-r0",
        "purl": "pkg:apk/alpine/libdemo@1.2.3-r0",
    }
    for platform in ("linux/amd64", "linux/arm64"):
        inventory, locked, _content = native_wheel_case(platform=platform)
        owner_payload = inventory["native_payloads"][0]
        nested_payload = {
            **copy.deepcopy(owner_payload),
            "path": (
                "opt/venv/lib/python3.14/site-packages/demo.libs/"
                f"libdemo-{'abcdef12' if platform == 'linux/amd64' else '1234abcd'}.so.1"
            ),
            "sha256": "2" * 64 if platform == "linux/amd64" else "3" * 64,
        }
        inventory["native_payloads"].append(nested_payload)
        inventory["embedded_sboms"][0]["cyclonedx"] = {
            "metadata_component": None,
            "components": [copy.deepcopy(nested_component)],
        }
        reviewed_component = {
            **copy.deepcopy(nested_component),
            "source": "alpine:demo-native@1.2.3-r0",
            "reviewed_license": "MIT",
        }
        inventories[platform] = inventory
        locked_wheels[platform] = locked
        coverage[platform] = [
            {
                "owner": "python:demo@1.0",
                "wheel": {field: locked[field] for field in ("url", "sha256", "size")},
                "owner_source": copy.deepcopy(owner_source),
                "components": [copy.deepcopy(reviewed_component)],
                "native_payloads": sorted(
                    [
                        {
                            "role": "demo/native.so",
                            **{field: owner_payload[field] for field in ("path", "sha256")},
                        },
                        {
                            "role": "demo.libs/libdemo.so.1",
                            **{field: nested_payload[field] for field in ("path", "sha256")},
                        },
                    ],
                    key=lambda record: record["role"],
                ),
                "sboms": [
                    {
                        "path": inventory["embedded_sboms"][0]["path"],
                        "sha256": inventory["embedded_sboms"][0]["sha256"],
                        "components": [copy.deepcopy(reviewed_component)],
                    }
                ],
            }
        ]
    source = {
        "kind": "alpine-aports",
        "origin": "demo-native",
        "version": "1.2.3-r0",
        "aports_commit": "4" * 40,
        "distfiles_release": "v3.22",
        "recipe": {
            "url": (
                "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
                f"{'4' * 40}/aports-{'4' * 40}.tar.gz?path=main/demo-native"
            ),
            "sha256": "5" * 64,
            "size": 456,
        },
        "distfiles": [
            {
                "filename": "demo-native-1.2.3.tar.xz",
                "url": (
                    "https://distfiles.alpinelinux.org/distfiles/v3.22/demo-native-1.2.3.tar.xz"
                ),
                "sha512": "6" * 128,
                "size": 789,
            }
        ],
        "observed_license": "MIT",
        "notices": [
            {
                "member": "demo-native-1.2.3/LICENSE",
                "sha256": "7" * 64,
                "size": 12,
            }
        ],
    }
    policy = {
        "native_component_sources": {"alpine:demo-native@1.2.3-r0": source},
        "native_component_coverage": coverage,
    }
    return inventories, locked_wheels, policy, {("demo", "1.0"): owner_source}


def native_component_v7_policy_case() -> dict[str, Any]:
    """Return a minimal cross-platform v7 observation/review/closure policy."""

    inventories, _locked, fixture, _lock_sources = _native_component_fixture_inputs()
    source_id = "alpine:demo-native@1.2.3-r0"
    source = copy.deepcopy(fixture["native_component_sources"][source_id])
    source["allowed_recipe_links"] = []
    coverage: dict[str, list[dict[str, Any]]] = {}
    for platform in ("linux/amd64", "linux/arm64"):
        inventory = inventories[platform]
        fixture_owner = fixture["native_component_coverage"][platform][0]
        component = {
            "type": "library",
            "name": "libdemo",
            "version": "1.2.3",
            "purl": "pkg:generic/libdemo@1.2.3",
            "bom_ref": "pkg:generic/libdemo@1.2.3",
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
            "licenses": [{"license": {"id": "MIT"}}],
        }
        observation_body = {
            "metadata_component": None,
            "metadata_root_echo": None,
            "upstream_invalid_duplicate_bom_ref": False,
            "components": [component],
        }
        observation = {
            "bom_format": "CycloneDX",
            "spec_version": "1.5",
            **observation_body,
            "observation_sha256": evidence.sha256_bytes(evidence.canonical_json(observation_body)),
        }
        sbom_path = fixture_owner["sboms"][0]["path"]
        payload_sizes = {record["path"]: record["size"] for record in inventory["native_payloads"]}
        native_payloads = [
            {**payload, "size": payload_sizes[payload["path"]]}
            for payload in fixture_owner["native_payloads"]
        ]
        reference = evidence.retained_observation_reference(
            sbom_path,
            observation["observation_sha256"],
            component,
        )
        coverage[platform] = [
            {
                "owner": fixture_owner["owner"],
                "wheel": copy.deepcopy(fixture_owner["wheel"]),
                "owner_source": copy.deepcopy(fixture_owner["owner_source"]),
                "cargo_lock": None,
                "native_payloads": native_payloads,
                "sboms": [
                    {
                        "path": sbom_path,
                        "sha256": fixture_owner["sboms"][0]["sha256"],
                        "observation": observation,
                        "metadata_root": {"kind": "missing", "anomaly_review": None},
                    }
                ],
                "component_reviews": [
                    {
                        "observations": [reference],
                        "source": source_id,
                        "reviewed_license": "MIT",
                    }
                ],
                "payload_dispositions": [
                    {
                        "kind": "sbom-components",
                        "role": "demo.libs/libdemo.so.1",
                        "observations": [reference],
                    },
                    {"kind": "owner", "role": "demo/native.so"},
                ],
                "known_omissions": [],
                "canonical_relationships": [],
                "review": {"state": "closed", "reason": "", "unresolved_items": []},
            }
        ]
    return {
        "native_component_sources": {source_id: source},
        "native_component_coverage": coverage,
    }


def native_component_coverage_case() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, Any],
    dict[tuple[str, str], dict[str, Any]],
]:
    """Build exact inventories and their schema-v7 closed review policy."""

    inventories, locked, _fixture, lock_sources = _native_component_fixture_inputs()
    policy = native_component_v7_policy_case()
    for platform in ("linux/amd64", "linux/arm64"):
        owner = policy["native_component_coverage"][platform][0]
        inventory_sbom = inventories[platform]["embedded_sboms"][0]
        inventory_sbom["cyclonedx"] = copy.deepcopy(owner["sboms"][0]["observation"])
    return inventories, locked, policy, lock_sources


def native_wheel_lock_record(locked: dict[str, Any], *extra_filenames: str) -> str:
    """Return a minimal uv.lock package record around one selected-wheel fixture."""

    owner = locked["owner"].removeprefix("python:")
    name, version = owner.rsplit("@", maxsplit=1)
    wheels = [locked["filename"], *extra_filenames]
    records = []
    for index, filename in enumerate(wheels):
        digest = locked["sha256"] if index == 0 else f"{index:064x}"
        size = locked["size"] if index == 0 else 1
        records.append(
            '    { url = "https://files.pythonhosted.org/packages/aa/'
            f'{filename}", hash = "sha256:{digest}", size = {size} }},'
        )
    return (
        "version = 1\nrevision = 3\n"
        "[[package]]\n"
        f'name = "{name}"\nversion = "{version}"\n'
        "wheels = [\n" + "\n".join(records) + "\n]\n"
    )


def rebind_policy_observation_digest(
    value: object,
    *,
    sbom_path: str,
    observation_sha256: str,
) -> None:
    """Update every policy reference to one intentionally changed observation."""

    if isinstance(value, dict):
        if value.get("sbom_path") == sbom_path and "observation_sha256" in value:
            value["observation_sha256"] = observation_sha256
        for item in value.values():
            rebind_policy_observation_digest(
                item,
                sbom_path=sbom_path,
                observation_sha256=observation_sha256,
            )
    elif isinstance(value, list):
        for item in value:
            rebind_policy_observation_digest(
                item,
                sbom_path=sbom_path,
                observation_sha256=observation_sha256,
            )


def rebind_policy_observation_bom_ref(
    value: object,
    *,
    sbom_path: str,
    old_bom_ref: str,
    new_bom_ref: str,
) -> None:
    """Update every exact policy reference to one intentionally changed bom-ref."""

    if isinstance(value, dict):
        if value.get("sbom_path") == sbom_path and value.get("bom_ref") == old_bom_ref:
            value["bom_ref"] = new_bom_ref
        for item in value.values():
            rebind_policy_observation_bom_ref(
                item,
                sbom_path=sbom_path,
                old_bom_ref=old_bom_ref,
                new_bom_ref=new_bom_ref,
            )
    elif isinstance(value, list):
        for item in value:
            rebind_policy_observation_bom_ref(
                item,
                sbom_path=sbom_path,
                old_bom_ref=old_bom_ref,
                new_bom_ref=new_bom_ref,
            )


def rewrite_native_wheel(
    content: bytes,
    *,
    replacements: dict[str, bytes] | None = None,
    removals: set[str] | None = None,
    additions: dict[str, bytes] | None = None,
) -> bytes:
    """Rewrite a fixture wheel and regenerate its authoritative archive RECORD."""

    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        files = {
            item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()
        }
    record_paths = [path for path in files if path.endswith(".dist-info/RECORD")]
    assert len(record_paths) == 1
    record_path = record_paths[0]
    files.pop(record_path)
    for path in removals or set():
        files.pop(path)
    files.update(replacements or {})
    files.update(additions or {})
    files[record_path] = wheel_record(files, record_path)
    return source_zip_bytes(list(files.items()))


def replace_native_wheel_record(content: bytes, record: bytes) -> bytes:
    """Replace archive RECORD bytes without repairing any claimed identities."""

    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        files = {
            item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()
        }
    record_paths = [path for path in files if path.endswith(".dist-info/RECORD")]
    assert len(record_paths) == 1
    files[record_paths[0]] = record
    return source_zip_bytes(list(files.items()))


def rebind_installed_wheel_member(
    inventory: dict[str, Any], installed_path: str, payload: bytes
) -> None:
    """Rebind a synthetic installed member while preserving its semantic contract."""

    installation = inventory["wheel_installations"][0]
    entry = next(item for item in installation["entries"] if item["path"] == installed_path)
    occurrence = entry["occurrence"]
    occurrence["sha256"] = evidence.sha256_bytes(payload)
    occurrence["size"] = len(payload)
    entry["recorded_sha256"] = occurrence["sha256"]
    entry["recorded_size"] = occurrence["size"]
    identity_field = PurePosixPath(installed_path).name.lower()
    assert identity_field in {"metadata", "wheel"}
    installation[identity_field] = copy.deepcopy(occurrence)


def locked_for_content(locked: dict[str, Any], content: bytes) -> dict[str, Any]:
    result = copy.deepcopy(locked)
    result["sha256"] = evidence.sha256_bytes(content)
    result["size"] = len(content)
    return result


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "a/../../escape",
        "a\\b",
        ".",
        "./",
        "././file",
        "a//b",
    ],
)
def test_checked_path_rejects_unsafe_names(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path(path)


@pytest.mark.parametrize(
    "path", ["LICENSE\nforged", "LICENSE\rforged", "LICENSE\tforged", "x\x7fy"]
)
def test_checked_path_rejects_control_characters(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path(path)


def test_checked_path_rejects_oversized_names() -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path("a" * (evidence.MAX_PATH_BYTES + 1))


@pytest.mark.parametrize("path", ["./retained/path", "retained/path/"])
def test_retained_paths_reject_archive_name_aliases(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="not a canonical archive path"):
        evidence.checked_canonical_path(path, "retained test path")


def test_link_and_record_paths_use_utf8_byte_limits() -> None:
    oversized = "é" * (evidence.MAX_PATH_BYTES // 2 + 1)
    with pytest.raises(evidence.EvidenceError, match="archive link target"):
        evidence.checked_link_target(oversized)
    with pytest.raises(evidence.EvidenceError, match="image link target"):
        evidence.checked_image_link_target(oversized)
    with pytest.raises(evidence.EvidenceError, match="Python RECORD path"):
        evidence.resolve_wheel_record_path(
            evidence.PurePosixPath("opt/venv/lib/python3.14/site-packages"),
            oversized,
        )


def test_strict_json_rejects_duplicates_and_non_finite_numbers(tmp_path: Path) -> None:
    for content, message in (
        ('{"distribution_approval": false, "distribution_approval": true}', "duplicate"),
        ('{"value": NaN}', "non-finite"),
        ('{"value": Infinity}', "non-finite"),
    ):
        path = tmp_path / "hostile.json"
        path.write_text(content)
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.load_json(path)
    with pytest.raises(ValueError, match="Out of range float values"):
        evidence.canonical_json({"value": float("nan")})


def test_strict_json_rejects_floats_and_excessive_nesting() -> None:
    with pytest.raises(evidence.EvidenceError, match="floating-point"):
        evidence.strict_json_loads(b'{"value":1e400}', "test")
    deeply_nested = b"[" * (evidence.MAX_JSON_DEPTH + 1) + b"]" * (evidence.MAX_JSON_DEPTH + 1)
    with pytest.raises(evidence.EvidenceError, match="nesting-depth"):
        evidence.strict_json_loads(deeply_nested, "test")


def test_strict_json_rejects_lone_unicode_surrogates() -> None:
    with pytest.raises(evidence.EvidenceError, match="invalid Unicode"):
        evidence.strict_json_loads(b'{"value":"\\ud800"}', "test")
    with pytest.raises(evidence.EvidenceError, match="invalid Unicode"):
        evidence.canonical_json({"value": "\ud800"})


def test_schema_version_requires_exact_v7_integer_and_media_type() -> None:
    evidence.require_schema({"schema_version": 7}, "test")
    for unsupported in (True, 1, 2, 3, 4, 5, 6, 8):
        with pytest.raises(evidence.EvidenceError, match="unsupported test schema"):
            evidence.require_schema({"schema_version": unsupported}, "test")
    assert evidence.EVIDENCE_MEDIA_TYPE == (
        "application/vnd.stampbot.container-evidence.v7+tar+gzip"
    )


def test_cpython_patchlevel_parser_requires_one_exact_final_version() -> None:
    assert evidence.parse_cpython_patchlevel_header(cpython_patchlevel_header()) == "3.14.6"
    guarded_header = (
        b"#ifndef _Py_PATCHLEVEL_H\n#define _Py_PATCHLEVEL_H\n"
        + cpython_patchlevel_header()
        + b"#endif //_Py_PATCHLEVEL_H\n"
    )
    assert evidence.parse_cpython_patchlevel_header(guarded_header) == "3.14.6"

    mutations = (
        (
            cpython_patchlevel_header("3.14.5"),
            "unexpected PY_MICRO_VERSION",
        ),
        (
            cpython_patchlevel_header() + b'#define PY_VERSION              "3.14.6"\n',
            "must define PY_VERSION exactly once",
        ),
        (
            cpython_patchlevel_header().replace(
                b"/*--end constants--*/",
                b"#define PY_UNREVIEWED_VERSION 1\n/*--end constants--*/",
            ),
            "unexpected version macro set",
        ),
        (
            cpython_patchlevel_header().replace(b"3.14.6", b"3.14.6\x00"),
            "invalid control bytes",
        ),
        (
            cpython_patchlevel_header()
            .replace(b"/*--start constants--*/", b"/*--start constants--*/\n#if 0")
            .replace(b"/*--end constants--*/", b"#endif\n/*--end constants--*/"),
            "constants are conditional",
        ),
        (
            b"#if 0\n" + cpython_patchlevel_header() + b"#endif\n",
            "constants are conditional",
        ),
        (
            cpython_patchlevel_header() + b"#undef PY_VERSION\n",
            "undefines a version constant",
        ),
    )
    for content, message in mutations:
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.parse_cpython_patchlevel_header(content)


def test_cpython_runtime_component_rejects_mutated_identity_fields() -> None:
    mutations = {
        "path": "invalid CPython version_header identity",
        "uid": "invalid CPython interpreter identity",
        "mode": "invalid CPython shared_library identity",
        "layer": "span multiple layers",
        "architecture": "ELF architecture mismatch",
        "link_target": "invalid CPython interpreter_link identity",
    }
    for mutation, message in mutations.items():
        component = synthetic_runtime_component()
        identities = component["identity_files"]
        if mutation == "path":
            identities["version_header"]["path"] = "usr/local/include/python3.14/other.h"
        elif mutation == "uid":
            identities["interpreter"]["uid"] = 1000
        elif mutation == "mode":
            identities["shared_library"]["mode"] = 0o644
        elif mutation == "layer":
            identities["shared_library"]["layer"] = 1
        elif mutation == "architecture":
            identities["interpreter"]["elf"] = {
                "bits": 64,
                "endianness": "little",
                "machine": "aarch64",
                "machine_id": 183,
            }
        else:
            identities["interpreter_link"]["target"] = "python3.13"
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.validate_platform_component_invariants(
                [component], "linux/amd64", "test inventory"
            )


@pytest.mark.parametrize(
    ("path", "content", "header", "message"),
    (
        (
            evidence.CPYTHON_VERSION_HEADER,
            cpython_patchlevel_header("3.14.5"),
            {"mode": 0o644, "uid": 0, "gid": 0},
            "unexpected PY_MICRO_VERSION",
        ),
        (
            evidence.CPYTHON_INTERPRETER,
            elf64_payload("arm64"),
            {"mode": 0o755, "uid": 0, "gid": 0},
            "ELF architecture does not match linux/amd64",
        ),
        (
            evidence.CPYTHON_SHARED_LIBRARY,
            elf64_payload(),
            {"mode": 0o644, "uid": 0, "gid": 0},
            "shared library has an invalid identity",
        ),
        (
            evidence.CPYTHON_INTERPRETER,
            elf64_payload(),
            {"mode": 0o755, "uid": 1000, "gid": 0},
            "interpreter has an invalid identity",
        ),
    ),
)
def test_saved_image_rejects_untrusted_cpython_runtime_identity(
    tmp_path: Path,
    path: str,
    content: bytes,
    header: dict[str, int],
    message: str,
) -> None:
    image = tmp_path / "image.tar"
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            path: content,
        },
        headers={path: header},
    )
    saved_image_layers(image, [layer])

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_saved_image_rejects_untrusted_cpython_interpreter_link(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    layer = tar_bytes(
        {"lib/apk/db/installed": apk_database()},
        links={evidence.CPYTHON_INTERPRETER_LINK: "python3.13"},
    )
    saved_image_layers(image, [layer])

    with pytest.raises(evidence.EvidenceError, match="interpreter link has an invalid identity"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_saved_image_inventory_tracks_whiteouts_and_all_layers(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("alpine", "busybox")]["aports_commit"] == "1" * 40
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "pip")]["effective"] is False
    runtime = components[("runtime", "cpython")]
    assert runtime == {
        "ecosystem": "runtime",
        "name": "cpython",
        "version": "3.14.6",
        "purl": "pkg:generic/python@3.14.6",
        "observed_license": "",
        "effective": True,
        "identity_files": {
            "version_header": {
                "effective": True,
                "layer": 0,
                "path": evidence.CPYTHON_VERSION_HEADER,
                "sha256": evidence.sha256_bytes(cpython_patchlevel_header()),
                "size": len(cpython_patchlevel_header()),
                "mode": 0o644,
                "uid": 0,
                "gid": 0,
            },
            "interpreter": {
                "effective": True,
                "layer": 0,
                "path": evidence.CPYTHON_INTERPRETER,
                "sha256": evidence.sha256_bytes(elf64_payload()),
                "size": len(elf64_payload()),
                "mode": 0o755,
                "uid": 0,
                "gid": 0,
                "elf": {
                    "bits": 64,
                    "endianness": "little",
                    "machine": "x86_64",
                    "machine_id": 62,
                },
            },
            "interpreter_link": {
                "effective": True,
                "kind": "symlink",
                "layer": 0,
                "path": evidence.CPYTHON_INTERPRETER_LINK,
                "target": evidence.CPYTHON_INTERPRETER_LINK_TARGET,
                "mode": 0o777,
                "uid": 0,
                "gid": 0,
            },
            "shared_library": {
                "effective": True,
                "layer": 0,
                "path": evidence.CPYTHON_SHARED_LIBRARY,
                "sha256": evidence.sha256_bytes(elf64_payload()),
                "size": len(elf64_payload()),
                "mode": 0o755,
                "uid": 0,
                "gid": 0,
                "elf": {
                    "bits": 64,
                    "endianness": "little",
                    "machine": "x86_64",
                    "machine_id": 62,
                },
            },
        },
    }
    assert inventory["image_revision"] == "a" * 40
    assert [layer["regular_file_count"] for layer in files["layers"]] == [6, 1]
    assert len(files["regular_files"]) == 7


def test_all_layer_inventory_binds_cpython_component_to_exact_file_occurrences(
    tmp_path: Path,
) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    evidence.validate_all_layer_inventory(files, inventory)

    mutated_component = copy.deepcopy(inventory)
    runtime = next(
        component
        for component in mutated_component["components"]
        if component["ecosystem"] == "runtime"
    )
    runtime["identity_files"]["version_header"]["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="not one exact all-layer"):
        evidence.validate_all_layer_inventory(files, mutated_component)

    mutated_files = copy.deepcopy(files)
    interpreter = next(
        record
        for record in mutated_files["regular_files"]
        if record["path"] == evidence.CPYTHON_INTERPRETER
    )
    interpreter["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="not one exact all-layer"):
        evidence.validate_all_layer_inventory(mutated_files, inventory)

    mutated_link = copy.deepcopy(files)
    interpreter_link = next(
        record
        for record in mutated_link["non_regular_files"]
        if record["path"] == evidence.CPYTHON_INTERPRETER_LINK
    )
    interpreter_link["target"] = "python3.13"
    with pytest.raises(evidence.EvidenceError, match="interpreter link"):
        evidence.validate_all_layer_inventory(mutated_link, inventory)


@pytest.mark.parametrize("replacement", ["opaque", "regular", "symlink"])
def test_all_layer_inventory_rejects_later_ancestor_replacement(
    tmp_path: Path, replacement: str
) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    mutated = copy.deepcopy(files)
    layer_index = len(mutated["layers"])
    digest_character = {"opaque": "c", "regular": "d", "symlink": "e"}[replacement]
    layer_digest = "sha256:" + digest_character * 64
    mutated["layers"].append(
        {
            "digest": layer_digest,
            "index": layer_index,
            "regular_file_count": int(replacement == "regular"),
            "directory_count": 0,
            "non_regular_file_count": int(replacement == "symlink"),
            "whiteout_count": int(replacement == "opaque"),
        }
    )
    if replacement == "opaque":
        mutated["whiteouts"].append(
            {
                "kind": "opaque",
                "layer": layer_index,
                "layer_digest": layer_digest,
                "path": "usr/local/bin/.wh..wh..opq",
                "target": "usr/local/bin",
                "mode": 0,
                "uid": 0,
                "gid": 0,
            }
        )
    elif replacement == "regular":
        mutated["regular_files"].append(
            {
                "effective": True,
                "layer": layer_index,
                "layer_digest": layer_digest,
                "path": "usr/local/bin",
                "sha256": "0" * 64,
                "size": 0,
                "mode": 0o755,
                "uid": 0,
                "gid": 0,
            }
        )
    else:
        mutated["non_regular_files"].append(
            {
                "kind": "symlink",
                "layer": layer_index,
                "layer_digest": layer_digest,
                "path": "usr/local/bin",
                "target": "elsewhere",
                "mode": 0o777,
                "uid": 0,
                "gid": 0,
            }
        )

    with pytest.raises(evidence.EvidenceError, match=r"CPython .* all-layer|interpreter link"):
        evidence.validate_all_layer_inventory(mutated, inventory)


def test_all_layer_validators_reject_cross_kind_path_duplicates(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    duplicate = copy.deepcopy(files)
    regular = duplicate["regular_files"][0]
    duplicate["directories"].append(
        {
            "effective": regular["effective"],
            "layer": regular["layer"],
            "layer_digest": regular["layer_digest"],
            "path": regular["path"],
            "mode": 0o755,
            "uid": 0,
            "gid": 0,
        }
    )
    duplicate["layers"][regular["layer"]]["directory_count"] += 1

    with pytest.raises(evidence.EvidenceError, match="across entry categories"):
        evidence.validate_all_layer_inventory(duplicate, inventory)
    with pytest.raises(evidence.EvidenceError, match="across entry categories"):
        evidence.validate_filesystem_policy_view_input(duplicate)


def test_saved_image_binds_config_and_layer_blob_names_to_bytes(tmp_path: Path) -> None:
    layer = tar_bytes({"lib/apk/db/installed": apk_database()})
    valid = tmp_path / "valid.tar"
    saved_image_layers(valid, [layer])
    with pytest.raises(evidence.EvidenceError, match="inspected image"):
        evidence._inventory_saved_image(
            valid,
            "linux/amd64",
            "sha256:" + "a" * 64,
            expected_config_digest="sha256:" + "b" * 64,
        )

    config = json.dumps(
        {
            "architecture": "amd64",
            "config": {"Labels": {}},
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "c" * 64]},
        }
    ).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config).hexdigest()}"
    hostile_layer_name = "blobs/sha256/" + "c" * 64
    hostile = tmp_path / "hostile.tar"
    hostile.write_bytes(
        tar_bytes(
            {
                "manifest.json": json.dumps(
                    [{"Config": config_name, "Layers": [hostile_layer_name]}]
                ).encode(),
                config_name: config,
                hostile_layer_name: layer,
            }
        )
    )
    with pytest.raises(evidence.EvidenceError, match="layer digest does not match"):
        evidence._inventory_saved_image(hostile, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("rootfs_kind", ["missing", "mismatched"])
def test_saved_image_requires_exact_config_rootfs_binding(rootfs_kind: str, tmp_path: Path) -> None:
    layer = tar_bytes({"lib/apk/db/installed": apk_database()})
    layer_hash = evidence.hashlib.sha256(layer).hexdigest()
    layer_name = f"blobs/sha256/{layer_hash}"
    config: dict[str, Any] = {
        "architecture": "amd64",
        "config": {"Labels": {}},
        "os": "linux",
    }
    if rootfs_kind == "mismatched":
        config["rootfs"] = {"type": "layers", "diff_ids": ["sha256:" + "b" * 64]}
    config_content = json.dumps(config).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config_content).hexdigest()}"
    image = tmp_path / "image.tar"
    image.write_bytes(
        tar_bytes(
            {
                "manifest.json": json.dumps(
                    [{"Config": config_name, "Layers": [layer_name]}]
                ).encode(),
                config_name: config_content,
                layer_name: layer,
            }
        )
    )

    message = "no layered root" if rootfs_kind == "missing" else "rootfs diff IDs"
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_docker_save_stream_has_an_exact_output_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_docker = tmp_path / "docker"
    fake_docker.write_text("#!/bin/sh\nprintf abc")
    fake_docker.chmod(0o755)
    monkeypatch.setattr(evidence, "executable", lambda _name: str(fake_docker))
    monkeypatch.setattr(evidence, "MAX_DOCKER_SAVE_BYTES", 3)
    output = tmp_path / "image.tar"

    evidence.save_docker_image_bounded("sha256:" + "a" * 64, output)
    assert output.read_bytes() == b"abc"

    fake_docker.write_text("#!/bin/sh\nprintf abcd")
    with pytest.raises(evidence.EvidenceError, match="exceeds the size limit"):
        evidence.save_docker_image_bounded("sha256:" + "a" * 64, output)


def test_docker_save_outer_members_are_bounded_before_random_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes({"lib/apk/db/installed": apk_database()})])
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBERS", 2)

    with pytest.raises(evidence.EvidenceError, match="too many entries"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_whiteouts_remove_only_lower_layer_files_independent_of_order(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0", "MIT"),
            f"{site}/stale-1.0.dist-info/METADATA": metadata("stale", "1.0", "MIT"),
        }
    )
    second = tar_sequence(
        [
            (f"{site}/demo-1.0.dist-info/METADATA", metadata("demo", "1.0", "MIT")),
            (f"{site}/.wh.demo-1.0.dist-info", b""),
            (f"{site}/.wh..wh..opq", b""),
        ]
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    inventory, _ = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "demo")]["observed_license"] == "MIT"
    assert components[("python", "stale")]["effective"] is False


def test_conflicting_metadata_for_one_python_release_fails_closed(tmp_path: Path) -> None:
    path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    path: metadata("demo", "1.0", "MIT"),
                }
            ),
            tar_bytes({path: metadata("demo", "1.0", "Apache-2.0")}),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="conflicting Python metadata"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_python_component_is_effective_when_any_identical_occurrence_survives(
    tmp_path: Path,
) -> None:
    system_site = "usr/local/lib/python3.14/site-packages"
    venv_site = "opt/venv/lib/python3.14/site-packages"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{system_site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        }
    )
    second = tar_bytes({f"{venv_site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0")})
    third = tar_bytes({f"{venv_site}/.wh.demo-1.0.dist-info": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second, third])

    inventory, _ = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    demo = next(item for item in inventory["components"] if item["name"] == "demo")
    assert demo["effective"] is True


def test_removed_apk_database_fails_closed(tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database()})
    second = tar_bytes({"lib/apk/db/.wh.installed": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="no effective Alpine"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_replaced_apk_database_retains_packages_distributed_in_lower_layers(
    tmp_path: Path,
) -> None:
    lower_database = apk_database(version="1.0-r0") + apk_database(version="2.0-r0", name="retired")
    upper_database = apk_database(version="2.0-r0")
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": lower_database,
                    "usr/lib/libretired.so": b"distributed lower-layer bytes",
                }
            ),
            tar_bytes(
                {
                    "lib/apk/db/installed": upper_database,
                    "usr/lib/.wh.libretired.so": b"",
                }
            ),
        ],
    )

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    alpine = {
        (item["name"], item["version"]): item
        for item in inventory["components"]
        if item["ecosystem"] == "alpine"
    }
    assert alpine[("busybox", "1.0-r0")]["effective"] is False
    assert alpine[("busybox", "2.0-r0")]["effective"] is True
    retired = alpine[("retired", "2.0-r0")]
    assert retired["effective"] is False
    assert retired["origin"] == "retired"
    assert retired["aports_commit"] == "1" * 40
    retired_file = next(
        item for item in files["regular_files"] if item["path"] == "usr/lib/libretired.so"
    )
    assert retired_file["effective"] is False


def test_conflicting_alpine_metadata_across_layers_fails_closed(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database()}),
            tar_bytes({"lib/apk/db/installed": apk_database(origin="other-origin")}),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="conflicting Alpine metadata"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_duplicate_paths_in_one_image_layer_fail_closed(tmp_path: Path) -> None:
    layer = tar_sequence(
        [
            ("lib/apk/db/installed", apk_database(version="1.0-r0")),
            ("lib/apk/db/installed", apk_database(version="2.0-r0")),
        ]
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    with pytest.raises(evidence.EvidenceError, match="image layer repeats path"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("kind", ["nonempty", "symlink", "empty-basename"])
def test_invalid_oci_whiteouts_fail_closed(kind: str, tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database(), "removed": b"old"})
    if kind == "nonempty":
        second = tar_bytes({".wh.removed": b"not empty"})
        message = "empty regular file"
    elif kind == "symlink":
        second = tar_bytes({}, links={".wh.removed": "safe-target"})
        message = "empty regular file"
    else:
        second = tar_bytes({".wh.": b""})
        message = "no target basename"
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("ancestor_kind", ["regular", "symlink"])
def test_whiteout_cannot_traverse_a_lower_non_directory_parent(
    ancestor_kind: str, tmp_path: Path
) -> None:
    first_files = {"lib/apk/db/installed": apk_database()}
    if ancestor_kind == "regular":
        first = tar_bytes({**first_files, "parent": b"not a directory"})
    else:
        first = tar_bytes(first_files, links={"parent": "elsewhere"})
    second = tar_bytes({"parent/.wh.child": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="non-directory parent topology"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_opaque_whiteout_requires_lower_layer_children(tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database(), "parent": b"not a directory"})
    second = tar_bytes(
        {"parent/.wh..wh..opq": b"", "parent/current": b"kept"},
        directories=["parent"],
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="does not remove any lower-layer entries"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_regular_file_replacing_a_directory_removes_its_descendants(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    package_directory = f"{site}/demo-1.0.dist-info"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{package_directory}/METADATA": metadata("demo", "1.0"),
        }
    )
    second = tar_bytes({package_directory: b"replacement"})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    demo = next(item for item in inventory["components"] if item["name"] == "demo")
    assert demo["effective"] is False
    metadata_record = next(
        item for item in files["regular_files"] if item["path"].endswith("/METADATA")
    )
    assert metadata_record["effective"] is False


@pytest.mark.parametrize("ancestor_kind", ["regular", "symlink"])
def test_layer_entries_cannot_traverse_a_non_directory_ancestor(
    ancestor_kind: str, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    first_files = {"lib/apk/db/installed": apk_database()}
    if ancestor_kind == "regular":
        first_files[site] = b"not a directory"
        first = tar_bytes(first_files)
    else:
        first = tar_bytes(first_files, links={site: "elsewhere"})
    second = tar_bytes({f"{site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0")})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="non-directory ancestor"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_non_regular_replacement_of_python_metadata_fails_closed(
    link_kind: str, tmp_path: Path
) -> None:
    path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
    first = tar_bytes({"lib/apk/db/installed": apk_database(), path: metadata("demo", "1.0")})
    links = {path: "other"} if link_kind == "symlink" else None
    hardlinks = {path: "other"} if link_kind == "hardlink" else None
    second = tar_bytes({}, links=links, hardlinks=hardlinks)
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="metadata path is not a regular file"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_image_size_limit_is_cumulative_across_layers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [tar_bytes({"lib/apk/db/installed": apk_database()}), tar_bytes({"second": b"x"})],
    )
    monkeypatch.setattr(evidence, "MAX_IMAGE_TOTAL_BYTES", 15_000)

    with pytest.raises(evidence.EvidenceError, match="cumulative size limit"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_image_member_limit_is_cumulative_across_layers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database(), "first": b"x"}),
            tar_bytes({"second": b"x"}),
        ],
    )
    monkeypatch.setattr(evidence, "MAX_IMAGE_MEMBERS", 2)

    with pytest.raises(evidence.EvidenceError, match="too many cumulative entries"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_apk_architecture_must_match_image_platform(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes({"lib/apk/db/installed": apk_database("aarch64")})])

    with pytest.raises(evidence.EvidenceError, match="does not match linux/amd64"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_claimed_subject_must_match_a_local_repository_digest() -> None:
    config_digest = "sha256:" + "a" * 64
    manifest_digest = "sha256:" + "b" * 64
    info = {
        "Id": config_digest,
        "RepoDigests": [f"ghcr.io/stampbot/extra-codeowners@{manifest_digest}"],
    }

    assert (
        evidence.verify_local_image_subject(
            info, manifest_digest, allow_config_digest_subject=False
        )
        == config_digest
    )
    with pytest.raises(evidence.EvidenceError, match="claimed subject digest"):
        evidence.verify_local_image_subject(
            info, "sha256:" + "c" * 64, allow_config_digest_subject=False
        )
    with pytest.raises(evidence.EvidenceError, match="claimed subject digest"):
        evidence.verify_local_image_subject(info, config_digest, allow_config_digest_subject=False)
    assert (
        evidence.verify_local_image_subject(
            {"Id": config_digest, "RepoDigests": []},
            config_digest,
            allow_config_digest_subject=True,
        )
        == config_digest
    )


def test_apk_database_requires_commit_provenance() -> None:
    broken = apk_database().replace(b"c:" + b"1" * 40 + b"\n", b"")
    with pytest.raises(evidence.EvidenceError, match="immutable source provenance"):
        evidence.parse_apk_database(broken)


def test_exact_apk_database_baseline_covers_virtual_records(tmp_path: Path) -> None:
    virtual = b"P:.python-rundeps\nV:20260714.000000\nA:noarch\n\n"
    clean_image = tmp_path / "clean-apk.tar"
    saved_image_layers(
        clean_image,
        [tar_bytes({"lib/apk/db/installed": apk_database() + virtual})],
    )
    clean_inventory, _files = evidence._inventory_saved_image(
        clean_image, "linux/amd64", "sha256:" + "a" * 64
    )
    policy = {
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": clean_inventory["apk_database_occurrences"],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        }
    }
    evidence.verify_apk_database_baseline(clean_inventory, policy)

    hostile_image = tmp_path / "hostile-apk.tar"
    saved_image_layers(
        hostile_image,
        [
            tar_bytes(
                {"lib/apk/db/installed": apk_database() + virtual + b"P:.evil\nV:1\nA:noarch\n\n"}
            )
        ],
    )
    hostile_inventory, _files = evidence._inventory_saved_image(
        hostile_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="APK databases differ"):
        evidence.verify_apk_database_baseline(hostile_inventory, policy)


@pytest.mark.parametrize("field", ["P", "V", "A", "L", "o", "c"])
def test_apk_database_rejects_duplicate_authoritative_fields(field: str) -> None:
    value = next(
        line.removeprefix(f"{field}:")
        for line in apk_database().decode().splitlines()
        if line.startswith(f"{field}:")
    )
    hostile = apk_database().replace(
        f"{field}:{value}\n".encode(), f"{field}:{value}\n{field}:{value}\n".encode()
    )
    with pytest.raises(evidence.EvidenceError, match=f"repeats field {field}"):
        evidence.parse_apk_database(hostile)


@pytest.mark.parametrize(
    "field", ["Metadata-Version", "Name", "Version", "License-Expression", "License"]
)
def test_python_metadata_rejects_duplicate_authoritative_fields(field: str) -> None:
    base = metadata("demo", "1.0")
    value = "demo" if field == "Name" else "1.0" if field == "Version" else "MIT"
    if field == "License":
        hostile = b"Name: demo\nVersion: 1.0\nLicense: MIT\nLicense: MIT\n\n"
    else:
        hostile = f"{field}: {value}\n".encode() + base
    with pytest.raises(evidence.EvidenceError, match=f"repeats {field}"):
        evidence.parse_python_metadata(hostile, DEMO_METADATA_PATH)


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("a/b", "1.0"),
        ("..", "1.0"),
        ("a@b", "1.0"),
        ("-demo", "1.0"),
        ("demo", "../escape"),
        ("demo", "1/2"),
        ("demo", "1\t2"),
        ("demo", "1\x7f2"),
    ],
)
def test_python_metadata_rejects_unsafe_identity_fields(name: str, version: str) -> None:
    hostile = (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nLicense-Expression: MIT\n\n"
    ).encode()
    with pytest.raises(
        evidence.EvidenceError,
        match=r"(?:invalid (?:name|version)|control characters)",
    ):
        evidence.parse_python_metadata(hostile, DEMO_METADATA_PATH)


def test_python_metadata_rejects_control_characters_and_oversized_fields() -> None:
    with pytest.raises(evidence.EvidenceError, match="control characters"):
        evidence.parse_python_metadata(
            b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\nLicense-Expression: MIT\tforged\n\n",
            DEMO_METADATA_PATH,
        )

    with pytest.raises(evidence.EvidenceError, match="invalid length"):
        evidence.parse_python_metadata(metadata("a" * 513, "1.0"), DEMO_METADATA_PATH)


@pytest.mark.parametrize(
    "hostile",
    [
        metadata("demo", "1.0").replace(b"Metadata-Version: 2.4\n", b""),
        metadata("demo", "1.0").replace(b"Metadata-Version: 2.4\n", b"Metadata-Version: 9.9\n"),
        b"Metadata-Version: 2.4\nMalformed Header\nName: demo\nVersion: 1.0\n\n",
    ],
)
def test_python_metadata_requires_supported_well_formed_core_metadata(
    hostile: bytes,
) -> None:
    with pytest.raises(
        evidence.EvidenceError, match=r"(invalid length|unsupported|parser defects)"
    ):
        evidence.parse_python_metadata(hostile, DEMO_METADATA_PATH)


def test_python_metadata_must_match_its_dist_info_directory() -> None:
    hostile_path = "opt/venv/lib/python3.14/site-packages/not_demo-999.dist-info/METADATA"
    with pytest.raises(evidence.EvidenceError, match="does not match its dist-info directory"):
        evidence.parse_python_metadata(metadata("demo", "1.0"), hostile_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("P", "../busybox", "invalid name"),
        ("V", "../escape", "invalid version"),
        ("A", "x86/64", "invalid architecture"),
        ("o", "../busybox", "invalid origin"),
        ("L", "MIT\tforged", "control characters"),
    ],
)
def test_apk_database_rejects_unsafe_component_fields(field: str, value: str, message: str) -> None:
    original = next(
        line for line in apk_database().decode().splitlines() if line.startswith(f"{field}:")
    )
    hostile = apk_database().replace(f"{original}\n".encode(), f"{field}:{value}\n".encode())
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_apk_database(hostile)


@pytest.mark.parametrize("second_version", ["1.37.0-r1", "2.0-r0"])
def test_apk_database_rejects_duplicate_package_names(second_version: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="repeats name"):
        evidence.parse_apk_database(apk_database() + apk_database(version=second_version))


def test_apk_database_enforces_component_count_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second = (
        apk_database().replace(b"P:busybox\n", b"P:other\n").replace(b"o:busybox\n", b"o:other\n")
    )
    monkeypatch.setattr(evidence, "MAX_COMPONENTS", 1)
    with pytest.raises(evidence.EvidenceError, match="too many records"):
        evidence.parse_apk_database(apk_database() + second)


def test_lock_sources_reject_duplicate_normalized_name_and_version(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        '[[package]]\nname = "Demo_Pkg"\nversion = "1.0"\n'
        'sdist = { url = "https://example.com/one.tar.gz", '
        f'hash = "sha256:{"a" * 64}", size = 1 }}\n\n'
        '[[package]]\nname = "demo-pkg"\nversion = "1.0"\n'
        'sdist = { url = "https://example.com/two.tar.gz", '
        f'hash = "sha256:{"b" * 64}", size = 1 }}\n'
    )

    with pytest.raises(evidence.EvidenceError, match="repeats Python source"):
        evidence.parse_lock_sources(lock)


def test_native_wheel_selection_uses_exact_installed_abi_build_and_platform(
    tmp_path: Path,
) -> None:
    inventory, locked, _content = native_wheel_case(
        component_name="cryptography",
        version="48.0.1",
        tag="cp311-abi3-musllinux_1_2_x86_64",
        build="1",
    )
    lock = tmp_path / "uv.lock"
    lock.write_text(
        native_wheel_lock_record(
            locked,
            "cryptography-48.0.1-cp39-abi3-musllinux_1_2_x86_64.whl",
            "cryptography-48.0.1-cp314t-cp314t-musllinux_1_2_x86_64.whl",
            "cryptography-48.0.1-cp311-abi3-musllinux_1_2_aarch64.whl",
            "cryptography-48.0.1-2-cp311-abi3-musllinux_1_2_x86_64.whl",
        )
    )

    assert evidence.select_locked_native_wheels(lock, inventory) == [locked]


def test_native_wheel_selection_and_verification_preserve_leading_zero_build(
    tmp_path: Path,
) -> None:
    inventory, locked, content = native_wheel_case(build="001alpha")
    lock = tmp_path / "uv.lock"
    lock.write_text(
        native_wheel_lock_record(
            locked,
            locked["filename"].replace("-001alpha-", "-1alpha-"),
        )
    )

    assert evidence.select_locked_native_wheels(lock, inventory) == [locked]
    record, _raw_sboms = evidence.verify_native_wheel_artifact(inventory, locked, content)
    assert record["build"] == "001alpha"


def test_committed_lock_selects_exact_seven_native_owner_wheels() -> None:
    policy = json.loads(Path(".compliance/container-policy.json").read_text())
    matrix = {
        "linux/amd64": {
            "python:cffi@2.1.0": (
                "cffi-2.1.0-cp314-cp314-musllinux_1_2_x86_64.whl",
                "cp314-cp314-musllinux_1_2_x86_64",
            ),
            "python:cryptography@48.0.1": (
                "cryptography-48.0.1-cp311-abi3-musllinux_1_2_x86_64.whl",
                "cp311-abi3-musllinux_1_2_x86_64",
            ),
            "python:greenlet@3.5.3": (
                "greenlet-3.5.3-cp314-cp314-musllinux_1_2_x86_64.whl",
                "cp314-cp314-musllinux_1_2_x86_64",
            ),
            "python:markupsafe@3.0.3": (
                "markupsafe-3.0.3-cp314-cp314-musllinux_1_2_x86_64.whl",
                "cp314-cp314-musllinux_1_2_x86_64",
            ),
            "python:psycopg-binary@3.3.4": (
                "psycopg_binary-3.3.4-cp314-cp314-musllinux_1_2_x86_64.whl",
                "cp314-cp314-musllinux_1_2_x86_64",
            ),
            "python:pydantic-core@2.46.4": (
                "pydantic_core-2.46.4-cp314-cp314-musllinux_1_1_x86_64.whl",
                "cp314-cp314-musllinux_1_1_x86_64",
            ),
            "python:sqlalchemy@2.0.51": (
                "sqlalchemy-2.0.51-cp314-cp314-musllinux_1_2_x86_64.whl",
                "cp314-cp314-musllinux_1_2_x86_64",
            ),
        },
        "linux/arm64": {
            "python:cffi@2.1.0": (
                "cffi-2.1.0-cp314-cp314-musllinux_1_2_aarch64.whl",
                "cp314-cp314-musllinux_1_2_aarch64",
            ),
            "python:cryptography@48.0.1": (
                "cryptography-48.0.1-cp311-abi3-musllinux_1_2_aarch64.whl",
                "cp311-abi3-musllinux_1_2_aarch64",
            ),
            "python:greenlet@3.5.3": (
                "greenlet-3.5.3-cp314-cp314-musllinux_1_2_aarch64.whl",
                "cp314-cp314-musllinux_1_2_aarch64",
            ),
            "python:markupsafe@3.0.3": (
                "markupsafe-3.0.3-cp314-cp314-musllinux_1_2_aarch64.whl",
                "cp314-cp314-musllinux_1_2_aarch64",
            ),
            "python:psycopg-binary@3.3.4": (
                "psycopg_binary-3.3.4-cp314-cp314-musllinux_1_2_aarch64.whl",
                "cp314-cp314-musllinux_1_2_aarch64",
            ),
            "python:pydantic-core@2.46.4": (
                "pydantic_core-2.46.4-cp314-cp314-musllinux_1_1_aarch64.whl",
                "cp314-cp314-musllinux_1_1_aarch64",
            ),
            "python:sqlalchemy@2.0.51": (
                "sqlalchemy-2.0.51-cp314-cp314-musllinux_1_2_aarch64.whl",
                "cp314-cp314-musllinux_1_2_aarch64",
            ),
        },
    }

    for platform, expected in matrix.items():
        inventory: dict[str, Any] = {
            "platform": platform,
            "components": [],
            "wheel_installations": [],
            "embedded_sboms": [],
            "native_payloads": [],
        }
        for index, (owner, (_filename, tag)) in enumerate(reversed(expected.items())):
            name, version = owner.removeprefix("python:").rsplit("@", maxsplit=1)
            inventory["components"].append(
                {"ecosystem": "python", "name": name, "version": version}
            )
            inventory["wheel_installations"].append({"owner": owner, "tags": [tag], "build": ""})
            inventory["native_payloads"].append(
                {"owner": owner, "path": f"opt/venv/native/{index}.so"}
            )

        selected = evidence.select_locked_native_wheels(Path("uv.lock"), inventory)

        assert [(record["owner"], record["filename"], record["tags"]) for record in selected] == [
            (owner, filename, [tag]) for owner, (filename, tag) in sorted(expected.items())
        ]
        selected_by_owner = {record["owner"]: record for record in selected}
        coverage_by_owner = {
            record["owner"]: record for record in policy["native_component_coverage"][platform]
        }
        for owner in ("python:greenlet@3.5.3", "python:markupsafe@3.0.3"):
            assert {
                field: selected_by_owner[owner][field] for field in ("url", "sha256", "size")
            } == coverage_by_owner[owner]["wheel"]


@pytest.mark.parametrize(
    "tag",
    [
        "cp314t-cp314t-musllinux_1_2_x86_64",
        "cp315-cp315-musllinux_1_2_x86_64",
        "cp314-cp314-manylinux_2_17_x86_64",
        "cp314-cp314-musllinux_2_0_x86_64",
        "cp314-cp314-musllinux_0_999_x86_64",
        "cp314-cp314-musllinux_1_2_aarch64",
    ],
)
def test_native_wheel_selection_rejects_incompatible_tags(tag: str, tmp_path: Path) -> None:
    inventory, locked, _content = native_wheel_case(tag=tag)
    lock = tmp_path / "uv.lock"
    lock.write_text(native_wheel_lock_record(locked))

    with pytest.raises(evidence.EvidenceError, match="found 0"):
        evidence.select_locked_native_wheels(lock, inventory)


def test_native_wheel_selection_rejects_zero_multiple_and_repeated_installations(
    tmp_path: Path,
) -> None:
    inventory, locked, _content = native_wheel_case()
    lock = tmp_path / "uv.lock"
    wrong_filename = locked["filename"].replace("cp314-cp314", "cp314t-cp314t")
    lock.write_text(native_wheel_lock_record(locked).replace(locked["filename"], wrong_filename))
    with pytest.raises(evidence.EvidenceError, match="found 0"):
        evidence.select_locked_native_wheels(lock, inventory)

    lock.write_text(native_wheel_lock_record(locked, locked["filename"]))
    with pytest.raises(evidence.EvidenceError, match="found 2"):
        evidence.select_locked_native_wheels(lock, inventory)

    repeated = copy.deepcopy(inventory)
    repeated["wheel_installations"].append(copy.deepcopy(repeated["wheel_installations"][0]))
    with pytest.raises(evidence.EvidenceError, match="exactly one historical installation"):
        evidence.select_locked_native_wheels(lock, repeated)

    with pytest.raises(evidence.EvidenceError, match="exactly one historical installation"):
        evidence.verify_native_wheel_artifact(repeated, locked, _content)


def test_native_wheel_selection_rejects_duplicate_packages_and_malformed_wheel_records(
    tmp_path: Path,
) -> None:
    inventory, locked, _content = native_wheel_case()
    lock_record = native_wheel_lock_record(locked)
    package_record = lock_record[lock_record.index("[[package]]") :]
    lock = tmp_path / "uv.lock"
    lock.write_text(f"{lock_record}\n{package_record}")
    with pytest.raises(evidence.EvidenceError, match="exactly one native-wheel package"):
        evidence.select_locked_native_wheels(lock, inventory)

    malformed = lock_record.replace(
        "wheels = [\n",
        'wheels = [\n    { url = "https://files.pythonhosted.org/bad.whl", '
        f'hash = "sha256:{"0" * 64}" }},\n',
    )
    lock.write_text(malformed)
    with pytest.raises(evidence.EvidenceError, match="invalid record"):
        evidence.select_locked_native_wheels(lock, inventory)


def test_native_wheel_verifier_binds_full_record_payloads_and_raw_sbom() -> None:
    inventory, locked, content = native_wheel_case()

    record, raw_sboms = evidence.verify_native_wheel_artifact(inventory, locked, content)

    assert record == {
        "owner": "python:demo@1.0",
        "platform": "linux/amd64",
        "url": locked["url"],
        "filename": locked["filename"],
        "size": len(content),
        "sha256": evidence.sha256_bytes(content),
        "build": "",
        "tags": ["cp314-cp314-musllinux_1_2_x86_64"],
        "generated_files": [],
    }
    assert len(raw_sboms) == 1
    raw_record, raw_content = raw_sboms[0]
    installed_sbom = inventory["embedded_sboms"][0]
    assert raw_content == cyclonedx_sbom()
    assert raw_record["owner"] == "python:demo@1.0"
    assert raw_record["archive_path"].endswith(".dist-info/sboms/auditwheel.cdx.json")
    assert raw_record["installed_occurrence"] == evidence.payload_record_projection(installed_sbom)
    assert raw_record["sha256"] == evidence.sha256_bytes(raw_content)
    assert raw_record["size"] == len(raw_content)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("semantic-tamper", "installed occurrence"),
        ("missing", "different member sets"),
        ("extra", "different member sets"),
    ],
)
def test_native_wheel_verifier_rejects_raw_sbom_drift_with_regenerated_record(
    mutation: str, message: str
) -> None:
    inventory, locked, content = native_wheel_case()
    sbom_path = "demo-1.0.dist-info/sboms/auditwheel.cdx.json"
    if mutation == "semantic-tamper":
        semantically_equivalent = json.dumps(
            json.loads(cyclonedx_sbom()), indent=2, sort_keys=True
        ).encode()
        assert json.loads(semantically_equivalent) == json.loads(cyclonedx_sbom())
        assert semantically_equivalent != cyclonedx_sbom()
        changed = rewrite_native_wheel(content, replacements={sbom_path: semantically_equivalent})
    elif mutation == "missing":
        changed = rewrite_native_wheel(content, removals={sbom_path})
    else:
        changed = rewrite_native_wheel(
            content,
            additions={"demo-1.0.dist-info/sboms/second.cdx.json": cyclonedx_sbom()},
        )

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed),
            changed,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("malformed", "RECORD row 1 has 1 fields"),
        ("self-hashed", "RECORD self-entry must be blank"),
        ("wrong-digest", "RECORD disagrees with member"),
        ("missing-row", "RECORD does not exactly cover archive members"),
        ("extra-row", "RECORD does not exactly cover archive members"),
    ],
)
def test_native_wheel_verifier_rejects_hostile_archive_record(mutation: str, message: str) -> None:
    inventory, locked, content = native_wheel_case()
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        record_path = "demo-1.0.dist-info/RECORD"
        rows = archive.read(record_path).decode().splitlines(keepends=True)
    zero_digest = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
    if mutation == "malformed":
        record = b"not-a-csv-row\n"
    elif mutation == "self-hashed":
        record = "".join(
            f"{record_path},sha256={zero_digest},0\n" if row.startswith(f"{record_path},") else row
            for row in rows
        ).encode()
    elif mutation == "wrong-digest":
        record = "".join(
            f"demo/native.so,sha256={zero_digest},{len(elf64_payload('amd64'))}\n"
            if row.startswith("demo/native.so,")
            else row
            for row in rows
        ).encode()
    elif mutation == "missing-row":
        record = "".join(row for row in rows if not row.startswith("demo/native.so,")).encode()
    else:
        record = (
            "".join(rows[:-1]) + f"demo/ghost.so,sha256={zero_digest},0\n" + rows[-1]
        ).encode()
    changed = replace_native_wheel_record(content, record)

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed),
            changed,
        )


def test_native_wheel_verifier_detects_extensionless_elf_payloads() -> None:
    inventory, locked, content = native_wheel_case(native_archive_path="demo/native_binary")

    evidence.verify_native_wheel_artifact(inventory, locked, content)


def test_native_wheel_verifier_accepts_pure_sbom_only_owner() -> None:
    inventory, locked, content = native_wheel_case()
    wheel_path = "demo-1.0.dist-info/WHEEL"
    installed_wheel_path = f"opt/venv/lib/python3.14/site-packages/{wheel_path}"
    native_path = "opt/venv/lib/python3.14/site-packages/demo/native.so"
    pure_wheel = (
        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp314-cp314-musllinux_1_2_x86_64\n"
    )
    changed = rewrite_native_wheel(
        content,
        replacements={wheel_path: pure_wheel},
        removals={"demo/native.so"},
    )
    pure_inventory = copy.deepcopy(inventory)
    pure_inventory["native_payloads"] = []
    installation = pure_inventory["wheel_installations"][0]
    installation["entries"] = [
        entry for entry in installation["entries"] if entry["path"] != native_path
    ]
    installation["root_is_purelib"] = True
    rebind_installed_wheel_member(pure_inventory, installed_wheel_path, pure_wheel)

    record, raw_sboms = evidence.verify_native_wheel_artifact(
        pure_inventory,
        locked_for_content(locked, changed),
        changed,
    )

    assert record["owner"] == "python:demo@1.0"
    assert len(raw_sboms) == 1


def test_native_wheel_verifier_accepts_reviewed_header_and_launcher_mappings() -> None:
    header_inventory, header_locked, header_content = native_wheel_case(
        component_name="greenlet",
        version="3.5.3",
        include_header_relocation=True,
    )
    evidence.verify_native_wheel_artifact(header_inventory, header_locked, header_content)

    script_inventory, script_locked, script_content = native_wheel_case(
        component_name="cffi",
        version="2.1.0",
        include_console_script=True,
    )
    record, _raw_sboms = evidence.verify_native_wheel_artifact(
        script_inventory, script_locked, script_content
    )
    assert record["generated_files"] == [
        {
            "callable": "main",
            "kind": "console_scripts",
            "module": "demo.module",
            "name": "cffi-gen-src",
            "source_path": "cffi-2.1.0.dist-info/entry_points.txt",
            "installed_occurrence": next(
                entry["occurrence"]
                for entry in script_inventory["wheel_installations"][0]["entries"]
                if entry["path"] == "opt/venv/bin/cffi-gen-src"
            ),
            "launcher_interpreter": "python",
        }
    ]


def test_native_wheel_verifier_accepts_gui_and_ineffective_historical_launchers() -> None:
    gui_inventory, gui_locked, gui_content = native_wheel_case(
        entry_points=b"[gui_scripts]\ngui-demo = demo.module:main\n"
    )
    gui_record, _raw_sboms = evidence.verify_native_wheel_artifact(
        gui_inventory, gui_locked, gui_content
    )
    assert [(item["kind"], item["name"]) for item in gui_record["generated_files"]] == [
        ("gui_scripts", "gui-demo")
    ]

    inactive_inventory, inactive_locked, inactive_content = native_wheel_case(
        include_console_script=True
    )
    launcher = next(
        entry
        for entry in inactive_inventory["wheel_installations"][0]["entries"]
        if entry["path"] == "opt/venv/bin/cffi-gen-src"
    )
    launcher["occurrence"]["effective"] = False
    inactive_record, _raw_sboms = evidence.verify_native_wheel_artifact(
        inactive_inventory, inactive_locked, inactive_content
    )
    assert inactive_record["generated_files"][0]["installed_occurrence"]["effective"] is False


@pytest.mark.parametrize(
    ("entry_points", "message"),
    [
        (b"[console_scripts]\n../escape = demo.module:main\n", "unsafe launcher name"),
        (
            b"[console_scripts]\ndemo = demo.module:main [extra]\n",
            "unsupported launcher entry point",
        ),
        (
            b"[console_scripts]\ndemo = demo.module:main\n[gui_scripts]\ndemo = demo.module:main\n",
            "repeats a launcher name",
        ),
    ],
)
def test_native_wheel_verifier_rejects_unsafe_entry_points(
    entry_points: bytes, message: str
) -> None:
    inventory, locked, content = native_wheel_case()
    changed = rewrite_native_wheel(
        content,
        additions={"demo-1.0.dist-info/entry_points.txt": entry_points},
    )

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed),
            changed,
        )


@pytest.mark.parametrize("interpreter", ["python", "python3", "python3.14"])
def test_native_wheel_launcher_template_matches_build_verifier(interpreter: str) -> None:
    builder = load_script("build_python_artifacts")

    assert evidence.expected_native_launcher(
        "demo.module", "main", interpreter_name=interpreter
    ) == builder.expected_launcher(
        Path("/opt/venv"),
        "demo.module",
        "main",
        interpreter_name=interpreter,
    )


def test_native_wheel_verifier_accepts_typeless_regular_and_stored_v20() -> None:
    inventory, locked, content = native_wheel_case()
    stored = rewrite_native_wheel(content)
    with zipfile.ZipFile(io.BytesIO(stored), mode="r") as archive:
        entries = [(item.filename, archive.read(item)) for item in archive.infolist()]
    stored = source_zip_bytes(entries, compression=zipfile.ZIP_STORED)
    hostile_shape = bytearray(stored)
    name = "demo-1.0.dist-info/METADATA"
    local, central = zip_record_offsets(hostile_shape, name)
    hostile_shape[local + 4 : local + 6] = (20).to_bytes(2, "little")
    hostile_shape[central + 6 : central + 8] = (20).to_bytes(2, "little")
    hostile_shape[central + 38 : central + 42] = (0o600 << 16).to_bytes(4, "little")
    content = bytes(hostile_shape)

    evidence.verify_native_wheel_artifact(
        inventory,
        locked_for_content(locked, content),
        content,
    )


def test_native_wheel_verifier_accepts_stored_v20_directory_entries() -> None:
    inventory, locked, content = native_wheel_case()
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        entries = [(item.filename, archive.read(item)) for item in archive.infolist()]
    directory_names = [
        "demo/",
        "demo-1.0.dist-info/",
        "demo-1.0.dist-info/sboms/",
    ]
    changed = bytearray(
        source_zip_bytes(
            [(name, b"") for name in directory_names] + entries,
            compression=zipfile.ZIP_STORED,
        )
    )
    for name in directory_names:
        local, central = zip_record_offsets(changed, name)
        changed[local + 4 : local + 6] = (20).to_bytes(2, "little")
        changed[central + 6 : central + 8] = (20).to_bytes(2, "little")
    changed_bytes = bytes(changed)

    evidence.verify_native_wheel_artifact(
        inventory,
        locked_for_content(locked, changed_bytes),
        changed_bytes,
    )


@pytest.mark.parametrize(
    "directory_alias",
    ["demo/native.so/", "demo-1.0.dist-info/METADATA/"],
)
def test_native_wheel_verifier_rejects_file_directory_aliases(directory_alias: str) -> None:
    inventory, locked, content = native_wheel_case()
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        entries = [(item.filename, archive.read(item)) for item in archive.infolist()]
    changed = source_zip_bytes([*entries, (directory_alias, b"")])

    with pytest.raises(evidence.EvidenceError, match="duplicate or non-canonical entry name"):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed),
            changed,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("modified", "installed occurrence"),
        ("missing", "different member sets"),
        ("missing-sbom", "different member sets"),
        ("extra", "different member sets"),
    ],
)
def test_native_wheel_verifier_rejects_modified_missing_and_extra_members(
    mutation: str, message: str
) -> None:
    inventory, locked, content = native_wheel_case()
    if mutation == "modified":
        changed = rewrite_native_wheel(
            content, replacements={"demo/native.so": b"changed native payload\n"}
        )
    elif mutation == "missing":
        changed = rewrite_native_wheel(content, removals={"demo/native.so"})
    elif mutation == "missing-sbom":
        changed = rewrite_native_wheel(
            content, removals={"demo-1.0.dist-info/sboms/auditwheel.cdx.json"}
        )
    else:
        changed = rewrite_native_wheel(content, additions={"demo/extra.so": b"extra\n"})

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed),
            changed,
        )


def test_native_wheel_verifier_rejects_reassigned_payload_and_identity_drift() -> None:
    inventory, locked, content = native_wheel_case()
    reassigned = copy.deepcopy(inventory)
    reassigned["native_payloads"][0]["owner"] = "python:other@1.0"
    with pytest.raises(evidence.EvidenceError, match="no Python component"):
        evidence.verify_native_wheel_artifact(reassigned, locked, content)

    drifted = copy.deepcopy(inventory)
    drifted["wheel_installations"][0]["wheel"]["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match=r"installed occurrence|identity.*drifted"):
        evidence.verify_native_wheel_artifact(drifted, locked, content)


@pytest.mark.parametrize(
    ("archive_path", "installed_name", "payload", "message"),
    [
        (
            "demo-1.0.dist-info/METADATA",
            "METADATA",
            metadata("other", "1.0"),
            "metadata name/version does not match",
        ),
        (
            "demo-1.0.dist-info/METADATA",
            "METADATA",
            metadata("demo", "2.0"),
            "metadata name/version does not match",
        ),
        (
            "demo-1.0.dist-info/WHEEL",
            "WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp314-cp314-musllinux_1_1_x86_64\n",
            "WHEEL identity disagrees",
        ),
        (
            "demo-1.0.dist-info/WHEEL",
            "WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nBuild: 1\n"
            b"Tag: cp314-cp314-musllinux_1_2_x86_64\n",
            "WHEEL identity disagrees",
        ),
        (
            "demo-1.0.dist-info/WHEEL",
            "WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp314-cp314-musllinux_1_2_x86_64\n",
            "WHEEL identity disagrees",
        ),
    ],
)
def test_native_wheel_verifier_rejects_semantic_identity_drift(
    archive_path: str,
    installed_name: str,
    payload: bytes,
    message: str,
) -> None:
    inventory, locked, content = native_wheel_case()
    changed = rewrite_native_wheel(content, replacements={archive_path: payload})
    drifted = copy.deepcopy(inventory)
    installed_path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/" + installed_name
    rebind_installed_wheel_member(drifted, installed_path, payload)

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_native_wheel_artifact(
            drifted,
            locked_for_content(locked, changed),
            changed,
        )


def test_native_wheel_verifier_isolates_payloads_between_owners() -> None:
    first_inventory, first_locked, first_content = native_wheel_case(
        component_name="alpha", version="1.0"
    )
    second_inventory, _second_locked, _second_content = native_wheel_case(
        component_name="beta", version="2.0"
    )
    combined = {
        "platform": "linux/amd64",
        "components": first_inventory["components"] + second_inventory["components"],
        "wheel_installations": first_inventory["wheel_installations"]
        + second_inventory["wheel_installations"],
        "embedded_sboms": first_inventory["embedded_sboms"] + second_inventory["embedded_sboms"],
        "native_payloads": first_inventory["native_payloads"] + second_inventory["native_payloads"],
    }
    swapped = copy.deepcopy(combined)
    first_native, second_native = swapped["native_payloads"]
    first_native["owner"], second_native["owner"] = (
        second_native["owner"],
        first_native["owner"],
    )

    with pytest.raises(evidence.EvidenceError, match="do not exactly match installed owner"):
        evidence.verify_native_wheel_artifact(swapped, first_locked, first_content)


def test_native_wheel_verifier_rejects_unreviewed_launcher_bytes() -> None:
    inventory, locked, content = native_wheel_case(include_console_script=True)
    tampered = copy.deepcopy(inventory)
    script_entry = next(
        entry
        for entry in tampered["wheel_installations"][0]["entries"]
        if entry["path"] == "opt/venv/bin/cffi-gen-src"
    )
    script_entry["occurrence"]["sha256"] = evidence.sha256_bytes(b"hostile wrapper\n")
    script_entry["occurrence"]["size"] = len(b"hostile wrapper\n")
    script_entry["recorded_sha256"] = script_entry["occurrence"]["sha256"]
    script_entry["recorded_size"] = script_entry["occurrence"]["size"]

    with pytest.raises(evidence.EvidenceError, match="differs from reviewed bytes"):
        evidence.verify_native_wheel_artifact(tampered, locked, content)


@pytest.mark.parametrize("mutation", ["encrypted", "compression", "link"])
def test_native_wheel_verifier_rejects_unsafe_zip_metadata(mutation: str) -> None:
    inventory, locked, content = native_wheel_case()
    changed = bytearray(content)
    local, central = zip_record_offsets(changed, "demo/native.so")
    if mutation == "encrypted":
        changed[local + 6 : local + 8] = (1).to_bytes(2, "little")
        changed[central + 8 : central + 10] = (1).to_bytes(2, "little")
    elif mutation == "compression":
        changed[local + 8 : local + 10] = (99).to_bytes(2, "little")
        changed[central + 10 : central + 12] = (99).to_bytes(2, "little")
    else:
        changed[central + 38 : central + 42] = ((stat.S_IFLNK | 0o777) << 16).to_bytes(4, "little")
    changed_bytes = bytes(changed)

    with pytest.raises(evidence.EvidenceError, match=r"metadata|compression|entry type"):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed_bytes),
            changed_bytes,
        )


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("../escape", "unsafe archive path"),
        ("other-1.0.dist-info/METADATA", "foreign dist-info"),
        ("demo-1.0.dist-info/INSTALLER", "installer-generated metadata"),
        ("demo/cache.pyc", "contains bytecode"),
    ],
)
def test_native_wheel_verifier_rejects_unsafe_or_foreign_members(path: str, message: str) -> None:
    inventory, locked, content = native_wheel_case()
    changed = rewrite_native_wheel(content, additions={path: b"hostile\n"})

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_native_wheel_artifact(
            inventory,
            locked_for_content(locked, changed),
            changed,
        )


def test_native_wheel_verifier_bounds_member_size_and_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory, locked, content = native_wheel_case()
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", 4)
    with pytest.raises(evidence.EvidenceError, match="resource limits"):
        evidence.verify_native_wheel_artifact(inventory, locked, content)

    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_COMPRESSION_RATIO", 1)
    with pytest.raises(evidence.EvidenceError, match="resource limits"):
        evidence.verify_native_wheel_artifact(inventory, locked, content)


def test_native_wheel_retention_is_deterministic_and_manifest_bound(tmp_path: Path) -> None:
    inventory, locked, content = native_wheel_case()
    records = []
    url_chain = (locked["url"], "https://files.pythonhosted.org/resolved/demo.whl")
    wheel_path = f"artifacts/native-wheels/demo/1.0/{locked['filename']}"
    sbom_archive_path = "demo-1.0.dist-info/sboms/auditwheel.cdx.json"
    sbom_path = "artifacts/native-wheels/demo/1.0/embedded-sboms/" + sbom_archive_path
    expected_sbom = {
        "owner": "python:demo@1.0",
        "platform": "linux/amd64",
        "url": locked["url"],
        "archive_path": sbom_archive_path,
        "installed_occurrence": evidence.payload_record_projection(inventory["embedded_sboms"][0]),
        "size": len(cyclonedx_sbom()),
        "sha256": evidence.sha256_bytes(cyclonedx_sbom()),
        "urls": list(url_chain),
        "path": sbom_path,
    }
    for suffix in ("one", "two"):
        root = tmp_path / suffix
        root.mkdir()
        record = evidence.retain_native_wheel_artifact(
            root,
            inventory,
            locked,
            content,
            budget=evidence.BundleBudget(),
            urls=url_chain,
        )
        records.append(record)
        assert record == {
            "owner": "python:demo@1.0",
            "platform": "linux/amd64",
            "url": locked["url"],
            "filename": locked["filename"],
            "size": len(content),
            "sha256": evidence.sha256_bytes(content),
            "build": "",
            "tags": ["cp314-cp314-musllinux_1_2_x86_64"],
            "generated_files": [],
            "urls": list(url_chain),
            "path": wheel_path,
            "embedded_sboms": [expected_sbom],
        }
        assert (root / record["path"]).read_bytes() == content
        assert record["sha256"] == evidence.sha256_file(
            root / record["path"], max_bytes=evidence.MAX_DOWNLOAD_BYTES
        )
        for sbom in record["embedded_sboms"]:
            retained = root / sbom["path"]
            assert retained.read_bytes() == cyclonedx_sbom()
            assert sbom["sha256"] == evidence.sha256_file(
                retained, max_bytes=evidence.MAX_ARCHIVE_MEMBER_BYTES
            )
            assert sbom["urls"] == record["urls"]

    assert evidence.canonical_json(records[0]) == evidence.canonical_json(records[1])


def test_native_wheel_retention_ignores_unrelated_owner_input_order(tmp_path: Path) -> None:
    first_inventory, first_locked, first_content = native_wheel_case(
        component_name="alpha", version="1.0"
    )
    second_inventory, _second_locked, _second_content = native_wheel_case(
        component_name="beta", version="2.0"
    )
    sequence_fields = (
        "components",
        "wheel_installations",
        "embedded_sboms",
        "native_payloads",
    )
    combined: dict[str, Any] = {"platform": "linux/amd64"}
    for field in sequence_fields:
        combined[field] = [*first_inventory[field], *second_inventory[field]]
    reversed_inventory = copy.deepcopy(combined)
    for field in sequence_fields:
        reversed_inventory[field] = list(reversed(reversed_inventory[field]))

    records = []
    for suffix, inventory in (("forward", combined), ("reversed", reversed_inventory)):
        root = tmp_path / suffix
        root.mkdir()
        records.append(
            evidence.retain_native_wheel_artifact(
                root,
                inventory,
                first_locked,
                first_content,
                budget=evidence.BundleBudget(),
            )
        )

    assert evidence.canonical_json(records[0]) == evidence.canonical_json(records[1])


@pytest.mark.parametrize(
    "urls",
    [
        (),
        ("https://files.pythonhosted.org/not-requested.whl",),
        ("https://files.pythonhosted.org/requested.whl", "http://example.com/redirect.whl"),
    ],
)
def test_native_wheel_retention_rejects_invalid_url_chains(
    tmp_path: Path, urls: tuple[str, ...]
) -> None:
    inventory, locked, content = native_wheel_case()
    if urls and urls[0].endswith("/requested.whl"):
        urls = (locked["url"], *urls[1:])

    with pytest.raises(evidence.EvidenceError, match=r"URL chain|credential-free HTTPS"):
        evidence.retain_native_wheel_artifact(
            tmp_path,
            inventory,
            locked,
            content,
            budget=evidence.BundleBudget(),
            urls=urls,
        )


def test_native_component_coverage_ledger_resolves_owner_native_set_and_lock() -> None:
    inventories, locked, policy, lock_sources = native_component_coverage_case()
    inventory = inventories["linux/amd64"]

    evidence.validate_native_component_policy_schema(policy)
    ledger = evidence.verify_native_component_lock_bindings(
        inventory,
        policy,
        [locked["linux/amd64"]],
        lock_sources,
    )

    assert ledger["complete"] is True
    assert [record["owner"] for record in ledger["resolved_owners"]] == ["python:demo@1.0"]
    assert ledger["unresolved_owners"] == []


def test_native_component_policy_accepts_explicit_empty_sbom_and_review_sets() -> None:
    inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    policy["native_component_sources"] = {}
    for platform in ("linux/amd64", "linux/arm64"):
        inventories[platform]["embedded_sboms"] = []
        owner = policy["native_component_coverage"][platform][0]
        owner["sboms"] = []
        owner["component_reviews"] = []
        owner["payload_dispositions"] = [
            {"kind": "owner", "role": payload["role"]} for payload in owner["native_payloads"]
        ]

    evidence.validate_native_component_policy_schema(policy)
    ledger = evidence.native_component_coverage_ledger(inventories["linux/amd64"], policy)

    assert ledger["complete"] is True
    assert ledger["resolved_owners"][0]["sboms"] == []
    assert ledger["resolved_owners"][0]["component_reviews"] == []


@pytest.mark.parametrize("field", ("sboms", "component_reviews"))
def test_native_component_policy_requires_explicit_empty_evidence_sets(field: str) -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    for platform_records in policy["native_component_coverage"].values():
        platform_records[0].pop(field)

    with pytest.raises(evidence.EvidenceError, match="unexpected schema shape"):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_policy_rejects_owner_without_native_or_sbom_surface() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    policy["native_component_sources"] = {}
    for platform_records in policy["native_component_coverage"].values():
        owner = platform_records[0]
        owner["native_payloads"] = []
        owner["sboms"] = []
        owner["component_reviews"] = []
        owner["payload_dispositions"] = []

    with pytest.raises(evidence.EvidenceError, match="no native payload or SBOM surface"):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_coverage_rejects_unexpected_observed_sbom_for_native_only_owner() -> None:
    inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    policy["native_component_sources"] = {}
    for platform_records in policy["native_component_coverage"].values():
        owner = platform_records[0]
        owner["sboms"] = []
        owner["component_reviews"] = []
        owner["payload_dispositions"] = [
            {"kind": "owner", "role": payload["role"]} for payload in owner["native_payloads"]
        ]

    with pytest.raises(evidence.EvidenceError, match="does not exactly cover SBOMs"):
        evidence.native_component_coverage_ledger(inventories["linux/amd64"], policy)


@pytest.mark.parametrize(
    ("platform", "path", "role"),
    (
        (
            "linux/amd64",
            (
                "opt/venv/lib/python3.14/site-packages/greenlet/"
                "_greenlet.cpython-314-x86_64-linux-musl.so"
            ),
            "greenlet/_greenlet.cpython-314.so",
        ),
        (
            "linux/arm64",
            (
                "opt/venv/lib/python3.14/site-packages/greenlet/tests/"
                "_test_extension.cpython-314-aarch64-linux-musl.so"
            ),
            "greenlet/tests/_test_extension.cpython-314.so",
        ),
        (
            "linux/amd64",
            ("opt/venv/lib/python3.14/site-packages/greenlet.libs/libgcc_s-0cd532bd.so.1"),
            "greenlet.libs/libgcc_s.so.1",
        ),
        (
            "linux/arm64",
            ("opt/venv/lib/python3.14/site-packages/greenlet.libs/libstdc++-85f2cd6d.so.6.0.33"),
            "greenlet.libs/libstdc++.so.6.0.33",
        ),
        (
            "linux/amd64",
            "opt/venv/lib/python3.14/site-packages/demo/native.abi3.so",
            "demo/native.abi3.so",
        ),
    ),
)
def test_native_component_payload_role_is_a_platform_neutral_path_projection(
    platform: str, path: str, role: str
) -> None:
    assert evidence.native_component_payload_role(path, platform, "test payload") == role


@pytest.mark.parametrize(
    ("platform", "path", "message"),
    (
        (
            "linux/amd64",
            "usr/local/lib/python3.14/site-packages/demo/native.so",
            "outside the reviewed site-packages root",
        ),
        (
            "linux/amd64",
            "opt/venv/lib/python3.14/site-packages/../escape.so",
            "unsafe archive path",
        ),
        (
            "linux/amd64",
            ("opt/venv/lib/python3.14/site-packages/demo/native.cpython-314-aarch64-linux-musl.so"),
            "ABI suffix conflicts with linux/amd64",
        ),
        (
            "linux/amd64",
            "opt/venv/lib/python3.14/site-packages/demo.libs/libdemo-ABCDEF12.so.1",
            "invalid auditwheel hash",
        ),
        (
            "linux/arm64",
            "opt/venv/lib/python3.14/site-packages/demo.libs/libdemo-abc1234.so.1",
            "invalid auditwheel hash",
        ),
    ),
)
def test_native_component_payload_role_rejects_unsafe_or_ambiguous_paths(
    platform: str, path: str, message: str
) -> None:
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.native_component_payload_role(path, platform, "test payload")


def test_native_component_coverage_ledger_rejects_unconfigured_owner() -> None:
    inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    policy["native_component_coverage"] = {"linux/amd64": [], "linux/arm64": []}
    policy["native_component_sources"] = {}

    with pytest.raises(evidence.EvidenceError, match="must exactly match observed owners"):
        evidence.native_component_coverage_ledger(inventories["linux/amd64"], policy)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing_payload", "does not exactly cover payloads"),
        ("stale_payload", "does not exactly cover payloads"),
        ("stale_sbom", "does not exactly cover SBOMs"),
        ("stale_owner", "must exactly match observed owners"),
        ("wrong_component", "differs from embedded SBOM observation"),
    ),
)
def test_native_component_coverage_rejects_missing_extra_or_stale_inventory_bindings(
    mutation: str, message: str
) -> None:
    inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    if mutation == "missing_payload":
        inventories["linux/amd64"]["native_payloads"].pop()
    elif mutation == "stale_payload":
        inventories["linux/amd64"]["native_payloads"][0]["sha256"] = "0" * 64
    elif mutation == "stale_sbom":
        inventories["linux/amd64"]["embedded_sboms"][0]["sha256"] = "0" * 64
    elif mutation == "stale_owner":
        for platform_records in policy["native_component_coverage"].values():
            platform_record = platform_records[0]
            platform_record["owner"] = "python:missing@1.0"
            platform_record["wheel"]["url"] = platform_record["wheel"]["url"].replace(
                "demo-1.0-", "missing-1.0-"
            )
    else:
        observation = inventories["linux/amd64"]["embedded_sboms"][0]["cyclonedx"]
        observation["components"][0]["version"] = "9.9.9"
        body = {
            field: observation[field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        observation["observation_sha256"] = evidence.sha256_bytes(evidence.canonical_json(body))

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.native_component_coverage_ledger(inventories["linux/amd64"], policy)


def test_native_component_policy_rejects_cross_platform_conflicts_and_duplicate_payloads() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    crossed = copy.deepcopy(policy)
    crossed["native_component_coverage"]["linux/arm64"][0]["wheel"] = copy.deepcopy(
        crossed["native_component_coverage"]["linux/amd64"][0]["wheel"]
    )
    with pytest.raises(evidence.EvidenceError, match="conflicts with linux/arm64"):
        evidence.validate_native_component_policy_schema(crossed)

    semantic_conflict = copy.deepcopy(policy)
    semantic_conflict["native_component_coverage"]["linux/arm64"][0]["component_reviews"][0][
        "reviewed_license"
    ] = "Apache-2.0"
    with pytest.raises(evidence.EvidenceError, match="semantics differ across platforms"):
        evidence.validate_native_component_policy_schema(semantic_conflict)

    duplicate_path = copy.deepcopy(policy)
    owner = duplicate_path["native_component_coverage"]["linux/amd64"][0]
    repeated_path = copy.deepcopy(owner["native_payloads"][0])
    owner["native_payloads"].append(repeated_path)
    with pytest.raises(evidence.EvidenceError, match="repeats payload path"):
        evidence.validate_native_component_policy_schema(duplicate_path)

    duplicate_role = copy.deepcopy(policy)
    owner = duplicate_role["native_component_coverage"]["linux/amd64"][0]
    repeated_role = copy.deepcopy(owner["native_payloads"][0])
    repeated_role["path"] = "opt/venv/lib/python3.14/site-packages/demo.libs/libdemo-deadbeef.so.1"
    owner["native_payloads"].append(repeated_role)
    with pytest.raises(evidence.EvidenceError, match="invalid payload role"):
        evidence.validate_native_component_policy_schema(duplicate_role)


def test_native_component_policy_rejects_cross_platform_payload_role_differences() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    arm_owner = policy["native_component_coverage"]["linux/arm64"][0]
    arm_owner["native_payloads"][1]["path"] = (
        "opt/venv/lib/python3.14/site-packages/demo/other-native.so"
    )
    arm_owner["native_payloads"][1]["role"] = "demo/other-native.so"
    arm_owner["native_payloads"].sort(key=lambda record: record["role"])
    disposition = next(
        record for record in arm_owner["payload_dispositions"] if record["role"] == "demo/native.so"
    )
    disposition["role"] = "demo/other-native.so"
    arm_owner["payload_dispositions"].sort(key=lambda record: record["role"])

    with pytest.raises(evidence.EvidenceError, match="semantics differ across platforms"):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_policy_rejects_cross_platform_source_drift() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()

    source_drift = copy.deepcopy(policy)
    arm_owner = source_drift["native_component_coverage"]["linux/arm64"][0]
    arm_owner["owner_source"]["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="semantics differ across platforms"):
        evidence.validate_native_component_policy_schema(source_drift)


def test_native_component_policy_rejects_same_set_cross_platform_role_swaps() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    arm_owner = policy["native_component_coverage"]["linux/arm64"][0]
    original_roles = {record["role"] for record in arm_owner["native_payloads"]}
    first, second = arm_owner["native_payloads"]
    first["role"], second["role"] = second["role"], first["role"]
    arm_owner["native_payloads"].sort(key=lambda record: record["role"])

    assert {record["role"] for record in arm_owner["native_payloads"]} == original_roles
    with pytest.raises(evidence.EvidenceError, match="payload role does not match its path"):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_policy_rejects_per_component_payload_fields() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    for platform_records in policy["native_component_coverage"].values():
        owner = platform_records[0]
        owner["sboms"][0]["observation"]["components"][0]["payloads"] = [
            owner["native_payloads"][0]
        ]

    with pytest.raises(evidence.EvidenceError, match="CycloneDX component projection is invalid"):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_policy_rejects_nested_custom_license_references() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    for platform_records in policy["native_component_coverage"].values():
        platform_records[0]["component_reviews"][0]["reviewed_license"] = (
            "LicenseRef-Native-Unreviewed"
        )

    with pytest.raises(evidence.EvidenceError, match="invalid reviewed license"):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_policy_rejects_missing_or_unsafe_payload_roles() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()

    legacy = copy.deepcopy(policy)
    legacy["native_component_coverage"]["linux/amd64"][0]["native_payloads"][0].pop("role")
    with pytest.raises(evidence.EvidenceError, match="unexpected schema shape"):
        evidence.validate_native_component_policy_schema(legacy)

    unsafe = copy.deepcopy(policy)
    unsafe["native_component_coverage"]["linux/amd64"][0]["native_payloads"][0]["role"] = (
        "../escape"
    )
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.validate_native_component_policy_schema(unsafe)

    overlong = copy.deepcopy(policy)
    overlong["native_component_coverage"]["linux/amd64"][0]["native_payloads"][0]["role"] = "a" * (
        evidence.MAX_PATH_BYTES + 1
    )
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.validate_native_component_policy_schema(overlong)


def test_native_component_policy_rejects_unknown_unused_and_mutable_sources() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    missing = copy.deepcopy(policy)
    missing["native_component_sources"] = {}
    with pytest.raises(evidence.EvidenceError, match="unknown source"):
        evidence.validate_native_component_policy_schema(missing)

    unused = copy.deepcopy(policy)
    extra = copy.deepcopy(next(iter(unused["native_component_sources"].values())))
    extra["origin"] = "unused"
    extra["version"] = "9-r0"
    extra["recipe"]["url"] = (
        "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
        f"{'4' * 40}/aports-{'4' * 40}.tar.gz?path=main/unused"
    )
    extra["distfiles"][0].update(
        {
            "filename": "unused-9.tar.xz",
            "url": "https://distfiles.alpinelinux.org/distfiles/v3.22/unused-9.tar.xz",
        }
    )
    unused["native_component_sources"]["alpine:unused@9-r0"] = extra
    with pytest.raises(evidence.EvidenceError, match="missing, extra, or unused"):
        evidence.validate_native_component_policy_schema(unused)

    mutable = copy.deepcopy(policy)
    source = next(iter(mutable["native_component_sources"].values()))
    source["recipe"]["url"] = "https://gitlab.alpinelinux.org/alpine/aports/archive/main.tar.gz"
    with pytest.raises(evidence.EvidenceError, match="not commit-pinned"):
        evidence.validate_native_component_policy_schema(mutable)

    unknown = copy.deepcopy(policy)
    unknown["native_component_coverage"]["linux/amd64"][0]["reviewed_by"] = "nobody"
    with pytest.raises(evidence.EvidenceError, match="unexpected schema shape"):
        evidence.validate_native_component_policy_schema(unknown)

    unknown_source = copy.deepcopy(policy)
    next(iter(unknown_source["native_component_sources"].values()))["reviewed_by"] = "nobody"
    with pytest.raises(evidence.EvidenceError, match="unexpected schema shape"):
        evidence.validate_native_component_policy_schema(unknown_source)


def test_native_component_source_union_accepts_all_v7_variants() -> None:
    alpine_commit = "1" * 40
    alpine_source = {
        "kind": "alpine-aports",
        "origin": "openldap",
        "version": "2.6.8-r0",
        "aports_commit": alpine_commit,
        "distfiles_release": "v3.22",
        "recipe": {
            "url": (
                "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
                f"{alpine_commit}/aports-{alpine_commit}.tar.gz?path=main/openldap"
            ),
            "sha256": "2" * 64,
            "size": 1024,
        },
        "distfiles": [
            {
                "filename": "openldap-2.6.8.tar.gz",
                "url": ("https://distfiles.alpinelinux.org/distfiles/v3.22/openldap-2.6.8.tar.gz"),
                "sha512": "3" * 128,
                "size": 2048,
            },
            {
                "filename": "openldap-fix.patch",
                "url": ("https://distfiles.alpinelinux.org/distfiles/v3.22/openldap-fix.patch"),
                "sha512": "4" * 128,
                "size": 512,
            },
        ],
        "allowed_recipe_links": [
            {
                "path": "main/openldap/openldap-lloadd.pre-install",
                "type": "symlink",
                "target": "main/openldap/openldap.pre-install",
            }
        ],
        "observed_license": "OLDAP-2.8",
        "notices": [
            {
                "member": "openldap-2.6.8/LICENSE",
                "sha256": "5" * 64,
                "size": 100,
            }
        ],
    }
    crate_source = {
        "kind": "crates-io",
        "name": "demo-crate",
        "version": "1.2.3",
        "crate": {
            "url": "https://static.crates.io/crates/demo-crate/demo-crate-1.2.3.crate",
            "sha256": "6" * 64,
            "size": 4096,
        },
        "manifest": {
            "member": "demo-crate-1.2.3/Cargo.toml",
            "sha256": "7" * 64,
            "size": 200,
        },
        "raw_license": "MIT/Apache-2.0",
        "normalized_license": "MIT OR Apache-2.0",
        "notices": [
            {
                "member": "demo-crate-1.2.3/LICENSE-MIT",
                "sha256": "8" * 64,
                "size": 300,
            }
        ],
    }
    owner_source_id = "owner-sdist:python:demo@1.0#src/native"
    owner_source = {
        "kind": "owner-sdist-subpath",
        "owner": "python:demo@1.0",
        "path": "src/native",
        "tree_sha256": "9" * 64,
        "member_count": 4,
        "expanded_size": 8192,
        "notices": [
            {
                "member": "src/native/LICENSE",
                "sha256": "a" * 64,
                "size": 400,
            }
        ],
    }
    upstream_source = {
        "kind": "checksummed-upstream-release",
        "name": "openssl",
        "version": "4.0.1",
        "archive": {
            "url": "https://www.openssl.org/source/openssl-4.0.1.tar.gz",
            "sha256": "b" * 64,
            "size": 16384,
        },
        "checksum_document": {
            "url": "https://www.openssl.org/source/openssl-4.0.1.tar.gz.sha256",
            "sha256": "c" * 64,
            "size": 100,
        },
        "checksum_filename": "openssl-4.0.1.tar.gz",
        "notices": [
            {
                "member": "openssl-4.0.1/LICENSE.txt",
                "sha256": "d" * 64,
                "size": 500,
            }
        ],
    }
    sources = {
        "alpine:openldap@2.6.8-r0": alpine_source,
        "crates-io:demo-crate@1.2.3": crate_source,
        owner_source_id: owner_source,
        "upstream-release:openssl@4.0.1": upstream_source,
    }

    assert evidence.native_component_sources({"native_component_sources": sources}) == sources


def test_native_component_source_union_rejects_legacy_and_ambiguous_records() -> None:
    _inventories, _locked, policy, _lock_sources = _native_component_fixture_inputs()
    legacy_source = next(iter(policy["native_component_sources"].values()))
    with pytest.raises(evidence.EvidenceError, match="unexpected schema shape"):
        evidence.native_component_sources(
            {"native_component_sources": {"alpine:demo-native@1.2.3-r0": legacy_source}}
        )

    ambiguous = {
        "kind": "checksummed-upstream-release",
        "name": "demo",
        "version": "1.0",
        "archive": {
            "url": "https://example.com/demo-1.0.tar.gz",
            "sha256": "1" * 64,
            "size": 10,
        },
        "checksum_document": {
            "url": "https://example.com/SHA256SUMS",
            "sha256": "2" * 64,
            "size": 10,
        },
        "checksum_filename": "different.tar.gz",
        "notices": [{"member": "LICENSE", "sha256": "3" * 64, "size": 10}],
    }
    with pytest.raises(evidence.EvidenceError, match="checksum filename"):
        evidence.native_component_sources(
            {"native_component_sources": {"upstream-release:demo@1.0": ambiguous}}
        )


@pytest.mark.parametrize(
    ("document", "expected_sha256", "message"),
    (
        (
            b"a" * 64 + b" *demo-1.0.tar.gz\n",
            "a" * 64,
            None,
        ),
        (
            b"a" * 64 + b" *demo-1.0.tar.gz\n" + b"a" * 64 + b"  demo-1.0.tar.gz\n",
            "a" * 64,
            "exactly one matching filename",
        ),
        (
            b"a" * 64 + b" *demo-1.0.tar.gz\n",
            "b" * 64,
            "digest differs",
        ),
        (
            b"not a checksum\n",
            "a" * 64,
            "malformed record",
        ),
    ),
)
def test_upstream_checksum_document_is_exact_and_unambiguous(
    document: bytes,
    expected_sha256: str,
    message: str | None,
) -> None:
    if message is None:
        evidence.verify_upstream_checksum_document(
            document,
            filename="demo-1.0.tar.gz",
            expected_sha256=expected_sha256,
        )
        return
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_upstream_checksum_document(
            document,
            filename="demo-1.0.tar.gz",
            expected_sha256=expected_sha256,
        )


def test_crates_io_archive_binds_manifest_license_and_notices() -> None:
    manifest = b'[package]\nname = "demo-crate"\nversion = "1.2.3"\nlicense = "MIT OR Apache-2.0"\n'
    notice = b"Copyright demo\n"
    archive = tar_bytes(
        {
            "demo-crate-1.2.3/Cargo.toml": manifest,
            "demo-crate-1.2.3/LICENSE": notice,
            "demo-crate-1.2.3/src/lib.rs": b"pub fn demo() {}\n",
        }
    )
    source = {
        "name": "demo-crate",
        "version": "1.2.3",
        "manifest": {
            "member": "demo-crate-1.2.3/Cargo.toml",
            "sha256": evidence.sha256_bytes(manifest),
            "size": len(manifest),
        },
        "raw_license": "MIT OR Apache-2.0",
        "notices": [
            {
                "member": "demo-crate-1.2.3/LICENSE",
                "sha256": evidence.sha256_bytes(notice),
                "size": len(notice),
            }
        ],
    }
    found = evidence.verify_crates_io_archive(
        archive,
        source_id="crates-io:demo-crate@1.2.3",
        source=source,
    )
    assert found == {
        "demo-crate-1.2.3/Cargo.toml": manifest,
        "demo-crate-1.2.3/LICENSE": notice,
    }

    changed = copy.deepcopy(source)
    changed["raw_license"] = "MIT"
    with pytest.raises(evidence.EvidenceError, match="identity or license differs"):
        evidence.verify_crates_io_archive(
            archive,
            source_id="crates-io:demo-crate@1.2.3",
            source=changed,
        )

    linked = tar_bytes(
        {"demo-crate-1.2.3/Cargo.toml": manifest},
        links={"demo-crate-1.2.3/LICENSE": "Cargo.toml"},
    )
    with pytest.raises(evidence.EvidenceError, match="unsupported entry"):
        evidence.verify_crates_io_archive(
            linked,
            source_id="crates-io:demo-crate@1.2.3",
            source=source,
        )


def test_owner_sdist_subtree_uses_a_canonical_link_free_manifest() -> None:
    source_file = b"int demo(void) { return 0; }\n"
    header_file = b"int demo(void);\n"
    archive = tar_bytes(
        {
            "demo-1.0/src/native/demo.c": source_file,
            "demo-1.0/src/native/include/demo.h": header_file,
            "demo-1.0/README.md": b"demo\n",
        },
        directories=[
            "demo-1.0",
            "demo-1.0/src",
            "demo-1.0/src/native",
            "demo-1.0/src/native/include",
        ],
    )
    manifest = [
        {
            "path": "demo.c",
            "type": "file",
            "mode": 0o644,
            "size": len(source_file),
            "sha256": evidence.sha256_bytes(source_file),
        },
        {
            "path": "include",
            "type": "directory",
            "mode": 0o755,
            "size": 0,
            "sha256": None,
        },
        {
            "path": "include/demo.h",
            "type": "file",
            "mode": 0o644,
            "size": len(header_file),
            "sha256": evidence.sha256_bytes(header_file),
        },
    ]
    source = {
        "path": "src/native",
        "member_count": len(manifest),
        "expanded_size": len(source_file) + len(header_file),
        "tree_sha256": evidence.sha256_bytes(evidence.canonical_json(manifest)),
    }
    assert (
        evidence.verify_owner_sdist_subtree(
            archive,
            source_id="owner-sdist:python:demo@1.0#src/native",
            source=source,
            archive_name="demo-1.0.tar.gz",
        )
        == manifest
    )

    linked = tar_bytes(
        {"demo-1.0/src/native/demo.c": source_file},
        links={"demo-1.0/docs/latest": "README.md"},
    )
    with pytest.raises(evidence.EvidenceError, match="unsupported entry"):
        evidence.verify_owner_sdist_subtree(
            linked,
            source_id="owner-sdist:python:demo@1.0#src/native",
            source=source,
            archive_name="demo-1.0.tar.gz",
        )

    multiple_roots = tar_bytes(
        {
            "demo-1.0/src/native/demo.c": source_file,
            "other-root/README": b"other\n",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="one top-level root"):
        evidence.verify_owner_sdist_subtree(
            multiple_roots,
            source_id="owner-sdist:python:demo@1.0#src/native",
            source=source,
            archive_name="demo-1.0.tar.gz",
        )


def test_owner_sdist_zip_subtree_tracks_top_level_roots() -> None:
    source_file = b"int demo(void) { return 0; }\n"
    manifest = [
        {
            "path": "demo.c",
            "type": "file",
            "mode": 0o644,
            "size": len(source_file),
            "sha256": evidence.sha256_bytes(source_file),
        }
    ]
    source = {
        "path": "src/native",
        "member_count": 1,
        "expanded_size": len(source_file),
        "tree_sha256": evidence.sha256_bytes(evidence.canonical_json(manifest)),
    }
    archive = source_zip_bytes(
        [
            ("demo-1.0/", b""),
            ("demo-1.0/src/", b""),
            ("demo-1.0/src/native/", b""),
            ("demo-1.0/src/native/demo.c", source_file),
            ("demo-1.0/README.md", b"demo\n"),
        ]
    )

    assert (
        evidence.verify_owner_sdist_subtree(
            archive,
            source_id="owner-sdist:python:demo@1.0#src/native",
            source=source,
            archive_name="demo-1.0.zip",
        )
        == manifest
    )

    multiple_roots = source_zip_bytes(
        [
            ("demo-1.0/src/native/demo.c", source_file),
            ("other-root/README.md", b"other\n"),
        ]
    )
    with pytest.raises(evidence.EvidenceError, match="one top-level root"):
        evidence.verify_owner_sdist_subtree(
            multiple_roots,
            source_id="owner-sdist:python:demo@1.0#src/native",
            source=source,
            archive_name="demo-1.0.zip",
        )


def test_native_component_v7_policy_separates_observation_review_and_closure() -> None:
    policy = native_component_v7_policy_case()
    evidence.validate_native_component_policy_schema(policy)

    missing_review = copy.deepcopy(policy)
    for records in missing_review["native_component_coverage"].values():
        records[0]["component_reviews"] = []
    with pytest.raises(evidence.EvidenceError, match="does not dispose every SBOM observation"):
        evidence.validate_native_component_policy_schema(missing_review)

    drifted_license = copy.deepcopy(policy)
    drifted_license["native_component_coverage"]["linux/arm64"][0]["sboms"][0]["observation"][
        "components"
    ][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    body = {
        field: drifted_license["native_component_coverage"]["linux/arm64"][0]["sboms"][0][
            "observation"
        ][field]
        for field in (
            "metadata_component",
            "metadata_root_echo",
            "upstream_invalid_duplicate_bom_ref",
            "components",
        )
    }
    drifted_license["native_component_coverage"]["linux/arm64"][0]["sboms"][0]["observation"][
        "observation_sha256"
    ] = evidence.sha256_bytes(evidence.canonical_json(body))
    drifted_owner = drifted_license["native_component_coverage"]["linux/arm64"][0]
    rebind_policy_observation_digest(
        drifted_owner,
        sbom_path=drifted_owner["sboms"][0]["path"],
        observation_sha256=drifted_owner["sboms"][0]["observation"]["observation_sha256"],
    )
    with pytest.raises(evidence.EvidenceError, match="semantics differ across platforms"):
        evidence.validate_native_component_policy_schema(drifted_license)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("observation_sha256", "0" * 64, "unknown observation"),
        ("bom_ref", "unrelated-occurrence", "unknown observation"),
        ("purl", "pkg:generic/other@9.9.9", "unknown observation"),
        ("identity_kind", "purl", "unexpected schema shape"),
    ),
)
def test_native_component_v7_review_references_bind_the_exact_observation(
    field: str,
    value: str,
    message: str,
) -> None:
    policy = native_component_v7_policy_case()
    for records in policy["native_component_coverage"].values():
        reference = records[0]["component_reviews"][0]["observations"][0]
        reference[field] = value
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.validate_native_component_policy_schema(policy)


def test_native_component_v7_crate_review_binds_purl_hash_and_normalized_license() -> None:
    policy = native_component_v7_policy_case()
    source_id = "crates-io:demo-crate@1.2.3"
    crate_digest = "a" * 64
    policy["native_component_sources"] = {
        source_id: {
            "kind": "crates-io",
            "name": "demo-crate",
            "version": "1.2.3",
            "crate": {
                "url": ("https://static.crates.io/crates/demo-crate/demo-crate-1.2.3.crate"),
                "sha256": crate_digest,
                "size": 100,
            },
            "manifest": {
                "member": "demo-crate-1.2.3/Cargo.toml",
                "sha256": "b" * 64,
                "size": 100,
            },
            "raw_license": "MIT OR Apache-2.0",
            "normalized_license": "MIT OR Apache-2.0",
            "notices": [
                {
                    "member": "demo-crate-1.2.3/LICENSE",
                    "sha256": "c" * 64,
                    "size": 100,
                }
            ],
        }
    }
    for records in policy["native_component_coverage"].values():
        owner = records[0]
        sbom = owner["sboms"][0]
        component = sbom["observation"]["components"][0]
        component.update(
            {
                "name": "demo-crate",
                "version": "1.2.3",
                "purl": "pkg:cargo/demo-crate@1.2.3",
                "bom_ref": "pkg:cargo/demo-crate@1.2.3",
                "hashes": [{"alg": "SHA-256", "content": crate_digest}],
                "licenses": [{"expression": "MIT OR Apache-2.0"}],
            }
        )
        body = {
            field: sbom["observation"][field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        sbom["observation"]["observation_sha256"] = evidence.sha256_bytes(
            evidence.canonical_json(body)
        )
        reference = evidence.retained_observation_reference(
            sbom["path"],
            sbom["observation"]["observation_sha256"],
            component,
        )
        owner["component_reviews"] = [
            {
                "observations": [reference],
                "source": source_id,
                "reviewed_license": "MIT OR Apache-2.0",
            }
        ]
        owner["cargo_lock"] = {
            "member": "demo-1.0/Cargo.lock",
            "sha256": "e" * 64,
            "size": 100,
            "source_ids": [source_id],
            "non_sbom_packages": [],
        }
        owner["payload_dispositions"][0]["observations"] = [reference]
    evidence.validate_native_component_policy_schema(policy)

    wrong_hash = copy.deepcopy(policy)
    for records in wrong_hash["native_component_coverage"].values():
        records[0]["sboms"][0]["observation"]["components"][0]["hashes"][0]["content"] = "d" * 64
        sbom = records[0]["sboms"][0]
        body = {
            field: sbom["observation"][field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        sbom["observation"]["observation_sha256"] = evidence.sha256_bytes(
            evidence.canonical_json(body)
        )
        rebind_policy_observation_digest(
            records[0],
            sbom_path=sbom["path"],
            observation_sha256=sbom["observation"]["observation_sha256"],
        )
    with pytest.raises(evidence.EvidenceError, match="crate review differs"):
        evidence.validate_native_component_policy_schema(wrong_hash)

    conflicting_hash = copy.deepcopy(policy)
    for records in conflicting_hash["native_component_coverage"].values():
        owner = records[0]
        sbom = owner["sboms"][0]
        sbom["observation"]["components"][0]["hashes"].append(
            {"alg": "SHA-256", "content": "d" * 64}
        )
        body = {
            field: sbom["observation"][field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        sbom["observation"]["observation_sha256"] = evidence.sha256_bytes(
            evidence.canonical_json(body)
        )
        rebind_policy_observation_digest(
            owner,
            sbom_path=sbom["path"],
            observation_sha256=sbom["observation"]["observation_sha256"],
        )
    with pytest.raises(evidence.EvidenceError, match="repeats a hash algorithm"):
        evidence.validate_native_component_policy_schema(conflicting_hash)

    wrong_observed_license = copy.deepcopy(policy)
    for records in wrong_observed_license["native_component_coverage"].values():
        owner = records[0]
        sbom = owner["sboms"][0]
        sbom["observation"]["components"][0]["licenses"] = [{"expression": "GPL-3.0-only"}]
        body = {
            field: sbom["observation"][field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        sbom["observation"]["observation_sha256"] = evidence.sha256_bytes(
            evidence.canonical_json(body)
        )
        rebind_policy_observation_digest(
            owner,
            sbom_path=sbom["path"],
            observation_sha256=sbom["observation"]["observation_sha256"],
        )
    with pytest.raises(evidence.EvidenceError, match="crate review differs"):
        evidence.validate_native_component_policy_schema(wrong_observed_license)


def test_native_component_v7_crate_review_requires_exact_cargo_lock_context() -> None:
    policy = native_component_v7_policy_case()
    source_id = "crates-io:demo-crate@1.2.3"
    source = {
        "kind": "crates-io",
        "name": "demo-crate",
        "version": "1.2.3",
        "crate": {
            "url": "https://static.crates.io/crates/demo-crate/demo-crate-1.2.3.crate",
            "sha256": "a" * 64,
            "size": 100,
        },
        "manifest": {
            "member": "demo-crate-1.2.3/Cargo.toml",
            "sha256": "b" * 64,
            "size": 100,
        },
        "raw_license": "MIT",
        "normalized_license": "MIT",
        "notices": [
            {
                "member": "demo-crate-1.2.3/LICENSE",
                "sha256": "c" * 64,
                "size": 100,
            }
        ],
    }
    policy["native_component_sources"] = {source_id: source}
    for records in policy["native_component_coverage"].values():
        owner = records[0]
        sbom = owner["sboms"][0]
        component = sbom["observation"]["components"][0]
        component.update(
            {
                "name": "demo-crate",
                "version": "1.2.3",
                "purl": "pkg:cargo/demo-crate@1.2.3",
                "bom_ref": "pkg:cargo/demo-crate@1.2.3",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                "licenses": [{"license": {"id": "MIT"}}],
            }
        )
        body = {
            field: sbom["observation"][field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        sbom["observation"]["observation_sha256"] = evidence.sha256_bytes(
            evidence.canonical_json(body)
        )
        reference = evidence.retained_observation_reference(
            sbom["path"],
            sbom["observation"]["observation_sha256"],
            component,
        )
        owner["component_reviews"] = [
            {
                "observations": [reference],
                "source": source_id,
                "reviewed_license": "MIT",
            }
        ]
        owner["payload_dispositions"][0]["observations"] = [reference]

    with pytest.raises(evidence.EvidenceError, match=r"require Cargo\.lock context"):
        evidence.validate_native_component_policy_schema(policy)

    for records in policy["native_component_coverage"].values():
        records[0]["cargo_lock"] = {
            "member": "demo-1.0/Cargo.lock",
            "sha256": "d" * 64,
            "size": 100,
            "source_ids": [source_id],
            "non_sbom_packages": [],
        }
    evidence.validate_native_component_policy_schema(policy)

    wrong_sources = copy.deepcopy(policy)
    for records in wrong_sources["native_component_coverage"].values():
        records[0]["cargo_lock"]["source_ids"] = []
    with pytest.raises(evidence.EvidenceError, match="source IDs differ"):
        evidence.validate_native_component_policy_schema(wrong_sources)

    overlap = copy.deepcopy(policy)
    for records in overlap["native_component_coverage"].values():
        records[0]["cargo_lock"]["non_sbom_packages"] = [
            {
                "name": "demo-crate",
                "version": "1.2.3",
                "source": evidence.CARGO_CRATES_IO_SOURCE,
                "checksum": "a" * 64,
            }
        ]
    with pytest.raises(evidence.EvidenceError, match="repeats a reviewed crate"):
        evidence.validate_native_component_policy_schema(overlap)

    cross_platform_drift = copy.deepcopy(policy)
    cross_platform_drift["native_component_coverage"]["linux/arm64"][0]["cargo_lock"]["sha256"] = (
        "e" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="semantics differ across platforms"):
        evidence.validate_native_component_policy_schema(cross_platform_drift)


def test_cargo_lock_verifier_rejects_missing_duplicate_foreign_and_unreviewed_packages() -> None:
    source_id = "crates-io:demo-crate@1.2.3"
    checksum_a = "a" * 64
    checksum_b = "b" * 64
    sources = {
        source_id: {
            "kind": "crates-io",
            "name": "demo-crate",
            "version": "1.2.3",
            "crate": {"sha256": checksum_a},
        }
    }
    package = (
        "[[package]]\n"
        'name = "demo-crate"\n'
        'version = "1.2.3"\n'
        f'source = "{evidence.CARGO_CRATES_IO_SOURCE}"\n'
        f'checksum = "{checksum_a}"\n'
    )
    valid = f"version = 4\n\n{package}".encode()

    def verify(content: bytes, *, context_content: bytes | None = None) -> None:
        expected = content if context_content is None else context_content
        context = {
            "owner": "python:demo@1.0",
            "owner_root_observations": set(),
            "observations": {},
            "record": {
                "cargo_lock": {
                    "member": "demo-1.0/Cargo.lock",
                    "sha256": evidence.sha256_bytes(expected),
                    "size": len(expected),
                    "source_ids": [source_id],
                    "non_sbom_packages": [],
                },
                "component_reviews": [],
            },
        }
        evidence.verify_owner_cargo_lock(
            context,
            sources,
            tar_bytes({"demo-1.0/Cargo.lock": content}),
            archive_name="demo-1.0.tar.gz",
        )

    verify(valid)

    missing = valid.replace(b"demo-crate", b"other-crate")
    with pytest.raises(evidence.EvidenceError, match="registry packages differ"):
        verify(missing)

    duplicate = valid + b"\n" + package.encode()
    with pytest.raises(evidence.EvidenceError, match="repeats a package"):
        verify(duplicate)

    foreign = valid.replace(
        evidence.CARGO_CRATES_IO_SOURCE.encode(),
        b"registry+https://example.com/index",
    )
    with pytest.raises(evidence.EvidenceError, match="foreign registry"):
        verify(foreign)

    extra = (
        valid
        + b"\n[[package]]\n"
        + b'name = "lock-only"\nversion = "9.0.0"\n'
        + f'source = "{evidence.CARGO_CRATES_IO_SOURCE}"\n'.encode()
        + f'checksum = "{checksum_b}"\n'.encode()
    )
    with pytest.raises(evidence.EvidenceError, match="registry packages differ"):
        verify(extra)

    with pytest.raises(evidence.EvidenceError, match="reviewed source file differs"):
        verify(valid + b"\n", context_content=valid)


def test_native_component_v7_open_owner_requires_exact_unresolved_evidence() -> None:
    policy = native_component_v7_policy_case()
    for records in policy["native_component_coverage"].values():
        owner = records[0]
        reference = copy.deepcopy(owner["component_reviews"][0]["observations"][0])
        owner["component_reviews"] = []
        owner["known_omissions"] = [
            {
                "id": "unproven-libdemo",
                "component": {
                    "type": "library",
                    "name": "libdemo",
                    "version": "1.2.3",
                    "purl": "pkg:generic/libdemo@1.2.3",
                },
                "observations": [reference],
                "payload_roles": ["demo.libs/libdemo.so.1"],
                "missing_evidence": ["source-payload-relationship"],
                "reason": "The retained source is not proven to have built this payload.",
            }
        ]
        owner["payload_dispositions"][0] = {
            "kind": "known-omission",
            "role": "demo.libs/libdemo.so.1",
            "omission": "unproven-libdemo",
        }
        owner["review"] = {
            "state": "open",
            "reason": "Exact build-material provenance is unavailable.",
            "unresolved_items": ["unproven-libdemo"],
        }
    policy["native_component_sources"] = {}
    evidence.validate_native_component_policy_schema(policy)

    falsely_closed = copy.deepcopy(policy)
    for records in falsely_closed["native_component_coverage"].values():
        records[0]["review"] = {"state": "closed", "reason": "", "unresolved_items": []}
    with pytest.raises(evidence.EvidenceError, match="cannot close"):
        evidence.validate_native_component_policy_schema(falsely_closed)

    stale_ledger = copy.deepcopy(policy)
    for records in stale_ledger["native_component_coverage"].values():
        records[0]["review"]["unresolved_items"] = ["different-gap"]
    with pytest.raises(evidence.EvidenceError, match="differ from known omissions"):
        evidence.validate_native_component_policy_schema(stale_ledger)


def test_native_component_v7_policy_requires_review_for_metadata_root_echo() -> None:
    policy = native_component_v7_policy_case()
    for records in policy["native_component_coverage"].values():
        sbom = records[0]["sboms"][0]
        wheel = records[0]["wheel"]["url"].rsplit("/", maxsplit=1)[-1]
        root = {
            "type": "library",
            "name": "demo",
            "version": "1.0",
            "purl": f"pkg:pypi/demo@1.0?file_name={wheel}",
            "bom_ref": f"pkg:pypi/demo@1.0?file_name={wheel}",
            "hashes": [],
            "licenses": [],
        }
        observation = sbom["observation"]
        observation["metadata_component"] = root
        observation["metadata_root_echo"] = copy.deepcopy(root)
        observation["upstream_invalid_duplicate_bom_ref"] = True
        body = {
            field: observation[field]
            for field in (
                "metadata_component",
                "metadata_root_echo",
                "upstream_invalid_duplicate_bom_ref",
                "components",
            )
        }
        observation["observation_sha256"] = evidence.sha256_bytes(evidence.canonical_json(body))
        rebind_policy_observation_digest(
            records[0],
            sbom_path=sbom["path"],
            observation_sha256=observation["observation_sha256"],
        )
        sbom["metadata_root"] = {
            "kind": "owner",
            "anomaly_review": {
                "kind": "metadata-root-echo",
                "reason": (
                    "The upstream auditwheel document repeats its metadata root and bom-ref "
                    "as one canonically identical top-level component."
                ),
            },
        }
    evidence.validate_native_component_policy_schema(policy)

    missing_review = copy.deepcopy(policy)
    for records in missing_review["native_component_coverage"].values():
        records[0]["sboms"][0]["metadata_root"]["anomaly_review"] = None
    with pytest.raises(evidence.EvidenceError, match="anomaly review"):
        evidence.validate_native_component_policy_schema(missing_review)


@pytest.mark.parametrize("field", ("url", "sha256", "size"))
def test_native_component_lock_binding_rejects_wheel_and_owner_source_drift(field: str) -> None:
    inventories, locked, policy, lock_sources = native_component_coverage_case()
    inventory = inventories["linux/amd64"]
    wrong_wheel = copy.deepcopy(locked["linux/amd64"])
    wrong_wheel[field] = {
        "url": "https://files.pythonhosted.org/packages/aa/demo-1.0-other.whl",
        "sha256": "0" * 64,
        "size": 1,
    }[field]
    with pytest.raises(evidence.EvidenceError, match="wheel differs from lock"):
        evidence.verify_native_component_lock_bindings(
            inventory, policy, [wrong_wheel], lock_sources
        )

    wrong_source = copy.deepcopy(lock_sources)
    wrong_source[("demo", "1.0")][field] = {
        "url": "https://files.pythonhosted.org/packages/aa/demo-1.0-other.tar.gz",
        "sha256": "0" * 64,
        "size": 1,
    }[field]
    with pytest.raises(evidence.EvidenceError, match="owner source differs from lock"):
        evidence.verify_native_component_lock_bindings(
            inventory, policy, [locked["linux/amd64"]], wrong_source
        )


def test_native_component_lock_binding_accepts_exact_reviewed_source_fallback() -> None:
    inventories, locked, policy, lock_sources = native_component_coverage_case()
    inventory = inventories["linux/amd64"]
    fallback = lock_sources.pop(("demo", "1.0"))
    policy["python_sources"] = [
        {
            "name": "demo",
            "version": "1.0",
            **fallback,
        }
    ]

    ledger = evidence.verify_native_component_lock_bindings(
        inventory,
        policy,
        [locked["linux/amd64"]],
        lock_sources,
    )
    assert ledger["complete"] is True

    wrong_fallback = copy.deepcopy(policy)
    wrong_fallback["python_sources"][0]["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="reviewed source fallback"):
        evidence.verify_native_component_lock_bindings(
            inventory,
            wrong_fallback,
            [locked["linux/amd64"]],
            lock_sources,
        )


def test_committed_native_owner_policy_is_exact_and_incomplete() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    evidence.validate_policy_schema(policy)

    assert policy["schema_version"] == 7
    assert policy["distribution_approval"]["approved"] is False
    source = policy["native_component_sources"]["alpine:gcc@14.2.0-r6"]
    assert source["allowed_recipe_links"] == []
    assert source["aports_commit"] == "fbf60319be3bbaf6dd32ef55cc6fb7189e05c266"
    assert source["recipe"]["sha256"] == (
        "5c623d22ac85b64f1dab2346cee6991432723cc7983ec7cb13a5b58692bfc658"
    )

    expected_owners = [
        "python:cffi@2.1.0",
        "python:cryptography@48.0.1",
        "python:greenlet@3.5.3",
        "python:markupsafe@3.0.3",
        "python:psycopg-binary@3.3.4",
        "python:pydantic-core@2.46.4",
        "python:sqlalchemy@2.0.51",
    ]
    expected_states = {
        "python:cffi@2.1.0": "open",
        "python:cryptography@48.0.1": "open",
        "python:greenlet@3.5.3": "closed",
        "python:markupsafe@3.0.3": "closed",
        "python:psycopg-binary@3.3.4": "open",
        "python:pydantic-core@2.46.4": "open",
        "python:sqlalchemy@2.0.51": "closed",
    }
    expected_omissions = {
        "python:cffi@2.1.0": ["unproven-libffi-build-input"],
        "python:cryptography@48.0.1": ["unresolved-rust-and-openssl-sources"],
        "python:greenlet@3.5.3": [],
        "python:markupsafe@3.0.3": [],
        "python:psycopg-binary@3.3.4": [
            "missing-libpq-sbom",
            "unreviewed-bundled-library-sources",
        ],
        "python:pydantic-core@2.46.4": [
            "missing-libgcc-sbom",
            "unreviewed-cargo-sources",
        ],
        "python:sqlalchemy@2.0.51": [],
    }
    for platform in ("linux/amd64", "linux/arm64"):
        owners = policy["native_component_coverage"][platform]
        assert [record["owner"] for record in owners] == expected_owners
        assert {record["owner"]: record["review"]["state"] for record in owners} == (
            expected_states
        )
        assert {
            record["owner"]: [omission["id"] for omission in record["known_omissions"]]
            for record in owners
        } == expected_omissions
        pydantic = next(
            record for record in owners if record["owner"] == "python:pydantic-core@2.46.4"
        )
        libgcc = next(
            omission
            for omission in pydantic["known_omissions"]
            if omission["id"] == "missing-libgcc-sbom"
        )
        assert libgcc["component"]["version"] == "12.4.0"
        assert (
            sum(
                sbom["metadata_root"]["anomaly_review"] is not None
                for owner in owners
                for sbom in owner["sboms"]
            )
            == 3
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("metadata-root", "metadata-root omission does not cite its observation"),
        ("payload", "named omission does not cite its payload"),
    ),
)
def test_known_omission_dispositions_bind_the_named_omission(
    mutation: str,
    message: str,
) -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))

    for records in policy["native_component_coverage"].values():
        owners = {record["owner"]: record for record in records}
        if mutation == "metadata-root":
            cryptography = owners["python:cryptography@48.0.1"]
            sbom = next(
                record
                for record in cryptography["sboms"]
                if record["metadata_root"]["kind"] == "owner"
            )
            observation = sbom["observation"]
            reference = evidence.retained_observation_reference(
                sbom["path"],
                observation["observation_sha256"],
                observation["metadata_component"],
            )
            cryptography["known_omissions"].append(
                {
                    "id": "unrelated-metadata-root-review",
                    "component": {
                        "type": "library",
                        "name": "unrelated-component",
                        "version": "1",
                        "purl": "",
                    },
                    "observations": [reference],
                    "payload_roles": [],
                    "missing_evidence": ["exact-source"],
                    "reason": "Adversarial fixture assigns the root to another omission.",
                }
            )
            cryptography["known_omissions"].sort(key=lambda record: record["id"])
            cryptography["review"]["unresolved_items"] = [
                record["id"] for record in cryptography["known_omissions"]
            ]
            anomaly_review = copy.deepcopy(sbom["metadata_root"]["anomaly_review"])
            sbom["metadata_root"] = {
                "kind": "known-omission",
                "omission": "unresolved-rust-and-openssl-sources",
                "anomaly_review": anomaly_review,
            }
        else:
            psycopg = owners["python:psycopg-binary@3.3.4"]
            disposition = next(
                record
                for record in psycopg["payload_dispositions"]
                if record["role"] == "psycopg_binary.libs/libpq.so.5.18"
            )
            disposition["omission"] = "unreviewed-bundled-library-sources"

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.validate_native_component_policy_schema(policy)


@pytest.mark.parametrize(
    ("side", "message"),
    (
        ("source", "relationship source payload does not cite its observation"),
        ("target", "relationship target payload does not cite its observation"),
    ),
)
def test_native_relationship_requires_payload_observation_mapping(side: str, message: str) -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    for records in policy["native_component_coverage"].values():
        owners = {record["owner"]: record for record in records}
        cryptography = owners["python:cryptography@48.0.1"]
        greenlet = owners["python:greenlet@3.5.3"]
        relationship = cryptography["canonical_relationships"][0]
        if side == "source":
            disposition = next(
                record
                for record in cryptography["payload_dispositions"]
                if record["role"] == relationship["payload_role"]
            )
            disposition["observations"] = [
                copy.deepcopy(cryptography["known_omissions"][0]["observations"][0])
            ]
        else:
            disposition = next(
                record
                for record in greenlet["payload_dispositions"]
                if record["role"] == relationship["reference_payload_role"]
            )
            unrelated = next(
                record
                for record in greenlet["payload_dispositions"]
                if record["role"] == "greenlet.libs/libstdc++.so.6.0.33"
            )
            disposition["observations"] = copy.deepcopy(unrelated["observations"])

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.validate_native_component_policy_schema(policy)


def test_native_relationship_target_bom_ref_drift_has_equivalent_semantics() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    records = policy["native_component_coverage"]["linux/arm64"]
    owners = {record["owner"]: record for record in records}
    cryptography = owners["python:cryptography@48.0.1"]
    greenlet = owners["python:greenlet@3.5.3"]
    target = cryptography["canonical_relationships"][0]["reference_observation"]
    sbom = next(record for record in greenlet["sboms"] if record["path"] == target["sbom_path"])
    observation = sbom["observation"]
    component = next(
        record for record in observation["components"] if record["bom_ref"] == target["bom_ref"]
    )
    old_bom_ref = component["bom_ref"]
    new_bom_ref = "zzzz-arm64-build-specific-libgcc"
    component["bom_ref"] = new_bom_ref
    rebind_policy_observation_bom_ref(
        records,
        sbom_path=sbom["path"],
        old_bom_ref=old_bom_ref,
        new_bom_ref=new_bom_ref,
    )

    semantic_body = {
        field: observation[field]
        for field in (
            "metadata_component",
            "metadata_root_echo",
            "upstream_invalid_duplicate_bom_ref",
            "components",
        )
    }
    observation["observation_sha256"] = evidence.sha256_bytes(
        evidence.canonical_json(semantic_body)
    )
    rebind_policy_observation_digest(
        records,
        sbom_path=sbom["path"],
        observation_sha256=observation["observation_sha256"],
    )

    def reference_key(reference: object) -> tuple[str, str, str, str, str]:
        return cast(
            tuple[str, str, str, str, str],
            evidence.validate_observation_reference(reference, "test reference"),
        )

    for review in greenlet["component_reviews"]:
        review["observations"].sort(key=reference_key)
    greenlet["component_reviews"].sort(
        key=lambda review: tuple(reference_key(item) for item in review["observations"])
    )
    for omission in greenlet["known_omissions"]:
        omission["observations"].sort(key=reference_key)
    for disposition in greenlet["payload_dispositions"]:
        if disposition["kind"] == "sbom-components":
            disposition["observations"].sort(key=reference_key)

    evidence.validate_native_component_policy_schema(policy)


def test_native_component_recipe_binds_version_license_and_distfile() -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    source_id, source = next(iter(policy["native_component_sources"].items()))
    distfile = source["distfiles"][0]
    apkbuild = (
        "pkgname=demo-native\n"
        "pkgver=1.2.3\n"
        "pkgrel=0\n"
        'license="MIT"\n'
        'source="https://example.com/demo-native-$pkgver.tar.xz"\n'
        f'sha512sums="\n{distfile["sha512"]}  {distfile["filename"]}\n"\n'
    ).encode()
    recipe = tar_bytes({"aports/main/demo-native/APKBUILD": apkbuild})

    evidence.verify_native_component_recipe(source_id, source, recipe)

    wrong_release = recipe.replace(b"pkgrel=0", b"pkgrel=1")
    with pytest.raises(evidence.EvidenceError, match="metadata differs"):
        evidence.verify_native_component_recipe(source_id, source, wrong_release)

    wrong_checksum = copy.deepcopy(source)
    wrong_checksum["distfiles"][0]["sha512"] = "0" * 128
    with pytest.raises(evidence.EvidenceError, match="distfiles differ"):
        evidence.verify_native_component_recipe(source_id, wrong_checksum, recipe)


def test_native_component_notice_retention_is_exact(tmp_path: Path) -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    source_id, source = next(iter(policy["native_component_sources"].items()))
    content = b"license text"
    source["notices"] = [
        {
            "member": "demo-native-1.2.3/LICENSE",
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
    ]
    archive = tar_bytes(
        {
            "demo-native-1.2.3/LICENSE": content,
            "demo-native-1.2.3/source.c": b"source",
        }
    )

    retained = evidence.retain_native_component_notices(
        archive,
        source_id,
        source,
        tmp_path,
        budget=evidence.BundleBudget(),
    )

    assert len(retained) == 1
    assert (tmp_path / retained[0]).read_bytes() == content


@pytest.mark.parametrize(
    ("archive", "message"),
    (
        (tar_bytes({"demo-native-1.2.3/source.c": b"source"}), "omits reviewed notices"),
        (tar_bytes({"demo-native-1.2.3/LICENSE": b"wrong"}), "differs from reviewed policy"),
        (tar_bytes({"../LICENSE": b"license text"}), "unsafe archive path"),
        (
            tar_bytes({}, links={"demo-native-1.2.3/LICENSE": "COPYING"}),
            "notice is not a regular file",
        ),
        (
            tar_bytes(
                {"demo-native-1.2.3/LICENSE": b"license text"},
                links={"demo-native-1.2.3/alias": "../../escape"},
            ),
            "unsafe archive link target",
        ),
    ),
)
def test_native_component_notice_retention_rejects_hostile_or_stale_archives(
    archive: bytes, message: str, tmp_path: Path
) -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    source_id, source = next(iter(policy["native_component_sources"].items()))
    content = b"license text"
    source["notices"] = [
        {
            "member": "demo-native-1.2.3/LICENSE",
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
    ]

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.retain_native_component_notices(
            archive,
            source_id,
            source,
            tmp_path,
            budget=evidence.BundleBudget(),
        )


def test_native_component_notice_retention_rejects_duplicate_archive_paths(
    tmp_path: Path,
) -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    source_id, source = next(iter(policy["native_component_sources"].items()))
    content = b"license text"
    source["notices"] = [
        {
            "member": "demo-native-1.2.3/LICENSE",
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
    ]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for _index in range(2):
            member = tarfile.TarInfo("demo-native-1.2.3/LICENSE")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

    with pytest.raises(evidence.EvidenceError, match="repeats an archive path"):
        evidence.retain_native_component_notices(
            output.getvalue(),
            source_id,
            source,
            tmp_path,
            budget=evidence.BundleBudget(),
        )


def test_native_component_notice_retention_enforces_resource_limits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _inventories, _locked, policy, _lock_sources = native_component_coverage_case()
    source_id, source = next(iter(policy["native_component_sources"].items()))
    content = b"license text"
    source["notices"] = [
        {
            "member": "demo-native-1.2.3/LICENSE",
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
    ]
    archive = tar_bytes({"demo-native-1.2.3/LICENSE": content})
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", len(content) - 1)

    with pytest.raises(evidence.EvidenceError, match="source is too large"):
        evidence.retain_native_component_notices(
            archive,
            source_id,
            source,
            tmp_path,
            budget=evidence.BundleBudget(),
        )


def test_recipe_checksum_parser_does_not_execute_recipe() -> None:
    remote_digest = "a" * 128
    local_digest = evidence.hashlib.sha512(b"patch").hexdigest()
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/demo-$pkgver.tar.gz\nlocal.patch"\n'
                f'sha512sums="\n{remote_digest}  demo-1.0.tar.gz\n'
                f'{local_digest}  local.patch\n"\n'
            ).encode(),
            "aports/main/demo/local.patch": b"patch",
        }
    )
    checksums, local = evidence.recipe_checksums(recipe, "demo")
    assert checksums == {
        "demo-1.0.tar.gz": remote_digest,
        "local.patch": local_digest,
    }
    assert local == {"local.patch"}


def test_recipe_checksum_parser_rejects_links() -> None:
    recipe = tar_bytes(
        {"aports/main/demo/APKBUILD": f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'.encode()},
        links={"aports/main/demo/escape": "../../secret"},
    )
    with pytest.raises(evidence.EvidenceError, match="unsafe archive link target"):
        evidence.recipe_checksums(recipe, "demo")


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_recipe_checksum_parser_rejects_even_safe_links(link_kind: str) -> None:
    apkbuild = (
        'source="local.patch"\n'
        f'sha512sums="\n{evidence.hashlib.sha512(b"patch").hexdigest()}  local.patch\n"\n'
    ).encode()
    links = {"aports/main/demo/local.patch": "target.patch"} if link_kind == "symlink" else None
    hardlinks = (
        {"aports/main/demo/local.patch": "aports/main/demo/target.patch"}
        if link_kind == "hardlink"
        else None
    )
    recipe = tar_bytes({"aports/main/demo/APKBUILD": apkbuild}, links=links, hardlinks=hardlinks)
    with pytest.raises(evidence.EvidenceError, match="links are not allowed"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_checksum_parser_requires_an_exact_pinned_link_exception() -> None:
    path = "aports/main/demo/post-upgrade"
    target = "aports/main/demo/post-install"
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": b"",
            target: b"#!/bin/sh\n",
        },
        links={path: "post-install"},
    )
    exception = {"path": path, "target": target, "type": "symlink"}

    assert evidence.recipe_checksums(recipe, "demo", allowed_links=[exception]) == ({}, set())
    with pytest.raises(evidence.EvidenceError, match="missing="):
        evidence.recipe_checksums(
            tar_bytes({"aports/main/demo/APKBUILD": b""}),
            "demo",
            allowed_links=[exception],
        )


@pytest.mark.parametrize("failure", ("dangling", "chain"))
def test_recipe_checksum_link_exception_must_resolve_directly_to_a_regular_file(
    failure: str,
) -> None:
    path = "aports/main/demo/post-upgrade"
    target = "aports/main/demo/post-install"
    files = {"aports/main/demo/APKBUILD": b""}
    links = {path: "post-install"}
    if failure == "chain":
        links[target] = "real-script"
        files["aports/main/demo/real-script"] = b"#!/bin/sh\n"
    exception = {"path": path, "target": target, "type": "symlink"}

    with pytest.raises(
        evidence.EvidenceError,
        match=r"resolve directly to retained regular files|unexpected=",
    ):
        evidence.recipe_checksums(
            tar_bytes(files, links=links),
            "demo",
            allowed_links=[exception],
        )


def test_dynamic_recipe_sources_require_an_explicit_exception() -> None:
    local = b"key"
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'for key in $keys; do\n\tsource="$source $key"\ndone\n'
                f'sha512sums="\n{evidence.hashlib.sha512(local).hexdigest()}  key.pub\n"\n'
            ).encode(),
            "aports/main/demo/key.pub": local,
        }
    )

    with pytest.raises(evidence.EvidenceError, match="one literal source block"):
        evidence.recipe_checksums(recipe, "demo")
    assert evidence.recipe_checksums(recipe, "demo", allow_dynamic_sources=True) == (
        {"key.pub": evidence.hashlib.sha512(local).hexdigest()},
        {"key.pub"},
    )


def test_recipe_checksum_parser_verifies_local_bytes() -> None:
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                f'source="local.patch"\nsha512sums="\n{"a" * 128}  local.patch\n"\n'
            ).encode(),
            "aports/main/demo/local.patch": b"different",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="local recipe source checksum mismatch"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_checksum_parser_rejects_duplicate_basenames() -> None:
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": b'source="local.patch"\n',
            "aports/main/demo/a/local.patch": b"one",
            "aports/main/demo/b/local.patch": b"two",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="repeats regular-file basename"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_source_and_checksums_must_have_exact_coverage() -> None:
    extra_source = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/one.tar.gz https://example.com/two.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  one.tar.gz\n"\n'
            ).encode()
        }
    )
    with pytest.raises(evidence.EvidenceError, match="counts differ"):
        evidence.recipe_checksums(extra_source, "demo")

    wrong_name = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/one-$pkgver.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  unrelated.zip\n"\n'
            ).encode()
        }
    )
    with pytest.raises(evidence.EvidenceError, match="does not match source"):
        evidence.recipe_checksums(wrong_name, "demo")


def test_recipe_checksum_parser_enforces_aggregate_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = tar_bytes({"aports/main/demo/APKBUILD": b"source=demo.tar.gz\n"})
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="recipe archive is too large"):
        evidence.recipe_checksums(recipe, "demo")


def test_fetch_rejects_an_invalid_expected_digest_before_network() -> None:
    with pytest.raises(evidence.EvidenceError, match="invalid expected sha256 digest"):
        evidence.fetch("https://example.com/source.tar.gz", "not-a-digest")


def test_source_url_rejects_an_out_of_range_port_before_network() -> None:
    with pytest.raises(evidence.EvidenceError, match="source URL is invalid"):
        evidence.require_https_source_url("https://example.com:65536/source.tar.gz")


def test_cpython_source_is_bound_to_official_recipe_version_and_hash() -> None:
    digest = "a" * 64
    recipe = f"ENV PYTHON_VERSION 3.14.6\nENV PYTHON_SHA256 {digest}\n".encode()
    source = {
        "url": "https://www.python.org/ftp/python/3.14.6/Python-3.14.6.tar.xz",
        "sha256": digest,
    }
    evidence.verify_cpython_source_binding(recipe, source)

    with pytest.raises(evidence.EvidenceError, match="source URL"):
        evidence.verify_cpython_source_binding(
            recipe,
            {**source, "url": "https://www.python.org/ftp/python/3.14.5/Python-3.14.5.tar.xz"},
        )
    with pytest.raises(evidence.EvidenceError, match="SHA-256"):
        evidence.verify_cpython_source_binding(recipe, {**source, "sha256": "b" * 64})
    with pytest.raises(evidence.EvidenceError, match="one literal"):
        evidence.verify_cpython_source_binding(
            b"ENV PYTHON_VERSION $VERSION\nENV PYTHON_SHA256 $HASH\n", source
        )
    with pytest.raises(evidence.EvidenceError, match="version differs from the runtime"):
        evidence.verify_cpython_source_binding(
            f"ENV PYTHON_VERSION 3.14.5\nENV PYTHON_SHA256 {digest}\n".encode(),
            {
                **source,
                "url": "https://www.python.org/ftp/python/3.14.5/Python-3.14.5.tar.xz",
            },
        )


def test_cpython_source_archive_binds_exact_archive_and_license_bytes() -> None:
    member = "Python-3.14.6/LICENSE"
    patchlevel_member = "Python-3.14.6/Include/patchlevel.h"
    license_content = b"Python source license\n"
    patchlevel_content = cpython_patchlevel_header()
    archive = tar_bytes(
        {
            member: license_content,
            patchlevel_member: patchlevel_content,
            "Python-3.14.6/Include/Python.h": b"source",
        }
    )
    source = {
        "size": len(archive),
        "sha256": evidence.sha256_bytes(archive),
        "license_member": member,
        "license_sha256": evidence.sha256_bytes(license_content),
        "patchlevel_member": patchlevel_member,
        "patchlevel_sha256": evidence.sha256_bytes(patchlevel_content),
    }

    assert evidence.verify_cpython_source_archive(archive, source) == license_content

    with pytest.raises(evidence.EvidenceError, match="reviewed identity"):
        evidence.verify_cpython_source_archive(
            archive,
            {**source, "sha256": "0" * 64},
        )
    with pytest.raises(evidence.EvidenceError, match="LICENSE does not match"):
        evidence.verify_cpython_source_archive(
            archive,
            {**source, "license_sha256": "0" * 64},
        )
    with pytest.raises(evidence.EvidenceError, match="LICENSE does not match"):
        evidence.verify_cpython_source_archive(
            archive,
            {**source, "license_member": "Python-3.14.6/OTHER"},
        )
    with pytest.raises(evidence.EvidenceError, match="patchlevel header does not match"):
        evidence.verify_cpython_source_archive(
            archive,
            {**source, "patchlevel_sha256": "0" * 64},
        )
    with pytest.raises(evidence.EvidenceError, match="patchlevel header does not match"):
        evidence.verify_cpython_source_archive(
            archive,
            {**source, "patchlevel_member": "Python-3.14.6/Include/other.h"},
        )


def test_detached_license_source_does_not_conflate_archive_member_digest() -> None:
    digest = "a" * 64
    assert (
        evidence.detached_license_source(
            {
                "license_member": "Python-3.14.6/LICENSE",
                "license_sha256": digest,
            },
            "cpython",
        )
        is None
    )
    assert evidence.detached_license_source(
        {
            "license_url": "https://example.com/LICENSE",
            "license_sha256": digest,
        },
        "docker-python-recipe",
    ) == ("https://example.com/LICENSE", digest)

    with pytest.raises(evidence.EvidenceError, match="invalid license source"):
        evidence.detached_license_source(
            {"license_url": "https://example.com/LICENSE"},
            "docker-python-recipe",
        )


def test_cpython_source_archive_rejects_ambiguous_or_linked_license() -> None:
    member = "Python-3.14.6/LICENSE"
    patchlevel_member = "Python-3.14.6/Include/patchlevel.h"
    license_content = b"Python source license\n"
    patchlevel_content = cpython_patchlevel_header()
    duplicate = tar_sequence(
        [
            (member, license_content),
            (member, license_content),
            (patchlevel_member, patchlevel_content),
        ]
    )
    source = {
        "size": len(duplicate),
        "sha256": evidence.sha256_bytes(duplicate),
        "license_member": member,
        "license_sha256": evidence.sha256_bytes(license_content),
        "patchlevel_member": patchlevel_member,
        "patchlevel_sha256": evidence.sha256_bytes(patchlevel_content),
    }
    with pytest.raises(evidence.EvidenceError, match="not one bounded regular archive member"):
        evidence.verify_cpython_source_archive(duplicate, source)

    linked = tar_bytes(
        {
            "Python-3.14.6/OTHER": license_content,
            patchlevel_member: patchlevel_content,
        },
        links={member: "OTHER"},
    )
    with pytest.raises(evidence.EvidenceError, match="reviewed source member is not a regular"):
        evidence.verify_cpython_source_archive(
            linked,
            {
                **source,
                "size": len(linked),
                "sha256": evidence.sha256_bytes(linked),
            },
        )


def test_cpython_source_archive_enforces_expansion_and_reviewed_member_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    license_member = "Python-3.14.6/LICENSE"
    patchlevel_member = "Python-3.14.6/Include/patchlevel.h"
    license_content = b"Python source license\n"
    patchlevel_content = cpython_patchlevel_header()

    def source_for(archive: bytes) -> dict[str, Any]:
        return {
            "size": len(archive),
            "sha256": evidence.sha256_bytes(archive),
            "license_member": license_member,
            "license_sha256": evidence.sha256_bytes(license_content),
            "patchlevel_member": patchlevel_member,
            "patchlevel_sha256": evidence.sha256_bytes(patchlevel_content),
        }

    largest_reviewed_member = max(len(license_content), len(patchlevel_content))
    oversized_member = tar_bytes(
        {
            license_member: license_content,
            patchlevel_member: patchlevel_content,
            "Python-3.14.6/oversized": b"x" * (largest_reviewed_member + 1),
        }
    )
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", largest_reviewed_member)
    with pytest.raises(evidence.EvidenceError, match="member exceeds its size limit"):
        evidence.verify_cpython_source_archive(oversized_member, source_for(oversized_member))

    aggregate = tar_bytes(
        {
            license_member: license_content,
            patchlevel_member: patchlevel_content,
            "Python-3.14.6/extra": b"extra",
        }
    )
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", 1024 * 1024)
    monkeypatch.setattr(
        evidence,
        "MAX_ARCHIVE_TOTAL_BYTES",
        len(license_content) + len(patchlevel_content) + len(b"extra") - 1,
    )
    with pytest.raises(evidence.EvidenceError, match="expanded-size limit"):
        evidence.verify_cpython_source_archive(aggregate, source_for(aggregate))

    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", 1024 * 1024)
    monkeypatch.setattr(evidence, "MAX_LICENSE_BYTES", len(license_content) - 1)
    with pytest.raises(evidence.EvidenceError, match="LICENSE is not one bounded"):
        evidence.verify_cpython_source_archive(aggregate, source_for(aggregate))

    monkeypatch.setattr(evidence, "MAX_LICENSE_BYTES", 1024 * 1024)
    monkeypatch.setattr(evidence, "MAX_CPYTHON_PATCHLEVEL_BYTES", len(patchlevel_content) - 1)
    with pytest.raises(evidence.EvidenceError, match="patchlevel header is not one bounded"):
        evidence.verify_cpython_source_archive(aggregate, source_for(aggregate))


@pytest.mark.parametrize(
    ("member_type", "message"),
    ((tarfile.SYMTYPE, "link has a payload"), (tarfile.DIRTYPE, "directory has a payload")),
)
def test_cpython_source_archive_rejects_nonregular_payloads(
    member_type: bytes, message: str
) -> None:
    license_member = "Python-3.14.6/LICENSE"
    patchlevel_member = "Python-3.14.6/Include/patchlevel.h"
    license_content = b"Python source license\n"
    patchlevel_content = cpython_patchlevel_header()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path, content in (
            (license_member, license_content),
            (patchlevel_member, patchlevel_content),
        ):
            member = tarfile.TarInfo(path)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        hostile = tarfile.TarInfo("Python-3.14.6/hostile")
        hostile.type = member_type
        hostile.size = 1
        if member_type == tarfile.SYMTYPE:
            hostile.linkname = "target"
        archive.addfile(hostile, io.BytesIO(b"x"))
    content = output.getvalue()
    source = {
        "size": len(content),
        "sha256": evidence.sha256_bytes(content),
        "license_member": license_member,
        "license_sha256": evidence.sha256_bytes(license_content),
        "patchlevel_member": patchlevel_member,
        "patchlevel_sha256": evidence.sha256_bytes(patchlevel_content),
    }

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.verify_cpython_source_archive(content, source)


def test_fetch_records_every_https_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"verified content"

    class Response:
        def __init__(self) -> None:
            self.headers = {"Content-Length": str(len(content))}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://cdn.example.com/source.tar.gz"

        def read(self, _limit: int) -> bytes:
            return content

    class Opener:
        def __init__(self, handler: Any) -> None:
            self.handler = handler

        def open(self, _request: Any, *, timeout: int) -> Response:
            assert timeout == 60
            self.handler.urls.append("https://cdn.example.com/source.tar.gz")
            return Response()

    monkeypatch.setattr(
        evidence.urllib.request,
        "build_opener",
        lambda handler: Opener(handler),
    )
    download = evidence.fetch(
        "https://example.com/source.tar.gz",
        evidence.hashlib.sha256(content).hexdigest(),
    )

    assert download.content == content
    assert download.urls == (
        "https://example.com/source.tar.gz",
        "https://cdn.example.com/source.tar.gz",
    )
    record = evidence.source_record("demo", download.urls, content, "sources/demo.tar.gz")
    assert record["url"] == download.urls[0]
    assert record["urls"] == list(download.urls)


def test_fetch_rejects_a_final_url_away_from_https(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://example.com/source.tar.gz"

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return Response()

    monkeypatch.setattr(evidence.urllib.request, "build_opener", lambda *_args: Opener())
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        evidence.fetch("https://example.com/source.tar.gz", "a" * 64)


def test_redirect_handler_rejects_downgrades_and_too_many_redirects() -> None:
    handler = evidence.AuditedRedirectHandler("https://example.com/source.tar.gz")
    request = evidence.urllib.request.Request("https://example.com/source.tar.gz")
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/next")

    handler.urls.extend(f"https://example.com/{index}" for index in range(5))
    with pytest.raises(evidence.EvidenceError, match="exceeded 5 redirects"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/final")


def test_license_extraction_rejects_control_paths_in_tar_and_zip(tmp_path: Path) -> None:
    hostile_tar = tar_bytes({"LICENSE\nforged": b"text"})
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.extract_license_files(hostile_tar, "demo", tmp_path)

    hostile_zip = io.BytesIO()
    with zipfile.ZipFile(hostile_zip, mode="w") as archive:
        archive.writestr("LICENSE\nforged", b"text")
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.extract_license_files(hostile_zip.getvalue(), "demo", tmp_path)


def test_license_extraction_rejects_zip_symlink_evidence(tmp_path: Path) -> None:
    hostile_zip = io.BytesIO()
    with zipfile.ZipFile(hostile_zip, mode="w") as archive:
        member = zipfile.ZipInfo("LICENSE")
        member.create_system = 3
        member.extract_version = 10
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "target")
    with pytest.raises(evidence.EvidenceError, match="unsupported entry type"):
        evidence.extract_license_files(hostile_zip.getvalue(), "demo", tmp_path)


def test_license_extraction_reads_bounded_regular_zip_evidence(tmp_path: Path) -> None:
    source_zip = io.BytesIO()
    with zipfile.ZipFile(source_zip, mode="w") as archive:
        for name, content in {
            "demo/LICENSE.md": b"license text\n",
            "demo/src/app.py": b"APP = True\n",
        }.items():
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)

    retained = evidence.extract_license_files(source_zip.getvalue(), "demo", tmp_path)

    assert len(retained) == 1
    assert retained[0].endswith("-LICENSE.md")
    assert (tmp_path / retained[0]).read_bytes() == b"license text\n"


def test_license_extraction_reads_stored_zip_evidence(tmp_path: Path) -> None:
    content = source_zip_bytes([("LICENSE", b"stored license\n")], compression=zipfile.ZIP_STORED)

    retained = evidence.extract_license_files(content, "demo", tmp_path)

    assert len(retained) == 1
    assert (tmp_path / retained[0]).read_bytes() == b"stored license\n"


def test_markupsafe_source_license_evidence_is_retained_exactly(tmp_path: Path) -> None:
    assert (
        evidence.sha256_bytes(MARKUPSAFE_LICENSE_TEXT),
        len(MARKUPSAFE_LICENSE_TEXT),
    ) == (
        "489a8e1108509ed98a37bb983e11e0f7e1d31f0bd8f99a79c8448e7ff37d07ea",
        1475,
    )
    assert (
        evidence.sha256_bytes(MARKUPSAFE_DOCS_LICENSE),
        len(MARKUPSAFE_DOCS_LICENSE),
    ) == (
        "6fc7e80b75b5999783a328d90976a2585e0956c4a348c3c888453938ceca742d",
        100,
    )
    archive = tar_bytes(
        {
            "markupsafe-3.0.3/LICENSE.txt": MARKUPSAFE_LICENSE_TEXT,
            "markupsafe-3.0.3/docs/license.rst": MARKUPSAFE_DOCS_LICENSE,
        }
    )

    retained = evidence.extract_license_files(archive, "python-markupsafe-3.0.3", tmp_path)

    assert retained == [
        "licenses/from-source/python-markupsafe-3.0.3/489a8e110850-LICENSE.txt",
        "licenses/from-source/python-markupsafe-3.0.3/6fc7e80b75b5-license.rst",
    ]
    assert (tmp_path / retained[0]).read_bytes() == MARKUPSAFE_LICENSE_TEXT
    assert (tmp_path / retained[1]).read_bytes() == MARKUPSAFE_DOCS_LICENSE


def test_sqlalchemy_source_license_evidence_is_retained_exactly(tmp_path: Path) -> None:
    assert (
        evidence.sha256_bytes(SQLALCHEMY_LICENSE_TEXT),
        len(SQLALCHEMY_LICENSE_TEXT),
    ) == (
        "e862bb5b904fb5513c3e14288d7a25a12eb0ecc7847a0a965d310e9a955e7cb9",
        1100,
    )
    assert (
        evidence.sha256_bytes(SQLALCHEMY_AUTHORS_TEXT),
        len(SQLALCHEMY_AUTHORS_TEXT),
    ) == (
        "dc1db0b5d17455adc37b693ff8e409c9a80f603e441695825518c36f786c963e",
        492,
    )
    archive = tar_bytes(
        {
            "sqlalchemy-2.0.51/AUTHORS": SQLALCHEMY_AUTHORS_TEXT,
            "sqlalchemy-2.0.51/LICENSE": SQLALCHEMY_LICENSE_TEXT,
        }
    )

    retained = evidence.extract_license_files(archive, "python-sqlalchemy-2.0.51", tmp_path)

    assert retained == [
        "licenses/from-source/python-sqlalchemy-2.0.51/dc1db0b5d174-AUTHORS",
        "licenses/from-source/python-sqlalchemy-2.0.51/e862bb5b904f-LICENSE",
    ]
    assert (tmp_path / retained[0]).read_bytes() == SQLALCHEMY_AUTHORS_TEXT
    assert (tmp_path / retained[1]).read_bytes() == SQLALCHEMY_LICENSE_TEXT


def test_source_zip_inflater_uses_the_declared_output_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_decompressobj = evidence.zlib.decompressobj
    output_caps: list[int] = []

    class DecoderProxy:
        def __init__(self, wbits: int) -> None:
            self.decoder = real_decompressobj(wbits)

        def decompress(self, payload: bytes, max_length: int) -> bytes:
            output_caps.append(max_length)
            return cast(bytes, self.decoder.decompress(payload, max_length))

        @property
        def eof(self) -> bool:
            return cast(bool, self.decoder.eof)

        @property
        def unused_data(self) -> bytes:
            return cast(bytes, self.decoder.unused_data)

        @property
        def unconsumed_tail(self) -> bytes:
            return cast(bytes, self.decoder.unconsumed_tail)

    monkeypatch.setattr(evidence.zlib, "decompressobj", DecoderProxy)
    payload = b"bounded license\n"
    content = source_zip_bytes([("LICENSE", payload)])

    retained = evidence.extract_license_files(content, "demo", tmp_path)

    assert len(retained) == 1
    assert output_caps == [len(payload) + 1]


def test_license_extraction_rejects_underdeclared_deflate_output(tmp_path: Path) -> None:
    source_zip = io.BytesIO()
    with zipfile.ZipFile(source_zip, mode="w") as archive:
        member = zipfile.ZipInfo("LICENSE")
        member.create_system = 3
        member.external_attr = (stat.S_IFREG | 0o644) << 16
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, b"ABCD")

    content = bytearray(source_zip.getvalue())
    local, central = zip_record_offsets(content, "LICENSE")
    declared = b"AB"
    crc = zlib.crc32(declared) & 0xFFFFFFFF
    content[local + 14 : local + 18] = crc.to_bytes(4, "little")
    content[local + 22 : local + 26] = len(declared).to_bytes(4, "little")
    content[central + 16 : central + 20] = crc.to_bytes(4, "little")
    content[central + 24 : central + 28] = len(declared).to_bytes(4, "little")

    # ZipFile.open() silently returns only the declared prefix for this archive.
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as permissive:
        assert permissive.read("LICENSE") == declared
    with pytest.raises(evidence.EvidenceError, match="license payload disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("entry-comment", "unsupported entry metadata"),
        ("archive-comment", "comments are not supported"),
        ("unsupported-extra", "unsupported extra metadata"),
        ("duplicate-extra", "malformed extra metadata"),
        ("descriptor", "unsupported entry metadata"),
        ("dos-directory-bit", "unsupported entry type"),
        ("special-mode-bit", "unsupported entry type"),
        ("invalid-timestamp", "invalid DOS timestamp"),
        ("invalid-calendar-date", "invalid DOS timestamp"),
        ("non-ascii-name", "non-ASCII entry name"),
        ("nul-name", "NUL-containing entry name"),
        ("stored-size", "stored entry has inconsistent sizes"),
    ],
)
def test_license_extraction_rejects_unsupported_source_zip_dialects(
    mutation: str, message: str, tmp_path: Path
) -> None:
    unix_owner = b"ux\x05\x00\x01\x01\x01\x01\x01"
    if mutation == "entry-comment":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], entry_comment=b"x"))
    elif mutation == "archive-comment":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], archive_comment=b"x"))
    elif mutation == "unsupported-extra":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], extra=b"\xfe\xca\x00\x00"))
    elif mutation == "duplicate-extra":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], extra=unix_owner + unix_owner))
    else:
        compression = zipfile.ZIP_STORED if mutation == "stored-size" else zipfile.ZIP_DEFLATED
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], compression=compression))
        local, central = zip_record_offsets(content, "LICENSE")
        if mutation == "descriptor":
            content[local + 6 : local + 8] = (8).to_bytes(2, "little")
            content[central + 8 : central + 10] = (8).to_bytes(2, "little")
        elif mutation == "dos-directory-bit":
            attributes = int.from_bytes(content[central + 38 : central + 42], "little") | 0x10
            content[central + 38 : central + 42] = attributes.to_bytes(4, "little")
        elif mutation == "special-mode-bit":
            attributes = int.from_bytes(content[central + 38 : central + 42], "little")
            attributes |= stat.S_ISUID << 16
            content[central + 38 : central + 42] = attributes.to_bytes(4, "little")
        elif mutation == "invalid-timestamp":
            invalid_time = 31 << 11
            content[local + 10 : local + 12] = invalid_time.to_bytes(2, "little")
            content[central + 12 : central + 14] = invalid_time.to_bytes(2, "little")
        elif mutation == "invalid-calendar-date":
            february_31 = 2 << 5 | 31
            content[local + 12 : local + 14] = february_31.to_bytes(2, "little")
            content[central + 14 : central + 16] = february_31.to_bytes(2, "little")
        elif mutation == "non-ascii-name":
            content[central + evidence.ZIP_CENTRAL_HEADER.size] = 0xFF
        elif mutation == "nul-name":
            content[central + evidence.ZIP_CENTRAL_HEADER.size] = 0
        else:
            content[central + 20 : central + 24] = (3).to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_source_zip_infozip_extra_fields_are_strictly_parsed() -> None:
    central = bytes.fromhex("55540500031b80206a75780b000104e803000004e8030000")
    local = bytes.fromhex("55540900031b80206a1c80206a75780b000104e803000004e8030000")

    assert evidence.validate_source_zip_extra(central, "entry", central=True) == {
        0x5455: (3, 0x6A20801B),
        0x7875: (4, 1000, 4, 1000),
    }
    assert evidence.validate_source_zip_extra(local, "entry", central=False) == {
        0x5455: (3, 0x6A20801B, 0x6A20801C),
        0x7875: (4, 1000, 4, 1000),
    }


@pytest.mark.parametrize(
    "extra",
    [
        b"U",
        b"UT\x01\x00",
        b"UT\x05\x00\x00\x00\x00\x00\x00",
        b"ux\x02\x00\x01\x00",
        b"ux\x05\x00\x02\x01\x01\x01\x01",
    ],
)
def test_source_zip_extra_fields_reject_malformed_payloads(extra: bytes) -> None:
    with pytest.raises(evidence.EvidenceError, match=r"malformed|unsupported"):
        evidence.validate_source_zip_extra(extra, "entry", central=True)


def test_license_extraction_rejects_local_extra_field_disagreement(tmp_path: Path) -> None:
    unix_owner = b"ux\x05\x00\x01\x01\x01\x01\x01"
    content = bytearray(source_zip_bytes([("LICENSE", b"text")], extra=unix_owner))
    local, _central = zip_record_offsets(content, "LICENSE")
    local_header = evidence.ZIP_LOCAL_HEADER.unpack_from(content, local)
    local_extra = local + evidence.ZIP_LOCAL_HEADER.size + local_header[-2]
    content[local_extra + 6] = 2

    with pytest.raises(evidence.EvidenceError, match="local Unix-owner metadata disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_duplicate_source_zip_names(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"a"), ("COPYING", b"b")]))
    _local, central = zip_record_offsets(content, "COPYING")
    name_start = central + evidence.ZIP_CENTRAL_HEADER.size
    content[name_start : name_start + len("COPYING")] = b"LICENSE"

    with pytest.raises(evidence.EvidenceError, match="duplicate or non-canonical entry name"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_file_directory_source_zip_aliases(tmp_path: Path) -> None:
    content = source_zip_bytes([("LICENSE", b"text"), ("LICENSE/", b"")])

    with pytest.raises(evidence.EvidenceError, match="duplicate or non-canonical entry name"):
        evidence.extract_license_files(content, "demo", tmp_path)


def test_license_extraction_rejects_local_source_zip_name_disagreement(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, _central = zip_record_offsets(content, "LICENSE")
    content[local + evidence.ZIP_LOCAL_HEADER.size] = ord("C")

    with pytest.raises(evidence.EvidenceError, match="local entry boundary disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_reordered_source_zip_central_records(
    tmp_path: Path,
) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"a"), ("NOTICE", b"b")]))
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central = evidence.ZIP_EOCD.unpack_from(content, eocd)[-2]
    records: list[bytes] = []
    position = central
    while position < eocd:
        assert content[position : position + 4] == b"PK\x01\x02"
        name_size = int.from_bytes(content[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(content[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(content[position + 32 : position + 34], "little")
        end = position + evidence.ZIP_CENTRAL_HEADER.size + name_size + extra_size + comment_size
        records.append(bytes(content[position:end]))
        position = end
    content[central:eocd] = b"".join(reversed(records))

    with pytest.raises(evidence.EvidenceError, match="local-record order"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


@pytest.mark.parametrize("mutation", ["prefix", "gap"])
def test_license_extraction_rejects_source_zip_prefixes_and_gaps(
    mutation: str, tmp_path: Path
) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, central = zip_record_offsets(content, "LICENSE")
    eocd = content.rfind(b"PK\x05\x06")
    assert local == 0 and eocd > central
    if mutation == "prefix":
        content[:0] = b"X"
        central += 1
        eocd += 1
        content[central + 42 : central + 46] = (1).to_bytes(4, "little")
    else:
        content[central:central] = b"X"
        central += 1
        eocd += 1
    content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match=r"prefix|gap|trailing"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_expected_zip_rejects_a_prefixed_truncated_archive(tmp_path: Path) -> None:
    content = b"X" + source_zip_bytes([("LICENSE", b"text")])[:-1]

    with pytest.raises(evidence.EvidenceError, match="source ZIP"):
        evidence.extract_license_files(content, "demo", tmp_path, archive_name="source.zip")


def test_archive_name_parse_errors_are_normalized(tmp_path: Path) -> None:
    with pytest.raises(evidence.EvidenceError, match="source archive name is invalid"):
        evidence.extract_license_files(b"text", "demo", tmp_path, archive_name="https://[")


def test_license_extraction_rejects_trailing_deflate_bytes(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, central = zip_record_offsets(content, "LICENSE")
    eocd = content.rfind(b"PK\x05\x06")
    local_compressed_size = int.from_bytes(content[local + 18 : local + 22], "little")
    content[central:central] = b"X"
    central += 1
    eocd += 1
    content[local + 18 : local + 22] = (local_compressed_size + 1).to_bytes(4, "little")
    content[central + 20 : central + 24] = (local_compressed_size + 1).to_bytes(4, "little")
    content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match="license payload disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_source_zip_crc_disagreement(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, central = zip_record_offsets(content, "LICENSE")
    content[local + 14 : local + 18] = (0).to_bytes(4, "little")
    content[central + 16 : central + 20] = (0).to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match="payload CRC disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_invalid_source_zip_directory_payload(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("source/", b"")]))
    local, central = zip_record_offsets(content, "source/")
    content[local + 14 : local + 18] = (1).to_bytes(4, "little")
    content[central + 16 : central + 20] = (1).to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match="directory has invalid payload metadata"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


@pytest.mark.parametrize("sentinel", [0xFFFF, 0xFFFFFFFF])
def test_license_extraction_rejects_source_zip64_eocd_sentinels(
    sentinel: int, tmp_path: Path
) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    if sentinel == 0xFFFF:
        content[eocd + 8 : eocd + 12] = sentinel.to_bytes(2, "little") * 2
    else:
        content[eocd + 12 : eocd + 20] = sentinel.to_bytes(4, "little") * 2

    with pytest.raises(evidence.EvidenceError, match="ZIP64"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_bounds_source_zip_metadata_and_licenses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    one_license = source_zip_bytes([("LICENSE", b"text")])
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_ENTRIES", 0)
    with pytest.raises(evidence.EvidenceError, match="entry count"):
        evidence.extract_license_files(one_license, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_ENTRIES", 10)
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_CENTRAL_DIRECTORY_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="central-directory boundary"):
        evidence.extract_license_files(one_license, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_CENTRAL_DIRECTORY_BYTES", 1024)
    monkeypatch.setattr(evidence, "MAX_SOURCE_LICENSE_FILES", 1)
    two_licenses = source_zip_bytes([("LICENSE", b"a"), ("NOTICE", b"b")])
    with pytest.raises(evidence.EvidenceError, match="too many license files"):
        evidence.extract_license_files(two_licenses, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_LICENSE_FILES", 10)
    monkeypatch.setattr(evidence, "MAX_SOURCE_LICENSE_TOTAL_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="license files exceed size limit"):
        evidence.extract_license_files(one_license, "demo", tmp_path)


def test_license_extraction_bounds_source_zip_expansion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    content = source_zip_bytes([("LICENSE", b"A" * 100)])
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_COMPRESSION_RATIO", 1)
    with pytest.raises(evidence.EvidenceError, match="resource limits"):
        evidence.extract_license_files(content, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_COMPRESSION_RATIO", 1_000)
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", 99)
    with pytest.raises(evidence.EvidenceError, match="cumulative expansion limit"):
        evidence.extract_license_files(content, "demo", tmp_path)


def test_license_extraction_ignores_safe_non_license_tar_symlinks(tmp_path: Path) -> None:
    archive = tar_bytes(
        {
            "demo/LICENSE": b"license text\n",
            "demo/src/tool.c": b"int main(void) { return 0; }\n",
        },
        links={"demo/src/tool-static.c": "tool.c"},
    )

    retained = evidence.extract_license_files(archive, "demo", tmp_path)

    assert len(retained) == 1
    assert retained[0].endswith("-LICENSE")
    assert (tmp_path / retained[0]).read_bytes() == b"license text\n"


def test_license_extraction_rejects_tar_symlink_license_evidence(tmp_path: Path) -> None:
    archive = tar_bytes(
        {"demo/COPYING": b"license text\n"},
        links={"demo/LICENSE": "COPYING"},
    )

    with pytest.raises(evidence.EvidenceError, match="license entry is not regular"):
        evidence.extract_license_files(archive, "demo", tmp_path)


def test_license_extraction_rejects_tar_symlink_payloads(tmp_path: Path) -> None:
    member = tarfile.TarInfo("demo/src/alias")
    member.type = tarfile.SYMTYPE
    member.linkname = "target"
    member.size = 1
    archive = member.tobuf(format=tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511 + b"\0" * 1024

    with pytest.raises(evidence.EvidenceError, match="symlink has a payload"):
        evidence.extract_license_files(archive, "demo", tmp_path)


@pytest.mark.parametrize("target", ("../outside", "/absolute", "dir\\alias"))
def test_license_extraction_rejects_unsafe_tar_symlink_targets(target: str, tmp_path: Path) -> None:
    archive = tar_bytes(
        {"demo/LICENSE": b"license text\n"},
        links={"demo/src/alias": target},
    )

    with pytest.raises(evidence.EvidenceError, match="unsafe archive link target"):
        evidence.extract_license_files(archive, "demo", tmp_path)


def test_license_extraction_still_rejects_tar_hardlinks(tmp_path: Path) -> None:
    archive = tar_bytes(
        {"demo/LICENSE": b"license text\n"},
        hardlinks={"demo/src/alias": "demo/LICENSE"},
    )

    with pytest.raises(evidence.EvidenceError, match="unsupported entry"):
        evidence.extract_license_files(archive, "demo", tmp_path)


@pytest.mark.parametrize("signature", (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
def test_license_extraction_rejects_every_zip_signature(signature: bytes, tmp_path: Path) -> None:
    with pytest.raises(evidence.EvidenceError, match="source ZIP"):
        evidence.extract_license_files(signature, "demo", tmp_path)


def test_tar_extension_payload_is_bounded_before_materialization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("LICENSE")
        member.size = 4
        member.pax_headers = {"comment": "x" * 2048}
        archive.addfile(member, io.BytesIO(b"text"))
    monkeypatch.setattr(evidence, "MAX_TAR_EXTENSION_BYTES", 1024)

    with pytest.raises(evidence.EvidenceError, match="extension header"):
        evidence.extract_license_files(archive_bytes.getvalue(), "demo", tmp_path)


def test_gnu_sparse_tar_entries_are_rejected(tmp_path: Path) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("LICENSE")
        member.size = 4
        member.pax_headers = {
            "GNU.sparse.map": "0,4",
            "GNU.sparse.size": "4",
        }
        archive.addfile(member, io.BytesIO(b"text"))

    with pytest.raises(evidence.EvidenceError, match="GNU sparse"):
        evidence.extract_license_files(archive_bytes.getvalue(), "demo", tmp_path)


def test_negative_pax_member_size_fails_closed(tmp_path: Path) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        hostile = tarfile.TarInfo("hostile")
        hostile.pax_headers = {"size": "-512"}
        archive.addfile(hostile)
        license_member = tarfile.TarInfo("LICENSE")
        license_member.size = 4
        archive.addfile(license_member, io.BytesIO(b"text"))

    with pytest.raises(evidence.EvidenceError, match=r"PAX|negative"):
        evidence.extract_license_files(archive_bytes.getvalue(), "demo", tmp_path)


def test_policy_comparison_and_human_approval_are_separate() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(
        component,
        "MIT",
        license_texts=[
            {
                "id": "MIT",
                "sha256": "e5" * 32,
                "url": "https://example.com/MIT.txt",
            }
        ],
    )
    evidence.verify_inventory(inventory, policy, require_approval=False)
    with pytest.raises(evidence.EvidenceError, match="maintainer approval"):
        evidence.verify_inventory(inventory, policy, require_approval=True)

    policy["distribution_approval"] = {
        "approved": True,
        "approved_by": "maintainer",
        "approved_on": "2026-07-14",
        "rationale": "Test-only approval.",
    }
    evidence.verify_inventory(inventory, policy, require_approval=True)

    policy["platforms"]["linux/amd64"][0] = {**component, "version": "2"}
    with pytest.raises(evidence.EvidenceError, match="differs from the reviewed policy"):
        evidence.verify_inventory(inventory, policy, require_approval=False)


def test_incomplete_native_coverage_cannot_claim_distribution_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    committed_policy = cast(
        dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text())
    )
    committed_policy["distribution_approval"] = {
        "approved": True,
        "approved_by": "maintainer",
        "approved_on": "2026-07-22",
        "rationale": "This must not override open owner reviews.",
    }
    with pytest.raises(evidence.EvidenceError, match=r"cannot be true while.*incomplete"):
        evidence.validate_policy_schema(committed_policy)

    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(
        component,
        "MIT",
        license_texts=[
            {
                "id": "MIT",
                "sha256": "e5" * 32,
                "url": "https://example.com/MIT.txt",
            }
        ],
    )
    policy["distribution_approval"] = {
        "approved": True,
        "approved_by": "maintainer",
        "approved_on": "2026-07-22",
        "rationale": "This must not override derived evidence.",
    }
    monkeypatch.setattr(
        evidence,
        "native_component_coverage_ledger",
        lambda _inventory, _policy: {
            "complete": False,
            "resolved_owners": [],
            "unresolved_owners": [{"owner": "python:demo@1"}],
        },
    )

    with pytest.raises(evidence.EvidenceError, match=r"cannot be true while.*incomplete"):
        evidence.verify_inventory(inventory, policy, require_approval=False)


def test_standalone_verification_rejects_extra_standard_license_text() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(
        component,
        "MIT",
        license_texts=[
            {
                "id": "MIT",
                "sha256": "e5" * 32,
                "url": "https://example.com/MIT.txt",
            }
        ],
    )
    policy["license_texts"].append(
        {
            "id": "Apache-2.0",
            "sha256": "a" * 64,
            "url": "https://example.com/Apache-2.0.txt",
        }
    )

    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)


def test_standard_license_union_includes_direct_reviews_in_open_owners() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    policy = standalone_policy(
        component,
        "MIT",
        license_texts=[
            {
                "id": "MIT",
                "sha256": "e5" * 32,
                "url": "https://example.com/MIT.txt",
            }
        ],
    )
    native_policy = native_component_v7_policy_case()
    for records in native_policy["native_component_coverage"].values():
        owner = records[0]
        owner["component_reviews"][0]["reviewed_license"] = "Apache-2.0"
        owner["known_omissions"] = [
            {
                "id": "missing-build-proof",
                "component": {
                    "type": "library",
                    "name": "demo-build",
                    "version": "1.0",
                    "purl": "",
                },
                "observations": [],
                "payload_roles": [],
                "missing_evidence": ["build-material-attestation"],
                "reason": "The exact build-material proof is not retained.",
            }
        ]
        owner["review"] = {
            "state": "open",
            "reason": "One build-material proof remains open.",
            "unresolved_items": ["missing-build-proof"],
        }
    evidence.validate_native_component_policy_schema(native_policy)
    policy.update(native_policy)

    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.validate_standard_license_text_coverage(
            [component, synthetic_runtime_component()], policy
        )

    policy["license_texts"].append(
        {
            "id": "Apache-2.0",
            "sha256": "a" * 64,
            "url": "https://example.com/Apache-2.0.txt",
        }
    )
    evidence.validate_standard_license_text_coverage(
        [component, synthetic_runtime_component()], policy
    )


def test_license_refs_require_exact_pinned_custom_evidence() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "Custom",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(component, "LicenseRef-Demo", license_texts=[])
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    requirement = {
        "components": ["python:demo@1"],
        "evidence": {
            "python:demo@1": {
                "path": "licenses/from-source/python-demo-1/notice-LICENSE",
                "sha256": "a" * 64,
            }
        },
        "rationale": "Exact source-carried notice reviewed.",
        "require_source_notice": True,
    }
    policy["custom_license_evidence"] = {"LicenseRef-Demo": requirement}
    evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {
        "LicenseRef-Demo": requirement,
        "LicenseRef-Unused": requirement,
    }
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {"LicenseRef-Demo": {**requirement, "rationale": ""}}
    with pytest.raises(evidence.EvidenceError, match="has no rationale"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {"LicenseRef-Demo": requirement}
    unrelated = [
        {
            "component": "python-demo-1",
            "path": "licenses/from-source/python-demo-1/COPYING.GPL",
            "sha256": "b" * 64,
        }
    ]
    with pytest.raises(evidence.EvidenceError, match="pinned source-carried notice"):
        evidence.verify_pinned_custom_license_records(inventory["components"], policy, unrelated)


def test_runtime_license_ref_uses_the_canonical_component_key() -> None:
    runtime = synthetic_runtime_component()
    component = "runtime:cpython@3.14.6"
    path = "licenses/from-source/runtime-cpython-3.14.6/LICENSE"
    digest = "a" * 64
    policy = {
        "license_resolutions": {
            component: {
                "expression": "LicenseRef-CPython",
                "rationale": "Reviewed synthetic CPython license.",
            }
        },
        "custom_license_evidence": {
            "LicenseRef-CPython": {
                "components": [component],
                "evidence": {component: {"path": path, "sha256": digest}},
                "rationale": "Exact source-carried CPython license reviewed.",
                "require_source_notice": True,
            }
        },
    }

    evidence.verify_pinned_custom_license_records(
        [runtime],
        policy,
        [{"component": component, "path": path, "sha256": digest}],
    )
    with pytest.raises(evidence.EvidenceError, match="pinned source-carried notice"):
        evidence.verify_pinned_custom_license_records(
            [runtime],
            policy,
            [{"component": "runtime-cpython-3.14.6", "path": path, "sha256": digest}],
        )


def test_image_revision_and_version_must_match_source() -> None:
    revision = "a" * 40
    inventory = {"image_revision": revision, "image_version": "1.2.3"}
    evidence.verify_image_revision(inventory, version="1.2.3", source_revision=revision)
    with pytest.raises(evidence.EvidenceError, match="does not match source revision"):
        evidence.verify_image_revision(inventory, version="1.2.3", source_revision="b" * 40)
    with pytest.raises(evidence.EvidenceError, match="image version"):
        evidence.verify_image_revision(inventory, version="1.2.4", source_revision=revision)


def test_application_artifact_labels_require_exact_proof_binding() -> None:
    inventory = standalone_inventory(
        {
            "ecosystem": "python",
            "name": "demo",
            "version": "1",
            "observed_license": "MIT",
            "effective": True,
            "metadata_sha256": "a" * 64,
        }
    )
    evidence.verify_application_artifact_labels(
        inventory,
        source_revision="c" * 40,
        wheel_sha256="e" * 64,
        selection_record_sha256="f" * 64,
    )

    for field, value in (
        ("image_revision", "d" * 40),
        ("application_wheel_sha256", "1" * 64),
        ("application_selection_record_sha256", "2" * 64),
    ):
        changed = copy.deepcopy(inventory)
        changed[field] = value
        with pytest.raises(evidence.EvidenceError, match="does not match selected"):
            evidence.verify_application_artifact_labels(
                changed,
                source_revision="c" * 40,
                wheel_sha256="e" * 64,
                selection_record_sha256="f" * 64,
            )

    for field in ("application_wheel_sha256", "application_selection_record_sha256"):
        changed = copy.deepcopy(inventory)
        changed[field] = ""
        with pytest.raises(evidence.EvidenceError, match=f"invalid {field}"):
            evidence.validate_component_inventory(changed)


def test_selected_wheel_contract_binds_every_application_owned_file() -> None:
    component = {
        "ecosystem": "python",
        "name": "extra-codeowners",
        "version": "1",
        "observed_license": "Apache-2.0",
        "effective": True,
        "metadata_sha256": "a" * 64,
    }
    inventory = standalone_inventory(component)
    alternatives: list[dict[str, Any]] = []
    for index, interpreter in enumerate(("python", "python3", "python3.14"), start=1):
        alternatives.append(
            {
                "launcher_interpreter": interpreter,
                "files": [
                    {
                        "path": "bin/extra-codeowners",
                        "sha256": str(index) * 64,
                        "size": 300 + index,
                        "mode": 0o755,
                    },
                    {
                        "path": "lib/python3.14/site-packages/extra_codeowners-1.dist-info/RECORD",
                        "sha256": str(index + 3) * 64,
                        "size": 500 + index,
                        "mode": 0o644,
                    },
                    {
                        "path": "lib/python3.14/site-packages/extra_codeowners/app.py",
                        "sha256": "a" * 64,
                        "size": 10,
                        "mode": 0o644,
                    },
                ],
            }
        )
    contract = {
        "environment_root": "/opt/venv",
        "project": "extra-codeowners",
        "version": "1",
        "python_directory": "python3.14",
        "alternatives": alternatives,
    }
    selected = alternatives[1]["files"]
    inventory["python_record_ownership"] = [
        {
            "owner": "extra-codeowners",
            "effective": True,
            "layer": 1,
            "path": f"opt/venv/{record['path']}",
            "sha256": record["sha256"],
            "size": record["size"],
            "mode": record["mode"],
            "uid": 0,
            "gid": 0,
        }
        for record in selected
    ]
    # Exercise the compatibility projection separately from the historical
    # installation evidence asserted below.
    inventory["wheel_installations"] = None

    assert evidence.verify_selected_application_installation(inventory, contract) == "python3"

    for path_suffix in ("app.py", "bin/extra-codeowners", ".dist-info/RECORD"):
        changed = copy.deepcopy(inventory)
        owned = next(
            record
            for record in changed["python_record_ownership"]
            if record["path"].endswith(path_suffix)
        )
        owned["sha256"] = "f" * 64
        with pytest.raises(evidence.EvidenceError, match="differs from every"):
            evidence.verify_selected_application_installation(changed, contract)

    self_consistent_rewrite = copy.deepcopy(inventory)
    application = next(
        record
        for record in self_consistent_rewrite["python_record_ownership"]
        if record["path"].endswith("app.py")
    )
    installed_record = next(
        record
        for record in self_consistent_rewrite["python_record_ownership"]
        if record["path"].endswith(".dist-info/RECORD")
    )
    application.update({"sha256": "e" * 64, "size": 11})
    installed_record.update({"sha256": "d" * 64, "size": 502})
    with pytest.raises(evidence.EvidenceError, match="differs from every"):
        evidence.verify_selected_application_installation(self_consistent_rewrite, contract)

    historical_occurrence = copy.deepcopy(inventory)
    hidden = copy.deepcopy(historical_occurrence["python_record_ownership"][0])
    hidden.update({"effective": False, "layer": 0, "sha256": "c" * 64})
    historical_occurrence["python_record_ownership"].append(hidden)
    with pytest.raises(evidence.EvidenceError, match="invalid runtime identity"):
        evidence.verify_selected_application_installation(historical_occurrence, contract)

    def historical_installation(
        files: list[dict[str, Any]],
        *,
        layer: int,
        effective: bool,
        owner: str = "python:extra-codeowners@1",
    ) -> dict[str, Any]:
        entries = []
        for file in files:
            occurrence = {
                "effective": effective,
                "layer": layer,
                "path": f"opt/venv/{file['path']}",
                "sha256": file["sha256"],
                "size": file["size"],
                "mode": file["mode"],
                "uid": 0,
                "gid": 0,
            }
            entries.append({"path": occurrence["path"], "occurrence": occurrence})
        record = next(
            entry["occurrence"] for entry in entries if entry["path"].endswith(".dist-info/RECORD")
        )
        return {"owner": owner, "record": record, "entries": entries}

    occurrence_inventory = copy.deepcopy(inventory)
    occurrence_inventory["wheel_installations"] = [
        historical_installation(alternatives[0]["files"], layer=1, effective=False),
        historical_installation(alternatives[1]["files"], layer=2, effective=True),
    ]
    assert (
        evidence.verify_selected_application_installation(occurrence_inventory, contract)
        == "python3"
    )

    rewritten_history = copy.deepcopy(occurrence_inventory)
    historical_entries = rewritten_history["wheel_installations"][0]["entries"]
    historical_app = next(entry for entry in historical_entries if entry["path"].endswith("app.py"))
    historical_record = next(
        entry for entry in historical_entries if entry["path"].endswith(".dist-info/RECORD")
    )
    historical_app["occurrence"].update({"sha256": "b" * 64, "size": 12})
    historical_record["occurrence"].update({"sha256": "c" * 64, "size": 503})
    with pytest.raises(evidence.EvidenceError, match="distributed application installation"):
        evidence.verify_selected_application_installation(rewritten_history, contract)

    old_application = copy.deepcopy(occurrence_inventory)
    old_application["wheel_installations"][0]["owner"] = "python:extra-codeowners@0.9"
    with pytest.raises(evidence.EvidenceError, match="selected version"):
        evidence.verify_selected_application_installation(old_application, contract)


def test_dockerfile_builder_and_final_runtime_match_reviewed_base(tmp_path: Path) -> None:
    digest = "sha256:" + "b" * 64
    policy = {"base_image": "python:3.14-alpine", "base_image_index_digest": digest}
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        f"FROM python:3.14-alpine@{digest} AS builder\n"
        "FROM builder AS test\n"
        f"FROM python:3.14-alpine@{digest} AS runtime\n"
    )
    evidence.verify_dockerfile_base(dockerfile, policy)

    policy["base_image_index_digest"] = "sha256:" + "c" * 64
    with pytest.raises(evidence.EvidenceError, match="builder stage"):
        evidence.verify_dockerfile_base(dockerfile, policy)

    policy["base_image_index_digest"] = digest
    dockerfile.write_text(
        dockerfile.read_text() + "FROM python:3.14-alpine@" + digest + " AS debug\n"
    )
    with pytest.raises(evidence.EvidenceError, match="final build stage"):
        evidence.verify_dockerfile_base(dockerfile, policy)


def test_committed_dockerfile_matches_the_reviewed_base_policy() -> None:
    policy = json.loads(Path(".compliance/container-policy.json").read_text())
    evidence.verify_dockerfile_base(Path("Dockerfile"), policy)


def test_final_image_layers_must_begin_with_the_reviewed_platform_base() -> None:
    policy = {
        "base_image_platforms": {
            platform: {
                "layer_diff_ids": ["sha256:" + character * 64],
            }
            for platform, character in (
                ("linux/amd64", "a"),
                ("linux/arm64", "b"),
            )
        }
    }
    files: dict[str, Any] = {
        "platform": "linux/amd64",
        "layers": [
            {"digest": "sha256:" + "a" * 64},
            {"digest": "sha256:" + "c" * 64},
        ],
    }

    evidence.verify_base_layer_binding(files, policy)
    files["layers"][0]["digest"] = "sha256:" + "d" * 64
    with pytest.raises(evidence.EvidenceError, match="do not begin with"):
        evidence.verify_base_layer_binding(files, policy)


@pytest.mark.parametrize(
    "hostile_path",
    (
        "usr/local/lib/python3.14/sitecustomize.py",
        "usr/local/bin/unreviewed-executable",
    ),
)
def test_post_base_provenance_rejects_unclassified_regular_files(
    hostile_path: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    license_content = b"reviewed application license\n"
    installed = {
        "demo.py": b"VALUE = 'reviewed'\n",
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    base = tar_bytes({"lib/apk/db/installed": apk_database()})
    application_files = {
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
        "usr/share/licenses/extra-codeowners/LICENSE": license_content,
        **{f"{site}/{path}": content for path, content in installed.items()},
    }
    application = tar_bytes(
        application_files,
        links=VENV_LINKS,
        directories=explicit_parent_directories((*application_files, *VENV_LINKS)),
    )
    clean_image = tmp_path / "clean.tar"
    saved_image_layers(clean_image, [base, application])
    clean_inventory, clean_files = evidence._inventory_saved_image(
        clean_image, "linux/amd64", "sha256:" + "a" * 64
    )
    base_digest = clean_files["layers"][0]["digest"]
    clean_directory_effects, _clean_removals = evidence.canonical_post_base_filesystem_changes(
        clean_files, 1, "linux/amd64"
    )
    policy = {
        "base_image_platforms": {
            "linux/amd64": {
                "layer_diff_ids": [base_digest],
            },
            "linux/arm64": {
                "layer_diff_ids": ["sha256:" + "e" * 64],
            },
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": clean_inventory["apk_database_occurrences"],
                "post_base_directory_effects": clean_directory_effects,
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    monkeypatch.setattr(
        evidence,
        "run",
        lambda *_args, **_kwargs: license_content,
    )
    evidence.verify_post_base_provenance(clean_inventory, clean_files, policy, tmp_path)

    hostile_image = tmp_path / "hostile.tar"
    saved_image_layers(hostile_image, [base, application, tar_bytes({hostile_path: b"payload"})])
    hostile_inventory, hostile_files = evidence._inventory_saved_image(
        hostile_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="unclassified post-base regular file"):
        evidence.verify_post_base_provenance(hostile_inventory, hostile_files, policy, tmp_path)

    hostile = evidence.PurePosixPath(hostile_path)
    marker = str(hostile.parent / f".wh.{hostile.name}")
    hidden_image = tmp_path / "hidden-hostile.tar"
    saved_image_layers(
        hidden_image,
        [base, application, tar_bytes({hostile_path: b"payload"}), tar_bytes({marker: b""})],
    )
    hidden_inventory, hidden_files = evidence._inventory_saved_image(
        hidden_image, "linux/amd64", "sha256:" + "a" * 64
    )
    hidden_policy = copy.deepcopy(policy)
    hidden_policy["filesystem_baselines"]["linux/amd64"]["post_base_removals"] = [
        {field: record[field] for field in ("kind", "path", "target")}
        for record in hidden_files["whiteouts"]
        if record["layer"] >= 1
    ]
    with pytest.raises(evidence.EvidenceError, match="unclassified post-base regular file"):
        evidence.verify_post_base_provenance(
            hidden_inventory, hidden_files, hidden_policy, tmp_path
        )

    altered_license_image = tmp_path / "altered-license.tar"
    saved_image_layers(
        altered_license_image,
        [
            base,
            application,
            tar_bytes({"usr/share/licenses/extra-codeowners/LICENSE": b"altered license\n"}),
        ],
    )
    altered_inventory, altered_files = evidence._inventory_saved_image(
        altered_license_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="LICENSE differs from Git HEAD"):
        evidence.verify_post_base_provenance(altered_inventory, altered_files, policy, tmp_path)

    extra_link_image = tmp_path / "extra-link.tar"
    saved_image_layers(
        extra_link_image,
        [base, application, tar_bytes({}, links={"usr/local/bin/unreviewed": "python3"})],
    )
    link_inventory, link_files = evidence._inventory_saved_image(
        extra_link_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="unreviewed post-base non-regular"):
        evidence.verify_post_base_provenance(link_inventory, link_files, policy, tmp_path)

    whiteout_path = "usr/local/bin/.wh.unreviewed"
    whiteout_image = tmp_path / "unreviewed-whiteout.tar"
    saved_image_layers(
        whiteout_image,
        [base, application, tar_bytes({whiteout_path: b""})],
    )
    with pytest.raises(evidence.EvidenceError, match="absent from lower layers"):
        evidence._inventory_saved_image(whiteout_image, "linux/amd64", "sha256:" + "a" * 64)


def test_directory_effects_ignore_portable_repeated_headers(tmp_path: Path) -> None:
    base = tar_bytes(
        {"lib/apk/db/installed": apk_database()},
        directories=["etc"],
    )
    without_repeated_header = tmp_path / "without-repeated-directory.tar"
    saved_image_layers(without_repeated_header, [base, tar_bytes({})])
    _inventory, without_files = evidence._inventory_saved_image(
        without_repeated_header, "linux/amd64", "sha256:" + "a" * 64
    )
    with_repeated_header = tmp_path / "with-repeated-directory.tar"
    saved_image_layers(with_repeated_header, [base, tar_bytes({}, directories=["etc"])])
    _inventory, with_files = evidence._inventory_saved_image(
        with_repeated_header, "linux/amd64", "sha256:" + "a" * 64
    )

    without_effects, without_removals = evidence.canonical_post_base_filesystem_changes(
        without_files, 1, "linux/amd64"
    )
    with_effects, with_removals = evidence.canonical_post_base_filesystem_changes(
        with_files, 1, "linux/amd64"
    )

    assert len(with_files["directories"]) == len(without_files["directories"]) + 1
    assert with_effects == without_effects == []
    assert with_removals == without_removals == []


def test_directory_effects_retain_real_transitions_and_reject_hostile_noops(
    tmp_path: Path,
) -> None:
    base = tar_bytes(
        {"lib/apk/db/installed": apk_database()},
        directories=["etc", "opt"],
        headers={"etc": {"mode": 0o777}},
    )
    image = tmp_path / "hostile-noop-directory.tar"
    saved_image_layers(
        image,
        [
            base,
            tar_bytes(
                {},
                directories=["etc", "opt/application"],
                headers={"etc": {"mode": 0o777}},
            ),
        ],
    )
    _inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    with pytest.raises(evidence.EvidenceError, match="root-owned"):
        evidence.canonical_post_base_filesystem_changes(files, 1, "linux/amd64")

    safe_image = tmp_path / "safe-directory-effect.tar"
    saved_image_layers(
        safe_image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database()}, directories=["etc", "opt"]),
            tar_bytes({}, directories=["etc", "opt/application"]),
        ],
    )
    _inventory, safe_files = evidence._inventory_saved_image(
        safe_image, "linux/amd64", "sha256:" + "a" * 64
    )
    effects, removals = evidence.canonical_post_base_filesystem_changes(
        safe_files, 1, "linux/amd64"
    )
    assert effects == [
        {
            "layer": 1,
            "path": "opt/application",
            "mode": 0o755,
            "uid": 0,
            "gid": 0,
        }
    ]
    assert removals == []
    with pytest.raises(evidence.EvidenceError, match="invalid post-base directory-effect"):
        evidence.validate_directory_effect_policy(
            [{**effects[0], "effective": True}], "linux/amd64"
        )

    policy = {
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [safe_files["layers"][0]["digest"]]},
            "linux/arm64": {"layer_diff_ids": ["sha256:" + "b" * 64]},
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": effects,
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    evidence.verify_post_base_filesystem_policy(safe_files, policy)
    policy["filesystem_baselines"]["linux/amd64"]["post_base_directory_effects"] = []
    with pytest.raises(evidence.EvidenceError, match="directory effects differ"):
        evidence.verify_post_base_filesystem_policy(safe_files, policy)


def test_post_base_semantic_replay_rejects_implicit_parent_directories(
    tmp_path: Path,
) -> None:
    image = tmp_path / "implicit-post-base-parent.tar"
    saved_image_layers(
        image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database()}),
            tar_bytes({"unreviewed-parent/payload": b"content"}),
        ],
    )
    _inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    with pytest.raises(evidence.EvidenceError, match="implicit parent directory"):
        evidence.canonical_post_base_filesystem_changes(files, 1, "linux/amd64")


def test_removal_policy_ignores_whiteout_marker_header_metadata(tmp_path: Path) -> None:
    expected = [
        {
            "kind": "whiteout",
            "path": ".wh.removed",
            "target": "removed",
        }
    ]
    observed_modes: list[int] = []
    for mode in (0, 0o600, 0o644):
        image = tmp_path / f"whiteout-{mode:o}.tar"
        saved_image_layers(
            image,
            [
                tar_bytes(
                    {
                        "lib/apk/db/installed": apk_database(),
                        "removed": b"lower-layer content",
                    }
                ),
                tar_bytes({".wh.removed": b""}, headers={".wh.removed": {"mode": mode}}),
            ],
        )
        _inventory, files = evidence._inventory_saved_image(
            image, "linux/amd64", "sha256:" + "a" * 64
        )
        _effects, removals = evidence.canonical_post_base_filesystem_changes(
            files, 1, "linux/amd64"
        )
        observed_modes.append(files["whiteouts"][0]["mode"])
        assert removals == expected

    assert observed_modes == [0, 0o600, 0o644]
    with pytest.raises(evidence.EvidenceError, match="invalid post-base removal"):
        evidence.validate_removal_policy([{**expected[0], "mode": 0}], "linux/amd64")

    policy: dict[str, Any] = {
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [files["layers"][0]["digest"]]},
            "linux/arm64": {"layer_diff_ids": ["sha256:" + "b" * 64]},
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": expected,
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    evidence.verify_post_base_filesystem_policy(files, policy)
    for reviewed_removals in (
        [],
        [{"kind": "whiteout", "path": ".wh.other", "target": "other"}],
        [*expected, {"kind": "whiteout", "path": ".wh.other", "target": "other"}],
    ):
        altered = copy.deepcopy(policy)
        altered["filesystem_baselines"]["linux/amd64"]["post_base_removals"] = reviewed_removals
        with pytest.raises(evidence.EvidenceError, match="removals differ"):
            evidence.verify_post_base_filesystem_policy(files, altered)


def test_post_base_provenance_rejects_hostile_tar_security_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    source_path = f"{site}/demo.py"
    license_path = "usr/share/licenses/extra-codeowners/LICENSE"
    license_content = b"reviewed application license\n"
    installed = {
        "demo.py": b"VALUE = 'reviewed'\n",
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    application_files = {
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
        license_path: license_content,
        **{f"{site}/{path}": content for path, content in installed.items()},
    }
    base = tar_bytes({"lib/apk/db/installed": apk_database()})

    def collect(
        name: str,
        *,
        headers: dict[str, dict[str, Any]] | None = None,
        directories: list[str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        image = tmp_path / name
        selected_directories = set(explicit_parent_directories((*application_files, *VENV_LINKS)))
        for directory in directories or []:
            selected_directories.add(directory)
            selected_directories.update(explicit_parent_directories([directory]))
        application = tar_bytes(
            application_files,
            links=VENV_LINKS,
            directories=sorted(
                selected_directories,
                key=lambda path: (len(PurePosixPath(path).parts), path),
            ),
            headers=headers,
        )
        saved_image_layers(image, [base, application])
        return cast(
            tuple[dict[str, Any], dict[str, Any]],
            evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64),
        )

    clean_inventory, clean_files = collect("clean-metadata.tar")
    base_digest = clean_files["layers"][0]["digest"]
    clean_directory_effects, _clean_removals = evidence.canonical_post_base_filesystem_changes(
        clean_files, 1, "linux/amd64"
    )
    policy = {
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [base_digest]},
            "linux/arm64": {"layer_diff_ids": ["sha256:" + "b" * 64]},
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": clean_inventory["apk_database_occurrences"],
                "post_base_directory_effects": clean_directory_effects,
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    monkeypatch.setattr(evidence, "run", lambda *_args, **_kwargs: license_content)

    for index, target in enumerate((source_path, license_path)):
        hostile_inventory, hostile_files = collect(
            f"hostile-header-{index}.tar",
            headers={target: {"mode": 0o4777, "uid": 1234, "gid": 5678}},
        )
        with pytest.raises(evidence.EvidenceError, match="must be root-owned"):
            evidence.verify_post_base_provenance(hostile_inventory, hostile_files, policy, tmp_path)

    with pytest.raises(evidence.EvidenceError, match="unsupported PAX fields"):
        collect(
            "hostile-capability.tar",
            headers={source_path: {"pax_headers": {"SCHILY.xattr.security.capability": "hostile"}}},
        )

    directory_inventory, directory_files = collect(
        "hostile-directory.tar",
        directories=["etc/extra-codeowners-hostile"],
        headers={"etc/extra-codeowners-hostile": {"mode": 0o777}},
    )
    with pytest.raises(evidence.EvidenceError, match="root-owned"):
        evidence.verify_post_base_provenance(directory_inventory, directory_files, policy, tmp_path)


def test_deep_inventory_validation_rejects_truncated_or_rebound_records(
    tmp_path: Path,
) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    evidence.validate_all_layer_inventory(files, inventory)

    truncated = copy.deepcopy(files)
    truncated["regular_files"].pop()
    with pytest.raises(evidence.EvidenceError, match="counts do not match"):
        evidence.validate_all_layer_inventory(truncated, inventory)

    rebound = copy.deepcopy(files)
    rebound["image_config_digest"] = "sha256:" + "b" * 64
    with pytest.raises(evidence.EvidenceError, match="disagree about image_config_digest"):
        evidence.validate_all_layer_inventory(rebound, inventory)

    fabricated = copy.deepcopy(files)
    fabricated["regular_files"][0]["layer_digest"] = "sha256:" + "c" * 64
    with pytest.raises(evidence.EvidenceError, match="wrong layer digest"):
        evidence.validate_all_layer_inventory(fabricated, inventory)

    noncanonical = copy.deepcopy(files)
    noncanonical["regular_files"][0]["path"] = "./" + noncanonical["regular_files"][0]["path"]
    with pytest.raises(evidence.EvidenceError, match="canonical archive path"):
        evidence.validate_all_layer_inventory(noncanonical, inventory)


def test_inventory_reports_unexpanded_wheel_sboms_and_native_payloads(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        "demo-1.0.dist-info/sboms/auditwheel.cdx.json": cyclonedx_sbom(),
        "demo.libs/libdemo.so.1": elf64_payload(),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    assert [item["path"] for item in inventory["embedded_sboms"]] == [
        f"{site}/demo-1.0.dist-info/sboms/auditwheel.cdx.json"
    ]
    assert [item["path"] for item in inventory["native_payloads"]] == [
        f"{site}/demo.libs/libdemo.so.1"
    ]
    assert inventory["embedded_sboms"][0]["owner"] == "python:demo@1.0"
    assert inventory["embedded_sboms"][0]["cyclonedx"]["components"] == [
        {
            "type": "library",
            "name": "libdemo",
            "version": "1.2.3",
            "purl": "pkg:generic/libdemo@1.2.3",
            "bom_ref": "pkg:generic/libdemo@1.2.3",
            "hashes": [],
            "licenses": [],
        }
    ]
    assert inventory["native_payloads"][0]["owner"] == "python:demo@1.0"
    assert inventory["native_payloads"][0]["elf"] == {
        "bits": 64,
        "endianness": "little",
        "machine": "x86_64",
        "machine_id": 62,
    }
    assert {item["path"] for item in inventory["wheel_identity_files"]} == {
        f"{site}/demo-1.0.dist-info/RECORD",
        f"{site}/demo-1.0.dist-info/WHEEL",
    }
    evidence.validate_all_layer_inventory(files, inventory)

    omitted = copy.deepcopy(inventory)
    omitted["embedded_sboms"] = []
    with pytest.raises(evidence.EvidenceError, match="omits or alters embedded wheel SBOMs"):
        evidence.validate_all_layer_inventory(files, omitted)

    payload_policy = {"unexpanded_python_payloads": empty_unexpanded_payload_policy()}
    payload_policy["unexpanded_python_payloads"]["linux/amd64"] = {
        "embedded_sboms": [
            evidence.payload_record_projection(record) for record in inventory["embedded_sboms"]
        ],
        "native_payloads": [
            evidence.payload_record_projection(record) for record in inventory["native_payloads"]
        ],
        "wheel_identity_files": copy.deepcopy(inventory["wheel_identity_files"]),
    }
    evidence.verify_unexpanded_payload_policy(inventory, payload_policy)

    changed_native = copy.deepcopy(inventory)
    changed_native["native_payloads"][0]["sha256"] = "a" * 64
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(changed_native, payload_policy)

    changed_sbom = copy.deepcopy(inventory)
    changed_sbom["embedded_sboms"][0]["sha256"] = "b" * 64
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(changed_sbom, payload_policy)

    changed_wheel = copy.deepcopy(inventory)
    changed_wheel["wheel_identity_files"][0]["sha256"] = "c" * 64
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(changed_wheel, payload_policy)


def test_cyclonedx_projection_uses_bom_ref_for_repeated_purl_occurrences() -> None:
    component = {
        "type": "library",
        "name": "libdemo",
        "version": "1.2.3",
        "purl": "pkg:generic/libdemo@1.2.3",
        "bom-ref": "libdemo:first",
    }
    second = copy.deepcopy(component)
    second["bom-ref"] = "libdemo:second"
    parsed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[second, component]), "demo.cdx.json"
    )
    reversed_order = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[component, second]), "demo.cdx.json"
    )
    assert parsed == reversed_order
    assert [item["bom_ref"] for item in parsed["components"]] == [
        "libdemo:first",
        "libdemo:second",
    ]

    conflicting_purl = copy.deepcopy(component)
    conflicting_purl["purl"] = "pkg:generic/libdemo@9.9.9"
    conflicting_purl["bom-ref"] = "libdemo-nine"
    parsed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[component, conflicting_purl]), "distinct.cdx.json"
    )
    assert [item["purl"] for item in parsed["components"]] == [
        "pkg:generic/libdemo@1.2.3",
        "pkg:generic/libdemo@9.9.9",
    ]

    duplicate_ref = copy.deepcopy(component)
    duplicate_ref["name"] = "other"
    with pytest.raises(evidence.EvidenceError, match="repeats a non-echo bom-ref"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[component, duplicate_ref]), "duplicate-ref.cdx.json"
        )

    missing_ref = copy.deepcopy(component)
    missing_ref.pop("bom-ref")
    with pytest.raises(evidence.EvidenceError, match="mixed or repeated fallback purl"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[component, missing_ref]), "mixed-identity.cdx.json"
        )


def test_cyclonedx_parser_accepts_nested_components_beyond_observation_array_limit() -> None:
    root = identified_cyclonedx_component("root")
    child_count = evidence.MAX_CYCLONEDX_OBSERVATION_VALUES + 1
    root["components"] = [
        identified_cyclonedx_component(f"child-{index}") for index in range(child_count)
    ]

    parsed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[root]),
        "nested-components.cdx.json",
    )

    assert len(parsed["components"]) == child_count + 1


def test_cyclonedx_parser_enforces_nested_component_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evidence, "MAX_CYCLONEDX_COMPONENTS", 4)
    root = identified_cyclonedx_component("root")
    root["components"] = [identified_cyclonedx_component(f"child-{index}") for index in range(5)]

    with pytest.raises(evidence.EvidenceError, match="too many nested components"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[root]),
            "too-many-nested-components.cdx.json",
        )


def test_cyclonedx_parser_keeps_general_nested_arrays_observation_bounded() -> None:
    root = identified_cyclonedx_component("root")
    root["extension"] = {"components": [None] * (evidence.MAX_CYCLONEDX_OBSERVATION_VALUES + 1)}

    with pytest.raises(evidence.EvidenceError, match="too many values"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[root]),
            "oversized-extension-array.cdx.json",
        )


def auditwheel_fixture_bytes(filename: str) -> bytes:
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "container_evidence"
        / "v7"
        / "auditwheel"
        / f"{filename}.b64"
    )
    return base64.b64decode(
        b"".join(fixture.read_bytes().splitlines()),
        validate=True,
    )


def real_v7_fixture_bytes(filename: str) -> bytes:
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "container_evidence"
        / "v7"
        / "real"
        / f"{filename}.b64"
    )
    return base64.b64decode(
        b"".join(fixture.read_bytes().splitlines()),
        validate=True,
    )


def real_v7_crate_bytes(name: str, version: str) -> bytes:
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "container_evidence"
        / "v7"
        / "real"
        / "crates"
        / f"{name}-{version}.crate.b64"
    )
    return base64.b64decode(
        b"".join(fixture.read_bytes().splitlines()),
        validate=True,
    )


def real_rust_cargo_lock_case(
    *,
    owner: str,
    sbom_filename: str,
    installed_sbom_path: str,
    lock_filename: str,
    lock_member: str,
    metadata_is_owner: bool,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    bytes,
    dict[str, Any],
]:
    """Build a verification context from exact locked-package Rust evidence."""

    raw_sbom = real_v7_fixture_bytes(sbom_filename)
    parsed = evidence.parse_cyclonedx_sbom(raw_sbom, sbom_filename)
    sbom_path = f"opt/venv/lib/python3.14/site-packages/{installed_sbom_path}"
    observation_sha256 = parsed["observation_sha256"]
    observations: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    owner_roots: set[tuple[str, str, str, str, str]] = set()
    local_references: list[dict[str, str]] = []
    sources: dict[str, dict[str, Any]] = {}

    projected = [
        *([parsed["metadata_component"]] if parsed["metadata_component"] is not None else []),
        *parsed["components"],
    ]
    for index, component in enumerate(projected):
        reference = evidence.retained_observation_reference(
            sbom_path,
            observation_sha256,
            component,
        )
        key = evidence.validate_observation_reference(
            reference,
            f"real Rust fixture observation {index}",
        )
        observations[key] = component
        identity = evidence.cargo_purl_identity(
            component["purl"],
            f"real Rust fixture observation {index}",
        )
        if identity is None:
            continue
        if "download_url=file:" in component["purl"]:
            if index == 0 and parsed["metadata_component"] is not None and metadata_is_owner:
                owner_roots.add(key)
            else:
                local_references.append(reference)
            continue
        hashes = [item["content"] for item in component["hashes"] if item["alg"] == "SHA-256"]
        assert len(hashes) == 1
        name, version = identity
        source_id = f"crates-io:{name}@{version}"
        sources[source_id] = {
            "kind": "crates-io",
            "name": name,
            "version": version,
            "crate": {"sha256": hashes[0]},
        }

    local_source_id = f"owner-sdist:{owner}#src/rust"
    sources[local_source_id] = {
        "kind": "owner-sdist-subpath",
        "owner": owner,
    }
    lock_bytes = real_v7_fixture_bytes(lock_filename)
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    reviewed = {
        (record["name"], record["version"])
        for source_id, record in sources.items()
        if source_id.startswith("crates-io:")
    }
    non_sbom_packages = sorted(
        (
            {
                "name": package["name"],
                "version": package["version"],
                "source": package["source"],
                "checksum": package["checksum"],
            }
            for package in lock["package"]
            if package.get("source") == evidence.CARGO_CRATES_IO_SOURCE
            and (package["name"], package["version"]) not in reviewed
        ),
        key=lambda record: (
            record["name"],
            record["version"],
            record["source"],
            record["checksum"],
        ),
    )
    cargo_lock = {
        "member": lock_member,
        "sha256": evidence.sha256_bytes(lock_bytes),
        "size": len(lock_bytes),
        "source_ids": sorted(
            source_id for source_id in sources if source_id.startswith("crates-io:")
        ),
        "non_sbom_packages": non_sbom_packages,
    }
    component_reviews = (
        [
            {
                "observations": sorted(
                    local_references,
                    key=evidence.canonical_json,
                ),
                "source": local_source_id,
                "reviewed_license": "fixture-only",
            }
        ]
        if local_references
        else []
    )
    context = {
        "owner": owner,
        "owner_root_observations": owner_roots,
        "observations": observations,
        "record": {
            "cargo_lock": cargo_lock,
            "component_reviews": component_reviews,
        },
    }
    archive = tar_bytes({lock_member: lock_bytes})
    return context, sources, archive, parsed


@pytest.mark.parametrize(
    ("name", "version", "crate_sha256"),
    (
        (
            "cfg-if",
            "1.0.0",
            "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd",
        ),
        (
            "lexical-parse-float",
            "1.0.5",
            "de6f9cb01fb0b08060209a057c048fcbab8717b4c1ecd2eac66ebfe39a65b0f2",
        ),
        (
            "lexical-parse-integer",
            "1.0.5",
            "72207aae22fc0a121ba7b6d479e42cbfea549af1479c3f3a4f12c70dd66df12e",
        ),
        (
            "lexical-util",
            "1.0.6",
            "5a82e24bf537fd24c177ffbbdc6ebcc8d54732c35b50a3f28cc3f4e4c949a0b3",
        ),
        (
            "stable_deref_trait",
            "1.2.0",
            "a8f112729512f8e442d81f95a8a7ddf2b7c6b8a1a6f509a95864142b30cab2d3",
        ),
        (
            "version_check",
            "0.9.5",
            "0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a",
        ),
    ),
)
def test_real_pydantic_legacy_crate_licenses_preserve_raw_slash_spelling(
    name: str,
    version: str,
    crate_sha256: str,
) -> None:
    crate = real_v7_crate_bytes(name, version)
    assert evidence.sha256_bytes(crate) == crate_sha256
    pydantic_sbom = evidence.parse_cyclonedx_sbom(
        real_v7_fixture_bytes("pydantic_core-2.46.4.pydantic-core.cyclonedx.json"),
        "Pydantic Core legacy-license fixture",
    )
    observed = [
        component
        for component in pydantic_sbom["components"]
        if component["purl"] == f"pkg:cargo/{name}@{version}"
    ]
    assert len(observed) == 1
    assert {"alg": "SHA-256", "content": crate_sha256} in observed[0]["hashes"]

    manifest_member = f"{name}-{version}/Cargo.toml"
    reviewed_files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(crate), mode="r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            if member.name != manifest_member and evidence.LICENSE_NAME.search(member.name) is None:
                continue
            stream = archive.extractfile(member)
            assert stream is not None
            reviewed_files[member.name] = stream.read()
    manifest = reviewed_files[manifest_member]
    assert tomllib.loads(manifest.decode("utf-8"))["package"]["license"] == "MIT/Apache-2.0"

    notices = [
        {
            "member": member,
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
        for member, content in sorted(reviewed_files.items())
        if member != manifest_member
    ]
    source_id = f"crates-io:{name}@{version}"
    source = {
        "kind": "crates-io",
        "name": name,
        "version": version,
        "crate": {
            "url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
            "sha256": crate_sha256,
            "size": len(crate),
        },
        "manifest": {
            "member": manifest_member,
            "sha256": evidence.sha256_bytes(manifest),
            "size": len(manifest),
        },
        "raw_license": "MIT/Apache-2.0",
        "normalized_license": "MIT OR Apache-2.0",
        "notices": notices,
    }
    validated = evidence.validate_crates_io_component_source(source_id, source)
    assert validated["raw_license"] == "MIT/Apache-2.0"
    assert validated["normalized_license"] == "MIT OR Apache-2.0"
    assert (
        evidence.verify_crates_io_archive(
            crate,
            source_id=source_id,
            source=validated,
        )
        == reviewed_files
    )
    if name == "cfg-if":
        false_normalization = copy.deepcopy(source)
        false_normalization["normalized_license"] = "MIT"
        with pytest.raises(evidence.EvidenceError, match="normalization differs"):
            evidence.validate_crates_io_component_source(source_id, false_normalization)


def test_real_pydantic_cargo_lock_accounts_for_87_crates_and_16_lock_only_packages() -> None:
    context, sources, archive, parsed = real_rust_cargo_lock_case(
        owner="python:pydantic-core@2.46.4",
        sbom_filename="pydantic_core-2.46.4.pydantic-core.cyclonedx.json",
        installed_sbom_path=("pydantic_core-2.46.4.dist-info/sboms/pydantic-core.cyclonedx.json"),
        lock_filename="pydantic_core-2.46.4.Cargo.lock",
        lock_member="pydantic_core-2.46.4/Cargo.lock",
        metadata_is_owner=True,
    )
    assert (
        evidence.sha256_bytes(
            real_v7_fixture_bytes("pydantic_core-2.46.4.pydantic-core.cyclonedx.json")
        )
        == "b2da43ae9b1f9f388f8845b6f96df645d16b7e5c8f9f9f2fa8e64ef894b59598"
    )
    assert len(parsed["components"]) == 88
    assert len(context["record"]["cargo_lock"]["source_ids"]) == 87
    assert len(context["record"]["cargo_lock"]["non_sbom_packages"]) == 16
    assert [
        (package["name"], package["version"])
        for package in context["record"]["cargo_lock"]["non_sbom_packages"]
    ] == [
        ("bitflags", "2.9.1"),
        ("bumpalo", "3.19.0"),
        ("cc", "1.0.101"),
        ("js-sys", "0.3.77"),
        ("log", "0.4.27"),
        ("portable-atomic", "1.6.0"),
        ("r-efi", "5.2.0"),
        ("rustversion", "1.0.17"),
        ("wasi", "0.14.2+wasi-0.2.4"),
        ("wasm-bindgen", "0.2.100"),
        ("wasm-bindgen-backend", "0.2.100"),
        ("wasm-bindgen-macro", "0.2.100"),
        ("wasm-bindgen-macro-support", "0.2.100"),
        ("wasm-bindgen-shared", "0.2.100"),
        ("wit-bindgen-rt", "0.39.0"),
        ("zerocopy-derive", "0.8.25"),
    ]
    assert evidence.verify_owner_cargo_lock(
        context,
        sources,
        archive,
        archive_name="pydantic_core-2.46.4.tar.gz",
    ) == real_v7_fixture_bytes("pydantic_core-2.46.4.Cargo.lock")

    missing_lock_only = copy.deepcopy(context)
    missing_lock_only["record"]["cargo_lock"]["non_sbom_packages"].pop()
    with pytest.raises(evidence.EvidenceError, match="registry packages differ"):
        evidence.verify_owner_cargo_lock(
            missing_lock_only,
            sources,
            archive,
            archive_name="pydantic_core-2.46.4.tar.gz",
        )

    changed_source = copy.deepcopy(sources)
    changed_source[context["record"]["cargo_lock"]["source_ids"][0]]["crate"]["sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="registry packages differ"):
        evidence.verify_owner_cargo_lock(
            context,
            changed_source,
            archive,
            archive_name="pydantic_core-2.46.4.tar.gz",
        )


def test_real_cryptography_cargo_lock_and_openssl_observation_are_retained() -> None:
    context, sources, archive, parsed = real_rust_cargo_lock_case(
        owner="python:cryptography@48.0.1",
        sbom_filename="cryptography-48.0.1.cryptography-rust.cyclonedx.json",
        installed_sbom_path=(
            "cryptography-48.0.1.dist-info/sboms/cryptography-rust.cyclonedx.json"
        ),
        lock_filename="cryptography-48.0.1.Cargo.lock",
        lock_member="cryptography-48.0.1/Cargo.lock",
        metadata_is_owner=False,
    )
    assert (
        evidence.sha256_bytes(
            real_v7_fixture_bytes("cryptography-48.0.1.cryptography-rust.cyclonedx.json")
        )
        == "9b2b3873832a3999a192327543e07e9cdcd66f083fd77a009054ace71cc6e92f"
    )
    assert len(parsed["components"]) == 40
    assert len(context["record"]["cargo_lock"]["source_ids"]) == 32
    assert context["record"]["cargo_lock"]["non_sbom_packages"] == []
    assert evidence.verify_owner_cargo_lock(
        context,
        sources,
        archive,
        archive_name="cryptography-48.0.1.tar.gz",
    ) == real_v7_fixture_bytes("cryptography-48.0.1.Cargo.lock")

    openssl_raw = real_v7_fixture_bytes("cryptography-48.0.1.openssl.cyclonedx.json")
    assert evidence.sha256_bytes(openssl_raw) == (
        "58f780e03ba9030ff66b3ed9e02c06e72a9f0a477caa3ae4299ab3e7b81c5f50"
    )
    openssl = evidence.parse_cyclonedx_sbom(openssl_raw, "cryptography OpenSSL fixture")
    assert openssl["components"] == [
        {
            "type": "library",
            "name": "openssl",
            "version": "4.0.1",
            "purl": (
                "pkg:generic/openssl@4.0.1?download_url=https://github.com/openssl/"
                "openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz"
            ),
            "bom_ref": "",
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09",
                }
            ],
            "licenses": [],
        }
    ]


def test_real_cffi_libffi_candidate_cannot_replace_missing_build_provenance() -> None:
    wheel = real_v7_fixture_bytes("cffi-2.1.0-cp314-musllinux-x86_64.whl")
    assert evidence.sha256_bytes(wheel) == (
        "dbf7c7a88e2bac086f06d14577332760bdeecc42bdec8ac4077f6260557d9326"
    )
    libffi_notice = (
        Path(__file__).parent
        / "fixtures"
        / "container_evidence"
        / "v7"
        / "real"
        / "libffi-3.4.6.LICENSE"
    ).read_bytes()
    assert evidence.sha256_bytes(libffi_notice) == (
        "67894089811f93fca47a76f85e017da6f8582d4ba0905963c6e0f1ad6df7a195"
    )
    assert b"Copyright (c) 1996-2024  Anthony Green, Red Hat, Inc and others." in libffi_notice
    assert b"The above copyright notice and this permission notice shall be" in libffi_notice
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        members = archive.namelist()
        assert not any(".dist-info/sboms/" in member for member in members)
        native_members = [member for member in members if member.endswith(".so")]
        assert native_members == ["_cffi_backend.cpython-314-x86_64-linux-musl.so"]
        extension = archive.read(native_members[0])
    assert evidence.sha256_bytes(extension) == (
        "d2ee0b7499f1b3fd3ee5bc6c7b90ee9d6111fdfb9901d32cff7cf462f094321f"
    )
    assert b"cffistatic_ffi_call" in extension
    assert b"ffi_prep_cif" in extension
    assert b"libffi.so" not in extension

    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    for platform in ("linux/amd64", "linux/arm64"):
        owner = next(
            record
            for record in policy["native_component_coverage"][platform]
            if record["owner"] == "python:cffi@2.1.0"
        )
        assert owner["sboms"] == []
        assert owner["review"]["state"] == "open"
        assert owner["known_omissions"] == [
            {
                "component": {
                    "name": "libffi",
                    "purl": "",
                    "type": "library",
                    "version": "3.4.6",
                },
                "id": "unproven-libffi-build-input",
                "missing_evidence": [
                    "build-material-attestation",
                    "exact-source",
                    "sbom-observation",
                    "source-payload-relationship",
                ],
                "observations": [],
                "payload_roles": ["_cffi_backend.cpython-314.so"],
                "reason": owner["known_omissions"][0]["reason"],
            }
        ]

    candidate = copy.deepcopy(policy)
    candidate["native_component_sources"]["upstream-release:libffi@3.4.6"] = {
        "kind": "checksummed-upstream-release",
        "name": "libffi",
        "version": "3.4.6",
        "archive": {
            "url": "https://github.com/libffi/libffi/archive/refs/tags/v3.4.6.tar.gz",
            "sha256": "9ac790464c1eb2f5ab5809e978a1683e9393131aede72d1b0a0703771d3c6cda",
            "size": 1_000_000,
        },
        "checksum_document": {
            "url": "https://example.com/libffi-3.4.6.tar.gz.sha256",
            "sha256": "1" * 64,
            "size": 100,
        },
        "checksum_filename": "v3.4.6.tar.gz",
        "notices": [
            {
                "member": "libffi-3.4.6/LICENSE",
                "sha256": "2" * 64,
                "size": 100,
            }
        ],
    }
    with pytest.raises(evidence.EvidenceError, match="missing, extra, or unused"):
        evidence.validate_native_component_policy_schema(candidate)


@pytest.mark.parametrize(
    ("filename", "sha256"),
    (
        (
            "cryptography-48.0.1-cp311-abi3-musllinux_1_2_aarch64.auditwheel.cdx.json",
            "2ec6b8e8ae1c144269de3834e53f5919f5042980d191ff7f3efd17885028102f",
        ),
        (
            "cryptography-48.0.1-cp311-abi3-musllinux_1_2_x86_64.auditwheel.cdx.json",
            "dae5479c7694801d07dbd8b0a8a495e4aebce0c30832910ca5c848ca66e40fd3",
        ),
        (
            "greenlet-3.5.3-cp314-cp314-musllinux_1_2_aarch64.auditwheel.cdx.json",
            "3adae2e69cbfa1547fec1c336a0a51b7ad5549fb0d321cae2d3afb43fc66d530",
        ),
        (
            "greenlet-3.5.3-cp314-cp314-musllinux_1_2_x86_64.auditwheel.cdx.json",
            "88ec96555dafdd7a1e4bac19a57701e712ff3a361a537e653b4baf6829a28e9e",
        ),
        (
            "psycopg_binary-3.3.4-cp314-cp314-musllinux_1_2_aarch64.auditwheel.cdx.json",
            "d4b27924b425127c33ddbc41f082abe2246bc1b25fc9b88716f889fb7686832e",
        ),
        (
            "psycopg_binary-3.3.4-cp314-cp314-musllinux_1_2_x86_64.auditwheel.cdx.json",
            "ed66539d58a72ebe684d6a918841d10b8f980c63a3eb65d401f3b4028a7c4a63",
        ),
    ),
)
def test_real_auditwheel_metadata_root_echo_is_review_visible(
    filename: str,
    sha256: str,
) -> None:
    raw = auditwheel_fixture_bytes(filename)
    assert evidence.sha256_bytes(raw) == sha256
    document = json.loads(raw)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.4"
    assert document["metadata"]["component"] in document["components"]

    parsed = evidence.parse_cyclonedx_sbom(raw, filename)
    assert parsed["metadata_root_echo"] == parsed["metadata_component"]
    assert parsed["upstream_invalid_duplicate_bom_ref"] is True
    assert len(parsed["components"]) == len(document["components"]) - 1
    evidence.validate_retained_cyclonedx_identity(parsed, filename)


@pytest.mark.parametrize(
    ("filename", "sha256"),
    (
        (
            "psycopg_binary-3.3.4-cp314-cp314-musllinux_1_2_aarch64.auditwheel.cdx.json",
            "d4b27924b425127c33ddbc41f082abe2246bc1b25fc9b88716f889fb7686832e",
        ),
        (
            "psycopg_binary-3.3.4-cp314-cp314-musllinux_1_2_x86_64.auditwheel.cdx.json",
            "ed66539d58a72ebe684d6a918841d10b8f980c63a3eb65d401f3b4028a7c4a63",
        ),
    ),
)
def test_real_psycopg_auditwheel_occurrences_are_retained_independently(
    filename: str,
    sha256: str,
) -> None:
    raw = auditwheel_fixture_bytes(filename)
    assert evidence.sha256_bytes(raw) == sha256

    parsed = evidence.parse_cyclonedx_sbom(raw, filename)
    assert parsed["metadata_root_echo"] == parsed["metadata_component"]
    assert parsed["upstream_invalid_duplicate_bom_ref"] is True
    purls = [item["purl"] for item in parsed["components"]]
    assert purls.count("pkg:apk/alpine/krb5@libs-1.21.3-r0") == 4
    assert purls.count("pkg:apk/alpine/libldap@2.6.8-r0") == 2
    assert len({item["bom_ref"] for item in parsed["components"]}) == len(parsed["components"])
    evidence.validate_retained_cyclonedx_identity(parsed, filename)

    reordered = json.loads(raw)
    reordered["components"] = list(reversed(reordered["components"]))
    reparsed = evidence.parse_cyclonedx_sbom(
        json.dumps(reordered).encode(),
        f"reordered-{filename}",
    )
    assert reparsed == parsed


def test_cyclonedx_projection_preserves_roots_hashes_and_license_observations() -> None:
    root = {
        "type": "application",
        "name": "not-the-wheel-owner",
        "version": "0.1.0",
        "purl": "pkg:cargo/not-the-wheel-owner@0.1.0",
        "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
        "licenses": [{"expression": "MIT/Apache-2.0"}],
    }
    component = {
        "type": "library",
        "name": "demo-crate",
        "version": "1.2.3",
        "purl": "pkg:cargo/demo-crate@1.2.3",
        "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
        "licenses": [{"license": {"id": "MIT"}}],
    }
    parsed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[component], metadata_component=root),
        "preserved.cdx.json",
    )

    assert parsed == {
        "bom_format": "CycloneDX",
        "spec_version": "1.5",
        "metadata_component": {
            **root,
            "bom_ref": "",
            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            "licenses": [{"expression": "MIT/Apache-2.0"}],
        },
        "metadata_root_echo": None,
        "upstream_invalid_duplicate_bom_ref": False,
        "components": [
            {
                **component,
                "bom_ref": "",
                "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
        "observation_sha256": parsed["observation_sha256"],
    }
    evidence.validate_retained_cyclonedx_identity(parsed, "preserved fixture")

    envelope_changed = json.loads(cyclonedx_sbom(components=[component], metadata_component=root))
    envelope_changed["serialNumber"] = "urn:uuid:abcdefab-cdef-4abc-8def-abcdefabcdef"
    envelope_changed["version"] = 7
    reparsed = evidence.parse_cyclonedx_sbom(
        json.dumps(envelope_changed).encode(), "changed-envelope.cdx.json"
    )
    assert reparsed == parsed

    license_changed = copy.deepcopy(component)
    license_changed["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    changed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[license_changed], metadata_component=root),
        "changed-license.cdx.json",
    )
    assert changed["observation_sha256"] != parsed["observation_sha256"]


@pytest.mark.parametrize(
    "hashes",
    (
        [
            {"alg": "SHA-256", "content": "a" * 64},
            {"alg": "SHA-256", "content": "b" * 64},
        ],
        [
            {"alg": "SHA-256", "content": "a" * 64},
            {"alg": "sha-256", "content": "b" * 64},
        ],
        [
            {"alg": "SHA-256", "content": "a" * 64},
            {"alg": "SHA-256", "content": "a" * 64},
        ],
    ),
)
def test_cyclonedx_projection_rejects_duplicate_hash_algorithms(
    hashes: list[dict[str, str]],
) -> None:
    component = {
        "type": "library",
        "name": "demo-crate",
        "version": "1.2.3",
        "purl": "pkg:cargo/demo-crate@1.2.3",
        "hashes": hashes,
    }

    with pytest.raises(evidence.EvidenceError, match="repeats a hash algorithm"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[component]),
            "duplicate-hash-algorithm.cdx.json",
        )


def test_cyclonedx_projection_retains_one_exact_metadata_root_echo() -> None:
    root = {
        "type": "library",
        "name": "demo",
        "version": "1.0",
        "purl": "pkg:pypi/demo@1.0?file_name=demo.whl",
        "bom-ref": "pkg:pypi/demo@1.0?file_name=demo.whl",
    }
    parsed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[copy.deepcopy(root)], metadata_component=root),
        "auditwheel.cdx.json",
    )

    expected_root = {
        "type": "library",
        "name": "demo",
        "version": "1.0",
        "purl": "pkg:pypi/demo@1.0?file_name=demo.whl",
        "bom_ref": "pkg:pypi/demo@1.0?file_name=demo.whl",
        "hashes": [],
        "licenses": [],
    }
    assert parsed["metadata_component"] == expected_root
    assert parsed["metadata_root_echo"] == expected_root
    assert parsed["upstream_invalid_duplicate_bom_ref"] is True
    assert parsed["components"] == []
    evidence.validate_retained_cyclonedx_identity(parsed, "auditwheel fixture")


@pytest.mark.parametrize(
    "mutation",
    (
        "second_echo",
        "same_purl_different_ref",
        "same_ref_different_purl",
        "different_field",
        "nested_duplicate",
    ),
)
def test_cyclonedx_metadata_root_echo_exception_is_exactly_scoped(mutation: str) -> None:
    root = {
        "type": "library",
        "name": "demo",
        "version": "1.0",
        "purl": "pkg:pypi/demo@1.0?file_name=demo.whl",
        "bom-ref": "pkg:pypi/demo@1.0?file_name=demo.whl",
    }
    echo = copy.deepcopy(root)
    components: list[dict[str, Any]] = [echo]
    if mutation == "second_echo":
        components.append(copy.deepcopy(root))
    elif mutation == "same_purl_different_ref":
        echo["bom-ref"] = "different"
    elif mutation == "same_ref_different_purl":
        echo["purl"] = "pkg:pypi/other@1.0"
    elif mutation == "different_field":
        echo["name"] = "other"
    else:
        components = [
            {
                "type": "library",
                "name": "parent",
                "version": "1.0",
                "purl": "pkg:generic/parent@1.0",
                "bom-ref": "parent",
                "components": [echo],
            }
        ]

    with pytest.raises(
        evidence.EvidenceError,
        match=r"repeats metadata component purl|repeats a non-echo bom-ref",
    ):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=components, metadata_component=root),
            "invalid-echo.cdx.json",
        )


def test_inventory_retains_document_scoped_cyclonedx_purl_observations(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    sboms = {
        "cryptography": cyclonedx_sbom(
            components=[
                {
                    "type": "library",
                    "name": "libgcc",
                    "version": "14.2.0-r6",
                    "purl": "pkg:apk/NotpineForGHA/libgcc@14.2.0-r6",
                    "bom-ref": "notpine-libgcc",
                }
            ]
        ),
        "greenlet": cyclonedx_sbom(
            components=[
                {
                    "type": "library",
                    "name": "libgcc",
                    "version": "14.2.0-r6",
                    "purl": "pkg:apk/alpine/libgcc@14.2.0-r6",
                    "bom-ref": "alpine-libgcc",
                }
            ]
        ),
    }
    installed: dict[str, bytes] = {}
    for owner, sbom in sboms.items():
        dist_info = f"{owner}-1.0.dist-info"
        wheel = {
            f"{dist_info}/METADATA": metadata(owner, "1.0"),
            f"{dist_info}/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
            ),
            f"{dist_info}/sboms/auditwheel.cdx.json": sbom,
        }
        record_path = f"{dist_info}/RECORD"
        wheel[record_path] = wheel_record(wheel, record_path)
        installed.update(wheel)

    image = tmp_path / "document-scoped-sboms.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                },
                links=VENV_LINKS,
            )
        ],
    )

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    observations = {
        record["owner"]: (
            record["cyclonedx"]["components"][0]["purl"],
            record["sha256"],
            record["size"],
        )
        for record in inventory["embedded_sboms"]
    }
    assert observations == {
        "python:cryptography@1.0": (
            "pkg:apk/NotpineForGHA/libgcc@14.2.0-r6",
            evidence.sha256_bytes(sboms["cryptography"]),
            len(sboms["cryptography"]),
        ),
        "python:greenlet@1.0": (
            "pkg:apk/alpine/libgcc@14.2.0-r6",
            evidence.sha256_bytes(sboms["greenlet"]),
            len(sboms["greenlet"]),
        ),
    }
    evidence.validate_component_inventory(inventory)
    evidence.validate_all_layer_inventory(files, inventory)

    payload_policy = {"unexpanded_python_payloads": empty_unexpanded_payload_policy()}
    payload_policy["unexpanded_python_payloads"]["linux/amd64"] = {
        "embedded_sboms": [
            evidence.payload_record_projection(record) for record in inventory["embedded_sboms"]
        ],
        "native_payloads": [],
        "wheel_identity_files": copy.deepcopy(inventory["wheel_identity_files"]),
    }
    evidence.verify_unexpanded_payload_policy(inventory, payload_policy)


@pytest.mark.parametrize(
    ("content", "message"),
    (
        (b"{}", "not CycloneDX"),
        (
            b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
            "duplicate JSON object key",
        ),
        (
            b'{"bomFormat":"CycloneDX","specVersion":"1.5","version":1.5}',
            "floating-point",
        ),
    ),
)
def test_cyclonedx_parser_rejects_malformed_documents(content: bytes, message: str) -> None:
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_cyclonedx_sbom(content, "malformed.cdx.json")


@pytest.mark.parametrize(
    ("offset", "value", "message"),
    (
        (4, 1, "not ELF64"),
        (5, 2, "not little-endian"),
        (6, 0, "identity version"),
        (52, 0, "malformed ELF header"),
    ),
)
def test_elf_parser_rejects_wrong_class_endianness_and_header(
    offset: int, value: int, message: str
) -> None:
    payload = bytearray(elf64_payload())
    payload[offset] = value
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_elf_identity(bytes(payload), "linux/amd64", "demo/native")


def test_inventory_detects_extensionless_elf_and_binds_payload_owners(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    native = elf64_payload()
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        "demo-1.0.dist-info/sboms/demo.cdx.json": cyclonedx_sbom(),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(
        {**installed, "../../../bin/extensionless-native": native},
        "demo-1.0.dist-info/RECORD",
    )
    image = tmp_path / "extensionless.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                    "opt/venv/bin/extensionless-native": native,
                },
                links=VENV_LINKS,
            )
        ],
    )

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    assert [record["path"] for record in inventory["native_payloads"]] == [
        "opt/venv/bin/extensionless-native"
    ]
    assert {record["owner"] for record in inventory["embedded_sboms"]} == {"python:demo@1.0"}
    assert {record["owner"] for record in inventory["native_payloads"]} == {"python:demo@1.0"}
    evidence.validate_component_inventory(inventory)
    evidence.validate_all_layer_inventory(files, inventory)


@pytest.mark.parametrize(
    ("payload_path", "payload", "message"),
    (
        ("demo/native.so", b"not ELF", "not ELF"),
        ("demo/native.so", elf64_payload("arm64"), "architecture does not match"),
        ("demo/native.so", b"\x7fELF", "truncated ELF"),
        (
            "demo-1.0.dist-info/sboms/demo.cdx.json",
            b"{}",
            "not CycloneDX",
        ),
    ),
)
def test_inventory_rejects_malformed_structured_wheel_payloads(
    tmp_path: Path, payload_path: str, payload: bytes, message: str
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        payload_path: payload,
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "malformed.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                },
                links=VENV_LINKS,
            )
        ],
    )
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    ("payload_path", "payload"),
    (
        ("demo/unowned-native", elf64_payload()),
        ("demo-1.0.dist-info/sboms/unowned.cdx.json", cyclonedx_sbom()),
    ),
)
def test_inventory_rejects_unowned_structured_payload_occurrences(
    tmp_path: Path, payload_path: str, payload: bytes
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "unowned.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                    f"{site}/{payload_path}": payload,
                },
                links=VENV_LINKS,
            )
        ],
    )
    with pytest.raises(evidence.EvidenceError, match="not owned by a wheel RECORD"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_structured_payload_validation_rejects_owner_and_identity_tampering(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        "demo-1.0.dist-info/sboms/demo.cdx.json": cyclonedx_sbom(),
        "demo/native.so": elf64_payload(),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                },
                links=VENV_LINKS,
            )
        ],
    )
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    wrong_owner = copy.deepcopy(inventory)
    wrong_owner["embedded_sboms"][0]["owner"] = "python:other@1.0"
    with pytest.raises(evidence.EvidenceError, match="invalid Python RECORD owner"):
        evidence.validate_component_inventory(wrong_owner)

    wrong_component_digest = copy.deepcopy(inventory)
    wrong_component_digest["embedded_sboms"][0]["cyclonedx"]["observation_sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="CycloneDX observation"):
        evidence.validate_all_layer_inventory(files, wrong_component_digest)

    wrong_elf = copy.deepcopy(inventory)
    wrong_elf["native_payloads"][0]["elf"] = {
        "bits": 64,
        "endianness": "little",
        "machine": "aarch64",
        "machine_id": 183,
    }
    with pytest.raises(evidence.EvidenceError, match="ELF architecture mismatch"):
        evidence.validate_all_layer_inventory(files, wrong_elf)


def test_effective_record_ownership_is_bound_to_historical_wheel_claims(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"

    def installed(name: str) -> dict[str, bytes]:
        files = {
            f"{name}-1.0.dist-info/METADATA": metadata(name, "1.0"),
            f"{name}-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            f"{name}.py": f"NAME = {name!r}\n".encode(),
        }
        record_name = f"{name}-1.0.dist-info/RECORD"
        files[record_name] = wheel_record(files, record_name)
        return files

    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{
                        f"{site}/{path}": content
                        for path, content in {**installed("alpha"), **installed("beta")}.items()
                    },
                },
                links=VENV_LINKS,
            )
        ],
    )
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    evidence.validate_component_inventory(inventory)
    evidence.validate_all_layer_inventory(files, inventory)

    relabeled = copy.deepcopy(inventory)
    alpha = next(
        record
        for record in relabeled["python_record_ownership"]
        if record["path"].endswith("/alpha.py")
    )
    alpha["owner"] = "beta"
    for validator in (
        evidence.validate_component_inventory,
        lambda candidate: evidence.validate_all_layer_inventory(files, candidate),
    ):
        with pytest.raises(evidence.EvidenceError, match="effective historical claim"):
            validator(relabeled)

    omitted = copy.deepcopy(inventory)
    omitted["python_record_ownership"] = omitted["python_record_ownership"][1:]
    with pytest.raises(evidence.EvidenceError, match="omits an effective historical claim"):
        evidence.validate_component_inventory(omitted)


def test_wheel_record_binds_effective_files_and_policy_detects_consistent_rewrite(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    metadata_content = metadata("demo", "1.0")
    wheel_content = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"

    def installed(source: bytes) -> dict[str, bytes]:
        result = {
            "demo-1.0.dist-info/METADATA": metadata_content,
            "demo-1.0.dist-info/WHEEL": wheel_content,
            "demo.py": source,
        }
        result["demo-1.0.dist-info/RECORD"] = wheel_record(result, "demo-1.0.dist-info/RECORD")
        return result

    trusted = installed(b"VALUE = 'trusted'\n")
    base_layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in trusted.items()},
        },
        links=VENV_LINKS,
    )
    base_image = tmp_path / "base.tar"
    saved_image_layers(base_image, [base_layer])
    base_inventory, _base_files = evidence._inventory_saved_image(
        base_image, "linux/amd64", "sha256:" + "a" * 64
    )

    changed_source = b"VALUE = 'tampered'\n"
    stale_image = tmp_path / "stale.tar"
    saved_image_layers(stale_image, [base_layer, tar_bytes({f"{site}/demo.py": changed_source})])
    with pytest.raises(evidence.EvidenceError, match="RECORD does not match installed file"):
        evidence._inventory_saved_image(stale_image, "linux/amd64", "sha256:" + "a" * 64)

    changed = installed(changed_source)
    consistent_image = tmp_path / "consistent.tar"
    saved_image_layers(
        consistent_image,
        [
            base_layer,
            tar_bytes(
                {
                    f"{site}/demo.py": changed_source,
                    f"{site}/demo-1.0.dist-info/RECORD": changed["demo-1.0.dist-info/RECORD"],
                }
            ),
        ],
    )
    consistent_inventory, _consistent_files = evidence._inventory_saved_image(
        consistent_image, "linux/amd64", "sha256:" + "a" * 64
    )
    installations = consistent_inventory["wheel_installations"]
    assert [item["owner"] for item in installations] == [
        "python:demo@1.0",
        "python:demo@1.0",
    ]
    assert [item["record"]["effective"] for item in installations] == [False, True]
    first_demo = next(
        item for item in installations[0]["entries"] if item["path"].endswith("demo.py")
    )
    replacement_demo = next(
        item for item in installations[1]["entries"] if item["path"].endswith("demo.py")
    )
    assert first_demo["occurrence"]["layer"] == 0
    assert first_demo["occurrence"]["effective"] is False
    assert replacement_demo["occurrence"]["layer"] == 1
    assert replacement_demo["occurrence"]["effective"] is True
    payload_policy = {"unexpanded_python_payloads": empty_unexpanded_payload_policy()}
    payload_policy["unexpanded_python_payloads"]["linux/amd64"] = {
        "embedded_sboms": [
            evidence.payload_record_projection(record)
            for record in base_inventory["embedded_sboms"]
        ],
        "native_payloads": [
            evidence.payload_record_projection(record)
            for record in base_inventory["native_payloads"]
        ],
        "wheel_identity_files": copy.deepcopy(base_inventory["wheel_identity_files"]),
    }
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(consistent_inventory, payload_policy)


def test_historical_record_replay_survives_complete_whiteout(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\nTag: cp314-cp314-musllinux_1_2_x86_64\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    base = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    removal = tar_bytes(
        {
            f"{site}/.wh.demo.py": b"",
            f"{site}/demo-1.0.dist-info/.wh.METADATA": b"",
            f"{site}/demo-1.0.dist-info/.wh.WHEEL": b"",
            f"{site}/demo-1.0.dist-info/.wh.RECORD": b"",
        }
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [base, removal])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    installation = inventory["wheel_installations"][0]
    assert installation["owner"] == "python:demo@1.0"
    assert installation["record"]["effective"] is False
    assert installation["root_is_purelib"] is True
    assert installation["tags"] == [
        "cp314-cp314-musllinux_1_2_x86_64",
        "py3-none-any",
    ]
    assert {entry["path"] for entry in installation["entries"]} == {
        f"{site}/demo.py",
        f"{site}/demo-1.0.dist-info/METADATA",
        f"{site}/demo-1.0.dist-info/WHEEL",
        f"{site}/demo-1.0.dist-info/RECORD",
    }
    assert all(entry["occurrence"]["effective"] is False for entry in installation["entries"])
    assert inventory["python_record_ownership"] == []
    evidence.validate_all_layer_inventory(files, inventory)

    tampered = copy.deepcopy(inventory)
    tampered["wheel_installations"][0]["entries"][0]["occurrence"]["sha256"] = "f" * 64
    with pytest.raises(evidence.EvidenceError, match=r"conflicting identity|all-layer inventory"):
        evidence.validate_all_layer_inventory(files, tampered)

    omitted = copy.deepcopy(inventory)
    omitted["wheel_installations"] = []
    with pytest.raises(evidence.EvidenceError, match="omits a historical Python RECORD"):
        evidence.validate_all_layer_inventory(files, omitted)


def test_record_replay_uses_complete_layer_snapshot_not_tar_order(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    record = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            f"{site}/demo-1.0.dist-info/RECORD": record,
            f"{site}/demo.py": installed["demo.py"],
            f"{site}/demo-1.0.dist-info/WHEEL": installed["demo-1.0.dist-info/WHEEL"],
            f"{site}/demo-1.0.dist-info/METADATA": installed["demo-1.0.dist-info/METADATA"],
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    assert inventory["wheel_installations"][0]["owner"] == "python:demo@1.0"
    evidence.validate_all_layer_inventory(files, inventory)


def test_replacement_requires_same_layer_record_before_later_whiteout(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    base = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    replacement = tar_bytes({f"{site}/demo.py": b"VALUE = 2\n"})
    later_removal = tar_bytes({f"{site}/.wh.demo.py": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [base, replacement, later_removal])

    with pytest.raises(evidence.EvidenceError, match="matching replacement RECORD"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_record_replay_rejects_duplicate_active_owner(tmp_path: Path) -> None:
    sites = [
        "opt/venv/lib/python3.14/site-packages",
        "opt/venv/alternate/site-packages",
    ]
    files: dict[str, bytes] = {
        "lib/apk/db/installed": apk_database(),
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
    }
    for index, site in enumerate(sites):
        installed = {
            "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
            "demo-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            f"demo_{index}.py": str(index).encode(),
        }
        installed["demo-1.0.dist-info/RECORD"] = wheel_record(
            installed, "demo-1.0.dist-info/RECORD"
        )
        files.update({f"{site}/{path}": content for path, content in installed.items()})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes(files, links=VENV_LINKS)])

    with pytest.raises(evidence.EvidenceError, match="duplicate Python owner"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_record_replay_rejects_overlapping_distribution_ownership(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    shared = b"VALUE = 1\n"
    files: dict[str, bytes] = {
        "lib/apk/db/installed": apk_database(),
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
        f"{site}/shared.py": shared,
    }
    for name in ("demo", "other"):
        installed = {
            f"{name}-1.0.dist-info/METADATA": metadata(name, "1.0"),
            f"{name}-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            "shared.py": shared,
        }
        record_path = f"{name}-1.0.dist-info/RECORD"
        files.update({f"{site}/{path}": content for path, content in installed.items()})
        files[f"{site}/{record_path}"] = wheel_record(installed, record_path)
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes(files, links=VENV_LINKS)])

    with pytest.raises(evidence.EvidenceError, match="claim the same RECORD path"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    ("extra_path", "message"),
    (
        ("demo.pyc", "executable bytecode"),
        ("unowned.pth", "not owned by a wheel RECORD"),
    ),
)
def test_wheel_validation_rejects_unrecorded_executable_surfaces(
    tmp_path: Path, extra_path: str, message: str
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
            f"{site}/{extra_path}": b"unrecorded",
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_wheel_record_parser_rejects_traversal_and_invalid_hash() -> None:
    site_root = evidence.PurePosixPath("opt/venv/lib/python3.14/site-packages")
    record_path = f"{site_root}/demo-1.0.dist-info/RECORD"
    with pytest.raises(evidence.EvidenceError, match="escapes /opt/venv"):
        evidence.parse_wheel_record(
            b"../../../../escape,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n"
            b"demo-1.0.dist-info/RECORD,,\n",
            site_root,
            record_path,
        )
    with pytest.raises(evidence.EvidenceError, match="invalid hash"):
        evidence.parse_wheel_record(
            b"demo.py,sha256=not-a-digest,1\ndemo-1.0.dist-info/RECORD,,\n",
            site_root,
            record_path,
        )
    with pytest.raises(evidence.EvidenceError, match="invalid size"):
        evidence.parse_wheel_record(
            (
                "demo.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,"
                + "9" * 5000
                + "\ndemo-1.0.dist-info/RECORD,,\n"
            ).encode(),
            site_root,
            record_path,
        )


def test_wheel_record_parser_rejects_aliases_malformed_and_oversized_csv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_root = evidence.PurePosixPath("opt/venv/lib/python3.14/site-packages")
    record_path = f"{site_root}/demo-1.0.dist-info/RECORD"
    digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(evidence.EvidenceError, match="repeats path"):
        evidence.parse_wheel_record(
            (
                f"demo.py,sha256={digest},1\n"
                f"subdir/../demo.py,sha256={digest},1\n"
                "demo-1.0.dist-info/RECORD,,\n"
            ).encode(),
            site_root,
            record_path,
        )
    with pytest.raises(evidence.EvidenceError, match="cannot parse Python RECORD"):
        evidence.parse_wheel_record(
            b'"unterminated,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n',
            site_root,
            record_path,
        )
    monkeypatch.setattr(evidence, "MAX_RECORD_BYTES", 16)
    with pytest.raises(evidence.EvidenceError, match="exceeds its size limit"):
        evidence.parse_wheel_record(b"x" * 17, site_root, record_path)


def test_record_replay_rejects_symlink_owned_as_regular_file(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    record = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    f"{site}/demo-1.0.dist-info/METADATA": installed["demo-1.0.dist-info/METADATA"],
                    f"{site}/demo-1.0.dist-info/WHEEL": installed["demo-1.0.dist-info/WHEEL"],
                    f"{site}/demo-1.0.dist-info/RECORD": record,
                },
                links={**VENV_LINKS, f"{site}/demo.py": "elsewhere.py"},
            )
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="target is not a regular file"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("suffix", ("pyc", "pyo"))
def test_historical_venv_bytecode_is_rejected_before_whiteout(tmp_path: Path, suffix: str) -> None:
    bytecode_path = f"opt/venv/lib/python3.14/site-packages/demo.{suffix}"
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    bytecode_path: b"executable",
                }
            ),
            tar_bytes(
                {
                    f"{PurePosixPath(bytecode_path).parent}/"
                    f".wh.{PurePosixPath(bytecode_path).name}": b""
                }
            ),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="executable bytecode"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_effective_interpreter_bytecode_is_rejected(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "usr/local/lib/python3.14/__pycache__/site.cpython-314.pyc": b"executable",
                }
            )
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="effective interpreter path"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    "content",
    (
        b'{"schema_version":1,"platform":"linux/amd64","components":[null]}',
        b'{"schema_version":' + b"9" * 5000 + b"}",
        b'{"schema_version":1e400}',
    ),
)
def test_verify_cli_rejects_malformed_json_without_traceback(
    tmp_path: Path, content: bytes
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_bytes(content)
    result = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed script
        [
            sys.executable,
            ".github/scripts/container_evidence.py",
            "verify",
            "--inventory",
            str(inventory),
            "--policy",
            ".compliance/container-policy.json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stderr.startswith("container evidence error:")
    assert "Traceback" not in result.stderr


def test_application_source_binding_is_exact_and_effective(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    trusted_source = b"VALUE = 'trusted'\n"
    installed = {
        "extra_codeowners-0.1.0.dist-info/METADATA": metadata("extra-codeowners", "0.1.0"),
        "extra_codeowners-0.1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "extra_codeowners/app.py": trusted_source,
    }
    installed["extra_codeowners-0.1.0.dist-info/RECORD"] = wheel_record(
        installed, "extra_codeowners-0.1.0.dist-info/RECORD"
    )
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    monkeypatch.setattr(
        evidence, "project_identity_at_head", lambda _repo: ("extra-codeowners", "0.1.0")
    )
    monkeypatch.setattr(
        evidence,
        "application_sources_at_head",
        lambda _repo: {"extra_codeowners/app.py": trusted_source},
    )

    assert evidence.validate_application_source_binding(inventory, files, tmp_path) == (
        "extra-codeowners",
        "0.1.0",
    )
    assert {item["path"] for item in inventory["wheel_identity_files"]} == {
        f"{site}/extra_codeowners-0.1.0.dist-info/RECORD",
        f"{site}/extra_codeowners-0.1.0.dist-info/WHEEL",
    }

    alternate = copy.deepcopy(inventory)
    application = next(
        item for item in alternate["components"] if item["name"] == "extra-codeowners"
    )
    application["version"] = "0.2.0"
    with pytest.raises(evidence.EvidenceError, match="does not match pyproject"):
        evidence.validate_application_source_binding(alternate, files, tmp_path)

    duplicate = copy.deepcopy(files)
    duplicate["regular_files"].append(
        copy.deepcopy(
            next(
                record
                for record in duplicate["regular_files"]
                if record["path"].endswith(".dist-info/METADATA")
            )
        )
    )
    with pytest.raises(evidence.EvidenceError, match="exactly one effective"):
        evidence.validate_application_source_binding(inventory, duplicate, tmp_path)

    tampered = copy.deepcopy(files)
    app_record = next(
        record for record in tampered["regular_files"] if record["path"].endswith("/app.py")
    )
    app_record["sha256"] = "f" * 64
    with pytest.raises(evidence.EvidenceError, match="differs from Git HEAD"):
        evidence.validate_application_source_binding(inventory, tampered, tmp_path)

    consistently_tampered = copy.deepcopy(tampered)
    record_file = next(
        record
        for record in consistently_tampered["regular_files"]
        if record["path"].endswith(".dist-info/RECORD")
    )
    record_file["sha256"] = "e" * 64
    with pytest.raises(evidence.EvidenceError, match="differs from Git HEAD"):
        evidence.validate_application_source_binding(inventory, consistently_tampered, tmp_path)

    absent = copy.deepcopy(inventory)
    absent["components"] = [
        item for item in absent["components"] if item["name"] != "extra-codeowners"
    ]
    with pytest.raises(evidence.EvidenceError, match="exactly one application"):
        evidence.validate_application_source_binding(absent, files, tmp_path)


def initialize_git_fixture(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git = evidence.executable("git")
    evidence.run([git, "init", "--quiet", str(repo)], max_output_bytes=1024 * 1024)
    evidence.run(
        [git, "-C", str(repo), "config", "user.email", "test@example.com"],
        max_output_bytes=1024 * 1024,
    )
    evidence.run(
        [git, "-C", str(repo), "config", "user.name", "Test"],
        max_output_bytes=1024 * 1024,
    )
    evidence.run(
        [git, "-C", str(repo), "config", "commit.gpgSign", "false"],
        max_output_bytes=1024 * 1024,
    )
    evidence.run(
        [git, "-C", str(repo), "config", "core.hooksPath", "/dev/null"],
        max_output_bytes=1024 * 1024,
    )
    return repo, git


def commit_git_fixture(repo: Path, git: str) -> None:
    evidence.run([git, "-C", str(repo), "add", "."], max_output_bytes=1024 * 1024)
    evidence.run(
        [git, "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
        max_output_bytes=1024 * 1024,
    )


def test_project_identity_is_read_from_git_head(tmp_path: Path) -> None:
    repo, git = initialize_git_fixture(tmp_path)
    pyproject = repo / "pyproject.toml"
    pyproject.write_text('[project]\nname = "extra-codeowners"\nversion = "0.1.0"\n')
    commit_git_fixture(repo, git)
    pyproject.write_text('[project]\nname = "tampered"\nversion = "9.9.9"\n')

    assert evidence.project_identity_at_head(repo) == ("extra-codeowners", "0.1.0")


def test_project_identity_rejects_oversized_version_without_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    oversized = "1." + "0" * evidence.MAX_COMPONENT_FIELD_LENGTH
    monkeypatch.setattr(
        evidence,
        "run",
        lambda *_args, **_kwargs: (
            f'[project]\nname = "extra-codeowners"\nversion = "{oversized}"\n'.encode()
        ),
    )
    with pytest.raises(evidence.EvidenceError, match="invalid length"):
        evidence.project_identity_at_head(tmp_path)


def test_portable_git_tree_reader_works_in_a_fixture_repository(tmp_path: Path) -> None:
    repo, git = initialize_git_fixture(tmp_path)
    package = repo / "extra_codeowners"
    package.mkdir()
    (package / "app.py").write_text("APP = True\n")
    executable = package / "entrypoint"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (repo / "outside.txt").write_text("not part of the requested tree\n")
    commit_git_fixture(repo, git)

    assert evidence.git_regular_tree_at_head(repo, "extra_codeowners") == [
        ("100644", "extra_codeowners/app.py"),
        ("100755", "extra_codeowners/entrypoint"),
    ]


def test_application_archive_ignores_export_transforms(tmp_path: Path) -> None:
    repo, git = initialize_git_fixture(tmp_path)
    (repo / "extra_codeowners").mkdir()
    (repo / "extra_codeowners" / "app.py").write_text("REV = '$Format:%H$'\n")
    (repo / "LICENSE").write_text("license\n")
    (repo / ".gitattributes").write_text(
        "extra_codeowners/app.py export-subst\nLICENSE export-ignore\n"
    )
    commit_git_fixture(repo, git)

    archive_bytes = evidence.deterministic_source_archive(repo)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        names = {member.name for member in archive}
        source = archive.extractfile("extra_codeowners/app.py")
        assert source is not None
        assert source.read() == b"REV = '$Format:%H$'\n"
    assert "LICENSE" in names


def test_runtime_identity_expectations_match_dockerfile_and_mise() -> None:
    dockerfile = Path("Dockerfile").read_text()
    mise = evidence.tomllib.loads(Path("mise.toml").read_text())
    builder_stage = dockerfile.split(" AS builder\n", 1)[1].split("\nFROM builder AS test", 1)[0]
    test_stage = dockerfile.split("FROM builder AS test\n", 1)[1].split("\nFROM python:", 1)[0]
    assert mise["tools"]["uv"] == evidence.EXPECTED_UV_VERSION
    assert f"ghcr.io/astral-sh/uv:{evidence.EXPECTED_UV_VERSION}@sha256:" in dockerfile
    assert (
        dockerfile.count(f"FROM python:{evidence.EXPECTED_RUNTIME_PYTHON}-alpine3.24@sha256:") == 2
    )
    assert "ENV UV_COMPILE_BYTECODE=0" in dockerfile
    assert (
        "test -z \"$(find /opt/venv \\( -name '*.pyc' -o -name '*.pyo' \\) -print -quit)\""
    ) in builder_stage
    assert dockerfile.count("UV_NO_INSTALLER_METADATA=1") == 1
    assert builder_stage.index("UV_NO_INSTALLER_METADATA=1") < builder_stage.index("uv sync")
    assert "RUN apk add --no-cache git=2.54.0-r0" in test_stage


def test_container_job_uses_the_locked_evidence_environment() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text()
    container_job = workflow.split("  container:\n", 1)[1]
    evidence_step = container_job.split(
        "      - name: Collect and verify container distribution evidence\n", 1
    )[1].split("      - name: Upload container distribution evidence\n", 1)[0]
    assert "astral-sh/setup-uv@" in container_job
    assert "uv sync --all-groups --frozen" in container_job
    assert container_job.count("uv run --frozen python .github/scripts/container_evidence.py") == 4
    assert evidence_step.index(" inventory \\") < evidence_step.index(" run-metadata \\")
    assert evidence_step.index(" run-metadata \\") < evidence_step.index(" verify \\")
    assert evidence_step.index(" verify \\") < evidence_step.index(" bundle \\")
    assert "packages: write" not in workflow
    assert "publish-container:" not in workflow


def test_container_build_toolchain_is_exactly_pinned_and_renovate_managed() -> None:
    ci = Path(".github/workflows/ci.yml").read_text()
    release = Path(".github/workflows/release.yml").read_text()
    qemu = (
        "tonistiigi/binfmt:qemu-v10.2.3@sha256:"
        "400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
    )
    buildkit = (
        "image=moby/buildkit:v0.30.0@sha256:"
        "0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
    )
    qemu_action = "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8"
    buildx_action = "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c"
    for workflow, expected_count in ((ci, 2), (release, 2)):
        assert workflow.count(qemu_action) == expected_count
        assert workflow.count(buildx_action) == expected_count
        assert workflow.count(qemu) == expected_count
        assert workflow.count("cache-binary: false") == expected_count
        assert workflow.count("version: v0.35.0") == expected_count
        assert workflow.count(buildkit) == expected_count

    renovate = json.loads(Path("renovate.json").read_text())
    managers = {manager["description"]: manager for manager in renovate["customManagers"]}
    workflow_pattern = [r"/^\.github/workflows/(?:ci|release)\.yml$/"]

    utility = managers["Update digest-pinned kubeconform and BuildKit utility containers"]
    assert utility["managerFilePatterns"] == workflow_pattern
    assert utility["datasourceTemplate"] == "docker"
    assert utility["versioningTemplate"] == "docker"
    assert utility["matchStrings"] == [
        r"(?<depName>ghcr.io/yannh/kubeconform):(?<currentValue>[^@\s]+)"
        + r"@(?<currentDigest>sha256:[a-f0-9]{64})",
        r"(?<depName>moby/buildkit):(?<currentValue>[^@\s]+)"
        + r"@(?<currentDigest>sha256:[a-f0-9]{64})",
    ]

    qemu_manager = managers["Update digest-pinned QEMU binfmt images"]
    assert qemu_manager["managerFilePatterns"] == workflow_pattern
    assert qemu_manager["matchStrings"] == [
        r"(?<depName>tonistiigi/binfmt):"
        r"(?<currentValue>qemu-v[0-9]+\.[0-9]+\.[0-9]+)"
        r"@(?<currentDigest>sha256:[a-f0-9]{64})"
    ]
    assert qemu_manager["datasourceTemplate"] == "docker"
    assert qemu_manager["versioningTemplate"] == (
        r"regex:^qemu-v(?<major>[0-9]+)\.(?<minor>[0-9]+)\.(?<patch>[0-9]+)$"
    )

    buildx_manager = managers["Update the pinned Docker Buildx client"]
    assert buildx_manager["managerFilePatterns"] == workflow_pattern
    assert buildx_manager["depNameTemplate"] == "docker/buildx"
    assert buildx_manager["datasourceTemplate"] == "github-releases"
    assert buildx_manager["extractVersionTemplate"] == (r"^v(?<version>[0-9]+\.[0-9]+\.[0-9]+)$")
    assert buildx_manager["versioningTemplate"] == "semver"

    shellcheck_manager = managers[
        "Open reviewed ShellCheck release updates; CI requires a matching asset digest"
    ]
    assert shellcheck_manager["managerFilePatterns"] == [r"/^\.github/workflows/ci\.yml$/"]
    assert shellcheck_manager["matchStrings"] == [
        r"SHELLCHECK_VERSION: v(?<currentValue>\d+\.\d+\.\d+)"
    ]
    assert shellcheck_manager["depNameTemplate"] == "koalaman/shellcheck"
    assert shellcheck_manager["datasourceTemplate"] == "github-releases"
    assert shellcheck_manager["versioningTemplate"] == "semver"
    assert "SHELLCHECK_VERSION: v0.11.0" in ci
    assert (
        "SHELLCHECK_SHA256: 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198" in ci
    )
    assert "koalaman/shellcheck:" not in ci


def test_run_metadata_binds_event_checkout_and_inventory(tmp_path: Path) -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_bytes(evidence.canonical_json(standalone_inventory(component)))
    output = tmp_path / "run-metadata.json"
    arguments = SimpleNamespace(
        inventory=str(inventory_path),
        output=str(output),
        run_id="1234",
        run_attempt=2,
        event_name="pull_request",
        repository_id="5678",
        pr_number="27",
        pr_head_sha="a" * 40,
        pr_base_sha="b" * 40,
        pr_head_repository_id="5678",
        github_sha="c" * 40,
        checkout_sha="c" * 40,
        workflow_ref="stampbot/extra-codeowners/.github/workflows/ci.yml@refs/pull/27/merge",
        workflow_sha="d" * 40,
        platform="linux/amd64",
        architecture="amd64",
        python_distribution_artifact_id="9012",
        python_distribution_artifact_digest="d" * 64,
        application_source_revision="c" * 40,
        application_wheel_sha256="e" * 64,
        application_selection_record_sha256="f" * 64,
    )
    evidence.command_run_metadata(arguments)
    metadata_record = json.loads(output.read_text())
    assert metadata_record["checkout_sha"] == "c" * 40
    assert metadata_record["pr_head_sha"] == "a" * 40
    assert metadata_record["inventory_subject_digest"] == "sha256:" + "a" * 64
    assert metadata_record["python_distribution_artifact_id"] == "9012"
    assert metadata_record["python_distribution_artifact_digest"] == "d" * 64
    assert metadata_record["application_selection_record_sha256"] == "f" * 64

    arguments.github_sha = "e" * 40
    with pytest.raises(evidence.EvidenceError, match="does not match"):
        evidence.command_run_metadata(arguments)

    arguments.github_sha = "c" * 40
    for field in ("run_id", "repository_id", "pr_head_repository_id"):
        original = getattr(arguments, field)
        setattr(arguments, field, "0")
        with pytest.raises(evidence.EvidenceError, match=field):
            evidence.command_run_metadata(arguments)
        setattr(arguments, field, original)

    arguments.pr_number = "0"
    with pytest.raises(evidence.EvidenceError, match="event and pull-request"):
        evidence.command_run_metadata(arguments)
    arguments.event_name = "push"
    evidence.command_run_metadata(arguments)
    arguments.pr_number = "27"
    with pytest.raises(evidence.EvidenceError, match="event and pull-request"):
        evidence.command_run_metadata(arguments)

    arguments.event_name = "pull_request"
    for field in (
        "python_distribution_artifact_digest",
        "application_wheel_sha256",
        "application_selection_record_sha256",
    ):
        original = getattr(arguments, field)
        setattr(arguments, field, "0")
        with pytest.raises(evidence.EvidenceError, match=field):
            evidence.command_run_metadata(arguments)
        setattr(arguments, field, original)

    arguments.python_distribution_artifact_id = "0"
    with pytest.raises(evidence.EvidenceError, match="python_distribution_artifact_id"):
        evidence.command_run_metadata(arguments)
    arguments.python_distribution_artifact_id = "9012"

    arguments.application_source_revision = "a" * 40
    with pytest.raises(evidence.EvidenceError, match="application source revision"):
        evidence.command_run_metadata(arguments)


def test_ci_artifact_extractor_validates_and_atomically_unpacks(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    output = tmp_path / "review-input"
    evidence.extract_ci_artifact(archive, "amd64", output)
    assert sorted(path.name for path in output.iterdir()) == sorted(
        evidence.ci_artifact_entry_limits("amd64")
    )
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())

    with pytest.raises(evidence.EvidenceError, match="already exists"):
        evidence.extract_ci_artifact(archive, "amd64", output)


def test_ci_artifact_extractor_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "artifact.fifo"
    os.mkfifo(fifo)
    command = [
        sys.executable,
        ".github/scripts/container_evidence.py",
        "extract-ci-artifact",
        "--archive",
        str(fifo),
        "--architecture",
        "amd64",
        "--output",
        str(tmp_path / "output"),
    ]
    # Starting a second emulated Python process can exceed two seconds in the
    # arm64 CI job. Ten seconds remains a strict upper bound for the FIFO-open
    # regression this test protects against.
    completed = subprocess.run(  # noqa: S603 - sys.executable is the trusted interpreter.
        command, capture_output=True, check=False, timeout=10
    )
    assert completed.returncode == 1
    assert b"input must be a regular file" in completed.stderr


def test_ci_artifact_extractor_rejects_symlinked_boundaries(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    archive_link = tmp_path / "artifact-link.zip"
    archive_link.symlink_to(archive)
    with pytest.raises(evidence.EvidenceError, match="safely extract"):
        evidence.extract_ci_artifact(archive_link, "amd64", tmp_path / "input-link-output")

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(evidence.EvidenceError, match="output parent"):
        evidence.extract_ci_artifact(archive, "amd64", parent_link / "output")

    output_link = tmp_path / "output-link"
    output_link.symlink_to(tmp_path / "absent")
    with pytest.raises(evidence.EvidenceError, match="already exists"):
        evidence.extract_ci_artifact(archive, "amd64", output_link)


def test_ci_artifact_pair_requires_one_shared_workflow_context(tmp_path: Path) -> None:
    roots: dict[str, Path] = {}
    for architecture in ("amd64", "arm64"):
        archive = tmp_path / f"{architecture}.zip"
        write_ci_artifact_zip(archive, ci_artifact_files(tmp_path, architecture))
        roots[architecture] = tmp_path / architecture
        evidence.extract_ci_artifact(archive, architecture, roots[architecture])
    evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])

    metadata_path = roots["arm64"] / "run-metadata-arm64.json"
    metadata_record = json.loads(metadata_path.read_text())
    metadata_record["run_attempt"] = 3
    metadata_path.write_bytes(evidence.canonical_json(metadata_record))
    with pytest.raises(evidence.EvidenceError, match="one exact workflow context"):
        evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])


@pytest.mark.parametrize(
    "field",
    [
        "python_distribution_artifact_id",
        "python_distribution_artifact_digest",
        "application_wheel_sha256",
        "application_selection_record_sha256",
        "application_source_revision",
    ],
)
def test_ci_artifact_pair_rejects_cross_platform_application_proof_mismatch(
    field: str, tmp_path: Path
) -> None:
    roots: dict[str, Path] = {}
    for architecture in ("amd64", "arm64"):
        archive = tmp_path / f"{architecture}.zip"
        write_ci_artifact_zip(archive, ci_artifact_files(tmp_path, architecture))
        roots[architecture] = tmp_path / architecture
        evidence.extract_ci_artifact(archive, architecture, roots[architecture])

    metadata_path = roots["arm64"] / "run-metadata-arm64.json"
    inventory_path = roots["arm64"] / "components-arm64.json"
    metadata = json.loads(metadata_path.read_text())
    inventory = json.loads(inventory_path.read_text())
    if field == "python_distribution_artifact_id":
        metadata[field] = "9013"
    elif field == "python_distribution_artifact_digest":
        metadata[field] = "0" * 64
    elif field in {
        "application_wheel_sha256",
        "application_selection_record_sha256",
    }:
        metadata[field] = "0" * 64
        inventory[field] = "0" * 64
    else:
        metadata["application_source_revision"] = "0" * 40
        metadata["github_sha"] = "0" * 40
        metadata["checkout_sha"] = "0" * 40
        inventory["image_revision"] = "0" * 40
    metadata_path.write_bytes(evidence.canonical_json(metadata))
    inventory_path.write_bytes(evidence.canonical_json(inventory))

    with pytest.raises(evidence.EvidenceError, match="one exact workflow context"):
        evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])


def test_ci_artifact_pair_rejects_shared_platform_digests(tmp_path: Path) -> None:
    roots: dict[str, Path] = {}
    for architecture in ("amd64", "arm64"):
        archive = tmp_path / f"{architecture}.zip"
        write_ci_artifact_zip(archive, ci_artifact_files(tmp_path, architecture))
        roots[architecture] = tmp_path / architecture
        evidence.extract_ci_artifact(archive, architecture, roots[architecture])

    amd64_inventory = json.loads((roots["amd64"] / "components-amd64.json").read_text())
    shared_digests = {
        field: amd64_inventory[field] for field in ("subject_digest", "image_config_digest")
    }
    for filename in ("components-arm64.json", "all-layer-files-arm64.json"):
        path = roots["arm64"] / filename
        record = json.loads(path.read_text())
        record.update(shared_digests)
        path.write_bytes(evidence.canonical_json(record))
    metadata_path = roots["arm64"] / "run-metadata-arm64.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["inventory_subject_digest"] = shared_digests["subject_digest"]
    metadata["inventory_image_config_digest"] = shared_digests["image_config_digest"]
    metadata_path.write_bytes(evidence.canonical_json(metadata))
    predicate_path = roots["arm64"] / "evidence-predicate-arm64.json"
    predicate = json.loads(predicate_path.read_text())
    predicate["subject_digest"] = shared_digests["subject_digest"]
    predicate_path.write_bytes(evidence.canonical_json(predicate))

    with pytest.raises(evidence.EvidenceError, match="unexpectedly share"):
        evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])


@pytest.mark.parametrize(
    "hostile_name",
    ("../components-amd64.json", "dir/components-amd64.json", "bad\\name", "bad\nname"),
)
def test_ci_artifact_extractor_rejects_unsafe_or_unexpected_names(
    hostile_name: str, tmp_path: Path
) -> None:
    files = ci_artifact_files(tmp_path)
    files[hostile_name] = files.pop("components-amd64.json")
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, files)
    with pytest.raises(evidence.EvidenceError, match="exact expected files"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_ci_artifact_extractor_rejects_links_and_resource_bombs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = ci_artifact_files(tmp_path)
    archive = tmp_path / "symlink.zip"
    write_ci_artifact_zip(archive, files)
    content = bytearray(archive.read_bytes())
    _local, central = zip_record_offsets(content, "components-amd64.json")
    content[central + 38 : central + 42] = ((stat.S_IFLNK | 0o777) << 16).to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match="entry metadata"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "link-output")

    ratio_archive = tmp_path / "ratio.zip"
    ratio_files = copy.deepcopy(files)
    ratio_files["components-amd64.json"] = b"0" * 10_000
    write_ci_artifact_zip(ratio_archive, ratio_files)
    monkeypatch.setattr(evidence, "MAX_CI_ARTIFACT_COMPRESSION_RATIO", 2)
    with pytest.raises(evidence.EvidenceError, match="resource limits"):
        evidence.extract_ci_artifact(ratio_archive, "amd64", tmp_path / "ratio-output")


def test_ci_artifact_extractor_enforces_central_directory_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    monkeypatch.setattr(evidence, "MAX_CI_ARTIFACT_CENTRAL_DIRECTORY_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="central-directory boundary"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_enforces_per_entry_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    monkeypatch.setattr(evidence, "MAX_JSON_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="entry exceeds its resource limits"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_rejects_duplicate_names(tmp_path: Path) -> None:
    files = ci_artifact_files(tmp_path)
    files.pop("evidence-predicate-amd64.json")
    archive = tmp_path / "duplicate.zip"
    entries = [*files.items(), ("components-amd64.json", files["components-amd64.json"])]
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive.write_bytes(ci_artifact_zip_bytes(entries))
    with pytest.raises(evidence.EvidenceError, match="exact expected files"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize(
    "mutation",
    ["stored", "seekable", "extra", "entry-comment", "archive-comment", "windows"],
)
def test_ci_artifact_extractor_rejects_non_provider_envelopes(
    mutation: str, tmp_path: Path
) -> None:
    files = ci_artifact_files(tmp_path)
    archive = tmp_path / "artifact.zip"
    if mutation == "seekable":
        with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, content in files.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.create_version = 45
                info.extract_version = 20
                info.external_attr = evidence.CI_ARTIFACT_EXTERNAL_ATTR
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, content)
    else:

        def modifier(name: str, info: zipfile.ZipInfo) -> None:
            if name != "components-amd64.json":
                return
            if mutation == "stored":
                info.compress_type = zipfile.ZIP_STORED
            elif mutation == "extra":
                info.extra = b"\xfe\xca\x00\x00"
            elif mutation == "entry-comment":
                info.comment = b"unexpected"
            elif mutation == "windows":
                info.create_system = 0

        archive.write_bytes(
            ci_artifact_zip_bytes(
                list(files.items()),
                modifier=modifier,
                archive_comment=b"unexpected" if mutation == "archive-comment" else b"",
            )
        )
    with pytest.raises(
        evidence.EvidenceError,
        match=r"metadata|flags|compression|central directory|end-of-central-directory",
    ):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("mutation", ["descriptor", "timestamp", "local-crc"])
def test_ci_artifact_extractor_rejects_local_descriptor_disagreement(
    mutation: str, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    name = "components-amd64.json"
    local, _central = zip_record_offsets(content, name)
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as source:
        entry = source.getinfo(name)
    header = evidence.ZIP_LOCAL_HEADER.unpack_from(content, local)
    data_offset = local + evidence.ZIP_LOCAL_HEADER.size + header[-2] + header[-1]
    descriptor_offset = data_offset + entry.compress_size
    if mutation == "descriptor":
        content[descriptor_offset] ^= 0xFF
    elif mutation == "timestamp":
        content[local + 10 : local + 14] = b"\x00\x00\x00\x00"
    else:
        content[local + 14 : local + 18] = (1).to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"descriptor|timestamp|local record"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("mutation", ["prefix", "gap"])
def test_ci_artifact_extractor_rejects_prefixes_and_gaps(mutation: str, tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central = int(evidence.ZIP_EOCD.unpack_from(content, eocd)[-2])
    if mutation == "prefix":
        content = bytearray(b"X") + content
        eocd += 1
        central += 1
        content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")
        position = central
        while position < eocd:
            assert content[position : position + 4] == b"PK\x01\x02"
            local_offset = int.from_bytes(content[position + 42 : position + 46], "little") + 1
            content[position + 42 : position + 46] = local_offset.to_bytes(4, "little")
            name_size = int.from_bytes(content[position + 28 : position + 30], "little")
            position += 46 + name_size
    else:
        content[central:central] = b"X"
        eocd += 1
        central += 1
        content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"prefix|gap|central-directory boundary"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_rejects_reordered_central_records(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central = int(evidence.ZIP_EOCD.unpack_from(content, eocd)[-2])
    records: list[bytes] = []
    position = central
    while position < eocd:
        assert content[position : position + 4] == b"PK\x01\x02"
        name_size = int.from_bytes(content[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(content[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(content[position + 32 : position + 34], "little")
        end = position + 46 + name_size + extra_size + comment_size
        records.append(bytes(content[position:end]))
        position = end
    assert len(records) == len(evidence.ci_artifact_entry_limits("amd64"))
    content[central:eocd] = b"".join(reversed(records))
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match="local-record order"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("mutation", ["encrypted", "utf8", "method", "overlap"])
def test_ci_artifact_extractor_rejects_hostile_local_and_central_records(
    mutation: str, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    first_name = "components-amd64.json"
    local, central = zip_record_offsets(content, first_name)
    if mutation == "encrypted":
        local_flags = int.from_bytes(content[local + 6 : local + 8], "little") | 1
        central_flags = int.from_bytes(content[central + 8 : central + 10], "little") | 1
        content[local + 6 : local + 8] = local_flags.to_bytes(2, "little")
        content[central + 8 : central + 10] = central_flags.to_bytes(2, "little")
    elif mutation == "utf8":
        content[local + 6 : local + 8] = (0x808).to_bytes(2, "little")
        content[central + 8 : central + 10] = (0x808).to_bytes(2, "little")
    elif mutation == "method":
        content[local + 8 : local + 10] = (99).to_bytes(2, "little")
        content[central + 10 : central + 12] = (99).to_bytes(2, "little")
    else:
        _second_local, second_central = zip_record_offsets(content, "run-metadata-amd64.json")
        content[second_central + 42 : second_central + 46] = local.to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"flags|compression|disagrees|overlap"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("sentinel", [7, 0xFFFF])
def test_ci_artifact_extractor_rejects_entry_count_and_zip64_sentinels(
    sentinel: int, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    offset = content.rfind(b"PK\x05\x06")
    assert offset >= 0
    content[offset + 8 : offset + 10] = sentinel.to_bytes(2, "little")
    content[offset + 10 : offset + 12] = sentinel.to_bytes(2, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"entry count|ZIP64"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_rejects_corrupt_payload_and_cleans_output(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as source:
        entry = source.getinfo("extra-codeowners-ci-linux-amd64-evidence.tar.gz")
        header = evidence.ZIP_LOCAL_HEADER.unpack_from(content, entry.header_offset)
        payload_offset = (
            entry.header_offset + evidence.ZIP_LOCAL_HEADER.size + header[-2] + header[-1]
        )
    content[payload_offset] ^= 0xFF
    archive.write_bytes(content)
    output = tmp_path / "output"
    with pytest.raises(evidence.EvidenceError, match=r"safely extract|CRC|decompress"):
        evidence.extract_ci_artifact(archive, "amd64", output)
    assert not output.exists()
    assert not list(tmp_path.glob(".output.*"))


@pytest.mark.parametrize("mutation", ["metadata", "predicate", "media-type", "sidecar"])
def test_ci_artifact_extractor_rejects_content_tampering(mutation: str, tmp_path: Path) -> None:
    files = ci_artifact_files(tmp_path)
    if mutation == "metadata":
        metadata = json.loads(files["run-metadata-amd64.json"])
        metadata["untrusted"] = True
        files["run-metadata-amd64.json"] = evidence.canonical_json(metadata)
        message = "run metadata has an unexpected schema shape"
    elif mutation == "predicate":
        predicate = json.loads(files["evidence-predicate-amd64.json"])
        predicate["subject_digest"] = "sha256:" + "0" * 64
        files["evidence-predicate-amd64.json"] = evidence.canonical_json(predicate)
        message = "predicate does not match"
    elif mutation == "media-type":
        predicate = json.loads(files["evidence-predicate-amd64.json"])
        predicate["media_type"] = "application/vnd.stampbot.container-evidence.v5+tar+gzip"
        files["evidence-predicate-amd64.json"] = evidence.canonical_json(predicate)
        message = "predicate does not match"
    else:
        name = "extra-codeowners-ci-linux-amd64-evidence.tar.gz.sha256"
        files[name] = b"0" * 64 + b"  extra-codeowners-ci-linux-amd64-evidence.tar.gz\n"
        message = "checksum sidecar does not match"
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, files)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_source_policy_has_exact_nonduplicated_coverage() -> None:
    policy = json.loads(Path(".compliance/container-policy.json").read_text())
    inventory = {"components": policy["platforms"]["linux/amd64"]}
    lock_sources = evidence.parse_lock_sources(Path("uv.lock"))
    evidence.validate_source_policy_coverage(inventory, policy, lock_sources)

    duplicate_python = copy.deepcopy(policy)
    duplicate_python["python_sources"].append(copy.deepcopy(duplicate_python["python_sources"][0]))
    with pytest.raises(evidence.EvidenceError, match="repeats Python source"):
        evidence.validate_source_policy_coverage(inventory, duplicate_python, lock_sources)

    extra_recipe = copy.deepcopy(policy)
    extra_recipe["alpine_recipe_archives"]["unused@" + "a" * 40] = "b" * 64
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.validate_source_policy_coverage(inventory, extra_recipe, lock_sources)

    stale_exception = copy.deepcopy(policy)
    stale_exception["alpine_recipe_exceptions"]["unused@" + "a" * 40] = {
        "allow_dynamic_sources": True,
        "rationale": "Unused test record.",
    }
    with pytest.raises(evidence.EvidenceError, match="unused origin"):
        evidence.validate_source_policy_coverage(inventory, stale_exception, lock_sources)

    duplicate_license = copy.deepcopy(policy)
    duplicate_license["license_texts"].append(copy.deepcopy(duplicate_license["license_texts"][0]))
    with pytest.raises(evidence.EvidenceError, match="repeats standard license"):
        evidence.validate_source_policy_coverage(inventory, duplicate_license, lock_sources)

    missing_native_exception = copy.deepcopy(policy)
    missing_native_exception["license_texts"] = [
        record
        for record in missing_native_exception["license_texts"]
        if record["id"] != "GCC-exception-3.1"
    ]
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.validate_source_policy_coverage(inventory, missing_native_exception, lock_sources)


def test_policy_schema_rejects_unknown_fields_at_every_boundary() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    evidence.validate_policy_schema(policy)
    assert "paid_hosting_legal_review" not in policy
    for platform_policy in policy["base_image_platforms"].values():
        assert set(platform_policy) == {"layer_diff_ids"}

    unknown_top_level = copy.deepcopy(policy)
    unknown_top_level["unknown"] = True
    with pytest.raises(evidence.EvidenceError, match="policy has an unexpected schema shape"):
        evidence.validate_policy_schema(unknown_top_level)

    unknown_base_field = copy.deepcopy(policy)
    unknown_base_field["base_image_platforms"]["linux/amd64"]["config_digest"] = (
        "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="base-image platform policy"):
        evidence.validate_policy_schema(unknown_base_field)

    unknown_resolution_field = copy.deepcopy(policy)
    resolution = next(iter(unknown_resolution_field["license_resolutions"].values()))
    resolution["reviewer"] = "untrusted"
    with pytest.raises(evidence.EvidenceError, match="license resolution"):
        evidence.validate_policy_schema(unknown_resolution_field)


def test_policy_binds_cpython_runtime_to_base_recipe_source_and_license() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    evidence.validate_policy_schema(policy)

    for platform, machine in (("linux/amd64", "x86_64"), ("linux/arm64", "aarch64")):
        runtime = next(
            component
            for component in policy["platforms"][platform]
            if component["ecosystem"] == "runtime"
        )
        assert (runtime["name"], runtime["version"], runtime["purl"]) == (
            "cpython",
            "3.14.6",
            "pkg:generic/python@3.14.6",
        )
        assert {
            record["elf"]["machine"]
            for record in runtime["identity_files"].values()
            if "elf" in record
        } == {machine}
        assert (
            runtime["identity_files"]["version_header"]["sha256"]
            == (policy["cpython_source"]["patchlevel_sha256"])
        )
        assert runtime["identity_files"]["interpreter_link"] == {
            "effective": True,
            "kind": "symlink",
            "layer": 2,
            "path": "usr/local/bin/python3",
            "target": "python3.14",
            "mode": 0o777,
            "uid": 0,
            "gid": 0,
        }
    assert policy["license_resolutions"]["runtime:cpython@3.14.6"]["expression"] == ("Python-2.0.1")
    assert any(record["id"] == "Python-2.0.1" for record in policy["license_texts"])

    outside_base = copy.deepcopy(policy)
    runtime = next(
        component
        for component in outside_base["platforms"]["linux/amd64"]
        if component["ecosystem"] == "runtime"
    )
    for record in runtime["identity_files"].values():
        record["layer"] = len(outside_base["base_image_platforms"]["linux/amd64"]["layer_diff_ids"])
    with pytest.raises(evidence.EvidenceError, match="outside the reviewed base"):
        evidence.validate_policy_schema(outside_base)

    mismatched_recipe = copy.deepcopy(policy)
    mismatched_recipe["docker_python_recipe"]["license_url"] = (
        f"https://raw.githubusercontent.com/docker-library/python/{'0' * 40}/LICENSE"
    )
    with pytest.raises(evidence.EvidenceError, match="one commit-pinned repository path"):
        evidence.validate_policy_schema(mismatched_recipe)

    mismatched_source = copy.deepcopy(policy)
    mismatched_source["cpython_source"]["license_member"] = "Python-3.14.5/LICENSE"
    with pytest.raises(evidence.EvidenceError, match="license member"):
        evidence.validate_policy_schema(mismatched_source)

    mismatched_patchlevel = copy.deepcopy(policy)
    mismatched_patchlevel["cpython_source"]["patchlevel_member"] = (
        "Python-3.14.5/Include/patchlevel.h"
    )
    with pytest.raises(evidence.EvidenceError, match="patchlevel member"):
        evidence.validate_policy_schema(mismatched_patchlevel)

    mismatched_installed_header = copy.deepcopy(policy)
    runtime = next(
        component
        for component in mismatched_installed_header["platforms"]["linux/arm64"]
        if component["ecosystem"] == "runtime"
    )
    runtime["identity_files"]["version_header"]["sha256"] = "0" * 64
    with pytest.raises(
        evidence.EvidenceError, match="version header does not match reviewed source"
    ):
        evidence.validate_policy_schema(mismatched_installed_header)


def test_policy_schema_rejects_malformed_nested_strings_and_recipe_links() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))

    malformed_link = copy.deepcopy(policy)
    exception = next(iter(malformed_link["alpine_recipe_exceptions"].values()))
    exception["allowed_links"] = [{"path": None, "target": 1, "type": []}]
    with pytest.raises(evidence.EvidenceError, match="allowed recipe link"):
        evidence.validate_policy_schema(malformed_link)

    unresolved_target = copy.deepcopy(policy)
    exception = next(iter(unresolved_target["alpine_recipe_exceptions"].values()))
    exception["allowed_links"][0]["target"] = "alpine-baselayout.post-install"
    with pytest.raises(evidence.EvidenceError, match="one canonical sibling"):
        evidence.validate_policy_schema(unresolved_target)

    duplicate_path = copy.deepcopy(policy)
    exception = next(iter(duplicate_path["alpine_recipe_exceptions"].values()))
    duplicate = copy.deepcopy(exception["allowed_links"][0])
    duplicate["target"] = duplicate["target"].replace("post-install", "pre-install")
    exception["allowed_links"].append(duplicate)
    with pytest.raises(evidence.EvidenceError, match="duplicate allowed recipe link"):
        evidence.validate_policy_schema(duplicate_path)

    malformed_rationale = copy.deepcopy(policy)
    exception = next(iter(malformed_rationale["alpine_recipe_exceptions"].values()))
    exception["rationale"] = "\ud800"
    with pytest.raises(evidence.EvidenceError, match="valid UTF-8"):
        evidence.validate_policy_schema(malformed_rationale)

    malformed_custom = copy.deepcopy(policy)
    requirement = next(iter(malformed_custom["custom_license_evidence"].values()))
    requirement["rationale"] = "\ud800"
    with pytest.raises(evidence.EvidenceError, match="valid UTF-8"):
        evidence.validate_policy_schema(malformed_custom)

    malformed_base = copy.deepcopy(policy)
    malformed_base["base_image"] = "\ud800"
    with pytest.raises(evidence.EvidenceError, match="valid UTF-8"):
        evidence.validate_policy_schema(malformed_base)

    mismatched_platform = copy.deepcopy(policy)
    alpine = next(
        component
        for component in mismatched_platform["platforms"]["linux/amd64"]
        if component["ecosystem"] == "alpine"
    )
    alpine["architecture"] = "aarch64"
    with pytest.raises(evidence.EvidenceError, match="architecture mismatch"):
        evidence.validate_policy_schema(mismatched_platform)


def test_policy_schema_rejects_noncanonical_retained_paths() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    variants: list[dict[str, Any]] = []

    custom = copy.deepcopy(policy)
    custom_record = next(
        iter(next(iter(custom["custom_license_evidence"].values()))["evidence"].values())
    )
    custom_record["path"] = "./" + custom_record["path"]
    variants.append(custom)

    unexpanded = copy.deepcopy(policy)
    unexpanded_record = unexpanded["unexpanded_python_payloads"]["linux/amd64"]["embedded_sboms"][0]
    unexpanded_record["path"] += "/"
    variants.append(unexpanded)

    for category in ("apk_database_occurrences", "post_base_directory_effects"):
        filesystem = copy.deepcopy(policy)
        record = filesystem["filesystem_baselines"]["linux/amd64"][category][0]
        record["path"] = "./" + record["path"]
        variants.append(filesystem)

    whiteout = copy.deepcopy(policy)
    whiteout_record = whiteout["filesystem_baselines"]["linux/amd64"]["post_base_removals"][0]
    whiteout_record["path"] = "./" + whiteout_record["path"]
    variants.append(whiteout)

    for variant in variants:
        with pytest.raises(evidence.EvidenceError, match="canonical archive path"):
            evidence.validate_policy_schema(variant)


def test_standalone_inventory_enforces_platform_and_python_ownership_invariants() -> None:
    alpine = {
        "ecosystem": "alpine",
        "name": "demo",
        "version": "1-r0",
        "architecture": "aarch64",
        "observed_license": "MIT",
        "origin": "demo",
        "aports_commit": "e" * 40,
        "effective": True,
    }
    with pytest.raises(evidence.EvidenceError, match="architecture mismatch"):
        evidence.validate_component_inventory(standalone_inventory(alpine))

    first = {
        "ecosystem": "python",
        "name": "first",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    second = {**first, "name": "second", "metadata_sha256": "f" * 64}
    duplicate_hash = standalone_inventory(first)
    duplicate_hash["components"].append(second)
    with pytest.raises(evidence.EvidenceError, match="reuses a Python metadata digest"):
        evidence.validate_component_inventory(duplicate_hash)

    second_version = {**first, "version": "2", "metadata_sha256": "e" * 64}
    ambiguous_owner = standalone_inventory(first)
    ambiguous_owner["components"].append(second_version)
    with pytest.raises(evidence.EvidenceError, match="multiple effective versions"):
        evidence.validate_component_inventory(ambiguous_owner)

    noncanonical = standalone_inventory(first)
    payload = copy.deepcopy(noncanonical["apk_database_occurrences"][0])
    payload["path"] = "./embedded/sbom.json"
    payload["owner"] = "python:first@1"
    payload["cyclonedx"] = evidence.parse_cyclonedx_sbom(cyclonedx_sbom(), "embedded/sbom.json")
    noncanonical["embedded_sboms"] = [payload]
    with pytest.raises(evidence.EvidenceError, match="canonical archive path"):
        evidence.validate_component_inventory(noncanonical)


@pytest.mark.parametrize("field", ["name", "version"])
def test_python_component_identity_is_bounded(field: str) -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    component[field] = "a" * (evidence.MAX_COMPONENT_FIELD_LENGTH + 1)
    with pytest.raises(evidence.EvidenceError, match="invalid length"):
        evidence.validate_component_inventory(standalone_inventory(component))


def selected_retention_fixture(
    command: list[str], *, mutation: str = ""
) -> tuple[dict[str, Any], bytes]:
    output = Path(command[command.index("--output") + 1])
    output.mkdir(parents=True)
    payloads = {
        "extra_codeowners-1-py3-none-any.whl": b"wheel",
        "extra_codeowners-1.tar.gz": b"source",
        "python-build-record-amd64.json": b"amd64-record",
        "python-build-record-arm64.json": b"arm64-record",
        "python-selection-record.json": b"selection-record",
    }
    for name, content in payloads.items():
        (output / name).write_bytes(content)
    files = [
        {
            "filename": name,
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
        for name, content in sorted(payloads.items())
    ]
    result = {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "selection_record_sha256": evidence.sha256_bytes(payloads["python-selection-record.json"]),
        "wheel_filename": "extra_codeowners-1-py3-none-any.whl",
        "wheel_sha256": evidence.sha256_bytes(payloads["extra_codeowners-1-py3-none-any.whl"]),
        "sdist_filename": "extra_codeowners-1.tar.gz",
        "sdist_sha256": evidence.sha256_bytes(payloads["extra_codeowners-1.tar.gz"]),
        "files": files,
        "installation": {"contract": "opaque to retention"},
    }
    if mutation == "schema":
        result["schema_version"] = 2
    elif mutation == "missing":
        result["files"] = files[:-1]
        (output / files[-1]["filename"]).unlink()
    elif mutation == "extra":
        extra = output / "unreviewed"
        extra.write_bytes(b"extra")
        result["files"] = [
            *files,
            {
                "filename": extra.name,
                "sha256": evidence.sha256_bytes(b"extra"),
                "size": 5,
            },
        ]
    elif mutation == "symlink":
        name = "python-build-record-arm64.json"
        linked = output / name
        content = linked.read_bytes()
        target = output.parent / "outside-record"
        target.write_bytes(content)
        linked.unlink()
        linked.symlink_to(target)
    elif mutation == "tampered":
        cast(list[dict[str, Any]], result["files"])[0]["sha256"] = "0" * 64
    compact = json.dumps(
        result,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if mutation == "noncanonical":
        compact = json.dumps(result, indent=2, sort_keys=True).encode()
    return result, compact + b"\n"


def test_retains_exact_selected_proof_for_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> bytes:
        nonlocal result
        result, output = selected_retention_fixture(command)
        return output

    monkeypatch.setattr(evidence, "run", fake_run)
    budget = evidence.BundleBudget()
    expected_payloads = {
        "wheel": evidence.sha256_bytes(b"wheel"),
        "selection": evidence.sha256_bytes(b"selection-record"),
    }
    binding, installation = evidence.retain_selected_application_artifacts(
        directory=tmp_path / "incoming",
        output=tmp_path / "bundle" / "artifacts" / "application",
        repo=tmp_path,
        source_revision="a" * 40,
        wheel_sha256=expected_payloads["wheel"],
        selection_record_sha256=expected_payloads["selection"],
        budget=budget,
    )

    assert len(binding["files"]) == 5
    assert {record["path"] for record in binding["files"]} == {
        f"artifacts/application/{record['filename']}" for record in result["files"]
    }
    assert binding["wheel_sha256"] == expected_payloads["wheel"]
    assert binding["selection_record_sha256"] == expected_payloads["selection"]
    assert installation == {"contract": "opaque to retention"}
    assert budget.retained_file_count == 5


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("noncanonical", "noncanonical JSON"),
        ("schema", "unsupported schema"),
        ("missing", "exactly five"),
        ("extra", "exactly five"),
        ("symlink", "cannot read retained"),
        ("tampered", "differs from its canonical hash"),
    ],
)
def test_selected_proof_retention_fails_closed(
    mutation: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(command: list[str], **_kwargs: Any) -> bytes:
        _result, output = selected_retention_fixture(command, mutation=mutation)
        return output

    monkeypatch.setattr(evidence, "run", fake_run)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.retain_selected_application_artifacts(
            directory=tmp_path / "incoming",
            output=tmp_path / "bundle" / "artifacts" / "application",
            repo=tmp_path,
            source_revision="a" * 40,
            wheel_sha256=evidence.sha256_bytes(b"wheel"),
            selection_record_sha256=evidence.sha256_bytes(b"selection-record"),
            budget=evidence.BundleBudget(),
        )


@pytest.mark.parametrize("platform", ("linux/amd64", "linux/arm64"))
def test_trusted_native_component_bundle_contract_is_internally_bound(
    platform: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _inventories, _locked, native_policy, _lock_sources = native_component_coverage_case()
    committed_policy = json.loads(Path(".compliance/container-policy.json").read_text())
    for coverage_platform, platform_records in native_policy["native_component_coverage"].items():
        markupsafe = next(
            copy.deepcopy(record)
            for record in committed_policy["native_component_coverage"][coverage_platform]
            if record["owner"] == "python:markupsafe@3.0.3"
        )
        platform_records.append(markupsafe)
    source_id = "alpine:demo-native@1.2.3-r0"
    source = native_policy["native_component_sources"][source_id]
    notice_content = b"reviewed native notice\n"
    notice_member = "demo-native-1.2.3/LICENSE"
    distfile_content = tar_bytes(
        {
            notice_member: notice_content,
            "demo-native-1.2.3/source.c": b"int demo(void) { return 0; }\n",
        }
    )
    distfile = source["distfiles"][0]
    distfile.update(
        {
            "sha512": evidence.hashlib.sha512(distfile_content).hexdigest(),
            "size": len(distfile_content),
        }
    )
    source["notices"] = [
        {
            "member": notice_member,
            "sha256": evidence.sha256_bytes(notice_content),
            "size": len(notice_content),
        }
    ]
    apkbuild = (
        "pkgname=demo-native\n"
        "pkgver=1.2.3\n"
        "pkgrel=0\n"
        'license="MIT"\n'
        'source="https://example.com/demo-native-$pkgver.tar.xz"\n'
        f'sha512sums="\n{distfile["sha512"]}  {distfile["filename"]}\n"\n'
    ).encode()
    recipe_content = tar_bytes({"aports/main/demo-native/APKBUILD": apkbuild})
    source["recipe"].update(
        {
            "sha256": evidence.sha256_bytes(recipe_content),
            "size": len(recipe_content),
        }
    )

    evidence.validate_native_component_policy_schema(native_policy)

    resolved_owner_records = copy.deepcopy(native_policy["native_component_coverage"][platform])
    owner_record = resolved_owner_records[0]
    native_coverage = {
        "schema_version": evidence.SCHEMA_VERSION,
        "platform": platform,
        "complete": True,
        "resolved_owners": resolved_owner_records,
        "unresolved_owners": [],
        "observed_sbom_anomalies": [],
        "remaining_owner_count": 0,
        "remaining_owner_names": [],
    }
    application = {
        "ecosystem": "python",
        "name": "extra-codeowners",
        "version": "0.0.0",
        "observed_license": "Apache-2.0",
        "effective": True,
        "metadata_sha256": "1" * 64,
    }
    markupsafe_component = {
        "ecosystem": "python",
        "name": "markupsafe",
        "version": "3.0.3",
        "observed_license": "BSD-3-Clause",
        "effective": True,
        "metadata_sha256": "12b4cc61a7fa288cf7667ee3f213786d9619db57fb33ff6f934afbcb5c12ec81",
    }
    inventory = {
        "platform": platform,
        "subject_digest": "sha256:" + "2" * 64,
        "components": [application, markupsafe_component],
    }
    files: dict[str, Any] = {}
    docker_recipe_content = b"trusted Docker Official Python recipe\n"
    cpython_source_content = b"trusted CPython source archive\n"
    cpython_license = b"trusted CPython license\n"
    docker_recipe_url = "https://example.com/docker-python-recipe.tar.gz"
    cpython_source_url = "https://example.com/Python-3.14.6.tgz"
    policy = {
        "base_image_index_digest": "sha256:" + "3" * 64,
        "distribution_approval": {
            "approved": False,
            "approved_by": "",
            "approved_on": "",
            "rationale": "The trusted fixture remains intentionally unapproved.",
        },
        "docker_python_recipe": {
            "url": docker_recipe_url,
            "sha256": evidence.sha256_bytes(docker_recipe_content),
        },
        "cpython_source": {
            "url": cpython_source_url,
            "sha256": evidence.sha256_bytes(cpython_source_content),
        },
        "license_resolutions": {
            "python:extra-codeowners@0.0.0": {
                "expression": "Apache-2.0",
                "rationale": "Reviewed trusted fixture.",
            },
            "python:markupsafe@3.0.3": {
                "expression": "BSD-3-Clause",
                "rationale": "Reviewed exact MarkupSafe fixture.",
            },
        },
        "custom_license_evidence": {},
        "license_texts": [],
        "native_component_sources": native_policy["native_component_sources"],
        "native_component_coverage": native_policy["native_component_coverage"],
        "alpine_distfiles_release": "v3.22",
        "alpine_recipe_archives": {},
        "alpine_recipe_exceptions": {},
    }

    inventory_path = tmp_path / "components.json"
    files_path = tmp_path / "files.json"
    policy_path = tmp_path / "policy.json"
    lock_path = tmp_path / "uv.lock"
    inventory_path.write_bytes(evidence.canonical_json(inventory))
    files_path.write_bytes(evidence.canonical_json(files))
    policy_path.write_bytes(evidence.canonical_json(policy))
    lock_path.write_text("version = 1\nrevision = 3\n")

    wheel_pin = MARKUPSAFE_WHEELS[platform]
    locked_wheel = {
        "owner": "python:markupsafe@3.0.3",
        "platform": platform,
        "url": wheel_pin["url"],
        "sha256": wheel_pin["sha256"],
        "size": wheel_pin["size"],
        "filename": wheel_pin["filename"],
        "build": "",
        "tags": [wheel_pin["tag"]],
    }
    wheel_content = b"\0" * cast(int, wheel_pin["size"])
    markupsafe_sdist = tar_bytes(
        {
            "markupsafe-3.0.3/LICENSE.txt": MARKUPSAFE_LICENSE_TEXT,
            "markupsafe-3.0.3/docs/license.rst": MARKUPSAFE_DOCS_LICENSE,
        }
    )
    assert len(markupsafe_sdist) < MARKUPSAFE_SOURCE["size"]
    markupsafe_sdist += b"\0" * (cast(int, MARKUPSAFE_SOURCE["size"]) - len(markupsafe_sdist))

    revision = "4" * 40
    monkeypatch.setattr(evidence, "validate_all_layer_inventory", lambda *_args: None)
    monkeypatch.setattr(evidence, "verify_inventory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(evidence, "verify_dockerfile_base", lambda *_args: None)
    monkeypatch.setattr(
        evidence, "verify_application_artifact_labels", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(evidence, "verify_base_layer_binding", lambda *_args: None)
    monkeypatch.setattr(evidence, "verify_post_base_provenance", lambda *_args: None)
    monkeypatch.setattr(
        evidence,
        "validate_application_source_binding",
        lambda *_args: ("extra-codeowners", "0.0.0"),
    )
    monkeypatch.setattr(
        evidence,
        "parse_lock_sources",
        lambda *_args: {("markupsafe", "3.0.3"): copy.deepcopy(MARKUPSAFE_SOURCE)},
    )
    monkeypatch.setattr(evidence, "validate_source_policy_coverage", lambda *_args: None)
    monkeypatch.setattr(
        evidence, "select_locked_native_wheels", lambda *_args: [copy.deepcopy(locked_wheel)]
    )
    monkeypatch.setattr(
        evidence,
        "verify_native_component_lock_bindings",
        lambda *_args: copy.deepcopy(native_coverage),
    )
    monkeypatch.setattr(
        evidence,
        "retain_selected_application_artifacts",
        lambda **_kwargs: (
            {
                "source_revision": revision,
                "wheel_sha256": "5" * 64,
                "selection_record_sha256": "6" * 64,
                "files": [],
            },
            {"trusted_fixture": True},
        ),
    )
    monkeypatch.setattr(
        evidence,
        "verify_selected_application_installation",
        lambda *_args: "/opt/venv/bin/python",
    )
    monkeypatch.setattr(evidence, "deterministic_source_archive", lambda *_args: b"app source")
    monkeypatch.setattr(evidence, "verify_cpython_source_binding", lambda *_args: None)
    monkeypatch.setattr(evidence, "verify_cpython_source_archive", lambda *_args: cpython_license)
    monkeypatch.setattr(evidence, "run", lambda *_args, **_kwargs: f"{revision}\n".encode())

    wheel_relative = f"artifacts/native-wheels/markupsafe/3.0.3/{wheel_pin['filename']}"

    def fake_retain_native_wheel_artifact(
        root: Path,
        _inventory: dict[str, Any],
        selected: dict[str, Any],
        content: bytes,
        *,
        budget: Any,
        urls: tuple[str, ...],
    ) -> dict[str, Any]:
        assert selected == locked_wheel
        assert content == wheel_content
        evidence.write_file(root, wheel_relative, content, budget=budget)
        return {
            **copy.deepcopy(selected),
            "url": urls[0],
            "urls": list(urls),
            "path": wheel_relative,
            "generated_files": [],
            "embedded_sboms": [],
        }

    monkeypatch.setattr(evidence, "retain_native_wheel_artifact", fake_retain_native_wheel_artifact)

    downloads = {
        docker_recipe_url: docker_recipe_content,
        cpython_source_url: cpython_source_content,
        source["recipe"]["url"]: recipe_content,
        distfile["url"]: distfile_content,
        cast(str, wheel_pin["url"]): wheel_content,
        cast(str, MARKUPSAFE_SOURCE["url"]): markupsafe_sdist,
    }

    fetched: list[tuple[str, str, str]] = []

    def fake_fetch(
        url: str,
        expected_hash: str,
        algorithm: str = "sha256",
        *,
        max_bytes: int = evidence.MAX_DOWNLOAD_BYTES,
    ) -> Any:
        fetched.append((url, expected_hash, algorithm))
        content = downloads[url]
        assert len(content) <= max_bytes
        return evidence.Download(content=content, urls=(url,))

    real_extract_license_files = evidence.extract_license_files

    def fake_extract_license_files(
        archive: bytes,
        component: str,
        root: Path,
        *,
        archive_name: str | None = None,
        budget: Any | None = None,
    ) -> list[str]:
        if component == "python-markupsafe-3.0.3":
            return cast(
                list[str],
                real_extract_license_files(
                    archive,
                    component,
                    root,
                    archive_name=archive_name,
                    budget=budget,
                ),
            )
        if component != "runtime-cpython-3.14.6":
            return []
        relative = (
            "licenses/from-source/runtime-cpython-3.14.6/"
            f"{evidence.sha256_bytes(cpython_license)[:12]}-LICENSE"
        )
        evidence.write_file(root, relative, cpython_license, budget=budget)
        return [relative]

    monkeypatch.setattr(evidence, "fetch", fake_fetch)
    monkeypatch.setattr(evidence, "extract_license_files", fake_extract_license_files)

    output = tmp_path / "evidence.tar.gz"
    predicate_output = tmp_path / "predicate.json"
    evidence.build_bundle(
        inventory_path=inventory_path,
        files_path=files_path,
        policy_path=policy_path,
        lock_path=lock_path,
        repo=tmp_path,
        output=output,
        predicate_output=predicate_output,
        version="0.0.0-test",
        source_date_epoch=123,
        selected_python_directory=tmp_path / "selected-python",
        application_source_revision=revision,
        application_wheel_sha256="5" * 64,
        application_selection_record_sha256="6" * 64,
        require_approval=False,
        require_image_revision=False,
    )

    archive_files: dict[str, bytes] = {}
    with tarfile.open(output, mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            assert extracted is not None
            archive_files[member.name] = extracted.read()

    manifest = json.loads(archive_files["MANIFEST.json"])
    emitted_ledger = json.loads(archive_files["inventory/native-component-coverage.json"])
    assert emitted_ledger == native_coverage
    assert manifest["native_component_coverage"] == emitted_ledger
    assert manifest["source_completeness"] == {
        "complete": True,
        "remaining_owner_count": 0,
        "remaining_owner_names": [],
    }
    assert policy["distribution_approval"]["approved"] is False
    assert manifest["native_wheel_artifacts"] == [
        {
            **locked_wheel,
            "url": wheel_pin["url"],
            "urls": [wheel_pin["url"]],
            "path": wheel_relative,
            "generated_files": [],
            "embedded_sboms": [],
        }
    ]
    assert archive_files[wheel_relative] == wheel_content
    assert (wheel_pin["url"], wheel_pin["sha256"], "sha256") in fetched
    assert (
        MARKUPSAFE_SOURCE["url"],
        MARKUPSAFE_SOURCE["sha256"],
        "sha256",
    ) in fetched

    native_source_directory = evidence.sha256_bytes(source_id.encode())[:20]
    recipe_path = f"sources/native-components/{native_source_directory}/recipe.tar.gz"
    distfile_path = (
        f"sources/native-components/{native_source_directory}/distfiles/demo-native-1.2.3.tar.xz"
    )
    source_records = {record["path"]: record for record in manifest["source_records"]}
    markupsafe_source_path = "sources/python/markupsafe/3.0.3/markupsafe-3.0.3.tar.gz"
    assert archive_files[markupsafe_source_path] == markupsafe_sdist
    assert source_records[markupsafe_source_path] == evidence.source_record(
        "python-markupsafe-3.0.3",
        cast(str, MARKUPSAFE_SOURCE["url"]),
        markupsafe_sdist,
        markupsafe_source_path,
    )
    assert source_records[recipe_path] == evidence.source_record(
        f"native-source:{source_id}", source["recipe"]["url"], recipe_content, recipe_path
    )
    assert source_records[distfile_path] == evidence.source_record(
        f"native-source:{source_id}",
        distfile["url"],
        distfile_content,
        distfile_path,
        sha512=distfile["sha512"],
    )

    notice_path = (
        f"licenses/from-source/native-{native_source_directory}/"
        f"{evidence.sha256_bytes(notice_content)[:12]}-LICENSE"
    )
    assert archive_files[notice_path] == notice_content
    nested_component = owner_record["sboms"][0]["observation"]["components"][0]
    nested_identity = f"native:{nested_component['purl']}#bom-ref:{nested_component['bom_ref']}"
    assert {
        "component": nested_identity,
        "path": notice_path,
        "sha256": evidence.sha256_bytes(notice_content),
        "size": len(notice_content),
    } in manifest["license_records"]

    markupsafe_license_paths = {
        "licenses/from-source/python-markupsafe-3.0.3/489a8e110850-LICENSE.txt": (
            MARKUPSAFE_LICENSE_TEXT
        ),
        "licenses/from-source/python-markupsafe-3.0.3/6fc7e80b75b5-license.rst": (
            MARKUPSAFE_DOCS_LICENSE
        ),
    }
    for path, content in markupsafe_license_paths.items():
        assert archive_files[path] == content
        assert {
            "component": "python-markupsafe-3.0.3",
            "path": path,
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        } in manifest["license_records"]

    notices = archive_files["THIRD_PARTY_NOTICES.md"].decode()
    assert (
        "| python:demo@1.0 | libdemo | 1.2.3 | pkg:generic/libdemo@1.2.3 | "
        "pkg:generic/libdemo@1.2.3 | alpine:demo-native@1.2.3-r0 |"
    ) in notices
    assert ("| python | markupsafe | 3.0.3 | yes | BSD-3-Clause | BSD-3-Clause |") in notices

    checksum_records = {
        path: digest
        for digest, path in (
            line.split("  ", maxsplit=1)
            for line in archive_files["SHA256SUMS"].decode().splitlines()
        )
    }
    assert set(checksum_records) == set(archive_files) - {"SHA256SUMS"}
    for path, digest in checksum_records.items():
        assert digest == evidence.sha256_bytes(archive_files[path])

    bundle_digest = evidence.sha256_bytes(output.read_bytes())
    assert output.with_suffix(output.suffix + ".sha256").read_text() == (
        f"{bundle_digest}  {output.name}\n"
    )
    predicate = json.loads(predicate_output.read_text())
    assert predicate["artifact"] == {"filename": output.name, "sha256": bundle_digest}


def test_bundle_budget_enforces_cumulative_download_and_retained_limits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(evidence, "MAX_BUNDLE_DOWNLOAD_BYTES", 3)
    download_budget = evidence.BundleBudget()
    download_budget.record_download(b"ab")
    with pytest.raises(evidence.EvidenceError, match="cumulative download-size"):
        download_budget.record_download(b"cd")

    monkeypatch.setattr(evidence, "MAX_BUNDLE_FILES", 1)
    retained_budget = evidence.BundleBudget()
    evidence.write_file(tmp_path, "first", b"one", budget=retained_budget)
    with pytest.raises(evidence.EvidenceError, match="cumulative file-count"):
        evidence.write_file(tmp_path, "second", b"two", budget=retained_budget)


def test_bundle_member_producer_enforces_exact_size_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", 3)
    evidence.write_file(tmp_path, "exact", b"abc")
    with pytest.raises(evidence.EvidenceError, match="bundle member exceeds"):
        evidence.write_file(tmp_path, "too-large", b"abcd")


def test_native_component_source_size_exception_is_path_scoped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", 3)
    monkeypatch.setattr(evidence, "MAX_NATIVE_COMPONENT_SOURCE_BYTES", 4)
    native_root = tmp_path / "native"
    native_root.mkdir()
    evidence.write_file(
        native_root,
        "sources/native-components/demo/1-r0/distfiles/source.tar.xz",
        b"abcd",
        max_bytes=evidence.MAX_NATIVE_COMPONENT_SOURCE_BYTES,
    )
    evidence.create_deterministic_tar(native_root, tmp_path / "native.tar.gz", 123)

    ordinary_root = tmp_path / "ordinary"
    ordinary_root.mkdir()
    (ordinary_root / "source.tar.xz").write_bytes(b"abcd")
    with pytest.raises(evidence.EvidenceError, match="bundle member exceeds"):
        evidence.create_deterministic_tar(ordinary_root, tmp_path / "ordinary.tar.gz", 123)


def test_deterministic_archive_has_normalized_metadata(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "b").write_bytes(b"second")
    (root / "a").write_bytes(b"first")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    evidence.create_deterministic_tar(root, first, 123)
    evidence.create_deterministic_tar(root, second, 123)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
    assert [item.name for item in members] == ["a", "b"]
    assert {(item.uid, item.gid, item.mode, item.mtime) for item in members} == {(0, 0, 0o644, 123)}


def test_release_milestone_must_match_pinned_number_and_be_open_and_empty() -> None:
    ready = {
        "number": 1,
        "title": "First supported release",
        "state": "open",
        "open_issues": 0,
        "closed_issues": 2,
    }
    checked = readiness.validate_milestone(ready, 1, "First supported release")
    readiness.require_ready(checked)

    for changed, message in (
        ({**ready, "number": 2}, "expected milestone #1"),
        ({**ready, "title": "Other"}, "expected 'First supported release'"),
        ({**ready, "closed_issues": True}, "invalid closed_issues"),
    ):
        with pytest.raises(readiness.ReadinessError, match=message):
            readiness.validate_milestone(changed, 1, "First supported release")

    for changed, message in (
        ({**ready, "open_issues": 1}, "still has 1 open"),
        ({**ready, "state": "closed"}, "is not open"),
    ):
        checked = readiness.validate_milestone(changed, 1, "First supported release")
        with pytest.raises(readiness.ReadinessError, match=message):
            readiness.require_ready(checked)


def test_release_policy_is_exact(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone": "First supported release"}'
    )
    assert readiness.configured_milestone(policy) == (1, "First supported release")
    policy.write_text(
        '{"schema_version": 2, "milestone_number": 1, "milestone": "First supported release"}'
    )
    with pytest.raises(readiness.ReadinessError, match="unsupported"):
        readiness.configured_milestone(policy)
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone_number": 2, '
        '"milestone": "First supported release"}'
    )
    with pytest.raises(readiness.ReadinessError, match="duplicate JSON object key"):
        readiness.configured_milestone(policy)


def test_release_summary_links_exact_run_commit_and_counts(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    milestone = {
        "number": 1,
        "title": "First supported release",
        "open_issues": 0,
        "closed_issues": 2,
    }
    readiness.write_summary(
        summary,
        milestone,
        repository="stampbot/extra-codeowners",
        commit="a" * 40,
        run_id="12345",
    )
    content = summary.read_text()
    assert "stampbot/extra-codeowners" in content
    assert f"/commit/{'a' * 40}" in content
    assert "/actions/runs/12345" in content
    assert "milestone/1" in content
    assert "Open issues: **0**" in content
    assert "Closed issues: **2**" in content


def test_release_query_gets_the_pinned_milestone_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[str] = []
    response_body = json.dumps(
        {
            "number": 1,
            "title": "First supported release",
            "state": "open",
            "open_issues": 0,
            "closed_issues": 2,
        }
    ).encode()

    class Response:
        status = 200

        def __init__(self) -> None:
            self.remaining = response_body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            result = self.remaining[:size]
            self.remaining = self.remaining[size:]
            return result

    def urlopen(request: Any, *, timeout: int) -> Response:
        assert timeout == 30
        requests.append(request.full_url)
        return Response()

    monkeypatch.setattr(readiness.urllib.request, "urlopen", urlopen)
    result = readiness.github_milestone("stampbot/extra-codeowners", 1, "token")

    assert result["number"] == 1
    assert requests == ["https://api.github.com/repos/stampbot/extra-codeowners/milestones/1"]


def test_blocked_release_still_writes_the_workflow_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone": "First supported release"}'
    )
    summary = tmp_path / "summary.md"
    milestone = {
        "number": 1,
        "title": "First supported release",
        "state": "open",
        "open_issues": 5,
        "closed_issues": 2,
    }
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(readiness, "github_milestone", lambda *_args: milestone)

    result = readiness.main(
        [
            "--repository",
            "stampbot/extra-codeowners",
            "--policy",
            str(policy),
            "--commit",
            "a" * 40,
            "--run-id",
            "12345",
            "--summary",
            str(summary),
        ]
    )

    assert result == 1
    assert "Open issues: **5**" in summary.read_text()


def test_workflows_keep_release_blocked_and_collect_review_evidence_in_ci() -> None:
    release = Path(".github/workflows/release.yml").read_text()
    ci = Path(".github/workflows/ci.yml").read_text()
    mise = Path("mise.toml").read_text()

    assert "issues: read" in release
    assert "release_readiness.py" in release
    release_block = "Keep tagged publication disabled pending isolated evidence collection"
    assert release_block in release
    assert "https://github.com/stampbot/extra-codeowners/issues/28" in release
    assert release.index(release_block) < release.index("Publish release image")
    publication_block = release.split("  publication-block:\n", 1)[1].split("  python:\n", 1)[0]
    assert "permissions: {}" in publication_block
    assert "exit 1" in publication_block
    assert '--summary "${GITHUB_STEP_SUMMARY}"' in release
    assert "Build digest-bound distribution evidence" not in release
    assert "--require-distribution-approval" not in release
    assert "container-distribution-evidence" not in release
    assert "evidence-predicate-amd64.json" not in release
    assert "evidence-predicate-arm64.json" not in release

    assert "container-evidence-${{ matrix.architecture }}-${{ github.sha }}-attempt-" in ci
    assert "${{ github.run_attempt }}" in ci
    assert '--platform "$PLATFORM"' in ci
    assert "--require-image-revision" in ci
    assert "--allow-config-digest-subject" in ci
    assert (
        "Upload container distribution evidence\n        if: ${{ always() && !cancelled() }}" in ci
    )
    assert "if-no-files-found: warn" in ci
    assert "retention-days: 5" in ci
    assert "run-metadata-${ARCHITECTURE}.json" in ci
    assert "publish-container:" not in ci
    assert "packages: write" not in ci
    assert "push: true" not in ci

    for checked_scope in (ci, release, mise):
        assert ".github/scripts/container_evidence.py" in checked_scope
        assert ".github/scripts/release_readiness.py" in checked_scope


def test_verify_ci_policy_command_composes_every_trusted_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = {
        "inventory.json": {"kind": "inventory"},
        "files.json": {"kind": "files"},
        "policy.json": {"kind": "policy"},
    }
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(evidence, "load_json", lambda path: records[path.name])
    monkeypatch.setattr(
        evidence,
        "validate_all_layer_inventory",
        lambda files, inventory: calls.append(("deep", files, inventory)),
    )
    monkeypatch.setattr(
        evidence,
        "verify_inventory",
        lambda inventory, policy, *, require_approval: calls.append(
            ("policy", inventory, policy, require_approval)
        ),
    )
    monkeypatch.setattr(
        evidence,
        "verify_base_layer_binding",
        lambda files, policy: calls.append(("base", files, policy)),
    )
    monkeypatch.setattr(
        evidence,
        "verify_post_base_filesystem_policy",
        lambda files, policy: calls.append(("filesystem", files, policy)),
    )
    monkeypatch.setattr(
        evidence,
        "verify_dockerfile_base",
        lambda dockerfile, policy: calls.append(("dockerfile", dockerfile, policy)),
    )

    evidence.command_verify_ci_policy(
        SimpleNamespace(
            inventory="inventory.json",
            files_inventory="files.json",
            policy="policy.json",
            dockerfile="Dockerfile",
        )
    )

    assert calls == [
        ("deep", records["files.json"], records["inventory.json"]),
        ("policy", records["inventory.json"], records["policy.json"], False),
        ("base", records["files.json"], records["policy.json"]),
        ("filesystem", records["files.json"], records["policy.json"]),
        ("dockerfile", Path("Dockerfile"), records["policy.json"]),
    ]


def test_filesystem_policy_view_emits_validated_semantic_projection(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "removed": b"lower-layer content",
                },
                directories=["etc", "opt"],
            ),
            tar_bytes(
                {".wh.removed": b""},
                directories=["etc", "opt/application"],
                headers={".wh.removed": {"mode": 0o600}},
            ),
        ],
    )
    _inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    files_path = tmp_path / "all-layer-files.json"
    files_path.write_bytes(evidence.canonical_json(files))
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    policy["base_image_platforms"]["linux/amd64"]["layer_diff_ids"] = [files["layers"][0]["digest"]]
    policy["platforms"]["linux/amd64"] = [
        component
        for component in policy["platforms"]["linux/amd64"]
        if component["ecosystem"] != "runtime"
    ] + [synthetic_runtime_component()]
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(evidence.canonical_json(policy))
    output = tmp_path / "filesystem-policy-view.json"
    arguments = evidence.parser().parse_args(
        [
            "filesystem-policy-view",
            "--files-inventory",
            str(files_path),
            "--policy",
            str(policy_path),
            "--output",
            str(output),
        ]
    )

    arguments.function(arguments)

    assert output.read_bytes() == evidence.canonical_json(
        {
            "platform": "linux/amd64",
            "post_base_directory_effects": [
                {
                    "layer": 1,
                    "path": "opt/application",
                    "mode": 0o755,
                    "uid": 0,
                    "gid": 0,
                }
            ],
            "post_base_removals": [
                {
                    "kind": "whiteout",
                    "path": ".wh.removed",
                    "target": "removed",
                }
            ],
        }
    )


def test_native_component_coverage_view_emits_validated_ledger(tmp_path: Path) -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(
        component,
        "MIT",
        license_texts=[
            {
                "id": "MIT",
                "sha256": "e" * 64,
                "url": "https://example.com/MIT.txt",
            }
        ],
    )
    inventory_path = tmp_path / "inventory.json"
    policy_path = tmp_path / "policy.json"
    output = tmp_path / "native-component-coverage.json"
    inventory_path.write_bytes(evidence.canonical_json(inventory))
    policy_path.write_bytes(evidence.canonical_json(policy))
    arguments = evidence.parser().parse_args(
        [
            "native-component-coverage-view",
            "--inventory",
            str(inventory_path),
            "--policy",
            str(policy_path),
            "--output",
            str(output),
        ]
    )

    arguments.function(arguments)

    assert json.loads(output.read_text()) == {
        "schema_version": evidence.SCHEMA_VERSION,
        "platform": "linux/amd64",
        "complete": True,
        "resolved_owners": [],
        "unresolved_owners": [],
        "observed_sbom_anomalies": [],
        "remaining_owner_count": 0,
        "remaining_owner_names": [],
    }


def test_bundle_command_forwards_image_revision_requirement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setattr(evidence, "build_bundle", lambda **kwargs: observed.update(kwargs))
    args = SimpleNamespace(
        inventory="inventory.json",
        files_inventory="files.json",
        policy="policy.json",
        uv_lock="uv.lock",
        repo=str(tmp_path),
        output="bundle.tar.gz",
        predicate_output="predicate.json",
        version="1.2.3",
        source_date_epoch=123,
        selected_python_directory="selected-python",
        application_source_revision="a" * 40,
        application_wheel_sha256="b" * 64,
        application_selection_record_sha256="c" * 64,
        require_distribution_approval=True,
        require_image_revision=True,
    )

    evidence.command_bundle(args)

    assert observed["require_approval"] is True
    assert observed["require_image_revision"] is True
    assert observed["selected_python_directory"] == Path("selected-python")
    assert observed["application_selection_record_sha256"] == "c" * 64


def test_evidence_cli_requires_selected_proof_identity() -> None:
    with pytest.raises(SystemExit):
        evidence.parser().parse_args(
            [
                "bundle",
                "--inventory",
                "inventory.json",
                "--files-inventory",
                "files.json",
                "--output",
                "bundle.tar.gz",
                "--predicate-output",
                "predicate.json",
                "--version",
                "1.0.0",
                "--source-date-epoch",
                "1",
            ]
        )

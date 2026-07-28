"""Adversarial tests for recipient-side container evidence verification."""

from __future__ import annotations

import ast
import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "recipient_evidence.py"
VERSION = "0.1.0"
PLATFORM = "linux/amd64"
SUBJECT = f"sha256:{'1' * 64}"
INDEX = f"sha256:{'2' * 64}"
REVISION = "3" * 40
SOURCE_DATE_EPOCH = 123_456_789


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("recipient_evidence_for_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier: Any = load_script()


def load_collector() -> ModuleType:
    path = ROOT / ".github" / "scripts" / "container_evidence.py"
    spec = importlib.util.spec_from_file_location("container_evidence_for_recipient_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Fixture:
    archive: Path
    checksum: Path
    predicate: Path
    output: Path
    expected: Any
    files: dict[str, bytes]


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def binding(path: str, content: bytes) -> dict[str, object]:
    return {"path": path, "sha256": sha256(content), "size": len(content)}


def application_source_archive(
    *,
    license_content: bytes,
    pyproject_content: bytes | None = None,
) -> bytes:
    application_package = b'"""Synthetic Extra CODEOWNERS fixture."""\n'
    application_pyproject = pyproject_content or (
        b'[project]\nname = "extra-codeowners"\nversion = "0.1.0"\n'
    )
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        for path, content, mode in (
            ("LICENSE", license_content, 0o644),
            ("extra_codeowners/__init__.py", application_package, 0o644),
            ("pyproject.toml", application_pyproject, 0o644),
        ):
            member = tarfile.TarInfo(path)
            member.size = len(content)
            member.mode = mode
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def runtime_component(platform: str, patchlevel_sha256: str) -> dict[str, Any]:
    machine_id, machine = {
        "linux/amd64": (62, "x86_64"),
        "linux/arm64": (183, "aarch64"),
    }[platform]

    def regular(
        path: str,
        digest: str,
        size: int,
        mode: int,
        *,
        elf: bool = False,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "effective": True,
            "gid": 0,
            "layer": 0,
            "mode": mode,
            "path": path,
            "sha256": digest,
            "size": size,
            "uid": 0,
        }
        if elf:
            record["elf"] = {
                "bits": 64,
                "endianness": "little",
                "machine": machine,
                "machine_id": machine_id,
            }
        return record

    return {
        "ecosystem": "runtime",
        "effective": True,
        "identity_files": {
            "interpreter": regular(
                "usr/local/bin/python3.14",
                "a" * 64,
                64,
                0o755,
                elf=True,
            ),
            "interpreter_link": {
                "effective": True,
                "gid": 0,
                "kind": "symlink",
                "layer": 0,
                "mode": 0o777,
                "path": "usr/local/bin/python3",
                "target": "python3.14",
                "uid": 0,
            },
            "shared_library": regular(
                "usr/local/lib/libpython3.14.so.1.0",
                "b" * 64,
                64,
                0o755,
                elf=True,
            ),
            "version_header": regular(
                "usr/local/include/python3.14/patchlevel.h",
                patchlevel_sha256,
                512,
                0o644,
            ),
        },
        "name": "cpython",
        "observed_license": "",
        "purl": "pkg:generic/python@3.14.6",
        "version": "3.14.6",
    }


def initial_payloads() -> tuple[dict[str, bytes], dict[str, Any]]:
    files: dict[str, bytes] = {}

    application_files = {
        "extra_codeowners-0.1.0-py3-none-any.whl": b"selected wheel\n",
        "extra_codeowners-0.1.0.tar.gz": b"selected sdist\n",
        "python-build-record-amd64.json": verifier.canonical_json({"architecture": "amd64"}),
        "python-build-record-arm64.json": verifier.canonical_json({"architecture": "arm64"}),
        "python-selection-record.json": verifier.canonical_json({"selected": "amd64"}),
    }
    for filename, content in application_files.items():
        files[f"artifacts/application/{filename}"] = content
    wheel_sha256 = sha256(application_files["extra_codeowners-0.1.0-py3-none-any.whl"])
    selection_sha256 = sha256(application_files["python-selection-record.json"])

    wheelhouse_index = f"sha256:{'5' * 64}"
    wheelhouse_revision = "6" * 40
    wheelhouse_contract_record = {
        "image": verifier.WHEELHOUSE_IMAGE,
        "index_digest": wheelhouse_index,
        "manifest_schema_version": verifier.WHEELHOUSE_MANIFEST_SCHEMA_VERSION,
        "platforms": {
            "linux/amd64": {"manifest_digest": f"sha256:{'7' * 64}"},
            "linux/arm64": {"manifest_digest": f"sha256:{'8' * 64}"},
        },
        "signature": {
            "certificate_identity": verifier.WHEELHOUSE_CERTIFICATE_IDENTITY,
            "oidc_issuer": verifier.WHEELHOUSE_OIDC_ISSUER,
        },
        "source_ref": verifier.WHEELHOUSE_SOURCE_REF,
        "source_revision": wheelhouse_revision,
    }
    wheelhouse_contract = verifier.canonical_json(wheelhouse_contract_record)
    wheelhouse_wheel = b"signed wheelhouse wheel\n"
    wheelhouse_store = verifier.canonical_json(
        {
            "contract": wheelhouse_contract_record,
            "kind": verifier.WHEELHOUSE_STORE_KIND,
            "platforms": {
                "linux/amd64": {
                    "directory": "linux-amd64",
                    "files": [
                        {
                            "path": "native.whl",
                            "sha256": sha256(wheelhouse_wheel),
                            "size": len(wheelhouse_wheel),
                        }
                    ],
                },
                "linux/arm64": {
                    "directory": "linux-arm64",
                    "files": [
                        {
                            "path": "native.whl",
                            "sha256": "9" * 64,
                            "size": 42,
                        }
                    ],
                },
            },
            "schema_version": verifier.WHEELHOUSE_STORE_SCHEMA_VERSION,
        }
    )
    files["policy/native-wheelhouse-consumer.json"] = wheelhouse_contract
    files["artifacts/native-wheelhouse/source.json"] = wheelhouse_store
    wheelhouse_path = "artifacts/native-wheelhouse/linux-amd64/native.whl"
    files[wheelhouse_path] = wheelhouse_wheel

    native_wheel_path = "artifacts/native-wheels/demo/1.0/demo.whl"
    files[native_wheel_path] = b"native wheel\n"

    docker_commit = "d" * 40
    alpine_commit = "e" * 40
    docker_recipe_url = (
        "https://raw.githubusercontent.com/docker-library/python/"
        f"{docker_commit}/3.14/alpine3.24/Dockerfile"
    )
    docker_license_url = (
        f"https://raw.githubusercontent.com/docker-library/python/{docker_commit}/LICENSE"
    )
    cpython_url = "https://www.python.org/ftp/python/3.14.6/Python-3.14.6.tar.xz"
    python_source_url = "https://files.pythonhosted.org/packages/demo-1.0.tar.gz"
    alpine_recipe_url = (
        "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
        f"{alpine_commit}/aports-{alpine_commit}.tar.gz?path=main/demo"
    )
    mit_url = "https://example.com/licenses/MIT.txt"
    python_license_url = "https://example.com/licenses/Python-2.0.1.txt"

    application_license = b"Apache License fixture\n"
    application_package = b'"""Synthetic Extra CODEOWNERS fixture."""\n'
    application_source_tar = application_source_archive(
        license_content=application_license,
    )

    long_native_name = "n" * 90 + ".tar.gz"
    source_contents = {
        "sources/application/extra-codeowners.tar": application_source_tar,
        "sources/base/docker-python-recipe/Dockerfile": b"FROM python fixture\n",
        "sources/base/cpython/Python-3.14.6.tar.xz": b"base source\n",
        "sources/python/demo/1.0/demo-1.0.tar.gz": b"python source\n",
        "sources/python/demo/1.0/café.txt": b"unicode path source\n",
        f"sources/alpine/demo/{alpine_commit}/recipe.tar.gz": b"alpine recipe\n",
        f"sources/native-components/{'a' * 20}/{long_native_name}": b"native source\n",
        "sources/cargo-locks/demo.lock": b"cargo lock\n",
    }
    files.update(source_contents)
    cpython_license = b"CPython license\n"
    license_contents = {
        "licenses/from-source/extra-codeowners/LICENSE": application_license,
        "licenses/from-source/docker-python-recipe/LICENSE": b"Docker Python license\n",
        "licenses/from-source/demo/LICENSE": b"source license\n",
        (
            f"licenses/from-source/runtime-cpython-3.14.6/{sha256(cpython_license)[:12]}-LICENSE"
        ): cpython_license,
        "licenses/standard/Apache-2.0.txt": b"Apache license text\n",
        "licenses/standard/MIT.txt": b"MIT license\n",
        "licenses/standard/Python-2.0.1.txt": b"Python license text\n",
    }
    files.update(license_contents)
    files["THIRD_PARTY_NOTICES.md"] = b"# Third-party notices\n\nReviewed fixture notices.\n"

    patchlevel_sha256 = "c" * 64
    python_component = {
        "ecosystem": "python",
        "effective": True,
        "metadata_sha256": "f" * 64,
        "name": "demo",
        "observed_license": "MIT",
        "version": "1.0",
    }
    application_component = {
        "ecosystem": "python",
        "effective": True,
        "metadata_sha256": "6" * 64,
        "name": "extra-codeowners",
        "observed_license": "Apache-2.0",
        "version": VERSION,
    }
    alpine_components = {
        "linux/amd64": {
            "aports_commit": alpine_commit,
            "architecture": "x86_64",
            "ecosystem": "alpine",
            "effective": True,
            "name": "demo",
            "observed_license": "MIT",
            "origin": "demo",
            "version": "1.0-r0",
        },
        "linux/arm64": {
            "aports_commit": alpine_commit,
            "architecture": "aarch64",
            "ecosystem": "alpine",
            "effective": True,
            "name": "demo",
            "observed_license": "MIT",
            "origin": "demo",
            "version": "1.0-r0",
        },
    }
    policy_components = {
        platform: [
            alpine_components[platform],
            python_component,
            application_component,
            runtime_component(platform, patchlevel_sha256),
        ]
        for platform in ("linux/amd64", "linux/arm64")
    }
    empty_payloads: dict[str, dict[str, list[dict[str, Any]]]] = {
        platform: {
            "embedded_sboms": [],
            "native_payloads": [],
            "wheel_identity_files": [],
        }
        for platform in ("linux/amd64", "linux/arm64")
    }
    empty_baselines: dict[str, dict[str, list[dict[str, Any]]]] = {
        platform: {
            "apk_database_occurrences": [],
            "post_base_apk_world_occurrences": [],
            "post_base_directory_effects": [],
            "post_base_removals": [],
            "post_base_system_links": [],
            "post_base_system_regular_occurrences": [],
        }
        for platform in ("linux/amd64", "linux/arm64")
    }
    native_wheel_url = "https://files.pythonhosted.org/packages/demo.whl"

    def native_owner(platform: str) -> dict[str, Any]:
        architecture = {
            "linux/amd64": "x86_64",
            "linux/arm64": "aarch64",
        }[platform]
        payload = {
            "path": (
                "opt/venv/lib/python3.14/site-packages/"
                f"demo.cpython-314-{architecture}-linux-musl.so"
            ),
            "role": "demo.cpython-314.so",
            "sha256": "7" * 64,
            "size": 1,
        }
        return {
            "canonical_relationships": [],
            "cargo_lock": None,
            "component_reviews": [],
            "known_omissions": [],
            "native_payloads": [payload],
            "owner": "python:demo@1.0",
            "owner_source": {
                "sha256": sha256(source_contents["sources/python/demo/1.0/demo-1.0.tar.gz"]),
                "size": len(source_contents["sources/python/demo/1.0/demo-1.0.tar.gz"]),
                "url": python_source_url,
            },
            "payload_dispositions": [
                {
                    "kind": "owner",
                    "role": payload["role"],
                }
            ],
            "review": {
                "reason": "",
                "state": "closed",
                "unresolved_items": [],
            },
            "sboms": [],
            "wheel": {
                "sha256": sha256(files[native_wheel_path]),
                "size": len(files[native_wheel_path]),
                "url": native_wheel_url,
            },
            "wheelhouse_build": None,
        }

    native_owners = {
        platform: [native_owner(platform)] for platform in ("linux/amd64", "linux/arm64")
    }
    coverage = {
        "schema_version": verifier.SCHEMA_VERSION,
        "platform": PLATFORM,
        "complete": True,
        "resolved_owners": native_owners[PLATFORM],
        "unresolved_owners": [],
        "observed_sbom_anomalies": [],
        "remaining_owner_count": 0,
        "remaining_owner_names": [],
    }
    policy = {
        "alpine_distfiles_release": "v3.24",
        "alpine_recipe_archives": {
            f"demo@{alpine_commit}": sha256(
                source_contents[f"sources/alpine/demo/{alpine_commit}/recipe.tar.gz"]
            )
        },
        "alpine_recipe_exceptions": {},
        "base_image": "python:3.14.6-alpine3.24",
        "base_image_index_digest": INDEX,
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [f"sha256:{'a' * 64}"]},
            "linux/arm64": {"layer_diff_ids": [f"sha256:{'b' * 64}"]},
        },
        "cpython_source": {
            "license_member": "Python-3.14.6/LICENSE",
            "license_sha256": sha256(cpython_license),
            "patchlevel_member": "Python-3.14.6/Include/patchlevel.h",
            "patchlevel_sha256": patchlevel_sha256,
            "sha256": sha256(source_contents["sources/base/cpython/Python-3.14.6.tar.xz"]),
            "size": len(source_contents["sources/base/cpython/Python-3.14.6.tar.xz"]),
            "url": cpython_url,
        },
        "custom_license_evidence": {},
        "distribution_approval": {
            "approved": True,
            "approved_by": "dannysauer",
            "approved_on": "2026-07-27",
            "rationale": "Approved synthetic recipient-verifier fixture.",
        },
        "docker_python_recipe": {
            "license_sha256": sha256(
                license_contents["licenses/from-source/docker-python-recipe/LICENSE"]
            ),
            "license_url": docker_license_url,
            "sha256": sha256(source_contents["sources/base/docker-python-recipe/Dockerfile"]),
            "url": docker_recipe_url,
        },
        "filesystem_baselines": empty_baselines,
        "license_resolutions": {
            "alpine:demo@1.0-r0": {
                "expression": "MIT",
                "rationale": "Reviewed synthetic Alpine component.",
            },
            "python:demo@1.0": {
                "expression": "MIT",
                "rationale": "Reviewed synthetic Python component.",
            },
            "python:extra-codeowners@0.1.0": {
                "expression": "Apache-2.0",
                "rationale": "Reviewed synthetic application component.",
            },
            "runtime:cpython@3.14.6": {
                "expression": "Python-2.0.1",
                "rationale": "Reviewed synthetic CPython runtime.",
            },
        },
        "license_texts": [
            {
                "id": "Apache-2.0",
                "sha256": sha256(license_contents["licenses/standard/Apache-2.0.txt"]),
                "url": "https://example.com/licenses/Apache-2.0.txt",
            },
            {
                "id": "MIT",
                "sha256": sha256(license_contents["licenses/standard/MIT.txt"]),
                "url": mit_url,
            },
            {
                "id": "Python-2.0.1",
                "sha256": sha256(license_contents["licenses/standard/Python-2.0.1.txt"]),
                "url": python_license_url,
            },
        ],
        "native_component_coverage": {
            "linux/amd64": native_owners["linux/amd64"],
            "linux/arm64": native_owners["linux/arm64"],
        },
        "native_component_sources": {},
        "native_wheelhouse_contract_sha256": sha256(wheelhouse_contract),
        "platforms": policy_components,
        "python_sources": [
            {
                "name": "demo",
                "sha256": sha256(source_contents["sources/python/demo/1.0/demo-1.0.tar.gz"]),
                "size": len(source_contents["sources/python/demo/1.0/demo-1.0.tar.gz"]),
                "url": python_source_url,
                "version": "1.0",
            }
        ],
        "schema_version": verifier.SCHEMA_VERSION,
        "unexpanded_python_payloads": empty_payloads,
    }
    image_config = f"sha256:{'4' * 64}"
    layer_digest = f"sha256:{'a' * 64}"

    def layer_occurrence(
        path: str,
        digest: str,
        size: int,
        mode: int,
    ) -> dict[str, Any]:
        return {
            "effective": True,
            "gid": 0,
            "layer": 0,
            "layer_digest": layer_digest,
            "mode": mode,
            "path": path,
            "sha256": digest,
            "size": size,
            "uid": 0,
        }

    def payload_occurrence(record: dict[str, Any]) -> dict[str, Any]:
        return {key: record[key] for key in verifier.REGULAR_OCCURRENCE_FIELDS}

    site_root = "opt/venv/lib/python3.14/site-packages"
    dist_info = f"{site_root}/demo-1.0.dist-info"
    native_path = native_owners[PLATFORM][0]["native_payloads"][0]["path"]
    application_launcher = verifier._expected_native_launcher(
        "extra_codeowners.cli",
        "main",
        interpreter="python",
    )
    regular_files = sorted(
        [
            layer_occurrence("lib/apk/db/installed", "1" * 64, 64, 0o644),
            layer_occurrence(f"{dist_info}/METADATA", "f" * 64, 100, 0o644),
            layer_occurrence(f"{dist_info}/RECORD", "9" * 64, 200, 0o644),
            layer_occurrence(f"{dist_info}/WHEEL", "8" * 64, 80, 0o644),
            layer_occurrence(native_path, "7" * 64, 1, 0o755),
            layer_occurrence(
                (f"{site_root}/extra_codeowners-0.1.0.dist-info/METADATA"),
                "6" * 64,
                120,
                0o644,
            ),
            layer_occurrence(
                f"{site_root}/extra_codeowners-0.1.0.dist-info/RECORD",
                "5" * 64,
                240,
                0o644,
            ),
            layer_occurrence(
                f"{site_root}/extra_codeowners-0.1.0.dist-info/WHEEL",
                "4" * 64,
                80,
                0o644,
            ),
            layer_occurrence(
                f"{site_root}/extra_codeowners/__init__.py",
                sha256(application_package),
                len(application_package),
                0o644,
            ),
            layer_occurrence(
                "opt/venv/bin/extra-codeowners",
                sha256(application_launcher),
                len(application_launcher),
                0o755,
            ),
            layer_occurrence("usr/local/bin/python3.14", "a" * 64, 64, 0o755),
            layer_occurrence(
                "usr/local/include/python3.14/patchlevel.h",
                patchlevel_sha256,
                512,
                0o644,
            ),
            layer_occurrence(
                "usr/local/lib/libpython3.14.so.1.0",
                "b" * 64,
                64,
                0o755,
            ),
        ],
        key=lambda record: str(record["path"]),
    )
    regular_by_path = {str(record["path"]): record for record in regular_files}
    metadata = payload_occurrence(regular_by_path[f"{dist_info}/METADATA"])
    wheel_identity = payload_occurrence(regular_by_path[f"{dist_info}/WHEEL"])
    record_identity = payload_occurrence(regular_by_path[f"{dist_info}/RECORD"])
    native_occurrence = payload_occurrence(regular_by_path[native_path])
    apk_occurrence = payload_occurrence(regular_by_path["lib/apk/db/installed"])
    installation_entries = [
        {
            "path": path,
            "recorded_sha256": None if path.endswith("/RECORD") else occurrence["sha256"],
            "recorded_size": None if path.endswith("/RECORD") else occurrence["size"],
            "occurrence": occurrence,
        }
        for path, occurrence in sorted(
            {
                f"{dist_info}/METADATA": metadata,
                f"{dist_info}/RECORD": record_identity,
                f"{dist_info}/WHEEL": wheel_identity,
                native_path: native_occurrence,
            }.items()
        )
    ]
    installation = {
        "build": "",
        "entries": installation_entries,
        "metadata": metadata,
        "owner": "python:demo@1.0",
        "record": record_identity,
        "root_is_purelib": False,
        "tags": ["cp314-cp314-linux_x86_64"],
        "wheel": wheel_identity,
    }
    application_dist_info = f"{site_root}/extra_codeowners-0.1.0.dist-info"
    application_metadata = payload_occurrence(regular_by_path[f"{application_dist_info}/METADATA"])
    application_record = payload_occurrence(regular_by_path[f"{application_dist_info}/RECORD"])
    application_wheel = payload_occurrence(regular_by_path[f"{application_dist_info}/WHEEL"])
    application_package_occurrence = payload_occurrence(
        regular_by_path[f"{site_root}/extra_codeowners/__init__.py"]
    )
    application_launcher_occurrence = payload_occurrence(
        regular_by_path["opt/venv/bin/extra-codeowners"]
    )
    application_entries = [
        {
            "path": path,
            "recorded_sha256": None if path.endswith("/RECORD") else occurrence["sha256"],
            "recorded_size": None if path.endswith("/RECORD") else occurrence["size"],
            "occurrence": occurrence,
        }
        for path, occurrence in sorted(
            {
                f"{application_dist_info}/METADATA": application_metadata,
                f"{application_dist_info}/RECORD": application_record,
                f"{application_dist_info}/WHEEL": application_wheel,
                f"{site_root}/extra_codeowners/__init__.py": application_package_occurrence,
                "opt/venv/bin/extra-codeowners": application_launcher_occurrence,
            }.items()
        )
    ]
    application_installation = {
        "build": "",
        "entries": application_entries,
        "metadata": application_metadata,
        "owner": "python:extra-codeowners@0.1.0",
        "record": application_record,
        "root_is_purelib": True,
        "tags": ["py3-none-any"],
        "wheel": application_wheel,
    }
    structured_native = {
        **native_occurrence,
        "owner": "python:demo@1.0",
        "elf": {
            "bits": 64,
            "endianness": "little",
            "machine": "x86_64",
            "machine_id": 62,
        },
    }
    wheel_identity_files = sorted(
        [
            record_identity,
            wheel_identity,
            application_record,
            application_wheel,
        ],
        key=lambda record: (int(record["layer"]), str(record["path"])),
    )
    selected_unexpanded = empty_payloads[PLATFORM]
    selected_unexpanded["native_payloads"] = [native_occurrence]
    selected_unexpanded["wheel_identity_files"] = wheel_identity_files
    empty_baselines[PLATFORM]["apk_database_occurrences"] = [apk_occurrence]
    components = {
        "apk_database_occurrences": [apk_occurrence],
        "apk_database_sha256": "1" * 64,
        "apk_shared_libraries": [],
        "application_selection_record_sha256": selection_sha256,
        "application_wheel_sha256": wheel_sha256,
        "components": policy_components[PLATFORM],
        "embedded_sboms": [],
        "image_config_digest": image_config,
        "image_revision": REVISION,
        "image_version": VERSION,
        "native_payloads": [structured_native],
        "native_wheelhouse_index_digest": wheelhouse_index,
        "native_wheelhouse_revision": wheelhouse_revision,
        "native_wheelhouse_schema": "2",
        "platform": PLATFORM,
        "python_record_ownership": sorted(
            [
                *({"owner": "demo", **entry["occurrence"]} for entry in installation_entries),
                *(
                    {
                        "owner": "extra-codeowners",
                        **cast(dict[str, Any], entry["occurrence"]),
                    }
                    for entry in application_entries
                ),
            ],
            key=lambda record: str(record["path"]),
        ),
        "schema_version": verifier.SCHEMA_VERSION,
        "subject_digest": SUBJECT,
        "wheel_identity_files": wheel_identity_files,
        "wheel_installations": [installation, application_installation],
    }
    all_layers = {
        "schema_version": verifier.SCHEMA_VERSION,
        "platform": PLATFORM,
        "subject_digest": SUBJECT,
        "image_config_digest": image_config,
        "layers": [
            {
                "digest": layer_digest,
                "index": 0,
                "regular_file_count": len(regular_files),
                "directory_count": 0,
                "non_regular_file_count": 1,
                "whiteout_count": 0,
            }
        ],
        "regular_files": regular_files,
        "directories": [],
        "non_regular_files": [
            {
                "gid": 0,
                "kind": "symlink",
                "layer": 0,
                "layer_digest": layer_digest,
                "mode": 0o777,
                "path": "usr/local/bin/python3",
                "target": "python3.14",
                "uid": 0,
            }
        ],
        "whiteouts": [],
    }
    files["policy/container-policy.json"] = verifier.canonical_json(policy)
    files["inventory/components.json"] = verifier.canonical_json(components)
    files["inventory/all-layer-files.json"] = verifier.canonical_json(all_layers)
    files["inventory/native-component-coverage.json"] = verifier.canonical_json(coverage)
    files["THIRD_PARTY_NOTICES.md"] = verifier._render_third_party_notices(
        components,
        policy,
        coverage,
        verifier.ExpectedIdentity(
            version=VERSION,
            platform=PLATFORM,
            subject_digest=SUBJECT,
            source_revision=REVISION,
            source_date_epoch=SOURCE_DATE_EPOCH,
        ),
    )

    source_metadata = {
        f"sources/alpine/demo/{alpine_commit}/recipe.tar.gz": (
            "alpine-demo-recipe",
            alpine_recipe_url,
        ),
        "sources/application/extra-codeowners.tar": (
            "extra-codeowners",
            f"https://github.com/stampbot/extra-codeowners/tree/{REVISION}",
        ),
        "sources/base/cpython/Python-3.14.6.tar.xz": (
            "runtime:cpython@3.14.6",
            cpython_url,
        ),
        "sources/base/docker-python-recipe/Dockerfile": (
            "docker-python-recipe",
            docker_recipe_url,
        ),
        "sources/cargo-locks/demo.lock": (
            "fixture-cargo-lock",
            "https://example.com/source/cargo-lock",
        ),
        f"sources/native-components/{'a' * 20}/{long_native_name}": (
            "fixture-native-source",
            "https://example.com/source/native",
        ),
        "sources/python/demo/1.0/café.txt": (
            "fixture-unicode-source",
            "https://example.com/source/unicode",
        ),
        "sources/python/demo/1.0/demo-1.0.tar.gz": (
            "python-demo-1.0",
            python_source_url,
        ),
    }
    source_records = [
        {
            "component": source_metadata[path][0],
            "url": source_metadata[path][1],
            "urls": [source_metadata[path][1]],
            **binding(path, content),
        }
        for path, content in sorted(source_contents.items())
    ]
    for path, component, url in (
        (
            "licenses/standard/Apache-2.0.txt",
            "license:Apache-2.0",
            "https://example.com/licenses/Apache-2.0.txt",
        ),
        (
            "licenses/from-source/docker-python-recipe/LICENSE",
            "docker-python-recipe-license",
            docker_license_url,
        ),
        ("licenses/standard/MIT.txt", "license:MIT", mit_url),
        (
            "licenses/standard/Python-2.0.1.txt",
            "license:Python-2.0.1",
            python_license_url,
        ),
    ):
        source_records.append(
            {
                "component": component,
                "url": url,
                "urls": [url],
                **binding(path, license_contents[path]),
            }
        )
    source_records.sort(key=lambda record: str(record["path"]))
    license_components = {
        "licenses/from-source/extra-codeowners/LICENSE": "extra-codeowners",
        "licenses/from-source/docker-python-recipe/LICENSE": "docker-python-recipe",
        "licenses/from-source/demo/LICENSE": "python-demo-1.0",
        (
            f"licenses/from-source/runtime-cpython-3.14.6/{sha256(cpython_license)[:12]}-LICENSE"
        ): "runtime:cpython@3.14.6",
        "licenses/standard/Apache-2.0.txt": "license:Apache-2.0",
        "licenses/standard/MIT.txt": "license:MIT",
        "licenses/standard/Python-2.0.1.txt": "license:Python-2.0.1",
    }
    license_records = [
        {"component": license_components[path], **binding(path, content)}
        for path, content in license_contents.items()
    ]
    license_records.sort(key=lambda record: (str(record["component"]), str(record["path"])))
    application_bindings = [
        binding(f"artifacts/application/{filename}", content)
        for filename, content in sorted(application_files.items())
    ]
    manifest = {
        "schema_version": verifier.SCHEMA_VERSION,
        "name": "extra-codeowners-container-distribution-evidence",
        "version": VERSION,
        "platform": PLATFORM,
        "subject_digest": SUBJECT,
        "base_image_index_digest": INDEX,
        "policy_sha256": sha256(files["policy/container-policy.json"]),
        "application_artifacts": {
            "source_revision": REVISION,
            "wheel_sha256": wheel_sha256,
            "selection_record_sha256": selection_sha256,
            "launcher_interpreter": "python",
            "files": application_bindings,
        },
        "native_wheelhouse_artifacts": {
            "contract": binding(
                "policy/native-wheelhouse-consumer.json",
                wheelhouse_contract,
            ),
            "consumer_store": binding(
                "artifacts/native-wheelhouse/source.json",
                wheelhouse_store,
            ),
            "platform": PLATFORM,
            "files": [
                {
                    "path": "native.whl",
                    "retained_path": wheelhouse_path,
                    "sha256": sha256(wheelhouse_wheel),
                    "size": len(wheelhouse_wheel),
                }
            ],
            "index_digest": wheelhouse_index,
            "source_revision": wheelhouse_revision,
            "store_schema_version": 1,
        },
        "native_wheel_artifacts": [
            {
                "build": None,
                "embedded_sboms": [],
                "filename": "demo.whl",
                "generated_files": [],
                "owner": "python:demo@1.0",
                "path": native_wheel_path,
                "platform": PLATFORM,
                "sha256": sha256(files[native_wheel_path]),
                "size": len(files[native_wheel_path]),
                "tags": ["cp314-cp314-linux_x86_64"],
                "url": native_wheel_url,
                "urls": [native_wheel_url],
            }
        ],
        "native_component_coverage": coverage,
        "source_completeness": {
            "complete": True,
            "remaining_owner_count": 0,
            "remaining_owner_names": [],
        },
        "source_records": source_records,
        "license_records": license_records,
        "legal_status": "Synthetic evidence fixture; not legal advice.",
    }
    return files, manifest


def finalize_payloads(files: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, bytes]:
    manifest["policy_sha256"] = sha256(files["policy/container-policy.json"])
    files["MANIFEST.json"] = verifier.canonical_json(manifest)
    files.pop("SHA256SUMS", None)
    files["SHA256SUMS"] = "".join(
        f"{sha256(content)}  {path}\n" for path, content in sorted(files.items())
    ).encode()
    return files


def archive_bytes(
    entries: Sequence[tuple[str, bytes]],
    *,
    source_date_epoch: int = SOURCE_DATE_EPOCH,
) -> bytes:
    result = io.BytesIO()
    with (
        gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=result,
            mtime=0,
            compresslevel=9,
        ) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path, content in entries:
            member = tarfile.TarInfo(path)
            member.size = len(content)
            member.mode = 0o644
            member.mtime = source_date_epoch
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            archive.addfile(member, io.BytesIO(content))
    return result.getvalue()


def write_external_bindings(fixture: Fixture) -> None:
    archive_hash = sha256(fixture.archive.read_bytes())
    fixture.checksum.write_text(f"{archive_hash}  {fixture.archive.name}\n")
    fixture.predicate.write_bytes(
        verifier.canonical_json(
            {
                "schema_version": verifier.SCHEMA_VERSION,
                "media_type": verifier.EVIDENCE_MEDIA_TYPE,
                "platform": PLATFORM,
                "subject_digest": SUBJECT,
                "artifact": {
                    "filename": fixture.archive.name,
                    "sha256": archive_hash,
                },
                "release_url": (
                    f"https://github.com/stampbot/extra-codeowners/releases/tag/v{VERSION}"
                ),
            }
        )
    )


def build_fixture(
    tmp_path: Path,
    *,
    mutate: Callable[[dict[str, bytes], dict[str, Any]], None] | None = None,
    entries: Callable[[dict[str, bytes]], Sequence[tuple[str, bytes]]] | None = None,
) -> Fixture:
    files, manifest = initial_payloads()
    if mutate is not None:
        mutate(files, manifest)
    files = finalize_payloads(files, manifest)
    ordered = (
        list(entries(files))
        if entries is not None
        else sorted(files.items(), key=lambda item: item[0].encode("utf-8"))
    )
    expected = verifier.ExpectedIdentity(
        version=VERSION,
        platform=PLATFORM,
        subject_digest=SUBJECT,
        source_revision=REVISION,
        source_date_epoch=SOURCE_DATE_EPOCH,
    )
    archive = tmp_path / verifier.expected_archive_filename(expected)
    fixture = Fixture(
        archive=archive,
        checksum=tmp_path / f"{archive.name}.sha256",
        predicate=tmp_path / "evidence-predicate-amd64.json",
        output=tmp_path / "verified",
        expected=expected,
        files=files,
    )
    archive.write_bytes(archive_bytes(ordered))
    write_external_bindings(fixture)
    return fixture


def verify_fixture(fixture: Fixture) -> dict[str, object]:
    return cast(
        dict[str, object],
        verifier.verify(
            archive_path=fixture.archive,
            checksum_path=fixture.checksum,
            predicate_path=fixture.predicate,
            output=fixture.output,
            expected=fixture.expected,
        ),
    )


def rewrite_tar(fixture: Fixture, mutation: Callable[[bytearray], None]) -> None:
    expanded = bytearray(gzip.decompress(fixture.archive.read_bytes()))
    mutation(expanded)
    result = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=result,
        mtime=0,
        compresslevel=9,
    ) as compressed:
        compressed.write(expanded)
    fixture.archive.write_bytes(result.getvalue())
    write_external_bindings(fixture)


def test_verifies_and_materializes_complete_schema_9_archive(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)

    result = verify_fixture(fixture)

    assert result["kind"] == verifier.VERIFICATION_KIND
    assert result["schema_version"] == verifier.VERIFIER_SCHEMA_VERSION
    assert result["platform"] == PLATFORM
    assert result["subject_digest"] == SUBJECT
    assert result["archive"] == {
        "filename": fixture.archive.name,
        "sha256": sha256(fixture.archive.read_bytes()),
        "size": fixture.archive.stat().st_size,
    }
    assert result["member_count"] == len(fixture.files)
    assert {
        path.relative_to(fixture.output).as_posix(): path.read_bytes()
        for path in fixture.output.rglob("*")
        if path.is_file()
    } == fixture.files
    assert all(
        path.stat().st_mode & 0o777 == 0o600 for path in fixture.output.rglob("*") if path.is_file()
    )


def test_verifies_filesystem_baseline_derived_from_layer_replay(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        inventory = json.loads(files["inventory/all-layer-files.json"])
        post_base_digest = f"sha256:{'c' * 64}"

        obsolete = {
            "effective": False,
            "gid": 0,
            "layer": 0,
            "layer_digest": f"sha256:{'a' * 64}",
            "mode": 0o644,
            "path": "usr/lib/obsolete",
            "sha256": "d" * 64,
            "size": 1,
            "uid": 0,
        }
        apk_world = {
            "effective": True,
            "gid": 0,
            "layer": 1,
            "layer_digest": post_base_digest,
            "mode": 0o644,
            "path": "etc/apk/world",
            "sha256": "e" * 64,
            "size": 1,
            "uid": 0,
        }
        system_regular = {
            "effective": True,
            "gid": 0,
            "layer": 1,
            "layer_digest": post_base_digest,
            "mode": 0o644,
            "path": "usr/lib/libgcc_s.so.1",
            "sha256": "f" * 64,
            "size": 1,
            "uid": 0,
        }
        directories = [
            {
                "effective": True,
                "gid": 0,
                "layer": 1,
                "layer_digest": post_base_digest,
                "mode": 0o755,
                "path": path,
                "uid": 0,
            }
            for path in ("etc", "etc/apk", "usr")
        ]
        system_link = {
            "gid": 0,
            "kind": "symlink",
            "layer": 1,
            "layer_digest": post_base_digest,
            "mode": 0o777,
            "path": "usr/lib/libpq.so.5",
            "target": "libpq.so.5.18",
            "uid": 0,
        }
        removal = {
            "gid": 0,
            "kind": "whiteout",
            "layer": 1,
            "layer_digest": post_base_digest,
            "mode": 0,
            "path": "usr/lib/.wh.obsolete",
            "target": "usr/lib/obsolete",
            "uid": 0,
        }

        inventory["regular_files"].extend((obsolete, apk_world, system_regular))
        inventory["regular_files"].sort(
            key=lambda record: (int(record["layer"]), str(record["path"]))
        )
        inventory["directories"] = directories
        inventory["non_regular_files"].append(system_link)
        inventory["non_regular_files"].sort(
            key=lambda record: (int(record["layer"]), str(record["path"]))
        )
        inventory["whiteouts"] = [removal]
        inventory["layers"][0]["regular_file_count"] += 1
        inventory["layers"].append(
            {
                "digest": post_base_digest,
                "directory_count": len(directories),
                "index": 1,
                "non_regular_file_count": 1,
                "regular_file_count": 2,
                "whiteout_count": 1,
            }
        )

        def occurrence(record: dict[str, Any]) -> dict[str, Any]:
            return {field: record[field] for field in verifier.REGULAR_OCCURRENCE_FIELDS}

        policy = json.loads(files["policy/container-policy.json"])
        baseline = policy["filesystem_baselines"][PLATFORM]
        baseline["post_base_apk_world_occurrences"] = [occurrence(apk_world)]
        baseline["post_base_directory_effects"] = [
            {field: record[field] for field in ("gid", "layer", "mode", "path", "uid")}
            for record in directories
        ]
        baseline["post_base_removals"] = [
            {field: removal[field] for field in ("kind", "path", "target")}
        ]
        baseline["post_base_system_links"] = [
            {
                field: system_link[field]
                for field in ("gid", "kind", "layer", "mode", "path", "target", "uid")
            }
        ]
        baseline["post_base_system_regular_occurrences"] = [occurrence(system_regular)]
        files["inventory/all-layer-files.json"] = verifier.canonical_json(inventory)
        files["policy/container-policy.json"] = verifier.canonical_json(policy)

    fixture = build_fixture(tmp_path, mutate=mutate)

    result = verify_fixture(fixture)

    assert result["kind"] == verifier.VERIFICATION_KIND


def test_checked_in_policy_passes_recipient_schema_before_retained_binding() -> None:
    policy_source = json.loads((ROOT / ".compliance" / "container-policy.json").read_bytes())
    policy = dict(
        verifier.strict_json_bytes(
            verifier.canonical_json(policy_source),
            "checked-in container policy",
        )
    )
    policy["distribution_approval"] = {
        "approved": True,
        "approved_by": "recipient-schema-test",
        "approved_on": "2026-07-27",
        "rationale": "Exercise the checked-in schema through the recipient validator.",
    }
    selected_components = policy["platforms"][PLATFORM]
    components = {
        "apk_database_occurrences": [],
        "apk_database_sha256": "1" * 64,
        "apk_shared_libraries": [],
        "application_selection_record_sha256": "2" * 64,
        "application_wheel_sha256": "3" * 64,
        "components": selected_components,
        "embedded_sboms": [],
        "image_config_digest": f"sha256:{'4' * 64}",
        "image_revision": REVISION,
        "image_version": VERSION,
        "native_payloads": [],
        "native_wheelhouse_index_digest": f"sha256:{'5' * 64}",
        "native_wheelhouse_revision": "6" * 40,
        "native_wheelhouse_schema": "2",
        "platform": PLATFORM,
        "python_record_ownership": [],
        "schema_version": verifier.SCHEMA_VERSION,
        "subject_digest": SUBJECT,
        "wheel_identity_files": [],
        "wheel_installations": [],
    }
    anomalies = [
        {
            "owner": owner["owner"],
            "sbom_path": sbom["path"],
            "observation_sha256": sbom["observation"]["observation_sha256"],
            **sbom["metadata_root"]["anomaly_review"],
        }
        for owner in policy["native_component_coverage"][PLATFORM]
        for sbom in owner["sboms"]
        if sbom["metadata_root"]["anomaly_review"] is not None
    ]
    coverage = {
        "complete": True,
        "observed_sbom_anomalies": anomalies,
        "platform": PLATFORM,
        "remaining_owner_count": 0,
        "remaining_owner_names": [],
        "resolved_owners": policy["native_component_coverage"][PLATFORM],
        "schema_version": verifier.SCHEMA_VERSION,
        "unresolved_owners": [],
    }

    with pytest.raises(
        verifier.VerificationError,
        match="Docker Official Python recipe does not bind one retained source record",
    ):
        verifier._verify_policy_and_coverage(
            policy,
            coverage,
            components,
            [],
            [],
            {},
            verifier.ExpectedIdentity(
                version=VERSION,
                platform=PLATFORM,
                subject_digest=SUBJECT,
                source_revision=REVISION,
                source_date_epoch=SOURCE_DATE_EPOCH,
            ),
            policy["base_image_index_digest"],
        )


def test_checked_in_source_tree_uses_the_recipient_tar_contract() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("requires Git metadata from a source checkout")
    collector = load_collector()

    raw = collector.deterministic_source_archive(ROOT, source_revision="HEAD")
    records, project = verifier._application_source_members(raw)

    assert "LICENSE" in records
    assert "extra_codeowners/__init__.py" in records
    assert any(len(path.encode()) > 100 for path in records)
    assert project["name"] == "extra-codeowners"
    assert project["version"] == VERSION


def test_retained_cargo_lock_is_reconciled_with_reviewed_packages() -> None:
    owner = "python:demo@1.0"
    crate_digest = "a" * 64
    native_sources = {
        "crates-io:reviewed@1.2.3": {
            "crate": {"sha256": crate_digest},
            "kind": "crates-io",
            "name": "reviewed",
            "version": "1.2.3",
        },
        "owner-sdist:python:demo@1.0#rust": {
            "cargo_packages": [{"name": "demo-rust", "version": "0.1.0"}],
            "kind": "owner-sdist-subpath",
            "owner": owner,
        },
    }
    lock_context = {
        "non_sbom_packages": [],
        "source_ids": ["crates-io:reviewed@1.2.3"],
    }
    owner_context = {
        "observations": {},
        "owner_root_observations": set(),
        "record": {"component_reviews": []},
    }
    cargo_lock = (
        b"version = 4\n"
        b"\n[[package]]\n"
        b'name = "demo-rust"\n'
        b'version = "0.1.0"\n'
        b'dependencies = ["reviewed 1.2.3"]\n'
        b"\n[[package]]\n"
        b'name = "reviewed"\n'
        b'version = "1.2.3"\n'
        + f'source = "{verifier.CARGO_CRATES_IO_SOURCE}"\n'.encode()
        + f'checksum = "{crate_digest}"\n'.encode()
    )

    verifier._verify_cargo_lock_bytes(
        cargo_lock,
        owner=owner,
        lock_context=lock_context,
        native_sources=native_sources,
        owner_context=owner_context,
    )

    with pytest.raises(
        verifier.VerificationError,
        match="registry packages differ from reviewed context",
    ):
        verifier._verify_cargo_lock_bytes(
            cargo_lock.replace(crate_digest.encode(), b"b" * 64),
            owner=owner,
            lock_context=lock_context,
            native_sources=native_sources,
            owner_context=owner_context,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("observation-field", "must contain exactly"),
        ("observation-digest", "observation digest is invalid"),
        ("review-reference", "references an unknown observation"),
        ("wheelhouse-library", "must contain exactly"),
        ("cargo-package", "must contain exactly"),
        ("payload-disposition", "must contain exactly"),
        ("relationship-target", "target is not directly reviewed"),
    ],
)
def test_rejects_deep_native_policy_drift(mutation: str, message: str) -> None:
    policy = json.loads((ROOT / ".compliance" / "container-policy.json").read_bytes())
    owners = policy["native_component_coverage"][PLATFORM]
    cryptography = next(
        owner for owner in owners if owner["owner"].startswith("python:cryptography@")
    )
    cffi = next(owner for owner in owners if owner["owner"].startswith("python:cffi@"))
    if mutation == "observation-field":
        cryptography["sboms"][0]["observation"]["components"][0]["unexpected"] = True
    elif mutation == "observation-digest":
        cryptography["sboms"][0]["observation"]["observation_sha256"] = "0" * 64
    elif mutation == "review-reference":
        cryptography["component_reviews"][0]["observations"][0]["purl"] = (
            "pkg:cargo/not-the-reviewed-component@0.1.0"
        )
    elif mutation == "wheelhouse-library":
        cffi["wheelhouse_build"]["linked_libraries"][0]["unexpected"] = True
    elif mutation == "cargo-package":
        cryptography["cargo_lock"]["non_sbom_packages"] = [
            {
                "checksum": "0" * 64,
                "name": "not-in-sbom",
                "source": verifier.CARGO_CRATES_IO_SOURCE,
                "unexpected": True,
                "version": "1.0.0",
            }
        ]
    elif mutation == "payload-disposition":
        cryptography["payload_dispositions"][0]["unexpected"] = True
    elif mutation == "relationship-target":
        cryptography["canonical_relationships"][0]["reference_observation"][
            "observation_sha256"
        ] = "0" * 64
    else:  # pragma: no cover - parametrization guard
        raise AssertionError(mutation)

    with pytest.raises(verifier.VerificationError, match=message):
        contexts: dict[str, Any] = {}
        for index, owner_record in enumerate(owners):
            owner, _sources, _licenses, context = verifier._validate_native_owner(
                owner_record,
                f"mutated checked-in owner {index}",
                policy["native_component_sources"],
                platform=PLATFORM,
            )
            contexts[owner] = context
        verifier._validate_native_relationships(contexts, platform=PLATFORM)


def owner_subtree_fixture() -> tuple[bytes, dict[str, Any]]:
    content = b"[workspace]\n"
    records = [
        {
            "mode": 0o644,
            "path": "Cargo.toml",
            "sha256": sha256(content),
            "size": len(content),
            "type": "file",
        }
    ]
    raw = verifier.canonical_json(records)
    source = {
        "cargo_packages": [
            {
                "manifest": {
                    "member": "demo-1.0/src/rust/Cargo.toml",
                    "sha256": sha256(content),
                    "size": len(content),
                },
                "name": "demo-rust",
                "path": ".",
                "version": "1.0.0",
            }
        ],
        "expanded_size": len(content),
        "member_count": 1,
        "path": "src/rust",
        "tree_sha256": sha256(raw),
    }
    return raw, source


def test_accepts_policy_bound_owner_subtree_manifest() -> None:
    raw, source = owner_subtree_fixture()

    verifier._verify_owner_subtree_manifest(
        raw,
        source_id="owner-sdist:python:demo@1.0#src/rust",
        native_source=source,
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("member-field", "must contain exactly"),
        ("tree-digest", "differs from reviewed policy"),
        ("manifest-pin", "Cargo package 0 differs from its subtree"),
    ],
)
def test_rejects_policy_bound_owner_subtree_drift(mutation: str, message: str) -> None:
    raw, source = owner_subtree_fixture()
    if mutation == "member-field":
        records = json.loads(raw)
        records[0]["unexpected"] = True
        raw = verifier.canonical_json(records)
        source["tree_sha256"] = sha256(raw)
    elif mutation == "tree-digest":
        source["tree_sha256"] = "0" * 64
    elif mutation == "manifest-pin":
        source["cargo_packages"][0]["manifest"]["sha256"] = "0" * 64
    else:  # pragma: no cover - parametrization guard
        raise AssertionError(mutation)

    with pytest.raises(verifier.VerificationError, match=message):
        verifier._verify_owner_subtree_manifest(
            raw,
            source_id="owner-sdist:python:demo@1.0#src/rust",
            native_source=source,
        )


def test_accepts_the_actual_collector_tar_envelope(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    staging = tmp_path / "collector-input"
    staging.mkdir()
    for path, content in fixture.files.items():
        destination = staging / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    collector = load_collector()
    collector.create_deterministic_tar(
        staging,
        fixture.archive,
        SOURCE_DATE_EPOCH,
    )
    write_external_bindings(fixture)

    result = verify_fixture(fixture)

    assert result["archive"] == {
        "filename": fixture.archive.name,
        "sha256": sha256(fixture.archive.read_bytes()),
        "size": fixture.archive.stat().st_size,
    }


def test_cli_emits_canonical_verification_summary(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            "--archive",
            str(fixture.archive),
            "--checksum",
            str(fixture.checksum),
            "--predicate",
            str(fixture.predicate),
            "--output",
            str(fixture.output),
            "--version",
            VERSION,
            "--platform",
            PLATFORM,
            "--subject-digest",
            SUBJECT,
            "--source-revision",
            REVISION,
            "--source-date-epoch",
            str(SOURCE_DATE_EPOCH),
        ],
        check=False,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr.decode()
    summary = verifier.strict_json_bytes(completed.stdout, "CLI summary")
    assert summary["kind"] == verifier.VERIFICATION_KIND
    assert summary["member_count"] == len(fixture.files)
    assert completed.stderr == b""


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("checksum", "checksum sidecar"),
        ("predicate-identity", "predicate does not match"),
        ("predicate-noncanonical", "canonical JSON"),
        ("gzip-header", "gzip header"),
        ("gzip-trailing", "after its gzip member"),
    ],
)
def test_rejects_untrusted_outer_envelope(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    fixture = build_fixture(tmp_path)
    if mutation == "checksum":
        fixture.checksum.write_text(f"{'0' * 64}  {fixture.archive.name}\n")
    elif mutation == "predicate-identity":
        predicate = json.loads(fixture.predicate.read_bytes())
        predicate["platform"] = "linux/arm64"
        fixture.predicate.write_bytes(verifier.canonical_json(predicate))
    elif mutation == "predicate-noncanonical":
        predicate = json.loads(fixture.predicate.read_bytes())
        fixture.predicate.write_text(json.dumps(predicate))
    elif mutation == "gzip-header":
        content = bytearray(fixture.archive.read_bytes())
        content[9] = 3
        fixture.archive.write_bytes(content)
        write_external_bindings(fixture)
    elif mutation == "gzip-trailing":
        fixture.archive.write_bytes(fixture.archive.read_bytes() + b"trailing")
        write_external_bindings(fixture)
    else:  # pragma: no cover - parametrization guard
        raise AssertionError(mutation)

    with pytest.raises(verifier.VerificationError, match=message):
        verify_fixture(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("header-number", "octal"),
        ("member-type", "non-regular"),
        ("pax", "PAX path"),
        ("end-padding", "end-of-archive"),
    ],
)
def test_rejects_malformed_raw_tar_records(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    fixture = build_fixture(tmp_path)

    def mutate(expanded: bytearray) -> None:
        if mutation == "header-number":
            expanded[124] = 0x80
        elif mutation == "member-type":
            expanded[156] = ord("2")
        elif mutation == "pax":
            marker = expanded.find(b" path=")
            assert marker > 0
            expanded[marker + 1] = ord("X")
        elif mutation == "end-padding":
            expanded[-1] = 1
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(mutation)

    rewrite_tar(fixture, mutate)

    with pytest.raises(verifier.VerificationError, match=message):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_bad_gzip_crc_even_when_outer_hashes_match(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    content = bytearray(fixture.archive.read_bytes())
    content[-8] ^= 1
    fixture.archive.write_bytes(content)
    write_external_bindings(fixture)

    with pytest.raises(verifier.VerificationError, match="gzip trailer"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_a_single_tar_end_block(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)

    def corrupt_second_end_block(expanded: bytearray) -> None:
        last_payload_byte = len(expanded.rstrip(b"\0"))
        first_end_block = (
            (last_payload_byte + verifier.TAR_BLOCK_BYTES - 1) // verifier.TAR_BLOCK_BYTES
        ) * verifier.TAR_BLOCK_BYTES
        expanded[first_end_block + verifier.TAR_BLOCK_BYTES] = 1

    rewrite_tar(fixture, corrupt_second_end_block)

    with pytest.raises(verifier.VerificationError, match="only one end-of-archive block"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_duplicate_member_even_when_checksums_are_unique(tmp_path: Path) -> None:
    def duplicate(files: dict[str, bytes]) -> Sequence[tuple[str, bytes]]:
        ordered = sorted(files.items())
        return [ordered[0], ordered[0], *ordered[1:]]

    fixture = build_fixture(tmp_path, entries=duplicate)

    with pytest.raises(verifier.VerificationError, match="repeats member path"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_unsorted_member_sequence(tmp_path: Path) -> None:
    def reverse(files: dict[str, bytes]) -> Sequence[tuple[str, bytes]]:
        return sorted(files.items(), reverse=True)

    fixture = build_fixture(tmp_path, entries=reverse)

    with pytest.raises(verifier.VerificationError, match="canonical byte order"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_case_folding_path_collisions(tmp_path: Path) -> None:
    def collide(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        files["licenses/standard/mit.txt"] = b"colliding license path\n"

    fixture = build_fixture(tmp_path, mutate=collide)

    with pytest.raises(verifier.VerificationError, match="case-folding path collision"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("approval", "explicit approval"),
        ("source-completeness", "complete source coverage"),
        ("coverage-count-boolean", "outside its integer bounds"),
        ("coverage-anomaly", "anomaly ledger differs from reviewed policy"),
        ("source-count-boolean", "outside its integer bounds"),
        ("source-sha512", "invalid SHA-512"),
        ("inventory-subject", "wrong platform subject"),
        ("config-digest", "disagree on image config"),
        ("base-image", "disagree on the base image index"),
        ("artifact-record", "must be nonempty"),
        ("native-wheel-policy", "differs from reviewed policy"),
        ("native-wheel-record-field", "must contain exactly"),
        ("application-record-field", "must contain exactly"),
        ("wheelhouse-policy", "does not bind the retained wheelhouse contract"),
        ("wheelhouse-inventory", "disagrees with native wheelhouse identity"),
        ("wheelhouse-store-schema-boolean", "outside its integer bounds"),
        ("unbound-source", "does not bind every retained source"),
        ("unknown-path", "unsupported top-level path"),
        ("missing-prefix", "sources/native-components"),
    ],
)
def test_rejects_cross_record_content_drift(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    def mutate(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        if mutation == "approval":
            policy = json.loads(files["policy/container-policy.json"])
            policy["distribution_approval"]["approved"] = False
            files["policy/container-policy.json"] = verifier.canonical_json(policy)
        elif mutation == "source-completeness":
            manifest["source_completeness"]["complete"] = False
        elif mutation == "coverage-count-boolean":
            coverage = json.loads(files["inventory/native-component-coverage.json"])
            coverage["remaining_owner_count"] = False
            files["inventory/native-component-coverage.json"] = verifier.canonical_json(coverage)
        elif mutation == "coverage-anomaly":
            coverage = json.loads(files["inventory/native-component-coverage.json"])
            coverage["observed_sbom_anomalies"] = [
                {
                    "kind": "metadata-root-echo",
                    "observation_sha256": "0" * 64,
                    "owner": "python:demo@1.0",
                    "reason": "Invented anomaly.",
                    "sbom_path": "demo-1.0.dist-info/sboms/demo.cdx.json",
                }
            ]
            files["inventory/native-component-coverage.json"] = verifier.canonical_json(coverage)
            manifest["native_component_coverage"] = coverage
        elif mutation == "source-count-boolean":
            manifest["source_completeness"]["remaining_owner_count"] = False
        elif mutation == "source-sha512":
            manifest["source_records"][0]["sha512"] = "9" * 128
        elif mutation == "inventory-subject":
            components = json.loads(files["inventory/components.json"])
            components["subject_digest"] = f"sha256:{'9' * 64}"
            files["inventory/components.json"] = verifier.canonical_json(components)
        elif mutation == "config-digest":
            layers = json.loads(files["inventory/all-layer-files.json"])
            layers["image_config_digest"] = f"sha256:{'8' * 64}"
            files["inventory/all-layer-files.json"] = verifier.canonical_json(layers)
        elif mutation == "base-image":
            policy = json.loads(files["policy/container-policy.json"])
            policy["base_image_index_digest"] = f"sha256:{'7' * 64}"
            files["policy/container-policy.json"] = verifier.canonical_json(policy)
        elif mutation == "artifact-record":
            manifest["native_wheel_artifacts"] = []
        elif mutation == "native-wheel-policy":
            replacement = b"coherently replaced native wheel\n"
            files["artifacts/native-wheels/demo/1.0/demo.whl"] = replacement
            manifest["native_wheel_artifacts"][0]["sha256"] = sha256(replacement)
            manifest["native_wheel_artifacts"][0]["size"] = len(replacement)
        elif mutation == "native-wheel-record-field":
            manifest["native_wheel_artifacts"][0]["unexpected"] = True
        elif mutation == "application-record-field":
            manifest["application_artifacts"]["files"][0]["unexpected"] = True
        elif mutation == "wheelhouse-policy":
            policy = json.loads(files["policy/container-policy.json"])
            policy["native_wheelhouse_contract_sha256"] = "9" * 64
            files["policy/container-policy.json"] = verifier.canonical_json(policy)
        elif mutation == "wheelhouse-inventory":
            components = json.loads(files["inventory/components.json"])
            components["native_wheelhouse_index_digest"] = f"sha256:{'9' * 64}"
            files["inventory/components.json"] = verifier.canonical_json(components)
        elif mutation == "wheelhouse-store-schema-boolean":
            store = json.loads(files["artifacts/native-wheelhouse/source.json"])
            store["schema_version"] = True
            files["artifacts/native-wheelhouse/source.json"] = verifier.canonical_json(store)
        elif mutation == "unbound-source":
            files["sources/application/unbound-source.tar"] = b"unbound source\n"
        elif mutation == "unknown-path":
            files["unexpected.txt"] = b"unexpected\n"
        elif mutation == "missing-prefix":
            for path in list(files):
                if path.startswith("sources/native-components/"):
                    del files[path]
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(mutation)

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match=message):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_application_packages_for_another_version(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        replacements = {
            "extra_codeowners-0.1.0-py3-none-any.whl": ("extra_codeowners-9.9.9-py3-none-any.whl"),
            "extra_codeowners-0.1.0.tar.gz": "extra_codeowners-9.9.9.tar.gz",
        }
        for old_name, new_name in replacements.items():
            old_path = f"artifacts/application/{old_name}"
            new_path = f"artifacts/application/{new_name}"
            files[new_path] = files.pop(old_path)
            for record in manifest["application_artifacts"]["files"]:
                if record["path"] == old_path:
                    record["path"] = new_path
        manifest["application_artifacts"]["files"].sort(key=lambda record: record["path"])

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="exact five-file identity"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_application_artifacts_moved_below_nested_aliases(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        old_path = "artifacts/application/python-selection-record.json"
        new_path = "artifacts/application/nested/python-selection-record.json"
        files[new_path] = files.pop(old_path)
        record = next(
            item for item in manifest["application_artifacts"]["files"] if item["path"] == old_path
        )
        record["path"] = new_path
        manifest["application_artifacts"]["files"].sort(key=lambda item: item["path"])

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="exact five-file identity"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_application_launcher_interpreter_not_bound_to_installation(
    tmp_path: Path,
) -> None:
    def mutate(_files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        manifest["application_artifacts"]["launcher_interpreter"] = "python3"

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError,
        match="launcher interpreter differs from the active installation",
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_coherently_replaced_application_source_archive(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        path = "sources/application/extra-codeowners.tar"
        files[path] = b"unrelated application source\n"
        record = next(item for item in manifest["source_records"] if item["path"] == path)
        record.update(binding(path, files[path]))

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="application source"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_application_source_license_drift(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        path = "sources/application/extra-codeowners.tar"
        files[path] = application_source_archive(
            license_content=b"Unrelated application license fixture\n",
        )
        record = next(item for item in manifest["source_records"] if item["path"] == path)
        record.update(binding(path, files[path]))

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError,
        match="source license differs from retained application license",
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_application_pyproject_beyond_toml_nesting_limit(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        path = "sources/application/extra-codeowners.tar"
        nesting = verifier.MAX_TOML_NESTING + 1
        pyproject = (
            b'[project]\nname = "extra-codeowners"\nversion = "0.1.0"\nnested = '
            + b"[" * nesting
            + b"0"
            + b"]" * nesting
            + b"\n"
        )
        files[path] = application_source_archive(
            license_content=files["licenses/from-source/extra-codeowners/LICENSE"],
            pyproject_content=pyproject,
        )
        record = next(item for item in manifest["source_records"] if item["path"] == path)
        record.update(binding(path, files[path]))

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="TOML nesting limit"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_application_source_record_for_another_revision(tmp_path: Path) -> None:
    def mutate(_files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        record = next(
            item
            for item in manifest["source_records"]
            if item["path"] == "sources/application/extra-codeowners.tar"
        )
        wrong_url = f"https://github.com/stampbot/extra-codeowners/tree/{'0' * 40}"
        record["url"] = wrong_url
        record["urls"] = [wrong_url]

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="trusted revision"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_truncated_all_layer_inventory(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        inventory = json.loads(files["inventory/all-layer-files.json"])
        files["inventory/all-layer-files.json"] = verifier.canonical_json(
            {
                field: inventory[field]
                for field in (
                    "schema_version",
                    "platform",
                    "subject_digest",
                    "image_config_digest",
                )
            }
        )

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError, match="all-layer inventory must contain exactly"
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_false_effective_state_for_uncovered_regular_file(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        inventory = json.loads(files["inventory/all-layer-files.json"])
        inventory["regular_files"].append(
            {
                "effective": False,
                "gid": 0,
                "layer": 0,
                "layer_digest": f"sha256:{'a' * 64}",
                "mode": 0o755,
                "path": "usr/lib/libmalware.so",
                "sha256": "0" * 64,
                "size": 1,
                "uid": 0,
            }
        )
        inventory["regular_files"].sort(key=lambda record: str(record["path"]))
        inventory["layers"][0]["regular_file_count"] += 1
        files["inventory/all-layer-files.json"] = verifier.canonical_json(inventory)

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="false effective state"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize(
    ("category", "fabricated"),
    [
        (
            "post_base_apk_world_occurrences",
            {
                "effective": True,
                "gid": 0,
                "layer": 1,
                "mode": 0o644,
                "path": "etc/apk/world",
                "sha256": "0" * 64,
                "size": 1,
                "uid": 0,
            },
        ),
        (
            "post_base_system_regular_occurrences",
            {
                "effective": True,
                "gid": 0,
                "layer": 1,
                "mode": 0o644,
                "path": "var/log/apk.log",
                "sha256": "0" * 64,
                "size": 1,
                "uid": 0,
            },
        ),
        (
            "post_base_system_links",
            {
                "gid": 0,
                "kind": "symlink",
                "layer": 1,
                "mode": 0o777,
                "path": "usr/lib/libpq.so.5",
                "target": "libpq.so.5.18",
                "uid": 0,
            },
        ),
        (
            "post_base_directory_effects",
            {
                "gid": 0,
                "layer": 1,
                "mode": 0o755,
                "path": "opt",
                "uid": 0,
            },
        ),
        (
            "post_base_removals",
            {
                "kind": "whiteout",
                "path": "tmp/.wh.unused",
                "target": "tmp/unused",
            },
        ),
    ],
)
def test_rejects_filesystem_baseline_not_derived_from_layers(
    tmp_path: Path,
    category: str,
    fabricated: dict[str, Any],
) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        policy = json.loads(files["policy/container-policy.json"])
        policy["filesystem_baselines"][PLATFORM][category] = [fabricated]
        files["policy/container-policy.json"] = verifier.canonical_json(policy)

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError,
        match=rf"{category} differs from all-layer inventory",
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize(
    "field",
    (
        "apk_database_occurrences",
        "apk_shared_libraries",
        "embedded_sboms",
        "native_payloads",
        "python_record_ownership",
        "wheel_identity_files",
        "wheel_installations",
    ),
)
def test_rejects_malformed_component_evidence_collections(
    tmp_path: Path,
    field: str,
) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        inventory = json.loads(files["inventory/components.json"])
        inventory[field] = [{}]
        files["inventory/components.json"] = verifier.canonical_json(inventory)

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_wheel_identity_without_historical_installation(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        inventory = json.loads(files["inventory/components.json"])
        inventory["wheel_installations"] = inventory["wheel_installations"][:1]
        files["inventory/components.json"] = verifier.canonical_json(inventory)

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="omits a historical Python RECORD"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_effective_component_without_active_installation(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        inventory = json.loads(files["inventory/components.json"])
        application_prefix = (
            "opt/venv/lib/python3.14/site-packages/extra_codeowners-0.1.0.dist-info/"
        )
        inventory["wheel_identity_files"] = [
            record
            for record in inventory["wheel_identity_files"]
            if not str(record["path"]).startswith(application_prefix)
        ]
        inventory["wheel_installations"] = inventory["wheel_installations"][:1]

        all_layers = json.loads(files["inventory/all-layer-files.json"])
        all_layers["regular_files"] = [
            record
            for record in all_layers["regular_files"]
            if not (
                str(record["path"]).startswith(application_prefix)
                and str(record["path"]).endswith(("/RECORD", "/WHEEL"))
            )
        ]
        all_layers["layers"][0]["regular_file_count"] -= 2

        policy = json.loads(files["policy/container-policy.json"])
        policy["unexpanded_python_payloads"][PLATFORM]["wheel_identity_files"] = inventory[
            "wheel_identity_files"
        ]
        files["inventory/components.json"] = verifier.canonical_json(inventory)
        files["inventory/all-layer-files.json"] = verifier.canonical_json(all_layers)
        files["policy/container-policy.json"] = verifier.canonical_json(policy)

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError,
        match="active Python installations differ from effective components",
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_unbound_generated_launcher_record(tmp_path: Path) -> None:
    def mutate(_files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        manifest["native_wheel_artifacts"][0]["generated_files"] = [{}]

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="generated file 0 must contain exactly"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("build", "1local"),
        ("tags", ["cp314-cp314-manylinux_2_39_x86_64"]),
    ],
)
def test_rejects_native_wheel_metadata_not_bound_to_installation(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    def mutate(_files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        manifest["native_wheel_artifacts"][0][field] = value

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError,
        match="build or tags differ from its installation",
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_generated_launchers_exactly_cover_their_historical_installation() -> None:
    launcher = verifier._expected_native_launcher(
        "demo.module",
        "main",
        interpreter="python",
    )
    occurrence = {
        "effective": True,
        "gid": 0,
        "layer": 1,
        "mode": 0o755,
        "path": "opt/venv/bin/demo",
        "sha256": sha256(launcher),
        "size": len(launcher),
        "uid": 0,
    }
    source_path = "demo-1.0.dist-info/entry_points.txt"
    installation = {
        "entries": [
            {
                "path": f"opt/venv/lib/python3.14/site-packages/{source_path}",
                "recorded_sha256": "1" * 64,
                "recorded_size": 32,
                "occurrence": {
                    **occurrence,
                    "mode": 0o644,
                    "path": f"opt/venv/lib/python3.14/site-packages/{source_path}",
                    "sha256": "1" * 64,
                    "size": 32,
                },
            },
            {
                "path": occurrence["path"],
                "recorded_sha256": occurrence["sha256"],
                "recorded_size": occurrence["size"],
                "occurrence": occurrence,
            },
        ]
    }
    record = {
        "callable": "main",
        "installed_occurrence": occurrence,
        "kind": "console_scripts",
        "launcher_interpreter": "python",
        "module": "demo.module",
        "name": "demo",
        "source_path": source_path,
    }

    verifier._validate_generated_files(
        [record],
        owner="python:demo@1.0",
        installation=installation,
        source="fixture native wheel",
    )
    with pytest.raises(verifier.VerificationError, match="exactly cover installed launchers"):
        verifier._validate_generated_files(
            [],
            owner="python:demo@1.0",
            installation=installation,
            source="fixture native wheel",
        )


def test_rejects_truncated_third_party_notices(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        files["THIRD_PARTY_NOTICES.md"] = b"# Third-party notices\n"

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(verifier.VerificationError, match="validated inventory and policy"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_invalid_spdx_license_resolution_with_matching_notice(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        policy = json.loads(files["policy/container-policy.json"])
        policy["license_resolutions"]["python:demo@1.0"]["expression"] = "MIT AND"
        components = json.loads(files["inventory/components.json"])
        coverage = json.loads(files["inventory/native-component-coverage.json"])
        expected = verifier.ExpectedIdentity(
            version=VERSION,
            platform=PLATFORM,
            subject_digest=SUBJECT,
            source_revision=REVISION,
            source_date_epoch=SOURCE_DATE_EPOCH,
        )
        files["policy/container-policy.json"] = verifier.canonical_json(policy)
        files["THIRD_PARTY_NOTICES.md"] = verifier._render_third_party_notices(
            components,
            policy,
            coverage,
            expected,
        )

    fixture = build_fixture(tmp_path, mutate=mutate)

    with pytest.raises(
        verifier.VerificationError,
        match="not a valid canonical SPDX expression",
    ):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_spdx_parser_accepts_canonical_operator_forms() -> None:
    identifiers, references = verifier._validate_spdx_expression(
        "GPL-2.0+ WITH Classpath-exception-2.0 OR DocumentRef-upstream:LicenseRef-project-specific",
        "synthetic SPDX expression",
    )

    assert identifiers == {"GPL-2.0", "Classpath-exception-2.0"}
    assert references == {"DocumentRef-upstream:LicenseRef-project-specific"}


@pytest.mark.parametrize(
    "expression",
    (
        "MIT++",
        "LicenseRef-project-specific+",
        "MIT AND",
        "MIT and Apache-2.0",
        "MIT OR (Apache-2.0)",
        "Definitely-Not-An-SPDX-License",
        "MIT WITH Definitely-Not-An-SPDX-Exception",
        f"{'(' * (verifier.MAX_SPDX_NESTING + 1)}MIT{')' * (verifier.MAX_SPDX_NESTING + 1)}",
    ),
)
def test_spdx_parser_rejects_noncanonical_or_unbounded_forms(expression: str) -> None:
    with pytest.raises(
        verifier.VerificationError,
        match="not a valid canonical SPDX expression",
    ):
        verifier._validate_spdx_expression(expression, "synthetic SPDX expression")


def test_spdx_identifier_sets_are_frozen_to_reviewed_license_list_data() -> None:
    assert verifier.SPDX_LICENSE_LIST_REVISION == "421fbabbe80c94c58c12316af1bc6a2dca2362bc"
    assert verifier.SPDX_LICENSE_LIST_VERSION == "3dfd9aa"
    assert len(verifier.SPDX_LICENSE_IDS) == 729
    assert len(verifier.SPDX_EXCEPTION_IDS) == 85
    assert (
        sha256(("\n".join(sorted(verifier.SPDX_LICENSE_IDS)) + "\n").encode())
        == "b25e1703a0de3c6c1a13baa7b8898b9085868a05f963ca8f0dc048f74c3fc8d9"
    )
    assert (
        sha256(("\n".join(sorted(verifier.SPDX_EXCEPTION_IDS)) + "\n").encode())
        == "e63c7dd55a9714a7e625c101f334985b9bf53568168dcaed2144f0a43d5a21e0"
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("contract", "consumer store has the wrong identity"),
        ("files", "retained files differ from the consumer store"),
    ],
)
def test_rejects_wheelhouse_consumer_store_drift(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    def mutate_store(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
        store_path = "artifacts/native-wheelhouse/source.json"
        store = json.loads(files[store_path])
        if mutation == "contract":
            store["contract"]["index_digest"] = f"sha256:{'0' * 64}"
        elif mutation == "files":
            store["platforms"][PLATFORM]["files"][0]["sha256"] = "0" * 64
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(mutation)
        files[store_path] = verifier.canonical_json(store)
        manifest["native_wheelhouse_artifacts"]["consumer_store"] = binding(
            store_path,
            files[store_path],
        )

    fixture = build_fixture(tmp_path, mutate=mutate_store)

    with pytest.raises(verifier.VerificationError, match=message):
        verify_fixture(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing-field", "container policy must contain exactly"),
        ("component", "component inventory differs from the reviewed platform policy"),
        ("license", "license resolutions do not exactly cover"),
        ("source", "does not bind one retained source record"),
    ],
)
def test_rejects_policy_inventory_license_and_source_drift(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    def mutate_policy(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        policy = json.loads(files["policy/container-policy.json"])
        if mutation == "missing-field":
            del policy["python_sources"]
        elif mutation == "component":
            policy["platforms"][PLATFORM][1]["metadata_sha256"] = "0" * 64
        elif mutation == "license":
            del policy["license_resolutions"]["python:demo@1.0"]
        elif mutation == "source":
            policy["python_sources"][0]["sha256"] = "0" * 64
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(mutation)
        files["policy/container-policy.json"] = verifier.canonical_json(policy)

    fixture = build_fixture(tmp_path, mutate=mutate_policy)

    with pytest.raises(verifier.VerificationError, match=message):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_incorrect_checksum_filename(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    wrong_checksum = tmp_path / "renamed.sha256"
    fixture.checksum.rename(wrong_checksum)

    with pytest.raises(verifier.VerificationError, match="checksum filename must be exactly"):
        verifier.verify(
            archive_path=fixture.archive,
            checksum_path=wrong_checksum,
            predicate_path=fixture.predicate,
            output=fixture.output,
            expected=fixture.expected,
        )
    assert not fixture.output.exists()


def test_rejects_incomplete_inner_checksum_coverage(tmp_path: Path) -> None:
    def mutate(files: dict[str, bytes], _manifest: dict[str, Any]) -> None:
        files["SHA256SUMS"] = b"ignored until finalization"

    fixture = build_fixture(tmp_path, mutate=mutate)
    expanded = gzip.decompress(fixture.archive.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        extracted: dict[str, bytes] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            source = archive.extractfile(member)
            assert source is not None
            extracted[member.name] = source.read()
    lines = extracted["SHA256SUMS"].splitlines(keepends=True)
    extracted["SHA256SUMS"] = b"".join(lines[:-1])
    fixture.archive.write_bytes(
        archive_bytes(sorted(extracted.items(), key=lambda item: item[0].encode()))
    )
    write_external_bindings(fixture)

    with pytest.raises(verifier.VerificationError, match="exactly and uniquely cover"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_linked_inputs_and_existing_output(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    real_archive = tmp_path / "real-archive"
    fixture.archive.rename(real_archive)
    fixture.archive.symlink_to(real_archive)

    with pytest.raises(verifier.VerificationError, match="single-link regular file"):
        verify_fixture(fixture)
    assert not fixture.output.exists()

    fixture.archive.unlink()
    real_archive.rename(fixture.archive)
    fixture.output.mkdir()
    with pytest.raises(verifier.VerificationError, match="already exists"):
        verify_fixture(fixture)


def test_rejects_hard_linked_input(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    os.link(fixture.archive, tmp_path / "second-archive-link")

    with pytest.raises(verifier.VerificationError, match="single-link regular file"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_rejects_symlinks_in_input_and_output_directory_chains(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    input_link = tmp_path / "linked-input-parent"
    input_link.symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(verifier.VerificationError, match="unsafe directory component"):
        verifier.read_stable_input(
            input_link / fixture.archive.name,
            "linked archive",
            maximum=verifier.MAX_ARCHIVE_BYTES,
        )

    output_parent = tmp_path / "real-output-parent"
    output_parent.mkdir()
    output_link = tmp_path / "linked-output-parent"
    output_link.symlink_to(output_parent, target_is_directory=True)
    with pytest.raises(verifier.VerificationError, match="unsafe directory component"):
        verifier.verify(
            archive_path=fixture.archive,
            checksum_path=fixture.checksum,
            predicate_path=fixture.predicate,
            output=output_link / "verified",
            expected=fixture.expected,
        )
    assert not (output_parent / "verified").exists()


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "..",
        "../escape",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
        "a\nb",
    ],
)
def test_rejects_unsafe_or_ambiguous_paths(path: str) -> None:
    with pytest.raises(verifier.VerificationError):
        verifier.checked_path(path)


def test_expected_identity_is_strict() -> None:
    expected = verifier.ExpectedIdentity(
        version="01.2.3",
        platform=PLATFORM,
        subject_digest=SUBJECT,
        source_revision=REVISION,
        source_date_epoch=SOURCE_DATE_EPOCH,
    )

    with pytest.raises(verifier.VerificationError, match="semantic version"):
        verifier.validate_expected_identity(expected)


def test_verifier_has_no_generic_archive_or_network_parser() -> None:
    tree = ast.parse(SCRIPT.read_text())
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert not imports & {"gzip", "socket", "subprocess", "tarfile", "urllib.request", "zipfile"}
    assert "zlib" in imports
    assert "urllib.parse" in imports


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"key":1,"key":2}\n', "repeats object key"),
        (b'{"value":1.5}\n', "floating-point"),
        (b'{"value":NaN}\n', "non-finite"),
        (b'{"value":"\\ud800"}\n', "invalid Unicode"),
    ],
)
def test_strict_json_rejects_ambiguous_values(raw: bytes, message: str) -> None:
    with pytest.raises(verifier.VerificationError, match=message):
        verifier.strict_json_bytes(raw, "hostile JSON")


@pytest.mark.parametrize(
    ("constant", "value", "raw", "message"),
    [
        ("MAX_JSON_ITEMS", 3, b'{"values":[0,0]}\n', "too many JSON values"),
        ("MAX_JSON_DEPTH", 2, b'{"values":[0]}\n', "JSON depth limit"),
    ],
)
def test_json_resource_preflight_runs_before_json_loads(
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    raw: bytes,
    message: str,
) -> None:
    monkeypatch.setattr(verifier, constant, value)

    def unexpected_load(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("json.loads materialized an over-limit document")

    monkeypatch.setattr(verifier.json, "loads", unexpected_load)

    with pytest.raises(verifier.VerificationError, match=message):
        verifier.strict_json_bytes(raw, "hostile JSON")


@pytest.mark.parametrize("limit_kind", ("bytes", "items"))
def test_aggregate_json_budget_rejects_before_loading_the_next_document(
    monkeypatch: pytest.MonkeyPatch,
    limit_kind: str,
) -> None:
    first = verifier.canonical_json({"first": [1, 2]})
    second = verifier.canonical_json({"second": [3, 4]})
    first_items = verifier._JsonPreflight(first, "first").verify()
    if limit_kind == "bytes":
        monkeypatch.setattr(verifier, "MAX_TOTAL_JSON_BYTES", len(first))
    else:
        monkeypatch.setattr(verifier, "MAX_TOTAL_JSON_ITEMS", first_items)
    budget = verifier.JsonBudget()
    real_loads = verifier.json.loads
    calls = 0

    def counted_loads(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return real_loads(*args, **kwargs)

    monkeypatch.setattr(verifier.json, "loads", counted_loads)
    verifier.strict_json_bytes(first, "first", budget=budget)

    with pytest.raises(verifier.VerificationError, match="aggregate JSON"):
        verifier.strict_json_bytes(second, "second", budget=budget)
    assert calls == 1


@pytest.mark.parametrize(
    ("constant", "value", "message"),
    [
        ("MAX_EXPANDED_TAR_BYTES", 1, "expansion limit"),
        ("MAX_RETAINED_BYTES", 1, "retained-byte limit"),
        ("MAX_MEMBERS", 1, "too many retained members"),
        ("MAX_TOTAL_PATH_BYTES", 1, "path-byte limit"),
        ("MAX_PATH_DEPTH", 1, "component-depth limit"),
        ("MAX_TOTAL_PATH_COMPONENTS", 1, "cumulative component limit"),
        ("MAX_MEMBER_BYTES", 1, "path-scoped size limit"),
        ("MAX_PAX_BYTES", 1, "PAX headers exceed"),
        ("MAX_TOTAL_PAX_BYTES", 1, "PAX headers exceed"),
        ("MAX_ARCHIVE_BYTES", 1, "single-link regular file"),
        ("MAX_JSON_BYTES", 1, "single-link regular file"),
        ("MAX_JSON_DEPTH", 1, "JSON depth limit"),
        ("MAX_JSON_ITEMS", 1, "too many JSON values"),
        ("MAX_TOTAL_JSON_BYTES", 1, "aggregate JSON byte budget"),
        ("MAX_TOTAL_JSON_ITEMS", 1, "aggregate JSON value budget"),
    ],
)
def test_enforces_internal_resource_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    message: str,
) -> None:
    fixture = build_fixture(tmp_path)
    monkeypatch.setattr(verifier, constant, value)

    with pytest.raises(verifier.VerificationError, match=message):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_identical_inputs_produce_byte_identical_archives_and_summaries(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = build_fixture(first_root)
    second = build_fixture(second_root)

    first_result = verify_fixture(first)
    second_result = verify_fixture(second)

    assert first.archive.read_bytes() == second.archive.read_bytes()
    assert first.checksum.read_bytes() == second.checksum.read_bytes()
    assert first.predicate.read_bytes() == second.predicate.read_bytes()
    assert verifier.canonical_json(first_result) == verifier.canonical_json(second_result)


def test_outer_fixture_inputs_are_not_mutated_by_verification(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    before = {
        path: (path.read_bytes(), os.stat(path, follow_symlinks=False))
        for path in (fixture.archive, fixture.checksum, fixture.predicate)
    }

    verify_fixture(fixture)

    for path, (content, metadata) in before.items():
        after = os.stat(path, follow_symlinks=False)
        assert path.read_bytes() == content
        assert (after.st_dev, after.st_ino, after.st_size) == (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        )


def test_late_archive_mutation_removes_materialized_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path)
    real_parse = verifier.parse_archive

    def mutate_after_parse(*args: object, **kwargs: object) -> Any:
        result = real_parse(*args, **kwargs)
        with fixture.archive.open("ab") as archive:
            archive.write(b"late mutation")
        return result

    monkeypatch.setattr(verifier, "parse_archive", mutate_after_parse)

    with pytest.raises(verifier.VerificationError, match="changed while it was verified"):
        verify_fixture(fixture)
    assert not fixture.output.exists()


def test_output_replacement_is_rejected_without_deleting_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path)
    displaced = tmp_path / "displaced-output"
    real_verify_content = verifier.verify_content_contract

    def replace_after_content_verification(*args: object, **kwargs: object) -> Any:
        result = real_verify_content(*args, **kwargs)
        fixture.output.rename(displaced)
        fixture.output.mkdir()
        (fixture.output / "unrelated").write_text("do not delete\n")
        return result

    monkeypatch.setattr(verifier, "verify_content_contract", replace_after_content_verification)

    with pytest.raises(verifier.VerificationError, match="replaced before cleanup"):
        verify_fixture(fixture)
    assert (fixture.output / "unrelated").read_text() == "do not delete\n"
    assert (displaced / "MANIFEST.json").is_file()

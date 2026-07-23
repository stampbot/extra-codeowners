"""Tests for the deterministic direct container-source request plan."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import socket
import stat
import sys
import tarfile
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "container_source_plan.py"
POLICY = ROOT / ".compliance" / "container-policy.json"
UV_LOCK = ROOT / "uv.lock"
REVISION = "1" * 40
REAL_PLAN_SHA256 = "0adebce0dfecb52a6622ffe710e07fc5f6440e3efd074a828d486ba37aa5ea18"
REQUEST_KEYS = {
    "id",
    "url",
    "allowed_hosts",
    "algorithm",
    "digest",
    "expected_size",
    "max_bytes",
    "consumers",
}


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("container_source_plan", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


source_plan: Any = load_script()


def real_policy() -> dict[str, Any]:
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_policy(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "container-policy.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def copy_lock(tmp_path: Path, content: bytes | None = None) -> Path:
    path = tmp_path / "uv.lock"
    path.write_bytes(UV_LOCK.read_bytes() if content is None else content)
    return path


def build_with_policy(tmp_path: Path, policy: object) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        source_plan.build_direct_plan(
            write_policy(tmp_path, policy),
            copy_lock(tmp_path),
            source_revision=REVISION,
        ),
    )


def requests_by_id(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    requests = plan["requests"]
    assert isinstance(requests, list)
    return {request["id"]: request for request in requests}


def recipe_archive(
    origin: str,
    apkbuild: bytes,
    *,
    files: dict[str, bytes] | None = None,
    symlinks: dict[str, str] | None = None,
    mode: Literal["w:", "w:gz", "w:bz2", "w:xz"] = "w:gz",
) -> bytes:
    output = io.BytesIO()
    members = {f"aports/main/{origin}/APKBUILD": apkbuild, **(files or {})}
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, content in members.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (symlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.mode = 0o777
            member.linkname = target
            archive.addfile(member)
    return output.getvalue()


def minimal_alpine_policy(
    recipes: dict[str, tuple[str, bytes]],
    *,
    platform_origins: dict[str, list[str]] | None = None,
    exceptions: dict[str, object] | None = None,
) -> dict[str, Any]:
    selected = platform_origins or {
        platform: sorted(recipes) for platform in ("linux/amd64", "linux/arm64")
    }
    platforms: dict[str, list[dict[str, Any]]] = {}
    for platform, architecture in (
        ("linux/amd64", "x86_64"),
        ("linux/arm64", "aarch64"),
    ):
        platforms[platform] = [
            {
                "ecosystem": "alpine",
                "name": origin,
                "version": "1.0-r0",
                "origin": origin,
                "aports_commit": recipes[origin][0],
                "architecture": architecture,
            }
            for origin in selected[platform]
        ]
    return {
        "schema_version": 7,
        "platforms": platforms,
        "native_component_coverage": {
            "linux/amd64": [],
            "linux/arm64": [],
        },
        "native_component_sources": {},
        "alpine_distfiles_release": "v3.24",
        "alpine_recipe_archives": {
            f"{origin}@{commit}": hashlib.sha256(content).hexdigest()
            for origin, (commit, content) in recipes.items()
        },
        "alpine_recipe_exceptions": exceptions or {},
    }


def direct_recipe_requests(
    policy: dict[str, Any],
    recipes: dict[str, tuple[str, bytes]],
) -> list[dict[str, Any]]:
    consumers: dict[tuple[str, str], set[str]] = {}
    for platform, components in policy["platforms"].items():
        for component in components:
            if component["ecosystem"] != "alpine":
                continue
            key = (component["origin"], component["aports_commit"])
            consumers.setdefault(key, set()).add(
                f"platform:{platform}:alpine:{component['name']}@{component['version']}"
            )
    requests: list[dict[str, Any]] = []
    for origin, (commit, content) in sorted(recipes.items()):
        url = (
            "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
            f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
        )
        requests.append(
            {
                "id": f"alpine-recipe:{origin}@{commit}",
                "url": url,
                "allowed_hosts": ["gitlab.alpinelinux.org"],
                "algorithm": "sha256",
                "digest": hashlib.sha256(content).hexdigest(),
                "expected_size": None,
                "max_bytes": source_plan.MAX_DOWNLOAD_BYTES,
                "consumers": sorted(consumers[(origin, commit)]),
            }
        )
    return requests


def write_direct_store(
    tmp_path: Path,
    policy_path: Path,
    requests: list[dict[str, Any]],
    content_by_id: dict[str, bytes],
) -> tuple[Path, str, int]:
    plan: dict[str, Any] = {
        "schema_version": 1,
        "media_type": "application/vnd.stampbot.container-source-plan.v1+json",
        "kind": "direct",
        "evidence_schema_version": 7,
        "source_revision": REVISION,
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "uv_lock_sha256": "2" * 64,
        "requests": sorted(requests, key=lambda request: request["id"]),
    }
    plan_bytes = source_plan.canonical_json(plan)
    root = tmp_path / "direct-store"
    objects_root = root / "objects" / "sha256"
    objects_root.mkdir(parents=True)
    root.chmod(0o700)
    (root / "objects").chmod(0o700)
    objects_root.chmod(0o700)
    objects: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for request in plan["requests"]:
        content = content_by_id[request["id"]]
        parsed_url = urllib.parse.urlsplit(request["url"])
        request_origin = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        object_digest = hashlib.sha256(content).hexdigest()
        object_path = objects_root / object_digest
        if not object_path.exists():
            object_path.write_bytes(content)
            object_path.chmod(0o600)
        objects[object_digest] = {
            "algorithm": "sha256",
            "digest": object_digest,
            "size": len(content),
            "path": f"objects/sha256/{object_digest}",
        }
        attempt = {
            "number": 1,
            "outcome": "success",
            "http_status": 200,
            "redirect_origins": [request_origin],
            "received_size": len(content),
            "sha256": object_digest,
            "retry_delay_seconds": None,
        }
        results.append(
            {
                "id": request["id"],
                "request_origin": request_origin,
                "algorithm": request["algorithm"],
                "digest": request["digest"],
                "expected_size": request["expected_size"],
                "max_bytes": request["max_bytes"],
                "object_sha256": object_digest,
                "size": len(content),
                "path": f"objects/sha256/{object_digest}",
                "redirect_origins": [request_origin],
                "attempts": [attempt],
            }
        )
    manifest = {
        "schema_version": 1,
        "media_type": "application/vnd.stampbot.verified-source-store.v1+json",
        "kind": "direct",
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "plan_size": len(plan_bytes),
        "objects": [objects[key] for key in sorted(objects)],
        "results": results,
    }
    plan_path = root / "SOURCE-PLAN.json"
    manifest_path = root / "SOURCE-STORE.json"
    plan_path.write_bytes(plan_bytes)
    manifest_path.write_bytes(source_plan.canonical_json(manifest))
    plan_path.chmod(0o600)
    manifest_path.chmod(0o600)
    return root, hashlib.sha256(plan_bytes).hexdigest(), len(plan_bytes)


def build_alpine_case(
    tmp_path: Path,
    recipes: dict[str, tuple[str, bytes]],
    *,
    policy: dict[str, Any] | None = None,
    mutate_requests: Any | None = None,
) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    selected_policy = policy or minimal_alpine_policy(recipes)
    policy_path = write_policy(tmp_path, selected_policy)
    requests = direct_recipe_requests(selected_policy, recipes)
    if mutate_requests is not None:
        mutate_requests(requests)
    content_by_id = {
        f"alpine-recipe:{origin}@{commit}": content for origin, (commit, content) in recipes.items()
    }
    store, digest, size = write_direct_store(
        tmp_path,
        policy_path,
        requests,
        content_by_id,
    )
    return cast(
        dict[str, Any],
        source_plan.build_alpine_distfile_plan(
            policy_path,
            store,
            expected_parent_plan_sha256=digest,
            expected_parent_plan_size=size,
        ),
    )


def build_native_alpine_case(
    tmp_path: Path,
    *,
    recipe_digest: str,
    reviewed_digest: str,
) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    origin = "demo-native"
    commit = "7" * 40
    source_id = "alpine:demo-native@1.0-r0"
    apkbuild = (
        'source="https://upstream.example.test/demo-native-1.0.tar.xz"\n'
        f'sha512sums="\n{recipe_digest}  demo-native-1.0.tar.xz\n"\n'
    ).encode()
    archive = recipe_archive(origin, apkbuild)
    owner_source = {
        "url": "https://files.pythonhosted.org/packages/demo-python-1.0.tar.gz",
        "sha256": "1" * 64,
        "size": 100,
    }
    wheel_platform_tags = {
        "linux/amd64": "musllinux_1_2_x86_64",
        "linux/arm64": "musllinux_1_2_aarch64",
    }
    policy: dict[str, Any] = {
        "schema_version": 7,
        "platforms": {
            platform: [
                {
                    "ecosystem": "python",
                    "name": "demo-python",
                    "version": "1.0",
                }
            ]
            for platform in ("linux/amd64", "linux/arm64")
        },
        "native_component_coverage": {
            platform: [
                {
                    "owner": "python:demo-python@1.0",
                    "owner_source": owner_source,
                    "wheel": {
                        "url": (
                            "https://files.pythonhosted.org/packages/"
                            f"demo_python-1.0-cp314-cp314-"
                            f"{wheel_platform_tags[platform]}.whl"
                        ),
                        "sha256": ("2" if platform == "linux/amd64" else "3") * 64,
                        "size": 200,
                    },
                    "component_reviews": [
                        {
                            "source": source_id,
                            "observations": [],
                        }
                    ],
                }
            ]
            for platform in ("linux/amd64", "linux/arm64")
        },
        "native_component_sources": {
            source_id: {
                "kind": "alpine-aports",
                "origin": origin,
                "version": "1.0-r0",
                "aports_commit": commit,
                "recipe": {
                    "url": (
                        "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
                        f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
                    ),
                    "sha256": hashlib.sha256(archive).hexdigest(),
                    "size": len(archive),
                },
                "distfiles_release": "v3.22",
                "distfiles": [
                    {
                        "filename": "demo-native-1.0.tar.xz",
                        "url": (
                            "https://distfiles.alpinelinux.org/distfiles/v3.22/"
                            "demo-native-1.0.tar.xz"
                        ),
                        "sha512": reviewed_digest,
                        "size": 1234,
                    }
                ],
                "allowed_recipe_links": [],
            }
        },
        "alpine_distfiles_release": "v3.24",
        "alpine_recipe_archives": {},
        "alpine_recipe_exceptions": {},
    }
    policy_path = write_policy(tmp_path, policy)
    request_id = f"native-source:{source_id}:recipe"
    recipe_policy = policy["native_component_sources"][source_id]["recipe"]
    request = {
        "id": request_id,
        "url": recipe_policy["url"],
        "allowed_hosts": ["gitlab.alpinelinux.org"],
        "algorithm": "sha256",
        "digest": recipe_policy["sha256"],
        "expected_size": len(archive),
        "max_bytes": source_plan.MAX_DOWNLOAD_BYTES,
        "consumers": [
            "platform:linux/amd64:native-owner:python:demo-python@1.0",
            "platform:linux/arm64:native-owner:python:demo-python@1.0",
        ],
    }
    store, digest, size = write_direct_store(
        tmp_path,
        policy_path,
        [request],
        {request_id: archive},
    )
    return cast(
        dict[str, Any],
        source_plan.build_alpine_distfile_plan(
            policy_path,
            store,
            expected_parent_plan_sha256=digest,
            expected_parent_plan_size=size,
        ),
    )


def test_real_policy_direct_plan_is_stable_and_complete() -> None:
    first = source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)
    second = source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)

    assert first == second
    assert set(first) == {
        "schema_version",
        "media_type",
        "kind",
        "evidence_schema_version",
        "source_revision",
        "policy_sha256",
        "uv_lock_sha256",
        "requests",
    }
    assert first["schema_version"] == 1
    assert first["media_type"] == "application/vnd.stampbot.container-source-plan.v1+json"
    assert first["kind"] == "direct"
    assert first["evidence_schema_version"] == 7
    assert first["source_revision"] == REVISION
    assert first["policy_sha256"] == hashlib.sha256(POLICY.read_bytes()).hexdigest()
    assert first["uv_lock_sha256"] == hashlib.sha256(UV_LOCK.read_bytes()).hexdigest()

    requests = first["requests"]
    assert isinstance(requests, list)
    assert len(requests) == 132
    assert [request["id"] for request in requests] == sorted(request["id"] for request in requests)
    assert len({request["id"] for request in requests}) == len(requests)
    assert Counter(request["id"].split(":", maxsplit=1)[0] for request in requests) == {
        "alpine-recipe": 20,
        "cpython": 1,
        "docker-python": 2,
        "license-text": 22,
        "native-source": 35,
        "python-sdist": 38,
        "python-wheel": 14,
    }
    for request in requests:
        assert set(request) == REQUEST_KEYS
        assert request["allowed_hosts"] == sorted(set(request["allowed_hosts"]))
        assert request["consumers"] == sorted(set(request["consumers"]))
        assert request["consumers"]
        assert len(request["consumers"]) <= 512
        assert request["algorithm"] in {"sha256", "sha512"}
        assert request["expected_size"] is None or (
            0 < request["expected_size"] <= request["max_bytes"]
        )
    assert sum(len(request["consumers"]) for request in requests) <= 2_048

    raw = source_plan.canonical_json(first)
    assert len(raw) <= 4 * 1024 * 1024
    assert raw.decode("ascii")
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert json.loads(raw) == first
    assert source_plan.canonical_json(json.loads(raw)) == raw
    assert hashlib.sha256(raw).hexdigest() == REAL_PLAN_SHA256
    contract = source_plan._source_store_contract()
    assert source_plan.MAX_TOTAL_OBJECT_BYTES == contract.MAX_TOTAL_OBJECT_BYTES
    parsed = contract.strict_json_bytes(
        raw,
        "test direct source plan",
        maximum=source_plan.MAX_PLAN_BYTES,
    )
    assert contract.validate_source_plan(parsed) == first


def test_real_policy_plan_covers_platform_wheels_and_reuses_owner_sdist() -> None:
    plan = source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)
    requests = requests_by_id(plan)

    for platform in ("linux/amd64", "linux/arm64"):
        wheel_ids = [
            request_id
            for request_id in requests
            if request_id.startswith(f"python-wheel:{platform}:")
        ]
        assert len(wheel_ids) == 7

    owner_request = requests["python-sdist:cryptography@48.0.1"]
    assert owner_request["consumers"] == [
        "platform:linux/amd64:native-owner:python:cryptography@48.0.1",
        "platform:linux/amd64:python:cryptography@48.0.1",
        "platform:linux/arm64:native-owner:python:cryptography@48.0.1",
        "platform:linux/arm64:python:cryptography@48.0.1",
    ]
    assert not any(request_id.startswith("native-source:owner-sdist:") for request_id in requests)


def test_real_policy_direct_plan_excludes_every_alpine_distfile() -> None:
    plan = source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)
    requests = plan["requests"]

    assert all(
        urllib.parse.urlsplit(request["url"]).hostname != "distfiles.alpinelinux.org"
        for request in requests
    )
    gcc_requests = [
        request for request in requests if request["id"].startswith("native-source:alpine:gcc@")
    ]
    assert [request["id"].rsplit(":", maxsplit=1)[-1] for request in gcc_requests] == ["recipe"]


def test_real_policy_missing_sizes_remain_bounded() -> None:
    plan = source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)
    requests = plan["requests"]
    unknown_size = [request for request in requests if request["expected_size"] is None]

    assert len(unknown_size) == 44
    assert all(request["max_bytes"] > 0 for request in unknown_size)
    assert {request["id"].split(":", maxsplit=1)[0] for request in unknown_size} == {
        "alpine-recipe",
        "docker-python",
        "license-text",
    }


def test_real_policy_github_requests_have_explicit_redirect_hosts() -> None:
    plan = source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)
    github_requests = [
        request for request in plan["requests"] if request["url"].startswith("https://github.com/")
    ]

    assert github_requests
    archive_requests = [request for request in github_requests if "/archive/" in request["url"]]
    release_requests = [
        request for request in github_requests if "/releases/download/" in request["url"]
    ]
    assert archive_requests
    assert release_requests
    assert all(
        request["allowed_hosts"] == ["codeload.github.com", "github.com"]
        for request in archive_requests
    )
    assert all(
        request["allowed_hosts"] == ["github.com", "release-assets.githubusercontent.com"]
        for request in release_requests
    )


def test_github_redirect_allowlist_is_narrowed_by_canonical_path() -> None:
    assert source_plan._allowed_hosts("https://github.com/owner/repo/archive/main.tar.gz") == (
        "codeload.github.com",
        "github.com",
    )
    assert source_plan._allowed_hosts(
        "https://github.com/owner/repo/releases/download/v1/source.tar.gz"
    ) == (
        "github.com",
        "release-assets.githubusercontent.com",
    )
    assert source_plan._allowed_hosts("https://github.com/owner/repo/issues/1") == ("github.com",)
    assert source_plan._allowed_hosts("https://github.com/owner/archive/issues/1") == (
        "github.com",
    )


@pytest.mark.parametrize(
    ("url", "message"),
    (
        ("http://example.com/source.tar.gz", "not HTTPS"),
        ("https://user:secret@example.com/source.tar.gz", "credentials"),
        ("https://example.com:444/source.tar.gz", "non-443"),
    ),
)
def test_direct_plan_rejects_unsafe_urls(tmp_path: Path, url: str, message: str) -> None:
    policy = real_policy()
    policy["docker_python_recipe"]["url"] = url

    with pytest.raises(source_plan.PlanError, match=message):
        build_with_policy(tmp_path, policy)


@pytest.mark.parametrize("failure", ("credentials", "conflicting-query-url"))
def test_direct_plan_cli_url_errors_disclose_only_the_origin(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    policy = real_policy()
    secret = "do-not-log-this-token"
    path = "private-object-name"
    if failure == "credentials":
        policy["docker_python_recipe"]["url"] = (
            f"https://leaky-user:{secret}@downloads.example.test/{path}?token={secret}"
        )
    else:
        signed_url = f"https://downloads.example.test/{path}?token={secret}"
        policy["license_texts"][0]["url"] = signed_url
        policy["license_texts"][1]["url"] = signed_url
    policy_path = write_policy(tmp_path, policy)

    result = source_plan.main(
        [
            "direct-plan",
            "--policy",
            str(policy_path),
            "--uv-lock",
            str(UV_LOCK),
            "--source-revision",
            REVISION,
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    expected_errors = {
        "credentials": (
            "Container source plan error: source URL contains credentials "
            "(https://downloads.example.test/)\n"
        ),
        "conflicting-query-url": (
            "Container source plan error: URL has conflicting artifact bindings at "
            "https://downloads.example.test/\n"
        ),
    }
    assert captured.err == expected_errors[failure]
    assert secret not in captured.err
    assert path not in captured.err
    assert "leaky-user" not in captured.err
    assert "?token" not in captured.err


def test_direct_plan_rejects_native_wheel_policy_substitution(tmp_path: Path) -> None:
    policy = real_policy()
    policy["native_component_coverage"]["linux/amd64"][0]["wheel"]["sha256"] = "0" * 64

    with pytest.raises(source_plan.PlanError, match="does not select one exact lock entry"):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_wrong_platform_wheel_even_when_it_is_locked(
    tmp_path: Path,
) -> None:
    policy = real_policy()
    amd64 = next(
        owner
        for owner in policy["native_component_coverage"]["linux/amd64"]
        if owner["owner"] == "python:cffi@2.1.0"
    )
    arm64 = next(
        owner
        for owner in policy["native_component_coverage"]["linux/arm64"]
        if owner["owner"] == "python:cffi@2.1.0"
    )
    amd64["wheel"] = copy.deepcopy(arm64["wheel"])

    with pytest.raises(source_plan.PlanError, match="targets the wrong platform"):
        build_with_policy(tmp_path, policy)


@pytest.mark.parametrize(
    ("filename", "message"),
    (
        (
            "other-1.0-cp314-cp314-musllinux_1_2_x86_64.whl",
            "differs from its owner",
        ),
        (
            "package-2.0-cp314-cp314-musllinux_1_2_x86_64.whl",
            "differs from its owner",
        ),
        (
            "package-1.0-build-cp314-cp314-musllinux_1_2_x86_64.whl",
            "invalid build tag",
        ),
        (
            "package-1.0-py3-none-musllinux_1_2_x86_64.whl",
            "invalid compatibility tags",
        ),
    ),
)
def test_native_wheel_filename_binds_canonical_identity_and_tags(
    filename: str,
    message: str,
) -> None:
    need = source_plan.WheelNeed(
        platform="linux/amd64",
        owner="python:package@1.0",
        package=("package", "1.0"),
        artifact=source_plan.Artifact(
            url=f"https://files.pythonhosted.org/packages/{filename}",
            digest="a" * 64,
            size=123,
        ),
        consumer="platform:linux/amd64:native-owner:python:package@1.0",
    )

    with pytest.raises(source_plan.PlanError, match=message):
        source_plan._validate_wheel_binding(need)


def test_direct_plan_binds_native_owner_to_each_platform_components(
    tmp_path: Path,
) -> None:
    policy = real_policy()
    policy["platforms"]["linux/amd64"] = [
        component
        for component in policy["platforms"]["linux/amd64"]
        if not (
            component["ecosystem"] == "python"
            and component["name"] == "cffi"
            and component["version"] == "2.1.0"
        )
    ]

    with pytest.raises(
        source_plan.PlanError,
        match=r"absent from platform components: linux/amd64/python:cffi@2\.1\.0",
    ):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_lock_source_substitution(tmp_path: Path) -> None:
    policy = real_policy()
    cryptography = next(
        owner
        for owner in policy["native_component_coverage"]["linux/amd64"]
        if owner["owner"] == "python:cryptography@48.0.1"
    )
    digest = cryptography["owner_source"]["sha256"]
    lock = UV_LOCK.read_bytes()
    old = f'hash = "sha256:{digest}"'.encode()
    assert lock.count(old) == 1
    lock = lock.replace(old, f'hash = "sha256:{"0" * 64}"'.encode())

    with pytest.raises(source_plan.PlanError, match="owner source differs"):
        source_plan.build_direct_plan(
            write_policy(tmp_path, policy),
            copy_lock(tmp_path, lock),
            source_revision=REVISION,
        )


def test_direct_plan_rejects_conflicting_python_source_identity(tmp_path: Path) -> None:
    policy = real_policy()
    duplicate = copy.deepcopy(policy["python_sources"][0])
    duplicate["sha256"] = "0" * 64
    policy["python_sources"].append(duplicate)

    with pytest.raises(source_plan.PlanError, match="repeats Python source fallback"):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_normalized_platform_identity_collision(
    tmp_path: Path,
) -> None:
    policy = real_policy()
    component = next(
        component
        for component in policy["platforms"]["linux/amd64"]
        if component["name"] == "annotated-doc"
    )
    duplicate = copy.deepcopy(component)
    duplicate["name"] = "annotated_doc"
    policy["platforms"]["linux/amd64"].append(duplicate)

    with pytest.raises(source_plan.PlanError, match="repeats component identity"):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_conflicting_url_binding(tmp_path: Path) -> None:
    policy = real_policy()
    policy["license_texts"][1]["url"] = policy["license_texts"][0]["url"]

    with pytest.raises(source_plan.PlanError, match="URL has conflicting artifact bindings"):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_owner_sdist_owner_substitution(tmp_path: Path) -> None:
    policy = real_policy()
    owner_source = next(
        source
        for source in policy["native_component_sources"].values()
        if source["kind"] == "owner-sdist-subpath"
    )
    owner_source["owner"] = "python:cffi@2.1.0"

    with pytest.raises(source_plan.PlanError, match="owner differs from reviewed consumers"):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_unknown_native_source_kind(tmp_path: Path) -> None:
    policy = real_policy()
    source = next(iter(policy["native_component_sources"].values()))
    source["kind"] = "git-snapshot"

    with pytest.raises(source_plan.PlanError, match="unsupported native source kind"):
        build_with_policy(tmp_path, policy)


def test_direct_plan_rejects_duplicate_policy_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "container-policy.json"
    duplicate.write_text('{"schema_version":7,"schema_version":7}', encoding="utf-8")

    with pytest.raises(source_plan.PlanError, match="repeats key"):
        source_plan.build_direct_plan(
            duplicate,
            copy_lock(tmp_path),
            source_revision=REVISION,
        )


def test_direct_plan_cli_does_not_echo_an_unsafe_duplicate_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    duplicate = tmp_path / "container-policy.json"
    attacker_text = "\n::error::do-not-run-this-workflow-command\x1b[2J"
    encoded_key = json.dumps(attacker_text)
    duplicate.write_text(
        f"{{{encoded_key}:0,{encoded_key}:1}}",
        encoding="utf-8",
    )

    result = source_plan.main(
        [
            "direct-plan",
            "--policy",
            str(duplicate),
            "--uv-lock",
            str(UV_LOCK),
            "--source-revision",
            REVISION,
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "Container source plan error: JSON object repeats key\n"
    assert attacker_text not in captured.err
    assert "::error::" not in captured.err
    assert "\x1b" not in captured.err


def test_direct_plan_rejects_alpine_distfile_in_direct_metadata(tmp_path: Path) -> None:
    policy = real_policy()
    policy["docker_python_recipe"]["url"] = (
        "https://distfiles.alpinelinux.org/distfiles/edge/source.tar.gz"
    )

    with pytest.raises(source_plan.PlanError, match="must not fetch Alpine distfiles"):
        build_with_policy(tmp_path, policy)


def test_policy_parser_rejects_excessive_container_nesting(tmp_path: Path) -> None:
    path = tmp_path / "nested-policy.json"
    path.write_text("[" * 65 + "0" + "]" * 65, encoding="utf-8")

    with pytest.raises(source_plan.PlanError, match="nesting limit"):
        source_plan._load_policy(path)


def test_policy_parser_translates_recursion_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "policy.json"
    path.write_text("{}", encoding="utf-8")

    def recurse(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("deliberate parser recursion")

    monkeypatch.setattr(source_plan.json, "loads", recurse)
    with pytest.raises(source_plan.PlanError, match="cannot parse container policy"):
        source_plan._load_policy(path)


@pytest.mark.parametrize(
    "revision",
    (
        "",
        "A" * 40,
        "1" * 39,
        "1" * 41,
        "refs/heads/main",
    ),
)
def test_direct_plan_rejects_noncanonical_source_revision(revision: str) -> None:
    with pytest.raises(source_plan.PlanError, match="source revision"):
        source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=revision)


def test_canonical_json_is_ascii_and_rejects_non_finite_values() -> None:
    assert source_plan.canonical_json({"snowman": "\N{SNOWMAN}"}) == (b'{"snowman":"\\u2603"}\n')
    with pytest.raises(source_plan.PlanError, match="canonical JSON"):
        source_plan.canonical_json({"number": float("nan")})


def test_request_primitive_accepts_sha512_and_merges_consumers() -> None:
    builder = source_plan._PlanBuilder()
    artifact = source_plan.Artifact(
        url="https://distfiles.example.com/source.tar.xz",
        digest="a" * 128,
        size=123,
    )

    builder.add(
        "future-distfile:source.tar.xz",
        artifact,
        algorithm="sha512",
        max_bytes=456,
        consumers={"platform:linux/arm64:alpine:example@1-r0"},
    )
    builder.add(
        "future-distfile:source.tar.xz",
        artifact,
        algorithm="sha512",
        max_bytes=456,
        consumers={"platform:linux/amd64:alpine:example@1-r0"},
    )

    assert builder.requests() == [
        {
            "id": "future-distfile:source.tar.xz",
            "url": "https://distfiles.example.com/source.tar.xz",
            "allowed_hosts": ["distfiles.example.com"],
            "algorithm": "sha512",
            "digest": "a" * 128,
            "expected_size": 123,
            "max_bytes": 456,
            "consumers": [
                "platform:linux/amd64:alpine:example@1-r0",
                "platform:linux/arm64:alpine:example@1-r0",
            ],
        }
    ]


def test_request_primitive_enforces_consumer_token_and_request_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = source_plan.Artifact(
        url="https://example.com/source.tar.gz",
        digest="a" * 64,
        size=123,
    )
    builder = source_plan._PlanBuilder()
    with pytest.raises(source_plan.PlanError, match="too many consumers"):
        builder.add(
            "bounded-request",
            artifact,
            max_bytes=456,
            consumers={f"consumer:{index}" for index in range(513)},
        )
    with pytest.raises(source_plan.PlanError, match="invalid request id"):
        builder.add(
            "a" * 513,
            artifact,
            max_bytes=456,
            consumers={"consumer:one"},
        )

    builder = source_plan._PlanBuilder()
    for request_index in range(4):
        builder.add(
            f"request:{request_index}",
            artifact,
            max_bytes=456,
            consumers={
                f"request:{request_index}:consumer:{consumer_index}"
                for consumer_index in range(512)
            },
        )
    with pytest.raises(source_plan.PlanError, match="too many consumer references"):
        builder.add(
            "request:overflow",
            artifact,
            max_bytes=456,
            consumers={"consumer:overflow"},
        )

    monkeypatch.setattr(source_plan, "MAX_REQUESTS", 1)
    builder = source_plan._PlanBuilder()
    builder.add(
        "request:one",
        artifact,
        max_bytes=456,
        consumers={"consumer:one"},
    )
    with pytest.raises(source_plan.PlanError, match="too many requests"):
        builder.add(
            "request:two",
            artifact,
            max_bytes=456,
            consumers={"consumer:two"},
        )


def test_request_primitive_bounds_unique_known_object_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(source_plan, "MAX_TOTAL_OBJECT_BYTES", 100)
    builder = source_plan._PlanBuilder()

    def add(
        request_id: str,
        url: str,
        digest: str,
        size: int | None,
    ) -> None:
        builder.add(
            request_id,
            source_plan.Artifact(url=url, digest=digest, size=size),
            max_bytes=100,
            consumers={f"consumer:{request_id}"},
        )

    add("request:first", "https://one.example.test/source", "a" * 64, 60)
    add("request:first-copy", "https://two.example.test/source", "a" * 64, 60)
    add("request:unknown", "https://three.example.test/source", "b" * 64, None)
    add("request:known-later", "https://four.example.test/source", "b" * 64, 40)

    assert len(builder.requests()) == 4
    with pytest.raises(source_plan.PlanError, match="aggregate byte limit"):
        add("request:overflow", "https://five.example.test/source", "c" * 64, 1)
    assert len(builder.requests()) == 4
    with pytest.raises(source_plan.PlanError, match="conflicting expected sizes"):
        add("request:conflict", "https://six.example.test/source", "a" * 64, 59)


def test_request_primitive_rejects_casefold_identity_collisions() -> None:
    artifact = source_plan.Artifact(
        url="https://example.com/source.tar.gz",
        digest="a" * 64,
        size=123,
    )
    builder = source_plan._PlanBuilder()
    builder.add(
        "Request:one",
        artifact,
        max_bytes=456,
        consumers={"consumer:one"},
    )
    with pytest.raises(source_plan.PlanError, match="IDs differ only by case"):
        builder.add(
            "request:one",
            artifact,
            max_bytes=456,
            consumers={"consumer:two"},
        )

    builder = source_plan._PlanBuilder()
    with pytest.raises(source_plan.PlanError, match="consumers differ only by case"):
        builder.add(
            "request:one",
            artifact,
            max_bytes=456,
            consumers={"Consumer:one", "consumer:one"},
        )

    builder = source_plan._PlanBuilder()
    builder.add(
        "request:one",
        artifact,
        max_bytes=456,
        consumers={"Consumer:one"},
    )
    with pytest.raises(source_plan.PlanError, match="consumers differ only by case"):
        builder.add(
            "request:two",
            artifact,
            max_bytes=456,
            consumers={"consumer:one"},
        )


def test_regular_file_reader_rejects_symlink_hardlink_fifo_and_oversize(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"safe")
    symlink = tmp_path / "symlink"
    symlink.symlink_to(target)
    with pytest.raises(source_plan.PlanError, match="not a regular file"):
        source_plan._read_regular_file(symlink, "test input", max_bytes=16)

    hardlink = tmp_path / "hardlink"
    os.link(target, hardlink)
    with pytest.raises(source_plan.PlanError, match="exactly one link"):
        source_plan._read_regular_file(target, "test input", max_bytes=16)
    hardlink.unlink()

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(source_plan.PlanError, match="not a regular file"):
        source_plan._read_regular_file(fifo, "test input", max_bytes=16)

    oversize = tmp_path / "oversize"
    oversize.write_bytes(b"too large")
    with pytest.raises(source_plan.PlanError, match="exceeds its size limit"):
        source_plan._read_regular_file(oversize, "test input", max_bytes=4)


def test_regular_file_reader_opens_a_raced_fifo_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    regular = tmp_path / "regular"
    regular.write_bytes(b"safe")
    regular_metadata = regular.lstat()
    fifo = tmp_path / "raced-fifo"
    os.mkfifo(fifo)
    real_lstat = Path.lstat
    first = True

    def regular_then_fifo(path: Path) -> os.stat_result:
        nonlocal first
        if path == fifo and first:
            first = False
            return regular_metadata
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", regular_then_fifo)
    with pytest.raises(source_plan.PlanError, match="not a regular file"):
        source_plan._read_regular_file(fifo, "test input", max_bytes=16)


def test_regular_file_reader_rejects_growth_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "growing"
    path.write_bytes(b"a")
    real_read = source_plan.os.read
    changed = False

    def grow_then_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        if not changed:
            changed = True
            with path.open("ab") as stream:
                stream.write(b"b")
        return cast(bytes, real_read(descriptor, count))

    monkeypatch.setattr(source_plan.os, "read", grow_then_read)
    with pytest.raises(source_plan.PlanError, match="changed while it was read"):
        source_plan._read_regular_file(path, "test input", max_bytes=16)


def test_regular_file_reader_rejects_path_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "replaceable"
    displaced = tmp_path / "displaced"
    path.write_bytes(b"old")
    real_read = source_plan.os.read
    changed = False

    def replace_then_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        if not changed:
            changed = True
            path.rename(displaced)
            path.write_bytes(b"new")
        return cast(bytes, real_read(descriptor, count))

    monkeypatch.setattr(source_plan.os, "read", replace_then_read)
    with pytest.raises(source_plan.PlanError, match="changed while it was read"):
        source_plan._read_regular_file(path, "test input", max_bytes=16)


def test_direct_plan_enforces_encoded_size_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(source_plan, "MAX_PLAN_BYTES", 1)

    with pytest.raises(source_plan.PlanError, match="encoded size limit"):
        source_plan.build_direct_plan(POLICY, UV_LOCK, source_revision=REVISION)


def test_direct_plan_cli_emits_one_canonical_json_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = source_plan.main(
        [
            "direct-plan",
            "--policy",
            str(POLICY),
            "--uv-lock",
            str(UV_LOCK),
            "--source-revision",
            REVISION,
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out.endswith("\n")
    assert captured.out.count("\n") == 1
    value = json.loads(captured.out)
    assert captured.out.encode("ascii") == source_plan.canonical_json(value)


def test_alpine_distfile_plan_is_offline_canonical_and_parent_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote_digest = "a" * 128
    local_content = b"reviewed patch\n"
    local_digest = hashlib.sha512(local_content).hexdigest()
    apkbuild = (
        'source="https://upstream.example.test/demo-$pkgver.tar.xz\nlocal.patch"\n'
        f'sha512sums="\n{remote_digest}  demo-1.0.tar.xz\n'
        f'{local_digest}  local.patch\n"\n'
    ).encode()
    archive = recipe_archive(
        "demo",
        apkbuild,
        files={"aports/main/demo/local.patch": local_content},
    )
    recipes = {"demo": ("a" * 40, archive)}

    def network_forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("distfile planning attempted network access")

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://proxy.invalid:1080")
    monkeypatch.setattr(socket, "getaddrinfo", network_forbidden)
    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", network_forbidden)
    read_regular_file = source_plan._read_regular_file

    def reject_store_path_reopen(
        path: Path,
        description: str,
        *,
        max_bytes: int,
    ) -> bytes:
        assert "direct-store" not in path.parts
        return cast(
            bytes,
            read_regular_file(
                path,
                description,
                max_bytes=max_bytes,
            ),
        )

    monkeypatch.setattr(source_plan, "_read_regular_file", reject_store_path_reopen)

    first = build_alpine_case(tmp_path, recipes)
    second_root = tmp_path / "second"
    second_root.mkdir()
    second = build_alpine_case(second_root, recipes)

    assert first == second
    assert set(first) == {
        "schema_version",
        "media_type",
        "kind",
        "evidence_schema_version",
        "source_revision",
        "policy_sha256",
        "uv_lock_sha256",
        "parent_plan",
        "parent_manifest",
        "recipes",
        "requests",
    }
    assert first["kind"] == "alpine-distfiles"
    assert first["source_revision"] == REVISION
    assert first["parent_plan"]["algorithm"] == "sha256"
    assert first["parent_manifest"]["algorithm"] == "sha256"
    assert first["recipes"] == [
        {
            "request_id": f"alpine-recipe:demo@{'a' * 40}",
            "object_sha256": hashlib.sha256(archive).hexdigest(),
            "size": len(archive),
        }
    ]
    filename_hash = hashlib.sha256(b"demo-1.0.tar.xz").hexdigest()
    assert first["requests"] == [
        {
            "id": f"alpine-distfile:v3.24:{filename_hash}",
            "url": ("https://distfiles.alpinelinux.org/distfiles/v3.24/demo-1.0.tar.xz"),
            "allowed_hosts": ["distfiles.alpinelinux.org"],
            "algorithm": "sha512",
            "digest": remote_digest,
            "expected_size": None,
            "max_bytes": source_plan.MAX_NATIVE_SOURCE_BYTES,
            "consumers": [
                "platform:linux/amd64:alpine:demo@1.0-r0",
                "platform:linux/arm64:alpine:demo@1.0-r0",
            ],
        }
    ]
    encoded = source_plan.canonical_json(first)
    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1
    contract = source_plan._source_store_contract()
    parsed = contract.strict_json_bytes(
        encoded,
        "test Alpine distfile plan",
        maximum=source_plan.MAX_PLAN_BYTES,
    )
    assert contract.validate_source_plan(parsed) == first


def test_alpine_distfile_plan_preserves_reviewed_dynamic_exception(
    tmp_path: Path,
) -> None:
    local_content = b"public key\n"
    local_digest = hashlib.sha512(local_content).hexdigest()
    remote_digest = "b" * 128
    apkbuild = (
        "for key in $keys; do\n"
        '  source="$source $key"\n'
        "done\n"
        f'sha512sums="\n{local_digest}  key.pub\n'
        f'{remote_digest}  upstream.tar.gz\n"\n'
    ).encode()
    archive = recipe_archive(
        "demo",
        apkbuild,
        files={"aports/main/demo/key.pub": local_content},
    )
    commit = "b" * 40
    recipes = {"demo": (commit, archive)}
    policy = minimal_alpine_policy(
        recipes,
        exceptions={
            f"demo@{commit}": {
                "allow_dynamic_sources": True,
                "rationale": "The reviewed recipe constructs a static local key list.",
            }
        },
    )

    plan = build_alpine_case(tmp_path, recipes, policy=policy)

    assert len(plan["requests"]) == 1
    assert plan["requests"][0]["digest"] == remote_digest
    assert plan["requests"][0]["url"].endswith("/upstream.tar.gz")
    assert "key.pub" not in plan["requests"][0]["url"]


def test_alpine_distfile_plan_cross_checks_native_policy_and_reuses_consumers(
    tmp_path: Path,
) -> None:
    digest = "c" * 128

    plan = build_native_alpine_case(
        tmp_path,
        recipe_digest=digest,
        reviewed_digest=digest,
    )

    assert plan["recipes"][0]["request_id"].startswith("native-source:alpine:")
    assert plan["requests"] == [
        {
            "id": (
                f"alpine-distfile:v3.22:{hashlib.sha256(b'demo-native-1.0.tar.xz').hexdigest()}"
            ),
            "url": ("https://distfiles.alpinelinux.org/distfiles/v3.22/demo-native-1.0.tar.xz"),
            "allowed_hosts": ["distfiles.alpinelinux.org"],
            "algorithm": "sha512",
            "digest": digest,
            "expected_size": 1234,
            "max_bytes": source_plan.MAX_NATIVE_SOURCE_BYTES,
            "consumers": [
                "platform:linux/amd64:native-owner:python:demo-python@1.0",
                "platform:linux/arm64:native-owner:python:demo-python@1.0",
            ],
        }
    ]


def test_alpine_distfile_plan_rejects_native_policy_digest_substitution(
    tmp_path: Path,
) -> None:
    with pytest.raises(source_plan.PlanError, match="distfiles differ from reviewed policy"):
        build_native_alpine_case(
            tmp_path,
            recipe_digest="c" * 128,
            reviewed_digest="d" * 128,
        )


def test_alpine_distfile_plan_rejects_unreviewed_dynamic_source_declaration(
    tmp_path: Path,
) -> None:
    apkbuild = (
        "for key in $keys; do\n"
        '  source="$source $key"\n'
        "done\n"
        f'sha512sums="\n{"a" * 128}  key.pub\n"\n'
    ).encode()
    archive = recipe_archive("demo", apkbuild)

    with pytest.raises(
        source_plan.PlanError,
        match=r"unsupported local APKBUILD source|literal source block",
    ):
        build_alpine_case(tmp_path, {"demo": ("c" * 40, archive)})


def test_alpine_distfile_plan_resolves_one_static_source_alias_variable(
    tmp_path: Path,
) -> None:
    digest = "a" * 128
    apkbuild = (
        "_nbver=6.4\n"
        'source="protocols-$_nbver::'
        'https://salsa.debian.org/md/netbase/-/raw/v${_nbver}/etc/protocols"\n'
        f'sha512sums="\n{digest}  protocols-6.4\n"\n'
    ).encode()
    archive = recipe_archive("demo", apkbuild)

    plan = build_alpine_case(tmp_path, {"demo": ("c" * 40, archive)})

    assert len(plan["requests"]) == 1
    assert plan["requests"][0]["url"].endswith("/protocols-6.4")
    assert plan["requests"][0]["digest"] == digest


def test_alpine_distfile_plan_resolves_static_pkgver_in_source_alias(
    tmp_path: Path,
) -> None:
    digest = "a" * 128
    apkbuild = (
        "pkgname=zstd\n"
        "pkgver=1.5.7\n"
        "pkgrel=2\n"
        'pkgdesc="Zstandard"\n'
        'subpackages="\n\t$pkgname-libs\n\t"\n'
        'source="zstd-$pkgver.tar.gz::'
        'https://github.com/facebook/zstd/archive/v$pkgver.tar.gz"\n'
        f'sha512sums="\n{digest}  zstd-1.5.7.tar.gz\n"\n'
    ).encode()
    archive = recipe_archive("zstd", apkbuild)

    plan = build_alpine_case(tmp_path, {"zstd": ("c" * 40, archive)})

    assert len(plan["requests"]) == 1
    assert plan["requests"][0]["url"].endswith("/zstd-1.5.7.tar.gz")
    assert plan["requests"][0]["digest"] == digest


@pytest.mark.parametrize(
    ("preamble", "message"),
    (
        ('pkgver="$(printf 1.5.7)"\n', "nonliteral static APKBUILD variable pkgver"),
        (
            "pkgver=1.5.7\npkgver=1.5.8\n",
            "ambiguous static APKBUILD variable pkgver",
        ),
        (
            "helper() {\npkgver=1.5.7\n}\n",
            "nonliteral static APKBUILD variable pkgver",
        ),
    ),
)
def test_alpine_distfile_plan_rejects_nonstatic_pkgver_in_source_alias(
    tmp_path: Path,
    preamble: str,
    message: str,
) -> None:
    apkbuild = (
        preamble + 'source="zstd-$pkgver.tar.gz::'
        'https://github.com/facebook/zstd/archive/v$pkgver.tar.gz"\n'
        + f'sha512sums="\n{"a" * 128}  zstd-1.5.7.tar.gz\n"\n'
    ).encode()
    archive = recipe_archive("zstd", apkbuild)

    with pytest.raises(source_plan.PlanError, match=message):
        build_alpine_case(tmp_path, {"zstd": ("c" * 40, archive)})


@pytest.mark.parametrize(
    ("assignment", "message"),
    (
        ("", "unresolved static APKBUILD variable _nbver"),
        ("_nbver=6.4\n_nbver=6.5\n", "ambiguous static APKBUILD variable _nbver"),
        ('_nbver="$(printf 6.4)"\n', "nonliteral static APKBUILD variable _nbver"),
        ("_nbver=6.4 # unreviewed shell text\n", "nonliteral static APKBUILD variable _nbver"),
        (
            "helper() {\n_nbver=6.4\n}\n",
            "nonliteral static APKBUILD variable _nbver",
        ),
    ),
)
def test_alpine_distfile_plan_rejects_unresolved_or_ambiguous_alias_variables(
    tmp_path: Path,
    assignment: str,
    message: str,
) -> None:
    apkbuild = (
        assignment + 'source="protocols-$_nbver::'
        'https://salsa.debian.org/md/netbase/-/raw/v$_nbver/etc/protocols"\n'
        + f'sha512sums="\n{"a" * 128}  protocols-6.4\n"\n'
    ).encode()
    archive = recipe_archive("demo", apkbuild)

    with pytest.raises(source_plan.PlanError, match=message):
        build_alpine_case(tmp_path, {"demo": ("c" * 40, archive)})


def test_alpine_distfile_plan_rejects_alias_assignment_after_source_use(
    tmp_path: Path,
) -> None:
    apkbuild = (
        'source="protocols-$_nbver::'
        'https://salsa.debian.org/md/netbase/-/raw/v$_nbver/etc/protocols"\n'
        "_nbver=6.4\n" + f'sha512sums="\n{"a" * 128}  protocols-6.4\n"\n'
    ).encode()
    archive = recipe_archive("demo", apkbuild)

    with pytest.raises(
        source_plan.PlanError,
        match="nonliteral static APKBUILD variable _nbver",
    ):
        build_alpine_case(tmp_path, {"demo": ("c" * 40, archive)})


@pytest.mark.parametrize(
    ("apkbuild", "message"),
    (
        (
            (
                "source=https://example.test/demo.tar.gz\n"
                f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
            ).encode(),
            "literal source block",
        ),
        (
            (
                'source="https://example.test/demo.tar.gz"\n'
                f'sha512sums="\n{"a" * 128} demo.tar.gz\n"\n'
            ).encode(),
            "checksum line",
        ),
        (
            (
                'source="https://example.test/one.tar.gz"\n'
                'source="https://example.test/two.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  one.tar.gz\n'
                f'{"b" * 128}  two.tar.gz\n"\n'
            ).encode(),
            r"repeats literal source blocks|literal source block",
        ),
        (
            (
                'source="http://example.test/demo.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
            ).encode(),
            "not HTTPS",
        ),
    ),
)
def test_alpine_distfile_plan_rejects_malformed_or_unsafe_source_blocks(
    tmp_path: Path,
    apkbuild: bytes,
    message: str,
) -> None:
    archive = recipe_archive("demo", apkbuild)

    with pytest.raises(source_plan.PlanError, match=message):
        build_alpine_case(tmp_path, {"demo": ("d" * 40, archive)})


def test_alpine_distfile_plan_rejects_unretained_or_mismatched_local_sources(
    tmp_path: Path,
) -> None:
    digest = hashlib.sha512(b"expected").hexdigest()
    apkbuild = f'source="local.patch"\nsha512sums="\n{digest}  local.patch\n"\n'.encode()
    missing = recipe_archive("demo", apkbuild)
    with pytest.raises(source_plan.PlanError, match="not retained exactly"):
        build_alpine_case(tmp_path / "missing", {"demo": ("e" * 40, missing)})

    wrong = recipe_archive(
        "demo",
        apkbuild,
        files={"aports/main/demo/local.patch": b"wrong"},
    )
    with pytest.raises(source_plan.PlanError, match="checksum mismatch"):
        build_alpine_case(tmp_path / "wrong", {"demo": ("e" * 40, wrong)})


def test_alpine_distfile_plan_requires_exact_reviewed_recipe_links(
    tmp_path: Path,
) -> None:
    apkbuild = (
        f'source="https://example.test/demo.tar.gz"\nsha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
    ).encode()
    link_path = "aports/main/demo/post-upgrade"
    target_path = "aports/main/demo/post-install"
    archive = recipe_archive(
        "demo",
        apkbuild,
        files={target_path: b"#!/bin/sh\n"},
        symlinks={link_path: "post-install"},
    )
    commit = "8" * 40
    recipes = {"demo": (commit, archive)}

    with pytest.raises(source_plan.PlanError, match="links differ from reviewed policy"):
        build_alpine_case(tmp_path / "unreviewed", recipes)

    policy = minimal_alpine_policy(
        recipes,
        exceptions={
            f"demo@{commit}": {
                "allowed_links": [
                    {
                        "path": link_path,
                        "target": target_path,
                        "type": "symlink",
                    }
                ],
                "rationale": "The exact maintainer-script alias is retained and reviewed.",
            }
        },
    )
    plan = build_alpine_case(tmp_path / "reviewed", recipes, policy=policy)
    assert len(plan["requests"]) == 1


@pytest.mark.parametrize(
    ("limit", "value", "message"),
    (
        ("MAX_RECIPE_ARCHIVE_MEMBERS", 0, "too many entries"),
        ("MAX_RECIPE_EXPANDED_BYTES", 1, "expanded size limit"),
        ("MAX_APKBUILD_BYTES", 1, "APKBUILD.*size limit"),
    ),
)
def test_alpine_distfile_recipe_parser_enforces_resource_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
    value: int,
    message: str,
) -> None:
    archive = recipe_archive(
        "demo",
        (
            'source="https://example.test/demo.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
        ).encode(),
    )
    monkeypatch.setattr(source_plan, limit, value)

    with pytest.raises(source_plan.PlanError, match=message):
        build_alpine_case(tmp_path, {"demo": ("6" * 40, archive)})


@pytest.mark.parametrize("mode", ("w:gz", "w:bz2", "w:xz"))
def test_alpine_distfile_recipe_parser_sanitizes_truncated_compressed_archives(
    tmp_path: Path,
    mode: Literal["w:gz", "w:bz2", "w:xz"],
) -> None:
    output = io.BytesIO()
    apkbuild = (
        f'source="https://example.test/demo.tar.gz"\nsha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
    ).encode()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, content in (
            ("aports/main/demo/APKBUILD", apkbuild),
            ("aports/main/demo/padding", b"x" * 100_000),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    complete = output.getvalue()
    truncated = complete[: len(complete) // 2]

    with pytest.raises(source_plan.PlanError, match="invalid recipe archive for demo"):
        build_alpine_case(tmp_path, {"demo": ("6" * 40, truncated)})


@pytest.mark.parametrize(
    ("write_mode", "read_mode"),
    (
        ("w:", "r:"),
        ("w:gz", "r:gz"),
        ("w:bz2", "r:bz2"),
        ("w:xz", "r:xz"),
    ),
)
def test_alpine_recipe_compression_modes_are_explicit_and_version_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_mode: Literal["w:", "w:gz", "w:bz2", "w:xz"],
    read_mode: Literal["r:", "r:gz", "r:bz2", "r:xz"],
) -> None:
    apkbuild = (
        f'source="https://example.test/demo.tar.gz"\nsha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
    ).encode()
    archive = recipe_archive("demo", apkbuild, mode=write_mode)
    observed_modes: list[str] = []
    real_open = source_plan.tarfile.open

    def record_mode(*args: Any, **kwargs: Any) -> Any:
        observed_modes.append(cast(str, kwargs.get("mode")))
        return real_open(*args, **kwargs)

    monkeypatch.setattr(source_plan.tarfile, "open", record_mode)

    plan = build_alpine_case(tmp_path, {"demo": ("7" * 40, archive)})

    assert len(plan["requests"]) == 1
    assert observed_modes == [read_mode]


@pytest.mark.parametrize(
    ("archive", "message"),
    (
        (b"\x28\xb5\x2f\xfduntrusted-zstd-frame", "unsupported zstd"),
        (b"\x50\x2a\x4d\x18untrusted-skippable-frame", "unsupported zstd"),
        (b"PK\x03\x04untrusted-unknown-archive", "unknown compression"),
    ),
)
def test_alpine_recipe_rejects_zstd_and_unknown_compression_before_tarfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    archive: bytes,
    message: str,
) -> None:
    def tarfile_forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("unsupported compression reached tarfile")

    monkeypatch.setattr(source_plan.tarfile, "open", tarfile_forbidden)

    with pytest.raises(source_plan.PlanError, match=message):
        build_alpine_case(tmp_path, {"demo": ("8" * 40, archive)})


def test_alpine_distfile_plan_detects_recipe_mutation_during_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = recipe_archive(
        "demo",
        (
            'source="https://example.test/demo.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
        ).encode(),
    )
    recipes = {"demo": ("5" * 40, archive)}
    policy = minimal_alpine_policy(recipes)
    policy_path = write_policy(tmp_path, policy)
    requests = direct_recipe_requests(policy, recipes)
    store, digest, size = write_direct_store(
        tmp_path,
        policy_path,
        requests,
        {requests[0]["id"]: archive},
    )
    object_path = store / "objects" / "sha256" / hashlib.sha256(archive).hexdigest()
    parse = source_plan._parse_recipe_distfiles

    def parse_then_mutate(content: bytes, need: Any) -> Any:
        parsed = parse(content, need)
        object_path.write_bytes(b"x" * len(content))
        return parsed

    monkeypatch.setattr(source_plan, "_parse_recipe_distfiles", parse_then_mutate)

    with pytest.raises(source_plan.PlanError, match="changed during recipe parsing"):
        source_plan.build_alpine_distfile_plan(
            policy_path,
            store,
            expected_parent_plan_sha256=digest,
            expected_parent_plan_size=size,
        )


def test_alpine_distfile_plan_rejects_conflicting_recipe_digests(
    tmp_path: Path,
) -> None:
    first = recipe_archive(
        "first",
        (
            'source="https://one.example.test/shared.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  shared.tar.gz\n"\n'
        ).encode(),
    )
    second = recipe_archive(
        "second",
        (
            'source="https://two.example.test/shared.tar.gz"\n'
            f'sha512sums="\n{"b" * 128}  shared.tar.gz\n"\n'
        ).encode(),
    )

    with pytest.raises(source_plan.PlanError, match="conflicting request binding"):
        build_alpine_case(
            tmp_path,
            {
                "first": ("1" * 40, first),
                "second": ("2" * 40, second),
            },
        )


def test_alpine_distfile_plan_rejects_cross_platform_recipe_consumer_swap(
    tmp_path: Path,
) -> None:
    first = recipe_archive(
        "first",
        (
            'source="https://one.example.test/first.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  first.tar.gz\n"\n'
        ).encode(),
    )
    second = recipe_archive(
        "second",
        (
            'source="https://two.example.test/second.tar.gz"\n'
            f'sha512sums="\n{"b" * 128}  second.tar.gz\n"\n'
        ).encode(),
    )
    recipes = {
        "first": ("1" * 40, first),
        "second": ("2" * 40, second),
    }
    policy = minimal_alpine_policy(
        recipes,
        platform_origins={
            "linux/amd64": ["first"],
            "linux/arm64": ["second"],
        },
    )

    def swap_consumers(requests: list[dict[str, Any]]) -> None:
        requests[0]["consumers"], requests[1]["consumers"] = (
            requests[1]["consumers"],
            requests[0]["consumers"],
        )

    with pytest.raises(source_plan.PlanError, match="swapped or stale recipe request"):
        build_alpine_case(
            tmp_path,
            recipes,
            policy=policy,
            mutate_requests=swap_consumers,
        )


def test_alpine_distfile_plan_rejects_wrong_caller_plan_binding(
    tmp_path: Path,
) -> None:
    archive = recipe_archive(
        "demo",
        (
            'source="https://example.test/demo.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
        ).encode(),
    )
    recipes = {"demo": ("f" * 40, archive)}
    policy = minimal_alpine_policy(recipes)
    policy_path = write_policy(tmp_path, policy)
    requests = direct_recipe_requests(policy, recipes)
    store, _digest, size = write_direct_store(
        tmp_path,
        policy_path,
        requests,
        {requests[0]["id"]: archive},
    )

    with pytest.raises(source_plan.PlanError, match=r"does not verify|trusted expected plan"):
        source_plan.build_alpine_distfile_plan(
            policy_path,
            store,
            expected_parent_plan_sha256="0" * 64,
            expected_parent_plan_size=size,
        )


def test_alpine_distfile_plan_cli_emits_one_canonical_line(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive = recipe_archive(
        "demo",
        (
            'source="https://example.test/demo.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
        ).encode(),
    )
    recipes = {"demo": ("9" * 40, archive)}
    policy = minimal_alpine_policy(recipes)
    policy_path = write_policy(tmp_path, policy)
    requests = direct_recipe_requests(policy, recipes)
    store, digest, size = write_direct_store(
        tmp_path,
        policy_path,
        requests,
        {requests[0]["id"]: archive},
    )

    result = source_plan.main(
        [
            "alpine-distfile-plan",
            "--policy",
            str(policy_path),
            "--direct-store",
            str(store),
            "--expected-parent-plan-sha256",
            digest,
            "--expected-parent-plan-size",
            str(size),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    parsed = json.loads(captured.out)
    assert parsed["kind"] == "alpine-distfiles"
    parent_plan_bytes = (store / "SOURCE-PLAN.json").read_bytes()
    parent_manifest_bytes = (store / "SOURCE-STORE.json").read_bytes()
    assert parsed["parent_plan"] == {
        "algorithm": "sha256",
        "digest": hashlib.sha256(parent_plan_bytes).hexdigest(),
        "size": len(parent_plan_bytes),
    }
    assert parsed["parent_manifest"] == {
        "algorithm": "sha256",
        "digest": hashlib.sha256(parent_manifest_bytes).hexdigest(),
        "size": len(parent_manifest_bytes),
    }
    assert captured.out.encode("ascii") == source_plan.canonical_json(parsed)


def test_alpine_distfile_plan_cli_can_publish_an_atomic_bounded_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive = recipe_archive(
        "demo",
        (
            'source="https://example.test/demo.tar.gz"\n'
            f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'
        ).encode(),
    )
    recipes = {"demo": ("9" * 40, archive)}
    policy = minimal_alpine_policy(recipes)
    policy_path = write_policy(tmp_path, policy)
    requests = direct_recipe_requests(policy, recipes)
    store, digest, size = write_direct_store(
        tmp_path,
        policy_path,
        requests,
        {requests[0]["id"]: archive},
    )
    output = tmp_path / "sandbox-output" / "alpine-plan.json"
    output.parent.mkdir()

    result = source_plan.main(
        [
            "alpine-distfile-plan",
            "--policy",
            str(policy_path),
            "--direct-store",
            str(store),
            "--expected-parent-plan-sha256",
            digest,
            "--expected-parent-plan-size",
            str(size),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == ""
    assert captured.err == ""
    encoded = output.read_bytes()
    assert encoded.endswith(b"\n")
    assert encoded == source_plan.canonical_json(json.loads(encoded))
    assert stat.S_IMODE(output.stat().st_mode) == 0o644
    assert not list(output.parent.glob(".alpine-plan.json.tmp-*"))


@pytest.mark.parametrize("attack", ("existing", "symlink-parent"))
def test_atomic_plan_output_rejects_existing_or_symlinked_destinations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    attack: str,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    parent = real_parent
    if attack == "symlink-parent":
        parent = tmp_path / "linked"
        parent.symlink_to(real_parent, target_is_directory=True)
    output = parent / "plan.json"
    if attack == "existing":
        output.write_bytes(b"do not replace")

    result = source_plan.main(
        [
            "direct-plan",
            "--policy",
            str(POLICY),
            "--uv-lock",
            str(UV_LOCK),
            "--source-revision",
            REVISION,
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "plan output" in captured.err
    if attack == "existing":
        assert output.read_bytes() == b"do not replace"
    else:
        assert not (real_parent / "plan.json").exists()

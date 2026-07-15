from __future__ import annotations

import importlib.util
import io
import json
import tarfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence = load_script("container_evidence")
readiness = load_script("release_readiness")


def tar_bytes(files: dict[str, bytes], *, links: dict[str, str] | None = None) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)
    return result.getvalue()


def apk_database(architecture: str = "x86_64") -> bytes:
    return (
        "P:busybox\n"
        "V:1.37.0-r1\n"
        f"A:{architecture}\n"
        "L:GPL-2.0-only\n"
        "o:busybox\n"
        "c:1111111111111111111111111111111111111111\n\n"
    ).encode()


def metadata(name: str, version: str, license_value: str = "MIT") -> bytes:
    return (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        f"License-Expression: {license_value}\n\n"
    ).encode()


def saved_image(path: Path) -> None:
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
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
    layer_names = ["blobs/sha256/" + "1" * 64, "blobs/sha256/" + "2" * 64]
    config_name = "blobs/sha256/" + "3" * 64
    outer = tar_bytes(
        {
            "manifest.json": json.dumps([{"Config": config_name, "Layers": layer_names}]).encode(),
            config_name: json.dumps(
                {
                    "config": {
                        "Labels": {
                            "org.opencontainers.image.revision": "a" * 40,
                            "org.opencontainers.image.version": "1.0",
                        }
                    }
                }
            ).encode(),
            layer_names[0]: first,
            layer_names[1]: second,
        }
    )
    path.write_bytes(outer)


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


def test_saved_image_inventory_tracks_whiteouts_and_all_layers(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("alpine", "busybox")]["aports_commit"] == "1" * 40
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "pip")]["effective"] is False
    assert inventory["image_revision"] == "a" * 40
    assert [layer["regular_file_count"] for layer in files["layers"]] == [3, 1]
    assert len(files["regular_files"]) == 4


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


def test_recipe_checksum_parser_does_not_execute_recipe() -> None:
    digest = "a" * 128
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": f'sha512sums="\n{digest}  demo.tar.gz\n"\n'.encode(),
            "aports/main/demo/local.patch": b"patch",
        }
    )
    checksums, local = evidence.recipe_checksums(recipe, "demo")
    assert checksums == {"demo.tar.gz": digest}
    assert local == {"APKBUILD", "local.patch"}


def test_recipe_checksum_parser_rejects_links() -> None:
    recipe = tar_bytes(
        {"aports/main/demo/APKBUILD": f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'.encode()},
        links={"aports/main/demo/escape": "../../secret"},
    )
    with pytest.raises(evidence.EvidenceError, match="unsafe archive link target"):
        evidence.recipe_checksums(recipe, "demo")


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


def test_fetch_rejects_a_redirect_away_from_https(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://example.com/source.tar.gz"

    monkeypatch.setattr(evidence.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        evidence.fetch("https://example.com/source.tar.gz", "a" * 64)


def test_policy_comparison_and_human_approval_are_separate() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = {
        "schema_version": 1,
        "platform": "linux/amd64",
        "components": [component],
    }
    policy: dict[str, Any] = {
        "schema_version": 1,
        "base_image_index_digest": "sha256:" + "b" * 64,
        "platforms": {"linux/amd64": [component]},
        "distribution_approval": {"approved": False},
        "license_resolutions": {
            "python:demo@1": {"expression": "MIT", "rationale": "Reviewed test fixture."}
        },
        "license_texts": [{"id": "MIT"}],
    }
    evidence.verify_inventory(inventory, policy, require_approval=False)
    with pytest.raises(evidence.EvidenceError, match="maintainer approval"):
        evidence.verify_inventory(inventory, policy, require_approval=True)

    policy["platforms"]["linux/amd64"][0] = {**component, "version": "2"}
    with pytest.raises(evidence.EvidenceError, match="differs from the reviewed policy"):
        evidence.verify_inventory(inventory, policy, require_approval=False)


def test_image_revision_and_version_must_match_source() -> None:
    revision = "a" * 40
    inventory = {"image_revision": revision, "image_version": "1.2.3"}
    evidence.verify_image_revision(inventory, version="1.2.3", source_revision=revision)
    with pytest.raises(evidence.EvidenceError, match="does not match source revision"):
        evidence.verify_image_revision(inventory, version="1.2.3", source_revision="b" * 40)
    with pytest.raises(evidence.EvidenceError, match="image version"):
        evidence.verify_image_revision(inventory, version="1.2.4", source_revision=revision)


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


def test_workflows_enforce_evidence_before_semantic_release_tags() -> None:
    release = Path(".github/workflows/release.yml").read_text()
    ci = Path(".github/workflows/ci.yml").read_text()

    assert "issues: read" in release
    assert "release_readiness.py" in release
    assert release.index("Build digest-bound distribution evidence") < release.index(
        "Add release tags to the verified image"
    )
    assert "--require-distribution-approval" in release
    assert "--require-image-revision" in release
    assert '--summary "${GITHUB_STEP_SUMMARY}"' in release
    assert "container-distribution-evidence" in release
    assert "evidence-predicate-amd64.json" in release
    assert "evidence-predicate-arm64.json" in release
    assert "Verify container evidence release assets" in release
    assert "${archive}.sha256" in release
    assert "${archive}.sigstore.json" in release
    assert ".subject_digest == $digest" in release
    assert ".artifact.filename == $filename" in release
    assert ".artifact.sha256 == $sha256" in release
    assert release.index("Verify container evidence release assets") < release.index(
        "Upload container distribution evidence"
    )
    assert "Download container distribution evidence" in release

    assert "container-distribution-evidence-${{ matrix.architecture }}" in ci
    assert '--platform "$PLATFORM"' in ci
    assert "--require-image-revision" in ci
    assert "--allow-config-digest-subject" in ci
    assert "Upload container distribution evidence\n        if: always()" in ci


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
        require_distribution_approval=True,
        require_image_revision=True,
    )

    evidence.command_bundle(args)

    assert observed["require_approval"] is True
    assert observed["require_image_revision"] is True

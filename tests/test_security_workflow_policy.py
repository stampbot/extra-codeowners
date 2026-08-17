"""Regression tests for GitHub Actions trust and publication boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SECURITY_WORKFLOWS = (
    "dco.yml",
    "codeql.yml",
    "dependency-review.yml",
    "workflow-security.yml",
)
PINNED_ACTION_WORKFLOWS = (
    *SECURITY_WORKFLOWS,
    "ci.yml",
    "cold-container.yml",
    "release.yml",
)
PULL_REQUEST_TYPES = "    types: [opened, reopened, synchronize, edited]"
FULL_SHA_ACTION = re.compile(r"uses: [^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")
GIT = shutil.which("git")
BASH = shutil.which("bash")


def _top_level_event(source: str, event: str) -> str:
    """Return one event body without treating YAML 1.1 ``on`` as a boolean."""
    _, separator, tail = source.partition("\non:\n")
    assert separator, "missing workflow triggers"
    trigger_lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith("  "):
            break
        trigger_lines.append(line)
    triggers = "\n".join(trigger_lines)
    marker = f"  {event}:\n"
    _, separator, tail = triggers.partition(marker)
    assert separator, f"missing {event!r} trigger"
    lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith("    "):
            break
        lines.append(line)
    return "\n".join(lines)


def _workflow_jobs(source: str) -> dict[str, str]:
    """Return top-level job bodies from one workflow source file."""
    _, separator, jobs_source = source.partition("\njobs:\n")
    assert separator, "missing jobs mapping"
    matches = list(re.finditer(r"(?m)^  (?P<name>[A-Za-z_][A-Za-z0-9_-]*):\n", jobs_source))
    assert matches, "workflow has no jobs"
    return {
        match.group("name"): jobs_source[
            match.end() : matches[index + 1].start() if index + 1 < len(matches) else None
        ]
        for index, match in enumerate(matches)
    }


def _job_permissions(job: str) -> dict[str, str] | None:
    """Return an explicit job permission map, or ``None`` when it inherits."""
    marker = "    permissions:\n"
    _, separator, tail = job.partition(marker)
    if not separator:
        return None
    permissions: dict[str, str] = {}
    for line in tail.splitlines():
        match = re.fullmatch(r"      (?P<scope>[a-z-]+): (?P<access>read|write|none)", line)
        if match is None:
            break
        scope = match.group("scope")
        assert scope not in permissions, f"duplicate permission scope: {scope}"
        permissions[scope] = match.group("access")
    assert permissions, "job has an empty explicit permissions mapping"
    return permissions


def _named_step(job: str, name: str) -> str:
    """Return one named step body from a top-level job body."""
    marker = f"      - name: {name}\n"
    _, separator, tail = job.partition(marker)
    assert separator, f"missing {name!r} step"
    next_step = re.search(r"(?m)^      - (?:name|uses):", tail)
    return tail[: next_step.start()] if next_step is not None else tail


def _run_script(source: str, step_name: str) -> str:
    """Extract the literal Bash program from one named workflow step."""
    step = f"      - name: {step_name}\n"
    _, separator, tail = source.partition(step)
    assert separator, f"missing {step_name!r} step"
    _, separator, tail = tail.partition("        run: |\n")
    assert separator, f"missing run script for {step_name!r}"
    lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    return "\n".join(lines)


@pytest.mark.parametrize("workflow_name", SECURITY_WORKFLOWS)
def test_security_workflows_run_for_every_pull_request_base_and_retarget(
    workflow_name: str,
) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert "pull_request_target:" not in source
    pull_request = _top_level_event(source, "pull_request")
    assert "branches:" not in pull_request
    assert PULL_REQUEST_TYPES in pull_request


@pytest.mark.parametrize("workflow_name", SECURITY_WORKFLOWS)
def test_security_workflows_do_not_expose_secrets_or_broad_write_permissions(
    workflow_name: str,
) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert "secrets:" not in source
    assert "id-token: write" not in source
    assert "contents: write" not in source
    assert "pull-requests: write" not in source
    assert "packages: write" not in source
    assert "environment:" not in source
    assert "permissions:\n  contents: read" in source
    if workflow_name != "codeql.yml":
        assert "security-events: write" not in source


def test_codeql_jobs_request_only_source_reads_and_result_upload() -> None:
    source = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
    jobs = _workflow_jobs(source)
    expected = {"actions": "read", "contents": "read", "security-events": "write"}

    assert set(jobs) == {"analyze", "analyze-trusted"}
    assert "if: github.event_name == 'pull_request'" in jobs["analyze"]
    assert "if: github.event_name != 'pull_request'" in jobs["analyze-trusted"]
    assert _job_permissions(jobs["analyze"]) == expected
    assert _job_permissions(jobs["analyze-trusted"]) == expected
    assert re.findall(r"(?m)^      ([a-z-]+): write$", source) == [
        "security-events",
        "security-events",
    ]


@pytest.mark.parametrize("workflow_name", PINNED_ACTION_WORKFLOWS)
def test_actions_are_immutable_and_checkouts_do_not_persist_credentials(
    workflow_name: str,
) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    for line in source.splitlines():
        if "uses:" in line and "uses: ./" not in line:
            assert FULL_SHA_ACTION.search(line.strip()), f"mutable action reference: {line}"
    assert source.count("persist-credentials: false") == source.count("actions/checkout@")


@pytest.mark.parametrize("workflow_name", SECURITY_WORKFLOWS)
def test_security_workflows_bound_execution(workflow_name: str) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert "concurrency:" in source
    assert "cancel-in-progress: true" in source
    assert "timeout-minutes:" in source


@pytest.mark.parametrize("workflow_name", ("codeql.yml", "workflow-security.yml"))
def test_trusted_push_trigger_remains_main_only(workflow_name: str) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert _top_level_event(source, "push") == "    branches:\n      - main"


def test_ci_keeps_pr_jobs_read_only_and_release_authority_push_gated() -> None:
    source = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    jobs = _workflow_jobs(source)

    assert set(jobs) == {
        "lint",
        "test",
        "package",
        "docs",
        "helm",
        "container",
        "required",
        "release",
    }
    assert "pull_request_target:" not in source
    assert _top_level_event(source, "pull_request") == "    branches:\n      - main"
    assert "permissions:\n  contents: read\n" in source
    assert all(_job_permissions(job) is None for name, job in jobs.items() if name != "release")
    assert _job_permissions(jobs["release"]) == {
        "artifact-metadata": "write",
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
        "packages": "write",
    }
    assert "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" in jobs["release"]
    assert "needs: required" in jobs["release"]
    assert "uses: ./.github/workflows/release.yml" in jobs["release"]

    for forbidden in (
        "docker/login-action@",
        "helm push ",
        "cosign sign",
        "gh release create",
        "push-by-digest=true",
    ):
        assert forbidden not in source
    assert not re.search(r"(?m)^\s+push:\s*true(?:\s*#.*)?$", source)
    assert "docker/build-push-action@" in jobs["container"]
    assert "          push: false\n" in jobs["container"]


def test_ci_required_summary_is_stable_and_fail_closed() -> None:
    source = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    required = _workflow_jobs(source)["required"]

    assert required.startswith("    name: Required\n")
    assert "    if: ${{ always() }}\n" in required
    for dependency in ("lint", "test", "package", "docs", "helm", "container"):
        assert f"      - {dependency}\n" in required
    assert "RESULTS: ${{ join(needs.*.result, ' ') }}" in required
    assert 'test "${result}" = success' in required
    assert "continue-on-error:" not in required


def test_release_is_reusable_only_and_inherits_the_tested_main_revision() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    trigger = source.split("\npermissions:\n", 1)[0]
    plan = _workflow_jobs(source)["plan"]

    assert trigger.endswith("on:\n  workflow_call:\n")
    for forbidden in (
        "  pull_request:\n",
        "  pull_request_target:\n",
        "  push:\n",
        "  schedule:\n",
        "  workflow_dispatch:\n",
        "  workflow_run:\n",
    ):
        assert forbidden not in trigger

    assert "SOURCE_REVISION: ${{ github.sha }}" in plan
    assert 'git merge-base --is-ancestor "${revision}" origin/main' in plan


def test_out_of_order_main_runs_coalesce_only_after_a_descendant_release_completes() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    plan = jobs["plan"]
    require_main = _named_step(plan, "Require a superseding release on main")
    detect = _named_step(plan, "Detect a completed release")
    complete = _named_step(jobs["complete"], "Require new or previously completed release")

    assert "superseded: ${{ steps.plan.outputs.superseded }}" in plan
    assert 'git rev-parse --verify "refs/tags/${TAG}^{commit}"' in require_main
    assert 'git merge-base --is-ancestor "${SOURCE_REVISION}" "${superseding_revision}"' in (
        require_main
    )
    assert 'git merge-base --is-ancestor "${superseding_revision}" origin/main' in require_main
    assert "SUPERSEDED: ${{ steps.plan.outputs.superseded }}" in detect
    assert 'if [[ "${SUPERSEDED}" == true ]]' in detect
    assert "A descendant run allocated %s but did not complete" in detect
    assert "Rerun that newer workflow" in detect
    assert "needs.plan.outputs.superseded != 'true'" in jobs["verify-existing"]
    assert "SUPERSEDED: ${{ needs.plan.outputs.superseded }}" in complete
    superseded_case = complete.split('if [[ "${SUPERSEDED}" == true ]]', 1)[1].split(
        'elif [[ "${ALREADY_RELEASED}" == true ]]', 1
    )[0]
    assert 'test "${ALREADY_RELEASED}" = true' in superseded_case
    for result in ("PACKAGE_RESULT", "CHART_RESULT", "IMAGE_RESULT", "PUBLISH_RESULT"):
        assert f'test "${{{result}}}" = skipped' in superseded_case
    assert 'test "${VERIFY_RESULT}" = skipped' in superseded_case


def test_release_complete_job_fails_closed_for_each_valid_job_topology() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    complete = _named_step(jobs["complete"], "Require new or previously completed release")

    existing_case = complete.split('elif [[ "${ALREADY_RELEASED}" == true ]]', 1)[1].split(
        "else", 1
    )[0]
    for result in ("PACKAGE_RESULT", "CHART_RESULT", "IMAGE_RESULT", "PUBLISH_RESULT"):
        assert f'test "${{{result}}}" = skipped' in existing_case
    assert 'test "${VERIFY_RESULT}" = success' in existing_case

    new_case = complete.rsplit("else", 1)[1].split("fi", 1)[0]
    for result in ("PACKAGE_RESULT", "CHART_RESULT", "IMAGE_RESULT", "PUBLISH_RESULT"):
        assert f'test "${{{result}}}" = success' in new_case
    assert 'test "${VERIFY_RESULT}" = skipped' in new_case


def test_release_write_permissions_are_limited_to_build_and_publish_jobs() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    jobs = _workflow_jobs(source)

    assert "permissions:\n  contents: read\n" in source
    assert _job_permissions(jobs["image"]) == {"contents": "read", "packages": "write"}
    assert _job_permissions(jobs["publish"]) == {
        "artifact-metadata": "write",
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
        "packages": "write",
    }
    for name, job in jobs.items():
        if name not in {"image", "publish"}:
            assert _job_permissions(job) is None, f"{name} unexpectedly overrides permissions"

    privileged = {
        name for name, job in jobs.items() if re.search(r"(?m)^      [a-z-]+: write$", job)
    }
    assert privileged == {"image", "publish"}
    assert "      - image\n" in jobs["publish"]
    assert "pull_request" not in source.split("\npermissions:\n", 1)[0]


def test_release_creates_an_immutable_tag_without_update_or_delete_paths() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    publish = _workflow_jobs(source)["publish"]
    tag = _named_step(publish, "Create immutable Git tag")

    assert 'git show-ref --verify --quiet "refs/tags/${TAG}"' in tag
    assert 'git cat-file -t "refs/tags/${TAG}"' in tag
    assert 'git rev-parse --verify "refs/tags/${TAG}^{commit}"' in tag
    assert "Existing release ref %s is not an annotated tag." in tag
    assert 'if [[ "${existing}" != "${REVISION}" ]]' in tag
    assert "Tag %s already points to %s, not %s." in tag
    assert '--method POST "repos/${GITHUB_REPOSITORY}/git/tags"' in tag
    assert '--method POST "repos/${GITHUB_REPOSITORY}/git/refs"' in tag
    assert '-f ref="refs/tags/${TAG}"' in tag
    for forbidden in ("--method PATCH", "--method DELETE", "git push", "--force"):
        assert forbidden not in tag
    assert "gh release create" in publish
    assert "--verify-tag" in publish


def test_release_pushes_native_digests_before_assembling_the_manifest() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    image = _named_step(jobs["image"], "Build and push native image by digest")
    publish = _named_step(jobs["publish"], "Publish or verify multiarch image")

    assert "push-by-digest=true" in image
    assert "name-canonical=true" in image
    assert "push=true" in image
    assert "docker buildx imagetools create" not in jobs["image"]
    assert "build-index-${ARCHITECTURE}.txt" in jobs["image"]
    assert 'platform_digest="$(' in jobs["image"]
    assert 'amd64_build_index="$(<release/image/amd64/build-index-amd64.txt)"' in publish
    assert 'arm64_build_index="$(<release/image/arm64/build-index-arm64.txt)"' in publish
    assert 'amd64_digest="$(<release/image/amd64/digest-amd64.txt)"' in publish
    assert 'arm64_digest="$(<release/image/arm64/digest-arm64.txt)"' in publish
    assert "docker buildx imagetools create" in publish
    assert '"${IMAGE}@${amd64_build_index}"' in publish
    assert '"${IMAGE}@${arm64_build_index}"' in publish
    assert '--tag "${reference}"' in publish
    assert "linux/amd64" in publish and "linux/arm64" in publish

    assert "${{ env.IMAGE }}@${{ steps.build.outputs.digest }}" in jobs["image"]
    assert jobs["publish"].index("Publish or verify multiarch image") < jobs["publish"].index(
        "Attest multiarch image"
    )


def test_release_state_lookups_retry_unavailable_apis_and_treat_only_404_as_missing() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    previous = _named_step(jobs["plan"], "Require the previous release to be complete")
    current = _named_step(jobs["plan"], "Detect a completed release")
    create = _named_step(jobs["publish"], "Create GitHub release")
    verify = _named_step(jobs["verify-existing"], "Verify published release surfaces")

    for lookup in (previous, current, create):
        assert "gh api --include" in lookup
        assert r"draft=\(.draft);immutable=\(.immutable)" in lookup
        assert "'draft=false;immutable=true'" in lookup
        assert "'draft=false;immutable=false'" in lookup
        assert "for attempt in 1 2 3" in lookup
        assert '[[ "${status}" == 404 ]]' in lookup
        assert '"${status:-unavailable}"' in lookup
        assert "|| true" not in lookup
        assert "2>/dev/null" not in lookup

    assert 'if [[ -z "${PREVIOUS_TAG}" ]]' in previous
    assert 'if [[ "${previous_state}" != published ]]' in previous
    assert "LEGACY_MUTABLE_BASELINE: v0.1.0-alpha.7" in previous
    assert '"${PREVIOUS_TAG}" == "${LEGACY_MUTABLE_BASELINE}"' in previous
    assert "Accepting legacy mutable baseline" in previous
    assert "repair it before advancing" in previous
    assert "draft|missing" in current
    assert "published but mutable" in current
    assert "draft) gh release delete" in create
    assert "published without immutability" in create
    assert 'gh release create "${TAG}" --draft' in create
    assert 'gh release upload "${TAG}" "${artifacts[@]}"' in create
    assert 'gh release edit "${TAG}" --draft=false' in create
    assert create.index("gh release create") < create.index("gh release upload")
    assert create.index("gh release upload") < create.index("gh release edit")
    assert "verify_published_release" in create
    assert "for attempt in 1 2 3" in create
    assert ".draft == false and" in create
    assert ".immutable == true and" in create
    assert ".prerelease == $prerelease" in create
    assert "published)" in create
    published_retry = "verify_published_release\n              exit 0"
    assert create.index("published)") < create.index(published_retry)
    assert create.rindex("gh release edit") < create.rindex("verify_published_release")
    assert ".draft == false and .immutable == true" in verify
    assert "repos/${GITHUB_REPOSITORY}/immutable-releases" not in jobs["plan"]


def test_release_publication_retry_verifies_the_completed_release_from_this_run() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    create = _named_step(jobs["publish"], "Create GitHub release")

    assert 'gh release download "${TAG}"' in create
    assert '--repo "${GITHUB_REPOSITORY}"' in create
    assert "release artifacts have duplicate names" in create
    assert "release artifact is missing or empty" in create
    assert "Sigstore bundle is not a JSON object" in create
    assert create.index("release artifacts have duplicate names") < create.index(
        'gh release create "${TAG}" --draft'
    )
    assert "([.assets[].name] | length == (unique | length))" in create
    assert '(.digest | test("^sha256:[0-9a-f]{64}$"))' in create
    assert 'release["assets"]' in create
    assert "collections.Counter(api_names) != expected_names" in create
    assert "expected_names = collections.Counter(local.keys())" in create
    assert "collections.Counter(remote.keys()) != expected_names" in create
    assert 'published.stat().st_size != asset["size"]' in create
    assert 'digest != asset["digest"]' in create
    assert 'name.endswith(".sigstore.json")' in create
    assert 'json.loads(published.read_text(encoding="utf-8"))' in create
    assert "published.read_bytes() != local[name].read_bytes()" in create
    assert "Release %s was published while this run was active" not in create

    published_case = create.split("published)", 1)[1].split(";;", 1)[0]
    assert "verify_published_release" in published_case
    assert "gh release delete" not in published_case
    assert "gh release edit" not in published_case

    first_publish = create.rsplit('gh release edit "${TAG}" --draft=false', 1)[1]
    assert "verify_published_release" in first_publish


def _release_asset_metadata(name: str, contents: bytes) -> dict[str, object]:
    return {
        "name": name,
        "size": len(contents),
        "digest": f"sha256:{hashlib.sha256(contents).hexdigest()}",
    }


def _run_published_release_recovery(
    tmp_path: Path,
    *,
    local_assets: dict[str, bytes],
    remote_assets: dict[str, bytes],
    api_assets: list[dict[str, object]] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Create GitHub release")
    published_json = tmp_path / "published-release.json"
    published_assets = tmp_path / "published-release-assets"
    script = script.replace(
        "/tmp/published-release.json",  # noqa: S108 - replaces workflow-owned path
        str(published_json),
    )
    script = script.replace(
        "/tmp/published-release-assets",  # noqa: S108 - replaces workflow-owned path
        str(published_assets),
    )

    repository = tmp_path / "repository"
    release = repository / "release"
    release.mkdir(parents=True)
    for name, contents in local_assets.items():
        target = release / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)

    remote = tmp_path / "remote-assets"
    remote.mkdir()
    for name, contents in remote_assets.items():
        target = remote / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)

    release_record = {
        "tag_name": "v0.1.0-alpha.8",
        "draft": False,
        "immutable": True,
        "prerelease": True,
        "assets": api_assets
        if api_assets is not None
        else [_release_asset_metadata(name, contents) for name, contents in remote_assets.items()],
    }
    release_record_path = tmp_path / "release-record.json"
    release_record_path.write_text(json.dumps(release_record), encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    operation_log = tmp_path / "gh-operations.log"
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        """#!/usr/bin/env python3
import os
import shutil
import sys
from pathlib import Path

arguments = sys.argv[1:]
with Path(os.environ["FAKE_GH_LOG"]).open("a", encoding="utf-8") as log:
    print(" ".join(arguments), file=log)
if arguments[0] == "api":
    if "--include" in arguments:
        print("HTTP/2 200")
        print()
        print("draft=false;immutable=true")
    else:
        print(Path(os.environ["FAKE_GH_RELEASE"]).read_text(encoding="utf-8"))
elif arguments[:2] == ["release", "download"]:
    destination = Path(arguments[arguments.index("--dir") + 1])
    remote = Path(os.environ["FAKE_GH_REMOTE"])
    destination.mkdir(parents=True, exist_ok=True)
    for source in remote.rglob("*"):
        if source.is_file():
            target = destination / source.relative_to(remote)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
else:
    print(f"unexpected mutating gh command: {arguments}", file=sys.stderr)
    raise SystemExit(97)
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    fake_sleep = fake_bin / "sleep"
    fake_sleep.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    fake_sleep.chmod(0o755)

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed script
        [BASH, "-c", script],
        cwd=repository,
        env=os.environ
        | {
            "FAKE_GH_LOG": str(operation_log),
            "FAKE_GH_RELEASE": str(release_record_path),
            "FAKE_GH_REMOTE": str(remote),
            "GH_TOKEN": "unused",
            "GITHUB_REPOSITORY": "example/extra-codeowners",
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            "PRERELEASE": "true",
            "PREVIOUS_TAG": "v0.1.0-alpha.7",
            "TAG": "v0.1.0-alpha.8",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    operations = operation_log.read_text(encoding="utf-8").splitlines()
    return result, operations


@pytest.mark.skipif(BASH is None, reason="Bash is required to exercise the workflow script")
def test_published_release_recovery_accepts_matching_immutable_release(
    tmp_path: Path,
) -> None:
    local = {
        "extra_codeowners-0.1.0a8-py3-none-any.whl": b"wheel artifact\n",
        "image.sigstore.json": b'{"source": "current run"}\n',
    }
    remote = local | {"image.sigstore.json": b'{"source": "published release"}\n'}

    result, operations = _run_published_release_recovery(
        tmp_path,
        local_assets=local,
        remote_assets=remote,
    )

    assert result.returncode == 0, result.stderr
    assert any(operation.startswith("release download ") for operation in operations)
    assert not any(
        operation.startswith(
            ("release create ", "release edit ", "release delete ", "release upload ")
        )
        for operation in operations
    )


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    (
        ("wrong", "does not match this run"),
        ("missing", "API asset names do not match this run"),
        ("duplicate", "Release postcondition attempt 3 is incomplete or inconsistent"),
        ("empty", "Release postcondition attempt 3 is incomplete or inconsistent"),
        ("digest", "has the wrong digest"),
    ),
)
@pytest.mark.skipif(BASH is None, reason="Bash is required to exercise the workflow script")
def test_published_release_recovery_rejects_inconsistent_assets(
    failure: str,
    expected_error: str,
    tmp_path: Path,
) -> None:
    local = {
        "extra_codeowners-0.1.0a8-py3-none-any.whl": b"wheel artifact\n",
        "image.sigstore.json": b'{"source": "current run"}\n',
    }
    remote = local | {"image.sigstore.json": b'{"source": "published release"}\n'}
    api_assets: list[dict[str, object]] | None = None
    if failure == "wrong":
        remote["extra_codeowners-0.1.0a8-py3-none-any.whl"] = b"other artifact\n"
    elif failure == "missing":
        remote.pop("extra_codeowners-0.1.0a8-py3-none-any.whl")
    elif failure == "duplicate":
        metadata = _release_asset_metadata(
            "extra_codeowners-0.1.0a8-py3-none-any.whl",
            remote["extra_codeowners-0.1.0a8-py3-none-any.whl"],
        )
        api_assets = [
            metadata,
            metadata,
            _release_asset_metadata("image.sigstore.json", remote["image.sigstore.json"]),
        ]
    elif failure == "empty":
        remote["extra_codeowners-0.1.0a8-py3-none-any.whl"] = b""
    elif failure == "digest":
        api_assets = [_release_asset_metadata(name, contents) for name, contents in remote.items()]
        api_assets[0]["digest"] = f"sha256:{'0' * 64}"
    else:  # pragma: no cover - the parametrization is exhaustive
        raise AssertionError(f"unknown failure case: {failure}")

    result, operations = _run_published_release_recovery(
        tmp_path,
        local_assets=local,
        remote_assets=remote,
        api_assets=api_assets,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert not any(
        operation.startswith(
            ("release create ", "release edit ", "release delete ", "release upload ")
        )
        for operation in operations
    )


def test_release_registry_probes_fail_closed_and_verify_immutable_digests() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    image = _named_step(jobs["publish"], "Publish or verify multiarch image")
    chart = _named_step(jobs["publish"], "Publish or verify Helm chart")

    for probe in (image, chart):
        assert "for attempt in 1 2 3" in probe
        assert "return 44" in probe
        assert "probe_status != 44" in probe
        assert "2>/dev/null" not in probe

    assert 'grep -Fxq "ERROR: ${reference}: not found"' in image
    assert "retry docker buildx imagetools create" in image
    assert 'imagetools inspect --raw "${IMAGE}@${digest}"' in image
    assert 'if [[ "${published_digest}" != "${expected_digest}" ]]' in image
    assert "Rerun failed jobs from the original workflow run" in image
    assert '"org.opencontainers.image.revision"' in image
    assert '"org.opencontainers.image.version"' in image
    assert '"${digest}" >release/image/image-reference.txt' in image

    assert 'grep -Fq "${plain_reference}:${VERSION}: not found"' in chart
    assert 'retry helm push "${chart}" "${registry}"' in chart
    assert "retry download_chart" in chart
    assert "cmp --silent" in chart
    assert '"${chart}"' in chart
    assert "does not contain this run" in chart
    assert "--format '{{json .Manifest}}'" in chart
    assert 'chart_digest="$(jq -er .digest /tmp/chart-manifest.json)"' in chart
    assert 'retry cosign sign --yes "${plain_reference}@${chart_digest}"' in chart
    assert '"${plain_reference}:${VERSION}"' not in chart.split("cosign sign", 1)[-1]
    assert ">release/chart/chart-reference.txt" in chart


def test_completed_release_verification_covers_identity_and_required_assets() -> None:
    jobs = _workflow_jobs((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    verify = _named_step(jobs["verify-existing"], "Verify published release surfaces")

    assert 'git cat-file -t "refs/tags/${TAG}"' in verify
    assert 'git rev-parse --verify "refs/tags/${TAG}^{commit}"' in verify
    assert ".draft == false and .immutable == true and .prerelease == $prerelease" in verify
    assert 'gh release download "${TAG}"' in verify
    assert "--clobber" in verify
    for asset in (
        "extra_codeowners-${PYTHON_VERSION}-py3-none-any.whl",
        "extra_codeowners-${PYTHON_VERSION}.tar.gz",
        "extra-codeowners-${VERSION}.tgz",
        "chart-reference.txt",
        "build-index-amd64.txt",
        "build-index-arm64.txt",
        "digest-amd64.txt",
        "digest-arm64.txt",
        "image-reference.txt",
        "vulnerability-report-amd64.json",
        "vulnerability-report-arm64.json",
    ):
        assert asset in verify
    assert 'test "${published_digest}" = "${released_digest}"' in verify
    assert 'test "$(<release-assets/image-reference.txt)" = "${IMAGE}@${image_digest}"' in verify
    assert 'grep -Fxq "version: ${VERSION}"' in verify
    assert 'grep -Fxq "appVersion: ${VERSION}"' in verify
    assert "release-assets/chart-reference.txt" in verify
    assert 'retry helm pull "oci://${chart_reference}"' in verify
    assert '"release-assets/extra-codeowners-${VERSION}.tgz"' in verify


def test_dco_uses_the_event_base_and_head_for_its_commit_range() -> None:
    source = (WORKFLOWS / "dco.yml").read_text(encoding="utf-8")

    assert "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in source
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in source
    assert 'git rev-list "${BASE_SHA}..${HEAD_SHA}" --' in source
    assert 'git cat-file -e "${BASE_SHA}^{commit}"' in source
    assert 'git cat-file -e "${HEAD_SHA}^{commit}"' in source
    assert "${#commits[@]} != 10#$PR_COMMIT_COUNT" in source


def _git(repo: Path, *arguments: str) -> str:
    assert GIT is not None
    result = subprocess.run(  # noqa: S603 - arguments are fixed by each test
        [GIT, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.mark.parametrize("superseding_branch", ("main", "side"))
@pytest.mark.skipif(BASH is None, reason="Bash is required to exercise the workflow script")
def test_superseding_release_must_be_on_main(superseding_branch: str, tmp_path: Path) -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Require a superseding release on main")
    repo = tmp_path / "repository"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "Release Workflow Tests")
    _git(repo, "config", "user.email", "release-workflow@example.invalid")
    marker = repo / "history.txt"
    marker.write_text("source\n", encoding="utf-8")
    _git(repo, "add", "history.txt")
    _git(repo, "commit", "-m", "chore: source revision")
    source_revision = _git(repo, "rev-parse", "HEAD")
    if superseding_branch == "side":
        _git(repo, "checkout", "-b", "side")
    marker.write_text("source\nsuperseding\n", encoding="utf-8")
    _git(repo, "add", "history.txt")
    _git(repo, "commit", "-m", "fix: superseding revision")
    superseding_revision = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", "-a", "v0.1.0-alpha.2", "-m", "test release")
    main_revision = source_revision if superseding_branch == "side" else superseding_revision
    _git(repo, "update-ref", "refs/remotes/origin/main", main_revision)
    _git(repo, "checkout", "--detach", source_revision)

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed script
        [BASH, "-c", script],
        cwd=repo,
        env=os.environ
        | {
            "SOURCE_REVISION": source_revision,
            "SUPERSEDED": "true",
            "TAG": "v0.1.0-alpha.2",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    if superseding_branch == "main":
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "is not on main" in result.stderr


def _dco_environment(base_sha: str, head_sha: str, commit_count: int) -> dict[str, str]:
    return os.environ | {
        "BASE_REPOSITORY_ID": "1",
        "BASE_SHA": base_sha,
        "GH_TOKEN": "unused",
        "HEAD_REF": "test/stacked-child",
        "HEAD_REPOSITORY_ID": "1",
        "HEAD_SHA": head_sha,
        "PR_AUTHOR_ID": "2",
        "PR_AUTHOR_LOGIN": "test-contributor",
        "PR_AUTHOR_TYPE": "User",
        "PR_COMMIT_COUNT": str(commit_count),
        "REPOSITORY": "example/extra-codeowners",
        "REPOSITORY_ID": "1",
    }


def _stacked_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repository"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "Test Contributor")
    _git(repo, "config", "user.email", "test-contributor@example.com")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "base.txt")
    _git(repo, "commit", "-m", "test: add stacked base", "-s")
    base_sha = _git(repo, "rev-parse", "HEAD")
    (repo / "child.txt").write_text("child\n", encoding="utf-8")
    _git(repo, "add", "child.txt")
    _git(repo, "commit", "-m", "test: add stacked child", "-s")
    return repo, base_sha, _git(repo, "rev-parse", "HEAD")


@pytest.mark.skipif(BASH is None, reason="Bash is required to exercise the workflow script")
def test_dco_script_accepts_an_exact_stacked_range(tmp_path: Path) -> None:
    source = (WORKFLOWS / "dco.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Verify every commit sign-off")
    repo, base_sha, head_sha = _stacked_repository(tmp_path)

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed script
        [BASH, "-c", script],
        cwd=repo,
        env=_dco_environment(base_sha, head_sha, 1),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ("missing-base", "commit-count"))
@pytest.mark.skipif(BASH is None, reason="Bash is required to exercise the workflow script")
def test_dco_script_fails_closed_when_the_range_cannot_be_proven(
    failure: str, tmp_path: Path
) -> None:
    source = (WORKFLOWS / "dco.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Verify every commit sign-off")
    repo, base_sha, head_sha = _stacked_repository(tmp_path)
    if failure == "missing-base":
        base_sha = "f" * 40
    commit_count = 2 if failure == "commit-count" else 1

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed script
        [BASH, "-c", script],
        cwd=repo,
        env=_dco_environment(base_sha, head_sha, commit_count),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    if failure == "missing-base":
        assert "is not an available commit" in result.stderr
    else:
        assert "does not match enumerated range count" in result.stderr


def test_dependency_review_uses_the_pull_request_delta_without_fixed_refs() -> None:
    source = (WORKFLOWS / "dependency-review.yml").read_text(encoding="utf-8")

    assert "actions/dependency-review-action@" in source
    assert "base-ref:" not in source
    assert "head-ref:" not in source
    assert "retry-on-snapshot-warnings: true" in source
    assert "retry-on-snapshot-warnings-timeout: 120" in source
    assert "x-github-dependency-graph-snapshot-warnings" in source.lower()
    assert "Dependency graph comparison is incomplete" in source


def test_workflow_security_keeps_every_expected_gate() -> None:
    source = (WORKFLOWS / "workflow-security.yml").read_text(encoding="utf-8")

    assert "raven-actions/actionlint@" in source
    assert "zgosalvez/github-actions-ensure-sha-pinned-actions@" in source
    assert "zizmorcore/zizmor-action@" in source

"""Adversarial tests for tagged release-workflow authentication."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
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


controller: Any = load_script("release_controller")
github_release: Any = load_script("verify_github_release")
acquisition: Any = load_script("acquire_github_release_assets")
verifier: Any = load_script("verify_release_workflow")

REPOSITORY = "stampbot/extra-codeowners"
REPOSITORY_ID = 1_299_090_885
OWNER_ID = 1_234_567
RELEASE_ID = 987_654_321
WORKFLOW_ID = 44_556_677
RUN_ID = 12_345_678
RUN_ATTEMPT = 2
TAG = "v0.1.0"
COMMIT = "a" * 40
WORKFLOW_PATH = ".github/workflows/release.yml"
WORKFLOW_CONTENT = b"name: Release\non:\n  push:\n    tags: ['v*']\n"
ASSET_CONTENT = {
    "extra-codeowners-0.1.0.tgz": b"chart",
    "extra_codeowners-0.1.0.tar.gz": b"source",
}


def manifest_value() -> dict[str, object]:
    assets = [
        {
            "name": name,
            "path": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        for name, content in ASSET_CONTENT.items()
    ]
    return {
        "assets": assets,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "run_id": RUN_ID,
        "schema_version": 1,
        "tag": TAG,
        "target_commit": COMMIT,
        "workflow_path": WORKFLOW_PATH,
        "workflow_sha": COMMIT,
    }


def release_plan(value: dict[str, object] | None = None) -> Any:
    manifest = manifest_value() if value is None else value
    raw = controller.canonical_json(manifest)
    return controller.validate_manifest(manifest, hashlib.sha256(raw).hexdigest())


def authenticated_record_value(plan: Any) -> dict[str, object]:
    return {
        "assets": [
            {"name": asset.name, "sha256": asset.sha256, "size": asset.size}
            for asset in plan.assets
        ],
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": github_release.RECORD_KIND,
        "release": {
            "attestation_payload_sha256": "c" * 64,
            "attestation_predicate_type": github_release.RELEASE_PREDICATE_TYPE,
            "id": RELEASE_ID,
            "immutable": True,
            "url": f"https://github.com/{REPOSITORY}/releases/tag/{TAG}",
        },
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
        },
        "schema_version": 1,
        "tag": {
            "attestation_subject_sha1": COMMIT,
            "name": TAG,
            "target_commit": COMMIT,
        },
    }


def write_record(
    path: Path,
    value: dict[str, object],
) -> tuple[Path, str]:
    raw = controller.canonical_json(value)
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def load_authenticated(tmp_path: Path, plan: Any) -> Any:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path, digest = write_record(
        tmp_path / "authenticated-release.json",
        authenticated_record_value(plan),
    )
    return acquisition.load_authenticated_release(
        path,
        expected_sha256=digest,
        plan=plan,
    )


def repository_value() -> dict[str, object]:
    return {
        "full_name": REPOSITORY,
        "id": REPOSITORY_ID,
        "owner": {"id": OWNER_ID},
    }


def run_value() -> dict[str, object]:
    return {
        "conclusion": "success",
        "event": "push",
        "head_branch": TAG,
        "head_repository": repository_value(),
        "head_sha": COMMIT,
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "id": RUN_ID,
        "path": WORKFLOW_PATH,
        "repository": repository_value(),
        "run_attempt": RUN_ATTEMPT,
        "status": "completed",
        "workflow_id": WORKFLOW_ID,
    }


def workflow_file_value(content: bytes = WORKFLOW_CONTENT) -> dict[str, object]:
    blob = hashlib.sha1(  # noqa: S324 - Git blob fixtures use SHA-1
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()
    return {
        "content": base64.encodebytes(content).decode("ascii"),
        "encoding": "base64",
        "name": "release.yml",
        "path": WORKFLOW_PATH,
        "sha": blob,
        "size": len(content),
        "type": "file",
    }


@dataclass
class Sequential:
    values: list[object]


class FakeClient:
    def __init__(self, plan: Any) -> None:
        self.responses: dict[str, object | Sequential] = {
            verifier._run_endpoint(plan): run_value(),
            verifier._workflow_content_endpoint(plan): workflow_file_value(),
        }
        self.events: list[tuple[str, ...]] = []
        self.version = "2.96.0"

    def check_version(self) -> str:
        self.events.append(("version",))
        if self.version < "2.93.0":
            raise github_release.VerificationError("GitHub CLI 2.93.0 or newer is required")
        return self.version

    def api(self, endpoint: str) -> object:
        self.events.append(("api", endpoint))
        value = self.responses[endpoint]
        if isinstance(value, Sequential):
            assert value.values
            return copy.deepcopy(value.values.pop(0))
        return copy.deepcopy(value)


def verify(tmp_path: Path, plan: Any, client: FakeClient) -> dict[str, object]:
    result = verifier.verify_release_workflow(
        plan,
        load_authenticated(tmp_path, plan),
        expected_manifest_sha256=plan.manifest_sha256,
        client=client,
    )
    return cast(dict[str, object], result)


def test_authenticates_exact_tagged_workflow_and_emits_blocked_record(
    tmp_path: Path,
) -> None:
    plan = release_plan()
    client = FakeClient(plan)

    result = verify(tmp_path, plan, client)

    workflow_sha256 = hashlib.sha256(WORKFLOW_CONTENT).hexdigest()
    workflow_blob = hashlib.sha1(  # noqa: S324 - Git blob identity uses SHA-1
        f"blob {len(WORKFLOW_CONTENT)}\0".encode("ascii") + WORKFLOW_CONTENT
    ).hexdigest()
    assert result == {
        "authenticated_release": {"sha256": load_authenticated(tmp_path, plan).record_sha256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": verifier.RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
        },
        "schema_version": 1,
        "tag": {"name": TAG, "target_commit": COMMIT},
        "workflow": {
            "event": "push",
            "file": {
                "git_blob_sha1": workflow_blob,
                "sha256": workflow_sha256,
                "size": len(WORKFLOW_CONTENT),
            },
            "id": WORKFLOW_ID,
            "path": WORKFLOW_PATH,
            "ref": f"refs/tags/{TAG}",
            "run_attempt": RUN_ATTEMPT,
            "run_id": RUN_ID,
            "sha": COMMIT,
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        },
    }
    assert controller.canonical_json(result).endswith(b"\n")
    assert client.events == [
        ("version",),
        ("api", verifier._run_endpoint(plan)),
        ("api", verifier._workflow_content_endpoint(plan)),
        ("api", verifier._run_endpoint(plan)),
        ("api", verifier._workflow_content_endpoint(plan)),
    ]


def test_same_inputs_produce_the_same_record(tmp_path: Path) -> None:
    plan = release_plan()
    first = verify(tmp_path / "first", plan, FakeClient(plan))
    second = verify(tmp_path / "second", plan, FakeClient(plan))

    assert first == second
    assert controller.canonical_json(first) == controller.canonical_json(second)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("id",), RUN_ID + 1),
        (("workflow_id",), 0),
        (("run_attempt",), True),
        (("event",), "workflow_dispatch"),
        (("status",), "in_progress"),
        (("conclusion",), "failure"),
        (("head_branch",), "main"),
        (("head_sha",), "b" * 40),
        (("path",), ".github/workflows/other.yml"),
        (("html_url",), "https://github.com/stampbot/extra-codeowners/actions/runs/1"),
        (("repository", "id"), REPOSITORY_ID + 1),
        (("repository", "full_name"), "stampbot/other"),
        (("repository", "owner", "id"), OWNER_ID + 1),
        (("head_repository", "id"), REPOSITORY_ID + 1),
        (("head_repository", "full_name"), "stampbot/other"),
        (("head_repository", "owner", "id"), OWNER_ID + 1),
    ],
)
def test_rejects_workflow_run_identity_drift(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    run = cast(dict[str, Any], run_value())
    target = run
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    client.responses[verifier._run_endpoint(plan)] = run

    with pytest.raises(verifier.WorkflowVerificationError, match="workflow"):
        verify(tmp_path, plan, client)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("type", "dir", "does not match"),
        ("name", "other.yml", "does not match"),
        ("path", ".github/workflows/other.yml", "does not match"),
        ("encoding", "none", "does not match"),
        ("size", len(WORKFLOW_CONTENT) + 1, "wrong size"),
        ("size", True, "integer bounds"),
        ("sha", "b" * 40, "Git blob identity"),
        ("sha", "invalid", "bounded nonempty"),
        ("content", "!!!!", "canonical base64"),
        ("content", "\r\n", "canonical base64"),
        ("content", "YQ==\v", "canonical base64"),
        ("content", "YQ==\u0085", "canonical base64"),
    ],
)
def test_rejects_workflow_file_drift(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    workflow = workflow_file_value()
    workflow[field] = value
    client.responses[verifier._workflow_content_endpoint(plan)] = workflow

    with pytest.raises(verifier.WorkflowVerificationError, match=message):
        verify(tmp_path, plan, client)


def test_rejects_oversized_and_noncanonical_workflow_content(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    oversized = b"x" * (verifier.MAX_WORKFLOW_BYTES + 1)
    client.responses[verifier._workflow_content_endpoint(plan)] = workflow_file_value(oversized)
    with pytest.raises(verifier.WorkflowVerificationError, match="byte bound"):
        verify(tmp_path, plan, client)

    client = FakeClient(plan)
    workflow = workflow_file_value()
    workflow["content"] = cast(str, workflow["content"]).replace("\n", "\n\n", 1)
    client.responses[verifier._workflow_content_endpoint(plan)] = workflow
    with pytest.raises(verifier.WorkflowVerificationError, match="canonical base64"):
        verify(tmp_path, plan, client)


def test_reread_rejects_run_and_workflow_changes(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    changed_run = run_value()
    changed_run["run_attempt"] = RUN_ATTEMPT + 1
    client.responses[verifier._run_endpoint(plan)] = Sequential([run_value(), changed_run])
    with pytest.raises(verifier.WorkflowVerificationError, match="changed"):
        verify(tmp_path / "run", plan, client)

    client = FakeClient(plan)
    changed_workflow = workflow_file_value(WORKFLOW_CONTENT + b"# changed\n")
    client.responses[verifier._workflow_content_endpoint(plan)] = Sequential(
        [workflow_file_value(), changed_workflow]
    )
    with pytest.raises(verifier.WorkflowVerificationError, match="changed"):
        verify(tmp_path / "workflow", plan, client)


def test_rejects_untrusted_manifest_digest_and_workflow_revision(
    tmp_path: Path,
) -> None:
    plan = release_plan()
    authenticated = load_authenticated(tmp_path, plan)
    client = FakeClient(plan)
    with pytest.raises(verifier.WorkflowVerificationError, match="trusted SHA-256"):
        verifier.verify_release_workflow(
            plan,
            authenticated,
            expected_manifest_sha256="f" * 64,
            client=client,
        )
    assert client.events == []

    value = manifest_value()
    value["workflow_sha"] = "b" * 40
    drifted = release_plan(value)
    authenticated = load_authenticated(tmp_path / "drifted", drifted)
    client = FakeClient(drifted)
    with pytest.raises(verifier.WorkflowVerificationError, match="tagged target"):
        verifier.verify_release_workflow(
            drifted,
            authenticated,
            expected_manifest_sha256=drifted.manifest_sha256,
            client=client,
        )
    assert client.events == []


def test_rejects_vulnerable_cli_before_github_reads(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    client.version = "2.92.0"

    with pytest.raises(github_release.VerificationError, match=r"2\.93\.0"):
        verify(tmp_path, plan, client)

    assert client.events == [("version",)]


def test_documented_isolated_python_invocation_loads_reviewed_siblings(
    tmp_path: Path,
) -> None:
    script = Path(__file__).parents[1] / ".github" / "scripts" / "verify_release_workflow.py"
    result = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed script
        [sys.executable, "-I", "-B", str(script), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert "--authenticated-release-record-sha256" in result.stdout
    assert result.stderr == ""


def test_documentation_matches_the_workflow_verifier_and_nonclaims() -> None:
    root = Path(__file__).parents[1]
    reference = (root / "docs/reference/authenticated-release-workflow-record.md").read_text(
        encoding="utf-8"
    )
    how_to = (root / "docs/how-to/verify-container-release-evidence.md").read_text(encoding="utf-8")
    contract = (root / "docs/reference/container-evidence-release-contract.md").read_text(
        encoding="utf-8"
    )
    navigation = (root / "mkdocs.yml").read_text(encoding="utf-8")

    for option in (
        "--manifest",
        "--manifest-sha256",
        "--authenticated-release-record",
        "--authenticated-release-record-sha256",
        "--gh",
        "--timeout-seconds",
    ):
        assert option in reference
    assert ".github/scripts/verify_release_workflow.py" in how_to
    assert "mise exec -- python -I -B" in how_to
    assert "Actions: read" in reference
    assert "Contents: read" in reference
    assert "2.93.0" in reference
    assert "2.96.0" in reference
    assert "`publication_allowed`" in reference
    assert "- prove that the checked workflow produced a release asset" in reference
    assert "No workflow" in reference
    assert "authenticated-release-workflow-record.md" in navigation
    assert "Current release workflow verifier" in contract


def test_workflow_verifier_remains_unwired_and_publication_disabled() -> None:
    root = Path(__file__).parents[1]
    script = ".github/scripts/verify_release_workflow.py"
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    assert workflows
    occurrences = 0
    for workflow in workflows:
        source = workflow.read_text(encoding="utf-8")
        occurrences += source.count(script)
        assert f"python {script}" not in source
        assert f"python3 {script}" not in source
        assert f"mise exec -- python -I -B {script}" not in source
    assert occurrences == 2  # CI and release strict type-check scopes only.

    source = (root / script).read_text(encoding="utf-8")
    for forbidden in (
        "release create",
        "release edit",
        "release upload",
        "attestation sign",
        "api --method POST",
        "api --method PATCH",
        "api --method DELETE",
    ):
        assert forbidden not in source
    assert '"publication_allowed": False' in source

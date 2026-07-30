"""Adversarial tests for authenticated GitHub release asset acquisition."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
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
acquirer: Any = load_script("acquire_github_release_assets")

REPOSITORY = "stampbot/extra-codeowners"
REPOSITORY_ID = 1_299_090_885
OWNER_ID = 1_234_567
RELEASE_ID = 987_654_321
TAG = "v0.1.0"
COMMIT = "a" * 40
WORKFLOW_SHA = "b" * 40
ASSET_CONTENT = {
    "evidence-predicate-amd64.json": b'{"schema_version":9}\n',
    "extra-codeowners-0.1.0-linux-amd64-evidence.tar.gz": b"synthetic-gzip-bytes",
}


def manifest_value() -> dict[str, object]:
    assets = []
    for name, path in (
        (
            "evidence-predicate-amd64.json",
            "release/evidence-predicate-amd64.json",
        ),
        (
            "extra-codeowners-0.1.0-linux-amd64-evidence.tar.gz",
            "release/extra-codeowners-0.1.0-linux-amd64-evidence.tar.gz",
        ),
    ):
        content = ASSET_CONTENT[name]
        assets.append(
            {
                "name": name,
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    return {
        "assets": assets,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "run_id": 445_566,
        "schema_version": 1,
        "tag": TAG,
        "target_commit": COMMIT,
        "workflow_path": ".github/workflows/release.yml",
        "workflow_sha": WORKFLOW_SHA,
    }


def release_plan() -> Any:
    value = manifest_value()
    raw = controller.canonical_json(value)
    return controller.validate_manifest(value, hashlib.sha256(raw).hexdigest())


def repository_response() -> dict[str, object]:
    return {
        "full_name": REPOSITORY,
        "id": REPOSITORY_ID,
        "owner": {"id": OWNER_ID, "login": "stampbot"},
    }


def tag_response() -> dict[str, object]:
    return {
        "object": {"sha": COMMIT, "type": "commit"},
        "ref": f"refs/tags/{TAG}",
    }


def release_response(plan: Any, release_id: int = RELEASE_ID) -> dict[str, object]:
    api_url = f"https://api.github.com/repos/{REPOSITORY}/releases/{release_id}"
    return {
        "assets_url": f"{api_url}/assets",
        "body": plan.marker,
        "draft": False,
        "html_url": f"https://github.com/{REPOSITORY}/releases/tag/{TAG}",
        "id": release_id,
        "immutable": True,
        "name": TAG,
        "prerelease": False,
        "tag_name": TAG,
        "target_commitish": COMMIT,
        "url": api_url,
    }


def asset_responses(plan: Any) -> list[dict[str, object]]:
    result = []
    for index, asset in enumerate(plan.assets, start=1):
        asset_id = 80_000 + index
        result.append(
            {
                "browser_download_url": (
                    f"https://github.com/{REPOSITORY}/releases/download/{TAG}/{asset.name}"
                ),
                "content_type": "application/octet-stream",
                "digest": f"sha256:{asset.sha256}",
                "id": asset_id,
                "label": None,
                "name": asset.name,
                "size": asset.size,
                "state": "uploaded",
                "url": f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}",
            }
        )
    return result


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
    value: Mapping[str, object],
) -> tuple[Path, str]:
    raw = controller.canonical_json(value)
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def load_authenticated(tmp_path: Path, plan: Any) -> Any:
    path, digest = write_record(
        tmp_path / "authenticated-release.json",
        authenticated_record_value(plan),
    )
    return acquirer.load_authenticated_release(
        path,
        expected_sha256=digest,
        plan=plan,
    )


@dataclass
class Sequential:
    values: list[object]


class FakeClient:
    def __init__(self, plan: Any) -> None:
        repository = github_release._repository_endpoint(REPOSITORY)
        release = github_release._release_id_endpoint(plan, RELEASE_ID)
        assets = github_release._assets_endpoint(plan, RELEASE_ID)
        tag = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
        self.responses: dict[str, object | Sequential] = {
            repository: repository_response(),
            tag: tag_response(),
            release: release_response(plan),
            assets: asset_responses(plan),
        }
        self.contents = dict(ASSET_CONTENT)
        self.events: list[tuple[object, ...]] = []
        self.version = "2.96.0"
        self.download_error: Exception | None = None

    def check_version(self) -> str:
        self.events.append(("version",))
        return self.version

    def api(self, endpoint: str) -> object:
        self.events.append(("api", endpoint))
        response = self.responses[endpoint]
        if isinstance(response, Sequential):
            assert response.values
            value = response.values.pop(0)
        else:
            value = response
        return copy.deepcopy(value)

    def download_asset(
        self,
        repository: str,
        asset_id: int,
        destination: int,
        maximum_bytes: int,
    ) -> tuple[int, str]:
        self.events.append(("download", repository, asset_id, maximum_bytes))
        if self.download_error is not None:
            raise self.download_error
        index = asset_id - 80_001
        name = list(ASSET_CONTENT)[index]
        content = self.contents[name]
        view = memoryview(content)
        while view:
            written = os.write(destination, view)
            assert written > 0
            view = view[written:]
        return len(content), hashlib.sha256(content).hexdigest()


def acquire(tmp_path: Path, plan: Any, client: FakeClient) -> tuple[Mapping[str, object], Path]:
    authenticated = load_authenticated(tmp_path, plan)
    output = tmp_path / "acquired-assets"
    result = acquirer.acquire_release_assets(
        plan,
        authenticated,
        output,
        client=client,
    )
    return cast(Mapping[str, object], result), output


def test_acquires_exact_bytes_and_emits_a_publication_blocked_record(
    tmp_path: Path,
) -> None:
    plan = release_plan()
    client = FakeClient(plan)

    record, output = acquire(tmp_path, plan, client)

    assert record == {
        "assets": [
            {
                "github_asset_id": 80_000 + index,
                "name": asset.name,
                "path": asset.name,
                "sha256": asset.sha256,
                "size": asset.size,
            }
            for index, asset in enumerate(plan.assets, start=1)
        ],
        "authenticated_release": {
            "attestation_payload_sha256": "c" * 64,
            "sha256": load_authenticated(tmp_path, plan).record_sha256,
        },
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {"minimum_version": "2.93.0", "version": "2.96.0"},
        "kind": acquirer.RECORD_KIND,
        "publication_allowed": False,
        "release": {
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
    assert controller.canonical_json(record).endswith(b"\n")
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for asset in plan.assets:
        path = output / asset.name
        assert path.read_bytes() == ASSET_CONTENT[asset.name]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (output / "release").exists()
    assert client.events[0] == ("version",)
    assert [event[0] for event in client.events].count("download") == len(plan.assets)
    assert client.events[-1][0] == "api"


def test_same_inputs_produce_the_same_record(tmp_path: Path) -> None:
    plan = release_plan()
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()

    first, _ = acquire(first_root, plan, FakeClient(plan))
    second, _ = acquire(second_root, plan, FakeClient(plan))

    assert first == second
    assert controller.canonical_json(first) == controller.canonical_json(second)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("kind",), "attacker/kind", "unsupported kind"),
        (("schema_version",), 2, "unsupported schema"),
        (("schema_version",), True, "unsupported schema"),
        (("controller_manifest", "sha256"), "f" * 64, "controller manifest"),
        (("github_cli", "minimum_version"), "0.0.0", "CLI minimum"),
        (("github_cli", "version"), "2.92.0", "predates"),
        (("repository", "id"), REPOSITORY_ID + 1, "different repository"),
        (("repository", "owner_id"), 0, "owner ID"),
        (("tag", "target_commit"), "f" * 40, "different tag"),
        (("tag", "attestation_subject_sha1"), "invalid", "subject SHA-1"),
        (("release", "id"), 0, "release ID"),
        (("release", "immutable"), False, "release identity"),
        (("release", "attestation_payload_sha256"), "invalid", "payload SHA-256"),
        (("assets",), [], "asset inventory"),
    ],
)
def test_rejects_authenticated_record_drift(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    plan = release_plan()
    record = cast(dict[str, Any], authenticated_record_value(plan))
    target = record
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    record_path, digest = write_record(tmp_path / "record.json", record)

    with pytest.raises(acquirer.AcquisitionError, match=message):
        acquirer.load_authenticated_release(
            record_path,
            expected_sha256=digest,
            plan=plan,
        )


def test_record_hash_is_an_independent_trust_input(tmp_path: Path) -> None:
    plan = release_plan()
    path, _digest = write_record(
        tmp_path / "record.json",
        authenticated_record_value(plan),
    )

    with pytest.raises(acquirer.AcquisitionError, match="trusted SHA-256"):
        acquirer.load_authenticated_release(
            path,
            expected_sha256="f" * 64,
            plan=plan,
        )


def test_rejects_noncanonical_duplicate_linked_and_oversized_records(
    tmp_path: Path,
) -> None:
    plan = release_plan()

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(json.dumps(authenticated_record_value(plan)), encoding="utf-8")
    digest = hashlib.sha256(noncanonical.read_bytes()).hexdigest()
    with pytest.raises(acquirer.AcquisitionError, match="not canonical"):
        acquirer.load_authenticated_release(
            noncanonical,
            expected_sha256=digest,
            plan=plan,
        )

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(b'{"kind":"first","kind":"second"}\n')
    digest = hashlib.sha256(duplicate.read_bytes()).hexdigest()
    with pytest.raises(acquirer.AcquisitionError, match="strict bounded JSON"):
        acquirer.load_authenticated_release(
            duplicate,
            expected_sha256=digest,
            plan=plan,
        )

    linked = tmp_path / "linked.json"
    linked_digest = write_record(
        linked,
        authenticated_record_value(plan),
    )[1]
    os.link(linked, tmp_path / "second-link.json")
    with pytest.raises(acquirer.AcquisitionError, match="single-link"):
        acquirer.load_authenticated_release(
            linked,
            expected_sha256=linked_digest,
            plan=plan,
        )

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (acquirer.MAX_AUTHENTICATED_RECORD_BYTES + 1))
    digest = hashlib.sha256(oversized.read_bytes()).hexdigest()
    with pytest.raises(acquirer.AcquisitionError, match="byte bound"):
        acquirer.load_authenticated_release(
            oversized,
            expected_sha256=digest,
            plan=plan,
        )


def test_wrong_download_bytes_fail_and_leave_no_output_or_staging(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    client.contents[plan.assets[0].name] = b"x" * plan.assets[0].size

    with pytest.raises(acquirer.AcquisitionError, match="wrong SHA-256"):
        acquire(tmp_path, plan, client)

    assert not (tmp_path / "acquired-assets").exists()
    assert not list(tmp_path.glob(".github-release-assets-*"))


def test_download_failure_is_sanitized_and_cleans_staging(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    client.download_error = github_release.VerificationError("untrusted diagnostic")

    with pytest.raises(acquirer.AcquisitionError, match="cannot download"):
        acquire(tmp_path, plan, client)

    assert not (tmp_path / "acquired-assets").exists()
    assert not list(tmp_path.glob(".github-release-assets-*"))


def test_rejects_vulnerable_client_version_before_github_reads(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    client.version = "2.92.0"

    with pytest.raises(acquirer.AcquisitionError, match="predates"):
        acquire(tmp_path, plan, client)

    assert client.events == [("version",)]
    assert not (tmp_path / "acquired-assets").exists()


def test_remote_change_during_download_fails_closed(tmp_path: Path) -> None:
    plan = release_plan()
    client = FakeClient(plan)
    endpoint = github_release._assets_endpoint(plan, RELEASE_ID)
    changed = asset_responses(plan)
    changed[0]["digest"] = "sha256:" + "f" * 64
    client.responses[endpoint] = Sequential([asset_responses(plan), changed])

    with pytest.raises(acquirer.AcquisitionError, match="final GitHub release identity"):
        acquire(tmp_path, plan, client)

    assert not (tmp_path / "acquired-assets").exists()
    assert not list(tmp_path.glob(".github-release-assets-*"))


def test_existing_output_and_symlink_are_never_replaced(tmp_path: Path) -> None:
    plan = release_plan()
    authenticated = load_authenticated(tmp_path, plan)

    output = tmp_path / "acquired-assets"
    output.mkdir()
    client = FakeClient(plan)
    with pytest.raises(acquirer.AcquisitionError, match="already exists"):
        acquirer.acquire_release_assets(plan, authenticated, output, client=client)
    assert client.events == []

    output.rmdir()
    target = tmp_path / "target"
    target.mkdir()
    output.symlink_to(target, target_is_directory=True)
    client = FakeClient(plan)
    with pytest.raises(acquirer.AcquisitionError, match="already exists"):
        acquirer.acquire_release_assets(plan, authenticated, output, client=client)
    assert output.is_symlink()
    assert client.events == []


def test_output_publication_race_never_replaces_the_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = release_plan()
    authenticated = load_authenticated(tmp_path, plan)
    output = tmp_path / "acquired-assets"
    original = acquirer._rename_noreplace

    def create_winner(parent: int, source: str, destination: str) -> None:
        os.mkdir(destination, 0o700, dir_fd=parent)
        original(parent, source, destination)

    monkeypatch.setattr(acquirer, "_rename_noreplace", create_winner)

    with pytest.raises(acquirer.AcquisitionError, match="appeared during acquisition"):
        acquirer.acquire_release_assets(
            plan,
            authenticated,
            output,
            client=FakeClient(plan),
        )

    assert output.is_dir()
    assert not list(output.iterdir())
    assert not list(tmp_path.glob(".github-release-assets-*"))


def test_documented_isolated_python_invocation_loads_reviewed_siblings(
    tmp_path: Path,
) -> None:
    script = Path(__file__).parents[1] / ".github" / "scripts" / "acquire_github_release_assets.py"
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


def test_unexpected_local_entry_and_special_file_are_rejected(tmp_path: Path) -> None:
    plan = release_plan()
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    retained = []
    with contextlib.ExitStack() as descriptors:
        for asset in plan.assets:
            path = root / asset.name
            path.write_bytes(ASSET_CONTENT[asset.name])
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            descriptors.callback(os.close, descriptor)
            retained.append(
                acquirer.RetainedAsset(
                    asset,
                    descriptor,
                    acquirer._file_identity(os.fstat(descriptor)),
                )
            )
        root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.callback(os.close, root_descriptor)

        (root / "unexpected").write_text("no", encoding="utf-8")
        with pytest.raises(acquirer.AcquisitionError, match="unexpected inventory"):
            acquirer._require_tree_matches(root_descriptor, plan, retained)
        (root / "unexpected").unlink()

        fifo = root / "special"
        os.mkfifo(fifo)
        with pytest.raises(acquirer.AcquisitionError, match="non-regular"):
            acquirer._require_tree_matches(root_descriptor, plan, retained)


def test_acquirer_remains_unwired_and_publication_disabled() -> None:
    root = Path(__file__).parents[1]
    script = ".github/scripts/acquire_github_release_assets.py"
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
        "id-token",
    ):
        assert forbidden not in source
    assert '"publication_allowed": False' in source


def test_documentation_matches_the_acquisition_command_and_nonclaims() -> None:
    root = Path(__file__).parents[1]
    reference = (root / "docs/reference/authenticated-release-asset-acquisition.md").read_text(
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
        "--output-dir",
        "--gh",
        "--timeout-seconds",
    ):
        assert option in reference
    assert ".github/scripts/acquire_github_release_assets.py" in how_to
    assert "mise exec -- python -I -B" in how_to
    assert "Contents: read" in reference
    assert "2.93.0" in reference
    assert "2.96.0" in reference
    assert "`publication_allowed`" in reference
    assert "- prove which workflow produced" in reference
    assert "No workflow calls this command" in reference
    assert "Current release asset acquirer" in contract
    assert (
        "Authenticated release asset acquisition: "
        "reference/authenticated-release-asset-acquisition.md"
    ) in navigation

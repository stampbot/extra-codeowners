"""Source reuse authenticates a prior release and preserves every content check."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tools import release_debian_sources as source

REPOSITORY = "example/project"
REVISION = "f" * 40


class PriorRelease:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.digests = {"amd64": "sha256:" + "a" * 64, "arm64": "sha256:" + "b" * 64}
        self.inventories = {
            architecture: json.dumps(
                {
                    "schema_version": 2,
                    "image": {
                        "architecture": architecture,
                        "platform_digest": digest,
                        "distro": "debian-13",
                    },
                    "debian": {
                        "packages": [
                            {
                                "package": "libexample",
                                "version": "1.2-3+b1",
                                "source": "example (1.2-3)",
                                "architecture": architecture,
                            }
                        ]
                    },
                }
            ).encode()
            for architecture, digest in self.digests.items()
        }
        payload = b"reviewed source payload"
        descriptor = (
            "Format: 3.0 (quilt)\nSource: example\nVersion: 1.2-3\nChecksums-Sha256:\n"
            f" {hashlib.sha256(payload).hexdigest()} {len(payload)} example_1.2.orig.tar.xz\n"
        ).encode()

        def file(name: str, data: bytes) -> dict[str, Any]:
            return {
                "name": name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "snapshot_sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            }

        resolved = {
            "name": "example",
            "version": "1.2-3",
            "descriptor": file("example_1.2-3.dsc", descriptor),
            "files": [file("example_1.2.orig.tar.xz", payload)],
        }
        monkeypatch.setattr(source, "resolve_source", lambda identity: (resolved, descriptor))
        monkeypatch.setattr(source, "_download", lambda url, output, limit: output.write(payload))
        self.bundle = tmp_path / "prior.tar"
        source.collect_bundle(self.inventories, self.digests, self.bundle, tmp_path / "cache")
        monkeypatch.setattr(
            source,
            "resolve_source",
            Mock(side_effect=AssertionError("no metadata lookup during reuse")),
        )
        monkeypatch.setattr(
            source,
            "_download",
            Mock(side_effect=AssertionError("no Snapshot download during reuse")),
        )
        self.calls: list[list[str]] = []
        self.catalog: list[dict[str, Any]] = [
            {
                "tag_name": "v0.1.0-alpha.1",
                "draft": False,
                "immutable": True,
                "assets": [
                    {"name": f"distribution-inventory-{a}.json", "size": len(data)}
                    for a, data in self.inventories.items()
                ]
                + [{"name": "debian-source.tar", "size": self.bundle.stat().st_size}],
            }
        ]
        self.bad_attestation: str | None = None
        self.bad_download: str | None = None
        monkeypatch.setattr(source, "_gh", self.gh)

    def gh(self, arguments: Sequence[str], description: str) -> bytes:
        args = list(arguments)
        self.calls.append(args)
        if args[0] == "api":
            if "/releases?" in args[1]:
                return json.dumps(self.catalog).encode()
            return json.dumps({"object": {"type": "commit", "sha": REVISION}}).encode()
        if args[:2] == ["release", "download"]:
            name = args[args.index("--pattern") + 1]
            directory = Path(args[args.index("--dir") + 1])
            data = (
                self.bundle.read_bytes()
                if name == "debian-source.tar"
                else self.inventories[
                    name.removeprefix("distribution-inventory-").removesuffix(".json")
                ]
            )
            damage = self.bad_download
            if damage is not None and damage.startswith("bundle-"):
                damage = damage.removeprefix("bundle-") if name == "debian-source.tar" else None
            if damage == "symlink":
                (directory / name).symlink_to(self.bundle)
            else:
                (directory / name).write_bytes(b"corrupt" if damage == "corrupt" else data)
            return b""
        assert args[:2] == ["attestation", "verify"]
        assert args[args.index("--repo") + 1] == REPOSITORY
        assert args[args.index("--source-digest") + 1] == REVISION
        assert args[args.index("--source-ref") + 1] == "refs/heads/main"
        assert (
            args[args.index("--signer-workflow") + 1]
            == f"{REPOSITORY}/.github/workflows/release.yml"
        )
        assert "--deny-self-hosted-runners" in args
        if self.bad_attestation == "command":
            raise source.DebianSourceError("verification failed")
        path = Path(args[2])
        identity = f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/heads/main"
        result: dict[str, Any] = {
            "verificationResult": {
                "signature": {"certificate": {"subjectAlternativeName": identity}},
                "statement": {
                    "subject": [
                        {
                            "name": path.name,
                            "digest": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                        }
                    ]
                },
            }
        }
        if self.bad_attestation == "identity":
            result["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"] = (
                "https://github.com/example/untrusted/.github/workflows/release.yml@refs/heads/main"
            )
        if self.bad_attestation == "hash":
            result["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
        if self.bad_attestation == "name":
            result["verificationResult"]["statement"]["subject"][0]["name"] = "different.json"
        return json.dumps([] if self.bad_attestation == "empty" else [result]).encode()


def new_identity(prior: PriorRelease) -> tuple[dict[str, bytes], dict[str, str]]:
    inventories = {}
    digests = {"amd64": "sha256:" + "c" * 64, "arm64": "sha256:" + "d" * 64}
    for architecture, raw in prior.inventories.items():
        value = json.loads(raw)
        value["image"]["platform_digest"] = digests[architecture]
        value["application_revision"] = "e" * 40
        inventories[architecture] = json.dumps(value).encode()
    return inventories, digests


def test_offline_reuse_authenticates_all_artifacts_and_rebinds_only_images(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    inventories, digests = new_identity(prior)
    output = tmp_path / "new.tar"
    original = prior.bundle.read_bytes()
    assert source.reuse_release(inventories, digests, output, REPOSITORY)
    old = source.verify_bundle(prior.inventories, prior.digests, prior.bundle)
    new = source.verify_bundle(inventories, digests, output)
    assert new["packages"] == old["packages"]
    assert new["images"] != old["images"]
    assert new["provenance"] == old["provenance"]
    assert prior.bundle.read_bytes() == original
    assert len([call for call in prior.calls if call[:2] == ["attestation", "verify"]]) == 3
    assert not list(tmp_path.glob("debian-prior-*"))
    assert not list(tmp_path.glob("debian-rebind-*"))
    with pytest.raises(source.DebianSourceError, match="inventories"):
        source.verify_bundle(prior.inventories, prior.digests, output)
    with tarfile.open(prior.bundle) as old_tar, tarfile.open(output) as new_tar:
        for member in old_tar:
            if member.name != "manifest.json":
                old_file, new_file = old_tar.extractfile(member), new_tar.extractfile(member.name)
                assert old_file is not None and new_file is not None
                assert old_file.read() == new_file.read()


@pytest.mark.parametrize("failure", ["identity", "hash", "name", "empty", "command"])
def test_attestation_failure_never_becomes_fresh_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    prior.bad_attestation = failure
    with pytest.raises(source.DebianSourceError):
        source.reuse_release(*new_identity(prior), tmp_path / "new.tar", REPOSITORY)
    assert not (tmp_path / "new.tar").exists()
    assert not list(tmp_path.glob("debian-prior-*"))


@pytest.mark.parametrize("failure", ["symlink", "corrupt", "bundle-symlink", "bundle-corrupt"])
def test_bad_download_never_reaches_rebinding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    prior.bad_download = failure
    with pytest.raises(source.DebianSourceError):
        source.reuse_release(*new_identity(prior), tmp_path / "new.tar", REPOSITORY)
    assert not (tmp_path / "new.tar").exists()


def test_changed_source_set_requests_fresh_collection_without_downloading_old_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    inventories, digests = new_identity(prior)
    document = json.loads(inventories["amd64"])
    document["debian"]["packages"][0]["source"] = "example (1.2-4)"
    inventories["amd64"] = json.dumps(document).encode()
    assert not source.reuse_release(inventories, digests, tmp_path / "new.tar", REPOSITORY)
    assert not any("debian-source.tar" in call for call in prior.calls)
    assert not (tmp_path / "new.tar").exists()


@pytest.mark.parametrize("change", ["draft", "mutable", "missing", "invalid_tag", "none"])
def test_only_completed_immutable_releases_with_all_evidence_are_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    if change == "draft":
        prior.catalog[0]["draft"] = True
    elif change == "mutable":
        prior.catalog[0]["immutable"] = False
    elif change == "missing":
        prior.catalog[0]["assets"].pop()
    elif change == "invalid_tag":
        prior.catalog[0]["tag_name"] = "--target=main"
    else:
        prior.catalog = []
    assert not source.reuse_release(*new_identity(prior), tmp_path / "new.tar", REPOSITORY)
    assert len(prior.calls) == 1


@pytest.mark.parametrize("change", ["oversize", "duplicate"])
def test_invalid_selected_asset_metadata_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    if change == "oversize":
        prior.catalog[0]["assets"][0]["size"] = source.MAX_BUNDLE + 1
    else:
        prior.catalog[0]["assets"].append(prior.catalog[0]["assets"][0])
    with pytest.raises(source.DebianSourceError):
        source.reuse_release(*new_identity(prior), tmp_path / "new.tar", REPOSITORY)


def test_rebind_rejects_corruption_even_when_new_source_identities_differ(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    prior.bundle.write_bytes(prior.bundle.read_bytes() + b"unexpected")
    inventories, digests = new_identity(prior)
    doc = json.loads(inventories["amd64"])
    doc["debian"]["packages"][0]["source"] = "example (1.2-4)"
    inventories["amd64"] = json.dumps(doc).encode()
    with pytest.raises(source.DebianSourceError):
        source.rebind_bundle(
            inventories,
            digests,
            prior.inventories,
            prior.digests,
            prior.bundle,
            tmp_path / "new.tar",
        )


def test_gh_adapter_uses_resolved_cli_without_a_shell_and_bounds_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("tools.release_debian_sources.shutil.which", lambda name: "/trusted/bin/gh")
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"{}", stderr=b""))
    monkeypatch.setattr("tools.release_debian_sources.subprocess.run", run)
    assert source._gh(["api", "repos/example/project/releases?per_page=5"], "catalog") == b"{}"
    assert run.call_args.args[0][0] == "/trusted/bin/gh"
    assert run.call_args.kwargs == {"capture_output": True, "check": True, "timeout": 90}
    source._gh(["release", "download", "v0.1.0", "--repo", REPOSITORY], "download")
    assert run.call_args.kwargs["timeout"] == 600
    run.side_effect = subprocess.TimeoutExpired("gh", 90)
    with pytest.raises(source.DebianSourceError, match="catalog"):
        source._gh(["api", "repos/example/project/releases?per_page=5"], "catalog")
    monkeypatch.setattr("tools.release_debian_sources.shutil.which", lambda name: None)
    with pytest.raises(source.DebianSourceError, match="GitHub CLI"):
        source._gh([], "missing")


def test_annotated_tag_resolution_is_bounded_and_returns_the_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read = Mock(
        side_effect=[
            json.dumps({"object": {"type": "tag", "sha": "a" * 40}}).encode(),
            json.dumps({"object": {"type": "commit", "sha": REVISION}}).encode(),
        ]
    )
    monkeypatch.setattr(source, "_gh", read)
    assert source._release_revision(REPOSITORY, "v0.1.0") == REVISION
    assert read.call_count == 2
    read.side_effect = None
    read.return_value = json.dumps({"object": {"type": "tag", "sha": "a" * 40}}).encode()
    read.reset_mock()
    with pytest.raises(source.DebianSourceError, match="nesting"):
        source._release_revision(REPOSITORY, "v0.1.0")
    assert read.call_count == 4


@pytest.mark.parametrize("reuse_result,expected", [(True, 0), (False, 3), (None, 1)])
def test_cli_distinguishes_safe_fresh_collection_from_evidence_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reuse_result: bool | None, expected: int
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    arguments = ["reuse-release", "--repository", REPOSITORY, "--bundle", str(tmp_path / "new.tar")]
    for architecture in ("amd64", "arm64"):
        path = tmp_path / f"{architecture}.json"
        path.write_bytes(prior.inventories[architecture])
        arguments += [
            f"--inventory-{architecture}",
            str(path),
            f"--digest-{architecture}",
            prior.digests[architecture],
        ]
    operation = Mock(return_value=reuse_result)
    if reuse_result is None:
        operation.side_effect = source.DebianSourceError("invalid evidence")
    monkeypatch.setattr(source, "reuse_release", operation)
    assert source.main(arguments) == expected


def test_existing_output_is_rejected_before_network_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior = PriorRelease(tmp_path, monkeypatch)
    output = tmp_path / "existing.tar"
    output.write_bytes(b"keep this")
    with pytest.raises(source.DebianSourceError, match="overwrite"):
        source.reuse_release(*new_identity(prior), output, REPOSITORY)
    assert output.read_bytes() == b"keep this"
    assert prior.calls == []

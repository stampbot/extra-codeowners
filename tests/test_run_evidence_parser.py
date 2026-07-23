"""Tests for the fixed offline evidence-parser Docker command."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import stat
import sys
import threading
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "run_evidence_parser.py"
COLLECTOR_SCRIPT = ROOT / ".github" / "scripts" / "container_evidence.py"
IMAGE = f"ghcr.io/stampbot/evidence-parser@sha256:{'1' * 64}"
SOURCE_CONTAINER_NAME = f"extra-codeowners-source-plan-{'1' * 32}"
EVIDENCE_CONTAINER_NAME = f"extra-codeowners-evidence-{'2' * 32}"


def load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sandbox: Any = load_script(SCRIPT, "run_evidence_parser_for_test")
collector: Any = load_script(COLLECTOR_SCRIPT, "container_evidence_for_sandbox_contract")


def make_mounts(tmp_path: Path) -> tuple[dict[str, Path], Path]:
    recipe = tmp_path / "recipe"
    recipe.mkdir()
    store = tmp_path / "store.json"
    store.write_bytes(b"store")
    output = tmp_path / "output"
    output.mkdir()
    return {"store": store, "recipe": recipe}, output


def allow_test_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sandbox,
        "_require_bounded_output_tmpfs",
        lambda *_args, **_kwargs: None,
    )


def test_builds_the_exact_fixed_docker_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, output = make_mounts(tmp_path)
    allow_test_output(monkeypatch)

    command = sandbox.build_docker_command(
        image=IMAGE,
        container_name=SOURCE_CONTAINER_NAME,
        inputs=inputs,
        output=output,
        parser="source-plan",
        parser_arguments=(
            "alpine-distfile-plan",
            "--direct-store",
            "/inputs/store",
        ),
    )

    assert command == (
        "/usr/bin/docker",
        "run",
        "--rm",
        f"--name={SOURCE_CONTAINER_NAME}",
        "--log-driver=none",
        "--pull=never",
        "--network=none",
        "--ipc=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=builtin",
        "--pids-limit=64",
        "--cpus=1.0",
        "--memory=536870912",
        "--memory-swap=536870912",
        "--ulimit=nofile=256:256",
        (
            "--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=67108864,"
            "nr_inodes=4096,mode=0700,uid=65532,gid=65532"
        ),
        "--workdir=/scratch",
        "--env=HOME=/scratch",
        "--env=TMPDIR=/scratch",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONUNBUFFERED=1",
        "--mount",
        (f"type=bind,src={inputs['recipe']},dst=/inputs/recipe,readonly,bind-recursive=disabled"),
        "--mount",
        (f"type=bind,src={inputs['store']},dst=/inputs/store,readonly,bind-recursive=disabled"),
        "--mount",
        f"type=bind,src={output},dst=/output,bind-recursive=disabled",
        "--entrypoint=/opt/venv/bin/python",
        IMAGE,
        "/build/.github/scripts/run_evidence_parser.py",
        "_inside",
        "--parser=source-plan",
        "--input=recipe",
        "--input=store",
        "--",
        "alpine-distfile-plan",
        "--direct-store",
        "/inputs/store",
    )
    assert not any("docker.sock" in argument for argument in command)
    assert not any(argument in {"--privileged", "--env-file"} for argument in command)


def test_accepts_an_exact_local_docker_image_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, output = make_mounts(tmp_path)
    allow_test_output(monkeypatch)
    image_id = f"sha256:{'2' * 64}"

    command = sandbox.build_docker_command(
        image=image_id,
        container_name=EVIDENCE_CONTAINER_NAME,
        inputs=inputs,
        output=output,
        parser="evidence",
        parser_arguments=("bundle",),
    )

    assert command.count("--pull=never") == 1
    assert image_id in command
    assert not any("@sha256:" in argument for argument in command)
    assert "--memory=5368709120" in command
    assert "--memory-swap=5368709120" in command
    work_mount = (
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=3221225472,"
        "nr_inodes=131072,mode=0700,uid=65532,gid=65532"
    )
    assert command.count(work_mount) == 1


def test_evidence_work_capacity_covers_retained_tree_and_staged_output() -> None:
    required_bytes = sandbox.EVIDENCE_RETAINED_BYTES + sandbox.EVIDENCE_MATERIALIZED_BYTES
    resident_filesystem_capacity = (
        sandbox.EVIDENCE_WORK_BYTES + sandbox.EVIDENCE_OUTPUT_BYTES + sandbox.SCRATCH_BYTES
    )

    assert sandbox.EVIDENCE_WORK_BYTES == 3072 * 1024 * 1024
    assert sandbox.EVIDENCE_RETAINED_BYTES == collector.MAX_BUNDLE_RETAINED_BYTES
    assert sandbox.EVIDENCE_ARCHIVE_BYTES == collector.MAX_BUNDLE_OUTPUT_BYTES
    assert required_bytes <= sandbox.EVIDENCE_WORK_BYTES
    assert sandbox.EVIDENCE_WORK_BYTES - required_bytes == 1_072_692_224
    assert resident_filesystem_capacity == 4288 * 1024 * 1024
    assert sandbox.EVIDENCE_MEMORY_HEADROOM_BYTES == 832 * 1024 * 1024
    assert sandbox.EVIDENCE_MEMORY_BYTES - resident_filesystem_capacity == 832 * 1024 * 1024


def test_host_command_defers_parser_owned_output_inventory_to_fixed_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, output = make_mounts(tmp_path)
    calls: list[tuple[Path, str, bool]] = []

    def validate_output(
        path: Path,
        parser: str,
        *,
        require_empty: bool = True,
        owner_uid: int | None = None,
        owner_gid: int | None = None,
    ) -> None:
        del owner_uid, owner_gid
        calls.append((path, parser, require_empty))

    monkeypatch.setattr(sandbox, "_require_bounded_output_tmpfs", validate_output)

    sandbox.build_docker_command(
        image=IMAGE,
        container_name=SOURCE_CONTAINER_NAME,
        inputs=inputs,
        output=output,
        parser="source-plan",
        parser_arguments=("alpine-distfile-plan",),
    )

    assert calls == [(output, "source-plan", False)]


@pytest.mark.parametrize(
    "container_name",
    (
        f"extra-codeowners-source-plan-{'1' * 32}",
        f"extra-codeowners-evidence-{'A' * 32}",
        f"extra-codeowners-evidence-{'1' * 31}",
        f"extra-codeowners-evidence-{'1' * 33}",
        f"extra-codeowners-evidence-{'1' * 31}\n",
        f"--privileged-{'1' * 32}",
    ),
)
def test_rejects_unbound_or_noncanonical_container_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    container_name: str,
) -> None:
    inputs, output = make_mounts(tmp_path)
    allow_test_output(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError, match="container name"):
        sandbox.build_docker_command(
            image=IMAGE,
            container_name=container_name,
            inputs=inputs,
            output=output,
            parser="evidence",
            parser_arguments=("bundle",),
        )


@pytest.mark.parametrize(
    "image",
    (
        "ghcr.io/stampbot/parser:latest",
        f"ghcr.io/stampbot/parser@sha256:{'A' * 64}",
        f"--privileged@sha256:{'1' * 64}",
        f"ghcr.io//stampbot/parser@sha256:{'1' * 64}",
        f"ghcr.io/stampbot/../parser@sha256:{'1' * 64}",
        f"ghcr.io/stampbot/parser@sha512:{'1' * 64}",
        f"ghcr.io:bad/stampbot/parser@sha256:{'1' * 64}",
        f"ghcr.io:70000/stampbot/parser@sha256:{'1' * 64}",
        f"ghcr.io/stampbot/parser:tag@sha256:{'1' * 64}",
        f"sha256:{'A' * 64}",
        f"sha256:{'1' * 63}",
        f"sha256:{'1' * 65}",
        f"sha256:{'1' * 64}:latest",
        f"--sha256:{'1' * 64}",
    ),
)
def test_rejects_mutable_or_noncanonical_image_references(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    image: str,
) -> None:
    inputs, output = make_mounts(tmp_path)
    allow_test_output(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError, match="parser image"):
        sandbox.build_docker_command(
            image=image,
            container_name=EVIDENCE_CONTAINER_NAME,
            inputs=inputs,
            output=output,
            parser="evidence",
            parser_arguments=("bundle",),
        )


@pytest.mark.parametrize("name", ("", "Upper", "../input", "two_words", "a" * 33))
def test_rejects_unsafe_input_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"source")
    output = tmp_path / "output"
    output.mkdir()
    allow_test_output(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError, match="input names"):
        sandbox.build_docker_command(
            image=IMAGE,
            container_name=EVIDENCE_CONTAINER_NAME,
            inputs={name: source},
            output=output,
            parser="evidence",
            parser_arguments=("bundle",),
        )


@pytest.mark.parametrize("kind", ("relative", "symlink", "comma", "special"))
def test_rejects_unsafe_input_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"source")
    source = target
    if kind == "relative":
        source = Path("target")
    elif kind == "symlink":
        source = tmp_path / "link"
        source.symlink_to(target)
    elif kind == "comma":
        source = tmp_path / "bad,input"
        source.write_bytes(b"source")
    elif kind == "special":
        source = tmp_path / "pipe"
        os.mkfifo(source)
    output = tmp_path / "output"
    output.mkdir()
    allow_test_output(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError):
        sandbox.build_docker_command(
            image=IMAGE,
            container_name=EVIDENCE_CONTAINER_NAME,
            inputs={"source": source},
            output=output,
            parser="evidence",
            parser_arguments=("bundle",),
        )


def test_rejects_overlapping_input_and_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    source = output / "source"
    source.write_bytes(b"source")
    allow_test_output(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError, match="must not overlap"):
        sandbox.build_docker_command(
            image=IMAGE,
            container_name=EVIDENCE_CONTAINER_NAME,
            inputs={"source": source},
            output=output,
            parser="evidence",
            parser_arguments=("bundle",),
        )


def test_rejects_any_input_that_could_contain_the_docker_socket(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()

    with pytest.raises(sandbox.ParserSandboxError, match="Docker socket"):
        sandbox._input_mounts({"runtime": Path("/run")}, output)


@pytest.mark.parametrize(
    "arguments",
    (
        (),
        ("--option",),
        ("bundle\n--privileged",),
        ("bundle", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ),
)
def test_rejects_unsafe_parser_arguments(arguments: tuple[str, ...]) -> None:
    with pytest.raises(sandbox.ParserSandboxError):
        sandbox._parser_arguments(arguments)


def test_output_must_be_a_small_empty_hardened_tmpfs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        (
            f"1 0 0:1 / {output} rw,nosuid,nodev,noexec - "
            "tmpfs tmpfs rw,nosuid,nodev,noexec,size=67108864,nr_inodes=8192\n"
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "PARSER_UID", os.getuid())
    monkeypatch.setattr(sandbox, "PARSER_GID", os.getgid())
    monkeypatch.setattr(
        sandbox.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=4096,
            f_blocks=(64 * 1024 * 1024) // 4096,
            f_files=8192,
        ),
    )

    sandbox._require_bounded_output_tmpfs(output, "source-plan")


@pytest.mark.parametrize(
    ("parser", "megabytes"),
    (("source-plan", 64), ("evidence", 1152)),
)
def test_each_parser_has_one_fixed_output_tmpfs_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    parser: str,
    megabytes: int,
) -> None:
    output = tmp_path / parser
    output.mkdir(mode=0o700)
    mountinfo = tmp_path / f"{parser}-mountinfo"
    mountinfo.write_text(
        (
            f"1 0 0:1 / {output} rw,nosuid,nodev,noexec - "
            f"tmpfs tmpfs rw,nosuid,nodev,noexec,size={megabytes}m,nr_inodes=8192\n"
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "PARSER_UID", os.getuid())
    monkeypatch.setattr(sandbox, "PARSER_GID", os.getgid())
    monkeypatch.setattr(
        sandbox.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=4096,
            f_blocks=(megabytes * 1024 * 1024) // 4096,
            f_files=8192,
        ),
    )

    sandbox._require_bounded_output_tmpfs(output, parser)


def test_source_plan_profile_rejects_the_evidence_sized_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        (
            f"1 0 0:1 / {output} rw,nosuid,nodev,noexec - "
            "tmpfs tmpfs rw,nosuid,nodev,noexec,size=1152m,nr_inodes=8192\n"
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "PARSER_UID", os.getuid())
    monkeypatch.setattr(sandbox, "PARSER_GID", os.getgid())
    monkeypatch.setattr(
        sandbox.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=4096,
            f_blocks=(1152 * 1024 * 1024) // 4096,
            f_files=8192,
        ),
    )

    with pytest.raises(sandbox.ParserSandboxError, match="byte or inode"):
        sandbox._require_bounded_output_tmpfs(output, "source-plan")


@pytest.mark.parametrize(
    ("filesystem", "options", "super_options", "blocks", "inodes"),
    (
        ("ext4", "rw,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec", 1, 1),
        ("tmpfs", "ro,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec", 1, 1),
        ("tmpfs", "rw,nodev,noexec", "rw,nosuid,nodev,noexec", 1, 1),
        ("tmpfs", "rw,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec", 16385, 1),
        ("tmpfs", "rw,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec", 1, 8193),
    ),
)
def test_rejects_unbounded_or_unhardened_output_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filesystem: str,
    options: str,
    super_options: str,
    blocks: int,
    inodes: int,
) -> None:
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        f"1 0 0:1 / {output} {options} - {filesystem} tmpfs {super_options}\n",
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "PARSER_UID", os.getuid())
    monkeypatch.setattr(sandbox, "PARSER_GID", os.getgid())
    monkeypatch.setattr(
        sandbox.os,
        "statvfs",
        lambda _path: SimpleNamespace(
            f_frsize=4096,
            f_blocks=blocks,
            f_files=inodes,
        ),
    )

    with pytest.raises(sandbox.ParserSandboxError):
        sandbox._require_bounded_output_tmpfs(output, "source-plan")


def test_output_mount_must_be_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    (output / "existing").write_bytes(b"unexpected")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        (f"1 0 0:1 / {output} rw,nosuid,nodev,noexec - tmpfs tmpfs rw,nosuid,nodev,noexec\n"),
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "PARSER_UID", os.getuid())
    monkeypatch.setattr(sandbox, "PARSER_GID", os.getgid())
    monkeypatch.setattr(
        sandbox.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_frsize=4096, f_blocks=1, f_files=1),
    )

    with pytest.raises(sandbox.ParserSandboxError, match="must be empty"):
        sandbox._require_bounded_output_tmpfs(output, "source-plan")


def test_fixed_uid_output_inventory_rejects_existing_entries(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    sandbox._require_empty_directory(output, "parser output tmpfs")

    (output / "existing").write_bytes(b"unexpected")
    with pytest.raises(sandbox.ParserSandboxError, match="must be empty"):
        sandbox._require_empty_directory(output, "parser output tmpfs")


def test_inside_tmpfs_identity_requires_the_fixed_parser_owner_and_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    monkeypatch.setattr(sandbox, "PARSER_UID", os.getuid())
    monkeypatch.setattr(sandbox, "PARSER_GID", os.getgid())

    sandbox._require_inside_tmpfs_identity(work, "evidence work")

    work.chmod(0o755)
    with pytest.raises(sandbox.ParserSandboxError, match="mode or owner"):
        sandbox._require_inside_tmpfs_identity(work, "evidence work")

    work.chmod(0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(work, target_is_directory=True)
    with pytest.raises(sandbox.ParserSandboxError, match="mode or owner"):
        sandbox._require_inside_tmpfs_identity(linked, "evidence work")


def test_execution_does_not_forward_the_ambient_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setenv("GITHUB_TOKEN", "host-secret")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-secret")
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.example:2375")
    monkeypatch.setattr(sandbox, "_require_safe_docker_binary", lambda: None)
    removed: list[str] = []

    class FakeProcess:
        def wait(self) -> int:
            return 23

    def fake_popen(command: tuple[str, ...], **kwargs: Any) -> FakeProcess:
        captured["command"] = command
        captured.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(sandbox.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = sandbox.execute_docker_command(
        (
            "/usr/bin/docker",
            "run",
            f"--name={EVIDENCE_CONTAINER_NAME}",
            "--log-driver=none",
        ),
        container_name=EVIDENCE_CONTAINER_NAME,
    )

    assert result == 23
    assert removed == [EVIDENCE_CONTAINER_NAME]
    assert captured["env"] == sandbox.SAFE_EXECUTION_ENVIRONMENT
    serialized = json.dumps(captured)
    assert "host-secret" not in serialized
    assert "oidc-secret" not in serialized
    assert "DOCKER_HOST" not in cast(dict[str, str], captured["env"])
    assert captured["close_fds"] is True
    assert captured["stdin"] == sandbox.subprocess.DEVNULL
    assert captured["stdout"] == sandbox.subprocess.DEVNULL
    assert captured["stderr"] == sandbox.subprocess.DEVNULL


def test_execution_discards_an_unbounded_hostile_output_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_docker = tmp_path / "fake-docker"
    fake_docker.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import os",
                "chunk = b'x' * 65536",
                "for _index in range(128):",
                "    os.write(1, chunk)",
                "    os.write(2, chunk)",
                "raise SystemExit(7)",
                "",
            )
        ),
        encoding="utf-8",
    )
    fake_docker.chmod(0o700)
    monkeypatch.setattr(sandbox, "DOCKER_BINARY", str(fake_docker))
    monkeypatch.setattr(sandbox, "_require_safe_docker_binary", lambda: None)
    monkeypatch.setattr(sandbox, "_force_remove_container", lambda _name: None)

    result = sandbox.execute_docker_command(
        (
            str(fake_docker),
            "run",
            f"--name={EVIDENCE_CONTAINER_NAME}",
            "--log-driver=none",
        ),
        container_name=EVIDENCE_CONTAINER_NAME,
    )

    captured = capsys.readouterr()
    assert result == 7
    assert captured.out == ""
    assert "x" * 100 not in captured.err
    assert len(captured.err.encode("utf-8")) < 256


def test_term_resistant_container_is_force_removed_before_execution_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "container.pid"
    removed = tmp_path / "container.removed"
    fake_docker = tmp_path / "fake-docker"
    fake_docker.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import os",
                "from pathlib import Path",
                "import signal",
                "import sys",
                "import time",
                f"state = Path({str(state)!r})",
                f"removed = Path({str(removed)!r})",
                "if len(sys.argv) > 1 and sys.argv[1] == 'rm':",
                "    try:",
                "        os.kill(int(state.read_text(encoding='ascii')), signal.SIGKILL)",
                "    except (FileNotFoundError, ProcessLookupError):",
                "        pass",
                "    removed.write_text('removed\\n', encoding='ascii')",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                "state.write_text(str(os.getpid()), encoding='ascii')",
                "while True:",
                "    time.sleep(1)",
                "",
            )
        ),
        encoding="utf-8",
    )
    fake_docker.chmod(0o700)
    monkeypatch.setattr(sandbox, "DOCKER_BINARY", str(fake_docker))
    monkeypatch.setattr(sandbox, "_require_safe_docker_binary", lambda: None)
    sender_failed: list[str] = []

    def interrupt_after_container_starts() -> None:
        for _attempt in range(500):
            if state.exists():
                os.kill(os.getpid(), signal.SIGTERM)
                return
            time.sleep(0.01)
        sender_failed.append("container never started")

    sender = threading.Thread(target=interrupt_after_container_starts, daemon=True)
    sender.start()
    result = sandbox.execute_docker_command(
        (
            str(fake_docker),
            "run",
            f"--name={EVIDENCE_CONTAINER_NAME}",
            "--log-driver=none",
        ),
        container_name=EVIDENCE_CONTAINER_NAME,
    )
    sender.join(timeout=2)

    assert sender_failed == []
    assert result == 128 + signal.SIGTERM
    assert removed.read_text(encoding="ascii") == "removed\n"
    container_pid = int(state.read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(container_pid, 0)


def test_command_mode_is_a_dry_run_until_execute_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs, output = make_mounts(tmp_path)
    allow_test_output(monkeypatch)

    def unexpected_execute(
        _command: tuple[str, ...],
        *,
        container_name: str,
    ) -> int:
        del container_name
        raise AssertionError("dry-run command executed Docker")

    monkeypatch.setattr(sandbox, "execute_docker_command", unexpected_execute)
    result = sandbox.main(
        (
            "command",
            "--image",
            IMAGE,
            "--container-name",
            EVIDENCE_CONTAINER_NAME,
            "--input",
            f"store={inputs['store']}",
            "--output",
            str(output),
            "--parser",
            "evidence",
            "--",
            "bundle",
        )
    )

    assert result == 0
    record = json.loads(capsys.readouterr().out)
    assert record["schema_version"] == 1
    assert record["kind"] == "extra-codeowners/evidence-parser-command"
    assert record["command"][0:2] == ["/usr/bin/docker", "run"]


def test_explicit_execute_returns_the_docker_exit_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, output = make_mounts(tmp_path)
    allow_test_output(monkeypatch)
    captured: list[tuple[str, ...]] = []

    def execute(command: tuple[str, ...], *, container_name: str) -> int:
        assert container_name == EVIDENCE_CONTAINER_NAME
        captured.append(command)
        return 19

    monkeypatch.setattr(sandbox, "execute_docker_command", execute)
    result = sandbox.main(
        (
            "command",
            "--image",
            IMAGE,
            "--container-name",
            EVIDENCE_CONTAINER_NAME,
            "--input",
            f"store={inputs['store']}",
            "--output",
            str(output),
            "--parser",
            "evidence",
            "--execute",
            "--",
            "bundle",
        )
    )

    assert result == 19
    assert len(captured) == 1


def test_inside_preflight_rejects_ambient_github_and_actions_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "secret")

    with pytest.raises(sandbox.ParserSandboxError, match="credential variable"):
        sandbox._require_no_ambient_credentials()


def test_capability_preflight_requires_every_capability_set_to_be_zero(
    tmp_path: Path,
) -> None:
    status = tmp_path / "status"
    status.write_text(
        "\n".join(
            (
                "CapInh:\t0000000000000000",
                "CapPrm:\t0000000000000000",
                "CapEff:\t0000000000000000",
                "CapBnd:\t0000000000000000",
                "CapAmb:\t0000000000000000",
                "NoNewPrivs:\t1",
                "Seccomp:\t2",
            )
        ),
        encoding="ascii",
    )
    sandbox._require_zero_capabilities(status)

    status.write_text(
        status.read_text(encoding="ascii").replace(
            "CapEff:\t0000000000000000",
            "CapEff:\t0000000000000001",
        ),
        encoding="ascii",
    )
    with pytest.raises(sandbox.ParserSandboxError, match="still has"):
        sandbox._require_zero_capabilities(status)


@pytest.mark.parametrize(
    ("field", "unsafe_value", "message"),
    (
        ("NoNewPrivs", "0", "no-new-privileges"),
        ("Seccomp", "0", "seccomp"),
    ),
)
def test_process_preflight_requires_nnp_and_seccomp(
    tmp_path: Path,
    field: str,
    unsafe_value: str,
    message: str,
) -> None:
    values = {
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
        "Seccomp": "2",
    }
    values[field] = unsafe_value
    status = tmp_path / "status"
    status.write_text(
        "".join(f"{name}:\t{value}\n" for name, value in values.items()),
        encoding="ascii",
    )

    with pytest.raises(sandbox.ParserSandboxError, match=message):
        sandbox._require_zero_capabilities(status)


def test_inside_mount_preflight_requires_exact_hardened_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "".join(
            (
                "1 0 0:1 / / ro,relatime - overlay overlay rw,lowerdir=/layers\n",
                (
                    "2 1 0:2 / /scratch rw,nosuid,nodev,noexec,relatime - "
                    "tmpfs tmpfs rw,size=67108864\n"
                ),
                (
                    "3 1 0:3 / /output rw,nosuid,nodev,noexec,relatime - "
                    "tmpfs tmpfs rw,size=67108864\n"
                ),
                "4 1 0:4 / /inputs/store ro,relatime - ext4 source rw,errors=remount-ro\n",
            )
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "_require_inside_tmpfs_identity", lambda _path, _source: None)
    monkeypatch.setattr(
        sandbox.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_frsize=4096, f_blocks=1, f_files=1),
    )

    sandbox._require_inside_mounts(("store",), "source-plan")

    mountinfo.write_text(
        mountinfo.read_text(encoding="ascii").replace(
            "/inputs/store ro,relatime - ext4 source rw,errors=remount-ro",
            "/inputs/store rw,relatime - ext4 source rw,errors=remount-ro",
        ),
        encoding="ascii",
    )
    with pytest.raises(sandbox.ParserSandboxError, match=r"input .* is writable"):
        sandbox._require_inside_mounts(("store",), "source-plan")


def test_evidence_mount_preflight_requires_a_distinct_large_bounded_work_tmpfs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "".join(
            (
                "1 0 0:1 / / ro,relatime - overlay overlay rw,lowerdir=/layers\n",
                (
                    "2 1 0:2 / /scratch rw,nosuid,nodev,noexec,relatime - "
                    "tmpfs tmpfs rw,size=67108864\n"
                ),
                (
                    "3 1 0:3 / /output rw,nosuid,nodev,noexec,relatime - "
                    "tmpfs tmpfs rw,size=1207959552\n"
                ),
                (
                    "4 1 0:4 / /work rw,nosuid,nodev,noexec,relatime - "
                    "tmpfs tmpfs rw,size=3221225472\n"
                ),
                "5 1 0:5 / /inputs/store ro,relatime - ext4 source rw,errors=remount-ro\n",
            )
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(sandbox, "MOUNTINFO_PATH", mountinfo)
    monkeypatch.setattr(sandbox, "_require_inside_tmpfs_identity", lambda _path, _source: None)

    def filesystem(path: Path) -> SimpleNamespace:
        if path == Path("/scratch"):
            return SimpleNamespace(f_frsize=4096, f_blocks=1, f_files=4096)
        if path == Path("/output"):
            return SimpleNamespace(f_frsize=4096, f_blocks=1, f_files=8192)
        assert path == Path("/work")
        return SimpleNamespace(
            f_frsize=4096,
            f_blocks=sandbox.EVIDENCE_WORK_BYTES // 4096,
            f_files=131072,
        )

    monkeypatch.setattr(sandbox.os, "statvfs", filesystem)

    sandbox._require_inside_mounts(("store",), "evidence")

    mountinfo.write_text(
        mountinfo.read_text(encoding="ascii").replace(
            ("4 1 0:4 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3221225472\n"),
            "",
        ),
        encoding="ascii",
    )
    with pytest.raises(sandbox.ParserSandboxError, match="evidence work"):
        sandbox._require_inside_mounts(("store",), "evidence")


def test_network_preflight_requires_only_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox.socket, "if_nameindex", lambda: ((1, "lo"), (2, "eth0")))

    with pytest.raises(sandbox.ParserSandboxError, match="non-loopback"):
        sandbox._require_offline_network()


def test_network_preflight_requires_an_outbound_probe_to_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _address: tuple[str, int]) -> None:
            raise OSError("network unreachable")

        def close(self) -> None:
            return None

    monkeypatch.setattr(sandbox.socket, "if_nameindex", lambda: ((1, "lo"),))
    monkeypatch.setattr(sandbox.socket, "socket", lambda *_args: FakeSocket())

    sandbox._require_offline_network()


def test_inside_exec_uses_only_the_fixed_parser_and_clean_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    preflight: list[str] = []
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: sandbox.PARSER_UID)
    monkeypatch.setattr(sandbox.os, "getegid", lambda: sandbox.PARSER_GID)
    monkeypatch.setattr(sandbox, "_require_no_ambient_credentials", lambda: None)
    monkeypatch.setattr(sandbox, "_require_zero_capabilities", lambda: None)
    monkeypatch.setattr(sandbox, "_require_no_docker_socket", lambda: None)
    monkeypatch.setattr(sandbox, "_require_offline_network", lambda: None)
    monkeypatch.setattr(
        sandbox,
        "_require_inside_mounts",
        lambda _names, _parser: preflight.append("mounts"),
    )
    monkeypatch.setattr(
        sandbox,
        "_require_empty_directory",
        lambda path, source: preflight.append(f"empty:{path}:{source}"),
    )
    monkeypatch.setattr(sandbox.os, "umask", lambda mode: captured.setdefault("umask", mode))

    def fake_execve(
        executable: str,
        command: tuple[str, ...],
        environment: dict[str, str],
    ) -> None:
        preflight.append("exec")
        captured["executable"] = executable
        captured["command"] = command
        captured["environment"] = environment

    monkeypatch.setattr(sandbox.os, "execve", fake_execve)

    sandbox._inside_command(
        "evidence",
        ("repo", "store"),
        ("bundle", "--output", "/output/bundle"),
    )

    assert captured["executable"] == "/opt/venv/bin/python"
    assert preflight == ["mounts", "empty:/output:parser output tmpfs", "exec"]
    assert captured["umask"] == 0o022
    assert captured["command"] == (
        "/opt/venv/bin/python",
        "/build/.github/scripts/container_evidence.py",
        "bundle",
        "--output",
        "/output/bundle",
    )
    assert captured["environment"] == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": "/inputs/repo",
        "HOME": "/scratch",
        "PATH": "/opt/venv/bin:/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "TMPDIR": "/scratch",
    }


def test_source_plan_staging_remains_on_the_small_scratch_tmpfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: sandbox.PARSER_UID)
    monkeypatch.setattr(sandbox.os, "getegid", lambda: sandbox.PARSER_GID)
    monkeypatch.setattr(sandbox, "_require_no_ambient_credentials", lambda: None)
    monkeypatch.setattr(sandbox, "_require_zero_capabilities", lambda: None)
    monkeypatch.setattr(sandbox, "_require_no_docker_socket", lambda: None)
    monkeypatch.setattr(sandbox, "_require_offline_network", lambda: None)
    monkeypatch.setattr(sandbox, "_require_inside_mounts", lambda _names, _parser: None)
    monkeypatch.setattr(sandbox, "_require_empty_directory", lambda _path, _source: None)
    monkeypatch.setattr(sandbox.os, "umask", lambda _mode: 0)

    def fake_execve(
        _executable: str,
        _command: tuple[str, ...],
        environment: dict[str, str],
    ) -> None:
        captured["environment"] = environment

    monkeypatch.setattr(sandbox.os, "execve", fake_execve)

    sandbox._inside_command("source-plan", ("store",), ("alpine-distfile-plan",))

    assert cast(dict[str, str], captured["environment"])["TMPDIR"] == "/scratch"


def test_evidence_inside_command_requires_only_the_exact_repo_safe_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: sandbox.PARSER_UID)
    monkeypatch.setattr(sandbox.os, "getegid", lambda: sandbox.PARSER_GID)

    with pytest.raises(sandbox.ParserSandboxError, match="repository input"):
        sandbox._inside_command("evidence", ("store",), ("bundle",))


def make_evidence_outputs(root: Path, architecture: str = "amd64") -> dict[str, bytes]:
    archive = f"extra-codeowners-ci-linux-{architecture}-evidence.tar.gz"
    archive_content = b"bounded evidence archive"
    digest = sandbox.hashlib.sha256(archive_content).hexdigest()
    values = {
        archive: archive_content,
        f"{archive}.sha256": f"{digest}  {archive}\n".encode("ascii"),
        f"evidence-predicate-{architecture}.json": sandbox.canonical_json(
            {
                "artifact": {"filename": archive, "sha256": digest},
                "media_type": "application/vnd.in-toto+json",
                "platform": f"linux/{architecture}",
                "schema_version": 7,
            }
        ),
    }
    for name, content in values.items():
        (root / name).write_bytes(content)
    return values


def allow_materialization_tmpfs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sandbox,
        "_require_bounded_output_tmpfs",
        lambda *_args, **_kwargs: None,
    )


def test_materializes_one_exact_stable_source_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source-plan-output"
    destination = tmp_path / "trusted-plan"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    content = b'{"kind":"test-plan"}\n'
    (source / "alpine-plan.json").write_bytes(content)
    allow_materialization_tmpfs(monkeypatch)

    binding = sandbox.materialize_source_plan(source, destination)

    assert binding == {
        "schema_version": 1,
        "kind": "extra-codeowners/materialized-source-plan",
        "filename": "alpine-plan.json",
        "sha256": sandbox.hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }
    published = destination / "alpine-plan.json"
    assert published.read_bytes() == content
    assert published.stat().st_nlink == 1
    assert not any(
        path.name.startswith(".extra-codeowners-materialize-") for path in destination.iterdir()
    )


@pytest.mark.parametrize(
    "attack",
    (
        "extra-entry",
        "symlink",
        "fifo",
        "hardlink",
        "oversized",
        "occupied-destination",
    ),
)
def test_source_plan_materialization_rejects_hostile_nodes_and_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    source = tmp_path / "source-plan-output"
    destination = tmp_path / "trusted-plan"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    plan = source / "alpine-plan.json"
    if attack == "symlink":
        target = tmp_path / "outside-plan.json"
        target.write_bytes(b"outside")
        plan.symlink_to(target)
    elif attack == "fifo":
        os.mkfifo(plan)
    else:
        plan.write_bytes(b'{"kind":"test-plan"}\n')
    if attack == "extra-entry":
        (source / "extra").write_bytes(b"unexpected")
    elif attack == "hardlink":
        os.link(plan, tmp_path / "outside-hardlink")
    elif attack == "oversized":
        plan.write_bytes(b"x" * (sandbox.SOURCE_PLAN_BYTES + 1))
    elif attack == "occupied-destination":
        (destination / "occupied").write_bytes(b"do not replace")
    allow_materialization_tmpfs(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError):
        sandbox.materialize_source_plan(source, destination)

    assert not (destination / "alpine-plan.json").exists()
    assert not any(
        path.name.startswith(".extra-codeowners-materialize-") for path in destination.iterdir()
    )


@pytest.mark.parametrize("node_type", (stat.S_IFCHR, stat.S_IFBLK))
def test_regular_output_identity_rejects_device_nodes(node_type: int) -> None:
    metadata = SimpleNamespace(
        st_mode=node_type | 0o600,
        st_nlink=1,
        st_size=1,
    )

    with pytest.raises(sandbox.ParserSandboxError, match="regular file"):
        sandbox._regular_identity(
            metadata,
            name="alpine-plan.json",
            maximum=sandbox.SOURCE_PLAN_BYTES,
        )


def test_source_plan_materialization_rejects_a_device_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source-plan-output"
    destination = tmp_path / "trusted-plan"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    (source / "alpine-plan.json").write_bytes(b"placeholder")
    allow_materialization_tmpfs(monkeypatch)
    real_stat = sandbox.os.stat

    def report_device(*args: Any, **kwargs: Any) -> Any:
        if (
            args
            and args[0] == "alpine-plan.json"
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            return SimpleNamespace(
                st_mode=stat.S_IFCHR | 0o600,
                st_nlink=1,
                st_size=1,
            )
        return real_stat(*args, **kwargs)

    monkeypatch.setattr(sandbox.os, "stat", report_device)

    with pytest.raises(sandbox.ParserSandboxError, match="regular file"):
        sandbox.materialize_source_plan(source, destination)

    assert list(destination.iterdir()) == []


def test_source_plan_materialization_requires_a_private_host_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source-plan-output"
    destination = tmp_path / "trusted-plan"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    destination.chmod(0o755)
    (source / "alpine-plan.json").write_bytes(b"plan")
    allow_materialization_tmpfs(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError, match="private and host-owned"):
        sandbox.materialize_source_plan(source, destination)

    assert list(destination.iterdir()) == []


def test_source_plan_materialization_rejects_in_place_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source-plan-output"
    destination = tmp_path / "trusted-plan"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    plan = source / "alpine-plan.json"
    plan.write_bytes(b"plan")
    allow_materialization_tmpfs(monkeypatch)
    original_copy = sandbox._copy_stable_output

    def mutate_after_copy(**kwargs: Any) -> tuple[str, tuple[int, ...], str, bytes]:
        result = original_copy(**kwargs)
        plan.write_bytes(b"evil")
        return cast(tuple[str, tuple[int, ...], str, bytes], result)

    monkeypatch.setattr(sandbox, "_copy_stable_output", mutate_after_copy)

    with pytest.raises(sandbox.ParserSandboxError, match="changed"):
        sandbox.materialize_source_plan(source, destination)

    assert list(destination.iterdir()) == []


def test_materializes_only_the_exact_stable_evidence_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    expected = make_evidence_outputs(source)
    allow_materialization_tmpfs(monkeypatch)

    sandbox.materialize_evidence_output(source, destination, "amd64")

    assert {path.name: path.read_bytes() for path in destination.iterdir()} == expected
    assert all(path.stat().st_nlink == 1 for path in destination.iterdir())
    assert not any(
        path.name.startswith(".extra-codeowners-materialize-") for path in destination.iterdir()
    )


@pytest.mark.parametrize(
    "attack",
    (
        "extra-entry",
        "case-variant",
        "symlink",
        "hardlink",
        "existing-destination",
        "bad-checksum",
        "bad-predicate",
        "deep-predicate",
    ),
)
def test_materialization_rejects_hostile_or_ambiguous_output_sets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    expected = make_evidence_outputs(source)
    archive = "extra-codeowners-ci-linux-amd64-evidence.tar.gz"
    checksum = f"{archive}.sha256"
    predicate = "evidence-predicate-amd64.json"
    if attack == "extra-entry":
        (source / "extra").write_bytes(b"unexpected")
    elif attack == "case-variant":
        (source / predicate.upper()).write_bytes(b"unexpected")
    elif attack == "symlink":
        (source / checksum).unlink()
        (source / checksum).symlink_to(source / archive)
    elif attack == "hardlink":
        external = tmp_path / "external"
        os.link(source / archive, external)
    elif attack == "existing-destination":
        (destination / archive).write_bytes(b"do not replace")
    elif attack == "bad-checksum":
        (source / checksum).write_bytes(f"{'0' * 64}  {archive}\n".encode("ascii"))
    elif attack == "bad-predicate":
        (source / predicate).write_bytes(
            sandbox.canonical_json(
                {
                    "artifact": {"filename": archive, "sha256": "0" * 64},
                    "schema_version": 7,
                }
            )
        )
    elif attack == "deep-predicate":
        (source / predicate).write_bytes(b"[" * 2000 + b"0" + b"]" * 2000)
    allow_materialization_tmpfs(monkeypatch)

    with pytest.raises(sandbox.ParserSandboxError):
        sandbox.materialize_evidence_output(source, destination, "amd64")

    for name in expected:
        path = destination / name
        if attack == "existing-destination" and name == archive:
            assert path.read_bytes() == b"do not replace"
        else:
            assert not path.exists()
    assert not any(
        path.name.startswith(".extra-codeowners-materialize-") for path in destination.iterdir()
    )


def test_materialization_requires_an_explicit_host_ownership_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    make_evidence_outputs(source)
    captured: dict[str, object] = {}

    def require_tmpfs(path: Path, parser: str, **kwargs: object) -> None:
        captured.update({"path": path, "parser": parser, **kwargs})

    monkeypatch.setattr(sandbox, "_require_bounded_output_tmpfs", require_tmpfs)

    sandbox.materialize_evidence_output(source, destination, "amd64")

    assert captured == {
        "path": source,
        "parser": "evidence",
        "require_empty": False,
        "owner_uid": os.getuid(),
        "owner_gid": os.getgid(),
    }

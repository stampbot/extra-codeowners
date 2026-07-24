#!/usr/bin/env python3
"""Build or run the fixed Docker sandbox used by offline evidence parsers.

The normal command prints the Docker argv as canonical JSON. It does not start a
container unless the caller also supplies ``--execute``. The output directory
must already be an empty, size-bounded tmpfs mount owned by the parser UID/GID.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

SCHEMA_VERSION = 1
COMMAND_KIND = "extra-codeowners/evidence-parser-command"
SOURCE_PLAN_BINDING_KIND = "extra-codeowners/materialized-source-plan"

DOCKER_BINARY = "/usr/bin/docker"
PARSER_UID = 65532
PARSER_GID = 65532
PARSER_PIDS = 64
PARSER_CPUS = "1.0"
SOURCE_PLAN_MEMORY_BYTES = 512 * 1024 * 1024
SCRATCH_BYTES = 64 * 1024 * 1024
SCRATCH_INODES = 4096
SOURCE_PLAN_OUTPUT_BYTES = 64 * 1024 * 1024
SOURCE_PLAN_BYTES = 4 * 1024 * 1024
EVIDENCE_OUTPUT_BYTES = 1152 * 1024 * 1024
OUTPUT_INODES = 8192
# The collector may retain a full 1 GiB tree while staging a full output trio.
# Keep a fixed additional allowance for filesystem metadata and bounded helpers.
EVIDENCE_RETAINED_BYTES = 1024 * 1024 * 1024
EVIDENCE_WORK_OVERHEAD_BYTES = 896 * 1024 * 1024
EVIDENCE_WORK_BYTES = EVIDENCE_RETAINED_BYTES + EVIDENCE_OUTPUT_BYTES + EVIDENCE_WORK_OVERHEAD_BYTES
EVIDENCE_WORK_INODES = 131072
EVIDENCE_MEMORY_HEADROOM_BYTES = 832 * 1024 * 1024
EVIDENCE_MEMORY_BYTES = (
    EVIDENCE_WORK_BYTES + EVIDENCE_OUTPUT_BYTES + SCRATCH_BYTES + EVIDENCE_MEMORY_HEADROOM_BYTES
)
EVIDENCE_ARCHIVE_BYTES = 1024 * 1024 * 1024
EVIDENCE_PREDICATE_BYTES = 1024 * 1024
EVIDENCE_CHECKSUM_BYTES = 1024
EVIDENCE_MATERIALIZED_BYTES = (
    EVIDENCE_ARCHIVE_BYTES + EVIDENCE_PREDICATE_BYTES + EVIDENCE_CHECKSUM_BYTES
)
COPY_CHUNK_BYTES = 1024 * 1024
MAX_INPUTS = 32
MAX_ARGUMENTS = 256
MAX_ARGUMENT_BYTES = 4096
MAX_MOUNTINFO_BYTES = 1024 * 1024
MAX_MOUNTINFO_LINES = 4096
CONTAINER_CLEANUP_SECONDS = 15

CONTAINER_PYTHON = "/opt/venv/bin/python"
CONTAINER_WRAPPER = "/build/.github/scripts/run_evidence_parser.py"
CONTAINER_INPUT_ROOT = "/inputs"
CONTAINER_OUTPUT = "/output"
CONTAINER_SCRATCH = "/scratch"
CONTAINER_WORK = "/work"
PARSER_PROGRAMS = {
    "evidence": "/build/.github/scripts/container_evidence.py",
    "source-plan": "/build/.github/scripts/container_source_plan.py",
}

MOUNTINFO_PATH = Path("/proc/self/mountinfo")
STATUS_PATH = Path("/proc/self/status")
DOCKER_SOCKET_PATHS = (
    Path("/run/docker.sock"),
    Path("/var/run/docker.sock"),
)
SAFE_EXECUTION_ENVIRONMENT = {
    "DOCKER_CONFIG": "/nonexistent",
    "HOME": "/nonexistent",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}
BLOCKED_ENVIRONMENT_NAMES = frozenset(
    {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    }
)

INPUT_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
CONTAINER_NAME = re.compile(r"extra-codeowners-(?:evidence|source-plan)-[0-9a-f]{32}")
IMAGE_COMPONENT = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
REGISTRY_HOST = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")
SAFE_ARGUMENT = re.compile(r"[\x20-\x7e]+")


class ParserSandboxError(RuntimeError):
    """The requested parser sandbox does not meet the fixed security contract."""


@dataclass(frozen=True)
class InputMount:
    """One exact host input and its fixed container mount name."""

    name: str
    source: Path
    directory: bool


@dataclass(frozen=True)
class MountRecord:
    """The mount fields needed by the host and in-container checks."""

    mount_point: Path
    filesystem: str
    options: frozenset[str]
    super_options: frozenset[str]


def canonical_json(value: object) -> bytes:
    """Return the one accepted JSON representation of a dry-run command."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ParserSandboxError("parser command cannot be encoded as canonical JSON") from exc


def canonical_evidence_json(value: object) -> bytes:
    """Return the collector's one accepted evidence JSON representation."""

    output = bytearray()
    encoder = json.JSONEncoder(
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    try:
        for chunk in encoder.iterencode(value):
            encoded = chunk.encode("utf-8")
            if len(output) + len(encoded) > EVIDENCE_PREDICATE_BYTES - 1:
                raise ParserSandboxError("evidence predicate canonical JSON exceeds its byte limit")
            output.extend(encoded)
        output.extend(b"\n")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ParserSandboxError("evidence predicate cannot be encoded as canonical JSON") from exc
    return bytes(output)


def _safe_text(value: str, source: str, *, maximum: int) -> str:
    if not 1 <= len(value.encode("utf-8")) <= maximum or SAFE_ARGUMENT.fullmatch(value) is None:
        raise ParserSandboxError(f"{source} contains unsupported characters or is too long")
    return value


def _image_reference(value: str) -> str:
    value = _safe_text(value, "parser image", maximum=512)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None:
        return value
    if value.count("@") != 1:
        raise ParserSandboxError("parser image must use one immutable SHA-256 digest")
    name, separator, digest = value.partition("@sha256:")
    components = name.split("/")
    registry = components[0] if len(components) > 1 else None
    if registry is not None and ":" in registry:
        host, colon, port = registry.rpartition(":")
        valid_registry = (
            colon == ":"
            and REGISTRY_HOST.fullmatch(host) is not None
            and port.isascii()
            and port.isdecimal()
            and 1 <= int(port) <= 65535
        )
    else:
        valid_registry = registry is None or REGISTRY_HOST.fullmatch(registry) is not None
    repository_components = components[1:] if registry is not None else components
    if (
        separator != "@sha256:"
        or LOWER_SHA256.fullmatch(digest) is None
        or not 1 <= len(name) <= 255
        or not valid_registry
        or not repository_components
        or any(IMAGE_COMPONENT.fullmatch(component) is None for component in repository_components)
    ):
        raise ParserSandboxError("parser image must use a canonical lowercase SHA-256 reference")
    return value


def _container_name(value: str, parser: str) -> str:
    value = _safe_text(value, "parser container name", maximum=96)
    if (
        CONTAINER_NAME.fullmatch(value) is None
        or value != f"extra-codeowners-{parser}-{value.rsplit('-', 1)[-1]}"
    ):
        raise ParserSandboxError(
            "parser container name must bind the parser to one 128-bit lowercase nonce"
        )
    return value


def _canonical_host_path(
    value: Path,
    source: str,
    *,
    require_directory: bool | None,
) -> Path:
    candidate = Path(value)
    encoded = os.fsencode(candidate)
    if (
        not candidate.is_absolute()
        or b"\x00" in encoded
        or b"," in encoded
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise ParserSandboxError(f"{source} must be an absolute path without mount separators")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = candidate.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise ParserSandboxError(f"{source} does not resolve to an existing path") from exc
    if candidate != resolved:
        raise ParserSandboxError(f"{source} must not contain symlinks or noncanonical components")
    if require_directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise ParserSandboxError(f"{source} must be a directory")
    if require_directory is False and not stat.S_ISREG(metadata.st_mode):
        raise ParserSandboxError(f"{source} must be a regular file")
    if require_directory is None and not (
        stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
    ):
        raise ParserSandboxError(f"{source} must be a regular file or directory")
    return resolved


def _mount_path(value: str) -> Path:
    def decode(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    decoded = MOUNT_ESCAPE.sub(decode, value)
    if "\\" in decoded or "\x00" in decoded or not decoded.startswith("/"):
        raise ParserSandboxError("mountinfo contains an unsupported path")
    return Path(decoded)


def _read_mountinfo(path: Path | None = None) -> tuple[MountRecord, ...]:
    if path is None:
        path = MOUNTINFO_PATH
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ParserSandboxError("cannot read the current mount table") from exc
    if not 1 <= len(raw) <= MAX_MOUNTINFO_BYTES:
        raise ParserSandboxError("the current mount table is outside its byte bound")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ParserSandboxError("the current mount table is not ASCII") from exc
    lines = text.splitlines()
    if not 1 <= len(lines) <= MAX_MOUNTINFO_LINES:
        raise ParserSandboxError("the current mount table has too many records")

    records: list[MountRecord] = []
    for line in lines:
        fields = line.split(" ")
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise ParserSandboxError("the current mount table has a malformed record") from exc
        if separator < 6 or len(fields) < separator + 4:
            raise ParserSandboxError("the current mount table has a malformed record")
        options = frozenset(fields[5].split(","))
        if options & {"ro", "rw"} not in (frozenset({"ro"}), frozenset({"rw"})):
            raise ParserSandboxError("the current mount table has an ambiguous access mode")
        records.append(
            MountRecord(
                mount_point=_mount_path(fields[4]),
                filesystem=fields[separator + 1],
                options=options,
                super_options=frozenset(fields[separator + 3].split(",")),
            )
        )
    return tuple(records)


def _exact_mount(records: Sequence[MountRecord], path: Path, source: str) -> MountRecord:
    matches = [record for record in records if record.mount_point == path]
    if len(matches) != 1:
        raise ParserSandboxError(f"{source} must be one exact mount point")
    return matches[0]


def _output_bytes(parser: str) -> int:
    if parser == "source-plan":
        return SOURCE_PLAN_OUTPUT_BYTES
    if parser == "evidence":
        return EVIDENCE_OUTPUT_BYTES
    raise ParserSandboxError("the requested parser program is not allowed")


def _memory_bytes(parser: str) -> int:
    if parser == "source-plan":
        return SOURCE_PLAN_MEMORY_BYTES
    if parser == "evidence":
        return EVIDENCE_MEMORY_BYTES
    raise ParserSandboxError("the requested parser program is not allowed")


def _require_bounded_output_tmpfs(
    path: Path,
    parser: str,
    *,
    require_empty: bool = True,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> None:
    if owner_uid is None:
        owner_uid = PARSER_UID
    if owner_gid is None:
        owner_gid = PARSER_GID
    metadata = path.stat(follow_symlinks=False)
    if (
        metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ParserSandboxError("parser output tmpfs has the wrong mode or owner")

    mount = _exact_mount(_read_mountinfo(), path, "parser output")
    if (
        mount.filesystem != "tmpfs"
        or "rw" not in mount.options
        or not {"nosuid", "nodev", "noexec"}.issubset(mount.options)
    ):
        raise ParserSandboxError(
            "parser output must be a writable tmpfs mounted nosuid,nodev,noexec"
        )
    try:
        filesystem = os.statvfs(path)
    except OSError as exc:
        raise ParserSandboxError("cannot measure the parser output tmpfs") from exc
    total_bytes = filesystem.f_frsize * filesystem.f_blocks
    if (
        not 1 <= total_bytes <= _output_bytes(parser)
        or not 1 <= filesystem.f_files <= OUTPUT_INODES
    ):
        raise ParserSandboxError("parser output tmpfs exceeds its byte or inode bound")
    if require_empty:
        try:
            with os.scandir(path) as entries:
                if next(entries, None) is not None:
                    raise ParserSandboxError("parser output tmpfs must be empty")
        except OSError as exc:
            raise ParserSandboxError("cannot inventory the parser output tmpfs") from exc


def _require_empty_directory(path: Path, source: str) -> None:
    """Require an empty directory from the identity allowed to inventory it."""

    try:
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                raise ParserSandboxError(f"{source} must be empty")
    except OSError as exc:
        raise ParserSandboxError(f"cannot inventory {source}") from exc


def _input_mounts(values: Mapping[str, Path], output: Path) -> tuple[InputMount, ...]:
    if not 1 <= len(values) <= MAX_INPUTS:
        raise ParserSandboxError("the parser requires a bounded, nonempty input set")
    casefolded: set[str] = set()
    identities: set[tuple[int, int]] = set()
    result: list[InputMount] = []
    for name, raw_path in sorted(values.items()):
        if INPUT_NAME.fullmatch(name) is None or name.casefold() in casefolded:
            raise ParserSandboxError("parser input names must be unique canonical tokens")
        casefolded.add(name.casefold())
        path = _canonical_host_path(
            raw_path,
            f"parser input {name!r}",
            require_directory=None,
        )
        metadata = path.stat(follow_symlinks=False)
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            raise ParserSandboxError("the same parser input cannot be mounted more than once")
        identities.add(identity)
        if path == Path("/") or path.name.casefold() == "docker.sock":
            raise ParserSandboxError("a parser input cannot expose the host or Docker socket")
        if any(socket_path.is_relative_to(path) for socket_path in DOCKER_SOCKET_PATHS):
            raise ParserSandboxError("a parser input cannot contain the Docker socket path")
        if path.is_relative_to(output) or output.is_relative_to(path):
            raise ParserSandboxError("parser input and output paths must not overlap")
        result.append(InputMount(name, path, stat.S_ISDIR(metadata.st_mode)))
    return tuple(result)


def _parser_arguments(values: Sequence[str]) -> tuple[str, ...]:
    arguments = tuple(values)
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    if not 1 <= len(arguments) <= MAX_ARGUMENTS:
        raise ParserSandboxError("the parser command has the wrong number of arguments")
    for argument in arguments:
        _safe_text(argument, "parser argument", maximum=MAX_ARGUMENT_BYTES)
        if any(name in argument for name in BLOCKED_ENVIRONMENT_NAMES):
            raise ParserSandboxError("a parser argument names a blocked credential variable")
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", arguments[0]) is None:
        raise ParserSandboxError("the parser subcommand is not a canonical token")
    return arguments


def build_docker_command(
    *,
    image: str,
    container_name: str,
    inputs: Mapping[str, Path],
    output: Path,
    parser: str,
    parser_arguments: Sequence[str],
) -> tuple[str, ...]:
    """Return the fixed offline parser command after validating host inputs."""

    image = _image_reference(image)
    if parser not in PARSER_PROGRAMS:
        raise ParserSandboxError("the requested parser program is not allowed")
    container_name = _container_name(container_name, parser)
    output = _canonical_host_path(
        output,
        "parser output",
        require_directory=True,
    )
    # The host runner cannot inventory a mode-0700 tmpfs owned by PARSER_UID.
    # The fixed-UID in-container entrypoint checks emptiness before either parser.
    _require_bounded_output_tmpfs(output, parser, require_empty=False)
    input_mounts = _input_mounts(inputs, output)
    arguments = _parser_arguments(parser_arguments)

    command = [
        DOCKER_BINARY,
        "run",
        "--rm",
        f"--name={container_name}",
        "--log-driver=none",
        "--pull=never",
        "--network=none",
        "--ipc=none",
        "--read-only",
        f"--user={PARSER_UID}:{PARSER_GID}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=builtin",
        f"--pids-limit={PARSER_PIDS}",
        f"--cpus={PARSER_CPUS}",
        f"--memory={_memory_bytes(parser)}",
        f"--memory-swap={_memory_bytes(parser)}",
        "--ulimit=nofile=256:256",
        (
            f"--tmpfs={CONTAINER_SCRATCH}:rw,nosuid,nodev,noexec,"
            f"size={SCRATCH_BYTES},nr_inodes={SCRATCH_INODES},"
            f"mode=0700,uid={PARSER_UID},gid={PARSER_GID}"
        ),
        f"--workdir={CONTAINER_SCRATCH}",
        f"--env=HOME={CONTAINER_SCRATCH}",
        f"--env=TMPDIR={CONTAINER_SCRATCH}",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONUNBUFFERED=1",
    ]
    if parser == "evidence":
        command.append(
            f"--tmpfs={CONTAINER_WORK}:rw,nosuid,nodev,noexec,"
            f"size={EVIDENCE_WORK_BYTES},nr_inodes={EVIDENCE_WORK_INODES},"
            f"mode=0700,uid={PARSER_UID},gid={PARSER_GID}"
        )
    for mount in input_mounts:
        command.extend(
            (
                "--mount",
                (
                    f"type=bind,src={mount.source},"
                    f"dst={CONTAINER_INPUT_ROOT}/{mount.name},"
                    "readonly,bind-recursive=disabled"
                ),
            )
        )
    command.extend(
        (
            "--mount",
            (f"type=bind,src={output},dst={CONTAINER_OUTPUT},bind-recursive=disabled"),
            f"--entrypoint={CONTAINER_PYTHON}",
            image,
            CONTAINER_WRAPPER,
            "_inside",
            f"--parser={parser}",
        )
    )
    command.extend(f"--input={mount.name}" for mount in input_mounts)
    command.extend(("--", *arguments))
    return tuple(command)


def _require_safe_docker_binary() -> None:
    try:
        metadata = os.stat(DOCKER_BINARY, follow_symlinks=False)
    except OSError as exc:
        raise ParserSandboxError("the fixed Docker client is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise ParserSandboxError("the fixed Docker client has unsafe ownership or mode")


def _force_remove_container(container_name: str) -> None:
    """Best-effort removal for the one container name owned by this invocation."""

    try:
        subprocess.run(  # noqa: S603 - executable and argv are fixed and validated.
            (DOCKER_BINARY, "rm", "--force", container_name),
            check=False,
            close_fds=True,
            env=SAFE_EXECUTION_ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=CONTAINER_CLEANUP_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def execute_docker_command(command: Sequence[str], *, container_name: str) -> int:
    """Run one validated command with bounded output and signal-aware cleanup."""

    _require_safe_docker_binary()
    container_name = _safe_text(container_name, "parser container name", maximum=96)
    command = tuple(command)
    if (
        CONTAINER_NAME.fullmatch(container_name) is None
        or command[:2] != (DOCKER_BINARY, "run")
        or command.count(f"--name={container_name}") != 1
        or command.count("--log-driver=none") != 1
    ):
        raise ParserSandboxError("the Docker command does not bind its cleanup identity")

    termination_signal = 0
    previous_handlers: dict[int, signal.Handlers] = {}

    def terminate(signum: int, _frame: object) -> None:
        nonlocal termination_signal
        if termination_signal == 0:
            termination_signal = signum
            signal.signal(signum, signal.SIG_IGN)
        _force_remove_container(container_name)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = cast(
                signal.Handlers,
                signal.getsignal(signum),
            )
            signal.signal(signum, terminate)
        process = subprocess.Popen(  # noqa: S603 - executable and argv are fixed above.
            command,
            close_fds=True,
            env=SAFE_EXECUTION_ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        returncode = process.wait()
    except OSError as exc:
        raise ParserSandboxError("the Docker client could not start") from exc
    finally:
        _force_remove_container(container_name)
        for restore_signum, previous in previous_handlers.items():
            signal.signal(restore_signum, previous)

    if termination_signal:
        sys.stderr.write("evidence parser sandbox: parser container was terminated\n")
        return 128 + termination_signal
    if returncode != 0:
        sys.stderr.write(
            f"evidence parser sandbox: parser container exited with status {returncode}\n"
        )
    return returncode


def _require_no_ambient_credentials() -> None:
    for name in os.environ:
        if name in BLOCKED_ENVIRONMENT_NAMES or name.startswith(("GITHUB_", "ACTIONS_")):
            raise ParserSandboxError("the parser container received a GitHub credential variable")


def _require_zero_capabilities(path: Path = STATUS_PATH) -> None:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ParserSandboxError("cannot inspect parser process capabilities") from exc
    if not 1 <= len(raw) <= 256 * 1024:
        raise ParserSandboxError("parser process status is outside its byte bound")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ParserSandboxError("parser process status is not ASCII") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key] = value.strip()
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        capability = values.get(name)
        if capability is None or re.fullmatch(r"[0-9A-Fa-f]{16}", capability) is None:
            raise ParserSandboxError("parser process capabilities are unavailable")
        if int(capability, 16) != 0:
            raise ParserSandboxError("parser process still has Linux capabilities")
    if values.get("NoNewPrivs") != "1":
        raise ParserSandboxError("parser process does not enforce no-new-privileges")
    if values.get("Seccomp") != "2":
        raise ParserSandboxError("parser process does not enforce a seccomp filter")


def _require_no_docker_socket() -> None:
    for path in DOCKER_SOCKET_PATHS:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ParserSandboxError("cannot prove the Docker socket is absent") from exc
        raise ParserSandboxError("the parser container can see a Docker socket")


def _require_inside_tmpfs_identity(path: Path, source: str) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ParserSandboxError(f"cannot inspect {source}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != PARSER_UID
        or metadata.st_gid != PARSER_GID
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ParserSandboxError(f"{source} has the wrong mode or owner")


def _require_offline_network() -> None:
    try:
        interfaces = {name for _index, name in socket.if_nameindex()}
    except OSError as exc:
        raise ParserSandboxError("cannot inspect parser network interfaces") from exc
    if interfaces != {"lo"}:
        raise ParserSandboxError("the parser container has a non-loopback network interface")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.1)
        try:
            probe.connect(("192.0.2.1", 9))
        except OSError:
            return
        raise ParserSandboxError("the parser container can make an outbound connection")
    finally:
        probe.close()


def _require_inside_mounts(input_names: Sequence[str], parser: str) -> None:
    records = _read_mountinfo()
    root = _exact_mount(records, Path("/"), "parser root")
    if "ro" not in root.options:
        raise ParserSandboxError("the parser root filesystem is writable")

    scratch = _exact_mount(records, Path(CONTAINER_SCRATCH), "parser scratch")
    if (
        scratch.filesystem != "tmpfs"
        or "rw" not in scratch.options
        or not {"nosuid", "nodev", "noexec"}.issubset(scratch.options)
    ):
        raise ParserSandboxError("parser scratch is not a writable tmpfs")
    output = _exact_mount(records, Path(CONTAINER_OUTPUT), "parser output")
    if (
        output.filesystem != "tmpfs"
        or "rw" not in output.options
        or not {"nosuid", "nodev", "noexec"}.issubset(output.options)
    ):
        raise ParserSandboxError("parser output is not a writable tmpfs")
    if parser == "evidence":
        work = _exact_mount(records, Path(CONTAINER_WORK), "evidence work")
        if (
            work.filesystem != "tmpfs"
            or "rw" not in work.options
            or not {"nosuid", "nodev", "noexec"}.issubset(work.options)
        ):
            raise ParserSandboxError("evidence work is not a writable tmpfs")

    for name in input_names:
        target = Path(CONTAINER_INPUT_ROOT) / name
        mount = _exact_mount(records, target, f"parser input {name!r}")
        if "ro" not in mount.options:
            raise ParserSandboxError(f"parser input {name!r} is writable")
        for record in records:
            if record.mount_point != target and record.mount_point.is_relative_to(target):
                raise ParserSandboxError(f"parser input {name!r} contains a nested mount")

    writable_system_mounts = frozenset(
        {
            Path("/proc"),
            Path("/dev"),
            Path("/dev/pts"),
            Path("/dev/mqueue"),
            Path("/etc/hostname"),
            Path("/etc/hosts"),
            Path("/etc/resolv.conf"),
        }
    )
    writable_roots = (Path("/proc"), Path("/dev"))
    for record in records:
        if "rw" not in record.options:
            continue
        permitted_writable_mounts = {
            Path(CONTAINER_SCRATCH),
            Path(CONTAINER_OUTPUT),
            *writable_system_mounts,
        }
        if parser == "evidence":
            permitted_writable_mounts.add(Path(CONTAINER_WORK))
        if record.mount_point in permitted_writable_mounts:
            continue
        if any(record.mount_point.is_relative_to(root) for root in writable_roots):
            continue
        raise ParserSandboxError(
            f"unexpected writable parser mount: {record.mount_point.as_posix()}"
        )

    for path, byte_limit, inode_limit, source in (
        (Path(CONTAINER_SCRATCH), SCRATCH_BYTES, SCRATCH_INODES, "parser scratch"),
        (Path(CONTAINER_OUTPUT), _output_bytes(parser), OUTPUT_INODES, "parser output"),
        *(
            (
                (
                    Path(CONTAINER_WORK),
                    EVIDENCE_WORK_BYTES,
                    EVIDENCE_WORK_INODES,
                    "evidence work",
                ),
            )
            if parser == "evidence"
            else ()
        ),
    ):
        _require_inside_tmpfs_identity(path, source)
        try:
            filesystem = os.statvfs(path)
        except OSError as exc:
            raise ParserSandboxError(f"cannot measure {source}") from exc
        if (
            not 1 <= filesystem.f_frsize * filesystem.f_blocks <= byte_limit
            or not 1 <= filesystem.f_files <= inode_limit
        ):
            raise ParserSandboxError(f"{source} exceeds its byte or inode bound")


def _inside_command(parser: str, input_names: Sequence[str], arguments: Sequence[str]) -> NoReturn:
    if os.geteuid() != PARSER_UID or os.getegid() != PARSER_GID:
        raise ParserSandboxError("the parser process does not have the fixed non-root UID/GID")
    if parser not in PARSER_PROGRAMS:
        raise ParserSandboxError("the requested parser program is not allowed")
    names = tuple(input_names)
    if (
        not 1 <= len(names) <= MAX_INPUTS
        or names != tuple(sorted(names))
        or len(set(names)) != len(names)
        or any(INPUT_NAME.fullmatch(name) is None for name in names)
    ):
        raise ParserSandboxError("the parser input mount names are not canonical")
    checked_arguments = _parser_arguments(arguments)
    if parser == "evidence" and "repo" not in names:
        raise ParserSandboxError("the evidence parser requires the exact repository input")
    _require_no_ambient_credentials()
    _require_zero_capabilities()
    _require_no_docker_socket()
    _require_offline_network()
    _require_inside_mounts(names, parser)
    _require_empty_directory(Path(CONTAINER_OUTPUT), "parser output tmpfs")

    command = (
        CONTAINER_PYTHON,
        PARSER_PROGRAMS[parser],
        *checked_arguments,
    )
    environment = {
        "HOME": CONTAINER_SCRATCH,
        "PATH": "/opt/venv/bin:/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "TMPDIR": CONTAINER_SCRATCH,
    }
    if parser == "evidence":
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_VALUE_0": f"{CONTAINER_INPUT_ROOT}/repo",
            }
        )
    os.umask(0o022)
    os.execve(  # noqa: S606 - executable and environment are fixed constants.
        CONTAINER_PYTHON,
        command,
        environment,
    )


def _parse_input_arguments(values: Sequence[str]) -> dict[str, Path]:
    inputs: dict[str, Path] = {}
    casefolded: set[str] = set()
    for value in values:
        name, separator, path = value.partition("=")
        if (
            separator != "="
            or INPUT_NAME.fullmatch(name) is None
            or name in inputs
            or name.casefold() in casefolded
            or not path
        ):
            raise ParserSandboxError(
                "each --input must be one unique canonical NAME=/absolute/path pair"
            )
        inputs[name] = Path(path)
        casefolded.add(name.casefold())
    return inputs


def _materialized_names(architecture: str) -> tuple[str, str, str]:
    if architecture not in {"amd64", "arm64"}:
        raise ParserSandboxError("evidence architecture must be amd64 or arm64")
    archive = f"extra-codeowners-ci-linux-{architecture}-evidence.tar.gz"
    return (
        archive,
        f"evidence-predicate-{architecture}.json",
        f"{archive}.sha256",
    )


def _regular_identity(
    metadata: os.stat_result,
    *,
    name: str,
    maximum: int,
) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        raise ParserSandboxError(
            f"evidence output {name!r} is not one bounded single-link regular file"
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_secure_directory(path: Path, source: str) -> tuple[int, tuple[int, int]]:
    required = (
        getattr(os, "O_CLOEXEC", None),
        getattr(os, "O_DIRECTORY", None),
        getattr(os, "O_NOFOLLOW", None),
    )
    if any(value is None for value in required):
        raise ParserSandboxError("secure descriptor flags are unavailable on this platform")
    cloexec, directory, nofollow = cast(tuple[int, int, int], required)
    try:
        before = path.stat(follow_symlinks=False)
        descriptor = os.open(path, os.O_RDONLY | cloexec | directory | nofollow)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ParserSandboxError(f"cannot open {source} securely") from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        raise ParserSandboxError(f"{source} changed before it was opened")
    return descriptor, (opened.st_dev, opened.st_ino)


def _copy_stable_output(
    *,
    source_parent: int,
    destination_parent: int,
    name: str,
    maximum: int,
) -> tuple[str, tuple[int, ...], str, bytes]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or nonblock is None or cloexec is None:
        raise ParserSandboxError("secure descriptor flags are unavailable on this platform")
    try:
        before_metadata = os.stat(name, dir_fd=source_parent, follow_symlinks=False)
    except OSError as exc:
        raise ParserSandboxError(f"cannot inspect evidence output {name!r}") from exc
    before = _regular_identity(before_metadata, name=name, maximum=maximum)
    source_descriptor = -1
    destination_descriptor = -1
    temporary = ""
    completed = False
    try:
        source_descriptor = os.open(
            name,
            os.O_RDONLY | nofollow | nonblock | cloexec,
            dir_fd=source_parent,
        )
        opened = _regular_identity(
            os.fstat(source_descriptor),
            name=name,
            maximum=maximum,
        )
        if opened != before:
            raise ParserSandboxError(f"evidence output {name!r} changed before it was opened")

        for _attempt in range(128):
            candidate = f".extra-codeowners-materialize-{secrets.token_hex(16)}"
            try:
                destination_descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                    0o600,
                    dir_fd=destination_parent,
                )
            except FileExistsError:
                continue
            temporary = candidate
            break
        if destination_descriptor < 0:
            raise ParserSandboxError("cannot allocate a materialization destination")

        digest = hashlib.sha256()
        retained = bytearray()
        received = 0
        while received <= maximum:
            chunk = os.read(
                source_descriptor,
                min(COPY_CHUNK_BYTES, maximum + 1 - received),
            )
            if not chunk:
                break
            received += len(chunk)
            if received > maximum:
                raise ParserSandboxError(f"evidence output {name!r} exceeds its byte limit")
            digest.update(chunk)
            if maximum <= EVIDENCE_PREDICATE_BYTES:
                retained.extend(chunk)
            view = memoryview(chunk)
            written = 0
            while written < len(view):
                count = os.write(destination_descriptor, view[written:])
                if count <= 0:
                    raise ParserSandboxError(f"cannot write materialized evidence output {name!r}")
                written += count
        if received != before_metadata.st_size:
            raise ParserSandboxError(f"evidence output {name!r} changed while it was read")
        os.fsync(destination_descriptor)
        after = _regular_identity(
            os.fstat(source_descriptor),
            name=name,
            maximum=maximum,
        )
        path_after = _regular_identity(
            os.stat(name, dir_fd=source_parent, follow_symlinks=False),
            name=name,
            maximum=maximum,
        )
        if after != before or path_after != before:
            raise ParserSandboxError(f"evidence output {name!r} changed while it was read")
        os.close(source_descriptor)
        source_descriptor = -1
        os.close(destination_descriptor)
        destination_descriptor = -1
        completed = True
        return temporary, before, digest.hexdigest(), bytes(retained)
    except OSError as exc:
        raise ParserSandboxError(f"cannot materialize evidence output {name!r}") from exc
    finally:
        for descriptor in (source_descriptor, destination_descriptor):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
        if temporary and not completed:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=destination_parent)


def materialize_source_plan(source: Path, destination: Path) -> dict[str, object]:
    """Copy the exact stable Alpine plan into one empty host-owned directory."""

    source = _canonical_host_path(source, "source-plan output", require_directory=True)
    destination = _canonical_host_path(
        destination,
        "source-plan materialization destination",
        require_directory=True,
    )
    if (
        source == destination
        or source.is_relative_to(destination)
        or destination.is_relative_to(source)
    ):
        raise ParserSandboxError("source-plan source and destination must not overlap")
    _require_bounded_output_tmpfs(
        source,
        "source-plan",
        require_empty=False,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )

    name = "alpine-plan.json"
    source_parent = -1
    destination_parent = -1
    temporary = ""
    published = False
    completed = False
    binding: dict[str, object] | None = None
    try:
        source_parent, source_identity = _open_secure_directory(source, "source-plan output")
        destination_parent, destination_identity = _open_secure_directory(
            destination,
            "source-plan materialization destination",
        )
        destination_metadata = os.fstat(destination_parent)
        if (
            destination_metadata.st_uid != os.getuid()
            or destination_metadata.st_gid != os.getgid()
            or stat.S_IMODE(destination_metadata.st_mode) != 0o700
        ):
            raise ParserSandboxError(
                "source-plan materialization destination is not private and host-owned"
            )
        try:
            source_inventory = os.listdir(source_parent)
            destination_inventory = os.listdir(destination_parent)
        except OSError as exc:
            raise ParserSandboxError("cannot inventory source-plan directories") from exc
        if source_inventory != [name]:
            raise ParserSandboxError("source-plan output must contain exactly alpine-plan.json")
        if destination_inventory:
            raise ParserSandboxError("source-plan materialization destination must be empty")

        temporary, identity, digest, _retained = _copy_stable_output(
            source_parent=source_parent,
            destination_parent=destination_parent,
            name=name,
            maximum=SOURCE_PLAN_BYTES,
        )
        try:
            final_inventory = os.listdir(source_parent)
            source_after = os.fstat(source_parent)
            destination_after = os.fstat(destination_parent)
            current = _regular_identity(
                os.stat(name, dir_fd=source_parent, follow_symlinks=False),
                name=name,
                maximum=SOURCE_PLAN_BYTES,
            )
        except OSError as exc:
            raise ParserSandboxError("cannot revalidate source-plan output") from exc
        if final_inventory != [name] or current != identity:
            raise ParserSandboxError("source-plan output changed during materialization")
        if (source_after.st_dev, source_after.st_ino) != source_identity or (
            destination_after.st_dev,
            destination_after.st_ino,
        ) != destination_identity:
            raise ParserSandboxError("a source-plan directory changed during materialization")

        try:
            os.link(
                temporary,
                name,
                src_dir_fd=destination_parent,
                dst_dir_fd=destination_parent,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ParserSandboxError("cannot publish the materialized source plan") from exc
        published = True
        os.fsync(destination_parent)
        binding = {
            "schema_version": SCHEMA_VERSION,
            "kind": SOURCE_PLAN_BINDING_KIND,
            "filename": name,
            "sha256": digest,
            "size": identity[6],
        }
        completed = True
    except OSError as exc:
        raise ParserSandboxError("cannot materialize source-plan output") from exc
    finally:
        if destination_parent >= 0:
            if published and not completed:
                with contextlib.suppress(OSError):
                    os.unlink(name, dir_fd=destination_parent)
            if temporary:
                with contextlib.suppress(OSError):
                    os.unlink(temporary, dir_fd=destination_parent)
        for descriptor in (source_parent, destination_parent):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)

    if binding is None:
        raise ParserSandboxError("source-plan materialization did not produce a binding")
    return binding


def materialize_evidence_output(source: Path, destination: Path, architecture: str) -> None:
    """Copy one exact, quiescent evidence output set into a host artifact directory."""

    source = _canonical_host_path(source, "evidence output source", require_directory=True)
    destination = _canonical_host_path(
        destination,
        "evidence materialization destination",
        require_directory=True,
    )
    if (
        source == destination
        or source.is_relative_to(destination)
        or destination.is_relative_to(source)
    ):
        raise ParserSandboxError("evidence source and destination must not overlap")
    _require_bounded_output_tmpfs(
        source,
        "evidence",
        require_empty=False,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    names = _materialized_names(architecture)
    limits = {
        names[0]: EVIDENCE_ARCHIVE_BYTES,
        names[1]: EVIDENCE_PREDICATE_BYTES,
        names[2]: EVIDENCE_CHECKSUM_BYTES,
    }
    source_parent = -1
    destination_parent = -1
    temporary_files: dict[str, str] = {}
    published: list[str] = []
    completed = False
    try:
        source_parent, source_identity = _open_secure_directory(source, "evidence output source")
        destination_parent, destination_identity = _open_secure_directory(
            destination,
            "evidence materialization destination",
        )
        try:
            inventory = os.listdir(source_parent)
        except OSError as exc:
            raise ParserSandboxError("cannot inventory the evidence output source") from exc
        if sorted(inventory) != sorted(names) or len(
            {name.casefold() for name in inventory}
        ) != len(inventory):
            raise ParserSandboxError("evidence output source has an unexpected inventory")
        for name in names:
            try:
                os.stat(name, dir_fd=destination_parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise ParserSandboxError(f"cannot inspect evidence destination {name!r}") from exc
            else:
                raise ParserSandboxError(f"evidence destination {name!r} already exists")

        identities: dict[str, tuple[int, ...]] = {}
        digests: dict[str, str] = {}
        retained: dict[str, bytes] = {}
        total = 0
        for name in names:
            temporary, identity, digest, small_content = _copy_stable_output(
                source_parent=source_parent,
                destination_parent=destination_parent,
                name=name,
                maximum=limits[name],
            )
            temporary_files[name] = temporary
            identities[name] = identity
            digests[name] = digest
            retained[name] = small_content
            total += identity[6]
            if total > EVIDENCE_MATERIALIZED_BYTES:
                raise ParserSandboxError("evidence output exceeds its aggregate byte limit")

        try:
            final_inventory = os.listdir(source_parent)
            source_after = os.fstat(source_parent)
            destination_after = os.fstat(destination_parent)
        except OSError as exc:
            raise ParserSandboxError("cannot revalidate evidence directories") from exc
        if sorted(final_inventory) != sorted(names):
            raise ParserSandboxError("evidence output inventory changed during materialization")
        if (source_after.st_dev, source_after.st_ino) != source_identity or (
            destination_after.st_dev,
            destination_after.st_ino,
        ) != destination_identity:
            raise ParserSandboxError("an evidence directory changed during materialization")
        for name in names:
            current = _regular_identity(
                os.stat(name, dir_fd=source_parent, follow_symlinks=False),
                name=name,
                maximum=limits[name],
            )
            if current != identities[name]:
                raise ParserSandboxError(f"evidence output {name!r} changed during materialization")

        archive, predicate, checksum = names
        expected_checksum = f"{digests[archive]}  {archive}\n".encode("ascii")
        if retained[checksum] != expected_checksum:
            raise ParserSandboxError("evidence checksum does not bind the exact archive")
        try:
            predicate_value = json.loads(retained[predicate])
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise ParserSandboxError("evidence predicate is not canonical JSON") from exc
        if canonical_evidence_json(predicate_value) != retained[predicate]:
            raise ParserSandboxError("evidence predicate is not canonical JSON")
        if not isinstance(predicate_value, dict) or predicate_value.get("artifact") != {
            "filename": archive,
            "sha256": digests[archive],
        }:
            raise ParserSandboxError("evidence predicate does not bind the exact archive")

        for name in names:
            try:
                os.link(
                    temporary_files[name],
                    name,
                    src_dir_fd=destination_parent,
                    dst_dir_fd=destination_parent,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ParserSandboxError(
                    f"cannot publish materialized evidence output {name!r}"
                ) from exc
            published.append(name)
        os.fsync(destination_parent)
        completed = True
    except OSError as exc:
        raise ParserSandboxError("cannot materialize evidence output") from exc
    finally:
        if destination_parent >= 0:
            if not completed:
                for name in reversed(published):
                    with contextlib.suppress(OSError):
                        os.unlink(name, dir_fd=destination_parent)
            for temporary in temporary_files.values():
                with contextlib.suppress(OSError):
                    os.unlink(temporary, dir_fd=destination_parent)
        for descriptor in (source_parent, destination_parent):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("command", help="print or explicitly run the parser sandbox")
    build.add_argument("--image", required=True)
    build.add_argument("--container-name", required=True)
    build.add_argument("--input", action="append", default=[])
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--parser", choices=tuple(sorted(PARSER_PROGRAMS)), required=True)
    build.add_argument("--execute", action="store_true")
    build.add_argument("parser_arguments", nargs=argparse.REMAINDER)

    inside = commands.add_parser("_inside", help=argparse.SUPPRESS)
    inside.add_argument("--input", action="append", default=[])
    inside.add_argument("--parser", choices=tuple(sorted(PARSER_PROGRAMS)), required=True)
    inside.add_argument("parser_arguments", nargs=argparse.REMAINDER)

    materialize = commands.add_parser(
        "materialize-evidence",
        help="safely copy one exact evidence output set out of its bounded tmpfs",
    )
    materialize.add_argument("--source", required=True, type=Path)
    materialize.add_argument("--destination", required=True, type=Path)
    materialize.add_argument("--architecture", choices=("amd64", "arm64"), required=True)

    materialize_plan = commands.add_parser(
        "materialize-source-plan",
        help="safely bind the exact Alpine source plan into a private host directory",
    )
    materialize_plan.add_argument("--source", required=True, type=Path)
    materialize_plan.add_argument("--destination", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Print a validated command, run it explicitly, or check the container."""

    arguments = _argument_parser().parse_args(argv)
    try:
        if arguments.command == "_inside":
            _inside_command(
                cast(str, arguments.parser),
                cast(list[str], arguments.input),
                cast(list[str], arguments.parser_arguments),
            )
        if arguments.command == "materialize-evidence":
            materialize_evidence_output(
                cast(Path, arguments.source),
                cast(Path, arguments.destination),
                cast(str, arguments.architecture),
            )
            return 0
        if arguments.command == "materialize-source-plan":
            sys.stdout.buffer.write(
                canonical_json(
                    materialize_source_plan(
                        cast(Path, arguments.source),
                        cast(Path, arguments.destination),
                    )
                )
            )
            return 0
        command = build_docker_command(
            image=cast(str, arguments.image),
            container_name=cast(str, arguments.container_name),
            inputs=_parse_input_arguments(cast(list[str], arguments.input)),
            output=cast(Path, arguments.output),
            parser=cast(str, arguments.parser),
            parser_arguments=cast(list[str], arguments.parser_arguments),
        )
        if cast(bool, arguments.execute):
            return execute_docker_command(
                command,
                container_name=cast(str, arguments.container_name),
            )
        sys.stdout.buffer.write(
            canonical_json(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": COMMAND_KIND,
                    "command": list(command),
                }
            )
        )
    except ParserSandboxError as exc:
        sys.stderr.write(f"evidence parser sandbox: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Start the evaluation-beta preflight without importing checkout shadows.

This file intentionally uses only the Python standard library. The required
interpreter flags keep the checkout and virtual environment off ``sys.path``
until the bootstrap has bound the checkout to the configured revision and
rejected local overlays.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import tomllib
from contextlib import suppress
from importlib.metadata import distributions
from pathlib import Path
from typing import Any, Final, NoReturn, cast

GIT_BINARY: Final = "/usr/bin/git"
GIT_TIMEOUT_SECONDS: Final = 10.0
GIT_OUTPUT_BYTES: Final = 6 * 1024 * 1024
MAX_CONFIG_BYTES: Final = 64 * 1024
MAX_TRACKED_FILES: Final = 10_000
MAX_TRACKED_PATH_BYTES: Final = 4096
MAX_TRACKED_FILE_BYTES: Final = 64 * 1024 * 1024
MAX_TRACKED_SOURCE_BYTES: Final = 512 * 1024 * 1024
SAFE_PATH: Final = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
VERSION_TEXT: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")


class BootstrapError(RuntimeError):
    """Raised when the pre-import safety boundary cannot be established."""


def _require_safe_interpreter() -> None:
    required_flags = {
        "-I (isolated)": sys.flags.isolated,
        "-S (no site initialization)": sys.flags.no_site,
        "-B (no bytecode writes)": sys.flags.dont_write_bytecode,
        "safe-path mode": sys.flags.safe_path,
    }
    missing = [name for name, enabled in required_flags.items() if not enabled]
    if missing:
        raise BootstrapError(
            "interpreter requires " + ", ".join(missing) + " before loading checkout code"
        )
    imported_customization = {
        name for name in ("site", "sitecustomize", "usercustomize") if name in sys.modules
    }
    if imported_customization:
        names = ", ".join(sorted(imported_customization))
        raise BootstrapError(f"interpreter loaded forbidden site customization: {names}")


def _resolved_directory(raw_path: str, *, description: str) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        raise BootstrapError(f"{description} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise BootstrapError(f"{description} is unavailable: {type(error).__name__}") from error
    if not resolved.is_dir():
        raise BootstrapError(f"{description} is not a directory")
    return resolved


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run_git(source_root: Path, arguments: list[str]) -> bytes:
    fixed_configuration = (
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "credential.helper=",
        "-c",
        "credential.interactive=never",
        "-c",
        "protocol.allow=never",
        "-c",
        "submodule.recurse=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
    )
    try:
        process = subprocess.Popen(  # noqa: S603 - executable and options are fixed.
            [
                GIT_BINARY,
                "--no-pager",
                *fixed_configuration,
                "-C",
                str(source_root),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        raise BootstrapError("fixed Git bootstrap check could not start") from error

    assert process.stdout is not None
    assert process.stderr is not None
    streams = (process.stdout, process.stderr)
    output = (bytearray(), bytearray())
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BootstrapError("fixed Git bootstrap check exceeded its time limit")
            events = selector.select(remaining)
            if not events:
                raise BootstrapError("fixed Git bootstrap check exceeded its time limit")
            for key, _ in events:
                stream = cast(Any, key.fileobj)
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                output[cast(int, key.data)].extend(chunk)
                if len(output[0]) + len(output[1]) > GIT_OUTPUT_BYTES:
                    raise BootstrapError("fixed Git bootstrap check exceeded its output limit")
        try:
            return_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise BootstrapError("fixed Git bootstrap check exceeded its time limit") from error
    except BaseException:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(OSError, subprocess.SubprocessError):
            process.wait(timeout=1)
        raise
    finally:
        selector.close()
        for stream in streams:
            stream.close()

    if return_code != 0:
        detail = bytes(output[1]).decode("utf-8", errors="replace").strip()
        if detail:
            raise BootstrapError(f"Git bootstrap check failed: {detail[:300]}")
        raise BootstrapError(f"Git bootstrap check exited {return_code}")
    return bytes(output[0])


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _read_stable_file(
    path: Path,
    *,
    modes: frozenset[int],
    limit: int,
    description: str,
) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise BootstrapError(f"{description} cannot be opened safely on this platform")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in modes
            or before.st_size < 0
            or before.st_size > limit
        ):
            raise BootstrapError(f"{description} has an unsafe type, owner, link count, or mode")
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(path, follow_symlinks=False)
        if (
            len(content) > limit
            or len(content) != before.st_size
            or _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(path_after)
        ):
            raise BootstrapError(f"{description} changed while it was being read")
        return bytes(content)
    except BootstrapError:
        raise
    except OSError as error:
        raise BootstrapError(f"{description} could not be inspected safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -I -S -B tools/evaluation_beta_bootstrap.py",
        description="Read-only safety tooling for the disposable evaluation beta.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser(
        "preflight",
        help="verify prerequisites and write a sanitized fail-closed report",
    )
    preflight.add_argument(
        "--config",
        type=Path,
        default=Path(
            os.getenv("EXTRA_CODEOWNERS_BETA_CONFIG_FILE", "evaluation-beta-preflight.toml")
        ),
        help="owner-only non-secret TOML configuration outside the checkout",
    )
    preflight.add_argument(
        "--report",
        type=Path,
        default=Path(
            os.getenv(
                "EXTRA_CODEOWNERS_BETA_REPORT_FILE",
                "evaluation-beta-preflight-report.json",
            )
        ),
        help="sanitized JSON report path",
    )
    return parser


def _expected_source_revision(config_path: Path, source_root: Path) -> str:
    absolute_config = config_path.absolute()
    try:
        resolved_config = absolute_config.parent.resolve(strict=True) / absolute_config.name
    except OSError as error:
        raise BootstrapError("bootstrap configuration parent is unavailable") from error
    if resolved_config == source_root or source_root in resolved_config.parents:
        raise BootstrapError("bootstrap configuration must be outside the source checkout")
    raw = _read_stable_file(
        absolute_config,
        modes=frozenset({0o400, 0o600}),
        limit=MAX_CONFIG_BYTES,
        description="bootstrap configuration file",
    )
    try:
        values = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BootstrapError("bootstrap configuration file is not valid TOML") from error
    raw_revision = values.get("source_revision")
    checkout_value = values.get("source_checkout")
    revision = raw_revision.strip().lower() if isinstance(raw_revision, str) else None
    if (
        revision is None
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is None
        or not isinstance(checkout_value, str)
    ):
        raise BootstrapError("bootstrap configuration must pin source_revision and source_checkout")
    checkout = Path(checkout_value)
    if not checkout.is_absolute():
        checkout = absolute_config.parent / checkout
    try:
        configured_checkout = checkout.resolve(strict=True)
    except OSError as error:
        raise BootstrapError("configured source checkout is unavailable") from error
    if configured_checkout != source_root:
        raise BootstrapError("bootstrap configuration does not name this source checkout")
    return revision


def _installed_distribution_version(site_packages: Path) -> str:
    try:
        installed = list(distributions(name="extra-codeowners", path=[str(site_packages)]))
        if len(installed) != 1:
            raise BootstrapError(
                "external environment must contain exactly one Extra CODEOWNERS distribution"
            )
        metadata = installed[0].metadata
        names = metadata.get_all("Name") or []
        versions = metadata.get_all("Version") or []
    except BootstrapError:
        raise
    except Exception as error:
        raise BootstrapError(
            "installed Extra CODEOWNERS distribution metadata could not be read"
        ) from error
    if names != ["extra-codeowners"] or len(versions) != 1 or not isinstance(versions[0], str):
        raise BootstrapError("installed Extra CODEOWNERS distribution metadata is invalid")
    version = versions[0]
    if version != version.strip() or VERSION_TEXT.fullmatch(version) is None:
        raise BootstrapError("installed Extra CODEOWNERS distribution metadata is invalid")
    return version


def _safe_tracked_path(raw_path: bytes) -> str:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BootstrapError("source tree contains a non-UTF-8 tracked path") from error
    if (
        SAFE_PATH.fullmatch(path) is None
        or len(raw_path) > MAX_TRACKED_PATH_BYTES
        or any(component in {".", ".."} for component in path.split("/"))
        or path.split("/", 1)[0] == ".git"
    ):
        raise BootstrapError("source tree contains an unsafe tracked path")
    return path


def _require_safe_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BootstrapError("tracked source directory has an unsafe type, owner, or mode")


def _hash_tracked_file(
    checkout_fd: int,
    path: str,
    *,
    expected_mode: str,
    object_format: str,
) -> tuple[str, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise BootstrapError("tracked source files cannot be opened safely on this platform")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow | directory
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
    directory_fd = -1
    file_fd = -1
    try:
        directory_fd = os.dup(checkout_fd)
        for component in path.split("/")[:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
            _require_safe_directory(os.fstat(directory_fd))

        name = path.rsplit("/", 1)[-1]
        file_fd = os.open(name, file_flags, dir_fd=directory_fd)
        before = os.fstat(file_fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or mode & 0o022
            or bool(mode & 0o111) != (expected_mode == "100755")
        ):
            raise BootstrapError(
                "tracked source file has an unsafe type, owner, link count, or mode"
            )
        if before.st_size < 0 or before.st_size > MAX_TRACKED_FILE_BYTES:
            raise BootstrapError(
                f"tracked source file exceeds the {MAX_TRACKED_FILE_BYTES}-byte limit"
            )

        digest = hashlib.new(object_format)
        digest.update(f"blob {before.st_size}\0".encode())
        observed_size = 0
        while observed_size <= MAX_TRACKED_FILE_BYTES:
            chunk = os.read(
                file_fd,
                min(64 * 1024, MAX_TRACKED_FILE_BYTES + 1 - observed_size),
            )
            if not chunk:
                break
            observed_size += len(chunk)
            digest.update(chunk)
        after = os.fstat(file_fd)
        path_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            observed_size != before.st_size
            or _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(path_after)
        ):
            raise BootstrapError("tracked source file changed while it was being hashed")
        return digest.hexdigest(), observed_size
    except BootstrapError:
        raise
    except (OSError, ValueError) as error:
        raise BootstrapError("tracked source file could not be inspected safely") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


def _reject_checkout_overlays(
    source_root: Path,
    *,
    expected_revision: str | None,
) -> None:
    top_level = _run_git(source_root, ["rev-parse", "--show-toplevel"])
    try:
        reported_root = Path(top_level.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise BootstrapError("Git returned an invalid source root") from error
    if reported_root != source_root:
        raise BootstrapError("bootstrap file is not in the repository root reported by Git")

    replacement_refs = _run_git(
        source_root,
        ["for-each-ref", "--format=%(refname)", "refs/replace"],
    )
    if replacement_refs:
        raise BootstrapError("source checkout contains replacement refs")

    object_format_raw = _run_git(source_root, ["rev-parse", "--show-object-format"])
    try:
        object_format = object_format_raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BootstrapError("Git returned an invalid object format") from error
    object_id_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if object_id_length is None:
        raise BootstrapError("source checkout uses an unsupported Git object format")
    if expected_revision is not None and len(expected_revision) != object_id_length:
        raise BootstrapError("configured source revision uses the wrong Git object format")

    head_raw = _run_git(source_root, ["rev-parse", "--verify", "HEAD"])
    try:
        head = head_raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BootstrapError("Git returned an invalid HEAD") from error
    if len(head) != object_id_length or any(
        character not in "0123456789abcdef" for character in head
    ):
        raise BootstrapError("Git returned an invalid HEAD")
    if expected_revision is not None and head != expected_revision:
        raise BootstrapError("source checkout HEAD does not match configured source_revision")
    tree_revision = expected_revision or head
    object_type = _run_git(source_root, ["cat-file", "-t", tree_revision])
    if object_type.strip() != b"commit":
        raise BootstrapError("source revision is not a commit object")
    resolved_commit = _run_git(
        source_root,
        ["rev-parse", "--verify", f"{tree_revision}^{{commit}}"],
    )
    if resolved_commit.decode("ascii", errors="replace").strip() != tree_revision:
        raise BootstrapError("source revision does not resolve to its exact commit")

    signed_tree = _run_git(
        source_root,
        [
            "ls-tree",
            "-r",
            "--full-tree",
            "-z",
            tree_revision,
        ],
    )
    tree: dict[str, tuple[str, str]] = {}
    for entry in (item for item in signed_tree.split(b"\0") if item):
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split()
        path = _safe_tracked_path(raw_path)
        if (
            not separator
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
            or len(fields[2]) != object_id_length
            or any(byte not in b"0123456789abcdef" for byte in fields[2])
            or path in tree
        ):
            raise BootstrapError(
                "source tree contains a symlink, gitlink, duplicate, or unsupported entry"
            )
        tree[path] = (fields[0].decode("ascii"), fields[2].decode("ascii"))
    if not tree or len(tree) > MAX_TRACKED_FILES:
        raise BootstrapError(f"source tree must contain 1-{MAX_TRACKED_FILES} tracked files")

    index_entries = _run_git(source_root, ["ls-files", "--stage", "-z", "--"])
    index: dict[str, tuple[str, str]] = {}
    for entry in (item for item in index_entries.split(b"\0") if item):
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split()
        path = _safe_tracked_path(raw_path)
        if (
            not separator
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[2] != b"0"
            or len(fields[1]) != object_id_length
            or any(byte not in b"0123456789abcdef" for byte in fields[1])
            or path in index
        ):
            raise BootstrapError(
                "source index contains a symlink, gitlink, conflict, or unsupported entry"
            )
        index[path] = (fields[0].decode("ascii"), fields[1].decode("ascii"))
    if index != tree:
        raise BootstrapError("source index does not exactly match HEAD")

    index_flags = _run_git(source_root, ["ls-files", "-v", "-f", "-z", "--"])
    flagged_paths: set[str] = set()
    for entry in (item for item in index_flags.split(b"\0") if item):
        tag, separator, raw_path = entry.partition(b" ")
        path = _safe_tracked_path(raw_path)
        if not separator or tag != b"H" or path in flagged_paths or path not in tree:
            raise BootstrapError("source checkout has unsafe index flags")
        flagged_paths.add(path)
    if flagged_paths != set(tree):
        raise BootstrapError("source checkout index flags do not cover HEAD")

    untracked_or_ignored = _run_git(source_root, ["ls-files", "--others", "-z", "--"])
    if untracked_or_ignored:
        raise BootstrapError("source checkout has untracked or ignored content")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise BootstrapError("source checkout cannot be opened safely on this platform")
    checkout_fd = -1
    try:
        checkout_fd = os.open(source_root, os.O_RDONLY | os.O_CLOEXEC | nofollow | directory)
        _require_safe_directory(os.fstat(checkout_fd))
        total_bytes = 0
        for path, (mode, expected_object_id) in sorted(tree.items()):
            observed_object_id, observed_size = _hash_tracked_file(
                checkout_fd,
                path,
                expected_mode=mode,
                object_format=object_format,
            )
            if observed_object_id != expected_object_id:
                raise BootstrapError("tracked source content does not exactly match HEAD")
            total_bytes += observed_size
            if total_bytes > MAX_TRACKED_SOURCE_BYTES:
                raise BootstrapError(
                    f"tracked source exceeds the {MAX_TRACKED_SOURCE_BYTES}-byte limit"
                )
    except BootstrapError:
        raise
    except OSError as error:
        raise BootstrapError("source checkout could not be inspected safely") from error
    finally:
        if checkout_fd >= 0:
            os.close(checkout_fd)


def _prepare_import_path(
    source_root: Path,
    *,
    expected_revision: str | None,
) -> Path:
    virtual_environment = _resolved_directory(
        os.environ.get("VIRTUAL_ENV", ""),
        description="VIRTUAL_ENV",
    )
    if virtual_environment == source_root or source_root in virtual_environment.parents:
        raise BootstrapError("VIRTUAL_ENV must be outside the source checkout")

    site_packages = (
        virtual_environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site_packages = _resolved_directory(str(site_packages), description="site-packages")
    if site_packages == source_root or source_root in site_packages.parents:
        raise BootstrapError("site-packages must be outside the source checkout")

    initial_paths = {
        Path(entry).resolve() for entry in sys.path if entry and Path(entry).is_absolute()
    }
    if any(
        path in (source_root, site_packages)
        or source_root in path.parents
        or site_packages in path.parents
        for path in initial_paths
    ):
        raise BootstrapError("checkout or virtual-environment paths were loaded before bootstrap")

    _reject_checkout_overlays(source_root, expected_revision=expected_revision)

    os.environ.pop("PYTHONPATH", None)
    os.environ.pop("PYTHONSTARTUP", None)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONNOUSERSITE"] = "1"
    os.environ["PYTHONSAFEPATH"] = "1"
    # Keep the standard library first, then resolve reviewed project modules
    # from the checkout before consulting the external dependency environment.
    sys.path.extend((str(source_root), str(site_packages)))
    return site_packages


def _delegate() -> NoReturn:
    _require_safe_interpreter()
    try:
        source_root = Path(__file__).resolve(strict=True).parent.parent
    except OSError as error:
        raise BootstrapError("source checkout is unavailable") from error
    arguments = sys.argv[1:]
    if arguments == ["--version"]:
        site_packages = _prepare_import_path(source_root, expected_revision=None)
        sys.stdout.write(f"{_installed_distribution_version(site_packages)}\n")
        raise SystemExit(0)
    parsed = _argument_parser().parse_args(arguments)
    config_path = cast(Path, parsed.config)
    expected_revision = _expected_source_revision(config_path, source_root)
    _prepare_import_path(source_root, expected_revision=expected_revision)
    from tools import evaluation_beta

    try:
        loaded_path = Path(evaluation_beta.__file__).resolve(strict=True)
    except (OSError, TypeError) as error:
        raise BootstrapError("preflight module has no valid checkout path") from error
    if loaded_path != source_root / "tools" / "evaluation_beta.py":
        raise BootstrapError("preflight module was not loaded from the source checkout")
    raise SystemExit(evaluation_beta.main())


def main() -> int:
    """Establish the import boundary and run the beta preflight."""

    try:
        _delegate()
    except BootstrapError as error:
        sys.stderr.write(f"evaluation-beta bootstrap: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

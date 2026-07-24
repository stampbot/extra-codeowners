"""Start the evaluation-beta preflight without importing checkout shadows.

This file intentionally uses only the Python standard library.  The required
interpreter flags keep the checkout and virtual environment off ``sys.path``
until the bootstrap has rejected untracked and ignored checkout content.
"""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, Final, NoReturn, cast

GIT_BINARY: Final = "/usr/bin/git"
GIT_TIMEOUT_SECONDS: Final = 10.0
GIT_OUTPUT_BYTES: Final = 6 * 1024 * 1024


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


def _reject_checkout_overlays(source_root: Path) -> None:
    top_level = _run_git(source_root, ["rev-parse", "--show-toplevel"])
    try:
        reported_root = Path(top_level.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise BootstrapError("Git returned an invalid source root") from error
    if reported_root != source_root:
        raise BootstrapError("bootstrap file is not in the repository root reported by Git")

    untracked_or_ignored = _run_git(source_root, ["ls-files", "--others", "-z", "--"])
    if untracked_or_ignored:
        raise BootstrapError("source checkout has untracked or ignored content")


def _prepare_import_path() -> Path:
    _require_safe_interpreter()
    source_root = Path(__file__).resolve(strict=True).parent.parent
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

    _reject_checkout_overlays(source_root)

    os.environ.pop("PYTHONPATH", None)
    os.environ.pop("PYTHONSTARTUP", None)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONNOUSERSITE"] = "1"
    os.environ["PYTHONSAFEPATH"] = "1"
    sys.path.extend((str(site_packages), str(source_root)))
    return source_root


def _delegate() -> NoReturn:
    _prepare_import_path()
    if sys.argv[1:] == ["--version"]:
        from extra_codeowners import __version__

        sys.stdout.write(f"{__version__}\n")
        raise SystemExit(0)
    from tools import evaluation_beta

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

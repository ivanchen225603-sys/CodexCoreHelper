#!/usr/bin/env python3
"""Bounded, process-tree-aware subprocess execution for lifecycle commands."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from _lifecycle import LifecycleError


class ProcessExecutionError(LifecycleError):
    def __init__(self, message: str, *, stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


def _read_limited(path: Path, maximum: int) -> str:
    with path.open("rb") as stream:
        payload = stream.read(maximum + 1)
    truncated = len(payload) > maximum
    text = payload[:maximum].decode("utf-8", errors="replace")
    return text + ("\n[OUTPUT TRUNCATED AT BYTE LIMIT]" if truncated else "")


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise LifecycleError("Command process tree could not be terminated") from exc


def run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    stdin_bytes: bytes | None = None,
    max_stdout_bytes: int = 8 * 1024 * 1024,
    max_stderr_bytes: int = 2 * 1024 * 1024,
) -> subprocess.CompletedProcess[str]:
    if (
        not command
        or len(command) > 128
        or not all(isinstance(item, str) and item and "\x00" not in item for item in command)
    ):
        raise LifecycleError("Command must be a non-empty bounded argument array")
    if not 1 <= timeout_seconds <= 7200:
        raise LifecycleError("Command timeout must be between 1 and 7200 seconds")
    if not 1024 <= max_stdout_bytes <= 64 * 1024 * 1024:
        raise LifecycleError("Command stdout limit is invalid")
    if not 1024 <= max_stderr_bytes <= 64 * 1024 * 1024:
        raise LifecycleError("Command stderr limit is invalid")
    with tempfile.TemporaryDirectory(prefix="ai-lifecycle-process-") as temporary_name:
        temporary = Path(temporary_name)
        stdout_path = temporary / "stdout.log"
        stderr_path = temporary / "stderr.log"
        stdin_path = temporary / "stdin.bin"
        stdin_path.write_bytes(stdin_bytes or b"")
        popen_options: dict[str, Any] = {}
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_options["start_new_session"] = True
        with (
            stdin_path.open("rb") as stdin_stream,
            stdout_path.open("w+b") as stdout_stream,
            stderr_path.open("w+b") as stderr_stream,
        ):
            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(cwd),
                    env=environment,
                    stdin=stdin_stream,
                    stdout=stdout_stream,
                    stderr=stderr_stream,
                    shell=False,
                    creationflags=creationflags,
                    **popen_options,
                )
            except (OSError, ValueError) as exc:
                raise ProcessExecutionError(f"Cannot start command: {exc}") from exc
            deadline = time.monotonic() + timeout_seconds
            failure: str | None = None
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        failure = f"Command timed out after {timeout_seconds} seconds"
                        terminate_process_tree(process)
                        break
                    stdout_stream.flush()
                    stderr_stream.flush()
                    if stdout_path.stat().st_size > max_stdout_bytes:
                        failure = f"Command stdout exceeded {max_stdout_bytes} bytes"
                        terminate_process_tree(process)
                        break
                    if stderr_path.stat().st_size > max_stderr_bytes:
                        failure = f"Command stderr exceeded {max_stderr_bytes} bytes"
                        terminate_process_tree(process)
                        break
                    time.sleep(0.05)
            except BaseException:
                terminate_process_tree(process)
                raise
            stdout_stream.flush()
            stderr_stream.flush()
            if failure is None and stdout_path.stat().st_size > max_stdout_bytes:
                failure = f"Command stdout exceeded {max_stdout_bytes} bytes"
            if failure is None and stderr_path.stat().st_size > max_stderr_bytes:
                failure = f"Command stderr exceeded {max_stderr_bytes} bytes"
        stdout = _read_limited(stdout_path, max_stdout_bytes)
        stderr = _read_limited(stderr_path, max_stderr_bytes)
        if failure is not None:
            raise ProcessExecutionError(failure, stdout=stdout, stderr=stderr)
        return subprocess.CompletedProcess(
            args=command,
            returncode=int(process.returncode),
            stdout=stdout,
            stderr=stderr,
        )

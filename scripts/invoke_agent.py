#!/usr/bin/env python3
"""Invoke a registered Codex or Claude Code CLI with a canonical task envelope."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from _lifecycle import (
    LifecycleError,
    atomic_create_json,
    contained_control_path,
    contained_path,
    lifecycle_dir,
    lifecycle_lock,
    redact,
    redact_json_value,
    require_trusted_project,
    resolve_root,
    safe_subprocess_environment,
    sha256_file,
    utc_now,
    validate_all,
    validate_identifier,
    worker_slot,
    write_scopes_overlap,
    write_scope_lease,
    write_scope_lease_guard,
)
from adapter_bridge import (
    persist_completion_receipt,
    validate_adapter_for_task,
    validate_envelope,
    validate_result_acceptance,
    validate_task_dependencies,
)


CONTROL_PARTS = {
    ".git",
    ".ai-lifecycle",
    ".agent-control",
}

MAX_SNAPSHOT_FILES = 100_000
MAX_AGENT_STDOUT_BYTES = 8 * 1024 * 1024
MAX_AGENT_STDERR_BYTES = 2 * 1024 * 1024


class AgentExecutionError(LifecycleError):
    def __init__(
        self,
        message: str,
        *,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
    ) -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


def _read_limited_text(path: Path, limit: int) -> str:
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    truncated = len(payload) > limit
    payload = payload[:limit]
    value = payload.decode("utf-8", errors="replace")
    if truncated:
        value += "\n[OUTPUT TRUNCATED AT BYTE LIMIT]"
    return value


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate the complete provider process tree without touching peers."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise LifecycleError("Provider process tree could not be terminated") from exc


def run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    stdin_text: str,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    """Run a provider with disk-backed, byte-limited output and tree cancellation."""
    with tempfile.TemporaryDirectory(prefix="ai-lifecycle-agent-io-") as io_name:
        io_directory = Path(io_name)
        stdin_path = io_directory / "stdin.json"
        stdout_path = io_directory / "stdout.log"
        stderr_path = io_directory / "stderr.log"
        stdin_path.write_text(stdin_text, encoding="utf-8")
        creationflags = 0
        popen_options: dict[str, Any] = {}
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_options["start_new_session"] = True
        with (
            stdin_path.open("rb") as stdin_stream,
            stdout_path.open("w+b") as stdout_stream,
            stderr_path.open("w+b") as stderr_stream,
        ):
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdin=stdin_stream,
                stdout=stdout_stream,
                stderr=stderr_stream,
                creationflags=creationflags,
                **popen_options,
            )
            deadline = time.monotonic() + timeout_seconds
            failure: str | None = None
            timed_out = False
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        failure = f"Agent invocation timed out after {timeout_seconds} seconds"
                        terminate_process_tree(process)
                        break
                    stdout_stream.flush()
                    stderr_stream.flush()
                    if stdout_path.stat().st_size > MAX_AGENT_STDOUT_BYTES:
                        failure = (
                            "Agent stdout exceeded the "
                            f"{MAX_AGENT_STDOUT_BYTES}-byte safety limit"
                        )
                        terminate_process_tree(process)
                        break
                    if stderr_path.stat().st_size > MAX_AGENT_STDERR_BYTES:
                        failure = (
                            "Agent stderr exceeded the "
                            f"{MAX_AGENT_STDERR_BYTES}-byte safety limit"
                        )
                        terminate_process_tree(process)
                        break
                    time.sleep(0.05)
            except BaseException:
                try:
                    terminate_process_tree(process)
                except LifecycleError:
                    pass
                raise
            stdout_stream.flush()
            stderr_stream.flush()
            if failure is None and stdout_path.stat().st_size > MAX_AGENT_STDOUT_BYTES:
                failure = (
                    "Agent stdout exceeded the "
                    f"{MAX_AGENT_STDOUT_BYTES}-byte safety limit"
                )
            if failure is None and stderr_path.stat().st_size > MAX_AGENT_STDERR_BYTES:
                failure = (
                    "Agent stderr exceeded the "
                    f"{MAX_AGENT_STDERR_BYTES}-byte safety limit"
                )
        stdout = _read_limited_text(stdout_path, MAX_AGENT_STDOUT_BYTES)
        stderr = _read_limited_text(stderr_path, MAX_AGENT_STDERR_BYTES)
        if failure is not None:
            raise AgentExecutionError(
                failure,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
            )
        return subprocess.CompletedProcess(
            args=command,
            returncode=int(process.returncode),
            stdout=stdout,
            stderr=stderr,
        )


def is_link_or_reparse(path: Path) -> bool:
    """Return true for links and Windows reparse points, including junctions."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        metadata = path.lstat()
    except OSError as exc:
        raise LifecycleError(f"Cannot inspect repository path: {path}: {exc}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def assert_regular_tree(root: Path) -> None:
    """Reject links, reparse points, and special files in the executable copy."""
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names if name not in CONTROL_PARTS]
        base = Path(directory)
        for name in names:
            path = base / name
            if is_link_or_reparse(path):
                raise LifecycleError(
                    f"Repository links and reparse points are not supported for isolated agent execution: {path.relative_to(root)}"
                )
            if not path.is_dir():
                raise LifecycleError(f"Repository path is not a regular directory: {path}")
        for name in files:
            if name in CONTROL_PARTS:
                continue
            path = base / name
            if is_link_or_reparse(path) or not path.is_file():
                raise LifecycleError(
                    f"Repository path is not a regular file: {path.relative_to(root)}"
                )


def copy_to_isolated_workspace(root: Path, workspace: Path) -> None:
    assert_regular_tree(root)

    def ignore_control(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in CONTROL_PARTS}

    try:
        shutil.copytree(
            root,
            workspace,
            symlinks=False,
            ignore=ignore_control,
            copy_function=shutil.copy2,
        )
    except (OSError, shutil.Error) as exc:
        raise LifecycleError(f"Cannot create isolated repository copy: {exc}") from exc
    if (workspace / ".git").exists() or (workspace / ".ai-lifecycle").exists():
        raise LifecycleError("Isolated workspace unexpectedly contains repository control data")


def repository_snapshot(
    root: Path, limit: int = MAX_SNAPSHOT_FILES
) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    count = 0
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names if name not in CONTROL_PARTS]
        base = Path(directory)
        for name in names:
            path = base / name
            if is_link_or_reparse(path) or not path.is_dir():
                raise LifecycleError(
                    f"Repository snapshot encountered a non-regular directory: {path.relative_to(root)}"
                )
        for name in files:
            if name in CONTROL_PARTS:
                continue
            path = base / name
            if is_link_or_reparse(path) or not path.is_file():
                raise LifecycleError(
                    f"Repository snapshot encountered a non-regular file: {path.relative_to(root)}"
                )
            relative = str(path.relative_to(root)).replace("\\", "/")
            try:
                snapshot[relative] = sha256_file(path)
            except OSError as exc:
                raise LifecycleError(f"Cannot hash repository file {relative}: {exc}") from exc
            count += 1
            if count > limit:
                raise LifecycleError(
                    f"Repository snapshot exceeds the safety limit of {limit} files"
                )
    return snapshot


def changed_paths(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(
        path
        for path in set(before).union(after)
        if before.get(path) != after.get(path)
    )


def scope_matches(path: str, scope: str) -> bool:
    normalized = scope.replace("\\", "/").rstrip("/") or "."
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized == ".":
        return True
    candidate = path.replace("\\", "/")
    if os.name == "nt":
        normalized = normalized.casefold()
        candidate = candidate.casefold()
    if any(character in normalized for character in "*?["):
        return fnmatch.fnmatchcase(candidate, normalized)
    return candidate == normalized or candidate.startswith(normalized + "/")


def normalize_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{label} must be a non-empty relative path")
    normalized = value.strip().replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute() or normalized.startswith("/"):
        raise LifecycleError(f"{label} must be relative: {value!r}")
    parts = normalized.split("/")
    if any(part in {"", ".."} for part in parts):
        raise LifecycleError(f"{label} contains an unsafe path component: {value!r}")
    parts = [part for part in parts if part != "."]
    if not parts:
        raise LifecycleError(f"{label} must identify a repository file")
    if parts[0] in CONTROL_PARTS:
        raise LifecycleError(f"{label} targets protected control data: {value!r}")
    return "/".join(parts)


def normalize_scope(value: Any, label: str, *, allow_control: bool = False) -> str:
    if value == ".":
        return "."
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{label} must be a non-empty relative path or glob")
    normalized = value.strip().replace("\\", "/").rstrip("/")
    if normalized == ".":
        return "."
    candidate = Path(normalized)
    if candidate.is_absolute() or normalized.startswith("/"):
        raise LifecycleError(f"{label} must be relative: {value!r}")
    parts = normalized.split("/")
    if any(part in {"", ".."} for part in parts):
        raise LifecycleError(f"{label} contains an unsafe path component: {value!r}")
    parts = [part for part in parts if part != "."]
    if not parts:
        return "."
    if not allow_control and parts[0] in CONTROL_PARTS:
        raise LifecycleError(f"{label} targets protected control data: {value!r}")
    return "/".join(parts)


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise LifecycleError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LifecycleError(f"{label} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise LifecycleError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def bind_task_context(
    task: dict[str, Any], config: dict[str, Any], state: dict[str, Any]
) -> None:
    validate_identifier(task.get("task_id"), "task_id", min_length=8)
    validate_identifier(task.get("correlation_id"), "correlation_id", min_length=8)
    if task.get("project_id") != config["project"]["id"]:
        raise LifecycleError("Task belongs to a different project")
    if task.get("lifecycle_run_id") != state["lifecycle_run_id"]:
        raise LifecycleError("Task belongs to a different lifecycle run")
    phase = task.get("phase")
    phase_state = state.get("phases", {}).get(phase)
    if not isinstance(phase_state, dict):
        raise LifecycleError("Task phase is not enabled in this lifecycle run")
    if state.get("current_phase") != phase or phase_state.get("status") != "in_progress":
        raise LifecycleError("Task phase must be the current in-progress lifecycle phase")
    expires_at = task.get("expires_at")
    if expires_at is not None and parse_timestamp(expires_at, "task.expires_at") <= datetime.now(timezone.utc):
        raise LifecycleError("Task has expired")
    if task.get("permissions", {}).get("external_mutations") is not False:
        raise LifecycleError("Coding-agent tasks must set external_mutations=false")


def bind_result_context(result: dict[str, Any], task: dict[str, Any]) -> None:
    expected = {
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "run_id": task["lifecycle_run_id"],
    }
    mismatches = [
        key for key, expected_value in expected.items() if result.get(key) != expected_value
    ]
    if mismatches:
        raise LifecycleError(
            "Result does not belong to the invoked task: " + ", ".join(mismatches)
        )
    if result.get("external_changes"):
        raise LifecycleError("Coding-agent results must not contain external changes")


def validate_result_artifacts(
    workspace: Path,
    result: dict[str, Any],
    task: dict[str, Any],
    changes: list[str],
    permission_scopes: list[str],
    allowed_scopes: list[str],
    forbidden_scopes: list[str],
) -> None:
    """Verify every declared coding artifact before any file reaches the repository."""
    seen: set[str] = set()
    allowed_types = set(task.get("output_contract", {}).get("artifact_types", []))
    for index, artifact in enumerate(result.get("artifacts", [])):
        if not isinstance(artifact, dict):
            raise LifecycleError(f"result.artifacts[{index}] must be an object")
        uri = artifact.get("uri")
        if not isinstance(uri, str):
            raise LifecycleError(f"result.artifacts[{index}].uri must be a string")
        parsed = urlsplit(uri)
        if parsed.scheme or parsed.netloc:
            raise LifecycleError(
                "Coding-agent artifact URIs must be local paths inside the isolated workspace"
            )
        relative = normalize_relative_path(uri, f"result.artifacts[{index}].uri")
        if relative in seen:
            raise LifecycleError("Result artifacts contain duplicate normalized URIs")
        seen.add(relative)
        path = contained_path(workspace, relative, must_exist=True)
        if is_link_or_reparse(path) or not path.is_file():
            raise LifecycleError(f"Result artifact must be a regular file: {relative}")
        if relative not in changes:
            raise LifecycleError(
                f"Result artifact is not an output of this isolated execution: {relative}"
            )
        if (
            not permission_scopes
            or not allowed_scopes
            or not any(scope_matches(relative, scope) for scope in permission_scopes)
            or not any(scope_matches(relative, scope) for scope in allowed_scopes)
            or any(scope_matches(relative, scope) for scope in forbidden_scopes)
        ):
            raise LifecycleError(f"Result artifact escaped the allowed write scope: {relative}")
        digest = artifact.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise LifecycleError("Coding-agent artifacts must use sha256 digests")
        if digest != sha256_file(path):
            raise LifecycleError(f"Result artifact digest does not match: {relative}")
        artifact_type = artifact.get("artifact_type")
        if allowed_types and artifact_type not in allowed_types:
            raise LifecycleError(
                f"Result artifact type is outside the task output contract: {artifact_type}"
            )


def unwrap_claude_result(stdout: str) -> dict[str, Any]:
    try:
        outer = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"Claude Code did not return JSON: {exc}") from exc
    if isinstance(outer, dict) and TASK_RESULT_KEYS.issubset(outer):
        return outer
    candidate = outer.get("result") if isinstance(outer, dict) else None
    if not isinstance(candidate, str):
        raise LifecycleError("Claude Code JSON does not contain a result envelope")
    candidate = candidate.strip()
    code_fence = chr(96) * 3
    if candidate.startswith("~~~") or candidate.startswith(code_fence):
        lines = candidate.splitlines()
        candidate = "\n".join(lines[1:-1]).strip()
        if candidate.startswith("json"):
            candidate = candidate[4:].lstrip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise LifecycleError(
            f"Claude Code result field is not a JSON result envelope: {exc}"
        ) from exc


TASK_RESULT_KEYS = {
    "spec_version",
    "task_id",
    "correlation_id",
    "run_id",
    "status",
    "summary",
}


def build_command(
    adapter_id: str,
    executable: str,
    task: dict[str, Any],
    result_schema: Path,
    result_path: Path,
    max_turns: int,
) -> list[str]:
    if adapter_id == "codex":
        sandbox = "workspace-write" if task["permissions"]["write"] else "read-only"
        return [
            executable,
            "exec",
            "--json",
            "--sandbox",
            sandbox,
            "--output-schema",
            str(result_schema),
            "-o",
            str(result_path),
            "-",
        ]
    if adapter_id == "claude-code":
        instruction = (
            "Execute the canonical task envelope supplied on standard input. "
            "Respect every permission and ownership scope. Return exactly one JSON object "
            "that conforms to the result schema named in output_contract, without markdown."
        )
        command = [
            executable,
            "-p",
            instruction,
            "--output-format",
            "json",
            "--max-turns",
            str(max_turns),
        ]
        if not task["permissions"]["write"]:
            command.extend(["--permission-mode", "plan"])
        return command
    raise LifecycleError(
        f"CLI invocation is not implemented for adapter: {adapter_id}"
    )


def prepare_isolated_task(
    root: Path,
    workspace: Path,
    task: dict[str, Any],
    source_schema: Path,
) -> tuple[dict[str, Any], Path, Path]:
    """Copy only declared lifecycle inputs into a control area in the sandbox."""
    control = workspace / ".agent-control"
    inputs_directory = control / "inputs"
    inputs_directory.mkdir(parents=True, exist_ok=False)
    isolated_schema = control / "result-envelope.schema.json"
    shutil.copy2(source_schema, isolated_schema)
    isolated_result = control / "result.json"
    isolated_task = json.loads(json.dumps(task))

    for index, artifact in enumerate(isolated_task.get("inputs", [])):
        if not isinstance(artifact, dict):
            raise LifecycleError(f"task.inputs[{index}] must be an object")
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri:
            raise LifecycleError(f"task.inputs[{index}].uri must be a non-empty string")
        parsed = urlsplit(uri)
        if parsed.scheme in {"https", "http"}:
            continue
        if parsed.scheme:
            raise LifecycleError(
                f"task.inputs[{index}].uri uses an unsupported local URI scheme"
            )
        source = contained_path(root, uri, must_exist=True)
        if is_link_or_reparse(source) or not source.is_file():
            raise LifecycleError(f"Task input must be a regular file: {uri}")
        declared_digest = artifact.get("digest")
        actual_digest = sha256_file(source)
        if declared_digest != actual_digest:
            raise LifecycleError(f"Task input digest does not match: {uri}")
        isolated_input = inputs_directory / f"{index:04d}.artifact"
        shutil.copy2(source, isolated_input)
        artifact["uri"] = str(isolated_input.relative_to(workspace)).replace("\\", "/")

    isolated_task["output_contract"]["result_schema"] = str(
        isolated_schema.relative_to(workspace)
    ).replace("\\", "/")
    return isolated_task, isolated_schema, isolated_result


def safe_merge_target(root: Path, relative: str) -> Path:
    target = contained_path(root, relative)
    current = root
    for part in Path(relative).parts[:-1]:
        current = current / part
        if current.exists() and is_link_or_reparse(current):
            raise LifecycleError(f"Merge target traverses a link or reparse point: {relative}")
    if target.exists() and (is_link_or_reparse(target) or not target.is_file()):
        raise LifecycleError(f"Merge target is not a regular file: {relative}")
    return target


def copy_file_atomically(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".agent-merge", dir=str(target.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(source, temporary)
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def merge_isolated_changes(
    root: Path,
    workspace: Path,
    changes: list[str],
    original_before: dict[str, str],
    isolated_after: dict[str, str],
    finalize: Callable[[], None],
) -> None:
    """Merge validated files only when the complete read baseline is unchanged."""
    current_before_merge = repository_snapshot(root)
    if current_before_merge != original_before:
        raise LifecycleError(
            "Original repository changed during agent execution; refusing a stale merge"
        )

    transaction = Path(tempfile.mkdtemp(prefix="ai-lifecycle-merge-"))
    backups = transaction / "backups"
    backups.mkdir()
    staged = transaction / "staged"
    staged.mkdir()
    original_files: dict[str, Path | None] = {}
    staged_files: dict[str, Path | None] = {}
    created_directories: set[Path] = set()
    applied: list[str] = []
    preserve_transaction = False

    try:
        for index, relative in enumerate(changes):
            source = workspace / Path(relative)
            target = safe_merge_target(root, relative)
            if source.exists() and (is_link_or_reparse(source) or not source.is_file()):
                raise LifecycleError(f"Isolated change is not a regular file: {relative}")
            if source.exists():
                try:
                    source.resolve().relative_to(workspace)
                except ValueError as exc:
                    raise LifecycleError(
                        f"Isolated change escapes the temporary workspace: {relative}"
                    ) from exc
                staged_source = staged / f"{index:06d}.file"
                shutil.copy2(source, staged_source)
                if sha256_file(staged_source) != isolated_after.get(relative):
                    raise LifecycleError(
                        f"Isolated change was modified while staging: {relative}"
                    )
                staged_files[relative] = staged_source
            else:
                if relative in isolated_after:
                    raise LifecycleError(
                        f"Isolated change disappeared while staging: {relative}"
                    )
                staged_files[relative] = None
            if target.exists():
                backup = backups / f"{index:06d}.file"
                shutil.copy2(target, backup)
                original_files[relative] = backup
            else:
                original_files[relative] = None

        for relative in changes:
            source = staged_files[relative]
            target = safe_merge_target(root, relative)
            current_digest = sha256_file(target) if target.exists() else None
            if current_digest != original_before.get(relative):
                raise LifecycleError(
                    f"Merge target changed while staging the agent result: {relative}"
                )
            missing: list[Path] = []
            parent = target.parent
            while parent != root and not parent.exists():
                missing.append(parent)
                parent = parent.parent
            if parent != root and (is_link_or_reparse(parent) or not parent.is_dir()):
                raise LifecycleError(f"Merge target has an unsafe parent: {relative}")
            for directory in reversed(missing):
                directory.mkdir()
                created_directories.add(directory)
            if source is not None:
                copy_file_atomically(source, target)
            elif target.exists():
                target.unlink()
            else:
                raise LifecycleError(f"Merge deletion target disappeared: {relative}")
            applied.append(relative)

        expected = dict(original_before)
        for relative in changes:
            if relative in isolated_after:
                expected[relative] = isolated_after[relative]
            else:
                expected.pop(relative, None)
        if repository_snapshot(root) != expected:
            raise LifecycleError(
                "Repository changed while applying the isolated result; rolling back"
            )
        finalize()
    except Exception as exc:
        rollback_errors: list[str] = []
        for relative in reversed(applied):
            try:
                target = safe_merge_target(root, relative)
                backup = original_files[relative]
                applied_digest = isolated_after.get(relative)
                current_digest = sha256_file(target) if target.exists() else None
                if current_digest != applied_digest:
                    rollback_errors.append(
                        f"{relative}: target diverged after agent application; "
                        f"backup retained at {backups}"
                    )
                    continue
                if backup is None:
                    if target.exists():
                        target.unlink()
                else:
                    copy_file_atomically(backup, target)
            except Exception as rollback_exc:  # pragma: no cover - catastrophic I/O path
                rollback_errors.append(f"{relative}: {rollback_exc}")
        for directory in sorted(created_directories, key=lambda item: len(item.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass
        if rollback_errors:
            preserve_transaction = True
            raise LifecycleError(
                f"Agent merge failed ({exc}); rollback also failed: "
                + "; ".join(rollback_errors)
            ) from exc
        if isinstance(exc, LifecycleError):
            raise
        raise LifecycleError(f"Agent merge failed and was rolled back: {exc}") from exc
    finally:
        if not preserve_transaction:
            shutil.rmtree(transaction, ignore_errors=True)


def write_failure_evidence(
    root: Path,
    adapter: str,
    task: dict[str, Any] | None,
    actor: str | None,
    reason: str | None,
    started_at: str,
    started_clock: float,
    error: str,
    *,
    command: list[str] | None = None,
    exit_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
) -> Path:
    task_id = task.get("task_id") if isinstance(task, dict) else None
    try:
        safe_task_id = validate_identifier(task_id, "task_id", min_length=8)
    except LifecycleError:
        safe_task_id = "unknown-task"
    evidence_path = contained_control_path(
        root,
        ".ai-lifecycle/evidence/external/"
        f"agent-{safe_task_id}-{adapter}-failure-{uuid.uuid4().hex}.json",
    )
    evidence = {
        "schema_version": 1,
        "task_id": task_id,
        "correlation_id": task.get("correlation_id") if isinstance(task, dict) else None,
        "adapter": adapter,
        "authorization": {"actor": actor, "reason": reason},
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_seconds": round(time.monotonic() - started_clock, 3),
        "status": "failed",
        "error": redact(error),
        "command": [redact(item) for item in (command or [])],
        "exit_code": exit_code,
        "stdout": redact(stdout),
        "stderr": redact(stderr),
        "accepted": False,
        "original_workspace_modified": False,
    }
    atomic_create_json(evidence_path, evidence)
    return evidence_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--adapter", required=True, choices=["codex", "claude-code"])
    parser.add_argument("--task-file", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--max-turns", type=int, default=12)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorization-actor")
    parser.add_argument("--authorization-reason")
    args = parser.parse_args()

    root: Path | None = None
    trusted = False
    task: dict[str, Any] | None = None
    command: list[str] = []
    completed: subprocess.CompletedProcess[str] | None = None
    started_at = utc_now()
    started_clock = time.monotonic()

    try:
        if not args.execute or not args.authorization_actor or not args.authorization_reason:
            raise LifecycleError(
                "Agent invocation requires --execute, --authorization-actor, and --authorization-reason"
            )
        if not 1 <= args.max_turns <= 100:
            raise LifecycleError("--max-turns must be between 1 and 100")
        if not 1 <= args.timeout_seconds <= 7200:
            raise LifecycleError("--timeout-seconds must be between 1 and 7200")

        root = resolve_root(args.project_root)
        require_trusted_project(root, "Coding-agent execution")
        trusted = True
        config, registry, state = validate_all(root)
        agent_config = config.get("agents", {})
        if agent_config.get("enabled") is not True:
            raise LifecycleError("Coding-agent execution is disabled by project configuration")
        if agent_config.get("ownership_strategy") != "exclusive-path":
            raise LifecycleError(
                "The bundled coding-agent adapter currently supports only the "
                "exclusive-path ownership strategy"
            )
        task_argument = args.task_file.expanduser()
        task_path = (
            task_argument.resolve()
            if task_argument.is_absolute()
            else (root / task_argument).resolve()
        )
        try:
            task_path.relative_to(lifecycle_dir(root) / "tasks")
        except ValueError as exc:
            raise LifecycleError(
                "Task file must be stored under .ai-lifecycle/tasks"
            ) from exc
        if is_link_or_reparse(task_path) or not task_path.is_file():
            raise LifecycleError("Task file must be a regular file")
        task = validate_envelope(
            "task", json.loads(task_path.read_text(encoding="utf-8"))
        )
        if task.get("role") not in agent_config.get("roles", []):
            raise LifecycleError(
                f"Task role is not enabled by project configuration: {task.get('role')}"
            )
        bind_task_context(task, config, state)
        validate_task_dependencies(root, task)
        if redact_json_value(task) != task:
            raise LifecycleError(
                "Task contains secret-bearing fields or values and cannot be sent to an agent"
            )
        canonical_task_path = contained_control_path(
            root,
            f".ai-lifecycle/tasks/{task['task_id']}/task.json",
            must_exist=True,
        )
        task_directory = canonical_task_path.parent
        if task_path != canonical_task_path.resolve():
            raise LifecycleError(
                "Task file must use the canonical .ai-lifecycle/tasks/<task_id>/task.json path"
            )
        if not task["permissions"]["network"]:
            raise LifecycleError(
                "External coding-agent invocation requires task permissions.network=true"
            )
        adapter = next(
            (tool for tool in registry["tools"] if tool.get("id") == args.adapter),
            None,
        )
        if adapter is None:
            raise LifecycleError(f"Adapter is not registered: {args.adapter}")
        if adapter.get("availability") != "available":
            raise LifecycleError(
                f"Adapter {args.adapter} is not available: {adapter.get('availability')}"
            )
        validate_adapter_for_task(
            adapter, task, adapter_id=args.adapter, transport="cli"
        )
        cli = adapter.get("cli")
        if not isinstance(cli, dict) or not isinstance(cli.get("executable"), str):
            raise LifecycleError(f"Adapter {args.adapter} has no CLI configuration")

        read_scopes = [
            normalize_scope(scope, f"permissions.read[{index}]")
            for index, scope in enumerate(task["permissions"]["read"])
        ]
        if "." not in read_scopes:
            raise LifecycleError(
                "Isolated coding-agent execution currently requires explicit repository read scope '.'"
            )
        permission_scopes = [
            normalize_scope(scope, f"permissions.write[{index}]")
            for index, scope in enumerate(task["permissions"]["write"])
        ]
        allowed_scopes = [
            normalize_scope(scope, f"ownership.write_scope[{index}]")
            for index, scope in enumerate(task["ownership"]["write_scope"])
        ]
        forbidden_scopes = [
            normalize_scope(
                scope,
                f"ownership.forbidden_scope[{index}]",
                allow_control=True,
            )
            for index, scope in enumerate(task["ownership"]["forbidden_scope"])
        ]
        if bool(permission_scopes) != bool(allowed_scopes):
            raise LifecycleError(
                "Task permissions.write and ownership.write_scope must both be empty or both grant scope"
            )
        if permission_scopes and not write_scopes_overlap(
            permission_scopes, allowed_scopes
        ):
            raise LifecycleError(
                "Task permissions.write and ownership.write_scope do not overlap"
            )

        result_path = task_directory / f"result-{args.adapter}.json"
        completion_path = task_directory / f"completion-receipt-{args.adapter}.json"
        raw_path = task_directory / f"raw-{args.adapter}.json"
        evidence_path = contained_control_path(
            root,
            ".ai-lifecycle/evidence/external/"
            f"agent-{task['task_id']}-{args.adapter}.json",
        )
        source_schema = contained_path(
            root, task["output_contract"]["result_schema"], must_exist=True
        )
        canonical_schema = task_directory / "result-envelope.schema.json"
        if source_schema != canonical_schema.resolve():
            raise LifecycleError(
                "Result schema must use the canonical per-task result-envelope.schema.json path"
            )
        if is_link_or_reparse(source_schema) or not source_schema.is_file():
            raise LifecycleError("Result schema must be a regular file")

        lock_digest = hashlib.sha256(
            f"{task['task_id']}:{task['revision']}:{args.adapter}".encode("utf-8")
        ).hexdigest()[:24]
        lease_ttl = min(24 * 60 * 60, args.timeout_seconds + 15 * 60)
        with (
            lifecycle_lock(root, f"agent-{lock_digest}"),
            worker_slot(
                root,
                task_id=task["task_id"],
                run_id=task["lifecycle_run_id"],
                owner=f"{args.adapter}-{os.getpid()}",
                max_workers=agent_config["max_parallel"],
                ttl_seconds=lease_ttl,
            ) as active_worker,
            write_scope_lease(
                root,
                task_id=task["task_id"],
                run_id=task["lifecycle_run_id"],
                owner=f"{args.adapter}-{os.getpid()}",
                write_scope=allowed_scopes,
                ttl_seconds=lease_ttl,
            ) as lease,
        ):
            if result_path.exists() or completion_path.exists() or evidence_path.exists():
                raise LifecycleError(
                    "An invocation result already exists for this task and adapter; create a new task revision"
                )

            original_before = repository_snapshot(root)
            with tempfile.TemporaryDirectory(
                prefix="ai-lifecycle-agent-", ignore_cleanup_errors=True
            ) as temporary_name:
                workspace = Path(temporary_name) / "workspace"
                copy_to_isolated_workspace(root, workspace)
                isolated_task, isolated_schema, isolated_result = prepare_isolated_task(
                    root, workspace, task, source_schema
                )
                isolated_before = repository_snapshot(workspace)
                command = build_command(
                    args.adapter,
                    cli["executable"],
                    isolated_task,
                    isolated_schema,
                    isolated_result,
                    args.max_turns,
                )

                # Repository-controlled credential names are deliberately ignored.
                environment = safe_subprocess_environment([])
                completed = run_bounded_process(
                    command,
                    cwd=workspace,
                    environment=environment,
                    stdin_text=json.dumps(isolated_task, ensure_ascii=False),
                    timeout_seconds=args.timeout_seconds,
                )
                isolated_after = repository_snapshot(workspace)
                changes = changed_paths(isolated_before, isolated_after)
                if completed.returncode != 0:
                    raise LifecycleError(
                        f"Agent process exited with code {completed.returncode}"
                    )

                if args.adapter == "claude-code":
                    raw_output: Any = (
                        json.loads(completed.stdout) if completed.stdout.strip() else {}
                    )
                    result = unwrap_claude_result(completed.stdout)
                else:
                    raw_output = [
                        json.loads(line)
                        for line in completed.stdout.splitlines()
                        if line.strip()
                    ]
                    if not isolated_result.exists():
                        raise LifecycleError(
                            "Codex did not write the configured result envelope"
                        )
                    result = json.loads(isolated_result.read_text(encoding="utf-8"))

                result = validate_envelope("result", result)
                bind_result_context(result, task)
                if redact_json_value(result) != result:
                    raise LifecycleError(
                        "Agent result contains secret-bearing fields or values and cannot be persisted"
                    )
                result_paths = [
                    normalize_relative_path(path, f"result.changed_paths[{index}]")
                    for index, path in enumerate(result.get("changed_paths", []))
                ]
                if len(result_paths) != len(set(result_paths)):
                    raise LifecycleError(
                        "Result changed_paths contains duplicate normalized paths"
                    )
                validate_result_artifacts(
                    workspace,
                    result,
                    task,
                    changes,
                    permission_scopes,
                    allowed_scopes,
                    forbidden_scopes,
                )
                scope_violations = [
                    path
                    for path in changes
                    if (
                        not permission_scopes
                        or not allowed_scopes
                        or not any(scope_matches(path, scope) for scope in permission_scopes)
                        or not any(scope_matches(path, scope) for scope in allowed_scopes)
                        or any(scope_matches(path, scope) for scope in forbidden_scopes)
                    )
                ]
                mismatch = sorted(set(result_paths).symmetric_difference(changes))
                rejection_reasons: list[str] = []
                if result.get("status") != "succeeded":
                    rejection_reasons.append(
                        f"result status is {result.get('status')!r}, not 'succeeded'"
                    )
                try:
                    validate_result_acceptance(task, result)
                except LifecycleError as exc:
                    rejection_reasons.append(str(exc))
                if scope_violations:
                    rejection_reasons.append("changes escaped the allowed write scope")
                if mismatch:
                    rejection_reasons.append(
                        "result changed_paths does not match the isolated repository diff"
                    )
                if rejection_reasons:
                    raise LifecycleError("; ".join(rejection_reasons))

                duration = round(time.monotonic() - started_clock, 3)
                evidence = {
                    "schema_version": 1,
                    "task_id": task["task_id"],
                    "revision": task["revision"],
                    "correlation_id": task["correlation_id"],
                    "lifecycle_run_id": task["lifecycle_run_id"],
                    "phase": task["phase"],
                    "adapter": args.adapter,
                    "authorization": {
                        "actor": args.authorization_actor,
                        "reason": args.authorization_reason,
                    },
                    "started_at": started_at,
                    "finished_at": utc_now(),
                    "duration_seconds": duration,
                    "command": [redact(item) for item in command],
                    "exit_code": completed.returncode,
                    "stderr": redact(completed.stderr),
                    "changed_paths": changes,
                    "scope_violations": [],
                    "result_changed_path_mismatch": [],
                    "credential_environment_forwarded": [],
                    "isolated_execution": True,
                    "original_control_directories_exposed": False,
                    "result_path": str(result_path.relative_to(root)).replace("\\", "/"),
                    "raw_path": str(raw_path.relative_to(root)).replace("\\", "/"),
                    "completion_receipt_path": str(
                        completion_path.relative_to(root)
                    ).replace("\\", "/"),
                    "write_scope_lease_id": lease.get("lease_id") if lease else None,
                    "worker_slot_id": active_worker["slot_id"],
                    "output_limits": {
                        "stdout_bytes": MAX_AGENT_STDOUT_BYTES,
                        "stderr_bytes": MAX_AGENT_STDERR_BYTES,
                    },
                    "accepted": True,
                }
                created_metadata: list[Path] = []
                expected_repository_outputs = [
                    {"path": relative, "digest": isolated_after.get(relative)}
                    for relative in sorted(changes)
                ]

                def finalize_metadata() -> None:
                    try:
                        atomic_create_json(
                            raw_path,
                            {
                                "schema_version": 1,
                                "redacted": True,
                                "output": redact_json_value(raw_output),
                            },
                        )
                        created_metadata.append(raw_path)
                        atomic_create_json(result_path, result)
                        created_metadata.append(result_path)
                        persisted_completion = persist_completion_receipt(
                            root,
                            args.adapter,
                            task,
                            result,
                            result_path,
                            expected_repository_outputs=expected_repository_outputs,
                        )
                        created_metadata.append(persisted_completion)
                        atomic_create_json(evidence_path, evidence)
                        created_metadata.append(evidence_path)
                    except Exception:
                        for created in reversed(created_metadata):
                            try:
                                created.unlink()
                            except FileNotFoundError:
                                pass
                        raise

                with write_scope_lease_guard(root, lease), lifecycle_lock(root, "state"):
                    current_config, _, current_state = validate_all(root)
                    bind_task_context(task, current_config, current_state)
                    validate_task_dependencies(root, task)
                    merge_isolated_changes(
                        root,
                        workspace,
                        changes,
                        original_before,
                        isolated_after,
                        finalize_metadata,
                    )

        print(
            json.dumps(
                {
                    "status": "accepted",
                    "adapter": args.adapter,
                    "task_id": task["task_id"],
                    "result_status": result["status"],
                    "changed_paths": changes,
                    "scope_violations": scope_violations,
                    "result_changed_path_mismatch": mismatch,
                    "evidence": str(evidence_path),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    except AgentExecutionError as exc:
        failure_evidence: Path | None = None
        if root is not None and trusted:
            try:
                failure_evidence = write_failure_evidence(
                    root,
                    args.adapter,
                    task,
                    args.authorization_actor,
                    args.authorization_reason,
                    started_at,
                    started_clock,
                    str(exc),
                    command=command,
                    stdout=exc.stdout,
                    stderr=exc.stderr,
                )
            except (LifecycleError, OSError):
                failure_evidence = None
        print(
            json.dumps(
                {
                    "status": "blocked" if exc.timed_out else "error",
                    "error": str(exc),
                    "evidence": str(failure_evidence) if failure_evidence else None,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 6 if exc.timed_out else 2
    except subprocess.TimeoutExpired as exc:
        failure_evidence: Path | None = None
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        error = f"Agent invocation timed out after {exc.timeout} seconds"
        if root is not None and trusted:
            try:
                failure_evidence = write_failure_evidence(
                    root,
                    args.adapter,
                    task,
                    args.authorization_actor,
                    args.authorization_reason,
                    started_at,
                    started_clock,
                    error,
                    command=command,
                    stdout=stdout,
                    stderr=stderr,
                )
            except (LifecycleError, OSError):
                failure_evidence = None
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "error": error,
                    "evidence": str(failure_evidence) if failure_evidence else None,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 6
    except (
        LifecycleError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        failure_evidence = None
        if root is not None and trusted:
            try:
                failure_evidence = write_failure_evidence(
                    root,
                    args.adapter,
                    task,
                    args.authorization_actor,
                    args.authorization_reason,
                    started_at,
                    started_clock,
                    str(exc),
                    command=command,
                    exit_code=completed.returncode if completed is not None else None,
                    stdout=completed.stdout if completed is not None else "",
                    stderr=completed.stderr if completed is not None else "",
                )
            except (LifecycleError, OSError):
                failure_evidence = None
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": str(exc),
                    "evidence": str(failure_evidence) if failure_evidence else None,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

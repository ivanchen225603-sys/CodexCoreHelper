#!/usr/bin/env python3
"""Plan or run a phase task graph through the bundled coding-agent adapter."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from _lifecycle import (
    LifecycleError,
    atomic_create_json,
    contained_control_path,
    lifecycle_lock,
    load_json,
    redact,
    require_trusted_project,
    resolve_root,
    safe_subprocess_environment,
    utc_now,
    validate_all,
)
from adapter_bridge import _validated_completion_receipt, validate_envelope
from invoke_agent import AgentExecutionError, run_bounded_process


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    path: Path
    document: dict[str, Any]

    @property
    def dependencies(self) -> tuple[str, ...]:
        return tuple(self.document.get("dependencies", []))

    @property
    def is_writer(self) -> bool:
        return bool(self.document.get("ownership", {}).get("write_scope", []))


def load_task(root: Path, task_id: str) -> TaskRecord:
    path = contained_control_path(
        root, f".ai-lifecycle/tasks/{task_id}/task.json", must_exist=True
    )
    if path.is_symlink() or not path.is_file():
        raise LifecycleError(f"Task must be a regular canonical file: {task_id}")
    document = validate_envelope("task", load_json(path))
    if document.get("task_id") != task_id:
        raise LifecycleError(f"Task directory does not match task_id: {task_id}")
    return TaskRecord(task_id=task_id, path=path, document=document)


def load_phase_tasks(
    root: Path,
    phase: str,
    selected_ids: list[str],
    config: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, TaskRecord]:
    task_root = contained_control_path(root, ".ai-lifecycle/tasks")
    records: dict[str, TaskRecord] = {}
    if selected_ids:
        candidates = selected_ids
    else:
        candidates = sorted(
            path.parent.name for path in task_root.glob("*/task.json") if path.is_file()
        )
    for task_id in candidates:
        if task_id in records:
            raise LifecycleError(f"Task selection contains a duplicate: {task_id}")
        record = load_task(root, task_id)
        task = record.document
        if task.get("phase") != phase:
            if selected_ids:
                raise LifecycleError(
                    f"Selected task {task_id} belongs to phase {task.get('phase')}, not {phase}"
                )
            continue
        if task.get("project_id") != config["project"]["id"]:
            raise LifecycleError(f"Task belongs to another project: {task_id}")
        if task.get("lifecycle_run_id") != state["lifecycle_run_id"]:
            raise LifecycleError(f"Task belongs to another lifecycle run: {task_id}")
        if task.get("role") not in config["agents"]["roles"]:
            raise LifecycleError(
                f"Task role is not enabled by project configuration: {task.get('role')}"
            )
        records[task_id] = record
    if not records:
        raise LifecycleError(f"No canonical tasks were found for phase {phase}")
    return records


def completion_is_accepted(root: Path, record: TaskRecord) -> bool:
    receipt_paths = sorted(record.path.parent.glob("completion-receipt-*.json"))
    if len(receipt_paths) > 32:
        raise LifecycleError(f"Task has too many completion receipts: {record.task_id}")
    valid = 0
    errors: list[str] = []
    for receipt_path in receipt_paths:
        try:
            # A completed task remains accepted as historical evidence when a
            # downstream writer intentionally supersedes one of its outputs.
            _validated_completion_receipt(
                root,
                record.document,
                receipt_path,
                require_current_outputs=False,
            )
            valid += 1
        except LifecycleError as exc:
            errors.append(str(exc))
    if errors:
        raise LifecycleError(
            f"Task {record.task_id} has invalid completion data: " + "; ".join(errors)
        )
    if valid > 1:
        raise LifecycleError(
            f"Task {record.task_id} has multiple accepted completions; reconcile a winner"
        )
    return valid == 1


def dependency_records(
    root: Path, records: dict[str, TaskRecord]
) -> dict[str, TaskRecord]:
    all_records = dict(records)
    queue = [dependency for record in records.values() for dependency in record.dependencies]
    while queue:
        task_id = queue.pop()
        if task_id in all_records:
            continue
        record = load_task(root, task_id)
        all_records[task_id] = record
        queue.extend(record.dependencies)
        if len(all_records) > 4096:
            raise LifecycleError("Task graph exceeds the maximum size of 4096 tasks")
    return all_records


def validate_acyclic(records: dict[str, TaskRecord]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise LifecycleError(f"Task dependency cycle detected at {task_id}")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in records[task_id].dependencies:
            if dependency not in records:
                raise LifecycleError(
                    f"Task {task_id} references a missing dependency: {dependency}"
                )
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in sorted(records):
        visit(task_id)


def select_wave(
    records: dict[str, TaskRecord],
    pending: set[str],
    completed: set[str],
    max_parallel: int,
) -> list[TaskRecord]:
    ready = sorted(
        (
            records[task_id]
            for task_id in pending
            if set(records[task_id].dependencies).issubset(completed)
        ),
        key=lambda record: record.task_id,
    )
    readers = [record for record in ready if not record.is_writer]
    if readers:
        return readers[:max_parallel]
    writers = [record for record in ready if record.is_writer]
    return writers[:1]


def build_plan(
    records: dict[str, TaskRecord],
    completed: set[str],
    max_parallel: int,
) -> tuple[list[list[TaskRecord]], dict[str, list[str]]]:
    simulated = set(completed)
    pending = set(records) - completed
    waves: list[list[TaskRecord]] = []
    while pending:
        wave = select_wave(records, pending, simulated, max_parallel)
        if not wave:
            break
        waves.append(wave)
        for record in wave:
            pending.remove(record.task_id)
            simulated.add(record.task_id)
    blocked = {
        task_id: sorted(set(records[task_id].dependencies) - simulated)
        for task_id in sorted(pending)
    }
    return waves, blocked


def invoke_task(
    root: Path,
    record: TaskRecord,
    *,
    adapter: str,
    timeout_seconds: int,
    max_turns: int,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("invoke_agent.py")),
        "--project-root",
        str(root),
        "--adapter",
        adapter,
        "--task-file",
        str(record.path),
        "--timeout-seconds",
        str(timeout_seconds),
        "--max-turns",
        str(max_turns),
        "--execute",
        "--authorization-actor",
        actor,
        "--authorization-reason",
        reason,
    ]
    started_at = utc_now()
    started_clock = time.monotonic()
    environment = safe_subprocess_environment([])
    environment["AI_LIFECYCLE_TRUSTED_PROJECT_ROOT"] = str(root)
    try:
        completed = run_bounded_process(
            command,
            cwd=Path(__file__).resolve().parent,
            environment=environment,
            stdin_text="",
            timeout_seconds=timeout_seconds + 120,
        )
        return {
            "task_id": record.task_id,
            "role": record.document["role"],
            "writer": record.is_writer,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started_clock, 3),
            "exit_code": completed.returncode,
            "stdout": redact(completed.stdout),
            "stderr": redact(completed.stderr),
        }
    except AgentExecutionError as exc:
        return {
            "task_id": record.task_id,
            "role": record.document["role"],
            "writer": record.is_writer,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started_clock, 3),
            "exit_code": 6 if exc.timed_out else 70,
            "stdout": redact(exc.stdout),
            "stderr": redact(exc.stderr),
            "error": redact(str(exc)),
        }


def orchestration_context(
    root: Path, phase: str, selected_ids: list[str], requested_parallel: int | None
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, TaskRecord],
    dict[str, TaskRecord],
    set[str],
    int,
]:
    config, _, state = validate_all(root)
    if phase not in config["lifecycle"]["phases"]:
        raise LifecycleError(f"Phase is not enabled: {phase}")
    if state["phases"][phase]["status"] != "in_progress":
        raise LifecycleError(
            f"Agent orchestration requires an in-progress phase; {phase} is "
            f"{state['phases'][phase]['status']}"
        )
    agents = config["agents"]
    if agents["enabled"] is not True:
        raise LifecycleError("Multi-agent execution is disabled by project configuration")
    if agents["ownership_strategy"] != "exclusive-path":
        raise LifecycleError(
            "The bundled phase orchestrator currently supports only exclusive-path ownership"
        )
    max_parallel = agents["max_parallel"]
    if requested_parallel is not None:
        if not 1 <= requested_parallel <= max_parallel:
            raise LifecycleError(
                f"--max-parallel must be between 1 and configured limit {max_parallel}"
            )
        max_parallel = requested_parallel
    records = load_phase_tasks(root, phase, selected_ids, config, state)
    all_records = dependency_records(root, records)
    validate_acyclic(all_records)
    completed = {
        task_id
        for task_id, record in all_records.items()
        if completion_is_accepted(root, record)
    }
    return config, state, records, all_records, completed, max_parallel


def command_status(args: argparse.Namespace) -> int:
    root = resolve_root(args.project_root)
    _, _, records, all_records, completed, max_parallel = orchestration_context(
        root, args.phase, args.task_id, args.max_parallel
    )
    waves, blocked = build_plan(records, completed, max_parallel)
    print(
        json.dumps(
            {
                "status": "ready" if not blocked else "blocked",
                "phase": args.phase,
                "max_parallel_workers": max_parallel,
                "completed": sorted(set(records) & completed),
                "waves": [
                    [
                        {
                            "task_id": record.task_id,
                            "role": record.document["role"],
                            "writer": record.is_writer,
                        }
                        for record in wave
                    ]
                    for wave in waves
                ],
                "blocked": blocked,
                "dependency_tasks": sorted(set(all_records) - set(records)),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if not blocked else 10


def command_run_phase(args: argparse.Namespace) -> int:
    if not args.execute or not args.authorization_actor or not args.authorization_reason:
        raise LifecycleError(
            "Phase orchestration requires --execute, --authorization-actor, and "
            "--authorization-reason"
        )
    if not args.task_id:
        raise LifecycleError(
            "run-phase requires an explicit --task-id for every active task; "
            "use status first to discover candidates"
        )
    root = resolve_root(args.project_root)
    require_trusted_project(root, "Multi-agent phase orchestration")
    evidence_path = contained_control_path(
        root,
        ".ai-lifecycle/evidence/external/"
        f"orchestration-{args.phase}-{uuid.uuid4().hex}.json",
    )
    started_at = utc_now()
    started_clock = time.monotonic()
    runs: list[dict[str, Any]] = []
    failed: list[str] = []
    blocked_tasks: list[str] = []
    with lifecycle_lock(root, f"orchestration-{args.phase}"):
        _, _, records, _, completed, max_parallel = orchestration_context(
            root, args.phase, args.task_id, args.max_parallel
        )
        pending = set(records) - completed
        while pending:
            wave = select_wave(records, pending, completed, max_parallel)
            if not wave:
                blocked_tasks.extend(sorted(pending))
                break
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(wave), thread_name_prefix="lifecycle-agent"
            ) as executor:
                futures = {
                    executor.submit(
                        invoke_task,
                        root,
                        record,
                        adapter=args.adapter,
                        timeout_seconds=args.timeout_seconds,
                        max_turns=args.max_turns,
                        actor=args.authorization_actor,
                        reason=args.authorization_reason,
                    ): record
                    for record in wave
                }
                for future in concurrent.futures.as_completed(futures):
                    record = futures[future]
                    try:
                        run = future.result()
                    except Exception as exc:  # pragma: no cover - defensive worker boundary
                        run = {
                            "task_id": record.task_id,
                            "role": record.document["role"],
                            "writer": record.is_writer,
                            "started_at": utc_now(),
                            "finished_at": utc_now(),
                            "duration_seconds": 0,
                            "exit_code": 70,
                            "stdout": "",
                            "stderr": "",
                            "error": redact(str(exc)),
                        }
                    runs.append(run)
                    if run["exit_code"] != 0:
                        failed.append(record.task_id)
                        continue
                    try:
                        accepted = completion_is_accepted(root, record)
                    except LifecycleError as exc:
                        run["error"] = redact(str(exc))
                        failed.append(record.task_id)
                        continue
                    if not accepted:
                        run["error"] = "Adapter exited successfully without an accepted completion"
                        failed.append(record.task_id)
                        continue
                    completed.add(record.task_id)
                    pending.remove(record.task_id)
            if failed:
                break
    unresolved = {
        task_id: sorted(set(records[task_id].dependencies) - completed)
        for task_id in sorted(pending)
    }
    status = "succeeded" if not pending and not failed and not blocked_tasks else "blocked"
    evidence = {
        "schema_version": 1,
        "status": status,
        "phase": args.phase,
        "adapter": args.adapter,
        "authorization": {
            "actor": redact(args.authorization_actor),
            "reason": redact(args.authorization_reason),
        },
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_seconds": round(time.monotonic() - started_clock, 3),
        "max_parallel_workers": max_parallel,
        "writers_run_in_isolated_waves": True,
        "selected_tasks": sorted(records),
        "completed_tasks": sorted(set(records) & completed),
        "failed_tasks": sorted(set(failed)),
        "blocked_tasks": sorted(set(blocked_tasks)),
        "unresolved_dependencies": unresolved,
        "runs": runs,
    }
    atomic_create_json(evidence_path, evidence)
    print(
        json.dumps(
            {
                "status": status,
                "phase": args.phase,
                "completed_tasks": evidence["completed_tasks"],
                "failed_tasks": evidence["failed_tasks"],
                "blocked_tasks": evidence["blocked_tasks"],
                "unresolved_dependencies": unresolved,
                "evidence": str(evidence_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if status == "succeeded" else 10


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--project-root", required=True, type=Path)
        command.add_argument("--phase", required=True)
        command.add_argument("--task-id", action="append", default=[])
        command.add_argument("--max-parallel", type=int)

    status = subparsers.add_parser("status")
    common(status)

    run = subparsers.add_parser("run-phase")
    common(run)
    run.add_argument("--adapter", required=True, choices=["codex", "claude-code"])
    run.add_argument("--timeout-seconds", type=int, default=1800)
    run.add_argument("--max-turns", type=int, default=12)
    run.add_argument("--execute", action="store_true")
    run.add_argument("--authorization-actor")
    run.add_argument("--authorization-reason")

    args = parser.parse_args()
    try:
        if args.command == "status":
            return command_status(args)
        if args.command == "run-phase":
            if not 1 <= args.timeout_seconds <= 7200:
                raise LifecycleError("--timeout-seconds must be between 1 and 7200")
            if not 1 <= args.max_turns <= 100:
                raise LifecycleError("--max-turns must be between 1 and 100")
            return command_run_phase(args)
        raise LifecycleError(f"Unsupported command: {args.command}")
    except (
        LifecycleError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2))
        return 2


if __name__ == "__main__":
    sys.exit(main())

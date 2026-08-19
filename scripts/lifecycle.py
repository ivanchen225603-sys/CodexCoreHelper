#!/usr/bin/env python3
"""Advance lifecycle phases, run deterministic gates, and record decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from approval_identity import verify_approval_assertion
from _lifecycle import (
    LifecycleError,
    atomic_write_json,
    contained_control_path,
    contained_path,
    lifecycle_lock,
    lifecycle_dir,
    load_json,
    redact,
    require_trusted_project,
    resolve_root,
    safe_subprocess_environment,
    sha256_file,
    unlock_next,
    utc_now,
    validate_all,
)
from process_runner import ProcessExecutionError, run_bounded_process

MAX_STATE_EVENTS = 1_000
MAX_STATE_APPROVALS = 1_000


def add_event(
    state: dict[str, Any],
    event_type: str,
    phase: str,
    data: dict[str, Any],
) -> None:
    state["events"].append(
        {
            "event_id": f"evt-{uuid.uuid4()}",
            "event_type": event_type,
            "occurred_at": utc_now(),
            "phase": phase,
            "data": data,
        }
    )
    overflow = len(state["events"]) - MAX_STATE_EVENTS
    if overflow > 0:
        del state["events"][:overflow]
        previous = state.get("dropped_event_count", 0)
        if isinstance(previous, bool) or not isinstance(previous, int) or previous < 0:
            previous = 0
        state["dropped_event_count"] = previous + overflow
    state["updated_at"] = utc_now()


def add_approval(state: dict[str, Any], record: dict[str, Any]) -> None:
    approvals = state.get("approvals")
    if not isinstance(approvals, list):
        raise LifecycleError("Lifecycle approvals state is invalid")
    if len(approvals) >= MAX_STATE_APPROVALS:
        raise LifecycleError(
            "Approval history reached its safety limit; archive it through a versioned state migration"
        )
    approvals.append(record)


def phase_predecessors(config: dict[str, Any], phase: str) -> list[str]:
    phases = config["lifecycle"]["phases"]
    if phase not in phases:
        raise LifecycleError(f"Phase is not enabled: {phase}")
    return phases[: phases.index(phase)]


def assert_unlocked(config: dict[str, Any], state: dict[str, Any], phase: str) -> None:
    unapproved = [
        item
        for item in phase_predecessors(config, phase)
        if state["phases"][item]["status"] != "approved"
    ]
    if unapproved:
        raise LifecycleError(
            f"{phase} is locked until predecessors are approved: {', '.join(unapproved)}"
        )


BASELINE_PHASES = {
    "implementation",
    "review",
    "verification",
    "integration",
    "deployment",
    "operations",
}

BASELINE_IGNORED_DIRECTORIES = {
    ".git",
    ".ai-lifecycle",
    ".venv",
    "venv",
    "node_modules",
    "bin",
    "obj",
    "dist",
    "build",
    "target",
    "coverage",
}

LEGACY_PROMOTION_MATRIX = {
    "schema_version": 1,
    "artifact_layout": "legacy-flat",
    "enforce_immutable_digest": True,
    "environments": [
        {
            "name": "production",
            "approval_policy": "human-required",
            "final": True,
        }
    ],
}


def deployment_promotion_policy(config: dict[str, Any]) -> dict[str, Any]:
    """Return a validated promotion policy, with a safe legacy production default."""

    configured = config["lifecycle"].get("promotion_matrix")
    policy = LEGACY_PROMOTION_MATRIX if configured is None else configured
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise LifecycleError("lifecycle.promotion_matrix schema_version must be 1")
    layout = policy.get("artifact_layout")
    if layout not in {"legacy-flat", "environment-subdirectories"}:
        raise LifecycleError("promotion_matrix artifact_layout is invalid")
    if configured is not None and layout != "environment-subdirectories":
        raise LifecycleError(
            "Configured promotion matrices must use environment-subdirectories"
        )
    if policy.get("enforce_immutable_digest") is not True:
        raise LifecycleError(
            "promotion_matrix must enforce one immutable artifact digest"
        )
    environments = policy.get("environments")
    if not isinstance(environments, list) or not environments:
        raise LifecycleError("promotion_matrix environments must be a non-empty array")
    names: list[str] = []
    finals: list[int] = []
    for index, environment in enumerate(environments):
        if not isinstance(environment, dict):
            raise LifecycleError(f"promotion environment {index} must be an object")
        name = environment.get("name")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 64
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789._-"
                for character in name
            )
        ):
            raise LifecycleError(
                f"promotion environment {index} name must be a lowercase portable identifier"
            )
        if name in names:
            raise LifecycleError(f"Duplicate promotion environment: {name}")
        names.append(name)
        if environment.get("approval_policy") not in {
            "human-required",
            "automatic-after-gates",
        }:
            raise LifecycleError(
                f"promotion environment {name} approval_policy is invalid"
            )
        if environment.get("final") is True:
            finals.append(index)
        for key in ("pre_check_ids", "post_check_ids"):
            selected = environment.get(key)
            if selected is not None and (
                not isinstance(selected, list)
                or any(not isinstance(item, str) or not item for item in selected)
                or len(selected) != len(set(selected))
            ):
                raise LifecycleError(f"promotion environment {name} {key} is invalid")
    if finals != [len(environments) - 1]:
        raise LifecycleError("Exactly the last promotion environment must be final")
    if names[-1] != "production":
        raise LifecycleError("Production must be the final promotion environment")
    for environment in environments:
        if (
            environment["name"] == "production"
            and environment["approval_policy"] != "human-required"
        ):
            raise LifecycleError("Production promotion must require human approval")
    return policy


def promotion_policy_digest(policy: dict[str, Any]) -> str:
    encoded = json.dumps(
        policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def ensure_promotion_state(
    config: dict[str, Any], phase_state: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    policy = deployment_promotion_policy(config)
    expected_policy_digest = promotion_policy_digest(policy)
    promotion = phase_state.get("promotion")
    if promotion is None:
        promotion = {
            "policy_digest": expected_policy_digest,
            "artifact_digest": None,
            "completed_environments": [],
            "pending_environment": None,
            "pending_artifact_digest": None,
        }
        phase_state["promotion"] = promotion
    if not isinstance(promotion, dict):
        raise LifecycleError("Deployment promotion state is invalid")
    if promotion.get("policy_digest") != expected_policy_digest:
        raise LifecycleError(
            "Promotion matrix changed after deployment began; reopen deployment through an explicit migration"
        )
    completed = promotion.get("completed_environments")
    if not isinstance(completed, list):
        raise LifecycleError("Deployment completed_environments state is invalid")
    environments = policy["environments"]
    if len(completed) > len(environments):
        raise LifecycleError("Deployment promotion state exceeds the configured matrix")
    for index, item in enumerate(completed):
        if (
            not isinstance(item, dict)
            or item.get("environment") != environments[index]["name"]
        ):
            raise LifecycleError(
                "Completed deployment environments do not match matrix order"
            )
        if (
            not isinstance(item.get("artifact_digest"), str)
            or not item["artifact_digest"]
        ):
            raise LifecycleError(
                "Completed deployment environment has no artifact digest"
            )
    immutable_digest = promotion.get("artifact_digest")
    if immutable_digest is not None and (
        not isinstance(immutable_digest, str) or not immutable_digest
    ):
        raise LifecycleError("Deployment immutable artifact digest state is invalid")
    if completed:
        digests = {item["artifact_digest"] for item in completed}
        if len(digests) != 1 or immutable_digest not in digests:
            raise LifecycleError(
                "Completed promotions do not share the immutable artifact digest"
            )
    return policy, promotion


def next_promotion_environment(
    policy: dict[str, Any], promotion: dict[str, Any], supplied: str | None
) -> tuple[int, dict[str, Any]]:
    index = len(promotion["completed_environments"])
    environments = policy["environments"]
    if index >= len(environments):
        raise LifecycleError(
            "Every configured deployment environment is already complete"
        )
    environment = environments[index]
    if supplied is not None and supplied != environment["name"]:
        raise LifecycleError(
            f"The next promotion environment is {environment['name']}, not {supplied}"
        )
    return index, environment


def deployment_artifact_paths(
    policy: dict[str, Any], gate: dict[str, Any], environment: str, *, post: bool
) -> list[str]:
    configured = gate.get(
        "post_required_artifacts" if post else "required_artifacts", []
    )
    if not isinstance(configured, list) or any(
        not isinstance(item, str) for item in configured
    ):
        raise LifecycleError(
            "Deployment artifact configuration must be an array of paths"
        )
    if policy["artifact_layout"] == "legacy-flat":
        return configured
    return [
        f".ai-lifecycle/artifacts/deployment/{environment}/{Path(item).name}"
        for item in configured
    ]


def deployment_checks(
    gate: dict[str, Any], environment: dict[str, Any], *, post: bool
) -> list[dict[str, Any]]:
    key = "post_checks" if post else "checks"
    checks = gate.get(key, [])
    if not isinstance(checks, list):
        raise LifecycleError(f"Deployment {key} must be an array")
    selector = environment.get("post_check_ids" if post else "pre_check_ids")
    if selector is None:
        return checks
    by_id = {
        check.get("id"): check
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("id"), str)
    }
    unknown = [check_id for check_id in selector if check_id not in by_id]
    if unknown:
        raise LifecycleError(
            f"Promotion environment {environment['name']} references unknown checks: "
            + ", ".join(unknown)
        )
    return [by_id[check_id] for check_id in selector]


def deployment_evidence_directory(
    root: Path, policy: dict[str, Any], environment: str
) -> Path:
    relative = ".ai-lifecycle/evidence/deployment"
    if policy["artifact_layout"] == "environment-subdirectories":
        relative += f"/{environment}"
    return contained_control_path(root, relative)


def deployment_contract_digest(
    policy: dict[str, Any], gate: dict[str, Any], environment: dict[str, Any]
) -> str:
    contract = {
        "policy_digest": promotion_policy_digest(policy),
        "environment": environment,
        "pre_artifacts": deployment_artifact_paths(
            policy, gate, environment["name"], post=False
        ),
        "post_artifacts": deployment_artifact_paths(
            policy, gate, environment["name"], post=True
        ),
        "pre_checks": deployment_checks(gate, environment, post=False),
        "post_checks": deployment_checks(gate, environment, post=True),
    }
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )


def assertion_jti_was_used(state: dict[str, Any], jti: str) -> bool:
    for approval in state.get("approvals", []):
        if not isinstance(approval, dict):
            continue
        identity = approval.get("identity_assertion")
        if isinstance(identity, dict) and identity.get("jti") == jti:
            return True
    return False


def repository_baseline(root: Path, limit: int = 30_000) -> dict[str, Any]:
    environment = safe_subprocess_environment([])
    try:
        commit = run_bounded_process(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            environment=environment,
            timeout_seconds=30,
            max_stdout_bytes=64 * 1024,
            max_stderr_bytes=64 * 1024,
        )
        if commit.returncode == 0:
            commit_id = commit.stdout.strip()
            diff = run_bounded_process(
                ["git", "diff", "--binary", "--no-ext-diff", "HEAD"],
                cwd=root,
                environment=environment,
                timeout_seconds=120,
                max_stdout_bytes=16 * 1024 * 1024,
                max_stderr_bytes=512 * 1024,
            )
            untracked = run_bounded_process(
                ["git", "ls-files", "--others", "--exclude-standard", "-z"],
                cwd=root,
                environment=environment,
                timeout_seconds=60,
                max_stdout_bytes=8 * 1024 * 1024,
                max_stderr_bytes=512 * 1024,
            )
            if diff.returncode != 0 or untracked.returncode != 0:
                raise OSError("Git worktree baseline commands failed")
            digest = hashlib.sha256()
            digest.update(diff.stdout.encode("utf-8", "surrogatepass"))
            untracked_paths = [
                item
                for item in untracked.stdout.split("\0")
                if item
            ]
            included_untracked: list[str] = []
            for relative in sorted(untracked_paths):
                normalized = relative.replace("\\", "/")
                if normalized == ".ai-lifecycle" or normalized.startswith(
                    ".ai-lifecycle/"
                ):
                    continue
                lexical_path = root / normalized
                if lexical_path.is_symlink():
                    raise LifecycleError(
                        f"Repository baseline rejects linked files: {normalized}"
                    )
                path = contained_path(root, normalized, must_exist=True)
                if not path.is_file():
                    continue
                digest.update(normalized.encode("utf-8", "surrogateescape"))
                digest.update(b"\0")
                digest.update(sha256_file(path).encode("ascii"))
                digest.update(b"\n")
                included_untracked.append(normalized)
            return {
                "kind": "git",
                "commit": commit_id,
                "worktree_digest": f"sha256:{digest.hexdigest()}",
                "untracked_files": included_untracked,
            }
    except (FileNotFoundError, OSError, ProcessExecutionError, LifecycleError):
        pass

    digest = hashlib.sha256()
    file_count = 0
    for directory, names, files in os.walk(root):
        names[:] = [name for name in names if name not in BASELINE_IGNORED_DIRECTORIES]
        base = Path(directory)
        for name in names:
            candidate = base / name
            metadata = candidate.lstat()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            attributes = getattr(metadata, "st_file_attributes", 0)
            if candidate.is_symlink() or bool(reparse_flag and attributes & reparse_flag):
                raise LifecycleError(
                    "Repository baseline rejects linked directories: "
                    + str(candidate.relative_to(root)).replace("\\", "/")
                )
        for name in sorted(files):
            path = base / name
            relative = str(path.relative_to(root)).replace("\\", "/")
            metadata = path.lstat()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            attributes = getattr(metadata, "st_file_attributes", 0)
            if path.is_symlink() or bool(reparse_flag and attributes & reparse_flag):
                raise LifecycleError(
                    f"Repository baseline rejects linked files: {relative}"
                )
            digest.update(relative.encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
            digest.update(sha256_file(path).encode("ascii"))
            digest.update(b"\n")
            file_count += 1
            if file_count > limit:
                raise LifecycleError(
                    f"Repository baseline exceeds {limit} files; use Git or a narrower project root"
                )
    return {
        "kind": "filesystem",
        "content_digest": f"sha256:{digest.hexdigest()}",
        "file_count": file_count,
    }


def combined_baseline(
    artifacts: list[dict[str, str]], repository: dict[str, Any] | None
) -> str:
    digest = hashlib.sha256()
    for artifact in sorted(artifacts, key=lambda item: item["path"]):
        digest.update(artifact["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(artifact["digest"].encode("ascii"))
        digest.update(b"\n")
    if repository is not None:
        digest.update(
            json.dumps(
                repository, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
    return f"sha256:{digest.hexdigest()}"


def run_check(root: Path, check: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    started_at = utc_now()
    started_clock = time.monotonic()
    cwd = contained_path(root, check.get("cwd", "."))
    command = check["command"]
    status = "failed"
    exit_code: int | None = None
    output = ""
    infrastructure_error = False
    current_os = (
        "windows"
        if os.name == "nt"
        else "macos"
        if sys.platform == "darwin"
        else "linux"
    )
    operating_systems = check.get("operating_systems")
    if isinstance(operating_systems, list) and current_os not in operating_systems:
        finished_at = utc_now()
        return (
            {
                "id": check["id"],
                "description": check["description"],
                "required": check["required"],
                "command": command,
                "cwd": str(cwd.relative_to(root)).replace("\\", "/") or ".",
                "evidence_type": check.get("evidence_type", "command"),
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_seconds": round(time.monotonic() - started_clock, 3),
                "status": "not_applicable",
                "exit_code": None,
                "output": f"Check applies only to {', '.join(operating_systems)}; current OS is {current_os}.",
            },
            False,
        )
    try:
        require_trusted_project(root, "gate command execution")
        environment = safe_subprocess_environment(check.get("forward_env", []))
        completed = run_bounded_process(
            command,
            cwd=cwd,
            environment=environment,
            timeout_seconds=check.get("timeout_seconds", 1200),
            max_stdout_bytes=8 * 1024 * 1024,
            max_stderr_bytes=2 * 1024 * 1024,
        )
        exit_code = completed.returncode
        status = "passed" if completed.returncode == 0 else "failed"
        output = f"STDOUT\n{completed.stdout}\nSTDERR\n{completed.stderr}"
    except ProcessExecutionError as exc:
        status = "timeout" if "timed out" in str(exc).lower() else "infrastructure_error"
        infrastructure_error = status == "infrastructure_error"
        output = f"STDOUT\n{exc.stdout}\nSTDERR\n{exc.stderr}\n{exc}"
    except (FileNotFoundError, OSError, LifecycleError) as exc:
        status = "infrastructure_error"
        infrastructure_error = True
        output = str(exc)
    return (
        {
            "id": check["id"],
            "description": check.get("description", ""),
            "required": check["required"],
            "command": [redact(item) for item in command],
            "cwd": str(cwd.relative_to(root)).replace("\\", "/") or ".",
            "evidence_type": check.get("evidence_type", "command"),
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started_clock, 3),
            "status": status,
            "exit_code": exit_code,
            "output": redact(output),
        },
        infrastructure_error,
    )


def evidence_name() -> str:
    return datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S.%fZ.json")


def command_status(root: Path) -> int:
    config, registry, state = validate_all(root)
    result = {
        "project_id": config["project"]["id"],
        "lifecycle_run_id": state["lifecycle_run_id"],
        "current_phase": state["current_phase"],
        "phases": {
            phase: details["status"] for phase, details in state["phases"].items()
        },
        "tools": {tool["id"]: tool["availability"] for tool in registry["tools"]},
        "last_event": state["events"][-1] if state["events"] else None,
    }
    deployment = state["phases"].get("deployment")
    if isinstance(deployment, dict) and isinstance(deployment.get("promotion"), dict):
        result["deployment_promotion"] = deployment["promotion"]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def command_start(root: Path, phase: str, baseline: str | None) -> int:
    config, _, state = validate_all(root)
    assert_unlocked(config, state, phase)
    phase_state = state["phases"][phase]
    if phase_state["status"] not in {"ready", "failed", "rejected", "blocked"}:
        raise LifecycleError(
            f"Cannot start {phase} from status {phase_state['status']}"
        )
    phase_state["status"] = "in_progress"
    phase_state["approval_nonce"] = None
    if phase == "deployment":
        phase_state["authorization"] = None
        ensure_promotion_state(config, phase_state)
    if baseline:
        phase_state["baseline"] = baseline
    phase_state["updated_at"] = utc_now()
    state["current_phase"] = phase
    add_event(
        state,
        "phase.started",
        phase,
        {"baseline": phase_state["baseline"]},
    )
    atomic_write_json(lifecycle_dir(root) / "state.json", state)
    print(
        json.dumps(
            {
                "phase": phase,
                "status": "in_progress",
                "baseline": phase_state["baseline"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def validate_artifact_content(phase: str, relative: str, path: Path) -> list[str]:
    """Apply small deterministic contracts so empty placeholders cannot pass gates."""
    errors: list[str] = []
    if path.stat().st_size == 0:
        return [f"{relative}: artifact is empty"]
    document: Any = None
    if path.suffix.lower() == ".json":
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [f"{relative}: invalid JSON: {exc}"]
        if document in ({}, []):
            errors.append(f"{relative}: JSON artifact may not be empty")

    required_fields: dict[str, tuple[str, ...]] = {
        "release-candidate.json": ("artifact_digest", "provenance"),
        "deployment-plan.json": ("environment", "artifact_digest", "steps"),
        "environment-readiness.json": ("environment", "artifact_digest", "checks"),
        "deployment-record.json": (
            "environment",
            "artifact_digest",
            "provider_run_id",
            "authorization_decision_id",
            "status",
        ),
        "post-deployment-verification.json": (
            "environment",
            "artifact_digest",
            "provider_run_id",
            "authorization_decision_id",
            "status",
            "checks",
        ),
    }
    expected = required_fields.get(path.name)
    if expected:
        if not isinstance(document, dict):
            errors.append(f"{relative}: expected a JSON object")
        else:
            missing = [key for key in expected if not document.get(key)]
            if missing:
                errors.append(
                    f"{relative}: missing non-empty fields: {', '.join(missing)}"
                )

    if isinstance(document, dict):
        if path.name == "deployment-plan.json":
            steps = document.get("steps")
            if not isinstance(steps, list) or not steps:
                errors.append(f"{relative}: steps must be a non-empty array")
        if path.name in {
            "environment-readiness.json",
            "post-deployment-verification.json",
        }:
            checks = document.get("checks")
            if not isinstance(checks, list) or not checks:
                errors.append(f"{relative}: checks must be a non-empty array")
            else:
                failed_checks = []
                passing_statuses = {
                    "passed",
                    "succeeded",
                    "success",
                    "completed",
                    "healthy",
                    "ready",
                }
                for index, check in enumerate(checks):
                    passed = check is True
                    if isinstance(check, dict):
                        status = str(check.get("status", "")).lower()
                        passed = (
                            check.get("passed") is True or status in passing_statuses
                        )
                    if not passed:
                        failed_checks.append(index)
                if failed_checks:
                    errors.append(
                        f"{relative}: checks are not passing at indexes: "
                        + ", ".join(str(index) for index in failed_checks)
                    )
        if path.name == "deployment-record.json" and str(
            document.get("status", "")
        ).lower() not in {"succeeded", "success", "completed", "deployed", "healthy"}:
            errors.append(f"{relative}: deployment status is not successful")
        if path.name == "post-deployment-verification.json" and str(
            document.get("status", "")
        ).lower() not in {"passed", "succeeded", "success", "completed", "healthy"}:
            errors.append(f"{relative}: post-deployment status is not successful")

    if (
        phase == "review"
        and path.name == "review-findings.json"
        and document is not None
    ):
        findings = document.get("findings") if isinstance(document, dict) else document
        if not isinstance(findings, list):
            errors.append(f"{relative}: findings must be an array")
        else:
            blocking = [
                item
                for item in findings
                if isinstance(item, dict)
                and str(item.get("severity", "")).lower() in {"critical", "high"}
                and str(item.get("status", "open")).lower()
                not in {"resolved", "closed", "accepted"}
            ]
            if blocking:
                errors.append(
                    f"{relative}: contains {len(blocking)} unresolved critical/high findings"
                )
    return errors


def verify_gate_evidence_is_current(
    root: Path,
    config: dict[str, Any],
    state: dict[str, Any],
    phase: str,
    *,
    evidence_reference: str | None = None,
    expected_baseline: str | None = None,
) -> dict[str, Any]:
    """Recompute a passed gate baseline immediately before recording approval."""
    phase_state = state["phases"][phase]
    evidence_reference = evidence_reference or phase_state.get("last_evidence")
    expected_baseline = expected_baseline or phase_state.get("baseline")
    if not isinstance(evidence_reference, str) or not evidence_reference:
        raise LifecycleError("Approval requires durable gate evidence")
    evidence_path = contained_control_path(root, evidence_reference, must_exist=True)
    expected_directory = (lifecycle_dir(root) / "evidence" / phase).resolve()
    try:
        evidence_path.relative_to(expected_directory)
    except ValueError as exc:
        raise LifecycleError(
            "Gate evidence is outside the canonical phase directory"
        ) from exc
    if not evidence_path.is_file():
        raise LifecycleError("Gate evidence must be a regular file")
    evidence = load_json(evidence_path)
    if not isinstance(evidence, dict):
        raise LifecycleError("Gate evidence must be a JSON object")
    bindings = {
        "project_id": config["project"]["id"],
        "lifecycle_run_id": state["lifecycle_run_id"],
        "phase": phase,
        "overall": "passed",
        "baseline": expected_baseline,
    }
    mismatches = [
        key for key, expected in bindings.items() if evidence.get(key) != expected
    ]
    if mismatches:
        raise LifecycleError(
            "Gate evidence does not match the pending approval: "
            + ", ".join(mismatches)
        )
    declared_artifacts = evidence.get("required_artifacts")
    if not isinstance(declared_artifacts, list):
        raise LifecycleError("Gate evidence required_artifacts must be an array")
    current_artifacts: list[dict[str, str]] = []
    for index, artifact in enumerate(declared_artifacts):
        if not isinstance(artifact, dict):
            raise LifecycleError(f"Gate evidence artifact {index} must be an object")
        relative = artifact.get("path")
        digest = artifact.get("digest")
        if not isinstance(relative, str) or not isinstance(digest, str):
            raise LifecycleError(f"Gate evidence artifact {index} is incomplete")
        path = contained_path(root, relative, must_exist=True)
        if not path.is_file() or sha256_file(path) != digest:
            raise LifecycleError(
                f"Gate artifact changed after verification: {relative}"
            )
        current_artifacts.append({"path": relative, "digest": digest})
    repository = (
        repository_baseline(root)
        if evidence.get("repository_baseline") is not None
        else None
    )
    current_baseline = combined_baseline(current_artifacts, repository)
    if current_baseline != expected_baseline:
        raise LifecycleError(
            "Project or gate artifacts changed after verification; rerun the gate"
        )
    return evidence


def verify_deployment_authorization_binding(
    root: Path,
    evidence: dict[str, Any],
    environment: str,
    artifact_digest: str,
) -> None:
    required_names = {"deployment-plan.json", "environment-readiness.json"}
    matched_names: set[str] = set()
    for artifact in evidence["required_artifacts"]:
        relative = artifact["path"]
        path = contained_path(root, relative, must_exist=True)
        if path.name not in required_names:
            continue
        document = load_json(path)
        if not isinstance(document, dict):
            raise LifecycleError(
                f"Deployment authorization artifact is invalid: {relative}"
            )
        if document.get("environment") != environment:
            raise LifecycleError(
                f"Deployment authorization environment differs from {relative}"
            )
        if document.get("artifact_digest") != artifact_digest:
            raise LifecycleError(
                f"Deployment authorization artifact digest differs from {relative}"
            )
        matched_names.add(path.name)
    if matched_names != required_names:
        raise LifecycleError(
            "Deployment authorization requires verified deployment plan and environment readiness artifacts"
        )


def command_run_gates(
    root: Path,
    phase: str,
    environment: str | None = None,
    artifact_digest: str | None = None,
) -> int:
    config, _, state = validate_all(root)
    assert_unlocked(config, state, phase)
    if phase != "deployment" and (
        environment is not None or artifact_digest is not None
    ):
        raise LifecycleError(
            "--environment and --artifact-digest apply only to the deployment gate"
        )
    phase_state = state["phases"][phase]
    if phase_state["status"] not in {
        "in_progress",
        "technical_pass",
        "failed",
        "blocked",
    }:
        raise LifecycleError(
            f"Cannot run gates for {phase} from status {phase_state['status']}"
        )
    gate = config["quality_gates"].get(phase)
    if not isinstance(gate, dict):
        raise LifecycleError(f"No gate configuration exists for phase: {phase}")
    if phase == "deployment" and {
        ".ai-lifecycle/artifacts/deployment/deployment-record.json",
        ".ai-lifecycle/artifacts/deployment/post-deployment-verification.json",
    }.intersection(gate.get("required_artifacts", [])):
        raise LifecycleError(
            "Unsafe legacy deployment gate: post-deployment artifacts cannot be required "
            "before production authorization"
        )

    promotion_policy: dict[str, Any] | None = None
    promotion: dict[str, Any] | None = None
    promotion_environment: dict[str, Any] | None = None
    resolved_environment: str | None = None
    if phase == "deployment":
        promotion_policy, promotion = ensure_promotion_state(config, phase_state)
        _, promotion_environment = next_promotion_environment(
            promotion_policy, promotion, environment
        )
        resolved_environment = promotion_environment["name"]
        required_artifact_paths = deployment_artifact_paths(
            promotion_policy, gate, resolved_environment, post=False
        )
        checks = deployment_checks(gate, promotion_environment, post=False)
    else:
        required_artifact_paths = gate.get("required_artifacts", [])
        checks = gate.get("checks", [])

    artifacts: list[dict[str, str]] = []
    missing_artifacts: list[str] = []
    artifact_errors: list[str] = []
    deployment_bindings: list[dict[str, Any]] = []
    for relative in required_artifact_paths:
        path = contained_path(root, relative)
        if not path.is_file():
            missing_artifacts.append(relative)
        else:
            artifacts.append({"path": relative, "digest": sha256_file(path)})
            artifact_errors.extend(validate_artifact_content(phase, relative, path))
            if phase == "deployment" and path.name in {
                "deployment-plan.json",
                "environment-readiness.json",
            }:
                try:
                    document = load_json(path)
                except (LifecycleError, OSError, json.JSONDecodeError):
                    document = None
                if isinstance(document, dict):
                    deployment_bindings.append(document)

    resolved_artifact_digest = artifact_digest
    if phase == "deployment":
        assert promotion_policy is not None
        assert promotion is not None
        assert promotion_environment is not None
        bound_environments = {
            item.get("environment")
            for item in deployment_bindings
            if isinstance(item.get("environment"), str)
        }
        bound_digests = {
            item.get("artifact_digest")
            for item in deployment_bindings
            if isinstance(item.get("artifact_digest"), str)
            and item.get("artifact_digest")
        }
        if bound_environments != {resolved_environment}:
            artifact_errors.append(
                "Deployment plan and readiness must bind the next promotion environment"
            )
        if len(bound_digests) != 1:
            artifact_errors.append(
                "Deployment plan and readiness must share one artifact digest"
            )
        else:
            bound_digest = next(iter(bound_digests))
            if resolved_artifact_digest is None:
                resolved_artifact_digest = bound_digest
            elif resolved_artifact_digest != bound_digest:
                artifact_errors.append(
                    "Requested artifact digest differs from deployment plan or readiness"
                )
        if (
            not isinstance(resolved_artifact_digest, str)
            or not resolved_artifact_digest
        ):
            artifact_errors.append("Deployment requires a non-empty artifact digest")
        immutable_digest = promotion.get("artifact_digest")
        if (
            immutable_digest is not None
            and resolved_artifact_digest != immutable_digest
        ):
            artifact_errors.append(
                "Promotion must use the same immutable artifact digest in every environment"
            )
        if promotion_policy["artifact_layout"] == "environment-subdirectories":
            if not isinstance(resolved_artifact_digest, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", resolved_artifact_digest
            ):
                artifact_errors.append(
                    "Configured promotion matrices require a sha256 digest with 64 lowercase hex characters"
                )
            candidate_path = contained_path(
                root,
                ".ai-lifecycle/artifacts/integration/release-candidate.json",
            )
            if not candidate_path.is_file():
                artifact_errors.append(
                    "Promotion requires the integration release-candidate.json artifact"
                )
            else:
                candidate_relative = (
                    ".ai-lifecycle/artifacts/integration/release-candidate.json"
                )
                artifacts.append(
                    {
                        "path": candidate_relative,
                        "digest": sha256_file(candidate_path),
                    }
                )
                artifact_errors.extend(
                    validate_artifact_content(
                        "integration", candidate_relative, candidate_path
                    )
                )
                try:
                    candidate = load_json(candidate_path)
                except (LifecycleError, OSError, json.JSONDecodeError):
                    candidate = None
                if (
                    not isinstance(candidate, dict)
                    or candidate.get("artifact_digest") != resolved_artifact_digest
                ):
                    artifact_errors.append(
                        "Promotion artifact digest differs from the integration release candidate"
                    )

    results: list[dict[str, Any]] = []
    infrastructure_error = False
    for check in checks:
        result, tool_error = run_check(root, check)
        results.append(result)
        infrastructure_error = infrastructure_error or (
            tool_error and result["required"]
        )

    automation_required = (
        config["project"]["risk_level"] in {"standard", "high"}
        and phase
        in {"implementation", "verification", "integration", "deployment", "operations"}
        and not checks
    )
    if automation_required:
        infrastructure_error = True
        results.append(
            {
                "id": "required-automation-not-configured",
                "description": "Risk policy requires at least one deterministic automated check",
                "required": True,
                "command": [],
                "cwd": ".",
                "evidence_type": "policy",
                "started_at": utc_now(),
                "finished_at": utc_now(),
                "duration_seconds": 0,
                "status": "infrastructure_error",
                "exit_code": None,
                "output": "Configure a repository-native or provider-backed required check.",
            }
        )

    required_failed = any(
        item["required"] and item["status"] not in {"passed", "not_applicable"}
        for item in results
    )
    if missing_artifacts or artifact_errors:
        overall = "failed"
    elif infrastructure_error:
        overall = "infrastructure_error"
    elif required_failed:
        overall = "failed"
    else:
        overall = "passed"

    repository = repository_baseline(root) if phase in BASELINE_PHASES else None
    baseline = combined_baseline(artifacts, repository)
    evidence = {
        "schema_version": 1,
        "evidence_id": f"gate-{uuid.uuid4()}",
        "lifecycle_run_id": state["lifecycle_run_id"],
        "project_id": config["project"]["id"],
        "phase": phase,
        "environment": resolved_environment,
        "artifact_digest": resolved_artifact_digest,
        "baseline": baseline,
        "created_at": utc_now(),
        "required_artifacts": artifacts,
        "repository_baseline": repository,
        "missing_artifacts": missing_artifacts,
        "artifact_errors": artifact_errors,
        "checks": results,
        "overall": overall,
    }
    if phase == "deployment":
        assert promotion_policy is not None
        assert promotion_environment is not None
        evidence["promotion_policy_digest"] = promotion_policy_digest(promotion_policy)
        evidence["deployment_contract_digest"] = deployment_contract_digest(
            promotion_policy, gate, promotion_environment
        )
    if phase == "deployment":
        assert promotion_policy is not None
        assert resolved_environment is not None
        evidence_directory = deployment_evidence_directory(
            root, promotion_policy, resolved_environment
        )
    else:
        evidence_directory = contained_control_path(
            root, f".ai-lifecycle/evidence/{phase}"
        )
    evidence_directory.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_directory / evidence_name()
    atomic_write_json(evidence_path, evidence)
    evidence_relative = str(evidence_path.relative_to(root)).replace("\\", "/")

    phase_state["baseline"] = baseline
    phase_state["last_evidence"] = evidence_relative
    phase_state["updated_at"] = utc_now()

    approval_required = phase in config["lifecycle"]["human_approvals"]
    if phase == "deployment":
        assert promotion_environment is not None
        approval_required = promotion_environment["approval_policy"] == "human-required"

    if phase == "deployment":
        phase_state["authorization"] = None
        assert promotion is not None
        promotion["pending_environment"] = None
        promotion["pending_artifact_digest"] = None

    if overall == "passed":
        if approval_required:
            phase_state["status"] = "technical_pass"
            phase_state["approval_nonce"] = f"approval-{uuid.uuid4()}"
            if phase == "deployment":
                assert promotion is not None
                promotion["pending_environment"] = resolved_environment
                promotion["pending_artifact_digest"] = resolved_artifact_digest
            event_type = "gate.passed"
        elif phase == "deployment":
            assert promotion is not None
            assert resolved_environment is not None
            assert isinstance(resolved_artifact_digest, str)
            if promotion["artifact_digest"] is None:
                promotion["artifact_digest"] = resolved_artifact_digest
            decision_id = f"decision-{uuid.uuid4()}"
            recorded_at = utc_now()
            record = {
                "decision_id": decision_id,
                "phase": phase,
                "decision": "auto-authorized",
                "actor": "state-machine",
                "actor_type": "state-machine",
                "reason": "Environment policy authorizes promotion after deterministic gates",
                "baseline": baseline,
                "evidence": evidence_relative,
                "recorded_at": recorded_at,
                "environment": resolved_environment,
                "artifact_digest": resolved_artifact_digest,
            }
            add_approval(state, record)
            phase_state["status"] = "authorized"
            phase_state["approval_nonce"] = None
            phase_state["authorization"] = {
                "decision_id": decision_id,
                "environment": resolved_environment,
                "artifact_digest": resolved_artifact_digest,
                "baseline": baseline,
                "gate_evidence": evidence_relative,
                "authorized_at": recorded_at,
                "actor": "state-machine",
                "promotion_policy_digest": evidence["promotion_policy_digest"],
                "deployment_contract_digest": evidence["deployment_contract_digest"],
            }
            state["current_phase"] = phase
            event_type = "gate.passed"
            add_event(state, "approval.recorded", phase, record)
        else:
            phase_state["status"] = "approved"
            event_type = "gate.passed"
            add_event(
                state,
                "approval.recorded",
                phase,
                {
                    "decision": "auto-approved",
                    "actor_type": "state-machine",
                    "baseline": baseline,
                },
            )
            unlock_next(config, state, phase)
    elif overall == "infrastructure_error":
        phase_state["status"] = "blocked"
        event_type = "gate.blocked"
    else:
        phase_state["status"] = "failed"
        event_type = "gate.failed"

    add_event(
        state,
        event_type,
        phase,
        {
            "overall": overall,
            "baseline": baseline,
            "evidence": evidence_relative,
            "missing_artifacts": missing_artifacts,
            "artifact_errors": artifact_errors,
            "environment": resolved_environment,
            "artifact_digest": resolved_artifact_digest,
        },
    )
    atomic_write_json(lifecycle_dir(root) / "state.json", state)
    summary = {
        "phase": phase,
        "status": phase_state["status"],
        "overall": overall,
        "baseline": baseline,
        "evidence": evidence_relative,
        "missing_artifacts": missing_artifacts,
        "artifact_errors": artifact_errors,
        "checks": [
            {
                "id": item["id"],
                "status": item["status"],
                "required": item["required"],
            }
            for item in results
        ],
        "environment": resolved_environment,
        "artifact_digest": resolved_artifact_digest,
        "approval_required": approval_required,
        "approval_nonce": phase_state.get("approval_nonce"),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if overall == "passed" else 1


def command_decide(
    root: Path,
    phase: str,
    decision: str,
    actor: str | None,
    actor_type: str | None,
    reason: str,
    baseline: str,
    approval_nonce: str,
    environment: str | None,
    artifact_digest: str | None,
    approval_assertion_file: Path | None,
) -> int:
    config, _, state = validate_all(root)
    phase_state = state["phases"].get(phase)
    if phase_state is None:
        raise LifecycleError(f"Phase is not enabled: {phase}")
    if phase_state["status"] != "technical_pass":
        raise LifecycleError(
            f"A decision requires technical_pass status; {phase} is {phase_state['status']}"
        )
    approval_required = phase in config["lifecycle"]["human_approvals"]
    if not reason.strip():
        raise LifecycleError("Decision reason must be non-empty")
    if baseline != phase_state.get("baseline"):
        raise LifecycleError(
            "Decision baseline does not match the current technical gate"
        )
    if approval_nonce != phase_state.get("approval_nonce"):
        raise LifecycleError("Approval nonce is missing, stale, or already consumed")
    promotion: dict[str, Any] | None = None
    if phase == "deployment":
        policy, promotion = ensure_promotion_state(config, phase_state)
        _, pending_environment = next_promotion_environment(
            policy, promotion, environment
        )
        approval_required = pending_environment["approval_policy"] == "human-required"
        if not approval_required:
            raise LifecycleError(
                "This environment is authorized automatically after its deterministic gates"
            )
        if not environment or not artifact_digest:
            raise LifecycleError(
                "Deployment decisions require --environment and --artifact-digest"
            )
        if promotion.get("pending_environment") != environment:
            raise LifecycleError(
                "Decision environment does not match the pending deployment gate"
            )
        if promotion.get("pending_artifact_digest") != artifact_digest:
            raise LifecycleError(
                "Decision artifact digest does not match the pending deployment gate"
            )
        immutable_digest = promotion.get("artifact_digest")
        if immutable_digest is not None and immutable_digest != artifact_digest:
            raise LifecycleError(
                "Decision would change the immutable promotion artifact"
            )
    elif environment is not None or artifact_digest is not None:
        raise LifecycleError(
            "Environment and artifact digest are only valid for deployment decisions"
        )
    if not approval_required:
        raise LifecycleError(f"{phase} does not have a pending human approval")
    if actor_type is not None and actor_type != "human":
        raise LifecycleError(
            f"{phase} requires a cryptographically verified human decision"
        )

    expected_claims = {
        "project_id": config["project"]["id"],
        "lifecycle_run_id": state["lifecycle_run_id"],
        "phase": phase,
        "decision": decision,
        "reason": reason,
        "baseline": baseline,
        "approval_nonce": approval_nonce,
        "environment": environment,
        "artifact_digest": artifact_digest,
    }
    identity = verify_approval_assertion(root, approval_assertion_file, expected_claims)
    if actor is not None and actor != identity["subject"]:
        raise LifecycleError("--actor does not match the signed approval subject")
    if assertion_jti_was_used(state, identity["jti"]):
        raise LifecycleError("Approval assertion jti has already been used")
    if decision == "approve":
        evidence = verify_gate_evidence_is_current(root, config, state, phase)
        if phase == "deployment":
            assert promotion is not None
            policy = deployment_promotion_policy(config)
            _, pending_environment = next_promotion_environment(
                policy, promotion, environment
            )
            gate = config["quality_gates"].get("deployment", {})
            expected_contract = deployment_contract_digest(
                policy, gate, pending_environment
            )
            if (
                evidence.get("promotion_policy_digest")
                != promotion_policy_digest(policy)
                or evidence.get("deployment_contract_digest") != expected_contract
            ):
                raise LifecycleError(
                    "Deployment promotion policy or gate contract changed; rerun the gate"
                )
            verify_deployment_authorization_binding(
                root, evidence, environment or "", artifact_digest or ""
            )

    record = {
        "decision_id": f"decision-{uuid.uuid4()}",
        "phase": phase,
        "decision": decision,
        "actor": identity["subject"],
        "actor_type": "human",
        "identity_assertion": identity,
        "reason": reason,
        "baseline": phase_state["baseline"],
        "evidence": phase_state["last_evidence"],
        "recorded_at": utc_now(),
        "environment": environment,
        "artifact_digest": artifact_digest,
    }
    add_approval(state, record)
    phase_state["approval_nonce"] = None
    if decision == "approve":
        if phase == "deployment":
            assert promotion is not None
            if promotion["artifact_digest"] is None:
                promotion["artifact_digest"] = artifact_digest
            phase_state["status"] = "authorized"
            phase_state["authorization"] = {
                "decision_id": record["decision_id"],
                "environment": environment,
                "artifact_digest": artifact_digest,
                "baseline": phase_state["baseline"],
                "gate_evidence": phase_state["last_evidence"],
                "authorized_at": record["recorded_at"],
                "actor": identity["subject"],
                "identity_assertion_jti": identity["jti"],
                "promotion_policy_digest": evidence["promotion_policy_digest"],
                "deployment_contract_digest": evidence["deployment_contract_digest"],
            }
            state["current_phase"] = phase
        else:
            phase_state["status"] = "approved"
            unlock_next(config, state, phase)
    else:
        phase_state["status"] = "rejected"
        state["current_phase"] = phase
    phase_state["updated_at"] = utc_now()
    add_event(state, "approval.recorded", phase, record)
    atomic_write_json(lifecycle_dir(root) / "state.json", state)
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return 0


def command_create_approval_request(
    root: Path,
    phase: str,
    decision: str,
    reason: str,
    issuer: str,
    subject: str,
    key_id: str,
    environment: str | None,
    artifact_digest: str | None,
    lifetime_seconds: int,
) -> int:
    """Emit exact short-lived claims for a trusted host approval signer."""

    config, _, state = validate_all(root)
    phase_state = state["phases"].get(phase)
    if (
        not isinstance(phase_state, dict)
        or phase_state.get("status") != "technical_pass"
    ):
        raise LifecycleError("Approval requests require a technical_pass phase")
    if (
        not reason.strip()
        or not issuer.strip()
        or not subject.strip()
        or not key_id.strip()
    ):
        raise LifecycleError("Reason, issuer, subject, and key ID must be non-empty")
    if lifetime_seconds < 30 or lifetime_seconds > 600:
        raise LifecycleError(
            "Approval request lifetime must be between 30 and 600 seconds"
        )
    approval_required = phase in config["lifecycle"]["human_approvals"]
    if phase == "deployment":
        policy, promotion = ensure_promotion_state(config, phase_state)
        _, target = next_promotion_environment(policy, promotion, environment)
        approval_required = target["approval_policy"] == "human-required"
        pending_environment = promotion.get("pending_environment")
        pending_digest = promotion.get("pending_artifact_digest")
        if environment is None:
            environment = pending_environment
        if artifact_digest is None:
            artifact_digest = pending_digest
        if environment != pending_environment or artifact_digest != pending_digest:
            raise LifecycleError(
                "Approval request must match the pending deployment environment and digest"
            )
    elif environment is not None or artifact_digest is not None:
        raise LifecycleError(
            "Environment and artifact digest apply only to deployment approval requests"
        )
    if not approval_required:
        raise LifecycleError(f"{phase} does not require a human approval")
    baseline = phase_state.get("baseline")
    nonce = phase_state.get("approval_nonce")
    if not isinstance(baseline, str) or not isinstance(nonce, str):
        raise LifecycleError("The pending approval baseline or nonce is missing")
    now = int(time.time())
    request = {
        "protected": {
            "alg": "EdDSA",
            "kid": key_id,
            "typ": "ai-lifecycle-approval+jws",
        },
        "claims": {
            "iss": issuer,
            "sub": subject,
            "aud": "software-lifecycle-orchestrator",
            "jti": f"approval-assertion-{uuid.uuid4()}",
            "iat": now,
            "nbf": now,
            "exp": now + lifetime_seconds,
            "project_id": config["project"]["id"],
            "lifecycle_run_id": state["lifecycle_run_id"],
            "phase": phase,
            "decision": decision,
            "reason": reason,
            "baseline": baseline,
            "approval_nonce": nonce,
            "environment": environment,
            "artifact_digest": artifact_digest,
        },
        "signature": None,
    }
    print(json.dumps(request, ensure_ascii=False, indent=2))
    return 0


def command_complete_deployment(
    root: Path, environment: str, artifact_digest: str
) -> int:
    config, _, state = validate_all(root)
    phase = "deployment"
    if phase not in state["phases"]:
        raise LifecycleError("Deployment phase is not enabled")
    phase_state = state["phases"][phase]
    policy, promotion = ensure_promotion_state(config, phase_state)
    environment_index, environment_policy = next_promotion_environment(
        policy, promotion, environment
    )
    if promotion.get("artifact_digest") != artifact_digest:
        raise LifecycleError(
            "Post-deployment verification must use the immutable promotion artifact digest"
        )
    if phase_state["status"] not in {"authorized", "failed", "blocked"}:
        raise LifecycleError(
            f"Post-deployment verification requires authorized status; deployment is {phase_state['status']}"
        )
    authorization = phase_state.get("authorization")
    if not isinstance(authorization, dict):
        raise LifecycleError("Deployment authorization is missing")
    if authorization.get("environment") != environment:
        raise LifecycleError("Deployment environment does not match the authorization")
    if authorization.get("artifact_digest") != artifact_digest:
        raise LifecycleError(
            "Deployment artifact digest does not match the authorization"
        )
    gate = config["quality_gates"].get(phase, {})
    if not isinstance(gate, dict):
        raise LifecycleError("Deployment gate configuration is invalid")
    if authorization.get("promotion_policy_digest") != promotion_policy_digest(
        policy
    ) or authorization.get("deployment_contract_digest") != deployment_contract_digest(
        policy, gate, environment_policy
    ):
        raise LifecycleError(
            "Deployment promotion policy or gate contract changed after authorization"
        )
    authorization_baseline = authorization.get("baseline")
    authorization_evidence = authorization.get("gate_evidence")
    if not isinstance(authorization_baseline, str) or not isinstance(
        authorization_evidence, str
    ):
        raise LifecycleError(
            "Deployment authorization is missing its verified gate binding"
        )
    verify_gate_evidence_is_current(
        root,
        config,
        state,
        phase,
        evidence_reference=authorization_evidence,
        expected_baseline=authorization_baseline,
    )

    required_paths = deployment_artifact_paths(policy, gate, environment, post=True)
    checks = deployment_checks(gate, environment_policy, post=True)
    artifacts: list[dict[str, str]] = []
    missing_artifacts: list[str] = []
    artifact_errors: list[str] = []
    provider_run_ids: set[str] = set()
    deployment_record: dict[str, Any] | None = None
    for relative in required_paths:
        path = contained_path(root, relative)
        if not path.is_file():
            missing_artifacts.append(relative)
            continue
        artifacts.append({"path": relative, "digest": sha256_file(path)})
        artifact_errors.extend(validate_artifact_content(phase, relative, path))
        if path.suffix.lower() == ".json":
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(document, dict):
                if path.name == "deployment-record.json":
                    deployment_record = document
                if document.get("environment") != environment:
                    artifact_errors.append(
                        f"{relative}: environment differs from authorization"
                    )
                if document.get("artifact_digest") != artifact_digest:
                    artifact_errors.append(
                        f"{relative}: artifact digest differs from authorization"
                    )
                if document.get("authorization_decision_id") != authorization.get(
                    "decision_id"
                ):
                    artifact_errors.append(
                        f"{relative}: authorization decision differs from authorization"
                    )
                provider_run_id = document.get("provider_run_id")
                if isinstance(provider_run_id, str) and provider_run_id:
                    provider_run_ids.add(provider_run_id)
    if len(provider_run_ids) != 1:
        artifact_errors.append(
            "Deployment record and post-deployment verification must share one provider_run_id"
        )
    final_environment = environment_policy.get("final") is True
    if final_environment and environment == "production":
        receipt = (
            deployment_record.get("provider_receipt")
            if isinstance(deployment_record, dict)
            else None
        )
        if not isinstance(receipt, dict):
            artifact_errors.append(
                "Production deployment record requires a verifiable provider_receipt"
            )
        else:
            required_receipt_fields = ("provider", "run_id", "receipt_id", "digest")
            missing_receipt = [
                field for field in required_receipt_fields if not receipt.get(field)
            ]
            if missing_receipt:
                artifact_errors.append(
                    "Production provider_receipt is missing: "
                    + ", ".join(missing_receipt)
                )
            if provider_run_ids and receipt.get("run_id") not in provider_run_ids:
                artifact_errors.append(
                    "Production provider_receipt run_id differs from deployment evidence"
                )
            receipt_digest = receipt.get("digest")
            if not isinstance(receipt_digest, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", receipt_digest
            ):
                artifact_errors.append(
                    "Production provider_receipt digest must be sha256 with 64 lowercase hex characters"
                )

    results: list[dict[str, Any]] = []
    infrastructure_error = False
    for check in checks:
        result, tool_error = run_check(root, check)
        results.append(result)
        infrastructure_error = infrastructure_error or (
            tool_error and result["required"]
        )
    receipt_check_passed = any(
        result.get("required") is True
        and result.get("status") == "passed"
        and result.get("evidence_type")
        in {"deployment-receipt", "provider-receipt", "attestation"}
        for result in results
    )
    if (
        final_environment
        and environment == "production"
        and not receipt_check_passed
    ):
        infrastructure_error = True
        results.append(
            {
                "id": "production-receipt-verification-not-configured",
                "description": "Production requires a provider-backed receipt verification check",
                "required": True,
                "command": [],
                "cwd": ".",
                "evidence_type": "provider-receipt",
                "started_at": utc_now(),
                "finished_at": utc_now(),
                "duration_seconds": 0,
                "status": "infrastructure_error",
                "exit_code": None,
                "output": "Configure a required provider receipt or attestation verification command.",
            }
        )
    elif config["project"]["risk_level"] in {"standard", "high"} and not any(
        result.get("status") != "not_applicable" for result in results
    ):
        infrastructure_error = True
        results.append(
            {
                "id": "post-deployment-automation-not-configured",
                "description": "Risk policy requires an automated post-deployment check",
                "required": True,
                "command": [],
                "cwd": ".",
                "evidence_type": "policy",
                "started_at": utc_now(),
                "finished_at": utc_now(),
                "duration_seconds": 0,
                "status": "infrastructure_error",
                "exit_code": None,
                "output": "Configure health, smoke, or synthetic verification.",
            }
        )
    required_failed = any(
        item["required"] and item["status"] not in {"passed", "not_applicable"}
        for item in results
    )
    if missing_artifacts or artifact_errors:
        overall = "failed"
    elif infrastructure_error:
        overall = "infrastructure_error"
    elif required_failed:
        overall = "failed"
    else:
        overall = "passed"

    repository = repository_baseline(root)
    baseline = combined_baseline(artifacts, repository)
    evidence = {
        "schema_version": 1,
        "evidence_id": f"gate-{uuid.uuid4()}",
        "lifecycle_run_id": state["lifecycle_run_id"],
        "project_id": config["project"]["id"],
        "phase": phase,
        "stage": "post-deployment",
        "environment": environment,
        "artifact_digest": artifact_digest,
        "authorization": authorization,
        "baseline": baseline,
        "created_at": utc_now(),
        "required_artifacts": artifacts,
        "repository_baseline": repository,
        "missing_artifacts": missing_artifacts,
        "artifact_errors": artifact_errors,
        "checks": results,
        "overall": overall,
    }
    evidence_directory = deployment_evidence_directory(root, policy, environment)
    evidence_directory.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_directory / evidence_name()
    atomic_write_json(evidence_path, evidence)
    evidence_relative = str(evidence_path.relative_to(root)).replace("\\", "/")
    phase_state["last_evidence"] = evidence_relative
    phase_state["updated_at"] = utc_now()
    if overall == "passed":
        provider_run_id = next(iter(provider_run_ids))
        promotion["completed_environments"].append(
            {
                "environment": environment,
                "artifact_digest": artifact_digest,
                "authorization_decision_id": authorization["decision_id"],
                "provider_run_id": provider_run_id,
                "evidence": evidence_relative,
                "completed_at": utc_now(),
            }
        )
        promotion["pending_environment"] = None
        promotion["pending_artifact_digest"] = None
        phase_state["authorization"] = None
        if final_environment:
            phase_state["status"] = "approved"
            unlock_next(config, state, phase)
        else:
            if environment_index + 1 >= len(policy["environments"]):
                raise LifecycleError(
                    "Non-final environment cannot be the end of the promotion matrix"
                )
            phase_state["status"] = "in_progress"
            phase_state["baseline"] = None
            phase_state["approval_nonce"] = None
            state["current_phase"] = phase
        event_type = "deployment.completed"
    elif overall == "infrastructure_error":
        phase_state["status"] = "blocked"
        state["current_phase"] = phase
        event_type = "gate.blocked"
    else:
        phase_state["status"] = "failed"
        state["current_phase"] = phase
        event_type = "deployment.failed"
    add_event(
        state,
        event_type,
        phase,
        {
            "overall": overall,
            "evidence": evidence_relative,
            "environment": environment,
            "artifact_digest": artifact_digest,
            "final_environment": final_environment,
        },
    )
    atomic_write_json(lifecycle_dir(root) / "state.json", state)
    next_environment = None
    if overall == "passed" and not final_environment:
        next_environment = policy["environments"][environment_index + 1]["name"]
    print(
        json.dumps(
            {
                "phase": phase,
                "status": phase_state["status"],
                "overall": overall,
                "environment": environment,
                "artifact_digest": artifact_digest,
                "evidence": evidence_relative,
                "next_environment": next_environment,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if overall == "passed" else 1


def command_block(root: Path, phase: str, category: str, reason: str) -> int:
    config, _, state = validate_all(root)
    assert_unlocked(config, state, phase)
    phase_state = state["phases"][phase]
    if phase_state["status"] not in {
        "ready",
        "in_progress",
        "failed",
        "blocked",
        "rejected",
        "technical_pass",
        "authorized",
    }:
        raise LifecycleError(
            f"Cannot block {phase} from status {phase_state['status']}"
        )
    phase_state["status"] = "blocked"
    if phase == "deployment":
        # A manual/policy block revokes any outstanding permission to deploy.
        # Post-check infrastructure failures retain authorization in their own path
        # so the same immutable deployment can be verified again.
        phase_state["authorization"] = None
    phase_state["updated_at"] = utc_now()
    state["current_phase"] = phase
    add_event(
        state,
        "phase.blocked",
        phase,
        {"category": category, "reason": reason},
    )
    atomic_write_json(lifecycle_dir(root) / "state.json", state)
    print(
        json.dumps(
            {
                "phase": phase,
                "status": "blocked",
                "category": category,
                "reason": reason,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_reopen(root: Path, phase: str, actor: str, reason: str) -> int:
    config, _, state = validate_all(root)
    phases = config["lifecycle"]["phases"]
    if phase not in phases:
        raise LifecycleError(f"Phase is not enabled: {phase}")
    if not actor.strip() or not reason.strip():
        raise LifecycleError("Actor and reason must be non-empty")
    index = phases.index(phase)
    invalidated: list[str] = []
    for current_index, current_phase in enumerate(phases[index:], start=index):
        details = state["phases"][current_phase]
        if details["status"] != "locked" or current_phase == phase:
            invalidated.append(current_phase)
        details["status"] = "ready" if current_index == index else "locked"
        details["baseline"] = None
        details["last_evidence"] = None
        details["approval_nonce"] = None
        details["authorization"] = None
        if current_phase == "deployment":
            details["promotion"] = None
        details["updated_at"] = utc_now()
    state["current_phase"] = phase
    add_event(
        state,
        "phase.reopened",
        phase,
        {
            "actor": actor,
            "reason": reason,
            "invalidated_phases": invalidated,
        },
    )
    atomic_write_json(lifecycle_dir(root) / "state.json", state)
    print(
        json.dumps(
            {
                "phase": phase,
                "status": "ready",
                "invalidated_phases": invalidated,
                "reason": reason,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status")

    start = subparsers.add_parser("start")
    start.add_argument("--phase", required=True)
    start.add_argument("--baseline")

    gates = subparsers.add_parser("run-gates")
    gates.add_argument("--phase", required=True)
    gates.add_argument("--environment")
    gates.add_argument("--artifact-digest")

    decide = subparsers.add_parser("decide")
    decide.add_argument("--phase", required=True)
    decide.add_argument("--decision", required=True, choices=["approve", "reject"])
    decide.add_argument("--actor")
    decide.add_argument("--actor-type", choices=["human", "service"])
    decide.add_argument("--reason", required=True)
    decide.add_argument("--baseline", required=True)
    decide.add_argument("--approval-nonce", required=True)
    decide.add_argument("--environment")
    decide.add_argument("--artifact-digest")
    decide.add_argument("--approval-assertion-file", type=Path)

    approval_request = subparsers.add_parser("create-approval-request")
    approval_request.add_argument("--phase", required=True)
    approval_request.add_argument(
        "--decision", required=True, choices=["approve", "reject"]
    )
    approval_request.add_argument("--reason", required=True)
    approval_request.add_argument("--issuer", required=True)
    approval_request.add_argument("--subject", required=True)
    approval_request.add_argument("--key-id", required=True)
    approval_request.add_argument("--environment")
    approval_request.add_argument("--artifact-digest")
    approval_request.add_argument("--lifetime-seconds", type=int, default=300)

    complete_deployment = subparsers.add_parser("complete-deployment")
    complete_deployment.add_argument("--environment", required=True)
    complete_deployment.add_argument("--artifact-digest", required=True)

    block = subparsers.add_parser("block")
    block.add_argument("--phase", required=True)
    block.add_argument(
        "--category",
        required=True,
        choices=[
            "specification",
            "dependency",
            "authentication",
            "permission",
            "infrastructure",
            "provider",
            "policy",
            "quality",
        ],
    )
    block.add_argument("--reason", required=True)

    reopen = subparsers.add_parser("reopen")
    reopen.add_argument("--phase", required=True)
    reopen.add_argument("--actor", required=True)
    reopen.add_argument("--reason", required=True)

    args = parser.parse_args()
    try:
        root = resolve_root(args.project_root)
        if args.command == "status":
            return command_status(root)
        with lifecycle_lock(root, "state"):
            if args.command == "start":
                return command_start(root, args.phase, args.baseline)
            if args.command == "run-gates":
                return command_run_gates(
                    root, args.phase, args.environment, args.artifact_digest
                )
            if args.command == "decide":
                return command_decide(
                    root,
                    args.phase,
                    args.decision,
                    args.actor,
                    args.actor_type,
                    args.reason,
                    args.baseline,
                    args.approval_nonce,
                    args.environment,
                    args.artifact_digest,
                    args.approval_assertion_file,
                )
            if args.command == "create-approval-request":
                return command_create_approval_request(
                    root,
                    args.phase,
                    args.decision,
                    args.reason,
                    args.issuer,
                    args.subject,
                    args.key_id,
                    args.environment,
                    args.artifact_digest,
                    args.lifetime_seconds,
                )
            if args.command == "complete-deployment":
                return command_complete_deployment(
                    root, args.environment, args.artifact_digest
                )
            if args.command == "block":
                return command_block(root, args.phase, args.category, args.reason)
            if args.command == "reopen":
                return command_reopen(root, args.phase, args.actor, args.reason)
        raise LifecycleError(f"Unsupported command: {args.command}")
    except (LifecycleError, OSError, KeyError, TypeError) as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

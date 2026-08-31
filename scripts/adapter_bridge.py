#!/usr/bin/env python3
"""Create canonical tasks, call configured HTTP adapters, and verify webhooks."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import re
import stat
import sys
import time
import uuid
from functools import lru_cache
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib import error, parse, request

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema.exceptions import SchemaError, ValidationError
except ImportError:  # Validation must fail closed when the optional runtime is absent.
    Draft202012Validator = None  # type: ignore[assignment]
    FormatChecker = None  # type: ignore[assignment]
    SchemaError = Exception  # type: ignore[assignment,misc]
    ValidationError = Exception  # type: ignore[assignment,misc]

from _lifecycle import (
    LifecycleError,
    atomic_create_json,
    atomic_write_json,
    contained_control_path,
    contained_path,
    lifecycle_lock,
    load_json,
    redact,
    redact_json_value,
    require_trusted_project,
    resolve_root,
    sha256_file,
    utc_now,
    validate_all,
    validate_identifier,
)

SCHEMA_FILES = {
    "task": "task-envelope.schema.json",
    "result": "result-envelope.schema.json",
    "event": "event-envelope.schema.json",
}
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
HTTP_ACCEPTED_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["run_id", "accepted_at", "status_url"],
    "properties": {
        "run_id": {
            "type": "string",
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        },
        "accepted_at": {"type": "string", "format": "date-time"},
        "status_url": {"type": "string", "format": "uri"},
        "cancel_url": {"type": ["string", "null"], "format": "uri"},
    },
}
MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024
MAX_WEBHOOK_BODY_BYTES = 2 * 1024 * 1024
MAX_REPLAY_ENTRIES = 100_000
MUTATING_SIDE_EFFECTS = {
    "external-write",
    "remote-write",
    "deploy",
    "deployment",
    "infrastructure-apply",
    "source-control-write",
    "message-send",
    "production-change",
}
NON_MUTATING_SIDE_EFFECTS = {
    "none",
    "external-read",
    "job-trigger",
    "network",
    "workspace-write",
}


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a JSON object")
    return value


def _schema_directory() -> Path:
    return Path(__file__).resolve().parent.parent / "references" / "schemas"


@lru_cache(maxsize=len(SCHEMA_FILES))
def _envelope_validator(kind: str) -> Any:
    if Draft202012Validator is None or FormatChecker is None:
        raise LifecycleError(
            "Envelope validation requires the 'jsonschema' package; refusing to continue"
        )
    schema = load_json(_schema_directory() / SCHEMA_FILES[kind])
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise LifecycleError(f"Invalid bundled {kind} envelope schema: {exc.message}") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validation_location(error_value: Any) -> str:
    parts = [str(item) for item in error_value.absolute_path]
    return ".".join(parts) if parts else "$"


def validate_against_schema(label: str, value: Any, schema: dict[str, Any]) -> dict[str, Any]:
    document = require_object(value, label)
    if Draft202012Validator is None or FormatChecker is None:
        raise LifecycleError(
            "Envelope validation requires the 'jsonschema' package; refusing to continue"
        )
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    except (SchemaError, ValidationError) as exc:
        location = _validation_location(exc) if isinstance(exc, ValidationError) else "$"
        message = getattr(exc, "message", str(exc))
        raise LifecycleError(f"{label} failed schema validation at {location}: {message}") from exc
    return document


def validate_envelope(kind: str, value: Any) -> dict[str, Any]:
    if kind not in SCHEMA_FILES:
        raise LifecycleError(f"Unsupported envelope kind: {kind}")
    document = require_object(value, kind)
    try:
        _envelope_validator(kind).validate(document)
    except ValidationError as exc:
        raise LifecycleError(
            f"{kind} envelope failed schema validation at "
            f"{_validation_location(exc)}: {exc.message}"
        ) from exc
    if kind == "task":
        created = parse_timestamp(document["created_at"], "task created_at")
        expires = parse_timestamp(document["expires_at"], "task expires_at")
        if expires <= created:
            raise LifecycleError("task expires_at must be later than created_at")
    elif kind == "result":
        started = parse_timestamp(document["started_at"], "result started_at")
        finished = parse_timestamp(document["finished_at"], "result finished_at")
        if finished < started:
            raise LifecycleError("result finished_at cannot be earlier than started_at")
    elif kind == "event":
        parse_timestamp(document["occurred_at"], "event occurred_at")
    return document


def validate_scope(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if not value or path.is_absolute() or ".." in path.parts:
        raise LifecycleError(f"Scope must be a relative non-traversing path or glob: {value}")
    return str(path)


def parse_timestamp(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value
    ):
        raise LifecycleError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed_value = datetime.fromisoformat(value[:-1] + "+00:00")
    except (AttributeError, ValueError) as exc:
        raise LifecycleError(f"{label} must be an RFC 3339 timestamp") from exc
    return parsed_value.astimezone(timezone.utc)


def validate_task_context(
    root: Path,
    config: dict[str, Any],
    state: dict[str, Any],
    task: dict[str, Any],
    *,
    task_path: Path | None = None,
) -> Path:
    task_id = validate_identifier(task.get("task_id"), "task_id", min_length=8)
    validate_identifier(task.get("correlation_id"), "correlation_id", min_length=8)
    if task.get("project_id") != config["project"]["id"]:
        raise LifecycleError("Task project_id does not match the current project")
    if task.get("lifecycle_run_id") != state["lifecycle_run_id"]:
        raise LifecycleError("Task lifecycle_run_id does not match the active run")
    phase = task.get("phase")
    if phase not in config["lifecycle"]["phases"]:
        raise LifecycleError(f"Task phase is not enabled: {phase}")
    if state["phases"][phase]["status"] != "in_progress":
        raise LifecycleError(
            f"Task phase must be in_progress; {phase} is {state['phases'][phase]['status']}"
        )
    expires_at = task.get("expires_at")
    if not isinstance(expires_at, str):
        raise LifecycleError("Task expires_at is required for execution")
    if parse_timestamp(expires_at, "task expires_at") <= datetime.now(timezone.utc):
        raise LifecycleError("Task has expired")
    canonical = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task_id}/task.json",
        must_exist=True,
    )
    if task_path is not None and task_path.resolve() != canonical.resolve():
        raise LifecycleError(
            "Task file must use the canonical .ai-lifecycle/tasks/<task_id>/task.json path"
        )
    validate_task_dependencies(root, task)
    return canonical


def parse_host_allowlist(name: str) -> set[str]:
    raw = os.environ.get(name, "")
    values = {item.strip() for item in raw.split(",") if item.strip()}
    if not values:
        raise LifecycleError(f"Host allowlist environment variable is empty: {name}")
    return values


def normalized_origin(value: str) -> str:
    parsed_value = parse.urlparse(value)
    if parsed_value.username or parsed_value.password:
        raise LifecycleError("Adapter endpoint cannot contain credentials")
    if not parsed_value.scheme or not parsed_value.hostname:
        raise LifecycleError("Adapter endpoint must be an absolute URL")
    if parsed_value.query or parsed_value.fragment:
        raise LifecycleError("Adapter endpoint cannot contain a query or fragment")
    scheme = parsed_value.scheme.lower()
    hostname = parsed_value.hostname.lower()
    localhost = hostname in {"127.0.0.1", "localhost", "::1"}
    if scheme != "https" and not (scheme == "http" and localhost):
        raise LifecycleError("Adapter endpoint must use HTTPS except explicit localhost")
    try:
        port = parsed_value.port
    except ValueError as exc:
        raise LifecycleError("Adapter endpoint port is invalid") from exc
    default_port = 443 if scheme == "https" else 80
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{host}" + (f":{port}" if port and port != default_port else "")


def require_allowed_origin(value: str) -> str:
    origin = normalized_origin(value)
    allowed = {normalized_origin(item) for item in parse_host_allowlist("AI_LIFECYCLE_ALLOWED_HTTP_ORIGINS")}
    if origin not in allowed:
        raise LifecycleError(f"Adapter endpoint origin is not host-allowlisted: {origin}")
    return origin


def require_allowed_credential_env(name: Any) -> str:
    if not isinstance(name, str) or not ENV_NAME.fullmatch(name):
        raise LifecycleError("Credential environment-variable name is invalid")
    allowed = parse_host_allowlist("AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS")
    if name not in allowed:
        raise LifecycleError(
            f"Credential environment variable is not host-allowlisted: {name}"
        )
    return name


def registered_adapter(registry: dict[str, Any], adapter_id: str) -> dict[str, Any]:
    validate_identifier(adapter_id, "adapter id")
    adapter = next(
        (tool for tool in registry["tools"] if tool.get("id") == adapter_id),
        None,
    )
    if adapter is None:
        raise LifecycleError(f"Adapter is not registered: {adapter_id}")
    if adapter.get("availability") != "available":
        raise LifecycleError(
            f"Adapter {adapter_id} is not available: {adapter.get('availability')}"
        )
    return adapter


def validate_adapter_for_task(
    adapter: dict[str, Any],
    task: dict[str, Any],
    *,
    adapter_id: str,
    transport: str,
) -> None:
    """Bind dispatch to the explicitly selected tool and its declared policy."""
    preferences = task.get("tool_preferences")
    if not isinstance(preferences, list) or not preferences:
        raise LifecycleError(
            "Task tool_preferences must explicitly list the selected adapter"
        )
    if adapter_id not in preferences:
        raise LifecycleError(
            f"Selected adapter {adapter_id} is not allowed by task.tool_preferences"
        )
    if adapter.get("transport") != transport:
        raise LifecycleError(
            f"Adapter {adapter_id} transport is {adapter.get('transport')!r}, not {transport!r}"
        )
    side_effects = adapter.get("side_effects")
    if not isinstance(side_effects, list) or not all(
        isinstance(item, str) and item for item in side_effects
    ):
        raise LifecycleError(f"Adapter {adapter_id} must declare side_effects")
    permissions = require_object(task.get("permissions"), "task.permissions")
    if permissions.get("external_mutations") is not True and any(
        effect in MUTATING_SIDE_EFFECTS for effect in side_effects
    ):
        raise LifecycleError(
            f"Adapter {adapter_id} declares external mutation side effects beyond task permissions"
        )
    unknown_effects = sorted(set(side_effects) - NON_MUTATING_SIDE_EFFECTS - MUTATING_SIDE_EFFECTS)
    if unknown_effects:
        raise LifecycleError(
            f"Adapter {adapter_id} declares unknown side effects: {', '.join(unknown_effects)}"
        )
    if permissions.get("write") and transport == "cli" and "workspace-write" not in side_effects:
        raise LifecycleError(
            f"Adapter {adapter_id} does not declare workspace-write for a writing task"
        )
    if transport == "http" and "task.submit" not in adapter.get("capabilities", []):
        raise LifecycleError(f"HTTP adapter {adapter_id} does not declare task.submit")
    if transport == "cli" and adapter.get("kind") != "coding-agent":
        raise LifecycleError(f"CLI adapter {adapter_id} is not registered as a coding-agent")
    if "network" in side_effects and permissions.get("network") is not True:
        raise LifecycleError(
            f"Adapter {adapter_id} declares network beyond task permissions"
        )


def bind_result_to_task(result: dict[str, Any], task: dict[str, Any]) -> None:
    expected = {
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "run_id": task["lifecycle_run_id"],
    }
    mismatches = [key for key, value in expected.items() if result.get(key) != value]
    if mismatches:
        raise LifecycleError(
            "Result does not match the submitted task: " + ", ".join(mismatches)
        )


def validate_result_acceptance(task: dict[str, Any], result: dict[str, Any]) -> None:
    """Require explicit passing evidence for every task acceptance criterion."""
    checks = result.get("checks", [])
    check_ids = [check.get("id") for check in checks]
    if len(check_ids) != len(set(check_ids)):
        raise LifecycleError("Result checks must use unique ids")
    nonpassing = [
        check.get("id", "unknown")
        for check in checks
        if check.get("status") != "passed"
    ]
    if nonpassing:
        raise LifecycleError(
            "Succeeded result contains non-passing checks: " + ", ".join(nonpassing)
        )
    by_id = {check["id"]: check for check in checks}
    missing: list[str] = []
    missing_evidence: list[str] = []
    for criterion in task.get("acceptance_criteria", []):
        criterion_id = criterion["id"]
        check = by_id.get(criterion_id)
        if check is None:
            missing.append(criterion_id)
            continue
        evidence = check.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            missing_evidence.append(criterion_id)
    if missing:
        raise LifecycleError(
            "Succeeded result lacks passing checks for acceptance criteria: "
            + ", ".join(missing)
        )
    if missing_evidence:
        raise LifecycleError(
            "Acceptance checks require evidence: " + ", ".join(missing_evidence)
        )


def validate_result_artifact_references(
    root: Path,
    task: dict[str, Any],
    result: dict[str, Any],
    *,
    ignored_current_paths: set[str] | None = None,
) -> None:
    """Validate accepted artifact identity and local bytes before completion."""
    if result.get("changed_paths") and not task["permissions"].get("write"):
        raise LifecycleError("Result claims repository changes beyond task permissions")
    if result.get("external_changes") and not task["permissions"].get(
        "external_mutations"
    ):
        raise LifecycleError("Result claims external changes beyond task permissions")
    allowed_types = set(task.get("output_contract", {}).get("artifact_types", []))
    seen_ids: set[str] = set()
    seen_uris: set[str] = set()
    for index, artifact in enumerate(result.get("artifacts", [])):
        artifact_id = artifact["artifact_id"]
        uri = artifact["uri"]
        digest = artifact["digest"]
        if artifact_id in seen_ids or uri in seen_uris:
            raise LifecycleError("Result artifacts must have unique ids and URIs")
        seen_ids.add(artifact_id)
        seen_uris.add(uri)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise LifecycleError(
                f"result.artifacts[{index}].digest must be lowercase sha256"
            )
        artifact_type = artifact["artifact_type"]
        if allowed_types and artifact_type not in allowed_types:
            raise LifecycleError(
                f"Result artifact type is outside the task output contract: {artifact_type}"
            )
        parsed = parse.urlsplit(uri)
        if parsed.scheme:
            if (
                parsed.scheme.lower() != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise LifecycleError(
                    "External result artifacts must use credential-free HTTPS URIs"
                )
            if not task["permissions"].get("network"):
                raise LifecycleError(
                    "External result artifacts require task permissions.network=true"
                )
            continue
        normalized = str(PurePosixPath(uri.replace("\\", "/")))
        if normalized.startswith(".ai-lifecycle/"):
            path = contained_control_path(root, normalized, must_exist=True)
        else:
            if normalized in (ignored_current_paths or set()):
                # A direct dependent writer may supersede this repository artifact.
                # Its own trusted task-output manifest validates the replacement.
                contained_path(root, normalized)
                continue
            lexical = root
            for part in Path(normalized).parts:
                lexical = lexical / part
                if not lexical.exists():
                    continue
                metadata = lexical.lstat()
                reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                attributes = getattr(metadata, "st_file_attributes", 0)
                if lexical.is_symlink() or bool(
                    reparse_flag and attributes & reparse_flag
                ):
                    raise LifecycleError(
                        f"Result artifact path contains a link: {normalized}"
                    )
            path = contained_path(root, normalized, must_exist=True)
        if not path.is_file():
            raise LifecycleError(f"Result artifact is not a regular file: {normalized}")
        if sha256_file(path) != digest:
            raise LifecycleError(f"Result artifact digest does not match: {normalized}")


def repository_output_bindings(
    root: Path, result: dict[str, Any]
) -> list[dict[str, str | None]]:
    """Bind every changed repository path to its current digest or deletion tombstone."""
    outputs: list[dict[str, str | None]] = []
    for relative in sorted(result.get("changed_paths", [])):
        normalized = relative.replace("\\", "/")
        if normalized == ".ai-lifecycle" or normalized.startswith(".ai-lifecycle/"):
            raise LifecycleError("Repository outputs cannot target lifecycle control data")
        path = contained_path(root, normalized)
        if path.exists():
            metadata = path.lstat()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            attributes = getattr(metadata, "st_file_attributes", 0)
            if path.is_symlink() or bool(reparse_flag and attributes & reparse_flag):
                raise LifecycleError(f"Repository output is a link: {normalized}")
            if not path.is_file():
                raise LifecycleError(f"Repository output is not a regular file: {normalized}")
            digest: str | None = sha256_file(path)
        else:
            digest = None
        outputs.append({"path": normalized, "digest": digest})
    return outputs


def _normalize_repository_outputs(
    value: Any, label: str
) -> list[dict[str, str | None]]:
    if not isinstance(value, list):
        raise LifecycleError(f"{label} must be an array")
    normalized: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"path", "digest"}:
            raise LifecycleError(
                f"{label}[{index}] must contain exactly path and digest"
            )
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            raise LifecycleError(f"{label}[{index}].path must be a string")
        path = validate_scope(raw_path)
        if path == ".ai-lifecycle" or path.startswith(".ai-lifecycle/"):
            raise LifecycleError(f"{label} cannot bind lifecycle control data")
        if path in seen:
            raise LifecycleError(f"{label} contains a duplicate path: {path}")
        seen.add(path)
        digest = item.get("digest")
        if digest is not None and not (
            isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
        ):
            raise LifecycleError(f"{label}[{index}].digest is not a SHA-256 digest")
        normalized.append({"path": path, "digest": digest})
    expected = sorted(normalized, key=lambda item: item["path"])
    if normalized != expected:
        raise LifecycleError(f"{label} must be sorted by path")
    return normalized


def _validate_repository_outputs_current(
    root: Path,
    outputs: list[dict[str, str | None]],
    *,
    ignored_paths: set[str] | None = None,
) -> None:
    ignored = ignored_paths or set()
    for binding in outputs:
        path = binding["path"]
        if path in ignored:
            continue
        current = repository_output_bindings(
            root, {"changed_paths": [path]}
        )[0]["digest"]
        if current != binding["digest"]:
            raise LifecycleError(
                f"Completion receipt repository output no longer matches: {path}"
            )


def _merged_repository_outputs(
    dependency_receipts: list[dict[str, Any]],
    task_outputs: list[dict[str, str | None]],
) -> list[dict[str, str | None]]:
    merged: dict[str, str | None] = {}
    for receipt in dependency_receipts:
        for binding in receipt.get("repository_outputs", []):
            path = binding["path"]
            digest = binding["digest"]
            prior = merged.get(path, digest)
            if path in merged and prior != digest:
                raise LifecycleError(
                    "Dependency receipts contain conflicting repository outputs: " + path
                )
            merged[path] = digest
    for binding in task_outputs:
        merged[binding["path"]] = binding["digest"]
    return [
        {"path": path, "digest": merged[path]}
        for path in sorted(merged)
    ]


def completion_receipt_document(
    root: Path,
    adapter_id: str,
    task: dict[str, Any],
    result: dict[str, Any],
    result_path: Path,
    *,
    expected_repository_outputs: list[dict[str, str | None]] | None = None,
) -> dict[str, Any]:
    validate_identifier(adapter_id, "completion adapter_id")
    bind_result_to_task(result, task)
    if result.get("status") != "succeeded":
        raise LifecycleError("Only a succeeded result can create a completion receipt")
    validate_result_acceptance(task, result)
    canonical_result = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task['task_id']}/result-{adapter_id}.json",
        must_exist=True,
    )
    if result_path.resolve() != canonical_result.resolve():
        raise LifecycleError("Completion result does not use the canonical result path")
    if canonical_result.is_symlink() or not canonical_result.is_file():
        raise LifecycleError("Completion result must be a regular file")
    stored_result = validate_envelope("result", load_json(canonical_result))
    if stored_result != result:
        raise LifecycleError("Completion result changed before receipt creation")
    validate_result_artifact_references(root, task, stored_result)
    current_task_outputs = repository_output_bindings(root, stored_result)
    if expected_repository_outputs is None:
        if current_task_outputs:
            raise LifecycleError(
                "A trusted expected repository-output manifest is required for a writing completion"
            )
        task_outputs: list[dict[str, str | None]] = []
    else:
        task_outputs = _normalize_repository_outputs(
            expected_repository_outputs, "expected_repository_outputs"
        )
        if task_outputs != current_task_outputs:
            raise LifecycleError(
                "Current repository outputs do not match the trusted agent output manifest"
            )
    dependency_bindings, dependency_receipts = _completion_dependency_state(
        root,
        task,
        superseded_paths={binding["path"] for binding in task_outputs},
    )
    return {
        "schema_version": 3,
        "accepted": True,
        "status": "succeeded",
        "adapter_id": adapter_id,
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "lifecycle_run_id": task["lifecycle_run_id"],
        "provider_run_id": result["run_id"],
        "result_path": str(canonical_result.relative_to(root)).replace("\\", "/"),
        "result_digest": sha256_file(canonical_result),
        "dependency_receipts": dependency_bindings,
        "task_outputs": task_outputs,
        "repository_outputs": _merged_repository_outputs(
            dependency_receipts, task_outputs
        ),
        "accepted_at": utc_now(),
    }


def persist_completion_receipt(
    root: Path,
    adapter_id: str,
    task: dict[str, Any],
    result: dict[str, Any],
    result_path: Path,
    *,
    expected_repository_outputs: list[dict[str, str | None]] | None = None,
) -> Path:
    receipt = completion_receipt_document(
        root,
        adapter_id,
        task,
        result,
        result_path,
        expected_repository_outputs=expected_repository_outputs,
    )
    path = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task['task_id']}/completion-receipt-{adapter_id}.json",
    )
    atomic_create_json(path, receipt)
    return path


def _validated_completion_receipt(
    root: Path,
    task: dict[str, Any],
    receipt_path: Path,
    *,
    require_current_outputs: bool = True,
    ignored_current_paths: set[str] | None = None,
    _receipt_stack: set[str] | None = None,
) -> dict[str, Any]:
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise LifecycleError(f"Completion receipt is not a regular file: {receipt_path}")
    receipt = require_object(load_json(receipt_path), "completion receipt")
    common_required = {
        "schema_version",
        "accepted",
        "status",
        "adapter_id",
        "task_id",
        "revision",
        "correlation_id",
        "lifecycle_run_id",
        "provider_run_id",
        "result_path",
        "result_digest",
        "accepted_at",
    }
    version = receipt.get("schema_version")
    version_fields = {
        1: set(),
        2: {"repository_outputs"},
        3: {"dependency_receipts", "task_outputs", "repository_outputs"},
    }
    if version not in version_fields or set(receipt) != common_required | version_fields[version]:
        raise LifecycleError("Completion receipt fields do not match a supported version")
    adapter_id = validate_identifier(receipt.get("adapter_id"), "completion adapter_id")
    bindings = {
        "schema_version": version,
        "accepted": True,
        "status": "succeeded",
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "lifecycle_run_id": task["lifecycle_run_id"],
        "provider_run_id": task["lifecycle_run_id"],
    }
    mismatches = [key for key, expected in bindings.items() if receipt.get(key) != expected]
    if mismatches:
        raise LifecycleError(
            "Completion receipt does not match its task: " + ", ".join(mismatches)
        )
    parse_timestamp(receipt.get("accepted_at"), "completion accepted_at")
    expected_receipt = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task['task_id']}/completion-receipt-{adapter_id}.json",
        must_exist=True,
    )
    if receipt_path.resolve() != expected_receipt.resolve():
        raise LifecycleError("Completion receipt path is not canonical")
    result_path = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task['task_id']}/result-{adapter_id}.json",
        must_exist=True,
    )
    expected_result_relative = str(result_path.relative_to(root)).replace("\\", "/")
    if receipt.get("result_path") != expected_result_relative:
        raise LifecycleError("Completion receipt result_path is not canonical")
    if result_path.is_symlink() or not result_path.is_file():
        raise LifecycleError("Accepted dependency result must be a regular file")
    if receipt.get("result_digest") != sha256_file(result_path):
        raise LifecycleError("Completion receipt result digest does not match")
    result = validate_envelope("result", load_json(result_path))
    bind_result_to_task(result, task)
    if result.get("status") != "succeeded":
        raise LifecycleError("Accepted dependency result is not succeeded")
    validate_result_acceptance(task, result)
    if require_current_outputs:
        validate_result_artifact_references(
            root,
            task,
            result,
            ignored_current_paths=ignored_current_paths,
        )

    if version == 1:
        if task.get("dependencies") or result.get("changed_paths") or task.get(
            "ownership", {}
        ).get("write_scope"):
            raise LifecycleError(
                "Legacy version 1 receipts are accepted only for dependency-free read-only tasks; "
                "create a replacement task with a new task_id"
            )
        return receipt

    if version == 2:
        if (
            task.get("dependencies")
            or result.get("changed_paths")
            or task.get("ownership", {}).get("write_scope")
        ):
            raise LifecycleError(
                "Version 2 receipts are accepted only for dependency-free read-only tasks; "
                "create a replacement task with a new task_id"
            )
        outputs = _normalize_repository_outputs(
            receipt.get("repository_outputs"), "receipt.repository_outputs"
        )
        expected_paths = sorted(result.get("changed_paths", []))
        if [binding["path"] for binding in outputs] != expected_paths:
            raise LifecycleError("Version 2 receipt outputs do not match result.changed_paths")
        if require_current_outputs:
            _validate_repository_outputs_current(
                root, outputs, ignored_paths=ignored_current_paths
            )
        return receipt

    task_outputs = _normalize_repository_outputs(
        receipt.get("task_outputs"), "receipt.task_outputs"
    )
    repository_outputs = _normalize_repository_outputs(
        receipt.get("repository_outputs"), "receipt.repository_outputs"
    )
    if [binding["path"] for binding in task_outputs] != sorted(
        result.get("changed_paths", [])
    ):
        raise LifecycleError("Completion receipt task_outputs do not match result.changed_paths")

    dependency_entries = receipt.get("dependency_receipts")
    if not isinstance(dependency_entries, list):
        raise LifecycleError("receipt.dependency_receipts must be an array")
    expected_dependency_ids = sorted(task.get("dependencies", []))
    if len(dependency_entries) != len(expected_dependency_ids):
        raise LifecycleError("Completion receipt dependency bindings do not match the task")
    dependency_receipts: list[dict[str, Any]] = []
    seen_dependencies: set[str] = set()
    stack = set() if _receipt_stack is None else set(_receipt_stack)
    receipt_key = str(receipt_path.resolve())
    if receipt_key in stack:
        raise LifecycleError("Completion receipt dependency chain contains a cycle")
    stack.add(receipt_key)
    for index, entry in enumerate(dependency_entries):
        if not isinstance(entry, dict) or set(entry) != {
            "task_id",
            "receipt_path",
            "receipt_digest",
        }:
            raise LifecycleError(
                f"receipt.dependency_receipts[{index}] has invalid fields"
            )
        dependency_id = validate_identifier(
            entry.get("task_id"),
            f"receipt.dependency_receipts[{index}].task_id",
            min_length=8,
        )
        if dependency_id in seen_dependencies:
            raise LifecycleError("Completion receipt contains a duplicate dependency")
        seen_dependencies.add(dependency_id)
        dependency_task_path = contained_control_path(
            root, f".ai-lifecycle/tasks/{dependency_id}/task.json", must_exist=True
        )
        dependency_task = validate_envelope("task", load_json(dependency_task_path))
        for key in ("project_id", "lifecycle_run_id"):
            if dependency_task.get(key) != task.get(key):
                raise LifecycleError(
                    f"Receipt dependency {dependency_id} belongs to a different {key}"
                )
        dependency_receipt_path = contained_control_path(
            root, entry.get("receipt_path"), must_exist=True
        )
        expected_prefix = (
            f".ai-lifecycle/tasks/{dependency_id}/completion-receipt-"
        )
        relative_receipt_path = str(dependency_receipt_path.relative_to(root)).replace(
            "\\", "/"
        )
        if not relative_receipt_path.startswith(expected_prefix):
            raise LifecycleError("Completion receipt dependency path is not canonical")
        receipt_digest = entry.get("receipt_digest")
        if not isinstance(receipt_digest, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", receipt_digest
        ):
            raise LifecycleError("Completion receipt dependency digest is invalid")
        if sha256_file(dependency_receipt_path) != receipt_digest:
            raise LifecycleError("Completion receipt dependency digest does not match")
        dependency_receipts.append(
            _validated_completion_receipt(
                root,
                dependency_task,
                dependency_receipt_path,
                require_current_outputs=False,
                _receipt_stack=stack,
            )
        )
    if sorted(seen_dependencies) != expected_dependency_ids:
        raise LifecycleError("Completion receipt dependency bindings do not match the task")
    expected_outputs = _merged_repository_outputs(
        dependency_receipts, task_outputs
    )
    if repository_outputs != expected_outputs:
        raise LifecycleError("Completion receipt effective repository outputs are inconsistent")
    if require_current_outputs:
        _validate_repository_outputs_current(
            root, repository_outputs, ignored_paths=ignored_current_paths
        )
    return receipt


def _single_valid_completion_receipt(
    root: Path,
    task: dict[str, Any],
    *,
    require_current_outputs: bool,
    ignored_current_paths: set[str] | None = None,
) -> tuple[Path, dict[str, Any]]:
    task_directory = contained_control_path(
        root, f".ai-lifecycle/tasks/{task['task_id']}", must_exist=True
    )
    receipt_paths = sorted(task_directory.glob("completion-receipt-*.json"))
    if len(receipt_paths) > 32:
        raise LifecycleError(f"Task {task['task_id']} has too many completion receipts")
    if not receipt_paths:
        raise LifecycleError(
            f"Task {task['task_id']} has no accepted completion receipt"
        )
    valid: list[tuple[Path, dict[str, Any]]] = []
    errors: list[str] = []
    for receipt_path in receipt_paths:
        try:
            valid.append(
                (
                    receipt_path,
                    _validated_completion_receipt(
                        root,
                        task,
                        receipt_path,
                        require_current_outputs=require_current_outputs,
                        ignored_current_paths=ignored_current_paths,
                    ),
                )
            )
        except LifecycleError as exc:
            errors.append(str(exc))
    if errors or len(valid) != 1:
        detail = "; ".join(errors) or "multiple accepted completions"
        raise LifecycleError(
            f"Task {task['task_id']} does not have exactly one valid completion: {detail}"
        )
    return valid[0]


def _completion_dependency_state(
    root: Path,
    task: dict[str, Any],
    *,
    superseded_paths: set[str],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    bindings: list[dict[str, str]] = []
    receipts: list[dict[str, Any]] = []
    for dependency_id in sorted(task.get("dependencies", [])):
        dependency_path = contained_control_path(
            root, f".ai-lifecycle/tasks/{dependency_id}/task.json", must_exist=True
        )
        dependency = validate_envelope("task", load_json(dependency_path))
        for key in ("project_id", "lifecycle_run_id"):
            if dependency.get(key) != task.get(key):
                raise LifecycleError(
                    f"Dependency {dependency_id} belongs to a different {key}"
                )
        receipt_path, receipt = _single_valid_completion_receipt(
            root,
            dependency,
            require_current_outputs=True,
            ignored_current_paths=superseded_paths,
        )
        bindings.append(
            {
                "task_id": dependency_id,
                "receipt_path": str(receipt_path.relative_to(root)).replace("\\", "/"),
                "receipt_digest": sha256_file(receipt_path),
            }
        )
        receipts.append(receipt)
    return bindings, receipts


def validate_task_dependencies(root: Path, task: dict[str, Any]) -> None:
    """Require an acyclic graph whose direct dependencies have current accepted state."""
    root_task_id = task["task_id"]
    visiting: set[str] = set()
    verified: set[str] = set()

    def visit(current: dict[str, Any]) -> None:
        current_id = current["task_id"]
        if current_id in visiting:
            raise LifecycleError(f"Task dependency cycle detected at {current_id}")
        if current_id in verified:
            return
        visiting.add(current_id)
        if len(visiting) > 256:
            raise LifecycleError("Task dependency graph exceeds the maximum depth of 256")
        for dependency_id in current.get("dependencies", []):
            validate_identifier(dependency_id, "dependency task_id", min_length=8)
            if dependency_id == current_id or dependency_id == root_task_id:
                raise LifecycleError("Task dependency graph contains a self-reference or cycle")
            dependency_path = contained_control_path(
                root,
                f".ai-lifecycle/tasks/{dependency_id}/task.json",
                must_exist=True,
            )
            dependency = validate_envelope("task", load_json(dependency_path))
            for key in ("project_id", "lifecycle_run_id"):
                if dependency.get(key) != task.get(key):
                    raise LifecycleError(
                        f"Dependency {dependency_id} belongs to a different {key}"
                    )
            visit(dependency)
        visiting.remove(current_id)
        verified.add(current_id)

    visit(task)
    for dependency_id in task.get("dependencies", []):
        dependency_path = contained_control_path(
            root, f".ai-lifecycle/tasks/{dependency_id}/task.json", must_exist=True
        )
        dependency = validate_envelope("task", load_json(dependency_path))
        _single_valid_completion_receipt(
            root, dependency, require_current_outputs=True
        )


def parse_acceptance(values: list[str], file_path: Path | None) -> list[dict[str, str]]:
    if file_path:
        document = load_json(file_path.expanduser().resolve())
        if not isinstance(document, list):
            raise LifecycleError("Acceptance JSON must contain an array")
        criteria = document
    else:
        criteria = []
        for value in values:
            parts = value.split("|", 2)
            if len(parts) != 3 or not all(part.strip() for part in parts):
                raise LifecycleError(
                    "--acceptance must use ID|criterion text|verification"
                )
            criteria.append(
                {
                    "id": parts[0].strip(),
                    "text": parts[1].strip(),
                    "verification": parts[2].strip(),
                }
            )
    if not criteria:
        raise LifecycleError("At least one acceptance criterion is required")
    for item in criteria:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) and item[key].strip()
            for key in ("id", "text", "verification")
        ):
            raise LifecycleError(
                "Every acceptance criterion requires non-empty id, text, and verification"
            )
    return criteria


def command_prepare_task(args: argparse.Namespace) -> int:
    root = resolve_root(args.project_root)
    config, _, state = validate_all(root)
    phase = args.phase
    if phase not in config["lifecycle"]["phases"]:
        raise LifecycleError(f"Phase is not enabled: {phase}")
    if state["phases"][phase]["status"] != "in_progress":
        raise LifecycleError(
            f"Tasks may be prepared only for an in-progress phase; {phase} is "
            f"{state['phases'][phase]['status']}"
        )
    if args.role not in config["agents"]["roles"]:
        raise LifecycleError(
            f"Task role is not enabled by project configuration: {args.role}"
        )
    if args.objective_file:
        objective = args.objective_file.expanduser().resolve().read_text(encoding="utf-8")
    else:
        objective = args.objective
    if not objective or not objective.strip():
        raise LifecycleError("Task objective cannot be empty")

    inputs: list[dict[str, str | None]] = []
    for index, relative in enumerate(args.input):
        path = contained_path(root, relative, must_exist=True)
        if not path.is_file():
            raise LifecycleError(f"Task input must be a file: {relative}")
        inputs.append(
            {
                "artifact_id": f"input-{index + 1}",
                "artifact_type": path.suffix.lstrip(".") or "file",
                "uri": str(path.relative_to(root)).replace("\\", "/"),
                "digest": sha256_file(path),
                "version": None,
            }
        )
    criteria = parse_acceptance(args.acceptance, args.acceptance_json)
    task_id = args.task_id or f"task-{uuid.uuid4()}"
    correlation_id = args.correlation_id or f"corr-{uuid.uuid4()}"
    validate_identifier(task_id, "task_id", min_length=8)
    validate_identifier(correlation_id, "correlation_id", min_length=8)
    if args.causation_id is not None:
        validate_identifier(args.causation_id, "causation_id")
    for dependency in args.dependency:
        validate_identifier(dependency, "dependency task_id", min_length=8)
        if dependency == task_id:
            raise LifecycleError("Task cannot depend on itself")
    if not 1 <= args.expires_hours <= 24 * 30:
        raise LifecycleError("--expires-hours must be between 1 and 720")
    canonical_output = contained_control_path(
        root, f".ai-lifecycle/tasks/{task_id}/task.json"
    )
    if args.output:
        output = args.output.expanduser().resolve()
        if output != canonical_output.resolve():
            raise LifecycleError(
                "Task output must use .ai-lifecycle/tasks/<task_id>/task.json"
            )
    else:
        output = canonical_output
    if output.exists():
        raise LifecycleError(f"Refusing to overwrite existing task: {output}")
    result_schema_output = output.parent / "result-envelope.schema.json"
    if result_schema_output.exists():
        raise LifecycleError(
            f"Refusing to overwrite existing task schema: {result_schema_output}"
        )
    source_result_schema = _schema_directory() / "result-envelope.schema.json"
    result_schema_relative = str(result_schema_output.relative_to(root)).replace(
        "\\", "/"
    )
    created = datetime.now(timezone.utc)
    expires = created + timedelta(hours=args.expires_hours)
    read_scope = [validate_scope(value) for value in args.read_scope]
    write_scope = [validate_scope(value) for value in args.write_scope]
    forbidden_scope = [validate_scope(value) for value in args.forbidden_scope]
    if args.external_mutations and not args.authorized_external_mutations:
        raise LifecycleError(
            "External mutation permission requires --authorized-external-mutations"
        )
    task = {
        "spec_version": "1.0.0",
        "task_id": task_id,
        "revision": 1,
        "created_at": created.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expires_at": expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "correlation_id": correlation_id,
        "causation_id": args.causation_id,
        "project_id": config["project"]["id"],
        "lifecycle_run_id": state["lifecycle_run_id"],
        "phase": phase,
        "role": args.role,
        "objective": objective.strip(),
        "inputs": inputs,
        "constraints": args.constraint,
        "assumptions": args.assumption,
        "dependencies": args.dependency,
        "acceptance_criteria": criteria,
        "permissions": {
            "read": read_scope,
            "write": write_scope,
            "network": args.network,
            "external_mutations": args.external_mutations,
        },
        "ownership": {
            "write_scope": write_scope,
            "forbidden_scope": forbidden_scope,
        },
        "tool_preferences": args.tool,
        "output_contract": {
            "result_schema": result_schema_relative,
            "artifact_types": args.artifact_type,
        },
        "callback": None,
        "retry_policy": config["integration"]["retry"],
    }
    validate_envelope("task", task)
    if redact_json_value(task) != task:
        raise LifecycleError(
            "Task contains secret-bearing fields or values; use host credential references"
        )
    atomic_create_json(result_schema_output, load_json(source_result_schema))
    try:
        atomic_create_json(output, task)
    except Exception:
        # The schema was created by this invocation and is safe to remove when the
        # paired task could not be created.
        try:
            result_schema_output.unlink()
        except OSError:
            pass
        raise
    print(
        json.dumps(
            {
                "status": "prepared",
                "task_id": task_id,
                "correlation_id": correlation_id,
                "path": str(output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def retryable_status(status: int) -> bool:
    return status == 429 or 500 <= status <= 599


def read_bounded_http_body(stream: Any, limit: int = MAX_HTTP_BODY_BYTES) -> bytes:
    body = stream.read(limit + 1)
    if len(body) > limit:
        raise LifecycleError(f"Adapter response exceeds {limit} bytes")
    return body


def retry_after_seconds(headers: Any, now: datetime | None = None) -> float | None:
    if headers is None:
        return None
    value = headers.get("Retry-After")
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        from email.utils import parsedate_to_datetime

        target = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return max(0.0, (target.astimezone(timezone.utc) - current).total_seconds())


def validate_http_success(
    status: int,
    body: bytes,
    task: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"Adapter success response is not valid UTF-8 JSON: {exc}") from exc
    if status == 202:
        accepted = validate_against_schema("HTTP 202 response", document, HTTP_ACCEPTED_SCHEMA)
        parse_timestamp(accepted["accepted_at"], "HTTP 202 accepted_at")
        require_allowed_origin(accepted["status_url"])
        if accepted.get("cancel_url") is not None:
            require_allowed_origin(accepted["cancel_url"])
        return accepted, accepted["run_id"]
    if status == 200:
        result = validate_envelope("result", document)
        bind_result_to_task(result, task)
        if redact_json_value(result) != result:
            raise LifecycleError(
                "Adapter result contains secret-bearing fields or values"
            )
        return result, result["run_id"]
    raise LifecycleError(
        f"Adapter returned unsupported success status {status}; expected 200 or 202"
    )


def persist_provider_receipt(
    root: Path,
    adapter_id: str,
    task: dict[str, Any],
    provider_run_id: str,
    response: dict[str, Any],
) -> Path:
    validate_identifier(provider_run_id, "provider run_id")
    receipt_path = contained_control_path(
        root,
        ".ai-lifecycle/tasks/"
        f"{task['task_id']}/provider-receipt-{adapter_id}.json",
    )
    receipt = {
        "schema_version": 1,
        "adapter_id": adapter_id,
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "provider_run_id": provider_run_id,
        "received_at": utc_now(),
        "response_digest": "sha256:"
        + hashlib.sha256(
            json.dumps(response, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "status_url": response.get("status_url"),
    }
    if receipt_path.exists():
        existing = require_object(load_json(receipt_path), "provider receipt")
        identity_fields = (
            "adapter_id",
            "task_id",
            "revision",
            "correlation_id",
            "provider_run_id",
            "response_digest",
            "status_url",
        )
        if any(existing.get(key) != receipt.get(key) for key in identity_fields):
            raise LifecycleError("Provider receipt conflicts with the existing task submission")
        return receipt_path
    atomic_create_json(receipt_path, receipt)
    return receipt_path


def command_invoke_http(args: argparse.Namespace) -> int:
    if not args.execute or not args.authorization_actor or not args.authorization_reason:
        raise LifecycleError(
            "HTTP invocation requires --execute, --authorization-actor, and --authorization-reason"
        )
    root = resolve_root(args.project_root)
    require_trusted_project(root, "HTTP adapter invocation")
    config, registry, state = validate_all(root)
    task_path = args.task_file.expanduser().resolve()
    task = validate_envelope("task", load_json(task_path))
    validate_task_context(root, config, state, task, task_path=task_path)
    if redact_json_value(task) != task:
        raise LifecycleError("Task contains secret-bearing fields or values")
    if task["permissions"]["external_mutations"]:
        raise LifecycleError(
            "External mutations are disabled until verifiable approval tokens are implemented"
        )
    if not task["permissions"]["network"]:
        raise LifecycleError("HTTP adapter invocation requires task permissions.network=true")
    if task["permissions"]["write"] or task["ownership"]["write_scope"]:
        raise LifecycleError(
            "Generic HTTP adapter tasks cannot claim repository write scope"
        )
    adapter = registered_adapter(registry, args.adapter)
    validate_adapter_for_task(
        adapter, task, adapter_id=args.adapter, transport="http"
    )
    http = adapter.get("http")
    if not isinstance(http, dict) or not isinstance(http.get("task_url"), str):
        raise LifecycleError(f"Adapter {args.adapter} does not define http.task_url")
    endpoint = http["task_url"]
    endpoint_origin = require_allowed_origin(endpoint)

    payload = json.dumps(task, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_HTTP_BODY_BYTES:
        raise LifecycleError(
            f"Task request exceeds the {MAX_HTTP_BODY_BYTES}-byte safety limit"
        )
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Idempotency-Key": f"{task['task_id']}:{task['revision']}",
        "X-Correlation-Id": task["correlation_id"],
    }
    auth_env = http.get("bearer_token_env_var")
    if auth_env:
        auth_env = require_allowed_credential_env(auth_env)
        token = os.environ.get(auth_env)
        if not token:
            raise LifecycleError(
                f"Required bearer-token environment variable is not set: {auth_env}"
            )
        base_headers["Authorization"] = f"Bearer {token}"
    signing_env = http.get("hmac_secret_env_var")
    if signing_env:
        signing_env = require_allowed_credential_env(signing_env)
        signing_secret = os.environ.get(signing_env)
        if not signing_secret:
            raise LifecycleError(
                f"Required signing environment variable is not set: {signing_env}"
            )
    else:
        signing_secret = None

    policy = task["retry_policy"]
    max_attempts = min(int(policy["max_attempts"]), 10)
    base_delay = float(policy["base_delay_seconds"])
    max_delay = float(policy["max_delay_seconds"])
    total_timeout = min(int(args.timeout_seconds), 600)
    if total_timeout < 1:
        raise LifecycleError("--timeout-seconds must be between 1 and 600")
    opener = request.build_opener(NoRedirect())
    attempts: list[dict[str, Any]] = []
    terminal_status: int | None = None
    response_body = b""
    response_document: dict[str, Any] | None = None
    provider_run_id: str | None = None
    final_error: str | None = None
    started = utc_now()
    deadline = time.monotonic() + total_timeout
    pending_retry_after: float | None = None

    for attempt in range(1, max_attempts + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            final_error = "HTTP adapter total time limit expired before the next attempt"
            break
        final_error = None
        pending_retry_after = None
        attempt_started = time.monotonic()
        request_id = f"request-{uuid.uuid4()}"
        headers = dict(base_headers)
        headers["X-Request-Id"] = request_id
        if signing_secret is not None:
            timestamp = str(int(time.time()))
            signature = hmac.new(
                signing_secret.encode("utf-8"),
                timestamp.encode("ascii") + b"." + payload,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Webhook-Timestamp"] = timestamp
            headers["X-Signature-256"] = f"v1={signature}"
        outbound = request.Request(endpoint, data=payload, headers=headers, method="POST")
        try:
            with opener.open(outbound, timeout=max(0.1, remaining)) as response:
                terminal_status = response.status
                response_body = read_bounded_http_body(response)
                pending_retry_after = retry_after_seconds(response.headers)
            if 200 <= terminal_status < 300:
                try:
                    response_document, provider_run_id = validate_http_success(
                        terminal_status, response_body, task
                    )
                    final_error = None
                except LifecycleError as exc:
                    final_error = str(exc)
            attempts.append(
                {
                    "attempt": attempt,
                    "request_id": request_id,
                    "status": terminal_status,
                    "duration_seconds": round(time.monotonic() - attempt_started, 3),
                    "response_valid": response_document is not None,
                    "retry_after_seconds": pending_retry_after,
                }
            )
            if 200 <= terminal_status < 300:
                break
            if not retryable_status(terminal_status):
                break
        except LifecycleError as exc:
            final_error = str(exc)
            response_body = b""
            attempts.append(
                {
                    "attempt": attempt,
                    "request_id": request_id,
                    "status": terminal_status,
                    "duration_seconds": round(time.monotonic() - attempt_started, 3),
                    "error": redact(final_error),
                }
            )
            break
        except error.HTTPError as exc:
            terminal_status = exc.code
            pending_retry_after = retry_after_seconds(exc.headers)
            try:
                response_body = read_bounded_http_body(exc)
            except LifecycleError as body_error:
                final_error = str(body_error)
                response_body = b""
            if final_error is None:
                final_error = str(exc)
            attempts.append(
                {
                    "attempt": attempt,
                    "request_id": request_id,
                    "status": terminal_status,
                    "duration_seconds": round(time.monotonic() - attempt_started, 3),
                    "error": redact(final_error),
                    "retry_after_seconds": pending_retry_after,
                }
            )
            if not retryable_status(exc.code):
                break
        except (error.URLError, TimeoutError, OSError) as exc:
            final_error = str(exc)
            attempts.append(
                {
                    "attempt": attempt,
                    "request_id": request_id,
                    "status": None,
                    "duration_seconds": round(time.monotonic() - attempt_started, 3),
                    "error": redact(final_error),
                }
            )
        if attempt < max_attempts:
            exponential = min(max_delay, base_delay * (2 ** (attempt - 1)))
            jittered = exponential * (0.75 + random.random() * 0.5)
            if pending_retry_after is not None and pending_retry_after > max_delay:
                final_error = (
                    "Provider Retry-After exceeds the configured maximum retry delay"
                )
                break
            delay = max(jittered, pending_retry_after or 0.0)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or delay >= remaining:
                final_error = "HTTP adapter total time limit would expire during retry delay"
                break
            if delay > 0:
                time.sleep(delay)
            pending_retry_after = None

    response_text = response_body.decode("utf-8", errors="replace")
    evidence = {
        "schema_version": 1,
        "adapter": args.adapter,
        "endpoint_origin": endpoint_origin,
        "task_id": task["task_id"],
        "correlation_id": task["correlation_id"],
        "authorization": {
            "actor": args.authorization_actor,
            "reason": args.authorization_reason,
        },
        "started_at": started,
        "finished_at": utc_now(),
        "attempts": attempts,
        "terminal_status": terminal_status,
        "response": redact(response_text),
        "error": redact(final_error) if final_error else None,
        "provider_run_id": provider_run_id,
    }
    evidence_path = contained_control_path(
        root,
        ".ai-lifecycle/evidence/external/"
        f"http-{task['task_id']}-{uuid.uuid4()}.json",
    )
    atomic_create_json(evidence_path, evidence)
    valid_response = (
        terminal_status in {200, 202}
        and response_document is not None
        and provider_run_id is not None
    )
    asynchronous = valid_response and terminal_status == 202
    completed = valid_response and terminal_status == 200
    succeeded = completed and response_document.get("status") == "succeeded"
    receipt_path: Path | None = None
    result_path: Path | None = None
    completion_path: Path | None = None
    if valid_response:
        receipt_path = persist_provider_receipt(
            root, args.adapter, task, provider_run_id, response_document
        )
    if completed:
        result_path = contained_control_path(
            root,
            f".ai-lifecycle/tasks/{task['task_id']}/result-{args.adapter}.json",
        )
        created: list[Path] = []
        try:
            atomic_create_json(result_path, response_document)
            created.append(result_path)
            if succeeded:
                completion_path = persist_completion_receipt(
                    root, args.adapter, task, response_document, result_path
                )
                created.append(completion_path)
        except Exception:
            for path in reversed(created):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise
    print(
        json.dumps(
            {
                "status": (
                    "submitted"
                    if asynchronous
                    else "completed"
                    if completed
                    else "failed"
                ),
                "completed": completed,
                "result_status": response_document.get("status") if completed else None,
                "http_status": terminal_status,
                "attempts": len(attempts),
                "evidence": str(evidence_path),
                "provider_receipt": str(receipt_path) if receipt_path else None,
                "result": str(result_path) if result_path else None,
                "completion_receipt": str(completion_path) if completion_path else None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if asynchronous or succeeded else 1


def resolve_webhook_key(adapter: dict[str, Any], key_id: str) -> tuple[str, str]:
    validate_identifier(key_id, "webhook key_id")
    webhook = adapter.get("webhook")
    if not isinstance(webhook, dict):
        raise LifecycleError(f"Adapter {adapter.get('id')} does not define webhook configuration")
    keys = webhook.get("keys")
    if not isinstance(keys, list):
        raise LifecycleError("Adapter webhook.keys must be an array")
    matching = [item for item in keys if isinstance(item, dict) and item.get("key_id") == key_id]
    if len(matching) != 1:
        raise LifecycleError("Webhook key_id is not uniquely registered for the adapter")
    key = matching[0]
    algorithm = key.get("algorithm", "hmac-sha256")
    if algorithm != "hmac-sha256":
        raise LifecycleError(f"Unsupported webhook signature algorithm: {algorithm}")
    secret_env = require_allowed_credential_env(key.get("secret_env_var"))
    return secret_env, algorithm


def bind_event_to_task(
    root: Path,
    config: dict[str, Any],
    state: dict[str, Any],
    adapter_id: str,
    event: dict[str, Any],
) -> dict[str, Any]:
    if event["source"]["adapter_id"] != adapter_id:
        raise LifecycleError("Webhook source.adapter_id does not match the selected adapter")
    subject = event["subject"]
    if subject["project_id"] != config["project"]["id"]:
        raise LifecycleError("Webhook subject.project_id does not match the current project")
    if subject["lifecycle_run_id"] != state["lifecycle_run_id"]:
        raise LifecycleError("Webhook subject.lifecycle_run_id does not match the active run")
    phase = subject["phase"]
    if phase not in config["lifecycle"]["phases"]:
        raise LifecycleError(f"Webhook subject phase is not enabled: {phase}")
    if state["phases"][phase]["status"] != "in_progress":
        raise LifecycleError(
            f"Webhook subject phase must be in_progress; {phase} is "
            f"{state['phases'][phase]['status']}"
        )
    task_id = subject.get("task_id")
    if task_id is None:
        raise LifecycleError("External webhook events must identify a task_id")
    validate_identifier(task_id, "event subject.task_id", min_length=8)
    task_path = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task_id}/task.json",
        must_exist=True,
    )
    task = validate_envelope("task", load_json(task_path))
    validate_task_context(root, config, state, task, task_path=task_path)
    if task["phase"] != phase:
        raise LifecycleError("Webhook subject.phase does not match the task phase")
    if event["trace"]["correlation_id"] != task["correlation_id"]:
        raise LifecycleError("Webhook correlation_id does not match the task")
    receipt_path = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task_id}/provider-receipt-{adapter_id}.json",
        must_exist=True,
    )
    receipt = require_object(load_json(receipt_path), "provider receipt")
    receipt_bindings = {
        "adapter_id": adapter_id,
        "task_id": task_id,
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "provider_run_id": event["source"]["run_id"],
    }
    mismatches = [
        key for key, expected in receipt_bindings.items() if receipt.get(key) != expected
    ]
    if mismatches:
        raise LifecycleError(
            "Webhook does not match the provider receipt: " + ", ".join(mismatches)
        )
    return task


def _load_webhook_replay_index(root: Path) -> tuple[Path, dict[str, Any]]:
    index_path = contained_control_path(
        root, ".ai-lifecycle/events/replay-index.json"
    )
    if index_path.exists():
        index = require_object(load_json(index_path), "webhook replay index")
        if set(index) != {"schema_version", "event_ids", "idempotency_keys", "updated_at"}:
            raise LifecycleError("Webhook replay index fields are invalid")
        if index.get("schema_version") != 1:
            raise LifecycleError("Webhook replay index schema_version must be 1")
        if not isinstance(index.get("event_ids"), dict) or not isinstance(
            index.get("idempotency_keys"), dict
        ):
            raise LifecycleError("Webhook replay index maps are invalid")
    else:
        index = {
            "schema_version": 1,
            "event_ids": {},
            "idempotency_keys": {},
            "updated_at": utc_now(),
        }

    event_ids = index["event_ids"]
    idempotency_keys = index["idempotency_keys"]
    if len(event_ids) != len(idempotency_keys):
        raise LifecycleError("Webhook replay index maps are not bijective")
    for event_id, idempotency_key in event_ids.items():
        validate_identifier(event_id, "replay index event_id", min_length=8)
        validate_identifier(
            idempotency_key,
            "replay index idempotency_key",
            min_length=8,
        )
        if idempotency_keys.get(idempotency_key) != event_id:
            raise LifecycleError("Webhook replay index maps are not bijective")
    for idempotency_key, event_id in idempotency_keys.items():
        validate_identifier(
            idempotency_key,
            "replay index idempotency_key",
            min_length=8,
        )
        validate_identifier(event_id, "replay index event_id", min_length=8)
        if event_ids.get(event_id) != idempotency_key:
            raise LifecycleError("Webhook replay index maps are not bijective")

    # Reconcile durable event files in case a process crashed between the event
    # and index writes. The common path compares filenames only; full envelope
    # parsing is reserved for a mismatch, avoiding repeated O(n) JSON parsing.
    event_files = sorted(
        path for path in index_path.parent.glob("*.json") if path != index_path
    )
    if len(event_files) > MAX_REPLAY_ENTRIES:
        raise LifecycleError("Webhook replay registry exceeds its safety limit")
    persisted_event_ids: set[str] = set()
    for path in event_files:
        if path.is_symlink() or not path.is_file():
            raise LifecycleError(f"Webhook event is not a regular file: {path}")
        persisted_event_ids.add(
            validate_identifier(path.stem, "persisted event filename", min_length=8)
        )

    rebuilt = persisted_event_ids != set(event_ids)
    if rebuilt:
        event_ids = {}
        idempotency_keys = {}
    for path in event_files if rebuilt else []:
        existing = validate_envelope("event", load_json(path))
        existing_event_id = existing["event_id"]
        existing_key = existing["delivery"]["idempotency_key"]
        if path.stem != existing_event_id:
            raise LifecycleError("Webhook event filename does not match event_id")
        prior_key = event_ids.get(existing_event_id)
        prior_event = idempotency_keys.get(existing_key)
        if prior_key not in {None, existing_key} or prior_event not in {
            None,
            existing_event_id,
        }:
            raise LifecycleError("Persisted webhook events contain replay conflicts")
        event_ids[existing_event_id] = existing_key
        idempotency_keys[existing_key] = existing_event_id
    index["event_ids"] = event_ids
    index["idempotency_keys"] = idempotency_keys
    if max(len(event_ids), len(idempotency_keys)) > MAX_REPLAY_ENTRIES:
        raise LifecycleError("Webhook replay registry exceeds its safety limit")
    if rebuilt and index_path.exists():
        index["updated_at"] = utc_now()
        atomic_write_json(index_path, index)
    return index_path, index


def command_verify_webhook(args: argparse.Namespace) -> int:
    root = resolve_root(args.project_root)
    require_trusted_project(root, "Webhook verification")
    config, registry, state = validate_all(root)
    adapter = registered_adapter(registry, args.adapter)
    secret_env, algorithm = resolve_webhook_key(adapter, args.key_id)
    supplied_body_path = Path(os.path.abspath(args.body_file.expanduser()))
    if supplied_body_path.is_symlink():
        raise LifecycleError("Webhook body must be a regular non-link file")
    body_path = supplied_body_path.resolve()
    if not body_path.is_file():
        raise LifecycleError("Webhook body must be a regular non-link file")
    with body_path.open("rb") as body_stream:
        body = body_stream.read(MAX_WEBHOOK_BODY_BYTES + 1)
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        raise LifecycleError(
            f"Webhook body exceeds the {MAX_WEBHOOK_BODY_BYTES}-byte safety limit"
        )
    secret = os.environ.get(secret_env)
    if not secret:
        raise LifecycleError(
            f"Webhook secret environment variable is not set: {secret_env}"
        )
    try:
        timestamp = int(args.timestamp)
    except ValueError as exc:
        raise LifecycleError("Webhook timestamp must be Unix seconds") from exc
    now = int(time.time())
    if not 1 <= args.tolerance_seconds <= 3600:
        raise LifecycleError("Webhook tolerance must be between 1 and 3600 seconds")
    if abs(now - timestamp) > args.tolerance_seconds:
        raise LifecycleError("Webhook timestamp is outside the allowed tolerance")
    signature = args.signature
    if not re.fullmatch(r"v1=[0-9a-f]{64}", signature):
        raise LifecycleError("Webhook signature must use v1=<64 lowercase hex characters>")
    expected = hmac.new(
        secret.encode("utf-8"),
        str(timestamp).encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature[3:], expected):
        raise LifecycleError("Webhook signature verification failed")
    try:
        event = validate_envelope("event", json.loads(body.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"Webhook body is not valid UTF-8 JSON: {exc}") from exc
    event_id = validate_identifier(event["event_id"], "event_id", min_length=8)
    if event_id == "replay-index":
        raise LifecycleError("Webhook event_id is reserved by the replay registry")
    security = event["security"]
    if security["key_id"] != args.key_id or security["algorithm"] != algorithm:
        raise LifecycleError("Webhook security metadata does not match the registered key")
    task = bind_event_to_task(root, config, state, args.adapter, event)
    if redact_json_value(event) != event:
        raise LifecycleError(
            "Webhook event contains secret-bearing fields or values and cannot be persisted"
        )
    default_output = contained_control_path(
        root, f".ai-lifecycle/events/{event_id}.json"
    )
    output = args.output.expanduser().resolve() if args.output else default_output
    if output != default_output.resolve():
        raise LifecycleError(
            "Verified event output must use .ai-lifecycle/events/<event_id>.json"
        )
    idempotency_key = validate_identifier(
        event["delivery"]["idempotency_key"],
        "delivery.idempotency_key",
        min_length=8,
    )
    result: dict[str, Any] | None = None
    if event["event_type"] == "task.completed" and isinstance(
        event.get("data", {}).get("result"), dict
    ):
        result = validate_envelope("result", event["data"]["result"])
        bind_result_to_task(result, task)
        if result.get("status") != "succeeded":
            raise LifecycleError("task.completed event result must be succeeded")
        if redact_json_value(result) != result:
            raise LifecycleError("Webhook completion result contains secret-bearing values")

    created_paths: list[Path] = []
    with lifecycle_lock(root, "webhook-replay-registry"):
        index_path, replay_index = _load_webhook_replay_index(root)
        if event_id in replay_index["event_ids"] or default_output.exists():
            raise LifecycleError(f"Replay detected for event: {event_id}")
        prior_event = replay_index["idempotency_keys"].get(idempotency_key)
        if prior_event is not None:
            raise LifecycleError(
                "Replay detected for delivery.idempotency_key "
                f"{idempotency_key} (first event {prior_event})"
            )
        old_index = json.loads(json.dumps(replay_index))
        try:
            atomic_create_json(default_output, event)
            created_paths.append(default_output)
            completion_path: Path | None = None
            if result is not None:
                result_path = contained_control_path(
                    root,
                    f".ai-lifecycle/tasks/{task['task_id']}/result-{args.adapter}.json",
                )
                atomic_create_json(result_path, result)
                created_paths.append(result_path)
                completion_path = persist_completion_receipt(
                    root, args.adapter, task, result, result_path
                )
                created_paths.append(completion_path)
            replay_index["event_ids"][event_id] = idempotency_key
            replay_index["idempotency_keys"][idempotency_key] = event_id
            replay_index["updated_at"] = utc_now()
            atomic_write_json(index_path, replay_index)
        except Exception:
            for path in reversed(created_paths):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            if index_path.exists():
                try:
                    atomic_write_json(index_path, old_index)
                except OSError:
                    pass
            raise
    print(
        json.dumps(
            {
                "status": "verified",
                "event_id": event_id,
                "event_type": event["event_type"],
                "path": str(default_output),
                "completion_recorded": result is not None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_validate(args: argparse.Namespace) -> int:
    value = load_json(args.file.expanduser().resolve())
    document = validate_envelope(args.kind, value)
    print(
        json.dumps(
            {
                "valid": True,
                "kind": args.kind,
                "id": document.get(
                    {"task": "task_id", "result": "run_id", "event": "event_id"}[args.kind]
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare-task")
    prepare.add_argument("--project-root", required=True, type=Path)
    prepare.add_argument("--phase", required=True)
    prepare.add_argument("--role", required=True)
    objective = prepare.add_mutually_exclusive_group(required=True)
    objective.add_argument("--objective")
    objective.add_argument("--objective-file", type=Path)
    prepare.add_argument("--task-id")
    prepare.add_argument("--correlation-id")
    prepare.add_argument("--causation-id")
    prepare.add_argument("--input", action="append", default=[])
    prepare.add_argument("--constraint", action="append", default=[])
    prepare.add_argument("--assumption", action="append", default=[])
    prepare.add_argument("--dependency", action="append", default=[])
    prepare.add_argument(
        "--acceptance",
        action="append",
        default=[],
        metavar="ID|CRITERION|VERIFICATION",
        help="repeatable acceptance criterion in ID|criterion|verification format",
    )
    prepare.add_argument("--acceptance-json", type=Path)
    prepare.add_argument("--read-scope", action="append", default=[])
    prepare.add_argument("--write-scope", action="append", default=[])
    prepare.add_argument("--forbidden-scope", action="append", default=[])
    prepare.add_argument("--tool", action="append", default=[])
    prepare.add_argument("--artifact-type", action="append", default=[])
    prepare.add_argument("--network", action="store_true")
    prepare.add_argument("--external-mutations", action="store_true")
    prepare.add_argument("--authorized-external-mutations", action="store_true")
    prepare.add_argument("--expires-hours", type=int, default=24)
    prepare.add_argument("--output", type=Path)

    invoke = subparsers.add_parser("invoke-http")
    invoke.add_argument("--project-root", required=True, type=Path)
    invoke.add_argument("--adapter", required=True)
    invoke.add_argument("--task-file", required=True, type=Path)
    invoke.add_argument("--timeout-seconds", type=int, default=120)
    invoke.add_argument("--execute", action="store_true")
    invoke.add_argument("--authorization-actor")
    invoke.add_argument("--authorization-reason")

    verify = subparsers.add_parser("verify-webhook")
    verify.add_argument("--project-root", required=True, type=Path)
    verify.add_argument("--adapter", required=True)
    verify.add_argument("--key-id", required=True)
    verify.add_argument("--body-file", required=True, type=Path)
    verify.add_argument("--signature", required=True)
    verify.add_argument("--timestamp", required=True)
    verify.add_argument("--tolerance-seconds", type=int, default=300)
    verify.add_argument("--output", type=Path)

    validate = subparsers.add_parser("validate-envelope")
    validate.add_argument("--kind", choices=["task", "result", "event"], required=True)
    validate.add_argument("--file", required=True, type=Path)

    args = parser.parse_args()
    try:
        if args.command == "prepare-task":
            return command_prepare_task(args)
        if args.command == "invoke-http":
            return command_invoke_http(args)
        if args.command == "verify-webhook":
            return command_verify_webhook(args)
        if args.command == "validate-envelope":
            return command_validate(args)
        raise LifecycleError(f"Unsupported command: {args.command}")
    except (LifecycleError, OSError, KeyError, TypeError, ValueError) as exc:
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

#!/usr/bin/env python3
"""Validate lifecycle configuration, registry, state, and referenced resources."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema.exceptions import SchemaError
except ImportError:  # pragma: no cover - exercised in dependency-isolation tests
    Draft202012Validator = None  # type: ignore[assignment]
    FormatChecker = None  # type: ignore[assignment]
    SchemaError = Exception  # type: ignore[assignment,misc]

from _lifecycle import (
    LifecycleError,
    contained_path,
    load_json,
    resolve_root,
    validate_all,
)


SECRET_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "password",
    "private_key",
    "client_secret",
    "secret_value",
    "token",
    "secret",
    "authorization",
    "cookie",
    "session",
    "session_cookie",
    "credential",
    "credentials",
}


def find_secret_fields(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key.lower() in SECRET_KEYS and isinstance(child, str) and child:
                findings.append(child_path)
            findings.extend(find_secret_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(find_secret_fields(child, f"{path}[{index}]"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = resolve_root(args.project_root)
        config, registry, state = validate_all(root)
        errors: list[str] = []
        warnings: list[str] = []

        if Draft202012Validator is None or FormatChecker is None:
            raise LifecycleError(
                "The jsonschema package is required for fail-closed lifecycle validation"
            )

        schema_root = Path(__file__).resolve().parent.parent / "references" / "schemas"
        project_schema = load_json(schema_root / "project.schema.json")
        try:
            Draft202012Validator.check_schema(project_schema)
            project_validator = Draft202012Validator(
                project_schema, format_checker=FormatChecker()
            )
        except SchemaError as exc:
            raise LifecycleError(f"Invalid project JSON Schema: {exc.message}") from exc
        for issue in sorted(project_validator.iter_errors(config), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in issue.absolute_path) or "$"
            errors.append(f"project.json {location}: {issue.message}")

        control = root / ".ai-lifecycle"
        secret_fields = find_secret_fields(config) + find_secret_fields(registry)
        if secret_fields:
            errors.append(
                "Configuration contains secret-value fields; use environment-variable names instead: "
                + ", ".join(secret_fields)
            )

        for phase in config["lifecycle"]["phases"]:
            gate = config["quality_gates"].get(phase)
            if not isinstance(gate, dict):
                errors.append(f"Missing quality gate definition for phase: {phase}")
                continue
            required_artifacts = gate.get("required_artifacts", [])
            checks = gate.get("checks", [])
            if not isinstance(required_artifacts, list) or not all(
                isinstance(item, str) for item in required_artifacts
            ):
                errors.append(f"{phase}.required_artifacts must be an array of relative paths")
            else:
                for artifact in required_artifacts:
                    try:
                        contained_path(root, artifact)
                    except LifecycleError as exc:
                        errors.append(str(exc))
            if not isinstance(checks, list):
                errors.append(f"{phase}.checks must be an array")
                continue
            for index, check in enumerate(checks):
                prefix = f"{phase}.checks[{index}]"
                if not isinstance(check, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                for key in ("id", "description", "required", "command", "cwd", "timeout_seconds"):
                    if key not in check:
                        errors.append(f"{prefix}.{key} is required")
                command = check.get("command")
                if not isinstance(command, list) or not command or not all(
                    isinstance(item, str) and item for item in command
                ):
                    errors.append(f"{prefix}.command must be a non-empty argument array")
                if not isinstance(check.get("required"), bool):
                    errors.append(f"{prefix}.required must be boolean")
                timeout = check.get("timeout_seconds")
                if not isinstance(timeout, int) or not 1 <= timeout <= 7200:
                    errors.append(f"{prefix}.timeout_seconds must be between 1 and 7200")
                try:
                    contained_path(root, check.get("cwd", "."))
                except LifecycleError as exc:
                    errors.append(str(exc))
                forward_env = check.get("forward_env", [])
                if not isinstance(forward_env, list) or not all(
                    isinstance(item, str) and item for item in forward_env
                ):
                    errors.append(f"{prefix}.forward_env must be an array of environment-variable names")

            if phase == "deployment":
                unsafe_pre_artifacts = {
                    ".ai-lifecycle/artifacts/deployment/deployment-record.json",
                    ".ai-lifecycle/artifacts/deployment/post-deployment-verification.json",
                }.intersection(required_artifacts if isinstance(required_artifacts, list) else [])
                if unsafe_pre_artifacts:
                    errors.append(
                        "deployment pre-authorization gate contains post-deployment artifacts; "
                        "move them to post_required_artifacts"
                    )
                post_artifacts = gate.get("post_required_artifacts", [])
                if not isinstance(post_artifacts, list) or not all(
                    isinstance(item, str) for item in post_artifacts
                ):
                    errors.append("deployment.post_required_artifacts must be an array of relative paths")
                else:
                    for artifact in post_artifacts:
                        try:
                            contained_path(root, artifact)
                        except LifecycleError as exc:
                            errors.append(str(exc))
                post_checks = gate.get("post_checks", [])
                if not isinstance(post_checks, list):
                    errors.append("deployment.post_checks must be an array")
                else:
                    for index, check in enumerate(post_checks):
                        prefix = f"deployment.post_checks[{index}]"
                        if not isinstance(check, dict):
                            errors.append(f"{prefix} must be an object")
                            continue
                        for key in ("id", "description", "required", "command", "cwd", "timeout_seconds"):
                            if key not in check:
                                errors.append(f"{prefix}.{key} is required")
                        command = check.get("command")
                        if not isinstance(command, list) or not command or not all(
                            isinstance(item, str) and item for item in command
                        ):
                            errors.append(f"{prefix}.command must be a non-empty argument array")
                        if not isinstance(check.get("required"), bool):
                            errors.append(f"{prefix}.required must be boolean")
                        timeout = check.get("timeout_seconds")
                        if not isinstance(timeout, int) or not 1 <= timeout <= 7200:
                            errors.append(f"{prefix}.timeout_seconds must be between 1 and 7200")
                        try:
                            contained_path(root, check.get("cwd", "."))
                        except LifecycleError as exc:
                            errors.append(str(exc))

        registry_path = config["integration"].get("tool_registry")
        if registry_path != ".ai-lifecycle/tool-registry.json":
            try:
                contained_path(root, registry_path, must_exist=True)
            except LifecycleError as exc:
                errors.append(str(exc))

        for folder in ("artifacts", "evidence", "tasks", "events", "logs"):
            if not (control / folder).is_dir():
                errors.append(f"Missing lifecycle directory: .ai-lifecycle/{folder}")

        unknown_tools = [
            tool["id"]
            for tool in registry["tools"]
            if tool.get("availability") == "unknown"
        ]
        if unknown_tools:
            warnings.append(
                "Tool availability has not been verified: " + ", ".join(unknown_tools)
            )

        gate_without_automation = [
            phase
            for phase in config["lifecycle"]["phases"]
            if not config["quality_gates"][phase].get("checks")
        ]
        if gate_without_automation:
            warnings.append(
                "These phases currently rely on artifact review and configured human gates: "
                + ", ".join(gate_without_automation)
            )

        for schema_path in schema_root.glob("*.json"):
            schema = load_json(schema_path)
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as exc:
                errors.append(f"Invalid JSON Schema {schema_path.name}: {exc.message}")

        result = {
            "valid": not errors,
            "project_id": config["project"]["id"],
            "lifecycle_run_id": state["lifecycle_run_id"],
            "current_phase": state["current_phase"],
            "phase_statuses": {
                phase: details["status"] for phase, details in state["phases"].items()
            },
            "errors": errors,
            "warnings": warnings,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if not errors else 1
    except (LifecycleError, OSError, KeyError, TypeError) as exc:
        print(
            json.dumps(
                {"valid": False, "errors": [str(exc)], "warnings": []},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

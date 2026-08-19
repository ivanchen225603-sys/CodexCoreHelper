#!/usr/bin/env python3
"""Discover local lifecycle tool availability without authenticating or mutating providers."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from _lifecycle import (
    LifecycleError,
    atomic_write_json,
    contained_control_path,
    lifecycle_lock,
    redact,
    require_trusted_project,
    resolve_root,
    safe_subprocess_environment,
    utc_now,
    validate_all,
)
from process_runner import ProcessExecutionError, run_bounded_process


def version_of(
    executable: str, arguments: list[str], *, cwd: Path
) -> tuple[str | None, str | None, str]:
    resolved = shutil.which(executable)
    if not resolved:
        return None, None, "unavailable"
    try:
        completed = run_bounded_process(
            [resolved, *arguments],
            cwd=cwd,
            environment=safe_subprocess_environment([]),
            timeout_seconds=15,
            max_stdout_bytes=64 * 1024,
            max_stderr_bytes=64 * 1024,
        )
        output = (completed.stdout or completed.stderr).strip().splitlines()
        version = redact(output[0])[:500] if output else f"exit-{completed.returncode}"
        availability = "available" if completed.returncode == 0 else "blocked"
        return resolved, version, availability
    except (OSError, ProcessExecutionError) as exc:
        return resolved, f"probe-error: {redact(str(exc))}", "blocked"


def set_probe(
    tool: dict[str, Any],
    resolved: str | None,
    version: str | None,
    availability: str,
) -> None:
    tool["availability"] = availability
    tool["last_verified_at"] = utc_now()
    tool["health"] = {
        "method": "local-cli-version",
        "resolved_executable": resolved,
        "version": version,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Persist verified local availability to tool-registry.json",
    )
    args = parser.parse_args()
    try:
        root = resolve_root(args.project_root)
        if args.write:
            require_trusted_project(root, "tool discovery registry update")
        config, registry, _ = validate_all(root)
        original_registry = json.loads(json.dumps(registry))
        report: dict[str, Any] = {
            "verified_at": utc_now(),
            "local_tools": {},
            "project_signals": {},
            "persisted": args.write,
        }

        probes = {
            "git": ("git", ["--version"]),
            "codex": ("codex", ["--version"]),
            "claude-code": ("claude", ["--version"]),
            "dotnet": ("dotnet", ["--version"]),
            "node": ("node", ["--version"]),
            "python": ("python", ["--version"]),
            "docker": ("docker", ["--version"]),
            "kubectl": ("kubectl", ["version", "--client"]),
            "terraform": ("terraform", ["version"]),
        }
        probe_results: dict[str, tuple[str | None, str | None, str]] = {}
        probe_cwd = Path(tempfile.gettempdir()).resolve()
        for identifier, (executable, arguments) in probes.items():
            resolved, version, availability = version_of(
                executable, arguments, cwd=probe_cwd
            )
            probe_results[identifier] = (resolved, version, availability)
            report["local_tools"][identifier] = {
                "availability": availability,
                "resolved_executable": resolved,
                "version": version,
            }

        workflow_paths = [
            ".github/workflows",
            ".gitlab-ci.yml",
            "azure-pipelines.yml",
            "Jenkinsfile",
            ".circleci/config.yml",
            "buildkite.yml",
        ]
        deployment_paths = [
            "Dockerfile",
            "compose.yaml",
            "compose.yml",
            "k8s",
            "kubernetes",
            "terraform",
            "infra",
        ]
        report["project_signals"]["ci"] = [
            path for path in workflow_paths if (root / path).exists()
        ]
        report["project_signals"]["deployment"] = [
            path for path in deployment_paths if (root / path).exists()
        ]
        report["project_signals"]["configured_gate_checks"] = sum(
            len(gate.get("checks", []))
            for gate in config["quality_gates"].values()
        )

        for tool in registry["tools"]:
            tool_id = tool["id"]
            if tool_id == "repository-native":
                tool["availability"] = "available"
                tool["last_verified_at"] = utc_now()
                tool["health"] = {
                    "method": "repository-access",
                    "project_root": ".",
                }
            elif tool_id in {"codex", "claude-code"}:
                resolved, version, availability = probe_results[tool_id]
                set_probe(tool, resolved, version, availability)
            elif tool_id == "source-control":
                resolved, version, availability = probe_results["git"]
                if availability == "available":
                    tool["availability"] = "available"
                    tool["provider"] = "git-local"
                    tool["transport"] = "cli"
                    tool["last_verified_at"] = utc_now()
                    tool["health"] = {
                        "method": "local-cli-version",
                        "resolved_executable": resolved,
                        "version": version,
                    }
            elif tool_id == "test-platform":
                checks = config["quality_gates"].get("implementation", {}).get("checks", [])
                if any(item.get("evidence_type") == "test" for item in checks):
                    tool["availability"] = "available"
                    tool["provider"] = "repository-native"
                    tool["transport"] = "native"
                    tool["last_verified_at"] = utc_now()
                    tool["health"] = {
                        "method": "configured-test-command",
                        "checks": [
                            item["id"]
                            for item in checks
                            if item.get("evidence_type") == "test"
                        ],
                    }

        if args.write:
            with lifecycle_lock(root, "tool-registry"):
                _, latest_registry, _ = validate_all(root)
                if latest_registry != original_registry:
                    raise LifecycleError(
                        "tool-registry.json changed during discovery; rerun before writing"
                    )
                atomic_write_json(
                    contained_control_path(
                        root, ".ai-lifecycle/tool-registry.json", must_exist=True
                    ),
                    registry,
                )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
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

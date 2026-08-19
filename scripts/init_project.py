#!/usr/bin/env python3
"""Initialize portable lifecycle control files in a software repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable

from _lifecycle import (
    LifecycleError,
    PHASES,
    atomic_write_json,
    atomic_write_text,
    initial_state,
    resolve_root,
    utc_now,
    validate_json_schema_document,
    validate_project_config,
    validate_registry,
    validate_state,
)


IGNORED_DIRECTORIES = {
    ".git",
    ".ai-lifecycle",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "node_modules",
    "bin",
    "obj",
    "dist",
    "build",
    "target",
    "vendor",
    "coverage",
}


def slugify(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._").lower()
    return value or f"project-{uuid.uuid4().hex[:8]}"


def repository_files(root: Path, limit: int = 12_000) -> Iterable[Path]:
    yielded = 0
    for directory, names, files in os.walk(root):
        names[:] = [name for name in names if name not in IGNORED_DIRECTORIES]
        base = Path(directory)
        for name in files:
            path = base / name
            try:
                metadata = path.lstat()
            except OSError:
                continue
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            attributes = getattr(metadata, "st_file_attributes", 0)
            if path.is_symlink() or bool(reparse_flag and attributes & reparse_flag):
                continue
            yield path
            yielded += 1
            if yielded >= limit:
                return


def read_text_if_small(path: Path, limit: int = 2_000_000) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def detect_stack(root: Path) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    files = list(repository_files(root))
    relative_names = {path.relative_to(root).as_posix() for path in files}
    file_names = {path.name for path in files}
    extensions = {path.suffix.lower() for path in files}

    languages: list[str] = []
    frameworks: list[str] = []
    package_managers: list[str] = []
    build_systems: list[str] = []
    databases: list[str] = []
    deployment_targets: list[str] = []
    checks: list[dict[str, Any]] = []

    def add_unique(target: list[str], value: str) -> None:
        if value not in target:
            target.append(value)

    def add_check(
        check_id: str,
        description: str,
        command: list[str],
        evidence_type: str,
        timeout: int = 1200,
    ) -> None:
        if any(item["id"] == check_id for item in checks):
            return
        checks.append(
            {
                "id": check_id,
                "description": description,
                "required": True,
                "command": command,
                "cwd": ".",
                "timeout_seconds": timeout,
                "forward_env": [],
                "evidence_type": evidence_type,
            }
        )

    if ".cs" in extensions or any(
        name.endswith((".csproj", ".sln", ".slnx")) for name in file_names
    ):
        add_unique(languages, "C#")
        add_unique(package_managers, "NuGet")
        add_unique(build_systems, "dotnet")
        project_text = "\n".join(
            read_text_if_small(path)
            for path in files
            if path.suffix.lower() == ".csproj"
        )
        if "Microsoft.NET.Sdk.Web" in project_text or "AspNetCore" in project_text:
            add_unique(frameworks, "ASP.NET Core")
        dotnet_lock_present = "packages.lock.json" in file_names
        dotnet_restore = ["dotnet", "restore"]
        dotnet_restore_description = "Restore .NET dependencies"
        if dotnet_lock_present:
            dotnet_restore.append("--locked-mode")
            dotnet_restore_description = "Restore locked .NET dependencies"
        add_check(
            "dotnet-restore",
            dotnet_restore_description,
            dotnet_restore,
            "dependency",
        )
        add_check(
            "dotnet-build",
            "Build the .NET solution",
            ["dotnet", "build", "--no-restore"],
            "build",
        )
        if any(
            "test" in part.lower()
            for path in files
            for part in path.parts
            if path.suffix.lower() == ".csproj"
        ):
            add_check(
                "dotnet-test",
                "Run .NET tests",
                ["dotnet", "test", "--no-restore"],
                "test",
            )

    package_path = root / "package.json"
    if package_path.exists():
        add_unique(languages, "JavaScript/TypeScript")
        scripts: dict[str, Any] = {}
        dependencies: dict[str, Any] = {}
        try:
            package = json.loads(package_path.read_text(encoding="utf-8"))
            scripts = (
                package.get("scripts", {})
                if isinstance(package.get("scripts"), dict)
                else {}
            )
            dependencies = {
                **(
                    package.get("dependencies", {})
                    if isinstance(package.get("dependencies"), dict)
                    else {}
                ),
                **(
                    package.get("devDependencies", {})
                    if isinstance(package.get("devDependencies"), dict)
                    else {}
                ),
            }
        except (OSError, json.JSONDecodeError):
            pass
        for dependency, framework in (
            ("next", "Next.js"),
            ("react", "React"),
            ("vue", "Vue"),
            ("@angular/core", "Angular"),
            ("svelte", "Svelte"),
            ("express", "Express"),
            ("nestjs", "NestJS"),
        ):
            if dependency in dependencies:
                add_unique(frameworks, framework)
        if "pnpm-lock.yaml" in file_names:
            manager = "pnpm"
            install = ["pnpm", "install", "--frozen-lockfile"]
        elif "yarn.lock" in file_names:
            manager = "yarn"
            install = ["yarn", "install", "--immutable"]
        elif "bun.lock" in file_names or "bun.lockb" in file_names:
            manager = "bun"
            install = ["bun", "install", "--frozen-lockfile"]
        elif "package-lock.json" in file_names or "npm-shrinkwrap.json" in file_names:
            manager = "npm"
            install = ["npm", "ci"]
        else:
            manager = "npm"
            install = None
        add_unique(package_managers, manager)
        add_unique(
            build_systems, scripts.get("build") and f"{manager} scripts" or manager
        )
        if install is not None:
            add_check(
                "node-install",
                f"Install {manager} dependencies from the lockfile",
                install,
                "dependency",
            )
        for script, evidence in (
            ("lint", "static-analysis"),
            ("test", "test"),
            ("build", "build"),
        ):
            if script in scripts:
                add_check(
                    f"node-{script}",
                    f"Run package {script} script",
                    [manager, "run", script],
                    evidence,
                )

    pyproject_path = root / "pyproject.toml"
    requirements_present = any(
        name.startswith("requirements") and name.endswith(".txt") for name in file_names
    )
    if ".py" in extensions or pyproject_path.exists() or requirements_present:
        add_unique(languages, "Python")
        if pyproject_path.exists():
            add_unique(package_managers, "pyproject")
            pyproject = read_text_if_small(pyproject_path).lower()
            for token, framework in (
                ("fastapi", "FastAPI"),
                ("django", "Django"),
                ("flask", "Flask"),
                ("pytest", "pytest"),
            ):
                if token in pyproject:
                    add_unique(frameworks, framework)
            if "pytest" in pyproject or "tests" in file_names:
                add_check(
                    "python-test",
                    "Run Python tests",
                    ["python", "-m", "pytest"],
                    "test",
                )
            if "ruff" in pyproject:
                add_check(
                    "python-lint",
                    "Run Ruff static analysis",
                    ["python", "-m", "ruff", "check", "."],
                    "static-analysis",
                )
        elif requirements_present:
            add_unique(package_managers, "pip")

    if ".go" in extensions or "go.mod" in file_names:
        add_unique(languages, "Go")
        add_unique(package_managers, "Go modules")
        add_unique(build_systems, "go")
        add_check("go-test", "Run Go tests", ["go", "test", "./..."], "test")
        add_check("go-vet", "Run Go vet", ["go", "vet", "./..."], "static-analysis")

    if ".rs" in extensions or "Cargo.toml" in file_names:
        add_unique(languages, "Rust")
        add_unique(package_managers, "Cargo")
        add_unique(build_systems, "Cargo")
        add_check("cargo-test", "Run Rust tests", ["cargo", "test", "--locked"], "test")
        add_check(
            "cargo-clippy",
            "Run Clippy",
            ["cargo", "clippy", "--locked", "--", "-D", "warnings"],
            "static-analysis",
        )

    if (
        ".java" in extensions
        or "pom.xml" in file_names
        or "build.gradle" in file_names
        or "build.gradle.kts" in file_names
    ):
        add_unique(languages, "Java")
        if "pom.xml" in file_names:
            add_unique(package_managers, "Maven")
            add_unique(build_systems, "Maven")
            add_check("maven-test", "Run Maven verification", ["mvn", "verify"], "test")
        if "gradlew" in file_names or "gradlew.bat" in file_names:
            add_unique(package_managers, "Gradle")
            add_unique(build_systems, "Gradle")
            wrapper = "gradlew.bat" if os.name == "nt" else "./gradlew"
            add_check("gradle-test", "Run Gradle tests", [wrapper, "test"], "test")

    combined_config = "\n".join(
        read_text_if_small(path).lower()
        for path in files
        if path.name.lower()
        in {
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
            "appsettings.json",
            "application.yml",
            "application.yaml",
            ".env.example",
        }
    )
    for token, database in (
        ("postgres", "PostgreSQL"),
        ("mysql", "MySQL"),
        ("mariadb", "MariaDB"),
        ("mongodb", "MongoDB"),
        ("redis", "Redis"),
        ("sqlite", "SQLite"),
        ("sqlserver", "SQL Server"),
    ):
        if token in combined_config:
            add_unique(databases, database)

    if "Dockerfile" in file_names or any(
        name.startswith("Dockerfile.") for name in file_names
    ):
        add_unique(deployment_targets, "Container")
    if any(
        name.endswith((".yaml", ".yml")) and ("k8s/" in name or "kubernetes/" in name)
        for name in relative_names
    ):
        add_unique(deployment_targets, "Kubernetes")
    if ".tf" in extensions:
        add_unique(deployment_targets, "Terraform-managed infrastructure")
    if ".github/workflows" in relative_names or any(
        name.startswith(".github/workflows/") for name in relative_names
    ):
        add_unique(build_systems, "GitHub Actions")

    if (root / ".git").exists():
        add_check(
            "git-diff-check",
            "Check patch whitespace and conflict markers",
            ["git", "diff", "--check"],
            "source-hygiene",
            300,
        )

    stack = {
        "languages": languages,
        "frameworks": frameworks,
        "package_managers": package_managers,
        "build_systems": build_systems,
        "databases": databases,
        "deployment_targets": deployment_targets,
    }
    return stack, checks


def phase_gates(implementation_checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "discovery": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/discovery/source-requirement.md"
            ],
            "checks": [],
        },
        "requirements": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/requirements/requirements.json",
                ".ai-lifecycle/artifacts/requirements/acceptance-criteria.json",
                ".ai-lifecycle/artifacts/requirements/traceability.json",
            ],
            "checks": [],
        },
        "architecture": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/architecture/architecture-overview.md",
                ".ai-lifecycle/artifacts/architecture/decision-log.md",
            ],
            "checks": [],
        },
        "prototype": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/prototype/prototype-manifest.json",
                ".ai-lifecycle/artifacts/prototype/flow-map.md",
            ],
            "checks": [],
        },
        "implementation": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/implementation/implementation-notes.md"
            ],
            "checks": implementation_checks,
        },
        "review": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/review/review-findings.json",
                ".ai-lifecycle/artifacts/review/review-summary.md",
            ],
            "checks": [],
        },
        "verification": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/verification/test-plan.md",
                ".ai-lifecycle/artifacts/verification/acceptance-test-trace.json",
            ],
            "checks": [],
        },
        "integration": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/integration/release-candidate.json",
                ".ai-lifecycle/artifacts/integration/release-readiness.md",
            ],
            "checks": [],
        },
        "deployment": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/deployment/deployment-plan.json",
                ".ai-lifecycle/artifacts/deployment/environment-readiness.json",
                ".ai-lifecycle/artifacts/deployment/rollback-plan.md",
            ],
            "checks": [],
            "post_required_artifacts": [
                ".ai-lifecycle/artifacts/deployment/deployment-record.json",
                ".ai-lifecycle/artifacts/deployment/post-deployment-verification.json",
            ],
            "post_checks": [],
        },
        "operations": {
            "required_artifacts": [
                ".ai-lifecycle/artifacts/operations/operational-readiness.md"
            ],
            "checks": [],
        },
    }


def parse_disabled(values: list[str]) -> dict[str, str]:
    disabled: dict[str, str] = {}
    for value in values:
        phase, separator, reason = value.partition("=")
        if not separator or phase not in PHASES or not reason.strip():
            raise LifecycleError(
                "--disable-phase values must use canonical-phase=non-empty-reason"
            )
        disabled[phase] = reason.strip()
    return disabled


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--name")
    parser.add_argument("--project-type", default="auto")
    parser.add_argument(
        "--risk", choices=["low", "standard", "high"], default="standard"
    )
    parser.add_argument("--description", default="")
    requirement = parser.add_mutually_exclusive_group(required=True)
    requirement.add_argument("--requirement")
    requirement.add_argument("--requirement-file", type=Path)
    parser.add_argument(
        "--disable-phase",
        action="append",
        default=[],
        metavar="PHASE=REASON",
    )
    args = parser.parse_args()

    try:
        root = resolve_root(args.project_root)
        control = root / ".ai-lifecycle"
        if os.path.lexists(control):
            raise LifecycleError(
                f"Lifecycle control directory already exists: {control}. Use validate_project.py to resume or inspect the partial directory."
            )

        if args.requirement_file:
            supplied_requirement_path = Path(
                os.path.abspath(args.requirement_file.expanduser())
            )
            if supplied_requirement_path.is_symlink():
                raise LifecycleError("The source requirement file must not be a link")
            requirement_path = supplied_requirement_path.resolve()
            if not requirement_path.is_file():
                raise LifecycleError("The source requirement must be a regular file")
            with requirement_path.open("rb") as requirement_stream:
                requirement_payload = requirement_stream.read(1024 * 1024 + 1)
            if len(requirement_payload) > 1024 * 1024:
                raise LifecycleError("The source requirement file exceeds 1 MiB")
            try:
                requirement_text = requirement_payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LifecycleError("The source requirement file must be UTF-8") from exc
            requirement_source = str(requirement_path)
        else:
            requirement_text = args.requirement or ""
            requirement_source = "user-input"
        if not requirement_text.strip():
            raise LifecycleError("The source requirement cannot be empty")

        disabled = parse_disabled(args.disable_phase)
        enabled = [phase for phase in PHASES if phase not in disabled]
        if not enabled:
            raise LifecycleError("At least one lifecycle phase must remain enabled")
        if "deployment" in disabled and "operations" in enabled:
            raise LifecycleError(
                "operations cannot remain enabled when deployment is disabled"
            )
        if "deployment" in enabled:
            deployment_obligations = {
                "requirements",
                "architecture",
                "implementation",
                "review",
                "verification",
                "integration",
            }
            missing = sorted(deployment_obligations - set(enabled))
            if missing:
                raise LifecycleError(
                    "deployment cannot remain enabled when required lifecycle phases are disabled: "
                    + ", ".join(missing)
                )

        project_name = args.name or root.name
        stack, detected_checks = detect_stack(root)
        approvals = [
            phase
            for phase in [
                "requirements",
                "architecture",
                "prototype",
                "verification",
                "deployment",
            ]
            if phase in enabled
        ]
        config = {
            "schema_version": 1,
            "project": {
                "id": slugify(project_name),
                "name": project_name,
                "type": args.project_type,
                "repository_root": ".",
                "risk_level": args.risk,
                "description": args.description,
            },
            "stack": stack,
            "lifecycle": {
                "phases": enabled,
                "disabled": disabled,
                "human_approvals": approvals,
                "promotion_matrix": {
                    "schema_version": 1,
                    "artifact_layout": "environment-subdirectories",
                    "enforce_immutable_digest": True,
                    "environments": [
                        {
                            "name": "development",
                            "approval_policy": "human-required",
                            "final": False,
                        },
                        {
                            "name": "test",
                            "approval_policy": "human-required",
                            "final": False,
                        },
                        {
                            "name": "staging",
                            "approval_policy": "human-required",
                            "final": False,
                        },
                        {
                            "name": "production",
                            "approval_policy": "human-required",
                            "final": True,
                        },
                    ],
                },
            },
            "agents": {
                "enabled": True,
                "max_parallel": 3,
                "ownership_strategy": "exclusive-path",
                "roles": [
                    "discovery-analyst",
                    "requirements-analyst",
                    "architect",
                    "product-designer",
                    "implementer",
                    "reviewer",
                    "quality-engineer",
                    "security-reviewer",
                    "release-engineer",
                    "operations-analyst",
                ],
            },
            "quality_gates": {
                phase: gate
                for phase, gate in phase_gates(detected_checks).items()
                if phase in enabled
            },
            "integration": {
                "tool_registry": ".ai-lifecycle/tool-registry.json",
                "default_timeout_seconds": 1200,
                "retry": {
                    "max_attempts": 3,
                    "base_delay_seconds": 2,
                    "max_delay_seconds": 30,
                },
                "evidence_retention_days": 90,
            },
            "policy": {
                "external_mutations": "require-explicit-authority",
                "production_approval": "human-required",
                "secrets": "environment-or-secret-manager",
                "network": "least-required",
                "data_classification": "internal",
            },
        }
        if "deployment" not in enabled:
            config["lifecycle"].pop("promotion_matrix", None)

        skill_root = Path(__file__).resolve().parent.parent
        registry = json.loads(
            (skill_root / "assets" / "tool-registry.template.json").read_text(
                encoding="utf-8"
            )
        )
        run_id = f"lifecycle-{uuid.uuid4()}"
        state = initial_state(config, run_id)
        validation_errors = (
            validate_project_config(config)
            + validate_registry(registry)
            + validate_state(config, state)
            + validate_json_schema_document(
                config,
                skill_root / "references" / "schemas" / "project.schema.json",
                "generated project.json",
            )
        )
        if validation_errors:
            raise LifecycleError(
                "Refusing to initialize an invalid lifecycle: "
                + "; ".join(validation_errors)
            )

        requirement_document = (
            "# Source requirement\n\n"
            f"- Captured at: {utc_now()}\n"
            f"- Source: {requirement_source}\n"
            f"- Lifecycle run: {run_id}\n\n"
            "## Requirement\n\n"
            f"{requirement_text.strip()}\n"
        )
        with tempfile.TemporaryDirectory(
            prefix=".ai-lifecycle-init-",
            dir=root,
        ) as staging_name:
            staging_control = Path(staging_name)
            for folder in (
                "artifacts",
                "evidence",
                "tasks",
                "events",
                "logs",
                "locks",
            ):
                (staging_control / folder).mkdir(parents=True, exist_ok=True)
            for phase in enabled:
                (staging_control / "artifacts" / phase).mkdir(
                    parents=True, exist_ok=True
                )
                (staging_control / "evidence" / phase).mkdir(
                    parents=True, exist_ok=True
                )
            if "deployment" in enabled:
                for environment in config["lifecycle"]["promotion_matrix"][
                    "environments"
                ]:
                    name = environment["name"]
                    (staging_control / "artifacts" / "deployment" / name).mkdir(
                        parents=True, exist_ok=True
                    )
                    (staging_control / "evidence" / "deployment" / name).mkdir(
                        parents=True, exist_ok=True
                    )

            atomic_write_json(staging_control / "project.json", config)
            atomic_write_json(staging_control / "tool-registry.json", registry)
            atomic_write_json(staging_control / "state.json", state)
            atomic_write_text(
                staging_control / "artifacts" / "discovery" / "source-requirement.md",
                requirement_document,
            )
            atomic_write_text(
                staging_control / ".gitignore",
                "logs/\nevents/inbox/\ntasks/**/raw-*\n*.tmp\n",
            )
            if os.path.lexists(control):
                raise LifecycleError(
                    "Lifecycle control directory appeared during initialization; refusing to overwrite it"
                )
            os.replace(staging_control, control)
        result = {
            "status": "initialized",
            "project_root": str(root),
            "project_id": config["project"]["id"],
            "lifecycle_run_id": run_id,
            "current_phase": state["current_phase"],
            "detected_stack": stack,
            "detected_implementation_checks": [item["id"] for item in detected_checks],
            "next": "Run validate_project.py, then lifecycle.py start --phase discovery",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (LifecycleError, OSError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

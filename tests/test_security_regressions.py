from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = SKILL_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import _lifecycle  # noqa: E402
import adapter_bridge  # noqa: E402
import approval_identity  # noqa: E402
import init_project  # noqa: E402
import invoke_agent  # noqa: E402
import lifecycle  # noqa: E402
import validate_project  # noqa: E402


RELEASE_DIGEST = "sha256:" + "a" * 64


def iso_time(delta: timedelta = timedelta()) -> str:
    return (
        (datetime.now(timezone.utc) + delta)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class ProjectFixture:
    """Minimal valid local lifecycle project used by command-boundary tests."""

    def __init__(self, active_phase: str = "implementation", status: str = "in_progress"):
        self._temporary = tempfile.TemporaryDirectory()
        self._trust_temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name).resolve()
        self.control = self.root / ".ai-lifecycle"
        self.project_id = "security-regression"
        self.run_id = f"lifecycle-{uuid.uuid4()}"
        self.active_phase = active_phase
        self.approval_private_key = Ed25519PrivateKey.generate()
        public_key = self.approval_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.approval_trust_path = (
            Path(self._trust_temporary.name).resolve() / "approval-trust.json"
        )
        self.approval_trust_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "issuers": [
                        {
                            "issuer": "test-host",
                            "status": "active",
                            "audiences": [approval_identity.ASSERTION_AUDIENCE],
                            "subjects": ["alice@example.invalid"],
                            "keys": [
                                {
                                    "key_id": "test-key",
                                    "status": "active",
                                    "public_key_base64url": base64.urlsafe_b64encode(
                                        public_key
                                    )
                                    .rstrip(b"=")
                                    .decode("ascii"),
                                }
                            ],
                        }
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        phases = list(_lifecycle.PHASES)
        self.config = {
            "schema_version": 1,
            "project": {
                "id": self.project_id,
                "name": "Security regression",
                "type": "test",
                "repository_root": ".",
                "risk_level": "high",
                "description": "Temporary test fixture",
            },
            "stack": {
                "languages": [],
                "frameworks": [],
                "package_managers": [],
                "build_systems": [],
                "databases": [],
                "deployment_targets": [],
            },
            "lifecycle": {
                "phases": phases,
                "disabled": {},
                "human_approvals": [
                    "requirements",
                    "architecture",
                    "prototype",
                    "verification",
                    "deployment",
                ],
            },
            "agents": {
                "enabled": True,
                "max_parallel": 3,
                "ownership_strategy": "worktree",
                "roles": ["implementer", "release-engineer"],
            },
            "quality_gates": {
                phase: {"required_artifacts": [], "checks": []} for phase in phases
            },
            "integration": {
                "tool_registry": ".ai-lifecycle/tool-registry.json",
                "default_timeout_seconds": 120,
                "retry": {
                    "max_attempts": 1,
                    "base_delay_seconds": 0,
                    "max_delay_seconds": 0,
                },
                "evidence_retention_days": 30,
            },
            "policy": {
                "external_mutations": "require-explicit-authority",
                "production_approval": "human-required",
                "secrets": "environment-or-secret-manager",
                "network": "least-required",
                "data_classification": "internal",
            },
        }
        self.config["quality_gates"]["deployment"] = {
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
        }
        self.registry = {
            "schema_version": 1,
            "tools": [
                {
                    "id": "test-http",
                    "display_name": "Local test HTTP adapter",
                    "provider": "test",
                    "kind": "coding-agent",
                    "capabilities": ["task.submit"],
                    "transport": "http",
                    "availability": "available",
                    "http": {"task_url": "https://adapter.example.invalid/v1/tasks"},
                    "authentication": {"type": "none", "environment_variables": []},
                    "side_effects": ["job-trigger"],
                    "approval": "task-scope",
                },
                {
                    "id": "trusted-webhook",
                    "display_name": "Trusted webhook source",
                    "provider": "test",
                    "kind": "ci",
                    "capabilities": ["event.deliver"],
                    "transport": "webhook",
                    "availability": "available",
                    "webhook": {
                        "keys": [
                            {
                                "key_id": "test-key-1",
                                "algorithm": "hmac-sha256",
                                "secret_env_var": "TEST_WEBHOOK_SECRET",
                            }
                        ]
                    },
                    "authentication": {
                        "type": "hmac",
                        "environment_variables": ["TEST_WEBHOOK_SECRET"],
                    },
                    "side_effects": ["external-read"],
                    "approval": "task-scope",
                },
                {
                    "id": "codex",
                    "display_name": "Fake Codex executable",
                    "provider": "test",
                    "kind": "coding-agent",
                    "capabilities": ["code.edit"],
                    "transport": "cli",
                    "availability": "available",
                    "cli": {"executable": sys.executable},
                    "authentication": {"type": "none", "environment_variables": []},
                    "side_effects": ["workspace-write"],
                    "approval": "task-permissions",
                },
            ],
        }
        self.state = _lifecycle.initial_state(self.config, self.run_id)
        active_index = phases.index(active_phase)
        now = iso_time()
        for index, phase in enumerate(phases):
            details = self.state["phases"][phase]
            details["status"] = (
                "approved" if index < active_index else status if index == active_index else "locked"
            )
            details["updated_at"] = now
        self.state["current_phase"] = active_phase

        for folder in ("artifacts", "evidence", "tasks", "events", "logs", "locks"):
            (self.control / folder).mkdir(parents=True, exist_ok=True)
        self.write_json(self.control / "project.json", self.config)
        self.write_json(self.control / "tool-registry.json", self.registry)
        self.write_state()

    def close(self) -> None:
        self._temporary.cleanup()
        self._trust_temporary.cleanup()

    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def write_state(self) -> None:
        self.write_json(self.control / "state.json", self.state)

    def task(self, **updates: object) -> tuple[dict[str, object], Path]:
        task_id = "task-valid-0001"
        task: dict[str, object] = {
            "spec_version": "1.0.0",
            "task_id": task_id,
            "revision": 1,
            "created_at": iso_time(timedelta(minutes=-1)),
            "expires_at": iso_time(timedelta(hours=1)),
            "correlation_id": "corr-valid-0001",
            "causation_id": None,
            "project_id": self.project_id,
            "lifecycle_run_id": self.run_id,
            "phase": self.active_phase,
            "role": "implementer",
            "objective": "Exercise a security boundary without external side effects.",
            "inputs": [],
            "constraints": ["No network"],
            "assumptions": [],
            "dependencies": [],
            "acceptance_criteria": [
                {
                    "id": "ac-1",
                    "text": "The boundary rejects invalid input.",
                    "verification": "Run this unittest.",
                }
            ],
            "permissions": {
                "read": ["."],
                "write": [],
                "network": True,
                "external_mutations": False,
            },
            "ownership": {"write_scope": [], "forbidden_scope": [".ai-lifecycle"]},
            "tool_preferences": ["test-http"],
            "output_contract": {
                "result_schema": (
                    f".ai-lifecycle/tasks/{task_id}/result-envelope.schema.json"
                ),
                "artifact_types": [],
            },
            "callback": None,
            "retry_policy": {
                "max_attempts": 1,
                "base_delay_seconds": 0,
                "max_delay_seconds": 0,
            },
        }
        task.update(updates)
        directory = self.control / "tasks" / str(task["task_id"])
        task_path = directory / "task.json"
        schema_source = SKILL_ROOT / "references" / "schemas" / "result-envelope.schema.json"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "result-envelope.schema.json").write_bytes(schema_source.read_bytes())
        self.write_json(task_path, task)
        return task, task_path

    def event(self, **updates: object) -> tuple[dict[str, object], Path, str, str]:
        event: dict[str, object] = {
            "spec_version": "1.0.0",
            "event_id": f"event-{uuid.uuid4()}",
            "event_type": "task.completed",
            "occurred_at": iso_time(),
            "source": {"adapter_id": "trusted-webhook", "run_id": "provider-run-0001"},
            "subject": {
                "project_id": self.project_id,
                "lifecycle_run_id": self.run_id,
                "phase": self.active_phase,
                "task_id": "task-valid-0001",
            },
            "data": {},
            "artifacts": [],
            "trace": {"correlation_id": "corr-valid-0001", "causation_id": None},
            "delivery": {"attempt": 1, "idempotency_key": f"delivery-{uuid.uuid4()}"},
            "security": {"key_id": "test-key-1", "algorithm": "hmac-sha256"},
        }
        event.update(updates)
        source = event["source"]
        if not isinstance(source, dict):
            raise AssertionError("test event source must be an object")
        task_path = self.control / "tasks" / "task-valid-0001" / "task.json"
        if not task_path.exists():
            self.task()
        receipt = {
            "adapter_id": "trusted-webhook",
            "task_id": "task-valid-0001",
            "revision": 1,
            "correlation_id": "corr-valid-0001",
            "provider_run_id": source["run_id"],
        }
        self.write_json(
            self.control
            / "tasks"
            / "task-valid-0001"
            / "provider-receipt-trusted-webhook.json",
            receipt,
        )
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        body_path = self.root / f"{event['event_id']}.json"
        body_path.write_bytes(body)
        timestamp = str(int(time.time()))
        secret = "test-only-webhook-secret"
        digest = hmac.new(
            secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256
        ).hexdigest()
        return event, body_path, timestamp, f"v1={digest}"


class SecurityRegressionTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.fixture = ProjectFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def run_adapter_main(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SKILL_ROOT / "scripts" / "adapter_bridge.py"), *arguments]):
            with redirect_stdout(output), redirect_stderr(output):
                code = adapter_bridge.main()
        return code, output.getvalue()

    def run_lifecycle_main(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SKILL_ROOT / "scripts" / "lifecycle.py"), *arguments]):
            with redirect_stdout(output), redirect_stderr(output):
                code = lifecycle.main()
        return code, output.getvalue()

    def run_invoke_agent_main(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SKILL_ROOT / "scripts" / "invoke_agent.py"), *arguments]):
            with redirect_stdout(output), redirect_stderr(output):
                code = invoke_agent.main()
        return code, output.getvalue()

    def run_init_project_main(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SKILL_ROOT / "scripts" / "init_project.py"), *arguments]):
            with redirect_stdout(output), redirect_stderr(output):
                code = init_project.main()
        return code, output.getvalue()

    def run_validate_project_main(self, project_root: Path) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(
            sys,
            "argv",
            [
                str(SKILL_ROOT / "scripts" / "validate_project.py"),
                "--project-root",
                str(project_root),
            ],
        ):
            with redirect_stdout(output), redirect_stderr(output):
                code = validate_project.main()
        return code, output.getvalue()

    def prepare_canonical_task(self, task_id: str = "task-canonical-0001") -> Path:
        code, output = self.run_adapter_main(
            [
                "prepare-task",
                "--project-root",
                str(self.fixture.root),
                "--phase",
                "implementation",
                "--role",
                "implementer",
                "--objective",
                "Verify prepare-task and invoke-agent use the same canonical contract.",
                "--task-id",
                task_id,
                "--correlation-id",
                "corr-canonical-0001",
                "--acceptance",
                "ac-1|Reach the provider boundary|Assert the provider mock was called",
                "--read-scope",
                ".",
                "--forbidden-scope",
                ".ai-lifecycle",
                "--tool",
                "codex",
                "--network",
            ]
        )
        self.assertEqual(code, 0, output)
        task_path = self.fixture.control / "tasks" / task_id / "task.json"
        schema_path = task_path.parent / "result-envelope.schema.json"
        self.assertTrue(task_path.is_file())
        self.assertTrue(schema_path.is_file())
        task = json.loads(task_path.read_text(encoding="utf-8"))
        self.assertEqual(
            task["output_contract"]["result_schema"],
            f".ai-lifecycle/tasks/{task_id}/result-envelope.schema.json",
        )
        return task_path

    def invoke_http_expect_rejection(
        self, task_path: Path, expected_message: str
    ) -> tuple[int, str]:
        arguments = [
            "invoke-http",
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "test-http",
            "--task-file",
            str(task_path),
            "--execute",
            "--authorization-actor",
            "regression-test",
            "--authorization-reason",
            "Validate a fail-closed boundary",
        ]
        environment = {
            "AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root),
            "AI_LIFECYCLE_ALLOWED_HTTP_ORIGINS": "https://adapter.example.invalid",
        }
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(adapter_bridge.request, "build_opener") as build_opener:
                code, output = self.run_adapter_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn(expected_message.lower(), output.lower())
        build_opener.assert_not_called()
        return code, output

    def prepare_passed_deployment_gate(self) -> tuple[dict[str, object], bytes]:
        self.fixture.close()
        self.fixture = ProjectFixture(active_phase="deployment", status="in_progress")
        self.fixture.config["project"]["risk_level"] = "low"
        self.fixture.config["quality_gates"]["deployment"]["post_checks"] = [
            {
                "id": "verify-provider-receipt",
                "description": "Verify the provider receipt in the regression fixture",
                "required": True,
                "command": [sys.executable, "-c", "raise SystemExit(0)"],
                "cwd": ".",
                "timeout_seconds": 30,
                "forward_env": [],
                "evidence_type": "provider-receipt",
            }
        ]
        self.fixture.write_json(self.fixture.control / "project.json", self.fixture.config)
        artifacts = self.fixture.control / "artifacts" / "deployment"
        self.fixture.write_json(
            artifacts / "deployment-plan.json",
            {
                "environment": "production",
                "artifact_digest": RELEASE_DIGEST,
                "steps": ["Deploy the bound release artifact"],
            },
        )
        self.fixture.write_json(
            artifacts / "environment-readiness.json",
            {
                "environment": "production",
                "artifact_digest": RELEASE_DIGEST,
                "checks": [{"id": "capacity", "status": "passed"}],
            },
        )
        rollback = artifacts / "rollback-plan.md"
        rollback.write_text("Rollback to the previous signed release.\n", encoding="utf-8")
        rollback_bytes = rollback.read_bytes()
        code, output = self.run_lifecycle_main(
            [
                "--project-root",
                str(self.fixture.root),
                "run-gates",
                "--phase",
                "deployment",
            ]
        )
        self.assertEqual(code, 0, output)
        state = json.loads((self.fixture.control / "state.json").read_text(encoding="utf-8"))
        phase = state["phases"]["deployment"]
        self.assertEqual(phase["status"], "technical_pass")
        self.assertTrue(phase["baseline"])
        self.assertTrue(phase["approval_nonce"])
        self.assertTrue(phase["last_evidence"])
        return phase, rollback_bytes

    def deployment_decision_arguments(
        self,
        phase: dict[str, object],
        *,
        baseline: str | None = None,
        nonce: str | None = None,
        environment: str = "production",
        artifact_digest: str = RELEASE_DIGEST,
    ) -> list[str]:
        return [
            "--project-root",
            str(self.fixture.root),
            "decide",
            "--phase",
            "deployment",
            "--decision",
            "approve",
            "--actor",
            "alice@example.invalid",
            "--actor-type",
            "human",
            "--reason",
            "Reviewed production gate evidence",
            "--baseline",
            baseline or str(phase["baseline"]),
            "--approval-nonce",
            nonce or str(phase["approval_nonce"]),
            "--environment",
            environment,
            "--artifact-digest",
            artifact_digest,
        ]

    @staticmethod
    def argument_value(arguments: list[str], name: str) -> str | None:
        if name not in arguments:
            return None
        return arguments[arguments.index(name) + 1]

    def signed_decision_environment(
        self,
        arguments: list[str],
        *,
        subject: str = "alice@example.invalid",
        jti: str | None = None,
        issued_delta: int = 0,
        expires_delta: int = 300,
    ) -> dict[str, str]:
        now = int(time.time())
        protected = {
            "alg": "EdDSA",
            "kid": "test-key",
            "typ": approval_identity.ASSERTION_TYPE,
        }
        claims = {
            "iss": "test-host",
            "sub": subject,
            "aud": approval_identity.ASSERTION_AUDIENCE,
            "jti": jti or f"approval-assertion-{uuid.uuid4()}",
            "iat": now + issued_delta,
            "nbf": now + issued_delta,
            "exp": now + expires_delta,
            "project_id": self.fixture.project_id,
            "lifecycle_run_id": self.fixture.run_id,
            "phase": self.argument_value(arguments, "--phase"),
            "decision": self.argument_value(arguments, "--decision"),
            "reason": self.argument_value(arguments, "--reason"),
            "baseline": self.argument_value(arguments, "--baseline"),
            "approval_nonce": self.argument_value(arguments, "--approval-nonce"),
            "environment": self.argument_value(arguments, "--environment"),
            "artifact_digest": self.argument_value(arguments, "--artifact-digest"),
        }
        signed = (
            approval_identity.SIGNING_CONTEXT
            + approval_identity._canonical_json(protected)
            + b"."
            + approval_identity._canonical_json(claims)
        )
        signature = self.fixture.approval_private_key.sign(signed)
        assertion = {
            "protected": protected,
            "claims": claims,
            "signature": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode("ascii"),
        }
        return {
            "AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE": str(
                self.fixture.approval_trust_path
            ),
            "AI_LIFECYCLE_APPROVAL_ASSERTION": json.dumps(
                assertion, ensure_ascii=False, separators=(",", ":")
            ),
        }

    def create_directory_link_or_skip(self, link: Path, target: Path) -> str:
        try:
            os.symlink(target, link, target_is_directory=True)
            return "symlink"
        except (NotImplementedError, OSError) as symlink_error:
            if os.name != "nt":
                self.skipTest(f"Directory symlinks are unavailable: {symlink_error}")
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if completed.returncode != 0:
                self.skipTest(
                    "Windows symlinks and junctions are unavailable: "
                    + (completed.stderr or completed.stdout or str(symlink_error)).strip()
                )
            return "junction"

    def assert_control_has_no_plaintext(self, *sentinels: str) -> None:
        for path in self.fixture.control.rglob("*"):
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            for sentinel in sentinels:
                self.assertNotIn(sentinel, content, f"plaintext leaked into {path}")

    def test_redact_removes_nested_json_and_plain_text_secrets(self) -> None:
        sentinel_values = [
            "JSON_TOKEN_SENTINEL",
            "NESTED_SECRET_SENTINEL",
            "AUTH_SENTINEL",
            "PLAIN_SENTINEL",
            "BEARER_SENTINEL",
            "URL_PASSWORD_SENTINEL",
        ]
        json_log = json.dumps(
            {
                "token": sentinel_values[0],
                "items": [{"client-secret": sentinel_values[1]}],
                "authorization": sentinel_values[2],
                "safe": "visible",
            }
        )
        plain_log = (
            f'token="{sentinel_values[3]}" '
            f"Bearer {sentinel_values[4]} "
            f"https://user:{sentinel_values[5]}@example.invalid/path"
        )
        redacted = _lifecycle.redact(json_log) + _lifecycle.redact(plain_log)
        for sentinel in sentinel_values:
            self.assertNotIn(sentinel, redacted)
        self.assertIn("visible", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_secret_field_detection_is_recursive_and_does_not_flag_env_var_names(self) -> None:
        document = {
            "token": "literal-one",
            "nested": [{"credentials": "literal-two"}],
            "authentication": {
                "environment_variables": ["SERVICE_TOKEN"],
                "token_env_var": "SERVICE_TOKEN",
            },
        }
        findings = validate_project.find_secret_fields(document)
        self.assertIn("$.token", findings)
        self.assertIn("$.nested[0].credentials", findings)
        self.assertNotIn("$.authentication.token_env_var", findings)

    def test_identifier_and_contained_path_reject_traversal(self) -> None:
        for value in ("../escape", "folder/name", r"folder\name", ".hidden", ""):
            with self.subTest(value=value):
                with self.assertRaises(_lifecycle.LifecycleError):
                    _lifecycle.validate_identifier(value, "test id")
        self.assertEqual(
            _lifecycle.validate_identifier("task-valid_1.2", "test id"), "task-valid_1.2"
        )
        for value in ("../escape.json", str(self.fixture.root.parent / "outside.json")):
            with self.subTest(value=value):
                with self.assertRaises(_lifecycle.LifecycleError):
                    _lifecycle.contained_path(self.fixture.root, value)

    def test_invalid_deployment_lifecycle_initialization_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as project_name:
            project_root = Path(project_name).resolve()
            arguments = [
                "--project-root",
                str(project_root),
                "--requirement",
                "Create a temporary lifecycle project.",
            ]
            for phase in ("architecture", "review", "verification", "integration"):
                arguments.extend(
                    ["--disable-phase", f"{phase}=Removed only for invalid initialization test"]
                )
            code, output = self.run_init_project_main(arguments)
            self.assertNotEqual(code, 0, output)
            self.assertIn("deployment", output.lower())
            self.assertFalse(os.path.lexists(project_root / ".ai-lifecycle"))
            self.assertEqual(list(project_root.glob(".ai-lifecycle-init-*")), [])

    def test_default_initialization_is_immediately_valid(self) -> None:
        with tempfile.TemporaryDirectory() as project_name:
            project_root = Path(project_name).resolve()
            code, output = self.run_init_project_main(
                [
                    "--project-root",
                    str(project_root),
                    "--requirement",
                    "Create a valid default lifecycle project.",
                ]
            )
            self.assertEqual(code, 0, output)
            self.assertTrue((project_root / ".ai-lifecycle").is_dir())
            self.assertEqual(list(project_root.glob(".ai-lifecycle-init-*")), [])

            code, output = self.run_validate_project_main(project_root)
            self.assertEqual(code, 0, output)
            validation = json.loads(output)
            self.assertTrue(validation["valid"], output)

    def test_control_directory_links_cannot_escape_event_or_evidence_storage(self) -> None:
        for folder in ("events", "evidence"):
            with self.subTest(folder=folder):
                control_folder = self.fixture.control / folder
                control_folder.rmdir()
                with tempfile.TemporaryDirectory() as outside_name:
                    outside = Path(outside_name).resolve()
                    try:
                        self.create_directory_link_or_skip(control_folder, outside)
                    except unittest.SkipTest:
                        control_folder.mkdir()
                        raise
                    try:
                        with self.assertRaises(_lifecycle.LifecycleError):
                            _lifecycle.contained_control_path(
                                self.fixture.root,
                                f".ai-lifecycle/{folder}/escaped.json",
                            )
                        with self.assertRaises(_lifecycle.LifecycleError):
                            _lifecycle.validate_all(self.fixture.root)
                        self.assertFalse((outside / "escaped.json").exists())
                    finally:
                        if control_folder.is_symlink():
                            control_folder.unlink()
                        elif os.path.lexists(control_folder):
                            os.rmdir(control_folder)
                        control_folder.mkdir()

    def test_prepare_task_rejects_traversal_identifier_without_creating_output(self) -> None:
        code, output = self.run_adapter_main(
            [
                "prepare-task",
                "--project-root",
                str(self.fixture.root),
                "--phase",
                "implementation",
                "--role",
                "implementer",
                "--objective",
                "Must not escape the task directory",
                "--task-id",
                "../escaped-task",
                "--acceptance",
                "ac-1|Reject traversal|Run the security test",
            ]
        )
        self.assertNotEqual(code, 0, output)
        self.assertIn("task", output.lower())
        self.assertFalse((self.fixture.control / "escaped-task" / "task.json").exists())

    def test_prepare_task_rejects_bearer_secret_before_persistence(self) -> None:
        sentinel = "TASK_BEARER_SECRET_SENTINEL"
        task_id = "task-secret-0001"
        code, output = self.run_adapter_main(
            [
                "prepare-task",
                "--project-root",
                str(self.fixture.root),
                "--phase",
                "implementation",
                "--role",
                "implementer",
                "--objective",
                f"Never persist Authorization: Bearer {sentinel}",
                "--task-id",
                task_id,
                "--correlation-id",
                "corr-secret-0001",
                "--acceptance",
                "ac-1|Reject secrets|Verify no task file is created",
                "--network",
            ]
        )
        self.assertNotEqual(code, 0, output)
        self.assertIn("secret", output.lower())
        self.assertNotIn(sentinel, output)
        task_directory = self.fixture.control / "tasks" / task_id
        self.assertFalse((task_directory / "task.json").exists())
        self.assertFalse((task_directory / "result-envelope.schema.json").exists())
        self.assert_control_has_no_plaintext(sentinel)

    def test_full_json_schema_rejects_malformed_task_envelopes(self) -> None:
        valid, _ = self.fixture.task()
        cases = {
            "wrong nested type": {"acceptance_criteria": [42]},
            "string boolean": {
                "permissions": {
                    "read": ["."],
                    "write": [],
                    "network": "true",
                    "external_mutations": False,
                }
            },
            "unexpected field": {"unrecognized": True},
            "invalid date": {"expires_at": "not-a-date"},
            "unsafe identifier": {"task_id": "../unsafe-task"},
        }
        for name, updates in cases.items():
            with self.subTest(name=name):
                malformed = dict(valid)
                malformed.update(updates)
                with self.assertRaises(_lifecycle.LifecycleError):
                    adapter_bridge.validate_envelope("task", malformed)

    def test_expired_task_is_rejected_before_http_is_constructed(self) -> None:
        _, task_path = self.fixture.task(
            created_at=iso_time(timedelta(hours=-2)),
            expires_at=iso_time(timedelta(hours=-1)),
        )
        self.invoke_http_expect_rejection(task_path, "expired")

    def test_cross_project_task_is_rejected_before_http_is_constructed(self) -> None:
        _, task_path = self.fixture.task(project_id="different-project")
        self.invoke_http_expect_rejection(task_path, "project")

    def test_cross_run_task_is_rejected_before_http_is_constructed(self) -> None:
        _, task_path = self.fixture.task(lifecycle_run_id="lifecycle-different-run")
        self.invoke_http_expect_rejection(task_path, "lifecycle")

    def test_task_for_non_in_progress_phase_is_rejected_before_http_is_constructed(self) -> None:
        self.fixture.state["phases"]["implementation"]["status"] = "ready"
        self.fixture.write_state()
        _, task_path = self.fixture.task()
        self.invoke_http_expect_rejection(task_path, "in_progress")

    def test_prepare_task_output_reaches_mocked_agent_provider_boundary(self) -> None:
        task_path = self.prepare_canonical_task()
        arguments = [
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "codex",
            "--task-file",
            str(task_path),
            "--execute",
            "--authorization-actor",
            "regression-test",
            "--authorization-reason",
            "Exercise the provider boundary with a mock",
        ]
        completed = subprocess.CompletedProcess(
            args=["mock-codex"],
            returncode=1,
            stdout="",
            stderr="mock provider boundary reached",
        )
        environment = {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)}
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(
                invoke_agent, "run_bounded_process", return_value=completed
            ) as provider:
                code, output = self.run_invoke_agent_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("agent process exited", output.lower())
        provider.assert_called_once()

    def test_noncanonical_task_path_fails_before_agent_provider_boundary(self) -> None:
        canonical = self.prepare_canonical_task()
        noncanonical = canonical.parent / "copied-task.json"
        noncanonical.write_bytes(canonical.read_bytes())
        arguments = [
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "codex",
            "--task-file",
            str(noncanonical),
            "--execute",
            "--authorization-actor",
            "regression-test",
            "--authorization-reason",
            "Reject a noncanonical task path",
        ]
        environment = {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)}
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(invoke_agent, "run_bounded_process") as provider:
                code, output = self.run_invoke_agent_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("canonical", output.lower())
        provider.assert_not_called()

    def test_noncanonical_result_schema_path_fails_before_agent_provider_boundary(self) -> None:
        task_path = self.prepare_canonical_task()
        task = json.loads(task_path.read_text(encoding="utf-8"))
        canonical_schema = task_path.parent / "result-envelope.schema.json"
        alternate_schema = task_path.parent / "alternate-result.schema.json"
        alternate_schema.write_bytes(canonical_schema.read_bytes())
        task["output_contract"]["result_schema"] = (
            ".ai-lifecycle/tasks/task-canonical-0001/alternate-result.schema.json"
        )
        self.fixture.write_json(task_path, task)
        arguments = [
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "codex",
            "--task-file",
            str(task_path),
            "--execute",
            "--authorization-actor",
            "regression-test",
            "--authorization-reason",
            "Reject a noncanonical result schema path",
        ]
        environment = {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)}
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(invoke_agent, "run_bounded_process") as provider:
                code, output = self.run_invoke_agent_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("canonical", output.lower())
        self.assertIn("schema", output.lower())
        provider.assert_not_called()

    def test_narrow_agent_read_scope_fails_before_copy_or_provider_start(self) -> None:
        task_path = self.prepare_canonical_task()
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["permissions"]["read"] = ["src"]
        self.fixture.write_json(task_path, task)
        arguments = [
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "codex",
            "--task-file",
            str(task_path),
            "--execute",
            "--authorization-actor",
            "regression-test",
            "--authorization-reason",
            "Reject a read scope narrower than the copied workspace",
        ]
        environment = {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)}
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(invoke_agent, "copy_to_isolated_workspace") as copy_workspace:
                with patch.object(invoke_agent, "run_bounded_process") as provider:
                    code, output = self.run_invoke_agent_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("read scope", output.lower())
        copy_workspace.assert_not_called()
        provider.assert_not_called()

    def test_agent_secret_result_and_raw_output_are_rejected_without_merging(self) -> None:
        result_secret = "AGENT_RESULT_SECRET_SENTINEL"
        raw_secret = "AGENT_RAW_SECRET_SENTINEL"
        source = self.fixture.root / "src" / "app.txt"
        source.parent.mkdir(parents=True)
        source.write_text("original source\n", encoding="utf-8")
        task_path = self.prepare_canonical_task()
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["permissions"]["write"] = ["src"]
        task["ownership"]["write_scope"] = ["src"]
        self.fixture.write_json(task_path, task)

        result = {
            "spec_version": "1.0.0",
            "task_id": task["task_id"],
            "revision": task["revision"],
            "correlation_id": task["correlation_id"],
            "run_id": task["lifecycle_run_id"],
            "provider": "codex",
            "adapter_version": "1.0.0",
            "status": "succeeded",
            "started_at": iso_time(timedelta(seconds=-1)),
            "finished_at": iso_time(),
            "summary": f"Authorization: Bearer {result_secret}",
            "artifacts": [],
            "changed_paths": ["src/app.txt"],
            "external_changes": [],
            "checks": [],
            "findings": [],
            "assumptions": [],
            "residual_risks": [],
            "handoffs": [],
            "invalidations": [],
        }

        def mocked_provider(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            workspace = Path(str(kwargs["cwd"]))
            (workspace / "src" / "app.txt").write_text(
                "untrusted isolated change\n", encoding="utf-8"
            )
            result_path = Path(command[command.index("-o") + 1])
            result_path.write_text(
                json.dumps(result, ensure_ascii=False), encoding="utf-8"
            )
            raw_line = json.dumps(
                {"type": "agent.message", "message": f"Bearer {raw_secret}"}
            )
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=raw_line + "\n",
                stderr="",
            )

        arguments = [
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "codex",
            "--task-file",
            str(task_path),
            "--execute",
            "--authorization-actor",
            "regression-test",
            "--authorization-reason",
            "Reject secret-bearing provider output",
        ]
        environment = {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)}
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(
                invoke_agent, "run_bounded_process", side_effect=mocked_provider
            ) as provider:
                code, output = self.run_invoke_agent_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("secret", output.lower())
        self.assertNotIn(result_secret, output)
        self.assertNotIn(raw_secret, output)
        provider.assert_called_once()
        self.assertEqual(source.read_text(encoding="utf-8"), "original source\n")
        task_directory = task_path.parent
        self.assertFalse((task_directory / "result-codex.json").exists())
        self.assertFalse((task_directory / "raw-codex.json").exists())
        accepted_evidence = (
            self.fixture.control
            / "evidence"
            / "external"
            / f"agent-{task['task_id']}-codex.json"
        )
        self.assertFalse(accepted_evidence.exists())
        self.assert_control_has_no_plaintext(result_secret, raw_secret)

    def test_root_scope_matches_repository_files_but_not_sibling_prefixes(self) -> None:
        self.assertTrue(invoke_agent.scope_matches("src/app.py", "."))
        self.assertTrue(invoke_agent.scope_matches("README.md", "."))
        self.assertTrue(invoke_agent.scope_matches("src/app.py", "src"))
        self.assertFalse(invoke_agent.scope_matches("src-other/app.py", "src"))

    def test_agent_path_normalization_rejects_control_and_traversal_paths(self) -> None:
        for protected in (
            ".ai-lifecycle/state.json",
            ".git/config",
            "../outside.txt",
            r"..\outside.txt",
        ):
            with self.subTest(path=protected):
                with self.assertRaises(_lifecycle.LifecycleError):
                    invoke_agent.normalize_relative_path(protected, "agent path")

    def test_isolated_workspace_excludes_control_data(self) -> None:
        source = self.fixture.root / "src" / "app.txt"
        source.parent.mkdir(parents=True)
        source.write_text("original", encoding="utf-8")
        git = self.fixture.root / ".git"
        git.mkdir()
        (git / "config").write_text("sensitive control data", encoding="utf-8")
        with tempfile.TemporaryDirectory() as isolated_parent:
            isolated = Path(isolated_parent) / "workspace"
            invoke_agent.copy_to_isolated_workspace(self.fixture.root, isolated)
            self.assertEqual((isolated / "src" / "app.txt").read_text(encoding="utf-8"), "original")
            self.assertFalse((isolated / ".git").exists())
            self.assertFalse((isolated / ".ai-lifecycle").exists())
            (isolated / "src" / "app.txt").write_text("isolated change", encoding="utf-8")
            self.assertEqual(source.read_text(encoding="utf-8"), "original")

    def test_isolated_merge_rolls_back_if_evidence_finalization_fails(self) -> None:
        source = self.fixture.root / "src" / "rollback.txt"
        source.parent.mkdir(parents=True)
        source.write_text("original", encoding="utf-8")
        before = invoke_agent.repository_snapshot(self.fixture.root)
        with tempfile.TemporaryDirectory() as isolated_parent:
            isolated = Path(isolated_parent) / "workspace"
            invoke_agent.copy_to_isolated_workspace(self.fixture.root, isolated)
            (isolated / "src" / "rollback.txt").write_text("agent change", encoding="utf-8")
            isolated_after = invoke_agent.repository_snapshot(isolated)

            def fail_finalization() -> None:
                raise RuntimeError("simulated evidence write failure")

            with self.assertRaises(_lifecycle.LifecycleError):
                invoke_agent.merge_isolated_changes(
                    self.fixture.root,
                    isolated,
                    ["src/rollback.txt"],
                    before,
                    isolated_after,
                    fail_finalization,
                )
        self.assertEqual(source.read_text(encoding="utf-8"), "original")

    def test_human_approval_requires_host_identity_and_current_nonce(self) -> None:
        phase, _ = self.prepare_passed_deployment_gate()
        base_arguments = self.deployment_decision_arguments(phase)
        with patch.dict(
            os.environ,
            {
                "AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE": str(
                    self.fixture.approval_trust_path
                )
            },
            clear=False,
        ):
            os.environ.pop("AI_LIFECYCLE_APPROVAL_ASSERTION", None)
            code, output = self.run_lifecycle_main(base_arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("signed approval", output.lower())

        wrong_nonce = self.deployment_decision_arguments(phase, nonce="wrong-nonce")
        with patch.dict(
            os.environ,
            {
                "AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE": str(
                    self.fixture.approval_trust_path
                )
            },
            clear=False,
        ):
            code, output = self.run_lifecycle_main(wrong_nonce)
        self.assertNotEqual(code, 0, output)
        self.assertIn("nonce", output.lower())

        with patch.dict(
            os.environ,
            self.signed_decision_environment(base_arguments),
            clear=False,
        ):
            code, output = self.run_lifecycle_main(base_arguments)
        self.assertEqual(code, 0, output)
        state = json.loads((self.fixture.control / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phases"]["deployment"]["status"], "authorized")
        self.assertEqual(state["phases"]["operations"]["status"], "locked")
        self.assertIsNone(state["phases"]["deployment"].get("approval_nonce"))
        decision_id = state["phases"]["deployment"]["authorization"]["decision_id"]

        artifacts = self.fixture.control / "artifacts" / "deployment"
        self.fixture.write_json(
            artifacts / "deployment-record.json",
            {
                "environment": "production",
                "artifact_digest": RELEASE_DIGEST,
                "provider_run_id": "deploy-run-0001",
                "authorization_decision_id": decision_id,
                "status": "succeeded",
                "provider_receipt": {
                    "provider": "test-provider",
                    "run_id": "deploy-run-0001",
                    "receipt_id": "receipt-0001",
                    "digest": "sha256:" + "b" * 64,
                },
            },
        )
        self.fixture.write_json(
            artifacts / "post-deployment-verification.json",
            {
                "environment": "production",
                "artifact_digest": RELEASE_DIGEST,
                "status": "passed",
                "provider_run_id": "deploy-run-0001",
                "authorization_decision_id": decision_id,
                "checks": [{"id": "smoke", "status": "passed"}],
            },
        )
        with patch.dict(
            os.environ,
            {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)},
            clear=False,
        ):
            code, output = self.run_lifecycle_main(
                [
                    "--project-root",
                    str(self.fixture.root),
                    "complete-deployment",
                    "--environment",
                    "production",
                    "--artifact-digest",
                    RELEASE_DIGEST,
                ]
            )
        self.assertEqual(code, 0, output)
        state = json.loads((self.fixture.control / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phases"]["deployment"]["status"], "approved")
        self.assertEqual(state["phases"]["operations"]["status"], "ready")
        self.assertEqual(state["current_phase"], "operations")

    def test_deployment_approval_rejects_stale_baseline_and_changed_artifacts(self) -> None:
        phase, _ = self.prepare_passed_deployment_gate()
        base_arguments = self.deployment_decision_arguments(phase)
        environment = self.signed_decision_environment(base_arguments)
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_lifecycle_main(
                self.deployment_decision_arguments(phase, baseline="sha256:stale-baseline")
            )
        self.assertNotEqual(code, 0, output)
        self.assertIn("baseline", output.lower())

        rollback = (
            self.fixture.control / "artifacts" / "deployment" / "rollback-plan.md"
        )
        rollback.write_text("A changed rollback plan invalidates the gate.\n", encoding="utf-8")
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_lifecycle_main(
                self.deployment_decision_arguments(phase)
            )
        self.assertNotEqual(code, 0, output)
        self.assertTrue(
            "changed" in output.lower() or "rerun" in output.lower(),
            output,
        )
        state = json.loads((self.fixture.control / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phases"]["deployment"]["status"], "technical_pass")

    def test_deployment_approval_rejects_environment_and_artifact_binding_mismatch(self) -> None:
        phase, _ = self.prepare_passed_deployment_gate()
        environment = self.signed_decision_environment(
            self.deployment_decision_arguments(phase)
        )
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_lifecycle_main(
                self.deployment_decision_arguments(phase, environment="staging")
            )
        self.assertNotEqual(code, 0, output)
        self.assertIn("environment", output.lower())

        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_lifecycle_main(
                self.deployment_decision_arguments(
                    phase, artifact_digest="sha256:different-artifact"
                )
            )
        self.assertNotEqual(code, 0, output)
        self.assertIn("artifact digest", output.lower())
        state = json.loads((self.fixture.control / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phases"]["deployment"]["status"], "technical_pass")

    def test_manual_block_revokes_deployment_authorization(self) -> None:
        phase, _ = self.prepare_passed_deployment_gate()
        decision_arguments = self.deployment_decision_arguments(phase)
        environment = self.signed_decision_environment(decision_arguments)
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_lifecycle_main(decision_arguments)
        self.assertEqual(code, 0, output)

        code, output = self.run_lifecycle_main(
            [
                "--project-root",
                str(self.fixture.root),
                "block",
                "--phase",
                "deployment",
                "--category",
                "quality",
                "--reason",
                "A human stopped the production promotion",
            ]
        )
        self.assertEqual(code, 0, output)
        state = json.loads((self.fixture.control / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phases"]["deployment"]["status"], "blocked")
        self.assertIsNone(state["phases"]["deployment"]["authorization"])

        code, output = self.run_lifecycle_main(
            [
                "--project-root",
                str(self.fixture.root),
                "complete-deployment",
                "--environment",
                "production",
                "--artifact-digest",
                RELEASE_DIGEST,
            ]
        )
        self.assertNotEqual(code, 0, output)
        self.assertIn("authorization", output.lower())

    def test_post_deployment_receipts_reject_forged_or_inconsistent_bindings(self) -> None:
        cases = (
            ("forged decision", "decision-forged", "deploy-run-0001", "deploy-run-0001"),
            ("provider mismatch", None, "deploy-run-0001", "deploy-run-0002"),
        )
        for name, decision_override, record_run, verification_run in cases:
            with self.subTest(name=name):
                phase, _ = self.prepare_passed_deployment_gate()
                decision_arguments = self.deployment_decision_arguments(phase)
                environment = self.signed_decision_environment(decision_arguments)
                with patch.dict(os.environ, environment, clear=False):
                    code, output = self.run_lifecycle_main(decision_arguments)
                self.assertEqual(code, 0, output)
                state = json.loads(
                    (self.fixture.control / "state.json").read_text(encoding="utf-8")
                )
                decision_id = state["phases"]["deployment"]["authorization"][
                    "decision_id"
                ]
                receipt_decision = decision_override or decision_id
                artifacts = self.fixture.control / "artifacts" / "deployment"
                self.fixture.write_json(
                    artifacts / "deployment-record.json",
                    {
                        "environment": "production",
                        "artifact_digest": RELEASE_DIGEST,
                        "provider_run_id": record_run,
                        "authorization_decision_id": receipt_decision,
                        "status": "succeeded",
                        "provider_receipt": {
                            "provider": "test-provider",
                            "run_id": record_run,
                            "receipt_id": "receipt-0001",
                            "digest": "sha256:" + "b" * 64,
                        },
                    },
                )
                self.fixture.write_json(
                    artifacts / "post-deployment-verification.json",
                    {
                        "environment": "production",
                        "artifact_digest": RELEASE_DIGEST,
                        "provider_run_id": verification_run,
                        "authorization_decision_id": receipt_decision,
                        "status": "passed",
                        "checks": [{"id": "smoke", "status": "passed"}],
                    },
                )
                with patch.dict(
                    os.environ,
                    {"AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root)},
                    clear=False,
                ):
                    code, output = self.run_lifecycle_main(
                        [
                            "--project-root",
                            str(self.fixture.root),
                            "complete-deployment",
                            "--environment",
                            "production",
                            "--artifact-digest",
                            RELEASE_DIGEST,
                        ]
                    )
                self.assertNotEqual(code, 0, output)
                state = json.loads(
                    (self.fixture.control / "state.json").read_text(encoding="utf-8")
                )
                self.assertEqual(state["phases"]["deployment"]["status"], "failed")
                evidence_path = self.fixture.root / state["phases"]["deployment"][
                    "last_evidence"
                ]
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                self.assertEqual(evidence["overall"], "failed")
                joined_errors = " ".join(evidence["artifact_errors"]).lower()
                if decision_override:
                    self.assertIn("authorization decision", joined_errors)
                else:
                    self.assertIn("provider_run_id", joined_errors)

    def test_webhook_replay_and_unregistered_source_are_rejected(self) -> None:
        event, body_path, timestamp, signature = self.fixture.event()
        arguments = [
            "verify-webhook",
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "trusted-webhook",
            "--key-id",
            "test-key-1",
            "--body-file",
            str(body_path),
            "--signature",
            signature,
            "--timestamp",
            timestamp,
        ]
        environment = {
            "TEST_WEBHOOK_SECRET": "test-only-webhook-secret",
            "AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS": "TEST_WEBHOOK_SECRET",
            "AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root),
        }
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_adapter_main(arguments)
            self.assertEqual(code, 0, output)
            code, output = self.run_adapter_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("replay", output.lower())
        self.assertTrue((self.fixture.control / "events" / f"{event['event_id']}.json").is_file())

        unknown_source = {"adapter_id": "unregistered-source", "run_id": "provider-run-0002"}
        event, body_path, timestamp, signature = self.fixture.event(source=unknown_source)
        arguments[arguments.index("--body-file") + 1] = str(body_path)
        arguments[arguments.index("--signature") + 1] = signature
        arguments[arguments.index("--timestamp") + 1] = timestamp
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_adapter_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("source", output.lower())
        self.assertFalse((self.fixture.control / "events" / f"{event['event_id']}.json").exists())

    def test_webhook_secret_fields_are_rejected_before_event_persistence(self) -> None:
        key_secret = "WEBHOOK_KEY_SECRET_SENTINEL"
        bearer_secret = "WEBHOOK_BEARER_SECRET_SENTINEL"
        event, body_path, timestamp, signature = self.fixture.event(
            data={
                "token": key_secret,
                "message": f"Authorization: Bearer {bearer_secret}",
            }
        )
        arguments = [
            "verify-webhook",
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "trusted-webhook",
            "--key-id",
            "test-key-1",
            "--body-file",
            str(body_path),
            "--signature",
            signature,
            "--timestamp",
            timestamp,
        ]
        environment = {
            "TEST_WEBHOOK_SECRET": "test-only-webhook-secret",
            "AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS": "TEST_WEBHOOK_SECRET",
            "AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root),
        }
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_adapter_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("secret", output.lower())
        self.assertNotIn(key_secret, output)
        self.assertNotIn(bearer_secret, output)
        event_path = self.fixture.control / "events" / f"{event['event_id']}.json"
        self.assertFalse(event_path.exists())
        self.assert_control_has_no_plaintext(key_secret, bearer_secret)

    def test_webhook_subject_must_match_current_project_and_run(self) -> None:
        subject = {
            "project_id": "different-project",
            "lifecycle_run_id": self.fixture.run_id,
            "phase": self.fixture.active_phase,
            "task_id": "task-valid-0001",
        }
        event, body_path, timestamp, signature = self.fixture.event(subject=subject)
        arguments = [
            "verify-webhook",
            "--project-root",
            str(self.fixture.root),
            "--adapter",
            "trusted-webhook",
            "--key-id",
            "test-key-1",
            "--body-file",
            str(body_path),
            "--signature",
            signature,
            "--timestamp",
            timestamp,
        ]
        environment = {
            "TEST_WEBHOOK_SECRET": "test-only-webhook-secret",
            "AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS": "TEST_WEBHOOK_SECRET",
            "AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root),
        }
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_adapter_main(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("project", output.lower())
        self.assertFalse((self.fixture.control / "events" / f"{event['event_id']}.json").exists())


if __name__ == "__main__":
    unittest.main()

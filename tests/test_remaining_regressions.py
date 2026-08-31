from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = SKILL_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import _lifecycle  # noqa: E402
import adapter_bridge  # noqa: E402
import init_project  # noqa: E402
import invoke_agent  # noqa: E402
import lifecycle  # noqa: E402
import mcp_bridge  # noqa: E402
import orchestrate_agents  # noqa: E402
import test_security_regressions as security_regressions  # noqa: E402
from process_runner import ProcessExecutionError, run_bounded_process  # noqa: E402

ProjectFixture = security_regressions.ProjectFixture
iso_time = security_regressions.iso_time


class RemainingRegressionTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.fixture = ProjectFixture()
        self.harness = security_regressions.SecurityRegressionTests(methodName="runTest")
        self.harness.fixture = self.fixture

    def tearDown(self) -> None:
        self.fixture.close()

    def run_lifecycle(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SCRIPTS_ROOT / "lifecycle.py"), *arguments]):
            with redirect_stdout(output), redirect_stderr(output):
                code = lifecycle.main()
        return code, output.getvalue()

    def run_adapter(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(
            sys, "argv", [str(SCRIPTS_ROOT / "adapter_bridge.py"), *arguments]
        ):
            with redirect_stdout(output), redirect_stderr(output):
                code = adapter_bridge.main()
        return code, output.getvalue()

    def run_mcp(self, arguments: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SCRIPTS_ROOT / "mcp_bridge.py"), *arguments]):
            with redirect_stdout(output), redirect_stderr(output):
                code = mcp_bridge.main()
        return code, output.getvalue()

    def succeeded_result(
        self, task: dict[str, object], *, artifacts: list[dict[str, str]] | None = None
    ) -> dict[str, object]:
        return {
            "spec_version": "1.0.0",
            "task_id": task["task_id"],
            "revision": task["revision"],
            "correlation_id": task["correlation_id"],
            "run_id": task["lifecycle_run_id"],
            "provider": "test",
            "adapter_version": "1.0.0",
            "status": "succeeded",
            "started_at": iso_time(timedelta(seconds=-1)),
            "finished_at": iso_time(),
            "summary": "The task completed successfully.",
            "artifacts": artifacts or [],
            "changed_paths": [],
            "external_changes": [],
            "checks": [
                {
                    "id": criterion["id"],
                    "status": "passed",
                    "evidence": "test fixture verification",
                }
                for criterion in task["acceptance_criteria"]
            ],
            "findings": [],
            "assumptions": [],
            "residual_risks": [],
            "handoffs": [],
            "invalidations": [],
        }

    def prepare_deployment_gate(self) -> tuple[dict[str, object], list[str]]:
        self.fixture.close()
        self.fixture = ProjectFixture(active_phase="deployment", status="in_progress")
        self.harness.fixture = self.fixture
        self.fixture.config["project"]["risk_level"] = "low"
        self.fixture.write_json(self.fixture.control / "project.json", self.fixture.config)
        artifacts = self.fixture.control / "artifacts" / "deployment"
        digest = "sha256:" + "c" * 64
        self.fixture.write_json(
            artifacts / "deployment-plan.json",
            {"environment": "production", "artifact_digest": digest, "steps": ["deploy"]},
        )
        self.fixture.write_json(
            artifacts / "environment-readiness.json",
            {
                "environment": "production",
                "artifact_digest": digest,
                "checks": [{"id": "ready", "status": "passed"}],
            },
        )
        (artifacts / "rollback-plan.md").write_text("Rollback safely.\n", encoding="utf-8")
        code, output = self.run_lifecycle(
            [
                "--project-root",
                str(self.fixture.root),
                "run-gates",
                "--phase",
                "deployment",
            ]
        )
        self.assertEqual(code, 0, output)
        state = _lifecycle.load_json(self.fixture.control / "state.json")
        phase = state["phases"]["deployment"]
        arguments = self.harness.deployment_decision_arguments(
            phase, artifact_digest=digest
        )
        return phase, arguments

    def test_signed_approval_rejects_expiry_unauthorized_subject_and_replay(self) -> None:
        phase, arguments = self.prepare_deployment_gate()
        duplicate_claims = self.harness.signed_decision_environment(arguments)
        duplicate_claims["AI_LIFECYCLE_APPROVAL_ASSERTION"] = duplicate_claims[
            "AI_LIFECYCLE_APPROVAL_ASSERTION"
        ].replace('"claims":', '"claims":{},"claims":', 1)
        with patch.dict(os.environ, duplicate_claims, clear=False):
            code, output = self.run_lifecycle(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("duplicate", output.lower())

        expired = self.harness.signed_decision_environment(
            arguments, issued_delta=-700, expires_delta=-100
        )
        with patch.dict(os.environ, expired, clear=False):
            code, output = self.run_lifecycle(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("expired", output.lower())

        unauthorized = self.harness.signed_decision_environment(
            arguments, subject="mallory@example.invalid"
        )
        with patch.dict(os.environ, unauthorized, clear=False):
            code, output = self.run_lifecycle(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("authorized", output.lower())

        replay_id = f"approval-assertion-{uuid.uuid4()}"
        signed = self.harness.signed_decision_environment(arguments, jti=replay_id)
        with patch.dict(os.environ, signed, clear=False):
            code, output = self.run_lifecycle(arguments)
        self.assertEqual(code, 0, output)
        state = _lifecycle.load_json(self.fixture.control / "state.json")
        deployment = state["phases"]["deployment"]
        deployment["status"] = "technical_pass"
        deployment["approval_nonce"] = phase["approval_nonce"]
        deployment["authorization"] = None
        self.fixture.write_json(self.fixture.control / "state.json", state)
        with patch.dict(os.environ, signed, clear=False):
            code, output = self.run_lifecycle(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("already been used", output.lower())

    def test_write_scope_leases_are_process_safe_and_tamper_evident(self) -> None:
        self.assertFalse(_lifecycle.write_scopes_overlap(["src/*.py"], ["docs/**"]))
        self.assertTrue(_lifecycle.write_scopes_overlap(["src/*.py"], ["src/app.py"]))
        lease = _lifecycle.acquire_write_scope_lease(
            self.fixture.root,
            task_id="task-lease-0001",
            run_id=self.fixture.run_id,
            owner="codex",
            write_scope=["src/*.py"],
            ttl_seconds=60,
        )
        self.assertIsNotNone(lease)
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "conflicts"):
            _lifecycle.acquire_write_scope_lease(
                self.fixture.root,
                task_id="task-lease-0002",
                run_id=self.fixture.run_id,
                owner="claude-code",
                write_scope=["src/app.py"],
                ttl_seconds=60,
            )
        assert lease is not None
        lease_path = self.fixture.control / "leases" / f"{lease['lease_id']}.json"
        persisted = _lifecycle.load_json(lease_path)
        persisted["owner_token"] = "0" * 32
        self.fixture.write_json(lease_path, persisted)
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "binding changed"):
            _lifecycle.release_write_scope_lease(self.fixture.root, lease)

    def test_worker_slots_enforce_global_agent_limit(self) -> None:
        slot = _lifecycle.acquire_worker_slot(
            self.fixture.root,
            task_id="task-worker-slot-0001",
            run_id=self.fixture.run_id,
            owner="codex-worker-1",
            max_workers=1,
            ttl_seconds=60,
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "already in use"):
            _lifecycle.acquire_worker_slot(
                self.fixture.root,
                task_id="task-worker-slot-0002",
                run_id=self.fixture.run_id,
                owner="codex-worker-2",
                max_workers=1,
                ttl_seconds=60,
            )
        _lifecycle.release_worker_slot(self.fixture.root, slot)
        replacement = _lifecycle.acquire_worker_slot(
            self.fixture.root,
            task_id="task-worker-slot-0002",
            run_id=self.fixture.run_id,
            owner="codex-worker-2",
            max_workers=1,
            ttl_seconds=60,
        )
        _lifecycle.release_worker_slot(self.fixture.root, replacement)

    def test_bounded_process_rejects_fast_overflow_and_timeout(self) -> None:
        environment = _lifecycle.safe_subprocess_environment([])
        with self.assertRaisesRegex(ProcessExecutionError, "stdout exceeded"):
            run_bounded_process(
                [sys.executable, "-c", "import sys;sys.stdout.write('x'*4096)"],
                cwd=self.fixture.root,
                environment=environment,
                timeout_seconds=10,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        started = time.monotonic()
        with self.assertRaisesRegex(ProcessExecutionError, "timed out"):
            run_bounded_process(
                [sys.executable, "-c", "import time;time.sleep(5)"],
                cwd=self.fixture.root,
                environment=environment,
                timeout_seconds=1,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertLess(time.monotonic() - started, 4)

    def test_dependency_requires_one_current_canonical_completion(self) -> None:
        dependency, dependency_path = self.fixture.task(task_id="task-dependency-0001")
        dependency_result = self.succeeded_result(dependency)
        result_path = dependency_path.parent / "result-test-http.json"
        self.fixture.write_json(result_path, dependency_result)
        adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            dependency,
            dependency_result,
            result_path,
        )
        task, _ = self.fixture.task(
            task_id="task-consumer-0001", dependencies=[dependency["task_id"]]
        )
        adapter_bridge.validate_task_dependencies(self.fixture.root, task)

        task["dependencies"] = [task["task_id"]]
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "self-reference|cycle"):
            adapter_bridge.validate_task_dependencies(self.fixture.root, task)

    def test_completion_rejects_missing_or_unverifiable_artifact(self) -> None:
        task, task_path = self.fixture.task(task_id="task-artifact-0001")
        result = self.succeeded_result(
            task,
            artifacts=[
                {
                    "artifact_id": "missing-output",
                    "artifact_type": "report",
                    "uri": "outputs/missing.json",
                    "digest": "sha256:" + "d" * 64,
                    "source": "test-http",
                }
            ],
        )
        result_path = task_path.parent / "result-test-http.json"
        self.fixture.write_json(result_path, result)
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "does not exist"):
            adapter_bridge.persist_completion_receipt(
                self.fixture.root, "test-http", task, result, result_path
            )

    def test_completion_rejects_succeeded_result_with_failed_check(self) -> None:
        task, task_path = self.fixture.task(task_id="task-check-failure-0001")
        result = self.succeeded_result(task)
        result["checks"] = [
            {"id": "unit-tests", "status": "failed", "evidence": "tests/output.txt"}
        ]
        result_path = task_path.parent / "result-test-http.json"
        self.fixture.write_json(result_path, result)
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "non-passing checks"):
            adapter_bridge.persist_completion_receipt(
                self.fixture.root, "test-http", task, result, result_path
            )

        result["checks"] = [
            {"id": "ac-1", "status": "passed", "evidence": "initial verification"}
        ]
        self.fixture.write_json(result_path, result)
        receipt_path = adapter_bridge.persist_completion_receipt(
            self.fixture.root, "test-http", task, result, result_path
        )
        result["checks"] = [
            {"id": "unit-tests", "status": "failed", "evidence": "tests/output.txt"}
        ]
        self.fixture.write_json(result_path, result)
        receipt = _lifecycle.load_json(receipt_path)
        receipt["result_digest"] = _lifecycle.sha256_file(result_path)
        self.fixture.write_json(receipt_path, receipt)
        consumer, _ = self.fixture.task(
            task_id="task-check-consumer-0001", dependencies=[task["task_id"]]
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "non-passing checks"):
            adapter_bridge.validate_task_dependencies(self.fixture.root, consumer)

        empty_task, empty_task_path = self.fixture.task(
            task_id="task-empty-checks-0001"
        )
        empty_result = self.succeeded_result(empty_task)
        empty_result["checks"] = []
        empty_result_path = empty_task_path.parent / "result-test-http.json"
        self.fixture.write_json(empty_result_path, empty_result)
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "acceptance criteria"):
            adapter_bridge.persist_completion_receipt(
                self.fixture.root,
                "test-http",
                empty_task,
                empty_result,
                empty_result_path,
            )
        self.assertFalse(
            (empty_task_path.parent / "completion-receipt-test-http.json").exists()
        )

    def test_completion_receipt_binds_changed_repository_outputs(self) -> None:
        output_path = self.fixture.root / "src" / "generated.txt"
        output_path.parent.mkdir()
        output_path.write_text("accepted\n", encoding="utf-8")
        task, task_path = self.fixture.task(
            task_id="task-output-binding-0001",
            permissions={
                "read": ["."],
                "write": ["src/generated.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["src/generated.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        result = self.succeeded_result(task)
        result["changed_paths"] = ["src/generated.txt"]
        result_path = task_path.parent / "result-test-http.json"
        self.fixture.write_json(result_path, result)
        receipt_path = adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            task,
            result,
            result_path,
            expected_repository_outputs=[
                {
                    "path": "src/generated.txt",
                    "digest": _lifecycle.sha256_file(output_path),
                }
            ],
        )
        receipt = _lifecycle.load_json(receipt_path)
        self.assertEqual(receipt["schema_version"], 3)
        self.assertEqual(receipt["dependency_receipts"], [])
        self.assertEqual(receipt["task_outputs"], receipt["repository_outputs"])
        self.assertEqual(
            receipt["repository_outputs"],
            [
                {
                    "path": "src/generated.txt",
                    "digest": _lifecycle.sha256_file(output_path),
                }
            ],
        )
        output_path.write_text("changed later\n", encoding="utf-8")
        consumer, _ = self.fixture.task(
            task_id="task-output-consumer-0001", dependencies=[task["task_id"]]
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "no longer match"):
            adapter_bridge.validate_task_dependencies(self.fixture.root, consumer)

    def test_receipt_chain_allows_a_dependent_writer_to_supersede_an_output(self) -> None:
        shared = self.fixture.root / "shared.txt"
        shared.write_text("from-a\n", encoding="utf-8")

        task_a, path_a = self.fixture.task(
            task_id="task-chain-a-0001",
            permissions={
                "read": ["."],
                "write": ["shared.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["shared.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        result_a = self.succeeded_result(
            task_a,
            artifacts=[
                {
                    "artifact_id": "shared-output",
                    "artifact_type": "text",
                    "uri": "shared.txt",
                    "digest": _lifecycle.sha256_file(shared),
                    "source": "test-http",
                }
            ],
        )
        result_a["changed_paths"] = ["shared.txt"]
        result_path_a = path_a.parent / "result-test-http.json"
        self.fixture.write_json(result_path_a, result_a)
        receipt_a = adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            task_a,
            result_a,
            result_path_a,
            expected_repository_outputs=[
                {"path": "shared.txt", "digest": _lifecycle.sha256_file(shared)}
            ],
        )

        task_b, path_b = self.fixture.task(
            task_id="task-chain-b-0001",
            dependencies=[task_a["task_id"]],
            permissions={
                "read": ["."],
                "write": ["shared.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["shared.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        adapter_bridge.validate_task_dependencies(self.fixture.root, task_b)
        shared.write_text("from-b\n", encoding="utf-8")
        result_b = self.succeeded_result(task_b)
        result_b["changed_paths"] = ["shared.txt"]
        result_path_b = path_b.parent / "result-test-http.json"
        self.fixture.write_json(result_path_b, result_b)
        receipt_b = adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            task_b,
            result_b,
            result_path_b,
            expected_repository_outputs=[
                {"path": "shared.txt", "digest": _lifecycle.sha256_file(shared)}
            ],
        )

        task_c, _ = self.fixture.task(
            task_id="task-chain-c-0001", dependencies=[task_b["task_id"]]
        )
        adapter_bridge.validate_task_dependencies(self.fixture.root, task_c)
        stored_b = _lifecycle.load_json(receipt_b)
        self.assertEqual(
            stored_b["dependency_receipts"],
            [
                {
                    "task_id": task_a["task_id"],
                    "receipt_path": str(receipt_a.relative_to(self.fixture.root)).replace(
                        "\\", "/"
                    ),
                    "receipt_digest": _lifecycle.sha256_file(receipt_a),
                }
            ],
        )
        self.assertEqual(
            stored_b["repository_outputs"], stored_b["task_outputs"]
        )
        self.assertTrue(
            orchestrate_agents.completion_is_accepted(
                self.fixture.root,
                orchestrate_agents.TaskRecord(
                    task_id=task_a["task_id"], path=path_a, document=task_a
                ),
            )
        )

    def test_receipt_chain_carries_forward_unsuperseded_ancestor_outputs(self) -> None:
        ancestor_output = self.fixture.root / "ancestor.txt"
        ancestor_output.write_text("ancestor\n", encoding="utf-8")
        ancestor, ancestor_path = self.fixture.task(
            task_id="task-ancestor-output-0001",
            permissions={
                "read": ["."],
                "write": ["ancestor.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["ancestor.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        ancestor_result = self.succeeded_result(ancestor)
        ancestor_result["changed_paths"] = ["ancestor.txt"]
        ancestor_result_path = ancestor_path.parent / "result-test-http.json"
        self.fixture.write_json(ancestor_result_path, ancestor_result)
        adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            ancestor,
            ancestor_result,
            ancestor_result_path,
            expected_repository_outputs=[
                {
                    "path": "ancestor.txt",
                    "digest": _lifecycle.sha256_file(ancestor_output),
                }
            ],
        )

        descendant_output = self.fixture.root / "descendant.txt"
        descendant_output.write_text("descendant\n", encoding="utf-8")
        descendant, descendant_path = self.fixture.task(
            task_id="task-descendant-output-0001",
            dependencies=[ancestor["task_id"]],
            permissions={
                "read": ["."],
                "write": ["descendant.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["descendant.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        descendant_result = self.succeeded_result(descendant)
        descendant_result["changed_paths"] = ["descendant.txt"]
        descendant_result_path = descendant_path.parent / "result-test-http.json"
        self.fixture.write_json(descendant_result_path, descendant_result)
        descendant_receipt = adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            descendant,
            descendant_result,
            descendant_result_path,
            expected_repository_outputs=[
                {
                    "path": "descendant.txt",
                    "digest": _lifecycle.sha256_file(descendant_output),
                }
            ],
        )
        self.assertEqual(
            [item["path"] for item in _lifecycle.load_json(descendant_receipt)["repository_outputs"]],
            ["ancestor.txt", "descendant.txt"],
        )
        ancestor_output.write_text("changed later\n", encoding="utf-8")
        consumer, _ = self.fixture.task(
            task_id="task-closure-consumer-0001",
            dependencies=[descendant["task_id"]],
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "ancestor.txt"):
            adapter_bridge.validate_task_dependencies(self.fixture.root, consumer)

    def test_receipt_uses_trusted_agent_manifest_instead_of_resampling(self) -> None:
        output = self.fixture.root / "race.txt"
        output.write_text("agent-version\n", encoding="utf-8")
        agent_digest = _lifecycle.sha256_file(output)
        task, task_path = self.fixture.task(
            task_id="task-receipt-race-0001",
            permissions={
                "read": ["."],
                "write": ["race.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["race.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        result = self.succeeded_result(task)
        result["changed_paths"] = ["race.txt"]
        result_path = task_path.parent / "result-test-http.json"
        self.fixture.write_json(result_path, result)
        output.write_text("user-version\n", encoding="utf-8")
        with self.assertRaisesRegex(
            _lifecycle.LifecycleError, "trusted agent output manifest"
        ):
            adapter_bridge.persist_completion_receipt(
                self.fixture.root,
                "test-http",
                task,
                result,
                result_path,
                expected_repository_outputs=[
                    {"path": "race.txt", "digest": agent_digest}
                ],
            )
        self.assertFalse(
            (task_path.parent / "completion-receipt-test-http.json").exists()
        )

    def test_legacy_read_only_receipt_remains_usable_but_writer_requires_replacement(
        self,
    ) -> None:
        read_task, read_task_path = self.fixture.task(
            task_id="task-legacy-read-0001"
        )
        read_result = self.succeeded_result(read_task)
        read_result_path = read_task_path.parent / "result-test-http.json"
        self.fixture.write_json(read_result_path, read_result)
        read_receipt_path = adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            read_task,
            read_result,
            read_result_path,
        )
        read_receipt = _lifecycle.load_json(read_receipt_path)
        read_receipt["schema_version"] = 1
        for field in ("dependency_receipts", "task_outputs", "repository_outputs"):
            read_receipt.pop(field)
        self.fixture.write_json(read_receipt_path, read_receipt)
        consumer, _ = self.fixture.task(
            task_id="task-legacy-consumer-0001",
            dependencies=[read_task["task_id"]],
        )
        adapter_bridge.validate_task_dependencies(self.fixture.root, consumer)

        output = self.fixture.root / "legacy-write.txt"
        output.write_text("legacy\n", encoding="utf-8")
        write_task, write_task_path = self.fixture.task(
            task_id="task-legacy-write-0001",
            permissions={
                "read": ["."],
                "write": ["legacy-write.txt"],
                "network": True,
                "external_mutations": False,
            },
            ownership={
                "write_scope": ["legacy-write.txt"],
                "forbidden_scope": [".ai-lifecycle"],
            },
        )
        write_result = self.succeeded_result(write_task)
        write_result["changed_paths"] = ["legacy-write.txt"]
        write_result_path = write_task_path.parent / "result-test-http.json"
        self.fixture.write_json(write_result_path, write_result)
        write_receipt_path = adapter_bridge.persist_completion_receipt(
            self.fixture.root,
            "test-http",
            write_task,
            write_result,
            write_result_path,
            expected_repository_outputs=[
                {"path": "legacy-write.txt", "digest": _lifecycle.sha256_file(output)}
            ],
        )
        write_receipt = _lifecycle.load_json(write_receipt_path)
        write_receipt["schema_version"] = 1
        for field in ("dependency_receipts", "task_outputs", "repository_outputs"):
            write_receipt.pop(field)
        self.fixture.write_json(write_receipt_path, write_receipt)
        replacement_consumer, _ = self.fixture.task(
            task_id="task-legacy-writer-consumer-0001",
            dependencies=[write_task["task_id"]],
        )
        with self.assertRaisesRegex(
            _lifecycle.LifecycleError, "create a replacement task with a new task_id"
        ):
            adapter_bridge.validate_task_dependencies(
                self.fixture.root, replacement_consumer
            )
        write_receipt["schema_version"] = 2
        write_receipt["repository_outputs"] = [
            {"path": "legacy-write.txt", "digest": _lifecycle.sha256_file(output)}
        ]
        self.fixture.write_json(write_receipt_path, write_receipt)
        with self.assertRaisesRegex(
            _lifecycle.LifecycleError, "Version 2 receipts are accepted only"
        ):
            adapter_bridge.validate_task_dependencies(
                self.fixture.root, replacement_consumer
            )

    def test_merge_rejects_unrelated_concurrent_changes_as_stale(self) -> None:
        source = self.fixture.root / "src"
        source.mkdir()
        (source / "agent.txt").write_text("before-agent\n", encoding="utf-8")
        (source / "peer.txt").write_text("before-peer\n", encoding="utf-8")
        original_before = invoke_agent.repository_snapshot(self.fixture.root)
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary) / "workspace"
            invoke_agent.copy_to_isolated_workspace(self.fixture.root, isolated)
            (isolated / "src" / "agent.txt").write_text(
                "after-agent\n", encoding="utf-8"
            )
            isolated_after = invoke_agent.repository_snapshot(isolated)
            (source / "peer.txt").write_text("after-peer\n", encoding="utf-8")
            with self.assertRaisesRegex(_lifecycle.LifecycleError, "stale merge"):
                invoke_agent.merge_isolated_changes(
                    self.fixture.root,
                    isolated,
                    ["src/agent.txt"],
                    original_before,
                    isolated_after,
                    lambda: None,
                )
        self.assertEqual(
            (source / "agent.txt").read_text(encoding="utf-8"), "before-agent\n"
        )
        self.assertEqual(
            (source / "peer.txt").read_text(encoding="utf-8"), "after-peer\n"
        )

    def test_merge_rejects_stale_target(self) -> None:
        target = self.fixture.root / "target.txt"
        target.write_text("before\n", encoding="utf-8")
        original_before = invoke_agent.repository_snapshot(self.fixture.root)
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary) / "workspace"
            invoke_agent.copy_to_isolated_workspace(self.fixture.root, isolated)
            (isolated / "target.txt").write_text("agent\n", encoding="utf-8")
            isolated_after = invoke_agent.repository_snapshot(isolated)
            target.write_text("peer\n", encoding="utf-8")
            with self.assertRaisesRegex(_lifecycle.LifecycleError, "stale merge"):
                invoke_agent.merge_isolated_changes(
                    self.fixture.root,
                    isolated,
                    ["target.txt"],
                    original_before,
                    isolated_after,
                    lambda: None,
                )
        self.assertEqual(target.read_text(encoding="utf-8"), "peer\n")

    def test_merge_rollback_preserves_user_edit_after_agent_application(self) -> None:
        target = self.fixture.root / "conflict.txt"
        target.write_text("before\n", encoding="utf-8")
        original_before = invoke_agent.repository_snapshot(self.fixture.root)
        transaction = (
            Path(self.fixture._trust_temporary.name) / "preserved-merge-transaction"
        )
        transaction.mkdir()
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary) / "workspace"
            invoke_agent.copy_to_isolated_workspace(self.fixture.root, isolated)
            (isolated / "conflict.txt").write_text("agent\n", encoding="utf-8")
            isolated_after = invoke_agent.repository_snapshot(isolated)

            def fail_after_user_edit() -> None:
                target.write_text("user edit\n", encoding="utf-8")
                raise OSError("metadata persistence failed")

            with (
                patch.object(
                    invoke_agent.tempfile, "mkdtemp", return_value=str(transaction)
                ),
                self.assertRaisesRegex(
                    _lifecycle.LifecycleError, "target diverged after agent application"
                ),
            ):
                invoke_agent.merge_isolated_changes(
                    self.fixture.root,
                    isolated,
                    ["conflict.txt"],
                    original_before,
                    isolated_after,
                    fail_after_user_edit,
                )
        self.assertEqual(target.read_text(encoding="utf-8"), "user edit\n")
        self.assertTrue((transaction / "backups").is_dir())

    def test_orchestrator_builds_dependency_waves_and_serializes_writers(self) -> None:
        def record(
            task_id: str, dependencies: list[str], write_scope: list[str]
        ) -> orchestrate_agents.TaskRecord:
            return orchestrate_agents.TaskRecord(
                task_id=task_id,
                path=Path(f"{task_id}.json"),
                document={
                    "role": "implementer",
                    "dependencies": dependencies,
                    "ownership": {"write_scope": write_scope},
                },
            )

        records = {
            "task-reader-0001": record("task-reader-0001", [], []),
            "task-writer-a-0001": record("task-writer-a-0001", [], ["src/a"]),
            "task-writer-b-0001": record("task-writer-b-0001", [], ["src/b"]),
            "task-review-0001": record(
                "task-review-0001",
                ["task-reader-0001", "task-writer-a-0001"],
                [],
            ),
        }
        waves, blocked = orchestrate_agents.build_plan(records, set(), 3)
        self.assertEqual(blocked, {})
        self.assertEqual(
            [[item.task_id for item in wave] for wave in waves],
            [
                ["task-reader-0001"],
                ["task-writer-a-0001"],
                ["task-review-0001"],
                ["task-writer-b-0001"],
            ],
        )
        self.assertTrue(
            all(sum(item.is_writer for item in wave) <= 1 for wave in waves)
        )
        self.assertTrue(
            all(not any(item.is_writer for item in wave) or len(wave) == 1 for wave in waves)
        )

    def test_orchestrator_runs_parallel_fanout_before_dependent_task(self) -> None:
        def record(
            task_id: str, dependencies: list[str]
        ) -> orchestrate_agents.TaskRecord:
            return orchestrate_agents.TaskRecord(
                task_id=task_id,
                path=self.fixture.control / "tasks" / task_id / "task.json",
                document={
                    "role": "implementer",
                    "dependencies": dependencies,
                    "ownership": {"write_scope": []},
                },
            )

        records = {
            "task-fanout-a-0001": record("task-fanout-a-0001", []),
            "task-fanout-b-0001": record("task-fanout-b-0001", []),
            "task-fanin-c-0001": record(
                "task-fanin-c-0001",
                ["task-fanout-a-0001", "task-fanout-b-0001"],
            ),
        }
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        active = 0
        max_active = 0
        finished: set[str] = set()
        fanin_saw: set[str] = set()

        def fake_invoke(
            _root: Path,
            task: orchestrate_agents.TaskRecord,
            **_kwargs: object,
        ) -> dict[str, object]:
            nonlocal active, max_active
            if task.task_id.startswith("task-fanout"):
                with lock:
                    active += 1
                    max_active = max(max_active, active)
                barrier.wait(timeout=2)
                time.sleep(0.02)
                with lock:
                    active -= 1
                    finished.add(task.task_id)
            else:
                with lock:
                    fanin_saw.update(finished)
            return {
                "task_id": task.task_id,
                "role": "implementer",
                "writer": False,
                "started_at": iso_time(timedelta(seconds=-1)),
                "finished_at": iso_time(),
                "duration_seconds": 0.02,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
            }

        arguments = argparse.Namespace(
            project_root=self.fixture.root,
            phase="implementation",
            task_id=list(records),
            max_parallel=None,
            adapter="codex",
            timeout_seconds=30,
            max_turns=4,
            execute=True,
            authorization_actor="tester",
            authorization_reason="exercise fanout and fanin",
        )
        output = io.StringIO()
        with (
            patch.object(
                orchestrate_agents,
                "orchestration_context",
                return_value=(
                    self.fixture.config,
                    self.fixture.state,
                    records,
                    records,
                    set(),
                    2,
                ),
            ),
            patch.object(orchestrate_agents, "invoke_task", side_effect=fake_invoke),
            patch.object(orchestrate_agents, "completion_is_accepted", return_value=True),
            patch.object(orchestrate_agents, "require_trusted_project"),
            redirect_stdout(output),
        ):
            code = orchestrate_agents.command_run_phase(arguments)
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(max_active, 2)
        self.assertEqual(
            fanin_saw, {"task-fanout-a-0001", "task-fanout-b-0001"}
        )

    def test_orchestrator_enforces_agent_configuration(self) -> None:
        self.fixture.config["agents"]["enabled"] = False
        self.fixture.write_json(
            self.fixture.control / "project.json", self.fixture.config
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "disabled"):
            orchestrate_agents.orchestration_context(
                self.fixture.root, "implementation", [], None
            )

        self.fixture.config["agents"]["enabled"] = True
        self.fixture.config["agents"]["ownership_strategy"] = "worktree"
        self.fixture.write_json(
            self.fixture.control / "project.json", self.fixture.config
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "exclusive-path"):
            orchestrate_agents.orchestration_context(
                self.fixture.root, "implementation", [], None
            )

        arguments = argparse.Namespace(
            project_root=self.fixture.root,
            phase="implementation",
            task_id=[],
            max_parallel=None,
            adapter="codex",
            timeout_seconds=30,
            max_turns=4,
            execute=True,
            authorization_actor="tester",
            authorization_reason="verify explicit graph selection",
        )
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "explicit --task-id"):
            orchestrate_agents.command_run_phase(arguments)

    def test_webhook_rejects_reused_idempotency_key_with_new_event_id(self) -> None:
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
            code, output = self.run_adapter(arguments)
        self.assertEqual(code, 0, output)

        with patch.object(
            adapter_bridge,
            "validate_envelope",
            side_effect=AssertionError("steady-state replay lookup reparsed event JSON"),
        ):
            _, replay_index = adapter_bridge._load_webhook_replay_index(
                self.fixture.root
            )
        self.assertIn(event["event_id"], replay_index["event_ids"])

        index_path = self.fixture.control / "events" / "replay-index.json"
        replay_index["event_ids"]["event-stale-0001"] = "delivery-stale-0001"
        replay_index["idempotency_keys"]["delivery-stale-0001"] = (
            "event-stale-0001"
        )
        self.fixture.write_json(index_path, replay_index)
        _, repaired_index = adapter_bridge._load_webhook_replay_index(
            self.fixture.root
        )
        self.assertNotIn("event-stale-0001", repaired_index["event_ids"])
        self.assertNotIn("delivery-stale-0001", repaired_index["idempotency_keys"])
        self.assertEqual(_lifecycle.load_json(index_path), repaired_index)

        delivery = dict(event["delivery"])
        _, second_body, second_timestamp, second_signature = self.fixture.event(
            delivery=delivery
        )
        arguments[arguments.index("--body-file") + 1] = str(second_body)
        arguments[arguments.index("--signature") + 1] = second_signature
        arguments[arguments.index("--timestamp") + 1] = second_timestamp
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_adapter(arguments)
        self.assertNotEqual(code, 0, output)
        self.assertIn("idempotency", output.lower())

    def test_http_202_is_submitted_but_never_completed(self) -> None:
        _, task_path = self.fixture.task()

        class Response:
            status = 202
            headers: dict[str, str] = {}

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def read(self, _: int) -> bytes:
                return json.dumps(
                    {
                        "run_id": "provider-run-202",
                        "accepted_at": iso_time(),
                        "status_url": "https://adapter.example.invalid/v1/runs/provider-run-202",
                    }
                ).encode("utf-8")

        opener = type("Opener", (), {"open": lambda *_args, **_kwargs: Response()})()
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
            "test-host",
            "--authorization-reason",
            "Submit a bounded read-only task",
        ]
        environment = {
            "AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root),
            "AI_LIFECYCLE_ALLOWED_HTTP_ORIGINS": "https://adapter.example.invalid",
        }
        with patch.dict(os.environ, environment, clear=False):
            with patch.object(adapter_bridge.request, "build_opener", return_value=opener):
                code, output = self.run_adapter(arguments)
        self.assertEqual(code, 0, output)
        self.assertIn('"status": "submitted"', output)
        self.assertFalse(
            (task_path.parent / "completion-receipt-test-http.json").exists()
        )

    def test_generic_mcp_runs_isolated_and_creates_completion_receipt(self) -> None:
        script = Path(self.fixture._trust_temporary.name) / "fake_mcp_server.py"
        script.write_text(
            """
import json, os, sys
schema = {"type": "object", "additionalProperties": False, "required": ["query"], "properties": {"query": {"type": "string"}}}
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "query_status", "inputSchema": schema, "annotations": {"readOnlyHint": True}}]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "isolated=" + str(not os.path.exists('.ai-lifecycle'))}], "structuredContent": {"acceptance_checks": [{"id": "ac-1", "status": "passed"}]}, "isError": False}
    else:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\\n")
    sys.stdout.flush()
""".lstrip(),
            encoding="utf-8",
        )
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["query"],
            "properties": {"query": {"type": "string"}},
        }
        self.fixture.registry["tools"].append(
            {
                "id": "fake-mcp",
                "display_name": "Fake MCP",
                "provider": "fake",
                "kind": "mcp-server",
                "capabilities": ["telemetry.query"],
                "transport": "mcp",
                "availability": "available",
                "read_scopes": ["."],
                "write_scopes": [],
                "authentication": {"type": "none", "environment_variables": []},
                "side_effects": ["external-read"],
                "approval": "task-scope",
                "mcp": {
                    "server_id": "fake-mcp",
                    "transport": "stdio",
                    "protocol_version": "2025-11-25",
                    "command": [sys.executable, str(script)],
                    "startup_timeout_seconds": 15,
                    "timeout_seconds": 15,
                    "max_output_bytes": 1048576,
                    "max_pages": 4,
                    "max_tools": 10,
                    "environment_variables": [],
                    "requires_network": False,
                    "mutation_policy": "deny",
                    "allowed_tools": [
                        {
                            "name": "query_status",
                            "capability": "telemetry.query",
                            "side_effect": "read-only",
                            "input_schema": schema,
                        }
                    ],
                },
            }
        )
        self.fixture.write_json(
            self.fixture.control / "tool-registry.json", self.fixture.registry
        )
        task, task_path = self.fixture.task(
            task_id="task-mcp-0001",
            tool_preferences=["fake-mcp"],
            permissions={
                "read": ["."],
                "write": [],
                "network": False,
                "external_mutations": False,
            },
        )
        arguments_path = task_path.parent / "mcp-arguments.json"
        self.fixture.write_json(arguments_path, {"query": "health"})
        environment = {
            "AI_LIFECYCLE_TRUSTED_PROJECT_ROOT": str(self.fixture.root),
            "AI_LIFECYCLE_ALLOWED_MCP_ENV_VARS": "",
        }
        with patch.dict(os.environ, environment, clear=False):
            code, output = self.run_mcp(
                [
                    "--project-root",
                    str(self.fixture.root),
                    "--adapter",
                    "fake-mcp",
                    "--task-file",
                    str(task_path),
                    "--tool",
                    "query_status",
                    "--arguments-file",
                    str(arguments_path),
                    "--execute",
                ]
            )
        self.assertEqual(code, 0, output)
        result_path = task_path.parent / "result-fake-mcp.json"
        receipt_path = task_path.parent / "completion-receipt-fake-mcp.json"
        self.assertTrue(result_path.is_file())
        self.assertTrue(receipt_path.is_file())
        result = _lifecycle.load_json(result_path)
        self.assertEqual(result["run_id"], task["lifecycle_run_id"])
        evidence = _lifecycle.load_json(self.fixture.root / result["artifacts"][0]["uri"])
        self.assertEqual(evidence["isolation"]["working_directory"], "system-temporary-empty")

    def test_strict_json_and_full_state_registry_schemas_fail_closed(self) -> None:
        duplicate = self.fixture.root / "duplicate.json"
        duplicate.write_text('{"value": 1, "value": 2}', encoding="utf-8")
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "duplicate key"):
            _lifecycle.load_json(duplicate)
        nonstandard = self.fixture.root / "nonstandard.json"
        nonstandard.write_text('{"value": NaN}', encoding="utf-8")
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "non-standard"):
            _lifecycle.load_json(nonstandard)
        too_large = self.fixture.root / "large.json"
        too_large.write_text('{"value": "0123456789"}', encoding="utf-8")
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "byte limit"):
            _lifecycle.load_json(too_large, max_bytes=8)

        self.fixture.state["unexpected"] = True
        self.fixture.write_state()
        with self.assertRaisesRegex(_lifecycle.LifecycleError, "unexpected"):
            _lifecycle.validate_all(self.fixture.root)

    def test_initializer_uses_only_existing_dependency_locks(self) -> None:
        cases = (
            ("node-unlocked", {"package.json": "{}\n"}, "npm", False),
            (
                "dotnet-unlocked",
                {"App.csproj": '<Project Sdk="Microsoft.NET.Sdk"></Project>\n'},
                "--locked-mode",
                False,
            ),
            (
                "dotnet-locked",
                {
                    "App.csproj": '<Project Sdk="Microsoft.NET.Sdk"></Project>\n',
                    "packages.lock.json": "{}\n",
                },
                "--locked-mode",
                True,
            ),
        )
        for name, files, marker, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                for relative, content in files.items():
                    (root / relative).write_text(content, encoding="utf-8")
                output = io.StringIO()
                with patch.object(
                    sys,
                    "argv",
                    [
                        str(SCRIPTS_ROOT / "init_project.py"),
                        "--project-root",
                        str(root),
                        "--requirement",
                        "Create a deterministic test project",
                    ],
                ):
                    with redirect_stdout(output), redirect_stderr(output):
                        code = init_project.main()
                self.assertEqual(code, 0, output.getvalue())
                config = _lifecycle.load_json(root / ".ai-lifecycle" / "project.json")
                commands = [
                    argument
                    for check in config["quality_gates"]["implementation"]["checks"]
                    for argument in check["command"]
                ]
                self.assertEqual(marker in commands, expected)


if __name__ == "__main__":
    unittest.main()

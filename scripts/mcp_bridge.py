#!/usr/bin/env python3
"""Invoke a registry-pinned, read-only MCP tool over a bounded STDIO session."""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema.exceptions import SchemaError, ValidationError
except ImportError:  # Protocol validation must fail closed.
    Draft202012Validator = None  # type: ignore[assignment]
    FormatChecker = None  # type: ignore[assignment]
    SchemaError = Exception  # type: ignore[assignment,misc]
    ValidationError = Exception  # type: ignore[assignment,misc]

from _lifecycle import (
    LifecycleError,
    atomic_create_json,
    contained_control_path,
    lifecycle_lock,
    load_json,
    redact,
    redact_json_value,
    require_trusted_project,
    resolve_root,
    safe_subprocess_environment,
    sha256_file,
    utc_now,
    validate_all,
)
from adapter_bridge import (
    persist_completion_receipt,
    registered_adapter,
    validate_adapter_for_task,
    validate_envelope,
    validate_task_context,
)


BRIDGE_VERSION = "1.0.0"
SUPPORTED_PROTOCOL_VERSIONS = {"2025-06-18", "2025-11-25"}
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SECRET_OPTION = re.compile(
    r"(?i)(?:^|[-_])(?:token|secret|password|credential|api[-_]?key|private[-_]?key)(?:$|[-_=])"
)
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_SCHEMA_BYTES = 256 * 1024
MAX_UNSOLICITED_MESSAGES = 64

INITIALIZE_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": True,
    "required": ["protocolVersion", "capabilities", "serverInfo"],
    "properties": {
        "protocolVersion": {"type": "string"},
        "capabilities": {"type": "object"},
        "serverInfo": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 256},
                "version": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "additionalProperties": True,
        },
        "instructions": {"type": "string", "maxLength": 20000},
    },
}

TOOLS_LIST_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": True,
    "required": ["tools"],
    "properties": {
        "tools": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["name", "inputSchema"],
                "properties": {
                    "name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
                    },
                    "description": {"type": "string", "maxLength": 20000},
                    "inputSchema": {"type": "object"},
                    "outputSchema": {"type": "object"},
                    "annotations": {"type": "object"},
                    "execution": {
                        "type": "object",
                        "additionalProperties": True,
                        "properties": {
                            "taskSupport": {
                                "enum": ["forbidden", "optional", "required"]
                            }
                        },
                    },
                },
            },
        },
        "nextCursor": {"type": "string", "minLength": 1, "maxLength": 4096},
    },
}

TOOL_CALL_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": True,
    "required": ["content"],
    "properties": {
        "content": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type"],
                "properties": {
                    "type": {
                        "enum": ["text", "image", "audio", "resource_link", "resource"]
                    }
                },
                "additionalProperties": True,
            },
        },
        "structuredContent": {"type": "object"},
        "isError": {"type": "boolean"},
        "_meta": {"type": "object"},
    },
}


def _validator(schema: dict[str, Any], label: str) -> Any:
    if Draft202012Validator is None or FormatChecker is None:
        raise LifecycleError(
            "MCP validation requires the 'jsonschema' package; refusing to continue"
        )
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise LifecycleError(f"Invalid {label} JSON Schema: {exc}") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_schema_value(value: Any, schema: dict[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must be a JSON object")
    try:
        _validator(schema, label).validate(value)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "$"
        raise LifecycleError(
            f"{label} failed schema validation at {location}: {exc.message}"
        ) from exc
    return value


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LifecycleError(f"Value is not JSON serializable: {exc}") from exc


def reject_remote_schema_references(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"$ref", "$dynamicRef"} and isinstance(child, str):
                if not child.startswith("#"):
                    raise LifecycleError(f"{label} contains a remote schema reference")
            reject_remote_schema_references(child, label)
    elif isinstance(value, list):
        for child in value:
            reject_remote_schema_references(child, label)


def validate_json_schema(schema: Any, label: str) -> dict[str, Any]:
    if not isinstance(schema, dict):
        raise LifecycleError(f"{label} must be a JSON Schema object")
    if len(canonical_json(schema)) > MAX_SCHEMA_BYTES:
        raise LifecycleError(f"{label} exceeds {MAX_SCHEMA_BYTES} bytes")
    reject_remote_schema_references(schema, label)
    _validator(schema, label)
    if schema.get("type") != "object":
        raise LifecycleError(f"{label} must declare an object at the schema root")
    return schema


def load_bounded_object(path: Path, label: str, maximum: int) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise LifecycleError(f"Cannot inspect {label}: {exc}") from exc
    if size > maximum:
        raise LifecycleError(f"{label} exceeds {maximum} bytes")
    value = load_json(path)
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a JSON object")
    return value


def validate_registry_document(registry: dict[str, Any]) -> None:
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "references"
        / "schemas"
        / "tool-registry.schema.json"
    )
    schema = load_json(schema_path)
    validate_schema_value(registry, schema, "tool-registry.json")


def parse_host_environment_allowlist() -> set[str]:
    raw = os.environ.get("AI_LIFECYCLE_ALLOWED_MCP_ENV_VARS", "")
    values = {item.strip() for item in raw.split(",") if item.strip()}
    return values


def subprocess_environment(mcp: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    names = mcp.get("environment_variables", [])
    if not isinstance(names, list) or not all(
        isinstance(name, str) and ENV_NAME.fullmatch(name) for name in names
    ):
        raise LifecycleError("mcp.environment_variables must contain valid names")
    if len(names) != len(set(names)):
        raise LifecycleError("mcp.environment_variables must not contain duplicates")
    allowed = parse_host_environment_allowlist()
    unexpected = sorted(set(names) - allowed)
    if unexpected:
        raise LifecycleError(
            "MCP environment variables are not host-allowlisted: " + ", ".join(unexpected)
        )
    missing = sorted(name for name in names if name not in os.environ)
    if missing:
        raise LifecycleError("Required MCP environment variables are not set: " + ", ".join(missing))
    environment = safe_subprocess_environment(names, allow_sensitive=True)
    for ambient_profile in ("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA"):
        if ambient_profile not in names:
            environment.pop(ambient_profile, None)
    return environment, names


def validate_command(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 32
        or not all(isinstance(item, str) and 1 <= len(item) <= 4096 for item in value)
    ):
        raise LifecycleError("mcp.command must contain 1-32 non-empty string arguments")
    for item in value:
        if "\x00" in item or "\r" in item or "\n" in item:
            raise LifecycleError("mcp.command arguments cannot contain control separators")
        if SECRET_OPTION.search(item):
            raise LifecycleError(
                "MCP credentials must use host-allowlisted environment variables, not command arguments"
            )
    return list(value)


def load_policy(adapter: dict[str, Any], tool_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if adapter.get("transport") != "mcp":
        raise LifecycleError(f"Adapter {adapter.get('id')} is not an MCP adapter")
    mcp = adapter.get("mcp")
    if not isinstance(mcp, dict):
        raise LifecycleError(f"Adapter {adapter.get('id')} does not define mcp configuration")
    if mcp.get("transport") != "stdio":
        raise LifecycleError(
            "The generic MCP bridge supports only STDIO; Streamable HTTP fails closed"
        )
    if mcp.get("protocol_version") not in SUPPORTED_PROTOCOL_VERSIONS:
        raise LifecycleError("MCP protocol_version is unsupported or not explicitly configured")
    if mcp.get("server_id") != adapter.get("id"):
        raise LifecycleError("mcp.server_id must match the adapter id")
    if mcp.get("mutation_policy") != "deny":
        raise LifecycleError("The generic MCP bridge supports only mutation_policy=deny")
    if adapter.get("write_scopes") not in (None, []):
        raise LifecycleError("A generic read-only MCP adapter cannot declare write_scopes")
    forbidden_effects = {
        "workspace-write",
        "external-write",
        "job-trigger",
        "production-change",
    }
    if forbidden_effects.intersection(adapter.get("side_effects", [])):
        raise LifecycleError("A generic read-only MCP adapter declares mutating side effects")
    if not TOOL_NAME.fullmatch(tool_name):
        raise LifecycleError("MCP tool name is invalid")
    allowed_tools = mcp.get("allowed_tools")
    if not isinstance(allowed_tools, list):
        raise LifecycleError("mcp.allowed_tools must be an array")
    names = [item.get("name") for item in allowed_tools if isinstance(item, dict)]
    if len(names) != len(allowed_tools) or len(names) != len(set(names)):
        raise LifecycleError("mcp.allowed_tools must contain unique tool definitions")
    matches = [item for item in allowed_tools if isinstance(item, dict) and item.get("name") == tool_name]
    if len(matches) != 1:
        raise LifecycleError(f"MCP tool is not uniquely allowlisted: {tool_name}")
    policy = matches[0]
    if policy.get("side_effect") != "read-only":
        raise LifecycleError("The generic MCP bridge permits only read-only tools")
    capability = policy.get("capability")
    if capability not in adapter.get("capabilities", []):
        raise LifecycleError("MCP tool capability is not declared by the adapter")
    validate_json_schema(policy.get("input_schema"), f"registry schema for {tool_name}")
    return mcp, policy


def validate_task_permissions(task: dict[str, Any], adapter: dict[str, Any], mcp: dict[str, Any]) -> None:
    permissions = task["permissions"]
    if permissions["external_mutations"]:
        raise LifecycleError("The generic MCP bridge does not execute external mutations")
    if mcp.get("requires_network", False) and not permissions["network"]:
        raise LifecycleError("This MCP server requires task permissions.network=true")
    adapter_reads = adapter.get("read_scopes", [])
    if not isinstance(adapter_reads, list) or not all(isinstance(item, str) for item in adapter_reads):
        raise LifecycleError("MCP adapter read_scopes must be an array of strings")
    def allowed_scope(requested: str) -> bool:
        for allowed in adapter_reads:
            normalized = allowed.replace("\\", "/").rstrip("/") or "."
            candidate = requested.replace("\\", "/").rstrip("/") or "."
            if normalized == "." or candidate == normalized or candidate.startswith(normalized + "/"):
                return True
        return False

    unexpected = sorted(scope for scope in permissions["read"] if not allowed_scope(scope))
    if unexpected:
        raise LifecycleError(
            "Task read scopes exceed the MCP adapter policy: " + ", ".join(unexpected)
        )


@dataclass
class MCPProcess:
    command: list[str]
    cwd: Path
    environment: dict[str, str]
    max_output_bytes: int
    process: subprocess.Popen[bytes] | None = None
    stdout_queue: queue.Queue[bytes | None] = field(
        default_factory=lambda: queue.Queue(maxsize=32)
    )
    stderr_parts: list[bytes] = field(default_factory=list)
    stderr_size: int = 0
    stderr_exceeded: threading.Event = field(default_factory=threading.Event)
    stdout_size: int = 0
    stdout_exceeded: threading.Event = field(default_factory=threading.Event)
    next_id: int = 1
    unsolicited: list[dict[str, Any]] = field(default_factory=list)
    initialized: bool = False

    def start(self) -> None:
        creationflags = 0
        popen_options: dict[str, Any] = {}
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_options["start_new_session"] = True
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=str(self.cwd),
                env=self.environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                bufsize=0,
                creationflags=creationflags,
                **popen_options,
            )
        except (OSError, ValueError) as exc:
            raise LifecycleError(f"Cannot start MCP server: {exc}") from exc
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        while True:
            try:
                line = self.process.stdout.readline(self.max_output_bytes + 1)
            except OSError:
                line = b""
            if not line:
                self.stdout_queue.put(None)
                return
            self.stdout_size += len(line)
            if self.stdout_size > self.max_output_bytes:
                self.stdout_exceeded.set()
                return
            self.stdout_queue.put(line)

    def _read_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        while True:
            try:
                chunk = self.process.stderr.read(8192)
            except OSError:
                return
            if not chunk:
                return
            remaining = self.max_output_bytes - self.stderr_size
            if remaining > 0:
                self.stderr_parts.append(chunk[:remaining])
                self.stderr_size += min(len(chunk), remaining)
            if len(chunk) > remaining:
                self.stderr_exceeded.set()

    def send(self, message: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise LifecycleError("MCP server is not running")
        payload = canonical_json(message) + b"\n"
        if len(payload) > self.max_output_bytes:
            raise LifecycleError("MCP request exceeds the configured output bound")
        try:
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LifecycleError("MCP server closed its input unexpectedly") from exc

    def request(self, method: str, params: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout_seconds
        while True:
            if self.stdout_exceeded.is_set():
                raise LifecycleError("MCP stdout exceeds the configured output bound")
            if self.stderr_exceeded.is_set():
                raise LifecycleError("MCP stderr exceeds the configured output bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LifecycleError(f"MCP request timed out: {method}")
            try:
                line = self.stdout_queue.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if line is None:
                raise LifecycleError("MCP server exited before returning a response")
            if not line.endswith(b"\n"):
                raise LifecycleError("MCP STDIO messages must be newline-delimited")
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LifecycleError(f"MCP server emitted invalid UTF-8 JSON: {exc}") from exc
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise LifecycleError("MCP server emitted a non-JSON-RPC 2.0 message")
            if "method" in message:
                self._handle_unsolicited(message)
                continue
            response_id = message.get("id")
            if isinstance(response_id, bool) or response_id != request_id:
                raise LifecycleError("MCP server returned an unexpected response id")
            has_result = "result" in message
            has_error = "error" in message
            if has_result == has_error:
                raise LifecycleError("MCP response must contain exactly one of result or error")
            if has_error:
                error_value = message["error"]
                if not (
                    isinstance(error_value, dict)
                    and isinstance(error_value.get("code"), int)
                    and not isinstance(error_value.get("code"), bool)
                    and isinstance(error_value.get("message"), str)
                ):
                    raise LifecycleError("MCP server returned a malformed JSON-RPC error")
                safe_error = redact(json.dumps(message["error"], ensure_ascii=False))
                raise LifecycleError(f"MCP server returned an error for {method}: {safe_error}")
            if not isinstance(message["result"], dict):
                raise LifecycleError(f"MCP {method} result must be an object")
            return message["result"]

    def _handle_unsolicited(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if not isinstance(method, str) or not method:
            raise LifecycleError("MCP server emitted an invalid method")
        if "result" in message or "error" in message:
            raise LifecycleError("MCP server emitted a hybrid request/response message")
        if "params" in message and not isinstance(message["params"], dict):
            raise LifecycleError("MCP server request or notification params must be an object")
        is_request = "id" in message
        if is_request:
            request_id = message["id"]
            if (
                isinstance(request_id, bool)
                or not isinstance(request_id, (int, str))
                or (isinstance(request_id, str) and not request_id)
            ):
                raise LifecycleError("MCP server emitted an invalid request id")
            self.send(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {
                        "code": -32601,
                        "message": "Client-side requests are not supported by this bridge",
                    },
                }
            )
        if not self.initialized:
            raise LifecycleError("MCP server emitted a message before initialization completed")
        self.unsolicited.append({"method": method, "request_rejected": is_request})
        if len(self.unsolicited) > MAX_UNSOLICITED_MESSAGES:
            raise LifecycleError("MCP server emitted too many unsolicited messages")

    def stderr_text(self) -> str:
        return redact(b"".join(self.stderr_parts).decode("utf-8", errors="replace"))

    def close(self) -> None:
        if self.process is None:
            return
        process = self.process
        if process.poll() is not None:
            self.process = None
            raise LifecycleError(
                "MCP server exited before controlled process-tree shutdown could be verified"
            )
        if os.name == "nt":
            try:
                if process.poll() is None:
                    tree_stop = subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=15,
                    )
                    if tree_stop.returncode != 0 and process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                        raise LifecycleError(
                            "MCP process tree termination could not be verified"
                        )
            except (OSError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.kill()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                raise LifecycleError("MCP process tree termination failed")
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise LifecycleError("MCP server process tree could not be terminated") from exc
        self.process = None


def initialize_session(client: MCPProcess, mcp: dict[str, Any]) -> dict[str, Any]:
    version = mcp["protocol_version"]
    result = client.request(
        "initialize",
        {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {
                "name": "codex-core-helper",
                "version": BRIDGE_VERSION,
            },
        },
        int(mcp["startup_timeout_seconds"]),
    )
    validate_schema_value(result, INITIALIZE_RESULT_SCHEMA, "MCP initialize result")
    if result["protocolVersion"] != version:
        raise LifecycleError(
            "MCP server negotiated a protocol version different from the registry pin"
        )
    if not isinstance(result["capabilities"].get("tools"), dict):
        raise LifecycleError("MCP server does not advertise the tools capability")
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    client.initialized = True
    return result


def list_tools(client: MCPProcess, mcp: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    cursor: str | None = None
    seen_cursors: set[str] = set()
    maximum_pages = int(mcp["max_pages"])
    maximum_tools = int(mcp["max_tools"])
    deadline = time.monotonic() + int(mcp["startup_timeout_seconds"])
    for _ in range(maximum_pages):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LifecycleError("MCP tools/list exceeded the total discovery timeout")
        params = {} if cursor is None else {"cursor": cursor}
        result = client.request("tools/list", params, max(0.001, remaining))
        validate_schema_value(result, TOOLS_LIST_RESULT_SCHEMA, "MCP tools/list result")
        for tool in result["tools"]:
            name = tool["name"]
            if name in tools:
                raise LifecycleError(f"MCP server advertised a duplicate tool: {name}")
            validate_json_schema(tool["inputSchema"], f"server inputSchema for {name}")
            if "outputSchema" in tool:
                validate_json_schema(tool["outputSchema"], f"server outputSchema for {name}")
            tools[name] = tool
            if len(tools) > maximum_tools:
                raise LifecycleError("MCP server advertised more tools than configured")
        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            return tools
        if next_cursor in seen_cursors:
            raise LifecycleError("MCP tools/list repeated a pagination cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise LifecycleError("MCP tools/list exceeded the configured page limit")


def validate_selected_tool(
    advertised: dict[str, dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    name = policy["name"]
    tool = advertised.get(name)
    if tool is None:
        raise LifecycleError(f"Allowlisted MCP tool is not advertised by the server: {name}")
    if canonical_json(tool["inputSchema"]) != canonical_json(policy["input_schema"]):
        raise LifecycleError(f"MCP inputSchema drift detected for tool: {name}")
    annotations = tool.get("annotations")
    if not isinstance(annotations, dict) or annotations.get("readOnlyHint") is not True:
        raise LifecycleError(
            "The selected MCP tool is not marked readOnlyHint=true by the server"
        )
    execution = tool.get("execution", {})
    if isinstance(execution, dict) and execution.get("taskSupport") == "required":
        raise LifecycleError("Task-augmented MCP tool calls are experimental and unsupported")
    return tool


def validate_arguments(arguments: dict[str, Any], policy: dict[str, Any]) -> None:
    if redact_json_value(arguments) != arguments:
        raise LifecycleError("MCP arguments contain secret-bearing fields or values")
    try:
        _validator(policy["input_schema"], "MCP input schema").validate(arguments)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "$"
        raise LifecycleError(
            f"MCP arguments failed validation at {location}: {exc.message}"
        ) from exc


def validate_tool_result(result: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    validate_schema_value(result, TOOL_CALL_RESULT_SCHEMA, "MCP tools/call result")
    if result.get("resultType") not in (None, "complete"):
        raise LifecycleError("Multi-round-trip or input-required MCP results are unsupported")
    for index, content in enumerate(result["content"]):
        kind = content["type"]
        if kind == "text" and not isinstance(content.get("text"), str):
            raise LifecycleError(f"MCP text content at index {index} is invalid")
        if kind in {"image", "audio"} and not (
            isinstance(content.get("data"), str)
            and isinstance(content.get("mimeType"), str)
        ):
            raise LifecycleError(f"MCP binary content at index {index} is invalid")
        if kind == "resource_link" and not (
            isinstance(content.get("uri"), str) and isinstance(content.get("name"), str)
        ):
            raise LifecycleError(f"MCP resource link at index {index} is invalid")
        if kind == "resource" and not isinstance(content.get("resource"), dict):
            raise LifecycleError(f"MCP embedded resource at index {index} is invalid")
    output_schema = tool.get("outputSchema")
    if output_schema is not None:
        if "structuredContent" not in result:
            raise LifecycleError("MCP tool declares outputSchema but omitted structuredContent")
        try:
            _validator(output_schema, "MCP output schema").validate(result["structuredContent"])
        except ValidationError as exc:
            location = ".".join(str(part) for part in exc.absolute_path) or "$"
            raise LifecycleError(
                f"MCP structuredContent failed validation at {location}: {exc.message}"
            ) from exc
    if "task" in result or (
        isinstance(result.get("_meta"), dict)
        and "io.modelcontextprotocol/related-task" in result["_meta"]
    ):
        raise LifecycleError("Task-augmented MCP results are experimental and unsupported")
    redacted = redact_json_value(result)
    if len(canonical_json(redacted)) > 1024 * 1024:
        raise LifecycleError("Redacted MCP tool result exceeds 1 MiB")
    return redacted


def result_summary(result: dict[str, Any], tool_name: str) -> str:
    for content in result.get("content", []):
        if content.get("type") == "text" and isinstance(content.get("text"), str):
            summary = redact(content["text"]).strip()
            if summary:
                return summary[:20000]
    return f"MCP tool {tool_name} completed"


def persist_failure(
    root: Path,
    task: dict[str, Any],
    adapter: dict[str, Any],
    tool_name: str,
    arguments_relative: str,
    arguments_digest: str,
    arguments: dict[str, Any],
    client: MCPProcess,
    started_at: str,
    error: Exception,
) -> tuple[Path, Path, dict[str, Any]]:
    invocation_id = f"mcp-{uuid.uuid4()}"
    safe_error = redact(str(error)).strip() or "MCP invocation failed"
    evidence_path = contained_control_path(
        root,
        f".ai-lifecycle/evidence/{task['phase']}/{invocation_id}-failure.json",
    )
    evidence = {
        "schema_version": 1,
        "invocation_id": invocation_id,
        "adapter_id": adapter["id"],
        "tool": tool_name,
        "task_id": task["task_id"],
        "revision": task["revision"],
        "project_id": task["project_id"],
        "lifecycle_run_id": task["lifecycle_run_id"],
        "phase": task["phase"],
        "correlation_id": task["correlation_id"],
        "arguments_path": arguments_relative,
        "arguments_digest": arguments_digest,
        "arguments": redact_json_value(arguments),
        "isolation": {
            "working_directory": "system-temporary-empty",
            "project_files_mounted": False,
            "control_files_mounted": False,
        },
        "unsolicited_messages": client.unsolicited,
        "stderr": client.stderr_text(),
        "started_at": started_at,
        "finished_at": utc_now(),
        "error": safe_error,
    }
    atomic_create_json(evidence_path, evidence)
    result = {
        "spec_version": task["spec_version"],
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "run_id": task["lifecycle_run_id"],
        "provider": adapter.get("provider", adapter["id"]),
        "adapter_version": BRIDGE_VERSION,
        "status": "failed",
        "started_at": started_at,
        "finished_at": utc_now(),
        "summary": safe_error[:20000],
        "artifacts": [
            {
                "artifact_id": "mcp-failure-evidence",
                "artifact_type": "evidence",
                "uri": str(evidence_path.relative_to(root)).replace("\\", "/"),
                "digest": sha256_file(evidence_path),
                "source": adapter["id"],
            }
        ],
        "changed_paths": [],
        "external_changes": [],
        "checks": [],
        "findings": [],
        "assumptions": [],
        "residual_risks": ["MCP invocation did not produce a trusted successful result"],
        "handoffs": [],
        "invalidations": [],
        "usage": None,
        "error": {"code": "mcp_protocol_failure", "message": safe_error[:20000], "retryable": False},
    }
    validate_envelope("result", result)
    if redact_json_value(result) != result:
        raise LifecycleError("Normalized MCP failure result still contains sensitive content")
    result_path = contained_control_path(
        root, f".ai-lifecycle/tasks/{task['task_id']}/failure-result-{invocation_id}.json"
    )
    atomic_create_json(result_path, result)
    return evidence_path, result_path, result


def persist_execution(
    root: Path,
    task: dict[str, Any],
    adapter: dict[str, Any],
    tool_name: str,
    arguments_relative: str,
    arguments_digest: str,
    arguments: dict[str, Any],
    initialized: dict[str, Any],
    advertised: dict[str, dict[str, Any]],
    tool_result: dict[str, Any],
    client: MCPProcess,
    started_at: str,
) -> tuple[Path, Path, Path | None, dict[str, Any]]:
    invocation_id = f"mcp-{uuid.uuid4()}"
    evidence_path = contained_control_path(
        root,
        f".ai-lifecycle/evidence/{task['phase']}/{invocation_id}.json",
    )
    evidence = {
        "schema_version": 1,
        "invocation_id": invocation_id,
        "adapter_id": adapter["id"],
        "tool": tool_name,
        "protocol_version": initialized["protocolVersion"],
        "server_info": redact_json_value(initialized["serverInfo"]),
        "server_capabilities": sorted(initialized["capabilities"].keys()),
        "advertised_tools": sorted(advertised),
        "task_id": task["task_id"],
        "revision": task["revision"],
        "project_id": task["project_id"],
        "lifecycle_run_id": task["lifecycle_run_id"],
        "phase": task["phase"],
        "correlation_id": task["correlation_id"],
        "arguments_path": arguments_relative,
        "arguments_digest": arguments_digest,
        "arguments": redact_json_value(arguments),
        "isolation": {
            "working_directory": "system-temporary-empty",
            "project_files_mounted": False,
            "control_files_mounted": False,
        },
        "result": tool_result,
        "unsolicited_messages": client.unsolicited,
        "stderr": client.stderr_text(),
        "started_at": started_at,
        "finished_at": utc_now(),
    }
    atomic_create_json(evidence_path, evidence)
    failed = tool_result.get("isError") is True
    result = {
        "spec_version": task["spec_version"],
        "task_id": task["task_id"],
        "revision": task["revision"],
        "correlation_id": task["correlation_id"],
        "run_id": task["lifecycle_run_id"],
        "provider": adapter.get("provider", adapter["id"]),
        "adapter_version": BRIDGE_VERSION,
        "status": "failed" if failed else "succeeded",
        "started_at": started_at,
        "finished_at": utc_now(),
        "summary": result_summary(tool_result, tool_name),
        "artifacts": [
            {
                "artifact_id": "mcp-evidence",
                "artifact_type": "evidence",
                "uri": str(evidence_path.relative_to(root)).replace("\\", "/"),
                "digest": sha256_file(evidence_path),
                "source": adapter["id"],
            }
        ],
        "changed_paths": [],
        "external_changes": [],
        "checks": [],
        "findings": [],
        "assumptions": [],
        "residual_risks": ["MCP server output remains untrusted until lifecycle gates pass"],
        "handoffs": [],
        "invalidations": [],
        "usage": None,
        "error": (
            {
                "code": "mcp_tool_error",
                "message": result_summary(tool_result, tool_name),
                "retryable": False,
            }
            if failed
            else None
        ),
    }
    validate_envelope("result", result)
    if redact_json_value(result) != result:
        raise LifecycleError("Normalized MCP result still contains sensitive content")
    if failed:
        result_path = contained_control_path(
            root,
            f".ai-lifecycle/tasks/{task['task_id']}/failure-result-{invocation_id}.json",
        )
        atomic_create_json(result_path, result)
        return evidence_path, result_path, None, result
    result_path = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task['task_id']}/result-{adapter['id']}.json",
    )
    atomic_create_json(result_path, result)
    try:
        receipt_path = persist_completion_receipt(
            root, adapter["id"], task, result, result_path
        )
    except Exception:
        try:
            result_path.unlink()
        except OSError:
            pass
        raise
    return evidence_path, result_path, receipt_path, result


def command_invoke(args: argparse.Namespace) -> int:
    if not args.execute:
        raise LifecycleError("MCP invocation requires --execute")
    root = resolve_root(args.project_root)
    require_trusted_project(root, "MCP adapter invocation")
    config, registry, state = validate_all(root)
    validate_registry_document(registry)
    task_path = args.task_file.expanduser().resolve()
    task = validate_envelope("task", load_json(task_path))
    validate_task_context(root, config, state, task, task_path=task_path)
    if redact_json_value(task) != task:
        raise LifecycleError("Task contains secret-bearing fields or values")
    adapter = registered_adapter(registry, args.adapter)
    validate_adapter_for_task(
        adapter, task, adapter_id=args.adapter, transport="mcp"
    )
    mcp, policy = load_policy(adapter, args.tool)
    validate_task_permissions(task, adapter, mcp)
    command = validate_command(mcp["command"])
    environment, forwarded_names = subprocess_environment(mcp)
    supplied_arguments_path = Path(os.path.abspath(args.arguments_file.expanduser()))
    task_directory = contained_control_path(
        root, f".ai-lifecycle/tasks/{task['task_id']}", must_exist=True
    )
    try:
        supplied_arguments_path.relative_to(task_directory)
    except ValueError as exc:
        raise LifecycleError("MCP arguments file must be stored in the canonical task directory") from exc
    arguments_relative = str(supplied_arguments_path.relative_to(root)).replace("\\", "/")
    arguments_path = contained_control_path(root, arguments_relative, must_exist=True)
    if not arguments_path.is_file() or arguments_path.is_symlink():
        raise LifecycleError("MCP arguments file must be a regular non-link file")
    arguments = load_bounded_object(arguments_path, "MCP arguments file", MAX_ARGUMENT_BYTES)
    validate_arguments(arguments, policy)
    arguments_digest = sha256_file(arguments_path)
    canonical_result_path = contained_control_path(
        root, f".ai-lifecycle/tasks/{task['task_id']}/result-{adapter['id']}.json"
    )
    canonical_receipt_path = contained_control_path(
        root,
        f".ai-lifecycle/tasks/{task['task_id']}/completion-receipt-{adapter['id']}.json",
    )
    if canonical_result_path.exists() or canonical_receipt_path.exists():
        raise LifecycleError(
            "A canonical MCP result or completion receipt already exists for this adapter"
        )
    if not 1 <= int(mcp["startup_timeout_seconds"]) <= 120:
        raise LifecycleError("MCP startup_timeout_seconds must be between 1 and 120")
    if not 1 <= int(mcp["timeout_seconds"]) <= 600:
        raise LifecycleError("MCP timeout_seconds must be between 1 and 600")
    maximum_output = int(mcp["max_output_bytes"])
    if not 4096 <= maximum_output <= 10 * 1024 * 1024:
        raise LifecycleError("MCP max_output_bytes must be between 4096 and 10485760")
    started_at = utc_now()
    client = MCPProcess(command, Path(tempfile.gettempdir()), environment, maximum_output)
    execution_error: Exception | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="ai-lifecycle-mcp-") as isolated_name:
            client.cwd = Path(isolated_name)
            try:
                client.start()
                initialized = initialize_session(client, mcp)
                advertised = list_tools(client, mcp)
                selected = validate_selected_tool(advertised, policy)
                raw_result = client.request(
                    "tools/call",
                    {"name": args.tool, "arguments": arguments},
                    int(mcp["timeout_seconds"]),
                )
                tool_result = validate_tool_result(raw_result, selected)
            except (LifecycleError, OSError, TypeError, ValueError) as exc:
                execution_error = exc
            try:
                client.close()
            except (LifecycleError, OSError, subprocess.SubprocessError) as exc:
                execution_error = LifecycleError(
                    f"{execution_error}; MCP shutdown failed: {exc}"
                    if execution_error
                    else f"MCP shutdown failed: {exc}"
                )
    except (LifecycleError, OSError, TypeError, ValueError) as exc:
        execution_error = exc

    if execution_error is not None:
        evidence_path, result_path, result = persist_failure(
            root,
            task,
            adapter,
            args.tool,
            arguments_relative,
            arguments_digest,
            arguments,
            client,
            started_at,
            execution_error,
        )
        receipt_path = None
    else:
        try:
            with lifecycle_lock(root, "state"):
                latest_config, latest_registry, latest_state = validate_all(root)
                latest_task = validate_envelope("task", load_json(task_path))
                if latest_task != task:
                    raise LifecycleError("Task changed during MCP execution")
                latest_adapter = registered_adapter(latest_registry, args.adapter)
                if latest_adapter != adapter:
                    raise LifecycleError("MCP adapter policy changed during execution")
                if sha256_file(arguments_path) != arguments_digest:
                    raise LifecycleError("MCP arguments changed during execution")
                validate_task_context(
                    root,
                    latest_config,
                    latest_state,
                    latest_task,
                    task_path=task_path,
                )
                evidence_path, result_path, receipt_path, result = persist_execution(
                    root,
                    task,
                    adapter,
                    args.tool,
                    arguments_relative,
                    arguments_digest,
                    arguments,
                    initialized,
                    advertised,
                    tool_result,
                    client,
                    started_at,
                )
        except (LifecycleError, OSError, TypeError, ValueError) as exc:
            evidence_path, result_path, result = persist_failure(
                root,
                task,
                adapter,
                args.tool,
                arguments_relative,
                arguments_digest,
                arguments,
                client,
                started_at,
                exc,
            )
            receipt_path = None
    print(
        json.dumps(
            {
                "status": result["status"],
                "task_id": task["task_id"],
                "adapter": adapter["id"],
                "tool": args.tool,
                "forwarded_environment_names": forwarded_names,
                "evidence": str(evidence_path),
                "result": str(result_path),
                "completion_receipt": str(receipt_path) if receipt_path else None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 1 if result["status"] == "failed" else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--task-file", required=True, type=Path)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--arguments-file", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        return command_invoke(args)
    except (LifecycleError, OSError, KeyError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {"status": "error", "error": redact(str(exc))},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

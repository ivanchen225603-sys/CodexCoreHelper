#!/usr/bin/env python3
"""Shared helpers for CodexCoreHelper."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


PHASES = [
    "discovery",
    "requirements",
    "architecture",
    "prototype",
    "implementation",
    "review",
    "verification",
    "integration",
    "deployment",
    "operations",
]

STATUSES = {
    "locked",
    "ready",
    "in_progress",
    "technical_pass",
    "authorized",
    "approved",
    "failed",
    "rejected",
    "blocked",
    "disabled",
}

SECRET_KEY_NAMES = {
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "token",
    "secret",
    "password",
    "authorization",
    "client_secret",
    "private_key",
    "cookie",
    "session",
    "session_cookie",
    "credential",
    "credentials",
}
SECRET_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|"
    r"authorization|client[_-]?secret|private[_-]?key|cookie|session(?:[_-]?cookie)?|"
    r"credentials?)[\"']?\s*[:=]\s*)([\"']?)([^\"'\s,;}]+)([\"']?)"
)
QUOTED_SECRET_ASSIGNMENT = re.compile(
    r"(?i)([\"'](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|"
    r"authorization|client[_-]?secret|private[_-]?key|cookie|session(?:[_-]?cookie)?|"
    r"credentials?)[\"']\s*[:=]\s*)([\"'])(.*?)(?<!\\)\2"
)
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
URL_CREDENTIALS = re.compile(r"(https?://)([^/@\s:]+):([^/@\s]+)@", re.IGNORECASE)
PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
MAX_OUTPUT_CHARS = 200_000
MAX_JSON_BYTES = 16 * 1024 * 1024
LEASE_SPEC_VERSION = 1
MAX_ACTIVE_WRITE_LEASES = 10_000


class LifecycleError(ValueError):
    """Raised when lifecycle configuration or state is invalid."""


class LeaseExpiredOrMissingError(LifecycleError):
    """Raised only when an otherwise identified lease is no longer active."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise LifecycleError(f"JSON object contains a duplicate key: {key}")
        value[key] = child
    return value


def _reject_json_constant(value: str) -> None:
    raise LifecycleError(f"JSON contains a non-standard numeric constant: {value}")


def load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise LifecycleError("JSON byte limit must be a positive integer")
    try:
        with path.open("rb") as stream:
            payload = stream.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise LifecycleError(f"JSON file exceeds the {max_bytes}-byte limit: {path}")
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except FileNotFoundError as exc:
        raise LifecycleError(f"Required file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"Invalid JSON in {path}: {exc}") from exc
    except (OSError, UnicodeDecodeError, RecursionError) as exc:
        raise LifecycleError(f"Cannot read JSON from {path}: {exc}") from exc


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_create_json(path: Path, value: Any) -> None:
    """Create a JSON file exactly once without a check-then-replace race."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise LifecycleError(f"Refusing to overwrite existing file: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            result[key] = "[REDACTED]" if normalized in SECRET_KEY_NAMES else _redact_json(child)
        return result
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, str):
        return _redact_text_patterns(value)
    return value


def _redact_text_patterns(value: str) -> str:
    value = QUOTED_SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]{match.group(2)}", value
    )
    value = SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]{match.group(4)}", value
    )
    value = BEARER.sub("Bearer [REDACTED]", value)
    value = URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    return PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)


def redact_json_value(value: Any) -> Any:
    """Return a JSON-compatible value with sensitive keys and strings redacted."""
    return _redact_json(value)


def redact(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            value = json.dumps(_redact_json(parsed), ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    value = _redact_text_patterns(value)
    if len(value) > MAX_OUTPUT_CHARS:
        value = value[:MAX_OUTPUT_CHARS] + "\n[OUTPUT TRUNCATED]"
    return value


def resolve_root(path: Path) -> Path:
    root = path.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise LifecycleError(f"Project root is not a directory: {root}")
    return root


def contained_path(root: Path, relative: str, *, must_exist: bool = False) -> Path:
    if not relative or Path(relative).is_absolute():
        raise LifecycleError(f"Expected a non-empty relative path, got: {relative!r}")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise LifecycleError(f"Path escapes the project root: {relative}") from exc
    if must_exist and not resolved.exists():
        raise LifecycleError(f"Path does not exist: {relative}")
    return resolved


def contained_control_path(
    root: Path, relative: str, *, must_exist: bool = False
) -> Path:
    """Resolve a control-plane path while rejecting symlink/junction components."""
    normalized = relative.replace("\\", "/")
    if normalized != ".ai-lifecycle" and not normalized.startswith(".ai-lifecycle/"):
        raise LifecycleError(f"Expected a path under .ai-lifecycle, got: {relative!r}")
    resolved = contained_path(root, normalized, must_exist=must_exist)
    current = root.resolve()
    for part in Path(normalized).parts:
        current = current / part
        if not current.exists():
            continue
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LifecycleError(f"Cannot inspect lifecycle control path: {current}") from exc
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if current.is_symlink() or bool(reparse_flag and attributes & reparse_flag):
            raise LifecycleError(
                f"Lifecycle control paths cannot contain links or reparse points: {relative}"
            )
    return resolved


SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_identifier(value: Any, label: str, *, min_length: int = 1) -> str:
    if (
        not isinstance(value, str)
        or len(value) < min_length
        or not SAFE_IDENTIFIER.fullmatch(value)
    ):
        raise LifecycleError(
            f"{label} must be {min_length}-128 characters using only letters, digits, '.', '_', or '-'"
        )
    return value


def require_trusted_project(root: Path, operation: str) -> None:
    """Require host-provided trust before executing repository-controlled operations."""
    trusted = os.environ.get("AI_LIFECYCLE_TRUSTED_PROJECT_ROOT")
    if not trusted:
        raise LifecycleError(
            f"{operation} requires AI_LIFECYCLE_TRUSTED_PROJECT_ROOT to be set by the host"
        )
    try:
        trusted_root = Path(trusted).expanduser().resolve()
    except OSError as exc:
        raise LifecycleError("Trusted project root is invalid") from exc
    if trusted_root != root.resolve():
        raise LifecycleError(f"{operation} is not authorized for this project root")


def sensitive_environment_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return any(
        marker in normalized
        for marker in ("token", "secret", "password", "api_key", "private_key", "credential", "cookie")
    )


@contextmanager
def lifecycle_lock(root: Path, name: str) -> Iterator[None]:
    """Take a crash-safe, process-scoped advisory lock.

    The lock file is intentionally retained.  The operating system releases the
    byte-range/advisory lock when a process exits, so a crashed writer cannot
    permanently strand lifecycle state behind an O_EXCL sentinel.
    """
    validate_identifier(name, "lock name")
    path = contained_control_path(
        root, f".ai-lifecycle/locks/{name}.lock"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise LifecycleError(f"Lifecycle lock path is not a regular file: {path}")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise LifecycleError(
                    f"Lifecycle operation is already active: {name}"
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise LifecycleError(
                    f"Lifecycle operation is already active: {name}"
                ) from exc
        locked = True
        payload = json.dumps(
            {
                "pid": os.getpid(),
                "created_at": utc_now(),
                "monotonic": time.monotonic(),
                "owner_token": uuid.uuid4().hex,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def _scope_literal_prefix(scope: str) -> tuple[str, bool]:
    normalized = scope.replace("\\", "/").strip().rstrip("/") or "."
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if os.name == "nt":
        normalized = normalized.casefold()
    if normalized == ".":
        return "", True
    wildcard = min(
        (normalized.find(marker) for marker in "*?[" if marker in normalized),
        default=-1,
    )
    if wildcard < 0:
        return normalized, False
    raw_prefix = normalized[:wildcard]
    # A glob is conservatively treated as owning its entire literal-prefix
    # directory. False positives serialize work; false negatives corrupt it.
    if raw_prefix.endswith("/"):
        prefix = raw_prefix.rstrip("/")
    elif "/" in raw_prefix:
        prefix = raw_prefix.rsplit("/", 1)[0]
    else:
        prefix = ""
    return prefix, True


def normalize_lease_scope(scope: Any) -> str:
    if not isinstance(scope, str) or not scope.strip():
        raise LifecycleError("Write-scope lease entries must be non-empty strings")
    normalized = scope.strip().replace("\\", "/").rstrip("/") or "."
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized == ".":
        return normalized
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise LifecycleError("Write-scope lease entries must be relative")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise LifecycleError("Write-scope lease entries cannot contain traversal")
    if normalized.split("/", 1)[0] in {".git", ".ai-lifecycle", ".agent-control"}:
        raise LifecycleError("Write-scope lease cannot target protected control data")
    return normalized


def write_scopes_overlap(left: list[str], right: list[str]) -> bool:
    """Conservatively detect overlap between exact, directory, and glob scopes."""
    for first in left:
        first_prefix, _ = _scope_literal_prefix(first)
        for second in right:
            second_prefix, _ = _scope_literal_prefix(second)
            if not first_prefix or not second_prefix:
                return True
            if (
                first_prefix == second_prefix
                or first_prefix.startswith(second_prefix + "/")
                or second_prefix.startswith(first_prefix + "/")
            ):
                return True
    return False


def _lease_expiry_epoch(lease: dict[str, Any]) -> float:
    value = lease.get("expires_at_epoch")
    if not isinstance(value, (int, float)):
        raise LifecycleError("Write-scope lease has an invalid expiry")
    return float(value)


def _lease_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LifecycleError(f"Write-scope lease {label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LifecycleError(f"Write-scope lease {label} is invalid") from exc
    return parsed.astimezone(timezone.utc)


def _lease_directory(root: Path) -> Path:
    directory = contained_control_path(root, ".ai-lifecycle/leases")
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise LifecycleError("Lifecycle leases path is not a regular directory")
    return directory


def _active_write_leases(root: Path, now: float) -> list[tuple[Path, dict[str, Any]]]:
    active: list[tuple[Path, dict[str, Any]]] = []
    directory = _lease_directory(root)
    paths = sorted(directory.glob("*.json"))
    if len(paths) > MAX_ACTIVE_WRITE_LEASES:
        raise LifecycleError("Write-scope lease registry exceeds its safety limit")
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise LifecycleError(f"Write-scope lease is not a regular file: {path}")
        lease = require_object_json(load_json(path), "write-scope lease")
        expected_fields = {
            "schema_version",
            "lease_id",
            "task_id",
            "lifecycle_run_id",
            "owner",
            "owner_token",
            "write_scope",
            "acquired_at",
            "expires_at",
            "expires_at_epoch",
        }
        if set(lease) != expected_fields or lease.get("schema_version") != LEASE_SPEC_VERSION:
            raise LifecycleError("Write-scope lease fields are invalid")
        validate_identifier(lease.get("lease_id"), "lease_id", min_length=8)
        validate_identifier(lease.get("task_id"), "lease task_id", min_length=8)
        validate_identifier(
            lease.get("lifecycle_run_id"), "lease lifecycle_run_id", min_length=8
        )
        validate_identifier(lease.get("owner"), "lease owner")
        if not isinstance(lease.get("owner_token"), str) or not re.fullmatch(
            r"[0-9a-f]{32}", lease["owner_token"]
        ):
            raise LifecycleError("Write-scope lease owner_token is invalid")
        acquired = _lease_timestamp(lease.get("acquired_at"), "acquired_at")
        expires = _lease_timestamp(lease.get("expires_at"), "expires_at")
        if expires <= acquired or abs(expires.timestamp() - _lease_expiry_epoch(lease)) > 1.1:
            raise LifecycleError("Write-scope lease expiry fields are inconsistent")
        if _lease_expiry_epoch(lease) <= now:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            continue
        scopes = lease.get("write_scope")
        if not isinstance(scopes, list) or not all(
            isinstance(item, str) and item for item in scopes
        ):
            raise LifecycleError("Write-scope lease has invalid scope data")
        if [normalize_lease_scope(item) for item in scopes] != scopes:
            raise LifecycleError("Write-scope lease entries are not normalized")
        active.append((path, lease))
    return active


def require_object_json(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a JSON object")
    return value


def acquire_write_scope_lease(
    root: Path,
    *,
    task_id: str,
    run_id: str,
    owner: str,
    write_scope: list[str],
    ttl_seconds: int,
) -> dict[str, Any] | None:
    """Atomically acquire an expiring exclusive lease for write scopes."""
    if not write_scope:
        return None
    validate_identifier(task_id, "lease task_id", min_length=8)
    validate_identifier(run_id, "lease run_id", min_length=8)
    validate_identifier(owner, "lease owner")
    if not 1 <= ttl_seconds <= 24 * 60 * 60:
        raise LifecycleError("Write-scope lease ttl must be between 1 and 86400 seconds")
    normalized_scope = [normalize_lease_scope(item) for item in write_scope]
    if len(normalized_scope) != len(set(normalized_scope)):
        raise LifecycleError("Write-scope lease entries must be unique")
    now = time.time()
    lease_id = f"lease-{uuid.uuid4()}"
    lease = {
        "schema_version": LEASE_SPEC_VERSION,
        "lease_id": lease_id,
        "task_id": task_id,
        "lifecycle_run_id": run_id,
        "owner": owner,
        "owner_token": uuid.uuid4().hex,
        "write_scope": normalized_scope,
        "acquired_at": utc_now(),
        "expires_at": datetime.fromtimestamp(now + ttl_seconds, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "expires_at_epoch": now + ttl_seconds,
    }
    with lifecycle_lock(root, "write-scope-registry"):
        for _, current in _active_write_leases(root, now):
            if write_scopes_overlap(normalized_scope, current["write_scope"]):
                raise LifecycleError(
                    "Write scope conflicts with active lease "
                    f"{current['lease_id']} owned by task {current.get('task_id')}"
                )
        path = contained_control_path(root, f".ai-lifecycle/leases/{lease_id}.json")
        atomic_create_json(path, lease)
    return lease


def _assert_write_scope_lease_unlocked(
    root: Path, lease: dict[str, Any] | None
) -> None:
    if lease is None:
        return
    lease_id = validate_identifier(lease.get("lease_id"), "lease_id", min_length=8)
    path = contained_control_path(
        root, f".ai-lifecycle/leases/{lease_id}.json"
    )
    active = {item_path: item for item_path, item in _active_write_leases(root, time.time())}
    current = active.get(path)
    if current is None:
        raise LeaseExpiredOrMissingError("Write-scope lease is missing or expired")
    for field in (
        "lease_id",
        "task_id",
        "lifecycle_run_id",
        "owner",
        "owner_token",
        "write_scope",
    ):
        if current.get(field) != lease.get(field):
            raise LifecycleError(f"Write-scope lease binding changed: {field}")


@contextmanager
def write_scope_lease_guard(
    root: Path, lease: dict[str, Any] | None
) -> Iterator[None]:
    """Revalidate a lease and prevent competing acquisition during integration."""
    if lease is None:
        yield
        return
    with lifecycle_lock(root, "write-scope-registry"):
        _assert_write_scope_lease_unlocked(root, lease)
        yield


def release_write_scope_lease(root: Path, lease: dict[str, Any] | None) -> None:
    if lease is None:
        return
    with lifecycle_lock(root, "write-scope-registry"):
        _assert_write_scope_lease_unlocked(root, lease)
        path = contained_control_path(
            root, f".ai-lifecycle/leases/{lease['lease_id']}.json", must_exist=True
        )
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise LeaseExpiredOrMissingError(
                "Write-scope lease disappeared during release"
            ) from exc


@contextmanager
def write_scope_lease(
    root: Path,
    *,
    task_id: str,
    run_id: str,
    owner: str,
    write_scope: list[str],
    ttl_seconds: int,
) -> Iterator[dict[str, Any] | None]:
    lease = acquire_write_scope_lease(
        root,
        task_id=task_id,
        run_id=run_id,
        owner=owner,
        write_scope=write_scope,
        ttl_seconds=ttl_seconds,
    )
    try:
        yield lease
    finally:
        try:
            release_write_scope_lease(root, lease)
        except LeaseExpiredOrMissingError:
            # An expired lease may already have been pruned by another process.
            pass


def lifecycle_dir(root: Path) -> Path:
    return root / ".ai-lifecycle"


ENVIRONMENT_VARIABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _portable_relative(value: Any, *, allow_dot: bool) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\\" in value
        or "\x00" in value
        or "\r" in value
        or "\n" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        return False
    if value == ".":
        return allow_dot
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _validate_gate_check(check: Any, prefix: str, seen_ids: set[str]) -> list[str]:
    errors: list[str] = []
    if not isinstance(check, dict):
        return [f"{prefix} must be an object"]
    required_fields = {"id", "description", "required", "command", "cwd", "timeout_seconds"}
    missing = sorted(required_fields - set(check))
    if missing:
        errors.append(f"{prefix} is missing: {', '.join(missing)}")
    check_id = check.get("id")
    try:
        check_id = validate_identifier(check_id, f"{prefix}.id")
    except LifecycleError as exc:
        errors.append(str(exc))
    else:
        if check_id in seen_ids:
            errors.append(f"Duplicate quality-gate check id: {check_id}")
        seen_ids.add(check_id)
    description = check.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 4000:
        errors.append(f"{prefix}.description must be 1-4000 characters")
    if not isinstance(check.get("required"), bool):
        errors.append(f"{prefix}.required must be boolean")
    command = check.get("command")
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 128
        or not all(
            isinstance(item, str)
            and 1 <= len(item) <= 4096
            and "\x00" not in item
            and "\r" not in item
            and "\n" not in item
            for item in command
        )
    ):
        errors.append(f"{prefix}.command must contain 1-128 bounded arguments")
    if not _portable_relative(check.get("cwd"), allow_dot=True):
        errors.append(f"{prefix}.cwd must be a portable relative directory")
    timeout = check.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 7200:
        errors.append(f"{prefix}.timeout_seconds must be between 1 and 7200")
    forward_env = check.get("forward_env", [])
    if (
        not isinstance(forward_env, list)
        or len(forward_env) > 64
        or len(forward_env) != len(set(forward_env))
        or not all(
            isinstance(item, str) and ENVIRONMENT_VARIABLE_NAME.fullmatch(item)
            for item in forward_env
        )
    ):
        errors.append(f"{prefix}.forward_env must contain unique environment-variable names")
    else:
        sensitive = sorted(item for item in forward_env if sensitive_environment_name(item))
        if sensitive:
            errors.append(
                f"{prefix}.forward_env may not expose sensitive variables: "
                + ", ".join(sensitive)
            )
    evidence_type = check.get("evidence_type")
    if evidence_type is not None:
        try:
            validate_identifier(evidence_type, f"{prefix}.evidence_type")
        except LifecycleError as exc:
            errors.append(str(exc))
    operating_systems = check.get("operating_systems")
    if operating_systems is not None and (
        not isinstance(operating_systems, list)
        or not operating_systems
        or len(operating_systems) != len(set(operating_systems))
        or any(item not in {"windows", "linux", "macos"} for item in operating_systems)
    ):
        errors.append(
            f"{prefix}.operating_systems must be a unique subset of windows, linux, macos"
        )
    return errors


def validate_project_config(config: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict):
        return ["project.json must contain an object"]
    if config.get("schema_version") != 1:
        errors.append("project.json schema_version must be 1")

    project = config.get("project")
    if not isinstance(project, dict):
        errors.append("project must be an object")
    else:
        for key in ("id", "name", "type", "repository_root", "risk_level", "description"):
            if key not in project:
                errors.append(f"project.{key} is required")
        if project.get("repository_root") != ".":
            errors.append("project.repository_root must be '.' for portability")
        if project.get("risk_level") not in {"low", "standard", "high"}:
            errors.append("project.risk_level must be low, standard, or high")

    lifecycle = config.get("lifecycle")
    if not isinstance(lifecycle, dict):
        errors.append("lifecycle must be an object")
        enabled: list[str] = []
    else:
        enabled = lifecycle.get("phases", [])
        if (
            not isinstance(enabled, list)
            or not enabled
            or any(phase not in PHASES for phase in enabled)
            or len(enabled) != len(set(enabled))
        ):
            errors.append("lifecycle.phases must be a non-empty unique subset of canonical phases")
            enabled = []
        elif enabled != [phase for phase in PHASES if phase in enabled]:
            errors.append("lifecycle.phases must preserve canonical phase order")
        approvals = lifecycle.get("human_approvals", [])
        if not isinstance(approvals, list) or any(phase not in enabled for phase in approvals):
            errors.append("lifecycle.human_approvals must be a subset of enabled phases")
        if "deployment" in enabled and "deployment" not in approvals:
            errors.append("deployment must require human approval")
        disabled = lifecycle.get("disabled", {})
        if not isinstance(disabled, dict):
            errors.append("lifecycle.disabled must be an object")
        elif any(
            phase not in PHASES or not isinstance(reason, str) or not reason.strip()
            for phase, reason in disabled.items()
        ):
            errors.append("disabled phases require canonical names and non-empty reasons")
        elif set(disabled) != set(PHASES) - set(enabled):
            errors.append("lifecycle.disabled must document every disabled phase and no enabled phase")
        if "deployment" in enabled:
            required_before_deployment = {
                "requirements",
                "architecture",
                "implementation",
                "review",
                "verification",
                "integration",
            }
            missing = sorted(required_before_deployment - set(enabled))
            if missing:
                errors.append(
                    "deployment requires lifecycle obligations: " + ", ".join(missing)
                )
        if "operations" in enabled and "deployment" not in enabled:
            errors.append("operations requires deployment")

    agents = config.get("agents")
    if not isinstance(agents, dict):
        errors.append("agents must be an object")
    else:
        if not isinstance(agents.get("enabled"), bool):
            errors.append("agents.enabled must be boolean")
        max_parallel = agents.get("max_parallel")
        if not isinstance(max_parallel, int) or not 1 <= max_parallel <= 16:
            errors.append("agents.max_parallel must be between 1 and 16")
        if agents.get("ownership_strategy") not in {"exclusive-path", "worktree"}:
            errors.append("agents.ownership_strategy must be exclusive-path or worktree")

    stack = config.get("stack")
    stack_fields = {
        "languages",
        "frameworks",
        "package_managers",
        "build_systems",
        "databases",
        "deployment_targets",
    }
    if not isinstance(stack, dict):
        errors.append("stack must be an object")
    elif set(stack) != stack_fields:
        errors.append("stack must contain exactly the supported stack categories")
    else:
        for name, values in stack.items():
            if (
                not isinstance(values, list)
                or len(values) > 128
                or len(values) != len(set(values))
                or not all(
                    isinstance(item, str) and item.strip() and len(item) <= 256
                    for item in values
                )
            ):
                errors.append(f"stack.{name} must contain unique bounded strings")
    quality_gates = config.get("quality_gates")
    if not isinstance(quality_gates, dict):
        errors.append("quality_gates must be an object")
    else:
        if set(quality_gates) != set(enabled):
            errors.append("quality_gates must contain exactly the enabled phases")
        seen_check_ids: set[str] = set()
        deployment_check_ids: set[str] = set()
        for phase in enabled:
            gate = quality_gates.get(phase)
            if not isinstance(gate, dict):
                errors.append(f"quality_gates.{phase} must be an object")
                continue
            artifacts = gate.get("required_artifacts")
            if (
                not isinstance(artifacts, list)
                or len(artifacts) > 256
                or len(artifacts) != len(set(artifacts))
                or not all(_portable_relative(item, allow_dot=False) for item in artifacts)
            ):
                errors.append(
                    f"quality_gates.{phase}.required_artifacts must contain unique portable paths"
                )
            checks = gate.get("checks")
            if not isinstance(checks, list) or len(checks) > 128:
                errors.append(f"quality_gates.{phase}.checks must be a bounded array")
            else:
                for index, check in enumerate(checks):
                    errors.extend(
                        _validate_gate_check(
                            check,
                            f"quality_gates.{phase}.checks[{index}]",
                            seen_check_ids,
                        )
                    )
                    if phase == "deployment" and isinstance(check, dict) and isinstance(
                        check.get("id"), str
                    ):
                        deployment_check_ids.add(check["id"])
            if phase != "deployment" and (
                "post_required_artifacts" in gate or "post_checks" in gate
            ):
                errors.append(f"quality_gates.{phase} cannot define deployment post gates")
        if "deployment" in enabled:
            deployment_gate = quality_gates.get("deployment")
            if not isinstance(deployment_gate, dict):
                errors.append("quality_gates.deployment must be an object")
            else:
                post_artifacts = deployment_gate.get("post_required_artifacts")
                if (
                    not isinstance(post_artifacts, list)
                    or len(post_artifacts) > 256
                    or len(post_artifacts) != len(set(post_artifacts))
                    or not all(
                        _portable_relative(item, allow_dot=False)
                        for item in post_artifacts
                    )
                ):
                    errors.append(
                        "quality_gates.deployment.post_required_artifacts must contain unique portable paths"
                    )
                post_checks = deployment_gate.get("post_checks")
                if not isinstance(post_checks, list) or len(post_checks) > 128:
                    errors.append("quality_gates.deployment.post_checks must be a bounded array")
                else:
                    for index, check in enumerate(post_checks):
                        errors.extend(
                            _validate_gate_check(
                                check,
                                f"quality_gates.deployment.post_checks[{index}]",
                                seen_check_ids,
                            )
                        )
                        if isinstance(check, dict) and isinstance(check.get("id"), str):
                            deployment_check_ids.add(check["id"])
            required_pre = {
                ".ai-lifecycle/artifacts/deployment/deployment-plan.json",
                ".ai-lifecycle/artifacts/deployment/environment-readiness.json",
                ".ai-lifecycle/artifacts/deployment/rollback-plan.md",
            }
            required_post = {
                ".ai-lifecycle/artifacts/deployment/deployment-record.json",
                ".ai-lifecycle/artifacts/deployment/post-deployment-verification.json",
            }
            configured_pre = deployment_gate.get("required_artifacts")
            configured_post = deployment_gate.get("post_required_artifacts")
            if (
                not isinstance(configured_pre, list)
                or not all(isinstance(item, str) for item in configured_pre)
                or not required_pre.issubset(set(configured_pre))
            ):
                errors.append(
                    "deployment required_artifacts must include plan, environment readiness, and rollback plan"
                )
            if (
                not isinstance(configured_post, list)
                or not all(isinstance(item, str) for item in configured_post)
                or not required_post.issubset(set(configured_post))
            ):
                errors.append(
                    "deployment post_required_artifacts must include deployment record and post-deployment verification"
                )
            if not isinstance(deployment_gate.get("post_checks"), list):
                errors.append("quality_gates.deployment.post_checks must be an array")
        promotion_matrix = lifecycle.get("promotion_matrix") if isinstance(lifecycle, dict) else None
        if promotion_matrix is not None:
            if "deployment" not in enabled:
                errors.append("lifecycle.promotion_matrix requires deployment")
            elif isinstance(promotion_matrix, dict):
                environments = promotion_matrix.get("environments")
                if isinstance(environments, list):
                    names = [
                        environment.get("name")
                        for environment in environments
                        if isinstance(environment, dict)
                    ]
                    if len(names) != len(environments) or len(names) != len(set(names)):
                        errors.append(
                            "promotion_matrix environments must have unique names"
                        )
                    finals = [
                        index
                        for index, environment in enumerate(environments)
                        if isinstance(environment, dict)
                        and environment.get("final") is True
                    ]
                    if finals != [len(environments) - 1]:
                        errors.append(
                            "exactly the last promotion_matrix environment must be final"
                        )
                    for environment in environments:
                        if not isinstance(environment, dict):
                            continue
                        if (
                            environment.get("name") == "production"
                            and (
                                environment.get("final") is not True
                                or environment.get("approval_policy")
                                != "human-required"
                            )
                        ):
                            errors.append(
                                "production must be the final human-approved environment"
                            )
                    referenced_ids = {
                        item
                        for environment in environments
                        if isinstance(environment, dict)
                        for key in ("pre_check_ids", "post_check_ids")
                        for item in environment.get(key, [])
                        if isinstance(item, str)
                    }
                    unknown = sorted(referenced_ids - deployment_check_ids)
                    if unknown:
                        errors.append(
                            "promotion_matrix references unknown deployment check ids: "
                            + ", ".join(unknown)
                        )
    integration = config.get("integration")
    if not isinstance(integration, dict):
        errors.append("integration must be an object")
    else:
        if integration.get("tool_registry") != ".ai-lifecycle/tool-registry.json":
            errors.append("integration.tool_registry must use the canonical control path")
        default_timeout = integration.get("default_timeout_seconds")
        if (
            isinstance(default_timeout, bool)
            or not isinstance(default_timeout, int)
            or not 1 <= default_timeout <= 7200
        ):
            errors.append("integration.default_timeout_seconds must be between 1 and 7200")
        retry = integration.get("retry")
        if not isinstance(retry, dict):
            errors.append("integration.retry must be an object")
        else:
            attempts = retry.get("max_attempts")
            base_delay = retry.get("base_delay_seconds")
            max_delay = retry.get("max_delay_seconds")
            if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 10:
                errors.append("integration.retry.max_attempts must be between 1 and 10")
            if (
                isinstance(base_delay, bool)
                or not isinstance(base_delay, (int, float))
                or not 0 <= base_delay <= 300
                or isinstance(max_delay, bool)
                or not isinstance(max_delay, (int, float))
                or not 0 <= max_delay <= 300
                or (
                    isinstance(base_delay, (int, float))
                    and isinstance(max_delay, (int, float))
                    and base_delay > max_delay
                )
            ):
                errors.append("integration retry delays must satisfy 0 <= base <= max <= 300")
        retention = integration.get("evidence_retention_days")
        if isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 3650:
            errors.append("integration.evidence_retention_days must be between 1 and 3650")
    policy = config.get("policy")
    if not isinstance(policy, dict):
        errors.append("policy must be an object")
    else:
        expected_policy = {
            "external_mutations": "require-explicit-authority",
            "production_approval": "human-required",
            "secrets": "environment-or-secret-manager",
            "network": "least-required",
            "data_classification": "internal",
        }
        for name, expected in expected_policy.items():
            if policy.get(name) != expected:
                errors.append(f"policy.{name} must be {expected}")
    return errors


def validate_registry(registry: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(registry, dict) or registry.get("schema_version") != 1:
        return ["tool-registry.json must be an object with schema_version 1"]
    tools = registry.get("tools")
    if not isinstance(tools, list):
        return ["tool-registry.json tools must be an array"]
    if len(tools) > 256:
        return ["tool-registry.json cannot contain more than 256 tools"]
    seen: set[str] = set()
    for index, tool in enumerate(tools):
        prefix = f"tools[{index}]"
        if not isinstance(tool, dict):
            errors.append(f"{prefix} must be an object")
            continue
        tool_id = tool.get("id")
        try:
            tool_id = validate_identifier(tool_id, f"{prefix}.id")
        except LifecycleError as exc:
            errors.append(str(exc))
        else:
            if tool_id in seen:
                errors.append(f"duplicate tool id: {tool_id}")
            seen.add(tool_id)
        if tool.get("availability") not in {"unknown", "available", "unavailable", "blocked"}:
            errors.append(f"{prefix}.availability is invalid")
        capabilities = tool.get("capabilities")
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) and item for item in capabilities
        ):
            errors.append(f"{prefix}.capabilities must be an array of strings")
        elif (
            not capabilities
            or len(capabilities) > 128
            or len(capabilities) != len(set(capabilities))
        ):
            errors.append(f"{prefix}.capabilities must be non-empty, unique, and bounded")
        authentication = tool.get("authentication")
        if not isinstance(authentication, dict):
            errors.append(f"{prefix}.authentication must be an object")
        else:
            environment_variables = authentication.get("environment_variables")
            if (
                not isinstance(environment_variables, list)
                or len(environment_variables) > 64
                or len(environment_variables) != len(set(environment_variables))
                or not all(
                    isinstance(item, str) and ENVIRONMENT_VARIABLE_NAME.fullmatch(item)
                    for item in environment_variables
                )
            ):
                errors.append(
                    f"{prefix}.authentication.environment_variables must be unique valid names"
                )
        side_effects = tool.get("side_effects")
        if (
            not isinstance(side_effects, list)
            or len(side_effects) > 32
            or len(side_effects) != len(set(side_effects))
            or not all(isinstance(item, str) and item for item in side_effects)
        ):
            errors.append(f"{prefix}.side_effects must be a unique bounded string array")
        if redact_json_value(tool) != tool:
            errors.append(f"{prefix} contains secret-bearing fields or values")
    return errors


def validate_state(config: dict[str, Any], state: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(state, dict) or state.get("schema_version") != 1:
        return ["state.json must be an object with schema_version 1"]
    enabled = config["lifecycle"]["phases"]
    statuses = state.get("phases")
    if not isinstance(statuses, dict) or set(statuses) != set(enabled):
        return ["state.phases must contain exactly the enabled phases"]
    for phase, phase_state in statuses.items():
        if not isinstance(phase_state, dict):
            errors.append(f"state.phases.{phase} must be an object")
            continue
        if phase_state.get("status") not in STATUSES - {"disabled"}:
            errors.append(f"state.phases.{phase}.status is invalid")
    if errors:
        return errors
    current = state.get("current_phase")
    if current is not None and current not in enabled:
        errors.append("state.current_phase must be null or an enabled phase")

    first_unapproved: str | None = None
    for phase in enabled:
        status = statuses[phase]["status"]
        if first_unapproved is None and status != "approved":
            first_unapproved = phase
        if first_unapproved is not None and phase != first_unapproved and status not in {"locked"}:
            prior = enabled[: enabled.index(phase)]
            if any(statuses[item]["status"] != "approved" for item in prior):
                errors.append(f"{phase} must remain locked until predecessors are approved")
    expected_current = first_unapproved
    if current != expected_current:
        errors.append(
            f"state.current_phase must be {expected_current!r} based on phase statuses"
        )
    if not isinstance(state.get("approvals", []), list):
        errors.append("state.approvals must be an array")
    if not isinstance(state.get("events", []), list):
        errors.append("state.events must be an array")
    return errors


def validate_json_schema_document(
    value: Any, schema_path: Path, label: str
) -> list[str]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except ImportError as exc:
        raise LifecycleError(
            "The jsonschema package is required for fail-closed lifecycle validation"
        ) from exc
    schema = load_json(schema_path)
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except SchemaError as exc:
        raise LifecycleError(f"Invalid JSON Schema {schema_path.name}: {exc.message}") from exc
    errors: list[str] = []
    for issue in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in issue.absolute_path) or "$"
        errors.append(f"{label} {location}: {issue.message}")
    return errors


def validate_all(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    config = load_json(
        contained_control_path(root, ".ai-lifecycle/project.json", must_exist=True)
    )
    registry = load_json(
        contained_control_path(
            root, ".ai-lifecycle/tool-registry.json", must_exist=True
        )
    )
    state = load_json(
        contained_control_path(root, ".ai-lifecycle/state.json", must_exist=True)
    )
    for folder in ("artifacts", "evidence", "tasks", "events", "logs"):
        path = contained_control_path(
            root, f".ai-lifecycle/{folder}", must_exist=True
        )
        if not path.is_dir():
            raise LifecycleError(f"Lifecycle control path is not a directory: {path}")
    schema_root = (
        Path(__file__).resolve().parent.parent / "references" / "schemas"
    )
    errors = (
        validate_project_config(config)
        + validate_json_schema_document(
            config,
            schema_root / "project.schema.json",
            "project.json",
        )
        + validate_registry(registry)
        + validate_json_schema_document(
            registry,
            schema_root / "tool-registry.schema.json",
            "tool-registry.json",
        )
        + validate_state(config, state)
        + validate_json_schema_document(
            state,
            schema_root / "state.schema.json",
            "state.json",
        )
    )
    if errors:
        raise LifecycleError("; ".join(errors))
    return config, registry, state


def initial_state(config: dict[str, Any], run_id: str) -> dict[str, Any]:
    phases = config["lifecycle"]["phases"]
    now = utc_now()
    return {
        "schema_version": 1,
        "lifecycle_run_id": run_id,
        "current_phase": phases[0],
        "phases": {
            phase: {
                "status": "ready" if index == 0 else "locked",
                "baseline": None,
                "last_evidence": None,
                "approval_nonce": None,
                "authorization": None,
                "updated_at": now,
            }
            for index, phase in enumerate(phases)
        },
        "approvals": [],
        "events": [],
        "created_at": now,
        "updated_at": now,
    }


def unlock_next(config: dict[str, Any], state: dict[str, Any], phase: str) -> None:
    phases = config["lifecycle"]["phases"]
    index = phases.index(phase)
    if index + 1 >= len(phases):
        state["current_phase"] = None
        return
    next_phase = phases[index + 1]
    next_state = state["phases"][next_phase]
    if next_state["status"] == "locked":
        next_state["status"] = "ready"
        next_state["updated_at"] = utc_now()
    state["current_phase"] = next_phase


def safe_subprocess_environment(
    forward_names: list[str], *, allow_sensitive: bool = False
) -> dict[str, str]:
    safe_names = {
        "PATH",
        "Path",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "LANG",
        "LC_ALL",
        "TERM",
        "CI",
    }
    if not all(isinstance(item, str) and item for item in forward_names):
        raise LifecycleError("Forwarded environment-variable names must be non-empty strings")
    sensitive = sorted(name for name in forward_names if sensitive_environment_name(name))
    if sensitive and not allow_sensitive:
        raise LifecycleError(
            "Repository-controlled steps may not receive sensitive environment variables: "
            + ", ".join(sensitive)
        )
    selected = safe_names.union(forward_names)
    return {name: value for name, value in os.environ.items() if name in selected}

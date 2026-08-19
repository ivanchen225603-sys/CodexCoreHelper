#!/usr/bin/env python3
"""Verify short-lived, host-issued Ed25519 lifecycle approval assertions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Mapping

from _lifecycle import LifecycleError, load_json


ASSERTION_ENV = "AI_LIFECYCLE_APPROVAL_ASSERTION"
TRUST_BUNDLE_ENV = "AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE"
ASSERTION_TYPE = "ai-lifecycle-approval+jws"
ASSERTION_AUDIENCE = "software-lifecycle-orchestrator"
SIGNING_CONTEXT = b"AI-LIFECYCLE-APPROVAL-V1\x00"
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_ASSERTION_LIFETIME_SECONDS = 600
CLOCK_SKEW_SECONDS = 60
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,255}$")
MAX_TRUSTED_ISSUERS = 64
MAX_ISSUER_AUDIENCES = 32
MAX_ISSUER_SUBJECTS = 1_000
MAX_ISSUER_KEYS = 32


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_base64url(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16_384:
        raise LifecycleError(f"{label} must be a non-empty base64url string")
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        raise LifecycleError(f"{label} is not valid base64url")
    unpadded = value.rstrip("=")
    padding = "=" * ((4 - len(unpadded) % 4) % 4)
    try:
        return base64.b64decode(
            unpadded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise LifecycleError(f"{label} is not valid base64url") from exc


def _read_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_DOCUMENT_BYTES:
            raise LifecycleError(
                f"{label} must be between 1 and {MAX_DOCUMENT_BYTES} bytes"
            )
        value = load_json(path, max_bytes=MAX_DOCUMENT_BYTES)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, LifecycleError) as exc:
        raise LifecycleError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a JSON object")
    return value


def _trusted_bundle_path(root: Path) -> Path:
    configured = os.environ.get(TRUST_BUNDLE_ENV)
    if not configured:
        raise LifecycleError(
            f"A host-managed Ed25519 trust bundle is required in {TRUST_BUNDLE_ENV}"
        )
    candidate = Path(configured).expanduser()
    if not candidate.is_absolute():
        raise LifecycleError(f"{TRUST_BUNDLE_ENV} must be an absolute path")
    if candidate.is_symlink():
        raise LifecycleError("The approval trust bundle may not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise LifecycleError("The approval trust bundle does not exist") from exc
    if not resolved.is_file():
        raise LifecycleError("The approval trust bundle must be a regular file")
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise LifecycleError(
            "The approval trust bundle must be outside the project repository"
        )
    if os.name != "nt":
        mode = resolved.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LifecycleError(
                "The approval trust bundle may not be group- or world-writable"
            )
    return resolved


def load_assertion(assertion_file: Path | None) -> dict[str, Any]:
    if assertion_file is not None:
        candidate = assertion_file.expanduser()
        if not candidate.is_absolute():
            raise LifecycleError("--approval-assertion-file must be an absolute path")
        if candidate.is_symlink():
            raise LifecycleError(
                "The approval assertion file may not be a symbolic link"
            )
        return _read_json_file(candidate.resolve(strict=True), "approval assertion")
    raw = os.environ.get(ASSERTION_ENV)
    if not raw:
        raise LifecycleError(
            "A signed approval assertion is required through "
            "--approval-assertion-file or AI_LIFECYCLE_APPROVAL_ASSERTION"
        )
    if len(raw.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise LifecycleError("The approval assertion is too large")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, child in pairs:
            if key in parsed:
                raise LifecycleError(
                    f"The approval assertion contains a duplicate JSON key: {key}"
                )
            parsed[key] = child
        return parsed

    def reject_nonstandard_number(value: str) -> None:
        raise LifecycleError(
            f"The approval assertion contains a non-standard number: {value}"
        )

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_number,
        )
    except LifecycleError:
        raise
    except json.JSONDecodeError as exc:
        raise LifecycleError(
            "The approval assertion environment value is invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise LifecycleError("The approval assertion must be a JSON object")
    return value


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise LifecycleError(f"Approval assertion {label} is invalid")
    return value


def _unique_identifiers(values: Any, label: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or not values or len(values) > maximum:
        raise LifecycleError(
            f"{label} must be a non-empty array with at most {maximum} entries"
        )
    validated = [
        _require_identifier(value, f"{label}[{index}]")
        for index, value in enumerate(values)
    ]
    if len(validated) != len(set(validated)):
        raise LifecycleError(f"{label} must contain unique identifiers")
    return validated


def _integer_timestamp(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LifecycleError(
            f"Approval assertion {label} must be an integer Unix timestamp"
        )
    return value


def _find_trusted_key(
    bundle: dict[str, Any], issuer: str, key_id: str, subject: str, audience: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if bundle.get("schema_version") != 1:
        raise LifecycleError("Approval trust bundle schema_version must be 1")
    issuers = bundle.get("issuers")
    if (
        not isinstance(issuers, list)
        or not issuers
        or len(issuers) > MAX_TRUSTED_ISSUERS
    ):
        raise LifecycleError(
            "Approval trust bundle issuers must be a non-empty array with at most "
            f"{MAX_TRUSTED_ISSUERS} entries"
        )
    if any(not isinstance(item, dict) for item in issuers):
        raise LifecycleError("Every approval trust bundle issuer must be an object")
    issuer_ids = [
        _require_identifier(item.get("issuer"), f"trust issuers[{index}].issuer")
        for index, item in enumerate(issuers)
    ]
    if len(issuer_ids) != len(set(issuer_ids)):
        raise LifecycleError("Approval trust bundle issuer identifiers must be unique")
    if issuer not in issuer_ids:
        raise LifecycleError("Approval assertion issuer is not trusted")
    issuer_entry = issuers[issuer_ids.index(issuer)]
    if issuer_entry.get("status", "active") != "active":
        raise LifecycleError("Approval assertion issuer is not active")
    audiences = _unique_identifiers(
        issuer_entry.get("audiences"),
        f"trust issuer {issuer} audiences",
        MAX_ISSUER_AUDIENCES,
    )
    if audience not in audiences:
        raise LifecycleError(
            "Approval assertion audience is not trusted for this issuer"
        )
    subjects = _unique_identifiers(
        issuer_entry.get("subjects"),
        f"trust issuer {issuer} subjects",
        MAX_ISSUER_SUBJECTS,
    )
    if subject not in subjects:
        raise LifecycleError(
            "Approval assertion subject is not authorized by the issuer"
        )
    keys = issuer_entry.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > MAX_ISSUER_KEYS:
        raise LifecycleError(
            f"Trust issuer {issuer} keys must be a non-empty array with at most "
            f"{MAX_ISSUER_KEYS} entries"
        )
    if any(not isinstance(item, dict) for item in keys):
        raise LifecycleError(f"Every trust issuer {issuer} key must be an object")
    key_ids = [
        _require_identifier(
            item.get("key_id"), f"trust issuer {issuer} keys[{index}].key_id"
        )
        for index, item in enumerate(keys)
    ]
    if len(key_ids) != len(set(key_ids)):
        raise LifecycleError(f"Trust issuer {issuer} key identifiers must be unique")
    if key_id not in key_ids:
        raise LifecycleError("Approval assertion key is not trusted")
    key = keys[key_ids.index(key_id)]
    if key.get("status", "active") != "active":
        raise LifecycleError("Approval assertion key is not active")
    return issuer_entry, key


def _verify_key_window(key: Mapping[str, Any], issued_at: int, expires_at: int) -> None:
    not_before = key.get("not_before")
    not_after = key.get("not_after")
    if not_before is not None and issued_at < _integer_timestamp(
        not_before, "key.not_before"
    ):
        raise LifecycleError("Approval assertion predates the trusted key window")
    if not_after is not None:
        trusted_until = _integer_timestamp(not_after, "key.not_after")
        if issued_at > trusted_until or expires_at > trusted_until:
            raise LifecycleError("Approval assertion exceeds the trusted key window")


def verify_approval_assertion(
    root: Path,
    assertion_file: Path | None,
    expected_claims: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify an assertion and return safe identity/audit metadata."""

    assertion = load_assertion(assertion_file)
    if set(assertion) != {"protected", "claims", "signature"}:
        raise LifecycleError(
            "Approval assertion must contain only protected, claims, and signature"
        )
    protected = assertion.get("protected")
    claims = assertion.get("claims")
    if not isinstance(protected, dict) or not isinstance(claims, dict):
        raise LifecycleError("Approval assertion protected and claims must be objects")
    if set(protected) != {"alg", "kid", "typ"}:
        raise LifecycleError("Approval assertion protected header is invalid")
    if protected.get("alg") != "EdDSA" or protected.get("typ") != ASSERTION_TYPE:
        raise LifecycleError(
            "Approval assertion must use EdDSA and the lifecycle assertion type"
        )

    issuer = _require_identifier(claims.get("iss"), "iss")
    subject = _require_identifier(claims.get("sub"), "sub")
    audience = claims.get("aud")
    if audience != ASSERTION_AUDIENCE:
        raise LifecycleError("Approval assertion audience is invalid")
    key_id = _require_identifier(protected.get("kid"), "kid")
    jti = _require_identifier(claims.get("jti"), "jti")

    issued_at = _integer_timestamp(claims.get("iat"), "iat")
    not_before = _integer_timestamp(claims.get("nbf"), "nbf")
    expires_at = _integer_timestamp(claims.get("exp"), "exp")
    now = int(time.time())
    if issued_at > now + CLOCK_SKEW_SECONDS or not_before > now + CLOCK_SKEW_SECONDS:
        raise LifecycleError("Approval assertion is not yet valid")
    if expires_at <= now - CLOCK_SKEW_SECONDS:
        raise LifecycleError("Approval assertion has expired")
    if not_before < issued_at - CLOCK_SKEW_SECONDS or expires_at <= not_before:
        raise LifecycleError("Approval assertion validity window is inconsistent")
    if expires_at - issued_at > MAX_ASSERTION_LIFETIME_SECONDS:
        raise LifecycleError("Approval assertion lifetime exceeds 10 minutes")

    required_claims = {
        "iss",
        "sub",
        "aud",
        "jti",
        "iat",
        "nbf",
        "exp",
        *expected_claims.keys(),
    }
    if set(claims) != required_claims:
        missing = sorted(required_claims - set(claims))
        extra = sorted(set(claims) - required_claims)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise LifecycleError(
            "Approval assertion claims are not canonical: " + "; ".join(details)
        )
    mismatches = [
        name
        for name, expected in expected_claims.items()
        if claims.get(name) != expected
    ]
    if mismatches:
        raise LifecycleError(
            "Approval assertion does not match the pending decision: "
            + ", ".join(sorted(mismatches))
        )

    bundle_path = _trusted_bundle_path(root)
    bundle = _read_json_file(bundle_path, "approval trust bundle")
    _, key = _find_trusted_key(bundle, issuer, key_id, subject, audience)
    _verify_key_window(key, issued_at, expires_at)
    public_key_bytes = _decode_base64url(
        key.get("public_key_base64url"), "trusted Ed25519 public key"
    )
    if len(public_key_bytes) != 32:
        raise LifecycleError("The trusted Ed25519 public key must contain 32 bytes")
    signature = _decode_base64url(assertion.get("signature"), "approval signature")
    if len(signature) != 64:
        raise LifecycleError("The Ed25519 approval signature must contain 64 bytes")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise LifecycleError(
            "The cryptography package with Ed25519 support is required for approvals"
        ) from exc
    signed = (
        SIGNING_CONTEXT + _canonical_json(protected) + b"." + _canonical_json(claims)
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, signed)
    except (InvalidSignature, ValueError) as exc:
        raise LifecycleError(
            "Approval assertion signature verification failed"
        ) from exc

    return {
        "algorithm": "Ed25519",
        "issuer": issuer,
        "subject": subject,
        "audience": audience,
        "key_id": key_id,
        "key_fingerprint": "sha256:" + hashlib.sha256(public_key_bytes).hexdigest(),
        "jti": jti,
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }

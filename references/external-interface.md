# External interface

All adapters translate provider-specific behavior into the canonical contracts below. JSON is the wire format. UTF-8, RFC 3339 UTC timestamps, UUID or equally collision-resistant IDs, and semantic spec versions are required.

Machine-readable schemas live in references/schemas/.

## Common headers

For HTTP mutations:

- Content-Type: application/json
- Accept: application/json
- Authorization: Bearer value obtained from the configured environment variable or OAuth client
- Idempotency-Key: stable per logical mutation
- X-Correlation-Id: stable across the lifecycle task
- X-Request-Id: unique per attempt
- X-Callback-Url: optional registered callback URL
- X-Signature-256: optional HMAC-SHA256 signature for configured shared-secret integrations

Never put credentials in URLs, request bodies, task prompts, or evidence.

## Task envelope

Required logical fields:

- spec_version;
- task_id, revision, created_at, and expires_at;
- correlation_id and optional causation_id;
- project_id, phase, and lifecycle_run_id;
- role and objective;
- inputs as artifact manifests;
- constraints and assumptions;
- dependencies;
- acceptance_criteria;
- permissions with read, write, network, and external mutation scopes;
- ownership with write_scope and forbidden_scope;
- tool_preferences;
- output_contract and result_schema;
- callback configuration;
- retry_policy.

An adapter must reject expired tasks, unknown major spec versions, missing required fields, unsupported capabilities, or permissions broader than the configured policy.

## Result envelope

Required logical fields:

- spec_version;
- task_id, revision, correlation_id, and run_id;
- provider and adapter version;
- status: succeeded, failed, partial, blocked, or cancelled;
- started_at and finished_at;
- summary;
- artifacts with URI, type, digest, and source;
- changed_paths and external_changes;
- checks with command or provider run ID, status, and evidence;
- findings with severity and location;
- assumptions and residual_risks;
- handoffs and invalidations;
- usage metadata when available;
- error object for non-success terminal states.

A succeeded result is not gate approval. The coordinator still validates schema, artifacts, write scope, review, and deterministic checks.

## Event envelope

Event types:

- task.accepted;
- task.started;
- task.progress;
- task.blocked;
- task.completed;
- task.failed;
- task.cancelled;
- artifact.created;
- artifact.superseded;
- gate.passed;
- gate.failed;
- approval.requested;
- approval.recorded;
- deployment.started;
- deployment.completed;
- deployment.failed;
- rollback.started;
- rollback.completed;
- incident.detected.

Fields:

- spec_version, event_id, event_type, occurred_at;
- source with adapter_id and run_id;
- subject with project_id, lifecycle_run_id, phase, and task_id;
- data;
- artifact references;
- trace with correlation_id and causation_id;
- delivery with attempt and idempotency_key;
- security metadata such as key_id and signature algorithm.

Consumers deduplicate by event_id and idempotency_key. Events may arrive more than once or out of order; consumers compare occurred_at and provider sequence when present.

## Human approval assertion

Human approval is a host-issued, short-lived Ed25519 envelope, not a project-provided actor
string. Generate the exact unsigned envelope with `lifecycle.py create-approval-request`; sign
the bytes below and supply the completed JSON through an absolute `--approval-assertion-file`
or the host-only `AI_LIFECYCLE_APPROVAL_ASSERTION` value:

    AI-LIFECYCLE-APPROVAL-V1\0
    + canonical_json(protected)
    + "."
    + canonical_json(claims)

`protected` contains only `alg=EdDSA`, `typ=ai-lifecycle-approval+jws`, and `kid`. Claims contain
only `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`, `project_id`, `lifecycle_run_id`, `phase`,
`decision`, `reason`, `baseline`, `approval_nonce`, `environment`, and `artifact_digest`. The
validity window is at most ten minutes. Canonical JSON uses UTF-8, sorted keys, no insignificant
whitespace, and the signature is unpadded base64url.

`AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE` names an absolute host-managed JSON file outside the
repository. It lists bounded, unique issuers; each issuer explicitly lists allowed audiences,
subjects, and active Ed25519 public keys. Omitting `subjects` does not mean everyone. The runtime
stores only safe identity metadata and the public-key fingerprint; it never persists the
assertion signature or private key. Every `jti` is single-use within lifecycle state.

## Completion receipt

A task dependency is satisfied only by exactly one canonical succeeded result plus
`completion-receipt-<adapter>.json`. The receipt binds adapter, task ID, revision, correlation
ID, lifecycle run, canonical result path, result digest, and acceptance time. Local result
artifacts are re-hashed before acceptance; external artifacts must use credential-free HTTPS and
a lowercase SHA-256 digest. A provider acknowledgement, 202 response, event file, or failed
result is not a completion receipt.

## HTTP adapter API

The generic bridge is deliberately limited to non-mutating task submission and status/event
collection. It rejects task envelopes whose permissions declare `external_mutations: true`.
Use an authenticated provider-native workflow for durable external changes until the adapter
can validate a host-issued authorization record.

The host, not the repository, supplies these trust settings before invocation:

- `AI_LIFECYCLE_TRUSTED_PROJECT_ROOT`: the exact resolved repository root;
- `AI_LIFECYCLE_ALLOWED_HTTP_ORIGINS`: a comma-separated list of normalized HTTPS origins
  (HTTP is accepted only for explicit localhost origins);
- `AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS`: a comma-separated allowlist of credential
  environment-variable names that registry entries may reference.

`http.task_url`, any returned `status_url` or `cancel_url`, and every credential reference are
rejected unless they satisfy those host allowlists. Redirects are not followed. The canonical
task file is `.ai-lifecycle/tasks/<task_id>/task.json`, and an invocation is accepted only for
the current project, lifecycle run, and in-progress phase before the task expires.

An HTTP task provider should implement:

### POST /v1/tasks

Accepts a task envelope.

Responses:

- 202 with run_id, accepted_at, status_url, and optional cancel_url;
- 200 only when the task completed synchronously and includes a result envelope;
- 400 for schema or unsupported spec errors;
- 401 or 403 for authentication or scope errors;
- 409 for an idempotency conflict;
- 422 for a valid envelope the provider cannot execute;
- 429 with Retry-After for rate limits;
- 5xx for provider failures.

### GET /v1/runs/{run_id}

Returns running state or the terminal result envelope. Polling uses exponential backoff with jitter and respects Retry-After.

### POST /v1/runs/{run_id}/cancel

Requests cancellation. Cancellation is idempotent. The provider reports whether execution stopped and which artifacts or mutations remain.

### GET /v1/capabilities

Returns adapter version, supported spec versions, capabilities, transports, limits, authentication, side-effect classes, and health.

### GET /health

Returns liveness and dependency readiness without exposing secrets.

## Webhook callback

The receiver:

1. reads the raw request body;
2. checks timestamp freshness and registered source;
3. resolves key_id to an environment or secret-manager reference;
4. verifies HMAC or provider-native signature with constant-time comparison;
5. rejects replayed event IDs;
6. validates the event schema;
7. persists the event before acknowledging;
8. returns 2xx only after durable acceptance.

Recommended signature input:

    <timestamp>.<raw_body_bytes>

Recommended header values:

    X-Webhook-Id: unique delivery ID
    X-Webhook-Timestamp: Unix seconds
    X-Webhook-Signature: v1=<hex hmac sha256>

Use provider-native schemes when available and document the difference in the registry. Do not silently accept unsigned callbacks.

Register signing keys on the selected adapter rather than passing a secret name on the command
line:

    "webhook": {
      "keys": [
        {
          "key_id": "primary",
          "algorithm": "hmac-sha256",
          "secret_env_var": "AI_LIFECYCLE_WEBHOOK_SECRET"
        }
      ]
    }

The secret environment-variable name must also appear in the host
`AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS` allowlist. Verify with `--adapter` and `--key-id`.
The receiver binds the event to the selected adapter, current project/run/in-progress phase,
canonical task, correlation ID, and persisted provider receipt. A verified event is atomically
created at `.ai-lifecycle/events/<event_id>.json`; an existing ID is a replay failure.

## CLI adapter contract

A portable CLI adapter:

- reads one task envelope from a file or standard input;
- writes structured progress or JSONL to standard output;
- writes human diagnostics to standard error;
- writes one final result envelope to the configured output path;
- never prompts in automation mode;
- accepts an explicit working directory and permission profile;
- supports cancellation through process termination and returns partial-state metadata.

Exit codes:

- 0: result envelope written and terminal status succeeded;
- 2: invalid task or schema;
- 3: authentication or permission failure;
- 4: required tool or capability unavailable;
- 5: transient provider failure;
- 6: timeout or cancellation;
- 10: task completed with failed or blocked status;
- 70: adapter internal error.

The result envelope, not free-form console text, is authoritative.

## MCP adapter contract

MCP is preferred for interactive tool access. Register:

- server ID;
- STDIO command or Streamable HTTP URL;
- authentication mode;
- required or optional status;
- allowed tools and resources;
- timeout and startup timeout;
- read-only versus mutation capabilities;
- tool-level approval rules.

Before dispatch:

1. verify server health and authentication;
2. list or search relevant tools;
3. select the narrowest tool;
4. validate input against the exposed schema;
5. record the tool name and non-secret arguments;
6. normalize the response into artifact or result envelopes.

MCP tool success still requires lifecycle validation. A required MCP server that cannot initialize blocks its dependent task.

The bundled generic MCP bridge is intentionally narrower than a full MCP host. It implements
the official newline-delimited STDIO transport and synchronous tool flow only:

1. `initialize` with the exact registry-pinned protocol version;
2. `notifications/initialized`;
3. cursor-paginated `tools/list`;
4. one synchronous `tools/call`.

It currently supports protocol revisions `2025-06-18` and `2025-11-25`. A different negotiated
version, Streamable HTTP configuration, task-augmented call, or tool whose
`execution.taskSupport` is `required` fails closed. The client advertises no roots, sampling,
elicitation, or tasks capabilities. Server-to-client requests receive JSON-RPC `-32601` and are
never executed; any message before initialization completes, unexpected response ID, duplicate
tool, cursor loop, malformed content block, or bound violation aborts the session. STDIO uses
one UTF-8 JSON-RPC message per line; `Content-Length` framing is not accepted.

Registry configuration for a STDIO server:

    "mcp": {
      "server_id": "local-inspector",
      "transport": "stdio",
      "protocol_version": "2025-11-25",
      "command": ["local-inspector", "--stdio"],
      "startup_timeout_seconds": 15,
      "timeout_seconds": 60,
      "max_output_bytes": 1048576,
      "max_pages": 20,
      "max_tools": 200,
      "environment_variables": [],
      "requires_network": false,
      "mutation_policy": "deny",
      "allowed_tools": [
        {
          "name": "query_status",
          "capability": "telemetry.query",
          "side_effect": "read-only",
          "input_schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": { "query": { "type": "string" } },
            "required": ["query"]
          }
        }
      ]
    }

The server-advertised `inputSchema` must exactly match the canonical JSON value pinned in the
registry, and arguments are validated against it before process launch. The selected server
tool must also advertise `annotations.readOnlyHint: true`; annotations are only a secondary
check and never grant permission. The generic bridge accepts only `mutation_policy: deny` and
`side_effect: read-only`. Use a provider-native integration for job triggers, remote writes, or
deployments.

Every name in `mcp.environment_variables` must be separately supplied by the host in
`AI_LIFECYCLE_ALLOWED_MCP_ENV_VARS`. Values are inherited by the child process but never written
to evidence. Command-line credential options are rejected.

Invoke a tool with an argument object stored under the canonical task directory:

    python scripts/mcp_bridge.py \
      --project-root <root> \
      --adapter <registry-id> \
      --task-file <root>/.ai-lifecycle/tasks/<task-id>/task.json \
      --tool <allowlisted-tool> \
      --arguments-file <root>/.ai-lifecycle/tasks/<task-id>/mcp-arguments.json \
      --execute

The task must match the current project, lifecycle run, and in-progress phase and must not be
expired, and `tool_preferences` must explicitly name the adapter. Read scopes and network
permission are checked against registry policy. The arguments file must be a regular non-link
file below the canonical task directory. The STDIO server runs in a new empty system-temporary
working directory with no repository, `.git`, or `.ai-lifecycle` copy. A generic MCP server
therefore cannot inspect repository files implicitly; pass bounded data as explicit tool
arguments/artifacts or use a dedicated sandboxed provider adapter. Validated,
redacted evidence is atomically created below `.ai-lifecycle/evidence/<phase>/`; a normalized
successful result is atomically created as `result-<adapter>.json`, remains bound to the
lifecycle run, and receives `completion-receipt-<adapter>.json`. Tool-level `isError` produces a
uniquely named failed result with no completion receipt and a non-zero exit status, so a safe
retry is not blocked; it is never reported as success.

The process tree is stopped before a result or completion receipt is accepted. After shutdown,
the bridge rechecks the task, phase state, registry policy, and arguments digest while holding
the lifecycle state lock; a shutdown or binding failure produces only failure evidence.

Protocol references:

- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks

## Provider adapter manifest

Each registry entry maps canonical operations to provider behavior:

- manifest_version and adapter_id;
- provider and adapter version;
- transports;
- capabilities;
- authentication references;
- health check;
- operation map;
- input and output transforms;
- error classification;
- retry and timeout policy;
- idempotency support;
- side-effect classification;
- required approvals;
- redaction fields;
- evidence retention.

Transforms must be deterministic and versioned. Provider-specific fields may be retained under extensions, but canonical required fields cannot be omitted.

## Security rules

- Use OAuth, workload identity, or short-lived tokens when supported.
- Store only secret references in configuration.
- Redact authorization headers, cookies, private keys, tokens, passwords, and provider secrets from logs.
- Reject secret-bearing task, result, or webhook envelopes before durable persistence. Raw coding-agent
  output may be retained only as a structured redacted record, never verbatim.
- Restrict callback URLs and HTTP endpoints to configured HTTPS origins, except explicit localhost development adapters.
- Resolve DNS and redirect behavior according to the host security policy; do not follow redirects to unapproved origins.
- Cap request and response sizes.
- Validate archive and artifact paths before extraction.
- Treat generated code, patches, test data, and infrastructure plans as untrusted until reviewed.

## Reliability rules

- Every mutation is idempotent or explicitly non-retriable.
- Default retryable classes are connection reset, timeout before acceptance, 429, and selected 5xx responses.
- Do not retry invalid input, authentication, permission, policy rejection, or deterministic task failures.
- Use bounded exponential backoff with jitter.
- Record request ID, idempotency key, provider run ID, attempt number, status, duration, and redacted error.
- On ambiguous timeout after a mutation, query by idempotency key or provider run ID before retrying.

## Versioning

Increment:

- patch for clarifications without wire changes;
- minor for backward-compatible optional fields or event types;
- major for incompatible required fields or semantics.

Adapters declare supported ranges. The coordinator blocks instead of guessing across incompatible major versions.

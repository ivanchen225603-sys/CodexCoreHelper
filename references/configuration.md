# Configuration

The project-local control directory is .ai-lifecycle/. It is portable and contains no credentials.

## Files

- project.json: project identity, enabled phases, risk, approval policy, and gate commands;
- tool-registry.json: verified tool and adapter capabilities;
- state.json: state-machine output; edit only through scripts/lifecycle.py;
- artifacts/: durable phase outputs or manifests for external artifacts;
- evidence/: deterministic checks, provider receipts, and normalized reports;
- tasks/: canonical task and result envelopes;
- events/: normalized external events;
- logs/: redacted orchestrator diagnostics when needed.

Commit project.json, tool-registry.json, approved artifacts, and reproducible evidence according to repository policy. Avoid committing large provider logs, temporary task context, personal data, or secret-bearing material.

## Portability principles

- Use paths relative to repository_root.
- Store commands as argument arrays, never shell strings.
- Keep provider selection optional and capability-based.
- Keep secret names as environment-variable references.
- Detect stack and repository conventions; do not replace them with defaults.
- Allow phases and gates to be enabled, disabled, or extended with recorded rationale.
- Use JSON schemas with an explicit schema_version.
- Keep platform-specific commands in profiles selected by operating system.

## Project profile

project.json contains:

- schema_version;
- project: id, name, type, repository_root, risk_level, and description;
- stack: detected languages, frameworks, package managers, build systems, databases, and deployment targets;
- lifecycle: ordered phases, disabled phase rationale, approvals, and invalidation rules;
- agents: enabled, max_parallel, ownership strategy, default roles, and optional model preferences;
- quality_gates: per-phase checks;
- integration: registry file, default timeout, retries, callback policy, and evidence retention;
- policy: external mutations, production approval, secrets, network, and data classification.

Risk levels:

- low: prototype, internal tool, or reversible low-impact change without sensitive data;
- standard: ordinary production software;
- high: sensitive data, financial or safety impact, regulated use, critical infrastructure, high availability, irreversible migration, or broad user impact.

Risk modifies gates but never reduces repository-required checks.

## Tool registry

tool-registry.json begins with optional entries in unknown state. Discovery updates an entry only with observed facts:

- executable resolved and version read;
- MCP server connected and required tools exposed;
- API health and authentication verified;
- native skill or tool available in the current runtime.

Availability values:

- unknown: not checked;
- available: verified for declared capabilities;
- unavailable: provider or executable absent;
- blocked: present but authentication, permission, policy, quota, or health prevents use.

## Enabled phases

Default:

- discovery;
- requirements;
- architecture;
- prototype;
- implementation;
- review;
- verification;
- integration;
- deployment;
- operations.

Disable prototype only when no visual or interaction uncertainty exists. Operations may be configured as release-readiness only for generated examples that will not be deployed. Record any disabled phase and why its obligations are covered elsewhere or out of scope.

## Approval defaults

Default human approvals:

- requirements;
- architecture;
- prototype when enabled;
- verification;
- deployment.

Production always requires explicit human approval. Projects may add approvals. Removing a default approval requires an explicit project policy decision and cannot remove production approval.

The CLI does not infer identity from text arguments or environment-variable names. Generate the
exact pending claim set with `lifecycle.py create-approval-request`. A trusted host signer returns
a short-lived Ed25519 assertion; `lifecycle.py decide` verifies it against the public-key bundle
named by `AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE`. The bundle must live outside the project and must
explicitly list every allowed issuer, audience, subject, and active key. `--actor`, when supplied,
is only an equality check against the signed subject.

The assertion binds the project, lifecycle run, phase, decision, reason, exact gate baseline,
one-time nonce, environment, and artifact digest. Its `jti` is single use and its lifetime cannot
exceed ten minutes. Missing cryptography support, an omitted subject allowlist, an invalid key,
expiry, replay, or any claim mismatch fails closed. Private signing keys never belong in the
repository, assertion, state, evidence, or trust bundle.

## Environment promotion matrix

New projects default to `development -> test -> staging -> production`. Every environment has a
pre-deployment gate, an authorization policy, a post-deployment gate, and optional check-ID
selection. Evidence and artifacts use environment subdirectories. All environments must promote
the same lowercase SHA-256 release-candidate digest in order; only the final environment unlocks
operations, and production must be final and human-approved.

Projects created before the matrix existed retain a safe single-production fallback. Migrating
an active deployment requires an explicit reopen/versioned state migration; changing a matrix or
gate contract after authorization invalidates the authorization instead of silently remapping it.

## Gate check format

Each check has:

- id and description;
- required;
- command as an argument array;
- cwd relative to the repository;
- timeout_seconds;
- environment variable names to forward;
- evidence type;
- operating_systems when platform-specific.

Example:

    {
      "id": "unit-tests",
      "description": "Run repository unit tests",
      "required": true,
      "command": ["dotnet", "test", "--no-restore"],
      "cwd": ".",
      "timeout_seconds": 1200,
      "forward_env": [],
      "evidence_type": "test"
    }

Do not place tokens or inline environment values in commands.

Before any configured command runs, the host must set
`AI_LIFECYCLE_TRUSTED_PROJECT_ROOT` to the resolved repository root. Sensitive environment
variables are not forwarded to repository-controlled checks. Provider secrets and allowed HTTP
origins are host policy, not project policy.

The generic HTTP/webhook adapter additionally requires the host to set
`AI_LIFECYCLE_ALLOWED_HTTP_ORIGINS` and
`AI_LIFECYCLE_ALLOWED_CREDENTIAL_ENV_VARS`. The registry may name `http.task_url`, bearer/HMAC
credential environment variables, and `webhook.keys`, but it cannot grant trust to them. The
host allowlists are authoritative and are never read from project-controlled configuration.

Deployment has separate pre-authorization and post-deployment contracts:

- `required_artifacts` and `checks` cover the deployment plan, environment readiness, artifact
  digest, migration plan, and rollback readiness;
- an approved decision moves the phase to `authorized` without advancing the lifecycle;
- `post_required_artifacts` and `post_checks` cover provider receipts, health, smoke, synthetic,
  security, and rollback viability;
- `complete-deployment` approves the phase only when the environment and artifact digest match
  the authorization and the authorized pre-deployment baseline is still current;
- deployment plan and environment-readiness JSON bind the environment and artifact digest, while
  deployment record and post-verification JSON must bind the authorization decision and provider
  run IDs, report successful status, and contain passing checks.

Minimum JSON shapes are:

    deployment-plan.json:
      {"environment":"production","artifact_digest":"sha256:...","steps":["..."]}
    environment-readiness.json:
      {"environment":"production","artifact_digest":"sha256:...","checks":[{"status":"passed"}]}
    deployment-record.json:
      {"environment":"production","artifact_digest":"sha256:...","provider_run_id":"...","authorization_decision_id":"...","status":"succeeded"}
    post-deployment-verification.json:
      {"environment":"production","artifact_digest":"sha256:...","provider_run_id":"...","authorization_decision_id":"...","status":"passed","checks":[{"status":"passed"}]}

The integration `release-candidate.json` minimally contains non-empty `artifact_digest` and
`provenance`. Review findings use a `findings` array; unresolved critical/high entries block the
review gate.

## Brownfield projects

Initialization must:

1. inspect existing workflows, package locks, build scripts, test runners, deployment files, and documentation;
2. set stack fields from evidence;
3. import existing commands as candidate checks without changing them;
4. mark prior phases as external_baseline only when approved artifacts exist and their digests are captured;
5. start the first phase affected by the user's requested change.

Do not force a complete rewrite of historical documentation before making a scoped change. Create the minimum trace needed for the current baseline and expand as risk requires.

## Greenfield projects

Initialization captures the user requirement, selects a stack through documented criteria, then generates repository structure, locks, tests, documentation, CI, and deployment configuration incrementally. Do not select a cloud provider, paid service, database, framework, or license when the choice materially affects cost or product direction without evidence or user approval.

## Configuration migration

Scripts reject unsupported schema major versions. A migration:

- preserves state and evidence;
- writes a backup or new version before replacement;
- records old and new digests;
- validates before activation;
- never changes approval history.

## Secret configuration

Allowed:

- OPENAI_API_KEY as an environment-variable name;
- secret manager URI;
- provider credential profile name.

Forbidden:

- secret values;
- access tokens;
- private keys;
- authenticated URLs;
- session cookies;
- copied authentication files.

Evidence records only whether a required secret reference was available, never its value.

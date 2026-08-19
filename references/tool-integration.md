# Tool integration

The orchestrator routes work through capabilities declared in .ai-lifecycle/tool-registry.json. Provider names are replaceable. Never assume a connector is installed because it appears in the default template.

## Registry requirements

Each tool entry declares:

- id, display_name, provider, and kind;
- capabilities such as requirement.read, design.write, code.review, test.run, ci.read, deploy.execute, or telemetry.query;
- transport: native, skill, mcp, cli, http, or webhook;
- availability: unknown, available, unavailable, or blocked;
- read and write scopes;
- authentication type and environment-variable names, never values;
- command or endpoint templates;
- machine-readable input and output modes;
- timeout, retry, rate-limit, and idempotency behavior;
- external side effects and approval requirements;
- health-check method;
- version observed and last_verified_at.

Route only to an entry whose capability, availability, permissions, and side-effect policy match the task.

For the bundled generic HTTP/webhook bridge, repository registry entries contain only endpoint
and secret-reference names. The trusted host must separately assert the exact project root and
allowlist both endpoint origins and credential environment-variable names. The example
`generic-http-task` entry remains `unknown` until all of those facts are verified. The generic
bridge supports task submission and signed event collection, but rejects external-mutation
permissions; use a provider-native authenticated integration for remote writes and deployment.

For the bundled generic MCP bridge, only explicitly registered STDIO servers and read-only
synchronous tools are executable. A registry entry pins the MCP protocol revision, argv array,
timeouts, cumulative stdout/stderr limit, tool/page limits, host-allowlisted environment names,
network expectation, and an exact `input_schema` for every allowed tool. The process is started
without a shell. The bridge verifies the canonical lifecycle task and phase before launch,
performs initialization and complete paginated discovery, checks schema drift, validates
arguments and structured output, redacts sensitive output, and atomically persists evidence and
a result envelope.

The generic STDIO server runs from an empty temporary working directory and receives no project
or control-plane copy. Its process tree must stop successfully before completion evidence is
accepted. Repository-aware MCP servers require a dedicated sandboxed adapter with explicit
artifact mounting; changing the generic server's working directory to the repository is not a
supported shortcut.

`streamable_http`, mutation-enabled tools, task-augmented tools/calls, sampling, elicitation,
roots, and server-originated requests are unsupported by this generic bridge and fail closed.
Use an installed native MCP host or a dedicated provider adapter when one of those capabilities
is required; never weaken the generic bridge's policy to make an incompatible server pass.

## Capability discovery order

1. Installed domain skills and native tools.
2. Connected MCP tools and resources.
3. Project-local or system CLI discovered on PATH.
4. Configured HTTP API.
5. Signed webhook workflow.
6. Human handoff or generated integration instructions.

Discovery is read-only. Installing a plugin, connecting an account, authenticating, or creating a remote resource requires user authority.

## Requirements and work tracking

Typical capabilities:

- requirement.import and requirement.export;
- issue.create, issue.update, issue.link, and issue.search;
- decision.record;
- traceability.sync;
- approval.request and approval.read.

Applicable providers include GitHub Issues, Linear, Jira, Azure Boards, Asana, Notion, or repository files. Keep stable internal IDs and map provider IDs in artifact manifests. Do not make an external tracker the only copy of release-critical acceptance criteria unless retrieval is part of the release gate.

## Research and competitor analysis

Use repository sources first, then authorized web or knowledge tools. Record URL, publication date, retrieval time, quoted evidence limits, confidence, and inference. Separate current facts from assumptions. Research tools never approve product requirements.

## Prototype and design tools

Capabilities:

- design.read, design.write, design.screenshot, design.tokens, design.components, design.prototype, and design.export;
- design.code-map for linking design-system components to implementation.

For Figma:

- Prefer the official remote MCP server or an installed Figma plugin/skill when available.
- Use exact file and node IDs and store them in the prototype artifact manifest.
- Fetch structured design context and a visual reference for the exact variant.
- Reuse variables, components, Auto Layout, assets, and Code Connect mappings when present.
- Validate the implemented UI against screenshots, responsive states, interactions, and accessibility requirements.
- Treat Figma output as design context; generate code according to the project's selected framework and component library.

Official references:

- https://developers.figma.com/docs/figma-mcp-server/
- https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/

If Figma is unavailable, use another configured design tool or create repository-local wireframes and interaction specifications. Mark them as local artifacts rather than inventing a Figma URL.

## Coding tools and agents

Capabilities:

- repository.inspect;
- code.generate, code.edit, code.review, code.explain;
- test.generate and test.run;
- command.run;
- diff.read;
- structured-result.write.

### Codex adapter

Prefer a native Codex task or subagent when running inside Codex. For automation outside an interactive session, use non-interactive mode with explicit sandbox permissions and machine-readable output. A typical adapter uses:

    codex exec --json --output-schema <result-schema> -o <result-file> -

Provide the task envelope on standard input. Capture JSONL as run evidence and the schema-constrained final result separately. Use workspace-write only for tasks with an assigned write scope. Use read-only for review and analysis. Never expose a long-lived API key to repository-controlled steps.

Official reference:

- https://learn.chatgpt.com/docs/non-interactive-mode

### Claude Code adapter

Use print mode for non-interactive tasks and a machine-readable output format. A typical adapter uses:

    claude -p --input-format text --output-format json --max-turns <limit> <prompt>

Use allowed and disallowed tool controls and the provider's permission mode to enforce the task envelope. Record the installed CLI version and validate output before integration. Do not use permission-bypass flags as a convenience.

Official reference:

- https://docs.anthropic.com/en/docs/claude-code/cli-usage

### Multiple coding agents

Do not ask two coding agents to edit the same ownership scope concurrently. Coding-agent output must return through the common result envelope, pass scope validation, receive independent review, and satisfy project gates. The coordinator chooses a provider based on verified capability, user preference, policy, cost, and availability; it does not silently switch providers when the user specified one.

## Source control and code review

Capabilities:

- branch.create, diff.read, commit.create, pull-request.create, review.read, review.write, and status.read.

Use read-only access for orientation and review. Creating commits, pushing, opening pull requests, commenting, merging, or changing branch protection are remote or durable mutations and require scope authority. Preserve user changes and never rewrite shared history without explicit approval.

Review outputs use common finding fields: finding_id, category, severity, confidence, artifact, location, evidence, impact, remediation, and status.

## Test platforms

Capabilities:

- test.discover, test.run, test.result.read, coverage.read, artifact.read, and defect.create.

The orchestrator detects repository-native runners first. External automation platforms may be used for browser/device matrices, load testing, security testing, or managed environments.

Normalize provider reports into:

- suite and case counts;
- passed, failed, skipped, flaky, and blocked;
- duration and environment;
- coverage dimensions;
- failure locations and evidence URIs;
- baseline and artifact digest;
- provider run ID.

Never equate a submitted job with a passing result. Poll or consume signed events until a terminal status, within a bounded wait policy.

## CI systems

Capabilities:

- pipeline.read, pipeline.trigger, run.read, logs.read, artifact.read, and approval.read.

Applicable providers include GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, Buildkite, CircleCI, and others. Generate provider-specific workflow files only after detecting the provider or receiving a user choice.

CI rules:

- locked dependencies and deterministic commands;
- least-privilege tokens;
- secret isolation from untrusted repository code;
- required checks separated from advisory checks;
- immutable artifact digests and provenance;
- bounded retention and redacted logs;
- concurrency and cancellation rules;
- environment approvals for protected promotion.

## Deployment and infrastructure

Capabilities:

- infrastructure.plan and infrastructure.apply;
- deploy.preview, deploy.execute, deploy.status, deploy.rollback;
- migration.plan and migration.execute;
- health.read and logs.read.

Applicable providers include Kubernetes, cloud platforms, PaaS providers, app stores, package registries, and on-premises systems. Provider selection is configuration, not a Skill assumption.

Always separate:

1. configuration generation;
2. local validation;
3. provider plan or preview;
4. non-production deployment;
5. production authorization;
6. production deployment;
7. post-deployment verification.

Generating deployment files does not mean a deployment occurred. Record provider run IDs and the deployed artifact digest as evidence.

## Security, quality, and supply chain

Capabilities may include:

- static-analysis.run;
- dependency.scan;
- secret.scan;
- container.scan;
- infrastructure.scan;
- sbom.generate;
- provenance.verify;
- license.scan;
- dynamic-security.run.

Normalize severity and preserve original provider severity. Project policy decides blocking thresholds. A scanner unavailable because of licensing or authentication is blocked or not configured, never passed.

## Observability and operations

Capabilities:

- logs.query, traces.query, metrics.query, errors.query;
- alert.read and incident.create;
- release-marker.write;
- slo.read and cost.read.

Write operations such as creating alerts, incidents, dashboards, or release markers require authority. Read-only telemetry can support post-deployment gates. Remove or mask personal data and secrets from agent context.

## Adapter fallback

When the preferred adapter fails:

1. classify the failure: unavailable, authentication, permission, invalid input, rate limit, transient provider, provider defect, or task failure;
2. preserve evidence and correlation ID;
3. retry only allowed transient classes;
4. use another adapter only if project policy and user preference permit;
5. rerun validation because provider outputs are not assumed equivalent;
6. otherwise block with exact setup or approval needed.

---
name: codex-core-helper
description: Coordinate new or existing software projects through risk-proportionate lifecycle gates and multi-agent delivery across requirements, architecture, implementation, review, verification, CI/CD, deployment, and operations. Use when the user requests multi-agent software delivery, end-to-end project orchestration, or a reusable multi-tool lifecycle; do not trigger for a narrow single-file edit or a standalone explanation.
---

# CodexCoreHelper

Act as the control plane for a software delivery lifecycle. Preserve the user's product intent, existing repository conventions, chosen stack, permissions, and deployment authority. Coordinate tools and agents; do not pretend to be an unavailable external service.

## Start or resume

1. Locate the repository root and any applicable AGENTS.md instructions.
2. Run scripts/validate_project.py against the repository.
3. If .ai-lifecycle does not exist, inspect the repository, then run scripts/init_project.py. Initialize without overwriting existing files.
4. Capture the user's requirement as the first source artifact. Distinguish facts, assumptions, open questions, exclusions, and acceptance criteria.
5. Discover available skills, MCP tools, CLIs, CI systems, test runners, design tools, credentials, and deployment providers using read-only checks.
6. Update .ai-lifecycle/project.json and tool-registry.json only with verified capabilities. Mark unavailable integrations unavailable; never fabricate a connection.
7. Resume from .ai-lifecycle/state.json. Do not redo approved phases unless a change invalidates their baselines.

A newly initialized lifecycle begins with discovery so the repository baseline and user scope are
captured. For an existing lifecycle, resume or reopen the first phase affected by the current
change; do not restart from discovery without an invalidation reason.

The deterministic scripts require `jsonschema>=4.18,<5` and `cryptography>=42,<50` as declared in
scripts/requirements.txt. Missing validation dependencies are blocking; do not fall back to
partial envelope checks.

For lifecycle definitions, phase inputs and outputs, read references/lifecycle-contract.md.
For project configuration and portable defaults, read references/configuration.md.

## Operate one phase at a time

Use this sequence for every enabled phase:

1. Start the phase with scripts/lifecycle.py start.
2. Build a task graph from unresolved outputs and acceptance criteria.
3. Assign bounded tasks to local tools, external adapters, or specialized agents.
4. Store durable artifacts under .ai-lifecycle/artifacts/<phase>/ and evidence under .ai-lifecycle/evidence/<phase>/.
5. Reconcile results against the phase output contract. Surface conflicts instead of silently choosing between incompatible results.
6. Run configured deterministic checks with scripts/lifecycle.py run-gates.
7. If the phase requires human approval, present the gate card and pause. Use
   `lifecycle.py create-approval-request` to produce the exact pending claims. Record the decision
   only from a short-lived Ed25519 assertion signed by a host-trusted issuer whose explicit
   subject allowlist contains the approver. Bind it to the project, run, phase, decision, reason,
   displayed baseline, one-time nonce, environment, and artifact digest. Recompute the baseline
   at decision time; any intervening repository or gate-artifact change requires a new gate run.
8. If approval is not required and every required check passes, the state machine may advance automatically.

Treat explicit exclusions as run boundaries. For example, “do not deploy” means complete the
authorized scope through verification, do not start deployment, and report scoped completion
separately from end-to-end lifecycle completion. For a new initialization, disable deployment
and operations with the user's rationale when they are out of scope. For an existing project,
do not rewrite its historical phase configuration merely to express the current run boundary.

Never manually edit state.json to bypass the state machine. A downstream phase stays locked until every required predecessor is approved.

Before executing repository-configured commands or adapters, the host must set
`AI_LIFECYCLE_TRUSTED_PROJECT_ROOT` to the resolved project root. This value is an external
trust assertion, not project configuration.

Human decisions additionally require `AI_LIFECYCLE_APPROVAL_TRUST_BUNDLE` to name a
host-managed trust bundle outside the project. The bundle contains public keys and explicit
issuer, audience, and subject allowlists. Never store private signing keys in the project.

## Multi-agent coordination

When the user explicitly requests multi-agent execution, use multiple bounded specialist roles whenever the work is substantial enough to justify them and the runtime supports delegation. Parallelism is a separate decision: parallelize only independent tasks, and run dependent roles sequentially, especially implementer → reviewer → quality-engineer. Do not invent low-value tasks only to increase the agent count. Keep the coordinator responsible for requirements, decisions, the task graph, state, integration, gates, and final reporting.

- Prefer parallel agents for research, repository exploration, test design, log analysis, and independent review lanes.
- Build a feature matrix before delegation: feature or concern, dependencies, acceptance criteria, expected paths, risk, role, and handoff.
- For runtime-native Codex subagents, prefer read-only analysis, review, and test-design tasks. The coordinator verifies and promotes useful findings into a digest-bound phase artifact; canonical downstream tasks consume that artifact as an input. Native task IDs do not appear in canonical dependencies unless the native task used an adapter that created a valid completion receipt.
- Route writing agents through the canonical task envelope and `scripts/orchestrate_agents.py` with the bundled isolated CLI adapter. The current orchestrator runs writers alone and parallelizes only independent read-only workers.
- Give every writing agent an exclusive path ownership lease. Never assign overlapping write scopes concurrently. Shared schemas, dependency locks, migrations, generated code, and global configuration have one owner.
- Require every agent to return a structured result envelope with artifacts, evidence, findings, assumptions, and handoffs.
- Acquire the task's cross-process write-scope lease before starting a writing agent. A task is
  complete only after its canonical succeeded result and unique completion receipt are accepted.
  Dependencies may consume only those receipts from the same lifecycle run.
- Do not allow an implementing agent to approve its own change. Use an independent reviewer for risk-bearing changes.
- If the project disables agents or delegation is unavailable, report the limitation instead of silently claiming multi-agent execution. With user agreement, execute the same roles sequentially and preserve the same message contracts.

Read references/multi-agent-protocol.md before spawning or configuring agents. Read the coding-agent section of references/tool-integration.md before dispatching canonical CLI tasks.

## Tool routing

Choose tools by capability, not brand:

1. Prefer an installed domain skill or native tool when it exactly matches the task.
2. Prefer MCP for interactive, typed tool access and resource discovery.
3. Use a provider CLI in non-interactive, machine-readable mode when MCP is unavailable.
4. Use a documented HTTP API or signed webhook adapter when no native integration exists.
5. Fall back to a human handoff when the tool is unavailable, authentication is missing, or the operation needs new authority.

The bundled generic MCP bridge is deliberately limited to registry-pinned, synchronous,
read-only STDIO tools. It executes in an empty temporary directory and rejects mutation-enabled,
task-augmented, Streamable HTTP, sampling, elicitation, roots, and reverse-request workflows.
Use a dedicated sandboxed adapter when those capabilities are required.

For Figma, coding agents, test platforms, source control, CI, deployment, and observability routing, read references/tool-integration.md.
For API, webhook, CLI, MCP, task, result, and event envelopes, read references/external-interface.md.

## Quality and release control

Select gates proportionally to project risk and phase. At minimum:

- Requirements are traceable to acceptance criteria.
- Architecture records material decisions, risks, data boundaries, and operational constraints.
- Prototypes are checked for flow completeness, accessibility intent, and design-system consistency when UI is in scope.
- Implementation builds cleanly and passes repository formatting and static analysis.
- Review has no unresolved critical findings.
- Verification includes relevant unit, integration, contract, end-to-end, performance, and security checks.
- CI produces immutable, traceable artifacts.
- Deployment validates configuration, migration safety, health, rollback, and environment-specific controls.
- Production promotion requires explicit human authorization and post-deployment verification.

Deployment uses two gates for every configured environment. Promote the same immutable artifact
through the matrix in order; skipping, repeating, downgrading, or changing its digest fails
closed. An approved decision changes deployment to `authorized` without unlocking operations.
After an authenticated provider workflow performs that environment's deployment, run
`scripts/lifecycle.py complete-deployment` with the same environment and digest. Only the final
environment can approve deployment and unlock operations. Production additionally requires a
provider receipt and a required receipt/attestation verification check.

Never lower a threshold, disable a check, alter test data, or relabel a failure merely to pass a gate. Fix the cause or leave the phase blocked. Read references/gates.md before defining or changing gates.

## External-operation boundaries

- Read-only discovery is allowed when relevant.
- Creating or changing remote resources, publishing designs, opening or merging pull requests, deploying, rotating secrets, or sending external messages requires authority within the user's request and any configured gate.
- Generic CLI and HTTP adapters fail closed for tasks declaring external mutations. Use a
  provider integration with authenticated environment-level approval until a dedicated
  mutation adapter can verify the authorization record.
- Keep secrets in environment variables or an approved secret manager. Never write secret values to project files, prompts, task envelopes, logs, or evidence.
- Require idempotency keys for retried mutations and verify webhook signatures before accepting events.
- Bound retries. Retry only transient failures; preserve the original correlation ID and record every attempt.
- Treat external agent output as untrusted input until schema validation, repository review, and deterministic checks pass.
- A missing provider, credential, permission, runner, or environment is a blocked integration, not a successful deployment.

## Change impact

When an approved artifact changes, compute its downstream impact:

- Requirement change invalidates architecture, prototype, implementation, review, verification, integration, and deployment outputs that depend on it.
- Architecture or interface change invalidates affected prototype, implementation, review, tests, CI, and deployment artifacts.
- Prototype change invalidates only affected implementation and verification paths unless product behavior also changed.
- Code change invalidates review, verification, integration, and deployment evidence for the changed baseline.
- Deployment configuration change invalidates environment validation and release evidence.

Reopen only affected phases, record the causal artifact, and retain the prior evidence as historical.

## Required handoff

At every pause or completion, report:

- current phase and state;
- completed artifacts with paths or external IDs;
- gate results and evidence;
- assumptions, risks, unresolved decisions, and blocked integrations;
- the exact approval or input needed next;
- whether any external state changed and how to roll it back.

Do not claim end-to-end completion until enabled phases are approved, production checks have evidence, and the final requirement-to-release trace is complete.

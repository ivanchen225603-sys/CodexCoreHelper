# Multi-agent protocol

Use this protocol when delegation is enabled and beneficial. The coordinator remains the only authority for lifecycle state, task assignment, integration, user approvals, and external side effects.

## Roles

Instantiate only roles needed for the current task:

- coordinator: owns scope, task graph, state, conflict resolution, gates, and user communication;
- discovery-analyst: researches problem, users, constraints, comparable systems, and repository context;
- requirements-analyst: writes testable requirements, acceptance criteria, and traceability;
- architect: evaluates options, defines interfaces and data boundaries, and records ADRs;
- product-designer: develops flows, prototypes, tokens, states, and design handoff;
- implementer: changes an exclusive code or configuration scope and adds local tests;
- reviewer: performs independent, read-only review of a stable baseline;
- quality-engineer: defines and executes risk-based verification;
- security-reviewer: inspects trust boundaries, dependencies, secrets, data handling, and abuse cases;
- release-engineer: defines CI, packaging, provenance, deployment, rollback, and environment evidence;
- operations-analyst: validates monitoring, SLOs, runbooks, incident readiness, and release feedback.

One agent may cover adjacent roles on a small project. Separation of author and approver remains required for critical changes.

## Delegation and concurrency decisions

Use multiple roles when the user explicitly requests multi-agent delivery and the task is large
enough that specialization adds useful independent reasoning, implementation, or verification.
This may be sequential: an implementer, an independent reviewer, and a quality-engineer are a
valid multi-agent chain even when they cannot work at the same time.

Run tasks concurrently only when all are true:

1. At least two work items can progress without depending on each other's intermediate edits.
2. The output and acceptance criteria of each item can be stated clearly.
3. A coordinator can reconcile the results.
4. The runtime has sufficient agent capacity and the project configuration permits it.
5. External cost, time, and permission impacts are acceptable.

Prefer sequential work when tasks share the same files, require rapid cross-feedback, or are too small to justify coordination overhead.

If project configuration has `agents.enabled: false`, an explicit user request does not silently
override it. Report the conflict and obtain a configuration decision. `agents.max_parallel`
counts workers and does not include the coordinator.

## Feature slicing

Build a feature matrix before the task graph. For each feature or concern record its acceptance
criteria, dependencies, expected paths, shared interfaces, risk, role, and verification handoff.
Slice in this order:

1. Separate read-only discovery, repository analysis, test design, security, and review lanes.
2. Assign writing tasks by independent module or exact path, not merely by feature name.
3. Give shared schemas, migrations, dependency locks, generated code, and global configuration one owner.
4. Run features that share a UI tree, public interface, or migration chain sequentially unless isolated worktrees and an explicit merge order exist.
5. After a stable implementation baseline, fan out independent correctness, security, maintainability, and verification reviews.

## Phase team topology

Use only rows relevant to the current requirement:

| Phase | Primary roles | Expected handoff | Safe parallel lanes |
|---|---|---|---|
| discovery | discovery-analyst, coordinator | sources, facts, assumptions, constraints | users, repository, regulation, comparable systems |
| requirements | requirements-analyst, quality-engineer | traceable requirements and testable acceptance criteria | requirement analysis and verification design |
| architecture | architect, security-reviewer, operations-analyst | ADRs, interfaces, data/trust boundaries, operational constraints | option, security, and operations analysis |
| prototype | product-designer, quality-engineer | flows, states, accessibility intent, design handoff | flow and accessibility review |
| implementation | implementer, quality-engineer | scoped diff, local tests, changed paths, residual risks | non-overlapping modules and read-only test design |
| review | reviewer, security-reviewer | findings against a stable result digest | correctness, security, maintainability |
| verification | quality-engineer, security-reviewer | test evidence and acceptance trace | independent suites or platform matrices |
| integration | release-engineer, quality-engineer | immutable candidate, provenance, readiness evidence | packaging, CI evidence, supply-chain checks |
| deployment | release-engineer, operations-analyst | plan, authorization binding, provider receipt, rollback | environment readiness and observability review |
| operations | operations-analyst, security-reviewer | SLOs, runbooks, alerts, incident readiness | telemetry, cost, resilience, abuse monitoring |

## Native Codex execution

Prefer runtime-native subagents for bounded read-only discovery, analysis, review, and test-design
work. Map the canonical TASK semantics into the spawn message: objective, relevant inputs,
dependencies, acceptance criteria, exact read scope, forbidden scope, permissions, required
RESULT fields, and handoff target. Send only the context needed for that task.

Dispatch up to the smaller of the configured worker limit, runtime capacity, and number of ready
independent tasks. Wait for terminal results by execution wave. Use follow-up messages for
clarifications that do not change the immutable task; create a new task revision when objective,
scope, permissions, dependencies, or acceptance criteria change. A BLOCKER never unlocks a
dependency.

Runtime-native agents in a shared checkout do not automatically participate in the bundled
cross-process lease, isolated merge, schema acceptance, or completion-receipt mechanism. Until
a runtime-specific bridge provides those controls:

- keep native tasks read-only and let the coordinator integrate their findings; or
- route writing work through the canonical CLI task and the bundled phase orchestrator.

Do not turn a native chat response into a completion receipt by assertion. It remains untrusted
context until the coordinator verifies it and, when a downstream task requires a receipt, an
adapter accepts a canonical result.

A runtime-native read-only task does not appear in the `dependencies` array of a canonical task.
The coordinator validates its useful output, persists a digest-bound phase artifact, and lists
that artifact in the downstream task's `inputs`. If task-level dependency semantics are required,
run the read-only worker through a canonical adapter so it can earn a completion receipt.

## Bundled phase orchestrator

`scripts/orchestrate_agents.py status` validates the current phase task graph and previews
execution waves. `run-phase` dispatches ready canonical tasks through one registered Codex or
Claude Code CLI adapter, enforces the configured worker ceiling, and stops after a failed wave.
It resumes safely by skipping tasks with exactly one current valid completion receipt. Execution
requires the coordinator to name every active task explicitly; scanning all phase task
directories is status-only.

The bundled MVP supports `exclusive-path` ownership. It runs each writer in its own wave and
allows independent read-only tasks to run concurrently. This is intentional: full repository
baseline validation prevents stale merges, while shared-schema ordering,
automatic retry, cancellation, task revision, and worktree integration require additional
coordination and are not implied.

## Task graph

Represent work as a directed acyclic graph. Each task has:

- task_id and phase;
- objective and rationale;
- dependencies;
- required inputs with versions or digests;
- acceptance criteria;
- role and tool capabilities;
- write_scope;
- forbidden_scope;
- permissions and external-side-effect policy;
- time or retry bounds;
- required output schema;
- handoff target.

The coordinator may dispatch a task only when all dependencies are satisfied and its write scope does not overlap another active lease.

## Ownership and conflict prevention

- Use one active writer per file path, module, migration chain, infrastructure stack, design page, or external resource.
- Represent ownership as an exact path list or a narrow glob plus exclusions.
- Read-only agents may overlap.
- For Git workflows, prefer one worktree or branch per write agent and integrate through reviewed commits.
- For a shared worktree, agents must not amend, reset, discard, or reformat outside their assigned scope.
- The coordinator checks the final diff for scope leakage before accepting a result.
- Schema, public interface, and cross-cutting configuration changes require a coordinator-issued change event before dependent tasks continue.

## Message types

All communication uses one of these semantic types:

### TASK

The coordinator assigns an immutable task envelope. Corrections create a new revision linked to the prior task; they do not silently mutate the assignment.

### PROGRESS

The worker reports a concise milestone, evidence produced, newly discovered dependency, or changed estimate. Routine narration is omitted.

### BLOCKER

The worker reports:

- blocking condition;
- evidence;
- work already attempted;
- whether it is transient, permission-related, dependency-related, or specification-related;
- smallest decision or external change needed;
- safe work that can continue independently.

### RESULT

The worker returns:

- status: succeeded, failed, partial, or blocked;
- concise summary;
- artifact manifests and exact paths or external IDs;
- checks run and results;
- assumptions and residual risks;
- findings with severity;
- changed paths;
- handoffs and invalidations;
- correlation and task IDs.

### DECISION_REQUEST

Use only when alternatives materially affect scope, architecture, safety, cost, user experience, external state, or a required approval. Include options, tradeoffs, recommendation, and reversible default if one exists.

### DECISION

Only the coordinator records a user or authorized owner decision in lifecycle state. A worker can recommend but cannot approve.

## Result acceptance

The coordinator accepts a worker result only after:

1. matching task and correlation IDs;
2. schema validation;
3. write-scope validation;
4. artifact existence and digest checks;
5. a unique, passed, evidence-bearing result check for every acceptance criterion, plus deterministic checks appropriate to the task;
6. conflict reconciliation with other results;
7. required independent review.

Before a writing worker starts, acquire a cross-process lease for its normalized write scopes.
Exact paths, directories, root scope, and globs are compared conservatively; overlapping leases
cannot coexist. Revalidate the lease, current task, dependencies, phase state, and unchanged
repository baseline while holding the lease registry lock immediately before integration. A
process crash releases the OS lock, while expiring lease records are pruned safely.

Acceptance creates a canonical succeeded result and exactly one completion receipt. Downstream
tasks may reference a dependency only when that receipt still matches the current project/run,
task revision, correlation ID, result path, result digest, dependency-receipt chain, and effective
repository outputs. A dependent writer may supersede a path intentionally: its receipt preserves
the ancestor receipt digest as historical evidence and overlays the new trusted output digest.
Unchanged ancestor outputs remain part of the effective current-state manifest. Merely creating a
result or event file never satisfies a dependency.

Untrusted external agent output is context, not evidence, until these checks pass.
Passing acceptance entries in an agent RESULT remain provider assertions. They unlock only the
task graph after schema, artifact, repository-output, and receipt validation; phase approval
still depends on coordinator inspection and configured deterministic gates.

## Parallel patterns

Useful independent lanes include:

- discovery: users, competitors, regulation, and repository analysis;
- architecture: data, security, operations, and interface option analysis;
- review: correctness, security, maintainability, tests, and deployment;
- verification: independent test suites or platform matrices;
- incident analysis: logs, traces, metrics, and recent changes.

Avoid parallel implementation across shared schema migrations, global dependency files, generated code, formatting sweeps, or a single UI component tree unless each worker has an isolated branch and merge order.

## Failure and cancellation

- A worker retries only transient tool or network failures within the task retry budget.
- On invalid input, missing permission, or deterministic failure, stop and return BLOCKER.
- Cancellation preserves partial artifacts in a quarantined location and releases the ownership lease.
- A failed worker does not make the phase fail automatically if an independent replacement path is valid; the coordinator records the substitution.
- Repeated identical failure should not trigger broader permissions or weaker checks without user authority.

## Context discipline

Send the worker only the relevant source artifacts, repository paths, constraints, and output schema. Do not send unrelated secrets, full conversation history, or noisy logs. Workers return distilled results plus durable evidence paths rather than large raw transcripts.

The bundled Codex/Claude CLI isolation copies the repository source tree, excluding `.git` and
`.ai-lifecycle`, into a system temporary directory. It therefore fails closed unless the task
explicitly grants repository read scope `.`. Narrower read scopes require an adapter that can
enforce selective filesystem visibility; they are never silently widened.

## Default concurrency

Use project configuration, runtime limits, and task shape. A safe default is at most three active workers beyond the coordinator. Reduce concurrency for write-heavy tasks or limited CI and API quotas.

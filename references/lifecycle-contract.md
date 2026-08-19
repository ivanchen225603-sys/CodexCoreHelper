# Lifecycle contract

Use this contract to translate an unstructured request into phase artifacts, traceable decisions, and gated handoffs. A project may disable phases that are genuinely out of scope, but it must record the reason and preserve predecessor relationships.

## Artifact conventions

Every durable artifact must include or accompany:

- artifact_id: stable identifier;
- artifact_type and phase;
- version or content digest;
- source requirement, decision, or task IDs;
- owner and reviewers;
- created_at and updated_at in UTC;
- status: draft, candidate, approved, superseded, or rejected;
- dependencies and downstream consumers;
- external URI when the source of truth is outside the repository.

Keep repository artifacts under .ai-lifecycle/artifacts/<phase>/. For an external source of truth such as Figma, Jira, GitHub, or a deployment platform, store a small manifest with the immutable external ID, URL, version, checksum when available, and retrieval time.

## Phase sequence

The default directed sequence is:

discovery -> requirements -> architecture -> prototype -> implementation -> review -> verification -> integration -> deployment -> operations

Prototype may be disabled for non-visual projects. Integration may be combined with verification for very small projects, but CI artifact production and deployment readiness must still be explicit. Operations begins only after a verified deployment.

## 1. Discovery

Purpose: establish the problem, context, stakeholders, constraints, repository state, and evidence sources.

Inputs:

- user's initial requirement;
- existing repository and documentation;
- business, legal, security, data, budget, schedule, and platform constraints;
- known competitors or comparable systems when research is authorized.

Workflow:

1. Separate stated facts from assumptions and unknowns.
2. Inspect existing product and repository before proposing replacement architecture.
3. Identify stakeholders, users, core journeys, system boundaries, dependencies, risks, and measures of success.
4. Create a research log with source dates and confidence.
5. Escalate only questions that materially change scope, safety, cost, or external state.

Outputs:

- discovery-brief.md;
- stakeholder-and-user-map.md;
- constraints.json;
- risk-register.json;
- research-log.json;
- initial scope and explicit exclusions.

Handoff: requirements consumes validated problem statements, constraints, risks, and research evidence.

## 2. Requirements

Purpose: define testable product and engineering obligations.

Inputs: approved discovery artifacts and change requests.

Workflow:

1. Define goals, non-goals, personas, journeys, functional requirements, non-functional requirements, data rules, and acceptance criteria.
2. Assign stable requirement IDs such as REQ-F-001 and REQ-NF-001.
3. Add priority, rationale, source, dependencies, risk, and verification method.
4. Resolve contradictions and record decisions.
5. Build a trace matrix from goals to requirements to acceptance criteria.

Outputs:

- product-requirements.md;
- requirements.json;
- acceptance-criteria.json;
- traceability.json;
- glossary.md;
- decision-log.md.

Gate: no unresolved requirement conflict; every in-scope requirement is testable or has a named manual verification; exclusions are explicit.

Handoff: architecture receives the approved requirement baseline and quality attributes; prototype receives journeys and behavior.

## 3. Architecture

Purpose: choose a maintainable solution that satisfies functional and quality requirements.

Inputs: requirement baseline, repository constraints, platform policies, and operational targets.

Workflow:

1. Compare feasible options using explicit drivers and tradeoffs.
2. Define system context, components, deployment topology, data model, interfaces, trust boundaries, failure modes, observability, and capacity assumptions.
3. Preserve existing stack unless change is required by evidence and approved.
4. Record material decisions as ADRs.
5. Produce threat and privacy analysis proportional to risk.

Outputs:

- architecture-overview.md;
- context-and-container diagrams;
- interface-contracts/;
- data-model/;
- ADRs/;
- threat-model.md when security relevant;
- migration-and-rollback-plan.md;
- architecture-to-requirement trace.

Gate: every high-priority quality attribute has a design response and verification approach; no unresolved critical security or data-boundary issue.

Handoff: prototype consumes journeys, interfaces, design constraints, and component boundaries; implementation consumes ADRs and contracts.

## 4. Prototype

Purpose: validate product flow, interaction, content, and technical assumptions before expensive implementation.

Inputs: journeys, design system, architecture constraints, interface mocks, accessibility requirements.

Workflow:

1. Select fidelity appropriate to uncertainty.
2. Cover happy paths, empty, loading, error, permission, and destructive-action states.
3. Reuse design tokens and components.
4. Link prototype nodes to requirement and journey IDs.
5. Test critical flows with stakeholders or deterministic UI checks when available.

Outputs:

- prototype manifest with Figma or other external IDs;
- flow-map.md;
- design tokens and component mappings;
- annotated screens or interaction specification;
- prototype-validation.md;
- implementation handoff.

Gate: critical flows are complete; accessibility intent and responsive behavior are recorded; unresolved feedback is prioritized.

Handoff: implementation receives approved screens, states, tokens, assets, behavior, and acceptance criteria.

## 5. Implementation

Purpose: create the smallest maintainable change that satisfies the approved baselines.

Inputs: requirements, architecture, prototype, coding standards, repository instructions, and task graph.

Workflow:

1. Decompose into independently verifiable tasks with ownership scopes.
2. Implement contracts and migrations with backward compatibility where required.
3. Add tests with the change, not after all code is complete.
4. Generate or update user, operator, API, and developer documentation.
5. Keep commits or change sets traceable to task and requirement IDs.

Outputs:

- source code and migrations;
- automated tests and fixtures;
- generated or updated documentation;
- implementation-notes.md;
- dependency and license changes;
- requirement-to-code trace.

Gate: clean build, formatting and static checks pass, required tests pass, secrets absent, dependency findings within policy.

Handoff: review receives the baseline identifier, diff, intent, risks, test evidence, and known limitations.

## 6. Review

Purpose: independently inspect correctness, security, maintainability, compatibility, and scope.

Inputs: implementation baseline, requirements, architecture decisions, diff, and evidence.

Workflow:

1. Use independent review lanes for correctness, security, data, concurrency, maintainability, tests, UX, and operations when applicable.
2. Report only actionable findings with severity, evidence, affected artifact, and recommended correction.
3. Separate blocking defects from suggestions.
4. Re-review changed areas after fixes.

Outputs:

- review-findings.json;
- review-summary.md;
- resolved-findings.json;
- approved baseline or rejection.

Gate: no unresolved critical or high-severity finding under project policy; reviewer is independent from the author for risk-bearing changes.

Handoff: verification receives the reviewed baseline and risk-based test focus.

## 7. Verification

Purpose: demonstrate that the reviewed baseline satisfies requirements and quality attributes.

Inputs: reviewed baseline, acceptance criteria, risk register, interface contracts, and target environment.

Workflow:

1. Select unit, integration, contract, component, end-to-end, accessibility, performance, reliability, security, and exploratory tests based on risk.
2. Use production-like configuration without production secrets or personal data.
3. Record environment, tool versions, commands, results, and artifact digests.
4. Treat flaky tests as failures until quarantined through an approved policy with an owner and expiry.

Outputs:

- test-plan.md;
- machine-readable test reports;
- coverage, performance, accessibility, and security evidence;
- defect register;
- acceptance-to-test trace.

Gate: required suites pass; thresholds meet project policy; no unresolved release-blocking defect.

Handoff: integration receives a verified immutable baseline and required build instructions.

## 8. Integration

Purpose: produce reproducible CI pipelines and immutable release candidates.

Inputs: verified baseline, build definition, dependency locks, environments, secret references, and release policy.

Workflow:

1. Define deterministic restore, build, test, scan, package, publish, and provenance steps.
2. Use least-privilege identities and environment-scoped secrets.
3. Pin or govern third-party actions and dependencies.
4. Produce versioned artifacts once and promote the same digest.
5. Validate rollback and migration ordering.

Outputs:

- CI workflow configuration;
- release candidate digest and provenance;
- SBOM and dependency reports when required;
- environment configuration contracts;
- release-readiness evidence.

Gate: pipeline is reproducible; mandatory jobs pass; artifact provenance and digest are recorded; no secret is embedded.

Handoff: deployment receives only the approved release candidate, deployment plan, environment contract, and rollback plan.

## 9. Deployment

Purpose: safely promote the approved release candidate through configured environments.

Inputs: immutable release candidate, approvals, environment configuration, migration and rollback plans.

Workflow:

1. Validate environment readiness and change window.
2. Plan or dry-run infrastructure and schema changes when supported.
3. Deploy progressively according to risk.
4. Run health, smoke, synthetic, migration, and security checks.
5. Roll back or halt on failed required checks.
6. Require explicit human authorization for production promotion.

Outputs:

- deployment record with provider run IDs;
- artifact digest and configuration version;
- migration receipt;
- health and smoke evidence;
- rollback result if invoked;
- release notes.

Gate: deployment and post-deployment checks pass; monitoring is active; rollback remains viable.

Handoff: operations receives the deployed version, SLOs, dashboards, alerts, runbooks, and known risks.

## 10. Operations

Purpose: keep the system reliable, secure, observable, and ready for learning.

Inputs: deployment record, telemetry, incidents, user feedback, vulnerabilities, costs, and SLOs.

Workflow:

1. Monitor availability, correctness, latency, errors, capacity, cost, and security signals.
2. Triage incidents with evidence and preserve timelines.
3. Feed validated product feedback and operational learning into new change requests.
4. Patch dependencies and rotate credentials through approved workflows.
5. Review SLOs, disaster recovery, and runbooks periodically.

Outputs:

- service catalog entry;
- dashboards, alerts, SLOs, and runbooks;
- incident and postmortem artifacts;
- operational review and backlog;
- requirement and architecture feedback events.

Gate: not a one-time completion. Record operational readiness at release, then manage changes as new lifecycle runs.

## Traceability invariant

For every production artifact, the following path must be resolvable:

goal -> requirement -> architecture decision or design -> implementation task -> code baseline -> review -> test evidence -> CI artifact digest -> deployment record -> operational signal

Missing links block release when they concern critical requirements, security, compliance, data integrity, migration safety, or rollback.

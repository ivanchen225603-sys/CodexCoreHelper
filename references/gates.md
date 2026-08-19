# Quality gates

Gates combine deterministic checks with explicit human decisions. A phase passes technically only when every required check passes and no infrastructure error makes the result unreliable.

## Gate result

Each run records:

- phase, baseline digest, environment, and start and finish times;
- tool and version;
- required and advisory checks;
- command argument arrays or provider run IDs;
- exit code or normalized terminal status;
- redacted output;
- artifact and report paths;
- threshold values and actual measurements;
- overall passed, failed, blocked, or infrastructure_error;
- correlation ID.

Passing checks do not imply human approval. Approval points remain separate state transitions.

## Default gates by phase

### Discovery

- sources and retrieval dates recorded;
- assumptions and unknowns separated;
- constraints and risks identified;
- external claims supported or marked uncertain.

### Requirements

- stable requirement IDs;
- scope and exclusions explicit;
- acceptance criteria testable;
- non-functional requirements cover relevant security, privacy, performance, reliability, accessibility, compatibility, and operations;
- contradictions resolved or explicitly blocked;
- trace matrix complete for critical requirements.

### Architecture

- ADRs for material choices;
- interfaces and data ownership defined;
- trust boundaries and threat analysis proportional to risk;
- failure, capacity, observability, migration, and rollback addressed;
- architecture requirements trace complete;
- no unresolved critical design risk.

### Prototype

- critical journeys and UI states complete;
- component and token reuse checked;
- responsive and accessibility intent validated;
- design-to-requirement links present;
- stakeholder feedback disposition recorded.

### Implementation

- locked restore or reproducible dependency resolution;
- formatting and lint;
- warnings-as-errors or repository equivalent where supported;
- clean build;
- relevant unit and component tests;
- secret scan;
- dependency and license checks;
- generated files and source hygiene;
- documentation and migrations updated.

### Review

- baseline and diff stable;
- independent review completed;
- correctness, security, maintainability, compatibility, tests, and operations lanes selected by risk;
- no unresolved blocker, critical, or policy-blocking high finding;
- fixes re-reviewed.

### Verification

- all acceptance criteria mapped to automated or named manual tests;
- required unit, integration, contract, end-to-end, accessibility, performance, reliability, and security suites selected by risk;
- coverage does not regress and meets project threshold;
- flaky and skipped tests comply with explicit policy;
- no release-blocking defect;
- reports identify exact baseline and environment.

### Integration

- CI configuration validates;
- deterministic restore, build, test, scan, and package pass;
- third-party actions and dependencies governed;
- immutable artifact digest recorded;
- SBOM and provenance generated when required;
- environment secrets referenced, not embedded;
- release candidate reproducible.

### Deployment

- target environment and approved artifact digest match;
- configuration and secret references complete;
- infrastructure and migration plan reviewed;
- backup and rollback readiness confirmed;
- health, smoke, synthetic, and security checks pass;
- monitoring and alerting active;
- production authorization explicit.

### Operations

- SLOs, dashboards, alerts, logs, traces, and runbooks available as applicable;
- incident, backup, restore, disaster recovery, and dependency response ownership defined;
- release marker and deployed version visible;
- post-deployment observation window complete;
- feedback creates traceable lifecycle events.

## Risk profiles

### Low

Use repository-native checks, core traceability, reversible deployment, smoke tests, and lightweight review. Security and secret scanning still apply to code and deployment configuration.

### Standard

Use all applicable default gates, independent review, unit and integration tests, coverage policy, dependency and secret scans, CI artifact provenance, environment validation, rollback, and post-deployment checks.

### High

Add formal threat modeling, privacy or compliance review, stricter separation of duties, contract and migration tests, performance and resilience testing, SBOM and signed provenance, independent security assessment, staged rollout, recovery rehearsal, and longer observation.

## Threshold policy

Thresholds live in project.json or repository-native configuration. The orchestrator may recommend stronger thresholds with rationale, but may not lower or bypass an existing threshold to obtain a pass.

For new code without a repository baseline, suggested starting points may be proposed, not silently imposed. Critical authorization, money, data integrity, migration, and security logic deserves higher coverage and independent tests than aggregate code.

## Infrastructure failures

Classify as infrastructure_error when a required runner, network, license, device, provider, credential, or service prevents a trustworthy result. Do not mark the check passed or failed on product quality without evidence. The phase remains blocked until the check can run or an authorized equivalent is configured.

## Failure handling

On failure:

1. preserve evidence;
2. identify the failing requirement, component, or environment;
3. classify product defect, test defect, configuration defect, provider defect, or infrastructure error;
4. create the smallest corrective task;
5. rerun the failed check and any invalidated dependent checks;
6. issue a new gate run, retaining the prior run.

Do not erase failed evidence.

## Human gate card

Present:

- phase and baseline;
- required checks and results;
- thresholds and actual values;
- changed external state;
- open risks, assumptions, and advisory findings;
- rollback or recovery readiness;
- recommendation;
- one-time approval nonce and exact baseline digest;
- exact choices: approve or reject with reason.

The coordinator records only an explicit decision carried by a valid host-issued Ed25519
assertion. The signed identity, project, run, phase, decision, reason, baseline, one-time nonce,
environment, artifact digest, validity window, and single-use `jti` must all match. Silence, a
request to continue analysis, a caller self-labeling as human, an unsigned environment variable,
or a tool's success is not approval.

Immediately before an approval is recorded, recompute the repository/artifact baseline and
compare every required artifact digest with the passed gate evidence. If anything changed, the
approval attempt fails and the gate must be rerun. A displayed historical digest alone is not
enough.

`run-gates` may be invoked again from `technical_pass`; the new run replaces the pending baseline
and one-time nonce while retaining the previous evidence as history.

## Production gate

Each configured environment must pass in matrix order with the same immutable artifact digest.
Production requires:

- all predecessor phases approved;
- immutable release candidate digest;
- target environment verification;
- explicit human approval tied to that digest and environment;
- bounded deployment procedure;
- migration and rollback controls;
- post-deployment health evidence;
- deployment receipt from the provider.

The first gate for an environment proves readiness and produces an `authorized` state; it does
not claim that deployment occurred and does not unlock operations. The post-deployment gate
verifies provider and health evidence for the same environment and artifact digest. A successful
non-final environment returns deployment to in-progress for the next matrix entry; only the
final environment changes deployment to approved. Production requires both a structured
provider receipt and a passing required provider-receipt or attestation check.

The authorization is also bound to the original pre-deployment gate evidence and baseline.
Deployment plan and environment-readiness artifacts must name the same environment and immutable
artifact digest. Before completion, the pre-deployment binding is checked again; deployment and
post-verification records must share the authorization decision ID and provider run ID, their
statuses must be successful, and their individual checks must all pass.

If provider access is absent, configuration may be complete but deployment remains blocked.

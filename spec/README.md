# FlockMesh v0 API Contracts

This folder defines implementation-ready contracts for the FlockMesh v0 core runtime.

## Scope

The contract set is intentionally small and aligned with the six primitives:

- Agent
- Connector
- Policy
- Playbook
- Run
- Ledger

This v0 package focuses on the operational core needed to run office agents safely:

- `AgentProfile`
- `ConnectorBinding`
- `ConnectorManifest`
- `ConnectorAdapterSimulationResult`
- `ConnectorAdapterInvokeResult`
- `ActionIntent`
- `PolicyDecision`
- `PolicyPatchHistory`
- `PolicyPatchHistoryExportPackage`
- `PolicySimulationResult`
- `ConnectorHealthSummary`
- `ConnectorScopeDriftReport`
- `RunRecord`
- `AuditEntry`

## Runtime Invariants Encoded

- No side effects without policy decision.
- Mutation actions require idempotency keys.
- Policy precedence is deterministic: `org > workspace > agent > run_override`.
- Unknown or failed policy resolution must fail closed.
- Event stream and audit ledger are separate concerns.
- Connector manifests are signed with capability attestations and verified at load.
- Connector adapter invokes are constrained by per-connector rate-limit guardrails.
- Connector adapter retries are bounded; mutation retries require idempotency keys.
- Agent workspace isolation is enforced for run creation and connector bindings.
- Replay integrity checks reconcile policy-allow paths with event/audit execution traces.
- Agent blueprint previews reconcile kit goals with connector manifests and policy outcomes.
- Agent blueprint apply is idempotent with caller-supplied idempotency keys.
- Agent blueprint lint reports expose readiness checks and remediation guidance.
- Agent blueprint remediation plans produce executable auto-fix requests rooted in current manifests and policy context.
- Remediation policy candidates declare applicability (`direct/manual/informational`) and can include estimated score deltas.
- Policy profile catalog endpoint exposes runtime policy inventory and rule-level decision summaries.
- Policy profile patches support dry-run/apply plus history listing and rollback from recorded snapshots.
- Policy rollback apply is owner-gated by policy admin config (`global_admins` or `profile_admins`).
- Policy patch history export is cryptographically signed for external evidence transfer.
- Policy patch/rollback apply requires optimistic guard with `expected_profile_hash`.

## Files

- OpenAPI draft: `openapi/v0.yaml`
- Schemas: `schemas/*.schema.json`
- Examples: `examples/*.json`

Implemented API surfaces in v0 runtime:

- `GET /health`
- `GET /v0/agents`
- `POST /v0/agents`
- `GET /v0/templates/agent-kits`
- `POST /v0/agent-blueprints/preview`
- `POST /v0/agent-blueprints/lint`
- `POST /v0/agent-blueprints/remediation-plan`
- `POST /v0/agent-blueprints/apply`
- `GET /v0/connectors/bindings`
- `POST /v0/connectors/bindings`
- `GET /v0/connectors/manifests`
- `GET /v0/connectors/health`
- `GET /v0/connectors/drift`
- `GET /v0/connectors/mcp/allowlists`
- `GET /v0/connectors/rate-limits`
- `POST /v0/connectors/adapters/{connector_id}/simulate`
- `POST /v0/connectors/adapters/{connector_id}/invoke`
- `POST /v0/runs/{run_id}/a2a/request`
- `POST /v0/runs/{run_id}/a2a/{delegation_id}/status`
- `POST /v0/runs/{run_id}/a2a/{delegation_id}/cancel`
- `GET /v0/policy/profiles`
- `GET /v0/policy/profiles/{profile_name}/version`
- `POST /v0/policy/evaluate`
- `POST /v0/policy/patch`
- `GET /v0/policy/patches`
- `GET /v0/policy/patches/export`
- `POST /v0/policy/rollback`
- `POST /v0/policy/simulate`
- `GET /v0/runs`
- `POST /v0/runs`
- `POST /v0/runs/{run_id}/approvals`
- `POST /v0/runs/{run_id}/cancel`
- `GET /v0/runs/{run_id}`
- `GET /v0/runs/{run_id}/audit`
- `GET /v0/runs/{run_id}/events`
- `GET /v0/runs/{run_id}/timeline-diff`
- `GET /v0/runs/{run_id}/replay-integrity`
- `GET /v0/runs/{run_id}/replay-export`
- `GET /v0/runs/{run_id}/incident-export`
- `GET /v0/monitoring/replay-drift`

Example coverage:

- `agent-profile.json`
- `agent-kit-catalog.json`
- `agent-blueprint-preview.json`
- `agent-blueprint-apply-result.json`
- `agent-blueprint-lint-report.json`
- `agent-blueprint-remediation-plan.json`
- `connector-binding.json`
- `connector-manifest.json`
- `connector-health.json`
- `connector-drift.json`
- `connector-adapter-simulate-result.json`
- `connector-adapter-invoke-result.json`
- `action-intent.json`
- `policy-profile-catalog.json`
- `policy-profile-version.json`
- `policy-decision.json`
- `policy-patch-history.json`
- `policy-patch-history-export-package.json`
- `policy-simulation.json`
- `policy-profile-patch-result.json`
- `run-record.json`
- `audit-entry.json`
- `incident-export-package.json`
- `run-timeline-diff.json`
- `run-replay-integrity.json`
- `run-replay-export-package.json`
- `replay-drift-summary.json`

## Compatibility Notes

- JSON Schema draft: `2020-12`
- OpenAPI version: `3.1.0`
- This is a draft contract. Field additions must be backward compatible in minor versions.

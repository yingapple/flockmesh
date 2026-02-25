# FlockMesh Implementation TODO

Last updated: `2026-02-24`

This board is checkpoint-driven.  
Every item must map to code, contracts, and tests.

## Priority Order (Non-Negotiable)

1. Governance core (`ActionIntent -> Policy -> Approval -> Audit`)
2. Agent ecosystem boundaries (`MCP`, `A2A`)
3. System connectors (calendar/docs/tickets/CRM/internal APIs)
4. Channel connectors as optional human entry surfaces
5. UI depth after runtime correctness

## Checkpoint Board

### CP0 Foundation (Done)

- [x] Contract-first skeleton (`spec/schemas`, `spec/openapi/v0.yaml`)
- [x] Runnable runtime server (`Fastify` + control panel)
- [x] Core resources (`AgentProfile`, `ConnectorBinding`, `RunRecord`)
- [x] Policy engine baseline (`R0-R3`, precedence, fail-closed, idempotency)
- [x] Approval workflow + dual ledger (`events` and immutable `audit`)
- [x] Initial automated test suite

### CP1 Runtime Reliability + Policy DSL (Done)

- [x] SQLite persistence for agents/bindings/runs/idempotency
- [x] Optimistic concurrency (`expected_revision`)
- [x] Run cancellation endpoint
- [x] Pagination/filtering for runtime listing surfaces
- [x] File-driven policy DSL (`policies/*.policy.json`)
- [x] Policy simulation endpoint (`POST /v0/policy/simulate`)
- [x] Policy regression fixtures

### CP2 Connector Governance (Done)

- [x] Connector manifest format (`connectors/manifests/*.connector.json`)
- [x] Manifest registry endpoint (`GET /v0/connectors/manifests`)
- [x] Connector health endpoint (`GET /v0/connectors/health`)
- [x] Scope drift detector (`GET /v0/connectors/drift`)
- [x] Connector runtime adapter contract (`invoke`/`dry-run` boundary)
- [x] Capability attestation signature field for manifests

### CP3 Protocol Bridges (Done)

- [x] MCP adapter registry with trust levels and allowlist policies
- [x] A2A delegation gateway adapter (request/status/cancel)
- [x] Protocol bridge audit event taxonomy
- [x] Failure-mode tests (bridge timeout -> fail-closed)

### CP4 Product Surface (Later)

- [x] Approval inbox panel in UI
- [x] Run timeline split view (events vs audit)
- [x] Policy trace visualizer
- [x] Mobile compact mode

## Immediate Next 10 Tasks

1. [x] Add MCP adapter allowlist policy by workspace/agent.
2. [x] Add A2A request/status/cancel run-level API wrapper.
3. [x] Add protocol bridge timeout simulation and fail-closed tests.
4. [x] Add `connector.invoke.timeout` and `connector.invoke.error` audit types.
5. [x] Add per-connector invocation rate-limit guardrail.
6. [x] Add adapter-level retry strategy with idempotency guarantees.
7. [x] Add adapter smoke test script for CI sanity check.
8. [x] Expose connector attestation summary in UI panel.
9. [x] Add docs for rotating attestation keys via env.
10. [x] Add compatibility matrix doc for office systems vs agent protocols.

## Next Wave Backlog (v0.4)

1. [x] Enforce workspace isolation on run and binding creation paths.
2. [x] Add run incident export API (`events + audit + policy trace summary`).
3. [x] Add signed incident export format for external compliance workflows.
4. [x] Add timeline diff mode (between two runs of same playbook).
5. [x] Add workspace isolation regression suite with mixed-tenant fixture sets.

## Next Wave Backlog (v0.5)

1. [x] Add run replay integrity check API (policy replay vs ledger consistency).
2. [x] Add signed replay integrity export format for external auditors.
3. [x] Add replay drift alerting hooks for CI and runtime monitoring.

## Next Wave Backlog (v0.6)

1. [x] Add agent kit catalog API for role-first onboarding templates.
2. [x] Add agent blueprint preview API (connector coverage + policy projection + approval forecast).
3. [x] Add agent blueprint apply API (agent + binding provisioning with strict mode).
4. [x] Add control-plane blueprint panel for preview/apply workflow.
5. [x] Add contract schemas/examples/tests/docs for blueprint runtime.

## Next Wave Backlog (v0.7)

1. [x] Add idempotent replay support for blueprint apply via caller key.
2. [x] Add planner performance metrics to blueprint preview payload.
3. [x] Upgrade blueprint UI with strict mode, policy context, auth refs, and idempotency inputs.
4. [x] Add integration tests for blueprint idempotent replay path.

## Next Wave Backlog (v0.8)

1. [x] Move agent kits to file-driven DSL (`kits/*.kit.json`) with runtime validation loader.
2. [x] Add blueprint lint/explain API for readiness scoring and remediation suggestions.
3. [x] Add blueprint UI lint action and surface lint summary.
4. [x] Add benchmark script for blueprint preview latency sampling.

## Next Wave Backlog (v0.9)

1. [x] Add blueprint remediation plan API with executable connector add/remove and policy candidate outputs.
2. [x] Add remediation schema/example/OpenAPI mapping and contract checks.
3. [x] Add Blueprint Studio auto-remediate action that adopts `auto_fix_request` into form inputs.
4. [x] Add integration tests for remediation endpoint and suggested connector adoption path.

## Next Wave Backlog (v1.0-rc1)

1. [x] Upgrade remediation policy candidates with applicability model (`direct/manual/informational`).
2. [x] Add policy candidate estimated lint deltas from simulation.
3. [x] Auto-adopt direct `run_override` candidate into `auto_fix_request.policy_context`.
4. [x] Add invalid-run-override recovery test for remediation endpoint.

## Next Wave Backlog (v1.0-rc2)

1. [x] Add policy patch API with `dry_run/apply` mode and simulation preview.
2. [x] Persist `apply` patches back to `policies/*.policy.json` with runtime policy library refresh.
3. [x] Emit audit evidence for policy patch apply operations.
4. [x] Add integration tests for dry-run no-op and apply outcome shift.

## Next Wave Backlog (v1.0-rc3)

1. [x] Add policy profile catalog API (`GET /v0/policy/profiles`) for runtime inventory and rule summaries.
2. [x] Add control-plane policy patch console with profile selection and dry-run/apply actions.
3. [x] Add one-click policy patch draft from blueprint remediation `policy_profile_patch` candidates.
4. [x] Add contract schema/example/OpenAPI mapping and API tests for policy profile catalog.

## Next Wave Backlog (v1.0-rc4)

1. [x] Add policy patch history API (`GET /v0/policy/patches`) with profile/operation filters.
2. [x] Persist patch/rollback lineage entries in append-only JSONL history with before/after snapshots.
3. [x] Add policy rollback API (`POST /v0/policy/rollback`) with dry-run/apply and `before|after` target state.
4. [x] Add integration tests for patch history visibility and rollback outcome restoration.

## Next Wave Backlog (v1.0-rc5)

1. [x] Add owner-gated rollback apply using policy admin config (`policies/policy-admins/*.policy-admins.json`).
2. [x] Add signed policy patch history export API (`GET /v0/policy/patches/export`).
3. [x] Add contract schema/example/OpenAPI mapping for policy history export package.
4. [x] Add integration tests for rollback authorization denial and export signature verification.

## Next Wave Backlog (v1.0-rc6)

1. [x] Add policy profile version API (`GET /v0/policy/profiles/{profile_name}/version`) with stable `document_hash`.
2. [x] Add optimistic hash guard on patch/rollback apply (`expected_profile_hash` -> `409` conflict).
3. [x] Add contract schema/example/OpenAPI updates for profile version and hash conflict responses.
4. [x] Add integration tests for profile hash mismatch and version endpoint correctness.

## Next Wave Backlog (v1.0-rc7)

1. [x] Enforce `mode=apply` requires `expected_profile_hash` for patch/rollback APIs.
2. [x] Add integration tests for missing-hash apply rejection paths.
3. [x] Upgrade control-plane Policy Patch console to load/display profile version hash.
4. [x] Auto-send `expected_profile_hash` on control-plane patch apply and surface `409` hash conflicts.

## Next Wave Backlog (v1.0-rc8)

1. [x] Add control-plane Policy Rollback console with profile selection, target state, and target patch controls.
2. [x] Add rollback history preview + one-click `Draft Latest` action.
3. [x] Auto-send `expected_profile_hash` on control-plane rollback apply and surface `409` hash conflicts.
4. [x] Shift API integration tests to isolated temp-root policy/history fixtures (avoid repo residue on interrupted runs).

## Next Wave Backlog (v1.0-rc9)

1. [x] Switch control-plane bootstrap demo defaults from channel-first to system-first preset.
2. [x] Update mainline review + README to reflect system-first bootstrap posture.

## Done Criteria Per Checkpoint

- Contract updated in `spec/`.
- Runtime behavior implemented in `src/`.
- Tests added/updated in `tests/`.
- Docs updated (`README`, `docs/*`, and this file).

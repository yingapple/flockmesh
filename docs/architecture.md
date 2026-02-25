# Architecture

## Layer Model

FlockMesh is split into three runtime layers:

1. Control Plane
- `Agent Registry`: role agents, owners, versioning
- `Connector Registry`: connector metadata and capability scopes
- `Policy Service`: allow/deny/escalate decisions
- `Template Service`: playbook and role templates

2. Execution Plane
- `Orchestrator`: run state machine and retries
- `Action Gateway`: unified connector invocation
- `Approval Gateway`: human checkpoints
- `Event Pipeline`: structured runtime events

3. Trust Plane
- `Audit Ledger`: append-only execution records
- `Replay API`: deterministic run replay for incident review
- `Evidence Store`: artifacts and policy decision context

## Trust Boundaries

Boundary A: User to agent runtime  
Requests are authenticated, paired, and mapped to a caller identity.

Boundary B: Runtime to connector  
All connector calls require scoped capabilities and policy decisions.

Boundary C: Runtime to side effects  
Sensitive actions require explicit approval and are always audited.

Boundary D: Cross-runtime delegation  
External A2A delegation cannot bypass local policy and audit gates.

## Runtime Invariants

1. Pairing First  
No agent side effects before user/workspace trust bootstrapping.

2. Fail Closed  
Policy timeout, approval failure, or ambiguous capability mapping means deny.

3. Deterministic Policy Precedence  
`org > workspace > agent > run override`; stricter decision wins.

4. Idempotent Mutations  
Every mutation action carries an idempotency key.

5. Dual Ledger  
Operational events and immutable audit evidence are stored separately.

6. Event Stream Is Not The Source Of Truth  
Consumers must tolerate gaps and recover from persisted run/audit state.

## Data Contracts

- `AgentProfile`: id, role, owner, model config, default policy profile
- `AgentKit`: reusable role template with capability goals and rollout phases
- `AgentBlueprint`: kit-to-runtime projection with connector plan and policy forecast
- `BlueprintLintReport`: readiness checks and remediation recommendations before apply
- `BlueprintRemediationPlan`: executable connector/policy auto-fix proposal with candidate applicability (`direct/manual/informational`) and estimated lint delta
- `ConnectorBinding`: connector id, scopes, secret ref, tenant scope
- `ConnectorManifest`: protocol, trust level, declared capabilities
- `ConnectorAdapterResult`: simulated or executed adapter payload with policy decision context
- `McpAllowlistRule`: workspace/agent scoped tool pattern gate for MCP invocations
- `Playbook`: trigger, steps, branching rules, approval nodes
- `ActionIntent`: normalized proposed action before side effects
- `PolicyDecision`: decision, reason codes, risk level, reviewer requirements
- `PolicyProfile`: DSL-backed rule set loaded from `policies/*.policy.json`
- `PolicyAdminConfig`: owner model for rollback apply authorization (`global_admins` + `profile_admins`)
- `PolicyProfileCatalog`: runtime policy inventory with rule-level decision summaries
- `PolicyProfilePatchResult`: dry-run/apply patch diff with simulation preview and audit record
- `PolicyProfileVersion`: immutable profile snapshot (`rule_count`, `document_hash`, `file_path`)
- `PolicyPatchHistory`: append-only patch/rollback timeline with snapshot lineage
- `PolicyPatchHistoryExport`: signed history package for external governance and compliance pipelines
- `RunRecord`: timeline of events with actor identities and payload hashes

## Minimal Runtime Flow

1. Request enters orchestrator and creates `RunRecord`.
2. Runtime resolves agent profile and playbook.
3. Candidate actions are generated and normalized.
4. Policy service evaluates each action with precedence lattice.
5. Optional simulation mode computes decisions without execution side effects.
6. Escalated actions wait at approval gateway.
7. Approved actions call connector gateway with short-lived credentials.
8. Mutation actions enforce idempotency key check.
9. Event pipeline stores operational telemetry.
10. Audit ledger stores immutable execution evidence.
11. Final output is returned with run id and trace links.
12. Policy patch/rollback apply requires `expected_profile_hash` to prevent stale overwrite.

## MVP Non-Goals

- Full collaboration suite replacement
- Unlimited custom workflow builders
- Complex cross-org federation before core safety matures

# System Design: Rooted Future Office Runtime

## 1. Product Intent

FlockMesh is an open framework for future office collaboration where agents are first-class workers.

It must satisfy two constraints at the same time:

- Future-native: execution is agent-native, policy-native, audit-native.
- Ecosystem-rooted: works with today's office stack without big-bang migration.

## 2. Design Boundaries

### 2.1 What We Are

- A runtime and control framework for office agents
- A policy and approval gate for side effects
- A connector contract layer for current enterprise tools

### 2.2 What We Are Not

- Another general chat product
- A replacement for every enterprise platform
- A full enterprise IAM suite in v0

## 3. Ecosystem Surfaces (Rooted, Not Isolated)

### 3.1 Channel Surfaces

- `feishu`
- `dingtalk`
- `slack`
- `email`

### 3.2 System Surfaces

- `calendar`
- `docs`
- `jira`
- `notion`
- `crm`
- internal APIs

### 3.3 Compatibility Policy

- Existing bots can be wrapped as connectors.
- Existing webhooks can be promoted to typed capabilities.
- Existing approval flows can be referenced as external approvers.

This avoids "start from zero" adoption risk.

## 4. Minimal Primitive Set

FlockMesh core stays small with six primitives:

- `Agent`
- `Connector`
- `Policy`
- `Playbook`
- `Run`
- `Ledger`

All advanced features must compile down to these primitives.

## 5. Trust Bootstrapping Model

Before an agent can execute actions, trust must be established:

1. User/workspace pairing handshake
2. Allowlist binding for reachable channels and connectors
3. Explicit owner assignment
4. Revocation path (`disable`, `rotate`, `quarantine`)

No pairing, no execution.

Inbound rule: unknown senders are gated before message processing.

## 6. Permission Model

### 6.1 Capability Scope

- Capabilities are typed (`calendar.read`, `message.send`, `ticket.create`)
- No wildcard capabilities in production
- Credentials are short-lived and scoped per run

### 6.2 Policy Lattice

Policy precedence is deterministic:

`org policy > workspace policy > agent policy > run override`

When policies conflict, stricter decision wins.

### 6.3 Risk Tiers

- `R0`: read-only lookup
- `R1`: low-impact internal write
- `R2`: external or customer-facing side effect
- `R3`: high-risk action (finance/legal/privileged data)

### 6.4 Default Decisions

- `R0`: allow + audit
- `R1`: allow by policy profile + audit
- `R2`: require approval unless pre-approved policy exception
- `R3`: dual approval + delay window

### 6.5 Fail-Closed Rules

Default decision is deny when:

- policy service timeout
- approval service unavailable
- connector confidence below threshold
- capability mapping is ambiguous

## 7. Execution Semantics

### 7.1 Action Pipeline

1. Agent creates `ActionIntent` before side effects
2. Runtime normalizes intent to typed action contract
3. Policy evaluates action
4. Action executes only after allow/approval

### 7.2 Serial Safety

- One active mutation run per session/thread by default
- Queue or reject concurrent mutation requests

### 7.3 Idempotency

- Every mutation action requires idempotency key
- Replays with same key return previous outcome or explicit conflict

This prevents duplicate side effects during retries.

## 8. Dual-Ledger Model

FlockMesh separates two data planes:

- `EventStream`: operational telemetry for monitoring and UX timeline
- `AuditLedger`: append-only legal/compliance evidence

`EventStream` can be sampled; `AuditLedger` cannot be lossy.
`EventStream` is non-authoritative and may not provide replay guarantees.

## 9. Open Interop Boundary

### 9.1 MCP Position

- MCP is a first-class bridge protocol for tools/connectors
- Core runtime remains protocol-agnostic internally

### 9.2 A2A Position

- A2A is used for cross-agent delegation across runtimes/orgs
- Delegation must still pass local policy and audit requirements

Interop is powerful, but not allowed to bypass core controls.

## 10. End-to-End Office Example

Scenario: `weekly_ops_sync`

1. Office agent receives trigger from Feishu channel.
2. Agent proposes plan (calendar read, Jira summary, doc draft, message send).
3. Runtime emits typed `ActionIntent` list.
4. Policy marks `message.send` as `R2`.
5. Human approver confirms outbound message.
6. Runtime executes via connector hub.
7. EventStream updates timeline; AuditLedger stores immutable evidence.

## 11. Open-Source v0 Deliverables

- Agent registry and template model
- Agent kit catalog and blueprint planner (`preview` + `lint` + `remediation-plan` + `apply`, strict-mode and idempotent replay key support)
- File-driven agent kit DSL (`kits/*.kit.json`) for open contribution
- Connector SDK and reference office connectors
- Connector manifest registry with health and scope-drift checks
- Connector adapter boundary (`simulate` and `invoke`) behind policy/audit gates
- MCP adapter allowlist by workspace/agent with fail-closed defaults
- Bridge timeout and connector uncertainty default to fail-closed
- Policy engine with precedence + fail-closed behavior
- Minimal policy DSL (`policies/*.policy.json`) and simulation API (`/v0/policy/simulate`)
- Approval gateway
- Idempotent execution runtime
- Dual-ledger data contracts and replay API
- Machine-readable API contracts (`spec/openapi/v0.yaml`, `spec/schemas/*.schema.json`)

## 12. Open Questions

- How should the v0 policy DSL evolve (conditions/time windows/exceptions) without losing simplicity?
- Which connector certification bar is required for community plugins?
- How should cross-org A2A trust contracts be represented in open source v1?

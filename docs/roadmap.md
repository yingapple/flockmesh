# Roadmap

## Strategy

FlockMesh is built as a governance runtime for enterprise agent collaboration.  
Roadmap priority is fixed:

1. Governance correctness
2. Protocol interoperability (`MCP`, `A2A`)
3. System-of-record connectors
4. Optional channel connectors and UI depth

## Current Status

- `CP0` completed: runnable foundation and core contracts.
- `CP1` completed: runtime reliability + policy DSL + simulation.
- `CP2` done: connector governance landed (`manifest/health/drift`), adapter API boundary (`simulate/invoke`) landed, and manifest capability attestation signatures are verified at load.
- `CP3` done: MCP tool allowlist is enforced by `workspace/agent` on `con_mcp_gateway`, run-level A2A request/status/cancel wrappers are available, and bridge timeout/error are covered by fail-closed auditable paths.
- `CP3` hardening complete: per-connector invoke rate-limit, bounded adapter retries with idempotency guard, adapter smoke check in CI, UI attestation summary panel, and ecosystem compatibility matrix.
- `CP4` started: approval inbox and run timeline split are available in the control plane UI.
- `CP4` UI baseline now includes approval inbox, timeline split, policy trace visualizer, compact mode, and timeline diff mode.
- Runtime isolation/export hardening: workspace boundary checks are enforced at run/binding creation and incident export now ships as a signed evidence package.
- Mixed-tenant workspace isolation regression suite is now in the automated test pack.
- Replay integrity API is available to reconcile policy-allow replay with event/audit execution traces.
- Signed replay export and replay-drift monitoring hooks are now available for external audit + runtime watch.
- Agent kit catalog and blueprint planner are available for role-first onboarding (`preview` and `apply` with strict-mode gating).
- Blueprint apply now supports idempotent replay keys, and preview exposes planner metrics for latency/capacity visibility.
- Agent kits are now file-driven (`kits/*.kit.json`), and blueprint lint reports provide readiness scoring plus remediation guidance.
- Blueprint remediation-plan now emits executable auto-fix requests and connector/policy action candidates for one-click adoption in UI.
- Remediation now models policy-candidate applicability (`direct/manual/informational`) and can auto-recover invalid run overrides with estimated lint deltas.
- Policy profile patch API now supports dry-run/apply flows with simulation previews, on-disk policy persistence, and auditable patch evidence.
- Policy profile catalog API and control-plane patch console are now connected, including one-click draft from remediation `policy_profile_patch` candidates.
- Policy governance kernel now includes patch history listing and profile rollback from recorded snapshots.
- Policy governance hardening now includes owner-gated rollback apply and signed patch-history export packages.
- Policy governance concurrency guard now includes profile version hash endpoint and stale-write protection for patch/rollback apply.
- Policy governance control-plane now surfaces profile hash versions and applies patch with mandatory optimistic hash guard.
- Policy governance control-plane now includes rollback console (history preview + draft latest + hash-guarded apply).

## Phase A (Now): Governance Runtime v0.2

Goal: make every agent action policy-checkable, approval-aware, and auditable.

- SQLite-backed runtime state
- optimistic concurrency and cancellation controls
- policy DSL and simulation
- dual-ledger event/audit traces
- connector manifest registry, health, and scope drift checks

Exit criteria:

- all runtime mutation paths enforce policy + idempotency
- connector bindings can be validated against manifests
- test suite covers critical decision and approval paths
- `npm run spec:check` passes for schema/example consistency

## Phase B (Next): Protocol Bridge Layer v0.3

Goal: connect to existing agent ecosystems without losing local controls.

- MCP adapter registry with trust levels and capability allowlists
- A2A delegation gateway (`request`, `status`, `cancel`)
- adapter invocation contract (`simulate`, `invoke`) with audit events
- fail-closed behavior for bridge timeout/unknown capability

Exit criteria:

- protocol bridge actions are first-class `ActionIntent` entries
- bridge invocations appear in audit stream with deterministic IDs
- cross-runtime delegation cannot bypass local policy

## Phase C (Later): Team Surface v0.5

Goal: make governance visible and operable by real teams.

- agent kit onboarding planner (`template -> connector plan -> policy projection`)
- approval inbox UI
- timeline split (`events` vs `audit`)
- policy trace visualizer
- workspace isolation tests and incident export

Exit criteria:

- teams can resolve approvals and inspect traces without CLI
- incident review can reconstruct a run end-to-end

## Phase D (Later): Open Interop Network v0.9

Goal: production-grade open-source interop.

- connector certification and trust metadata
- signed audit export
- deployment profiles for self-hosting and regulated environments

Exit criteria:

- third-party connectors can be onboarded with explicit trust posture
- compliance workflows can consume signed evidence

## Global Gates

- Gate 1: first-time local setup under 30 minutes
- Gate 2: every run has deterministic replay path
- Gate 3: risky actions cannot bypass policy and approval
- Gate 4: existing office and agent ecosystems can be bridged incrementally

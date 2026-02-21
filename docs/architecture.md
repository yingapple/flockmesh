# Architecture (v0 -> v1)

## High-Level Components

1. Control Plane
- Agent registry service
- Prompt/version repository
- Connector metadata service
- Policy engine

2. Data Plane
- Workflow orchestrator
- Event bus
- Execution workers
- Audit sink

3. Interface Plane
- Web console for ops/admin
- API gateway
- Notification surfaces (chat/email/webhook)

## Core Data Objects

- AgentProfile: role, model policy, tools, owners
- ToolContract: schema, auth mode, rate limits, data scope
- Playbook: trigger, steps, approvals, escalation rules
- ExecutionRun: input, state transitions, outputs, audit trail

## Minimal Execution Flow

1. Trigger enters runtime
2. Runtime resolves playbook
3. Policy engine validates action + data scope
4. Agent invokes tools through connector hub
5. Human approval step is requested when required
6. Output and decision trail persisted to audit sink

## Non-Goals for MVP

- Building another general chat app
- Supporting unlimited model vendors from day one
- Full no-code workflow builder before runtime hardening

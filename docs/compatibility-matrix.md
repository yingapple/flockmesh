# Compatibility Matrix (Office Systems x Agent Protocols)

As of `2026-02-23`.

This matrix keeps FlockMesh grounded in today's ecosystem while staying agent-native.

## System Matrix

| Office surface | Native connector (`http`/`sdk`) | MCP gateway | A2A gateway | FlockMesh status |
| --- | --- | --- | --- | --- |
| Feishu / Lark chat + docs | Yes | Yes | Optional | `con_feishu_official` stub in v0, expand by capabilities |
| Slack channels | Planned | Yes | Optional | Not implemented yet (recommended next office channel) |
| DingTalk channels | Planned | Yes | Optional | Not implemented yet |
| Email systems | Planned | Yes | No | Not implemented yet |
| Calendar systems | Yes | Optional | No | `con_office_calendar` stub in v0 |
| Ticket systems (Jira/Linear) | Planned | Yes | Optional | Not implemented yet |
| Knowledge systems (Notion/Confluence) | Planned | Yes | Optional | Not implemented yet |
| CRM systems | Planned | Yes | Optional | Not implemented yet |
| Internal business APIs | Yes | Optional | Optional | Not implemented yet |

Interpretation:

- `Native connector` is best for high-assurance workflows with typed scopes and explicit policy/audit.
- `MCP gateway` is best for broad tool interoperability and rapid ecosystem coverage.
- `A2A gateway` is best for agent-to-agent delegation, not as a replacement for system APIs.

## Protocol Matrix

| Protocol | Best fit | Main risk | Required controls in FlockMesh |
| --- | --- | --- | --- |
| MCP | Tool-level interop across agent ecosystems | Tool sprawl and hidden side effects | workspace/agent allowlist, risk tier policy, rate-limit guardrail, fail-closed timeout |
| A2A | Delegation between specialist agents | Cross-runtime trust boundary ambiguity | run-level wrapper, local policy gate before delegation, immutable audit |
| Native `http`/`sdk` | High-value system-of-record actions | Credential blast radius | scoped binding, idempotency key for mutation, approval for high risk |

## Recommended First Push (Grounded + Future-ready)

1. Keep `con_mcp_gateway` as broad compatibility bridge for existing agent tooling.
2. Keep `con_a2a_gateway` for delegation workflows across specialized agents.
3. Prioritize `office_system` native connectors for system-of-record actions (calendar, ticketing, CRM).
4. Keep channel connectors optional entry surfaces, not the execution center.

This order preserves migration from today's office stack without making channels the product core.

# MCP Compatibility Notes (For FlockMesh)

Last updated: `2026-02-23`

## Why This Exists

MCP integration can quickly become too broad.  
This note defines what mainstream ecosystems are doing, and what we should ship first for enterprise internal collaboration.

## What Others Commonly Do

1. Transport compatibility first.
- The MCP spec supports local `stdio` and remote `Streamable HTTP`.
- In current MCP transport docs, `Streamable HTTP` is the preferred HTTP transport and it supersedes older HTTP+SSE transport.
- Practical meaning: local dev is easy (`stdio`), production remote services are possible (`Streamable HTTP`).

2. Permission gates above protocol wiring.
- Tool compatibility is usually paired with explicit allow/deny controls, not "all tools by default".
- Anthropic's MCP docs expose an explicit `allowedTools` control surface, matching this pattern.
- Human-in-the-loop approval remains common for sensitive actions.

3. Remote deployment expects auth-aware gateways.
- Cloudflare's remote MCP guidance includes OAuth-enabled flows and token usage for authenticated remote access.

## Sources

- MCP specification (GitHub): <https://github.com/modelcontextprotocol/specification>
- MCP transports in spec docs: <https://modelcontextprotocol.io/specification/2025-06-18/basic/transports>
- Anthropic/Claude Code config with `allowedTools`: <https://docs.anthropic.com/en/docs/claude-code/mcp>
- Cloudflare remote MCP with Streamable HTTP + auth patterns: <https://developers.cloudflare.com/agents/guides/remote-mcp-server/>

## FlockMesh Decision (Current)

We prioritize compatibility that fits enterprise collaboration safety:

1. Enforce MCP tool allowlist by `workspace_id + agent_id`.
2. Keep manifest trust metadata + attestation verification at load.
3. Keep runtime policy/approval/audit as separate hard gates after allowlist.

This avoids coupling MCP compatibility to any single office platform.

## Starter Tool Set (Phase 1)

We recommend starting with read-heavy and low-blast-radius tools:

- `search.*`
- `jira.issue.read`
- `calendar.events.read`
- `docs.page.read`
- `knowledge.fetch`

Then gradually add mutation tools only with explicit policy and approval controls.

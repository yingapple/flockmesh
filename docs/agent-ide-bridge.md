# Agent IDE Bridge (Codex / Claude Code)

This bridge turns FlockMesh into a focused MCP server for enterprise workflows.

## Why This Exists

- Keep Codex/Claude Code ergonomics
- Add enterprise guardrails (`allowlist`, `policy`, `approval`, `audit`)
- Keep tool surface intentionally small

## Start Stdio Bridge

```bash
FLOCKMESH_ROOT_DIR="$(pwd)" \
FLOCKMESH_WORKSPACE_ID="wsp_mindverse_cn" \
FLOCKMESH_ACTOR_ID="usr_yingapple" \
npm run mcp:bridge
```

## Use Streamable HTTP Bridge

HTTP endpoint: `POST /v0/mcp/stream`

Optional bearer auth:

```bash
export FLOCKMESH_MCP_BRIDGE_BEARER_TOKEN="replace-with-strong-token"
```

Initialize:

```bash
curl -i -s http://127.0.0.1:8080/v0/mcp/stream \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-with-strong-token' \
  -d '{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"codex","version":"1.0.0"}}}'
```

Reuse the returned `mcp-session-id` for follow-up calls:

```bash
curl -s http://127.0.0.1:8080/v0/mcp/stream \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-with-strong-token' \
  -H 'mcp-session-id: mcp_session_xxx' \
  -d '{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}' | jq
```

## Discover Profile

```bash
curl -s "http://127.0.0.1:8080/v0/integrations/agent-ide-profile?workspace_id=wsp_mindverse_cn&actor_id=usr_yingapple" | jq
```

The profile returns:

- stdio command/args/env for MCP mounting
- streamable HTTP endpoint metadata
- core bridge tools
- workspace/agent filtered MCP allowlist snapshot

## Core Enterprise Tools

- `flockmesh_quickstart_one_person`
- `flockmesh_invoke_mcp_tool`
- `flockmesh_list_pending_approvals`
- `flockmesh_resolve_approval`
- `flockmesh_get_run_audit`

## Recommended User Path

1. Run `flockmesh_quickstart_one_person`.
2. Execute low-risk tool calls via `flockmesh_invoke_mcp_tool` (`R0`/`none`).
3. Review and resolve escalations (`flockmesh_list_pending_approvals` + `flockmesh_resolve_approval`).
4. Export evidence using `flockmesh_get_run_audit`.

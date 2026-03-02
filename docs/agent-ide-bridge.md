# Agent IDE Bridge (Codex / Claude Code)

This bridge turns FlockMesh into a focused MCP stdio server for enterprise workflows.

## Why This Exists

- Keep Codex/Claude Code ergonomics
- Add enterprise guardrails (`allowlist`, `policy`, `approval`, `audit`)
- Keep tool surface intentionally small

## Start Bridge

```bash
FLOCKMESH_ROOT_DIR="$(pwd)" \
FLOCKMESH_WORKSPACE_ID="wsp_mindverse_cn" \
FLOCKMESH_ACTOR_ID="usr_yingapple" \
npm run mcp:bridge
```

## Discover Profile

```bash
curl -s "http://127.0.0.1:8080/v0/integrations/agent-ide-profile?workspace_id=wsp_mindverse_cn&actor_id=usr_yingapple" | jq
```

The profile returns:

- stdio command/args/env for MCP mounting
- core bridge tools
- workspace/agent filtered MCP allowlist snapshot

## Core Enterprise Tools

- `flockmesh_quickstart_one_person`
- `flockmesh_invoke_mcp_tool`
- `flockmesh_list_pending_approvals`
- `flockmesh_resolve_approval`
- `flockmesh_get_run_audit`

## Recommended User Path

1. Run `flockmesh_quickstart_one_person`
2. Execute low-risk tool calls via `flockmesh_invoke_mcp_tool` (`R0`/`none`)
3. Review and resolve escalations (`flockmesh_list_pending_approvals` + `flockmesh_resolve_approval`)
4. Export evidence using `flockmesh_get_run_audit`

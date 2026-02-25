import test from 'node:test';
import assert from 'node:assert/strict';

import { buildConnectorAdapterRegistry } from '../src/lib/connector-adapters.js';

test('connector adapter registry exposes MCP and A2A adapters', async () => {
  const adapters = buildConnectorAdapterRegistry();
  assert.ok(adapters.con_mcp_gateway);
  assert.ok(adapters.con_a2a_gateway);

  const mcpSimulated = await adapters.con_mcp_gateway.simulate({
    runId: 'run_adapter_123456',
    capability: 'tool.invoke',
    parameters: {
      tool_name: 'search.docs',
      tool_args: { query: 'policy trace' }
    }
  });
  assert.equal(mcpSimulated.mode, 'simulate');
  assert.equal(mcpSimulated.protocol, 'mcp');
});

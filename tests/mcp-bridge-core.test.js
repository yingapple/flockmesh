import test from 'node:test';
import assert from 'node:assert/strict';

import { buildApp } from '../src/app.js';
import {
  MCP_BRIDGE_TOOL_DEFINITIONS,
  createMcpBridgeCore
} from '../src/lib/mcp-bridge-core.js';

function createTestApp(overrides = {}) {
  return buildApp({
    logger: false,
    dbPath: ':memory:',
    trustedDefaultActorId: 'usr_yingapple',
    ...overrides
  });
}

test('mcp bridge core exposes focused enterprise toolset', () => {
  const names = MCP_BRIDGE_TOOL_DEFINITIONS.map((item) => item.name).sort();
  assert.deepEqual(names, [
    'flockmesh_get_run_audit',
    'flockmesh_invoke_mcp_tool',
    'flockmesh_list_pending_approvals',
    'flockmesh_quickstart_one_person',
    'flockmesh_resolve_approval'
  ]);
});

test('mcp bridge core runs enterprise flow: quickstart -> invoke -> approval', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const bridge = createMcpBridgeCore({
      app,
      defaults: {
        workspaceId: 'wsp_mindverse_cn',
        actorId: 'usr_yingapple'
      }
    });

    const quickstart = await bridge.callTool('flockmesh_quickstart_one_person', {
      workspace_id: 'wsp_mindverse_cn',
      owner_id: 'usr_yingapple',
      template_id: 'weekly_ops_sync',
      connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
      idempotency_key: `idem_mcp_bridge_${Date.now().toString(36)}`
    });

    assert.equal(quickstart.summary.workspace_id, 'wsp_mindverse_cn');
    assert.equal(quickstart.summary.owner_id, 'usr_yingapple');
    assert.equal(quickstart.summary.template_id, 'weekly_ops_sync');
    assert.equal(quickstart.run.workspace_id, 'wsp_mindverse_cn');

    const mcpBinding = quickstart.created_bindings.find(
      (item) => item.connector_id === 'con_mcp_gateway'
    );
    assert.ok(mcpBinding);

    const invoke = await bridge.callTool('flockmesh_invoke_mcp_tool', {
      run_id: quickstart.run.id,
      workspace_id: quickstart.run.workspace_id,
      agent_id: quickstart.created_agent.id,
      connector_binding_id: mcpBinding.id,
      tool_name: 'search.docs',
      tool_args: { query: 'bridge smoke' },
      side_effect: 'none',
      risk_hint: 'R0',
      initiated_by: 'usr_yingapple'
    });

    assert.ok(['executed', 'deduped'].includes(invoke.status));
    assert.equal(invoke.policy_decision.decision, 'allow');

    const pending = await bridge.callTool('flockmesh_list_pending_approvals', {
      workspace_id: 'wsp_mindverse_cn',
      limit: 20
    });
    assert.ok(Array.isArray(pending.items));
    assert.ok(
      pending.items.some((item) => item.run_id === quickstart.run.id && item.approvals.length >= 1)
    );

    const resolved = await bridge.callTool('flockmesh_resolve_approval', {
      run_id: quickstart.run.id,
      approved: true,
      approved_by: 'usr_yingapple',
      note: 'approved by bridge test'
    });

    assert.equal(resolved.run.id, quickstart.run.id);
    assert.ok(['completed', 'waiting_approval'].includes(resolved.run.status));
  } finally {
    await app.close();
  }
});

test('mcp bridge core pending approval listing stays workspace-scoped under pagination pressure', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const bridge = createMcpBridgeCore({
      app,
      defaults: {
        workspaceId: 'wsp_mindverse_cn',
        actorId: 'usr_yingapple'
      }
    });

    const targetQuickstart = await bridge.callTool('flockmesh_quickstart_one_person', {
      workspace_id: 'wsp_mindverse_cn',
      owner_id: 'usr_yingapple',
      template_id: 'weekly_ops_sync',
      connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
      idempotency_key: `idem_mcp_bridge_target_${Date.now().toString(36)}`
    });
    assert.equal(targetQuickstart.run.workspace_id, 'wsp_mindverse_cn');

    for (let index = 0; index < 3; index += 1) {
      const outsider = await bridge.callTool('flockmesh_quickstart_one_person', {
        workspace_id: 'wsp_other_suite',
        owner_id: 'usr_yingapple',
        template_id: 'weekly_ops_sync',
        connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
        idempotency_key: `idem_mcp_bridge_other_${Date.now().toString(36)}_${index}`
      });
      assert.equal(outsider.run.workspace_id, 'wsp_other_suite');
    }

    const scoped = await bridge.callTool('flockmesh_list_pending_approvals', {
      workspace_id: 'wsp_mindverse_cn',
      limit: 1,
      offset: 0
    });
    assert.equal(scoped.workspace_id, 'wsp_mindverse_cn');
    assert.equal(scoped.total >= 1, true);
    assert.ok(scoped.items.every((item) => item.workspace_id === 'wsp_mindverse_cn'));
    assert.ok(scoped.items.some((item) => item.run_id === targetQuickstart.run.id));
  } finally {
    await app.close();
  }
});

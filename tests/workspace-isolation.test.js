import test from 'node:test';
import assert from 'node:assert/strict';

import { buildApp } from '../src/app.js';

function createTestApp(overrides = {}) {
  return buildApp({
    logger: false,
    dbPath: ':memory:',
    trustedDefaultActorId: 'usr_yingapple',
    ...overrides
  });
}

async function createAgent(app, workspaceId, roleSuffix = 'ops') {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/agents',
    payload: {
      workspace_id: workspaceId,
      role: `assistant_${roleSuffix}`,
      owners: ['usr_yingapple'],
      name: `Agent ${workspaceId}`
    }
  });

  assert.equal(res.statusCode, 201);
  return res.json();
}

async function createBinding(app, {
  workspaceId,
  agentId,
  connectorId = 'con_mcp_gateway',
  scopes = ['tool.invoke'],
  authRef = 'sec_mcp_workspace_token',
  riskProfile = 'high_control'
}) {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/connectors/bindings',
    payload: {
      workspace_id: workspaceId,
      agent_id: agentId,
      connector_id: connectorId,
      scopes,
      auth_ref: authRef,
      risk_profile: riskProfile
    }
  });

  assert.equal(res.statusCode, 201);
  return res.json();
}

async function createRun(app, {
  workspaceId,
  agentId,
  playbookId = 'pbk_weekly_ops_sync',
  source = 'ops.control'
}) {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/runs',
    payload: {
      workspace_id: workspaceId,
      agent_id: agentId,
      playbook_id: playbookId,
      trigger: {
        type: 'manual',
        source,
        actor_id: 'usr_yingapple',
        at: new Date().toISOString()
      }
    }
  });

  assert.equal(res.statusCode, 202);
  return res.json();
}

test('workspace isolation rejects mixed-tenant adapter invoke payloads', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const wspA = 'wsp_tenant_a_cn';
    const wspB = 'wsp_tenant_b_us';

    const agentA = await createAgent(app, wspA, 'a');
    const agentB = await createAgent(app, wspB, 'b');

    const bindingA = await createBinding(app, {
      workspaceId: wspA,
      agentId: agentA.id,
      authRef: 'sec_mcp_workspace_a'
    });
    const bindingB = await createBinding(app, {
      workspaceId: wspB,
      agentId: agentB.id,
      authRef: 'sec_mcp_workspace_b'
    });

    const runA = await createRun(app, {
      workspaceId: wspA,
      agentId: agentA.id,
      source: 'ops.wspA'
    });

    const crossRunIdentity = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: runA.id,
        workspace_id: wspB,
        agent_id: agentB.id,
        connector_binding_id: bindingA.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'incident' }
        }
      }
    });

    assert.equal(crossRunIdentity.statusCode, 409);
    assert.match(crossRunIdentity.json().message, /Run does not match workspace_id\/agent_id/i);

    const crossBindingWorkspace = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: runA.id,
        workspace_id: wspA,
        agent_id: agentA.id,
        connector_binding_id: bindingB.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'incident' }
        }
      }
    });

    assert.equal(crossBindingWorkspace.statusCode, 409);
    assert.match(crossBindingWorkspace.json().message, /Binding workspace does not match/i);
  } finally {
    await app.close();
  }
});

test('timeline diff explicit base requires same workspace, agent, and playbook', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const wspA = 'wsp_tenant_a_cn';
    const wspB = 'wsp_tenant_b_us';

    const agentA = await createAgent(app, wspA, 'a');
    const agentA2 = await createAgent(app, wspA, 'a2');
    const agentB = await createAgent(app, wspB, 'b');

    await createBinding(app, {
      workspaceId: wspA,
      agentId: agentA.id,
      connectorId: 'con_feishu_official',
      scopes: ['message.send'],
      authRef: 'sec_feishu_workspace_a',
      riskProfile: 'restricted'
    });
    await createBinding(app, {
      workspaceId: wspA,
      agentId: agentA2.id,
      connectorId: 'con_feishu_official',
      scopes: ['message.send'],
      authRef: 'sec_feishu_workspace_a2',
      riskProfile: 'restricted'
    });
    await createBinding(app, {
      workspaceId: wspB,
      agentId: agentB.id,
      connectorId: 'con_feishu_official',
      scopes: ['message.send'],
      authRef: 'sec_feishu_workspace_b',
      riskProfile: 'restricted'
    });

    const run = await createRun(app, {
      workspaceId: wspA,
      agentId: agentA.id,
      playbookId: 'pbk_weekly_ops_sync',
      source: 'ops.run.main'
    });

    const baseWorkspace = await createRun(app, {
      workspaceId: wspB,
      agentId: agentB.id,
      playbookId: 'pbk_weekly_ops_sync',
      source: 'ops.run.workspace'
    });
    const baseAgent = await createRun(app, {
      workspaceId: wspA,
      agentId: agentA2.id,
      playbookId: 'pbk_weekly_ops_sync',
      source: 'ops.run.agent'
    });
    const basePlaybook = await createRun(app, {
      workspaceId: wspA,
      agentId: agentA.id,
      playbookId: 'pbk_monthly_ops_review',
      source: 'ops.run.playbook'
    });

    const mismatchWorkspace = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/timeline-diff?base_run_id=${baseWorkspace.id}`
    });
    assert.equal(mismatchWorkspace.statusCode, 409);
    assert.match(mismatchWorkspace.json().message, /workspace/i);

    const mismatchAgent = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/timeline-diff?base_run_id=${baseAgent.id}`
    });
    assert.equal(mismatchAgent.statusCode, 409);
    assert.match(mismatchAgent.json().message, /agent/i);

    const mismatchPlaybook = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/timeline-diff?base_run_id=${basePlaybook.id}`
    });
    assert.equal(mismatchPlaybook.statusCode, 409);
    assert.match(mismatchPlaybook.json().message, /playbook/i);
  } finally {
    await app.close();
  }
});

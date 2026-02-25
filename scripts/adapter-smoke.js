import assert from 'node:assert/strict';

import { buildApp } from '../src/app.js';

const ACTOR_ID = 'usr_yingapple';

function actorHeaders(actorId = ACTOR_ID) {
  return {
    'x-flockmesh-actor-id': actorId
  };
}

function ensureStatus(response, expected, label) {
  assert.equal(
    response.statusCode,
    expected,
    `${label} expected HTTP ${expected}, got ${response.statusCode} -> ${response.body}`
  );
}

async function createAgent(app) {
  const response = await app.inject({
    method: 'POST',
    url: '/v0/agents',
    payload: {
      workspace_id: 'wsp_mindverse_cn',
      role: 'ops_assistant',
      owners: ['usr_yingapple'],
      name: 'Adapter Smoke Agent'
    }
  });
  ensureStatus(response, 201, 'create agent');
  return response.json();
}

async function createBinding(app, payload) {
  const response = await app.inject({
    method: 'POST',
    url: '/v0/connectors/bindings',
    payload
  });
  ensureStatus(response, 201, `create binding ${payload.connector_id}`);
  return response.json();
}

async function createRun(app, agentId) {
  const response = await app.inject({
    method: 'POST',
    url: '/v0/runs',
    headers: actorHeaders(),
    payload: {
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agentId,
      playbook_id: 'pbk_adapter_smoke_v1',
      trigger: {
        type: 'manual',
        source: 'smoke.adapter.local',
        actor_id: ACTOR_ID,
        at: new Date().toISOString()
      }
    }
  });
  ensureStatus(response, 202, 'create run');
  return response.json();
}

async function main() {
  const app = buildApp({ logger: false, dbPath: ':memory:' });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const mcpBinding = await createBinding(app, {
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agent.id,
      connector_id: 'con_mcp_gateway',
      scopes: ['tool.invoke'],
      auth_ref: 'sec_mcp_gateway_smoke',
      risk_profile: 'high_control'
    });
    const a2aBinding = await createBinding(app, {
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agent.id,
      connector_id: 'con_a2a_gateway',
      scopes: ['delegation.request', 'delegation.status', 'delegation.cancel'],
      auth_ref: 'sec_a2a_gateway_smoke',
      risk_profile: 'high_control'
    });
    const run = await createRun(app, agent.id);

    const mcpSim = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/simulate',
      headers: actorHeaders(),
      payload: {
        run_id: run.id,
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        connector_binding_id: mcpBinding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: ACTOR_ID,
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'adapter smoke' }
        }
      }
    });
    ensureStatus(mcpSim, 200, 'mcp simulate');

    const mcpInvoke = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      headers: actorHeaders(),
      payload: {
        run_id: run.id,
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        connector_binding_id: mcpBinding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: ACTOR_ID,
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'adapter smoke invoke' }
        }
      }
    });
    ensureStatus(mcpInvoke, 200, 'mcp invoke');

    const a2aRequest = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/a2a/request`,
      headers: actorHeaders(),
      payload: {
        connector_binding_id: a2aBinding.id,
        initiated_by: ACTOR_ID,
        target_agent: 'agent_smoke_delegate',
        task_type: 'smoke.check'
      }
    });
    ensureStatus(a2aRequest, 200, 'a2a request');

    const rateLimits = await app.inject({
      method: 'GET',
      url: '/v0/connectors/rate-limits?connector_id=con_mcp_gateway'
    });
    ensureStatus(rateLimits, 200, 'rate-limit policy read');

    const health = await app.inject({
      method: 'GET',
      url: '/v0/connectors/health'
    });
    ensureStatus(health, 200, 'connector health');

    console.log('adapter smoke passed');
  } finally {
    await app.close();
  }
}

main().catch((err) => {
  console.error('adapter smoke failed');
  console.error(err?.stack || err?.message || err);
  process.exit(1);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import { buildApp } from '../src/app.js';
import { verifyIncidentExportSignature } from '../src/lib/incident-export.js';

function createTestApp(overrides = {}) {
  return buildApp({
    logger: false,
    dbPath: ':memory:',
    trustedDefaultActorId: 'usr_yingapple',
    ...overrides
  });
}

async function createPolicySandboxRoot() {
  const repoRoot = process.cwd();
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), 'flockmesh-policy-api-'));
  await Promise.all([
    fs.cp(path.join(repoRoot, 'spec'), path.join(rootDir, 'spec'), { recursive: true }),
    fs.cp(path.join(repoRoot, 'public'), path.join(rootDir, 'public'), { recursive: true }),
    fs.cp(path.join(repoRoot, 'connectors'), path.join(rootDir, 'connectors'), { recursive: true }),
    fs.cp(path.join(repoRoot, 'kits'), path.join(rootDir, 'kits'), { recursive: true }),
    fs.cp(path.join(repoRoot, 'policies'), path.join(rootDir, 'policies'), { recursive: true })
  ]);
  await fs.mkdir(path.join(rootDir, 'data'), { recursive: true });
  return rootDir;
}

async function cleanupPolicySandboxRoot(rootDir) {
  if (!rootDir) return;
  await fs.rm(rootDir, { recursive: true, force: true });
}

async function createAgent(app) {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/agents',
    payload: {
      workspace_id: 'wsp_mindverse_cn',
      role: 'ops_assistant',
      owners: ['usr_yingapple'],
      name: 'Ops Assistant'
    }
  });

  assert.equal(res.statusCode, 201);
  return res.json();
}

async function createBinding(app, agentId) {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/connectors/bindings',
    payload: {
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agentId,
      connector_id: 'con_feishu_official',
      scopes: ['message.send', 'calendar.read', 'doc.read'],
      auth_ref: 'sec_feishu_tenant_token_prod',
      risk_profile: 'restricted'
    }
  });

  assert.equal(res.statusCode, 201);
  return res.json();
}

async function createRun(app, agentId) {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/runs',
    payload: {
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agentId,
      playbook_id: 'pbk_weekly_ops_sync',
      trigger: {
        type: 'manual',
        source: 'feishu.group:ops-war-room',
        actor_id: 'usr_yingapple',
        at: new Date().toISOString()
      }
    }
  });

  assert.equal(res.statusCode, 202);
  return res.json();
}

function buildPolicyPatchTestActionIntent({
  runId = 'run_patch_eval_123456',
  actionId = 'act_patch_eval_ticket_create',
  capability = 'ticket.create',
  riskHint = 'R2'
} = {}) {
  return {
    id: actionId,
    run_id: runId,
    step_id: 'policy_patch_eval',
    capability,
    side_effect: 'mutation',
    idempotency_key: `${runId}_${capability.replace(/[^a-zA-Z0-9]/g, '_')}`,
    risk_hint: riskHint,
    parameters: {
      source: 'tests'
    },
    target: {
      surface: 'tests.policy'
    }
  };
}

async function getPolicyProfileVersion(app, profileName) {
  const versionRes = await app.inject({
    method: 'GET',
    url: `/v0/policy/profiles/${profileName}/version`
  });
  assert.equal(versionRes.statusCode, 200);
  return versionRes.json();
}

async function approveFirstEscalation(app, run, {
  approved = true,
  approvedBy = 'usr_yingapple',
  note = 'approved by test'
} = {}) {
  const pendingDecision = run.policy_decisions.find((item) => item.decision === 'escalate');
  assert.ok(pendingDecision);

  const res = await app.inject({
    method: 'POST',
    url: `/v0/runs/${run.id}/approvals`,
    payload: {
      action_intent_id: pendingDecision.action_intent_id,
      approved,
      approved_by: approvedBy,
      expected_revision: run.revision,
      note
    }
  });

  return res;
}

async function createA2aBinding(app, agentId) {
  const res = await app.inject({
    method: 'POST',
    url: '/v0/connectors/bindings',
    payload: {
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agentId,
      connector_id: 'con_a2a_gateway',
      scopes: ['delegation.request', 'delegation.status', 'delegation.cancel'],
      auth_ref: 'sec_a2a_gateway_token',
      risk_profile: 'high_control'
    }
  });

  assert.equal(res.statusCode, 201);
  return res.json();
}

test('run lifecycle: create -> waiting approval -> approve -> completed', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const runRes = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'feishu.group:ops-war-room',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });

    assert.equal(runRes.statusCode, 202);
    const run = runRes.json();
    assert.equal(run.status, 'waiting_approval');

    const pendingDecision = run.policy_decisions.find((item) => item.decision === 'escalate');
    assert.ok(pendingDecision);

    const approvalRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/approvals`,
      payload: {
        action_intent_id: pendingDecision.action_intent_id,
        approved: true,
        approved_by: 'usr_yingapple',
        expected_revision: run.revision,
        note: 'approved by test'
      }
    });

    assert.equal(approvalRes.statusCode, 200);
    const approvalBody = approvalRes.json();
    assert.equal(approvalBody.run.status, 'completed');

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });

    assert.equal(auditRes.statusCode, 200);
    const audit = auditRes.json();
    assert.ok(Array.isArray(audit.items));
    assert.ok(audit.items.some((item) => item.event_type === 'run.completed'));
  } finally {
    await app.close();
  }
});

test('run creation fails when agent does not exist', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: 'agt_missing_123456',
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'feishu.group:ops-war-room',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });

    assert.equal(res.statusCode, 404);
  } finally {
    await app.close();
  }
});

test('connector binding creation rejects cross-workspace agent binding', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_future_us',
        agent_id: agent.id,
        connector_id: 'con_feishu_official',
        scopes: ['message.send'],
        auth_ref: 'sec_cross_workspace_test',
        risk_profile: 'restricted'
      }
    });

    assert.equal(res.statusCode, 409);
    assert.match(res.json().message, /workspace/i);
  } finally {
    await app.close();
  }
});

test('run creation rejects workspace mismatch with agent profile', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_future_us',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'ops.war-room',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });

    assert.equal(res.statusCode, 409);
    assert.match(res.json().message, /workspace/i);
  } finally {
    await app.close();
  }
});

test('run creation rejects actor spoofing when trigger.actor_id mismatches authenticated actor', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      headers: {
        'x-flockmesh-actor-id': 'usr_yingapple'
      },
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'ops.spoof-check',
          actor_id: 'usr_spoof_actor',
          at: new Date().toISOString()
        }
      }
    });

    assert.equal(res.statusCode, 403);
    assert.match(res.json().message, /trigger\.actor_id/i);
  } finally {
    await app.close();
  }
});

test('run creation resolves agent policy from agent default_policy_profile', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    app.policyLibrary.agent_custom_profile = {
      name: 'agent_custom_profile',
      rules: {
        'calendar.read': { decision: 'allow' }
      }
    };

    const agentRes = await app.inject({
      method: 'POST',
      url: '/v0/agents',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        role: 'ops_assistant',
        owners: ['usr_yingapple'],
        name: 'Ops Assistant',
        default_policy_profile: 'agent_custom_profile'
      }
    });
    assert.equal(agentRes.statusCode, 201);
    const agent = agentRes.json();
    assert.equal(agent.default_policy_profile, 'agent_custom_profile');

    const runRes = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'ops.manual',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });

    assert.equal(runRes.statusCode, 202);
    const run = runRes.json();
    assert.ok(Array.isArray(run.policy_decisions));
    assert.ok(run.policy_decisions.length >= 1);
    assert.equal(run.policy_decisions[0].policy_trace.agent_policy, 'agent_custom_profile');
  } finally {
    await app.close();
  }
});

test('run creation accepts policy_context override instead of hardcoded context', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    app.policyLibrary.org_custom_safe = {
      name: 'org_custom_safe',
      rules: {
        'message.send': { decision: 'escalate', requiredApprovals: 1 }
      }
    };
    app.policyLibrary.workspace_custom_ops = {
      name: 'workspace_custom_ops',
      rules: {
        'message.send': { decision: 'escalate', requiredApprovals: 1 }
      }
    };
    app.policyLibrary.agent_custom_runtime = {
      name: 'agent_custom_runtime',
      rules: {
        'calendar.read': { decision: 'allow' }
      }
    };

    const agent = await createAgent(app);

    const runRes = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'ops.override',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        },
        policy_context: {
          org_policy: 'org_custom_safe',
          workspace_policy: 'workspace_custom_ops',
          agent_policy: 'agent_custom_runtime'
        }
      }
    });

    assert.equal(runRes.statusCode, 202);
    const run = runRes.json();
    assert.ok(run.policy_decisions.length >= 1);
    const trace = run.policy_decisions[0].policy_trace;
    assert.equal(trace.org_policy, 'org_custom_safe');
    assert.equal(trace.workspace_policy, 'workspace_custom_ops');
    assert.equal(trace.agent_policy, 'agent_custom_runtime');
  } finally {
    await app.close();
  }
});

test('list endpoints return created resources', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const listAgents = await app.inject({
      method: 'GET',
      url: '/v0/agents'
    });
    assert.equal(listAgents.statusCode, 200);
    assert.ok(listAgents.json().items.some((item) => item.id === agent.id));

    const listBindings = await app.inject({
      method: 'GET',
      url: '/v0/connectors/bindings'
    });
    assert.equal(listBindings.statusCode, 200);
    assert.ok(listBindings.json().items.length >= 1);

    const listRuns = await app.inject({
      method: 'GET',
      url: '/v0/runs'
    });
    assert.equal(listRuns.statusCode, 200);
    assert.ok(Array.isArray(listRuns.json().items));
  } finally {
    await app.close();
  }
});

test('agent kit catalog endpoint lists onboarding templates', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'GET',
      url: '/v0/templates/agent-kits'
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.equal(payload.version, 'v0');
    assert.ok(payload.total >= 2);
    assert.ok(payload.items.some((item) => item.kit_id === 'kit_office_ops_core'));
  } finally {
    await app.close();
  }
});

test('agent blueprint preview projects connector coverage and policy outcomes', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/preview',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        kit_id: 'kit_office_ops_core',
        owners: ['usr_yingapple'],
        selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway']
      }
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.equal(payload.kit.kit_id, 'kit_office_ops_core');
    assert.ok(payload.connector_plan.proposed_bindings.length >= 2);
    assert.ok(payload.capability_coverage.covered_total >= 4);
    assert.ok(payload.policy_projection.summary.total >= 4);
    assert.ok(payload.approval_forecast.escalated_actions >= 1);
    assert.ok(payload.planner_metrics.elapsed_ms >= 0);
    assert.ok(payload.planner_metrics.evaluated_capabilities >= 1);
    assert.ok(
      payload.policy_projection.items.some((item) => item.capability === 'message.send')
    );
  } finally {
    await app.close();
  }
});

test('agent blueprint lint returns readiness checks and recommendations', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/lint',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        kit_id: 'kit_office_ops_core',
        owners: ['usr_yingapple'],
        selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway']
      }
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.kit_id, 'kit_office_ops_core');
    assert.ok(['pass', 'warn', 'fail'].includes(payload.summary.status));
    assert.ok(payload.summary.total_checks >= 3);
    assert.ok(Array.isArray(payload.checks));
    assert.ok(Array.isArray(payload.recommendations));
  } finally {
    await app.close();
  }
});

test('agent blueprint remediation-plan returns executable auto-fix request', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/remediation-plan',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        kit_id: 'kit_office_ops_core',
        owners: ['usr_yingapple'],
        selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant'
        }
      }
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.kit_id, 'kit_office_ops_core');
    assert.ok(['pass', 'warn', 'fail'].includes(payload.summary.status_before));
    assert.ok(['pass', 'warn', 'fail'].includes(payload.summary.status_after_estimate));
    assert.equal(payload.auto_fix_request.workspace_id, 'wsp_mindverse_cn');
    assert.ok(Array.isArray(payload.connector_actions.suggested_connector_ids));
    assert.ok(Array.isArray(payload.connector_actions.add));
    assert.ok(Array.isArray(payload.unresolved_capabilities));
    assert.ok(Array.isArray(payload.policy_candidates.items));
    for (const item of payload.policy_candidates.items) {
      assert.ok(
        [
          'policy_profile_review',
          'approval_capacity',
          'run_override_candidate',
          'policy_profile_patch'
        ].includes(item.type)
      );
      if (item.estimated_effect) {
        assert.equal(typeof item.estimated_effect.expected_delta, 'number');
      }
    }
    assert.ok(payload.connector_actions.suggested_connector_ids.includes('con_a2a_gateway'));
    assert.ok(payload.auto_fix_request.selected_connector_ids.includes('con_a2a_gateway'));
  } finally {
    await app.close();
  }
});

test('agent blueprint remediation-plan recovers invalid run_override with direct candidate adoption', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/remediation-plan',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        kit_id: 'kit_office_ops_core',
        owners: ['usr_yingapple'],
        selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: 'missing_override_profile'
        }
      }
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    const runOverrideCandidate = payload.policy_candidates.items.find(
      (item) => item.type === 'run_override_candidate'
    );
    assert.ok(runOverrideCandidate);
    assert.equal(
      payload.policy_candidates.items.some(
        (item) =>
          item.type === 'policy_profile_patch' &&
          item.target_profile === 'missing_override_profile'
      ),
      false
    );
    assert.notEqual(runOverrideCandidate.suggested_run_override, 'missing_override_profile');
    assert.equal(
      payload.auto_fix_request.policy_context.run_override,
      runOverrideCandidate.suggested_run_override
    );
    assert.ok(payload.summary.score_after_estimate >= payload.summary.score_before);
  } finally {
    await app.close();
  }
});

test('agent blueprint apply provisions agent and connector bindings', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const applyRes = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/apply',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        kit_id: 'kit_office_ops_core',
        owners: ['usr_yingapple'],
        selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
        binding_auth_refs: {
          con_feishu_official: 'sec_feishu_blueprint_token'
        }
      }
    });

    assert.equal(applyRes.statusCode, 201);
    const payload = applyRes.json();
    assert.equal(payload.applied, true);
    assert.equal(payload.reused, false);
    assert.equal(payload.created_agent.workspace_id, 'wsp_mindverse_cn');
    assert.ok(payload.created_bindings.length >= 2);
    assert.ok(payload.auto_auth_connectors.includes('con_mcp_gateway'));

    const listAgents = await app.inject({
      method: 'GET',
      url: '/v0/agents'
    });
    assert.equal(listAgents.statusCode, 200);
    assert.ok(listAgents.json().items.some((item) => item.id === payload.created_agent.id));

    const listBindings = await app.inject({
      method: 'GET',
      url: '/v0/connectors/bindings'
    });
    assert.equal(listBindings.statusCode, 200);
    assert.ok(
      listBindings.json().items.some(
        (item) =>
          item.agent_id === payload.created_agent.id &&
          item.connector_id === 'con_mcp_gateway'
      )
    );
  } finally {
    await app.close();
  }
});

test('agent blueprint apply supports idempotent replay with same idempotency key', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const idempotencyKey = 'idem_blueprint_apply_replay_20260223';
    const payload = {
      workspace_id: 'wsp_mindverse_cn',
      kit_id: 'kit_office_ops_core',
      owners: ['usr_yingapple'],
      selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway'],
      idempotency_key: idempotencyKey
    };

    const firstRes = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/apply',
      payload
    });
    assert.equal(firstRes.statusCode, 201);
    const first = firstRes.json();
    assert.equal(first.reused, false);
    assert.equal(first.idempotency_key, idempotencyKey);

    const secondRes = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/apply',
      payload
    });
    assert.equal(secondRes.statusCode, 200);
    const second = secondRes.json();
    assert.equal(second.reused, true);
    assert.equal(second.idempotency_key, idempotencyKey);
    assert.equal(second.created_agent.id, first.created_agent.id);
    assert.equal(second.created_bindings.length, first.created_bindings.length);
  } finally {
    await app.close();
  }
});

test('one-person quickstart endpoint provisions agent, bindings, and first run', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/quickstart/one-person',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        owner_id: 'usr_yingapple',
        template_id: 'weekly_ops_sync'
      }
    });

    assert.equal(res.statusCode, 201);
    const payload = res.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.template_id, 'weekly_ops_sync');
    assert.equal(payload.reused, false);
    assert.equal(payload.quickstart.owner_id, 'usr_yingapple');
    assert.equal(payload.created_agent.workspace_id, 'wsp_mindverse_cn');
    assert.ok(payload.created_bindings.length >= 1);
    assert.equal(typeof payload.run.id, 'string');
    assert.equal(payload.run.workspace_id, 'wsp_mindverse_cn');
    assert.equal(payload.run.agent_id, payload.created_agent.id);
    assert.ok(Array.isArray(payload.next_actions));
    assert.ok(payload.next_actions.length >= 1);
  } finally {
    await app.close();
  }
});

test('one-person quickstart endpoint supports idempotent replay with same key', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const idempotencyKey = 'idem_one_person_quickstart_replay_20260225';
    const body = {
      workspace_id: 'wsp_mindverse_cn',
      owner_id: 'usr_yingapple',
      template_id: 'incident_response',
      idempotency_key: idempotencyKey
    };

    const firstRes = await app.inject({
      method: 'POST',
      url: '/v0/quickstart/one-person',
      payload: body
    });
    assert.equal(firstRes.statusCode, 201);
    const first = firstRes.json();
    assert.equal(first.reused, false);
    assert.equal(first.idempotency_key, idempotencyKey);

    const secondRes = await app.inject({
      method: 'POST',
      url: '/v0/quickstart/one-person',
      payload: body
    });
    assert.equal(secondRes.statusCode, 200);
    const second = secondRes.json();
    assert.equal(second.reused, true);
    assert.equal(second.idempotency_key, idempotencyKey);
    assert.equal(second.created_agent.id, first.created_agent.id);
    assert.equal(second.run.id, first.run.id);
  } finally {
    await app.close();
  }
});

test('one-person quickstart endpoint rejects unknown template', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/quickstart/one-person',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        owner_id: 'usr_yingapple',
        template_id: 'unknown_template'
      }
    });

    assert.equal(res.statusCode, 400);
  } finally {
    await app.close();
  }
});

test('agent blueprint apply strict mode blocks missing connector manifests', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const applyRes = await app.inject({
      method: 'POST',
      url: '/v0/agent-blueprints/apply',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        kit_id: 'kit_office_ops_core',
        owners: ['usr_yingapple'],
        selected_connector_ids: ['con_feishu_official', 'con_unknown_bridge'],
        strict_mode: true
      }
    });

    assert.equal(applyRes.statusCode, 409);
    assert.match(applyRes.json().message, /strict_mode/i);
  } finally {
    await app.close();
  }
});

test('incident export endpoint returns run evidence package', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const exportRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/incident-export?max_items_per_stream=500`
    });

    assert.equal(exportRes.statusCode, 200);
    const payload = exportRes.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.run_id, run.id);
    assert.equal(payload.workspace_id, run.workspace_id);
    assert.equal(payload.run.id, run.id);
    assert.equal(payload.policy_trace_summary.total, run.policy_decisions.length);
    assert.ok(payload.evidence.events.exported >= 1);
    assert.ok(payload.evidence.audit.exported >= 1);
    assert.equal(typeof payload.evidence.events.truncated, 'boolean');
    assert.equal(typeof payload.evidence.audit.truncated, 'boolean');
    assert.equal(payload.signature.algorithm, 'HMAC-SHA256');
    assert.equal(payload.signature.key_id, 'exp_dev_main_v1');
    const { signature, ...unsignedPayload } = payload;
    assert.equal(
      verifyIncidentExportSignature(
        unsignedPayload,
        signature,
        { keys: app.incidentExportSigning.keys }
      ),
      true
    );
  } finally {
    await app.close();
  }
});

test('timeline diff endpoint compares run against explicit base run', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const baseRun = await createRun(app, agent.id);
    const approvalRes = await approveFirstEscalation(app, baseRun);
    assert.equal(approvalRes.statusCode, 200);
    assert.equal(approvalRes.json().run.status, 'completed');

    const run = await createRun(app, agent.id);

    const diffRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/timeline-diff?base_run_id=${baseRun.id}&max_items_per_stream=500&sample_limit=30`
    });

    assert.equal(diffRes.statusCode, 200);
    const payload = diffRes.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.run_id, run.id);
    assert.equal(payload.base_run_id, baseRun.id);
    assert.equal(payload.base_source, 'explicit');
    assert.equal(payload.scope.playbook_id, 'pbk_weekly_ops_sync');
    assert.equal(payload.summary.current_status, 'waiting_approval');
    assert.equal(payload.summary.base_status, 'completed');
    assert.equal(typeof payload.summary.totals.events.delta, 'number');
    assert.equal(typeof payload.summary.totals.audit.delta, 'number');
    assert.ok(Array.isArray(payload.diff.audit_event_types.items));
    assert.ok(
      payload.diff.audit_event_types.items.some((row) => row.key === 'run.completed')
    );
  } finally {
    await app.close();
  }
});

test('timeline diff endpoint auto-selects previous run in same playbook scope', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const previous = await createRun(app, agent.id);
    await new Promise((resolve) => setTimeout(resolve, 12));
    const current = await createRun(app, agent.id);

    const diffRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${current.id}/timeline-diff?max_items_per_stream=500`
    });

    assert.equal(diffRes.statusCode, 200);
    const payload = diffRes.json();
    assert.equal(payload.base_source, 'auto_previous');
    assert.equal(payload.base_run_id, previous.id);
  } finally {
    await app.close();
  }
});

test('timeline diff endpoint returns 404 when no comparable base run exists', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const diffRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/timeline-diff`
    });

    assert.equal(diffRes.statusCode, 404);
    assert.match(diffRes.json().message, /base run/i);
  } finally {
    await app.close();
  }
});

test('timeline diff endpoint rejects explicit base run outside playbook scope', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const run = await createRun(app, agent.id);
    const otherPlaybookRes = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_monthly_ops_review',
        trigger: {
          type: 'manual',
          source: 'ops.review',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });
    assert.equal(otherPlaybookRes.statusCode, 202);
    const otherRun = otherPlaybookRes.json();

    const diffRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/timeline-diff?base_run_id=${otherRun.id}`
    });

    assert.equal(diffRes.statusCode, 409);
    assert.match(diffRes.json().message, /playbook/i);
  } finally {
    await app.close();
  }
});

test('replay integrity endpoint marks waiting_approval run as pending', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const replayRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/replay-integrity?max_items_per_stream=500&sample_limit=30`
    });

    assert.equal(replayRes.statusCode, 200);
    const payload = replayRes.json();
    assert.equal(payload.run_id, run.id);
    assert.equal(payload.run_status, 'waiting_approval');
    assert.equal(payload.replay_state, 'pending');
    assert.equal(payload.summary.expected_action_executions, 0);
  } finally {
    await app.close();
  }
});

test('replay integrity endpoint marks completed run as consistent', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);
    const run = await createRun(app, agent.id);
    const approvalRes = await approveFirstEscalation(app, run);
    assert.equal(approvalRes.statusCode, 200);
    assert.equal(approvalRes.json().run.status, 'completed');

    const replayRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/replay-integrity?max_items_per_stream=500&sample_limit=30`
    });

    assert.equal(replayRes.statusCode, 200);
    const payload = replayRes.json();
    assert.equal(payload.run_status, 'completed');
    assert.equal(payload.replay_state, 'consistent');
    assert.equal(payload.issues.length, 0);
    assert.equal(payload.summary.missing_expected_actions, 0);
    assert.equal(payload.summary.unexpected_actions, 0);
  } finally {
    await app.close();
  }
});

test('replay integrity endpoint detects tampered execution event as inconsistent', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);
    const run = await createRun(app, agent.id);
    const approvalRes = await approveFirstEscalation(app, run);
    assert.equal(approvalRes.statusCode, 200);

    await app.ledger.appendEvent({
      id: 'evt_tampered_replay_check',
      run_id: run.id,
      name: 'action.executed',
      payload: {
        action_intent_id: 'act_tampered_unknown_999999',
        capability: 'message.send',
        status: 'executed',
        deduped: false,
        executed_at: new Date().toISOString()
      },
      at: new Date().toISOString()
    });

    const replayRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/replay-integrity?max_items_per_stream=500&sample_limit=30`
    });

    assert.equal(replayRes.statusCode, 200);
    const payload = replayRes.json();
    assert.equal(payload.replay_state, 'inconsistent');
    assert.ok(payload.issues.includes('replay.unexpected_action_execution'));
    assert.ok(payload.issues.includes('replay.audit_event_count_mismatch'));
    assert.ok(payload.summary.unexpected_actions >= 1);
  } finally {
    await app.close();
  }
});

test('replay export endpoint returns signed replay integrity package', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);
    const run = await createRun(app, agent.id);
    const approvalRes = await approveFirstEscalation(app, run);
    assert.equal(approvalRes.statusCode, 200);

    const exportRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/replay-export?max_items_per_stream=500&sample_limit=20`
    });

    assert.equal(exportRes.statusCode, 200);
    const payload = exportRes.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.run_id, run.id);
    assert.equal(payload.run_status, 'completed');
    assert.equal(payload.replay_integrity.run_id, run.id);
    assert.equal(payload.replay_integrity.replay_state, 'consistent');
    assert.equal(payload.signature.algorithm, 'HMAC-SHA256');
    assert.equal(payload.signature.key_id, 'exp_dev_main_v1');
    const { signature, ...unsignedPayload } = payload;
    assert.equal(
      verifyIncidentExportSignature(
        unsignedPayload,
        signature,
        { keys: app.incidentExportSigning.keys }
      ),
      true
    );
  } finally {
    await app.close();
  }
});

test('replay drift monitoring endpoint summarizes inconsistent runs', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const run = await createRun(app, agent.id);
    const approvalRes = await approveFirstEscalation(app, run);
    assert.equal(approvalRes.statusCode, 200);

    await app.ledger.appendEvent({
      id: 'evt_tampered_for_drift_summary',
      run_id: run.id,
      name: 'action.executed',
      payload: {
        action_intent_id: 'act_tampered_drift_777777',
        capability: 'message.send',
        status: 'executed',
        deduped: false,
        executed_at: new Date().toISOString()
      },
      at: new Date().toISOString()
    });

    const pendingRun = await createRun(app, agent.id);
    assert.equal(pendingRun.status, 'waiting_approval');

    const summaryRes = await app.inject({
      method: 'GET',
      url: '/v0/monitoring/replay-drift?limit=20&max_items_per_stream=500&sample_limit=20'
    });

    assert.equal(summaryRes.statusCode, 200);
    const payload = summaryRes.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.window.include_pending, false);
    assert.ok(payload.totals.evaluated >= 1);
    assert.ok(payload.totals.inconsistent >= 1);
    assert.equal(payload.alert, true);
    assert.ok(payload.items.some((item) => item.run_id === run.id));
    assert.ok(payload.items.every((item) => item.run_status !== 'waiting_approval'));
  } finally {
    await app.close();
  }
});

test('connector manifest list exposes protocol-aware registry', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'GET',
      url: '/v0/connectors/manifests?category=agent_protocol'
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.ok(payload.items.some((item) => item.connector_id === 'con_mcp_gateway'));
    assert.ok(payload.items.some((item) => item.connector_id === 'con_a2a_gateway'));
    assert.ok(payload.items.every((item) => item.attestation?.verified === true));
  } finally {
    await app.close();
  }
});

test('mcp allowlist endpoint returns workspace-scoped rules', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'GET',
      url: '/v0/connectors/mcp/allowlists?workspace_id=wsp_mindverse_cn'
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.ok(payload.total >= 1);
    assert.ok(
      payload.items.some((doc) =>
        doc.rules.some((rule) => rule.workspace_id === 'wsp_mindverse_cn')
      )
    );
  } finally {
    await app.close();
  }
});

test('connector rate-limit endpoint returns effective policy', async () => {
  const app = createTestApp({
    connectorRateLimitPolicy: {
      version: 'v0',
      default: { limit: 40, window_ms: 120000 },
      connectors: {
        con_mcp_gateway: { limit: 5, window_ms: 30000 }
      }
    }
  });
  await app.ready();

  try {
    const fullRes = await app.inject({
      method: 'GET',
      url: '/v0/connectors/rate-limits'
    });
    assert.equal(fullRes.statusCode, 200);
    const fullPayload = fullRes.json();
    assert.equal(fullPayload.default.limit, 40);
    assert.equal(fullPayload.connectors.con_mcp_gateway.limit, 5);

    const oneRes = await app.inject({
      method: 'GET',
      url: '/v0/connectors/rate-limits?connector_id=con_a2a_gateway'
    });
    assert.equal(oneRes.statusCode, 200);
    const onePayload = oneRes.json();
    assert.equal(onePayload.source, 'default');
    assert.equal(onePayload.limit, 40);
  } finally {
    await app.close();
  }
});

test('connector drift and health detect undeclared scopes and missing manifests', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);

    const mcpBinding = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke', 'payment.execute'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(mcpBinding.statusCode, 201);

    const unknownBinding = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_unknown_bridge',
        scopes: ['crm.read'],
        auth_ref: 'sec_unknown_bridge_token',
        risk_profile: 'restricted'
      }
    });
    assert.equal(unknownBinding.statusCode, 201);

    const driftRes = await app.inject({
      method: 'GET',
      url: '/v0/connectors/drift'
    });
    assert.equal(driftRes.statusCode, 200);
    const drift = driftRes.json();
    assert.ok(drift.items.some((item) => item.issue === 'scope_not_declared'));
    assert.ok(drift.items.some((item) => item.issue === 'manifest_missing'));

    const healthRes = await app.inject({
      method: 'GET',
      url: '/v0/connectors/health'
    });
    assert.equal(healthRes.statusCode, 200);
    const health = healthRes.json();
    assert.ok(health.degraded >= 1);
    assert.ok(
      health.items.some(
        (item) => item.connector_id === 'con_unknown_bridge' && item.manifest_loaded === false
      )
    );
  } finally {
    await app.close();
  }
});

test('connector adapter simulate and invoke succeed with allow decision', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);

    const simRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/simulate',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'incident report' }
        }
      }
    });

    assert.equal(simRes.statusCode, 200);
    const simPayload = simRes.json();
    assert.equal(simPayload.status, 'simulated');
    assert.equal(simPayload.policy_decision.decision, 'allow');

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'incident report' }
        }
      }
    });

    assert.equal(invokeRes.statusCode, 200);
    const invokePayload = invokeRes.json();
    assert.equal(invokePayload.status, 'executed');
    assert.equal(invokePayload.policy_decision.decision, 'allow');

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    const auditPayload = auditRes.json();
    assert.ok(auditPayload.items.some((item) => item.event_type === 'connector.invoke.requested'));
    assert.ok(auditPayload.items.some((item) => item.event_type === 'connector.invoke.executed'));
  } finally {
    await app.close();
  }
});

test('connector adapter invoke blocks on policy escalate (fail-closed path)', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'mutation',
        risk_hint: 'R2',
        idempotency_key: `${run.id}_mcp_invoke_r2`,
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { summary: 'escalated action' }
        }
      }
    });

    assert.equal(invokeRes.statusCode, 409);
    const payload = invokeRes.json();
    assert.equal(payload.status, 'blocked');
    assert.equal(payload.policy_decision.decision, 'escalate');

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    const auditPayload = auditRes.json();
    assert.ok(auditPayload.items.some((item) => item.event_type === 'connector.invoke.blocked'));
  } finally {
    await app.close();
  }
});

test('connector adapter invoke dedupes mutation by idempotency key', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);
    const idempotencyKey = `${run.id}_mcp_mutation_once`;

    const first = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'mutation',
        risk_hint: 'R1',
        idempotency_key: idempotencyKey,
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { summary: 'idempotent mutation' }
        }
      }
    });
    assert.equal(first.statusCode, 200);
    assert.equal(first.json().status, 'executed');

    const second = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'mutation',
        risk_hint: 'R1',
        idempotency_key: idempotencyKey,
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { summary: 'idempotent mutation' }
        }
      }
    });

    assert.equal(second.statusCode, 200);
    assert.equal(second.json().status, 'deduped');
  } finally {
    await app.close();
  }
});

test('connector adapter invoke blocks on per-connector rate-limit guardrail', async () => {
  const app = createTestApp({
    connectorRateLimitPolicy: {
      version: 'v0',
      default: { limit: 30, window_ms: 60000 },
      connectors: {
        con_mcp_gateway: { limit: 1, window_ms: 60000 }
      }
    }
  });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);

    const firstInvoke = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'first request' }
        }
      }
    });
    assert.equal(firstInvoke.statusCode, 200);

    const secondInvoke = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          tool_args: { query: 'second request' }
        }
      }
    });

    assert.equal(secondInvoke.statusCode, 429);
    const blockedPayload = secondInvoke.json();
    assert.equal(blockedPayload.status, 'blocked');
    assert.ok(blockedPayload.policy_decision.reason_codes.includes('connector.invoke.rate_limited'));
    assert.ok(blockedPayload.retry_after_ms >= 1);

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    assert.ok(
      auditRes.json().items.some((item) => item.event_type === 'connector.invoke.rate_limited')
    );
  } finally {
    await app.close();
  }
});

test('connector adapter invoke blocks MCP tool outside allowlist', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'admin.user.delete',
          tool_args: { user: 'usr_demo' }
        }
      }
    });

    assert.equal(invokeRes.statusCode, 403);
    const payload = invokeRes.json();
    assert.equal(payload.status, 'blocked');
    assert.ok(payload.policy_decision.reason_codes.includes('mcp.allowlist.tool_not_allowed'));
  } finally {
    await app.close();
  }
});

test('connector adapter simulate blocks MCP tool outside allowlist', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);

    const simRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/simulate',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'admin.user.delete',
          tool_args: { user: 'usr_demo' }
        }
      }
    });

    assert.equal(simRes.statusCode, 403);
    const payload = simRes.json();
    assert.equal(payload.reason_code, 'mcp.allowlist.tool_not_allowed');
  } finally {
    await app.close();
  }
});

test('connector adapter invoke fails closed on adapter timeout', async () => {
  const app = createTestApp({ adapterTimeoutMs: 20 });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const binding = await createA2aBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        connector_binding_id: binding.id,
        capability: 'delegation.status',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          delegation_id: 'dlg_timeout_123456',
          simulate_timeout_ms: 80
        }
      }
    });

    assert.equal(invokeRes.statusCode, 503);
    const payload = invokeRes.json();
    assert.equal(payload.status, 'blocked');
    assert.ok(payload.policy_decision.reason_codes.includes('connector.invoke.timeout'));

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    assert.ok(auditRes.json().items.some((item) => item.event_type === 'connector.invoke.timeout'));
  } finally {
    await app.close();
  }
});

test('connector adapter invoke retries read-only failure within retry budget', async () => {
  const app = createTestApp({
    adapterTimeoutMs: 20,
    adapterRetryPolicy: {
      version: 'v0',
      max_attempts: 2,
      base_delay_ms: 0,
      max_delay_ms: 0,
      jitter_ms: 0
    }
  });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const binding = await createA2aBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        connector_binding_id: binding.id,
        capability: 'delegation.status',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          delegation_id: 'dlg_timeout_retry_123456',
          simulate_timeout_ms: 80
        }
      }
    });

    assert.equal(invokeRes.statusCode, 503);
    const payload = invokeRes.json();
    assert.equal(payload.status, 'blocked');
    assert.ok(payload.policy_decision.reason_codes.includes('connector.invoke.timeout'));

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    const auditItems = auditRes.json().items;
    assert.ok(auditItems.some((item) => item.event_type === 'connector.invoke.retry'));
    assert.ok(auditItems.some((item) => item.event_type === 'connector.invoke.timeout'));
  } finally {
    await app.close();
  }
});

test('connector adapter invoke retries mutation when idempotency key is present', async () => {
  const app = createTestApp({
    adapterTimeoutMs: 20,
    adapterRetryPolicy: {
      version: 'v0',
      max_attempts: 3,
      base_delay_ms: 0,
      max_delay_ms: 0,
      jitter_ms: 0
    }
  });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const binding = await createA2aBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        connector_binding_id: binding.id,
        capability: 'delegation.cancel',
        side_effect: 'mutation',
        risk_hint: 'R1',
        idempotency_key: `${run.id}_cancel_retry_once`,
        initiated_by: 'usr_yingapple',
        parameters: {
          delegation_id: 'dlg_timeout_with_idempotency_123456',
          reason: 'cancel',
          simulate_timeout_ms: 80
        }
      }
    });

    assert.equal(invokeRes.statusCode, 503);
    const payload = invokeRes.json();
    assert.equal(payload.status, 'blocked');
    assert.ok(payload.policy_decision.reason_codes.includes('connector.invoke.timeout'));

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    const retryEvents = auditRes.json().items.filter((item) => item.event_type === 'connector.invoke.retry');
    assert.ok(retryEvents.length >= 1);
  } finally {
    await app.close();
  }
});

test('connector adapter invoke fails closed on adapter runtime error', async () => {
  const app = createTestApp({ adapterTimeoutMs: 100 });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const binding = await createA2aBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      payload: {
        run_id: run.id,
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        connector_binding_id: binding.id,
        capability: 'delegation.status',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          delegation_id: 'dlg_error_123456',
          simulate_error: true
        }
      }
    });

    assert.equal(invokeRes.statusCode, 503);
    const payload = invokeRes.json();
    assert.equal(payload.status, 'blocked');
    assert.ok(payload.policy_decision.reason_codes.includes('connector.invoke.error'));

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    assert.ok(auditRes.json().items.some((item) => item.event_type === 'connector.invoke.error'));
  } finally {
    await app.close();
  }
});

test('connector adapter simulate returns timeout error when adapter exceeds deadline', async () => {
  const app = createTestApp({ adapterTimeoutMs: 20 });
  await app.ready();

  try {
    const agent = await createAgent(app);
    const bindingRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/bindings',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        connector_id: 'con_mcp_gateway',
        scopes: ['tool.invoke'],
        auth_ref: 'sec_mcp_gateway_token',
        risk_profile: 'high_control'
      }
    });
    assert.equal(bindingRes.statusCode, 201);
    const binding = bindingRes.json();
    const run = await createRun(app, agent.id);

    const simRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_mcp_gateway/simulate',
      payload: {
        run_id: run.id,
        workspace_id: 'wsp_mindverse_cn',
        agent_id: run.agent_id,
        connector_binding_id: binding.id,
        capability: 'tool.invoke',
        side_effect: 'none',
        risk_hint: 'R0',
        initiated_by: 'usr_yingapple',
        parameters: {
          tool_name: 'search.docs',
          simulate_timeout_ms: 80
        }
      }
    });

    assert.equal(simRes.statusCode, 503);
    const payload = simRes.json();
    assert.equal(payload.reason_code, 'connector.invoke.timeout');
  } finally {
    await app.close();
  }
});

test('run-level A2A wrapper supports request/status/cancel lifecycle', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const binding = await createA2aBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const requestRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/a2a/request`,
      payload: {
        connector_binding_id: binding.id,
        initiated_by: 'usr_yingapple',
        target_agent: 'agent_finance_delegate',
        task_type: 'incident.summary',
        payload: {
          incident_id: 'inc_20260223_001'
        }
      }
    });

    assert.equal(requestRes.statusCode, 200);
    const requestPayload = requestRes.json();
    assert.equal(requestPayload.operation, 'delegation.request');
    assert.equal(requestPayload.status, 'executed');
    assert.ok(requestPayload.delegation_id);

    const delegationId = requestPayload.delegation_id;

    const statusRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/a2a/${delegationId}/status`,
      payload: {
        connector_binding_id: binding.id,
        initiated_by: 'usr_yingapple'
      }
    });

    assert.equal(statusRes.statusCode, 200);
    const statusPayload = statusRes.json();
    assert.equal(statusPayload.operation, 'delegation.status');
    assert.equal(statusPayload.status, 'executed');

    const cancelRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/a2a/${delegationId}/cancel`,
      payload: {
        connector_binding_id: binding.id,
        initiated_by: 'usr_yingapple',
        reason: 'workflow completed'
      }
    });

    assert.equal(cancelRes.statusCode, 200);
    const cancelPayload = cancelRes.json();
    assert.equal(cancelPayload.operation, 'delegation.cancel');
    assert.equal(cancelPayload.status, 'executed');
  } finally {
    await app.close();
  }
});

test('run-level A2A request can be blocked by risk policy escalation', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    const binding = await createA2aBinding(app, agent.id);
    const run = await createRun(app, agent.id);

    const requestRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/a2a/request`,
      payload: {
        connector_binding_id: binding.id,
        initiated_by: 'usr_yingapple',
        target_agent: 'agent_finance_delegate',
        task_type: 'incident.summary',
        risk_hint: 'R2'
      }
    });

    assert.equal(requestRes.statusCode, 409);
    const payload = requestRes.json();
    assert.equal(payload.status, 'blocked');
    assert.equal(payload.policy_decision.decision, 'escalate');
  } finally {
    await app.close();
  }
});

test('run can be cancelled while waiting approval', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const runRes = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'feishu.group:ops-war-room',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });

    const run = runRes.json();
    assert.equal(run.status, 'waiting_approval');

    const cancelRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/cancel`,
      payload: {
        cancelled_by: 'usr_yingapple',
        expected_revision: run.revision,
        reason: 'manual stop in test'
      }
    });

    assert.equal(cancelRes.statusCode, 200);
    const cancelled = cancelRes.json();
    assert.equal(cancelled.run.status, 'cancelled');

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v0/runs/${run.id}/audit`
    });
    assert.equal(auditRes.statusCode, 200);
    assert.ok(auditRes.json().items.some((item) => item.event_type === 'run.cancelled'));
  } finally {
    await app.close();
  }
});

test('approval rejects stale revision updates', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const agent = await createAgent(app);
    await createBinding(app, agent.id);

    const runRes = await app.inject({
      method: 'POST',
      url: '/v0/runs',
      payload: {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: agent.id,
        playbook_id: 'pbk_weekly_ops_sync',
        trigger: {
          type: 'manual',
          source: 'feishu.group:ops-war-room',
          actor_id: 'usr_yingapple',
          at: new Date().toISOString()
        }
      }
    });

    const run = runRes.json();
    const decision = run.policy_decisions.find((item) => item.decision === 'escalate');
    assert.ok(decision);

    const staleRes = await app.inject({
      method: 'POST',
      url: `/v0/runs/${run.id}/approvals`,
      payload: {
        action_intent_id: decision.action_intent_id,
        approved: true,
        approved_by: 'usr_yingapple',
        expected_revision: run.revision + 1,
        note: 'stale revision test'
      }
    });

    assert.equal(staleRes.statusCode, 409);
  } finally {
    await app.close();
  }
});

test('policy profile catalog endpoint returns sorted profile summaries', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'GET',
      url: '/v0/policy/profiles'
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.equal(payload.version, 'v0');
    assert.ok(payload.total >= 1);
    assert.equal(payload.total, payload.items.length);

    const names = payload.items.map((item) => item.profile_name);
    assert.deepEqual(names, [...names].sort());

    for (const item of payload.items) {
      assert.equal(item.rule_count, item.rules.length);
      const summary = item.rules.reduce((acc, rule) => {
        if (rule.decision === 'allow') acc.allow += 1;
        if (rule.decision === 'escalate') acc.escalate += 1;
        if (rule.decision === 'deny') acc.deny += 1;
        return acc;
      }, { allow: 0, escalate: 0, deny: 0 });
      assert.deepEqual(item.decision_summary, summary);
    }
  } finally {
    await app.close();
  }
});

test('policy profile version endpoint returns hash snapshot and reflects apply updates', async () => {
  const profileName = `policy_profile_version_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforeRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/profiles/${profileName}/version`
    });
    assert.equal(versionBeforeRes.statusCode, 200);
    const versionBefore = versionBeforeRes.json();
    assert.equal(versionBefore.profile_name, profileName);
    assert.equal(versionBefore.rule_count, 1);
    assert.match(versionBefore.document_hash, /^sha256:[a-f0-9]{64}$/);

    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'update version hash',
        expected_profile_hash: versionBefore.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);

    const versionAfterRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/profiles/${profileName}/version`
    });
    assert.equal(versionAfterRes.statusCode, 200);
    const versionAfter = versionAfterRes.json();
    assert.equal(versionAfter.profile_name, profileName);
    assert.equal(versionAfter.rule_count, 1);
    assert.match(versionAfter.document_hash, /^sha256:[a-f0-9]{64}$/);
    assert.notEqual(versionAfter.document_hash, versionBefore.document_hash);
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy patch apply rejects actor_id mismatch with authenticated actor', async () => {
  const profileName = `policy_patch_actor_mismatch_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionPayload = await getPolicyProfileVersion(app, profileName);

    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      headers: {
        'x-flockmesh-actor-id': 'usr_yingapple'
      },
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_non_admin',
        reason: 'spoof actor_id claim',
        expected_profile_hash: versionPayload.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });

    assert.equal(patchRes.statusCode, 403);
    assert.equal(patchRes.json().message, 'Authenticated actor does not match actor_id');
    assert.equal(patchRes.json().reason_code, 'auth.actor_claim_mismatch');
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy patch apply rejects stale expected_profile_hash and keeps profile unchanged', async () => {
  const profileName = `policy_patch_hash_conflict_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/profiles/${profileName}/version`
    });
    assert.equal(versionRes.statusCode, 200);
    const versionPayload = versionRes.json();

    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'simulate stale write',
        expected_profile_hash: `sha256:${'0'.repeat(64)}`,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 409);
    assert.equal(patchRes.json().expected_profile_hash, `sha256:${'0'.repeat(64)}`);
    assert.equal(patchRes.json().current_profile_hash, versionPayload.document_hash);

    const evaluateRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_policy_patch_hash_conflict',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_policy_patch_hash_conflict',
          actionId: 'act_policy_patch_hash_conflict'
        })
      }
    });
    assert.equal(evaluateRes.statusCode, 200);
    assert.equal(evaluateRes.json().decision, 'deny');
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy patch apply requires expected_profile_hash', async () => {
  const profileName = `policy_patch_missing_hash_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'missing hash should fail',
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 400);
    assert.match(String(patchRes.json().message || ''), /expected_profile_hash/);
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy patch dry_run does not mutate active policy library', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const evaluateBefore = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_patch_dry_eval_before',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: 'workspace_ops_cn'
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_patch_dry_eval_before',
          actionId: 'act_patch_dry_eval_before'
        })
      }
    });
    assert.equal(evaluateBefore.statusCode, 200);
    assert.equal(evaluateBefore.json().decision, 'escalate');

    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: 'workspace_ops_cn',
        mode: 'dry_run',
        actor_id: 'usr_yingapple',
        reason: 'validate dry_run behavior',
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'deny'
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();
    assert.equal(patchPayload.mode, 'dry_run');
    assert.equal(patchPayload.persisted, false);
    assert.equal(patchPayload.audit_entry, null);
    assert.equal(patchPayload.summary.patch_rules, 1);
    assert.equal(patchPayload.simulation_preview.summary_after.deny, 1);

    const evaluateAfter = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_patch_dry_eval_after',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: 'workspace_ops_cn'
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_patch_dry_eval_after',
          actionId: 'act_patch_dry_eval_after'
        })
      }
    });
    assert.equal(evaluateAfter.statusCode, 200);
    assert.equal(evaluateAfter.json().decision, 'escalate');
  } finally {
    await app.close();
  }
});

test('policy patch apply persists profile update and changes evaluation outcome', async () => {
  const profileName = `policy_patch_apply_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const evaluateBefore = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_patch_apply_eval_before',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_patch_apply_eval_before',
          actionId: 'act_patch_apply_eval_before'
        })
      }
    });
    assert.equal(evaluateBefore.statusCode, 200);
    assert.equal(evaluateBefore.json().decision, 'deny');
    const versionBeforeApply = await getPolicyProfileVersion(app, profileName);

    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'promote deny to approval gate',
        expected_profile_hash: versionBeforeApply.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();
    assert.equal(patchPayload.mode, 'apply');
    assert.equal(patchPayload.persisted, true);
    assert.equal(patchPayload.file_path, profileFilePath);
    assert.equal(patchPayload.audit_entry.event_type, 'policy.patch.applied');
    assert.equal(patchPayload.audit_entry.actor.id, 'usr_yingapple');

    const evaluateAfter = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_patch_apply_eval_after',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_patch_apply_eval_after',
          actionId: 'act_patch_apply_eval_after'
        })
      }
    });
    assert.equal(evaluateAfter.statusCode, 200);
    assert.equal(evaluateAfter.json().decision, 'escalate');

    const persistedDoc = JSON.parse(await fs.readFile(profileFilePath, 'utf8'));
    const ticketRule = persistedDoc.rules.find((item) => item.capability === 'ticket.create');
    assert.ok(ticketRule);
    assert.equal(ticketRule.decision, 'escalate');
    assert.equal(ticketRule.required_approvals, 1);

    const catalogRes = await app.inject({
      method: 'GET',
      url: '/v0/policy/profiles'
    });
    assert.equal(catalogRes.statusCode, 200);
    const catalog = catalogRes.json();
    const patchedProfile = catalog.items.find((item) => item.profile_name === profileName);
    assert.ok(patchedProfile);
    const patchedRule = patchedProfile.rules.find((item) => item.capability === 'ticket.create');
    assert.ok(patchedRule);
    assert.equal(patchedRule.decision, 'escalate');
    assert.equal(patchedRule.required_approvals, 1);
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy patch history endpoint lists applied patch entries by profile and operation', async () => {
  const profileName = `policy_patch_history_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforeApply = await getPolicyProfileVersion(app, profileName);
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'record history entry',
        expected_profile_hash: versionBeforeApply.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();
    assert.match(String(patchPayload.patch_id || ''), /^pph_/);
    assert.equal(patchPayload.summary.removed, 0);
    assert.deepEqual(patchPayload.changes.removed_capabilities, []);

    const historyRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/patches?profile_name=${profileName}&operation=patch&limit=10`
    });
    assert.equal(historyRes.statusCode, 200);
    const historyPayload = historyRes.json();
    assert.ok(historyPayload.total >= 1);
    const item = historyPayload.items.find((entry) => entry.patch_id === patchPayload.patch_id);
    assert.ok(item);
    assert.equal(item.profile_name, profileName);
    assert.equal(item.operation, 'patch');
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy rollback apply restores profile snapshot and records rollback history', async () => {
  const profileName = `policy_rollback_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforePatch = await getPolicyProfileVersion(app, profileName);
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'promote deny to escalate',
        expected_profile_hash: versionBeforePatch.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();
    assert.match(String(patchPayload.patch_id || ''), /^pph_/);

    const evaluateEscalated = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_policy_rollback_after_patch',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_policy_rollback_after_patch',
          actionId: 'act_policy_rollback_after_patch'
        })
      }
    });
    assert.equal(evaluateEscalated.statusCode, 200);
    assert.equal(evaluateEscalated.json().decision, 'escalate');

    const rollbackDryRunRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/rollback',
      payload: {
        profile_name: profileName,
        mode: 'dry_run',
        target_patch_id: patchPayload.patch_id,
        target_state: 'before',
        actor_id: 'usr_yingapple',
        reason: 'preview rollback'
      }
    });
    assert.equal(rollbackDryRunRes.statusCode, 200);
    const rollbackDryRunPayload = rollbackDryRunRes.json();
    assert.equal(rollbackDryRunPayload.persisted, false);
    assert.equal(rollbackDryRunPayload.summary.removed, 0);
    const versionBeforeRollbackApply = await getPolicyProfileVersion(app, profileName);

    const rollbackApplyRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/rollback',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        target_patch_id: patchPayload.patch_id,
        target_state: 'before',
        actor_id: 'usr_yingapple',
        reason: 'apply rollback',
        expected_profile_hash: versionBeforeRollbackApply.document_hash
      }
    });
    assert.equal(rollbackApplyRes.statusCode, 200);
    const rollbackPayload = rollbackApplyRes.json();
    assert.equal(rollbackPayload.mode, 'apply');
    assert.equal(rollbackPayload.persisted, true);
    assert.equal(rollbackPayload.rollback_target_patch_id, patchPayload.patch_id);
    assert.match(String(rollbackPayload.patch_id || ''), /^pph_/);
    assert.equal(rollbackPayload.audit_entry.event_type, 'policy.rollback.applied');

    const evaluateRestored = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_policy_rollback_after_apply',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_policy_rollback_after_apply',
          actionId: 'act_policy_rollback_after_apply'
        })
      }
    });
    assert.equal(evaluateRestored.statusCode, 200);
    assert.equal(evaluateRestored.json().decision, 'deny');

    const historyRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/patches?profile_name=${profileName}&operation=rollback&limit=10`
    });
    assert.equal(historyRes.statusCode, 200);
    const historyPayload = historyRes.json();
    assert.ok(historyPayload.items.some((item) => item.patch_id === rollbackPayload.patch_id));
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy rollback apply rejects stale expected_profile_hash and keeps current profile', async () => {
  const profileName = `policy_rollback_hash_conflict_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforePatch = await getPolicyProfileVersion(app, profileName);
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'prepare rollback history',
        expected_profile_hash: versionBeforePatch.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();
    assert.match(String(patchPayload.patch_id || ''), /^pph_/);

    const versionRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/profiles/${profileName}/version`
    });
    assert.equal(versionRes.statusCode, 200);
    const versionPayload = versionRes.json();

    const rollbackConflictRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/rollback',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        target_patch_id: patchPayload.patch_id,
        target_state: 'before',
        actor_id: 'usr_yingapple',
        reason: 'simulate stale rollback write',
        expected_profile_hash: `sha256:${'f'.repeat(64)}`
      }
    });
    assert.equal(rollbackConflictRes.statusCode, 409);
    assert.equal(rollbackConflictRes.json().expected_profile_hash, `sha256:${'f'.repeat(64)}`);
    assert.equal(rollbackConflictRes.json().current_profile_hash, versionPayload.document_hash);

    const evaluateRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_policy_rollback_hash_conflict',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_policy_rollback_hash_conflict',
          actionId: 'act_policy_rollback_hash_conflict'
        })
      }
    });
    assert.equal(evaluateRes.statusCode, 200);
    assert.equal(evaluateRes.json().decision, 'escalate');
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy rollback apply requires expected_profile_hash', async () => {
  const profileName = `policy_rollback_missing_hash_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforePatch = await getPolicyProfileVersion(app, profileName);
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'prepare rollback target',
        expected_profile_hash: versionBeforePatch.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();

    const rollbackRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/rollback',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        target_patch_id: patchPayload.patch_id,
        target_state: 'before',
        actor_id: 'usr_yingapple',
        reason: 'missing hash should fail'
      }
    });
    assert.equal(rollbackRes.statusCode, 400);
    assert.match(String(rollbackRes.json().message || ''), /expected_profile_hash/);
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy rollback apply is blocked for actor outside policy admin config', async () => {
  const profileName = `policy_rollback_authz_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforePatch = await getPolicyProfileVersion(app, profileName);
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'create rollback target',
        expected_profile_hash: versionBeforePatch.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();
    const versionBeforeForbiddenRollback = await getPolicyProfileVersion(app, profileName);

    const rollbackForbiddenRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/rollback',
      headers: {
        'x-flockmesh-actor-id': 'usr_non_admin'
      },
      payload: {
        profile_name: profileName,
        mode: 'apply',
        target_patch_id: patchPayload.patch_id,
        target_state: 'before',
        actor_id: 'usr_non_admin',
        reason: 'should be forbidden',
        expected_profile_hash: versionBeforeForbiddenRollback.document_hash
      }
    });
    assert.equal(rollbackForbiddenRes.statusCode, 403);
    assert.equal(rollbackForbiddenRes.json().reason_code, 'policy.admin.not_authorized');

    const evaluateAfterForbidden = await app.inject({
      method: 'POST',
      url: '/v0/policy/evaluate',
      payload: {
        run_id: 'run_policy_rollback_forbidden_eval',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant',
          run_override: profileName
        },
        action_intent: buildPolicyPatchTestActionIntent({
          runId: 'run_policy_rollback_forbidden_eval',
          actionId: 'act_policy_rollback_forbidden_eval'
        })
      }
    });
    assert.equal(evaluateAfterForbidden.statusCode, 200);
    assert.equal(evaluateAfterForbidden.json().decision, 'escalate');
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy patch history export endpoint returns signed package', async () => {
  const profileName = `policy_history_export_${Date.now().toString(36)}`;
  const rootDir = await createPolicySandboxRoot();
  const profileFilePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);

  await fs.writeFile(profileFilePath, `${JSON.stringify({
    version: 'v0',
    name: profileName,
    rules: [
      {
        capability: 'ticket.create',
        decision: 'deny'
      }
    ]
  }, null, 2)}\n`, 'utf8');

  const app = createTestApp({ rootDir });
  await app.ready();

  try {
    const versionBeforeApply = await getPolicyProfileVersion(app, profileName);
    const patchRes = await app.inject({
      method: 'POST',
      url: '/v0/policy/patch',
      payload: {
        profile_name: profileName,
        mode: 'apply',
        actor_id: 'usr_yingapple',
        reason: 'seed history export',
        expected_profile_hash: versionBeforeApply.document_hash,
        patch_rules: [
          {
            capability: 'ticket.create',
            decision: 'escalate',
            required_approvals: 1
          }
        ]
      }
    });
    assert.equal(patchRes.statusCode, 200);
    const patchPayload = patchRes.json();

    const exportRes = await app.inject({
      method: 'GET',
      url: `/v0/policy/patches/export?profile_name=${profileName}&operation=patch&limit=10&offset=0`
    });
    assert.equal(exportRes.statusCode, 200);
    const payload = exportRes.json();
    assert.equal(payload.version, 'v0');
    assert.equal(payload.filters.profile_name, profileName);
    assert.equal(payload.filters.operation, 'patch');
    assert.ok(Array.isArray(payload.history.items));
    assert.ok(payload.history.items.some((item) => item.patch_id === patchPayload.patch_id));
    const { signature, ...unsignedPayload } = payload;
    assert.equal(
      verifyIncidentExportSignature(unsignedPayload, signature, { keys: app.incidentExportSigning.keys }),
      true
    );
  } finally {
    await app.close();
    await cleanupPolicySandboxRoot(rootDir);
  }
});

test('policy simulation returns decision summary for mixed-risk intents', async () => {
  const app = createTestApp();
  await app.ready();

  try {
    const res = await app.inject({
      method: 'POST',
      url: '/v0/policy/simulate',
      payload: {
        run_id: 'run_simulate_123456',
        policy_context: {
          org_policy: 'org_default_safe',
          workspace_policy: 'workspace_ops_cn',
          agent_policy: 'agent_ops_assistant'
        },
        action_intents: [
          {
            id: 'act_simulate_send_123456',
            run_id: 'run_simulate_123456',
            step_id: 'send_summary',
            capability: 'message.send',
            side_effect: 'mutation',
            idempotency_key: 'run_simulate_123456_send_summary',
            risk_hint: 'R2',
            parameters: {
              channel: 'ops-room',
              content: 'Simulated output'
            },
            target: { surface: 'office.chat' }
          },
          {
            id: 'act_simulate_cal_123456',
            run_id: 'run_simulate_123456',
            step_id: 'read_calendar',
            capability: 'calendar.read',
            side_effect: 'none',
            risk_hint: 'R1',
            parameters: {
              owner: 'usr_yingapple'
            },
            target: { surface: 'office.calendar' }
          }
        ]
      }
    });

    assert.equal(res.statusCode, 200);
    const payload = res.json();
    assert.equal(payload.summary.total, 2);
    assert.equal(payload.summary.allow, 1);
    assert.equal(payload.summary.escalate, 1);
    assert.equal(payload.summary.deny, 0);
    assert.equal(payload.summary.status, 'waiting_approval');
    assert.equal(payload.decisions.length, 2);
  } finally {
    await app.close();
  }
});

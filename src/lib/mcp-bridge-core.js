import { nowIso } from './time.js';

const TOOLSET = Object.freeze([
  Object.freeze({
    name: 'flockmesh_quickstart_one_person',
    description: 'Provision one-person runtime (agent + bindings + first run) with policy and audit controls.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
        owner_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
        template_id: { type: 'string', enum: ['weekly_ops_sync', 'incident_response'] },
        connector_ids: {
          type: 'array',
          uniqueItems: true,
          items: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
        },
        idempotency_key: { type: 'string', pattern: '^idem_[A-Za-z0-9_-]{8,128}$' }
      }
    }
  }),
  Object.freeze({
    name: 'flockmesh_list_pending_approvals',
    description: 'List pending approval actions across waiting runs, scoped by workspace.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
        limit: { type: 'integer', minimum: 1, maximum: 100 },
        offset: { type: 'integer', minimum: 0 }
      }
    }
  }),
  Object.freeze({
    name: 'flockmesh_resolve_approval',
    description: 'Approve or reject one pending action intent with optimistic revision guard.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['run_id', 'approved'],
      properties: {
        run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
        action_intent_id: { type: 'string', pattern: '^act_[A-Za-z0-9_-]{6,64}$' },
        approved: { type: 'boolean' },
        approved_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
        expected_revision: { type: 'integer', minimum: 1 },
        note: { type: 'string', maxLength: 1000 }
      }
    }
  }),
  Object.freeze({
    name: 'flockmesh_get_run_audit',
    description: 'Fetch immutable audit entries for one run.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['run_id'],
      properties: {
        run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
        limit: { type: 'integer', minimum: 1, maximum: 500 },
        offset: { type: 'integer', minimum: 0 }
      }
    }
  }),
  Object.freeze({
    name: 'flockmesh_invoke_mcp_tool',
    description: 'Invoke con_mcp_gateway under enterprise guardrails (allowlist, policy, rate-limit, audit).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['run_id', 'workspace_id', 'agent_id', 'connector_binding_id', 'tool_name'],
      properties: {
        run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
        workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
        agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' },
        connector_binding_id: { type: 'string', pattern: '^cnb_[A-Za-z0-9_-]{6,64}$' },
        tool_name: { type: 'string', minLength: 1, maxLength: 200 },
        tool_args: { type: 'object' },
        side_effect: { type: 'string', enum: ['none', 'mutation'] },
        risk_hint: { type: 'string', enum: ['R0', 'R1', 'R2', 'R3'] },
        initiated_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
        idempotency_key: { type: 'string', minLength: 8, maxLength: 128 }
      }
    }
  })
]);

const TOOL_NAMES = new Set(TOOLSET.map((item) => item.name));

function safeObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return value;
}

function asString(value) {
  return String(value || '').trim();
}

function asInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : fallback;
}

function buildQuery(urlPath, query = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${urlPath}?${qs}` : urlPath;
}

async function injectJson(app, {
  method = 'GET',
  url = '',
  payload = undefined,
  actorId = ''
} = {}) {
  const headers = {};
  if (actorId) {
    headers['x-flockmesh-actor-id'] = actorId;
  }

  const res = await app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
    ...(Object.keys(headers).length ? { headers } : {})
  });

  let body;
  try {
    body = res.payload ? JSON.parse(res.payload) : {};
  } catch {
    body = { raw: String(res.payload || '') };
  }

  if (res.statusCode >= 400) {
    const err = new Error(`HTTP ${res.statusCode} ${method} ${url}`);
    err.statusCode = res.statusCode;
    err.payload = body;
    throw err;
  }

  return body;
}

function summarizePendingApprovals(run) {
  const decisions = Array.isArray(run?.policy_decisions) ? run.policy_decisions : [];
  const approvalState = safeObject(run?.approval_state);

  return decisions
    .filter((item) => item?.decision === 'escalate')
    .map((item) => {
      const state = safeObject(approvalState[item.action_intent_id]);
      const required = Number(state.required_approvals ?? item.required_approvals ?? 0);
      const approvedBy = Array.isArray(state.approved_by) ? state.approved_by : [];
      return {
        action_intent_id: item.action_intent_id,
        decision_id: item.id,
        capability: item.capability,
        required_approvals: required,
        approved_by: approvedBy,
        approvals_left: Math.max(0, required - approvedBy.length),
        reason_codes: Array.isArray(item.reason_codes) ? item.reason_codes : []
      };
    });
}

function defaultIdempotencyKey(prefix = 'idem_bridge_quickstart') {
  const stamp = nowIso().replace(/[^0-9]/g, '').slice(0, 14);
  return `${prefix}_${stamp}`;
}

export const MCP_BRIDGE_TOOL_DEFINITIONS = TOOLSET;

export function createMcpBridgeCore({
  app,
  defaults = {}
} = {}) {
  if (!app) {
    throw new Error('createMcpBridgeCore requires app');
  }

  const defaultWorkspaceId = asString(defaults.workspaceId) || 'wsp_mindverse_cn';
  const defaultActorId = asString(defaults.actorId) || 'usr_yingapple';

  return {
    listTools() {
      return TOOLSET;
    },

    async callTool(name, rawArgs = {}) {
      if (!TOOL_NAMES.has(name)) {
        throw new Error(`Unknown MCP bridge tool: ${name}`);
      }
      const args = safeObject(rawArgs);

      if (name === 'flockmesh_quickstart_one_person') {
        const workspaceId = asString(args.workspace_id) || defaultWorkspaceId;
        const ownerId = asString(args.owner_id) || defaultActorId;
        const templateId = asString(args.template_id) || 'weekly_ops_sync';
        const idempotencyKey = asString(args.idempotency_key) || defaultIdempotencyKey();
        const requestedConnectorIds = Array.isArray(args.connector_ids)
          ? args.connector_ids.map((item) => asString(item)).filter(Boolean)
          : [];
        const connectorIds = requestedConnectorIds.length
          ? Array.from(new Set(requestedConnectorIds))
          : ['con_feishu_official', 'con_mcp_gateway'];

        const payload = await injectJson(app, {
          method: 'POST',
          url: '/v0/quickstart/one-person',
          actorId: ownerId,
          payload: {
            workspace_id: workspaceId,
            owner_id: ownerId,
            template_id: templateId,
            connector_ids: connectorIds,
            idempotency_key: idempotencyKey
          }
        });

        return {
          summary: {
            workspace_id: payload?.quickstart?.workspace_id || workspaceId,
            owner_id: payload?.quickstart?.owner_id || ownerId,
            template_id: payload?.template_id || templateId,
            reused: Boolean(payload?.reused),
            agent_id: payload?.created_agent?.id || '',
            run_id: payload?.run?.id || '',
            run_status: payload?.run?.status || ''
          },
          ...payload
        };
      }

      if (name === 'flockmesh_list_pending_approvals') {
        const workspaceId = asString(args.workspace_id) || defaultWorkspaceId;
        const limit = Math.min(100, Math.max(1, asInteger(args.limit, 20)));
        const offset = Math.max(0, asInteger(args.offset, 0));
        const page = await injectJson(app, {
          method: 'GET',
          url: buildQuery('/v0/runs', {
            status: 'waiting_approval',
            workspace_id: workspaceId,
            limit,
            offset
          })
        });

        const runs = Array.isArray(page.items) ? page.items : [];
        const items = runs
          .map((run) => ({
            run_id: run.id,
            workspace_id: run.workspace_id,
            agent_id: run.agent_id,
            status: run.status,
            revision: run.revision,
            approvals: summarizePendingApprovals(run)
          }))
          .filter((run) => run.approvals.length > 0);

        return {
          workspace_id: workspaceId,
          total: items.length,
          items
        };
      }

      if (name === 'flockmesh_resolve_approval') {
        const runId = asString(args.run_id);
        if (!runId) {
          throw new Error('run_id is required');
        }

        const approved = Boolean(args.approved);
        const approvedBy = asString(args.approved_by) || defaultActorId;
        const note = asString(args.note);
        let expectedRevision = asInteger(args.expected_revision, 0);
        let actionIntentId = asString(args.action_intent_id);

        const currentRun = await injectJson(app, {
          method: 'GET',
          url: `/v0/runs/${encodeURIComponent(runId)}`
        });
        if (!expectedRevision) {
          expectedRevision = Number(currentRun?.revision || 0);
        }

        if (!actionIntentId) {
          const firstPending = summarizePendingApprovals(currentRun)[0];
          if (!firstPending?.action_intent_id) {
            throw new Error('No pending approval action_intent_id found for run');
          }
          actionIntentId = firstPending.action_intent_id;
        }

        const payload = await injectJson(app, {
          method: 'POST',
          url: `/v0/runs/${encodeURIComponent(runId)}/approvals`,
          actorId: approvedBy,
          payload: {
            action_intent_id: actionIntentId,
            approved,
            approved_by: approvedBy,
            expected_revision: expectedRevision,
            ...(note ? { note } : {})
          }
        });

        return {
          run_id: runId,
          action_intent_id: actionIntentId,
          approved,
          status: payload?.status || '',
          run: payload?.run || null
        };
      }

      if (name === 'flockmesh_get_run_audit') {
        const runId = asString(args.run_id);
        if (!runId) {
          throw new Error('run_id is required');
        }
        const limit = Math.min(500, Math.max(1, asInteger(args.limit, 100)));
        const offset = Math.max(0, asInteger(args.offset, 0));
        return await injectJson(app, {
          method: 'GET',
          url: buildQuery(`/v0/runs/${encodeURIComponent(runId)}/audit`, {
            limit,
            offset
          })
        });
      }

      if (name === 'flockmesh_invoke_mcp_tool') {
        const runId = asString(args.run_id);
        const workspaceId = asString(args.workspace_id) || defaultWorkspaceId;
        const agentId = asString(args.agent_id);
        const connectorBindingId = asString(args.connector_binding_id);
        const toolName = asString(args.tool_name);
        const sideEffect = asString(args.side_effect) || 'none';
        const riskHint = asString(args.risk_hint) || 'R0';
        const initiatedBy = asString(args.initiated_by) || defaultActorId;
        const toolArgs = safeObject(args.tool_args);
        const idempotencyKey = asString(args.idempotency_key);

        if (!runId || !agentId || !connectorBindingId || !toolName) {
          throw new Error('run_id, agent_id, connector_binding_id, and tool_name are required');
        }

        const payload = await injectJson(app, {
          method: 'POST',
          url: '/v0/connectors/adapters/con_mcp_gateway/invoke',
          actorId: initiatedBy,
          payload: {
            run_id: runId,
            workspace_id: workspaceId,
            agent_id: agentId,
            connector_binding_id: connectorBindingId,
            capability: 'tool.invoke',
            side_effect: sideEffect === 'mutation' ? 'mutation' : 'none',
            risk_hint: ['R0', 'R1', 'R2', 'R3'].includes(riskHint) ? riskHint : 'R0',
            initiated_by: initiatedBy,
            ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {}),
            parameters: {
              tool_name: toolName,
              tool_args: toolArgs
            }
          }
        });

        return payload;
      }

      throw new Error(`Unhandled MCP bridge tool: ${name}`);
    }
  };
}

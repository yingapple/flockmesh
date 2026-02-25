import crypto from 'node:crypto';
import { nowIso } from './time.js';

function digest(payload) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex')
    .slice(0, 12);
}

export class AdapterCapabilityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AdapterCapabilityError';
    this.code = 'ADAPTER_CAPABILITY_UNSUPPORTED';
  }
}

async function maybeSimulateTimeout(parameters) {
  const ms = Number(parameters?.simulate_timeout_ms || 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function maybeSimulateError(parameters) {
  if (!parameters?.simulate_error) return;
  const detail = parameters.simulate_error === true
    ? 'simulated adapter failure'
    : String(parameters.simulate_error);
  throw new Error(detail);
}

function assertCapability(supportedCapabilities, requestedCapability, adapterId) {
  if (!supportedCapabilities.includes(requestedCapability)) {
    throw new AdapterCapabilityError(
      `Adapter ${adapterId} does not support capability ${requestedCapability}`
    );
  }
}

function buildMcpGatewayAdapter() {
  const id = 'con_mcp_gateway';
  const capabilities = ['tool.list', 'tool.read', 'tool.invoke'];

  return {
    id,
    capabilities,
    async simulate({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'simulate',
        connector_id: id,
        run_id: runId,
        protocol: 'mcp',
        preview: {
          tool_name: parameters?.tool_name || 'unknown_tool',
          tool_args: parameters?.tool_args || {},
          estimated_tokens: 400
        }
      };
    },
    async invoke({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'invoke',
        connector_id: id,
        run_id: runId,
        protocol: 'mcp',
        tx_id: `mcp_tx_${digest({ runId, capability, parameters, at: nowIso() })}`,
        output: {
          ok: true,
          capability,
          tool_name: parameters?.tool_name || 'unknown_tool',
          result_ref: `mcp://result/${digest(parameters || {})}`
        }
      };
    }
  };
}

function buildA2aGatewayAdapter() {
  const id = 'con_a2a_gateway';
  const capabilities = ['delegation.request', 'delegation.status', 'delegation.cancel'];

  return {
    id,
    capabilities,
    async simulate({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'simulate',
        connector_id: id,
        run_id: runId,
        protocol: 'a2a',
        preview: {
          delegation_target: parameters?.target_agent || 'agent_unknown',
          task_type: parameters?.task_type || 'generic_task',
          expected_state: 'queued'
        }
      };
    },
    async invoke({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'invoke',
        connector_id: id,
        run_id: runId,
        protocol: 'a2a',
        tx_id: `a2a_tx_${digest({ runId, capability, parameters, at: nowIso() })}`,
        output: {
          ok: true,
          delegation_id: `dlg_${digest(parameters || {})}`,
          state: capability === 'delegation.cancel' ? 'cancelled' : 'queued'
        }
      };
    }
  };
}

function buildOfficeCalendarAdapter() {
  const id = 'con_office_calendar';
  const capabilities = ['calendar.read', 'calendar.write'];

  return {
    id,
    capabilities,
    async simulate({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'simulate',
        connector_id: id,
        run_id: runId,
        protocol: 'http',
        preview: {
          calendar_owner: parameters?.owner || 'usr_unknown',
          mutation: capability === 'calendar.write'
        }
      };
    },
    async invoke({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'invoke',
        connector_id: id,
        run_id: runId,
        protocol: 'http',
        tx_id: `cal_tx_${digest({ runId, capability, parameters, at: nowIso() })}`,
        output: {
          ok: true,
          capability,
          item_ref: `calendar://event/${digest(parameters || {})}`
        }
      };
    }
  };
}

function buildOfficeChatAdapter() {
  const id = 'con_feishu_official';
  const capabilities = ['message.send', 'calendar.read', 'doc.read', 'doc.write'];

  return {
    id,
    capabilities,
    async simulate({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'simulate',
        connector_id: id,
        run_id: runId,
        protocol: 'http',
        preview: {
          channel: parameters?.channel || 'unknown_channel',
          capability
        }
      };
    },
    async invoke({ capability, parameters, runId }) {
      assertCapability(capabilities, capability, id);
      maybeSimulateError(parameters);
      await maybeSimulateTimeout(parameters);
      return {
        mode: 'invoke',
        connector_id: id,
        run_id: runId,
        protocol: 'http',
        tx_id: `chat_tx_${digest({ runId, capability, parameters, at: nowIso() })}`,
        output: {
          ok: true,
          capability,
          message_ref: `office://message/${digest(parameters || {})}`
        }
      };
    }
  };
}

export function buildConnectorAdapterRegistry() {
  const adapters = [
    buildMcpGatewayAdapter(),
    buildA2aGatewayAdapter(),
    buildOfficeCalendarAdapter(),
    buildOfficeChatAdapter()
  ];

  return Object.fromEntries(adapters.map((adapter) => [adapter.id, adapter]));
}

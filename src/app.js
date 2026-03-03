import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';

import { createStore, addRunAudit, addRunEvent } from './lib/store.js';
import { makeId } from './lib/ids.js';
import { nowIso } from './lib/time.js';
import { loadContractSchemas } from './lib/schemas.js';
import { DualLedger } from './lib/dual-ledger.js';
import { POLICY_LIBRARY, evaluatePolicy } from './lib/policy-engine.js';
import { compilePolicyProfileDsl, loadPolicyLibraryFromDir } from './lib/policy-dsl.js';
import {
  buildConnectorHealthSummary,
  detectScopeDrift,
  listConnectorManifestsPage,
  loadConnectorManifestsFromDir
} from './lib/connector-manifests.js';
import {
  AdapterCapabilityError,
  buildConnectorAdapterRegistry
} from './lib/connector-adapters.js';
import {
  evaluateMcpAllowlist,
  loadMcpAllowlistsFromDir
} from './lib/mcp-allowlist.js';
import {
  canActorManagePolicyProfile,
  loadPolicyAdminConfigFromDir,
  mergePolicyAdminConfigs
} from './lib/policy-admins.js';
import {
  createConnectorRateLimiter,
  resolveConnectorRateLimitPolicy
} from './lib/connector-rate-limiter.js';
import {
  buildAdapterRetryDecision,
  classifyAdapterFailureReason,
  computeAdapterRetryDelayMs,
  resolveAdapterRetryPolicy
} from './lib/adapter-retry.js';
import {
  buildIncidentExportPayloadHash,
  resolveIncidentExportSigningConfig,
  signIncidentExportPayload
} from './lib/incident-export.js';
import {
  buildAgentBlueprintLintReport,
  buildAgentBlueprintPreview,
  buildAgentBlueprintRemediationPlan,
  loadAgentKitsFromDir,
  listAgentKits,
  makeBlueprintAuthRef
} from './lib/agent-kits.js';
import { MCP_BRIDGE_TOOL_DEFINITIONS, createMcpBridgeCore } from './lib/mcp-bridge-core.js';
import {
  buildDefaultActionIntents,
  buildExecutionResult,
  buildRunRecord,
  runStatusFromDecisions
} from './lib/runtime.js';
import { RevisionConflictError, StateDB } from './lib/state-db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const defaultProjectRoot = path.resolve(__dirname, '..');
const POLICY_PATCH_HISTORY_DIRNAME = path.join('data', 'policy-patches');
const POLICY_PATCH_HISTORY_FILE = 'history.jsonl';
const POLICY_PATCH_ID_PATTERN = /^pph_[A-Za-z0-9_-]{6,64}$/;
const POLICY_PROFILE_NAME_PATTERN = /^[a-z][a-z0-9_]{2,80}$/;
const POLICY_CAPABILITY_PATTERN = /^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)$/;
const ACTOR_ID_PATTERN = /^(usr|svc|agt|sys)_[A-Za-z0-9_-]{4,128}$/;
const POLICY_DECISION_SET = new Set(['allow', 'deny', 'escalate']);
const POLICY_READ_ONLY_SUFFIXES = ['.read', '.list', '.status', '.search', '.get'];
const POLICY_HIGH_RISK_TOKENS = [
  'payment',
  'finance',
  'legal',
  'contract',
  'credential',
  'admin',
  'delete',
  'terminate'
];
const POLICY_DECISION_WEIGHT = {
  allow: 1,
  escalate: 2,
  deny: 3
};
const MCP_BRIDGE_STDIO_COMMAND = process.execPath || 'node';
const MCP_BRIDGE_CORE_TOOL_NAMES = MCP_BRIDGE_TOOL_DEFINITIONS.map((item) => item.name);
const MCP_BRIDGE_PROTOCOL_VERSION = '2025-11-25';
const MCP_PROTOCOL_HEADER = 'mcp-protocol-version';
const MCP_SESSION_HEADER = 'mcp-session-id';
const MCP_BRIDGE_SESSION_TTL_MS = 30 * 60 * 1000;
const MCP_BRIDGE_MAX_SESSIONS = 500;
const ACCESS_MODE_SET = new Set(['opc', 'organization']);
const ENV_SCOPE_SET = new Set(['opc', 'workspace', 'org', 'agent']);
const ENV_VISIBILITY_SET = new Set(['secret', 'masked', 'plain']);
const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{1,127}$/;
const ENV_VERIFY_PROBE_MODE_SET = new Set(['syntax', 'connectivity']);
const WORKSTATION_READINESS_STAGE_WEIGHT = Object.freeze({
  access: 25,
  environment: 30,
  bridge: 20,
  delivery: 15,
  session_audit: 10
});
const ROLE_NAME_SET = new Set(['org_admin', 'workspace_admin', 'operator', 'auditor']);
const ROLE_PERMISSION_LIBRARY = Object.freeze({
  org_admin: [
    'environment.manage',
    'role.manage',
    'run.execute',
    'approval.resolve',
    'audit.read',
    'session.read'
  ],
  workspace_admin: [
    'environment.manage',
    'role.manage',
    'run.execute',
    'approval.resolve',
    'audit.read',
    'session.read'
  ],
  operator: [
    'run.execute',
    'approval.resolve',
    'session.read'
  ],
  auditor: [
    'audit.read',
    'session.read'
  ]
});

function sha256(payload) {
  return `sha256:${crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex')}`;
}

function shortHash(payload) {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex').slice(0, 24);
}

class AdapterTimeoutError extends Error {
  constructor(message, { timeoutMs } = {}) {
    super(message);
    this.name = 'AdapterTimeoutError';
    this.code = 'ADAPTER_TIMEOUT';
    this.timeoutMs = timeoutMs;
  }
}

async function withTimeout(promiseFactory, timeoutMs) {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new AdapterTimeoutError('Adapter invocation timed out', { timeoutMs }));
    }, timeoutMs);

    Promise.resolve()
      .then(() => promiseFactory())
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

function asTrimmedString(value = '') {
  return String(value || '').trim();
}

function maskSecretUrl(rawUrl = '') {
  const value = asTrimmedString(rawUrl);
  if (!value) return '';

  try {
    const parsed = new URL(value);
    const segments = parsed.pathname.split('/').filter(Boolean);
    const tail = segments.length ? segments[segments.length - 1] : '';
    const maskedTail = tail
      ? `${tail.slice(0, 4)}...${tail.slice(-4)}`
      : '...';
    const prefix = segments.length > 1
      ? `/${segments.slice(0, -1).join('/')}`
      : '';
    return `${parsed.origin}${prefix}/${maskedTail}`;
  } catch {
    if (value.length <= 10) return `${value.slice(0, 2)}...`;
    return `${value.slice(0, 6)}...${value.slice(-4)}`;
  }
}

function resolveActiveFeishuWebhook(app) {
  const runtimeWebhook = asTrimmedString(app?.integrationRuntime?.feishu_webhook_url);
  if (runtimeWebhook) {
    return { webhook_url: runtimeWebhook, source: 'runtime' };
  }

  const envWebhook = asTrimmedString(process.env.FLOCKMESH_FEISHU_WEBHOOK_URL);
  if (envWebhook) {
    return { webhook_url: envWebhook, source: 'env' };
  }

  return { webhook_url: '', source: 'none' };
}

function resolveFeishuConnectionStatus(app) {
  const active = resolveActiveFeishuWebhook(app);
  return {
    integration: 'feishu',
    connected: Boolean(active.webhook_url),
    delivery_mode: active.webhook_url ? 'feishu_webhook' : 'stub',
    source: active.source,
    webhook_masked: active.webhook_url ? maskSecretUrl(active.webhook_url) : '',
    webhook_configurable: true
  };
}

function normalizeAccessMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (ACCESS_MODE_SET.has(normalized)) return normalized;
  return 'opc';
}

function normalizeEnvironmentScope(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (ENV_SCOPE_SET.has(normalized)) return normalized;
  return 'workspace';
}

function normalizeRoleName(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (!ROLE_NAME_SET.has(normalized)) {
    throw new Error(`Unsupported role: ${value}`);
  }
  return normalized;
}

function maskSensitiveValue(raw = '') {
  const value = asTrimmedString(raw);
  if (!value) return '';
  if (value.length <= 6) return '***';
  return `${value.slice(0, 2)}***${value.slice(-2)}`;
}

function sanitizeEnvironmentEntry(entry = {}, { includeValue = false } = {}) {
  const key = asTrimmedString(entry.key);
  const visibility = asTrimmedString(entry.visibility || 'secret') || 'secret';
  const value = asTrimmedString(entry.value || '');
  const masked = maskSensitiveValue(value);

  return {
    key,
    provider: asTrimmedString(entry.provider || 'generic') || 'generic',
    visibility,
    target: asTrimmedString(entry.target || ''),
    updated_at: asTrimmedString(entry.updated_at || nowIso()),
    value: includeValue && visibility === 'plain' ? value : '',
    masked_value: visibility === 'plain' ? value : masked
  };
}

function sanitizeEnvironmentSet(environmentSet = {}, { includePlainValues = false } = {}) {
  const entries = Array.isArray(environmentSet.entries) ? environmentSet.entries : [];
  return {
    ...environmentSet,
    entries: entries.map((entry) =>
      sanitizeEnvironmentEntry(entry, { includeValue: includePlainValues })
    )
  };
}

function normalizeEnvironmentEntries(rawEntries = []) {
  if (!Array.isArray(rawEntries)) {
    throw new Error('entries must be an array');
  }

  const normalized = [];
  const seen = new Set();

  for (let i = 0; i < rawEntries.length; i += 1) {
    const raw = rawEntries[i];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`entries[${i}] must be an object`);
    }

    const key = asTrimmedString(raw.key).toUpperCase();
    if (!ENV_KEY_PATTERN.test(key)) {
      throw new Error(`entries[${i}] invalid key`);
    }

    const provider = asTrimmedString(raw.provider || 'generic').toLowerCase() || 'generic';
    const visibility = asTrimmedString(raw.visibility || 'secret').toLowerCase() || 'secret';
    if (!ENV_VISIBILITY_SET.has(visibility)) {
      throw new Error(`entries[${i}] invalid visibility`);
    }

    const value = asTrimmedString(raw.value);
    if (!value) {
      throw new Error(`entries[${i}] value is required`);
    }

    const dedupeKey = `${provider}::${key}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    normalized.push({
      key,
      provider,
      visibility,
      value,
      target: asTrimmedString(raw.target || ''),
      updated_at: nowIso()
    });
  }

  return normalized;
}

function mergeEnvironmentEntries(existingEntries = [], patchEntries = []) {
  const result = [];
  const indexByKey = new Map();

  for (const existing of existingEntries) {
    const provider = asTrimmedString(existing.provider || 'generic').toLowerCase() || 'generic';
    const key = asTrimmedString(existing.key).toUpperCase();
    const dedupeKey = `${provider}::${key}`;
    const item = {
      key,
      provider,
      visibility: asTrimmedString(existing.visibility || 'secret').toLowerCase() || 'secret',
      value: asTrimmedString(existing.value),
      target: asTrimmedString(existing.target || ''),
      updated_at: asTrimmedString(existing.updated_at || nowIso())
    };
    indexByKey.set(dedupeKey, result.length);
    result.push(item);
  }

  for (const patch of patchEntries) {
    const dedupeKey = `${patch.provider}::${patch.key}`;
    if (indexByKey.has(dedupeKey)) {
      result[indexByKey.get(dedupeKey)] = { ...result[indexByKey.get(dedupeKey)], ...patch };
      continue;
    }
    indexByKey.set(dedupeKey, result.length);
    result.push(patch);
  }

  return result;
}

function parseHttpUrl(rawValue = '') {
  const value = asTrimmedString(rawValue);
  if (!value) return null;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function isSensitiveEnvironmentKey(rawKey = '') {
  const key = asTrimmedString(rawKey).toUpperCase();
  if (!key) return false;
  return (
    key.includes('SECRET')
    || key.includes('TOKEN')
    || key.includes('PASSWORD')
    || key.includes('PRIVATE')
    || key.includes('API_KEY')
    || key.includes('ACCESS_KEY')
  );
}

function finalizeEnvironmentVerification(provider = '', checks = [], recommendations = []) {
  const failCount = checks.filter((item) => item.status === 'fail').length;
  const warnCount = checks.filter((item) => item.status === 'warn').length;
  const status = failCount > 0 ? 'fail' : warnCount > 0 ? 'warn' : 'pass';

  return {
    provider,
    status,
    summary: {
      total_checks: checks.length,
      pass: checks.filter((item) => item.status === 'pass').length,
      warn: warnCount,
      fail: failCount
    },
    checks,
    recommendations: Array.from(new Set(recommendations.filter(Boolean)))
  };
}

function buildEnvironmentProviderVerification(provider = '', entries = []) {
  const normalizedProvider = asTrimmedString(provider || 'generic').toLowerCase() || 'generic';
  const list = Array.isArray(entries) ? entries : [];
  const checks = [];
  const recommendations = [];

  const addCheck = ({ code, status, message, key = '' }) => {
    checks.push({
      code: asTrimmedString(code),
      status: asTrimmedString(status) || 'warn',
      key: asTrimmedString(key),
      message: asTrimmedString(message)
    });
  };

  const findByKeys = (keys = []) => {
    const keySet = new Set(keys.map((item) => asTrimmedString(item).toUpperCase()).filter(Boolean));
    return list.find((entry) => {
      const key = asTrimmedString(entry.key).toUpperCase();
      const value = asTrimmedString(entry.value);
      return keySet.has(key) && Boolean(value);
    }) || null;
  };

  if (!list.length) {
    addCheck({
      code: `${normalizedProvider}.entries.missing`,
      status: 'fail',
      message: 'No entries found for this provider.'
    });
    recommendations.push(`Add required keys for provider ${normalizedProvider}.`);
    return finalizeEnvironmentVerification(normalizedProvider, checks, recommendations);
  }

  if (normalizedProvider === 'feishu') {
    const webhook = findByKeys(['FLOCKMESH_FEISHU_WEBHOOK_URL', 'FEISHU_WEBHOOK_URL']);
    if (!webhook) {
      addCheck({
        code: 'feishu.webhook.missing',
        status: 'fail',
        key: 'FLOCKMESH_FEISHU_WEBHOOK_URL',
        message: 'Feishu webhook URL is required.'
      });
      recommendations.push('Add Feishu webhook URL to enable approval/result delivery.');
    } else {
      const parsed = parseHttpUrl(webhook.value);
      if (!parsed) {
        addCheck({
          code: 'feishu.webhook.invalid_url',
          status: 'fail',
          key: webhook.key,
          message: 'Webhook must be a valid http/https URL.'
        });
      } else {
        addCheck({
          code: 'feishu.webhook.url_format',
          status: 'pass',
          key: webhook.key,
          message: 'Webhook URL format is valid.'
        });
        if (!/(feishu|lark)/i.test(parsed.hostname)) {
          addCheck({
            code: 'feishu.webhook.host_unusual',
            status: 'warn',
            key: webhook.key,
            message: 'Webhook host does not look like Feishu/Lark.'
          });
          recommendations.push('Confirm webhook host is the official Feishu/Lark endpoint.');
        }
      }
    }
  } else if (normalizedProvider === 'langfuse') {
    const host = findByKeys(['LANGFUSE_HOST']);
    const publicKey = findByKeys(['LANGFUSE_PUBLIC_KEY']);
    const secretKey = findByKeys(['LANGFUSE_SECRET_KEY']);

    if (!host) {
      addCheck({
        code: 'langfuse.host.missing',
        status: 'fail',
        key: 'LANGFUSE_HOST',
        message: 'LANGFUSE_HOST is required.'
      });
    } else {
      const parsed = parseHttpUrl(host.value);
      if (!parsed) {
        addCheck({
          code: 'langfuse.host.invalid_url',
          status: 'fail',
          key: host.key,
          message: 'LANGFUSE_HOST must be a valid URL.'
        });
      } else {
        addCheck({
          code: 'langfuse.host.url_format',
          status: parsed.protocol === 'https:' ? 'pass' : 'warn',
          key: host.key,
          message: parsed.protocol === 'https:'
            ? 'LANGFUSE_HOST uses HTTPS.'
            : 'LANGFUSE_HOST should use HTTPS in production.'
        });
      }
    }

    if (!publicKey) {
      addCheck({
        code: 'langfuse.public_key.missing',
        status: 'fail',
        key: 'LANGFUSE_PUBLIC_KEY',
        message: 'LANGFUSE_PUBLIC_KEY is required.'
      });
    } else {
      const isLikely = asTrimmedString(publicKey.value).startsWith('pk_');
      addCheck({
        code: 'langfuse.public_key.format',
        status: isLikely ? 'pass' : 'warn',
        key: publicKey.key,
        message: isLikely
          ? 'LANGFUSE_PUBLIC_KEY format looks valid.'
          : 'LANGFUSE_PUBLIC_KEY usually starts with pk_.'
      });
    }

    if (!secretKey) {
      addCheck({
        code: 'langfuse.secret_key.missing',
        status: 'fail',
        key: 'LANGFUSE_SECRET_KEY',
        message: 'LANGFUSE_SECRET_KEY is required.'
      });
    } else {
      const isLikely = asTrimmedString(secretKey.value).startsWith('sk_');
      addCheck({
        code: 'langfuse.secret_key.format',
        status: isLikely ? 'pass' : 'warn',
        key: secretKey.key,
        message: isLikely
          ? 'LANGFUSE_SECRET_KEY format looks valid.'
          : 'LANGFUSE_SECRET_KEY usually starts with sk_.'
      });
    }
  } else if (normalizedProvider === 'claude_code') {
    const apiKey = findByKeys(['ANTHROPIC_API_KEY']);
    const baseUrl = findByKeys(['ANTHROPIC_BASE_URL']);

    if (!apiKey) {
      addCheck({
        code: 'claude_code.api_key.missing',
        status: 'fail',
        key: 'ANTHROPIC_API_KEY',
        message: 'ANTHROPIC_API_KEY is required.'
      });
      recommendations.push('Configure ANTHROPIC_API_KEY for Claude Code bridge.');
    } else {
      const likely = asTrimmedString(apiKey.value).startsWith('sk-ant-');
      addCheck({
        code: 'claude_code.api_key.format',
        status: likely ? 'pass' : 'warn',
        key: apiKey.key,
        message: likely
          ? 'ANTHROPIC_API_KEY format looks valid.'
          : 'ANTHROPIC_API_KEY usually starts with sk-ant-.'
      });
    }

    if (baseUrl) {
      addCheck({
        code: 'claude_code.base_url.format',
        status: parseHttpUrl(baseUrl.value) ? 'pass' : 'warn',
        key: baseUrl.key,
        message: parseHttpUrl(baseUrl.value)
          ? 'ANTHROPIC_BASE_URL format is valid.'
          : 'ANTHROPIC_BASE_URL should be a valid URL.'
      });
    } else {
      addCheck({
        code: 'claude_code.base_url.default',
        status: 'pass',
        key: 'ANTHROPIC_BASE_URL',
        message: 'ANTHROPIC_BASE_URL is optional; default endpoint can be used.'
      });
    }
  } else if (normalizedProvider === 'codex') {
    const apiKey = findByKeys(['OPENAI_API_KEY']);
    const baseUrl = findByKeys(['OPENAI_BASE_URL']);

    if (!apiKey) {
      addCheck({
        code: 'codex.api_key.missing',
        status: 'fail',
        key: 'OPENAI_API_KEY',
        message: 'OPENAI_API_KEY is required.'
      });
      recommendations.push('Configure OPENAI_API_KEY for Codex/OpenAI runtime.');
    } else {
      const likely = asTrimmedString(apiKey.value).startsWith('sk-');
      addCheck({
        code: 'codex.api_key.format',
        status: likely ? 'pass' : 'warn',
        key: apiKey.key,
        message: likely
          ? 'OPENAI_API_KEY format looks valid.'
          : 'OPENAI_API_KEY usually starts with sk-.'
      });
    }

    if (baseUrl) {
      addCheck({
        code: 'codex.base_url.format',
        status: parseHttpUrl(baseUrl.value) ? 'pass' : 'warn',
        key: baseUrl.key,
        message: parseHttpUrl(baseUrl.value)
          ? 'OPENAI_BASE_URL format is valid.'
          : 'OPENAI_BASE_URL should be a valid URL.'
      });
    } else {
      addCheck({
        code: 'codex.base_url.default',
        status: 'pass',
        key: 'OPENAI_BASE_URL',
        message: 'OPENAI_BASE_URL is optional; default endpoint can be used.'
      });
    }
  } else if (normalizedProvider === 'aws') {
    const accessKeyId = findByKeys(['AWS_ACCESS_KEY_ID']);
    const secretAccessKey = findByKeys(['AWS_SECRET_ACCESS_KEY']);
    const region = findByKeys(['AWS_REGION']);

    if (!accessKeyId) {
      addCheck({
        code: 'aws.access_key_id.missing',
        status: 'fail',
        key: 'AWS_ACCESS_KEY_ID',
        message: 'AWS_ACCESS_KEY_ID is required.'
      });
    } else {
      const likely = /^(AKIA|ASIA)[A-Z0-9]{12,20}$/.test(asTrimmedString(accessKeyId.value));
      addCheck({
        code: 'aws.access_key_id.format',
        status: likely ? 'pass' : 'warn',
        key: accessKeyId.key,
        message: likely
          ? 'AWS_ACCESS_KEY_ID format looks valid.'
          : 'AWS_ACCESS_KEY_ID format looks unusual.'
      });
    }

    if (!secretAccessKey) {
      addCheck({
        code: 'aws.secret_access_key.missing',
        status: 'fail',
        key: 'AWS_SECRET_ACCESS_KEY',
        message: 'AWS_SECRET_ACCESS_KEY is required.'
      });
    } else {
      const value = asTrimmedString(secretAccessKey.value);
      addCheck({
        code: 'aws.secret_access_key.length',
        status: value.length >= 20 ? 'pass' : 'fail',
        key: secretAccessKey.key,
        message: value.length >= 20
          ? 'AWS_SECRET_ACCESS_KEY length looks valid.'
          : 'AWS_SECRET_ACCESS_KEY is too short.'
      });
    }

    if (!region) {
      addCheck({
        code: 'aws.region.missing',
        status: 'warn',
        key: 'AWS_REGION',
        message: 'AWS_REGION is recommended for stable behavior.'
      });
      recommendations.push('Set AWS_REGION to avoid cross-region defaults.');
    } else {
      const likely = /^[a-z]{2}-[a-z]+-\d$/i.test(asTrimmedString(region.value));
      addCheck({
        code: 'aws.region.format',
        status: likely ? 'pass' : 'warn',
        key: region.key,
        message: likely
          ? 'AWS_REGION format looks valid.'
          : 'AWS_REGION format looks unusual (example: us-east-1).'
      });
    }
  } else {
    for (const entry of list) {
      const value = asTrimmedString(entry.value);
      addCheck({
        code: `${normalizedProvider}.entry.${asTrimmedString(entry.key).toLowerCase() || 'unknown'}`,
        status: value ? 'pass' : 'fail',
        key: asTrimmedString(entry.key),
        message: value ? 'Entry value is present.' : 'Entry value is empty.'
      });
    }
  }

  for (const entry of list) {
    const key = asTrimmedString(entry.key).toUpperCase();
    const visibility = asTrimmedString(entry.visibility).toLowerCase();
    if (visibility === 'plain' && isSensitiveEnvironmentKey(key)) {
      addCheck({
        code: `${normalizedProvider}.visibility.${key.toLowerCase()}`,
        status: 'warn',
        key,
        message: `${key} is marked plain; consider secret/masked visibility.`
      });
    }
  }

  return finalizeEnvironmentVerification(normalizedProvider, checks, recommendations);
}

function groupEnvironmentEntriesByProvider(entries = []) {
  const groups = new Map();
  for (const entry of entries) {
    const provider = asTrimmedString(entry.provider || 'generic').toLowerCase() || 'generic';
    if (!groups.has(provider)) groups.set(provider, []);
    groups.get(provider).push(entry);
  }
  if (!groups.size) {
    groups.set('generic', []);
  }
  return groups;
}

function normalizeVerifyProbeMode(value = '') {
  const normalized = asTrimmedString(value).toLowerCase();
  if (ENV_VERIFY_PROBE_MODE_SET.has(normalized)) return normalized;
  return 'syntax';
}

function findEnvironmentEntryValue(entries = [], keys = []) {
  const keySet = new Set(keys.map((item) => asTrimmedString(item).toUpperCase()).filter(Boolean));
  for (const entry of entries) {
    const key = asTrimmedString(entry.key).toUpperCase();
    const value = asTrimmedString(entry.value);
    if (!keySet.has(key) || !value) continue;
    return value;
  }
  return '';
}

async function probeHttpEndpoint({
  url = '',
  method = 'GET',
  headers = {},
  body = '',
  timeoutMs = 4000
}) {
  const endpoint = asTrimmedString(url);
  if (!endpoint) {
    return {
      reachable: false,
      http_status: null,
      error_code: 'endpoint.missing',
      error_message: 'endpoint is required'
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(endpoint, {
      method,
      headers,
      body: body || undefined,
      signal: controller.signal,
      redirect: 'follow'
    });
    return {
      reachable: true,
      http_status: response.status,
      ok: response.ok,
      error_code: '',
      error_message: ''
    };
  } catch (err) {
    const isTimeout = err?.name === 'AbortError';
    return {
      reachable: false,
      http_status: null,
      ok: false,
      error_code: isTimeout ? 'network.timeout' : 'network.error',
      error_message: String(err?.message || err)
    };
  } finally {
    clearTimeout(timer);
  }
}

function finalizeProviderConnectivityProbe({
  provider = '',
  endpoint = '',
  reachable = false,
  httpStatus = null,
  status = 'warn',
  message = '',
  errorCode = '',
  errorMessage = ''
}) {
  return {
    provider,
    endpoint_masked: endpoint ? maskSecretUrl(endpoint) : '',
    reachable,
    http_status: Number.isFinite(Number(httpStatus)) ? Number(httpStatus) : null,
    status,
    message: asTrimmedString(message),
    error_code: asTrimmedString(errorCode),
    error_message: asTrimmedString(errorMessage)
  };
}

async function probeProviderConnectivity({
  provider = '',
  entries = [],
  timeoutMs = 4000
}) {
  const normalizedProvider = asTrimmedString(provider || 'generic').toLowerCase() || 'generic';
  const providerEntries = Array.isArray(entries) ? entries : [];

  if (normalizedProvider === 'feishu') {
    const webhook = findEnvironmentEntryValue(providerEntries, [
      'FLOCKMESH_FEISHU_WEBHOOK_URL',
      'FEISHU_WEBHOOK_URL'
    ]);
    const parsed = parseHttpUrl(webhook);
    if (!parsed) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: webhook,
        status: 'fail',
        message: 'Feishu webhook URL missing or invalid.',
        errorCode: 'feishu.webhook.invalid'
      });
    }

    const probe = await probeHttpEndpoint({
      url: parsed.toString(),
      method: 'GET',
      timeoutMs
    });
    if (!probe.reachable) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: parsed.toString(),
        reachable: false,
        httpStatus: probe.http_status,
        status: 'fail',
        message: 'Feishu endpoint is unreachable from runtime.',
        errorCode: probe.error_code,
        errorMessage: probe.error_message
      });
    }

    return finalizeProviderConnectivityProbe({
      provider: normalizedProvider,
      endpoint: parsed.toString(),
      reachable: true,
      httpStatus: probe.http_status,
      status: Number(probe.http_status) >= 500 ? 'warn' : 'pass',
      message: Number(probe.http_status) >= 500
        ? 'Feishu endpoint reachable but returned 5xx.'
        : 'Feishu endpoint reachable.'
    });
  }

  if (normalizedProvider === 'langfuse') {
    const host = findEnvironmentEntryValue(providerEntries, ['LANGFUSE_HOST']);
    const parsed = parseHttpUrl(host);
    if (!parsed) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: host,
        status: 'fail',
        message: 'LANGFUSE_HOST missing or invalid.',
        errorCode: 'langfuse.host.invalid'
      });
    }

    const healthEndpoint = new URL('/api/public/health', parsed).toString();
    const probe = await probeHttpEndpoint({
      url: healthEndpoint,
      method: 'GET',
      timeoutMs
    });
    if (!probe.reachable) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: healthEndpoint,
        reachable: false,
        httpStatus: probe.http_status,
        status: 'fail',
        message: 'Langfuse host is unreachable from runtime.',
        errorCode: probe.error_code,
        errorMessage: probe.error_message
      });
    }

    return finalizeProviderConnectivityProbe({
      provider: normalizedProvider,
      endpoint: healthEndpoint,
      reachable: true,
      httpStatus: probe.http_status,
      status: Number(probe.http_status) >= 500 ? 'warn' : 'pass',
      message: Number(probe.http_status) >= 500
        ? 'Langfuse endpoint reachable but returned 5xx.'
        : 'Langfuse endpoint reachable.'
    });
  }

  if (normalizedProvider === 'claude_code') {
    const apiKey = findEnvironmentEntryValue(providerEntries, ['ANTHROPIC_API_KEY']);
    const baseUrlRaw = findEnvironmentEntryValue(providerEntries, ['ANTHROPIC_BASE_URL']) || 'https://api.anthropic.com';
    const baseUrl = parseHttpUrl(baseUrlRaw);
    if (!apiKey || !baseUrl) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: baseUrlRaw,
        status: 'fail',
        message: 'ANTHROPIC_API_KEY or ANTHROPIC_BASE_URL is invalid.',
        errorCode: 'claude_code.credentials.invalid'
      });
    }

    const modelsEndpoint = new URL('/v1/models', baseUrl).toString();
    const probe = await probeHttpEndpoint({
      url: modelsEndpoint,
      method: 'GET',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      timeoutMs
    });
    if (!probe.reachable) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: modelsEndpoint,
        reachable: false,
        httpStatus: probe.http_status,
        status: 'fail',
        message: 'Claude API endpoint is unreachable.',
        errorCode: probe.error_code,
        errorMessage: probe.error_message
      });
    }

    const authFailure = [401, 403].includes(Number(probe.http_status));
    return finalizeProviderConnectivityProbe({
      provider: normalizedProvider,
      endpoint: modelsEndpoint,
      reachable: true,
      httpStatus: probe.http_status,
      status: authFailure ? 'fail' : (Number(probe.http_status) >= 500 ? 'warn' : 'pass'),
      message: authFailure
        ? 'Claude credentials rejected by remote endpoint.'
        : (Number(probe.http_status) >= 500
          ? 'Claude endpoint reachable but returned 5xx.'
          : 'Claude endpoint reachable.')
    });
  }

  if (normalizedProvider === 'codex') {
    const apiKey = findEnvironmentEntryValue(providerEntries, ['OPENAI_API_KEY']);
    const baseUrlRaw = findEnvironmentEntryValue(providerEntries, ['OPENAI_BASE_URL']) || 'https://api.openai.com/v1';
    const baseUrl = parseHttpUrl(baseUrlRaw);
    if (!apiKey || !baseUrl) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: baseUrlRaw,
        status: 'fail',
        message: 'OPENAI_API_KEY or OPENAI_BASE_URL is invalid.',
        errorCode: 'codex.credentials.invalid'
      });
    }

    const modelsEndpoint = new URL('/models', baseUrl).toString();
    const probe = await probeHttpEndpoint({
      url: modelsEndpoint,
      method: 'GET',
      headers: {
        authorization: `Bearer ${apiKey}`
      },
      timeoutMs
    });
    if (!probe.reachable) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint: modelsEndpoint,
        reachable: false,
        httpStatus: probe.http_status,
        status: 'fail',
        message: 'OpenAI endpoint is unreachable.',
        errorCode: probe.error_code,
        errorMessage: probe.error_message
      });
    }

    const authFailure = [401, 403].includes(Number(probe.http_status));
    return finalizeProviderConnectivityProbe({
      provider: normalizedProvider,
      endpoint: modelsEndpoint,
      reachable: true,
      httpStatus: probe.http_status,
      status: authFailure ? 'fail' : (Number(probe.http_status) >= 500 ? 'warn' : 'pass'),
      message: authFailure
        ? 'OpenAI credentials rejected by remote endpoint.'
        : (Number(probe.http_status) >= 500
          ? 'OpenAI endpoint reachable but returned 5xx.'
          : 'OpenAI endpoint reachable.')
    });
  }

  if (normalizedProvider === 'aws') {
    const region = findEnvironmentEntryValue(providerEntries, ['AWS_REGION']) || 'us-east-1';
    const endpoint = `https://sts.${region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15`;
    const probe = await probeHttpEndpoint({
      url: endpoint,
      method: 'GET',
      timeoutMs
    });
    if (!probe.reachable) {
      return finalizeProviderConnectivityProbe({
        provider: normalizedProvider,
        endpoint,
        reachable: false,
        httpStatus: probe.http_status,
        status: 'fail',
        message: 'AWS STS endpoint is unreachable.',
        errorCode: probe.error_code,
        errorMessage: probe.error_message
      });
    }

    return finalizeProviderConnectivityProbe({
      provider: normalizedProvider,
      endpoint,
      reachable: true,
      httpStatus: probe.http_status,
      status: Number(probe.http_status) >= 500 ? 'warn' : 'pass',
      message: Number(probe.http_status) >= 500
        ? 'AWS STS endpoint reachable but returned 5xx.'
        : 'AWS STS endpoint reachable.'
    });
  }

  return finalizeProviderConnectivityProbe({
    provider: normalizedProvider,
    status: 'skip',
    message: 'Connectivity probe is not defined for this provider.'
  });
}

async function probeEnvironmentSetConnectivity(environmentSet = {}, { timeoutMs = 4000 } = {}) {
  const entries = Array.isArray(environmentSet.entries) ? environmentSet.entries : [];
  const groups = groupEnvironmentEntriesByProvider(entries);
  const providers = [];

  for (const [provider, providerEntries] of groups.entries()) {
    // Sequential probing keeps outbound verification requests predictable.
    const result = await probeProviderConnectivity({
      provider,
      entries: providerEntries,
      timeoutMs
    });
    providers.push(result);
  }

  const summary = providers.reduce((acc, item) => {
    acc.total += 1;
    if (item.status === 'pass') acc.pass += 1;
    if (item.status === 'warn') acc.warn += 1;
    if (item.status === 'fail') acc.fail += 1;
    if (item.status === 'skip') acc.skip += 1;
    return acc;
  }, { total: 0, pass: 0, warn: 0, fail: 0, skip: 0 });

  const status = summary.fail > 0 ? 'fail' : summary.warn > 0 ? 'warn' : 'pass';
  return {
    status,
    summary,
    providers
  };
}

function verifyEnvironmentSet(environmentSet = {}) {
  const entries = Array.isArray(environmentSet.entries) ? environmentSet.entries : [];
  const groups = groupEnvironmentEntriesByProvider(entries);

  const providers = Array.from(groups.entries())
    .map(([provider, list]) => buildEnvironmentProviderVerification(provider, list))
    .sort((a, b) => a.provider.localeCompare(b.provider));

  const providerSummary = providers.reduce((acc, item) => {
    acc.total += 1;
    acc[item.status] += 1;
    return acc;
  }, { total: 0, pass: 0, warn: 0, fail: 0 });

  const totalChecks = providers.reduce((acc, item) => acc + item.summary.total_checks, 0);
  const overallStatus = providerSummary.fail > 0 ? 'fail' : providerSummary.warn > 0 ? 'warn' : 'pass';
  const recommendations = Array.from(
    new Set(
      providers.flatMap((item) => Array.isArray(item.recommendations) ? item.recommendations : [])
    )
  );

  const findProviderStatus = (providerName) => {
    const item = providers.find((provider) => provider.provider === providerName);
    if (!item) return 'missing';
    return item.status;
  };

  return {
    set_id: asTrimmedString(environmentSet.id),
    workspace_id: asTrimmedString(environmentSet.workspace_id),
    mode: normalizeAccessMode(environmentSet.mode),
    scope: normalizeEnvironmentScope(environmentSet.scope),
    status: overallStatus,
    summary: {
      total_providers: providerSummary.total,
      total_checks: totalChecks,
      pass: providerSummary.pass,
      warn: providerSummary.warn,
      fail: providerSummary.fail
    },
    runtime_readiness: {
      feishu_delivery: ['pass', 'warn'].includes(findProviderStatus('feishu')),
      langfuse_observability: ['pass', 'warn'].includes(findProviderStatus('langfuse')),
      claude_code_bridge: ['pass', 'warn'].includes(findProviderStatus('claude_code')),
      codex_bridge: ['pass', 'warn'].includes(findProviderStatus('codex'))
    },
    providers,
    recommendations
  };
}

function parseIsoTimeMs(value = '') {
  const ms = Date.parse(String(value || ''));
  return Number.isFinite(ms) ? ms : 0;
}

function normalizeReadinessStatus(value = '') {
  const normalized = asTrimmedString(value).toLowerCase();
  if (normalized === 'pass') return 'pass';
  if (normalized === 'fail') return 'fail';
  return 'warn';
}

function readinessScoreFactor(status = 'warn') {
  const normalized = normalizeReadinessStatus(status);
  if (normalized === 'pass') return 1;
  if (normalized === 'fail') return 0;
  return 0.6;
}

function buildWorkstationReadinessScore(stages = []) {
  const normalizedStages = Array.isArray(stages) ? stages : [];
  let maxPoints = 0;
  let points = 0;
  let pass = 0;
  let warn = 0;
  let fail = 0;
  let requiredFail = 0;

  for (const stage of normalizedStages) {
    const weight = Math.max(Number(stage?.weight || 0), 0);
    const status = normalizeReadinessStatus(stage?.status || 'warn');
    maxPoints += weight;
    points += weight * readinessScoreFactor(status);
    if (status === 'pass') pass += 1;
    if (status === 'warn') warn += 1;
    if (status === 'fail') {
      fail += 1;
      if (stage?.required !== false) {
        requiredFail += 1;
      }
    }
  }

  const roundedPoints = Number(points.toFixed(1));
  const ratio = maxPoints > 0 ? roundedPoints / maxPoints : 0;
  const percent = Number((ratio * 100).toFixed(1));
  const grade = percent >= 85
    ? 'ready'
    : percent >= 70
      ? 'near_ready'
      : percent >= 40
        ? 'bootstrapping'
        : 'blocked';
  const status = requiredFail > 0
    ? 'fail'
    : percent >= 85
      ? 'pass'
      : 'warn';

  return {
    status,
    grade,
    points: roundedPoints,
    max_points: maxPoints,
    percent,
    summary: {
      pass,
      warn,
      fail,
      required_fail: requiredFail
    }
  };
}

function buildWorkstationReadinessNextActions({
  accessStage = null,
  environmentStage = null,
  bridgeStage = null,
  deliveryStage = null,
  sessionStage = null,
  selectedEnvironmentSet = null
} = {}) {
  const actions = [];
  const pushAction = (action) => {
    if (!action || typeof action !== 'object') return;
    const actionId = asTrimmedString(action.action_id);
    if (!actionId) return;
    if (actions.some((item) => item.action_id === actionId)) return;
    actions.push({
      action_id: actionId,
      title: asTrimmedString(action.title),
      description: asTrimmedString(action.description),
      cta: asTrimmedString(action.cta)
    });
  };

  if (normalizeReadinessStatus(accessStage?.status) === 'fail') {
    pushAction({
      action_id: 'assign_workspace_role',
      title: 'Assign workspace role',
      description: 'Current actor is not assigned in this workspace.',
      cta: 'POST /v0/access/role-bindings'
    });
  } else if (accessStage?.details?.bootstrap_available) {
    pushAction({
      action_id: 'bootstrap_workspace_roles',
      title: 'Bootstrap workspace permissions',
      description: 'No role bindings exist yet. Grant workspace_admin/operator/auditor for first admin.',
      cta: 'POST /v0/access/role-bindings'
    });
  }

  if (normalizeReadinessStatus(environmentStage?.status) === 'fail') {
    pushAction({
      action_id: 'create_environment_set',
      title: 'Create active environment set',
      description: 'Add provider keys (Feishu, Claude/Codex, Langfuse, cloud) and mark set active.',
      cta: 'POST /v0/environments/sets'
    });
  } else if (normalizeReadinessStatus(environmentStage?.status) === 'warn') {
    pushAction({
      action_id: 'verify_environment_set',
      title: 'Fix environment warnings',
      description: 'Run verification and resolve key format/provider warnings before first production run.',
      cta: 'POST /v0/environments/sets/{set_id}/verify'
    });
  }

  if (normalizeReadinessStatus(bridgeStage?.status) !== 'pass') {
    if (!bridgeStage?.details?.workspace_path_set) {
      pushAction({
        action_id: 'set_workspace_folder',
        title: 'Set workspace folder',
        description: 'Workspace folder is required for IDE agent bridge over local project context.',
        cta: 'GET /v0/integrations/agent-ide-profile?workspace_path=...'
      });
    }
    if (!bridgeStage?.details?.bridge_credentials_ready) {
      pushAction({
        action_id: 'add_bridge_credentials',
        title: 'Add Claude/Codex credentials',
        description: 'Configure ANTHROPIC_API_KEY or OPENAI_API_KEY in active environment set.',
        cta: 'POST /v0/environments/sets/{set_id}/entries'
      });
    }
  }

  if (normalizeReadinessStatus(deliveryStage?.status) !== 'pass') {
    if (deliveryStage?.details?.environment_has_feishu_webhook && selectedEnvironmentSet?.id) {
      pushAction({
        action_id: 'apply_env_to_runtime',
        title: 'Apply active env set to runtime',
        description: 'Feishu webhook exists in environment set but is not applied to runtime yet.',
        cta: `POST /v0/environments/sets/${selectedEnvironmentSet.id}/apply-runtime`
      });
    } else {
      pushAction({
        action_id: 'configure_feishu_webhook',
        title: 'Configure Feishu delivery',
        description: 'Set a Feishu webhook for approval/result notifications.',
        cta: 'POST /v0/integrations/feishu/webhook'
      });
    }
  }

  const sessionTotal = Number(sessionStage?.details?.sessions?.total || 0);
  const pendingApprovals = Number(sessionStage?.details?.sessions?.pending_approvals || 0);
  if (sessionTotal < 1) {
    pushAction({
      action_id: 'start_first_run',
      title: 'Start first run',
      description: 'Create your first session to unlock timeline and audit review.',
      cta: 'POST /v0/quickstart/one-person'
    });
  } else if (pendingApprovals > 0) {
    pushAction({
      action_id: 'resolve_pending_approvals',
      title: 'Resolve pending approvals',
      description: `There are ${pendingApprovals} pending approval actions in recent sessions.`,
      cta: 'POST /v0/runs/{run_id}/approvals'
    });
  }

  if (!actions.length) {
    pushAction({
      action_id: 'inspect_session_evidence',
      title: 'Inspect session evidence',
      description: 'Review events and immutable audit to validate your workflow baseline.',
      cta: 'GET /v0/sessions/{session_id}?include_evidence=true'
    });
  }

  return actions.slice(0, 8);
}

async function buildWorkstationReadinessSnapshot({
  app,
  request,
  workspaceId = '',
  actorId = '',
  modeFilter = '',
  workspacePath = '',
  includeProbe = false,
  probeTimeoutMs = 2200,
  rootDir = ''
}) {
  const normalizedWorkspaceId = asTrimmedString(workspaceId);
  const normalizedActorId = asTrimmedString(actorId);
  const normalizedMode = asTrimmedString(modeFilter);
  const normalizedWorkspacePath = asTrimmedString(workspacePath);
  const normalizedRootDir = path.resolve(String(rootDir || defaultProjectRoot));
  const generatedAt = nowIso();

  const workspaceRoleBindings = listWorkspaceRoleBindings(app, normalizedWorkspaceId);
  const bootstrapAvailable = workspaceRoleBindings.length < 1;
  const actorAssigned = bootstrapAvailable || actorHasAnyWorkspaceRole({
    app,
    workspaceId: normalizedWorkspaceId,
    actorId: normalizedActorId
  });
  const resolvedPermissions = resolveActorPermissions({
    app,
    workspaceId: normalizedWorkspaceId,
    actorId: normalizedActorId
  });
  const permissionChecks = {
    environment_manage: bootstrapAvailable || resolvedPermissions.permissions.includes('environment.manage'),
    role_manage: bootstrapAvailable || resolvedPermissions.permissions.includes('role.manage'),
    run_execute: bootstrapAvailable || resolvedPermissions.permissions.includes('run.execute'),
    session_read: bootstrapAvailable || resolvedPermissions.permissions.includes('session.read'),
    audit_read: bootstrapAvailable || resolvedPermissions.permissions.includes('audit.read'),
    approval_resolve: bootstrapAvailable || resolvedPermissions.permissions.includes('approval.resolve')
  };

  const accessStageStatus = !actorAssigned
    ? 'fail'
    : bootstrapAvailable
      ? 'warn'
      : permissionChecks.run_execute && permissionChecks.session_read
        ? 'pass'
        : 'warn';
  const accessStage = {
    id: 'access',
    title: 'Access Control',
    required: true,
    weight: WORKSTATION_READINESS_STAGE_WEIGHT.access,
    status: accessStageStatus,
    summary: !actorAssigned
      ? 'Actor is not assigned in workspace role bindings.'
      : bootstrapAvailable
        ? 'Workspace has no role bindings yet. First admin bootstrap is available.'
        : permissionChecks.run_execute && permissionChecks.session_read
          ? 'Actor has baseline execute/read permissions.'
          : 'Actor is assigned but missing part of execute/read permissions.',
    details: {
      bootstrap_available: bootstrapAvailable,
      actor_assigned: actorAssigned,
      roles: resolvedPermissions.roles,
      permissions: resolvedPermissions.permissions,
      permission_checks: permissionChecks,
      workspace_role_binding_count: workspaceRoleBindings.length
    }
  };

  const activeEnvironmentModePage = normalizedMode
    ? app.stateDb.listActiveEnvironmentSets({
      workspaceId: normalizedWorkspaceId,
      mode: normalizedMode,
      limit: 120,
      offset: 0
    })
    : null;
  const activeEnvironmentPage = app.stateDb.listActiveEnvironmentSets({
    workspaceId: normalizedWorkspaceId,
    limit: 120,
    offset: 0
  });
  const selectedEnvironmentSet = activeEnvironmentModePage?.items?.[0]
    || activeEnvironmentPage.items?.[0]
    || null;
  const environmentReport = selectedEnvironmentSet
    ? verifyEnvironmentSet(selectedEnvironmentSet)
    : null;
  const environmentConnectivity = (includeProbe && selectedEnvironmentSet)
    ? await probeEnvironmentSetConnectivity(selectedEnvironmentSet, { timeoutMs: probeTimeoutMs })
    : null;
  const environmentStageStatus = selectedEnvironmentSet
    ? normalizeReadinessStatus(environmentReport?.status || 'warn')
    : 'fail';
  const environmentStage = {
    id: 'environment',
    title: 'Environment Center',
    required: true,
    weight: WORKSTATION_READINESS_STAGE_WEIGHT.environment,
    status: environmentStageStatus,
    summary: !selectedEnvironmentSet
      ? 'No active environment set found for this workspace/mode.'
      : `Active set ${selectedEnvironmentSet.name} verification is ${String(environmentReport?.status || 'warn').toUpperCase()}.`,
    details: {
      mode_filter: normalizedMode || 'all',
      selected_set: selectedEnvironmentSet ? sanitizeEnvironmentSet(selectedEnvironmentSet) : null,
      active_sets_total: Number(activeEnvironmentPage.total || 0),
      active_sets_mode_total: normalizedMode
        ? Number(activeEnvironmentModePage?.total || 0)
        : Number(activeEnvironmentPage.total || 0),
      report: environmentReport,
      ...(environmentConnectivity ? { connectivity: environmentConnectivity } : {})
    }
  };

  const publicBaseUrl = resolvePublicBaseUrl({ request, app });
  const allowlists = app.mcpAllowlists
    .map((doc) => ({
      version: doc.version,
      name: doc.name,
      rules: doc.rules.filter((rule) => {
        if (rule.workspace_id !== normalizedWorkspaceId) return false;
        return true;
      })
    }))
    .filter((doc) => doc.rules.length > 0);
  const bridgeProfile = buildAgentIdeBridgeProfile({
    workspaceId: normalizedWorkspaceId,
    actorId: normalizedActorId,
    workspacePath: normalizedWorkspacePath,
    rootDir: normalizedRootDir,
    allowlists,
    mcpBridgeBearerTokenEnabled: Boolean(app.mcpBridgeBearerToken),
    streamableHttpUrl: `${publicBaseUrl}/v0/mcp/stream`,
    protocolVersion: MCP_BRIDGE_PROTOCOL_VERSION
  });
  const claudeBridgeReady = environmentReport?.runtime_readiness?.claude_code_bridge === true;
  const codexBridgeReady = environmentReport?.runtime_readiness?.codex_bridge === true;
  const bridgeCredentialsReady = claudeBridgeReady || codexBridgeReady;
  const workspacePathSet = Boolean(normalizedWorkspacePath);
  const bridgeStageStatus = bridgeCredentialsReady && workspacePathSet
    ? 'pass'
    : bridgeCredentialsReady || workspacePathSet
      ? 'warn'
      : 'fail';
  const bridgeStage = {
    id: 'bridge',
    title: 'Agent IDE Bridge',
    required: true,
    weight: WORKSTATION_READINESS_STAGE_WEIGHT.bridge,
    status: bridgeStageStatus,
    summary: bridgeStageStatus === 'pass'
      ? 'Bridge credentials and workspace folder are both ready for Claude/Codex.'
      : bridgeStageStatus === 'warn'
        ? 'Bridge is partially ready. Complete missing folder or credentials.'
        : 'Bridge is blocked. Configure workspace folder and Claude/Codex credentials.',
    details: {
      workspace_path_set: workspacePathSet,
      workspace_path: normalizedWorkspacePath || null,
      bridge_credentials_ready: bridgeCredentialsReady,
      claude_code_ready: claudeBridgeReady,
      codex_ready: codexBridgeReady,
      streamable_http_url: bridgeProfile?.mcp_bridge?.streamable_http?.url || '',
      command: bridgeProfile?.mcp_bridge?.command || '',
      args: bridgeProfile?.mcp_bridge?.args || []
    }
  };

  const feishuStatus = resolveFeishuConnectionStatus(app);
  const environmentHasFeishuWebhook = environmentReport?.runtime_readiness?.feishu_delivery === true;
  const deliveryStageStatus = feishuStatus.connected
    ? 'pass'
    : environmentHasFeishuWebhook
      ? 'warn'
      : 'warn';
  const deliveryStage = {
    id: 'delivery',
    title: 'Feishu Delivery',
    required: false,
    weight: WORKSTATION_READINESS_STAGE_WEIGHT.delivery,
    status: deliveryStageStatus,
    summary: feishuStatus.connected
      ? 'Feishu webhook is connected in runtime.'
      : environmentHasFeishuWebhook
        ? 'Feishu webhook exists in environment set but not active in runtime yet.'
        : 'Feishu webhook not configured. Delivery will run in stub mode.',
    details: {
      connected: feishuStatus.connected,
      source: feishuStatus.source,
      delivery_mode: feishuStatus.delivery_mode,
      webhook_masked: feishuStatus.webhook_masked,
      environment_has_feishu_webhook: environmentHasFeishuWebhook
    }
  };

  const runSummary = app.stateDb.summarizeRunsByWorkspace({
    workspaceId: normalizedWorkspaceId
  });
  const sessionSummary = {
    total: Number(runSummary.total || 0),
    pending_approvals: Number(runSummary.by_status?.waiting_approval || 0),
    completed: Number(runSummary.by_status?.completed || 0),
    by_status: runSummary.by_status && typeof runSummary.by_status === 'object'
      ? runSummary.by_status
      : {}
  };
  const sessionStageStatus = !permissionChecks.session_read
    ? 'fail'
    : sessionSummary.total < 1
      ? 'warn'
      : sessionSummary.pending_approvals > 0 || !permissionChecks.audit_read
        ? 'warn'
        : 'pass';
  const sessionStage = {
    id: 'session_audit',
    title: 'Session Audit',
    required: true,
    weight: WORKSTATION_READINESS_STAGE_WEIGHT.session_audit,
    status: sessionStageStatus,
    summary: !permissionChecks.session_read
      ? 'Actor cannot read sessions in this workspace.'
      : sessionSummary.total < 1
        ? 'No sessions yet. Start first run to unlock audit review.'
        : sessionSummary.pending_approvals > 0
          ? `${sessionSummary.pending_approvals} session(s) waiting approval.`
          : !permissionChecks.audit_read
            ? 'Session exists but actor lacks audit.read for evidence retrieval.'
            : 'Session and audit review path is ready.',
    details: {
      permission_session_read: permissionChecks.session_read,
      permission_audit_read: permissionChecks.audit_read,
      sessions: sessionSummary
    }
  };

  const stages = [
    accessStage,
    environmentStage,
    bridgeStage,
    deliveryStage,
    sessionStage
  ];
  const score = buildWorkstationReadinessScore(stages);
  const nextActions = buildWorkstationReadinessNextActions({
    accessStage,
    environmentStage,
    bridgeStage,
    deliveryStage,
    sessionStage,
    selectedEnvironmentSet
  });

  return {
    version: 'v0',
    generated_at: generatedAt,
    workspace_id: normalizedWorkspaceId,
    actor_id: normalizedActorId,
    mode_filter: normalizedMode || 'all',
    include_probe: includeProbe,
    probe_timeout_ms: probeTimeoutMs,
    score,
    stages,
    next_actions: nextActions,
    context: {
      bootstrap_available: bootstrapAvailable,
      roles: resolvedPermissions.roles,
      permissions: resolvedPermissions.permissions,
      selected_environment_set_id: selectedEnvironmentSet?.id || '',
      feishu_connected: feishuStatus.connected,
      total_sessions: sessionSummary.total
    },
    feishu_status: {
      version: 'v0',
      generated_at: generatedAt,
      ...feishuStatus
    },
    bridge_profile: bridgeProfile
  };
}

function parseEnvironmentTarget(rawTarget = '') {
  const raw = asTrimmedString(rawTarget);
  if (!raw) {
    return {
      has_target: false,
      predicates: []
    };
  }

  const tokens = raw
    .split(',')
    .map((item) => asTrimmedString(item))
    .filter(Boolean);
  const predicates = [];

  for (const token of tokens) {
    if (token === '*') {
      predicates.push({ kind: 'all', value: '*' });
      continue;
    }

    const index = token.indexOf(':');
    if (index > 0) {
      const kind = asTrimmedString(token.slice(0, index)).toLowerCase();
      const value = asTrimmedString(token.slice(index + 1));
      if (!value) continue;
      if (kind === 'actor') {
        predicates.push({ kind: 'actor', value });
        continue;
      }
      if (kind === 'role') {
        predicates.push({ kind: 'role', value: value.toLowerCase() });
        continue;
      }
      if (kind === 'mode') {
        predicates.push({ kind: 'mode', value: normalizeAccessMode(value) });
        continue;
      }
      continue;
    }

    if (/^usr_[A-Za-z0-9_-]{4,128}$/.test(token)) {
      predicates.push({ kind: 'actor', value: token });
      continue;
    }
    const lower = token.toLowerCase();
    if (ROLE_NAME_SET.has(lower)) {
      predicates.push({ kind: 'role', value: lower });
    }
  }

  return {
    has_target: true,
    predicates
  };
}

function environmentEntryTargetMatches({
  entry = {},
  targetActorId = '',
  targetRoles = [],
  mode = ''
}) {
  const target = parseEnvironmentTarget(entry.target || '');
  if (!target.has_target) return true;
  if (!target.predicates.length) return false;

  const actorId = asTrimmedString(targetActorId);
  const roleSet = new Set(
    (Array.isArray(targetRoles) ? targetRoles : [])
      .map((role) => asTrimmedString(role).toLowerCase())
      .filter(Boolean)
  );
  const normalizedMode = normalizeAccessMode(mode || '');

  for (const predicate of target.predicates) {
    if (predicate.kind === 'all') return true;
    if (predicate.kind === 'actor' && actorId && actorId === predicate.value) return true;
    if (predicate.kind === 'role' && roleSet.has(predicate.value)) return true;
    if (predicate.kind === 'mode' && normalizedMode && normalizedMode === predicate.value) return true;
  }
  return false;
}

function buildEffectiveEnvironmentEntries({
  app,
  workspaceId = '',
  targetActorId = '',
  modeFilter = ''
}) {
  const resolvedTarget = resolveActorPermissions({
    app,
    workspaceId,
    actorId: targetActorId
  });
  const targetRoles = resolvedTarget.roles;
  const sets = app.stateDb.listEnvironmentSets({
    workspaceId,
    limit: 5000,
    offset: 0
  }).items
    .filter((item) => asTrimmedString(item.status || '') === 'active')
    .filter((item) => !modeFilter || asTrimmedString(item.mode) === modeFilter)
    .sort((a, b) => parseIsoTimeMs(a.updated_at) - parseIsoTimeMs(b.updated_at));

  const byEntry = new Map();
  for (const set of sets) {
    const entries = Array.isArray(set.entries) ? set.entries : [];
    for (const entry of entries) {
      if (!environmentEntryTargetMatches({
        entry,
        targetActorId,
        targetRoles,
        mode: set.mode
      })) {
        continue;
      }

      const provider = asTrimmedString(entry.provider || 'generic').toLowerCase() || 'generic';
      const key = asTrimmedString(entry.key).toUpperCase();
      const dedupeKey = `${provider}::${key}`;
      byEntry.set(dedupeKey, {
        ...entry,
        provider,
        key,
        source_set_id: asTrimmedString(set.id),
        source_set_name: asTrimmedString(set.name),
        source_set_scope: asTrimmedString(set.scope),
        source_set_mode: asTrimmedString(set.mode),
        source_set_status: asTrimmedString(set.status),
        source_set_updated_at: asTrimmedString(set.updated_at)
      });
    }
  }

  const items = Array.from(byEntry.values()).sort((a, b) => {
    const providerDiff = a.provider.localeCompare(b.provider);
    if (providerDiff !== 0) return providerDiff;
    return a.key.localeCompare(b.key);
  });

  return {
    target_roles: targetRoles,
    matched_sets: sets.length,
    items
  };
}

function sanitizeEffectiveEnvironmentEntry(entry = {}, { includePlainValues = false } = {}) {
  const sanitized = sanitizeEnvironmentEntry(entry, { includeValue: includePlainValues });
  return {
    ...sanitized,
    source: {
      set_id: asTrimmedString(entry.source_set_id),
      set_name: asTrimmedString(entry.source_set_name),
      scope: asTrimmedString(entry.source_set_scope),
      mode: asTrimmedString(entry.source_set_mode),
      status: asTrimmedString(entry.source_set_status),
      updated_at: asTrimmedString(entry.source_set_updated_at)
    }
  };
}

function listWorkspaceRoleBindings(app, workspaceId = '') {
  const targetWorkspace = asTrimmedString(workspaceId);
  if (!targetWorkspace) return [];

  return Array.from(app.store.roleBindings.values())
    .filter((binding) => asTrimmedString(binding.workspace_id) === targetWorkspace);
}

function workspaceHasRoleBindings(app, workspaceId = '') {
  return listWorkspaceRoleBindings(app, workspaceId).length > 0;
}

function listActorRoleBindings({
  app,
  workspaceId = '',
  actorId = ''
}) {
  const targetWorkspace = asTrimmedString(workspaceId);
  const targetActor = asTrimmedString(actorId);
  if (!targetWorkspace || !targetActor) return [];

  return listWorkspaceRoleBindings(app, targetWorkspace)
    .filter((binding) => asTrimmedString(binding.actor_id) === targetActor);
}

function actorHasAnyWorkspaceRole({
  app,
  workspaceId = '',
  actorId = ''
}) {
  return listActorRoleBindings({ app, workspaceId, actorId }).length > 0;
}

function resolveActorPermissions({
  app,
  workspaceId = '',
  actorId = ''
}) {
  const roles = Array.from(
    new Set(
      listActorRoleBindings({
        app,
        workspaceId,
        actorId
      })
        .map((binding) => asTrimmedString(binding.role))
        .filter((role) => ROLE_NAME_SET.has(role))
    )
  ).sort();

  const permissions = Array.from(
    new Set(
      roles.flatMap((role) => ROLE_PERMISSION_LIBRARY[role] || [])
    )
  ).sort();

  return {
    workspace_id: asTrimmedString(workspaceId),
    actor_id: asTrimmedString(actorId),
    roles,
    permissions
  };
}

function actorHasPermission({
  app,
  workspaceId = '',
  actorId = '',
  permission = ''
}) {
  const normalizedPermission = asTrimmedString(permission);
  if (!normalizedPermission) return false;

  const resolved = resolveActorPermissions({
    app,
    workspaceId,
    actorId
  });
  return resolved.permissions.includes(normalizedPermission);
}

function ensureActorPermission({
  app,
  request,
  workspaceId = '',
  permission = '',
  allowWorkspaceBootstrap = false
}) {
  const actorIdentity = resolveRequestActorId(request, {
    fallbackActorId: app.trustedDefaultActorId
  });
  if (!actorIdentity.ok) {
    return actorIdentity;
  }

  const targetWorkspace = asTrimmedString(workspaceId);
  if (!targetWorkspace) {
    return {
      ok: false,
      errorCode: 400,
      message: 'workspace_id is required for permission check'
    };
  }

  if (
    allowWorkspaceBootstrap &&
    !workspaceHasRoleBindings(app, targetWorkspace)
  ) {
    return {
      ok: true,
      actor_id: actorIdentity.actor_id,
      bootstrap: true
    };
  }

  if (!actorHasPermission({
    app,
    workspaceId: targetWorkspace,
    actorId: actorIdentity.actor_id,
    permission
  })) {
    return {
      ok: false,
      errorCode: 403,
      message: `Actor lacks permission: ${permission}`
    };
  }

  return {
    ok: true,
    actor_id: actorIdentity.actor_id,
    bootstrap: false
  };
}

function bootstrapWorkspaceRoleBindings({
  app,
  workspaceId = '',
  ownerActorId = ''
}) {
  const workspace = asTrimmedString(workspaceId);
  const actorId = asTrimmedString(ownerActorId);
  if (!workspace || !actorId) return [];
  if (!ACTOR_ID_PATTERN.test(actorId)) return [];
  if (workspaceHasRoleBindings(app, workspace)) return [];

  const now = nowIso();
  const bootstrapRoles = ['workspace_admin', 'operator', 'auditor'];
  const created = [];

  for (const role of bootstrapRoles) {
    const binding = {
      id: makeId('rlb'),
      workspace_id: workspace,
      actor_id: actorId,
      role,
      source: 'workspace_bootstrap',
      created_at: now,
      updated_at: now
    };
    app.store.roleBindings.set(binding.id, binding);
    app.stateDb.saveRoleBinding(binding);
    created.push(binding);
  }

  return created;
}

function resolveFeishuWebhookFromEnvironmentSet(environmentSet = {}) {
  const entries = Array.isArray(environmentSet.entries) ? environmentSet.entries : [];
  for (const entry of entries) {
    const provider = asTrimmedString(entry.provider).toLowerCase();
    const key = asTrimmedString(entry.key).toUpperCase();
    const value = asTrimmedString(entry.value);
    if (!value) continue;

    if (provider === 'feishu') {
      return value;
    }
    if (key === 'FLOCKMESH_FEISHU_WEBHOOK_URL' || key === 'FEISHU_WEBHOOK_URL') {
      return value;
    }
  }
  return '';
}

function actor(type, id) {
  return { type, id };
}

function makeAuditEntry({ runId, eventType, actorInfo, payload, decisionRef }) {
  return {
    id: makeId('aud'),
    run_id: runId,
    event_type: eventType,
    actor: actorInfo,
    payload_hash: sha256(payload),
    ...(decisionRef ? { decision_ref: decisionRef } : {}),
    occurred_at: nowIso()
  };
}

async function appendEvent({ app, runId, name, payload }) {
  const event = {
    id: makeId('evt'),
    run_id: runId,
    name,
    payload,
    at: nowIso()
  };

  addRunEvent(app.store, runId, event);
  await app.ledger.appendEvent(event);
}

async function appendAudit({ app, entry }) {
  addRunAudit(app.store, entry.run_id, entry);
  await app.ledger.appendAudit(entry);
}

function findBindingForAgent(store, agentId, workspaceId, capability) {
  for (const binding of store.connectorBindings.values()) {
    if (binding.status !== 'active') continue;
    if (binding.workspace_id !== workspaceId) continue;
    if (binding.agent_id && binding.agent_id !== agentId) continue;
    if (!binding.scopes.includes(capability)) continue;
    return binding;
  }
  return null;
}

function makeIntentFailureResult({
  intent,
  connectorId = '',
  connectorBindingId = '',
  reasonCode = 'action.execute.error',
  message = 'Intent execution failed'
}) {
  return {
    action_intent_id: intent.id,
    capability: intent.capability,
    status: 'failed',
    deduped: false,
    reason_code: reasonCode,
    message,
    ...(connectorId ? { connector_id: connectorId } : {}),
    ...(connectorBindingId ? { connector_binding_id: connectorBindingId } : {}),
    executed_at: nowIso()
  };
}

async function invokeIntentViaConnector({ app, run, intent }) {
  const bindingId = String(intent.connector_binding_id || '').trim();
  if (!bindingId) return null;

  const binding = findBindingById(app, bindingId);
  if (!binding || binding.status !== 'active') {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorBindingId: bindingId,
        reasonCode: 'connector.binding.unavailable',
        message: 'Connector binding is missing or inactive'
      })
    };
  }

  if (binding.workspace_id !== run.workspace_id) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId: binding.connector_id,
        connectorBindingId: binding.id,
        reasonCode: 'connector.binding.workspace_mismatch',
        message: 'Binding workspace does not match run workspace'
      })
    };
  }

  if (binding.agent_id && binding.agent_id !== run.agent_id) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId: binding.connector_id,
        connectorBindingId: binding.id,
        reasonCode: 'connector.binding.agent_mismatch',
        message: 'Binding agent does not match run agent'
      })
    };
  }

  if (!Array.isArray(binding.scopes) || !binding.scopes.includes(intent.capability)) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId: binding.connector_id,
        connectorBindingId: binding.id,
        reasonCode: 'connector.binding.scope_mismatch',
        message: `Capability ${intent.capability} is outside binding scope`
      })
    };
  }

  const connectorId = String(binding.connector_id || '').trim();
  const adapter = app.connectorAdapters[connectorId];
  if (!adapter) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId,
        connectorBindingId: binding.id,
        reasonCode: 'connector.adapter.missing',
        message: `Connector adapter not implemented: ${connectorId}`
      })
    };
  }

  const manifest = app.connectorRegistry[connectorId];
  if (manifest && Array.isArray(manifest.capabilities) && !manifest.capabilities.includes(intent.capability)) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId,
        connectorBindingId: binding.id,
        reasonCode: 'connector.manifest.capability_missing',
        message: `Capability ${intent.capability} is not declared by connector manifest`
      })
    };
  }

  const rateLimitDecision = app.connectorRateLimiter.evaluate({
    connectorId,
    workspaceId: run.workspace_id
  });
  if (!rateLimitDecision.allowed) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId,
        connectorBindingId: binding.id,
        reasonCode: 'connector.invoke.rate_limited',
        message: `Rate limited: retry_after_ms=${rateLimitDecision.retry_after_ms}`
      })
    };
  }

  const runtimeConfig = {
    feishuWebhookUrl: resolveActiveFeishuWebhook(app).webhook_url
  };
  let adapterPayload;
  let lastAdapterError;
  let lastFailureReasonCode = '';
  let attemptsUsed = 0;

  for (let attempt = 1; attempt <= app.adapterRetryPolicy.max_attempts; attempt += 1) {
    attemptsUsed = attempt;
    try {
      adapterPayload = await withTimeout(
        () => adapter.invoke({
          runId: run.id,
          capability: intent.capability,
          parameters: intent.parameters || {},
          idempotencyKey: intent.idempotency_key,
          attempt,
          runtime: runtimeConfig
        }),
        app.adapterTimeoutMs
      );
      break;
    } catch (err) {
      if (err instanceof AdapterCapabilityError) {
        return {
          result: makeIntentFailureResult({
            intent,
            connectorId,
            connectorBindingId: binding.id,
            reasonCode: 'connector.adapter.capability_unsupported',
            message: err.message
          })
        };
      }

      lastAdapterError = err;
      lastFailureReasonCode = classifyAdapterFailureReason(err);
      const retryDecision = buildAdapterRetryDecision({
        attempt,
        policy: app.adapterRetryPolicy,
        sideEffect: intent.side_effect,
        idempotencyKey: intent.idempotency_key,
        errorReason: lastFailureReasonCode
      });

      if (!retryDecision.retry) break;

      const delayMs = computeAdapterRetryDelayMs({
        attempt,
        policy: app.adapterRetryPolicy
      });
      if (delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  if (!adapterPayload) {
    return {
      result: makeIntentFailureResult({
        intent,
        connectorId,
        connectorBindingId: binding.id,
        reasonCode: lastFailureReasonCode || 'connector.invoke.error',
        message: String(lastAdapterError?.message || 'connector invoke failed')
      })
    };
  }

  return {
    connectorId,
    connectorBindingId: binding.id,
    result: {
      action_intent_id: intent.id,
      connector_id: connectorId,
      connector_binding_id: binding.id,
      capability: intent.capability,
      status: 'executed',
      output: adapterPayload,
      retry: {
        attempts: attemptsUsed,
        max_attempts: app.adapterRetryPolicy.max_attempts
      },
      deduped: false,
      executed_at: nowIso()
    }
  };
}

async function executeIntent({ app, run, intent }) {
  const key = intent.idempotency_key;
  const persistedReuse = key ? app.stateDb.getIdempotencyResult(key) : null;
  if (persistedReuse && !app.store.idempotencyResults.has(key)) {
    app.store.idempotencyResults.set(key, persistedReuse);
  }

  if (key && app.store.idempotencyResults.has(key)) {
    const reused = app.store.idempotencyResults.get(key);

    await appendEvent({
      app,
      runId: run.id,
      name: 'action.executed.deduped',
      payload: reused
    });

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: run.id,
        eventType: 'action.executed',
        actorInfo: actor('system', 'runtime'),
        payload: { ...reused, deduped: true }
      })
    });

    return reused;
  }

  let connectorMeta = null;
  let result = buildExecutionResult({ actionIntent: intent });
  const connectorExecution = await invokeIntentViaConnector({ app, run, intent });
  if (connectorExecution?.result) {
    result = connectorExecution.result;
    connectorMeta = connectorExecution;
  }

  if (key) {
    app.store.idempotencyResults.set(key, result);
    app.stateDb.saveIdempotencyResult({
      key,
      runId: run.id,
      payload: result,
      createdAt: nowIso()
    });
  }

  if (connectorMeta?.connectorId && connectorMeta?.connectorBindingId) {
    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: run.id,
        eventType: 'connector.invoke.requested',
        actorInfo: actor('agent', run.agent_id),
        payload: {
          connector_id: connectorMeta.connectorId,
          connector_binding_id: connectorMeta.connectorBindingId,
          capability: intent.capability,
          side_effect: intent.side_effect,
          risk_hint: intent.risk_hint
        }
      })
    });

    await appendEvent({
      app,
      runId: run.id,
      name: result.status === 'executed' ? 'connector.invoked' : 'connector.invoke.failed',
      payload: result
    });

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: run.id,
        eventType: result.status === 'executed' ? 'connector.invoke.executed' : 'connector.invoke.error',
        actorInfo: actor('agent', run.agent_id),
        payload: result
      })
    });
  }

  await appendEvent({
    app,
    runId: run.id,
    name: 'action.executed',
    payload: result
  });

  await appendAudit({
    app,
    entry: makeAuditEntry({
      runId: run.id,
      eventType: 'action.executed',
      actorInfo: actor('agent', run.agent_id),
      payload: result
    })
  });

  return result;
}

async function executeAllowedIntents({ app, run }) {
  const decisionsByActionId = new Map(
    run.policy_decisions.map((decision) => [decision.action_intent_id, decision])
  );

  for (const intent of run.action_intents) {
    const decision = decisionsByActionId.get(intent.id);
    if (!decision || decision.decision !== 'allow') continue;
    const execution = await executeIntent({ app, run, intent });
    if (!execution || execution.status !== 'executed') {
      return {
        ok: false,
        failed_intent_id: intent.id,
        reason_code: execution?.reason_code || 'action.execute.error'
      };
    }
  }

  return { ok: true };
}

function rebuildPendingApprovalsForRun(run) {
  const pending = new Map();
  const approvalState = run.approval_state || {};

  for (const decision of run.policy_decisions || []) {
    if (decision.decision !== 'escalate') continue;
    const state = approvalState[decision.action_intent_id] || {
      decision_id: decision.id,
      required_approvals: decision.required_approvals,
      approved_by: []
    };

    pending.set(decision.action_intent_id, {
      decision_id: state.decision_id,
      required_approvals: state.required_approvals,
      approvals: new Set(state.approved_by || [])
    });
  }

  return pending;
}

function findRunById(app, runId) {
  const run = app.store.runs.get(runId) || app.stateDb.getRun(runId);
  if (run) app.store.runs.set(run.id, run);
  return run;
}

function findBindingById(app, bindingId) {
  const binding = app.store.connectorBindings.get(bindingId) || app.stateDb.getBinding(bindingId);
  if (binding) app.store.connectorBindings.set(binding.id, binding);
  return binding;
}

function buildAdapterActionIntent({
  runId,
  bindingId,
  connectorId,
  capability,
  sideEffect,
  riskHint,
  idempotencyKey,
  parameters
}) {
  return {
    id: makeId('act'),
    run_id: runId,
    step_id: 'connector_invoke',
    connector_binding_id: bindingId,
    capability,
    side_effect: sideEffect,
    ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {}),
    risk_hint: riskHint,
    parameters: parameters || {},
    target: {
      surface: 'connector.adapter',
      connector_id: connectorId
    }
  };
}

function defaultPolicyContext() {
  return {
    org_policy: 'org_default_safe',
    workspace_policy: 'workspace_ops_cn',
    agent_policy: 'agent_ops_assistant'
  };
}

function normalizePolicyProfileName(value = '') {
  return String(value || '').trim();
}

function firstAvailablePolicyProfile(policyLibrary = {}, candidates = [], fallback = '') {
  for (const candidate of candidates) {
    const profileName = normalizePolicyProfileName(candidate);
    if (!profileName) continue;
    if (policyLibrary[profileName]) return profileName;
  }
  return normalizePolicyProfileName(fallback);
}

function resolveRuntimePolicyContext({
  policyLibrary = {},
  baseContext = defaultPolicyContext(),
  orgPolicy = '',
  workspacePolicy = '',
  agentPolicy = '',
  runOverride = ''
} = {}) {
  const resolved = {
    org_policy: firstAvailablePolicyProfile(
      policyLibrary,
      [orgPolicy, baseContext.org_policy],
      baseContext.org_policy
    ),
    workspace_policy: firstAvailablePolicyProfile(
      policyLibrary,
      [workspacePolicy, baseContext.workspace_policy],
      baseContext.workspace_policy
    ),
    agent_policy: firstAvailablePolicyProfile(
      policyLibrary,
      [agentPolicy, baseContext.agent_policy],
      baseContext.agent_policy
    ),
    run_override: ''
  };

  const runOverrideProfile = normalizePolicyProfileName(runOverride);
  if (runOverrideProfile && policyLibrary[runOverrideProfile]) {
    resolved.run_override = runOverrideProfile;
  }

  return resolved;
}

function resolveRequestActorId(request, { fallbackActorId = '' } = {}) {
  const headerValue = request?.headers?.['x-flockmesh-actor-id'];
  const actorIdRaw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  const actorId = String(actorIdRaw || fallbackActorId || '').trim();
  if (!ACTOR_ID_PATTERN.test(actorId)) {
    return {
      ok: false,
      errorCode: 401,
      message: 'Missing or invalid actor identity header: x-flockmesh-actor-id'
    };
  }

  return {
    ok: true,
    actor_id: actorId
  };
}

function ensureActorClaimMatches({ actorId, claimedActorId, fieldName }) {
  const claimed = String(claimedActorId || '').trim();
  if (!claimed) {
    return {
      ok: false,
      errorCode: 400,
      message: `${fieldName} is required`
    };
  }

  if (claimed !== actorId) {
    return {
      ok: false,
      errorCode: 403,
      message: `Authenticated actor does not match ${fieldName}`
    };
  }

  return { ok: true };
}

const ONE_PERSON_QUICKSTART_TEMPLATES = Object.freeze({
  weekly_ops_sync: Object.freeze({
    template_id: 'weekly_ops_sync',
    kit_id: 'kit_office_ops_core',
    playbook_id: 'pbk_weekly_ops_sync',
    default_agent_name: 'Solo Ops Assistant',
    default_connector_ids: ['con_feishu_official'],
    default_trigger_source: 'quickstart.one_person:weekly_ops_sync'
  }),
  incident_response: Object.freeze({
    template_id: 'incident_response',
    kit_id: 'kit_incident_commander',
    playbook_id: 'pbk_incident_triage',
    default_agent_name: 'Solo Incident Commander',
    default_connector_ids: ['con_feishu_official'],
    default_trigger_source: 'quickstart.one_person:incident_response'
  })
});

function resolveOnePersonQuickstartTemplate(templateIdRaw = '') {
  const templateId = String(templateIdRaw || '').trim();
  const template = ONE_PERSON_QUICKSTART_TEMPLATES[templateId];
  if (!template) {
    throw new Error(`unsupported template_id: ${templateId}`);
  }
  return template;
}

function buildOnePersonQuickstartNextActions({ run, warnings, createdBindings }) {
  const actions = [];
  if (run?.status === 'waiting_approval') {
    actions.push('Open Approval Inbox and approve escalated actions to finish the first run.');
  }

  const warningCount = Array.isArray(warnings) ? warnings.length : 0;
  if (warningCount > 0) {
    actions.push('Review blueprint warnings and tighten connector scope before production usage.');
  }

  if (!Array.isArray(createdBindings) || createdBindings.length < 1) {
    actions.push('Create at least one connector binding before triggering side-effect workflows.');
  }

  if (
    Array.isArray(createdBindings) &&
    !createdBindings.some((item) => Array.isArray(item?.scopes) && item.scopes.includes('message.send'))
  ) {
    actions.push('Add a connector scope that supports message.send for outbound communication tasks.');
  }

  if (!actions.length) {
    actions.push('Inspect Run Timeline and Replay Integrity to validate the first execution path.');
  }
  return actions;
}

function normalizePolicyPatchRules(rawRules = []) {
  if (!Array.isArray(rawRules) || rawRules.length < 1) {
    throw new Error('patch_rules must be a non-empty array');
  }

  const normalized = [];
  const seen = new Set();

  for (let i = 0; i < rawRules.length; i += 1) {
    const rule = rawRules[i];
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new Error(`patch_rules[${i}] must be an object`);
    }

    const capability = String(rule.capability || '').trim();
    if (!POLICY_CAPABILITY_PATTERN.test(capability)) {
      throw new Error(`patch_rules[${i}] has invalid capability: ${capability}`);
    }
    if (seen.has(capability)) {
      throw new Error(`patch_rules has duplicated capability: ${capability}`);
    }
    seen.add(capability);

    const decision = String(rule.decision || '').trim();
    if (!POLICY_DECISION_SET.has(decision)) {
      throw new Error(`patch_rules[${i}] has invalid decision: ${decision}`);
    }

    const requiredApprovals = decision === 'escalate'
      ? Number(rule.required_approvals ?? 1)
      : 0;
    if (decision === 'escalate' && (!Number.isInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 5)) {
      throw new Error(`patch_rules[${i}] must set required_approvals between 1 and 5 for escalate`);
    }

    normalized.push({
      capability,
      decision,
      required_approvals: decision === 'escalate' ? requiredApprovals : 0
    });
  }

  normalized.sort((a, b) => a.capability.localeCompare(b.capability));
  return normalized;
}

function profileRulesToList(profile = {}) {
  const rules = profile?.rules && typeof profile.rules === 'object' && !Array.isArray(profile.rules)
    ? profile.rules
    : {};

  return Object.entries(rules)
    .filter(([capability, rule]) => POLICY_CAPABILITY_PATTERN.test(capability) && rule && typeof rule === 'object')
    .map(([capability, rule]) => ({
      capability,
      decision: String(rule.decision || 'deny'),
      required_approvals: String(rule.decision || '') === 'escalate'
        ? Math.max(1, Math.min(5, Number(rule.requiredApprovals || 1)))
        : 0
    }))
    .sort((a, b) => a.capability.localeCompare(b.capability));
}

function profileRulesToDocumentRules(rules = []) {
  return (rules || []).map((item) => ({
    capability: item.capability,
    decision: item.decision,
    ...(item.decision === 'escalate' ? { required_approvals: item.required_approvals } : {})
  }));
}

function normalizePolicyFileDocument(document = {}, { profileName } = {}) {
  const docProfileName = String(document?.name || profileName || '').trim();
  const rules = Array.isArray(document?.rules)
    ? document.rules
    : [];
  return {
    version: 'v0',
    name: docProfileName,
    rules
  };
}

function toPolicyRulePatchList(rules = []) {
  return (rules || []).map((item) => ({
    capability: item.capability,
    decision: item.decision,
    required_approvals: item.decision === 'escalate' ? Number(item.required_approvals || 1) : 0
  }));
}

function summarizePolicyRuleSet(rules = []) {
  return rules.reduce(
    (acc, rule) => {
      if (rule.decision === 'allow') acc.allow += 1;
      if (rule.decision === 'escalate') acc.escalate += 1;
      if (rule.decision === 'deny') acc.deny += 1;
      return acc;
    },
    {
      allow: 0,
      escalate: 0,
      deny: 0
    }
  );
}

function listPolicyProfileCatalogItems(policyLibrary = {}) {
  return Object.keys(policyLibrary || {})
    .filter((profileName) => POLICY_PROFILE_NAME_PATTERN.test(profileName))
    .sort()
    .map((profileName) => {
      const rules = profileRulesToList(policyLibrary[profileName]);
      return {
        profile_name: profileName,
        rule_count: rules.length,
        decision_summary: summarizePolicyRuleSet(rules),
        rules
      };
    });
}

function buildPatchedPolicyProfile({ profileName, beforeProfile, patchRules }) {
  const nextRules = {};

  for (const item of profileRulesToList(beforeProfile)) {
    nextRules[item.capability] = {
      decision: item.decision,
      requiredApprovals: item.decision === 'escalate' ? item.required_approvals : 0
    };
  }

  for (const item of patchRules) {
    nextRules[item.capability] = {
      decision: item.decision,
      requiredApprovals: item.decision === 'escalate' ? item.required_approvals : 0
    };
  }

  return {
    name: profileName,
    rules: nextRules
  };
}

function comparePolicyRules({ beforeRules, afterRules }) {
  const beforeByCapability = new Map(beforeRules.map((item) => [item.capability, item]));
  const afterByCapability = new Map(afterRules.map((item) => [item.capability, item]));
  const added = [];
  const updated = [];
  const unchanged = [];
  const removed = [];

  for (const item of afterRules) {
    const previous = beforeByCapability.get(item.capability);
    if (!previous) {
      added.push(item.capability);
      continue;
    }

    if (
      previous.decision !== item.decision ||
      Number(previous.required_approvals || 0) !== Number(item.required_approvals || 0)
    ) {
      updated.push(item.capability);
    } else {
      unchanged.push(item.capability);
    }
  }

  for (const item of beforeRules) {
    if (!afterByCapability.has(item.capability)) {
      removed.push(item.capability);
    }
  }

  added.sort();
  updated.sort();
  unchanged.sort();
  removed.sort();

  return {
    added_capabilities: added,
    updated_capabilities: updated,
    removed_capabilities: removed,
    unchanged_capabilities: unchanged,
    summary: {
      total_rules_before: beforeRules.length,
      total_rules_after: afterRules.length,
      patch_rules: added.length + updated.length + removed.length,
      added: added.length,
      updated: updated.length,
      removed: removed.length,
      unchanged: unchanged.length
    }
  };
}

function toPolicyProfileDocument({ profileName, profile }) {
  const rules = profileRulesToDocumentRules(profileRulesToList(profile));

  return {
    version: 'v0',
    name: profileName,
    rules
  };
}

function hashPolicyProfileDocument(document = {}) {
  return buildIncidentExportPayloadHash(normalizePolicyFileDocument(document, {
    profileName: document?.name
  }));
}

function buildPolicyProfileVersionSnapshot({ profileName, profile }) {
  const normalizedProfileName = String(profileName || '').trim();
  const rules = profileRulesToList(profile);
  const document = normalizePolicyFileDocument(
    toPolicyProfileDocument({
      profileName: normalizedProfileName,
      profile
    }),
    { profileName: normalizedProfileName }
  );

  return {
    profile_name: normalizedProfileName,
    rule_count: rules.length,
    document_hash: hashPolicyProfileDocument(document),
    file_path: path.join('policies', `${normalizedProfileName}.policy.json`)
  };
}

function policyPatchHistoryPath(rootDir) {
  return path.join(rootDir, POLICY_PATCH_HISTORY_DIRNAME, POLICY_PATCH_HISTORY_FILE);
}

async function appendPolicyPatchHistoryEntry({ rootDir, entry }) {
  const filePath = policyPatchHistoryPath(rootDir);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, `${JSON.stringify(entry)}\n`, 'utf8');
}

async function readPolicyPatchHistoryEntries({ rootDir }) {
  const filePath = policyPatchHistoryPath(rootDir);
  try {
    const text = await fs.readFile(filePath, 'utf8');
    return text
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter((item) => item && typeof item === 'object');
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

function paginateDescendingByAppliedAt(entries = [], { limit = 50, offset = 0 } = {}) {
  const boundedLimit = Math.min(Math.max(Number(limit) || 50, 1), 500);
  const boundedOffset = Math.max(Number(offset) || 0, 0);
  const ordered = [...entries].sort((a, b) => {
    const aMs = Date.parse(a?.applied_at || '') || 0;
    const bMs = Date.parse(b?.applied_at || '') || 0;
    return bMs - aMs;
  });
  return {
    total: ordered.length,
    limit: boundedLimit,
    offset: boundedOffset,
    items: ordered.slice(boundedOffset, boundedOffset + boundedLimit)
  };
}

function resolvePolicyPatchMode(modeRaw) {
  return modeRaw === 'apply' ? 'apply' : 'dry_run';
}

function buildPolicyPatchHistorySummaryItem(entry = {}) {
  return {
    patch_id: String(entry.patch_id || ''),
    profile_name: String(entry.profile_name || ''),
    operation: String(entry.operation || 'patch'),
    rollback_target_patch_id: String(entry.rollback_target_patch_id || ''),
    rollback_target_state: String(entry.rollback_target_state || ''),
    actor_id: String(entry.actor_id || ''),
    reason: String(entry.reason || ''),
    applied_at: String(entry.applied_at || ''),
    file_path: String(entry.file_path || ''),
    before_profile_hash: String(entry.before_profile_hash || ''),
    after_profile_hash: String(entry.after_profile_hash || ''),
    summary: {
      total_rules_before: Number(entry.summary?.total_rules_before || 0),
      total_rules_after: Number(entry.summary?.total_rules_after || 0),
      patch_rules: Number(entry.summary?.patch_rules || 0),
      added: Number(entry.summary?.added || 0),
      updated: Number(entry.summary?.updated || 0),
      removed: Number(entry.summary?.removed || 0),
      unchanged: Number(entry.summary?.unchanged || 0)
    },
    changes: {
      added_capabilities: Array.isArray(entry.changes?.added_capabilities)
        ? entry.changes.added_capabilities
        : [],
      updated_capabilities: Array.isArray(entry.changes?.updated_capabilities)
        ? entry.changes.updated_capabilities
        : [],
      removed_capabilities: Array.isArray(entry.changes?.removed_capabilities)
        ? entry.changes.removed_capabilities
        : [],
      unchanged_capabilities: Array.isArray(entry.changes?.unchanged_capabilities)
        ? entry.changes.unchanged_capabilities
        : []
    }
  };
}

function isPolicyPatchHistoryEntry(entry) {
  return Boolean(
    entry &&
      typeof entry === 'object' &&
      POLICY_PATCH_ID_PATTERN.test(String(entry.patch_id || '')) &&
      POLICY_PROFILE_NAME_PATTERN.test(String(entry.profile_name || '')) &&
      ['patch', 'rollback'].includes(String(entry.operation || ''))
  );
}

async function listPolicyPatchHistoryPage({
  rootDir,
  profileName = '',
  operation = '',
  limit,
  offset
}) {
  const entries = await readPolicyPatchHistoryEntries({ rootDir });
  const filtered = entries.filter((item) => {
    if (!isPolicyPatchHistoryEntry(item)) return false;
    if (profileName && item.profile_name !== profileName) return false;
    if (operation && item.operation !== operation) return false;
    return true;
  });

  return paginateDescendingByAppliedAt(filtered, { limit, offset });
}

function buildPolicyPatchResponsePayload({
  mode,
  profileName,
  actorInfo,
  reason,
  persisted,
  filePath,
  summary,
  patchRules,
  beforeRules,
  afterRules,
  compared,
  simulationPreview,
  auditEntry,
  patchId = null,
  rollbackTargetPatchId = null,
  beforeProfileHash = '',
  afterProfileHash = ''
}) {
  return {
    version: 'v0',
    generated_at: nowIso(),
    mode,
    profile_name: profileName,
    actor_id: actorInfo.id,
    reason,
    persisted,
    patch_id: patchId,
    rollback_target_patch_id: rollbackTargetPatchId,
    before_profile_hash: beforeProfileHash,
    after_profile_hash: afterProfileHash,
    file_path: filePath,
    summary,
    patch_rules: patchRules,
    before_profile: {
      name: profileName,
      rules: beforeRules
    },
    after_profile: {
      name: profileName,
      rules: afterRules
    },
    changes: {
      added_capabilities: compared.added_capabilities,
      updated_capabilities: compared.updated_capabilities,
      removed_capabilities: compared.removed_capabilities,
      unchanged_capabilities: compared.unchanged_capabilities
    },
    simulation_preview: simulationPreview,
    audit_entry: auditEntry
  };
}

function classifyCapabilityForPolicyPatchSimulation(capability) {
  const value = String(capability || '').toLowerCase();
  if (POLICY_READ_ONLY_SUFFIXES.some((suffix) => value.endsWith(suffix))) {
    return { side_effect: 'none', risk_hint: 'R0' };
  }

  if (POLICY_HIGH_RISK_TOKENS.some((token) => value.includes(token))) {
    return { side_effect: 'mutation', risk_hint: 'R3' };
  }

  return { side_effect: 'mutation', risk_hint: 'R2' };
}

function summarizePolicyDecisions(decisions = []) {
  return decisions.reduce((acc, decision) => {
    acc.total += 1;
    if (decision.decision === 'allow') acc.allow += 1;
    if (decision.decision === 'escalate') acc.escalate += 1;
    if (decision.decision === 'deny') acc.deny += 1;
    return acc;
  }, {
    total: 0,
    allow: 0,
    escalate: 0,
    deny: 0
  });
}

function simulatePolicyPatch({
  profileName,
  patchRules,
  beforeLibrary,
  afterLibrary
}) {
  const simulationContext = {
    ...defaultPolicyContext(),
    run_override: profileName
  };

  const beforeDecisions = [];
  const afterDecisions = [];
  for (const patchRule of patchRules) {
    const classified = classifyCapabilityForPolicyPatchSimulation(patchRule.capability);
    const actionIntent = {
      id: `act_patch_sim_${patchRule.capability.replace(/[^a-zA-Z0-9]/g, '_')}`,
      run_id: 'run_patch_simulation',
      step_id: `policy.patch.sim.${patchRule.capability}`,
      capability: patchRule.capability,
      side_effect: classified.side_effect,
      risk_hint: classified.risk_hint,
      ...(classified.side_effect === 'mutation'
        ? { idempotency_key: `idem_patch_${patchRule.capability.replace(/[^a-zA-Z0-9]/g, '_')}` }
        : {}),
      parameters: {},
      target: {
        surface: 'policy.patch'
      }
    };

    const before = evaluatePolicy({
      runId: 'run_patch_simulation',
      actionIntent,
      policyContext: simulationContext,
      policyLibrary: beforeLibrary
    });
    const after = evaluatePolicy({
      runId: 'run_patch_simulation',
      actionIntent,
      policyContext: simulationContext,
      policyLibrary: afterLibrary
    });

    beforeDecisions.push(before);
    afterDecisions.push(after);
  }

  const beforeByCapability = new Map(
    beforeDecisions.map((item, index) => [patchRules[index].capability, item.decision])
  );
  const improvedCapabilities = patchRules
    .map((item, index) => ({
      capability: item.capability,
      before: beforeByCapability.get(item.capability),
      after: afterDecisions[index].decision
    }))
    .filter((item) =>
      Number(POLICY_DECISION_WEIGHT[item.after] || 99) <
      Number(POLICY_DECISION_WEIGHT[item.before] || 99)
    )
    .map((item) => item.capability)
    .sort();

  return {
    policy_context: simulationContext,
    summary_before: summarizePolicyDecisions(beforeDecisions),
    summary_after: summarizePolicyDecisions(afterDecisions),
    improved_capabilities: improvedCapabilities
  };
}

function resolvePolicyPatchActor(actorIdRaw = '') {
  const actorId = String(actorIdRaw || '').trim() || 'usr_policy_admin';
  if (actorId.startsWith('usr_')) return actor('user', actorId);
  if (actorId.startsWith('agt_')) return actor('agent', actorId);
  return actor('system', actorId);
}

function evaluateMcpAllowlistForRequest({ app, body, connectorId }) {
  if (connectorId !== 'con_mcp_gateway') {
    return { allowed: true, reason_code: 'mcp.allowlist.not_applicable' };
  }

  const toolName = body?.parameters?.tool_name;
  if (typeof toolName !== 'string' || !toolName.length) {
    return {
      allowed: false,
      reason_code: 'mcp.allowlist.tool_name_required'
    };
  }

  return evaluateMcpAllowlist({
    documents: app.mcpAllowlists,
    workspaceId: body.workspace_id,
    agentId: body.agent_id,
    toolName,
    sideEffect: body.side_effect,
    riskHint: body.risk_hint
  });
}

function buildAgentIdeBridgeProfile({
  workspaceId = '',
  agentId = '',
  actorId = '',
  workspacePath = '',
  rootDir = '',
  allowlists = [],
  mcpBridgeBearerTokenEnabled = false,
  streamableHttpUrl = '',
  protocolVersion = MCP_BRIDGE_PROTOCOL_VERSION
} = {}) {
  const normalizedWorkspaceId = String(workspaceId || '').trim();
  const normalizedAgentId = String(agentId || '').trim();
  const normalizedActorId = String(actorId || '').trim() || 'usr_yingapple';
  const normalizedWorkspacePath = String(workspacePath || '').trim();
  const normalizedRootDir = path.resolve(String(rootDir || defaultProjectRoot));
  const bridgeScriptPath = path.resolve(normalizedRootDir, 'src', 'mcp-bridge-stdio.js');
  const normalizedStreamableHttpUrl = String(streamableHttpUrl || '').trim();

  return {
    version: 'v0',
    integration: 'agent_ide_bridge',
    workspace_id: normalizedWorkspaceId,
    agent_id: normalizedAgentId || null,
    actor_id: normalizedActorId,
    mcp_bridge: {
      transport: 'stdio',
      command: MCP_BRIDGE_STDIO_COMMAND,
      args: [bridgeScriptPath],
      cwd: normalizedRootDir,
      streamable_http: {
        endpoint: '/v0/mcp/stream',
        url: normalizedStreamableHttpUrl || '/v0/mcp/stream',
        protocol_version: protocolVersion,
        ...(mcpBridgeBearerTokenEnabled
          ? {
              auth: {
                type: 'bearer',
                env_var: 'FLOCKMESH_MCP_BRIDGE_BEARER_TOKEN'
              }
            }
          : {})
      },
      env: {
        FLOCKMESH_ROOT_DIR: normalizedRootDir,
        FLOCKMESH_WORKSPACE_ID: normalizedWorkspaceId,
        ...(normalizedWorkspacePath ? { FLOCKMESH_WORKSPACE_PATH: normalizedWorkspacePath } : {}),
        ...(normalizedAgentId ? { FLOCKMESH_AGENT_ID: normalizedAgentId } : {}),
        FLOCKMESH_ACTOR_ID: normalizedActorId
      }
    },
    core_tools: MCP_BRIDGE_CORE_TOOL_NAMES,
    mcp_allowlists: allowlists,
    enterprise_guardrails: [
      'workspace/agent MCP allowlist',
      'policy-gated side effects (fail-closed)',
      'connector invoke rate-limit guardrail',
      'immutable audit for every approval and invoke'
    ]
  };
}

function mcpToolCallResult(payload, { isError = false } = {}) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2)
      }
    ],
    isError
  };
}

function mcpJsonRpcResult(id, result) {
  return {
    jsonrpc: '2.0',
    id,
    result
  };
}

function mcpJsonRpcError(id, code, message, data = undefined) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      ...(data !== undefined ? { data } : {})
    }
  };
}

function parseBearerTokenFromAuthorizationHeader(headerValue = '') {
  const value = String(headerValue || '').trim();
  if (!value) return '';
  const match = /^Bearer\s+(.+)$/i.exec(value);
  return match ? String(match[1] || '').trim() : '';
}

function resolveMcpProtocolVersionFromRequest(request) {
  const headerValue = String(request.headers[MCP_PROTOCOL_HEADER] || '').trim();
  return headerValue || MCP_BRIDGE_PROTOCOL_VERSION;
}

function nowMs() {
  return Date.now();
}

function sessionUpdatedAtMs(session = {}) {
  const direct = Number(session.updated_at_ms);
  if (Number.isFinite(direct) && direct > 0) return direct;
  const parsed = Date.parse(String(session.updated_at || ''));
  return Number.isFinite(parsed) ? parsed : 0;
}

function pruneMcpBridgeSessions(app, currentMs = nowMs()) {
  const sessions = app.mcpBridgeSessions;
  if (!sessions || sessions.size === 0) return;

  for (const [sessionId, session] of sessions.entries()) {
    const updatedMs = sessionUpdatedAtMs(session);
    if (!updatedMs || (currentMs - updatedMs) > MCP_BRIDGE_SESSION_TTL_MS) {
      sessions.delete(sessionId);
    }
  }

  if (sessions.size <= MCP_BRIDGE_MAX_SESSIONS) return;

  const sorted = Array.from(sessions.entries())
    .map(([sessionId, session]) => ({
      sessionId,
      updatedAtMs: sessionUpdatedAtMs(session)
    }))
    .sort((a, b) => a.updatedAtMs - b.updatedAtMs);

  const deleteCount = sessions.size - MCP_BRIDGE_MAX_SESSIONS;
  for (let index = 0; index < deleteCount; index += 1) {
    sessions.delete(sorted[index].sessionId);
  }
}

function normalizeBaseUrl(baseUrl = '') {
  const value = String(baseUrl || '').trim();
  if (!value) return '';
  return value.replace(/\/+$/, '');
}

function resolvePublicBaseUrl({ request, app }) {
  const configured = normalizeBaseUrl(app.mcpBridgePublicBaseUrl);
  if (configured) return configured;

  const forwardedProtoRaw = String(request.headers['x-forwarded-proto'] || '').trim();
  const forwardedHostRaw = String(request.headers['x-forwarded-host'] || '').trim();
  const forwardedProto = forwardedProtoRaw.split(',')[0]?.trim();
  const forwardedHost = forwardedHostRaw.split(',')[0]?.trim();
  const protocol = forwardedProto || String(request.protocol || 'http');
  const host = forwardedHost || String(request.headers.host || `127.0.0.1:${process.env.PORT || 8080}`);
  return normalizeBaseUrl(`${protocol}://${host}`);
}

function setMcpProtocolHeader(reply, protocolVersion = MCP_BRIDGE_PROTOCOL_VERSION) {
  reply.header(MCP_PROTOCOL_HEADER, protocolVersion);
}

function authorizeMcpBridgeRequest(app, request, reply) {
  const expectedBearerToken = app.mcpBridgeBearerToken;
  if (!expectedBearerToken) return true;
  const providedToken = parseBearerTokenFromAuthorizationHeader(request.headers.authorization);
  if (providedToken && providedToken === expectedBearerToken) return true;
  reply.code(401);
  reply.send({ message: 'Unauthorized MCP bridge request' });
  return false;
}

function buildPolicyTraceSummary(decisions = []) {
  const summary = {
    total: decisions.length,
    allow: 0,
    escalate: 0,
    deny: 0,
    by_risk_tier: {},
    by_effective_source: {}
  };

  for (const decision of decisions) {
    if (decision.decision === 'allow') summary.allow += 1;
    if (decision.decision === 'escalate') summary.escalate += 1;
    if (decision.decision === 'deny') summary.deny += 1;

    const riskTier = decision.risk_tier || 'unknown';
    summary.by_risk_tier[riskTier] = (summary.by_risk_tier[riskTier] || 0) + 1;

    const effectiveSource = decision.policy_trace?.effective_source || 'unknown';
    summary.by_effective_source[effectiveSource] = (summary.by_effective_source[effectiveSource] || 0) + 1;
  }

  return summary;
}

async function collectLedgerEvidence({
  listFn,
  runId,
  maxItemsPerStream
}) {
  let offset = 0;
  let total = 0;
  const items = [];

  while (items.length < maxItemsPerStream) {
    const limit = Math.min(500, maxItemsPerStream - items.length);
    const page = await listFn(runId, { limit, offset });
    total = page.total;
    items.push(...page.items);

    if (page.items.length < limit) break;
    offset += page.items.length;
    if (offset >= page.total) break;
  }

  return {
    total,
    exported: items.length,
    truncated: total > items.length,
    items
  };
}

function toEpochMs(value) {
  const ms = Date.parse(value || '');
  return Number.isFinite(ms) ? ms : 0;
}

function buildCountMap(items = [], keySelector) {
  const counts = {};
  for (const item of items) {
    const selected = keySelector(item);
    const keys = Array.isArray(selected) ? selected : [selected];
    for (const raw of keys) {
      const key = typeof raw === 'string' && raw.trim() ? raw.trim() : 'unknown';
      counts[key] = (counts[key] || 0) + 1;
    }
  }
  return counts;
}

function buildDiffGroup(currentCounts = {}, baseCounts = {}, { sampleLimit = 20 } = {}) {
  const rows = [];
  const keys = new Set([
    ...Object.keys(currentCounts),
    ...Object.keys(baseCounts)
  ]);

  for (const key of keys) {
    const current = Number(currentCounts[key] || 0);
    const base = Number(baseCounts[key] || 0);
    if (current === base) continue;
    rows.push({
      key,
      current,
      base,
      delta: current - base
    });
  }

  rows.sort(
    (a, b) =>
      Math.abs(b.delta) - Math.abs(a.delta) ||
      b.current - a.current ||
      a.key.localeCompare(b.key)
  );

  return {
    total: rows.length,
    truncated: rows.length > sampleLimit,
    items: rows.slice(0, sampleLimit)
  };
}

function metricDelta(current, base) {
  return {
    current,
    base,
    delta: current - base
  };
}

function toEvidenceDigest(stream) {
  return {
    total: stream.total,
    exported: stream.exported,
    truncated: stream.truncated
  };
}

function buildSessionSummaryFromRun(run) {
  const decisions = Array.isArray(run.policy_decisions) ? run.policy_decisions : [];
  const approvalState = run.approval_state && typeof run.approval_state === 'object'
    ? run.approval_state
    : {};
  const decisionSummary = decisions.reduce(
    (acc, item) => {
      const decision = asTrimmedString(item?.decision);
      if (!decision) return acc;
      if (decision === 'allow') acc.allow += 1;
      if (decision === 'escalate') acc.escalate += 1;
      if (decision === 'deny') acc.deny += 1;
      return acc;
    },
    { allow: 0, escalate: 0, deny: 0 }
  );

  return {
    session_id: run.id,
    run_id: run.id,
    workspace_id: run.workspace_id,
    agent_id: run.agent_id,
    playbook_id: run.playbook_id,
    actor_id: asTrimmedString(run.trigger?.actor_id || ''),
    trigger_source: asTrimmedString(run.trigger?.source || ''),
    status: run.status,
    started_at: run.started_at,
    ended_at: run.ended_at || null,
    revision: Number(run.revision || 1),
    pending_approvals: Object.keys(approvalState).length,
    policy_summary: decisionSummary
  };
}

function resolveTimelineDiffBaseRun({ app, run, baseRunId }) {
  if (baseRunId) {
    const baseRun = findRunById(app, baseRunId);
    if (!baseRun) {
      return {
        errorCode: 404,
        message: `Base run not found: ${baseRunId}`
      };
    }
    if (baseRun.id === run.id) {
      return {
        errorCode: 409,
        message: 'Base run cannot be the same as run_id'
      };
    }
    if (baseRun.workspace_id !== run.workspace_id) {
      return {
        errorCode: 409,
        message: 'Base run workspace does not match run workspace'
      };
    }
    if (baseRun.agent_id !== run.agent_id) {
      return {
        errorCode: 409,
        message: 'Base run agent does not match run agent'
      };
    }
    if (baseRun.playbook_id !== run.playbook_id) {
      return {
        errorCode: 409,
        message: 'Base run playbook does not match run playbook'
      };
    }
    return {
      baseRun,
      baseSource: 'explicit'
    };
  }

  const allRuns = app.stateDb.listRuns({ limit: 5000, offset: 0 }).items;
  for (const item of allRuns) {
    app.store.runs.set(item.id, item);
  }

  const candidates = allRuns.filter((item) =>
    item.id !== run.id &&
    item.workspace_id === run.workspace_id &&
    item.agent_id === run.agent_id &&
    item.playbook_id === run.playbook_id
  );

  if (!candidates.length) {
    return { baseRun: null, baseSource: 'auto_previous' };
  }

  const runStartedMs = toEpochMs(run.started_at);
  candidates.sort((a, b) => toEpochMs(b.started_at) - toEpochMs(a.started_at));

  const earlier = runStartedMs > 0
    ? candidates.filter((item) => toEpochMs(item.started_at) < runStartedMs)
    : [];

  const baseRun = earlier.length ? earlier[0] : candidates[0];
  return {
    baseRun,
    baseSource: 'auto_previous'
  };
}

function replayStateFromContext({
  runStatus,
  issues
}) {
  if (['accepted', 'running', 'waiting_approval'].includes(runStatus)) {
    return 'pending';
  }

  const hardIssues = issues.filter((code) => code !== 'replay.partial_evidence');
  if (hardIssues.length > 0) return 'inconsistent';
  if (issues.includes('replay.partial_evidence')) return 'inconclusive';
  return 'consistent';
}

function collectReplayExecutionStats({
  run,
  eventEvidence,
  auditEvidence,
  sampleLimit
}) {
  const expectedByActionId = new Map();
  const intentsById = new Map(
    (run.action_intents || []).map((item) => [item.id, item])
  );

  for (const decision of run.policy_decisions || []) {
    if (decision.decision !== 'allow') continue;
    const intent = intentsById.get(decision.action_intent_id);
    if (!intent) continue;
    expectedByActionId.set(intent.id, {
      action_intent_id: intent.id,
      capability: intent.capability,
      side_effect: intent.side_effect,
      idempotency_key: intent.idempotency_key || '',
      decision_id: decision.id,
      risk_tier: decision.risk_tier
    });
  }

  const observedActionCounts = {};
  let unknownEventActionIds = 0;
  let observedActionExecutionEvents = 0;

  for (const item of eventEvidence.items) {
    if (item.name !== 'action.executed' && item.name !== 'action.executed.deduped') continue;
    observedActionExecutionEvents += 1;
    const actionIntentId = item.payload?.action_intent_id;
    if (typeof actionIntentId !== 'string' || !actionIntentId) {
      unknownEventActionIds += 1;
      continue;
    }
    observedActionCounts[actionIntentId] = (observedActionCounts[actionIntentId] || 0) + 1;
  }

  const observedActionIds = Object.keys(observedActionCounts);
  const expectedActionIds = Array.from(expectedByActionId.keys());
  const expectedSet = new Set(expectedActionIds);

  const missing = expectedActionIds
    .filter((id) => !observedActionCounts[id])
    .map((id) => expectedByActionId.get(id));

  const unexpected = observedActionIds
    .filter((id) => !expectedSet.has(id))
    .map((id) => ({
      action_intent_id: id,
      executions: observedActionCounts[id]
    }));

  const duplicates = observedActionIds
    .filter((id) => observedActionCounts[id] > 1)
    .map((id) => ({
      action_intent_id: id,
      executions: observedActionCounts[id]
    }));

  const observedActions = observedActionIds
    .map((id) => {
      const expected = expectedByActionId.get(id);
      return {
        action_intent_id: id,
        executions: observedActionCounts[id],
        expected: Boolean(expected),
        capability: expected?.capability || ''
      };
    })
    .sort((a, b) => b.executions - a.executions || a.action_intent_id.localeCompare(b.action_intent_id))
    .slice(0, sampleLimit);

  const observedActionExecutionAudit = auditEvidence.items
    .filter((item) => item.event_type === 'action.executed')
    .length;

  const issues = [];
  if (eventEvidence.truncated || auditEvidence.truncated) {
    issues.push('replay.partial_evidence');
  }
  if (missing.length > 0) {
    issues.push('replay.missing_expected_action_execution');
  }
  if (unexpected.length > 0) {
    issues.push('replay.unexpected_action_execution');
  }
  if (duplicates.length > 0) {
    issues.push('replay.duplicate_action_execution');
  }
  if (unknownEventActionIds > 0) {
    issues.push('replay.unknown_event_action_id');
  }
  if (observedActionExecutionAudit !== observedActionExecutionEvents) {
    issues.push('replay.audit_event_count_mismatch');
  }

  return {
    issues,
    summary: {
      expected_action_executions: expectedActionIds.length,
      observed_action_execution_events: observedActionExecutionEvents,
      observed_action_execution_audit: observedActionExecutionAudit,
      missing_expected_actions: missing.length,
      unexpected_actions: unexpected.length,
      duplicate_actions: duplicates.length,
      unknown_event_action_ids: unknownEventActionIds
    },
    expectedActions: Array.from(expectedByActionId.values()).slice(0, sampleLimit),
    observedActions,
    missingActions: missing.slice(0, sampleLimit),
    unexpectedActions: unexpected.slice(0, sampleLimit),
    duplicateActions: duplicates.slice(0, sampleLimit)
  };
}

async function buildReplayIntegrityPayload({
  app,
  run,
  maxItemsPerStream = 2000,
  sampleLimit = 20,
  generatedAt = nowIso()
}) {
  const [eventEvidence, auditEvidence] = await Promise.all([
    collectLedgerEvidence({
      listFn: app.ledger.listEvents.bind(app.ledger),
      runId: run.id,
      maxItemsPerStream
    }),
    collectLedgerEvidence({
      listFn: app.ledger.listAudit.bind(app.ledger),
      runId: run.id,
      maxItemsPerStream
    })
  ]);

  const replayStats = collectReplayExecutionStats({
    run,
    eventEvidence,
    auditEvidence,
    sampleLimit
  });
  const replayState = replayStateFromContext({
    runStatus: run.status,
    issues: replayStats.issues
  });

  return {
    version: 'v0',
    generated_at: generatedAt,
    run_id: run.id,
    run_status: run.status,
    replay_state: replayState,
    summary: replayStats.summary,
    expected_actions: replayStats.expectedActions,
    observed_actions: replayStats.observedActions,
    missing_actions: replayStats.missingActions,
    unexpected_actions: replayStats.unexpectedActions,
    duplicate_actions: replayStats.duplicateActions,
    issues: replayStats.issues,
    evidence: {
      max_items_per_stream: maxItemsPerStream,
      events: toEvidenceDigest(eventEvidence),
      audit: toEvidenceDigest(auditEvidence)
    }
  };
}

export function buildApp({
  logger = false,
  rootDir = defaultProjectRoot,
  dbPath,
  adapterTimeoutMs = Number(process.env.FLOCKMESH_ADAPTER_TIMEOUT_MS || 1200),
  adapterRetryPolicy,
  connectorRateLimitPolicy,
  incidentExportSigningKeys,
  incidentExportSigningKeyId,
  policyAdminConfig,
  trustedDefaultActorId = process.env.FLOCKMESH_TRUSTED_DEFAULT_ACTOR_ID || '',
  mcpBridgeBearerToken = process.env.FLOCKMESH_MCP_BRIDGE_BEARER_TOKEN || '',
  mcpBridgePublicBaseUrl = process.env.FLOCKMESH_PUBLIC_BASE_URL || ''
} = {}) {
  const app = Fastify({ logger });
  const store = createStore();
  const ledger = new DualLedger({ rootDir });
  const stateDb = new StateDB({ rootDir, dbPath });
  const resolvedRateLimitPolicy = resolveConnectorRateLimitPolicy({
    overridePolicy: connectorRateLimitPolicy
  });
  const resolvedAdapterRetryPolicy = resolveAdapterRetryPolicy({
    overridePolicy: adapterRetryPolicy
  });
  const incidentExportSigning = resolveIncidentExportSigningConfig({
    overrideKeys: incidentExportSigningKeys,
    keyId: incidentExportSigningKeyId
  });

  app.decorate('store', store);
  app.decorate('ledger', ledger);
  app.decorate('stateDb', stateDb);
  app.decorate('policyLibrary', { ...POLICY_LIBRARY });
  app.decorate('connectorRegistry', {});
  app.decorate('connectorAdapters', buildConnectorAdapterRegistry());
  app.decorate('mcpAllowlists', []);
  app.decorate('adapterTimeoutMs', adapterTimeoutMs);
  app.decorate('adapterRetryPolicy', resolvedAdapterRetryPolicy);
  app.decorate('connectorRateLimitPolicy', resolvedRateLimitPolicy);
  app.decorate('incidentExportSigning', incidentExportSigning);
  app.decorate('connectorRateLimiter', createConnectorRateLimiter({
    policy: resolvedRateLimitPolicy
  }));
  app.decorate('agentKitLibrary', {});
  app.decorate('policyAdminConfig', mergePolicyAdminConfigs([policyAdminConfig]));
  app.decorate('trustedDefaultActorId', String(trustedDefaultActorId || '').trim());
  app.decorate('mcpBridgeBearerToken', String(mcpBridgeBearerToken || '').trim());
  app.decorate('mcpBridgePublicBaseUrl', normalizeBaseUrl(mcpBridgePublicBaseUrl));
  app.decorate('integrationRuntime', {
    feishu_webhook_url: ''
  });
  app.decorate('mcpBridgeSessions', new Map());
  app.decorate('mcpBridgeCore', createMcpBridgeCore({
    app,
    defaults: {
      workspaceId: process.env.FLOCKMESH_WORKSPACE_ID || 'wsp_mindverse_cn',
      actorId: String(trustedDefaultActorId || '').trim() || 'usr_yingapple'
    }
  }));

  for (const schema of loadContractSchemas(rootDir)) {
    app.addSchema(schema);
  }

  app.addHook('onReady', async () => {
    stateDb.init();
    await ledger.init();
    const loadedPolicies = await loadPolicyLibraryFromDir({ rootDir });
    const loadedConnectors = await loadConnectorManifestsFromDir({ rootDir });
    const loadedMcpAllowlists = await loadMcpAllowlistsFromDir({ rootDir });
    const loadedPolicyAdminConfig = await loadPolicyAdminConfigFromDir({ rootDir });
    const loadedAgentKits = await loadAgentKitsFromDir({ rootDir });
    Object.assign(app.policyLibrary, loadedPolicies);
    Object.assign(app.connectorRegistry, loadedConnectors);
    app.mcpAllowlists.splice(0, app.mcpAllowlists.length, ...loadedMcpAllowlists);
    Object.assign(app.agentKitLibrary, loadedAgentKits);
    const resolvedPolicyAdminConfig = mergePolicyAdminConfigs([
      loadedPolicyAdminConfig,
      policyAdminConfig
    ]);
    app.policyAdminConfig.version = resolvedPolicyAdminConfig.version;
    app.policyAdminConfig.global_admins = resolvedPolicyAdminConfig.global_admins;
    app.policyAdminConfig.profile_admins = resolvedPolicyAdminConfig.profile_admins;

    const agents = stateDb.listAgents({ limit: 5000, offset: 0 }).items;
    const bindings = stateDb.listBindings({ limit: 5000, offset: 0 }).items;
    const runs = stateDb.listRuns({ limit: 5000, offset: 0 }).items;
    const idempotencyResults = stateDb.listIdempotencyResults({ limit: 5000, offset: 0 });
    const environmentSets = stateDb.listEnvironmentSets({ limit: 5000, offset: 0 }).items;
    const roleBindings = stateDb.listRoleBindings({ limit: 5000, offset: 0 }).items;

    for (const agent of agents) app.store.agents.set(agent.id, agent);
    for (const binding of bindings) app.store.connectorBindings.set(binding.id, binding);
    for (const environmentSet of environmentSets) app.store.environmentSets.set(environmentSet.id, environmentSet);
    for (const roleBinding of roleBindings) app.store.roleBindings.set(roleBinding.id, roleBinding);

    for (const run of runs) {
      app.store.runs.set(run.id, run);
      if (run.status === 'waiting_approval') {
        app.store.pendingApprovals.set(run.id, rebuildPendingApprovalsForRun(run));
      }
    }

    for (const entry of idempotencyResults) {
      app.store.idempotencyResults.set(entry.key, entry.payload);
    }
  });

  app.addHook('onClose', async () => {
    stateDb.close();
  });

  app.register(fastifyStatic, {
    root: path.join(rootDir, 'public'),
    prefix: '/'
  });

  app.get('/', async (_request, reply) => {
    return reply.sendFile('index.html');
  });

  app.get('/health', async () => ({
    ok: true,
    service: 'flockmesh-runtime',
    version: '0.1.0',
    now: nowIso()
  }));

  app.post('/v0/agents', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'role', 'owners'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          role: { type: 'string', minLength: 1, maxLength: 80 },
          owners: {
            type: 'array',
            minItems: 1,
            items: { type: 'string', pattern: '^(usr|svc)_[A-Za-z0-9_-]{4,64}$' },
            uniqueItems: true
          },
          name: { type: 'string', minLength: 1, maxLength: 120 },
          default_policy_profile: { type: 'string' },
          model_policy: {
            type: 'object',
            additionalProperties: false,
            properties: {
              provider: { type: 'string' },
              model: { type: 'string' },
              temperature: { type: 'number' },
              max_tokens: { type: 'integer' }
            }
          }
        }
      },
      response: {
        201: { $ref: 'https://flockmesh.dev/spec/schemas/agent-profile.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const input = request.body;
    const now = nowIso();
    const resolvedAgentPolicy = resolveRuntimePolicyContext({
      policyLibrary: app.policyLibrary,
      agentPolicy: input.default_policy_profile
    }).agent_policy;
    const profile = {
      id: makeId('agt'),
      workspace_id: input.workspace_id,
      name: input.name || input.role,
      role: input.role,
      owners: input.owners,
      model_policy: input.model_policy || {
        provider: 'openai',
        model: 'gpt-5',
        temperature: 0.2,
        max_tokens: 64000
      },
      default_policy_profile: resolvedAgentPolicy,
      status: 'active',
      metadata: {},
      created_at: now,
      updated_at: now
    };

    app.store.agents.set(profile.id, profile);
    app.stateDb.saveAgent(profile);
    reply.code(201);
    return profile;
  });

  app.get('/v0/agents', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: {
          type: 'object',
          additionalProperties: false,
          required: ['total', 'limit', 'offset', 'items'],
          properties: {
            total: { type: 'integer', minimum: 0 },
            limit: { type: 'integer', minimum: 1 },
            offset: { type: 'integer', minimum: 0 },
            items: {
              type: 'array',
              items: { $ref: 'https://flockmesh.dev/spec/schemas/agent-profile.schema.json#' }
            }
          }
        }
      }
    }
  }, async (request) => {
    const { limit, offset } = request.query || {};
    return app.stateDb.listAgents({ limit, offset });
  });

  app.get('/v0/agents/:agent_id', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['agent_id'],
        properties: {
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/agent-profile.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const { agent_id: agentId } = request.params;
    const agent = app.store.agents.get(agentId) || app.stateDb.getAgent(agentId);
    if (!agent) {
      reply.code(404);
      return { message: 'Agent not found' };
    }
    app.store.agents.set(agent.id, agent);
    return agent;
  });

  app.get('/v0/templates/agent-kits', {
    schema: {
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/agent-kit-catalog.schema.json#' }
      }
    }
  }, async () => {
    return listAgentKits({ kitLibrary: app.agentKitLibrary });
  });

  app.post('/v0/agent-blueprints/preview', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'kit_id', 'owners'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          kit_id: { type: 'string', pattern: '^kit_[A-Za-z0-9_-]{4,64}$' },
          owners: {
            type: 'array',
            minItems: 1,
            uniqueItems: true,
            items: { type: 'string', pattern: '^(usr|svc)_[A-Za-z0-9_-]{4,64}$' }
          },
          agent_name: { type: 'string', minLength: 1, maxLength: 120 },
          selected_connector_ids: {
            type: 'array',
            uniqueItems: true,
            items: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
          },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/agent-blueprint-preview.schema.json#' }
      }
    }
  }, async (request, reply) => {
    try {
      const input = request.body;
      return buildAgentBlueprintPreview({
        workspaceId: input.workspace_id,
        kitId: input.kit_id,
        owners: input.owners,
        agentName: input.agent_name,
        selectedConnectorIds: input.selected_connector_ids,
        manifests: app.connectorRegistry,
        policyContext: input.policy_context || defaultPolicyContext(),
        policyLibrary: app.policyLibrary,
        kitLibrary: app.agentKitLibrary
      });
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.post('/v0/agent-blueprints/lint', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'kit_id', 'owners'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          kit_id: { type: 'string', pattern: '^kit_[A-Za-z0-9_-]{4,64}$' },
          owners: {
            type: 'array',
            minItems: 1,
            uniqueItems: true,
            items: { type: 'string', pattern: '^(usr|svc)_[A-Za-z0-9_-]{4,64}$' }
          },
          agent_name: { type: 'string', minLength: 1, maxLength: 120 },
          selected_connector_ids: {
            type: 'array',
            uniqueItems: true,
            items: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
          },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/agent-blueprint-lint-report.schema.json#' }
      }
    }
  }, async (request, reply) => {
    try {
      const input = request.body;
      const preview = buildAgentBlueprintPreview({
        workspaceId: input.workspace_id,
        kitId: input.kit_id,
        owners: input.owners,
        agentName: input.agent_name,
        selectedConnectorIds: input.selected_connector_ids,
        manifests: app.connectorRegistry,
        policyContext: input.policy_context || defaultPolicyContext(),
        policyLibrary: app.policyLibrary,
        kitLibrary: app.agentKitLibrary
      });
      return buildAgentBlueprintLintReport({ preview });
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.post('/v0/agent-blueprints/remediation-plan', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'kit_id', 'owners'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          kit_id: { type: 'string', pattern: '^kit_[A-Za-z0-9_-]{4,64}$' },
          owners: {
            type: 'array',
            minItems: 1,
            uniqueItems: true,
            items: { type: 'string', pattern: '^(usr|svc)_[A-Za-z0-9_-]{4,64}$' }
          },
          agent_name: { type: 'string', minLength: 1, maxLength: 120 },
          selected_connector_ids: {
            type: 'array',
            uniqueItems: true,
            items: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
          },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/agent-blueprint-remediation-plan.schema.json#' }
      }
    }
  }, async (request, reply) => {
    try {
      const input = request.body;
      const policyContext = input.policy_context || defaultPolicyContext();
      const preview = buildAgentBlueprintPreview({
        workspaceId: input.workspace_id,
        kitId: input.kit_id,
        owners: input.owners,
        agentName: input.agent_name,
        selectedConnectorIds: input.selected_connector_ids,
        manifests: app.connectorRegistry,
        policyContext,
        policyLibrary: app.policyLibrary,
        kitLibrary: app.agentKitLibrary
      });
      const lint = buildAgentBlueprintLintReport({ preview });
      return buildAgentBlueprintRemediationPlan({
        preview,
        lint,
        manifests: app.connectorRegistry,
        policyContext,
        policyLibrary: app.policyLibrary,
        kitLibrary: app.agentKitLibrary
      });
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.post('/v0/agent-blueprints/apply', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'kit_id', 'owners'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          kit_id: { type: 'string', pattern: '^kit_[A-Za-z0-9_-]{4,64}$' },
          owners: {
            type: 'array',
            minItems: 1,
            uniqueItems: true,
            items: { type: 'string', pattern: '^(usr|svc)_[A-Za-z0-9_-]{4,64}$' }
          },
          agent_name: { type: 'string', minLength: 1, maxLength: 120 },
          selected_connector_ids: {
            type: 'array',
            uniqueItems: true,
            items: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
          },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          },
          strict_mode: { type: 'boolean' },
          binding_auth_refs: {
            type: 'object',
            additionalProperties: {
              type: 'string',
              pattern: '^sec_[A-Za-z0-9_-]{6,64}$'
            }
          },
          idempotency_key: {
            type: 'string',
            pattern: '^idem_[A-Za-z0-9_-]{8,128}$'
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/agent-blueprint-apply-result.schema.json#' },
        201: { $ref: 'https://flockmesh.dev/spec/schemas/agent-blueprint-apply-result.schema.json#' }
      }
    }
  }, async (request, reply) => {
    try {
      const input = request.body;
      const idempotencyKey = input.idempotency_key
        ? `blueprint.apply:${input.idempotency_key}`
        : '';
      if (idempotencyKey) {
        const persistedReuse = app.stateDb.getIdempotencyResult(idempotencyKey);
        if (persistedReuse && !app.store.idempotencyResults.has(idempotencyKey)) {
          app.store.idempotencyResults.set(idempotencyKey, persistedReuse);
        }

        if (app.store.idempotencyResults.has(idempotencyKey)) {
          const reusedResult = app.store.idempotencyResults.get(idempotencyKey);
          reply.code(200);
          return {
            ...reusedResult,
            reused: true,
            ...(input.idempotency_key ? { idempotency_key: input.idempotency_key } : {})
          };
        }
      }

      const preview = buildAgentBlueprintPreview({
        workspaceId: input.workspace_id,
        kitId: input.kit_id,
        owners: input.owners,
        agentName: input.agent_name,
        selectedConnectorIds: input.selected_connector_ids,
        manifests: app.connectorRegistry,
        policyContext: input.policy_context || defaultPolicyContext(),
        policyLibrary: app.policyLibrary,
        kitLibrary: app.agentKitLibrary
      });

      if (input.strict_mode) {
        const blockingWarning = preview.warnings.find(
          (item) => item.severity === 'critical'
        );
        if (blockingWarning) {
          reply.code(409);
          return {
            message: 'Blueprint apply blocked in strict_mode',
            warning: blockingWarning
          };
        }
      }

      const now = nowIso();
      const resolvedAgentPolicy = resolveRuntimePolicyContext({
        policyLibrary: app.policyLibrary,
        agentPolicy: preview.agent_draft.default_policy_profile
      }).agent_policy;
      const profile = {
        id: makeId('agt'),
        workspace_id: preview.agent_draft.workspace_id,
        name: preview.agent_draft.name,
        role: preview.agent_draft.role,
        owners: preview.agent_draft.owners,
        model_policy: {
          provider: 'openai',
          model: 'gpt-5',
          temperature: 0.2,
          max_tokens: 64000
        },
        default_policy_profile: resolvedAgentPolicy,
        status: 'active',
        metadata: {
          source: 'agent_blueprint_apply',
          kit_id: preview.kit.kit_id
        },
        created_at: now,
        updated_at: now
      };

      app.store.agents.set(profile.id, profile);
      app.stateDb.saveAgent(profile);

      const authRefs = input.binding_auth_refs || {};
      const createdBindings = [];
      const autoAuthConnectors = [];

      for (const draft of preview.connector_plan.proposed_bindings) {
        const authRef = authRefs[draft.connector_id] || makeBlueprintAuthRef({
          workspaceId: preview.workspace_id,
          connectorId: draft.connector_id
        });
        if (!authRefs[draft.connector_id]) {
          autoAuthConnectors.push(draft.connector_id);
        }

        const binding = {
          id: makeId('cnb'),
          workspace_id: preview.workspace_id,
          agent_id: profile.id,
          connector_id: draft.connector_id,
          scopes: draft.scopes,
          auth_ref: authRef,
          risk_profile: draft.risk_profile || 'standard',
          status: 'active',
          created_at: nowIso(),
          updated_at: nowIso()
        };

        app.store.connectorBindings.set(binding.id, binding);
        app.stateDb.saveBinding(binding);
        createdBindings.push(binding);
      }

      for (const connectorId of autoAuthConnectors) {
        const code = 'blueprint.binding.auth_ref_autogenerated';
        const alreadyWarned = preview.warnings.some(
          (item) => item.code === code && item.connector_id === connectorId
        );
        if (alreadyWarned) continue;
        preview.warnings.push({
          code,
          message: `Connector ${connectorId} used an autogenerated auth_ref placeholder.`,
          severity: 'info',
          connector_id: connectorId,
          capability: ''
        });
      }

      const proposedConnectorIds = new Set(
        preview.connector_plan.proposed_bindings.map((item) => item.connector_id)
      );
      const skippedConnectors = preview.connector_plan.connectors
        .filter((item) => !proposedConnectorIds.has(item.connector_id))
        .map((item) => ({
          connector_id: item.connector_id,
          status: item.status,
          reason: item.status
        }));

      const responsePayload = {
        version: 'v0',
        generated_at: nowIso(),
        workspace_id: preview.workspace_id,
        kit_id: preview.kit.kit_id,
        applied: true,
        reused: false,
        ...(input.idempotency_key ? { idempotency_key: input.idempotency_key } : {}),
        created_agent: profile,
        created_bindings: createdBindings,
        skipped_connectors: skippedConnectors,
        auto_auth_connectors: autoAuthConnectors,
        warnings: preview.warnings,
        blueprint: preview
      };

      if (idempotencyKey) {
        app.store.idempotencyResults.set(idempotencyKey, responsePayload);
        app.stateDb.saveIdempotencyResult({
          key: idempotencyKey,
          runId: profile.id,
          payload: responsePayload,
          createdAt: nowIso()
        });
      }

      reply.code(201);
      return responsePayload;
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.post('/v0/quickstart/one-person', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'owner_id', 'template_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          workspace_path: { type: 'string', minLength: 1, maxLength: 1024 },
          owner_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          template_id: { type: 'string', enum: ['weekly_ops_sync', 'incident_response'] },
          agent_name: { type: 'string', minLength: 1, maxLength: 120 },
          connector_ids: {
            type: 'array',
            uniqueItems: true,
            items: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
          },
          trigger_source: { type: 'string', minLength: 1, maxLength: 120 },
          idempotency_key: {
            type: 'string',
            pattern: '^idem_[A-Za-z0-9_-]{8,128}$'
          }
        }
      }
    }
  }, async (request, reply) => {
    try {
      const input = request.body;
      const workspaceId = String(input.workspace_id || '').trim();
      const workspacePath = String(input.workspace_path || '').trim();
      const ownerId = String(input.owner_id || '').trim();
      const actorIdentity = resolveRequestActorId(request, {
        fallbackActorId: app.trustedDefaultActorId
      });
      if (!actorIdentity.ok) {
        reply.code(actorIdentity.errorCode);
        return { message: actorIdentity.message };
      }
      const ownerActorMatch = ensureActorClaimMatches({
        actorId: actorIdentity.actor_id,
        claimedActorId: ownerId,
        fieldName: 'owner_id'
      });
      if (!ownerActorMatch.ok) {
        reply.code(ownerActorMatch.errorCode);
        return { message: ownerActorMatch.message };
      }
      const template = resolveOnePersonQuickstartTemplate(input.template_id);
      const idempotencyKey = input.idempotency_key
        ? `quickstart.one_person:${input.idempotency_key}`
        : '';

      if (idempotencyKey) {
        const persistedReuse = app.stateDb.getIdempotencyResult(idempotencyKey);
        if (persistedReuse && !app.store.idempotencyResults.has(idempotencyKey)) {
          app.store.idempotencyResults.set(idempotencyKey, persistedReuse);
        }

        if (app.store.idempotencyResults.has(idempotencyKey)) {
          const reusedResult = app.store.idempotencyResults.get(idempotencyKey);
          reply.code(200);
          return {
            ...reusedResult,
            reused: true,
            ...(input.idempotency_key ? { idempotency_key: input.idempotency_key } : {})
          };
        }
      }

      const explicitConnectorIds = Array.from(
        new Set(
          (Array.isArray(input.connector_ids) ? input.connector_ids : [])
            .map((value) => String(value || '').trim())
            .filter(Boolean)
        )
      );
      const selectedConnectorIds = explicitConnectorIds.length
        ? explicitConnectorIds
        : template.default_connector_ids;
      const agentName = String(input.agent_name || '').trim() || template.default_agent_name;
      const policyContext = defaultPolicyContext();

      const preview = buildAgentBlueprintPreview({
        workspaceId,
        kitId: template.kit_id,
        owners: [ownerId],
        agentName,
        selectedConnectorIds,
        manifests: app.connectorRegistry,
        policyContext,
        policyLibrary: app.policyLibrary,
        kitLibrary: app.agentKitLibrary
      });

      const now = nowIso();
      const resolvedAgentPolicy = resolveRuntimePolicyContext({
        policyLibrary: app.policyLibrary,
        agentPolicy: preview.agent_draft.default_policy_profile
      }).agent_policy;
      const profile = {
        id: makeId('agt'),
        workspace_id: preview.agent_draft.workspace_id,
        name: preview.agent_draft.name,
        role: preview.agent_draft.role,
        owners: preview.agent_draft.owners,
        model_policy: {
          provider: 'openai',
          model: 'gpt-5',
          temperature: 0.2,
          max_tokens: 64000
        },
        default_policy_profile: resolvedAgentPolicy,
        status: 'active',
        metadata: {
          source: 'quickstart.one_person',
          template_id: template.template_id,
          kit_id: preview.kit.kit_id,
          ...(workspacePath ? { workspace_path: workspacePath } : {})
        },
        created_at: now,
        updated_at: now
      };

      app.store.agents.set(profile.id, profile);
      app.stateDb.saveAgent(profile);

      const createdBindings = [];
      const autoAuthConnectors = [];
      for (const draft of preview.connector_plan.proposed_bindings) {
        const authRef = makeBlueprintAuthRef({
          workspaceId: preview.workspace_id,
          connectorId: draft.connector_id
        });
        autoAuthConnectors.push(draft.connector_id);

        const binding = {
          id: makeId('cnb'),
          workspace_id: preview.workspace_id,
          agent_id: profile.id,
          connector_id: draft.connector_id,
          scopes: draft.scopes,
          auth_ref: authRef,
          risk_profile: draft.risk_profile || 'standard',
          status: 'active',
          created_at: nowIso(),
          updated_at: nowIso()
        };

        app.store.connectorBindings.set(binding.id, binding);
        app.stateDb.saveBinding(binding);
        createdBindings.push(binding);
      }

      const bootstrappedRoleBindings = bootstrapWorkspaceRoleBindings({
        app,
        workspaceId,
        ownerActorId: ownerId
      });

      const proposedConnectorIds = new Set(
        preview.connector_plan.proposed_bindings.map((item) => item.connector_id)
      );
      const skippedConnectors = preview.connector_plan.connectors
        .filter((item) => !proposedConnectorIds.has(item.connector_id))
        .map((item) => ({
          connector_id: item.connector_id,
          status: item.status,
          reason: item.status
        }));

      const runCreateRes = await app.inject({
        method: 'POST',
        url: '/v0/runs',
        headers: {
          'x-flockmesh-actor-id': ownerId
        },
        payload: {
          workspace_id: workspaceId,
          agent_id: profile.id,
          playbook_id: template.playbook_id,
          trigger: {
            type: 'manual',
            source: String(input.trigger_source || '').trim() || template.default_trigger_source,
            actor_id: ownerId,
            at: nowIso()
          }
        }
      });
      const runPayload = runCreateRes.json();
      if (runCreateRes.statusCode !== 202) {
        reply.code(runCreateRes.statusCode);
        return {
          message: 'Quickstart failed while creating run',
          stage: 'run.create',
          detail: runPayload
        };
      }

      const responsePayload = {
        version: 'v0',
        generated_at: nowIso(),
        template_id: template.template_id,
        reused: false,
        ...(input.idempotency_key ? { idempotency_key: input.idempotency_key } : {}),
        quickstart: {
          workspace_id: workspaceId,
          workspace_path: workspacePath || null,
          owner_id: ownerId,
          agent_name: profile.name,
          kit_id: template.kit_id,
          selected_connector_ids: selectedConnectorIds,
          playbook_id: template.playbook_id
        },
        created_agent: profile,
        created_bindings: createdBindings,
        skipped_connectors: skippedConnectors,
        auto_auth_connectors: autoAuthConnectors,
        role_bootstrap: {
          created: bootstrappedRoleBindings.length,
          items: bootstrappedRoleBindings
        },
        run: runPayload,
        blueprint_summary: {
          warning_count: preview.warnings.length,
          critical_warning_count: preview.warnings.filter((item) => item.severity === 'critical').length,
          capability_coverage: preview.capability_coverage,
          approval_forecast: preview.approval_forecast,
          policy_projection_summary: preview.policy_projection.summary
        },
        next_actions: buildOnePersonQuickstartNextActions({
          run: runPayload,
          warnings: preview.warnings,
          createdBindings
        })
      };

      if (idempotencyKey) {
        app.store.idempotencyResults.set(idempotencyKey, responsePayload);
        app.stateDb.saveIdempotencyResult({
          key: idempotencyKey,
          runId: runPayload.id || profile.id,
          payload: responsePayload,
          createdAt: nowIso()
        });
      }

      reply.code(201);
      return responsePayload;
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.get('/v0/access/permissions', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' }
        }
      }
    }
  }, async (request, reply) => {
    const workspaceId = asTrimmedString(request.query?.workspace_id || '');
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }

    const targetActorId = asTrimmedString(request.query?.actor_id || actorIdentity.actor_id);
    if (
      targetActorId !== actorIdentity.actor_id &&
      !actorHasPermission({
        app,
        workspaceId,
        actorId: actorIdentity.actor_id,
        permission: 'role.manage'
      })
    ) {
      reply.code(403);
      return { message: 'Actor lacks permission: role.manage' };
    }

    const bootstrap = !workspaceHasRoleBindings(app, workspaceId);
    const resolved = resolveActorPermissions({
      app,
      workspaceId,
      actorId: targetActorId
    });

    const bootstrapRoles = ['workspace_admin', 'operator', 'auditor'];
    const bootstrapPermissions = Array.from(
      new Set(bootstrapRoles.flatMap((role) => ROLE_PERMISSION_LIBRARY[role] || []))
    ).sort();

    return {
      version: 'v0',
      generated_at: nowIso(),
      workspace_id: workspaceId,
      actor_id: targetActorId,
      bootstrap_available: bootstrap,
      roles: resolved.roles,
      permissions: resolved.permissions,
      bootstrap_roles: bootstrap ? bootstrapRoles : [],
      bootstrap_permissions: bootstrap ? bootstrapPermissions : []
    };
  });

  app.get('/v0/access/role-bindings', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          role: { type: 'string', enum: Array.from(ROLE_NAME_SET) },
          limit: { type: 'integer', minimum: 1, maximum: 1000 },
          offset: { type: 'integer', minimum: 0 }
        }
      }
    }
  }, async (request, reply) => {
    const workspaceId = asTrimmedString(request.query?.workspace_id || '');
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }

    const bootstrap = !workspaceHasRoleBindings(app, workspaceId);
    if (
      !bootstrap &&
      !actorHasPermission({
        app,
        workspaceId,
        actorId: actorIdentity.actor_id,
        permission: 'role.manage'
      })
    ) {
      reply.code(403);
      return { message: 'Actor lacks permission: role.manage' };
    }

    const page = app.stateDb.listRoleBindings({
      workspaceId,
      limit: request.query?.limit,
      offset: request.query?.offset
    });

    const actorFilter = asTrimmedString(request.query?.actor_id || '');
    const roleFilter = asTrimmedString(request.query?.role || '');
    const filtered = page.items.filter((item) => {
      if (actorFilter && asTrimmedString(item.actor_id) !== actorFilter) return false;
      if (roleFilter && asTrimmedString(item.role) !== roleFilter) return false;
      return true;
    });

    return {
      total: filtered.length,
      limit: page.limit,
      offset: page.offset,
      bootstrap_available: bootstrap,
      items: filtered
    };
  });

  app.post('/v0/access/role-bindings', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'actor_id', 'role'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          role: { type: 'string', enum: Array.from(ROLE_NAME_SET) },
          reason: { type: 'string', maxLength: 300 }
        }
      }
    }
  }, async (request, reply) => {
    const body = request.body;
    const workspaceId = asTrimmedString(body.workspace_id || '');
    const permission = ensureActorPermission({
      app,
      request,
      workspaceId,
      permission: 'role.manage',
      allowWorkspaceBootstrap: true
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    if (permission.bootstrap && asTrimmedString(body.actor_id) !== permission.actor_id) {
      reply.code(403);
      return { message: 'Bootstrap role binding can only target current actor' };
    }

    const role = normalizeRoleName(body.role);
    const actorId = asTrimmedString(body.actor_id || '');
    const existing = listActorRoleBindings({
      app,
      workspaceId,
      actorId
    }).find((binding) => binding.role === role);

    if (existing) {
      reply.code(200);
      return {
        ...existing,
        reused: true
      };
    }

    const now = nowIso();
    const binding = {
      id: makeId('rlb'),
      workspace_id: workspaceId,
      actor_id: actorId,
      role,
      source: permission.bootstrap ? 'workspace_bootstrap_manual' : 'manual_grant',
      reason: asTrimmedString(body.reason || ''),
      created_at: now,
      updated_at: now
    };

    app.store.roleBindings.set(binding.id, binding);
    app.stateDb.saveRoleBinding(binding);
    reply.code(201);
    return binding;
  });

  app.get('/v0/environments/sets', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          mode: { type: 'string', enum: Array.from(ACCESS_MODE_SET) },
          scope: { type: 'string', enum: Array.from(ENV_SCOPE_SET) },
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      }
    }
  }, async (request, reply) => {
    const workspaceId = asTrimmedString(request.query?.workspace_id || '');
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }

    const hasWorkspaceRole = actorHasAnyWorkspaceRole({
      app,
      workspaceId,
      actorId: actorIdentity.actor_id
    });
    if (!hasWorkspaceRole && workspaceHasRoleBindings(app, workspaceId)) {
      reply.code(403);
      return { message: 'Actor is not assigned in workspace' };
    }

    const page = app.stateDb.listEnvironmentSets({
      workspaceId,
      limit: request.query?.limit,
      offset: request.query?.offset
    });
    const modeFilter = asTrimmedString(request.query?.mode || '');
    const scopeFilter = asTrimmedString(request.query?.scope || '');
    const filtered = page.items.filter((item) => {
      if (modeFilter && asTrimmedString(item.mode) !== modeFilter) return false;
      if (scopeFilter && asTrimmedString(item.scope) !== scopeFilter) return false;
      return true;
    });

    return {
      total: filtered.length,
      limit: page.limit,
      offset: page.offset,
      items: filtered.map((item) => sanitizeEnvironmentSet(item))
    };
  });

  app.get('/v0/environments/effective', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          mode: { type: 'string', enum: Array.from(ACCESS_MODE_SET) },
          include_values: { type: 'boolean' }
        }
      }
    }
  }, async (request, reply) => {
    const workspaceId = asTrimmedString(request.query?.workspace_id || '');
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }

    const callerActorId = actorIdentity.actor_id;
    const targetActorId = asTrimmedString(request.query?.actor_id || callerActorId);
    const modeFilter = asTrimmedString(request.query?.mode || '');
    const hasBindings = workspaceHasRoleBindings(app, workspaceId);
    const callerAssigned = actorHasAnyWorkspaceRole({
      app,
      workspaceId,
      actorId: callerActorId
    });
    if (hasBindings && !callerAssigned) {
      reply.code(403);
      return { message: 'Actor is not assigned in workspace' };
    }

    const callerCanManageEnvironment = actorHasPermission({
      app,
      workspaceId,
      actorId: callerActorId,
      permission: 'environment.manage'
    });
    const callerCanManageRole = actorHasPermission({
      app,
      workspaceId,
      actorId: callerActorId,
      permission: 'role.manage'
    });

    if (
      targetActorId !== callerActorId &&
      hasBindings &&
      !callerCanManageEnvironment &&
      !callerCanManageRole
    ) {
      reply.code(403);
      return { message: 'Actor lacks permission: environment.manage or role.manage' };
    }

    const effective = buildEffectiveEnvironmentEntries({
      app,
      workspaceId,
      targetActorId,
      modeFilter
    });
    const includePlainValues = request.query?.include_values === true
      && (!hasBindings || callerCanManageEnvironment || callerCanManageRole || targetActorId === callerActorId);

    return {
      version: 'v0',
      generated_at: nowIso(),
      workspace_id: workspaceId,
      actor_id: targetActorId,
      mode_filter: modeFilter || 'all',
      include_values: includePlainValues,
      target_roles: effective.target_roles,
      matched_sets: effective.matched_sets,
      total: effective.items.length,
      items: effective.items.map((entry) =>
        sanitizeEffectiveEnvironmentEntry(entry, { includePlainValues })
      )
    };
  });

  app.get('/v0/environments/sets/:set_id', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['set_id'],
        properties: {
          set_id: { type: 'string', pattern: '^envs_[A-Za-z0-9_-]{6,64}$' }
        }
      }
    }
  }, async (request, reply) => {
    const { set_id: setId } = request.params;
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }

    const environmentSet = app.store.environmentSets.get(setId) || app.stateDb.getEnvironmentSet(setId);
    if (!environmentSet) {
      reply.code(404);
      return { message: 'Environment set not found' };
    }
    app.store.environmentSets.set(environmentSet.id, environmentSet);

    if (
      workspaceHasRoleBindings(app, environmentSet.workspace_id) &&
      !actorHasAnyWorkspaceRole({
        app,
        workspaceId: environmentSet.workspace_id,
        actorId: actorIdentity.actor_id
      })
    ) {
      reply.code(403);
      return { message: 'Actor is not assigned in workspace' };
    }

    return sanitizeEnvironmentSet(environmentSet);
  });

  app.post('/v0/environments/sets', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'name', 'entries'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          mode: { type: 'string', enum: Array.from(ACCESS_MODE_SET) },
          scope: { type: 'string', enum: Array.from(ENV_SCOPE_SET) },
          name: { type: 'string', minLength: 2, maxLength: 120 },
          description: { type: 'string', maxLength: 400 },
          status: { type: 'string', enum: ['active', 'inactive'] },
          entries: {
            type: 'array',
            minItems: 1,
            maxItems: 300,
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['key', 'value'],
              properties: {
                key: { type: 'string', minLength: 2, maxLength: 128 },
                provider: { type: 'string', minLength: 1, maxLength: 40 },
                value: { type: 'string', minLength: 1, maxLength: 4000 },
                visibility: { type: 'string', enum: Array.from(ENV_VISIBILITY_SET) },
                target: { type: 'string', maxLength: 120 }
              }
            }
          }
        }
      }
    }
  }, async (request, reply) => {
    const body = request.body;
    const workspaceId = asTrimmedString(body.workspace_id || '');
    const permission = ensureActorPermission({
      app,
      request,
      workspaceId,
      permission: 'environment.manage',
      allowWorkspaceBootstrap: true
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    let entries;
    try {
      entries = normalizeEnvironmentEntries(body.entries);
    } catch (err) {
      reply.code(400);
      return { message: String(err.message || err) };
    }

    const now = nowIso();
    const environmentSet = {
      id: makeId('envs'),
      workspace_id: workspaceId,
      mode: normalizeAccessMode(body.mode),
      scope: normalizeEnvironmentScope(body.scope),
      name: asTrimmedString(body.name),
      description: asTrimmedString(body.description || ''),
      status: asTrimmedString(body.status || 'active') === 'inactive' ? 'inactive' : 'active',
      entries,
      created_by: permission.actor_id,
      updated_by: permission.actor_id,
      created_at: now,
      updated_at: now
    };

    app.store.environmentSets.set(environmentSet.id, environmentSet);
    app.stateDb.saveEnvironmentSet(environmentSet);

    if (permission.bootstrap) {
      bootstrapWorkspaceRoleBindings({
        app,
        workspaceId,
        ownerActorId: permission.actor_id
      });
    }

    reply.code(201);
    return sanitizeEnvironmentSet(environmentSet);
  });

  app.post('/v0/environments/sets/:set_id/entries', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['set_id'],
        properties: {
          set_id: { type: 'string', pattern: '^envs_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['entries'],
        properties: {
          entries: {
            type: 'array',
            minItems: 1,
            maxItems: 300,
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['key', 'value'],
              properties: {
                key: { type: 'string', minLength: 2, maxLength: 128 },
                provider: { type: 'string', minLength: 1, maxLength: 40 },
                value: { type: 'string', minLength: 1, maxLength: 4000 },
                visibility: { type: 'string', enum: Array.from(ENV_VISIBILITY_SET) },
                target: { type: 'string', maxLength: 120 }
              }
            }
          }
        }
      }
    }
  }, async (request, reply) => {
    const { set_id: setId } = request.params;
    const environmentSet = app.store.environmentSets.get(setId) || app.stateDb.getEnvironmentSet(setId);
    if (!environmentSet) {
      reply.code(404);
      return { message: 'Environment set not found' };
    }
    app.store.environmentSets.set(environmentSet.id, environmentSet);

    const permission = ensureActorPermission({
      app,
      request,
      workspaceId: environmentSet.workspace_id,
      permission: 'environment.manage'
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    let patchEntries;
    try {
      patchEntries = normalizeEnvironmentEntries(request.body.entries);
    } catch (err) {
      reply.code(400);
      return { message: String(err.message || err) };
    }

    environmentSet.entries = mergeEnvironmentEntries(environmentSet.entries || [], patchEntries);
    environmentSet.updated_by = permission.actor_id;
    environmentSet.updated_at = nowIso();
    app.store.environmentSets.set(environmentSet.id, environmentSet);
    app.stateDb.saveEnvironmentSet(environmentSet);
    return sanitizeEnvironmentSet(environmentSet);
  });

  app.post('/v0/environments/sets/:set_id/activate', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['set_id'],
        properties: {
          set_id: { type: 'string', pattern: '^envs_[A-Za-z0-9_-]{6,64}$' }
        }
      }
    }
  }, async (request, reply) => {
    const { set_id: setId } = request.params;
    const environmentSet = app.store.environmentSets.get(setId) || app.stateDb.getEnvironmentSet(setId);
    if (!environmentSet) {
      reply.code(404);
      return { message: 'Environment set not found' };
    }
    app.store.environmentSets.set(environmentSet.id, environmentSet);

    const permission = ensureActorPermission({
      app,
      request,
      workspaceId: environmentSet.workspace_id,
      permission: 'environment.manage'
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    const allSets = app.stateDb.listEnvironmentSets({
      workspaceId: environmentSet.workspace_id,
      limit: 5000,
      offset: 0
    }).items;
    for (const item of allSets) {
      if (item.mode !== environmentSet.mode || item.scope !== environmentSet.scope) continue;
      if (item.id === environmentSet.id) continue;
      if (item.status === 'inactive') continue;
      item.status = 'inactive';
      item.updated_by = permission.actor_id;
      item.updated_at = nowIso();
      app.store.environmentSets.set(item.id, item);
      app.stateDb.saveEnvironmentSet(item);
    }

    environmentSet.status = 'active';
    environmentSet.updated_by = permission.actor_id;
    environmentSet.updated_at = nowIso();
    app.store.environmentSets.set(environmentSet.id, environmentSet);
    app.stateDb.saveEnvironmentSet(environmentSet);
    return sanitizeEnvironmentSet(environmentSet);
  });

  app.post('/v0/environments/sets/:set_id/apply-runtime', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['set_id'],
        properties: {
          set_id: { type: 'string', pattern: '^envs_[A-Za-z0-9_-]{6,64}$' }
        }
      }
    }
  }, async (request, reply) => {
    const { set_id: setId } = request.params;
    const environmentSet = app.store.environmentSets.get(setId) || app.stateDb.getEnvironmentSet(setId);
    if (!environmentSet) {
      reply.code(404);
      return { message: 'Environment set not found' };
    }
    app.store.environmentSets.set(environmentSet.id, environmentSet);

    const permission = ensureActorPermission({
      app,
      request,
      workspaceId: environmentSet.workspace_id,
      permission: 'environment.manage'
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    const feishuWebhook = resolveFeishuWebhookFromEnvironmentSet(environmentSet);
    app.integrationRuntime.feishu_webhook_url = feishuWebhook;

    return {
      version: 'v0',
      applied_at: nowIso(),
      set_id: environmentSet.id,
      workspace_id: environmentSet.workspace_id,
      runtime_updates: {
        feishu_webhook_applied: Boolean(feishuWebhook)
      },
      feishu_status: resolveFeishuConnectionStatus(app)
    };
  });

  app.post('/v0/environments/sets/:set_id/verify', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['set_id'],
        properties: {
          set_id: { type: 'string', pattern: '^envs_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          probe_mode: { type: 'string', enum: Array.from(ENV_VERIFY_PROBE_MODE_SET) },
          timeout_ms: { type: 'integer', minimum: 500, maximum: 10000 }
        }
      }
    }
  }, async (request, reply) => {
    const { set_id: setId } = request.params;
    const environmentSet = app.store.environmentSets.get(setId) || app.stateDb.getEnvironmentSet(setId);
    if (!environmentSet) {
      reply.code(404);
      return { message: 'Environment set not found' };
    }
    app.store.environmentSets.set(environmentSet.id, environmentSet);

    const permission = ensureActorPermission({
      app,
      request,
      workspaceId: environmentSet.workspace_id,
      permission: 'environment.manage'
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    const probeMode = normalizeVerifyProbeMode(request.body?.probe_mode);
    const timeoutMs = Math.min(
      Math.max(Number(request.body?.timeout_ms || 4000), 500),
      10000
    );
    const report = verifyEnvironmentSet(environmentSet);
    const connectivity = probeMode === 'connectivity'
      ? await probeEnvironmentSetConnectivity(environmentSet, { timeoutMs })
      : null;

    return {
      version: 'v0',
      verified_at: nowIso(),
      probe_mode: probeMode,
      timeout_ms: timeoutMs,
      set: sanitizeEnvironmentSet(environmentSet),
      report,
      ...(connectivity ? { connectivity } : {})
    };
  });

  app.post('/v0/connectors/bindings', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'connector_id', 'scopes', 'auth_ref'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          connector_id: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' },
          scopes: {
            type: 'array',
            minItems: 1,
            uniqueItems: true,
            items: { type: 'string', pattern: '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$' }
          },
          auth_ref: { type: 'string', pattern: '^sec_[A-Za-z0-9_-]{6,64}$' },
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' },
          risk_profile: { type: 'string', enum: ['standard', 'restricted', 'high_control'] }
        }
      },
      response: {
        201: { $ref: 'https://flockmesh.dev/spec/schemas/connector-binding.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const input = request.body;
    if (input.agent_id) {
      const agent = app.store.agents.get(input.agent_id) || app.stateDb.getAgent(input.agent_id);
      if (!agent) {
        reply.code(404);
        return { message: 'Agent not found' };
      }
      app.store.agents.set(agent.id, agent);

      if (agent.workspace_id !== input.workspace_id) {
        reply.code(409);
        return { message: 'Agent workspace does not match binding workspace_id' };
      }
    }

    const now = nowIso();
    const binding = {
      id: makeId('cnb'),
      workspace_id: input.workspace_id,
      agent_id: input.agent_id,
      connector_id: input.connector_id,
      scopes: input.scopes,
      auth_ref: input.auth_ref,
      risk_profile: input.risk_profile || 'standard',
      status: 'active',
      created_at: now,
      updated_at: now
    };

    app.store.connectorBindings.set(binding.id, binding);
    app.stateDb.saveBinding(binding);
    reply.code(201);
    return binding;
  });

  app.get('/v0/connectors/bindings', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: {
          type: 'object',
          additionalProperties: false,
          required: ['total', 'limit', 'offset', 'items'],
          properties: {
            total: { type: 'integer', minimum: 0 },
            limit: { type: 'integer', minimum: 1 },
            offset: { type: 'integer', minimum: 0 },
            items: {
              type: 'array',
              items: { $ref: 'https://flockmesh.dev/spec/schemas/connector-binding.schema.json#' }
            }
          }
        }
      }
    }
  }, async (request) => {
    const { limit, offset } = request.query || {};
    return app.stateDb.listBindings({ limit, offset });
  });

  app.get('/v0/connectors/manifests', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          category: { type: 'string', enum: ['office_channel', 'office_system', 'agent_protocol'] },
          protocol: { type: 'string', enum: ['sdk', 'http', 'mcp', 'a2a'] },
          trust_level: { type: 'string', enum: ['sandbox', 'standard', 'high_control'] },
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: {
          type: 'object',
          additionalProperties: false,
          required: ['total', 'limit', 'offset', 'items'],
          properties: {
            total: { type: 'integer', minimum: 0 },
            limit: { type: 'integer', minimum: 1 },
            offset: { type: 'integer', minimum: 0 },
            items: {
              type: 'array',
              items: { $ref: 'https://flockmesh.dev/spec/schemas/connector-manifest.schema.json#' }
            }
          }
        }
      }
    }
  }, async (request) => {
    const { category, protocol, trust_level: trustLevel, limit, offset } = request.query || {};
    const filtered = Object.fromEntries(
      Object.entries(app.connectorRegistry).filter(([, manifest]) => {
        if (category && manifest.category !== category) return false;
        if (protocol && manifest.protocol !== protocol) return false;
        if (trustLevel && manifest.trust_level !== trustLevel) return false;
        return true;
      })
    );

    return listConnectorManifestsPage(filtered, { limit, offset });
  });

  app.get('/v0/connectors/health', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          connector_id: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/connector-health.schema.json#' }
      }
    }
  }, async (request) => {
    const bindings = app.stateDb.listBindings({ limit: 5000, offset: 0 }).items;
    return buildConnectorHealthSummary({
      manifests: app.connectorRegistry,
      bindings,
      connectorId: request.query?.connector_id
    });
  });

  app.get('/v0/connectors/drift', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          connector_id: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/connector-drift.schema.json#' }
      }
    }
  }, async (request) => {
    const bindings = app.stateDb.listBindings({ limit: 5000, offset: 0 }).items;
    return detectScopeDrift({
      manifests: app.connectorRegistry,
      bindings,
      connectorId: request.query?.connector_id
    });
  });

  app.get('/v0/connectors/mcp/allowlists', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' }
        }
      }
    }
  }, async (request) => {
    const { workspace_id: workspaceId, agent_id: agentId } = request.query || {};

    const items = app.mcpAllowlists
      .map((doc) => ({
        version: doc.version,
        name: doc.name,
        rules: doc.rules.filter((rule) => {
          if (workspaceId && rule.workspace_id !== workspaceId) return false;
          if (agentId && ![agentId, '*'].includes(rule.agent_id)) return false;
          return true;
        })
      }))
      .filter((doc) => doc.rules.length > 0 || (!workspaceId && !agentId));

    return {
      total: items.length,
      items
    };
  });

  app.get('/v0/integrations/feishu/status', async () => {
    return {
      version: 'v0',
      generated_at: nowIso(),
      ...resolveFeishuConnectionStatus(app)
    };
  });

  app.post('/v0/integrations/feishu/webhook', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          webhook_url: { type: 'string', minLength: 1, maxLength: 2000 },
          clear: { type: 'boolean' }
        }
      }
    }
  }, async (request, reply) => {
    const clear = request.body?.clear === true;
    const webhookUrl = asTrimmedString(request.body?.webhook_url || '');

    if (!clear && !webhookUrl) {
      reply.code(400);
      return { message: 'webhook_url is required unless clear=true' };
    }

    if (clear) {
      app.integrationRuntime.feishu_webhook_url = '';
      return {
        version: 'v0',
        updated_at: nowIso(),
        status: 'cleared',
        ...resolveFeishuConnectionStatus(app)
      };
    }

    try {
      const parsed = new URL(webhookUrl);
      if (parsed.protocol !== 'https:') {
        reply.code(400);
        return { message: 'webhook_url must use https protocol' };
      }
    } catch {
      reply.code(400);
      return { message: 'webhook_url must be a valid URL' };
    }

    app.integrationRuntime.feishu_webhook_url = webhookUrl;
    return {
      version: 'v0',
      updated_at: nowIso(),
      status: 'updated',
      ...resolveFeishuConnectionStatus(app)
    };
  });

  app.post('/v0/integrations/feishu/test-message', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          channel: { type: 'string', minLength: 1, maxLength: 120 },
          content: { type: 'string', minLength: 1, maxLength: 4000 }
        }
      }
    }
  }, async (request, reply) => {
    const adapter = app.connectorAdapters.con_feishu_official;
    if (!adapter) {
      reply.code(501);
      return { message: 'Feishu adapter not implemented' };
    }

    const payload = request.body || {};
    const channel = asTrimmedString(payload.channel || 'flockmesh-onboarding');
    const content = asTrimmedString(payload.content || 'FlockMesh onboarding Feishu connectivity test');

    try {
      const adapterResult = await withTimeout(
        () => adapter.invoke({
          runId: `run_probe_${shortHash({ at: nowIso(), channel, content })}`,
          capability: 'message.send',
          parameters: { channel, content },
          attempt: 1,
          runtime: {
            feishuWebhookUrl: resolveActiveFeishuWebhook(app).webhook_url
          }
        }),
        app.adapterTimeoutMs
      );

      return {
        version: 'v0',
        generated_at: nowIso(),
        ...resolveFeishuConnectionStatus(app),
        adapter_result: adapterResult
      };
    } catch (err) {
      if (err instanceof AdapterCapabilityError) {
        reply.code(409);
        return { message: err.message };
      }
      if (err instanceof AdapterTimeoutError) {
        reply.code(503);
        return {
          message: 'Feishu test message timed out',
          reason_code: 'connector.invoke.timeout',
          timeout_ms: err.timeoutMs
        };
      }
      throw err;
    }
  });

  app.get('/v0/integrations/agent-ide-profile', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          workspace_path: { type: 'string', minLength: 1, maxLength: 1024 },
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' }
        }
      }
    }
  }, async (request) => {
    const workspaceId = request.query?.workspace_id || '';
    const workspacePath = request.query?.workspace_path || '';
    const agentId = request.query?.agent_id || '';
    const actorId = request.query?.actor_id || '';
    const publicBaseUrl = resolvePublicBaseUrl({ request, app });

    const allowlists = app.mcpAllowlists
      .map((doc) => ({
        version: doc.version,
        name: doc.name,
        rules: doc.rules.filter((rule) => {
          if (rule.workspace_id !== workspaceId) return false;
          if (agentId && ![agentId, '*'].includes(rule.agent_id)) return false;
          return true;
        })
      }))
      .filter((doc) => doc.rules.length > 0);

    return buildAgentIdeBridgeProfile({
      workspaceId,
      agentId,
      actorId,
      workspacePath,
      rootDir,
      allowlists,
      mcpBridgeBearerTokenEnabled: Boolean(app.mcpBridgeBearerToken),
      streamableHttpUrl: `${publicBaseUrl}/v0/mcp/stream`,
      protocolVersion: MCP_BRIDGE_PROTOCOL_VERSION
    });
  });

  app.get('/v0/workstation/readiness', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          mode: { type: 'string', enum: Array.from(ACCESS_MODE_SET) },
          workspace_path: { type: 'string', minLength: 1, maxLength: 1024 },
          include_probe: { type: 'boolean' },
          timeout_ms: { type: 'integer', minimum: 500, maximum: 10000 }
        }
      }
    }
  }, async (request, reply) => {
    const workspaceId = asTrimmedString(request.query?.workspace_id || '');
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }

    const callerActorId = actorIdentity.actor_id;
    const targetActorId = asTrimmedString(request.query?.actor_id || callerActorId);
    const hasBindings = workspaceHasRoleBindings(app, workspaceId);
    const callerAssigned = actorHasAnyWorkspaceRole({
      app,
      workspaceId,
      actorId: callerActorId
    });
    if (hasBindings && !callerAssigned) {
      reply.code(403);
      return { message: 'Actor is not assigned in workspace' };
    }
    if (
      targetActorId !== callerActorId &&
      !actorHasPermission({
        app,
        workspaceId,
        actorId: callerActorId,
        permission: 'role.manage'
      })
    ) {
      reply.code(403);
      return { message: 'Actor lacks permission: role.manage' };
    }

    const modeFilterRaw = asTrimmedString(request.query?.mode || '');
    const modeFilter = ACCESS_MODE_SET.has(modeFilterRaw) ? modeFilterRaw : '';
    const workspacePath = asTrimmedString(request.query?.workspace_path || '');
    const includeProbe = request.query?.include_probe === true;
    const timeoutMs = Math.min(
      Math.max(Number(request.query?.timeout_ms || 2200), 500),
      10000
    );

    return await buildWorkstationReadinessSnapshot({
      app,
      request,
      workspaceId,
      actorId: targetActorId,
      modeFilter,
      workspacePath,
      includeProbe,
      probeTimeoutMs: timeoutMs,
      rootDir
    });
  });

  app.get('/v0/mcp/stream', async (request, reply) => {
    if (!authorizeMcpBridgeRequest(app, request, reply)) return;

    pruneMcpBridgeSessions(app);

    const incomingSessionId = String(request.headers[MCP_SESSION_HEADER] || '').trim();
    const session = incomingSessionId ? app.mcpBridgeSessions.get(incomingSessionId) : null;
    const protocolVersion = session?.protocolVersion || resolveMcpProtocolVersionFromRequest(request);
    setMcpProtocolHeader(reply, protocolVersion);

    if (incomingSessionId && session?.initialized) {
      reply.header(MCP_SESSION_HEADER, incomingSessionId);
    }

    reply
      .header('cache-control', 'no-cache, no-transform')
      .header('connection', 'keep-alive')
      .type('text/event-stream; charset=utf-8');

    return ': flockmesh mcp stream ready\n\n';
  });

  app.post('/v0/mcp/stream', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: true
      }
    }
  }, async (request, reply) => {
    if (!authorizeMcpBridgeRequest(app, request, reply)) return;

    pruneMcpBridgeSessions(app);

    const body = request.body;
    const hasId = Object.prototype.hasOwnProperty.call(body || {}, 'id');
    const id = hasId ? body.id : null;
    const isNotification = !hasId || id === null;
    const method = String(body?.method || '').trim();
    const jsonrpcVersion = String(body?.jsonrpc || '').trim();
    const incomingSessionId = String(request.headers[MCP_SESSION_HEADER] || '').trim();
    const session = incomingSessionId ? app.mcpBridgeSessions.get(incomingSessionId) : null;
    const headerProtocolVersion = session?.protocolVersion || resolveMcpProtocolVersionFromRequest(request);
    setMcpProtocolHeader(reply, headerProtocolVersion);

    if (jsonrpcVersion !== '2.0' || !method) {
      if (isNotification) {
        reply.code(202);
        return '';
      }
      return mcpJsonRpcError(id, -32600, 'Invalid Request');
    }

    if (method === 'initialize') {
      const requestedProtocolVersion = String(body?.params?.protocolVersion || '').trim()
        || resolveMcpProtocolVersionFromRequest(request);
      const protocolVersion = requestedProtocolVersion || MCP_BRIDGE_PROTOCOL_VERSION;
      const sessionId = incomingSessionId || makeId('mcp_session');
      app.mcpBridgeSessions.set(sessionId, {
        initialized: true,
        protocolVersion,
        updated_at: nowIso(),
        updated_at_ms: nowMs()
      });
      reply.header(MCP_SESSION_HEADER, sessionId);
      setMcpProtocolHeader(reply, protocolVersion);

      if (isNotification) {
        reply.code(202);
        return '';
      }

      return mcpJsonRpcResult(id, {
        protocolVersion,
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        serverInfo: {
          name: 'flockmesh-mcp-bridge-http',
          version: '0.1.0'
        },
        instructions: [
          'Streamable HTTP bridge for Codex/Claude enterprise workflows.',
          'Use core tools only; mutating operations stay policy-gated and audited.'
        ].join(' ')
      });
    }

    if (method === 'notifications/initialized') {
      reply.code(202);
      return '';
    }

    if (!session?.initialized) {
      if (isNotification) {
        reply.code(202);
        return '';
      }
      return mcpJsonRpcError(id, -32002, 'Server not initialized');
    }

    if (incomingSessionId) {
      reply.header(MCP_SESSION_HEADER, incomingSessionId);
      setMcpProtocolHeader(reply, session.protocolVersion || headerProtocolVersion);
      session.updated_at = nowIso();
      session.updated_at_ms = nowMs();
      app.mcpBridgeSessions.set(incomingSessionId, session);
    }

    if (method === 'ping') {
      if (isNotification) {
        reply.code(202);
        return '';
      }
      return mcpJsonRpcResult(id, {});
    }

    if (method === 'tools/list') {
      if (isNotification) {
        reply.code(202);
        return '';
      }
      return mcpJsonRpcResult(id, {
        tools: app.mcpBridgeCore.listTools()
      });
    }

    if (method === 'tools/call') {
      if (isNotification) {
        reply.code(202);
        return '';
      }

      const name = String(body?.params?.name || '').trim();
      const args = body?.params?.arguments;
      try {
        const payload = await app.mcpBridgeCore.callTool(name, args);
        return mcpJsonRpcResult(id, mcpToolCallResult(payload));
      } catch (err) {
        return mcpJsonRpcResult(id, mcpToolCallResult({
          message: String(err?.message || err),
          ...(err?.statusCode ? { status_code: err.statusCode } : {}),
          ...(err?.payload ? { payload: err.payload } : {})
        }, { isError: true }));
      }
    }

    if (isNotification) {
      reply.code(202);
      return '';
    }
    return mcpJsonRpcError(id, -32601, `Method not found: ${method}`);
  });

  app.get('/v0/connectors/rate-limits', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          connector_id: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
        }
      }
    }
  }, async (request) => {
    const connectorId = request.query?.connector_id;
    const policy = app.connectorRateLimitPolicy;

    if (!connectorId) {
      return policy;
    }

    const bucket = policy.connectors[connectorId] || policy.default;
    return {
      connector_id: connectorId,
      source: policy.connectors[connectorId] ? 'connector' : 'default',
      limit: bucket.limit,
      window_ms: bucket.window_ms
    };
  });

  app.post('/v0/connectors/adapters/:connector_id/simulate', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['connector_id'],
        properties: {
          connector_id: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: [
          'run_id',
          'workspace_id',
          'agent_id',
          'connector_binding_id',
          'capability',
          'side_effect',
          'risk_hint',
          'parameters',
          'initiated_by'
        ],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' },
          connector_binding_id: { type: 'string', pattern: '^cnb_[A-Za-z0-9_-]{6,64}$' },
          capability: { type: 'string', pattern: '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$' },
          side_effect: { type: 'string', enum: ['none', 'mutation'] },
          risk_hint: { type: 'string', enum: ['R0', 'R1', 'R2', 'R3'] },
          idempotency_key: { type: 'string', minLength: 8, maxLength: 128 },
          parameters: { type: 'object' },
          initiated_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/connector-adapter-simulation-result.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const { connector_id: connectorId } = request.params;
    const body = request.body;
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }
    const initiatedActorMatch = ensureActorClaimMatches({
      actorId: actorIdentity.actor_id,
      claimedActorId: body.initiated_by,
      fieldName: 'initiated_by'
    });
    if (!initiatedActorMatch.ok) {
      reply.code(initiatedActorMatch.errorCode);
      return { message: initiatedActorMatch.message };
    }
    const manifest = app.connectorRegistry[connectorId];
    if (!manifest) {
      reply.code(404);
      return { message: 'Connector manifest not found' };
    }

    const adapter = app.connectorAdapters[connectorId];
    if (!adapter) {
      reply.code(501);
      return { message: 'Connector adapter not implemented' };
    }

    const binding = findBindingById(app, body.connector_binding_id);
    if (!binding) {
      reply.code(404);
      return { message: 'Connector binding not found' };
    }

    if (binding.connector_id !== connectorId) {
      reply.code(409);
      return { message: 'Binding connector does not match request connector_id' };
    }

    if (binding.workspace_id !== body.workspace_id) {
      reply.code(409);
      return { message: 'Binding workspace does not match request workspace_id' };
    }

    if (binding.agent_id && binding.agent_id !== body.agent_id) {
      reply.code(409);
      return { message: 'Binding agent does not match request agent_id' };
    }

    if (binding.status !== 'active') {
      reply.code(409);
      return { message: 'Binding is not active' };
    }

    if (!binding.scopes.includes(body.capability)) {
      reply.code(403);
      return { message: 'Capability is outside binding scope' };
    }

    if (!manifest.capabilities.includes(body.capability)) {
      reply.code(409);
      return { message: 'Capability is not declared by connector manifest' };
    }

    const allowlistDecision = evaluateMcpAllowlistForRequest({
      app,
      body,
      connectorId
    });
    if (!allowlistDecision.allowed) {
      reply.code(403);
      return {
        message: 'MCP invocation blocked by allowlist',
        reason_code: allowlistDecision.reason_code
      };
    }

    const actionIntent = buildAdapterActionIntent({
      runId: body.run_id,
      bindingId: binding.id,
      connectorId,
      capability: body.capability,
      sideEffect: body.side_effect,
      riskHint: body.risk_hint,
      idempotencyKey: body.idempotency_key,
      parameters: body.parameters
    });

    const policyDecision = evaluatePolicy({
      runId: body.run_id,
      actionIntent,
      policyContext: body.policy_context || defaultPolicyContext(),
      policyLibrary: app.policyLibrary
    });

    let adapterPreview;
    try {
      adapterPreview = await withTimeout(
        () => adapter.simulate({
          runId: body.run_id,
          capability: body.capability,
          parameters: body.parameters,
          runtime: {
            feishuWebhookUrl: resolveActiveFeishuWebhook(app).webhook_url
          }
        }),
        app.adapterTimeoutMs
      );
    } catch (err) {
      if (err instanceof AdapterCapabilityError) {
        reply.code(409);
        return { message: err.message };
      }
      if (err instanceof AdapterTimeoutError) {
        reply.code(503);
        return {
          message: 'Connector adapter simulation timed out',
          reason_code: 'connector.invoke.timeout',
          timeout_ms: err.timeoutMs
        };
      }
      throw err;
    }

    return {
      status: 'simulated',
      run_id: body.run_id,
      connector_id: connectorId,
      connector_binding_id: binding.id,
      capability: body.capability,
      policy_decision: policyDecision,
      adapter_preview: adapterPreview
    };
  });

  app.post('/v0/connectors/adapters/:connector_id/invoke', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['connector_id'],
        properties: {
          connector_id: { type: 'string', pattern: '^con_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: [
          'run_id',
          'workspace_id',
          'agent_id',
          'connector_binding_id',
          'capability',
          'side_effect',
          'risk_hint',
          'parameters',
          'initiated_by'
        ],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' },
          connector_binding_id: { type: 'string', pattern: '^cnb_[A-Za-z0-9_-]{6,64}$' },
          capability: { type: 'string', pattern: '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$' },
          side_effect: { type: 'string', enum: ['none', 'mutation'] },
          risk_hint: { type: 'string', enum: ['R0', 'R1', 'R2', 'R3'] },
          idempotency_key: { type: 'string', minLength: 8, maxLength: 128 },
          parameters: { type: 'object' },
          initiated_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/connector-adapter-invoke-result.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const { connector_id: connectorId } = request.params;
    const body = request.body;
    const manifest = app.connectorRegistry[connectorId];
    if (!manifest) {
      reply.code(404);
      return { message: 'Connector manifest not found' };
    }

    const adapter = app.connectorAdapters[connectorId];
    if (!adapter) {
      reply.code(501);
      return { message: 'Connector adapter not implemented' };
    }

    const run = findRunById(app, body.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    if (run.workspace_id !== body.workspace_id || run.agent_id !== body.agent_id) {
      reply.code(409);
      return { message: 'Run does not match workspace_id/agent_id in request' };
    }

    const binding = findBindingById(app, body.connector_binding_id);
    if (!binding) {
      reply.code(404);
      return { message: 'Connector binding not found' };
    }

    if (binding.connector_id !== connectorId) {
      reply.code(409);
      return { message: 'Binding connector does not match request connector_id' };
    }

    if (binding.workspace_id !== body.workspace_id) {
      reply.code(409);
      return { message: 'Binding workspace does not match request workspace_id' };
    }

    if (binding.agent_id && binding.agent_id !== body.agent_id) {
      reply.code(409);
      return { message: 'Binding agent does not match request agent_id' };
    }

    if (binding.status !== 'active') {
      reply.code(409);
      return { message: 'Binding is not active' };
    }

    if (!binding.scopes.includes(body.capability)) {
      reply.code(403);
      return { message: 'Capability is outside binding scope' };
    }

    if (!manifest.capabilities.includes(body.capability)) {
      reply.code(409);
      return { message: 'Capability is not declared by connector manifest' };
    }

    const allowlistDecision = evaluateMcpAllowlistForRequest({
      app,
      body,
      connectorId
    });
    if (!allowlistDecision.allowed) {
      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: body.run_id,
          eventType: 'connector.invoke.blocked',
          actorInfo: actor('system', 'runtime'),
          payload: {
            decision: 'deny',
            reason_code: allowlistDecision.reason_code,
            source: 'mcp_allowlist'
          }
        })
      });

      reply.code(403);
      return {
        status: 'blocked',
        run_id: body.run_id,
        connector_id: connectorId,
        connector_binding_id: binding.id,
        capability: body.capability,
        policy_decision: {
          id: makeId('pol'),
          run_id: body.run_id,
          action_intent_id: makeId('act'),
          decision: 'deny',
          risk_tier: body.risk_hint,
          reason_codes: [allowlistDecision.reason_code, 'safety.fail_closed'],
          required_approvals: 0,
          policy_trace: {
            ...defaultPolicyContext(),
            run_override: '',
            effective_source: 'org'
          },
          evaluated_at: nowIso()
        },
        adapter_result: null
      };
    }

    const actionIntent = buildAdapterActionIntent({
      runId: body.run_id,
      bindingId: binding.id,
      connectorId,
      capability: body.capability,
      sideEffect: body.side_effect,
      riskHint: body.risk_hint,
      idempotencyKey: body.idempotency_key,
      parameters: body.parameters
    });

    const policyDecision = evaluatePolicy({
      runId: body.run_id,
      actionIntent,
      policyContext: body.policy_context || defaultPolicyContext(),
      policyLibrary: app.policyLibrary
    });

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: body.run_id,
        eventType: 'policy.evaluated',
        actorInfo: actor('system', 'policy-engine'),
        payload: policyDecision,
        decisionRef: policyDecision.id
      })
    });

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: body.run_id,
        eventType: 'connector.invoke.requested',
        actorInfo: actor('user', body.initiated_by),
        payload: {
          connector_id: connectorId,
          connector_binding_id: binding.id,
          capability: body.capability,
          side_effect: body.side_effect,
          risk_hint: body.risk_hint
        },
        decisionRef: policyDecision.id
      })
    });

    if (policyDecision.decision !== 'allow') {
      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: body.run_id,
          eventType: 'connector.invoke.blocked',
          actorInfo: actor('system', 'runtime'),
          payload: {
            decision: policyDecision.decision,
            required_approvals: policyDecision.required_approvals,
            reason_codes: policyDecision.reason_codes
          },
          decisionRef: policyDecision.id
        })
      });

      reply.code(policyDecision.decision === 'deny' ? 403 : 409);
      return {
        status: 'blocked',
        run_id: body.run_id,
        connector_id: connectorId,
        connector_binding_id: binding.id,
        capability: body.capability,
        policy_decision: policyDecision,
        adapter_result: null
      };
    }

    const key = actionIntent.idempotency_key;
    const persistedReuse = key ? app.stateDb.getIdempotencyResult(key) : null;
    if (persistedReuse && !app.store.idempotencyResults.has(key)) {
      app.store.idempotencyResults.set(key, persistedReuse);
    }

    if (key && app.store.idempotencyResults.has(key)) {
      const reused = app.store.idempotencyResults.get(key);
      await appendEvent({
        app,
        runId: body.run_id,
        name: 'connector.invoked.deduped',
        payload: reused
      });

      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: body.run_id,
          eventType: 'connector.invoke.executed',
          actorInfo: actor('system', 'runtime'),
          payload: { ...reused, deduped: true },
          decisionRef: policyDecision.id
        })
      });

      return {
        status: 'deduped',
        run_id: body.run_id,
        connector_id: connectorId,
        connector_binding_id: binding.id,
        capability: body.capability,
        policy_decision: policyDecision,
        adapter_result: reused
      };
    }

    const rateLimitDecision = app.connectorRateLimiter.evaluate({
      connectorId,
      workspaceId: body.workspace_id
    });
    if (!rateLimitDecision.allowed) {
      const failClosedDecision = {
        id: makeId('pol'),
        run_id: body.run_id,
        action_intent_id: actionIntent.id,
        decision: 'deny',
        risk_tier: body.risk_hint,
        reason_codes: ['connector.invoke.rate_limited', 'safety.fail_closed'],
        required_approvals: 0,
        policy_trace: {
          ...defaultPolicyContext(),
          run_override: '',
          effective_source: 'org'
        },
        evaluated_at: nowIso()
      };

      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: body.run_id,
          eventType: 'connector.invoke.rate_limited',
          actorInfo: actor('system', 'runtime'),
          payload: {
            decision: 'deny',
            reason_code: 'connector.invoke.rate_limited',
            source: 'connector_rate_limiter',
            scope: rateLimitDecision.scope,
            limit: rateLimitDecision.limit,
            window_ms: rateLimitDecision.window_ms,
            retry_after_ms: rateLimitDecision.retry_after_ms
          },
          decisionRef: failClosedDecision.id
        })
      });

      reply.code(429);
      return {
        status: 'blocked',
        run_id: body.run_id,
        connector_id: connectorId,
        connector_binding_id: binding.id,
        capability: body.capability,
        policy_decision: failClosedDecision,
        adapter_result: null,
        retry_after_ms: rateLimitDecision.retry_after_ms
      };
    }

    let adapterPayload;
    let lastAdapterError;
    let lastFailureReasonCode = '';
    let attemptsUsed = 0;

    for (let attempt = 1; attempt <= app.adapterRetryPolicy.max_attempts; attempt += 1) {
      attemptsUsed = attempt;
      try {
        adapterPayload = await withTimeout(
          () => adapter.invoke({
            runId: body.run_id,
            capability: body.capability,
            parameters: body.parameters,
            idempotencyKey: key,
            attempt,
            runtime: {
              feishuWebhookUrl: resolveActiveFeishuWebhook(app).webhook_url
            }
          }),
          app.adapterTimeoutMs
        );
        break;
      } catch (err) {
        if (err instanceof AdapterCapabilityError) {
          reply.code(409);
          return { message: err.message };
        }

        lastAdapterError = err;
        lastFailureReasonCode = classifyAdapterFailureReason(err);
        const retryDecision = buildAdapterRetryDecision({
          attempt,
          policy: app.adapterRetryPolicy,
          sideEffect: body.side_effect,
          idempotencyKey: key,
          errorReason: lastFailureReasonCode
        });

        if (!retryDecision.retry) {
          break;
        }

        const delayMs = computeAdapterRetryDelayMs({
          attempt,
          policy: app.adapterRetryPolicy
        });

        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId: body.run_id,
            eventType: 'connector.invoke.retry',
            actorInfo: actor('system', 'runtime'),
            payload: {
              reason_code: lastFailureReasonCode,
              attempt,
              next_attempt: attempt + 1,
              delay_ms: delayMs,
              side_effect: body.side_effect,
              idempotency_key_present: Boolean(key),
              retry_decision: retryDecision.reason_code
            },
            decisionRef: policyDecision.id
          })
        });

        if (delayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }
    }

    if (!adapterPayload) {
      const failClosedDecision = {
        id: makeId('pol'),
        run_id: body.run_id,
        action_intent_id: actionIntent.id,
        decision: 'deny',
        risk_tier: body.risk_hint,
        reason_codes: [lastFailureReasonCode || 'connector.invoke.error', 'safety.fail_closed'],
        required_approvals: 0,
        policy_trace: {
          ...defaultPolicyContext(),
          run_override: '',
          effective_source: 'org'
        },
        evaluated_at: nowIso()
      };

      if (lastFailureReasonCode === 'connector.invoke.timeout') {
        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId: body.run_id,
            eventType: 'connector.invoke.timeout',
            actorInfo: actor('system', 'runtime'),
            payload: {
              decision: 'deny',
              reason_code: 'connector.invoke.timeout',
              timeout_ms: lastAdapterError?.timeoutMs || app.adapterTimeoutMs,
              source: 'adapter_timeout',
              attempts: attemptsUsed
            },
            decisionRef: failClosedDecision.id
          })
        });
      } else {
        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId: body.run_id,
            eventType: 'connector.invoke.error',
            actorInfo: actor('system', 'runtime'),
            payload: {
              decision: 'deny',
              reason_code: 'connector.invoke.error',
              message: String(lastAdapterError?.message || 'unknown adapter error'),
              source: 'adapter_invoke',
              attempts: attemptsUsed
            },
            decisionRef: failClosedDecision.id
          })
        });
      }

      reply.code(503);
      return {
        status: 'blocked',
        run_id: body.run_id,
        connector_id: connectorId,
        connector_binding_id: binding.id,
        capability: body.capability,
        policy_decision: failClosedDecision,
        adapter_result: null
      };
    }

    const execution = {
      action_intent_id: actionIntent.id,
      connector_id: connectorId,
      connector_binding_id: binding.id,
      capability: body.capability,
      status: 'executed',
      output: adapterPayload,
      retry: {
        attempts: attemptsUsed,
        max_attempts: app.adapterRetryPolicy.max_attempts
      },
      executed_at: nowIso()
    };

    if (key) {
      app.store.idempotencyResults.set(key, execution);
      app.stateDb.saveIdempotencyResult({
        key,
        runId: body.run_id,
        payload: execution,
        createdAt: nowIso()
      });
    }

    await appendEvent({
      app,
      runId: body.run_id,
      name: 'connector.invoked',
      payload: execution
    });

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: body.run_id,
        eventType: 'connector.invoke.executed',
        actorInfo: actor('agent', body.agent_id),
        payload: execution,
        decisionRef: policyDecision.id
      })
    });

    return {
      status: 'executed',
      run_id: body.run_id,
      connector_id: connectorId,
      connector_binding_id: binding.id,
      capability: body.capability,
      policy_decision: policyDecision,
      adapter_result: execution
    };
  });

  app.post('/v0/runs/:run_id/a2a/request', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['connector_binding_id', 'initiated_by', 'target_agent', 'task_type'],
        properties: {
          connector_binding_id: { type: 'string', pattern: '^cnb_[A-Za-z0-9_-]{6,64}$' },
          initiated_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          target_agent: { type: 'string', minLength: 3, maxLength: 120 },
          task_type: { type: 'string', minLength: 3, maxLength: 120 },
          payload: { type: 'object' },
          risk_hint: { type: 'string', enum: ['R0', 'R1', 'R2', 'R3'] },
          idempotency_key: { type: 'string', minLength: 8, maxLength: 128 },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      }
    }
  }, async (request, reply) => {
    const run = findRunById(app, request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const body = request.body;
    const invokePayload = {
      run_id: run.id,
      workspace_id: run.workspace_id,
      agent_id: run.agent_id,
      connector_binding_id: body.connector_binding_id,
      capability: 'delegation.request',
      side_effect: 'mutation',
      risk_hint: body.risk_hint || 'R1',
      idempotency_key: body.idempotency_key || `a2a_req_${shortHash({
        run_id: run.id,
        target_agent: body.target_agent,
        task_type: body.task_type,
        payload: body.payload || {}
      })}`,
      initiated_by: body.initiated_by,
      parameters: {
        target_agent: body.target_agent,
        task_type: body.task_type,
        input: body.payload || {}
      },
      ...(body.policy_context ? { policy_context: body.policy_context } : {})
    };

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      headers: {
        'x-flockmesh-actor-id': body.initiated_by
      },
      payload: invokePayload
    });

    const payload = invokeRes.json();
    reply.code(invokeRes.statusCode);
    return {
      operation: 'delegation.request',
      delegation_id: payload?.adapter_result?.output?.output?.delegation_id || null,
      ...payload
    };
  });

  app.post('/v0/runs/:run_id/a2a/:delegation_id/status', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id', 'delegation_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          delegation_id: { type: 'string', pattern: '^dlg_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['connector_binding_id', 'initiated_by'],
        properties: {
          connector_binding_id: { type: 'string', pattern: '^cnb_[A-Za-z0-9_-]{6,64}$' },
          initiated_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          risk_hint: { type: 'string', enum: ['R0', 'R1', 'R2', 'R3'] },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      }
    }
  }, async (request, reply) => {
    const run = findRunById(app, request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const body = request.body;
    const invokePayload = {
      run_id: run.id,
      workspace_id: run.workspace_id,
      agent_id: run.agent_id,
      connector_binding_id: body.connector_binding_id,
      capability: 'delegation.status',
      side_effect: 'none',
      risk_hint: body.risk_hint || 'R0',
      initiated_by: body.initiated_by,
      parameters: {
        delegation_id: request.params.delegation_id
      },
      ...(body.policy_context ? { policy_context: body.policy_context } : {})
    };

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      headers: {
        'x-flockmesh-actor-id': body.initiated_by
      },
      payload: invokePayload
    });

    const payload = invokeRes.json();
    reply.code(invokeRes.statusCode);
    return {
      operation: 'delegation.status',
      delegation_id: request.params.delegation_id,
      ...payload
    };
  });

  app.post('/v0/runs/:run_id/a2a/:delegation_id/cancel', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id', 'delegation_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          delegation_id: { type: 'string', pattern: '^dlg_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['connector_binding_id', 'initiated_by'],
        properties: {
          connector_binding_id: { type: 'string', pattern: '^cnb_[A-Za-z0-9_-]{6,64}$' },
          initiated_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          reason: { type: 'string', maxLength: 1000 },
          risk_hint: { type: 'string', enum: ['R0', 'R1', 'R2', 'R3'] },
          idempotency_key: { type: 'string', minLength: 8, maxLength: 128 },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      }
    }
  }, async (request, reply) => {
    const run = findRunById(app, request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const body = request.body;
    const invokePayload = {
      run_id: run.id,
      workspace_id: run.workspace_id,
      agent_id: run.agent_id,
      connector_binding_id: body.connector_binding_id,
      capability: 'delegation.cancel',
      side_effect: 'mutation',
      risk_hint: body.risk_hint || 'R1',
      idempotency_key: body.idempotency_key || `a2a_cancel_${shortHash({
        run_id: run.id,
        delegation_id: request.params.delegation_id
      })}`,
      initiated_by: body.initiated_by,
      parameters: {
        delegation_id: request.params.delegation_id,
        reason: body.reason || ''
      },
      ...(body.policy_context ? { policy_context: body.policy_context } : {})
    };

    const invokeRes = await app.inject({
      method: 'POST',
      url: '/v0/connectors/adapters/con_a2a_gateway/invoke',
      headers: {
        'x-flockmesh-actor-id': body.initiated_by
      },
      payload: invokePayload
    });

    const payload = invokeRes.json();
    reply.code(invokeRes.statusCode);
    return {
      operation: 'delegation.cancel',
      delegation_id: request.params.delegation_id,
      ...payload
    };
  });

  app.get('/v0/policy/profiles', {
    schema: {
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-profile-catalog.schema.json#' }
      }
    }
  }, async () => {
    const items = listPolicyProfileCatalogItems(app.policyLibrary);
    return {
      version: 'v0',
      generated_at: nowIso(),
      total: items.length,
      items
    };
  });

  app.get('/v0/policy/profiles/:profile_name/version', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['profile_name'],
        properties: {
          profile_name: {
            type: 'string',
            pattern: '^[a-z][a-z0-9_]{2,80}$'
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-profile-version.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const profileName = String(request.params.profile_name || '').trim();
    const profile = app.policyLibrary[profileName];
    if (!profile) {
      reply.code(404);
      return { message: `Policy profile not found: ${profileName}` };
    }

    return {
      version: 'v0',
      generated_at: nowIso(),
      ...buildPolicyProfileVersionSnapshot({
        profileName,
        profile
      })
    };
  });

  app.get('/v0/policy/patches', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          profile_name: {
            type: 'string',
            pattern: '^[a-z][a-z0-9_]{2,80}$'
          },
          operation: {
            type: 'string',
            enum: ['patch', 'rollback']
          },
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-patch-history.schema.json#' }
      }
    }
  }, async (request) => {
    const query = request.query || {};
    const profileName = String(query.profile_name || '').trim();
    const operation = String(query.operation || '').trim();
    const page = await listPolicyPatchHistoryPage({
      rootDir,
      profileName,
      operation,
      limit: query.limit,
      offset: query.offset
    });

    return {
      version: 'v0',
      generated_at: nowIso(),
      total: page.total,
      limit: page.limit,
      offset: page.offset,
      items: page.items.map(buildPolicyPatchHistorySummaryItem)
    };
  });

  app.get('/v0/policy/patches/export', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          profile_name: {
            type: 'string',
            pattern: '^[a-z][a-z0-9_]{2,80}$'
          },
          operation: {
            type: 'string',
            enum: ['patch', 'rollback']
          },
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-patch-history-export-package.schema.json#' }
      }
    }
  }, async (request) => {
    const query = request.query || {};
    const profileName = String(query.profile_name || '').trim();
    const operation = String(query.operation || '').trim();
    const page = await listPolicyPatchHistoryPage({
      rootDir,
      profileName,
      operation,
      limit: query.limit,
      offset: query.offset
    });
    const historyPage = {
      total: page.total,
      limit: page.limit,
      offset: page.offset,
      items: page.items.map(buildPolicyPatchHistorySummaryItem)
    };

    const envelope = {
      version: 'v0',
      exported_at: nowIso(),
      filters: {
        profile_name: profileName,
        operation,
        limit: page.limit,
        offset: page.offset
      },
      history: historyPage
    };
    const signature = signIncidentExportPayload(envelope, {
      keyId: app.incidentExportSigning.key_id,
      keys: app.incidentExportSigning.keys
    });

    return {
      ...envelope,
      signature
    };
  });

  app.post('/v0/policy/patch', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['profile_name', 'mode', 'patch_rules'],
        properties: {
          profile_name: {
            type: 'string',
            pattern: '^[a-z][a-z0-9_]{2,80}$'
          },
          mode: {
            type: 'string',
            enum: ['dry_run', 'apply']
          },
          patch_rules: {
            type: 'array',
            minItems: 1,
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['capability', 'decision'],
              properties: {
                capability: {
                  type: 'string',
                  pattern: '^(\\*|[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+)$'
                },
                decision: {
                  type: 'string',
                  enum: ['allow', 'deny', 'escalate']
                },
                required_approvals: {
                  type: 'integer',
                  minimum: 1,
                  maximum: 5
                }
              }
            }
          },
          reason: {
            type: 'string',
            maxLength: 320
          },
          actor_id: {
            type: 'string',
            minLength: 3,
            maxLength: 128
          },
          expected_profile_hash: {
            type: 'string',
            pattern: '^sha256:[a-f0-9]{64}$'
          }
        },
        allOf: [
          {
            if: {
              properties: {
                mode: {
                  const: 'apply'
                }
              }
            },
            then: {
              required: ['expected_profile_hash']
            }
          }
        ]
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-profile-patch-result.schema.json#' },
        403: {
          type: 'object',
          additionalProperties: false,
          required: ['message', 'reason_code'],
          properties: {
            message: { type: 'string' },
            reason_code: { type: 'string' }
          }
        },
        409: {
          type: 'object',
          additionalProperties: false,
          required: ['message', 'expected_profile_hash', 'current_profile_hash'],
          properties: {
            message: { type: 'string' },
            expected_profile_hash: { type: 'string' },
            current_profile_hash: { type: 'string' }
          }
        }
      }
    }
  }, async (request, reply) => {
    try {
      const body = request.body;
      const actorIdentity = resolveRequestActorId(request, {
        fallbackActorId: app.trustedDefaultActorId
      });
      if (!actorIdentity.ok) {
        reply.code(actorIdentity.errorCode);
        return { message: actorIdentity.message };
      }
      const actorClaim = String(body.actor_id || '').trim();
      if (actorClaim && actorClaim !== actorIdentity.actor_id) {
        reply.code(403);
        return {
          message: 'Authenticated actor does not match actor_id',
          reason_code: 'auth.actor_claim_mismatch'
        };
      }
      const mode = resolvePolicyPatchMode(body.mode);
      const profileName = String(body.profile_name || '').trim();
      if (!POLICY_PROFILE_NAME_PATTERN.test(profileName)) {
        throw new Error(`invalid profile_name: ${profileName}`);
      }

      const beforeProfile = app.policyLibrary[profileName];
      if (!beforeProfile) {
        reply.code(404);
        return { message: `Policy profile not found: ${profileName}` };
      }

      const beforeDocument = normalizePolicyFileDocument(
        toPolicyProfileDocument({
          profileName,
          profile: beforeProfile
        }),
        { profileName }
      );
      const beforeProfileHash = hashPolicyProfileDocument(beforeDocument);
      const expectedProfileHash = String(body.expected_profile_hash || '').trim();
      if (mode === 'apply' && !expectedProfileHash) {
        throw new Error('expected_profile_hash is required when mode=apply');
      }
      if (expectedProfileHash && expectedProfileHash !== beforeProfileHash) {
        reply.code(409);
        return {
          message: `Policy profile hash mismatch for ${profileName}`,
          expected_profile_hash: expectedProfileHash,
          current_profile_hash: beforeProfileHash
        };
      }
      const patchRules = normalizePolicyPatchRules(body.patch_rules);
      const beforeRules = profileRulesToList(beforeProfile);
      const afterProfile = buildPatchedPolicyProfile({
        profileName,
        beforeProfile,
        patchRules
      });
      const afterDocument = normalizePolicyFileDocument(
        toPolicyProfileDocument({
          profileName,
          profile: afterProfile
        }),
        { profileName }
      );
      const afterProfileHash = hashPolicyProfileDocument(afterDocument);
      compilePolicyProfileDsl(afterDocument, { source: 'policy.patch.runtime' });
      const afterRules = profileRulesToList(afterProfile);
      const compared = comparePolicyRules({
        beforeRules,
        afterRules
      });
      const summary = {
        ...compared.summary,
        patch_rules: patchRules.length
      };

      const afterLibrary = {
        ...app.policyLibrary,
        [profileName]: afterProfile
      };
      const simulationPreview = simulatePolicyPatch({
        profileName,
        patchRules,
        beforeLibrary: app.policyLibrary,
        afterLibrary
      });

      const filePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);
      const reason = String(body.reason || '').trim();
      const actorInfo = resolvePolicyPatchActor(actorIdentity.actor_id);
      let persisted = false;
      let auditEntry = null;
      let patchId = null;

      if (mode === 'apply') {
        const authz = canActorManagePolicyProfile({
          config: app.policyAdminConfig,
          actorId: actorInfo.id,
          profileName
        });
        if (!authz.allowed) {
          reply.code(403);
          return {
            message: `Actor is not authorized to apply patch for profile: ${profileName}`,
            reason_code: authz.reason_code
          };
        }

        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, `${JSON.stringify(afterDocument, null, 2)}\n`, 'utf8');
        app.policyLibrary[profileName] = afterProfile;
        persisted = true;
        patchId = makeId('pph');

        const auditRunId = makeId('run');
        auditEntry = makeAuditEntry({
          runId: auditRunId,
          eventType: 'policy.patch.applied',
          actorInfo,
          payload: {
            profile_name: profileName,
            mode,
            reason,
            summary,
            patch_rules: patchRules,
            simulation_preview: simulationPreview
          }
        });
        await appendAudit({ app, entry: auditEntry });

        await appendPolicyPatchHistoryEntry({
          rootDir,
          entry: {
            version: 'v0',
            patch_id: patchId,
            operation: 'patch',
            rollback_target_patch_id: '',
            rollback_target_state: '',
            profile_name: profileName,
            actor_id: actorInfo.id,
            reason,
            applied_at: nowIso(),
            file_path: filePath,
            before_profile_hash: beforeProfileHash,
            after_profile_hash: afterProfileHash,
            summary,
            changes: {
              added_capabilities: compared.added_capabilities,
              updated_capabilities: compared.updated_capabilities,
              removed_capabilities: compared.removed_capabilities,
              unchanged_capabilities: compared.unchanged_capabilities
            },
            simulation_preview: simulationPreview,
            before_document: beforeDocument,
            after_document: afterDocument
          }
        });
      }

      return buildPolicyPatchResponsePayload({
        mode,
        profileName,
        actorInfo,
        reason,
        persisted,
        filePath,
        summary,
        patchRules,
        beforeRules,
        afterRules,
        compared,
        simulationPreview,
        auditEntry,
        patchId,
        beforeProfileHash,
        afterProfileHash
      });
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.post('/v0/policy/rollback', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['profile_name', 'mode'],
        properties: {
          profile_name: {
            type: 'string',
            pattern: '^[a-z][a-z0-9_]{2,80}$'
          },
          mode: {
            type: 'string',
            enum: ['dry_run', 'apply']
          },
          target_patch_id: {
            type: 'string',
            pattern: '^pph_[A-Za-z0-9_-]{6,64}$'
          },
          target_state: {
            type: 'string',
            enum: ['before', 'after']
          },
          reason: {
            type: 'string',
            maxLength: 320
          },
          actor_id: {
            type: 'string',
            minLength: 3,
            maxLength: 128
          },
          expected_profile_hash: {
            type: 'string',
            pattern: '^sha256:[a-f0-9]{64}$'
          }
        },
        allOf: [
          {
            if: {
              properties: {
                mode: {
                  const: 'apply'
                }
              }
            },
            then: {
              required: ['expected_profile_hash']
            }
          }
        ]
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-profile-patch-result.schema.json#' },
        403: {
          type: 'object',
          additionalProperties: false,
          required: ['message', 'reason_code'],
          properties: {
            message: { type: 'string' },
            reason_code: { type: 'string' }
          }
        },
        409: {
          type: 'object',
          additionalProperties: false,
          required: ['message', 'expected_profile_hash', 'current_profile_hash'],
          properties: {
            message: { type: 'string' },
            expected_profile_hash: { type: 'string' },
            current_profile_hash: { type: 'string' }
          }
        }
      }
    }
  }, async (request, reply) => {
    try {
      const body = request.body;
      const actorIdentity = resolveRequestActorId(request, {
        fallbackActorId: app.trustedDefaultActorId
      });
      if (!actorIdentity.ok) {
        reply.code(actorIdentity.errorCode);
        return { message: actorIdentity.message };
      }
      const actorClaim = String(body.actor_id || '').trim();
      if (actorClaim && actorClaim !== actorIdentity.actor_id) {
        reply.code(403);
        return {
          message: 'Authenticated actor does not match actor_id',
          reason_code: 'auth.actor_claim_mismatch'
        };
      }
      const mode = resolvePolicyPatchMode(body.mode);
      const profileName = String(body.profile_name || '').trim();
      if (!POLICY_PROFILE_NAME_PATTERN.test(profileName)) {
        throw new Error(`invalid profile_name: ${profileName}`);
      }

      const beforeProfile = app.policyLibrary[profileName];
      if (!beforeProfile) {
        reply.code(404);
        return { message: `Policy profile not found: ${profileName}` };
      }
      const beforeDocument = normalizePolicyFileDocument(
        toPolicyProfileDocument({
          profileName,
          profile: beforeProfile
        }),
        { profileName }
      );
      const beforeProfileHash = hashPolicyProfileDocument(beforeDocument);
      const expectedProfileHash = String(body.expected_profile_hash || '').trim();
      if (mode === 'apply' && !expectedProfileHash) {
        throw new Error('expected_profile_hash is required when mode=apply');
      }
      if (expectedProfileHash && expectedProfileHash !== beforeProfileHash) {
        reply.code(409);
        return {
          message: `Policy profile hash mismatch for ${profileName}`,
          expected_profile_hash: expectedProfileHash,
          current_profile_hash: beforeProfileHash
        };
      }

      const historyEntries = await readPolicyPatchHistoryEntries({ rootDir });
      const profileHistory = historyEntries
        .filter((item) => isPolicyPatchHistoryEntry(item) && item.profile_name === profileName)
        .sort((a, b) => (Date.parse(b?.applied_at || '') || 0) - (Date.parse(a?.applied_at || '') || 0));

      if (!profileHistory.length) {
        reply.code(404);
        return { message: `No policy patch history found for profile: ${profileName}` };
      }

      const targetPatchId = String(body.target_patch_id || '').trim();
      const targetEntry = targetPatchId
        ? profileHistory.find((item) => item.patch_id === targetPatchId)
        : profileHistory[0];

      if (!targetEntry) {
        reply.code(404);
        return { message: `Policy patch history entry not found: ${targetPatchId}` };
      }

      const targetState = body.target_state === 'after' ? 'after' : 'before';
      const targetDocumentRaw = targetState === 'after'
        ? targetEntry.after_document
        : targetEntry.before_document;
      const targetDocument = normalizePolicyFileDocument(targetDocumentRaw, { profileName });
      if (!targetDocument.name || targetDocument.name !== profileName) {
        throw new Error(`rollback target document profile mismatch: ${targetDocument.name || 'unknown'}`);
      }
      const afterProfileHash = hashPolicyProfileDocument(targetDocument);

      const afterProfile = compilePolicyProfileDsl(targetDocument, {
        source: `policy.rollback.${targetEntry.patch_id || 'unknown'}`
      });
      const beforeRules = profileRulesToList(beforeProfile);
      const afterRules = profileRulesToList(afterProfile);
      const patchRules = toPolicyRulePatchList(afterRules);
      const compared = comparePolicyRules({
        beforeRules,
        afterRules
      });
      const summary = {
        ...compared.summary
      };

      const afterLibrary = {
        ...app.policyLibrary,
        [profileName]: afterProfile
      };
      const simulationPreview = simulatePolicyPatch({
        profileName,
        patchRules,
        beforeLibrary: app.policyLibrary,
        afterLibrary
      });

      const filePath = path.join(rootDir, 'policies', `${profileName}.policy.json`);
      const reason = String(body.reason || '').trim() || `rollback to ${targetState}:${targetEntry.patch_id}`;
      const actorInfo = resolvePolicyPatchActor(actorIdentity.actor_id);
      let persisted = false;
      let auditEntry = null;
      let patchId = null;

      if (mode === 'apply') {
        const authz = canActorManagePolicyProfile({
          config: app.policyAdminConfig,
          actorId: actorInfo.id,
          profileName
        });
        if (!authz.allowed) {
          reply.code(403);
          return {
            message: `Actor is not authorized to apply rollback for profile: ${profileName}`,
            reason_code: authz.reason_code
          };
        }

        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, `${JSON.stringify(targetDocument, null, 2)}\n`, 'utf8');
        app.policyLibrary[profileName] = afterProfile;
        persisted = true;
        patchId = makeId('pph');

        const auditRunId = makeId('run');
        auditEntry = makeAuditEntry({
          runId: auditRunId,
          eventType: 'policy.rollback.applied',
          actorInfo,
          payload: {
            profile_name: profileName,
            mode,
            reason,
            rollback_target_patch_id: targetEntry.patch_id,
            rollback_target_state: targetState,
            summary,
            simulation_preview: simulationPreview
          }
        });
        await appendAudit({ app, entry: auditEntry });

        await appendPolicyPatchHistoryEntry({
          rootDir,
          entry: {
            version: 'v0',
            patch_id: patchId,
            operation: 'rollback',
            rollback_target_patch_id: targetEntry.patch_id,
            rollback_target_state: targetState,
            profile_name: profileName,
            actor_id: actorInfo.id,
            reason,
            applied_at: nowIso(),
            file_path: filePath,
            before_profile_hash: beforeProfileHash,
            after_profile_hash: afterProfileHash,
            summary,
            changes: {
              added_capabilities: compared.added_capabilities,
              updated_capabilities: compared.updated_capabilities,
              removed_capabilities: compared.removed_capabilities,
              unchanged_capabilities: compared.unchanged_capabilities
            },
            simulation_preview: simulationPreview,
            before_document: beforeDocument,
            after_document: targetDocument
          }
        });
      }

      return buildPolicyPatchResponsePayload({
        mode,
        profileName,
        actorInfo,
        reason,
        persisted,
        filePath,
        summary,
        patchRules,
        beforeRules,
        afterRules,
        compared,
        simulationPreview,
        auditEntry,
        patchId,
        rollbackTargetPatchId: targetEntry.patch_id || null,
        beforeProfileHash,
        afterProfileHash
      });
    } catch (err) {
      reply.code(400);
      return { message: err.message };
    }
  });

  app.post('/v0/policy/evaluate', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id', 'action_intent'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          action_intent: { $ref: 'https://flockmesh.dev/spec/schemas/action-intent.schema.json#' },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-decision.schema.json#' }
      }
    }
  }, async (request) => {
    const decision = evaluatePolicy({
      runId: request.body.run_id,
      actionIntent: request.body.action_intent,
      policyContext: request.body.policy_context,
      policyLibrary: app.policyLibrary
    });

    return decision;
  });

  app.post('/v0/policy/simulate', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id', 'action_intents'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          action_intents: {
            type: 'array',
            minItems: 1,
            items: { $ref: 'https://flockmesh.dev/spec/schemas/action-intent.schema.json#' }
          },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/policy-simulation.schema.json#' }
      }
    }
  }, async (request) => {
    const decisions = request.body.action_intents.map((intent) =>
      evaluatePolicy({
        runId: request.body.run_id,
        actionIntent: intent,
        policyContext: request.body.policy_context,
        policyLibrary: app.policyLibrary
      })
    );

    const summary = decisions.reduce(
      (acc, item) => {
        acc[item.decision] += 1;
        return acc;
      },
      { allow: 0, escalate: 0, deny: 0 }
    );

    return {
      run_id: request.body.run_id,
      policy_context: request.body.policy_context || {},
      summary: {
        total: decisions.length,
        allow: summary.allow,
        escalate: summary.escalate,
        deny: summary.deny,
        status: runStatusFromDecisions(decisions)
      },
      decisions
    };
  });

  app.post('/v0/runs', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id', 'agent_id', 'playbook_id', 'trigger'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          agent_id: { type: 'string', pattern: '^agt_[A-Za-z0-9_-]{6,64}$' },
          playbook_id: { type: 'string', pattern: '^pbk_[A-Za-z0-9_-]{6,64}$' },
          trigger: {
            type: 'object',
            additionalProperties: false,
            required: ['type', 'source', 'actor_id', 'at'],
            properties: {
              type: { type: 'string', enum: ['manual', 'scheduled', 'event'] },
              source: { type: 'string', minLength: 1, maxLength: 120 },
              actor_id: { type: 'string', minLength: 3, maxLength: 128 },
              at: { type: 'string', format: 'date-time' }
            }
          },
          policy_context: {
            type: 'object',
            additionalProperties: false,
            properties: {
              org_policy: { type: 'string' },
              workspace_policy: { type: 'string' },
              agent_policy: { type: 'string' },
              run_override: { type: 'string' }
            }
          }
        }
      },
      response: {
        202: { $ref: 'https://flockmesh.dev/spec/schemas/run-record.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const body = request.body;
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }
    const triggerActorMatch = ensureActorClaimMatches({
      actorId: actorIdentity.actor_id,
      claimedActorId: body.trigger?.actor_id,
      fieldName: 'trigger.actor_id'
    });
    if (!triggerActorMatch.ok) {
      reply.code(triggerActorMatch.errorCode);
      return { message: triggerActorMatch.message };
    }
    const runPermission = ensureActorPermission({
      app,
      request,
      workspaceId: body.workspace_id,
      permission: 'run.execute',
      allowWorkspaceBootstrap: true
    });
    if (!runPermission.ok) {
      reply.code(runPermission.errorCode);
      return { message: runPermission.message };
    }
    if (runPermission.bootstrap) {
      bootstrapWorkspaceRoleBindings({
        app,
        workspaceId: body.workspace_id,
        ownerActorId: runPermission.actor_id
      });
    }
    const agent = app.store.agents.get(body.agent_id) || app.stateDb.getAgent(body.agent_id);
    if (!agent) {
      reply.code(404);
      return { message: 'Agent not found' };
    }
    app.store.agents.set(agent.id, agent);

    if (agent.workspace_id !== body.workspace_id) {
      reply.code(409);
      return { message: 'Agent workspace does not match run workspace_id' };
    }

    let run = buildRunRecord({
      workspaceId: body.workspace_id,
      agentId: body.agent_id,
      playbookId: body.playbook_id,
      trigger: {
        ...body.trigger,
        actor_id: actorIdentity.actor_id
      }
    });

    app.store.runs.set(run.id, run);

    await appendEvent({
      app,
      runId: run.id,
      name: 'run.created',
      payload: { run_id: run.id, playbook_id: run.playbook_id }
    });

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId: run.id,
        eventType: 'run.created',
        actorInfo: actor('user', actorIdentity.actor_id),
        payload: { run_id: run.id }
      })
    });

    const binding = findBindingForAgent(
      app.store,
      body.agent_id,
      body.workspace_id,
      'message.send'
    );

    run.action_intents = buildDefaultActionIntents({
      runId: run.id,
      connectorBindingId: binding?.id
    });

    for (const intent of run.action_intents) {
      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: run.id,
          eventType: 'action.planned',
          actorInfo: actor('agent', run.agent_id),
          payload: intent
        })
      });
    }

    const requestedPolicyContext = body.policy_context || {};
    const policyContext = resolveRuntimePolicyContext({
      policyLibrary: app.policyLibrary,
      orgPolicy: requestedPolicyContext.org_policy,
      workspacePolicy: requestedPolicyContext.workspace_policy,
      agentPolicy: requestedPolicyContext.agent_policy || agent.default_policy_profile,
      runOverride: requestedPolicyContext.run_override
    });

    run.policy_decisions = run.action_intents.map((intent) =>
      evaluatePolicy({
        runId: run.id,
        actionIntent: intent,
        policyContext,
        policyLibrary: app.policyLibrary
      })
    );

    for (const decision of run.policy_decisions) {
      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: run.id,
          eventType: 'policy.evaluated',
          actorInfo: actor('system', 'policy-engine'),
          payload: decision,
          decisionRef: decision.id
        })
      });
    }

    run.status = runStatusFromDecisions(run.policy_decisions);

    if (run.status === 'failed') {
      run.ended_at = nowIso();

      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId: run.id,
          eventType: 'run.failed',
          actorInfo: actor('system', 'runtime'),
          payload: { status: run.status }
        })
      });
    }

    if (run.status === 'waiting_approval') {
      const pendingMap = new Map();
      for (const decision of run.policy_decisions) {
        if (decision.decision !== 'escalate') continue;
        run.approval_state[decision.action_intent_id] = {
          decision_id: decision.id,
          required_approvals: decision.required_approvals,
          approved_by: []
        };
        pendingMap.set(decision.action_intent_id, {
          decision_id: decision.id,
          required_approvals: decision.required_approvals,
          approvals: new Set()
        });

        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId: run.id,
            eventType: 'approval.requested',
            actorInfo: actor('system', 'runtime'),
            payload: {
              action_intent_id: decision.action_intent_id,
              required_approvals: decision.required_approvals
            },
            decisionRef: decision.id
          })
        });
      }
      app.store.pendingApprovals.set(run.id, pendingMap);
    }

    if (run.status === 'running') {
      const executionSummary = await executeAllowedIntents({ app, run });
      if (executionSummary?.ok) {
        run.status = 'completed';
        run.ended_at = nowIso();

        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId: run.id,
            eventType: 'run.completed',
            actorInfo: actor('system', 'runtime'),
            payload: { status: run.status }
          })
        });
      } else {
        run.status = 'failed';
        run.ended_at = nowIso();

        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId: run.id,
            eventType: 'run.failed',
            actorInfo: actor('system', 'runtime'),
            payload: {
              reason: executionSummary?.reason_code || 'action.execute.error',
              failed_intent_id: executionSummary?.failed_intent_id || ''
            }
          })
        });
      }
    }

    run = app.stateDb.saveRun(run);
    app.store.runs.set(run.id, run);

    reply.code(202);
    return run;
  });

  app.post('/v0/runs/:run_id/approvals', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['action_intent_id', 'approved', 'approved_by', 'expected_revision'],
        properties: {
          action_intent_id: { type: 'string', pattern: '^act_[A-Za-z0-9_-]{6,64}$' },
          approved: { type: 'boolean' },
          approved_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          expected_revision: { type: 'integer', minimum: 1 },
          note: { type: 'string', maxLength: 1000 }
        }
      }
    }
  }, async (request, reply) => {
    const { run_id: runId } = request.params;
    const {
      action_intent_id: actionIntentId,
      approved,
      approved_by: approvedBy,
      expected_revision: expectedRevision,
      note
    } = request.body;
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }
    const approvalActorMatch = ensureActorClaimMatches({
      actorId: actorIdentity.actor_id,
      claimedActorId: approvedBy,
      fieldName: 'approved_by'
    });
    if (!approvalActorMatch.ok) {
      reply.code(approvalActorMatch.errorCode);
      return { message: approvalActorMatch.message };
    }

    let run = app.store.runs.get(runId) || app.stateDb.getRun(runId);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const workspaceBootstrap = !workspaceHasRoleBindings(app, run.workspace_id);
    const canResolveApproval = actorHasPermission({
      app,
      workspaceId: run.workspace_id,
      actorId: actorIdentity.actor_id,
      permission: 'approval.resolve'
    });
    if (!workspaceBootstrap && !canResolveApproval) {
      reply.code(403);
      return { message: 'Actor lacks permission: approval.resolve' };
    }

    if (run.status !== 'waiting_approval') {
      reply.code(409);
      return { message: 'Run is not waiting for approvals' };
    }

    if (run.revision !== expectedRevision) {
      reply.code(409);
      return {
        message: 'Run revision mismatch',
        expected_revision: expectedRevision,
        current_revision: run.revision
      };
    }

    const approvalState = run.approval_state?.[actionIntentId];
    if (!approvalState) {
      reply.code(404);
      return { message: 'Approval target not found' };
    }

    const decision = run.policy_decisions.find((item) => item.action_intent_id === actionIntentId);
    const intent = run.action_intents.find((item) => item.id === actionIntentId);
    if (!decision || !intent) {
      reply.code(404);
      return { message: 'Action intent or policy decision missing' };
    }

    if (!approved) {
      run.status = 'failed';
      run.ended_at = nowIso();
      delete run.approval_state[actionIntentId];
      decision.decision = 'deny';
      decision.reason_codes = Array.from(new Set([...decision.reason_codes, 'approval.resolved.deny']));
      decision.required_approvals = 0;
      decision.evaluated_at = nowIso();
    } else {
      const approvedBySet = new Set(approvalState.approved_by || []);
      approvedBySet.add(approvedBy);
      approvalState.approved_by = Array.from(approvedBySet);

      const approvalsLeft = Math.max(0, approvalState.required_approvals - approvalState.approved_by.length);
      if (approvalsLeft > 0) {
        try {
          run = app.stateDb.saveRun(run, { expectedRevision });
        } catch (err) {
          if (err instanceof RevisionConflictError) {
            reply.code(409);
            return {
              message: 'Run revision conflict while recording approval',
              expected_revision: err.expectedRevision,
              current_revision: err.currentRevision
            };
          }
          throw err;
        }

        app.store.runs.set(run.id, run);
        app.store.pendingApprovals.set(run.id, rebuildPendingApprovalsForRun(run));

        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId,
            eventType: 'approval.resolved',
            actorInfo: actor('user', approvedBy),
            payload: { approved, note: note || '', approvals_left: approvalsLeft },
            decisionRef: approvalState.decision_id
          })
        });

        return {
          status: 'waiting_more_approvals',
          approvals_left: approvalsLeft,
          run
        };
      }

      delete run.approval_state[actionIntentId];
      decision.decision = 'allow';
      decision.reason_codes = Array.from(new Set([...decision.reason_codes, 'approval.resolved.allow']));
      decision.required_approvals = 0;
      decision.evaluated_at = nowIso();
      if (!Object.keys(run.approval_state).length) {
        run.status = 'completed';
        run.ended_at = nowIso();
      }
    }

    try {
      run = app.stateDb.saveRun(run, { expectedRevision });
    } catch (err) {
      if (err instanceof RevisionConflictError) {
        reply.code(409);
        return {
          message: 'Run revision conflict while finalizing approval',
          expected_revision: err.expectedRevision,
          current_revision: err.currentRevision
        };
      }
      throw err;
    }

    app.store.runs.set(run.id, run);
    if (run.status === 'waiting_approval') {
      app.store.pendingApprovals.set(run.id, rebuildPendingApprovalsForRun(run));
    } else {
      app.store.pendingApprovals.delete(run.id);
    }

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId,
        eventType: 'approval.resolved',
        actorInfo: actor('user', approvedBy),
        payload: { approved, note: note || '' },
        decisionRef: approvalState.decision_id
      })
    });

    if (!approved) {
      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId,
          eventType: 'action.denied',
          actorInfo: actor('user', approvedBy),
          payload: { action_intent_id: actionIntentId, note: note || '' },
          decisionRef: approvalState.decision_id
        })
      });

      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId,
          eventType: 'run.failed',
          actorInfo: actor('system', 'runtime'),
          payload: { reason: 'approval_rejected' }
        })
      });
    } else if (decision.decision === 'allow') {
      const execution = await executeIntent({ app, run, intent });
      if (!execution || execution.status !== 'executed') {
        run.status = 'failed';
        run.ended_at = nowIso();
        run = app.stateDb.saveRun(run);
        app.store.runs.set(run.id, run);

        await appendAudit({
          app,
          entry: makeAuditEntry({
            runId,
            eventType: 'run.failed',
            actorInfo: actor('system', 'runtime'),
            payload: {
              reason: execution?.reason_code || 'action.execute.error',
              action_intent_id: actionIntentId
            }
          })
        });
      }
    }

    if (run.status === 'completed') {
      await appendAudit({
        app,
        entry: makeAuditEntry({
          runId,
          eventType: 'run.completed',
          actorInfo: actor('system', 'runtime'),
          payload: { status: run.status }
        })
      });
    }

    return {
      status: run.status,
      run
    };
  });

  app.post('/v0/runs/:run_id/cancel', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['cancelled_by', 'expected_revision'],
        properties: {
          cancelled_by: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          expected_revision: { type: 'integer', minimum: 1 },
          reason: { type: 'string', maxLength: 1000 }
        }
      }
    }
  }, async (request, reply) => {
    const { run_id: runId } = request.params;
    const { cancelled_by: cancelledBy, expected_revision: expectedRevision, reason } = request.body;
    const actorIdentity = resolveRequestActorId(request, {
      fallbackActorId: app.trustedDefaultActorId
    });
    if (!actorIdentity.ok) {
      reply.code(actorIdentity.errorCode);
      return { message: actorIdentity.message };
    }
    const cancelActorMatch = ensureActorClaimMatches({
      actorId: actorIdentity.actor_id,
      claimedActorId: cancelledBy,
      fieldName: 'cancelled_by'
    });
    if (!cancelActorMatch.ok) {
      reply.code(cancelActorMatch.errorCode);
      return { message: cancelActorMatch.message };
    }

    let run = app.store.runs.get(runId) || app.stateDb.getRun(runId);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    if (['completed', 'failed', 'cancelled'].includes(run.status)) {
      reply.code(409);
      return { message: `Run is already terminal: ${run.status}` };
    }

    if (run.revision !== expectedRevision) {
      reply.code(409);
      return {
        message: 'Run revision mismatch',
        expected_revision: expectedRevision,
        current_revision: run.revision
      };
    }

    run.status = 'cancelled';
    run.ended_at = nowIso();
    app.store.pendingApprovals.delete(runId);
    run.approval_state = {};

    try {
      run = app.stateDb.saveRun(run, { expectedRevision });
    } catch (err) {
      if (err instanceof RevisionConflictError) {
        reply.code(409);
        return {
          message: 'Run revision conflict while cancelling',
          expected_revision: err.expectedRevision,
          current_revision: err.currentRevision
        };
      }
      throw err;
    }

    app.store.runs.set(run.id, run);

    await appendAudit({
      app,
      entry: makeAuditEntry({
        runId,
        eventType: 'run.cancelled',
        actorInfo: actor('user', cancelledBy),
        payload: { reason: reason || 'manual_cancel' }
      })
    });

    return {
      status: run.status,
      run
    };
  });

  app.get('/v0/runs', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          status: {
            type: 'string',
            enum: ['accepted', 'running', 'waiting_approval', 'completed', 'failed', 'cancelled']
          },
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: {
          type: 'object',
          additionalProperties: false,
          required: ['total', 'limit', 'offset', 'items'],
          properties: {
            total: { type: 'integer', minimum: 0 },
            limit: { type: 'integer', minimum: 1 },
            offset: { type: 'integer', minimum: 0 },
            items: {
              type: 'array',
              items: { $ref: 'https://flockmesh.dev/spec/schemas/run-record.schema.json#' }
            }
          }
        }
      }
    }
  }, async (request) => {
    const { status, workspace_id: workspaceId, limit, offset } = request.query;
    return app.stateDb.listRuns({
      status,
      workspaceId,
      limit,
      offset
    });
  });

  app.get('/v0/sessions', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        required: ['workspace_id'],
        properties: {
          workspace_id: { type: 'string', pattern: '^wsp_[A-Za-z0-9_-]{6,64}$' },
          actor_id: { type: 'string', pattern: '^usr_[A-Za-z0-9_-]{4,64}$' },
          status: {
            type: 'string',
            enum: ['accepted', 'running', 'waiting_approval', 'completed', 'failed', 'cancelled']
          },
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      }
    }
  }, async (request, reply) => {
    const workspaceId = asTrimmedString(request.query?.workspace_id || '');
    const permission = ensureActorPermission({
      app,
      request,
      workspaceId,
      permission: 'session.read',
      allowWorkspaceBootstrap: true
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    const actorFilter = asTrimmedString(request.query?.actor_id || '');
    if (
      actorFilter &&
      actorFilter !== permission.actor_id &&
      !actorHasPermission({
        app,
        workspaceId,
        actorId: permission.actor_id,
        permission: 'role.manage'
      })
    ) {
      reply.code(403);
      return { message: 'Actor lacks permission: role.manage' };
    }

    const allRuns = app.stateDb.listRuns({
      workspaceId,
      status: request.query?.status,
      limit: 5000,
      offset: 0
    }).items;
    const filtered = allRuns.filter((run) => {
      if (actorFilter && asTrimmedString(run.trigger?.actor_id || '') !== actorFilter) return false;
      return true;
    });
    const limit = Math.min(Math.max(Number(request.query?.limit || 100), 1), 500);
    const offset = Math.max(Number(request.query?.offset || 0), 0);
    const pageItems = filtered
      .slice(offset, offset + limit)
      .map((run) => buildSessionSummaryFromRun(run));

    return {
      total: filtered.length,
      limit,
      offset,
      items: pageItems
    };
  });

  app.get('/v0/sessions/:session_id', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['session_id'],
        properties: {
          session_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          include_evidence: { type: 'boolean' },
          limit: { type: 'integer', minimum: 1, maximum: 500 }
        }
      }
    }
  }, async (request, reply) => {
    const sessionId = request.params.session_id;
    const run = app.store.runs.get(sessionId) || app.stateDb.getRun(sessionId);
    if (!run) {
      reply.code(404);
      return { message: 'Session not found' };
    }
    app.store.runs.set(run.id, run);

    const permission = ensureActorPermission({
      app,
      request,
      workspaceId: run.workspace_id,
      permission: 'session.read',
      allowWorkspaceBootstrap: true
    });
    if (!permission.ok) {
      reply.code(permission.errorCode);
      return { message: permission.message };
    }

    const payload = {
      session: buildSessionSummaryFromRun(run)
    };

    if (request.query?.include_evidence === true) {
      const canReadAudit = actorHasPermission({
        app,
        workspaceId: run.workspace_id,
        actorId: permission.actor_id,
        permission: 'audit.read'
      }) || permission.bootstrap;
      if (!canReadAudit) {
        reply.code(403);
        return { message: 'Actor lacks permission: audit.read' };
      }

      const limit = Math.min(Math.max(Number(request.query?.limit || 100), 1), 500);
      const [events, audit] = await Promise.all([
        app.ledger.listEvents(run.id, { limit, offset: 0 }),
        app.ledger.listAudit(run.id, { limit, offset: 0 })
      ]);
      payload.evidence = {
        events,
        audit
      };
    }

    return payload;
  });

  app.get('/v0/runs/:run_id', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/run-record.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const run = app.store.runs.get(request.params.run_id) || app.stateDb.getRun(request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }
    app.store.runs.set(run.id, run);
    return run;
  });

  app.get('/v0/runs/:run_id/audit', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      }
    }
  }, async (request, reply) => {
    const run = app.store.runs.get(request.params.run_id) || app.stateDb.getRun(request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }
    app.store.runs.set(run.id, run);

    const { limit, offset } = request.query;
    const page = await app.ledger.listAudit(run.id, { limit, offset });
    return {
      run_id: run.id,
      ...page
    };
  });

  app.get('/v0/runs/:run_id/events', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 500 },
          offset: { type: 'integer', minimum: 0 }
        }
      }
    }
  }, async (request, reply) => {
    const run = app.store.runs.get(request.params.run_id) || app.stateDb.getRun(request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }
    app.store.runs.set(run.id, run);

    const { limit, offset } = request.query;
    const page = await app.ledger.listEvents(run.id, { limit, offset });
    return {
      run_id: run.id,
      ...page
    };
  });

  app.get('/v0/runs/:run_id/timeline-diff', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          base_run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' },
          max_items_per_stream: { type: 'integer', minimum: 100, maximum: 10000 },
          sample_limit: { type: 'integer', minimum: 1, maximum: 100 }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/run-timeline-diff.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const run = findRunById(app, request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const maxItemsPerStream = Number(request.query?.max_items_per_stream || 2000);
    const sampleLimit = Number(request.query?.sample_limit || 20);
    const resolution = resolveTimelineDiffBaseRun({
      app,
      run,
      baseRunId: request.query?.base_run_id
    });

    if (resolution.message) {
      reply.code(resolution.errorCode || 400);
      return { message: resolution.message };
    }

    if (!resolution.baseRun) {
      reply.code(404);
      return {
        message: 'No comparable base run found; pass base_run_id explicitly'
      };
    }

    const baseRun = resolution.baseRun;
    app.store.runs.set(baseRun.id, baseRun);

    const [
      currentEvents,
      currentAudit,
      baseEvents,
      baseAudit
    ] = await Promise.all([
      collectLedgerEvidence({
        listFn: app.ledger.listEvents.bind(app.ledger),
        runId: run.id,
        maxItemsPerStream
      }),
      collectLedgerEvidence({
        listFn: app.ledger.listAudit.bind(app.ledger),
        runId: run.id,
        maxItemsPerStream
      }),
      collectLedgerEvidence({
        listFn: app.ledger.listEvents.bind(app.ledger),
        runId: baseRun.id,
        maxItemsPerStream
      }),
      collectLedgerEvidence({
        listFn: app.ledger.listAudit.bind(app.ledger),
        runId: baseRun.id,
        maxItemsPerStream
      })
    ]);

    const partial = currentEvents.truncated ||
      currentAudit.truncated ||
      baseEvents.truncated ||
      baseAudit.truncated;

    const eventTypeDiff = buildDiffGroup(
      buildCountMap(currentEvents.items, (item) => item.name),
      buildCountMap(baseEvents.items, (item) => item.name),
      { sampleLimit }
    );
    const auditEventTypeDiff = buildDiffGroup(
      buildCountMap(currentAudit.items, (item) => item.event_type),
      buildCountMap(baseAudit.items, (item) => item.event_type),
      { sampleLimit }
    );
    const actionCapabilityDiff = buildDiffGroup(
      buildCountMap(run.action_intents || [], (item) => item.capability),
      buildCountMap(baseRun.action_intents || [], (item) => item.capability),
      { sampleLimit }
    );
    const policyDecisionDiff = buildDiffGroup(
      buildCountMap(run.policy_decisions || [], (item) => item.decision),
      buildCountMap(baseRun.policy_decisions || [], (item) => item.decision),
      { sampleLimit }
    );
    const policyReasonDiff = buildDiffGroup(
      buildCountMap(run.policy_decisions || [], (item) => item.reason_codes || []),
      buildCountMap(baseRun.policy_decisions || [], (item) => item.reason_codes || []),
      { sampleLimit }
    );

    return {
      version: 'v0',
      generated_at: nowIso(),
      run_id: run.id,
      base_run_id: baseRun.id,
      base_source: resolution.baseSource,
      scope: {
        workspace_id: run.workspace_id,
        agent_id: run.agent_id,
        playbook_id: run.playbook_id
      },
      summary: {
        current_status: run.status,
        base_status: baseRun.status,
        partial,
        totals: {
          events: metricDelta(currentEvents.total, baseEvents.total),
          audit: metricDelta(currentAudit.total, baseAudit.total),
          action_intents: metricDelta(
            (run.action_intents || []).length,
            (baseRun.action_intents || []).length
          ),
          policy_decisions: metricDelta(
            (run.policy_decisions || []).length,
            (baseRun.policy_decisions || []).length
          )
        }
      },
      diff: {
        event_types: eventTypeDiff,
        audit_event_types: auditEventTypeDiff,
        action_capabilities: actionCapabilityDiff,
        policy_decisions: policyDecisionDiff,
        policy_reason_codes: policyReasonDiff
      },
      evidence: {
        max_items_per_stream: maxItemsPerStream,
        current: {
          events: toEvidenceDigest(currentEvents),
          audit: toEvidenceDigest(currentAudit)
        },
        base: {
          events: toEvidenceDigest(baseEvents),
          audit: toEvidenceDigest(baseAudit)
        }
      }
    };
  });

  app.get('/v0/runs/:run_id/replay-integrity', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          max_items_per_stream: { type: 'integer', minimum: 100, maximum: 10000 },
          sample_limit: { type: 'integer', minimum: 1, maximum: 100 }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/run-replay-integrity.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const run = findRunById(app, request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const maxItemsPerStream = Number(request.query?.max_items_per_stream || 2000);
    const sampleLimit = Number(request.query?.sample_limit || 20);
    return buildReplayIntegrityPayload({
      app,
      run,
      maxItemsPerStream,
      sampleLimit
    });
  });

  app.get('/v0/runs/:run_id/replay-export', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          max_items_per_stream: { type: 'integer', minimum: 100, maximum: 10000 },
          sample_limit: { type: 'integer', minimum: 1, maximum: 100 }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/run-replay-export-package.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const run = findRunById(app, request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }

    const maxItemsPerStream = Number(request.query?.max_items_per_stream || 2000);
    const sampleLimit = Number(request.query?.sample_limit || 20);
    const replayIntegrity = await buildReplayIntegrityPayload({
      app,
      run,
      maxItemsPerStream,
      sampleLimit
    });

    const envelope = {
      version: 'v0',
      exported_at: nowIso(),
      run_id: run.id,
      workspace_id: run.workspace_id,
      agent_id: run.agent_id,
      run_status: run.status,
      replay_integrity: replayIntegrity
    };

    const signature = signIncidentExportPayload(envelope, {
      keyId: app.incidentExportSigning.key_id,
      keys: app.incidentExportSigning.keys
    });

    return {
      ...envelope,
      signature
    };
  });

  app.get('/v0/monitoring/replay-drift', {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 100 },
          max_items_per_stream: { type: 'integer', minimum: 100, maximum: 10000 },
          sample_limit: { type: 'integer', minimum: 1, maximum: 100 },
          include_pending: { type: 'boolean' },
          alert_on_inconclusive: { type: 'boolean' }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/replay-drift-summary.schema.json#' }
      }
    }
  }, async (request) => {
    const limit = Number(request.query?.limit || 30);
    const maxItemsPerStream = Number(request.query?.max_items_per_stream || 1200);
    const sampleLimit = Number(request.query?.sample_limit || 20);
    const includePending = request.query?.include_pending === true;
    const alertOnInconclusive = request.query?.alert_on_inconclusive === true;
    const generatedAt = nowIso();

    const runs = app.stateDb.listRuns({ limit, offset: 0 }).items;
    for (const run of runs) {
      app.store.runs.set(run.id, run);
    }

    const targetRuns = includePending
      ? runs
      : runs.filter((run) => !['accepted', 'running', 'waiting_approval'].includes(run.status));
    const runById = new Map(targetRuns.map((run) => [run.id, run]));

    const snapshots = await Promise.all(
      targetRuns.map((run) =>
        buildReplayIntegrityPayload({
          app,
          run,
          maxItemsPerStream,
          sampleLimit,
          generatedAt
        })
      )
    );

    const weight = {
      inconsistent: 3,
      inconclusive: 2,
      pending: 1,
      consistent: 0
    };
    snapshots.sort((a, b) => {
      const score = (weight[b.replay_state] || 0) - (weight[a.replay_state] || 0);
      if (score !== 0) return score;
      return b.issues.length - a.issues.length;
    });

    const totals = {
      evaluated: snapshots.length,
      pending: snapshots.filter((item) => item.replay_state === 'pending').length,
      consistent: snapshots.filter((item) => item.replay_state === 'consistent').length,
      inconsistent: snapshots.filter((item) => item.replay_state === 'inconsistent').length,
      inconclusive: snapshots.filter((item) => item.replay_state === 'inconclusive').length
    };
    totals.alerting = totals.inconsistent + (alertOnInconclusive ? totals.inconclusive : 0);

    return {
      version: 'v0',
      generated_at: generatedAt,
      window: {
        limit,
        include_pending: includePending,
        alert_on_inconclusive: alertOnInconclusive,
        max_items_per_stream: maxItemsPerStream
      },
      totals,
      alert: totals.alerting > 0,
      items: snapshots.map((snapshot) => {
        const run = runById.get(snapshot.run_id);
        return {
          run_id: snapshot.run_id,
          workspace_id: run.workspace_id,
          agent_id: run.agent_id,
          playbook_id: run.playbook_id,
          run_status: snapshot.run_status,
          replay_state: snapshot.replay_state,
          issue_count: snapshot.issues.length,
          issues: snapshot.issues
        };
      })
    };
  });

  app.get('/v0/runs/:run_id/incident-export', {
    schema: {
      params: {
        type: 'object',
        additionalProperties: false,
        required: ['run_id'],
        properties: {
          run_id: { type: 'string', pattern: '^run_[A-Za-z0-9_-]{6,64}$' }
        }
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          max_items_per_stream: { type: 'integer', minimum: 100, maximum: 10000 }
        }
      },
      response: {
        200: { $ref: 'https://flockmesh.dev/spec/schemas/incident-export-package.schema.json#' }
      }
    }
  }, async (request, reply) => {
    const run = app.store.runs.get(request.params.run_id) || app.stateDb.getRun(request.params.run_id);
    if (!run) {
      reply.code(404);
      return { message: 'Run not found' };
    }
    app.store.runs.set(run.id, run);

    const maxItemsPerStream = Number(request.query?.max_items_per_stream || 2000);
    const decisions = run.policy_decisions || [];

    const [eventEvidence, auditEvidence] = await Promise.all([
      collectLedgerEvidence({
        listFn: app.ledger.listEvents.bind(app.ledger),
        runId: run.id,
        maxItemsPerStream
      }),
      collectLedgerEvidence({
        listFn: app.ledger.listAudit.bind(app.ledger),
        runId: run.id,
        maxItemsPerStream
      })
    ]);

    const envelope = {
      version: 'v0',
      exported_at: nowIso(),
      run_id: run.id,
      workspace_id: run.workspace_id,
      agent_id: run.agent_id,
      run_status: run.status,
      policy_trace_summary: buildPolicyTraceSummary(decisions),
      run,
      evidence: {
        events: eventEvidence,
        audit: auditEvidence
      }
    };

    const signature = signIncidentExportPayload(envelope, {
      keyId: app.incidentExportSigning.key_id,
      keys: app.incidentExportSigning.keys
    });

    return {
      ...envelope,
      signature
    };
  });

  return app;
}

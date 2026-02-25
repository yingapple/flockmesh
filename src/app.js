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

  const result = buildExecutionResult({ actionIntent: intent });

  if (key) {
    app.store.idempotencyResults.set(key, result);
    app.stateDb.saveIdempotencyResult({
      key,
      runId: run.id,
      payload: result,
      createdAt: nowIso()
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
    await executeIntent({ app, run, intent });
  }
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
  trustedDefaultActorId = process.env.FLOCKMESH_TRUSTED_DEFAULT_ACTOR_ID || ''
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

    for (const agent of agents) app.store.agents.set(agent.id, agent);
    for (const binding of bindings) app.store.connectorBindings.set(binding.id, binding);

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
          kit_id: preview.kit.kit_id
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
          parameters: body.parameters
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
            attempt
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
      await executeAllowedIntents({ app, run });
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
      await executeIntent({ app, run, intent });
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
    const { status, limit, offset } = request.query;
    return app.stateDb.listRuns({ status, limit, offset });
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

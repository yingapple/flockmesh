import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluatePolicy } from './policy-engine.js';
import { nowIso } from './time.js';

const WORKSPACE_PATTERN = /^wsp_[A-Za-z0-9_-]{6,64}$/;
const KIT_PATTERN = /^kit_[A-Za-z0-9_-]{4,64}$/;
const CONNECTOR_PATTERN = /^con_[A-Za-z0-9_-]{6,64}$/;
const OWNER_PATTERN = /^(usr|svc)_[A-Za-z0-9_-]{4,64}$/;
const PLAYBOOK_PATTERN = /^pbk_[A-Za-z0-9_-]{6,64}$/;
const CAPABILITY_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const PHASE_PATTERN = /^phase_[A-Za-z0-9_-]{3,64}$/;
const RISK_PROFILE_SET = new Set(['standard', 'restricted', 'high_control']);
const APPROVAL_EXPECTATION_SET = new Set(['none', 'single', 'single_or_dual', 'dual']);

const DEFAULT_AGENT_KIT_LIBRARY = Object.freeze({
  kit_office_ops_core: {
    kit_id: 'kit_office_ops_core',
    name: 'Office Ops Core',
    description: 'Baseline office operations agent with policy-first messaging, docs, calendar, and bridge controls.',
    role: 'ops_assistant',
    default_policy_profile: 'polprof_ops_standard',
    default_playbook_id: 'pbk_weekly_ops_sync',
    capability_goals: [
      'message.send',
      'calendar.read',
      'doc.read',
      'doc.write',
      'tool.list',
      'tool.read',
      'tool.invoke',
      'delegation.request',
      'delegation.status'
    ],
    connector_candidates: [
      {
        connector_id: 'con_feishu_official',
        required_capabilities: ['message.send', 'doc.read'],
        optional_capabilities: ['doc.write', 'calendar.read'],
        risk_profile: 'restricted'
      },
      {
        connector_id: 'con_office_calendar',
        required_capabilities: ['calendar.read'],
        optional_capabilities: ['calendar.write'],
        risk_profile: 'standard'
      },
      {
        connector_id: 'con_mcp_gateway',
        required_capabilities: ['tool.list', 'tool.read'],
        optional_capabilities: ['tool.invoke'],
        risk_profile: 'high_control'
      },
      {
        connector_id: 'con_a2a_gateway',
        required_capabilities: ['delegation.request', 'delegation.status'],
        optional_capabilities: ['delegation.cancel'],
        risk_profile: 'high_control'
      }
    ],
    rollout: [
      {
        phase_id: 'phase_observe',
        title: 'Observe First',
        focus: 'Enable read/list/status capabilities and build trust with zero side effects.',
        approval_expectation: 'none'
      },
      {
        phase_id: 'phase_coordinate',
        title: 'Coordinate',
        focus: 'Enable controlled write/send capabilities with human approval checkpoints.',
        approval_expectation: 'single'
      },
      {
        phase_id: 'phase_delegate',
        title: 'Delegate Across Agents',
        focus: 'Enable MCP invoke and A2A delegation only after connector evidence is stable.',
        approval_expectation: 'single_or_dual'
      }
    ]
  },
  kit_incident_commander: {
    kit_id: 'kit_incident_commander',
    name: 'Incident Commander',
    description: 'Incident-first agent kit optimized for triage, evidence collection, and approved outbound updates.',
    role: 'incident_commander',
    default_policy_profile: 'polprof_ops_standard',
    default_playbook_id: 'pbk_incident_triage',
    capability_goals: [
      'message.send',
      'calendar.read',
      'doc.read',
      'tool.list',
      'tool.read',
      'delegation.request',
      'delegation.status'
    ],
    connector_candidates: [
      {
        connector_id: 'con_feishu_official',
        required_capabilities: ['message.send', 'doc.read'],
        optional_capabilities: ['calendar.read'],
        risk_profile: 'restricted'
      },
      {
        connector_id: 'con_mcp_gateway',
        required_capabilities: ['tool.list', 'tool.read'],
        optional_capabilities: ['tool.invoke'],
        risk_profile: 'high_control'
      },
      {
        connector_id: 'con_a2a_gateway',
        required_capabilities: ['delegation.request', 'delegation.status'],
        optional_capabilities: ['delegation.cancel'],
        risk_profile: 'high_control'
      }
    ],
    rollout: [
      {
        phase_id: 'phase_triage',
        title: 'Triage',
        focus: 'Read incident context and summarize evidence into a deterministic timeline.',
        approval_expectation: 'none'
      },
      {
        phase_id: 'phase_notify',
        title: 'Notify',
        focus: 'Send stakeholder updates through approval-gated outbound message actions.',
        approval_expectation: 'single'
      },
      {
        phase_id: 'phase_delegate',
        title: 'Delegate',
        focus: 'Delegate specialist tasks through A2A once trust and audit baselines pass.',
        approval_expectation: 'single_or_dual'
      }
    ]
  }
});

const READ_ONLY_SUFFIXES = Object.freeze(['.read', '.list', '.status', '.search', '.get']);
const HIGH_RISK_TOKENS = Object.freeze([
  'payment',
  'finance',
  'legal',
  'contract',
  'credential',
  'admin',
  'delete',
  'terminate'
]);
const MUTATION_TOKENS = Object.freeze([
  'send',
  'write',
  'create',
  'update',
  'request',
  'invoke',
  'cancel',
  'execute',
  'publish'
]);

const POLICY_DECISION_WEIGHT = Object.freeze({
  allow: 1,
  escalate: 2,
  deny: 3
});

const DEFAULT_POLICY_CONTEXT = Object.freeze({
  org_policy: 'org_default_safe',
  workspace_policy: 'workspace_ops_cn',
  agent_policy: 'agent_ops_assistant',
  run_override: ''
});

function stableClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function unique(values) {
  return Array.from(new Set(values));
}

function uniqueSorted(values) {
  return unique(values).sort();
}

function normalizeCapabilityList(values = []) {
  return uniqueSorted(
    (values || [])
      .map((item) => String(item || '').trim())
      .filter((item) => CAPABILITY_PATTERN.test(item))
  );
}

function normalizeConnectorIds(values = []) {
  const normalized = [];
  for (const value of values) {
    const id = String(value || '').trim();
    if (!id || !CONNECTOR_PATTERN.test(id)) continue;
    if (!normalized.includes(id)) normalized.push(id);
  }
  return normalized;
}

function defaultConnectorSelection(kit) {
  return kit.connector_candidates.map((item) => item.connector_id);
}

function deriveBindingRiskProfile({ candidate, manifest }) {
  if (candidate?.risk_profile) return candidate.risk_profile;
  if (manifest?.trust_level === 'high_control') return 'high_control';
  if (manifest?.trust_level === 'sandbox') return 'restricted';
  return 'standard';
}

function classifyCapability(capability) {
  const text = String(capability || '').toLowerCase();
  const readOnly = READ_ONLY_SUFFIXES.some((suffix) => text.endsWith(suffix));

  if (readOnly) {
    return {
      side_effect: 'none',
      risk_hint: 'R0'
    };
  }

  if (HIGH_RISK_TOKENS.some((token) => text.includes(token))) {
    return {
      side_effect: 'mutation',
      risk_hint: 'R3'
    };
  }

  if (MUTATION_TOKENS.some((token) => text.includes(token))) {
    return {
      side_effect: 'mutation',
      risk_hint: 'R2'
    };
  }

  return {
    side_effect: 'mutation',
    risk_hint: 'R1'
  };
}

function warning({ code, message, severity = 'warning', connectorId = '', capability = '' }) {
  return {
    code,
    message,
    severity,
    connector_id: connectorId,
    capability
  };
}

function normalizeString(value, fallback = '') {
  const text = String(value || '').trim();
  return text || fallback;
}

function normalizeOwners(owners) {
  const valid = unique(
    (owners || []).map((item) => String(item || '').trim()).filter((item) => OWNER_PATTERN.test(item))
  );
  return valid.length ? valid : ['usr_bootstrap'];
}

function resolveConnectorSelection({ kit, selectedConnectorIds }) {
  const selected = normalizeConnectorIds(selectedConnectorIds || []);
  if (selected.length) return selected;
  return defaultConnectorSelection(kit);
}

function assertPattern(value, pattern, message) {
  if (!pattern.test(String(value || ''))) {
    throw new Error(message);
  }
}

function assertNonEmptyArray(value, message) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(message);
  }
}

function compileConnectorCandidate(raw, { source, index }) {
  const pointer = `${source}.connector_candidates[${index}]`;
  assertPattern(raw?.connector_id, CONNECTOR_PATTERN, `[${pointer}] invalid connector_id`);
  if (!RISK_PROFILE_SET.has(String(raw?.risk_profile || ''))) {
    throw new Error(`[${pointer}] invalid risk_profile`);
  }

  const required = normalizeCapabilityList(raw?.required_capabilities || []);
  const optional = normalizeCapabilityList(raw?.optional_capabilities || []);

  return {
    connector_id: String(raw.connector_id),
    required_capabilities: required,
    optional_capabilities: optional,
    risk_profile: String(raw.risk_profile)
  };
}

function compileRolloutPhase(raw, { source, index }) {
  const pointer = `${source}.rollout[${index}]`;
  assertPattern(raw?.phase_id, PHASE_PATTERN, `[${pointer}] invalid phase_id`);

  const title = normalizeString(raw?.title);
  if (!title) throw new Error(`[${pointer}] title is required`);

  const focus = normalizeString(raw?.focus);
  if (!focus) throw new Error(`[${pointer}] focus is required`);

  const expectation = normalizeString(raw?.approval_expectation);
  if (!APPROVAL_EXPECTATION_SET.has(expectation)) {
    throw new Error(`[${pointer}] invalid approval_expectation`);
  }

  return {
    phase_id: String(raw.phase_id),
    title,
    focus,
    approval_expectation: expectation
  };
}

export function compileAgentKitDsl(document, { source = 'memory' } = {}) {
  const doc = document && typeof document === 'object' && !Array.isArray(document)
    ? document
    : null;
  if (!doc) {
    throw new Error(`[${source}] agent kit must be an object`);
  }

  if (doc.version !== 'v0') {
    throw new Error(`[${source}] unsupported agent kit version: ${doc.version}`);
  }

  assertPattern(doc.kit_id, KIT_PATTERN, `[${source}] invalid kit_id`);

  const name = normalizeString(doc.name);
  if (!name) throw new Error(`[${source}] name is required`);

  const description = normalizeString(doc.description);
  if (!description) throw new Error(`[${source}] description is required`);

  const role = normalizeString(doc.role);
  if (!role) throw new Error(`[${source}] role is required`);

  const defaultPolicyProfile = normalizeString(doc.default_policy_profile);
  if (!defaultPolicyProfile) {
    throw new Error(`[${source}] default_policy_profile is required`);
  }

  assertPattern(doc.default_playbook_id, PLAYBOOK_PATTERN, `[${source}] invalid default_playbook_id`);

  assertNonEmptyArray(doc.capability_goals, `[${source}] capability_goals must be non-empty`);
  const capabilityGoals = normalizeCapabilityList(doc.capability_goals);
  if (!capabilityGoals.length) {
    throw new Error(`[${source}] capability_goals has no valid capability values`);
  }

  assertNonEmptyArray(doc.connector_candidates, `[${source}] connector_candidates must be non-empty`);
  const connectorCandidates = doc.connector_candidates.map((item, index) =>
    compileConnectorCandidate(item, { source, index })
  );

  assertNonEmptyArray(doc.rollout, `[${source}] rollout must be non-empty`);
  const rollout = doc.rollout.map((item, index) =>
    compileRolloutPhase(item, { source, index })
  );

  return {
    kit_id: String(doc.kit_id),
    name,
    description,
    role,
    default_policy_profile: defaultPolicyProfile,
    default_playbook_id: String(doc.default_playbook_id),
    capability_goals: capabilityGoals,
    connector_candidates: connectorCandidates,
    rollout
  };
}

export async function loadAgentKitsFromDir({
  rootDir,
  dirName = 'kits'
} = {}) {
  const directoryPath = path.join(rootDir, dirName);
  let entries = [];

  try {
    entries = await fs.readdir(directoryPath, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return stableClone(DEFAULT_AGENT_KIT_LIBRARY);
    }
    throw err;
  }

  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.kit.json'))
    .map((entry) => entry.name)
    .sort();

  if (!files.length) {
    return stableClone(DEFAULT_AGENT_KIT_LIBRARY);
  }

  const library = {};
  for (const fileName of files) {
    const filePath = path.join(directoryPath, fileName);
    const parsed = JSON.parse(await fs.readFile(filePath, 'utf8'));
    const compiled = compileAgentKitDsl(parsed, { source: fileName });
    library[compiled.kit_id] = compiled;
  }

  return library;
}

function buildPolicyProjection({
  workspaceId,
  capabilities,
  policyContext,
  policyLibrary
}) {
  const items = [];

  for (const capability of capabilities) {
    const classified = classifyCapability(capability);
    const intent = {
      id: `act_plan_${capability.replace(/[^a-zA-Z0-9]/g, '_')}`,
      run_id: 'run_plan_preview',
      step_id: `plan.${capability}`,
      capability,
      side_effect: classified.side_effect,
      risk_hint: classified.risk_hint,
      ...(classified.side_effect === 'mutation'
        ? { idempotency_key: `plan_${workspaceId}_${capability}` }
        : {}),
      parameters: {
        planner: 'agent-blueprint-preview'
      },
      target: {
        surface: 'blueprint'
      }
    };

    const decision = evaluatePolicy({
      runId: 'run_plan_preview',
      actionIntent: intent,
      policyContext,
      policyLibrary
    });

    items.push({
      capability,
      side_effect: classified.side_effect,
      risk_hint: classified.risk_hint,
      decision: decision.decision,
      required_approvals: decision.required_approvals,
      reason_codes: decision.reason_codes,
      effective_source: decision.policy_trace?.effective_source || 'unknown'
    });
  }

  const summary = items.reduce((acc, item) => {
    acc.total += 1;
    if (item.decision === 'allow') acc.allow += 1;
    if (item.decision === 'escalate') acc.escalate += 1;
    if (item.decision === 'deny') acc.deny += 1;
    return acc;
  }, {
    total: 0,
    allow: 0,
    escalate: 0,
    deny: 0
  });

  const maxRequiredApprovals = items.reduce(
    (max, item) => Math.max(max, Number(item.required_approvals || 0)),
    0
  );

  return {
    summary,
    items,
    approval_forecast: {
      total_actions: summary.total,
      escalated_actions: summary.escalate,
      denied_actions: summary.deny,
      max_required_approvals: maxRequiredApprovals
    }
  };
}

function summarizeLintStatus(checks) {
  const failed = checks.filter((item) => item.status === 'fail').length;
  const warned = checks.filter((item) => item.status === 'warn').length;
  const passed = checks.filter((item) => item.status === 'pass').length;

  if (failed > 0) return { status: 'fail', failed, warned, passed };
  if (warned > 0) return { status: 'warn', failed, warned, passed };
  return { status: 'pass', failed, warned, passed };
}

function recommendation(id, message, priority = 'medium') {
  return {
    id,
    message,
    priority
  };
}

export function listAgentKits({ kitLibrary = DEFAULT_AGENT_KIT_LIBRARY } = {}) {
  const items = Object.values(kitLibrary)
    .map((item) => stableClone(item))
    .sort((a, b) => a.kit_id.localeCompare(b.kit_id));

  return {
    version: 'v0',
    generated_at: nowIso(),
    total: items.length,
    items
  };
}

export function makeBlueprintAuthRef({ workspaceId, connectorId }) {
  const digest = crypto
    .createHash('sha256')
    .update(`${workspaceId}:${connectorId}`)
    .digest('hex')
    .slice(0, 20);
  return `sec_blueprint_${digest}`;
}

export function buildAgentBlueprintPreview({
  workspaceId,
  kitId,
  owners,
  agentName,
  selectedConnectorIds,
  manifests,
  policyContext,
  policyLibrary,
  kitLibrary = DEFAULT_AGENT_KIT_LIBRARY
}) {
  const startedMs = Date.now();

  if (!WORKSPACE_PATTERN.test(String(workspaceId || ''))) {
    throw new Error('workspace_id must match pattern ^wsp_[A-Za-z0-9_-]{6,64}$');
  }

  const kit = kitLibrary[String(kitId || '')];
  if (!kit) {
    throw new Error(`Unknown agent kit: ${kitId}`);
  }

  const selected = resolveConnectorSelection({
    kit,
    selectedConnectorIds
  });

  const warnings = [];
  const goalCapabilities = uniqueSorted(
    (kit.capability_goals || []).filter((item) => CAPABILITY_PATTERN.test(item))
  );
  const goalSet = new Set(goalCapabilities);
  const coveredSet = new Set();

  const connectorPlan = [];
  for (const connectorId of selected) {
    const candidate = (kit.connector_candidates || []).find((item) => item.connector_id === connectorId) || null;
    const manifest = manifests[connectorId] || null;

    const requiredCapabilities = uniqueSorted(candidate?.required_capabilities || []);
    const optionalCapabilities = uniqueSorted(candidate?.optional_capabilities || []);

    const manifestCapabilities = new Set(Array.isArray(manifest?.capabilities) ? manifest.capabilities : []);
    const missingRequiredCapabilities = requiredCapabilities.filter((item) => !manifestCapabilities.has(item));

    let scopes = [];
    if (manifest) {
      if (candidate) {
        scopes = uniqueSorted([
          ...requiredCapabilities.filter((item) => manifestCapabilities.has(item)),
          ...optionalCapabilities.filter((item) => manifestCapabilities.has(item))
        ]);
      } else {
        scopes = goalCapabilities.filter((capability) => manifestCapabilities.has(capability));
      }
    }

    let status = 'ready';
    if (!manifest) {
      status = 'manifest_missing';
      warnings.push(warning({
        code: 'blueprint.connector.manifest_missing',
        message: `Connector manifest is missing: ${connectorId}`,
        severity: 'critical',
        connectorId
      }));
    } else if (!scopes.length) {
      status = 'no_scope_match';
      warnings.push(warning({
        code: 'blueprint.connector.no_scope_match',
        message: `No compatible scopes found for connector ${connectorId} under kit ${kit.kit_id}.`,
        severity: 'warning',
        connectorId
      }));
    } else if (missingRequiredCapabilities.length > 0) {
      status = 'partial';
      for (const capability of missingRequiredCapabilities) {
        warnings.push(warning({
          code: 'blueprint.connector.required_capability_missing',
          message: `Connector ${connectorId} is missing required capability ${capability}.`,
          severity: 'warning',
          connectorId,
          capability
        }));
      }
    }

    for (const scope of scopes) {
      if (goalSet.has(scope)) {
        coveredSet.add(scope);
      }
    }

    connectorPlan.push({
      connector_id: connectorId,
      status,
      risk_profile: deriveBindingRiskProfile({ candidate, manifest }),
      trust_level: manifest?.trust_level || 'unknown',
      required_capabilities: requiredCapabilities,
      optional_capabilities: optionalCapabilities,
      missing_required_capabilities: missingRequiredCapabilities,
      scopes
    });
  }

  const coveredCapabilities = Array.from(coveredSet).sort();
  const missingCapabilities = goalCapabilities.filter((item) => !coveredSet.has(item));

  for (const capability of missingCapabilities) {
    warnings.push(warning({
      code: 'blueprint.goal.capability_uncovered',
      message: `Kit goal capability is not covered by selected connectors: ${capability}`,
      severity: 'warning',
      capability
    }));
  }

  const projection = buildPolicyProjection({
    workspaceId,
    capabilities: coveredCapabilities,
    policyContext,
    policyLibrary
  });

  const proposedBindings = connectorPlan.filter(
    (item) => item.scopes.length > 0 && item.status !== 'manifest_missing'
  );

  const elapsedMs = Math.max(0, Date.now() - startedMs);

  return {
    version: 'v0',
    generated_at: nowIso(),
    workspace_id: workspaceId,
    kit: {
      kit_id: kit.kit_id,
      name: kit.name,
      role: kit.role,
      description: kit.description,
      default_policy_profile: kit.default_policy_profile,
      default_playbook_id: kit.default_playbook_id
    },
    agent_draft: {
      workspace_id: workspaceId,
      name: String(agentName || '').trim() || kit.name,
      role: kit.role,
      owners: normalizeOwners(owners),
      default_policy_profile: kit.default_policy_profile,
      default_playbook_id: kit.default_playbook_id
    },
    connector_plan: {
      selected_connector_ids: selected,
      proposed_bindings: proposedBindings,
      connectors: connectorPlan
    },
    capability_coverage: {
      required_total: goalCapabilities.length,
      covered_total: coveredCapabilities.length,
      gap_total: missingCapabilities.length,
      covered_capabilities: coveredCapabilities,
      missing_capabilities: missingCapabilities
    },
    policy_projection: {
      summary: projection.summary,
      items: projection.items
    },
    planner_metrics: {
      elapsed_ms: elapsedMs,
      selected_connectors: selected.length,
      proposed_bindings: proposedBindings.length,
      evaluated_capabilities: coveredCapabilities.length,
      warnings: warnings.length
    },
    approval_forecast: projection.approval_forecast,
    rollout: stableClone(kit.rollout || []),
    warnings
  };
}

export function buildAgentBlueprintLintReport({ preview }) {
  const checks = [];
  const recommendations = [];

  const criticalWarnings = preview.warnings.filter((item) => item.severity === 'critical').length;
  const warningWarnings = preview.warnings.filter((item) => item.severity === 'warning').length;
  const manifestMissing = preview.connector_plan.connectors.filter(
    (item) => item.status === 'manifest_missing'
  ).length;
  const deniedActions = Number(preview.policy_projection.summary.deny || 0);
  const escalatedActions = Number(preview.policy_projection.summary.escalate || 0);
  const gapTotal = Number(preview.capability_coverage.gap_total || 0);

  checks.push({
    id: 'connector_manifest_integrity',
    title: 'Connector Manifest Integrity',
    status: manifestMissing > 0 ? 'fail' : 'pass',
    score_impact: manifestMissing > 0 ? -30 : 0,
    detail: manifestMissing > 0
      ? `${manifestMissing} selected connectors are missing manifests.`
      : 'All selected connectors have manifests.'
  });

  checks.push({
    id: 'capability_coverage',
    title: 'Capability Coverage',
    status: gapTotal === 0 ? 'pass' : gapTotal <= 2 ? 'warn' : 'fail',
    score_impact: gapTotal === 0 ? 0 : gapTotal <= 2 ? -8 : -18,
    detail: gapTotal === 0
      ? 'All kit goal capabilities are covered.'
      : `${gapTotal} goal capabilities are not covered by selected connectors.`
  });

  checks.push({
    id: 'policy_decision_safety',
    title: 'Policy Decision Safety',
    status: deniedActions > 0 ? 'fail' : escalatedActions > 0 ? 'warn' : 'pass',
    score_impact: deniedActions > 0 ? -25 : escalatedActions > 0 ? -6 : 0,
    detail: deniedActions > 0
      ? `${deniedActions} capabilities are denied by policy.`
      : escalatedActions > 0
        ? `${escalatedActions} capabilities require approval.`
        : 'No denied or escalated capabilities in projection.'
  });

  checks.push({
    id: 'warning_budget',
    title: 'Warning Budget',
    status: criticalWarnings > 0 ? 'fail' : warningWarnings > 3 ? 'warn' : 'pass',
    score_impact: criticalWarnings > 0 ? -20 : warningWarnings > 3 ? -10 : 0,
    detail: criticalWarnings > 0
      ? `${criticalWarnings} critical warnings found.`
      : `${warningWarnings} warning-level issues found.`
  });

  if (manifestMissing > 0) {
    recommendations.push(recommendation(
      'add_connector_manifest',
      'Add or restore connector manifests for every selected connector before apply.',
      'high'
    ));
  }

  if (gapTotal > 0) {
    recommendations.push(recommendation(
      'close_capability_gap',
      'Add connectors or adjust kit connector selection to close capability coverage gaps.',
      gapTotal > 2 ? 'high' : 'medium'
    ));
  }

  if (deniedActions > 0) {
    recommendations.push(recommendation(
      'resolve_policy_denies',
      'Review org/workspace/agent policy profiles and remove hard denies for required capabilities.',
      'high'
    ));
  } else if (escalatedActions > 0) {
    recommendations.push(recommendation(
      'prepare_approval_capacity',
      'Prepare approval workload and approver rota for escalated capabilities.',
      'medium'
    ));
  }

  const scoreRaw = 100 + checks.reduce((sum, item) => sum + item.score_impact, 0);
  const score = Math.max(0, Math.min(100, scoreRaw));
  const summary = summarizeLintStatus(checks);

  return {
    version: 'v0',
    generated_at: nowIso(),
    workspace_id: preview.workspace_id,
    kit_id: preview.kit.kit_id,
    summary: {
      status: summary.status,
      score,
      total_checks: checks.length,
      passed: summary.passed,
      warned: summary.warned,
      failed: summary.failed
    },
    checks,
    recommendations,
    preview_ref: {
      capability_coverage: preview.capability_coverage,
      policy_projection_summary: preview.policy_projection.summary,
      approval_forecast: preview.approval_forecast,
      planner_metrics: preview.planner_metrics,
      warning_count: preview.warnings.length
    }
  };
}

function categoryWeight(category) {
  if (category === 'office_system') return 30;
  if (category === 'office_channel') return 20;
  if (category === 'agent_protocol') return 10;
  return 0;
}

function trustWeight(trustLevel) {
  if (trustLevel === 'standard') return 10;
  if (trustLevel === 'sandbox') return 6;
  if (trustLevel === 'high_control') return 2;
  return 0;
}

function buildConnectorSuggestionPool({ manifests, excludedConnectorIds = [] }) {
  const excluded = new Set(excludedConnectorIds);
  return Object.values(manifests || {})
    .filter((manifest) => !excluded.has(manifest.connector_id))
    .map((manifest) => ({
      connector_id: manifest.connector_id,
      category: manifest.category || 'unknown',
      trust_level: manifest.trust_level || 'unknown',
      capabilities: normalizeCapabilityList(manifest.capabilities || [])
    }));
}

function chooseConnectorSuggestions({
  missingCapabilities,
  manifests,
  selectedConnectorIds
}) {
  const remaining = new Set(missingCapabilities || []);
  const pool = buildConnectorSuggestionPool({
    manifests,
    excludedConnectorIds: selectedConnectorIds
  });
  const suggestions = [];

  while (remaining.size > 0) {
    let winner = null;
    for (const candidate of pool) {
      if (suggestions.some((item) => item.connector_id === candidate.connector_id)) continue;
      const covered = candidate.capabilities.filter((capability) => remaining.has(capability));
      if (!covered.length) continue;

      const score = covered.length * 100
        + categoryWeight(candidate.category)
        + trustWeight(candidate.trust_level);

      if (!winner || score > winner.score) {
        winner = {
          ...candidate,
          covered_capabilities: covered,
          score
        };
      }
    }

    if (!winner) break;
    suggestions.push(winner);
    for (const capability of winner.covered_capabilities) {
      remaining.delete(capability);
    }
  }

  return {
    add: suggestions,
    unresolved_capabilities: Array.from(remaining).sort()
  };
}

function statusRank(status) {
  if (status === 'pass') return 2;
  if (status === 'warn') return 1;
  return 0;
}

function normalizePolicyContext(policyContext = {}) {
  return {
    org_policy: String(policyContext.org_policy || DEFAULT_POLICY_CONTEXT.org_policy),
    workspace_policy: String(policyContext.workspace_policy || DEFAULT_POLICY_CONTEXT.workspace_policy),
    agent_policy: String(policyContext.agent_policy || DEFAULT_POLICY_CONTEXT.agent_policy),
    run_override: String(policyContext.run_override || '')
  };
}

function decisionWeight(decision) {
  return POLICY_DECISION_WEIGHT[String(decision || '')] || 99;
}

function simulateBlueprintLint({
  preview,
  manifests,
  policyContext,
  policyLibrary,
  kitLibrary,
  selectedConnectorIds
}) {
  const nextPreview = buildAgentBlueprintPreview({
    workspaceId: preview.workspace_id,
    kitId: preview.kit.kit_id,
    owners: preview.agent_draft.owners,
    agentName: preview.agent_draft.name,
    selectedConnectorIds: selectedConnectorIds || preview.connector_plan.selected_connector_ids || [],
    manifests,
    policyContext,
    policyLibrary,
    kitLibrary
  });
  const nextLint = buildAgentBlueprintLintReport({ preview: nextPreview });
  return {
    preview: nextPreview,
    lint: nextLint
  };
}

function derivePolicyPatchRule(item) {
  const capability = String(item?.capability || '');
  if (!CAPABILITY_PATTERN.test(capability)) return null;

  if (item.side_effect === 'none' || item.risk_hint === 'R0' || item.risk_hint === 'R1') {
    return {
      capability,
      decision: 'allow',
      required_approvals: 0
    };
  }

  if (item.risk_hint === 'R3') {
    return {
      capability,
      decision: 'escalate',
      required_approvals: 2
    };
  }

  return {
    capability,
    decision: 'escalate',
    required_approvals: 1
  };
}

function patchPolicyLibrary({
  policyLibrary,
  profileName,
  patchRules
}) {
  if (!profileName || !policyLibrary?.[profileName]) return null;

  const next = stableClone(policyLibrary);
  const profile = next[profileName];
  if (!profile || typeof profile !== 'object') return null;
  if (!profile.rules || typeof profile.rules !== 'object' || Array.isArray(profile.rules)) {
    profile.rules = {};
  }

  for (const rule of patchRules || []) {
    const capability = String(rule?.capability || '');
    if (!CAPABILITY_PATTERN.test(capability)) continue;
    const decision = String(rule?.decision || '');
    if (!['allow', 'escalate', 'deny'].includes(decision)) continue;
    const requiredApprovals = decision === 'escalate'
      ? Math.max(1, Math.min(5, Number(rule?.required_approvals || 1)))
      : 0;

    profile.rules[capability] = {
      decision,
      requiredApprovals
    };
  }

  return next;
}

function estimatePolicyPatchEffect({
  preview,
  lint,
  manifests,
  policyContext,
  policyLibrary,
  kitLibrary,
  selectedConnectorIds,
  targetProfile,
  patchRules
}) {
  const patchedLibrary = patchPolicyLibrary({
    policyLibrary,
    profileName: targetProfile,
    patchRules
  });

  if (!patchedLibrary) return null;
  const simulation = simulateBlueprintLint({
    preview,
    manifests,
    policyContext,
    policyLibrary: patchedLibrary,
    kitLibrary,
    selectedConnectorIds
  });

  return {
    status_after_estimate: simulation.lint.summary.status,
    score_after_estimate: simulation.lint.summary.score,
    expected_delta: simulation.lint.summary.score - lint.summary.score
  };
}

function improvedCapabilities({ beforePreview, afterPreview }) {
  const beforeByCapability = new Map(
    (beforePreview.policy_projection.items || []).map((item) => [item.capability, item.decision])
  );
  const improved = [];

  for (const item of afterPreview.policy_projection.items || []) {
    const beforeDecision = beforeByCapability.get(item.capability);
    if (!beforeDecision) continue;
    if (decisionWeight(item.decision) < decisionWeight(beforeDecision)) {
      improved.push(item.capability);
    }
  }

  return uniqueSorted(improved);
}

function chooseBestRunOverrideCandidate({
  preview,
  lint,
  manifests,
  policyContext,
  policyLibrary,
  kitLibrary,
  selectedConnectorIds
}) {
  const normalizedContext = normalizePolicyContext(policyContext);
  const profileNames = Object.keys(policyLibrary || {}).sort();
  if (!profileNames.length) return null;

  let best = null;
  for (const profileName of profileNames) {
    if (!profileName || profileName === normalizedContext.run_override) continue;

    const simulation = simulateBlueprintLint({
      preview,
      manifests,
      policyContext: {
        ...normalizedContext,
        run_override: profileName
      },
      policyLibrary,
      kitLibrary,
      selectedConnectorIds
    });
    const expectedDelta = simulation.lint.summary.score - lint.summary.score;
    const statusDelta = statusRank(simulation.lint.summary.status) - statusRank(lint.summary.status);

    if (statusDelta <= 0 && expectedDelta <= 0) continue;

    const candidate = {
      run_override: profileName,
      expected_delta: expectedDelta,
      status_delta: statusDelta,
      status_after_estimate: simulation.lint.summary.status,
      score_after_estimate: simulation.lint.summary.score,
      improved_capabilities: improvedCapabilities({
        beforePreview: preview,
        afterPreview: simulation.preview
      })
    };

    if (!best) {
      best = candidate;
      continue;
    }

    if (candidate.status_delta > best.status_delta) {
      best = candidate;
      continue;
    }

    if (candidate.status_delta === best.status_delta && candidate.expected_delta > best.expected_delta) {
      best = candidate;
    }
  }

  return best;
}

function buildPolicyCandidates({
  preview,
  lint,
  manifests,
  policyContext,
  policyLibrary,
  kitLibrary,
  selectedConnectorIds
}) {
  const items = [];
  const normalizedContext = normalizePolicyContext(policyContext);
  const projectionItems = preview.policy_projection.items || [];
  const deniedItems = projectionItems.filter((item) => item.decision === 'deny');
  const escalatedCapabilities = projectionItems
    .filter((item) => item.decision === 'escalate')
    .map((item) => item.capability);

  const deniedBySource = new Map();
  for (const item of deniedItems) {
    const source = String(item.effective_source || 'unknown');
    if (!deniedBySource.has(source)) {
      deniedBySource.set(source, []);
    }
    deniedBySource.get(source).push(item);
  }

  for (const [source, sourceItems] of deniedBySource.entries()) {
    const targetCapabilities = uniqueSorted(sourceItems.map((item) => item.capability));
    const patchRules = uniqueSorted(sourceItems.map((item) => item.capability))
      .map((capability) => {
        const sample = sourceItems.find((item) => item.capability === capability);
        return derivePolicyPatchRule(sample);
      })
      .filter(Boolean);
    const targetProfile = source === 'org'
      ? normalizedContext.org_policy
      : source === 'workspace'
        ? normalizedContext.workspace_policy
        : source === 'agent'
          ? normalizedContext.agent_policy
          : source === 'run_override'
            ? normalizedContext.run_override
            : '';
    const profileExists = Boolean(targetProfile && policyLibrary?.[targetProfile]);

    const estimatedEffect = profileExists
      ? estimatePolicyPatchEffect({
        preview,
        lint,
        manifests,
        policyContext: normalizedContext,
        policyLibrary,
        kitLibrary,
        selectedConnectorIds,
        targetProfile,
        patchRules
      })
      : null;

    items.push({
      candidate_id: `cand_policy_patch_${source}_${items.length + 1}`,
      type: profileExists ? 'policy_profile_patch' : 'policy_profile_review',
      target_capabilities: targetCapabilities,
      rationale: profileExists
        ? `Denied capabilities are effective at ${source} policy (${targetProfile}). Patch this profile to unblock execution safely.`
        : `Denied capabilities are effective at ${source}; identify and patch the governing profile.`,
      risk_tradeoff: 'high',
      suggested_run_override: '',
      applicability: profileExists ? 'manual' : 'informational',
      target_profile: targetProfile,
      patch_rules: patchRules,
      ...(estimatedEffect ? { estimated_effect: estimatedEffect } : {})
    });
  }

  if (escalatedCapabilities.length > 0) {
    items.push({
      candidate_id: 'cand_approval_capacity',
      type: 'approval_capacity',
      target_capabilities: uniqueSorted(escalatedCapabilities),
      rationale: 'Escalated actions are expected and should be covered by approval rota.',
      risk_tradeoff: 'medium',
      suggested_run_override: '',
      applicability: 'informational',
      target_profile: '',
      patch_rules: []
    });
  }

  const runOverrideCandidate = chooseBestRunOverrideCandidate({
    preview,
    lint,
    manifests,
    policyContext: normalizedContext,
    policyLibrary,
    kitLibrary,
    selectedConnectorIds
  });

  if (runOverrideCandidate) {
    items.push({
      candidate_id: 'cand_run_override_best',
      type: 'run_override_candidate',
      target_capabilities: runOverrideCandidate.improved_capabilities,
      rationale: `Set run_override to existing profile ${runOverrideCandidate.run_override} to recover from current policy-context failures or improve readiness.`,
      risk_tradeoff: 'medium',
      suggested_run_override: runOverrideCandidate.run_override,
      applicability: 'direct',
      target_profile: runOverrideCandidate.run_override,
      patch_rules: [],
      estimated_effect: {
        status_after_estimate: runOverrideCandidate.status_after_estimate,
        score_after_estimate: runOverrideCandidate.score_after_estimate,
        expected_delta: runOverrideCandidate.expected_delta
      }
    });
  }

  if (lint.summary.status === 'fail' && !items.length) {
    items.push({
      candidate_id: 'cand_policy_baseline_review',
      type: 'policy_profile_review',
      target_capabilities: [],
      rationale: 'Lint failed without explicit deny/escalate concentration; baseline policy stack review is required.',
      risk_tradeoff: 'medium',
      suggested_run_override: '',
      applicability: 'informational',
      target_profile: '',
      patch_rules: []
    });
  }

  return items;
}

function mapLintSummary(summary) {
  return {
    status: summary.status,
    score: summary.score,
    total_checks: summary.total_checks,
    passed: summary.passed,
    warned: summary.warned,
    failed: summary.failed
  };
}

export function buildAgentBlueprintRemediationPlan({
  preview,
  lint,
  manifests,
  policyContext,
  policyLibrary,
  kitLibrary
}) {
  const startedMs = Date.now();
  const selectedConnectorIds = normalizeConnectorIds(
    preview.connector_plan.selected_connector_ids || []
  );

  const removable = (preview.connector_plan.connectors || [])
    .filter((item) => ['manifest_missing', 'no_scope_match'].includes(item.status))
    .map((item) => ({
      connector_id: item.connector_id,
      reason: item.status
    }));

  const removableIds = new Set(removable.map((item) => item.connector_id));
  const baseConnectorIds = selectedConnectorIds.filter((id) => !removableIds.has(id));

  const suggestion = chooseConnectorSuggestions({
    missingCapabilities: preview.capability_coverage.missing_capabilities || [],
    manifests,
    selectedConnectorIds: baseConnectorIds
  });

  const suggestedConnectorIds = uniqueSorted([
    ...baseConnectorIds,
    ...suggestion.add.map((item) => item.connector_id)
  ]);

  const normalizedPolicyContext = normalizePolicyContext(policyContext);
  const policyCandidates = buildPolicyCandidates({
    preview,
    lint,
    manifests,
    policyContext: normalizedPolicyContext,
    policyLibrary,
    kitLibrary,
    selectedConnectorIds: suggestedConnectorIds
  });
  const bestDirectRunOverride = policyCandidates
    .filter((item) =>
      item.type === 'run_override_candidate' &&
      item.applicability === 'direct' &&
      Number(item.estimated_effect?.expected_delta || 0) > 0
    )
    .sort((a, b) => Number(b.estimated_effect?.expected_delta || 0) - Number(a.estimated_effect?.expected_delta || 0))[0] || null;
  const effectivePolicyContext = {
    ...normalizedPolicyContext,
    run_override: bestDirectRunOverride?.suggested_run_override || normalizedPolicyContext.run_override
  };

  const previewAfter = buildAgentBlueprintPreview({
    workspaceId: preview.workspace_id,
    kitId: preview.kit.kit_id,
    owners: preview.agent_draft.owners,
    agentName: preview.agent_draft.name,
    selectedConnectorIds: suggestedConnectorIds,
    manifests,
    policyContext: effectivePolicyContext,
    policyLibrary,
    kitLibrary
  });
  const lintAfter = buildAgentBlueprintLintReport({ preview: previewAfter });

  const recommendations = [];

  if (removable.length > 0) {
    recommendations.push(recommendation(
      'remove_unhealthy_connectors',
      'Drop connectors with missing manifests or no scope match before apply.',
      'high'
    ));
  }

  if (suggestion.add.length > 0) {
    recommendations.push(recommendation(
      'add_recommended_connectors',
      `Add ${suggestion.add.length} connectors to close capability gaps.`,
      suggestion.unresolved_capabilities.length ? 'high' : 'medium'
    ));
  }

  if (suggestion.unresolved_capabilities.length > 0) {
    recommendations.push(recommendation(
      'unresolved_capability_gap',
      `Unresolved capabilities remain: ${suggestion.unresolved_capabilities.join(', ')}`,
      'high'
    ));
  }

  if (policyCandidates.length > 0) {
    recommendations.push(recommendation(
      'policy_candidate_review',
      'Review policy candidates before production apply.',
      'medium'
    ));
  }

  if (bestDirectRunOverride) {
    recommendations.push(recommendation(
      'adopt_run_override_candidate',
      `Adopt run_override ${bestDirectRunOverride.suggested_run_override} for estimated score delta ${bestDirectRunOverride.estimated_effect.expected_delta >= 0 ? '+' : ''}${bestDirectRunOverride.estimated_effect.expected_delta}.`,
      'medium'
    ));
  }

  const elapsedMs = Math.max(0, Date.now() - startedMs);

  return {
    version: 'v0',
    generated_at: nowIso(),
    workspace_id: preview.workspace_id,
    kit_id: preview.kit.kit_id,
    summary: {
      status_before: lint.summary.status,
      score_before: lint.summary.score,
      status_after_estimate: lintAfter.summary.status,
      score_after_estimate: lintAfter.summary.score,
      expected_delta: lintAfter.summary.score - lint.summary.score
    },
    connector_actions: {
      suggested_connector_ids: suggestedConnectorIds,
      add: suggestion.add.map((item) => ({
        connector_id: item.connector_id,
        reason: 'capability_gap',
        covered_capabilities: item.covered_capabilities,
        trust_level: item.trust_level,
        category: item.category
      })),
      remove: removable
    },
    policy_candidates: {
      context: {
        org_policy: normalizedPolicyContext.org_policy,
        workspace_policy: normalizedPolicyContext.workspace_policy,
        agent_policy: normalizedPolicyContext.agent_policy,
        run_override: normalizedPolicyContext.run_override
      },
      items: policyCandidates
    },
    auto_fix_request: {
      workspace_id: preview.workspace_id,
      kit_id: preview.kit.kit_id,
      owners: preview.agent_draft.owners,
      agent_name: preview.agent_draft.name,
      selected_connector_ids: suggestedConnectorIds,
      policy_context: {
        org_policy: effectivePolicyContext.org_policy,
        workspace_policy: effectivePolicyContext.workspace_policy,
        agent_policy: effectivePolicyContext.agent_policy,
        run_override: effectivePolicyContext.run_override
      }
    },
    auto_fix_preview: {
      capability_coverage: previewAfter.capability_coverage,
      policy_projection_summary: previewAfter.policy_projection.summary,
      approval_forecast: previewAfter.approval_forecast,
      lint_summary: mapLintSummary(lintAfter.summary)
    },
    unresolved_capabilities: suggestion.unresolved_capabilities,
    planner_metrics: {
      elapsed_ms: elapsedMs
    },
    recommendations
  };
}

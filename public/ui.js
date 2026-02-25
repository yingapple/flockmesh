const state = {
  agents: [],
  bindings: [],
  runs: [],
  connectorHealth: null,
  connectorDrift: null,
  attestationSummary: null,
  agentKits: [],
  quickstartResult: null,
  blueprintPreview: null,
  blueprintLint: null,
  blueprintRemediation: null,
  policyProfiles: [],
  policyProfileVersions: {},
  policyPatchResult: null,
  policyRollbackHistory: [],
  policyRollbackResult: null,
  pendingApprovals: [],
  selectedRunId: null,
  timelineEvents: null,
  timelineAudit: null,
  timelineDiff: null,
  replayIntegrity: null,
  replayDrift: null,
  timelineDiffBaseRunId: '',
  uiMode: 'starter',
  compactMode: false
};

const DEMO_BOOTSTRAP_PRESET = Object.freeze({
  connector_id: 'con_office_calendar',
  scopes: ['calendar.read', 'calendar.write'],
  auth_ref: 'sec_office_calendar_token_prod',
  risk_profile: 'restricted',
  trigger_source: 'system.scheduler:weekly_ops_sync'
});

const ONE_PERSON_QUICKSTART_TEMPLATES = Object.freeze({
  weekly_ops_sync: Object.freeze({
    label: 'Weekly Ops Sync',
    defaultConnectorIds: ['con_feishu_official']
  }),
  incident_response: Object.freeze({
    label: 'Incident Response',
    defaultConnectorIds: ['con_feishu_official']
  })
});

const UI_MODE_STORAGE_KEY = 'flockmesh_ui_mode';
const UI_MODE_SET = new Set(['starter', 'advanced']);

const els = {
  bootstrapBtn: document.getElementById('bootstrapBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  starterModeBtn: document.getElementById('starterModeBtn'),
  advancedModeBtn: document.getElementById('advancedModeBtn'),
  compactToggleBtn: document.getElementById('compactToggleBtn'),
  quickstartTag: document.getElementById('quickstartTag'),
  quickstartWorkspaceInput: document.getElementById('quickstartWorkspaceInput'),
  quickstartOwnerInput: document.getElementById('quickstartOwnerInput'),
  quickstartTemplateSelect: document.getElementById('quickstartTemplateSelect'),
  quickstartConnectorIdsInput: document.getElementById('quickstartConnectorIdsInput'),
  quickstartIdemInput: document.getElementById('quickstartIdemInput'),
  quickstartStartBtn: document.getElementById('quickstartStartBtn'),
  quickstartMeta: document.getElementById('quickstartMeta'),
  quickstartPayload: document.getElementById('quickstartPayload'),
  advancedToolsOpenBtn: document.getElementById('advancedToolsOpenBtn'),
  createAgentBtn: document.getElementById('createAgentBtn'),
  createBindingBtn: document.getElementById('createBindingBtn'),
  createRunBtn: document.getElementById('createRunBtn'),
  healthTag: document.getElementById('healthTag'),
  healthPayload: document.getElementById('healthPayload'),
  connectorHealthTag: document.getElementById('connectorHealthTag'),
  connectorHealthPayload: document.getElementById('connectorHealthPayload'),
  connectorDriftPayload: document.getElementById('connectorDriftPayload'),
  attestationTag: document.getElementById('attestationTag'),
  attestationVerifiedCount: document.getElementById('attestationVerifiedCount'),
  attestationUnverifiedCount: document.getElementById('attestationUnverifiedCount'),
  attestationMissingCount: document.getElementById('attestationMissingCount'),
  attestationHighControlRiskCount: document.getElementById('attestationHighControlRiskCount'),
  attestationKeyIds: document.getElementById('attestationKeyIds'),
  approvalInboxTag: document.getElementById('approvalInboxTag'),
  approvalInbox: document.getElementById('approvalInbox'),
  timelineTag: document.getElementById('timelineTag'),
  timelineRunSelect: document.getElementById('timelineRunSelect'),
  timelineBaseRunSelect: document.getElementById('timelineBaseRunSelect'),
  timelineReloadBtn: document.getElementById('timelineReloadBtn'),
  timelineDiffBtn: document.getElementById('timelineDiffBtn'),
  timelineReplayBtn: document.getElementById('timelineReplayBtn'),
  timelineReplayExportBtn: document.getElementById('timelineReplayExportBtn'),
  timelineExportBtn: document.getElementById('timelineExportBtn'),
  timelineMeta: document.getElementById('timelineMeta'),
  timelineEventsPayload: document.getElementById('timelineEventsPayload'),
  timelineAuditPayload: document.getElementById('timelineAuditPayload'),
  timelineDiffMeta: document.getElementById('timelineDiffMeta'),
  timelineDiffPayload: document.getElementById('timelineDiffPayload'),
  timelineReplayMeta: document.getElementById('timelineReplayMeta'),
  timelineReplayPayload: document.getElementById('timelineReplayPayload'),
  replayDriftTag: document.getElementById('replayDriftTag'),
  replayDriftRefreshBtn: document.getElementById('replayDriftRefreshBtn'),
  replayDriftMeta: document.getElementById('replayDriftMeta'),
  replayDriftPayload: document.getElementById('replayDriftPayload'),
  policyTraceTag: document.getElementById('policyTraceTag'),
  policyTracePayload: document.getElementById('policyTracePayload'),
  actionLog: document.getElementById('actionLog'),
  runFeed: document.getElementById('runFeed'),
  agentsCount: document.getElementById('agentsCount'),
  bindingsCount: document.getElementById('bindingsCount'),
  runsCount: document.getElementById('runsCount'),
  pendingCount: document.getElementById('pendingCount'),
  blueprintTag: document.getElementById('blueprintTag'),
  blueprintWorkspaceInput: document.getElementById('blueprintWorkspaceInput'),
  blueprintKitSelect: document.getElementById('blueprintKitSelect'),
  blueprintAgentNameInput: document.getElementById('blueprintAgentNameInput'),
  blueprintOwnersInput: document.getElementById('blueprintOwnersInput'),
  blueprintConnectorsInput: document.getElementById('blueprintConnectorsInput'),
  blueprintPolicyOrgInput: document.getElementById('blueprintPolicyOrgInput'),
  blueprintPolicyWorkspaceInput: document.getElementById('blueprintPolicyWorkspaceInput'),
  blueprintPolicyAgentInput: document.getElementById('blueprintPolicyAgentInput'),
  blueprintRunOverrideInput: document.getElementById('blueprintRunOverrideInput'),
  blueprintAuthRefsInput: document.getElementById('blueprintAuthRefsInput'),
  blueprintIdemInput: document.getElementById('blueprintIdemInput'),
  blueprintStrictModeInput: document.getElementById('blueprintStrictModeInput'),
  blueprintReloadBtn: document.getElementById('blueprintReloadBtn'),
  blueprintPreviewBtn: document.getElementById('blueprintPreviewBtn'),
  blueprintLintBtn: document.getElementById('blueprintLintBtn'),
  blueprintRemediateBtn: document.getElementById('blueprintRemediateBtn'),
  blueprintApplyBtn: document.getElementById('blueprintApplyBtn'),
  blueprintMeta: document.getElementById('blueprintMeta'),
  blueprintPayload: document.getElementById('blueprintPayload'),
  policyPatchTag: document.getElementById('policyPatchTag'),
  policyPatchProfileSelect: document.getElementById('policyPatchProfileSelect'),
  policyPatchActorInput: document.getElementById('policyPatchActorInput'),
  policyPatchReasonInput: document.getElementById('policyPatchReasonInput'),
  policyPatchHashInput: document.getElementById('policyPatchHashInput'),
  policyPatchRulesInput: document.getElementById('policyPatchRulesInput'),
  policyPatchReloadBtn: document.getElementById('policyPatchReloadBtn'),
  policyPatchVersionBtn: document.getElementById('policyPatchVersionBtn'),
  policyPatchFromRemediationBtn: document.getElementById('policyPatchFromRemediationBtn'),
  policyPatchDryRunBtn: document.getElementById('policyPatchDryRunBtn'),
  policyPatchApplyBtn: document.getElementById('policyPatchApplyBtn'),
  policyPatchMeta: document.getElementById('policyPatchMeta'),
  policyPatchPayload: document.getElementById('policyPatchPayload'),
  policyRollbackTag: document.getElementById('policyRollbackTag'),
  policyRollbackProfileSelect: document.getElementById('policyRollbackProfileSelect'),
  policyRollbackActorInput: document.getElementById('policyRollbackActorInput'),
  policyRollbackReasonInput: document.getElementById('policyRollbackReasonInput'),
  policyRollbackTargetPatchIdInput: document.getElementById('policyRollbackTargetPatchIdInput'),
  policyRollbackTargetStateSelect: document.getElementById('policyRollbackTargetStateSelect'),
  policyRollbackHashInput: document.getElementById('policyRollbackHashInput'),
  policyRollbackReloadBtn: document.getElementById('policyRollbackReloadBtn'),
  policyRollbackVersionBtn: document.getElementById('policyRollbackVersionBtn'),
  policyRollbackDraftLatestBtn: document.getElementById('policyRollbackDraftLatestBtn'),
  policyRollbackDryRunBtn: document.getElementById('policyRollbackDryRunBtn'),
  policyRollbackApplyBtn: document.getElementById('policyRollbackApplyBtn'),
  policyRollbackMeta: document.getElementById('policyRollbackMeta'),
  policyRollbackHistoryPayload: document.getElementById('policyRollbackHistoryPayload'),
  policyRollbackPayload: document.getElementById('policyRollbackPayload'),
  runCardTemplate: document.getElementById('runCardTemplate')
};

function logAction(label, payload) {
  const line = `[${new Date().toISOString()}] ${label}\n${JSON.stringify(payload, null, 2)}\n`;
  els.actionLog.textContent = `${line}\n${els.actionLog.textContent}`.slice(0, 8000);
}

function inferActorIdFromInit(init = {}) {
  if (typeof init?.body !== 'string' || !init.body.trim()) {
    return '';
  }

  try {
    const payload = JSON.parse(init.body);
    const candidates = [
      payload?.owner_id,
      payload?.actor_id,
      payload?.approved_by,
      payload?.cancelled_by,
      payload?.initiated_by,
      payload?.trigger?.actor_id
    ];
    for (const candidate of candidates) {
      const actorId = String(candidate || '').trim();
      if (actorId) return actorId;
    }
  } catch {
    return '';
  }

  return '';
}

function resolveUiActorId(init = {}) {
  const fromPayload = inferActorIdFromInit(init);
  if (fromPayload) return fromPayload;
  const fromQuickstart = String(els.quickstartOwnerInput?.value || '').trim();
  if (fromQuickstart) return fromQuickstart;
  return 'usr_yingapple';
}

async function api(path, init = {}) {
  const actorId = resolveUiActorId(init);
  const requestHeaders = {
    'Content-Type': 'application/json',
    'x-flockmesh-actor-id': actorId,
    ...(init.headers || {})
  };

  const res = await fetch(path, {
    ...init,
    headers: requestHeaders
  });

  const text = await res.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }

  if (!res.ok) {
    const err = new Error(`${res.status} ${res.statusText}: ${JSON.stringify(payload)}`);
    err.status = res.status;
    err.payload = payload;
    throw err;
  }

  return payload;
}

function safeDateMs(value) {
  const ms = Date.parse(value || '');
  return Number.isFinite(ms) ? ms : 0;
}

function summarizeAttestation(health) {
  const items = Array.isArray(health?.items) ? health.items : [];
  const verified = items.filter((item) => item.attestation_valid === true).length;
  const unverified = items.length - verified;
  const missingManifest = items.filter((item) => item.manifest_loaded === false).length;
  const highControlRisk = items.filter(
    (item) => item.trust_level === 'high_control' && item.attestation_valid !== true
  ).length;
  const keyIds = Array.from(
    new Set(
      items
        .map((item) => item.attestation_key_id)
        .filter((value) => typeof value === 'string' && value && value !== 'unknown')
    )
  ).sort();

  return {
    total: items.length,
    verified,
    unverified,
    missingManifest,
    highControlRisk,
    keyIds
  };
}

function parseCsvUnique(value) {
  const parts = String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  return Array.from(new Set(parts));
}

function parseAuthRefsMap(value) {
  const map = {};
  const entries = String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  for (const entry of entries) {
    const index = entry.indexOf('=');
    if (index <= 0) continue;
    const connectorId = entry.slice(0, index).trim();
    const authRef = entry.slice(index + 1).trim();
    if (!connectorId || !authRef) continue;
    map[connectorId] = authRef;
  }

  return map;
}

function setQuickstartTag(label, color = '#b9d4cc') {
  els.quickstartTag.textContent = label;
  els.quickstartTag.style.color = color;
}

function selectedQuickstartTemplateId() {
  return String(els.quickstartTemplateSelect.value || 'weekly_ops_sync');
}

function quickstartTemplateDefaultConnectorIds(templateId) {
  const template = ONE_PERSON_QUICKSTART_TEMPLATES[templateId];
  if (!template) return ['con_feishu_official'];
  return template.defaultConnectorIds || ['con_feishu_official'];
}

function effectiveQuickstartConnectorIds() {
  const explicit = parseCsvUnique(els.quickstartConnectorIdsInput.value);
  if (explicit.length) return explicit;
  return quickstartTemplateDefaultConnectorIds(selectedQuickstartTemplateId());
}

function listModeNodes(mode) {
  return Array.from(document.querySelectorAll(`[data-ui-mode="${mode}"]`));
}

function readInitialUiMode() {
  const persisted = window.localStorage.getItem(UI_MODE_STORAGE_KEY);
  if (UI_MODE_SET.has(persisted)) return persisted;
  return 'starter';
}

function setUiMode(mode, { persist = true } = {}) {
  const nextMode = mode === 'advanced' ? 'advanced' : 'starter';
  state.uiMode = nextMode;

  const showAdvanced = nextMode === 'advanced';
  const showStarter = nextMode === 'starter';
  for (const node of listModeNodes('advanced')) {
    node.classList.toggle('mode-hidden', !showAdvanced);
    node.setAttribute('aria-hidden', showAdvanced ? 'false' : 'true');
  }
  for (const node of listModeNodes('starter')) {
    node.classList.toggle('mode-hidden', !showStarter);
    node.setAttribute('aria-hidden', showStarter ? 'false' : 'true');
  }

  els.starterModeBtn.classList.toggle('is-active', nextMode === 'starter');
  els.advancedModeBtn.classList.toggle('is-active', nextMode === 'advanced');

  if (persist) {
    window.localStorage.setItem(UI_MODE_STORAGE_KEY, nextMode);
  }
}

const POLICY_PATCH_CAPABILITY_PATTERN = /^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)$/;
const POLICY_PATCH_DECISION_SET = new Set(['allow', 'deny', 'escalate']);

function setPolicyPatchTag(label, color = '#b9d4cc') {
  els.policyPatchTag.textContent = label;
  els.policyPatchTag.style.color = color;
}

function setPolicyRollbackTag(label, color = '#b9d4cc') {
  els.policyRollbackTag.textContent = label;
  els.policyRollbackTag.style.color = color;
}

function normalizePolicyPatchRule(rawRule, index) {
  if (!rawRule || typeof rawRule !== 'object' || Array.isArray(rawRule)) {
    throw new Error(`patch_rules[${index}] must be an object`);
  }

  const capability = String(rawRule.capability || '').trim();
  if (!POLICY_PATCH_CAPABILITY_PATTERN.test(capability)) {
    throw new Error(`patch_rules[${index}] invalid capability: ${capability}`);
  }

  const decision = String(rawRule.decision || '').trim();
  if (!POLICY_PATCH_DECISION_SET.has(decision)) {
    throw new Error(`patch_rules[${index}] invalid decision: ${decision}`);
  }

  const requiredApprovals = decision === 'escalate'
    ? Number(rawRule.required_approvals ?? rawRule.requiredApprovals ?? 1)
    : 0;

  if (
    decision === 'escalate' &&
    (!Number.isInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 5)
  ) {
    throw new Error(`patch_rules[${index}] required_approvals must be 1..5 for escalate`);
  }

  return {
    capability,
    decision,
    required_approvals: decision === 'escalate' ? requiredApprovals : 0
  };
}

function parsePolicyPatchRulesInput(rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) {
    throw new Error('Patch rules are required.');
  }

  let rawRules = [];
  if (value.startsWith('[') || value.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch {
      throw new Error('Patch rules JSON is invalid.');
    }
    if (Array.isArray(parsed)) {
      rawRules = parsed;
    } else if (parsed && typeof parsed === 'object' && Array.isArray(parsed.patch_rules)) {
      rawRules = parsed.patch_rules;
    } else {
      throw new Error('Patch rules JSON must be an array or an object with patch_rules.');
    }
  } else {
    rawRules = value
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line, index) => {
        const parts = line.replace(/,/g, ' ').split(/\s+/).filter(Boolean);
        if (parts.length < 2) {
          throw new Error(`Line ${index + 1} must use: capability decision [required_approvals]`);
        }
        const [capability, decision, requiredApprovalsRaw] = parts;
        return {
          capability,
          decision,
          ...(requiredApprovalsRaw ? { required_approvals: Number(requiredApprovalsRaw) } : {})
        };
      });
  }

  if (!rawRules.length) {
    throw new Error('Patch rules are required.');
  }

  const normalized = rawRules.map((item, index) => normalizePolicyPatchRule(item, index));
  const seen = new Set();
  for (const rule of normalized) {
    if (seen.has(rule.capability)) {
      throw new Error(`Duplicate capability in patch_rules: ${rule.capability}`);
    }
    seen.add(rule.capability);
  }
  normalized.sort((a, b) => a.capability.localeCompare(b.capability));
  return normalized;
}

function formatPolicyPatchRulesText(rules = []) {
  return (rules || [])
    .map((item) =>
      item.decision === 'escalate'
        ? `${item.capability} ${item.decision} ${item.required_approvals ?? 1}`
        : `${item.capability} ${item.decision}`
    )
    .join('\n');
}

function refreshPolicyPatchProfileSelect({ preferredProfileName = '' } = {}) {
  const profiles = [...state.policyProfiles].sort((a, b) =>
    String(a.profile_name || '').localeCompare(String(b.profile_name || ''))
  );
  const previous = els.policyPatchProfileSelect.value;
  els.policyPatchProfileSelect.innerHTML = '';

  if (!profiles.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No policy profiles loaded';
    els.policyPatchProfileSelect.appendChild(option);
    els.policyPatchProfileSelect.disabled = true;
    els.policyPatchHashInput.value = '(no profile selected)';
    return;
  }

  els.policyPatchProfileSelect.disabled = false;
  for (const profile of profiles) {
    const option = document.createElement('option');
    option.value = profile.profile_name;
    option.textContent = `${profile.profile_name} · rules ${profile.rule_count}`;
    els.policyPatchProfileSelect.appendChild(option);
  }

  const preferred = preferredProfileName && profiles.some((item) => item.profile_name === preferredProfileName)
    ? preferredProfileName
    : previous && profiles.some((item) => item.profile_name === previous)
      ? previous
      : profiles[0].profile_name;
  els.policyPatchProfileSelect.value = preferred;
}

function refreshPolicyRollbackProfileSelect({ preferredProfileName = '' } = {}) {
  const profiles = [...state.policyProfiles].sort((a, b) =>
    String(a.profile_name || '').localeCompare(String(b.profile_name || ''))
  );
  const previous = els.policyRollbackProfileSelect.value;
  els.policyRollbackProfileSelect.innerHTML = '';

  if (!profiles.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No policy profiles loaded';
    els.policyRollbackProfileSelect.appendChild(option);
    els.policyRollbackProfileSelect.disabled = true;
    els.policyRollbackHashInput.value = '(no profile selected)';
    return;
  }

  els.policyRollbackProfileSelect.disabled = false;
  for (const profile of profiles) {
    const option = document.createElement('option');
    option.value = profile.profile_name;
    option.textContent = `${profile.profile_name} · rules ${profile.rule_count}`;
    els.policyRollbackProfileSelect.appendChild(option);
  }

  const preferred = preferredProfileName && profiles.some((item) => item.profile_name === preferredProfileName)
    ? preferredProfileName
    : previous && profiles.some((item) => item.profile_name === previous)
      ? previous
      : profiles[0].profile_name;
  els.policyRollbackProfileSelect.value = preferred;
}

function selectedPolicyPatchProfileName() {
  return String(els.policyPatchProfileSelect.value || '').trim();
}

function selectedPolicyProfileName() {
  return selectedPolicyPatchProfileName();
}

function selectedPolicyRollbackProfileName() {
  return String(els.policyRollbackProfileSelect.value || '').trim();
}

function setPolicyPatchVersionField(profileName) {
  const targetProfile = String(profileName || '').trim() || selectedPolicyPatchProfileName();
  if (!targetProfile) {
    els.policyPatchHashInput.value = '(no profile selected)';
    return;
  }

  const snapshot = state.policyProfileVersions[targetProfile];
  if (!snapshot || typeof snapshot.document_hash !== 'string' || !snapshot.document_hash) {
    els.policyPatchHashInput.value = '(version not loaded)';
    return;
  }

  els.policyPatchHashInput.value = snapshot.document_hash;
}

function setPolicyRollbackVersionField(profileName) {
  const targetProfile = String(profileName || '').trim() || selectedPolicyRollbackProfileName();
  if (!targetProfile) {
    els.policyRollbackHashInput.value = '(no profile selected)';
    return;
  }

  const snapshot = state.policyProfileVersions[targetProfile];
  if (!snapshot || typeof snapshot.document_hash !== 'string' || !snapshot.document_hash) {
    els.policyRollbackHashInput.value = '(version not loaded)';
    return;
  }

  els.policyRollbackHashInput.value = snapshot.document_hash;
}

async function loadPolicyProfileVersion({ profileName = '', silent = false } = {}) {
  const targetProfile = String(profileName || '').trim();
  if (!targetProfile) {
    setPolicyPatchVersionField('');
    setPolicyRollbackVersionField('');
    return null;
  }

  try {
    const payload = await api(`/v0/policy/profiles/${encodeURIComponent(targetProfile)}/version`);
    state.policyProfileVersions[targetProfile] = payload;
    if (selectedPolicyPatchProfileName() === targetProfile) {
      setPolicyPatchVersionField(targetProfile);
    }
    if (selectedPolicyRollbackProfileName() === targetProfile) {
      setPolicyRollbackVersionField(targetProfile);
    }
    return payload;
  } catch (err) {
    delete state.policyProfileVersions[targetProfile];
    if (selectedPolicyPatchProfileName() === targetProfile) {
      setPolicyPatchVersionField(targetProfile);
    }
    if (selectedPolicyRollbackProfileName() === targetProfile) {
      setPolicyRollbackVersionField(targetProfile);
    }
    if (!silent) {
      throw err;
    }
    return null;
  }
}

function pickPolicyPatchCandidateFromRemediation(remediation = state.blueprintRemediation) {
  const candidates = Array.isArray(remediation?.policy_candidates?.items)
    ? remediation.policy_candidates.items
    : [];
  return [...candidates]
    .filter((item) =>
      item?.type === 'policy_profile_patch' &&
      typeof item.target_profile === 'string' &&
      item.target_profile &&
      Array.isArray(item.patch_rules) &&
      item.patch_rules.length > 0
    )
    .sort(
      (a, b) =>
        Number(b.estimated_effect?.expected_delta || 0) -
          Number(a.estimated_effect?.expected_delta || 0) ||
        String(a.candidate_id || '').localeCompare(String(b.candidate_id || ''))
    )[0] || null;
}

function adoptPolicyPatchCandidateFromRemediation({ remediation, overwriteRules = true } = {}) {
  const candidate = pickPolicyPatchCandidateFromRemediation(remediation);
  if (!candidate) return null;

  const hasRules = String(els.policyPatchRulesInput.value || '').trim().length > 0;
  if (!overwriteRules && hasRules) {
    return candidate;
  }

  if (candidate.target_profile) {
    refreshPolicyPatchProfileSelect({ preferredProfileName: candidate.target_profile });
  }
  els.policyPatchReasonInput.value = `from ${candidate.candidate_id}: ${candidate.rationale}`;
  els.policyPatchRulesInput.value = formatPolicyPatchRulesText(candidate.patch_rules);
  return candidate;
}

function formatPolicyRollbackHistoryPreview(items = []) {
  if (!Array.isArray(items) || !items.length) {
    return 'No rollback history loaded.';
  }

  return items
    .slice(0, 20)
    .map((item, index) => {
      const when = String(item.applied_at || '').replace('T', ' ').replace('Z', 'Z');
      const target = String(item.rollback_target_patch_id || '').trim() || '-';
      return `${String(index + 1).padStart(2, '0')}. ${item.patch_id} | ${item.operation} | ${when} | target:${target}`;
    })
    .join('\n');
}

async function loadPolicyRollbackHistory({
  profileName = '',
  silent = false,
  updateMeta = true
} = {}) {
  const targetProfile = String(profileName || '').trim() || selectedPolicyRollbackProfileName();
  if (!targetProfile) {
    state.policyRollbackHistory = [];
    els.policyRollbackHistoryPayload.textContent = 'No rollback history loaded.';
    return null;
  }

  try {
    const payload = await api(
      `/v0/policy/patches?profile_name=${encodeURIComponent(targetProfile)}&limit=50&offset=0`
    );
    const items = Array.isArray(payload.items) ? payload.items : [];
    state.policyRollbackHistory = items;
    els.policyRollbackHistoryPayload.textContent = formatPolicyRollbackHistoryPreview(items);
    if (updateMeta) {
      els.policyRollbackMeta.textContent = `${items.length} history entries loaded for ${targetProfile}.`;
    }
    return payload;
  } catch (err) {
    state.policyRollbackHistory = [];
    els.policyRollbackHistoryPayload.textContent = String(err);
    if (!silent) {
      throw err;
    }
    return null;
  }
}

function draftPolicyRollbackFromLatest() {
  const latest = Array.isArray(state.policyRollbackHistory) ? state.policyRollbackHistory[0] : null;
  if (!latest) {
    throw new Error('No policy history entry found for selected profile.');
  }

  els.policyRollbackTargetPatchIdInput.value = String(latest.patch_id || '');
  els.policyRollbackTargetStateSelect.value = 'before';
  els.policyRollbackReasonInput.value = `rollback to before:${latest.patch_id}`;
  return latest;
}

async function loadPolicyProfiles({ preferredProfileName = '', setReadyTag = true } = {}) {
  try {
    const payload = await api('/v0/policy/profiles');
    state.policyProfiles = Array.isArray(payload.items) ? payload.items : [];
    state.policyProfileVersions = {};
    state.policyRollbackHistory = [];
    refreshPolicyPatchProfileSelect({ preferredProfileName });
    refreshPolicyRollbackProfileSelect({ preferredProfileName });
    if (setReadyTag) {
      setPolicyPatchTag(
        state.policyProfiles.length ? 'profiles-ready' : 'profiles-empty',
        state.policyProfiles.length ? '#5ae2a8' : '#ffb03a'
      );
      setPolicyRollbackTag(
        state.policyProfiles.length ? 'profiles-ready' : 'profiles-empty',
        state.policyProfiles.length ? '#5ae2a8' : '#ffb03a'
      );
    }
    els.policyPatchMeta.textContent = `${state.policyProfiles.length} policy profiles loaded.`;
    if (!state.policyRollbackResult) {
      els.policyRollbackMeta.textContent = `${state.policyProfiles.length} policy profiles loaded.`;
    }
    if (state.policyProfiles.length > 0) {
      const patchProfile = selectedPolicyPatchProfileName();
      const rollbackProfile = selectedPolicyRollbackProfileName();
      const tasks = [];

      if (patchProfile) {
        tasks.push(loadPolicyProfileVersion({ profileName: patchProfile, silent: true }));
      }
      if (rollbackProfile && rollbackProfile !== patchProfile) {
        tasks.push(loadPolicyProfileVersion({ profileName: rollbackProfile, silent: true }));
      }
      await Promise.all(tasks);
      setPolicyPatchVersionField(patchProfile);
      setPolicyRollbackVersionField(rollbackProfile);
      await loadPolicyRollbackHistory({
        profileName: rollbackProfile,
        silent: true,
        updateMeta: !state.policyRollbackResult
      });
    } else {
      setPolicyPatchVersionField('');
      setPolicyRollbackVersionField('');
      els.policyRollbackHistoryPayload.textContent = 'No rollback history loaded.';
    }
    if (!state.policyPatchResult) {
      els.policyPatchPayload.textContent = 'No policy patch payload yet.';
    }
    if (!state.policyRollbackResult) {
      els.policyRollbackPayload.textContent = 'No policy rollback payload yet.';
    }
  } catch (err) {
    state.policyProfiles = [];
    state.policyProfileVersions = {};
    state.policyRollbackHistory = [];
    refreshPolicyPatchProfileSelect();
    refreshPolicyRollbackProfileSelect();
    setPolicyPatchTag('error', '#ff6b6b');
    setPolicyRollbackTag('error', '#ff6b6b');
    els.policyPatchMeta.textContent = String(err);
    els.policyRollbackMeta.textContent = String(err);
    if (!state.policyPatchResult) {
      els.policyPatchPayload.textContent = String(err);
    }
    if (!state.policyRollbackResult) {
      els.policyRollbackPayload.textContent = String(err);
    }
    els.policyRollbackHistoryPayload.textContent = String(err);
  }
}

function buildPolicyPatchRequest(mode) {
  const profileName = String(els.policyPatchProfileSelect.value || '').trim();
  if (!profileName) {
    throw new Error('Select a policy profile first.');
  }

  const patchRules = parsePolicyPatchRulesInput(els.policyPatchRulesInput.value);
  const requestPayload = {
    profile_name: profileName,
    mode,
    actor_id: String(els.policyPatchActorInput.value || '').trim() || 'usr_policy_admin',
    reason: String(els.policyPatchReasonInput.value || '').trim() || 'policy patch from control plane',
    patch_rules: patchRules
  };

  if (mode === 'apply') {
    const version = state.policyProfileVersions[profileName];
    const expectedProfileHash = String(version?.document_hash || '').trim();
    if (!expectedProfileHash) {
      throw new Error(`Missing profile hash for ${profileName}. Click Refresh Version first.`);
    }
    requestPayload.expected_profile_hash = expectedProfileHash;
  }

  return requestPayload;
}

async function refreshSelectedPolicyProfileVersion({ updateMeta = false } = {}) {
  const profileName = selectedPolicyPatchProfileName();
  if (!profileName) {
    setPolicyPatchVersionField('');
    return null;
  }

  const payload = await loadPolicyProfileVersion({ profileName });
  if (updateMeta && payload?.document_hash) {
    els.policyPatchMeta.textContent = `Loaded version hash for ${profileName}.`;
  }
  return payload;
}

async function refreshSelectedPolicyRollbackProfileVersion({ updateMeta = false } = {}) {
  const profileName = selectedPolicyRollbackProfileName();
  if (!profileName) {
    setPolicyRollbackVersionField('');
    return null;
  }

  const payload = await loadPolicyProfileVersion({ profileName });
  if (updateMeta && payload?.document_hash) {
    els.policyRollbackMeta.textContent = `Loaded version hash for ${profileName}.`;
  }
  return payload;
}

function buildPolicyRollbackRequest(mode) {
  const profileName = selectedPolicyRollbackProfileName();
  if (!profileName) {
    throw new Error('Select a policy profile first.');
  }

  const requestPayload = {
    profile_name: profileName,
    mode,
    target_state: String(els.policyRollbackTargetStateSelect.value || 'before') === 'after'
      ? 'after'
      : 'before',
    actor_id: String(els.policyRollbackActorInput.value || '').trim() || 'usr_policy_admin',
    reason: String(els.policyRollbackReasonInput.value || '').trim() || 'policy rollback from control plane'
  };

  const targetPatchId = String(els.policyRollbackTargetPatchIdInput.value || '').trim();
  if (targetPatchId) {
    requestPayload.target_patch_id = targetPatchId;
  }

  if (mode === 'apply') {
    const version = state.policyProfileVersions[profileName];
    const expectedProfileHash = String(version?.document_hash || '').trim();
    if (!expectedProfileHash) {
      throw new Error(`Missing profile hash for ${profileName}. Click Refresh Version first.`);
    }
    requestPayload.expected_profile_hash = expectedProfileHash;
  }

  return requestPayload;
}

function applyPolicyPatchConflictHint(err, requestPayload) {
  const conflictPayload = err?.payload && typeof err.payload === 'object' ? err.payload : null;
  if (!conflictPayload || Number(err?.status || 0) !== 409) return false;
  if (!requestPayload || requestPayload.mode !== 'apply') return false;

  const profileName = String(requestPayload.profile_name || '').trim();
  const currentHash = String(conflictPayload.current_profile_hash || '').trim();
  if (profileName && currentHash) {
    state.policyProfileVersions[profileName] = {
      version: 'v0',
      generated_at: new Date().toISOString(),
      profile_name: profileName,
      rule_count: Number(
        state.policyProfiles.find((item) => item.profile_name === profileName)?.rule_count || 0
      ),
      document_hash: currentHash,
      file_path: String(
        state.policyProfiles.find((item) => item.profile_name === profileName)?.file_path ||
          `policies/${profileName}.policy.json`
      )
    };
    setPolicyPatchVersionField(profileName);
  }

  const expectedHash = String(conflictPayload.expected_profile_hash || '').trim();
  els.policyPatchMeta.textContent =
    `Hash conflict for ${profileName}. Current hash has been refreshed; retry apply.`;
  els.policyPatchPayload.textContent = JSON.stringify({
    message: conflictPayload.message || 'Policy hash conflict',
    profile_name: profileName,
    expected_profile_hash: expectedHash,
    current_profile_hash: currentHash
  }, null, 2);
  setPolicyPatchTag('hash-conflict', '#ffb03a');
  logAction('policy:patch:hash-conflict', {
    profile_name: profileName,
    expected_profile_hash: expectedHash,
    current_profile_hash: currentHash
  });
  return true;
}

async function runPolicyPatch(mode) {
  let requestPayload = null;
  try {
    requestPayload = buildPolicyPatchRequest(mode);
    if (mode === 'apply') {
      await refreshSelectedPolicyProfileVersion();
      requestPayload = buildPolicyPatchRequest(mode);
    }
    setPolicyPatchTag(mode === 'apply' ? 'applying' : 'simulating', '#5fd1ff');
    const payload = await api('/v0/policy/patch', {
      method: 'POST',
      body: JSON.stringify(requestPayload)
    });
    state.policyPatchResult = payload;
    els.policyPatchPayload.textContent = JSON.stringify(payload, null, 2);

    const improved = Number(payload.simulation_preview?.improved_capabilities?.length || 0);
    const meta = `${payload.mode} ${payload.profile_name} · added ${payload.summary.added} · updated ${payload.summary.updated} · improved ${improved}`;
    els.policyPatchMeta.textContent = meta;

    if (payload.mode === 'apply') {
      await loadPolicyProfiles({
        preferredProfileName: payload.profile_name,
        setReadyTag: false
      });
      await refreshSelectedPolicyProfileVersion();
      setPolicyPatchTag('applied', '#5ae2a8');
      els.policyPatchMeta.textContent = meta;
    } else {
      setPolicyPatchTag('dry-run', '#ffb03a');
    }

    logAction(`policy:patch:${payload.mode}:${payload.profile_name}`, {
      added: payload.summary.added,
      updated: payload.summary.updated,
      improved_capabilities: improved,
      persisted: payload.persisted
    });
  } catch (err) {
    if (applyPolicyPatchConflictHint(err, requestPayload)) {
      return;
    }
    setPolicyPatchTag('error', '#ff6b6b');
    els.policyPatchMeta.textContent = String(err);
    els.policyPatchPayload.textContent = String(err);
    logAction('policy:patch:error', String(err));
  }
}

function applyPolicyRollbackConflictHint(err, requestPayload) {
  const conflictPayload = err?.payload && typeof err.payload === 'object' ? err.payload : null;
  if (!conflictPayload || Number(err?.status || 0) !== 409) return false;
  if (!requestPayload || requestPayload.mode !== 'apply') return false;

  const profileName = String(requestPayload.profile_name || '').trim();
  const currentHash = String(conflictPayload.current_profile_hash || '').trim();
  if (profileName && currentHash) {
    state.policyProfileVersions[profileName] = {
      version: 'v0',
      generated_at: new Date().toISOString(),
      profile_name: profileName,
      rule_count: Number(
        state.policyProfiles.find((item) => item.profile_name === profileName)?.rule_count || 0
      ),
      document_hash: currentHash,
      file_path: String(
        state.policyProfiles.find((item) => item.profile_name === profileName)?.file_path ||
          `policies/${profileName}.policy.json`
      )
    };
    setPolicyRollbackVersionField(profileName);
  }

  const expectedHash = String(conflictPayload.expected_profile_hash || '').trim();
  els.policyRollbackMeta.textContent =
    `Hash conflict for ${profileName}. Current hash has been refreshed; retry apply.`;
  els.policyRollbackPayload.textContent = JSON.stringify({
    message: conflictPayload.message || 'Policy hash conflict',
    profile_name: profileName,
    expected_profile_hash: expectedHash,
    current_profile_hash: currentHash
  }, null, 2);
  setPolicyRollbackTag('hash-conflict', '#ffb03a');
  logAction('policy:rollback:hash-conflict', {
    profile_name: profileName,
    expected_profile_hash: expectedHash,
    current_profile_hash: currentHash
  });
  return true;
}

async function runPolicyRollback(mode) {
  let requestPayload = null;
  try {
    requestPayload = buildPolicyRollbackRequest(mode);
    if (mode === 'apply') {
      await refreshSelectedPolicyRollbackProfileVersion();
      requestPayload = buildPolicyRollbackRequest(mode);
    }

    setPolicyRollbackTag(mode === 'apply' ? 'applying' : 'simulating', '#5fd1ff');
    const payload = await api('/v0/policy/rollback', {
      method: 'POST',
      body: JSON.stringify(requestPayload)
    });
    state.policyRollbackResult = payload;
    els.policyRollbackPayload.textContent = JSON.stringify(payload, null, 2);

    const targetPatchId = String(payload.rollback_target_patch_id || '').trim() || '(latest)';
    const meta = `${payload.mode} ${payload.profile_name} · target ${targetPatchId} · added ${payload.summary.added} · updated ${payload.summary.updated}`;
    els.policyRollbackMeta.textContent = meta;

    if (payload.mode === 'apply') {
      await loadPolicyProfiles({
        preferredProfileName: payload.profile_name,
        setReadyTag: false
      });
      await refreshSelectedPolicyRollbackProfileVersion();
      await loadPolicyRollbackHistory({
        profileName: payload.profile_name,
        silent: true,
        updateMeta: false
      });
      setPolicyRollbackTag('applied', '#5ae2a8');
      els.policyRollbackMeta.textContent = meta;
    } else {
      setPolicyRollbackTag('dry-run', '#ffb03a');
      await loadPolicyRollbackHistory({
        profileName: payload.profile_name,
        silent: true,
        updateMeta: false
      });
    }

    logAction(`policy:rollback:${payload.mode}:${payload.profile_name}`, {
      rollback_target_patch_id: payload.rollback_target_patch_id,
      added: payload.summary.added,
      updated: payload.summary.updated,
      persisted: payload.persisted
    });
  } catch (err) {
    if (applyPolicyRollbackConflictHint(err, requestPayload)) {
      return;
    }
    setPolicyRollbackTag('error', '#ff6b6b');
    els.policyRollbackMeta.textContent = String(err);
    els.policyRollbackPayload.textContent = String(err);
    logAction('policy:rollback:error', String(err));
  }
}

function clearBlueprint(message) {
  state.blueprintPreview = null;
  state.blueprintLint = null;
  state.blueprintRemediation = null;
  els.blueprintTag.textContent = 'idle';
  els.blueprintTag.style.color = '#b9d4cc';
  els.blueprintMeta.textContent = message;
  els.blueprintPayload.textContent = message;
}

function setBlueprintTagFromWarnings(warnings = []) {
  const hasCritical = warnings.some((item) => item.severity === 'critical');
  const hasWarning = warnings.some((item) => item.severity === 'warning');

  if (hasCritical) {
    els.blueprintTag.textContent = 'critical';
    els.blueprintTag.style.color = '#ff6b6b';
    return;
  }

  if (hasWarning) {
    els.blueprintTag.textContent = 'warning';
    els.blueprintTag.style.color = '#ffb03a';
    return;
  }

  els.blueprintTag.textContent = 'ready';
  els.blueprintTag.style.color = '#5ae2a8';
}

function refreshBlueprintKitSelect() {
  const kits = [...state.agentKits].sort((a, b) => a.kit_id.localeCompare(b.kit_id));
  const currentValue = els.blueprintKitSelect.value;
  els.blueprintKitSelect.innerHTML = '';

  if (!kits.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No kits loaded';
    els.blueprintKitSelect.appendChild(option);
    els.blueprintKitSelect.disabled = true;
    return;
  }

  els.blueprintKitSelect.disabled = false;
  for (const kit of kits) {
    const option = document.createElement('option');
    option.value = kit.kit_id;
    option.textContent = `${kit.name} · ${kit.role}`;
    els.blueprintKitSelect.appendChild(option);
  }

  if (kits.some((kit) => kit.kit_id === currentValue)) {
    els.blueprintKitSelect.value = currentValue;
  } else {
    els.blueprintKitSelect.value = kits[0].kit_id;
  }

  const selectedKit = kits.find((kit) => kit.kit_id === els.blueprintKitSelect.value);
  if (selectedKit && !String(els.blueprintConnectorsInput.value || '').trim()) {
    els.blueprintConnectorsInput.value = (selectedKit.connector_candidates || [])
      .map((item) => item.connector_id)
      .join(', ');
  }
  if (selectedKit && !String(els.blueprintAgentNameInput.value || '').trim()) {
    els.blueprintAgentNameInput.value = selectedKit.name;
  }
}

async function loadAgentKits() {
  try {
    const payload = await api('/v0/templates/agent-kits');
    state.agentKits = Array.isArray(payload.items) ? payload.items : [];
    refreshBlueprintKitSelect();

    els.blueprintMeta.textContent = `${state.agentKits.length} kits loaded. Select one and preview blueprint.`;
    if (!state.blueprintPreview) {
      els.blueprintTag.textContent = state.agentKits.length ? 'catalog-ready' : 'catalog-empty';
      els.blueprintTag.style.color = state.agentKits.length ? '#5ae2a8' : '#ffb03a';
    }
  } catch (err) {
    state.agentKits = [];
    refreshBlueprintKitSelect();
    clearBlueprint(String(err));
  }
}

function buildBlueprintRequest() {
  const owners = parseCsvUnique(els.blueprintOwnersInput.value);
  const selectedConnectors = parseCsvUnique(els.blueprintConnectorsInput.value);
  const policyContext = {
    org_policy: String(els.blueprintPolicyOrgInput.value || '').trim(),
    workspace_policy: String(els.blueprintPolicyWorkspaceInput.value || '').trim(),
    agent_policy: String(els.blueprintPolicyAgentInput.value || '').trim(),
    run_override: String(els.blueprintRunOverrideInput.value || '').trim()
  };
  const normalizedPolicyContext = Object.fromEntries(
    Object.entries(policyContext).filter(([, value]) => value.length > 0)
  );

  return {
    workspace_id: String(els.blueprintWorkspaceInput.value || '').trim() || 'wsp_mindverse_cn',
    kit_id: els.blueprintKitSelect.value,
    owners: owners.length ? owners : ['usr_yingapple'],
    agent_name: String(els.blueprintAgentNameInput.value || '').trim() || 'Ops Blueprint Agent',
    selected_connector_ids: selectedConnectors.length ? selectedConnectors : undefined,
    policy_context: Object.keys(normalizedPolicyContext).length ? normalizedPolicyContext : undefined
  };
}

async function previewAgentBlueprint() {
  const requestPayload = buildBlueprintRequest();
  if (!requestPayload.kit_id) {
    clearBlueprint('No kit selected.');
    return;
  }

  try {
    const payload = await api('/v0/agent-blueprints/preview', {
      method: 'POST',
      body: JSON.stringify(requestPayload)
    });
    state.blueprintPreview = payload;
    els.blueprintPayload.textContent = JSON.stringify(payload, null, 2);
    els.blueprintMeta.textContent = `${payload.kit.kit_id} · covered ${payload.capability_coverage.covered_total}/${payload.capability_coverage.required_total} · escalated ${payload.approval_forecast.escalated_actions} · ${payload.planner_metrics.elapsed_ms}ms`;
    setBlueprintTagFromWarnings(payload.warnings || []);
    logAction(`blueprint:preview:${payload.kit.kit_id}`, {
      covered: payload.capability_coverage.covered_total,
      required: payload.capability_coverage.required_total,
      warnings: payload.warnings.length,
      elapsed_ms: payload.planner_metrics.elapsed_ms
    });
  } catch (err) {
    clearBlueprint(String(err));
    logAction('blueprint:preview:error', String(err));
  }
}

async function lintAgentBlueprint() {
  const requestPayload = buildBlueprintRequest();
  if (!requestPayload.kit_id) {
    clearBlueprint('No kit selected.');
    return;
  }

  try {
    const payload = await api('/v0/agent-blueprints/lint', {
      method: 'POST',
      body: JSON.stringify(requestPayload)
    });
    state.blueprintLint = payload;
    els.blueprintPayload.textContent = JSON.stringify(payload, null, 2);
    els.blueprintMeta.textContent = `lint ${payload.summary.status} · score ${payload.summary.score} · fail ${payload.summary.failed} · warn ${payload.summary.warned}`;

    if (payload.summary.status === 'fail') {
      els.blueprintTag.textContent = 'lint-fail';
      els.blueprintTag.style.color = '#ff6b6b';
    } else if (payload.summary.status === 'warn') {
      els.blueprintTag.textContent = 'lint-warn';
      els.blueprintTag.style.color = '#ffb03a';
    } else {
      els.blueprintTag.textContent = 'lint-pass';
      els.blueprintTag.style.color = '#5ae2a8';
    }

    logAction(`blueprint:lint:${payload.kit_id}`, {
      status: payload.summary.status,
      score: payload.summary.score,
      checks: payload.summary.total_checks
    });
  } catch (err) {
    clearBlueprint(String(err));
    logAction('blueprint:lint:error', String(err));
  }
}

function adoptAutoFixRequestToForm(autoFixRequest) {
  if (!autoFixRequest || typeof autoFixRequest !== 'object') return;

  if (typeof autoFixRequest.workspace_id === 'string' && autoFixRequest.workspace_id) {
    els.blueprintWorkspaceInput.value = autoFixRequest.workspace_id;
  }

  if (typeof autoFixRequest.kit_id === 'string' && autoFixRequest.kit_id) {
    const hasOption = Array.from(els.blueprintKitSelect.options)
      .some((option) => option.value === autoFixRequest.kit_id);
    if (hasOption) {
      els.blueprintKitSelect.value = autoFixRequest.kit_id;
    }
  }

  if (Array.isArray(autoFixRequest.owners) && autoFixRequest.owners.length > 0) {
    els.blueprintOwnersInput.value = autoFixRequest.owners.join(', ');
  }

  if (typeof autoFixRequest.agent_name === 'string' && autoFixRequest.agent_name) {
    els.blueprintAgentNameInput.value = autoFixRequest.agent_name;
  }

  if (Array.isArray(autoFixRequest.selected_connector_ids)) {
    els.blueprintConnectorsInput.value = autoFixRequest.selected_connector_ids.join(', ');
  }

  const policyContext = autoFixRequest.policy_context || {};
  els.blueprintPolicyOrgInput.value = String(policyContext.org_policy || '');
  els.blueprintPolicyWorkspaceInput.value = String(policyContext.workspace_policy || '');
  els.blueprintPolicyAgentInput.value = String(policyContext.agent_policy || '');
  els.blueprintRunOverrideInput.value = String(policyContext.run_override || '');
}

async function remediateAgentBlueprint() {
  const requestPayload = buildBlueprintRequest();
  if (!requestPayload.kit_id) {
    clearBlueprint('No kit selected.');
    return;
  }

  try {
    const payload = await api('/v0/agent-blueprints/remediation-plan', {
      method: 'POST',
      body: JSON.stringify(requestPayload)
    });
    state.blueprintRemediation = payload;
    adoptAutoFixRequestToForm(payload.auto_fix_request);
    els.blueprintPayload.textContent = JSON.stringify(payload, null, 2);

    const delta = Number(payload.summary.expected_delta || 0);
    const deltaLabel = delta >= 0 ? `+${delta}` : `${delta}`;
    const adoptedRunOverride = String(payload.auto_fix_request?.policy_context?.run_override || '');
    els.blueprintMeta.textContent = `remediation ${payload.summary.status_before} -> ${payload.summary.status_after_estimate} · score ${payload.summary.score_before} -> ${payload.summary.score_after_estimate} (${deltaLabel}) · unresolved ${payload.unresolved_capabilities.length} · run_override ${adoptedRunOverride || 'none'} · auto-fix adopted`;

    if (payload.summary.status_after_estimate === 'fail') {
      els.blueprintTag.textContent = 'remediation-fail';
      els.blueprintTag.style.color = '#ff6b6b';
    } else if (payload.summary.status_after_estimate === 'warn') {
      els.blueprintTag.textContent = 'remediation-warn';
      els.blueprintTag.style.color = '#ffb03a';
    } else {
      els.blueprintTag.textContent = 'remediation-pass';
      els.blueprintTag.style.color = '#5ae2a8';
    }

    if (!state.policyProfiles.length) {
      await loadPolicyProfiles();
    }
    const adoptedPolicyCandidate = adoptPolicyPatchCandidateFromRemediation({
      remediation: payload,
      overwriteRules: false
    });
    if (adoptedPolicyCandidate) {
      setPolicyPatchTag('drafted', '#ffb03a');
      els.policyPatchMeta.textContent = `Drafted from remediation candidate ${adoptedPolicyCandidate.candidate_id} -> ${adoptedPolicyCandidate.target_profile}`;
    }

    logAction(`blueprint:remediation:${payload.kit_id}`, {
      status_before: payload.summary.status_before,
      status_after: payload.summary.status_after_estimate,
      score_before: payload.summary.score_before,
      score_after: payload.summary.score_after_estimate,
      expected_delta: payload.summary.expected_delta,
      unresolved_capabilities: payload.unresolved_capabilities.length
    });
  } catch (err) {
    clearBlueprint(String(err));
    logAction('blueprint:remediation:error', String(err));
  }
}

async function applyAgentBlueprint() {
  const requestPayload = buildBlueprintRequest();
  if (!requestPayload.kit_id) {
    clearBlueprint('No kit selected.');
    return;
  }

  const authRefs = parseAuthRefsMap(els.blueprintAuthRefsInput.value);
  const idempotencyKey = String(els.blueprintIdemInput.value || '').trim();
  const strictMode = Boolean(els.blueprintStrictModeInput.checked);

  try {
    const payload = await api('/v0/agent-blueprints/apply', {
      method: 'POST',
      body: JSON.stringify({
        ...requestPayload,
        strict_mode: strictMode,
        binding_auth_refs: Object.keys(authRefs).length ? authRefs : undefined,
        idempotency_key: idempotencyKey || undefined
      })
    });

    state.blueprintPreview = payload.blueprint;
    els.blueprintPayload.textContent = JSON.stringify(payload, null, 2);
    els.blueprintMeta.textContent = `${payload.reused ? 'reused' : 'applied'} ${payload.kit_id} · agent ${payload.created_agent.id} · bindings ${payload.created_bindings.length}`;
    setBlueprintTagFromWarnings(payload.warnings || []);

    state.selectedRunId = null;
    await syncState();
    await loadConnectorGovernance();
    refreshRuntimeViews();
    await refreshTimelineForSelectedRun();

    logAction(`blueprint:apply:${payload.kit_id}`, {
      agent_id: payload.created_agent.id,
      created_bindings: payload.created_bindings.length,
      warnings: payload.warnings.length,
      reused: payload.reused
    });
  } catch (err) {
    clearBlueprint(String(err));
    logAction('blueprint:apply:error', String(err));
  }
}

function buildPendingApprovals(runs) {
  const items = [];
  for (const run of runs) {
    if (run.status !== 'waiting_approval') continue;

    const approvalState = run.approval_state || {};
    for (const [actionIntentId, approval] of Object.entries(approvalState)) {
      const intent = (run.action_intents || []).find((item) => item.id === actionIntentId);
      const decision = (run.policy_decisions || []).find(
        (item) => item.action_intent_id === actionIntentId
      );
      const approvedBy = Array.isArray(approval?.approved_by) ? approval.approved_by : [];
      const requiredApprovals = Number(approval?.required_approvals || 1);

      items.push({
        run_id: run.id,
        run_revision: run.revision,
        run_started_at: run.started_at,
        action_intent_id: actionIntentId,
        step_id: intent?.step_id || 'unknown',
        capability: intent?.capability || 'unknown',
        side_effect: intent?.side_effect || 'none',
        risk_tier: decision?.risk_tier || 'R0',
        required_approvals: requiredApprovals,
        approved_by: approvedBy,
        approvals_left: Math.max(0, requiredApprovals - approvedBy.length),
        reason_codes: decision?.reason_codes || [],
        run
      });
    }
  }

  return items.sort((a, b) => safeDateMs(b.run_started_at) - safeDateMs(a.run_started_at));
}

function renderAttestationSummary(summary) {
  els.attestationVerifiedCount.textContent = String(summary.verified);
  els.attestationUnverifiedCount.textContent = String(summary.unverified);
  els.attestationMissingCount.textContent = String(summary.missingManifest);
  els.attestationHighControlRiskCount.textContent = String(summary.highControlRisk);
  els.attestationKeyIds.textContent = summary.keyIds.length
    ? `key ids: ${summary.keyIds.join(', ')}`
    : 'key ids: none';

  if (summary.unverified > 0 || summary.highControlRisk > 0) {
    els.attestationTag.textContent = 'attention';
    els.attestationTag.style.color = '#ffb03a';
  } else {
    els.attestationTag.textContent = 'verified';
    els.attestationTag.style.color = '#5ae2a8';
  }
}

function renderApprovalInbox() {
  els.approvalInbox.innerHTML = '';

  if (!state.pendingApprovals.length) {
    els.approvalInboxTag.textContent = 'clear';
    els.approvalInboxTag.style.color = '#5ae2a8';
    els.approvalInbox.innerHTML = '<p class="run-meta">No pending approvals.</p>';
    return;
  }

  els.approvalInboxTag.textContent = `${state.pendingApprovals.length} pending`;
  els.approvalInboxTag.style.color = '#ffb03a';

  for (const item of state.pendingApprovals) {
    const card = document.createElement('article');
    card.className = 'approval-card';

    const top = document.createElement('div');
    top.className = 'approval-top';

    const title = document.createElement('h3');
    title.textContent = item.run_id;

    const risk = document.createElement('span');
    risk.className = 'tag';
    risk.textContent = item.risk_tier;
    risk.style.color = item.risk_tier === 'R3' || item.risk_tier === 'R2' ? '#ffb03a' : '#5ae2a8';

    top.append(title, risk);

    const meta = document.createElement('p');
    meta.className = 'run-meta';
    meta.textContent = `${item.step_id} · ${item.capability} · ${item.side_effect}`;

    const progress = document.createElement('p');
    progress.className = 'run-meta';
    progress.textContent = `approvals ${item.approved_by.length}/${item.required_approvals} · left ${item.approvals_left}`;

    const actions = document.createElement('div');
    actions.className = 'run-actions';

    const approveBtn = document.createElement('button');
    approveBtn.className = 'btn btn-secondary';
    approveBtn.textContent = 'Approve Action';
    approveBtn.addEventListener('click', () =>
      resolveRunApproval(item.run, true, item.action_intent_id)
    );

    const rejectBtn = document.createElement('button');
    rejectBtn.className = 'btn btn-danger';
    rejectBtn.textContent = 'Reject Action';
    rejectBtn.addEventListener('click', () =>
      resolveRunApproval(item.run, false, item.action_intent_id)
    );

    const inspectBtn = document.createElement('button');
    inspectBtn.className = 'btn btn-ghost';
    inspectBtn.textContent = 'Inspect Timeline';
    inspectBtn.addEventListener('click', async () => {
      state.selectedRunId = item.run_id;
      refreshTimelineRunSelect();
      await refreshTimelineForSelectedRun();
    });

    actions.append(approveBtn, rejectBtn, inspectBtn);
    card.append(top, meta, progress, actions);
    els.approvalInbox.appendChild(card);
  }
}

function clearTimeline(message) {
  els.timelineTag.textContent = 'idle';
  els.timelineTag.style.color = '#b9d4cc';
  els.timelineMeta.textContent = message;
  els.timelineEventsPayload.textContent = message;
  els.timelineAuditPayload.textContent = message;
  state.timelineEvents = null;
  state.timelineAudit = null;
}

function clearTimelineDiff(message) {
  els.timelineDiffMeta.textContent = message;
  els.timelineDiffPayload.textContent = message;
  state.timelineDiff = null;
}

function clearReplayIntegrity(message) {
  els.timelineReplayMeta.textContent = message;
  els.timelineReplayPayload.textContent = message;
  state.replayIntegrity = null;
}

function clearReplayDrift(message) {
  els.replayDriftTag.textContent = 'idle';
  els.replayDriftTag.style.color = '#b9d4cc';
  els.replayDriftMeta.textContent = message;
  els.replayDriftPayload.textContent = message;
  state.replayDrift = null;
}

function clearPolicyTrace(message) {
  els.policyTraceTag.textContent = 'idle';
  els.policyTraceTag.style.color = '#b9d4cc';
  els.policyTracePayload.textContent = message;
}

function renderPolicyTraceForRun(runId) {
  if (!runId) {
    clearPolicyTrace('No run selected.');
    return;
  }

  const run = state.runs.find((item) => item.id === runId);
  if (!run) {
    clearPolicyTrace(`Run not found in current page: ${runId}`);
    return;
  }

  const decisions = Array.isArray(run.policy_decisions) ? run.policy_decisions : [];
  const summary = decisions.reduce(
    (acc, item) => {
      if (item.decision === 'allow') acc.allow += 1;
      if (item.decision === 'escalate') acc.escalate += 1;
      if (item.decision === 'deny') acc.deny += 1;
      const source = item.policy_trace?.effective_source || 'unknown';
      acc.sources[source] = (acc.sources[source] || 0) + 1;
      return acc;
    },
    { allow: 0, escalate: 0, deny: 0, sources: {} }
  );

  if (summary.deny > 0) {
    els.policyTraceTag.style.color = '#ff6b6b';
  } else if (summary.escalate > 0) {
    els.policyTraceTag.style.color = '#ffb03a';
  } else {
    els.policyTraceTag.style.color = '#5ae2a8';
  }
  els.policyTraceTag.textContent = `A${summary.allow} E${summary.escalate} D${summary.deny}`;

  const trace = {
    run_id: run.id,
    revision: run.revision,
    status: run.status,
    summary,
    decisions: decisions.map((item) => ({
      step_id: (run.action_intents || []).find((intent) => intent.id === item.action_intent_id)?.step_id || 'unknown',
      action_intent_id: item.action_intent_id,
      decision: item.decision,
      risk_tier: item.risk_tier,
      reason_codes: item.reason_codes,
      policy_lattice: {
        org_policy: item.policy_trace?.org_policy || 'unknown',
        workspace_policy: item.policy_trace?.workspace_policy || 'unknown',
        agent_policy: item.policy_trace?.agent_policy || 'unknown',
        run_override: item.policy_trace?.run_override || '',
        effective_source: item.policy_trace?.effective_source || 'unknown'
      }
    }))
  };

  els.policyTracePayload.textContent = JSON.stringify(trace, null, 2);
}

function readInitialCompactMode() {
  const persisted = window.localStorage.getItem('flockmesh_compact_mode');
  if (persisted === '1') return true;
  if (persisted === '0') return false;
  return window.matchMedia('(max-width: 620px)').matches;
}

function setCompactMode(enabled, { persist = true } = {}) {
  state.compactMode = Boolean(enabled);
  document.body.classList.toggle('compact-mode', state.compactMode);
  els.compactToggleBtn.textContent = `Compact: ${state.compactMode ? 'On' : 'Off'}`;
  if (persist) {
    window.localStorage.setItem('flockmesh_compact_mode', state.compactMode ? '1' : '0');
  }
}

function refreshTimelineRunSelect() {
  const runs = [...state.runs].sort((a, b) => safeDateMs(b.started_at) - safeDateMs(a.started_at));
  const previous = state.selectedRunId;
  els.timelineRunSelect.innerHTML = '';

  if (!runs.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No runs';
    els.timelineRunSelect.appendChild(option);
    els.timelineRunSelect.disabled = true;
    els.timelineBaseRunSelect.innerHTML = '';
    els.timelineBaseRunSelect.disabled = true;
    state.selectedRunId = null;
    state.timelineDiffBaseRunId = '';
    clearTimeline('No runs available.');
    clearTimelineDiff('No runs available.');
    clearReplayIntegrity('No runs available.');
    clearReplayDrift('No runs available.');
    clearPolicyTrace('No runs available.');
    return;
  }

  els.timelineRunSelect.disabled = false;
  for (const run of runs) {
    const option = document.createElement('option');
    option.value = run.id;
    option.textContent = `${run.id} · ${run.status}`;
    els.timelineRunSelect.appendChild(option);
  }

  const selected = runs.some((run) => run.id === previous) ? previous : runs[0].id;
  state.selectedRunId = selected;
  els.timelineRunSelect.value = selected;
  refreshTimelineBaseRunSelect();
  renderPolicyTraceForRun(selected);
}

function refreshTimelineBaseRunSelect() {
  const runs = [...state.runs].sort((a, b) => safeDateMs(b.started_at) - safeDateMs(a.started_at));
  els.timelineBaseRunSelect.innerHTML = '';

  if (!state.selectedRunId || runs.length < 2) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'Auto previous';
    els.timelineBaseRunSelect.appendChild(option);
    els.timelineBaseRunSelect.disabled = true;
    state.timelineDiffBaseRunId = '';
    return;
  }

  els.timelineBaseRunSelect.disabled = false;
  const auto = document.createElement('option');
  auto.value = '';
  auto.textContent = 'Auto previous';
  els.timelineBaseRunSelect.appendChild(auto);

  const candidates = runs.filter((run) => run.id !== state.selectedRunId);
  for (const run of candidates) {
    const option = document.createElement('option');
    option.value = run.id;
    option.textContent = `${run.id} · ${run.status}`;
    els.timelineBaseRunSelect.appendChild(option);
  }

  const keep = candidates.some((run) => run.id === state.timelineDiffBaseRunId)
    ? state.timelineDiffBaseRunId
    : '';
  state.timelineDiffBaseRunId = keep;
  els.timelineBaseRunSelect.value = keep;
}

async function loadRunTimeline(runId) {
  if (!runId) {
    clearTimeline('No run selected.');
    return;
  }

  try {
    els.timelineTag.textContent = 'loading';
    els.timelineTag.style.color = '#5fd1ff';

    const [events, audit] = await Promise.all([
      api(`/v0/runs/${runId}/events`),
      api(`/v0/runs/${runId}/audit`)
    ]);

    state.timelineEvents = events;
    state.timelineAudit = audit;
    els.timelineEventsPayload.textContent = JSON.stringify(events, null, 2);
    els.timelineAuditPayload.textContent = JSON.stringify(audit, null, 2);

    const eventCount = Array.isArray(events.items) ? events.items.length : 0;
    const auditCount = Array.isArray(audit.items) ? audit.items.length : 0;
    const run = state.runs.find((item) => item.id === runId);

    els.timelineTag.textContent = `${eventCount}/${auditCount}`;
    els.timelineTag.style.color = '#5ae2a8';
    els.timelineMeta.textContent = `${runId} · status ${run?.status || 'unknown'} · events ${eventCount} · audit ${auditCount}`;
  } catch (err) {
    els.timelineTag.textContent = 'error';
    els.timelineTag.style.color = '#ff6b6b';
    els.timelineMeta.textContent = String(err);
    els.timelineEventsPayload.textContent = String(err);
    els.timelineAuditPayload.textContent = String(err);
  }
}

async function loadRunTimelineDiff(runId) {
  if (!runId) {
    clearTimelineDiff('No run selected.');
    return;
  }

  try {
    const query = new URLSearchParams({
      max_items_per_stream: '2000',
      sample_limit: '24'
    });
    if (state.timelineDiffBaseRunId) {
      query.set('base_run_id', state.timelineDiffBaseRunId);
    }

    const payload = await api(`/v0/runs/${runId}/timeline-diff?${query.toString()}`);
    state.timelineDiff = payload;
    els.timelineDiffPayload.textContent = JSON.stringify(payload, null, 2);

    const mode = payload.summary.partial ? 'partial' : 'full';
    els.timelineDiffMeta.textContent = `base ${payload.base_source}:${payload.base_run_id} · ${mode} diff`;
    logAction(`timeline-diff:${runId}`, {
      base_run_id: payload.base_run_id,
      base_source: payload.base_source,
      partial: payload.summary.partial
    });
  } catch (err) {
    els.timelineDiffMeta.textContent = String(err);
    els.timelineDiffPayload.textContent = String(err);
    logAction('timeline-diff:error', String(err));
  }
}

async function loadRunReplayIntegrity(runId) {
  if (!runId) {
    clearReplayIntegrity('No run selected.');
    return;
  }

  try {
    const query = new URLSearchParams({
      max_items_per_stream: '2000',
      sample_limit: '24'
    });
    const payload = await api(`/v0/runs/${runId}/replay-integrity?${query.toString()}`);
    state.replayIntegrity = payload;
    els.timelineReplayPayload.textContent = JSON.stringify(payload, null, 2);
    els.timelineReplayMeta.textContent = `state ${payload.replay_state} · issues ${payload.issues.length} · expected ${payload.summary.expected_action_executions}`;
    logAction(`replay-integrity:${runId}`, {
      replay_state: payload.replay_state,
      issue_count: payload.issues.length
    });
  } catch (err) {
    els.timelineReplayMeta.textContent = String(err);
    els.timelineReplayPayload.textContent = String(err);
    logAction('replay-integrity:error', String(err));
  }
}

async function exportRunReplayIntegrity(runId) {
  if (!runId) {
    logAction('replay-export:error', 'No run selected for replay export.');
    return;
  }

  try {
    const payload = await api(`/v0/runs/${runId}/replay-export?max_items_per_stream=2000&sample_limit=24`);
    logAction(`replay-export:${runId}`, payload);
  } catch (err) {
    logAction('replay-export:error', String(err));
  }
}

async function loadReplayDriftSummary() {
  try {
    const payload = await api('/v0/monitoring/replay-drift?limit=30&max_items_per_stream=1200&sample_limit=20');
    state.replayDrift = payload;
    els.replayDriftPayload.textContent = JSON.stringify(payload, null, 2);
    els.replayDriftMeta.textContent = `evaluated ${payload.totals.evaluated} · inconsistent ${payload.totals.inconsistent} · inconclusive ${payload.totals.inconclusive}`;
    if (payload.alert) {
      els.replayDriftTag.textContent = 'alert';
      els.replayDriftTag.style.color = '#ff6b6b';
    } else {
      els.replayDriftTag.textContent = 'stable';
      els.replayDriftTag.style.color = '#5ae2a8';
    }
  } catch (err) {
    els.replayDriftTag.textContent = 'error';
    els.replayDriftTag.style.color = '#ff6b6b';
    els.replayDriftMeta.textContent = String(err);
    els.replayDriftPayload.textContent = String(err);
    state.replayDrift = null;
  }
}

async function refreshTimelineForSelectedRun() {
  if (!state.selectedRunId) {
    clearTimeline('No run selected.');
    clearTimelineDiff('No run selected.');
    clearReplayIntegrity('No run selected.');
    clearPolicyTrace('No run selected.');
    return;
  }
  clearTimelineDiff('Select base run and click Load Diff.');
  clearReplayIntegrity('Click Replay Check to validate run integrity.');
  renderPolicyTraceForRun(state.selectedRunId);
  await loadRunTimeline(state.selectedRunId);
}

async function loadHealth() {
  try {
    const payload = await api('/health');
    els.healthTag.textContent = payload.ok ? 'healthy' : 'unhealthy';
    els.healthTag.style.color = payload.ok ? '#5ae2a8' : '#ff6b6b';
    els.healthPayload.textContent = JSON.stringify(payload, null, 2);
  } catch (err) {
    els.healthTag.textContent = 'offline';
    els.healthTag.style.color = '#ff6b6b';
    els.healthPayload.textContent = String(err);
  }
}

async function loadConnectorGovernance() {
  try {
    const [health, drift] = await Promise.all([
      api('/v0/connectors/health'),
      api('/v0/connectors/drift')
    ]);

    state.connectorHealth = health;
    state.connectorDrift = drift;
    state.attestationSummary = summarizeAttestation(health);
    els.connectorHealthPayload.textContent = JSON.stringify(health, null, 2);
    els.connectorDriftPayload.textContent = JSON.stringify(drift, null, 2);
    renderAttestationSummary(state.attestationSummary);

    if (health.degraded > 0) {
      els.connectorHealthTag.textContent = `degraded ${health.degraded}`;
      els.connectorHealthTag.style.color = '#ffb03a';
    } else {
      els.connectorHealthTag.textContent = `healthy ${health.healthy}`;
      els.connectorHealthTag.style.color = '#5ae2a8';
    }
  } catch (err) {
    els.connectorHealthTag.textContent = 'offline';
    els.connectorHealthTag.style.color = '#ff6b6b';
    els.connectorHealthPayload.textContent = String(err);
    els.connectorDriftPayload.textContent = String(err);
    els.attestationTag.textContent = 'offline';
    els.attestationTag.style.color = '#ff6b6b';
    els.attestationVerifiedCount.textContent = '-';
    els.attestationUnverifiedCount.textContent = '-';
    els.attestationMissingCount.textContent = '-';
    els.attestationHighControlRiskCount.textContent = '-';
    els.attestationKeyIds.textContent = 'key ids: unavailable';
  }
}

async function syncState() {
  const [agents, bindings, runs] = await Promise.all([
    api('/v0/agents?limit=200&offset=0'),
    api('/v0/connectors/bindings?limit=200&offset=0'),
    api('/v0/runs?limit=200&offset=0')
  ]);

  state.agents = agents.items;
  state.bindings = bindings.items;
  state.runs = runs.items;
  state.pendingApprovals = buildPendingApprovals(state.runs);
}

function refreshStats() {
  els.agentsCount.textContent = String(state.agents.length);
  els.bindingsCount.textContent = String(state.bindings.length);
  els.runsCount.textContent = String(state.runs.length);
  els.pendingCount.textContent = String(state.pendingApprovals.length);
}

function renderRunFeed() {
  els.runFeed.innerHTML = '';

  const ordered = [...state.runs].sort((a, b) => safeDateMs(b.started_at) - safeDateMs(a.started_at));
  for (const run of ordered) {
    const node = els.runCardTemplate.content.firstElementChild.cloneNode(true);
    node.querySelector('.run-id').textContent = run.id;

    const statusEl = node.querySelector('.run-status');
    statusEl.textContent = run.status;
    statusEl.classList.add(run.status);

    node.querySelector('.run-meta').textContent = `${run.playbook_id} · ${run.trigger.source} · rev ${run.revision}`;

    const actionsWrap = node.querySelector('.run-actions');

    if (run.status === 'waiting_approval') {
      const approveBtn = document.createElement('button');
      approveBtn.className = 'btn btn-secondary';
      approveBtn.textContent = 'Approve';
      approveBtn.addEventListener('click', () => resolveRunApproval(run, true));

      const rejectBtn = document.createElement('button');
      rejectBtn.className = 'btn btn-danger';
      rejectBtn.textContent = 'Reject';
      rejectBtn.addEventListener('click', () => resolveRunApproval(run, false));

      actionsWrap.append(approveBtn, rejectBtn);
    }

    if (['accepted', 'running', 'waiting_approval'].includes(run.status)) {
      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn btn-danger';
      cancelBtn.textContent = 'Cancel Run';
      cancelBtn.addEventListener('click', () => resolveRunCancel(run));
      actionsWrap.append(cancelBtn);
    }

    const inspectBtn = document.createElement('button');
    inspectBtn.className = 'btn btn-ghost';
    inspectBtn.textContent = 'Inspect Timeline';
    inspectBtn.addEventListener('click', async () => {
      state.selectedRunId = run.id;
      refreshTimelineRunSelect();
      await refreshTimelineForSelectedRun();
    });

    const auditBtn = document.createElement('button');
    auditBtn.className = 'btn btn-ghost';
    auditBtn.textContent = 'Fetch Audit';
    auditBtn.addEventListener('click', async () => {
      try {
        const audit = await api(`/v0/runs/${run.id}/audit`);
        logAction(`audit:${run.id}`, audit);
      } catch (err) {
        logAction('audit:error', String(err));
      }
    });

    actionsWrap.append(inspectBtn, auditBtn);
    els.runFeed.appendChild(node);
  }

  if (!state.runs.length) {
    els.runFeed.innerHTML = '<p class="run-meta">No runs yet. Start with Bootstrap Demo Run.</p>';
  }
}

function refreshRuntimeViews() {
  refreshStats();
  renderRunFeed();
  renderApprovalInbox();
  refreshTimelineRunSelect();
}

async function startOnePersonQuickstart() {
  try {
    setQuickstartTag('running', '#ffb03a');
    const templateId = selectedQuickstartTemplateId();
    const idempotencyKey = String(els.quickstartIdemInput.value || '').trim();

    const payload = await api('/v0/quickstart/one-person', {
      method: 'POST',
      body: JSON.stringify({
        workspace_id: String(els.quickstartWorkspaceInput.value || '').trim() || 'wsp_mindverse_cn',
        owner_id: String(els.quickstartOwnerInput.value || '').trim() || 'usr_yingapple',
        template_id: templateId,
        connector_ids: effectiveQuickstartConnectorIds(),
        ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {})
      })
    });

    state.quickstartResult = payload;
    els.quickstartPayload.textContent = JSON.stringify(payload, null, 2);
    els.quickstartMeta.textContent = `${payload.reused ? 'reused' : 'created'} · agent ${payload.created_agent.id} · run ${payload.run.id} · status ${payload.run.status}`;
    setQuickstartTag(payload.reused ? 'reused' : 'completed', '#5ae2a8');

    state.selectedRunId = payload.run.id;
    await Promise.all([
      syncState(),
      loadConnectorGovernance()
    ]);
    refreshRuntimeViews();
    await refreshTimelineForSelectedRun();

    logAction(`quickstart:${templateId}`, {
      reused: payload.reused,
      agent_id: payload.created_agent.id,
      run_id: payload.run.id,
      run_status: payload.run.status
    });
  } catch (err) {
    setQuickstartTag('error', '#ff6b6b');
    els.quickstartMeta.textContent = String(err);
    els.quickstartPayload.textContent = String(err);
    logAction('quickstart:error', String(err));
  }
}

async function createAgent() {
  const payload = await api('/v0/agents', {
    method: 'POST',
    body: JSON.stringify({
      workspace_id: 'wsp_mindverse_cn',
      role: 'ops_assistant',
      owners: ['usr_yingapple'],
      name: 'Ops Assistant',
      default_policy_profile: 'polprof_ops_standard'
    })
  });
  await syncState();
  refreshRuntimeViews();
  await refreshTimelineForSelectedRun();
  logAction('agent:created', payload);
  return payload;
}

async function createBinding(agentId) {
  const payload = await api('/v0/connectors/bindings', {
    method: 'POST',
    body: JSON.stringify({
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agentId,
      connector_id: DEMO_BOOTSTRAP_PRESET.connector_id,
      scopes: DEMO_BOOTSTRAP_PRESET.scopes,
      auth_ref: DEMO_BOOTSTRAP_PRESET.auth_ref,
      risk_profile: DEMO_BOOTSTRAP_PRESET.risk_profile
    })
  });
  await syncState();
  await loadConnectorGovernance();
  refreshRuntimeViews();
  await refreshTimelineForSelectedRun();
  logAction('binding:created', payload);
  return payload;
}

async function createRun(agentId) {
  const payload = await api('/v0/runs', {
    method: 'POST',
    body: JSON.stringify({
      workspace_id: 'wsp_mindverse_cn',
      agent_id: agentId,
      playbook_id: 'pbk_weekly_ops_sync',
      trigger: {
        type: 'manual',
        source: DEMO_BOOTSTRAP_PRESET.trigger_source,
        actor_id: 'usr_yingapple',
        at: new Date().toISOString()
      }
    })
  });

  state.selectedRunId = payload.id;
  await syncState();
  refreshRuntimeViews();
  await refreshTimelineForSelectedRun();
  logAction('run:created', payload);
  return payload;
}

async function resolveRunApproval(run, approved, actionIntentId = null) {
  const fallbackAction = run.policy_decisions.find((item) => item.decision === 'escalate');
  const targetActionIntentId = actionIntentId || fallbackAction?.action_intent_id;
  if (!targetActionIntentId) return;

  try {
    const result = await api(`/v0/runs/${run.id}/approvals`, {
      method: 'POST',
      body: JSON.stringify({
        action_intent_id: targetActionIntentId,
        approved,
        approved_by: 'usr_yingapple',
        expected_revision: run.revision,
        note: approved ? 'approved from control panel' : 'rejected from control panel'
      })
    });

    state.selectedRunId = run.id;
    await syncState();
    refreshRuntimeViews();
    await refreshTimelineForSelectedRun();
    logAction(`approval:${approved ? 'approved' : 'rejected'}`, result);
  } catch (err) {
    logAction('approval:error', String(err));
  }
}

async function resolveRunCancel(run) {
  try {
    const result = await api(`/v0/runs/${run.id}/cancel`, {
      method: 'POST',
      body: JSON.stringify({
        cancelled_by: 'usr_yingapple',
        expected_revision: run.revision,
        reason: 'cancelled from control panel'
      })
    });

    state.selectedRunId = run.id;
    await syncState();
    refreshRuntimeViews();
    await refreshTimelineForSelectedRun();
    logAction('run:cancelled', result);
  } catch (err) {
    logAction('cancel:error', String(err));
  }
}

async function bootstrapDemo() {
  try {
    let agent = state.agents[state.agents.length - 1];
    if (!agent) {
      agent = await createAgent();
    }

    const existingBinding = state.bindings.find((item) => item.agent_id === agent.id);
    if (!existingBinding) {
      await createBinding(agent.id);
    }

    await createRun(agent.id);
  } catch (err) {
    logAction('bootstrap:error', String(err));
  }
}

els.bootstrapBtn.addEventListener('click', bootstrapDemo);
els.quickstartStartBtn.addEventListener('click', async () => {
  await startOnePersonQuickstart();
});
els.quickstartTemplateSelect.addEventListener('change', () => {
  if (!parseCsvUnique(els.quickstartConnectorIdsInput.value).length) {
    const defaults = quickstartTemplateDefaultConnectorIds(selectedQuickstartTemplateId());
    els.quickstartConnectorIdsInput.value = defaults.join(', ');
  }
  if (!state.quickstartResult) {
    const templateId = selectedQuickstartTemplateId();
    const template = ONE_PERSON_QUICKSTART_TEMPLATES[templateId];
    els.quickstartMeta.textContent = `Template ${template?.label || templateId} selected. Click Start Quickstart.`;
  }
});
els.blueprintReloadBtn.addEventListener('click', async () => {
  await loadAgentKits();
});
els.blueprintPreviewBtn.addEventListener('click', async () => {
  await previewAgentBlueprint();
});
els.blueprintLintBtn.addEventListener('click', async () => {
  await lintAgentBlueprint();
});
els.blueprintRemediateBtn.addEventListener('click', async () => {
  await remediateAgentBlueprint();
});
els.blueprintApplyBtn.addEventListener('click', async () => {
  await applyAgentBlueprint();
});
els.policyPatchReloadBtn.addEventListener('click', async () => {
  await loadPolicyProfiles();
});
els.policyPatchVersionBtn.addEventListener('click', async () => {
  try {
    await refreshSelectedPolicyProfileVersion({ updateMeta: true });
    setPolicyPatchTag('version-ready', '#5ae2a8');
    logAction('policy:patch:version:refresh', {
      profile_name: selectedPolicyProfileName(),
      document_hash: els.policyPatchHashInput.value
    });
  } catch (err) {
    setPolicyPatchTag('error', '#ff6b6b');
    els.policyPatchMeta.textContent = String(err);
    logAction('policy:patch:version:error', String(err));
  }
});
els.policyPatchFromRemediationBtn.addEventListener('click', async () => {
  try {
    if (!state.blueprintRemediation) {
      throw new Error('Run Auto Remediate first to generate policy patch candidates.');
    }
    if (!state.policyProfiles.length) {
      await loadPolicyProfiles();
    }

    const candidate = adoptPolicyPatchCandidateFromRemediation({
      remediation: state.blueprintRemediation,
      overwriteRules: true
    });
    if (!candidate) {
      throw new Error('No policy_profile_patch candidate found in current remediation payload.');
    }

    setPolicyPatchTag('drafted', '#ffb03a');
    els.policyPatchMeta.textContent = `Drafted ${candidate.patch_rules.length} rules from ${candidate.candidate_id} -> ${candidate.target_profile}`;
    logAction('policy:patch:draft-from-remediation', {
      candidate_id: candidate.candidate_id,
      target_profile: candidate.target_profile,
      patch_rules: candidate.patch_rules.length
    });
  } catch (err) {
    setPolicyPatchTag('error', '#ff6b6b');
    els.policyPatchMeta.textContent = String(err);
    logAction('policy:patch:draft:error', String(err));
  }
});
els.policyPatchDryRunBtn.addEventListener('click', async () => {
  await runPolicyPatch('dry_run');
});
els.policyPatchApplyBtn.addEventListener('click', async () => {
  await runPolicyPatch('apply');
});
els.policyPatchProfileSelect.addEventListener('change', async () => {
  const profileName = selectedPolicyProfileName();
  try {
    await loadPolicyProfileVersion({ profileName, silent: true });
  } catch {
    // ignore and keep UI responsive; version field already reflects missing snapshot.
  }
  if (!state.policyPatchResult) {
    els.policyPatchMeta.textContent = `Selected profile ${profileName || 'none'}.`;
  }
});
els.policyRollbackReloadBtn.addEventListener('click', async () => {
  try {
    await loadPolicyRollbackHistory({
      profileName: selectedPolicyRollbackProfileName(),
      silent: false,
      updateMeta: true
    });
    setPolicyRollbackTag('history-ready', '#5ae2a8');
    logAction('policy:rollback:history:refresh', {
      profile_name: selectedPolicyRollbackProfileName(),
      history_entries: state.policyRollbackHistory.length
    });
  } catch (err) {
    setPolicyRollbackTag('error', '#ff6b6b');
    els.policyRollbackMeta.textContent = String(err);
    logAction('policy:rollback:history:error', String(err));
  }
});
els.policyRollbackVersionBtn.addEventListener('click', async () => {
  try {
    await refreshSelectedPolicyRollbackProfileVersion({ updateMeta: true });
    setPolicyRollbackTag('version-ready', '#5ae2a8');
    logAction('policy:rollback:version:refresh', {
      profile_name: selectedPolicyRollbackProfileName(),
      document_hash: els.policyRollbackHashInput.value
    });
  } catch (err) {
    setPolicyRollbackTag('error', '#ff6b6b');
    els.policyRollbackMeta.textContent = String(err);
    logAction('policy:rollback:version:error', String(err));
  }
});
els.policyRollbackDraftLatestBtn.addEventListener('click', async () => {
  try {
    if (!state.policyRollbackHistory.length) {
      await loadPolicyRollbackHistory({
        profileName: selectedPolicyRollbackProfileName(),
        silent: false,
        updateMeta: false
      });
    }
    const latest = draftPolicyRollbackFromLatest();
    setPolicyRollbackTag('drafted', '#ffb03a');
    els.policyRollbackMeta.textContent = `Drafted rollback target ${latest.patch_id} (before).`;
    logAction('policy:rollback:draft-latest', {
      profile_name: selectedPolicyRollbackProfileName(),
      target_patch_id: latest.patch_id,
      target_state: 'before'
    });
  } catch (err) {
    setPolicyRollbackTag('error', '#ff6b6b');
    els.policyRollbackMeta.textContent = String(err);
    logAction('policy:rollback:draft:error', String(err));
  }
});
els.policyRollbackDryRunBtn.addEventListener('click', async () => {
  await runPolicyRollback('dry_run');
});
els.policyRollbackApplyBtn.addEventListener('click', async () => {
  await runPolicyRollback('apply');
});
els.policyRollbackProfileSelect.addEventListener('change', async () => {
  const profileName = selectedPolicyRollbackProfileName();
  try {
    await loadPolicyProfileVersion({ profileName, silent: true });
    await loadPolicyRollbackHistory({
      profileName,
      silent: true,
      updateMeta: false
    });
  } catch {
    // ignore and keep UI responsive; fields already reflect fallback state.
  }
  if (!state.policyRollbackResult) {
    els.policyRollbackMeta.textContent = `Selected profile ${profileName || 'none'}.`;
  }
});
els.blueprintKitSelect.addEventListener('change', () => {
  const kit = state.agentKits.find((item) => item.kit_id === els.blueprintKitSelect.value);
  if (kit && !String(els.blueprintConnectorsInput.value || '').trim()) {
    els.blueprintConnectorsInput.value = (kit.connector_candidates || [])
      .map((item) => item.connector_id)
      .join(', ');
  }
  if (kit && !String(els.blueprintAgentNameInput.value || '').trim()) {
    els.blueprintAgentNameInput.value = kit.name;
  }
  if (!state.blueprintPreview) {
    els.blueprintMeta.textContent = `Selected ${kit?.name || 'kit'}. Click Preview Blueprint.`;
  }
});
els.refreshBtn.addEventListener('click', async () => {
  try {
    await Promise.all([
      loadHealth(),
      syncState(),
      loadConnectorGovernance(),
      loadReplayDriftSummary(),
      loadAgentKits(),
      loadPolicyProfiles()
    ]);
    refreshRuntimeViews();
    await refreshTimelineForSelectedRun();
  } catch (err) {
    logAction('refresh:error', String(err));
  }
});
els.starterModeBtn.addEventListener('click', () => {
  setUiMode('starter');
});
els.advancedModeBtn.addEventListener('click', () => {
  setUiMode('advanced');
});
els.advancedToolsOpenBtn.addEventListener('click', () => {
  setUiMode('advanced');
});
els.compactToggleBtn.addEventListener('click', () => {
  setCompactMode(!state.compactMode);
});
els.createAgentBtn.addEventListener('click', async () => {
  try {
    await createAgent();
  } catch (err) {
    logAction('agent:error', String(err));
  }
});
els.createBindingBtn.addEventListener('click', async () => {
  try {
    const agent = state.agents[state.agents.length - 1];
    if (!agent) {
      throw new Error('Create an agent first.');
    }
    await createBinding(agent.id);
  } catch (err) {
    logAction('binding:error', String(err));
  }
});
els.createRunBtn.addEventListener('click', async () => {
  try {
    const agent = state.agents[state.agents.length - 1];
    if (!agent) {
      throw new Error('Create an agent first.');
    }
    await createRun(agent.id);
  } catch (err) {
    logAction('run:error', String(err));
  }
});
els.timelineRunSelect.addEventListener('change', async () => {
  state.selectedRunId = els.timelineRunSelect.value || null;
  refreshTimelineBaseRunSelect();
  await refreshTimelineForSelectedRun();
});
els.timelineBaseRunSelect.addEventListener('change', () => {
  state.timelineDiffBaseRunId = els.timelineBaseRunSelect.value || '';
  clearTimelineDiff('Base run changed. Click Load Diff.');
});
els.timelineReloadBtn.addEventListener('click', async () => {
  await refreshTimelineForSelectedRun();
});
els.timelineDiffBtn.addEventListener('click', async () => {
  await loadRunTimelineDiff(state.selectedRunId);
});
els.timelineReplayBtn.addEventListener('click', async () => {
  await loadRunReplayIntegrity(state.selectedRunId);
});
els.timelineReplayExportBtn.addEventListener('click', async () => {
  await exportRunReplayIntegrity(state.selectedRunId);
});
els.timelineExportBtn.addEventListener('click', async () => {
  try {
    if (!state.selectedRunId) {
      throw new Error('No run selected for incident export.');
    }
    const incident = await api(`/v0/runs/${state.selectedRunId}/incident-export?max_items_per_stream=2000`);
    logAction(`incident-export:${state.selectedRunId}`, incident);
  } catch (err) {
    logAction('incident-export:error', String(err));
  }
});
els.replayDriftRefreshBtn.addEventListener('click', async () => {
  await loadReplayDriftSummary();
});

if (!parseCsvUnique(els.quickstartConnectorIdsInput.value).length) {
  const defaults = quickstartTemplateDefaultConnectorIds(selectedQuickstartTemplateId());
  els.quickstartConnectorIdsInput.value = defaults.join(', ');
}

try {
  setUiMode(readInitialUiMode(), { persist: false });
  setCompactMode(readInitialCompactMode(), { persist: false });
  await Promise.all([
    loadHealth(),
    syncState(),
    loadConnectorGovernance(),
    loadReplayDriftSummary(),
    loadAgentKits(),
    loadPolicyProfiles()
  ]);
  refreshRuntimeViews();
  await refreshTimelineForSelectedRun();
} catch (err) {
  logAction('init:error', String(err));
}

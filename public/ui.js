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
  environmentSets: [],
  roleBindings: [],
  sessions: [],
  sessionDetail: null,
  effectiveEnvironment: null,
  accessPermissions: null,
  environmentVerification: null,
  selectedEnvironmentSetId: '',
  selectedSessionId: '',
  pendingApprovals: [],
  selectedRunId: null,
  timelineEvents: null,
  timelineAudit: null,
  timelineDiff: null,
  replayIntegrity: null,
  replayDrift: null,
  timelineDiffBaseRunId: '',
  uiMode: 'starter',
  compactMode: false,
  runtimeView: 'approvals',
  workbenchSection: 'agent',
  journeySetupConfirmed: false,
  journeyPresetId: 'opc',
  starterBridgeProfile: null,
  starterReadiness: null,
  feishuStatus: null
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

const ENV_PROVIDER_TEMPLATES = Object.freeze({
  feishu: Object.freeze({
    label: 'Feishu',
    subtitle: 'Approval & delivery',
    entries: [
      {
        provider: 'feishu',
        key: 'FLOCKMESH_FEISHU_WEBHOOK_URL',
        value: 'https://open.feishu.cn/open-apis/bot/v2/hook/replace_me',
        visibility: 'secret'
      }
    ]
  }),
  langfuse: Object.freeze({
    label: 'Langfuse',
    subtitle: 'Tracing & observability',
    entries: [
      {
        provider: 'langfuse',
        key: 'LANGFUSE_HOST',
        value: 'https://cloud.langfuse.com',
        visibility: 'plain'
      },
      {
        provider: 'langfuse',
        key: 'LANGFUSE_PUBLIC_KEY',
        value: 'pk_replace_me',
        visibility: 'secret'
      },
      {
        provider: 'langfuse',
        key: 'LANGFUSE_SECRET_KEY',
        value: 'sk_replace_me',
        visibility: 'secret'
      }
    ]
  }),
  aws: Object.freeze({
    label: 'AWS',
    subtitle: 'Cloud resources',
    entries: [
      {
        provider: 'aws',
        key: 'AWS_ACCESS_KEY_ID',
        value: 'AKIA_REPLACE_ME',
        visibility: 'secret'
      },
      {
        provider: 'aws',
        key: 'AWS_SECRET_ACCESS_KEY',
        value: 'replace_secret',
        visibility: 'secret'
      },
      {
        provider: 'aws',
        key: 'AWS_REGION',
        value: 'us-east-1',
        visibility: 'plain'
      }
    ]
  }),
  claude_code: Object.freeze({
    label: 'Claude Code',
    subtitle: 'IDE agent bridge',
    entries: [
      {
        provider: 'claude_code',
        key: 'ANTHROPIC_API_KEY',
        value: 'sk-ant-api03-replace_me',
        visibility: 'secret'
      },
      {
        provider: 'claude_code',
        key: 'ANTHROPIC_BASE_URL',
        value: 'https://api.anthropic.com',
        visibility: 'plain'
      }
    ]
  }),
  codex: Object.freeze({
    label: 'Codex/OpenAI',
    subtitle: 'IDE agent bridge',
    entries: [
      {
        provider: 'codex',
        key: 'OPENAI_API_KEY',
        value: 'sk-proj-replace_me',
        visibility: 'secret'
      },
      {
        provider: 'codex',
        key: 'OPENAI_BASE_URL',
        value: 'https://api.openai.com/v1',
        visibility: 'plain'
      }
    ]
  })
});

const QUICKSTART_WORKSPACE_ID_PATTERN = /^wsp_[A-Za-z0-9_-]{6,64}$/;
const QUICKSTART_OWNER_ID_PATTERN = /^usr_[A-Za-z0-9_-]{4,64}$/;

const JOURNEY_PATH_PRESETS = Object.freeze({
  startup: Object.freeze({
    label: 'Team Setup',
    workspaceId: 'wsp_startup_launch',
    ownerId: 'usr_founder_ops',
    templateId: 'incident_response',
    connectorIds: ['con_feishu_official', 'con_mcp_gateway'],
    idempotencyPrefix: 'idem_startup_first_run'
  }),
  opc: Object.freeze({
    label: 'Solo Setup',
    workspaceId: 'wsp_one_person_company',
    ownerId: 'usr_solo_builder',
    templateId: 'weekly_ops_sync',
    connectorIds: ['con_feishu_official'],
    idempotencyPrefix: 'idem_opc_first_run'
  })
});

const UI_MODE_STORAGE_KEY = 'flockmesh_ui_mode';
const WORKSPACE_PATH_STORAGE_KEY = 'flockmesh_workspace_path';
const UI_MODE_SET = new Set(['starter', 'advanced']);
const RUNTIME_VIEW_SET = new Set(['approvals', 'runs']);
const WORKBENCH_SECTION_SET = new Set(['agent', 'governance', 'observability']);
let starterBridgeRefreshTimer = null;
let starterBridgeRequestToken = 0;
let starterReadinessRefreshTimer = null;
let starterReadinessRequestToken = 0;
let workspaceContextRefreshTimer = null;

const els = {
  bootstrapBtn: document.getElementById('bootstrapBtn'),
  heroStartQuickstartBtn: document.getElementById('heroStartQuickstartBtn'),
  heroStartupPathBtn: document.getElementById('heroStartupPathBtn'),
  heroOpcPathBtn: document.getElementById('heroOpcPathBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  starterModeBtn: document.getElementById('starterModeBtn'),
  advancedModeBtn: document.getElementById('advancedModeBtn'),
  compactToggleBtn: document.getElementById('compactToggleBtn'),
  quickstartSection: document.getElementById('quickstartSection'),
  runLaunchSection: document.getElementById('runLaunchSection'),
  runtimeFocusSection: document.getElementById('runtimeFocusSection'),
  journeyTag: document.getElementById('journeyTag'),
  journeyStepSetup: document.getElementById('journeyStepSetup'),
  journeyStepRun: document.getElementById('journeyStepRun'),
  journeyStepReview: document.getElementById('journeyStepReview'),
  journeySetupStatus: document.getElementById('journeySetupStatus'),
  journeyRunStatus: document.getElementById('journeyRunStatus'),
  journeyReviewStatus: document.getElementById('journeyReviewStatus'),
  journeyPresetTag: document.getElementById('journeyPresetTag'),
  journeyGoSetupBtn: document.getElementById('journeyGoSetupBtn'),
  journeyStartRunBtn: document.getElementById('journeyStartRunBtn'),
  journeyContinueToStartBtn: document.getElementById('journeyContinueToStartBtn'),
  journeyBackToSetupBtn: document.getElementById('journeyBackToSetupBtn'),
  journeyReviewBtn: document.getElementById('journeyReviewBtn'),
  runLaunchTag: document.getElementById('runLaunchTag'),
  runLaunchSummary: document.getElementById('runLaunchSummary'),
  quickstartTag: document.getElementById('quickstartTag'),
  quickstartWorkspaceInput: document.getElementById('quickstartWorkspaceInput'),
  quickstartWorkspacePathInput: document.getElementById('quickstartWorkspacePathInput'),
  quickstartWorkspacePathDefaultBtn: document.getElementById('quickstartWorkspacePathDefaultBtn'),
  quickstartOwnerInput: document.getElementById('quickstartOwnerInput'),
  quickstartTemplateSelect: document.getElementById('quickstartTemplateSelect'),
  quickstartModeSelect: document.getElementById('quickstartModeSelect'),
  quickstartConnectorIdsInput: document.getElementById('quickstartConnectorIdsInput'),
  quickstartIdemInput: document.getElementById('quickstartIdemInput'),
  quickstartStartBtn: document.getElementById('quickstartStartBtn'),
  envSetNameInput: document.getElementById('envSetNameInput'),
  envSetScopeSelect: document.getElementById('envSetScopeSelect'),
  envSetEntriesInput: document.getElementById('envSetEntriesInput'),
  envProviderCards: document.getElementById('envProviderCards'),
  envTemplateMeta: document.getElementById('envTemplateMeta'),
  envTemplateTargetInput: document.getElementById('envTemplateTargetInput'),
  envSetCreateBtn: document.getElementById('envSetCreateBtn'),
  envSetCreateApplyBtn: document.getElementById('envSetCreateApplyBtn'),
  envSetRefreshBtn: document.getElementById('envSetRefreshBtn'),
  envSetSelect: document.getElementById('envSetSelect'),
  envSetVerifyModeSelect: document.getElementById('envSetVerifyModeSelect'),
  envSetVerifyTimeoutInput: document.getElementById('envSetVerifyTimeoutInput'),
  envSetVerifyBtn: document.getElementById('envSetVerifyBtn'),
  envSetActivateBtn: document.getElementById('envSetActivateBtn'),
  envSetApplyRuntimeBtn: document.getElementById('envSetApplyRuntimeBtn'),
  envSetMeta: document.getElementById('envSetMeta'),
  envVerifySummary: document.getElementById('envVerifySummary'),
  envSetPayload: document.getElementById('envSetPayload'),
  quickstartGuideMeta: document.getElementById('quickstartGuideMeta'),
  quickstartMeta: document.getElementById('quickstartMeta'),
  quickstartPayload: document.getElementById('quickstartPayload'),
  starterBridgeCommand: document.getElementById('starterBridgeCommand'),
  starterBridgeCopyBtn: document.getElementById('starterBridgeCopyBtn'),
  starterBridgeProfileBtn: document.getElementById('starterBridgeProfileBtn'),
  starterBridgeMeta: document.getElementById('starterBridgeMeta'),
  starterReadinessTag: document.getElementById('starterReadinessTag'),
  starterReadinessProbeInput: document.getElementById('starterReadinessProbeInput'),
  starterReadinessRefreshBtn: document.getElementById('starterReadinessRefreshBtn'),
  starterReadinessMeta: document.getElementById('starterReadinessMeta'),
  starterReadinessStageList: document.getElementById('starterReadinessStageList'),
  starterReadinessActionList: document.getElementById('starterReadinessActionList'),
  starterReadinessPayload: document.getElementById('starterReadinessPayload'),
  feishuWebhookInput: document.getElementById('feishuWebhookInput'),
  feishuWebhookSaveBtn: document.getElementById('feishuWebhookSaveBtn'),
  feishuWebhookClearBtn: document.getElementById('feishuWebhookClearBtn'),
  feishuWebhookTestBtn: document.getElementById('feishuWebhookTestBtn'),
  feishuStatusMeta: document.getElementById('feishuStatusMeta'),
  openApprovalInboxBtn: document.getElementById('openApprovalInboxBtn'),
  latestExecutionEvidence: document.getElementById('latestExecutionEvidence'),
  runtimeFocusTag: document.getElementById('runtimeFocusTag'),
  runtimeOpenWorkbenchBtn: document.getElementById('runtimeOpenWorkbenchBtn'),
  runtimeViewApprovalsBtn: document.getElementById('runtimeViewApprovalsBtn'),
  runtimeViewRunsBtn: document.getElementById('runtimeViewRunsBtn'),
  runtimeApprovalsPane: document.getElementById('runtimeApprovalsPane'),
  runtimeRunsPane: document.getElementById('runtimeRunsPane'),
  accessPermissionsRefreshBtn: document.getElementById('accessPermissionsRefreshBtn'),
  accessPermissionsMeta: document.getElementById('accessPermissionsMeta'),
  accessPermissionsPayload: document.getElementById('accessPermissionsPayload'),
  roleBindingActorInput: document.getElementById('roleBindingActorInput'),
  roleBindingRoleSelect: document.getElementById('roleBindingRoleSelect'),
  roleBindingGrantBtn: document.getElementById('roleBindingGrantBtn'),
  roleBindingRefreshBtn: document.getElementById('roleBindingRefreshBtn'),
  roleBindingMeta: document.getElementById('roleBindingMeta'),
  roleBindingPayload: document.getElementById('roleBindingPayload'),
  effectiveEnvActorInput: document.getElementById('effectiveEnvActorInput'),
  effectiveEnvModeSelect: document.getElementById('effectiveEnvModeSelect'),
  effectiveEnvIncludeValuesInput: document.getElementById('effectiveEnvIncludeValuesInput'),
  effectiveEnvLoadBtn: document.getElementById('effectiveEnvLoadBtn'),
  effectiveEnvMeta: document.getElementById('effectiveEnvMeta'),
  effectiveEnvPayload: document.getElementById('effectiveEnvPayload'),
  sessionFilterActorInput: document.getElementById('sessionFilterActorInput'),
  sessionFilterStatusSelect: document.getElementById('sessionFilterStatusSelect'),
  sessionRefreshBtn: document.getElementById('sessionRefreshBtn'),
  sessionSelect: document.getElementById('sessionSelect'),
  sessionIncludeEvidenceInput: document.getElementById('sessionIncludeEvidenceInput'),
  sessionLoadDetailBtn: document.getElementById('sessionLoadDetailBtn'),
  sessionList: document.getElementById('sessionList'),
  sessionMeta: document.getElementById('sessionMeta'),
  sessionPayload: document.getElementById('sessionPayload'),
  sessionDetailPayload: document.getElementById('sessionDetailPayload'),
  advancedToolsOpenBtn: document.getElementById('advancedToolsOpenBtn'),
  workbenchAgentTabBtn: document.getElementById('workbenchAgentTabBtn'),
  workbenchGovernanceTabBtn: document.getElementById('workbenchGovernanceTabBtn'),
  workbenchObservabilityTabBtn: document.getElementById('workbenchObservabilityTabBtn'),
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
  runCardTemplate: document.getElementById('runCardTemplate'),
  heroPathCards: Array.from(document.querySelectorAll('.hero-path-card'))
};

function logAction(label, payload) {
  const line = `[${new Date().toISOString()}] ${label}\n${JSON.stringify(payload, null, 2)}\n`;
  els.actionLog.textContent = `${line}\n${els.actionLog.textContent}`.slice(0, 8000);
}

async function copyTextToClipboard(text) {
  const normalized = String(text || '');
  if (!normalized) return false;

  if (navigator?.clipboard?.writeText) {
    await navigator.clipboard.writeText(normalized);
    return true;
  }

  const textarea = document.createElement('textarea');
  textarea.value = normalized;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.top = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  document.body.removeChild(textarea);
  return copied;
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
  const fallback = currentUiActorId();
  if (fallback) return fallback;
  return 'usr_yingapple';
}

function currentUiActorId() {
  const fromQuickstart = String(els.quickstartOwnerInput?.value || '').trim();
  if (fromQuickstart) return fromQuickstart;
  const fromAccess = String(state.accessPermissions?.actor_id || '').trim();
  if (fromAccess) return fromAccess;
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

function currentWorkspaceId() {
  return String(els.quickstartWorkspaceInput?.value || '').trim();
}

function currentQuickstartMode() {
  return String(els.quickstartModeSelect?.value || 'opc').trim() || 'opc';
}

function setEnvironmentMeta(text, color = '#5f6b7f') {
  if (!els.envSetMeta) return;
  els.envSetMeta.textContent = text;
  els.envSetMeta.style.color = color;
}

function setRoleBindingMeta(text, color = '#5f6b7f') {
  if (!els.roleBindingMeta) return;
  els.roleBindingMeta.textContent = text;
  els.roleBindingMeta.style.color = color;
}

function setSessionMeta(text, color = '#5f6b7f') {
  if (!els.sessionMeta) return;
  els.sessionMeta.textContent = text;
  els.sessionMeta.style.color = color;
}

function setEffectiveEnvMeta(text, color = '#5f6b7f') {
  if (!els.effectiveEnvMeta) return;
  els.effectiveEnvMeta.textContent = text;
  els.effectiveEnvMeta.style.color = color;
}

function setEnvironmentTemplateMeta(text, color = '#5f6b7f') {
  if (!els.envTemplateMeta) return;
  els.envTemplateMeta.textContent = text;
  els.envTemplateMeta.style.color = color;
}

function setAccessPermissionsMeta(text, color = '#5f6b7f') {
  if (!els.accessPermissionsMeta) return;
  els.accessPermissionsMeta.textContent = text;
  els.accessPermissionsMeta.style.color = color;
}

function renderEnvironmentVerificationSummary(payload = null) {
  if (!els.envVerifySummary) return;
  els.envVerifySummary.innerHTML = '';

  const report = payload?.report;
  if (!report || !Array.isArray(report.providers) || !report.providers.length) {
    return;
  }

  const connectivityByProvider = new Map(
    Array.isArray(payload?.connectivity?.providers)
      ? payload.connectivity.providers.map((item) => [String(item.provider || ''), item])
      : []
  );

  for (const providerReport of report.providers) {
    const providerName = String(providerReport.provider || 'generic');
    const card = document.createElement('article');
    card.className = 'env-verify-card';

    const title = document.createElement('h4');
    title.textContent = `${providerName} · ${String(providerReport.status || 'unknown').toUpperCase()}`;
    const detail = document.createElement('p');
    detail.textContent =
      `checks ${providerReport.summary?.total_checks || 0} · fail ${providerReport.summary?.fail || 0} · warn ${providerReport.summary?.warn || 0}`;

    card.append(title, detail);

    const probe = connectivityByProvider.get(providerName);
    if (probe) {
      const probeLine = document.createElement('p');
      probeLine.textContent =
        `probe ${String(probe.status || 'skip').toUpperCase()} · reachable ${probe.reachable ? 'yes' : 'no'}${probe.http_status ? ` · http ${probe.http_status}` : ''}`;
      card.append(probeLine);
    }

    const recs = Array.isArray(providerReport.recommendations)
      ? providerReport.recommendations.filter(Boolean).slice(0, 2)
      : [];
    if (recs.length) {
      const recLine = document.createElement('p');
      recLine.textContent = `next: ${recs.join(' | ')}`;
      card.append(recLine);
    }

    els.envVerifySummary.append(card);
  }
}

function syncAccessDrivenControls() {
  const payload = state.accessPermissions || {};
  const permissions = new Set(Array.isArray(payload.permissions) ? payload.permissions : []);
  const bootstrapAvailable = payload.bootstrap_available === true;

  const canManageEnvironment = bootstrapAvailable || permissions.has('environment.manage');
  const canManageRoles = bootstrapAvailable || permissions.has('role.manage');
  const canReadSessions = bootstrapAvailable || permissions.has('session.read');

  if (els.envSetCreateBtn) els.envSetCreateBtn.disabled = !canManageEnvironment;
  if (els.envSetCreateApplyBtn) els.envSetCreateApplyBtn.disabled = !canManageEnvironment;
  if (els.envSetVerifyBtn) els.envSetVerifyBtn.disabled = !canManageEnvironment;
  if (els.envSetActivateBtn) els.envSetActivateBtn.disabled = !canManageEnvironment;
  if (els.envSetApplyRuntimeBtn) els.envSetApplyRuntimeBtn.disabled = !canManageEnvironment;
  if (els.roleBindingGrantBtn) els.roleBindingGrantBtn.disabled = !canManageRoles;
  if (els.sessionRefreshBtn) els.sessionRefreshBtn.disabled = !canReadSessions;
  if (els.sessionLoadDetailBtn) els.sessionLoadDetailBtn.disabled = !canReadSessions;
}

function toEnvironmentEntryLine(entry = {}) {
  const provider = String(entry.provider || 'generic').trim();
  const key = String(entry.key || '').trim();
  const value = String(entry.value || '').trim();
  const visibility = String(entry.visibility || '').trim();
  const target = String(entry.target || '').trim();
  if (!provider || !key || !value) return '';
  if (!visibility && !target) return `${provider} ${key} ${value}`;
  if (visibility && !target) return `${provider} ${key} ${value} ${visibility}`;
  if (!visibility && target) return `${provider} ${key} ${value} ${target}`;
  return `${provider} ${key} ${value} ${visibility} ${target}`;
}

function listEnvironmentEntryKeysFromText(rawText = '') {
  const keys = new Set();
  const lines = String(rawText || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.startsWith('#'));

  for (const line of lines) {
    const [providerRaw, keyRaw] = line.split(/\s+/).filter(Boolean);
    const provider = String(providerRaw || '').trim().toLowerCase();
    const key = String(keyRaw || '').trim().toUpperCase();
    if (!provider || !key) continue;
    keys.add(`${provider}::${key}`);
  }

  return keys;
}

function addEnvironmentProviderTemplate(templateId) {
  const template = ENV_PROVIDER_TEMPLATES[templateId];
  if (!template) {
    setEnvironmentTemplateMeta(`Unknown template: ${templateId}`, '#d92d20');
    return;
  }

  const existingText = String(els.envSetEntriesInput?.value || '');
  const existingKeys = listEnvironmentEntryKeysFromText(existingText);
  const templateTarget = String(els.envTemplateTargetInput?.value || '').trim();
  const appended = [];

  for (const entry of template.entries || []) {
    const provider = String(entry.provider || 'generic').trim().toLowerCase();
    const key = String(entry.key || '').trim().toUpperCase();
    if (!provider || !key) continue;
    const dedupeKey = `${provider}::${key}`;
    if (existingKeys.has(dedupeKey)) continue;
    const line = toEnvironmentEntryLine({
      ...entry,
      ...(templateTarget ? { target: templateTarget } : {})
    });
    if (!line) continue;
    appended.push(line);
    existingKeys.add(dedupeKey);
  }

  if (!appended.length) {
    setEnvironmentTemplateMeta(`${template.label} keys already exist in entries.`, '#c17b23');
    return;
  }

  const merged = [existingText.trim(), ...appended].filter(Boolean).join('\n');
  els.envSetEntriesInput.value = merged;
  setEnvironmentTemplateMeta(
    `Inserted ${template.label} template (${appended.length} new key${appended.length > 1 ? 's' : ''}).`,
    '#1d9a6c'
  );
}

function renderEnvironmentProviderCards() {
  if (!els.envProviderCards) return;
  els.envProviderCards.innerHTML = '';

  Object.entries(ENV_PROVIDER_TEMPLATES).forEach(([templateId, template]) => {
    const card = document.createElement('article');
    card.className = 'env-provider-card';

    const title = document.createElement('h4');
    title.textContent = template.label;
    const subtitle = document.createElement('p');
    subtitle.textContent = template.subtitle;
    const button = document.createElement('button');
    button.className = 'btn btn-ghost';
    button.type = 'button';
    button.textContent = 'Insert Template';
    button.dataset.envTemplateId = templateId;
    button.addEventListener('click', () => {
      addEnvironmentProviderTemplate(templateId);
    });

    card.append(title, subtitle, button);
    els.envProviderCards.append(card);
  });
}

function parseEnvironmentEntriesText(rawText = '') {
  const lines = String(rawText || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.startsWith('#'));

  const visibilitySet = new Set(['secret', 'masked', 'plain']);
  const entries = [];
  for (const [index, line] of lines.entries()) {
    const parts = line.split(/\s+/).filter(Boolean);
    if (parts.length < 3) {
      throw new Error(`Invalid entry at line ${index + 1}. Use: provider key value [visibility] [target]`);
    }
    const [provider, key, value, fourthRaw, fifthRaw] = parts;
    let visibility = '';
    let target = '';

    if (fourthRaw) {
      const normalizedFourth = String(fourthRaw || '').trim().toLowerCase();
      if (visibilitySet.has(normalizedFourth)) {
        visibility = normalizedFourth;
        if (fifthRaw) {
          target = String(fifthRaw || '').trim();
        }
      } else {
        target = String(fourthRaw || '').trim();
      }
    }

    const entry = {
      provider,
      key,
      value
    };
    if (visibility) entry.visibility = visibility;
    if (target) entry.target = target;
    entries.push(entry);
  }
  return entries;
}

function renderEnvironmentSetSelect() {
  if (!els.envSetSelect) return;
  els.envSetSelect.innerHTML = '';

  const workspaceId = currentWorkspaceId();
  const sets = state.environmentSets.filter((item) => item.workspace_id === workspaceId);
  if (!sets.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No env sets';
    els.envSetSelect.append(option);
    state.selectedEnvironmentSetId = '';
    return;
  }

  sets.forEach((item) => {
    const option = document.createElement('option');
    option.value = item.id;
    option.textContent = `${item.name} (${item.scope}/${item.mode})${item.status === 'active' ? ' *active' : ''}`;
    els.envSetSelect.append(option);
  });

  const preferred = sets.find((item) => item.id === state.selectedEnvironmentSetId)
    || sets.find((item) => item.status === 'active')
    || sets[0];
  state.selectedEnvironmentSetId = preferred.id;
  els.envSetSelect.value = preferred.id;
}

function readEnvironmentVerifyOptions() {
  const mode = String(els.envSetVerifyModeSelect?.value || 'syntax').trim() || 'syntax';
  const timeoutMsRaw = Number(els.envSetVerifyTimeoutInput?.value || 4000);
  const timeoutMs = Number.isFinite(timeoutMsRaw)
    ? Math.min(Math.max(Math.round(timeoutMsRaw), 500), 10000)
    : 4000;
  return {
    probe_mode: mode === 'connectivity' ? 'connectivity' : 'syntax',
    timeout_ms: timeoutMs
  };
}

async function loadEnvironmentSets() {
  const workspaceId = currentWorkspaceId();
  if (!workspaceId) {
    setEnvironmentMeta('Workspace is required before loading environment sets.', '#c17b23');
    return;
  }

  try {
    const payload = await api(`/v0/environments/sets?workspace_id=${encodeURIComponent(workspaceId)}&limit=200&offset=0`);
    state.environmentSets = payload.items || [];
    renderEnvironmentSetSelect();
    state.environmentVerification = null;
    renderEnvironmentVerificationSummary(null);
    els.envSetPayload.textContent = JSON.stringify(payload, null, 2);
    setEnvironmentMeta(`Loaded ${state.environmentSets.length} environment set(s).`, '#1d9a6c');
  } catch (err) {
    setEnvironmentMeta(`Failed to load environment sets: ${String(err)}`, '#d92d20');
    els.envSetPayload.textContent = String(err);
  }
}

async function createEnvironmentSet() {
  const workspaceId = currentWorkspaceId();
  const name = String(els.envSetNameInput?.value || '').trim();
  const mode = currentQuickstartMode();
  const scope = String(els.envSetScopeSelect?.value || 'workspace').trim() || 'workspace';
  const entriesText = String(els.envSetEntriesInput?.value || '').trim();

  if (!workspaceId) {
    setEnvironmentMeta('Workspace is required.', '#d92d20');
    return;
  }
  if (!name) {
    setEnvironmentMeta('Environment set name is required.', '#d92d20');
    return;
  }
  if (!entriesText) {
    setEnvironmentMeta('At least one environment entry is required.', '#d92d20');
    return;
  }

  try {
    const entries = parseEnvironmentEntriesText(entriesText);
    const payload = await api('/v0/environments/sets', {
      method: 'POST',
      body: JSON.stringify({
        workspace_id: workspaceId,
        mode,
        scope,
        name,
        status: 'active',
        entries
      })
    });
    state.selectedEnvironmentSetId = payload.id;
    setEnvironmentMeta(`Created environment set ${payload.id}.`, '#1d9a6c');
    els.envSetPayload.textContent = JSON.stringify(payload, null, 2);
    await loadEnvironmentSets();
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
    return payload;
  } catch (err) {
    setEnvironmentMeta(`Failed to create environment set: ${String(err)}`, '#d92d20');
    els.envSetPayload.textContent = String(err);
    return null;
  }
}

async function verifySelectedEnvironmentSet({ quiet = false } = {}) {
  const setId = String(els.envSetSelect?.value || '').trim();
  if (!setId) {
    setEnvironmentMeta('Select an environment set first.', '#d92d20');
    return null;
  }

  try {
    const verifyOptions = readEnvironmentVerifyOptions();
    const payload = await api(`/v0/environments/sets/${encodeURIComponent(setId)}/verify`, {
      method: 'POST',
      body: JSON.stringify(verifyOptions)
    });
    state.environmentVerification = payload;
    renderEnvironmentVerificationSummary(payload);
    els.envSetPayload.textContent = JSON.stringify(payload, null, 2);

    const status = String(payload?.report?.status || 'warn');
    const summary = payload?.report?.summary || {};
    const probeSummary = payload?.connectivity?.summary;
    const probeSuffix = probeSummary
      ? ` · probe fail ${probeSummary.fail || 0} warn ${probeSummary.warn || 0}`
      : '';
    const label = `Verify ${status.toUpperCase()} · providers ${summary.total_providers || 0} · checks ${summary.total_checks || 0} (fail ${summary.fail || 0}, warn ${summary.warn || 0})${probeSuffix}`;
    if (!quiet || status !== 'pass') {
      setEnvironmentMeta(label, status === 'fail' ? '#d92d20' : status === 'warn' ? '#c17b23' : '#1d9a6c');
    }
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
    return payload;
  } catch (err) {
    setEnvironmentMeta(`Failed to verify environment set: ${String(err)}`, '#d92d20');
    els.envSetPayload.textContent = String(err);
    return null;
  }
}

async function activateSelectedEnvironmentSet() {
  const setId = String(els.envSetSelect?.value || '').trim();
  if (!setId) {
    setEnvironmentMeta('Select an environment set first.', '#d92d20');
    return;
  }

  try {
    const payload = await api(`/v0/environments/sets/${encodeURIComponent(setId)}/activate`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    state.selectedEnvironmentSetId = payload.id;
    els.envSetPayload.textContent = JSON.stringify(payload, null, 2);
    setEnvironmentMeta(`Activated environment set ${payload.id}.`, '#1d9a6c');
    await loadEnvironmentSets();
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
  } catch (err) {
    setEnvironmentMeta(`Failed to activate environment set: ${String(err)}`, '#d92d20');
    els.envSetPayload.textContent = String(err);
  }
}

async function applySelectedEnvironmentSetRuntime() {
  const setId = String(els.envSetSelect?.value || '').trim();
  if (!setId) {
    setEnvironmentMeta('Select an environment set first.', '#d92d20');
    return;
  }

  try {
    const payload = await api(`/v0/environments/sets/${encodeURIComponent(setId)}/apply-runtime`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    els.envSetPayload.textContent = JSON.stringify(payload, null, 2);
    setEnvironmentMeta(
      payload?.runtime_updates?.feishu_webhook_applied
        ? 'Applied env set to runtime (Feishu webhook active).'
        : 'Applied env set to runtime.',
      '#1d9a6c'
    );
    await loadFeishuStatus();
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
  } catch (err) {
    setEnvironmentMeta(`Failed to apply env set to runtime: ${String(err)}`, '#d92d20');
    els.envSetPayload.textContent = String(err);
  }
}

async function createActivateApplyEnvironmentSet() {
  const created = await createEnvironmentSet();
  if (!created?.id) return;
  state.selectedEnvironmentSetId = created.id;
  if (els.envSetSelect) {
    els.envSetSelect.value = created.id;
  }
  await activateSelectedEnvironmentSet();
  await verifySelectedEnvironmentSet({ quiet: true });
  await applySelectedEnvironmentSetRuntime();
  setEnvironmentMeta('Created, activated, verified, and applied environment set to runtime.', '#1d9a6c');
  scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
}

async function loadAccessPermissions() {
  const workspaceId = currentWorkspaceId();
  if (!workspaceId) {
    setAccessPermissionsMeta('Workspace is required before loading access.', '#c17b23');
    return;
  }

  const actorId = String(els.quickstartOwnerInput?.value || '').trim();
  const query = new URLSearchParams();
  query.set('workspace_id', workspaceId);
  if (actorId) {
    query.set('actor_id', actorId);
  }

  try {
    const payload = await api(`/v0/access/permissions?${query.toString()}`);
    state.accessPermissions = payload;
    els.accessPermissionsPayload.textContent = JSON.stringify(payload, null, 2);
    setAccessPermissionsMeta(
      `Roles ${payload.roles.length} · Permissions ${payload.permissions.length} · Bootstrap ${payload.bootstrap_available ? 'available' : 'off'}.`,
      '#1d9a6c'
    );
    syncAccessDrivenControls();
  } catch (err) {
    state.accessPermissions = null;
    setAccessPermissionsMeta(`Failed to load access: ${String(err)}`, '#d92d20');
    els.accessPermissionsPayload.textContent = String(err);
    syncAccessDrivenControls();
  }
}

async function loadRoleBindings() {
  const workspaceId = currentWorkspaceId();
  if (!workspaceId) {
    setRoleBindingMeta('Workspace is required before loading role bindings.', '#c17b23');
    return;
  }

  try {
    const payload = await api(`/v0/access/role-bindings?workspace_id=${encodeURIComponent(workspaceId)}&limit=200&offset=0`);
    state.roleBindings = payload.items || [];
    els.roleBindingPayload.textContent = JSON.stringify(payload, null, 2);
    setRoleBindingMeta(`Loaded ${state.roleBindings.length} role binding(s).`, '#1d9a6c');
  } catch (err) {
    setRoleBindingMeta(`Failed to load role bindings: ${String(err)}`, '#d92d20');
    els.roleBindingPayload.textContent = String(err);
  }
}

async function loadEffectiveEnvironment() {
  const workspaceId = currentWorkspaceId();
  if (!workspaceId) {
    setEffectiveEnvMeta('Workspace is required before loading effective environment.', '#c17b23');
    return null;
  }

  const actorId = String(els.effectiveEnvActorInput?.value || '').trim()
    || String(els.quickstartOwnerInput?.value || '').trim();
  const mode = String(els.effectiveEnvModeSelect?.value || 'all').trim();
  const includeValues = Boolean(els.effectiveEnvIncludeValuesInput?.checked);

  const query = new URLSearchParams();
  query.set('workspace_id', workspaceId);
  if (actorId) query.set('actor_id', actorId);
  if (mode && mode !== 'all') query.set('mode', mode);
  if (includeValues) query.set('include_values', 'true');

  try {
    const payload = await api(`/v0/environments/effective?${query.toString()}`);
    state.effectiveEnvironment = payload;
    if (els.effectiveEnvPayload) {
      els.effectiveEnvPayload.textContent = JSON.stringify(payload, null, 2);
    }
    setEffectiveEnvMeta(
      `Loaded ${payload.total || 0} effective env entries for ${payload.actor_id || actorId || 'actor'}.`,
      '#1d9a6c'
    );
    return payload;
  } catch (err) {
    state.effectiveEnvironment = null;
    if (els.effectiveEnvPayload) {
      els.effectiveEnvPayload.textContent = String(err);
    }
    setEffectiveEnvMeta(`Failed to load effective environment: ${String(err)}`, '#d92d20');
    return null;
  }
}

async function grantRoleBinding() {
  const workspaceId = currentWorkspaceId();
  const actorId = String(els.roleBindingActorInput?.value || '').trim();
  const role = String(els.roleBindingRoleSelect?.value || '').trim();

  if (!workspaceId) {
    setRoleBindingMeta('Workspace is required.', '#d92d20');
    return;
  }
  if (!actorId) {
    setRoleBindingMeta('Grant actor is required.', '#d92d20');
    return;
  }

  try {
    const payload = await api('/v0/access/role-bindings', {
      method: 'POST',
      body: JSON.stringify({
        workspace_id: workspaceId,
        actor_id: actorId,
        role
      })
    });
    els.roleBindingPayload.textContent = JSON.stringify(payload, null, 2);
    setRoleBindingMeta(`Granted ${role} to ${actorId}.`, '#1d9a6c');
    await Promise.all([
      loadRoleBindings(),
      loadAccessPermissions(),
      loadEffectiveEnvironment()
    ]);
  } catch (err) {
    setRoleBindingMeta(`Failed to grant role: ${String(err)}`, '#d92d20');
    els.roleBindingPayload.textContent = String(err);
  }
}

function buildSessionListQuery() {
  const workspaceId = currentWorkspaceId();
  const query = new URLSearchParams();
  query.set('workspace_id', workspaceId);
  query.set('limit', '100');
  query.set('offset', '0');

  const actorFilter = String(els.sessionFilterActorInput?.value || '').trim();
  if (actorFilter) {
    query.set('actor_id', actorFilter);
  }

  const statusFilter = String(els.sessionFilterStatusSelect?.value || 'all').trim();
  if (statusFilter && statusFilter !== 'all') {
    query.set('status', statusFilter);
  }

  return query;
}

async function loadSessions() {
  const workspaceId = currentWorkspaceId();
  if (!workspaceId) {
    setSessionMeta('Workspace is required before loading sessions.', '#c17b23');
    return;
  }

  try {
    const payload = await api(`/v0/sessions?${buildSessionListQuery().toString()}`);
    state.sessions = payload.items || [];
    renderSessionSelect();
    renderSessionList();
    if (!state.selectedSessionId && els.sessionDetailPayload) {
      els.sessionDetailPayload.textContent = 'No session detail payload.';
    }
    els.sessionPayload.textContent = JSON.stringify(payload, null, 2);
    setSessionMeta(`Loaded ${state.sessions.length} session(s).`, '#1d9a6c');
  } catch (err) {
    setSessionMeta(`Failed to load sessions: ${String(err)}`, '#d92d20');
    els.sessionPayload.textContent = String(err);
    if (els.sessionList) {
      els.sessionList.innerHTML = '';
    }
  }
}

function renderSessionSelect() {
  if (!els.sessionSelect) return;
  els.sessionSelect.innerHTML = '';
  const items = Array.isArray(state.sessions) ? state.sessions : [];
  if (!items.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No sessions';
    els.sessionSelect.append(option);
    state.selectedSessionId = '';
    state.sessionDetail = null;
    return;
  }

  items.forEach((item) => {
    const option = document.createElement('option');
    option.value = String(item.session_id || '');
    const started = String(item.started_at || '').replace('T', ' ').slice(0, 19);
    option.textContent = `${item.session_id} · ${item.status} · ${started || 'unknown'}`;
    els.sessionSelect.append(option);
  });

  const preferred = items.find((item) => item.session_id === state.selectedSessionId) || items[0];
  state.selectedSessionId = String(preferred?.session_id || '');
  els.sessionSelect.value = state.selectedSessionId;
}

function renderSessionList() {
  if (!els.sessionList) return;
  els.sessionList.innerHTML = '';

  const items = Array.isArray(state.sessions) ? state.sessions : [];
  if (!items.length) {
    els.sessionList.innerHTML = '<p class="run-meta">No session summaries yet.</p>';
    return;
  }

  const top = items.slice(0, 8);
  for (const item of top) {
    const card = document.createElement('article');
    card.className = 'session-card';
    if (item.session_id === state.selectedSessionId) {
      card.style.borderColor = '#b8cbf5';
      card.style.boxShadow = 'inset 0 0 0 1px rgba(20, 86, 240, 0.08)';
    }

    const title = document.createElement('h4');
    title.textContent = item.session_id || 'session';
    const line1 = document.createElement('p');
    line1.textContent = `status ${item.status} · actor ${item.actor_id || '-'} · playbook ${item.playbook_id || '-'}`;
    const line2 = document.createElement('p');
    line2.textContent = `pending ${item.pending_approvals || 0} · policy allow ${item.policy_summary?.allow || 0} escalate ${item.policy_summary?.escalate || 0} deny ${item.policy_summary?.deny || 0}`;
    const line3 = document.createElement('p');
    line3.textContent = `started ${String(item.started_at || '').replace('T', ' ').slice(0, 19) || '-'} · revision ${item.revision || 1}`;

    const actions = document.createElement('div');
    actions.className = 'run-actions';
    const openBtn = document.createElement('button');
    openBtn.type = 'button';
    openBtn.className = 'btn btn-ghost';
    openBtn.textContent = 'Open Detail';
    openBtn.addEventListener('click', async () => {
      state.selectedSessionId = String(item.session_id || '');
      if (els.sessionSelect) {
        els.sessionSelect.value = state.selectedSessionId;
      }
      await loadSelectedSessionDetail();
      renderSessionList();
    });
    actions.append(openBtn);

    card.append(title, line1, line2, line3, actions);
    els.sessionList.append(card);
  }
}

async function loadSelectedSessionDetail() {
  const sessionId = String(els.sessionSelect?.value || state.selectedSessionId || '').trim();
  if (!sessionId) {
    setSessionMeta('Select a session first.', '#d92d20');
    return null;
  }
  state.selectedSessionId = sessionId;

  const includeEvidence = Boolean(els.sessionIncludeEvidenceInput?.checked);
  const query = new URLSearchParams();
  if (includeEvidence) query.set('include_evidence', 'true');
  query.set('limit', '120');

  try {
    const payload = await api(`/v0/sessions/${encodeURIComponent(sessionId)}?${query.toString()}`);
    state.sessionDetail = payload;
    if (els.sessionDetailPayload) {
      els.sessionDetailPayload.textContent = JSON.stringify(payload, null, 2);
    }

    const eventsCount = Number(payload?.evidence?.events?.items?.length || 0);
    const auditCount = Number(payload?.evidence?.audit?.items?.length || 0);
    setSessionMeta(
      includeEvidence
        ? `Loaded session ${sessionId} with evidence (events ${eventsCount}, audit ${auditCount}).`
        : `Loaded session ${sessionId}.`,
      '#1d9a6c'
    );
    return payload;
  } catch (err) {
    setSessionMeta(`Failed to load session detail: ${String(err)}`, '#d92d20');
    if (els.sessionDetailPayload) {
      els.sessionDetailPayload.textContent = String(err);
    }
    return null;
  }
}

async function refreshWorkspaceContext() {
  await Promise.all([
    loadEnvironmentSets(),
    loadAccessPermissions(),
    loadRoleBindings(),
    loadEffectiveEnvironment(),
    loadSessions()
  ]);
}

function scheduleWorkspaceContextRefresh({ immediate = false } = {}) {
  if (workspaceContextRefreshTimer) {
    clearTimeout(workspaceContextRefreshTimer);
    workspaceContextRefreshTimer = null;
  }

  if (immediate) {
    void refreshWorkspaceContext();
    return;
  }

  workspaceContextRefreshTimer = setTimeout(() => {
    void refreshWorkspaceContext();
  }, 280);
}

function setQuickstartTag(label, color = '#5f6b7f') {
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

function readInitialWorkspacePath() {
  return String(window.localStorage.getItem(WORKSPACE_PATH_STORAGE_KEY) || '').trim();
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
  els.starterModeBtn.classList.toggle('mode-hidden', nextMode !== 'advanced');
  els.advancedModeBtn.classList.toggle('mode-hidden', nextMode !== 'starter');

  if (persist) {
    window.localStorage.setItem(UI_MODE_STORAGE_KEY, nextMode);
  }
}

function setRuntimeView(view) {
  const nextView = RUNTIME_VIEW_SET.has(view) ? view : 'approvals';
  state.runtimeView = nextView;

  const showApprovals = nextView === 'approvals';
  els.runtimeApprovalsPane.classList.toggle('mode-hidden', !showApprovals);
  els.runtimeRunsPane.classList.toggle('mode-hidden', showApprovals);
  els.runtimeViewApprovalsBtn.classList.toggle('is-active', showApprovals);
  els.runtimeViewRunsBtn.classList.toggle('is-active', !showApprovals);
  els.runtimeViewApprovalsBtn.classList.toggle('btn-secondary', showApprovals);
  els.runtimeViewApprovalsBtn.classList.toggle('btn-ghost', !showApprovals);
  els.runtimeViewRunsBtn.classList.toggle('btn-secondary', !showApprovals);
  els.runtimeViewRunsBtn.classList.toggle('btn-ghost', showApprovals);
  els.runtimeFocusTag.textContent = showApprovals ? 'approvals' : 'runs';
}

function resolveJourneyPresetId(value) {
  return String(value || '').trim() === 'startup' ? 'startup' : 'opc';
}

function selectedJourneyPreset() {
  return JOURNEY_PATH_PRESETS[resolveJourneyPresetId(state.journeyPresetId)];
}

function setJourneyPresetUi() {
  const presetId = resolveJourneyPresetId(state.journeyPresetId);
  const preset = selectedJourneyPreset();
  if (els.journeyPresetTag) {
    els.journeyPresetTag.textContent = `selected: ${preset.label}`;
  }

  for (const card of els.heroPathCards) {
    const pathId = card.querySelector('button')?.id === 'heroStartupPathBtn' ? 'startup' : 'opc';
    card.classList.toggle('is-active', pathId === presetId);
  }

  if (els.heroStartupPathBtn) {
    const active = presetId === 'startup';
    els.heroStartupPathBtn.classList.toggle('btn-secondary', active);
    els.heroStartupPathBtn.classList.toggle('btn-ghost', !active);
  }

  if (els.heroOpcPathBtn) {
    const active = presetId === 'opc';
    els.heroOpcPathBtn.classList.toggle('btn-secondary', active);
    els.heroOpcPathBtn.classList.toggle('btn-ghost', !active);
  }
}

function buildJourneyPresetIdempotencyKey(presetId) {
  const target = JOURNEY_PATH_PRESETS[resolveJourneyPresetId(presetId)];
  const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return `${target.idempotencyPrefix}_${datePart}`;
}

function applyJourneyPreset(presetId, { focus = true, enforceStarterMode = true } = {}) {
  const nextPresetId = resolveJourneyPresetId(presetId);
  const preset = JOURNEY_PATH_PRESETS[nextPresetId];
  state.journeyPresetId = nextPresetId;
  state.journeySetupConfirmed = false;

  if (enforceStarterMode) {
    setUiMode('starter');
  }

  els.quickstartWorkspaceInput.value = preset.workspaceId;
  els.quickstartOwnerInput.value = preset.ownerId;
  if (els.effectiveEnvActorInput && !String(els.effectiveEnvActorInput.value || '').trim()) {
    els.effectiveEnvActorInput.value = preset.ownerId;
  }
  els.quickstartTemplateSelect.value = preset.templateId;
  els.quickstartModeSelect.value = nextPresetId === 'startup' ? 'organization' : 'opc';
  els.quickstartConnectorIdsInput.value = preset.connectorIds.join(', ');
  els.quickstartIdemInput.value = buildJourneyPresetIdempotencyKey(nextPresetId);

  state.quickstartResult = null;
  els.quickstartMeta.textContent = `${preset.label} selected. Confirm Step 1 inputs, then continue to Step 2.`;
  updateJourneyState();
  scheduleStarterBridgeProfileRefresh({ immediate: true });
  scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
  scheduleWorkspaceContextRefresh({ immediate: true });
  setJourneyPresetUi();
  if (focus) {
    focusQuickstartSetup();
  }
  logAction('journey:preset:selected', {
    preset_id: nextPresetId,
    workspace_id: preset.workspaceId,
    owner_id: preset.ownerId,
    template_id: preset.templateId
  });
}

function quickstartSetupSnapshot() {
  const workspaceId = String(els.quickstartWorkspaceInput.value || '').trim();
  const workspacePath = String(els.quickstartWorkspacePathInput?.value || '').trim();
  const ownerId = String(els.quickstartOwnerInput.value || '').trim();
  const templateId = selectedQuickstartTemplateId();
  const mode = currentQuickstartMode();
  const errors = [];

  if (!workspaceId) {
    errors.push('Workspace ID is required.');
  } else if (!QUICKSTART_WORKSPACE_ID_PATTERN.test(workspaceId)) {
    errors.push('Use format: wsp_team_alpha (must start with "wsp_").');
  }

  if (!ownerId) {
    errors.push('Owner ID is required.');
  } else if (!QUICKSTART_OWNER_ID_PATTERN.test(ownerId)) {
    errors.push('Use format: usr_alice_ops (must start with "usr_").');
  }

  if (!templateId) {
    errors.push('Template is required.');
  }

  return {
    workspaceId,
    workspacePath,
    ownerId,
    templateId,
    mode,
    errors,
    ready: errors.length === 0
  };
}

function quickstartSetupReady() {
  return quickstartSetupSnapshot().ready;
}

function renderQuickstartGuideMeta(snapshot = quickstartSetupSnapshot()) {
  if (!els.quickstartGuideMeta) return;

  if (snapshot.errors.length) {
    els.quickstartGuideMeta.textContent = `Before Step 2: ${snapshot.errors[0]}`;
    els.quickstartGuideMeta.style.color = '#d92d20';
    return;
  }

  const template = ONE_PERSON_QUICKSTART_TEMPLATES[snapshot.templateId];
  const modeText = snapshot.mode === 'organization'
    ? 'Organization mode enables role-based access and audit.'
    : 'OPC mode is optimized for a single operator.';
  const workspacePathText = snapshot.workspacePath
    ? ` Workspace folder is set: ${snapshot.workspacePath}.`
    : ' Workspace folder is optional; add it only for Claude/Codex local file operations.';
  els.quickstartGuideMeta.textContent =
    `Ready for Step 2. Workspace ${snapshot.workspaceId}. Owner ${snapshot.ownerId}. ` +
    `Mode ${snapshot.mode.toUpperCase()}. Template ${template?.label || snapshot.templateId}. ` +
    `${modeText} ${workspacePathText}`;
  els.quickstartGuideMeta.style.color = '#1d9a6c';
}

function toShellArg(rawValue = '') {
  const value = String(rawValue ?? '');
  if (!value) return "''";
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function buildStarterBridgeProfilePath(snapshot = quickstartSetupSnapshot()) {
  const workspaceId = QUICKSTART_WORKSPACE_ID_PATTERN.test(snapshot.workspaceId)
    ? snapshot.workspaceId
    : 'wsp_mindverse_cn';
  const params = new URLSearchParams({
    workspace_id: workspaceId
  });
  if (snapshot.workspacePath) {
    params.set('workspace_path', snapshot.workspacePath);
  }
  if (QUICKSTART_OWNER_ID_PATTERN.test(snapshot.ownerId)) {
    params.set('actor_id', snapshot.ownerId);
  }
  return `/v0/integrations/agent-ide-profile?${params.toString()}`;
}

function buildStarterBridgeCommandFromProfile(profile = null) {
  const bridge = profile?.mcp_bridge || {};
  const command = String(bridge.command || '').trim();
  const args = Array.isArray(bridge.args)
    ? bridge.args.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  const cwd = String(bridge.cwd || '').trim();
  const env = bridge.env && typeof bridge.env === 'object' ? bridge.env : {};
  const envEntries = Object.entries(env)
    .map(([key, value]) => [String(key || '').trim(), String(value || '')])
    .filter(([key]) => Boolean(key));

  if (!command) return '';

  const execLine = [toShellArg(command), ...args.map((item) => toShellArg(item))].join(' ');
  const envLine = envEntries.length
    ? `${envEntries.map(([key, value]) => `${key}=${toShellArg(value)}`).join(' \\\n')} \\\n${execLine}`
    : execLine;
  return cwd ? `cd ${toShellArg(cwd)}\n${envLine}` : envLine;
}

function buildStarterBridgeFallbackCommand(snapshot = quickstartSetupSnapshot()) {
  const lines = [
    `FLOCKMESH_WORKSPACE_ID=${toShellArg(snapshot.workspaceId || 'wsp_mindverse_cn')} \\`,
    ...(snapshot.workspacePath ? [`FLOCKMESH_WORKSPACE_PATH=${toShellArg(snapshot.workspacePath)} \\`] : []),
    `FLOCKMESH_ACTOR_ID=${toShellArg(snapshot.ownerId || currentUiActorId())} \\`,
    'npm run mcp:bridge'
  ];
  return lines.join('\n');
}

function setStarterBridgeMeta(text, color = '#5f6b7f') {
  if (!els.starterBridgeMeta) return;
  els.starterBridgeMeta.textContent = text;
  els.starterBridgeMeta.style.color = color;
}

function setStarterBridgeCommand(command = '', { disableCopy = false } = {}) {
  if (!els.starterBridgeCommand) return;
  const normalized = String(command || '').trim();
  els.starterBridgeCommand.textContent = normalized || 'No bridge command available yet.';
  if (els.starterBridgeCopyBtn) {
    els.starterBridgeCopyBtn.disabled = disableCopy || !normalized;
  }
}

function setStarterReadinessMeta(text, color = '#5f6b7f') {
  if (!els.starterReadinessMeta) return;
  els.starterReadinessMeta.textContent = text;
  els.starterReadinessMeta.style.color = color;
}

function setStarterReadinessTag(label, color = '#5f6b7f') {
  if (!els.starterReadinessTag) return;
  els.starterReadinessTag.textContent = label;
  els.starterReadinessTag.style.color = color;
}

function clearStarterReadinessView(message = 'No readiness payload.') {
  if (els.starterReadinessPayload) {
    els.starterReadinessPayload.textContent = message;
  }
  if (els.starterReadinessStageList) {
    els.starterReadinessStageList.innerHTML = '';
  }
  if (els.starterReadinessActionList) {
    els.starterReadinessActionList.innerHTML = '<p class="run-meta">No actions yet.</p>';
  }
  setStarterReadinessTag('idle');
  setStarterReadinessMeta('Run readiness check to see blockers.');
}

function readinessColorFromStatus(status = 'warn') {
  const normalized = String(status || '').trim().toLowerCase();
  if (normalized === 'pass') return '#1d9a6c';
  if (normalized === 'fail') return '#d92d20';
  return '#c17b23';
}

function renderStarterReadiness(payload = null) {
  if (!payload || typeof payload !== 'object') {
    clearStarterReadinessView('No readiness payload.');
    return;
  }

  state.starterReadiness = payload;
  if (els.starterReadinessPayload) {
    els.starterReadinessPayload.textContent = JSON.stringify(payload, null, 2);
  }

  const score = payload.score || {};
  const scoreStatus = String(score.status || 'warn').trim().toLowerCase();
  const grade = String(score.grade || 'unknown').replace(/_/g, ' ');
  setStarterReadinessTag(
    `${score.points ?? 0}/${score.max_points ?? 0} ${grade}`,
    readinessColorFromStatus(scoreStatus)
  );
  setStarterReadinessMeta(
    `Score ${score.percent ?? 0}% · pass ${score.summary?.pass ?? 0} · warn ${score.summary?.warn ?? 0} · fail ${score.summary?.fail ?? 0}.`,
    readinessColorFromStatus(scoreStatus)
  );

  if (els.starterReadinessStageList) {
    els.starterReadinessStageList.innerHTML = '';
    const stages = Array.isArray(payload.stages) ? payload.stages : [];
    for (const stage of stages) {
      const status = String(stage?.status || 'warn').trim().toLowerCase();
      const card = document.createElement('article');
      card.className = `readiness-stage-card status-${status}`;

      const title = document.createElement('h4');
      title.textContent = `${stage.title || stage.id || 'stage'} · ${status.toUpperCase()}`;

      const summary = document.createElement('p');
      summary.textContent = String(stage.summary || '');

      const detail = document.createElement('p');
      detail.textContent = `weight ${stage.weight ?? 0} · ${stage.required === false ? 'optional' : 'required'}`;

      card.append(title, summary, detail);
      els.starterReadinessStageList.append(card);
    }
  }

  if (els.starterReadinessActionList) {
    els.starterReadinessActionList.innerHTML = '';
    const actions = Array.isArray(payload.next_actions) ? payload.next_actions : [];
    if (!actions.length) {
      els.starterReadinessActionList.innerHTML = '<p class="run-meta">No actions. You can start the run.</p>';
    } else {
      for (const action of actions) {
        const item = document.createElement('article');
        item.className = 'readiness-action-item';

        const title = document.createElement('strong');
        title.textContent = action.title || action.action_id || 'action';

        const description = document.createElement('p');
        description.textContent = String(action.description || '');

        const cta = document.createElement('p');
        cta.textContent = action.cta ? `How to fix: ${action.cta}` : '';
        cta.style.fontFamily = "'IBM Plex Mono', monospace";

        item.append(title, description);
        if (action.cta) {
          item.append(cta);
        }
        els.starterReadinessActionList.append(item);
      }
    }
  }
}

function buildStarterReadinessPath({
  includeProbe = Boolean(els.starterReadinessProbeInput?.checked)
} = {}) {
  const snapshot = quickstartSetupSnapshot();
  if (!snapshot.workspaceId || !QUICKSTART_WORKSPACE_ID_PATTERN.test(snapshot.workspaceId)) {
    throw new Error('Workspace ID is required before readiness check.');
  }
  if (!snapshot.ownerId || !QUICKSTART_OWNER_ID_PATTERN.test(snapshot.ownerId)) {
    throw new Error('Owner ID is required before readiness check.');
  }

  const query = new URLSearchParams();
  query.set('workspace_id', snapshot.workspaceId);
  query.set('actor_id', snapshot.ownerId);
  query.set('mode', snapshot.mode);
  if (snapshot.workspacePath) {
    query.set('workspace_path', snapshot.workspacePath);
  }
  if (includeProbe) {
    query.set('include_probe', 'true');
  }
  return `/v0/workstation/readiness?${query.toString()}`;
}

async function loadStarterReadiness({
  includeProbe = Boolean(els.starterReadinessProbeInput?.checked),
  quiet = false
} = {}) {
  const snapshot = quickstartSetupSnapshot();
  if (!snapshot.workspaceId || !QUICKSTART_WORKSPACE_ID_PATTERN.test(snapshot.workspaceId) || !snapshot.ownerId || !QUICKSTART_OWNER_ID_PATTERN.test(snapshot.ownerId)) {
    state.starterReadiness = null;
    clearStarterReadinessView('No readiness payload.');
    if (!quiet) {
      setStarterReadinessMeta(
        'Fill valid Workspace ID and Owner ID in Step 1 before readiness check.',
        '#c17b23'
      );
    }
    return null;
  }

  const requestToken = ++starterReadinessRequestToken;
  if (!quiet) {
    setStarterReadinessMeta('Checking readiness...', '#c17b23');
  }

  try {
    const payload = await api(buildStarterReadinessPath({ includeProbe }));
    if (requestToken !== starterReadinessRequestToken) return null;
    renderStarterReadiness(payload);
    return payload;
  } catch (err) {
    if (requestToken !== starterReadinessRequestToken) return null;
    state.starterReadiness = null;
    if (els.starterReadinessPayload) {
      els.starterReadinessPayload.textContent = String(err);
    }
    if (els.starterReadinessStageList) {
      els.starterReadinessStageList.innerHTML = '';
    }
    if (els.starterReadinessActionList) {
      els.starterReadinessActionList.innerHTML = '<p class="run-meta">Readiness actions unavailable.</p>';
    }
    setStarterReadinessTag('error', '#d92d20');
    setStarterReadinessMeta(`Readiness check failed: ${String(err)}`, '#d92d20');
    return null;
  }
}

function scheduleStarterReadinessRefresh({ immediate = false, quiet = true } = {}) {
  if (starterReadinessRefreshTimer) {
    clearTimeout(starterReadinessRefreshTimer);
    starterReadinessRefreshTimer = null;
  }

  if (immediate) {
    void loadStarterReadiness({ quiet });
    return;
  }

  starterReadinessRefreshTimer = setTimeout(() => {
    void loadStarterReadiness({ quiet });
  }, 650);
}

function setFeishuStatusMeta(text, color = '#5f6b7f') {
  if (!els.feishuStatusMeta) return;
  els.feishuStatusMeta.textContent = text;
  els.feishuStatusMeta.style.color = color;
}

function formatFeishuStatusText(status = null) {
  if (!status || typeof status !== 'object') {
    return 'Feishu status unavailable.';
  }

  const mode = String(status.delivery_mode || 'stub');
  if (status.connected) {
    const masked = String(status.webhook_masked || '').trim();
    return `Feishu connected (${status.source || 'unknown'}) · mode ${mode}${masked ? ` · ${masked}` : ''}`;
  }
  return `Feishu not connected · mode ${mode} (stub). Add webhook for real delivery.`;
}

async function loadFeishuStatus() {
  try {
    const payload = await api('/v0/integrations/feishu/status');
    state.feishuStatus = payload;
    setFeishuStatusMeta(formatFeishuStatusText(payload), payload.connected ? '#1d9a6c' : '#c17b23');
  } catch (err) {
    setFeishuStatusMeta(`Failed to load Feishu status: ${String(err)}`, '#d92d20');
  }
}

async function saveFeishuWebhook() {
  const webhookUrl = String(els.feishuWebhookInput?.value || '').trim();
  if (!webhookUrl) {
    setFeishuStatusMeta('Enter a Feishu webhook URL before saving.', '#d92d20');
    return;
  }

  try {
    setFeishuStatusMeta('Saving Feishu webhook...', '#c17b23');
    const payload = await api('/v0/integrations/feishu/webhook', {
      method: 'POST',
      body: JSON.stringify({ webhook_url: webhookUrl })
    });
    state.feishuStatus = payload;
    setFeishuStatusMeta(formatFeishuStatusText(payload), '#1d9a6c');
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
  } catch (err) {
    setFeishuStatusMeta(`Failed to save webhook: ${String(err)}`, '#d92d20');
  }
}

async function clearFeishuWebhook() {
  try {
    setFeishuStatusMeta('Clearing Feishu webhook...', '#c17b23');
    const payload = await api('/v0/integrations/feishu/webhook', {
      method: 'POST',
      body: JSON.stringify({ clear: true })
    });
    state.feishuStatus = payload;
    if (els.feishuWebhookInput) {
      els.feishuWebhookInput.value = '';
    }
    setFeishuStatusMeta(formatFeishuStatusText(payload), '#c17b23');
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
  } catch (err) {
    setFeishuStatusMeta(`Failed to clear webhook: ${String(err)}`, '#d92d20');
  }
}

function resolveLatestConnectorEvent(events = []) {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const item = events[i];
    if (item?.name === 'connector.invoked' || item?.name === 'connector.invoke.failed') {
      return item;
    }
  }
  return null;
}

function resolveLatestActionExecutionEvent(events = []) {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const item = events[i];
    if (item?.name === 'action.executed' || item?.name === 'action.executed.deduped') {
      return item;
    }
  }
  return null;
}

function readDeliveryModeFromEvent(event = null) {
  if (!event || typeof event !== 'object') return '';
  return String(
    event?.payload?.output?.output?.delivery_mode
    || event?.payload?.output?.delivery_mode
    || event?.payload?.delivery_mode
    || ''
  ).trim();
}

async function refreshLatestExecutionEvidence() {
  if (!els.latestExecutionEvidence) return;
  if (!state.runs.length) {
    els.latestExecutionEvidence.textContent = 'No run evidence yet.';
    return;
  }

  const orderedRuns = [...state.runs].sort((a, b) => safeDateMs(b.started_at) - safeDateMs(a.started_at));
  const targetRun = orderedRuns[0];

  try {
    const eventsPayload = await api(`/v0/runs/${targetRun.id}/events?limit=80&offset=0`);
    const events = Array.isArray(eventsPayload?.items) ? eventsPayload.items : [];
    const latestConnectorEvent = resolveLatestConnectorEvent(events);
    const latestActionEvent = resolveLatestActionExecutionEvent(events);
    const deliveryMode = readDeliveryModeFromEvent(latestConnectorEvent || latestActionEvent) || 'unknown';
    const capability = String(
      latestConnectorEvent?.payload?.capability
      || latestActionEvent?.payload?.capability
      || 'unknown'
    );
    const connectorId = String(
      latestConnectorEvent?.payload?.connector_id
      || latestActionEvent?.payload?.connector_id
      || 'unknown'
    );

    const lines = [
      `run_id: ${targetRun.id}`,
      `run_status: ${targetRun.status}`,
      `workspace: ${targetRun.workspace_id}`,
      `latest_connector_event: ${latestConnectorEvent?.name || 'none'}`,
      `latest_action_event: ${latestActionEvent?.name || 'none'}`,
      `connector_id: ${connectorId}`,
      `capability: ${capability}`,
      `delivery_mode: ${deliveryMode}`
    ];
    if (latestConnectorEvent?.payload?.reason_code || latestActionEvent?.payload?.reason_code) {
      lines.push(`reason_code: ${latestConnectorEvent?.payload?.reason_code || latestActionEvent?.payload?.reason_code}`);
    }
    els.latestExecutionEvidence.textContent = lines.join('\n');
  } catch (err) {
    els.latestExecutionEvidence.textContent = `Failed to load execution evidence: ${String(err)}`;
  }
}

async function sendFeishuTestMessage() {
  try {
    setFeishuStatusMeta('Sending Feishu test message...', '#c17b23');
    const payload = await api('/v0/integrations/feishu/test-message', {
      method: 'POST',
      body: JSON.stringify({
        channel: 'flockmesh-onboarding',
        content: 'FlockMesh onboarding test message'
      })
    });
    state.feishuStatus = payload;
    const ok = payload?.adapter_result?.output?.ok !== false;
    const deliveryMode = String(payload?.adapter_result?.output?.delivery_mode || payload?.delivery_mode || 'unknown');
    setFeishuStatusMeta(
      ok
        ? `Feishu test finished. delivery ${deliveryMode}.`
        : `Feishu test returned non-ok. delivery ${deliveryMode}.`,
      ok ? '#1d9a6c' : '#c17b23'
    );
    await refreshLatestExecutionEvidence();
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
  } catch (err) {
    setFeishuStatusMeta(`Feishu test failed: ${String(err)}`, '#d92d20');
  }
}

async function refreshStarterBridgeProfile() {
  const snapshot = quickstartSetupSnapshot();

  if (!snapshot.ready) {
    state.starterBridgeProfile = null;
    setStarterBridgeCommand('Set valid Workspace ID and Owner ID in Step 1 to generate command.', { disableCopy: true });
    setStarterBridgeMeta(snapshot.errors[0] || 'Bridge command is generated from Step 1 inputs.', '#c17b23');
    return;
  }

  const requestToken = ++starterBridgeRequestToken;
  setStarterBridgeMeta('Preparing bridge command...', '#c17b23');

  try {
    const profile = await api(buildStarterBridgeProfilePath(snapshot));
    if (requestToken !== starterBridgeRequestToken) return;

    state.starterBridgeProfile = profile;
    const command = buildStarterBridgeCommandFromProfile(profile) || buildStarterBridgeFallbackCommand(snapshot);
    setStarterBridgeCommand(command);
    setStarterBridgeMeta(
      `Bridge ready for ${snapshot.workspaceId}. Run in a new terminal, then add this MCP server in Claude/Codex.`,
      '#1d9a6c'
    );
  } catch {
    if (requestToken !== starterBridgeRequestToken) return;

    state.starterBridgeProfile = null;
    setStarterBridgeCommand(buildStarterBridgeFallbackCommand(snapshot));
    setStarterBridgeMeta('Bridge profile API unavailable. Showing fallback command.', '#c17b23');
  }
}

function scheduleStarterBridgeProfileRefresh({ immediate = false } = {}) {
  if (starterBridgeRefreshTimer) {
    clearTimeout(starterBridgeRefreshTimer);
    starterBridgeRefreshTimer = null;
  }

  if (immediate) {
    void refreshStarterBridgeProfile();
    return;
  }

  starterBridgeRefreshTimer = setTimeout(() => {
    void refreshStarterBridgeProfile();
  }, 200);
}

function focusQuickstartSetup() {
  const snapshot = quickstartSetupSnapshot();
  els.quickstartSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (!snapshot.workspaceId || !QUICKSTART_WORKSPACE_ID_PATTERN.test(snapshot.workspaceId)) {
    els.quickstartWorkspaceInput.focus();
    return;
  }
  if (!snapshot.ownerId || !QUICKSTART_OWNER_ID_PATTERN.test(snapshot.ownerId)) {
    els.quickstartOwnerInput.focus();
    return;
  }
  els.journeyContinueToStartBtn.focus();
}

function updateJourneyState() {
  const setup = quickstartSetupSnapshot();
  const setupReady = setup.ready;
  const hasRuns = state.runs.length > 0;
  const pendingCount = state.pendingApprovals.length;

  if (!setupReady) {
    state.journeySetupConfirmed = false;
  }

  const activeStep = !state.journeySetupConfirmed ? 1 : (hasRuns ? 3 : 2);

  els.journeyTag.textContent = `step ${activeStep}/3`;
  els.journeySetupStatus.textContent = state.journeySetupConfirmed ? 'done' : (setupReady ? 'ready' : 'required');
  els.journeyRunStatus.textContent = hasRuns ? 'done' : (state.journeySetupConfirmed ? 'next' : 'blocked');
  els.journeyReviewStatus.textContent = hasRuns ? (pendingCount ? `${pendingCount} pending` : 'ready') : 'locked';

  els.journeyStepSetup.classList.toggle('mode-hidden', activeStep !== 1);
  els.journeyStepRun.classList.toggle('mode-hidden', activeStep !== 2);
  els.journeyStepReview.classList.toggle('mode-hidden', activeStep !== 3);
  els.journeyStepSetup.classList.toggle('is-active', activeStep === 1);
  els.journeyStepRun.classList.toggle('is-active', activeStep === 2);
  els.journeyStepReview.classList.toggle('is-active', activeStep === 3);
  els.journeyStepSetup.classList.toggle('is-complete', state.journeySetupConfirmed);
  els.journeyStepRun.classList.toggle('is-complete', hasRuns);
  els.journeyStepReview.classList.toggle('is-complete', hasRuns && pendingCount === 0);

  const isStarterMode = state.uiMode === 'starter';
  els.quickstartSection.classList.toggle('mode-hidden', !isStarterMode || activeStep !== 1);
  els.runLaunchSection.classList.toggle('mode-hidden', !isStarterMode || activeStep !== 2);
  els.runtimeFocusSection.classList.toggle('mode-hidden', !isStarterMode || activeStep !== 3);

  const workspaceId = setup.workspaceId || '-';
  const workspacePath = setup.workspacePath || '(not set)';
  const ownerId = setup.ownerId || '-';
  const template = ONE_PERSON_QUICKSTART_TEMPLATES[setup.templateId];
  const preset = selectedJourneyPreset();
  els.runLaunchSummary.textContent =
    `${preset.label} · ${setup.mode.toUpperCase()} · Workspace ${workspaceId} · Owner ${ownerId} · ` +
    `Template ${template?.label || setup.templateId} · Folder ${workspacePath}.`;
  els.runLaunchTag.textContent = setupReady ? 'ready' : 'fix step 1';
  renderQuickstartGuideMeta(setup);

  els.journeyContinueToStartBtn.disabled = !setupReady;
  els.journeyStartRunBtn.disabled = !state.journeySetupConfirmed || !setupReady;
  els.quickstartStartBtn.disabled = !state.journeySetupConfirmed || !setupReady;
  els.journeyBackToSetupBtn.disabled = !state.journeySetupConfirmed;
  els.journeyReviewBtn.disabled = !hasRuns;
  els.heroStartQuickstartBtn.disabled = !setupReady;
  setJourneyPresetUi();
}

function openRuntimeReview() {
  const preferred = state.pendingApprovals.length ? 'approvals' : 'runs';
  setRuntimeView(preferred);
  updateJourneyState();
  els.runtimeFocusSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function listWorkbenchGroups() {
  return Array.from(document.querySelectorAll('.workbench-group[data-workbench-section]'));
}

function setWorkbenchSection(section, { openSelected = true } = {}) {
  const nextSection = WORKBENCH_SECTION_SET.has(section) ? section : 'agent';
  state.workbenchSection = nextSection;

  const groups = listWorkbenchGroups();
  for (const group of groups) {
    const isTarget = group.dataset.workbenchSection === nextSection;
    group.classList.toggle('mode-hidden', !isTarget);
    group.setAttribute('aria-hidden', isTarget ? 'false' : 'true');
    if (isTarget && openSelected) group.open = true;
    if (!isTarget) group.open = false;
  }

  els.workbenchAgentTabBtn.classList.toggle('is-active', nextSection === 'agent');
  els.workbenchGovernanceTabBtn.classList.toggle('is-active', nextSection === 'governance');
  els.workbenchObservabilityTabBtn.classList.toggle('is-active', nextSection === 'observability');
  els.workbenchAgentTabBtn.classList.toggle('btn-secondary', nextSection === 'agent');
  els.workbenchAgentTabBtn.classList.toggle('btn-ghost', nextSection !== 'agent');
  els.workbenchGovernanceTabBtn.classList.toggle('btn-secondary', nextSection === 'governance');
  els.workbenchGovernanceTabBtn.classList.toggle('btn-ghost', nextSection !== 'governance');
  els.workbenchObservabilityTabBtn.classList.toggle('btn-secondary', nextSection === 'observability');
  els.workbenchObservabilityTabBtn.classList.toggle('btn-ghost', nextSection !== 'observability');
}

function openPrimaryWorkbenchGroup() {
  setWorkbenchSection('agent');
}

function setupWorkbenchDisclosure() {
  const groups = listWorkbenchGroups();
  if (!groups.length) return;

  for (const group of groups) {
    group.addEventListener('toggle', () => {
      if (!group.open) return;
      setWorkbenchSection(group.dataset.workbenchSection || 'agent', { openSelected: false });
    });
  }
}

const POLICY_PATCH_CAPABILITY_PATTERN = /^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)$/;
const POLICY_PATCH_DECISION_SET = new Set(['allow', 'deny', 'escalate']);

function setPolicyPatchTag(label, color = '#5f6b7f') {
  els.policyPatchTag.textContent = label;
  els.policyPatchTag.style.color = color;
}

function setPolicyRollbackTag(label, color = '#5f6b7f') {
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
        state.policyProfiles.length ? '#1d9a6c' : '#c17b23'
      );
      setPolicyRollbackTag(
        state.policyProfiles.length ? 'profiles-ready' : 'profiles-empty',
        state.policyProfiles.length ? '#1d9a6c' : '#c17b23'
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
    setPolicyPatchTag('error', '#d92d20');
    setPolicyRollbackTag('error', '#d92d20');
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
  setPolicyPatchTag('hash-conflict', '#c17b23');
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
    setPolicyPatchTag(mode === 'apply' ? 'applying' : 'simulating', '#1456f0');
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
      setPolicyPatchTag('applied', '#1d9a6c');
      els.policyPatchMeta.textContent = meta;
    } else {
      setPolicyPatchTag('dry-run', '#c17b23');
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
    setPolicyPatchTag('error', '#d92d20');
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
  setPolicyRollbackTag('hash-conflict', '#c17b23');
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

    setPolicyRollbackTag(mode === 'apply' ? 'applying' : 'simulating', '#1456f0');
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
      setPolicyRollbackTag('applied', '#1d9a6c');
      els.policyRollbackMeta.textContent = meta;
    } else {
      setPolicyRollbackTag('dry-run', '#c17b23');
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
    setPolicyRollbackTag('error', '#d92d20');
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
  els.blueprintTag.style.color = '#5f6b7f';
  els.blueprintMeta.textContent = message;
  els.blueprintPayload.textContent = message;
}

function setBlueprintTagFromWarnings(warnings = []) {
  const hasCritical = warnings.some((item) => item.severity === 'critical');
  const hasWarning = warnings.some((item) => item.severity === 'warning');

  if (hasCritical) {
    els.blueprintTag.textContent = 'critical';
    els.blueprintTag.style.color = '#d92d20';
    return;
  }

  if (hasWarning) {
    els.blueprintTag.textContent = 'warning';
    els.blueprintTag.style.color = '#c17b23';
    return;
  }

  els.blueprintTag.textContent = 'ready';
  els.blueprintTag.style.color = '#1d9a6c';
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
      els.blueprintTag.style.color = state.agentKits.length ? '#1d9a6c' : '#c17b23';
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
    owners: owners.length ? owners : [currentUiActorId()],
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
      els.blueprintTag.style.color = '#d92d20';
    } else if (payload.summary.status === 'warn') {
      els.blueprintTag.textContent = 'lint-warn';
      els.blueprintTag.style.color = '#c17b23';
    } else {
      els.blueprintTag.textContent = 'lint-pass';
      els.blueprintTag.style.color = '#1d9a6c';
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
      els.blueprintTag.style.color = '#d92d20';
    } else if (payload.summary.status_after_estimate === 'warn') {
      els.blueprintTag.textContent = 'remediation-warn';
      els.blueprintTag.style.color = '#c17b23';
    } else {
      els.blueprintTag.textContent = 'remediation-pass';
      els.blueprintTag.style.color = '#1d9a6c';
    }

    if (!state.policyProfiles.length) {
      await loadPolicyProfiles();
    }
    const adoptedPolicyCandidate = adoptPolicyPatchCandidateFromRemediation({
      remediation: payload,
      overwriteRules: false
    });
    if (adoptedPolicyCandidate) {
      setPolicyPatchTag('drafted', '#c17b23');
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
    els.attestationTag.style.color = '#c17b23';
  } else {
    els.attestationTag.textContent = 'verified';
    els.attestationTag.style.color = '#1d9a6c';
  }
}

function renderApprovalInbox() {
  els.approvalInbox.innerHTML = '';

  if (!state.pendingApprovals.length) {
    els.approvalInboxTag.textContent = 'clear';
    els.approvalInboxTag.style.color = '#1d9a6c';
    els.approvalInbox.innerHTML = '<p class="run-meta">No pending approvals.</p>';
    return;
  }

  els.approvalInboxTag.textContent = `${state.pendingApprovals.length} pending`;
  els.approvalInboxTag.style.color = '#c17b23';

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
    risk.style.color = item.risk_tier === 'R3' || item.risk_tier === 'R2' ? '#c17b23' : '#1d9a6c';

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

    const moreActions = document.createElement('details');
    moreActions.className = 'card-actions-disclosure';
    const moreSummary = document.createElement('summary');
    moreSummary.textContent = 'More Actions';
    const moreWrap = document.createElement('div');
    moreWrap.className = 'run-actions run-actions-secondary';
    moreWrap.append(rejectBtn, inspectBtn);
    moreActions.append(moreSummary, moreWrap);

    actions.append(approveBtn, moreActions);
    card.append(top, meta, progress, actions);
    els.approvalInbox.appendChild(card);
  }
}

function clearTimeline(message) {
  els.timelineTag.textContent = 'idle';
  els.timelineTag.style.color = '#5f6b7f';
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
  els.replayDriftTag.style.color = '#5f6b7f';
  els.replayDriftMeta.textContent = message;
  els.replayDriftPayload.textContent = message;
  state.replayDrift = null;
}

function clearPolicyTrace(message) {
  els.policyTraceTag.textContent = 'idle';
  els.policyTraceTag.style.color = '#5f6b7f';
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
    els.policyTraceTag.style.color = '#d92d20';
  } else if (summary.escalate > 0) {
    els.policyTraceTag.style.color = '#c17b23';
  } else {
    els.policyTraceTag.style.color = '#1d9a6c';
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
    els.timelineTag.style.color = '#1456f0';

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
    els.timelineTag.style.color = '#1d9a6c';
    els.timelineMeta.textContent = `${runId} · status ${run?.status || 'unknown'} · events ${eventCount} · audit ${auditCount}`;
  } catch (err) {
    els.timelineTag.textContent = 'error';
    els.timelineTag.style.color = '#d92d20';
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
      els.replayDriftTag.style.color = '#d92d20';
    } else {
      els.replayDriftTag.textContent = 'stable';
      els.replayDriftTag.style.color = '#1d9a6c';
    }
  } catch (err) {
    els.replayDriftTag.textContent = 'error';
    els.replayDriftTag.style.color = '#d92d20';
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
    els.healthTag.style.color = payload.ok ? '#1d9a6c' : '#d92d20';
    els.healthPayload.textContent = JSON.stringify(payload, null, 2);
  } catch (err) {
    els.healthTag.textContent = 'offline';
    els.healthTag.style.color = '#d92d20';
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
      els.connectorHealthTag.style.color = '#c17b23';
    } else {
      els.connectorHealthTag.textContent = `healthy ${health.healthy}`;
      els.connectorHealthTag.style.color = '#1d9a6c';
    }
  } catch (err) {
    els.connectorHealthTag.textContent = 'offline';
    els.connectorHealthTag.style.color = '#d92d20';
    els.connectorHealthPayload.textContent = String(err);
    els.connectorDriftPayload.textContent = String(err);
    els.attestationTag.textContent = 'offline';
    els.attestationTag.style.color = '#d92d20';
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
    const secondaryActions = [];

    const inspectBtn = document.createElement('button');
    inspectBtn.className = 'btn btn-secondary';
    inspectBtn.textContent = 'Inspect Timeline';
    inspectBtn.addEventListener('click', async () => {
      state.selectedRunId = run.id;
      refreshTimelineRunSelect();
      await refreshTimelineForSelectedRun();
    });
    actionsWrap.append(inspectBtn);

    if (run.status === 'waiting_approval') {
      const approveBtn = document.createElement('button');
      approveBtn.className = 'btn btn-secondary';
      approveBtn.textContent = 'Approve';
      approveBtn.addEventListener('click', () => resolveRunApproval(run, true));
      actionsWrap.append(approveBtn);

      const rejectBtn = document.createElement('button');
      rejectBtn.className = 'btn btn-danger';
      rejectBtn.textContent = 'Reject';
      rejectBtn.addEventListener('click', () => resolveRunApproval(run, false));
      secondaryActions.push(rejectBtn);
    }

    if (['accepted', 'running', 'waiting_approval'].includes(run.status)) {
      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn btn-danger';
      cancelBtn.textContent = 'Cancel Run';
      cancelBtn.addEventListener('click', () => resolveRunCancel(run));
      secondaryActions.push(cancelBtn);
    }

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
    secondaryActions.push(auditBtn);

    if (secondaryActions.length) {
      const moreActions = document.createElement('details');
      moreActions.className = 'card-actions-disclosure';
      const moreSummary = document.createElement('summary');
      moreSummary.textContent = 'More Actions';
      const moreWrap = document.createElement('div');
      moreWrap.className = 'run-actions run-actions-secondary';
      moreWrap.append(...secondaryActions);
      moreActions.append(moreSummary, moreWrap);
      actionsWrap.append(moreActions);
    }
    els.runFeed.appendChild(node);
  }

  if (!state.runs.length) {
    els.runFeed.innerHTML = '<p class="run-meta">No runs yet. Start with Quickstart, or use Bootstrap Demo Run in Workbench.</p>';
  }
}

function refreshRuntimeViews() {
  refreshStats();
  renderRunFeed();
  renderApprovalInbox();
  setRuntimeView(state.runtimeView);
  updateJourneyState();
  refreshTimelineRunSelect();
  void refreshLatestExecutionEvidence();
}

async function startOnePersonQuickstart() {
  try {
    setQuickstartTag('starting', '#c17b23');
    const setup = quickstartSetupSnapshot();
    const templateId = setup.templateId;
    const idempotencyKey = String(els.quickstartIdemInput.value || '').trim();
    if (setup.workspacePath) {
      window.localStorage.setItem(WORKSPACE_PATH_STORAGE_KEY, setup.workspacePath);
    } else {
      window.localStorage.removeItem(WORKSPACE_PATH_STORAGE_KEY);
    }

    const payload = await api('/v0/quickstart/one-person', {
      method: 'POST',
      body: JSON.stringify({
        workspace_id: setup.workspaceId || 'wsp_mindverse_cn',
        ...(setup.workspacePath ? { workspace_path: setup.workspacePath } : {}),
        owner_id: setup.ownerId || currentUiActorId(),
        template_id: templateId,
        connector_ids: effectiveQuickstartConnectorIds(),
        ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {})
      })
    });

    state.quickstartResult = payload;
    els.quickstartPayload.textContent = JSON.stringify(payload, null, 2);
    els.quickstartMeta.textContent =
      `Run ${payload.run.id} ${payload.reused ? 'reused' : 'started'} (status: ${payload.run.status}). ` +
      `Agent ${payload.created_agent.id}. Next: review Step 3 approvals and sessions.`;
    setQuickstartTag(payload.reused ? 'reused' : 'started', '#1d9a6c');

    state.selectedRunId = payload.run.id;
    await Promise.all([
      syncState(),
      loadConnectorGovernance()
    ]);
    await loadFeishuStatus();
    await Promise.all([
      loadEnvironmentSets(),
      loadAccessPermissions(),
      loadRoleBindings(),
      loadSessions()
    ]);
    await loadEffectiveEnvironment();
    await loadStarterReadiness({ quiet: true });
    if (state.sessions.length) {
      await loadSelectedSessionDetail();
    }
    refreshRuntimeViews();
    setUiMode('starter');
    openRuntimeReview();
    await refreshTimelineForSelectedRun();

    logAction(`quickstart:${templateId}`, {
      reused: payload.reused,
      agent_id: payload.created_agent.id,
      run_id: payload.run.id,
      run_status: payload.run.status
    });
  } catch (err) {
    setQuickstartTag('error', '#d92d20');
    els.quickstartMeta.textContent = `Start run failed: ${String(err)}`;
    els.quickstartPayload.textContent = String(err);
    logAction('quickstart:error', String(err));
  }
}

async function createAgent() {
  const actorId = currentUiActorId();
  const workspaceId = currentWorkspaceId() || 'wsp_mindverse_cn';
  const payload = await api('/v0/agents', {
    method: 'POST',
    body: JSON.stringify({
      workspace_id: workspaceId,
      role: 'ops_assistant',
      owners: [actorId],
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
  const workspaceId = currentWorkspaceId() || 'wsp_mindverse_cn';
  const payload = await api('/v0/connectors/bindings', {
    method: 'POST',
    body: JSON.stringify({
      workspace_id: workspaceId,
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
  const actorId = currentUiActorId();
  const workspaceId = currentWorkspaceId() || 'wsp_mindverse_cn';
  const payload = await api('/v0/runs', {
    method: 'POST',
    body: JSON.stringify({
      workspace_id: workspaceId,
      agent_id: agentId,
      playbook_id: 'pbk_weekly_ops_sync',
      trigger: {
        type: 'manual',
        source: DEMO_BOOTSTRAP_PRESET.trigger_source,
        actor_id: actorId,
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
    const actorId = currentUiActorId();
    const result = await api(`/v0/runs/${run.id}/approvals`, {
      method: 'POST',
      body: JSON.stringify({
        action_intent_id: targetActionIntentId,
        approved,
        approved_by: actorId,
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
    const actorId = currentUiActorId();
    const result = await api(`/v0/runs/${run.id}/cancel`, {
      method: 'POST',
      body: JSON.stringify({
        cancelled_by: actorId,
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
els.heroStartupPathBtn.addEventListener('click', () => {
  applyJourneyPreset('startup');
});
els.heroOpcPathBtn.addEventListener('click', () => {
  applyJourneyPreset('opc');
});
els.heroStartQuickstartBtn.addEventListener('click', async () => {
  if (!quickstartSetupReady()) {
    focusQuickstartSetup();
    return;
  }
  if (!state.journeySetupConfirmed) {
    state.journeySetupConfirmed = true;
    updateJourneyState();
    els.runLaunchSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    els.quickstartStartBtn.focus();
    return;
  }
  await startOnePersonQuickstart();
});
els.journeyGoSetupBtn.addEventListener('click', () => {
  state.journeySetupConfirmed = false;
  updateJourneyState();
  focusQuickstartSetup();
});
els.journeyContinueToStartBtn.addEventListener('click', () => {
  if (!quickstartSetupReady()) {
    focusQuickstartSetup();
    return;
  }
  state.journeySetupConfirmed = true;
  updateJourneyState();
  els.runLaunchSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  els.quickstartStartBtn.focus();
});
els.journeyStartRunBtn.addEventListener('click', () => {
  els.runLaunchSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  els.quickstartStartBtn.focus();
});
els.journeyBackToSetupBtn.addEventListener('click', () => {
  state.journeySetupConfirmed = false;
  updateJourneyState();
  focusQuickstartSetup();
});
els.journeyReviewBtn.addEventListener('click', () => {
  openRuntimeReview();
});
els.quickstartStartBtn.addEventListener('click', async () => {
  await startOnePersonQuickstart();
});
els.starterBridgeCopyBtn.addEventListener('click', async () => {
  const command = String(els.starterBridgeCommand.textContent || '').trim();
  if (!command) return;

  try {
    const copied = await copyTextToClipboard(command);
    setStarterBridgeMeta(copied ? 'Command copied. Paste it in a new terminal.' : 'Clipboard unavailable. Copy command manually.', copied ? '#1d9a6c' : '#c17b23');
  } catch {
    setStarterBridgeMeta('Clipboard unavailable. Copy command manually.', '#c17b23');
  }
});
els.starterBridgeProfileBtn.addEventListener('click', () => {
  const profilePath = buildStarterBridgeProfilePath(quickstartSetupSnapshot());
  window.open(profilePath, '_blank', 'noopener,noreferrer');
});
els.starterReadinessRefreshBtn.addEventListener('click', async () => {
  await loadStarterReadiness({
    includeProbe: Boolean(els.starterReadinessProbeInput?.checked),
    quiet: false
  });
});
els.starterReadinessProbeInput.addEventListener('change', () => {
  if (els.starterReadinessProbeInput?.checked) {
    setStarterReadinessMeta('Connectivity probe enabled. Refresh readiness to run outbound checks.', '#c17b23');
  } else {
    setStarterReadinessMeta('Connectivity probe disabled. Refresh readiness for syntax-only checks.', '#5f6b7f');
  }
});
els.feishuWebhookSaveBtn.addEventListener('click', async () => {
  await saveFeishuWebhook();
});
els.feishuWebhookClearBtn.addEventListener('click', async () => {
  await clearFeishuWebhook();
});
els.feishuWebhookTestBtn.addEventListener('click', async () => {
  await sendFeishuTestMessage();
});
els.envSetCreateBtn.addEventListener('click', async () => {
  await createEnvironmentSet();
});
els.envSetCreateApplyBtn.addEventListener('click', async () => {
  await createActivateApplyEnvironmentSet();
});
els.envSetRefreshBtn.addEventListener('click', async () => {
  await loadEnvironmentSets();
});
els.envSetVerifyBtn.addEventListener('click', async () => {
  await verifySelectedEnvironmentSet();
});
els.envSetVerifyModeSelect.addEventListener('change', () => {
  const mode = String(els.envSetVerifyModeSelect.value || 'syntax').trim();
  if (mode === 'connectivity') {
    setEnvironmentMeta('Verify mode connectivity will probe external endpoints.', '#c17b23');
  } else {
    setEnvironmentMeta('Verify mode syntax checks key format without outbound probe.', '#5f6b7f');
  }
});
els.envSetVerifyTimeoutInput.addEventListener('change', () => {
  const raw = Number(els.envSetVerifyTimeoutInput.value || 4000);
  const next = Number.isFinite(raw) ? Math.min(Math.max(Math.round(raw), 500), 10000) : 4000;
  els.envSetVerifyTimeoutInput.value = String(next);
});
els.envSetActivateBtn.addEventListener('click', async () => {
  await activateSelectedEnvironmentSet();
});
els.envSetApplyRuntimeBtn.addEventListener('click', async () => {
  await applySelectedEnvironmentSetRuntime();
});
els.envSetSelect.addEventListener('change', () => {
  state.selectedEnvironmentSetId = String(els.envSetSelect.value || '').trim();
  state.environmentVerification = null;
  renderEnvironmentVerificationSummary(null);
  const selected = state.environmentSets.find((item) => item.id === state.selectedEnvironmentSetId);
  if (selected) {
    els.envSetPayload.textContent = JSON.stringify(selected, null, 2);
  }
});
els.accessPermissionsRefreshBtn.addEventListener('click', async () => {
  await loadAccessPermissions();
});
els.roleBindingGrantBtn.addEventListener('click', async () => {
  await grantRoleBinding();
});
els.roleBindingRefreshBtn.addEventListener('click', async () => {
  await Promise.all([
    loadRoleBindings(),
    loadAccessPermissions(),
    loadEffectiveEnvironment()
  ]);
});
els.effectiveEnvLoadBtn.addEventListener('click', async () => {
  await loadEffectiveEnvironment();
});
els.effectiveEnvActorInput.addEventListener('change', async () => {
  await loadEffectiveEnvironment();
});
els.effectiveEnvModeSelect.addEventListener('change', async () => {
  await loadEffectiveEnvironment();
});
els.effectiveEnvIncludeValuesInput.addEventListener('change', async () => {
  await loadEffectiveEnvironment();
});
els.sessionRefreshBtn.addEventListener('click', async () => {
  await loadSessions();
});
els.sessionFilterActorInput.addEventListener('change', async () => {
  await loadSessions();
});
els.sessionFilterStatusSelect.addEventListener('change', async () => {
  await loadSessions();
});
els.sessionSelect.addEventListener('change', () => {
  state.selectedSessionId = String(els.sessionSelect.value || '').trim();
  renderSessionList();
});
els.sessionLoadDetailBtn.addEventListener('click', async () => {
  await loadSelectedSessionDetail();
});
els.openApprovalInboxBtn.addEventListener('click', () => {
  setUiMode('starter');
  state.journeySetupConfirmed = true;
  setRuntimeView('approvals');
  openRuntimeReview();
});
els.runtimeOpenWorkbenchBtn.addEventListener('click', () => {
  setUiMode('advanced');
  openPrimaryWorkbenchGroup();
  document.getElementById('advancedWorkbenchPanel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
});
els.quickstartWorkspaceInput.addEventListener('input', () => {
  updateJourneyState();
  scheduleStarterBridgeProfileRefresh();
  scheduleStarterReadinessRefresh();
  scheduleWorkspaceContextRefresh();
});
els.quickstartWorkspacePathInput.addEventListener('input', () => {
  const value = String(els.quickstartWorkspacePathInput.value || '').trim();
  if (value) {
    window.localStorage.setItem(WORKSPACE_PATH_STORAGE_KEY, value);
  } else {
    window.localStorage.removeItem(WORKSPACE_PATH_STORAGE_KEY);
  }
  updateJourneyState();
  scheduleStarterBridgeProfileRefresh();
  scheduleStarterReadinessRefresh();
});
els.quickstartWorkspacePathDefaultBtn.addEventListener('click', async () => {
  try {
    const profile = await api(buildStarterBridgeProfilePath(quickstartSetupSnapshot()));
    const cwd = String(profile?.mcp_bridge?.cwd || '').trim();
    if (!cwd) {
      setStarterBridgeMeta('Runtime root is unavailable from profile response.', '#c17b23');
      return;
    }
    els.quickstartWorkspacePathInput.value = cwd;
    window.localStorage.setItem(WORKSPACE_PATH_STORAGE_KEY, cwd);
    updateJourneyState();
    scheduleStarterBridgeProfileRefresh({ immediate: true });
    scheduleStarterReadinessRefresh({ immediate: true, quiet: true });
    setStarterBridgeMeta(`Workspace folder set to runtime root: ${cwd}`, '#1d9a6c');
  } catch (err) {
    setStarterBridgeMeta(`Failed to load runtime root: ${String(err)}`, '#d92d20');
  }
});
els.quickstartOwnerInput.addEventListener('input', () => {
  if (els.effectiveEnvActorInput && !String(els.effectiveEnvActorInput.value || '').trim()) {
    els.effectiveEnvActorInput.value = String(els.quickstartOwnerInput.value || '').trim();
  }
  updateJourneyState();
  scheduleStarterBridgeProfileRefresh();
  scheduleStarterReadinessRefresh();
  scheduleWorkspaceContextRefresh();
});
els.quickstartModeSelect.addEventListener('change', () => {
  updateJourneyState();
  scheduleStarterReadinessRefresh();
  scheduleWorkspaceContextRefresh();
});
els.quickstartTemplateSelect.addEventListener('change', () => {
  if (!parseCsvUnique(els.quickstartConnectorIdsInput.value).length) {
    const defaults = quickstartTemplateDefaultConnectorIds(selectedQuickstartTemplateId());
    els.quickstartConnectorIdsInput.value = defaults.join(', ');
  }
  if (!state.quickstartResult) {
    const templateId = selectedQuickstartTemplateId();
    const template = ONE_PERSON_QUICKSTART_TEMPLATES[templateId];
    els.quickstartMeta.textContent = `Template ${template?.label || templateId} selected. Continue to Step 2 when ready.`;
  }
  updateJourneyState();
  scheduleStarterReadinessRefresh();
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
    setPolicyPatchTag('version-ready', '#1d9a6c');
    logAction('policy:patch:version:refresh', {
      profile_name: selectedPolicyProfileName(),
      document_hash: els.policyPatchHashInput.value
    });
  } catch (err) {
    setPolicyPatchTag('error', '#d92d20');
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

    setPolicyPatchTag('drafted', '#c17b23');
    els.policyPatchMeta.textContent = `Drafted ${candidate.patch_rules.length} rules from ${candidate.candidate_id} -> ${candidate.target_profile}`;
    logAction('policy:patch:draft-from-remediation', {
      candidate_id: candidate.candidate_id,
      target_profile: candidate.target_profile,
      patch_rules: candidate.patch_rules.length
    });
  } catch (err) {
    setPolicyPatchTag('error', '#d92d20');
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
    setPolicyRollbackTag('history-ready', '#1d9a6c');
    logAction('policy:rollback:history:refresh', {
      profile_name: selectedPolicyRollbackProfileName(),
      history_entries: state.policyRollbackHistory.length
    });
  } catch (err) {
    setPolicyRollbackTag('error', '#d92d20');
    els.policyRollbackMeta.textContent = String(err);
    logAction('policy:rollback:history:error', String(err));
  }
});
els.policyRollbackVersionBtn.addEventListener('click', async () => {
  try {
    await refreshSelectedPolicyRollbackProfileVersion({ updateMeta: true });
    setPolicyRollbackTag('version-ready', '#1d9a6c');
    logAction('policy:rollback:version:refresh', {
      profile_name: selectedPolicyRollbackProfileName(),
      document_hash: els.policyRollbackHashInput.value
    });
  } catch (err) {
    setPolicyRollbackTag('error', '#d92d20');
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
    setPolicyRollbackTag('drafted', '#c17b23');
    els.policyRollbackMeta.textContent = `Drafted rollback target ${latest.patch_id} (before).`;
    logAction('policy:rollback:draft-latest', {
      profile_name: selectedPolicyRollbackProfileName(),
      target_patch_id: latest.patch_id,
      target_state: 'before'
    });
  } catch (err) {
    setPolicyRollbackTag('error', '#d92d20');
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
      loadFeishuStatus(),
      loadEnvironmentSets(),
      loadAccessPermissions(),
      loadRoleBindings(),
      loadEffectiveEnvironment(),
      loadSessions(),
      loadStarterReadiness({ quiet: true }),
      loadReplayDriftSummary(),
      loadAgentKits(),
      loadPolicyProfiles()
    ]);
    if (state.sessions.length) {
      await loadSelectedSessionDetail();
    }
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
  openPrimaryWorkbenchGroup();
});
els.advancedToolsOpenBtn.addEventListener('click', () => {
  setUiMode('advanced');
  openPrimaryWorkbenchGroup();
});
els.runtimeViewApprovalsBtn.addEventListener('click', () => {
  setRuntimeView('approvals');
});
els.runtimeViewRunsBtn.addEventListener('click', () => {
  setRuntimeView('runs');
});
els.workbenchAgentTabBtn.addEventListener('click', () => {
  setWorkbenchSection('agent');
});
els.workbenchGovernanceTabBtn.addEventListener('click', () => {
  setWorkbenchSection('governance');
});
els.workbenchObservabilityTabBtn.addEventListener('click', () => {
  setWorkbenchSection('observability');
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
  renderEnvironmentProviderCards();
  syncAccessDrivenControls();
  setupWorkbenchDisclosure();
  setRuntimeView('approvals');
  setWorkbenchSection('agent');
  setUiMode(readInitialUiMode(), { persist: false });
  if (state.uiMode === 'advanced') {
    openPrimaryWorkbenchGroup();
  }
  applyJourneyPreset(state.journeyPresetId, { focus: false, enforceStarterMode: false });
  const initialWorkspacePath = readInitialWorkspacePath();
  if (initialWorkspacePath) {
    els.quickstartWorkspacePathInput.value = initialWorkspacePath;
  }
  setCompactMode(readInitialCompactMode(), { persist: false });
  updateJourneyState();
  scheduleStarterBridgeProfileRefresh({ immediate: true });
  await Promise.all([
    loadHealth(),
    syncState(),
    loadConnectorGovernance(),
    loadFeishuStatus(),
    loadEnvironmentSets(),
    loadAccessPermissions(),
    loadRoleBindings(),
    loadEffectiveEnvironment(),
    loadSessions(),
    loadStarterReadiness({ quiet: true }),
    loadReplayDriftSummary(),
    loadAgentKits(),
    loadPolicyProfiles()
  ]);
  if (state.sessions.length) {
    await loadSelectedSessionDetail();
  }
  refreshRuntimeViews();
  await refreshTimelineForSelectedRun();
} catch (err) {
  logAction('init:error', String(err));
}

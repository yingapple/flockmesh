import { makeId } from './ids.js';
import { nowIso } from './time.js';

const DECISION_WEIGHT = {
  allow: 1,
  escalate: 2,
  deny: 3
};

const SOURCE_ORDER = ['org', 'workspace', 'agent', 'run_override'];

const RISK_DEFAULTS = {
  R0: { decision: 'allow', requiredApprovals: 0, reason: 'risk.r0.read_only' },
  R1: { decision: 'allow', requiredApprovals: 0, reason: 'risk.r1.low_impact' },
  R2: { decision: 'escalate', requiredApprovals: 1, reason: 'risk.r2.requires_approval' },
  R3: { decision: 'escalate', requiredApprovals: 2, reason: 'risk.r3.dual_approval' }
};

export const POLICY_LIBRARY = {
  org_default_safe: {
    name: 'org_default_safe',
    rules: {
      'message.send': { decision: 'escalate', requiredApprovals: 1 },
      'payment.execute': { decision: 'deny' }
    }
  },
  workspace_ops_cn: {
    name: 'workspace_ops_cn',
    rules: {
      'message.send': { decision: 'escalate', requiredApprovals: 1 },
      'doc.write': { decision: 'allow' }
    }
  },
  agent_ops_assistant: {
    name: 'agent_ops_assistant',
    rules: {
      'calendar.read': { decision: 'allow' },
      'jira.read': { decision: 'allow' }
    }
  }
};

function strictestDecision(...decisions) {
  return decisions.reduce((winner, current) => {
    if (!winner) return current;
    if (DECISION_WEIGHT[current] > DECISION_WEIGHT[winner]) return current;
    return winner;
  }, null);
}

function sourceRank(source) {
  const idx = SOURCE_ORDER.indexOf(source);
  return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
}

function pickEffectiveSource(candidates) {
  const valid = candidates.filter(Boolean);
  if (!valid.length) return 'agent';

  valid.sort((a, b) => {
    const weightA = DECISION_WEIGHT[a.decision] ?? 0;
    const weightB = DECISION_WEIGHT[b.decision] ?? 0;
    if (weightA !== weightB) return weightB - weightA;
    return sourceRank(a.source) - sourceRank(b.source);
  });

  return valid[0].source;
}

function policyRuleDecision(profile, capability) {
  if (!profile) return null;
  const rule = profile.rules[capability] || profile.rules['*'];
  if (!rule) return null;
  return {
    decision: rule.decision,
    requiredApprovals: rule.requiredApprovals ?? 0
  };
}

function failClosedDecision({ runId, actionIntentId, reasonCode, source = 'org' }) {
  return {
    id: makeId('pol'),
    run_id: runId,
    action_intent_id: actionIntentId,
    decision: 'deny',
    risk_tier: 'R3',
    reason_codes: [reasonCode, 'safety.fail_closed'],
    required_approvals: 0,
    policy_trace: {
      org_policy: 'unknown',
      workspace_policy: 'unknown',
      agent_policy: 'unknown',
      run_override: '',
      effective_source: source
    },
    evaluated_at: nowIso()
  };
}

export function evaluatePolicy({
  runId,
  actionIntent,
  policyContext = {},
  policyLibrary = POLICY_LIBRARY
}) {
  if (!actionIntent?.id || !actionIntent?.capability || !actionIntent?.risk_hint) {
    return failClosedDecision({
      runId,
      actionIntentId: actionIntent?.id || 'act_unknown',
      reasonCode: 'policy.invalid_intent',
      source: 'org'
    });
  }

  const riskBaseline = RISK_DEFAULTS[actionIntent.risk_hint];
  if (!riskBaseline) {
    return failClosedDecision({
      runId,
      actionIntentId: actionIntent.id,
      reasonCode: 'policy.unknown_risk_tier',
      source: 'org'
    });
  }

  if (actionIntent.side_effect === 'mutation' && !actionIntent.idempotency_key) {
    return failClosedDecision({
      runId,
      actionIntentId: actionIntent.id,
      reasonCode: 'policy.idempotency_required',
      source: 'org'
    });
  }

  const trace = {
    org_policy: policyContext.org_policy || 'org_default_safe',
    workspace_policy: policyContext.workspace_policy || 'workspace_ops_cn',
    agent_policy: policyContext.agent_policy || 'agent_ops_assistant',
    run_override: policyContext.run_override || ''
  };

  const profiles = {
    org: policyLibrary[trace.org_policy],
    workspace: policyLibrary[trace.workspace_policy],
    agent: policyLibrary[trace.agent_policy],
    run_override: trace.run_override ? policyLibrary[trace.run_override] : null
  };

  for (const source of ['org', 'workspace', 'agent']) {
    if (!profiles[source]) {
      return failClosedDecision({
        runId,
        actionIntentId: actionIntent.id,
        reasonCode: `policy.profile_missing.${source}`,
        source
      });
    }
  }

  if (trace.run_override && !profiles.run_override) {
    return failClosedDecision({
      runId,
      actionIntentId: actionIntent.id,
      reasonCode: 'policy.profile_missing.run_override',
      source: 'run_override'
    });
  }

  const baseline = {
    source: 'agent',
    decision: riskBaseline.decision,
    requiredApprovals: riskBaseline.requiredApprovals,
    reason: riskBaseline.reason
  };

  const evaluations = [
    baseline,
    ...Object.entries(profiles)
      .map(([source, profile]) => {
        const result = policyRuleDecision(profile, actionIntent.capability);
        if (!result) return null;
        return {
          source,
          decision: result.decision,
          requiredApprovals: result.requiredApprovals,
          reason: `policy.rule.${source}`
        };
      })
      .filter(Boolean)
  ];

  const strictDecision = strictestDecision(...evaluations.map((item) => item.decision));
  const effectiveSource = pickEffectiveSource(
    evaluations.filter((item) => item.decision === strictDecision)
  );

  const requiredApprovals = Math.max(
    ...evaluations
      .filter((item) => item.decision === strictDecision)
      .map((item) => item.requiredApprovals || 0),
    0
  );

  const reasonCodes = new Set([
    baseline.reason,
    ...evaluations.map((item) => item.reason)
  ]);

  return {
    id: makeId('pol'),
    run_id: runId,
    action_intent_id: actionIntent.id,
    decision: strictDecision,
    risk_tier: actionIntent.risk_hint,
    reason_codes: Array.from(reasonCodes),
    required_approvals: strictDecision === 'escalate' ? Math.max(1, requiredApprovals) : 0,
    policy_trace: {
      ...trace,
      effective_source: effectiveSource
    },
    evaluated_at: nowIso()
  };
}

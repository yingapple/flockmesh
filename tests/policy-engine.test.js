import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluatePolicy } from '../src/lib/policy-engine.js';

test('policy escalates message.send in R2', () => {
  const decision = evaluatePolicy({
    runId: 'run_test_123456',
    actionIntent: {
      id: 'act_test_123456',
      run_id: 'run_test_123456',
      step_id: 'send_summary',
      capability: 'message.send',
      side_effect: 'mutation',
      idempotency_key: 'run_test_123456_send_summary_v1',
      risk_hint: 'R2',
      parameters: {}
    },
    policyContext: {
      org_policy: 'org_default_safe',
      workspace_policy: 'workspace_ops_cn',
      agent_policy: 'agent_ops_assistant'
    }
  });

  assert.equal(decision.decision, 'escalate');
  assert.equal(decision.required_approvals, 1);
  assert.equal(decision.risk_tier, 'R2');
});

test('policy fails closed when mutation idempotency key is missing', () => {
  const decision = evaluatePolicy({
    runId: 'run_test_abcdef',
    actionIntent: {
      id: 'act_test_abcdef',
      run_id: 'run_test_abcdef',
      step_id: 'send_summary',
      capability: 'message.send',
      side_effect: 'mutation',
      risk_hint: 'R2',
      parameters: {}
    },
    policyContext: {
      org_policy: 'org_default_safe',
      workspace_policy: 'workspace_ops_cn',
      agent_policy: 'agent_ops_assistant'
    }
  });

  assert.equal(decision.decision, 'deny');
  assert.ok(decision.reason_codes.includes('policy.idempotency_required'));
  assert.ok(decision.reason_codes.includes('safety.fail_closed'));
});

test('policy fails closed on missing policy profile', () => {
  const decision = evaluatePolicy({
    runId: 'run_test_profile',
    actionIntent: {
      id: 'act_test_profile',
      run_id: 'run_test_profile',
      step_id: 'send_summary',
      capability: 'message.send',
      side_effect: 'mutation',
      idempotency_key: 'run_test_profile_send_summary_v1',
      risk_hint: 'R2',
      parameters: {}
    },
    policyContext: {
      org_policy: 'org_default_safe',
      workspace_policy: 'workspace_ops_cn',
      agent_policy: 'missing_profile'
    }
  });

  assert.equal(decision.decision, 'deny');
  assert.ok(decision.reason_codes.some((code) => code.includes('policy.profile_missing.agent')));
});

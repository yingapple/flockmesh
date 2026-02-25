import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildAdapterRetryDecision,
  classifyAdapterFailureReason,
  compileAdapterRetryPolicy,
  computeAdapterRetryDelayMs
} from '../src/lib/adapter-retry.js';

test('compileAdapterRetryPolicy normalizes policy', () => {
  const policy = compileAdapterRetryPolicy({
    version: 'v0',
    max_attempts: 3,
    base_delay_ms: 10,
    max_delay_ms: 100,
    jitter_ms: 5
  }, { source: 'inline-test' });

  assert.equal(policy.version, 'v0');
  assert.equal(policy.max_attempts, 3);
  assert.equal(policy.base_delay_ms, 10);
});

test('buildAdapterRetryDecision requires idempotency key for mutation retries', () => {
  const policy = compileAdapterRetryPolicy({
    version: 'v0',
    max_attempts: 3,
    base_delay_ms: 10,
    max_delay_ms: 100,
    jitter_ms: 0
  });

  const noKey = buildAdapterRetryDecision({
    attempt: 1,
    policy,
    sideEffect: 'mutation',
    idempotencyKey: '',
    errorReason: 'connector.invoke.timeout'
  });
  assert.equal(noKey.retry, false);
  assert.equal(noKey.reason_code, 'retry.idempotency_key_required_for_mutation');

  const withKey = buildAdapterRetryDecision({
    attempt: 1,
    policy,
    sideEffect: 'mutation',
    idempotencyKey: 'run_abc12345_mutation_once',
    errorReason: 'connector.invoke.timeout'
  });
  assert.equal(withKey.retry, true);
});

test('computeAdapterRetryDelayMs applies bounded exponential backoff', () => {
  const policy = compileAdapterRetryPolicy({
    version: 'v0',
    max_attempts: 4,
    base_delay_ms: 10,
    max_delay_ms: 25,
    jitter_ms: 0
  });

  const firstDelay = computeAdapterRetryDelayMs({ attempt: 1, policy, random: () => 0 });
  const secondDelay = computeAdapterRetryDelayMs({ attempt: 2, policy, random: () => 0 });
  const thirdDelay = computeAdapterRetryDelayMs({ attempt: 3, policy, random: () => 0 });

  assert.equal(firstDelay, 10);
  assert.equal(secondDelay, 20);
  assert.equal(thirdDelay, 25);
});

test('classifyAdapterFailureReason maps timeout code to timeout reason', () => {
  assert.equal(
    classifyAdapterFailureReason({ code: 'ADAPTER_TIMEOUT' }),
    'connector.invoke.timeout'
  );
  assert.equal(
    classifyAdapterFailureReason(new Error('generic')),
    'connector.invoke.error'
  );
});

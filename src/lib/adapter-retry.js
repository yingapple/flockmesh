const DEFAULT_POLICY = Object.freeze({
  version: 'v0',
  max_attempts: 2,
  base_delay_ms: 40,
  max_delay_ms: 320,
  jitter_ms: 20
});

function assertObject(value, label, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[${source}] ${label} must be an object`);
  }
}

function normalizeInt(rawValue, field, source, { min, max }) {
  const value = Number(rawValue);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`[${source}] ${field} must be an integer between ${min} and ${max}`);
  }
  return value;
}

export function compileAdapterRetryPolicy(document, { source = 'memory' } = {}) {
  assertObject(document, 'document', source);
  const version = document.version || 'v0';
  if (version !== 'v0') {
    throw new Error(`[${source}] unsupported adapter retry policy version: ${version}`);
  }

  return {
    version: 'v0',
    max_attempts: normalizeInt(
      document.max_attempts ?? DEFAULT_POLICY.max_attempts,
      'max_attempts',
      source,
      { min: 1, max: 5 }
    ),
    base_delay_ms: normalizeInt(
      document.base_delay_ms ?? DEFAULT_POLICY.base_delay_ms,
      'base_delay_ms',
      source,
      { min: 0, max: 10_000 }
    ),
    max_delay_ms: normalizeInt(
      document.max_delay_ms ?? DEFAULT_POLICY.max_delay_ms,
      'max_delay_ms',
      source,
      { min: 0, max: 60_000 }
    ),
    jitter_ms: normalizeInt(
      document.jitter_ms ?? DEFAULT_POLICY.jitter_ms,
      'jitter_ms',
      source,
      { min: 0, max: 5_000 }
    )
  };
}

function parsePolicyFromEnv() {
  const raw = process.env.FLOCKMESH_ADAPTER_RETRY_POLICY;
  if (!raw) return null;

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('FLOCKMESH_ADAPTER_RETRY_POLICY must be valid JSON');
  }
  return parsed;
}

export function resolveAdapterRetryPolicy({ overridePolicy } = {}) {
  if (overridePolicy) {
    return compileAdapterRetryPolicy(overridePolicy, { source: 'overridePolicy' });
  }

  const fromEnv = parsePolicyFromEnv();
  if (fromEnv) {
    return compileAdapterRetryPolicy(fromEnv, { source: 'FLOCKMESH_ADAPTER_RETRY_POLICY' });
  }

  return compileAdapterRetryPolicy(DEFAULT_POLICY, { source: 'default' });
}

export function classifyAdapterFailureReason(error) {
  if (error?.code === 'ADAPTER_TIMEOUT') {
    return 'connector.invoke.timeout';
  }
  return 'connector.invoke.error';
}

function canRetryByIdempotency({ sideEffect, idempotencyKey }) {
  if (sideEffect !== 'mutation') return true;
  return typeof idempotencyKey === 'string' && idempotencyKey.length >= 8;
}

export function buildAdapterRetryDecision({
  attempt,
  policy,
  sideEffect,
  idempotencyKey,
  errorReason
}) {
  if (!['connector.invoke.timeout', 'connector.invoke.error'].includes(errorReason)) {
    return { retry: false, reason_code: 'retry.non_retryable_error' };
  }

  if (attempt >= policy.max_attempts) {
    return { retry: false, reason_code: 'retry.attempt_budget_exhausted' };
  }

  if (!canRetryByIdempotency({ sideEffect, idempotencyKey })) {
    return { retry: false, reason_code: 'retry.idempotency_key_required_for_mutation' };
  }

  return { retry: true, reason_code: 'retry.allowed' };
}

export function computeAdapterRetryDelayMs({
  attempt,
  policy,
  random = Math.random
}) {
  const exponential = policy.base_delay_ms * (2 ** Math.max(0, attempt - 1));
  const bounded = Math.min(policy.max_delay_ms, exponential);
  const jitter = policy.jitter_ms > 0
    ? Math.floor(random() * (policy.jitter_ms + 1))
    : 0;
  return bounded + jitter;
}

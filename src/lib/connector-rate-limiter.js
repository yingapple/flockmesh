const CONNECTOR_ID_PATTERN = /^con_[A-Za-z0-9_-]{6,64}$/;

const DEFAULT_POLICY = Object.freeze({
  version: 'v0',
  default: {
    limit: 30,
    window_ms: 60_000
  },
  connectors: {}
});

function assertObject(value, label, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[${source}] ${label} must be an object`);
  }
}

function normalizePositiveInt(rawValue, field, source) {
  const value = Number(rawValue);
  if (!Number.isInteger(value) || value < 1 || value > 3_600_000) {
    throw new Error(`[${source}] ${field} must be an integer between 1 and 3600000`);
  }
  return value;
}

function normalizeBucket(rawBucket, { source, field }) {
  assertObject(rawBucket, field, source);
  return {
    limit: normalizePositiveInt(rawBucket.limit, `${field}.limit`, source),
    window_ms: normalizePositiveInt(rawBucket.window_ms, `${field}.window_ms`, source)
  };
}

function sortObjectByKeys(input) {
  const keys = Object.keys(input).sort();
  const output = {};
  for (const key of keys) {
    output[key] = input[key];
  }
  return output;
}

export function compileConnectorRateLimitPolicy(document, { source = 'memory' } = {}) {
  assertObject(document, 'document', source);

  const version = document.version || 'v0';
  if (version !== 'v0') {
    throw new Error(`[${source}] unsupported connector rate-limit policy version: ${version}`);
  }

  const defaultBucket = normalizeBucket(
    document.default || DEFAULT_POLICY.default,
    { source, field: 'default' }
  );

  const connectorsRaw = document.connectors || {};
  assertObject(connectorsRaw, 'connectors', source);

  const normalizedConnectors = {};
  for (const [connectorId, bucket] of Object.entries(connectorsRaw)) {
    if (!CONNECTOR_ID_PATTERN.test(connectorId)) {
      throw new Error(`[${source}] invalid connector id in connectors: ${connectorId}`);
    }
    normalizedConnectors[connectorId] = normalizeBucket(
      bucket,
      { source, field: `connectors.${connectorId}` }
    );
  }

  return {
    version: 'v0',
    default: defaultBucket,
    connectors: sortObjectByKeys(normalizedConnectors)
  };
}

function parsePolicyFromEnv() {
  const envRaw = process.env.FLOCKMESH_CONNECTOR_RATE_LIMIT_POLICY;
  if (!envRaw) return null;

  let parsed;
  try {
    parsed = JSON.parse(envRaw);
  } catch {
    throw new Error('FLOCKMESH_CONNECTOR_RATE_LIMIT_POLICY must be valid JSON');
  }
  return parsed;
}

export function resolveConnectorRateLimitPolicy({ overridePolicy } = {}) {
  if (overridePolicy) {
    return compileConnectorRateLimitPolicy(overridePolicy, { source: 'overridePolicy' });
  }

  const fromEnv = parsePolicyFromEnv();
  if (fromEnv) {
    return compileConnectorRateLimitPolicy(fromEnv, { source: 'FLOCKMESH_CONNECTOR_RATE_LIMIT_POLICY' });
  }

  return compileConnectorRateLimitPolicy(DEFAULT_POLICY, { source: 'default' });
}

function bucketKey({ workspaceId, connectorId }) {
  return `${workspaceId}::${connectorId}`;
}

function trimToWindow(timestamps, now, windowMs) {
  const lowerBound = now - windowMs;
  return timestamps.filter((item) => item > lowerBound);
}

export function createConnectorRateLimiter({ policy, nowMs } = {}) {
  const compiledPolicy = policy
    ? compileConnectorRateLimitPolicy(policy, { source: 'createConnectorRateLimiter' })
    : resolveConnectorRateLimitPolicy();

  const readNowMs = typeof nowMs === 'function' ? nowMs : () => Date.now();
  const buckets = new Map();

  function resolveBucket(connectorId) {
    return compiledPolicy.connectors[connectorId] || compiledPolicy.default;
  }

  function evaluate({ connectorId, workspaceId }) {
    const bucket = resolveBucket(connectorId);
    const now = readNowMs();
    const key = bucketKey({ connectorId, workspaceId });
    const current = trimToWindow(buckets.get(key) || [], now, bucket.window_ms);

    if (current.length >= bucket.limit) {
      buckets.set(key, current);
      const oldestInWindow = current[0];
      const retryAfterMs = Math.max(1, bucket.window_ms - (now - oldestInWindow));

      return {
        allowed: false,
        reason_code: 'connector.invoke.rate_limited',
        scope: 'workspace_connector',
        limit: bucket.limit,
        window_ms: bucket.window_ms,
        retry_after_ms: retryAfterMs,
        observed: current.length
      };
    }

    current.push(now);
    buckets.set(key, current);

    return {
      allowed: true,
      reason_code: 'connector.rate_limit.allowed',
      scope: 'workspace_connector',
      limit: bucket.limit,
      window_ms: bucket.window_ms,
      remaining: Math.max(0, bucket.limit - current.length)
    };
  }

  return {
    policy: compiledPolicy,
    evaluate
  };
}

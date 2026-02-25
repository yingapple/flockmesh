import test from 'node:test';
import assert from 'node:assert/strict';

import {
  compileConnectorRateLimitPolicy,
  createConnectorRateLimiter
} from '../src/lib/connector-rate-limiter.js';

test('compileConnectorRateLimitPolicy normalizes connector buckets', () => {
  const policy = compileConnectorRateLimitPolicy({
    version: 'v0',
    default: { limit: 20, window_ms: 60_000 },
    connectors: {
      con_mcp_gateway: { limit: 8, window_ms: 30_000 },
      con_a2a_gateway: { limit: 5, window_ms: 10_000 }
    }
  }, { source: 'inline-test' });

  assert.equal(policy.version, 'v0');
  assert.equal(policy.default.limit, 20);
  assert.deepEqual(Object.keys(policy.connectors), ['con_a2a_gateway', 'con_mcp_gateway']);
});

test('createConnectorRateLimiter enforces per-workspace connector window', () => {
  let now = 1_000;
  const limiter = createConnectorRateLimiter({
    policy: {
      version: 'v0',
      default: { limit: 30, window_ms: 60_000 },
      connectors: {
        con_mcp_gateway: { limit: 1, window_ms: 1_000 }
      }
    },
    nowMs: () => now
  });

  const first = limiter.evaluate({
    connectorId: 'con_mcp_gateway',
    workspaceId: 'wsp_mindverse_cn'
  });
  assert.equal(first.allowed, true);
  assert.equal(first.remaining, 0);

  const second = limiter.evaluate({
    connectorId: 'con_mcp_gateway',
    workspaceId: 'wsp_mindverse_cn'
  });
  assert.equal(second.allowed, false);
  assert.equal(second.reason_code, 'connector.invoke.rate_limited');
  assert.ok(second.retry_after_ms >= 1);

  now = 2_001;
  const third = limiter.evaluate({
    connectorId: 'con_mcp_gateway',
    workspaceId: 'wsp_mindverse_cn'
  });
  assert.equal(third.allowed, true);
});

test('createConnectorRateLimiter isolates limits by workspace', () => {
  const limiter = createConnectorRateLimiter({
    policy: {
      version: 'v0',
      default: { limit: 30, window_ms: 60_000 },
      connectors: {
        con_a2a_gateway: { limit: 1, window_ms: 5_000 }
      }
    },
    nowMs: () => 50_000
  });

  const firstWorkspace = limiter.evaluate({
    connectorId: 'con_a2a_gateway',
    workspaceId: 'wsp_alpha_123456'
  });
  const secondWorkspace = limiter.evaluate({
    connectorId: 'con_a2a_gateway',
    workspaceId: 'wsp_beta_123456'
  });

  assert.equal(firstWorkspace.allowed, true);
  assert.equal(secondWorkspace.allowed, true);
});

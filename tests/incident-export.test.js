import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildIncidentExportPayloadHash,
  resolveIncidentExportSigningConfig,
  signIncidentExportPayload,
  verifyIncidentExportSignature
} from '../src/lib/incident-export.js';

test('buildIncidentExportPayloadHash is stable across object key order', () => {
  const a = {
    run_id: 'run_abcd1234',
    policy_trace_summary: {
      allow: 1,
      deny: 0,
      escalate: 2
    },
    version: 'v0'
  };

  const b = {
    version: 'v0',
    policy_trace_summary: {
      escalate: 2,
      deny: 0,
      allow: 1
    },
    run_id: 'run_abcd1234'
  };

  assert.equal(buildIncidentExportPayloadHash(a), buildIncidentExportPayloadHash(b));
});

test('signIncidentExportPayload and verifyIncidentExportSignature succeed for valid payload', () => {
  const payload = {
    version: 'v0',
    run_id: 'run_abcd1234',
    workspace_id: 'wsp_abcd1234',
    agent_id: 'agt_abcd1234'
  };
  const keys = {
    exp_test_sign_v1: 'test-secret-v1'
  };

  const signature = signIncidentExportPayload(payload, {
    keyId: 'exp_test_sign_v1',
    keys
  });

  assert.equal(signature.algorithm, 'HMAC-SHA256');
  assert.equal(signature.key_id, 'exp_test_sign_v1');
  assert.equal(verifyIncidentExportSignature(payload, signature, { keys }), true);
});

test('verifyIncidentExportSignature fails when payload is tampered', () => {
  const payload = {
    version: 'v0',
    run_id: 'run_abcd1234',
    status: 'waiting_approval'
  };
  const keys = {
    exp_test_sign_v1: 'test-secret-v1'
  };

  const signature = signIncidentExportPayload(payload, {
    keyId: 'exp_test_sign_v1',
    keys
  });

  const tamperedPayload = {
    ...payload,
    status: 'completed'
  };

  assert.throws(
    () => verifyIncidentExportSignature(tamperedPayload, signature, { keys }),
    /payload hash mismatch/
  );
});

test('signature verification tolerates dropped undefined fields after JSON serialization', () => {
  const payloadWithUndefined = {
    version: 'v0',
    run_id: 'run_abcd1234',
    optional: undefined,
    nested: {
      keep: 'yes',
      drop: undefined
    }
  };
  const keys = {
    exp_test_sign_v1: 'test-secret-v1'
  };

  const signature = signIncidentExportPayload(payloadWithUndefined, {
    keyId: 'exp_test_sign_v1',
    keys
  });

  const payloadAsJson = JSON.parse(JSON.stringify(payloadWithUndefined));
  assert.equal(
    verifyIncidentExportSignature(payloadAsJson, signature, { keys }),
    true
  );
});

test('resolveIncidentExportSigningConfig validates key id and configured secret', () => {
  assert.throws(
    () => resolveIncidentExportSigningConfig({
      overrideKeys: {
        exp_test_sign_v1: 'test-secret-v1'
      },
      keyId: 'bad_key_id'
    }),
    /Invalid incident export signing key id/
  );

  assert.throws(
    () => resolveIncidentExportSigningConfig({
      overrideKeys: {
        exp_test_sign_v1: 'test-secret-v1'
      },
      keyId: 'exp_missing_v1'
    }),
    /not configured/
  );

  const config = resolveIncidentExportSigningConfig({
    overrideKeys: {
      exp_test_sign_v1: 'test-secret-v1'
    },
    keyId: 'exp_test_sign_v1'
  });

  assert.equal(config.algorithm, 'HMAC-SHA256');
  assert.equal(config.key_id, 'exp_test_sign_v1');
  assert.equal(config.keys.exp_test_sign_v1, 'test-secret-v1');
});

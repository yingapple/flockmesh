import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildConnectorHealthSummary,
  compileConnectorManifestDsl,
  detectScopeDrift,
  loadConnectorManifestsFromDir,
  signManifestAttestation
} from '../src/lib/connector-manifests.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

test('compileConnectorManifestDsl validates and normalizes manifest', () => {
  const manifest = {
    version: 'v0',
    connector_id: 'con_test_connector',
    name: 'Test Connector',
    category: 'office_system',
    protocol: 'http',
    trust_level: 'standard',
    capabilities: ['doc.read', 'doc.write', 'doc.read']
  };
  manifest.attestation = signManifestAttestation(manifest);

  const compiled = compileConnectorManifestDsl(manifest, { source: 'inline-test' });

  assert.equal(compiled.connector_id, 'con_test_connector');
  assert.deepEqual(compiled.capabilities, ['doc.read', 'doc.write']);
  assert.equal(compiled.status, 'active');
  assert.equal(compiled.attestation.verified, true);
});

test('compileConnectorManifestDsl fails on attestation signature mismatch', () => {
  const manifest = {
    version: 'v0',
    connector_id: 'con_test_attestation',
    name: 'Test Attestation',
    category: 'agent_protocol',
    protocol: 'mcp',
    trust_level: 'high_control',
    capabilities: ['tool.invoke']
  };
  manifest.attestation = signManifestAttestation(manifest);
  manifest.attestation.signature = '0'.repeat(64);

  assert.throws(() => {
    compileConnectorManifestDsl(manifest, { source: 'inline-attestation-test' });
  }, /attestation signature mismatch/);
});

test('loadConnectorManifestsFromDir loads repository manifests', async () => {
  const registry = await loadConnectorManifestsFromDir({ rootDir: projectRoot });
  assert.ok(registry.con_mcp_gateway);
  assert.ok(registry.con_a2a_gateway);
  assert.ok(registry.con_office_calendar);
});

test('detectScopeDrift flags missing manifests and undeclared scopes', () => {
  const manifests = {
    con_mcp_gateway: {
      connector_id: 'con_mcp_gateway',
      capabilities: ['tool.invoke', 'tool.list'],
      attestation: {
        key_id: 'att_dev_main_v1',
        verified: true
      }
    },
    con_bad_attestation: {
      connector_id: 'con_bad_attestation',
      capabilities: ['crm.read'],
      attestation: {
        key_id: 'att_dev_main_v1',
        verified: false
      }
    }
  };

  const bindings = [
    {
      id: 'cnb_scope_drift_123456',
      connector_id: 'con_mcp_gateway',
      scopes: ['tool.invoke', 'payment.execute']
    },
    {
      id: 'cnb_manifest_miss_123456',
      connector_id: 'con_missing_gateway',
      scopes: ['crm.read']
    },
    {
      id: 'cnb_attestation_bad_1234',
      connector_id: 'con_bad_attestation',
      scopes: ['crm.read']
    }
  ];

  const report = detectScopeDrift({ manifests, bindings });
  assert.equal(report.total, 3);
  assert.ok(report.items.some((item) => item.issue === 'scope_not_declared'));
  assert.ok(report.items.some((item) => item.issue === 'manifest_missing'));
  assert.ok(report.items.some((item) => item.issue === 'attestation_invalid'));
});

test('buildConnectorHealthSummary marks degraded connectors correctly', () => {
  const manifests = {
    con_mcp_gateway: {
      connector_id: 'con_mcp_gateway',
      category: 'agent_protocol',
      protocol: 'mcp',
      trust_level: 'high_control',
      capabilities: ['tool.invoke'],
      attestation: {
        key_id: 'att_dev_main_v1',
        verified: false
      }
    }
  };

  const bindings = [
    {
      id: 'cnb_health_123456',
      connector_id: 'con_mcp_gateway',
      status: 'active',
      scopes: ['tool.invoke', 'tool.read']
    },
    {
      id: 'cnb_health_654321',
      connector_id: 'con_unknown_bridge',
      status: 'active',
      scopes: ['crm.read']
    }
  ];

  const summary = buildConnectorHealthSummary({ manifests, bindings });
  assert.equal(summary.total, 2);
  assert.equal(summary.degraded, 2);
  assert.ok(
    summary.items.some((item) => item.connector_id === 'con_unknown_bridge' && !item.manifest_loaded)
  );
  assert.ok(
    summary.items.some((item) => item.connector_id === 'con_mcp_gateway' && item.attestation_valid === false)
  );
});

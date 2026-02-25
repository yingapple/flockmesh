import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { compilePolicyProfileDsl, loadPolicyLibraryFromDir } from '../src/lib/policy-dsl.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

test('compilePolicyProfileDsl compiles v0 profile into runtime rule shape', () => {
  const compiled = compilePolicyProfileDsl({
    version: 'v0',
    name: 'workspace_sales_cn',
    rules: [
      { capability: 'message.send', decision: 'escalate', required_approvals: 2 },
      { capability: 'crm.read', decision: 'allow' }
    ]
  }, { source: 'inline-test' });

  assert.equal(compiled.name, 'workspace_sales_cn');
  assert.deepEqual(compiled.rules['message.send'], {
    decision: 'escalate',
    requiredApprovals: 2
  });
  assert.deepEqual(compiled.rules['crm.read'], {
    decision: 'allow',
    requiredApprovals: 0
  });
});

test('compilePolicyProfileDsl rejects escalate rules without valid required_approvals', () => {
  assert.throws(() => {
    compilePolicyProfileDsl({
      version: 'v0',
      name: 'broken_policy',
      rules: [
        { capability: 'message.send', decision: 'escalate', required_approvals: 0 }
      ]
    }, { source: 'inline-test' });
  }, /required_approvals/);
});

test('loadPolicyLibraryFromDir loads policy files from the repository policies folder', async () => {
  const library = await loadPolicyLibraryFromDir({ rootDir: projectRoot });

  assert.ok(library.org_default_safe);
  assert.ok(library.workspace_ops_cn);
  assert.ok(library.agent_ops_assistant);
  assert.equal(library.org_default_safe.rules['message.send'].decision, 'escalate');
});

import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import { evaluatePolicy } from '../src/lib/policy-engine.js';
import { loadPolicyLibraryFromDir } from '../src/lib/policy-dsl.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const fixturesPath = path.join(projectRoot, 'tests', 'fixtures', 'policy-regressions.json');
const fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

test('policy regression fixtures remain stable', async () => {
  const policyLibrary = await loadPolicyLibraryFromDir({ rootDir: projectRoot });

  for (const fixture of fixtures) {
    const decision = evaluatePolicy({
      runId: fixture.input.run_id,
      actionIntent: fixture.input.action_intent,
      policyContext: fixture.input.policy_context,
      policyLibrary
    });

    assert.equal(decision.decision, fixture.expect.decision, fixture.name);
    assert.equal(decision.required_approvals, fixture.expect.required_approvals, fixture.name);
    assert.equal(decision.policy_trace.effective_source, fixture.expect.effective_source, fixture.name);
  }
});

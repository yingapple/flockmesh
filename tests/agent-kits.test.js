import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  compileAgentKitDsl,
  loadAgentKitsFromDir,
  listAgentKits
} from '../src/lib/agent-kits.js';

test('compileAgentKitDsl validates and normalizes kit', () => {
  const compiled = compileAgentKitDsl({
    version: 'v0',
    kit_id: 'kit_test_runtime',
    name: 'Test Runtime',
    description: 'Test description',
    role: 'ops_assistant',
    default_policy_profile: 'polprof_ops_standard',
    default_playbook_id: 'pbk_test_runtime',
    capability_goals: ['message.send', 'calendar.read', 'calendar.read'],
    connector_candidates: [
      {
        connector_id: 'con_feishu_official',
        required_capabilities: ['message.send'],
        optional_capabilities: ['calendar.read'],
        risk_profile: 'restricted'
      }
    ],
    rollout: [
      {
        phase_id: 'phase_start',
        title: 'Start',
        focus: 'Focus',
        approval_expectation: 'single'
      }
    ]
  }, { source: 'test' });

  assert.equal(compiled.kit_id, 'kit_test_runtime');
  assert.deepEqual(compiled.capability_goals, ['calendar.read', 'message.send']);
  assert.equal(compiled.connector_candidates.length, 1);
});

test('loadAgentKitsFromDir loads kit files from kits directory', async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'flockmesh-kits-'));

  try {
    const kitsDir = path.join(tempRoot, 'kits');
    await fs.mkdir(kitsDir, { recursive: true });
    await fs.writeFile(path.join(kitsDir, 'demo.kit.json'), JSON.stringify({
      version: 'v0',
      kit_id: 'kit_demo_runtime',
      name: 'Demo Runtime',
      description: 'Demo runtime kit',
      role: 'assistant',
      default_policy_profile: 'polprof_ops_standard',
      default_playbook_id: 'pbk_demo_runtime',
      capability_goals: ['message.send'],
      connector_candidates: [
        {
          connector_id: 'con_feishu_official',
          required_capabilities: ['message.send'],
          optional_capabilities: [],
          risk_profile: 'restricted'
        }
      ],
      rollout: [
        {
          phase_id: 'phase_bootstrap',
          title: 'Bootstrap',
          focus: 'Bootstrap focus',
          approval_expectation: 'single'
        }
      ]
    }, null, 2));

    const library = await loadAgentKitsFromDir({ rootDir: tempRoot });
    assert.ok(library.kit_demo_runtime);

    const catalog = listAgentKits({ kitLibrary: library });
    assert.equal(catalog.total, 1);
    assert.equal(catalog.items[0].kit_id, 'kit_demo_runtime');
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

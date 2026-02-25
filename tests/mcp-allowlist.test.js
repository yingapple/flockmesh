import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  compileMcpAllowlistDocument,
  evaluateMcpAllowlist,
  loadMcpAllowlistsFromDir
} from '../src/lib/mcp-allowlist.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

test('compileMcpAllowlistDocument normalizes rules', () => {
  const compiled = compileMcpAllowlistDocument({
    version: 'v0',
    name: 'mcp_test',
    rules: [
      {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: '*',
        allowed_tool_patterns: ['search.*', 'search.*', 'jira.issue.read'],
        max_risk_tier: 'R2',
        allow_mutation: true
      }
    ]
  }, { source: 'inline-test' });

  assert.equal(compiled.name, 'mcp_test');
  assert.equal(compiled.rules.length, 1);
  assert.deepEqual(compiled.rules[0].allowed_tool_patterns, ['jira.issue.read', 'search.*']);
});

test('evaluateMcpAllowlist allows matching workspace/agent rule', () => {
  const docs = [compileMcpAllowlistDocument({
    version: 'v0',
    name: 'mcp_test',
    rules: [
      {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: '*',
        allowed_tool_patterns: ['search.*'],
        max_risk_tier: 'R2',
        allow_mutation: true
      }
    ]
  }, { source: 'inline-test' })];

  const result = evaluateMcpAllowlist({
    documents: docs,
    workspaceId: 'wsp_mindverse_cn',
    agentId: 'agt_demo_123456',
    toolName: 'search.docs',
    sideEffect: 'none',
    riskHint: 'R0'
  });

  assert.equal(result.allowed, true);
});

test('evaluateMcpAllowlist denies non-allowlisted tool', () => {
  const docs = [compileMcpAllowlistDocument({
    version: 'v0',
    name: 'mcp_test',
    rules: [
      {
        workspace_id: 'wsp_mindverse_cn',
        agent_id: '*',
        allowed_tool_patterns: ['search.*'],
        max_risk_tier: 'R2',
        allow_mutation: true
      }
    ]
  }, { source: 'inline-test' })];

  const result = evaluateMcpAllowlist({
    documents: docs,
    workspaceId: 'wsp_mindverse_cn',
    agentId: 'agt_demo_123456',
    toolName: 'admin.user.delete',
    sideEffect: 'none',
    riskHint: 'R0'
  });

  assert.equal(result.allowed, false);
  assert.equal(result.reason_code, 'mcp.allowlist.tool_not_allowed');
});

test('loadMcpAllowlistsFromDir loads repository MCP allowlist policies', async () => {
  const docs = await loadMcpAllowlistsFromDir({ rootDir: projectRoot });
  assert.ok(docs.length >= 1);
  assert.ok(docs.some((doc) => doc.name === 'mcp_ops_bootstrap'));
});

import fs from 'node:fs/promises';
import path from 'node:path';

const WORKSPACE_PATTERN = /^wsp_[A-Za-z0-9_-]{6,64}$/;
const AGENT_PATTERN = /^(\*|agt_[A-Za-z0-9_-]{6,64})$/;
const TOOL_PATTERN = /^[a-z][a-z0-9_.*-]{2,128}$/;

const RISK_ORDER = {
  R0: 0,
  R1: 1,
  R2: 2,
  R3: 3
};

function assertObject(value, label, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[${source}] ${label} must be an object`);
  }
}

function normalizeRule(rule, { source, index }) {
  const pointer = `${source}#rule[${index}]`;
  assertObject(rule, 'rule', pointer);

  if (!WORKSPACE_PATTERN.test(String(rule.workspace_id || ''))) {
    throw new Error(`[${pointer}] invalid workspace_id`);
  }

  const agentId = String(rule.agent_id || '*');
  if (!AGENT_PATTERN.test(agentId)) {
    throw new Error(`[${pointer}] invalid agent_id`);
  }

  if (!Array.isArray(rule.allowed_tool_patterns) || rule.allowed_tool_patterns.length < 1) {
    throw new Error(`[${pointer}] allowed_tool_patterns must be a non-empty array`);
  }

  const allowedToolPatterns = Array.from(new Set(rule.allowed_tool_patterns.map(String))).sort();
  for (const pattern of allowedToolPatterns) {
    if (!TOOL_PATTERN.test(pattern)) {
      throw new Error(`[${pointer}] invalid tool pattern: ${pattern}`);
    }
  }

  const maxRiskTier = String(rule.max_risk_tier || 'R3');
  if (!Object.prototype.hasOwnProperty.call(RISK_ORDER, maxRiskTier)) {
    throw new Error(`[${pointer}] invalid max_risk_tier`);
  }

  return {
    workspace_id: String(rule.workspace_id),
    agent_id: agentId,
    allowed_tool_patterns: allowedToolPatterns,
    max_risk_tier: maxRiskTier,
    allow_mutation: rule.allow_mutation !== false
  };
}

export function compileMcpAllowlistDocument(document, { source = 'memory' } = {}) {
  assertObject(document, 'document', source);

  if (document.version !== 'v0') {
    throw new Error(`[${source}] unsupported allowlist version: ${document.version}`);
  }

  if (!Array.isArray(document.rules) || document.rules.length < 1) {
    throw new Error(`[${source}] rules must be a non-empty array`);
  }

  const rules = document.rules.map((rule, index) => normalizeRule(rule, { source, index }));

  return {
    version: 'v0',
    name: String(document.name || path.basename(source, '.json')),
    rules
  };
}

export async function loadMcpAllowlistsFromDir({
  rootDir,
  dirName = path.join('policies', 'mcp-allowlists')
} = {}) {
  const directoryPath = path.join(rootDir, dirName);
  let entries = [];

  try {
    entries = await fs.readdir(directoryPath, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }

  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.mcp-allowlist.json'))
    .map((entry) => entry.name)
    .sort();

  const documents = [];
  for (const fileName of files) {
    const filePath = path.join(directoryPath, fileName);
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    const compiled = compileMcpAllowlistDocument(parsed, { source: fileName });
    documents.push(compiled);
  }

  return documents;
}

function wildcardToRegExp(pattern) {
  const escaped = pattern
    .replace(/[|\\{}()[\]^$+?.]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function matchesToolPattern(toolName, patterns) {
  for (const pattern of patterns) {
    if (wildcardToRegExp(pattern).test(toolName)) return true;
  }
  return false;
}

function chooseMatchingRule({ rules, workspaceId, agentId }) {
  const candidates = rules.filter((rule) => rule.workspace_id === workspaceId);
  const exact = candidates.find((rule) => rule.agent_id === agentId);
  if (exact) return exact;
  return candidates.find((rule) => rule.agent_id === '*') || null;
}

export function evaluateMcpAllowlist({
  documents,
  workspaceId,
  agentId,
  toolName,
  sideEffect,
  riskHint
}) {
  const rules = documents.flatMap((doc) => doc.rules);
  const matchedRule = chooseMatchingRule({
    rules,
    workspaceId,
    agentId
  });

  if (!matchedRule) {
    return {
      allowed: false,
      reason_code: 'mcp.allowlist.no_matching_rule'
    };
  }

  if (!matchesToolPattern(toolName, matchedRule.allowed_tool_patterns)) {
    return {
      allowed: false,
      reason_code: 'mcp.allowlist.tool_not_allowed'
    };
  }

  if (sideEffect === 'mutation' && !matchedRule.allow_mutation) {
    return {
      allowed: false,
      reason_code: 'mcp.allowlist.mutation_not_allowed'
    };
  }

  const requestedRisk = RISK_ORDER[riskHint];
  const maxRisk = RISK_ORDER[matchedRule.max_risk_tier];

  if (
    Number.isInteger(requestedRisk) &&
    Number.isInteger(maxRisk) &&
    requestedRisk > maxRisk
  ) {
    return {
      allowed: false,
      reason_code: 'mcp.allowlist.risk_tier_exceeded'
    };
  }

  return {
    allowed: true,
    reason_code: 'mcp.allowlist.allowed'
  };
}

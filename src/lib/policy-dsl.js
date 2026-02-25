import fs from 'node:fs/promises';
import path from 'node:path';

const DECISIONS = new Set(['allow', 'deny', 'escalate']);
const CAPABILITY_PATTERN = /^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)$/;
const PROFILE_NAME_PATTERN = /^[a-z][a-z0-9_]{2,80}$/;

function toRuleShape(rule, { profileName, index, source }) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    throw new Error(`[${source}] policy ${profileName} rule #${index} must be an object`);
  }

  const capability = String(rule.capability || '');
  if (!CAPABILITY_PATTERN.test(capability)) {
    throw new Error(
      `[${source}] policy ${profileName} rule #${index} has invalid capability: ${capability}`
    );
  }

  const decision = String(rule.decision || '');
  if (!DECISIONS.has(decision)) {
    throw new Error(`[${source}] policy ${profileName} rule #${index} has invalid decision: ${decision}`);
  }

  if (decision === 'escalate') {
    const requiredApprovals = Number(rule.required_approvals ?? 1);
    if (!Number.isInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 5) {
      throw new Error(
        `[${source}] policy ${profileName} rule #${index} must set required_approvals between 1 and 5 for escalate`
      );
    }
    return { capability, decision, requiredApprovals };
  }

  return { capability, decision, requiredApprovals: 0 };
}

export function compilePolicyProfileDsl(document, { source = 'memory' } = {}) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error(`[${source}] policy profile must be an object`);
  }

  const name = String(document.name || '');
  if (!PROFILE_NAME_PATTERN.test(name)) {
    throw new Error(`[${source}] policy profile has invalid name: ${name}`);
  }

  if (document.version !== 'v0') {
    throw new Error(`[${source}] policy ${name} has unsupported version: ${document.version}`);
  }

  if (!Array.isArray(document.rules) || document.rules.length < 1) {
    throw new Error(`[${source}] policy ${name} must contain at least one rule`);
  }

  const rules = {};
  for (let i = 0; i < document.rules.length; i += 1) {
    const compiled = toRuleShape(document.rules[i], {
      profileName: name,
      index: i,
      source
    });
    if (rules[compiled.capability]) {
      throw new Error(`[${source}] policy ${name} has duplicated capability: ${compiled.capability}`);
    }

    rules[compiled.capability] = {
      decision: compiled.decision,
      requiredApprovals: compiled.requiredApprovals
    };
  }

  return {
    name,
    rules
  };
}

export async function loadPolicyLibraryFromDir({
  rootDir,
  dirName = 'policies'
} = {}) {
  const directoryPath = path.join(rootDir, dirName);
  let entries = [];

  try {
    entries = await fs.readdir(directoryPath, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }

  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.policy.json'))
    .map((entry) => entry.name)
    .sort();

  const compiledLibrary = {};

  for (const fileName of files) {
    const absPath = path.join(directoryPath, fileName);
    const raw = await fs.readFile(absPath, 'utf8');
    const parsed = JSON.parse(raw);
    const compiled = compilePolicyProfileDsl(parsed, { source: fileName });
    compiledLibrary[compiled.name] = compiled;
  }

  return compiledLibrary;
}

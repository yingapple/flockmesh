import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const schemaDir = path.join(rootDir, 'spec', 'schemas');
const exampleDir = path.join(rootDir, 'spec', 'examples');

const exampleSchemaMap = {
  'action-intent.json': 'https://flockmesh.dev/spec/schemas/action-intent.schema.json',
  'agent-kit-catalog.json': 'https://flockmesh.dev/spec/schemas/agent-kit-catalog.schema.json',
  'agent-blueprint-preview.json': 'https://flockmesh.dev/spec/schemas/agent-blueprint-preview.schema.json',
  'agent-blueprint-apply-result.json': 'https://flockmesh.dev/spec/schemas/agent-blueprint-apply-result.schema.json',
  'agent-blueprint-lint-report.json': 'https://flockmesh.dev/spec/schemas/agent-blueprint-lint-report.schema.json',
  'agent-blueprint-remediation-plan.json': 'https://flockmesh.dev/spec/schemas/agent-blueprint-remediation-plan.schema.json',
  'agent-profile.json': 'https://flockmesh.dev/spec/schemas/agent-profile.schema.json',
  'audit-entry.json': 'https://flockmesh.dev/spec/schemas/audit-entry.schema.json',
  'connector-binding.json': 'https://flockmesh.dev/spec/schemas/connector-binding.schema.json',
  'connector-manifest.json': 'https://flockmesh.dev/spec/schemas/connector-manifest.schema.json',
  'connector-health.json': 'https://flockmesh.dev/spec/schemas/connector-health.schema.json',
  'connector-drift.json': 'https://flockmesh.dev/spec/schemas/connector-drift.schema.json',
  'connector-adapter-simulate-result.json': 'https://flockmesh.dev/spec/schemas/connector-adapter-simulation-result.schema.json',
  'connector-adapter-invoke-result.json': 'https://flockmesh.dev/spec/schemas/connector-adapter-invoke-result.schema.json',
  'policy-decision.json': 'https://flockmesh.dev/spec/schemas/policy-decision.schema.json',
  'policy-profile-catalog.json': 'https://flockmesh.dev/spec/schemas/policy-profile-catalog.schema.json',
  'policy-profile-version.json': 'https://flockmesh.dev/spec/schemas/policy-profile-version.schema.json',
  'policy-patch-history.json': 'https://flockmesh.dev/spec/schemas/policy-patch-history.schema.json',
  'policy-patch-history-export-package.json': 'https://flockmesh.dev/spec/schemas/policy-patch-history-export-package.schema.json',
  'policy-simulation.json': 'https://flockmesh.dev/spec/schemas/policy-simulation.schema.json',
  'policy-profile-patch-result.json': 'https://flockmesh.dev/spec/schemas/policy-profile-patch-result.schema.json',
  'run-record.json': 'https://flockmesh.dev/spec/schemas/run-record.schema.json',
  'incident-export-package.json': 'https://flockmesh.dev/spec/schemas/incident-export-package.schema.json',
  'run-timeline-diff.json': 'https://flockmesh.dev/spec/schemas/run-timeline-diff.schema.json',
  'run-replay-integrity.json': 'https://flockmesh.dev/spec/schemas/run-replay-integrity.schema.json',
  'run-replay-export-package.json': 'https://flockmesh.dev/spec/schemas/run-replay-export-package.schema.json',
  'replay-drift-summary.json': 'https://flockmesh.dev/spec/schemas/replay-drift-summary.schema.json'
};

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function collectSchemaFiles() {
  return fs
    .readdirSync(schemaDir)
    .filter((name) => name.endsWith('.schema.json'))
    .sort();
}

function collectExampleFiles() {
  return fs
    .readdirSync(exampleDir)
    .filter((name) => name.endsWith('.json'))
    .sort();
}

function formatAjvErrors(errors = []) {
  if (!errors.length) return 'unknown validation error';
  return errors
    .map((err) => {
      const at = err.instancePath || '/';
      return `${at} ${err.message}`;
    })
    .join('; ');
}

function run() {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: false
  });
  addFormats(ajv);

  const schemaFiles = collectSchemaFiles();
  for (const fileName of schemaFiles) {
    const schema = loadJson(path.join(schemaDir, fileName));
    ajv.addSchema(schema);
  }

  const exampleFiles = collectExampleFiles();
  const failures = [];

  for (const fileName of exampleFiles) {
    const schemaId = exampleSchemaMap[fileName];
    if (!schemaId) {
      failures.push(`${fileName}: missing schema mapping in script`);
      continue;
    }

    const validate = ajv.getSchema(schemaId);
    if (!validate) {
      failures.push(`${fileName}: schema not loaded (${schemaId})`);
      continue;
    }

    const payload = loadJson(path.join(exampleDir, fileName));
    const ok = validate(payload);
    if (!ok) {
      failures.push(`${fileName}: ${formatAjvErrors(validate.errors)}`);
    }
  }

  if (failures.length) {
    console.error('spec consistency check failed:');
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log(`spec consistency check passed (${schemaFiles.length} schemas, ${exampleFiles.length} examples)`);
}

run();

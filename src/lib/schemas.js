import fs from 'node:fs';
import path from 'node:path';

export function loadContractSchemas(projectRoot) {
  const schemaDir = path.join(projectRoot, 'spec', 'schemas');
  const files = fs
    .readdirSync(schemaDir)
    .filter((name) => name.endsWith('.schema.json'))
    .sort();

  return files.map((name) => {
    const absPath = path.join(schemaDir, name);
    const schema = JSON.parse(fs.readFileSync(absPath, 'utf8'));
    // Fastify's default AJV setup does not preload draft-2020 meta schema.
    // Removing $schema keeps validation focused on runtime constraints.
    delete schema.$schema;
    return schema;
  });
}

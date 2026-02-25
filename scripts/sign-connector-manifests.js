import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { signManifestAttestation } from '../src/lib/connector-manifests.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const manifestDir = path.join(rootDir, 'connectors', 'manifests');

const keyId = process.env.FLOCKMESH_MANIFEST_SIGN_KEY_ID || 'att_dev_main_v1';
const keySecret = process.env.FLOCKMESH_MANIFEST_SIGN_SECRET;

async function run() {
  const entries = await fs.readdir(manifestDir, { withFileTypes: true });
  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.connector.json'))
    .map((entry) => entry.name)
    .sort();

  for (const fileName of files) {
    const filePath = path.join(manifestDir, fileName);
    const payload = JSON.parse(await fs.readFile(filePath, 'utf8'));
    payload.attestation = signManifestAttestation(payload, {
      keyId,
      ...(keySecret ? { secret: keySecret } : {})
    });
    await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    console.log(`signed ${fileName}`);
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});

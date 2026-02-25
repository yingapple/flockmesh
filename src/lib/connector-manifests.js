import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { nowIso } from './time.js';

const CONNECTOR_ID_PATTERN = /^con_[A-Za-z0-9_-]{6,64}$/;
const CAPABILITY_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const CATEGORY_SET = new Set(['office_channel', 'office_system', 'agent_protocol']);
const PROTOCOL_SET = new Set(['sdk', 'http', 'mcp', 'a2a']);
const TRUST_LEVEL_SET = new Set(['sandbox', 'standard', 'high_control']);
const STATUS_SET = new Set(['active', 'preview', 'deprecated']);

const ATTESTATION_ALGORITHM = 'HMAC-SHA256';
const ATTESTATION_KEY_ID_PATTERN = /^att_[A-Za-z0-9_-]{4,64}$/;
const SHA256_TAG_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE_PATTERN = /^[a-f0-9]{64}$/;

export const DEFAULT_ATTESTATION_KEYS = Object.freeze({
  att_dev_main_v1: 'flockmesh-dev-attestation-key-v1'
});

function sha256Hex(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function hmacSha256Hex(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function assertString(value, name, source, minLength = 1, maxLength = 120) {
  if (typeof value !== 'string' || value.length < minLength || value.length > maxLength) {
    throw new Error(`[${source}] ${name} must be a string with length ${minLength}-${maxLength}`);
  }
}

function uniqueSorted(values) {
  return Array.from(new Set(values)).sort();
}

function stableSerialize(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableSerialize(item)).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const body = keys
      .map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key])}`)
      .join(',');
    return `{${body}}`;
  }

  return JSON.stringify(value);
}

function normalizeManifestCore(document, { source = 'memory' } = {}) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error(`[${source}] connector manifest must be an object`);
  }

  if (document.version !== 'v0') {
    throw new Error(`[${source}] unsupported connector manifest version: ${document.version}`);
  }

  assertString(document.connector_id, 'connector_id', source, 10, 80);
  if (!CONNECTOR_ID_PATTERN.test(document.connector_id)) {
    throw new Error(`[${source}] invalid connector_id: ${document.connector_id}`);
  }

  assertString(document.name, 'name', source, 3, 120);

  if (!CATEGORY_SET.has(document.category)) {
    throw new Error(`[${source}] invalid category: ${document.category}`);
  }

  if (!PROTOCOL_SET.has(document.protocol)) {
    throw new Error(`[${source}] invalid protocol: ${document.protocol}`);
  }

  if (!TRUST_LEVEL_SET.has(document.trust_level)) {
    throw new Error(`[${source}] invalid trust_level: ${document.trust_level}`);
  }

  if (!Array.isArray(document.capabilities) || document.capabilities.length < 1) {
    throw new Error(`[${source}] capabilities must be a non-empty array`);
  }

  for (const capability of document.capabilities) {
    if (typeof capability !== 'string' || !CAPABILITY_PATTERN.test(capability)) {
      throw new Error(`[${source}] invalid capability: ${capability}`);
    }
  }

  const status = document.status || 'active';
  if (!STATUS_SET.has(status)) {
    throw new Error(`[${source}] invalid status: ${status}`);
  }

  return {
    connector_id: document.connector_id,
    name: document.name,
    category: document.category,
    protocol: document.protocol,
    trust_level: document.trust_level,
    status,
    capabilities: uniqueSorted(document.capabilities),
    metadata: document.metadata && typeof document.metadata === 'object' ? document.metadata : {}
  };
}

export function buildManifestPayloadHash(manifestCore) {
  const canonicalPayload = {
    connector_id: manifestCore.connector_id,
    name: manifestCore.name,
    category: manifestCore.category,
    protocol: manifestCore.protocol,
    trust_level: manifestCore.trust_level,
    status: manifestCore.status,
    capabilities: uniqueSorted(manifestCore.capabilities),
    metadata: manifestCore.metadata && typeof manifestCore.metadata === 'object'
      ? manifestCore.metadata
      : {}
  };

  return `sha256:${sha256Hex(stableSerialize(canonicalPayload))}`;
}

export function resolveConnectorAttestationKeys({ overrideKeys } = {}) {
  const keys = { ...DEFAULT_ATTESTATION_KEYS };
  const envRaw = process.env.FLOCKMESH_CONNECTOR_ATTESTATION_KEYS;

  if (envRaw) {
    let parsed;
    try {
      parsed = JSON.parse(envRaw);
    } catch (err) {
      throw new Error('FLOCKMESH_CONNECTOR_ATTESTATION_KEYS must be valid JSON object');
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('FLOCKMESH_CONNECTOR_ATTESTATION_KEYS must be a JSON object');
    }

    for (const [keyId, secret] of Object.entries(parsed)) {
      if (typeof secret !== 'string' || !secret.length) {
        throw new Error(`FLOCKMESH_CONNECTOR_ATTESTATION_KEYS has invalid secret for ${keyId}`);
      }
      keys[keyId] = secret;
    }
  }

  if (overrideKeys) {
    for (const [keyId, secret] of Object.entries(overrideKeys)) {
      keys[keyId] = secret;
    }
  }

  return keys;
}

export function signManifestAttestation(manifestDocument, {
  keyId = 'att_dev_main_v1',
  secret,
  algorithm = ATTESTATION_ALGORITHM
} = {}) {
  if (algorithm !== ATTESTATION_ALGORITHM) {
    throw new Error(`Unsupported attestation algorithm: ${algorithm}`);
  }

  if (!ATTESTATION_KEY_ID_PATTERN.test(keyId)) {
    throw new Error(`Invalid attestation key_id: ${keyId}`);
  }

  const normalized = normalizeManifestCore(
    { ...manifestDocument, version: manifestDocument.version || 'v0' },
    { source: 'signManifestAttestation' }
  );

  const effectiveSecret = secret || DEFAULT_ATTESTATION_KEYS[keyId];
  if (!effectiveSecret) {
    throw new Error(`Missing attestation secret for key_id: ${keyId}`);
  }

  const payloadHash = buildManifestPayloadHash(normalized);
  const signature = hmacSha256Hex(effectiveSecret, payloadHash);

  return {
    algorithm,
    key_id: keyId,
    payload_hash: payloadHash,
    signature
  };
}

export function compileConnectorManifestDsl(document, {
  source = 'memory',
  attestationKeys
} = {}) {
  const normalized = normalizeManifestCore(document, { source });
  const keyring = resolveConnectorAttestationKeys({ overrideKeys: attestationKeys });

  const attestation = document.attestation;
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
    throw new Error(`[${source}] attestation is required`);
  }

  if (attestation.algorithm !== ATTESTATION_ALGORITHM) {
    throw new Error(`[${source}] unsupported attestation algorithm: ${attestation.algorithm}`);
  }

  if (!ATTESTATION_KEY_ID_PATTERN.test(attestation.key_id || '')) {
    throw new Error(`[${source}] invalid attestation key_id`);
  }

  if (!SHA256_TAG_PATTERN.test(attestation.payload_hash || '')) {
    throw new Error(`[${source}] invalid attestation payload_hash`);
  }

  if (!SIGNATURE_PATTERN.test(attestation.signature || '')) {
    throw new Error(`[${source}] invalid attestation signature format`);
  }

  const expectedPayloadHash = buildManifestPayloadHash(normalized);
  if (attestation.payload_hash !== expectedPayloadHash) {
    throw new Error(`[${source}] attestation payload_hash mismatch`);
  }

  const secret = keyring[attestation.key_id];
  if (!secret) {
    throw new Error(`[${source}] attestation key not configured: ${attestation.key_id}`);
  }

  const expectedSignature = hmacSha256Hex(secret, attestation.payload_hash);
  if (attestation.signature !== expectedSignature) {
    throw new Error(`[${source}] attestation signature mismatch`);
  }

  return {
    ...normalized,
    attestation: {
      algorithm: attestation.algorithm,
      key_id: attestation.key_id,
      payload_hash: attestation.payload_hash,
      signature: attestation.signature,
      verified: true
    }
  };
}

export async function loadConnectorManifestsFromDir({
  rootDir,
  dirName = path.join('connectors', 'manifests'),
  attestationKeys
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
    .filter((entry) => entry.isFile() && entry.name.endsWith('.connector.json'))
    .map((entry) => entry.name)
    .sort();

  const keyring = resolveConnectorAttestationKeys({ overrideKeys: attestationKeys });
  const registry = {};
  for (const fileName of files) {
    const absPath = path.join(directoryPath, fileName);
    const raw = await fs.readFile(absPath, 'utf8');
    const parsed = JSON.parse(raw);
    const compiled = compileConnectorManifestDsl(parsed, {
      source: fileName,
      attestationKeys: keyring
    });
    registry[compiled.connector_id] = compiled;
  }

  return registry;
}

function boundedInt(value, fallback, min, max) {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(Math.max(Math.floor(num), min), max);
}

function paginate(items, { limit = 100, offset = 0 } = {}) {
  const boundedLimit = boundedInt(limit, 100, 1, 500);
  const boundedOffset = boundedInt(offset, 0, 0, Number.MAX_SAFE_INTEGER);
  return {
    total: items.length,
    limit: boundedLimit,
    offset: boundedOffset,
    items: items.slice(boundedOffset, boundedOffset + boundedLimit)
  };
}

export function listConnectorManifestsPage(manifests, { limit, offset } = {}) {
  const ordered = Object.values(manifests).sort((a, b) =>
    a.connector_id.localeCompare(b.connector_id)
  );
  return paginate(ordered, { limit, offset });
}

export function detectScopeDrift({ manifests, bindings, connectorId }) {
  const items = [];
  const selectedBindings = connectorId
    ? bindings.filter((binding) => binding.connector_id === connectorId)
    : bindings;

  for (const binding of selectedBindings) {
    const manifest = manifests[binding.connector_id];
    if (!manifest) {
      items.push({
        binding_id: binding.id,
        connector_id: binding.connector_id,
        issue: 'manifest_missing',
        unknown_scopes: binding.scopes,
        detected_at: nowIso()
      });
      continue;
    }

    if (manifest.attestation?.verified !== true) {
      items.push({
        binding_id: binding.id,
        connector_id: binding.connector_id,
        issue: 'attestation_invalid',
        unknown_scopes: [],
        detected_at: nowIso()
      });
    }

    const unknownScopes = binding.scopes.filter(
      (scope) => !manifest.capabilities.includes(scope)
    );

    if (unknownScopes.length) {
      items.push({
        binding_id: binding.id,
        connector_id: binding.connector_id,
        issue: 'scope_not_declared',
        unknown_scopes: unknownScopes,
        detected_at: nowIso()
      });
    }
  }

  return {
    generated_at: nowIso(),
    total: items.length,
    items
  };
}

export function buildConnectorHealthSummary({ manifests, bindings, connectorId }) {
  const manifestIds = Object.keys(manifests);
  const bindingIds = bindings.map((binding) => binding.connector_id);
  const allConnectorIds = uniqueSorted([...manifestIds, ...bindingIds]).filter((id) =>
    connectorId ? id === connectorId : true
  );

  const items = allConnectorIds.map((id) => {
    const manifest = manifests[id];
    const relatedBindings = bindings.filter((binding) => binding.connector_id === id);
    const activeBindings = relatedBindings.filter((binding) => binding.status === 'active');
    const attestationValid = manifest ? manifest.attestation?.verified === true : false;

    let driftCount = 0;
    if (!manifest && relatedBindings.length) {
      driftCount = relatedBindings.length;
    } else if (manifest) {
      for (const binding of relatedBindings) {
        driftCount += binding.scopes.filter((scope) => !manifest.capabilities.includes(scope)).length;
      }
    }

    const status = !manifest && relatedBindings.length
      ? 'degraded'
      : driftCount > 0 || !attestationValid
        ? 'degraded'
        : 'healthy';

    return {
      connector_id: id,
      status,
      manifest_loaded: Boolean(manifest),
      attestation_key_id: manifest?.attestation?.key_id || 'unknown',
      attestation_valid: attestationValid,
      protocol: manifest?.protocol || 'unknown',
      trust_level: manifest?.trust_level || 'unknown',
      category: manifest?.category || 'unknown',
      binding_count: relatedBindings.length,
      active_binding_count: activeBindings.length,
      drift_count: driftCount
    };
  });

  return {
    generated_at: nowIso(),
    total: items.length,
    healthy: items.filter((item) => item.status === 'healthy').length,
    degraded: items.filter((item) => item.status === 'degraded').length,
    items
  };
}

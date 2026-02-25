import crypto from 'node:crypto';

const INCIDENT_EXPORT_ALGORITHM = 'HMAC-SHA256';
const KEY_ID_PATTERN = /^exp_[A-Za-z0-9_-]{4,64}$/;
const SHA256_TAG_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE_PATTERN = /^[a-f0-9]{64}$/;

export const DEFAULT_INCIDENT_EXPORT_SIGN_KEYS = Object.freeze({
  exp_dev_main_v1: 'flockmesh-dev-incident-export-key-v1'
});

function sha256Hex(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function hmacSha256Hex(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function normalizeForJson(value) {
  if (Array.isArray(value)) {
    return value.map((item) => (item === undefined ? null : normalizeForJson(item)));
  }

  if (value && typeof value === 'object') {
    const normalized = {};
    for (const key of Object.keys(value)) {
      const item = value[key];
      if (item === undefined) continue;
      normalized[key] = normalizeForJson(item);
    }
    return normalized;
  }

  return value;
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

export function buildIncidentExportPayloadHash(payload) {
  return `sha256:${sha256Hex(stableSerialize(normalizeForJson(payload)))}`;
}

export function resolveIncidentExportSigningKeys({ overrideKeys } = {}) {
  const keys = { ...DEFAULT_INCIDENT_EXPORT_SIGN_KEYS };
  const envRaw = process.env.FLOCKMESH_INCIDENT_EXPORT_SIGN_KEYS;

  if (envRaw) {
    let parsed;
    try {
      parsed = JSON.parse(envRaw);
    } catch {
      throw new Error('FLOCKMESH_INCIDENT_EXPORT_SIGN_KEYS must be valid JSON object');
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('FLOCKMESH_INCIDENT_EXPORT_SIGN_KEYS must be a JSON object');
    }

    for (const [keyId, secret] of Object.entries(parsed)) {
      if (!KEY_ID_PATTERN.test(keyId)) {
        throw new Error(`FLOCKMESH_INCIDENT_EXPORT_SIGN_KEYS has invalid key id: ${keyId}`);
      }
      if (typeof secret !== 'string' || !secret.length) {
        throw new Error(`FLOCKMESH_INCIDENT_EXPORT_SIGN_KEYS has invalid secret for ${keyId}`);
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

export function resolveIncidentExportSigningConfig({
  overrideKeys,
  keyId
} = {}) {
  const keys = resolveIncidentExportSigningKeys({ overrideKeys });
  const resolvedKeyId = keyId || process.env.FLOCKMESH_INCIDENT_EXPORT_SIGN_KEY_ID || 'exp_dev_main_v1';

  if (!KEY_ID_PATTERN.test(resolvedKeyId)) {
    throw new Error(`Invalid incident export signing key id: ${resolvedKeyId}`);
  }

  if (!keys[resolvedKeyId]) {
    throw new Error(`Incident export signing key not configured: ${resolvedKeyId}`);
  }

  return {
    algorithm: INCIDENT_EXPORT_ALGORITHM,
    key_id: resolvedKeyId,
    keys
  };
}

export function signIncidentExportPayload(payload, {
  keyId,
  keys,
  algorithm = INCIDENT_EXPORT_ALGORITHM
} = {}) {
  if (algorithm !== INCIDENT_EXPORT_ALGORITHM) {
    throw new Error(`Unsupported incident export algorithm: ${algorithm}`);
  }

  if (!KEY_ID_PATTERN.test(String(keyId || ''))) {
    throw new Error(`Invalid incident export key id: ${keyId}`);
  }

  const secret = keys?.[keyId];
  if (!secret) {
    throw new Error(`Missing incident export key secret for key id: ${keyId}`);
  }

  const payloadHash = buildIncidentExportPayloadHash(payload);
  const signature = hmacSha256Hex(secret, payloadHash);

  return {
    algorithm,
    key_id: keyId,
    payload_hash: payloadHash,
    signature
  };
}

export function verifyIncidentExportSignature(payload, signatureEnvelope, {
  keys
} = {}) {
  if (!signatureEnvelope || typeof signatureEnvelope !== 'object' || Array.isArray(signatureEnvelope)) {
    throw new Error('incident export signature envelope must be an object');
  }

  if (signatureEnvelope.algorithm !== INCIDENT_EXPORT_ALGORITHM) {
    throw new Error(`Unsupported incident export signature algorithm: ${signatureEnvelope.algorithm}`);
  }

  if (!KEY_ID_PATTERN.test(String(signatureEnvelope.key_id || ''))) {
    throw new Error('incident export signature key_id is invalid');
  }

  if (!SHA256_TAG_PATTERN.test(String(signatureEnvelope.payload_hash || ''))) {
    throw new Error('incident export payload_hash format is invalid');
  }

  if (!SIGNATURE_PATTERN.test(String(signatureEnvelope.signature || ''))) {
    throw new Error('incident export signature format is invalid');
  }

  const secret = keys?.[signatureEnvelope.key_id];
  if (!secret) {
    throw new Error(`incident export signature key not configured: ${signatureEnvelope.key_id}`);
  }

  const expectedPayloadHash = buildIncidentExportPayloadHash(payload);
  if (signatureEnvelope.payload_hash !== expectedPayloadHash) {
    throw new Error('incident export payload hash mismatch');
  }

  const expectedSignature = hmacSha256Hex(secret, expectedPayloadHash);
  if (signatureEnvelope.signature !== expectedSignature) {
    throw new Error('incident export signature mismatch');
  }

  return true;
}

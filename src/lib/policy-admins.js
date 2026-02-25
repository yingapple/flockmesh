import fs from 'node:fs/promises';
import path from 'node:path';

const PROFILE_NAME_PATTERN = /^[a-z][a-z0-9_]{2,80}$/;
const USER_ID_PATTERN = /^usr_[A-Za-z0-9_-]{4,64}$/;

export const DEFAULT_POLICY_ADMIN_CONFIG = Object.freeze({
  version: 'v0',
  global_admins: ['usr_policy_admin'],
  profile_admins: {}
});

function assertObject(value, label, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[${source}] ${label} must be an object`);
  }
}

function normalizeAdminList(input = [], { source, label }) {
  if (!Array.isArray(input)) {
    throw new Error(`[${source}] ${label} must be an array`);
  }

  const admins = Array.from(new Set(input.map((value) => String(value || '').trim()).filter(Boolean))).sort();
  for (const actorId of admins) {
    if (!USER_ID_PATTERN.test(actorId)) {
      throw new Error(`[${source}] ${label} has invalid actor id: ${actorId}`);
    }
  }
  return admins;
}

function cloneConfig(config) {
  return {
    version: 'v0',
    global_admins: [...(config.global_admins || [])].sort(),
    profile_admins: Object.fromEntries(
      Object.entries(config.profile_admins || {})
        .map(([profileName, admins]) => [profileName, [...admins].sort()])
    )
  };
}

export function compilePolicyAdminConfigDocument(document, { source = 'memory' } = {}) {
  assertObject(document, 'document', source);

  if (document.version !== 'v0') {
    throw new Error(`[${source}] unsupported policy admin config version: ${document.version}`);
  }

  const globalAdmins = normalizeAdminList(
    document.global_admins || [],
    { source, label: 'global_admins' }
  );

  const profileAdminsInput = document.profile_admins || {};
  assertObject(profileAdminsInput, 'profile_admins', source);
  const profileAdmins = {};

  for (const [profileNameRaw, actors] of Object.entries(profileAdminsInput)) {
    const profileName = String(profileNameRaw || '').trim();
    if (!PROFILE_NAME_PATTERN.test(profileName)) {
      throw new Error(`[${source}] profile_admins has invalid profile name: ${profileName}`);
    }
    profileAdmins[profileName] = normalizeAdminList(actors, {
      source,
      label: `profile_admins.${profileName}`
    });
  }

  return {
    version: 'v0',
    global_admins: globalAdmins,
    profile_admins: profileAdmins
  };
}

export function mergePolicyAdminConfigs(configs = []) {
  const merged = cloneConfig(DEFAULT_POLICY_ADMIN_CONFIG);

  for (const config of configs) {
    if (!config) continue;

    const compiled = compilePolicyAdminConfigDocument({
      version: config.version || 'v0',
      global_admins: config.global_admins || [],
      profile_admins: config.profile_admins || {}
    }, {
      source: 'policy-admin-config.merge'
    });

    merged.global_admins = Array.from(
      new Set([...merged.global_admins, ...compiled.global_admins])
    ).sort();

    for (const [profileName, admins] of Object.entries(compiled.profile_admins)) {
      const existing = merged.profile_admins[profileName] || [];
      merged.profile_admins[profileName] = Array.from(
        new Set([...existing, ...admins])
      ).sort();
    }
  }

  return merged;
}

export async function loadPolicyAdminConfigFromDir({
  rootDir,
  dirName = path.join('policies', 'policy-admins')
} = {}) {
  const directoryPath = path.join(rootDir, dirName);
  let entries = [];

  try {
    entries = await fs.readdir(directoryPath, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return cloneConfig(DEFAULT_POLICY_ADMIN_CONFIG);
    throw err;
  }

  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.policy-admins.json'))
    .map((entry) => entry.name)
    .sort();

  const compiled = [];
  for (const fileName of files) {
    const filePath = path.join(directoryPath, fileName);
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    compiled.push(compilePolicyAdminConfigDocument(parsed, { source: fileName }));
  }

  return mergePolicyAdminConfigs(compiled);
}

export function canActorManagePolicyProfile({
  config,
  actorId,
  profileName
}) {
  const actor = String(actorId || '').trim();
  if (!USER_ID_PATTERN.test(actor)) {
    return {
      allowed: false,
      reason_code: 'policy.admin.invalid_actor'
    };
  }

  const profile = String(profileName || '').trim();
  if (!PROFILE_NAME_PATTERN.test(profile)) {
    return {
      allowed: false,
      reason_code: 'policy.admin.invalid_profile'
    };
  }

  const normalized = mergePolicyAdminConfigs([config]);
  if (normalized.global_admins.includes(actor)) {
    return {
      allowed: true,
      scope: 'global'
    };
  }

  const profileAdmins = normalized.profile_admins[profile] || [];
  if (profileAdmins.includes(actor)) {
    return {
      allowed: true,
      scope: 'profile'
    };
  }

  return {
    allowed: false,
    reason_code: 'policy.admin.not_authorized'
  };
}

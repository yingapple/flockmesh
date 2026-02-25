import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canActorManagePolicyProfile,
  compilePolicyAdminConfigDocument,
  mergePolicyAdminConfigs
} from '../src/lib/policy-admins.js';

test('compilePolicyAdminConfigDocument normalizes admin config', () => {
  const compiled = compilePolicyAdminConfigDocument({
    version: 'v0',
    global_admins: ['usr_policy_admin', 'usr_policy_admin', 'usr_yingapple'],
    profile_admins: {
      workspace_ops_cn: ['usr_ops_reviewer', 'usr_ops_reviewer']
    }
  }, { source: 'test.policy-admins' });

  assert.deepEqual(compiled.global_admins, ['usr_policy_admin', 'usr_yingapple']);
  assert.deepEqual(compiled.profile_admins.workspace_ops_cn, ['usr_ops_reviewer']);
});

test('canActorManagePolicyProfile enforces global/profile owner scopes', () => {
  const config = mergePolicyAdminConfigs([
    {
      version: 'v0',
      global_admins: ['usr_global_admin'],
      profile_admins: {
        workspace_ops_cn: ['usr_profile_admin']
      }
    }
  ]);

  const globalAllowed = canActorManagePolicyProfile({
    config,
    actorId: 'usr_global_admin',
    profileName: 'workspace_ops_cn'
  });
  assert.equal(globalAllowed.allowed, true);
  assert.equal(globalAllowed.scope, 'global');

  const profileAllowed = canActorManagePolicyProfile({
    config,
    actorId: 'usr_profile_admin',
    profileName: 'workspace_ops_cn'
  });
  assert.equal(profileAllowed.allowed, true);
  assert.equal(profileAllowed.scope, 'profile');

  const denied = canActorManagePolicyProfile({
    config,
    actorId: 'usr_non_admin',
    profileName: 'workspace_ops_cn'
  });
  assert.equal(denied.allowed, false);
  assert.equal(denied.reason_code, 'policy.admin.not_authorized');
});

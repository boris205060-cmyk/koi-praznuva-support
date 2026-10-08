import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AccountDeletionError,
  deleteAuthenticatedAccount,
  isConfiguredFirebaseWebApp,
} from './deletion-core.mjs';

function fixture(overrides = {}) {
  const calls = [];
  const user = { uid: 'user-1' };
  return {
    calls,
    options: {
      user,
      providerId: 'google.com',
      reauthenticate: async () => {
        calls.push('reauthenticate');
        return { user };
      },
      deleteCloudData: async (uid) => calls.push(`cloud:${uid}`),
      revokeAppleToken: async (token) => calls.push(`revoke:${token}`),
      deleteAuthUser: async (verifiedUser) =>
        calls.push(`auth:${verifiedUser.uid}`),
      ...overrides,
    },
  };
}

test('successful deletion removes cloud data before the Auth user', async () => {
  const { calls, options } = fixture();
  await deleteAuthenticatedAccount(options);
  assert.deepEqual(calls, [
    'reauthenticate',
    'cloud:user-1',
    'auth:user-1',
  ]);
});

test('cancelled reauthentication leaves all data untouched', async () => {
  const { calls, options } = fixture({
    reauthenticate: async () => {
      calls.push('cancelled');
      throw Object.assign(new Error('cancelled'), {
        code: 'auth/popup-closed-by-user',
      });
    },
  });
  await assert.rejects(deleteAuthenticatedAccount(options));
  assert.deepEqual(calls, ['cancelled']);
});

test('a different reauthenticated UID cannot be deleted', async () => {
  const { calls, options } = fixture({
    reauthenticate: async () => ({ user: { uid: 'user-2' } }),
  });
  await assert.rejects(
    deleteAuthenticatedAccount(options),
    (error) =>
      error instanceof AccountDeletionError &&
      error.code === 'account-mismatch',
  );
  assert.deepEqual(calls, []);
});

test('network failure during cloud deletion does not delete Auth user', async () => {
  const { calls, options } = fixture({
    deleteCloudData: async () => {
      calls.push('cloud-failed');
      throw Object.assign(new Error('offline'), { code: 'unavailable' });
    },
  });
  await assert.rejects(deleteAuthenticatedAccount(options));
  assert.deepEqual(calls, ['reauthenticate', 'cloud-failed']);
});

test('partial cloud success can be retried idempotently', async () => {
  let attempt = 0;
  const { calls, options } = fixture({
    deleteCloudData: async (uid) => {
      attempt += 1;
      calls.push(`cloud-${attempt}:${uid}`);
      if (attempt === 1) throw new Error('partial batch failure');
    },
  });
  await assert.rejects(deleteAuthenticatedAccount(options));
  await deleteAuthenticatedAccount(options);
  assert.deepEqual(calls, [
    'reauthenticate',
    'cloud-1:user-1',
    'reauthenticate',
    'cloud-2:user-1',
    'auth:user-1',
  ]);
});

test('Auth deletion failure is reported after cloud cleanup and can retry', async () => {
  let authAttempt = 0;
  const { calls, options } = fixture({
    deleteAuthUser: async (verifiedUser) => {
      authAttempt += 1;
      calls.push(`auth-${authAttempt}:${verifiedUser.uid}`);
      if (authAttempt === 1) throw new Error('temporary Auth failure');
    },
  });
  await assert.rejects(deleteAuthenticatedAccount(options));
  await deleteAuthenticatedAccount(options);
  assert.deepEqual(calls, [
    'reauthenticate',
    'cloud:user-1',
    'auth-1:user-1',
    'reauthenticate',
    'cloud:user-1',
    'auth-2:user-1',
  ]);
});

test('Apple token is revoked before the Auth user is deleted', async () => {
  const { calls, options } = fixture({
    providerId: 'apple.com',
    reauthenticate: async () => {
      calls.push('reauthenticate');
      return { user: { uid: 'user-1' }, accessToken: 'apple-token' };
    },
  });
  await deleteAuthenticatedAccount(options);
  assert.deepEqual(calls, [
    'reauthenticate',
    'cloud:user-1',
    'revoke:apple-token',
    'auth:user-1',
  ]);
});

test('Firebase config must identify the existing project and Web app', () => {
  assert.equal(isConfiguredFirebaseWebApp({}), false);
  assert.equal(
    isConfiguredFirebaseWebApp({
      apiKey: 'public-web-key',
      appId: '1:220982322770:web:example',
      authDomain: 'koi-praznuva.firebaseapp.com',
      projectId: 'koi-praznuva',
    }),
    true,
  );
});

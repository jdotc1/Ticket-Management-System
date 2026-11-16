const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');
const { completeReset, PasswordResetError } = require('../utils/password-reset');

test('expired or unknown reset tokens are rejected before hashing or opening a transaction', async (t) => {
  const hash = t.mock.method(bcrypt, 'hash', async () => 'unused-hash');
  const query = t.mock.method(db, 'query', async () => ({ rows: [] }));
  const transaction = t.mock.method(db, 'withTransaction', async () => {
    throw new Error('no transaction expected');
  });

  await assert.rejects(completeReset('expired-link', 'valid-new-password'), (error) =>
    error instanceof PasswordResetError && error.status === 400 && /invalid or has expired/.test(error.message));

  assert.equal(query.mock.callCount(), 1);
  assert.match(query.mock.calls[0].arguments[0], /SELECT.*password_reset_tokens/s);
  assert.match(query.mock.calls[0].arguments[0], /used_at IS NULL AND expires_at > now\(\)/);
  assert.equal(hash.mock.callCount(), 0);
  assert.equal(transaction.mock.callCount(), 0);
});

test('valid reset hashes asynchronously, claims token, revokes sessions, and returns owner', async (t) => {
  const calls = [];
  t.mock.method(db, 'query', async () => ({ rows: [{ owner_type: 'admin', owner_id: 'ADM-1' }] }));
  const hash = t.mock.method(bcrypt, 'hash', async (...args) => {
    calls.push('hash');
    assert.deepEqual(args, ['valid-new-password', 10]);
    return 'hashed-new-password';
  });
  const client = {
    query: async (sql, params) => {
      calls.push(sql.match(/^(?:UPDATE|SELECT)\s+(\w+)/)[1]);
      if (/UPDATE password_reset_tokens SET used_at/.test(sql)) return { rows: [{ owner_type: 'admin', owner_id: 'ADM-1' }] };
      if (/UPDATE auth_credentials/.test(sql)) {
        assert.equal(params[0], 'hashed-new-password');
        return { rows: [{ id: 'cred-1' }] };
      }
      if (/SELECT id, email/.test(sql)) return { rows: [{ id: 'ADM-1', email: 'admin@example.org', full_name: 'Admin' }] };
      return { rows: [] };
    }
  };
  const transaction = t.mock.method(db, 'withTransaction', (work) => work(client));

  const owner = await completeReset('valid-link', 'valid-new-password');
  assert.deepEqual(owner, { ownerType: 'admin', id: 'ADM-1', email: 'admin@example.org', full_name: 'Admin' });
  assert.equal(hash.mock.callCount(), 1);
  assert.equal(transaction.mock.callCount(), 1);
  assert.deepEqual(calls, ['hash', 'password_reset_tokens', 'auth_credentials', 'password_reset_tokens', 'admins', 'id']);
});

test('token claimed by another request still fails atomically', async (t) => {
  const hash = t.mock.method(bcrypt, 'hash', async () => 'hashed-new-password');
  t.mock.method(db, 'query', async () => ({ rows: [{}] }));
  const client = { query: t.mock.fn(async () => ({ rows: [] })) };
  t.mock.method(db, 'withTransaction', (work) => work(client));

  await assert.rejects(completeReset('replayed-link', 'valid-new-password'), (error) =>
    error instanceof PasswordResetError && error.status === 400);
  assert.equal(hash.mock.callCount(), 1);
  assert.equal(client.query.mock.callCount(), 1);
});

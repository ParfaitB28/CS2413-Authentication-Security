'use strict';

// Tests for the hashing and strength code.
// Run with: node --test

const test = require('node:test');
const assert = require('node:assert');

const { hashPassword, verifyPassword } = require('../src/security/hashing');
const strength = require('../src/security/passwordStrength');
const { SCHEMES } = require('../src/security/config');

test('bcrypt: correct password verifies, wrong one fails', async () => {
  const h = await hashPassword('correct-horse-battery-staple-7', { scheme: SCHEMES.BCRYPT, bcryptCost: 8 });
  assert.strictEqual(await verifyPassword('correct-horse-battery-staple-7', h), true);
  assert.strictEqual(await verifyPassword('wrong', h), false);
});

test('argon2: correct password verifies', async () => {
  const h = await hashPassword('Gx9$kLm2@qZr4!vW', { scheme: SCHEMES.ARGON2 });
  assert.strictEqual(await verifyPassword('Gx9$kLm2@qZr4!vW', h), true);
});

test('salt works: same password gives different hashes', async () => {
  const a = await hashPassword('samePassword123!', { scheme: SCHEMES.BCRYPT, bcryptCost: 8 });
  const b = await hashPassword('samePassword123!', { scheme: SCHEMES.BCRYPT, bcryptCost: 8 });
  assert.notStrictEqual(a.hash, b.hash);
});

test('baseline has no salt: same password gives the same hash', async () => {
  const a = await hashPassword('samePassword123!', { scheme: SCHEMES.BASELINE });
  const b = await hashPassword('samePassword123!', { scheme: SCHEMES.BASELINE });
  assert.strictEqual(a.hash, b.hash);
});

test('strength check rejects weak and breached passwords', () => {
  assert.strictEqual(strength.evaluate('password').ok, false);
  assert.strictEqual(strength.evaluate('123456').ok, false);
  assert.strictEqual(strength.evaluate('short').ok, false);
});

test('strength check accepts a strong password', () => {
  const r = strength.evaluate('vT#8pR^2mNb5&xQ1zL');
  assert.strictEqual(r.ok, true);
  assert.ok(r.score >= 3);
});

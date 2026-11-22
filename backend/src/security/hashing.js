'use strict';

// Password hashing.
// This handles three ways of hashing so we can compare them:
//   'sha256-unsalted' - fast, no salt. This is the weak one we test against.
//   'bcrypt'          - slow hash with a built-in salt and an adjustable cost.
//   'argon2'          - argon2id, slow and memory-hard.
// If a pepper is set (see config), it gets mixed into the password before
// hashing. The pepper is kept outside the database, so stealing just the DB
// isn't enough to crack anything.

const crypto = require('crypto');
const { promisify } = require('util');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const config = require('./config');

const scryptAsync = promisify(crypto.scrypt);

// Mix in the pepper if one is set, otherwise just return the password as-is.
function applyPepper(password) {
  if (!config.PEPPER) return password;
  return crypto.createHmac('sha256', config.PEPPER).update(password).digest('hex');
}

// Hash a password with whichever scheme is picked.
// Returns the scheme used, the hash, and the params so the experiments can log them.
async function hashPassword(password, opts = {}) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('password must be a non-empty string');
  }
  const scheme = opts.scheme || config.ACTIVE_SCHEME;
  const material = applyPepper(password);

  if (scheme === config.SCHEMES.BASELINE) {
    // Fast unsalted SHA-256 on purpose - this is the weak baseline.
    const hash = crypto.createHash('sha256').update(material).digest('hex');
    return { scheme, hash, salt: null, params: {} };
  }

  if (scheme === config.SCHEMES.BCRYPT) {
    const cost = opts.bcryptCost || config.BCRYPT_COST;
    // bcrypt makes its own random salt and puts it inside the output string.
    const hash = await bcrypt.hash(material, cost);
    return { scheme, hash, salt: 'embedded', params: { cost } };
  }

  if (scheme === config.SCHEMES.ARGON2) {
    const p = opts.argon2 || config.ARGON2;
    const hash = await argon2.hash(material, {
      type: argon2.argon2id,
      memoryCost: p.memoryCost,
      timeCost: p.timeCost,
      parallelism: p.parallelism,
    });
    return { scheme, hash, salt: 'embedded', params: p };
  }

  throw new Error(`unknown scheme: ${scheme}`);
}

// Check a password against a record we made with hashPassword (used by tests).
async function verifyPassword(password, record) {
  if (!record || typeof record.hash !== 'string') return false;
  const material = applyPepper(password);
  const scheme = record.scheme;

  if (scheme === config.SCHEMES.BASELINE) {
    const candidate = crypto.createHash('sha256').update(material).digest('hex');
    // compare in constant time even though this scheme is weak
    const a = Buffer.from(candidate, 'hex');
    const b = Buffer.from(record.hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  if (scheme === config.SCHEMES.BCRYPT) {
    return bcrypt.compare(material, record.hash);
  }

  if (scheme === config.SCHEMES.ARGON2) {
    return argon2.verify(record.hash, material);
  }

  return false;
}

// ---- helpers the actual app (register / login) uses ----
//
// The users table stores one string in password_hash. We can tell the format
// from how it starts:
//   "$2b$..."        -> bcrypt (new accounts, the default)
//   "$argon2id$..."  -> argon2 (new accounts if AUTH_SCHEME=argon2)
//   "scrypt:salt:hash" -> old accounts from before this change
// verifyAgainstStorage looks at the start of the string, so old accounts still
// log in while new ones use the stronger hashing.

// Keep one dummy hash around so that logging in with an email that doesn't
// exist still takes about as long as a real check (so you can't tell which
// emails are registered from the response time).
let dummyHashPromise;
function getDummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = bcrypt.hash('invalid-placeholder-password', config.BCRYPT_COST);
  }
  return dummyHashPromise;
}

// Make the string to save in password_hash for a new account.
async function hashForStorage(password) {
  const scheme = config.ACTIVE_SCHEME === config.SCHEMES.ARGON2
    ? config.SCHEMES.ARGON2
    : config.SCHEMES.BCRYPT;
  const r = await hashPassword(password, { scheme });
  return r.hash; // the bcrypt/argon2 string already says which one it is
}

// Check a password against whatever is stored, in any of the formats above.
// Always runs a hash (even when the user is missing) to keep the timing even.
async function verifyAgainstStorage(password, stored) {
  if (typeof stored !== 'string' || stored.length === 0) {
    await bcrypt.compare(String(password), await getDummyHash());
    return false;
  }

  const material = applyPepper(password);

  if (stored.startsWith('$2a$') || stored.startsWith('$2b$') || stored.startsWith('$2y$')) {
    return bcrypt.compare(material, stored);
  }

  if (stored.startsWith('$argon2')) {
    return argon2.verify(stored, material);
  }

  if (stored.startsWith('scrypt:')) {
    // old accounts were hashed from the raw password (there was no pepper then)
    const [, saltHex, hashHex] = stored.split(':');
    if (!saltHex || !hashHex) return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scryptAsync(password, salt, expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  }

  return false;
}

module.exports = {
  hashPassword,
  verifyPassword,
  applyPepper,
  hashForStorage,
  verifyAgainstStorage,
};

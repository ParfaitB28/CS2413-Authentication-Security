'use strict';

/**
 * hashing.js — Mady's core deliverable.
 *
 * Provides one unified interface over three schemes so the login app and the
 * experiment harness can switch with a single flag:
 *
 *   - 'sha256-unsalted'  Build A baseline. Fast, no salt. INTENTIONALLY WEAK.
 *   - 'bcrypt'           Build B. Per-user salt baked into the hash, tunable cost.
 *   - 'argon2'           Build B. Memory-hard argon2id, tunable memory/time/parallelism.
 *
 * Pepper: when configured, a secret key is HMAC'd into the password BEFORE the
 * slow hash. The pepper lives outside the DB, so a database-only breach yields
 * nothing crackable (hypothesis H5).
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const config = require('./config');

/**
 * Apply the optional pepper. Returns the password unchanged when no pepper is
 * set, so the "with vs without pepper" comparison stays controlled.
 * @param {string} password
 * @returns {string} peppered material (hex) or the original password
 */
function applyPepper(password) {
  if (!config.PEPPER) return password;
  return crypto.createHmac('sha256', config.PEPPER).update(password).digest('hex');
}

/**
 * Hash a password under a chosen scheme.
 * @param {string} password
 * @param {object} [opts]
 * @param {string} [opts.scheme] one of config.SCHEMES values
 * @param {number} [opts.bcryptCost]
 * @param {object} [opts.argon2] {memoryCost,timeCost,parallelism}
 * @returns {Promise<{scheme:string, hash:string, salt:(string|null), params:object}>}
 */
async function hashPassword(password, opts = {}) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('password must be a non-empty string');
  }
  const scheme = opts.scheme || config.ACTIVE_SCHEME;
  const material = applyPepper(password);

  if (scheme === config.SCHEMES.BASELINE) {
    // Build A: fast, unsalted SHA-256. No work factor, no salt on purpose.
    const hash = crypto.createHash('sha256').update(material).digest('hex');
    return { scheme, hash, salt: null, params: {} };
  }

  if (scheme === config.SCHEMES.BCRYPT) {
    const cost = opts.bcryptCost || config.BCRYPT_COST;
    // bcrypt generates a random 16-byte salt and embeds it in the output string.
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

/**
 * Verify a password against a stored record.
 * @param {string} password
 * @param {{scheme:string, hash:string}} record
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, record) {
  if (!record || typeof record.hash !== 'string') return false;
  const material = applyPepper(password);
  const scheme = record.scheme;

  if (scheme === config.SCHEMES.BASELINE) {
    const candidate = crypto.createHash('sha256').update(material).digest('hex');
    // constant-time compare even for the weak scheme
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

module.exports = { hashPassword, verifyPassword, applyPepper };

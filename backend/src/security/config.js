'use strict';

/**
 * Central config for the two builds.
 *
 * Build A (baseline)  -> scheme: 'sha256-unsalted'   (deliberately weak)
 * Build B (hardened)  -> scheme: 'bcrypt' or 'argon2' (salted, slow, + optional pepper)
 *
 * Flip ACTIVE_SCHEME (or the AUTH_SCHEME env var) to switch which one the
 * login app runs with. Every control is isolated so experiments can toggle
 * one layer at a time.
 */

const SCHEMES = {
  BASELINE: 'sha256-unsalted', // Build A
  BCRYPT: 'bcrypt',            // Build B (default)
  ARGON2: 'argon2',            // Build B (alternative)
};

module.exports = {
  SCHEMES,

  // Which scheme the running app uses. Override with AUTH_SCHEME=sha256-unsalted etc.
  ACTIVE_SCHEME: process.env.AUTH_SCHEME || SCHEMES.BCRYPT,

  // bcrypt work factor (cost). 10 is a sane default; experiments sweep 8..14.
  BCRYPT_COST: parseInt(process.env.BCRYPT_COST || '12', 10),

  // argon2id parameters. Swept in experiments.
  ARGON2: {
    memoryCost: parseInt(process.env.ARGON2_MEM || String(19 * 1024), 10), // KiB (~19 MiB)
    timeCost: parseInt(process.env.ARGON2_TIME || '2', 10),
    parallelism: parseInt(process.env.ARGON2_PAR || '1', 10),
  },

  // Optional pepper: a secret applied IN ADDITION to the per-user salt and
  // stored OUTSIDE the database (here: env var). A DB-only breach can't use it.
  // Leave empty to disable (so the "with vs without pepper" experiment is clean).
  PEPPER: process.env.AUTH_PEPPER || '',

  // Password-strength policy
  STRENGTH: {
    minLength: 8,
    minZxcvbnScore: 3, // 0..4; require "safely unguessable"
  },
};

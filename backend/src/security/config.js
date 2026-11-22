'use strict';

// Settings for the login/hashing code.
// There are two setups we compare:
//   baseline -> 'sha256-unsalted' (fast, no salt - the weak one)
//   hardened -> 'bcrypt' or 'argon2' (salted, slow, optional pepper)
// You can switch which one the app uses with the AUTH_SCHEME env variable.

const SCHEMES = {
  BASELINE: 'sha256-unsalted', // weak baseline
  BCRYPT: 'bcrypt',            // default
  ARGON2: 'argon2',            // alternative
};

module.exports = {
  SCHEMES,

  // Which scheme the app uses. Change with AUTH_SCHEME=sha256-unsalted etc.
  ACTIVE_SCHEME: process.env.AUTH_SCHEME || SCHEMES.BCRYPT,

  // bcrypt cost. Higher = slower = harder to crack. We tried 8..14 in testing.
  BCRYPT_COST: parseInt(process.env.BCRYPT_COST || '12', 10),

  // argon2id settings.
  ARGON2: {
    memoryCost: parseInt(process.env.ARGON2_MEM || String(19 * 1024), 10), // in KiB (~19 MiB)
    timeCost: parseInt(process.env.ARGON2_TIME || '2', 10),
    parallelism: parseInt(process.env.ARGON2_PAR || '1', 10),
  },

  // Optional pepper: an extra secret mixed in on top of the salt, kept out of
  // the database (in an env var). If someone only steals the DB they still
  // can't crack anything. Leave blank to turn it off.
  PEPPER: process.env.AUTH_PEPPER || '',

  // Password strength rules.
  STRENGTH: {
    minLength: 8,
    minZxcvbnScore: 3, // zxcvbn score is 0..4, we require at least 3
  },
};

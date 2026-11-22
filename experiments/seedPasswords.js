'use strict';

// Makes the test accounts used by the cracking experiments.
// Same weak/medium/strong passwords hashed with whichever scheme is set, so
// the results can be compared fairly. Saves to experiments/out/accounts.<scheme>.json
//
// Run it once per scheme, e.g. (PowerShell):
//   $env:AUTH_SCHEME="sha256-unsalted"; node seedPasswords.js
//   $env:AUTH_SCHEME="bcrypt"; node seedPasswords.js
//   $env:AUTH_SCHEME="argon2"; node seedPasswords.js

const fs = require('fs');
const path = require('path');
const { hashPassword } = require('../backend/src/security/hashing');
const config = require('../backend/src/security/config');

// Test passwords grouped by how strong they are.
const TEST_PASSWORDS = [
  { tier: 'weak', username: 'weak1', password: 'password' },
  { tier: 'weak', username: 'weak2', password: '123456' },
  { tier: 'weak', username: 'weak3', password: 'qwerty' },
  { tier: 'medium', username: 'med1', password: 'Summer2021' },
  { tier: 'medium', username: 'med2', password: 'Tiger!99' },
  { tier: 'medium', username: 'med3', password: 'letmein2024' },
  { tier: 'strong', username: 'strong1', password: 'correct-horse-battery-staple-7' },
  { tier: 'strong', username: 'strong2', password: 'Gx9$kLm2@qZr4!vW' },
  { tier: 'strong', username: 'strong3', password: 'vT#8pR^2mNb5&xQ1zL' },
];

async function main() {
  const outDir = path.join(__dirname, 'out');
  fs.mkdirSync(outDir, { recursive: true });
  const scheme = config.ACTIVE_SCHEME;

  const records = [];
  for (const row of TEST_PASSWORDS) {
    const h = await hashPassword(row.password, { scheme });
    records.push({
      username: row.username,
      tier: row.tier,
      plaintext: row.password, // only stored because these are fake test accounts
      scheme: h.scheme,
      hash: h.hash,
      params: h.params,
    });
  }

  const file = path.join(outDir, `accounts.${scheme}.json`);
  fs.writeFileSync(file, JSON.stringify(records, null, 2));
  console.log(`Wrote ${records.length} ${scheme} accounts -> ${file}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

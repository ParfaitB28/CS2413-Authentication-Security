'use strict';

/**
 * experiments/exportDump.js
 *
 * Simulates "attacker steals the database" by exporting each seeded account set
 * into the hash formats the cracking tools expect:
 *
 *   - sha256-unsalted -> out/dump.sha256.txt   (username:hexhash)  [Hashcat -m 1400]
 *   - bcrypt          -> out/dump.bcrypt.txt   ($2b$...)           [Hashcat -m 3200]
 *   - argon2          -> out/dump.argon2.txt   ($argon2id$...)     [John --format=argon2]
 *
 * Also prints what the attacker actually obtains, so the report can show the
 * difference between "plaintext/fast hash" and "salted slow hash".
 *
 * Usage:
 *   node experiments/exportDump.js            # exports every accounts.*.json found
 */

const fs = require('fs');
const path = require('path');

const outDir = path.join(__dirname, 'out');

function exportScheme(scheme) {
  const accFile = path.join(outDir, `accounts.${scheme}.json`);
  if (!fs.existsSync(accFile)) return null;
  const records = JSON.parse(fs.readFileSync(accFile, 'utf8'));

  const lines = records.map((r) => {
    if (scheme === 'sha256-unsalted') return `${r.username}:${r.hash}`;
    return `${r.username}:${r.hash}`; // bcrypt/argon2 strings already self-contained
  });

  const dumpFile = path.join(outDir, `dump.${scheme.replace('sha256-unsalted', 'sha256')}.txt`);
  fs.writeFileSync(dumpFile, lines.join('\n') + '\n');

  // What does the attacker see?
  const sample = records[0];
  const distinctHashes = new Set(records.map((r) => r.hash)).size;
  console.log(`\n[${scheme}] -> ${dumpFile}`);
  console.log(`  rows: ${records.length}, distinct hashes: ${distinctHashes}`);
  console.log(`  example: ${sample.username} -> ${String(sample.hash).slice(0, 48)}${sample.hash.length > 48 ? '…' : ''}`);

  // Salt check: do the two "weak" accounts that share a password collide?
  const byPlain = {};
  for (const r of records) (byPlain[r.plaintext] = byPlain[r.plaintext] || []).push(r.hash);
  const reused = Object.entries(byPlain).filter(([, hs]) => hs.length > 1);
  if (reused.length) {
    for (const [pw, hs] of reused) {
      const collide = new Set(hs).size === 1;
      console.log(`  reuse of "${pw}": hashes ${collide ? 'COLLIDE (no salt!)' : 'distinct (salt works)'}`);
    }
  }
  return dumpFile;
}

for (const scheme of ['sha256-unsalted', 'bcrypt', 'argon2']) {
  exportScheme(scheme);
}

console.log('\nCrack with, e.g.:');
console.log('  hashcat -m 1400 -a 0 out/dump.sha256.txt data/rockyou-sample.txt   # fast unsalted');
console.log('  hashcat -m 3200 -a 0 out/dump.bcrypt.txt data/rockyou-sample.txt   # bcrypt (slow)');
console.log('  john --format=argon2 --wordlist=data/rockyou-sample.txt out/dump.argon2.txt');

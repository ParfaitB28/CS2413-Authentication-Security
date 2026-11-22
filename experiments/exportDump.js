'use strict';

// Pretends an attacker stole the database. Takes the seeded accounts and writes
// them out in the formats cracking tools read:
//   sha256-unsalted -> out/dump.sha256.txt
//   bcrypt          -> out/dump.bcrypt.txt
//   argon2          -> out/dump.argon2.txt
// It also prints what the attacker would actually see for each one.
//
// Run: node exportDump.js

const fs = require('fs');
const path = require('path');

const outDir = path.join(__dirname, 'out');

function exportScheme(scheme) {
  const accFile = path.join(outDir, `accounts.${scheme}.json`);
  if (!fs.existsSync(accFile)) return null;
  const records = JSON.parse(fs.readFileSync(accFile, 'utf8'));

  const lines = records.map((r) => {
    if (scheme === 'sha256-unsalted') return `${r.username}:${r.hash}`;
    return `${r.username}:${r.hash}`; // bcrypt/argon2 strings already hold everything
  });

  const dumpFile = path.join(outDir, `dump.${scheme.replace('sha256-unsalted', 'sha256')}.txt`);
  fs.writeFileSync(dumpFile, lines.join('\n') + '\n');

  // Show what the attacker ends up with.
  const sample = records[0];
  const distinctHashes = new Set(records.map((r) => r.hash)).size;
  console.log(`\n[${scheme}] -> ${dumpFile}`);
  console.log(`  rows: ${records.length}, distinct hashes: ${distinctHashes}`);
  console.log(`  example: ${sample.username} -> ${String(sample.hash).slice(0, 48)}${sample.hash.length > 48 ? '…' : ''}`);

  // If any two accounts share a password, check whether their hashes match.
  // They match only when there's no salt, which is the point we're showing.
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

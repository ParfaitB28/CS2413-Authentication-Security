'use strict';

/**
 * crackDump.js — self-contained offline dictionary attack (Mady).
 *
 * Does the same job as Hashcat/John but in Node, so it runs anywhere bcrypt and
 * argon2 are installed. It loads the seeded accounts for a scheme, tries every
 * word in the wordlist against each stored hash, and reports:
 *   - % cracked overall and per strength tier
 *   - which accounts fell
 *   - total guesses, elapsed time, and effective guesses/sec
 *   - time-to-first-crack
 *
 * Usage (run from the experiments/ folder, after seedPasswords.js):
 *   node crackDump.js sha256-unsalted
 *   node crackDump.js bcrypt
 *   node crackDump.js argon2
 *
 * Matching is done on the plaintext in the seeded lab dataset, which is safe
 * here because these are known test passwords in a controlled experiment.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

async function matches(scheme, word, hash) {
  if (scheme === 'sha256-unsalted') {
    return crypto.createHash('sha256').update(word).digest('hex') === hash;
  }
  if (scheme === 'bcrypt') {
    return bcrypt.compare(word, hash);
  }
  if (scheme === 'argon2') {
    return argon2.verify(hash, word);
  }
  throw new Error(`unknown scheme: ${scheme}`);
}

async function main() {
  const scheme = process.argv[2];
  if (!scheme) {
    console.error('usage: node crackDump.js <sha256-unsalted|bcrypt|argon2>');
    process.exit(1);
  }

  const accFile = path.join(__dirname, 'out', `accounts.${scheme}.json`);
  const wordFile = path.join(__dirname, 'data', 'rockyou-sample.txt');

  if (!fs.existsSync(accFile)) {
    console.error(`missing ${accFile} — run seedPasswords.js for this scheme first`);
    process.exit(1);
  }

  const accounts = JSON.parse(fs.readFileSync(accFile, 'utf8'));
  const words = fs.readFileSync(wordFile, 'utf8')
    .split(/\r?\n/).map((w) => w.trim()).filter(Boolean);

  const tiers = {};
  const fell = [];
  let cracked = 0;
  let guesses = 0;
  let firstCrackMs = null;

  const start = process.hrtime.bigint();

  for (const acc of accounts) {
    tiers[acc.tier] = tiers[acc.tier] || { total: 0, cracked: 0 };
    tiers[acc.tier].total++;

    for (const word of words) {
      guesses++;
      if (await matches(scheme, word, acc.hash)) {
        cracked++;
        tiers[acc.tier].cracked++;
        fell.push(`${acc.username} (${acc.tier}) -> "${word}"`);
        if (firstCrackMs === null) {
          firstCrackMs = Number(process.hrtime.bigint() - start) / 1e6;
        }
        break;
      }
    }
  }

  const totalMs = Number(process.hrtime.bigint() - start) / 1e6;
  const total = accounts.length;
  const pct = (cr, to) => (to ? ((100 * cr) / to).toFixed(1) + '%' : 'n/a');
  const guessesPerSec = Math.round((guesses / totalMs) * 1000);

  console.log(`\nScheme: ${scheme}`);
  console.log(`Wordlist size: ${words.length}   Accounts: ${total}`);
  console.log(`Overall cracked: ${cracked}/${total} (${pct(cracked, total)})`);
  console.log('\nBy strength tier:');
  for (const tier of ['weak', 'medium', 'strong']) {
    if (tiers[tier]) {
      console.log(`  ${tier.padEnd(7)} ${tiers[tier].cracked}/${tiers[tier].total} (${pct(tiers[tier].cracked, tiers[tier].total)})`);
    }
  }
  console.log('\nTiming:');
  console.log(`  total guesses attempted : ${guesses}`);
  console.log(`  elapsed time            : ${(totalMs / 1000).toFixed(2)} s`);
  console.log(`  effective guesses/sec   : ${guessesPerSec.toLocaleString()}`);
  console.log(`  time-to-first-crack     : ${firstCrackMs === null ? 'none cracked' : (firstCrackMs / 1000).toFixed(3) + ' s'}`);

  if (fell.length) {
    console.log('\nAccounts recovered:');
    for (const f of fell) console.log(`  - ${f}`);
  } else {
    console.log('\nNo accounts recovered.');
  }

  const summary = {
    scheme,
    wordlistSize: words.length,
    total,
    cracked,
    crackedPct: total ? (100 * cracked) / total : 0,
    byTier: tiers,
    guesses,
    elapsedSec: totalMs / 1000,
    guessesPerSec,
    timeToFirstCrackSec: firstCrackMs === null ? null : firstCrackMs / 1000,
  };
  const outFile = path.join(__dirname, 'out', `crackresult.${scheme}.json`);
  fs.writeFileSync(outFile, JSON.stringify(summary, null, 2));
  console.log(`\nWrote ${outFile}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

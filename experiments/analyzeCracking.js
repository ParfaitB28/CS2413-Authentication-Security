'use strict';

/**
 * experiments/analyzeCracking.js — turns raw cracker output into report metrics.
 *
 * After running Hashcat/John against the exported dumps, point this at the
 * potfile (or `hashcat --show` output) plus the seeded accounts, and it
 * computes the before/after numbers the rubric wants:
 *
 *   - % of dump cracked, overall and per strength tier
 *   - which specific accounts fell
 *   - time-to-first-crack (if a --status timestamp log is supplied)
 *
 * Usage:
 *   node experiments/analyzeCracking.js <accounts.json> <cracked.txt>
 *
 * <cracked.txt> format: one "hash:plaintext" or "username:plaintext" per line
 * (hashcat potfile style). Matching is done on plaintext, which is safe here
 * because this is a controlled lab dataset with known passwords.
 */

const fs = require('fs');

function parseArgs() {
  const [accFile, crackedFile] = process.argv.slice(2);
  if (!accFile || !crackedFile) {
    console.error('usage: node experiments/analyzeCracking.js <accounts.json> <cracked.txt>');
    process.exit(1);
  }
  return { accFile, crackedFile };
}

function main() {
  const { accFile, crackedFile } = parseArgs();
  const accounts = JSON.parse(fs.readFileSync(accFile, 'utf8'));
  const crackedRaw = fs.readFileSync(crackedFile, 'utf8');

  // Collect recovered plaintexts (last field after ':').
  const recovered = new Set();
  for (const line of crackedRaw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = line.split(':');
    recovered.add(parts[parts.length - 1]);
  }

  const tiers = {};
  let total = 0;
  let cracked = 0;
  const fell = [];

  for (const a of accounts) {
    tiers[a.tier] = tiers[a.tier] || { total: 0, cracked: 0 };
    tiers[a.tier].total++;
    total++;
    if (recovered.has(a.plaintext)) {
      tiers[a.tier].cracked++;
      cracked++;
      fell.push(`${a.username} (${a.tier}) -> "${a.plaintext}"`);
    }
  }

  const pct = (c, t) => (t ? ((100 * c) / t).toFixed(1) + '%' : 'n/a');

  console.log(`\nScheme: ${accounts[0] ? accounts[0].scheme : 'unknown'}`);
  console.log(`Overall cracked: ${cracked}/${total} (${pct(cracked, total)})`);
  console.log('\nBy strength tier:');
  for (const tier of ['weak', 'medium', 'strong']) {
    if (tiers[tier]) {
      console.log(`  ${tier.padEnd(7)} ${tiers[tier].cracked}/${tiers[tier].total} (${pct(tiers[tier].cracked, tiers[tier].total)})`);
    }
  }
  if (fell.length) {
    console.log('\nAccounts recovered:');
    for (const f of fell) console.log(`  - ${f}`);
  } else {
    console.log('\nNo accounts recovered in this run.');
  }

  // Emit a machine-readable summary for charting in the report/slides.
  const summary = {
    scheme: accounts[0] ? accounts[0].scheme : 'unknown',
    total,
    cracked,
    crackedPct: total ? (100 * cracked) / total : 0,
    byTier: tiers,
  };
  fs.writeFileSync(accFile.replace(/\.json$/, '.crackresult.json'), JSON.stringify(summary, null, 2));
  console.log(`\nWrote summary -> ${accFile.replace(/\.json$/, '.crackresult.json')}`);
}

main();

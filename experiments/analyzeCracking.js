'use strict';

// Reads the output of Hashcat/John and turns it into numbers for the report:
// how many accounts were cracked overall and per strength tier, and which ones.
// (If you use crackDump.js instead of Hashcat, you don't need this.)
//
// Run: node analyzeCracking.js <accounts.json> <cracked.txt>
// cracked.txt is one "something:plaintext" per line (hashcat potfile style).

const fs = require('fs');

function parseArgs() {
  const [accFile, crackedFile] = process.argv.slice(2);
  if (!accFile || !crackedFile) {
    console.error('usage: node analyzeCracking.js <accounts.json> <cracked.txt>');
    process.exit(1);
  }
  return { accFile, crackedFile };
}

function main() {
  const { accFile, crackedFile } = parseArgs();
  const accounts = JSON.parse(fs.readFileSync(accFile, 'utf8'));
  const crackedRaw = fs.readFileSync(crackedFile, 'utf8');

  // grab the recovered passwords (last field after ':')
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

  // save a small summary file for making charts later
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

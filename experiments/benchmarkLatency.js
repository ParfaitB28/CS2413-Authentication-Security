'use strict';

// Measures how long one hash takes for each scheme and cost setting.
// A slower hash is better for security but costs the user a little time on
// login, so this shows that trade-off. It also works out how many guesses an
// attacker could do per second on one core (1000 / ms per hash).
//
// Run: node benchmarkLatency.js   (saves out/latency.json)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

const PASSWORD = 'correct-horse-battery-staple-7';
const REPS = 5;

async function timeAvg(fn, reps = REPS) {
  // run once first to warm up
  await fn();
  const start = process.hrtime.bigint();
  for (let i = 0; i < reps; i++) await fn();
  const end = process.hrtime.bigint();
  return Number(end - start) / 1e6 / reps; // ms per hash
}

async function main() {
  const rows = [];

  // baseline fast hash
  const sha = await timeAvg(() => {
    crypto.createHash('sha256').update(PASSWORD).digest('hex');
    return Promise.resolve();
  }, 1000);
  rows.push({ scheme: 'sha256-unsalted', param: '-', msPerHash: sha });

  // try a few bcrypt costs
  for (const cost of [8, 10, 12, 14]) {
    const ms = await timeAvg(() => bcrypt.hash(PASSWORD, cost));
    rows.push({ scheme: 'bcrypt', param: `cost=${cost}`, msPerHash: ms });
  }

  // try a few argon2 memory settings
  for (const mem of [19 * 1024, 46 * 1024, 64 * 1024]) {
    const ms = await timeAvg(() =>
      argon2.hash(PASSWORD, { type: argon2.argon2id, memoryCost: mem, timeCost: 2, parallelism: 1 })
    );
    rows.push({ scheme: 'argon2id', param: `mem=${Math.round(mem / 1024)}MiB,t=2`, msPerHash: ms });
  }

  // print the table with the guesses/sec worked out
  console.log('\nscheme            param              ms/hash     ~guesses/sec/core');
  console.log('-----------------------------------------------------------------------');
  for (const r of rows) {
    r.guessesPerSecPerCore = Math.round(1000 / r.msPerHash);
    console.log(
      `${r.scheme.padEnd(17)} ${String(r.param).padEnd(18)} ${r.msPerHash.toFixed(4).padStart(9)}   ${r.guessesPerSecPerCore.toLocaleString().padStart(16)}`
    );
  }

  const outDir = path.join(__dirname, 'out');
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'latency.json');
  fs.writeFileSync(file, JSON.stringify(rows, null, 2));
  console.log(`\nWrote ${file}`);
  console.log('Note: a real GPU is much faster than one core, so compare the ratios, not the exact numbers.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

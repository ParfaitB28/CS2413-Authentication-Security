'use strict';

/**
 * experiments/benchmarkLatency.js — the "latency curve" deliverable.
 *
 * Measures how long one hash takes under each scheme / cost factor. This is the
 * usability cost that trades off against crack resistance (hypothesis H6).
 *
 * Also derives the attacker's per-guess cost: guesses/sec achievable on ONE
 * core = 1000 / ms_per_hash. The security story is the inverse of the usability
 * story — the same slow-down that costs the user a few ms costs the attacker
 * billions of guesses.
 *
 * Usage:
 *   node experiments/benchmarkLatency.js
 * Writes: experiments/out/latency.json  (+ a printed table)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

const PASSWORD = 'correct-horse-battery-staple-7';
const REPS = 5;

async function timeAvg(fn, reps = REPS) {
  // warm-up
  await fn();
  const start = process.hrtime.bigint();
  for (let i = 0; i < reps; i++) await fn();
  const end = process.hrtime.bigint();
  return Number(end - start) / 1e6 / reps; // ms per op
}

async function main() {
  const rows = [];

  // Baseline fast hash
  const sha = await timeAvg(() => {
    crypto.createHash('sha256').update(PASSWORD).digest('hex');
    return Promise.resolve();
  }, 1000);
  rows.push({ scheme: 'sha256-unsalted', param: '-', msPerHash: sha });

  // bcrypt cost sweep
  for (const cost of [8, 10, 12, 14]) {
    const ms = await timeAvg(() => bcrypt.hash(PASSWORD, cost));
    rows.push({ scheme: 'bcrypt', param: `cost=${cost}`, msPerHash: ms });
  }

  // argon2id memory sweep
  for (const mem of [19 * 1024, 46 * 1024, 64 * 1024]) {
    const ms = await timeAvg(() =>
      argon2.hash(PASSWORD, { type: argon2.argon2id, memoryCost: mem, timeCost: 2, parallelism: 1 })
    );
    rows.push({ scheme: 'argon2id', param: `mem=${Math.round(mem / 1024)}MiB,t=2`, msPerHash: ms });
  }

  // Derive attacker guesses/sec on one core and print.
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
  console.log('Note: GPU crack rates are far higher per device; use these ratios, not absolutes, in the report.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

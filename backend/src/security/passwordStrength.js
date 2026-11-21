'use strict';

/**
 * passwordStrength.js — Mady's deliverable (password-strength policy).
 *
 * Two layers:
 *   1. zxcvbn entropy estimation — rejects guessable passwords, returns a
 *      0..4 score plus crack-time estimates and human feedback.
 *   2. Breached-password blocklist — rejects known-leaked passwords. Works
 *      offline against data/breached-sample.txt; can also check the live
 *      Have I Been Pwned range API via k-anonymity (no password leaves the app).
 *
 * Shrinking the realistic keyspace at registration is what makes the offline
 * cracking numbers meaningful: weak choices never enter the DB.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const zxcvbn = require('zxcvbn');
const config = require('./config');

// Load the offline breached-password sample once.
let BREACHED = null;
function loadBreached() {
  if (BREACHED) return BREACHED;
  const file = path.join(__dirname, '..', 'data', 'breached-sample.txt');
  BREACHED = new Set();
  try {
    const text = fs.readFileSync(file, 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const p = line.trim();
      if (p) BREACHED.add(p.toLowerCase());
    }
  } catch (_) {
    // sample missing -> empty set; policy still runs on zxcvbn + length
  }
  return BREACHED;
}

/**
 * Check a password locally (no network).
 * @param {string} password
 * @param {string[]} [userInputs] e.g. [username, email] to penalise
 * @returns {{ok:boolean, score:number, errors:string[], feedback:object, crackTimes:object}}
 */
function evaluate(password, userInputs = []) {
  const errors = [];
  const pw = String(password || '');

  if (pw.length < config.STRENGTH.minLength) {
    errors.push(`Password must be at least ${config.STRENGTH.minLength} characters.`);
  }

  if (loadBreached().has(pw.toLowerCase())) {
    errors.push('This password appears in a known data breach. Choose another.');
  }

  const result = zxcvbn(pw, userInputs);
  if (result.score < config.STRENGTH.minZxcvbnScore) {
    const hint = result.feedback && result.feedback.warning
      ? ` ${result.feedback.warning}.`
      : '';
    errors.push(`Password is too weak (score ${result.score}/4, need ${config.STRENGTH.minZxcvbnScore}+).${hint}`);
  }

  return {
    ok: errors.length === 0,
    score: result.score,
    errors,
    feedback: result.feedback,
    crackTimes: result.crack_times_display,
  };
}

/**
 * Optional: check Have I Been Pwned using k-anonymity. Only the first 5 chars
 * of the SHA-1 are sent; the full password never leaves the process.
 * @param {string} password
 * @returns {Promise<number>} breach count (0 = not found)
 */
function checkHIBP(password) {
  return new Promise((resolve, reject) => {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const req = https.get(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      { headers: { 'User-Agent': 'login-security-final-project' } },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          for (const line of body.split(/\r?\n/)) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix && hashSuffix.trim() === suffix) {
              return resolve(parseInt(count, 10) || 0);
            }
          }
          resolve(0);
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('HIBP timeout')));
  });
}

module.exports = { evaluate, checkHIBP };

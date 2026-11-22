'use strict';

// Password strength checking.
// Two checks:
//   1. zxcvbn - estimates how guessable a password is (score 0..4).
//   2. A blocklist of passwords that have shown up in known breaches.
// The idea is to stop weak passwords from ever getting saved, so they can't
// be cracked later.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const zxcvbn = require('zxcvbn');
const config = require('./config');

// Load the breached-password list once and keep it in memory.
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
    // if the file isn't there, just skip the blocklist and use zxcvbn + length
  }
  return BREACHED;
}

// Check a password without using the network.
// userInputs lets us pass things like the username/email so zxcvbn penalises
// passwords based on them.
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

// Optional extra check against Have I Been Pwned. It only sends the first 5
// characters of the SHA-1, so the actual password never leaves the program.
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

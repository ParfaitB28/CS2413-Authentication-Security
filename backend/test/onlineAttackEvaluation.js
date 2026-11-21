
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');

const { loginRateLimiter } = require('../src/security/loginRateLimiter');
const {
  checkAccountLockout,
  recordFailedLogin,
  resetFailedLogins
} = require('../src/security/accountLockout');

const app = express();
app.use(express.json());

const TEST_EMAIL = 'evaluation@example.test';
const TOTAL_ATTEMPTS = 12;
const passwordChecks = { baseline: 0, hardened: 0 };

// Baseline: no login protection.
app.post('/baseline/login', (req, res) => {
  passwordChecks.baseline++;
  res.status(401).json({ reason: 'wrong-password' });
});

// Hardened: use our real security modules.
app.post('/hardened/login', loginRateLimiter, (req, res) => {
  const status = checkAccountLockout(TEST_EMAIL);

  if (status.locked || status.backoff) {
    return res.status(429).json({
      reason: status.locked ? 'lockout' : 'backoff'
    });
  }

  passwordChecks.hardened++;

  // Simulate an incorrect password verification.
  const failure = recordFailedLogin(TEST_EMAIL);

 if (failure.locked) {
  return res.status(429).json({
    reason: 'lockout'
  });
}

  return res.status(401).json({ reason: 'wrong-password' });
});

const server = app.listen(0, '127.0.0.1', async () => {
  const port = server.address().port;
  const baseURL = `http://127.0.0.1:${port}`;
  const results = [];

  try {
    for (const mode of ['baseline', 'hardened']) {
      resetFailedLogins(TEST_EMAIL);

      for (let attempt = 1; attempt <= TOTAL_ATTEMPTS; attempt++) {
        const start = performance.now();

        const response = await fetch(`${baseURL}/${mode}/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: TEST_EMAIL,
            password: `WrongPassword${attempt}!`
          })
        });

        const elapsed = performance.now() - start;
        const body = await response.json();

        results.push({
          mode,
          attempt,
          status: response.status,
          reason: body.reason || body.error,
          response_ms: elapsed.toFixed(2)
        });
      }
    }

    console.table(results);

    console.log('\nPASSWORD VERIFICATION COMPARISON');
    console.log('Baseline:', passwordChecks.baseline);
    console.log('Hardened:', passwordChecks.hardened);
    console.log(
      'Blocked before verification:',
      TOTAL_ATTEMPTS - passwordChecks.hardened
    );

    const outputDir = path.resolve(__dirname, '../../experiments/results');
    fs.mkdirSync(outputDir, { recursive: true });

    const rows = [
      'mode,attempt,status,reason,response_ms',
      ...results.map(r =>
        [r.mode, r.attempt, r.status, JSON.stringify(r.reason), r.response_ms].join(',')
      )
    ];

    const outputFile = path.join(outputDir, 'rate_limiting_online_results.csv');
    fs.writeFileSync(outputFile, rows.join('\n'));

    console.log('\nResults saved to:', outputFile);
  } catch (error) {
    console.error('Evaluation failed:', error);
    process.exitCode = 1;
  } finally {
    resetFailedLogins(TEST_EMAIL);
    server.close();
  }
});

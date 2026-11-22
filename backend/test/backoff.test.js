
const assert = require('node:assert/strict');

const {
  checkAccountLockout,
  recordFailedLogin,
  resetFailedLogins
} = require('../src/security/accountLockout');

const email = 'backoff-test@example.com';
const originalNow = Date.now;
let fakeTime = 1800000000000;

Date.now = () => fakeTime;

try {
  resetFailedLogins(email);

  for (let attempt = 1; attempt <= 4; attempt++) {
    const result = recordFailedLogin(email);
    const expectedDelay = 2 ** (attempt - 1);

    assert.equal(result.backoff, true);
    assert.equal(result.retryAfter, expectedDelay);

    console.log(`Attempt ${attempt}: ${result.retryAfter}s backoff`);

    fakeTime += expectedDelay * 1000;
  }

  const fifth = recordFailedLogin(email);

  assert.equal(fifth.locked, true);
  assert.equal(fifth.retryAfter, 300);

  console.log('Attempt 5: Account locked for 300 seconds');

  resetFailedLogins(email);
  assert.equal(checkAccountLockout(email).locked, false);

  console.log('Reset successful');
  console.log('All exponential backoff tests passed!');
} finally {
  Date.now = originalNow;
  resetFailedLogins(email);
}

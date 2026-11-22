

const failedLogins = new Map();

const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 5 * 60 * 1000;
const ATTEMPT_WINDOW = 15 * 60 * 1000;

const BASE_DELAY = 1000;
const MAX_BACKOFF = 8 * 1000;

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// Check whether an account is locked or in a backoff period.
function checkAccountLockout(email) {
  const key = normalizeEmail(email);
  const record = failedLogins.get(key);

  if (!record) {
    return { locked: false, backoff: false };
  }

  const now = Date.now();

  if (record.lockedUntil > now) {
    return {
      locked: true,
      backoff: false,
      retryAfter: Math.ceil((record.lockedUntil - now) / 1000)
    };
  }

  if (record.lockedUntil ||
      now - record.firstFailure >= ATTEMPT_WINDOW) {
    failedLogins.delete(key);
    return { locked: false, backoff: false };
  }

  if (record.nextAllowedAt > now) {
    return {
      locked: false,
      backoff: true,
      retryAfter: Math.ceil((record.nextAllowedAt - now) / 1000)
    };
  }

  return { locked: false, backoff: false };
}

// Record a failed login and calculate the next delay.
function recordFailedLogin(email) {
  const key = normalizeEmail(email);
  const status = checkAccountLockout(key);

  if (status.locked || status.backoff) {
    return status;
  }

  const now = Date.now();

  const record = failedLogins.get(key) || {
    attempts: 0,
    firstFailure: now,
    lockedUntil: 0,
    nextAllowedAt: 0
  };

  record.attempts++;

  if (record.attempts >= MAX_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_TIME;
  } else {
    const delay = Math.min(
      BASE_DELAY * (2 ** (record.attempts - 1)),
      MAX_BACKOFF
    );

    record.nextAllowedAt = now + delay;
  }

  failedLogins.set(key, record);
  return checkAccountLockout(key);
}

// Clear failed attempts after successful login.
function resetFailedLogins(email) {
  failedLogins.delete(normalizeEmail(email));
}

module.exports = {
  checkAccountLockout,
  recordFailedLogin,
  resetFailedLogins
};

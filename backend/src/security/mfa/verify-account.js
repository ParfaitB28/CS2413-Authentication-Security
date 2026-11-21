const { verifyCodeDetails } = require('./totp');

async function verifyAccountCode(db, account, token, confirming = false) {
  const client = await db.connect();

  try {
    await client.query('BEGIN');

    const lookup = confirming ? 'email = $1' : 'id = $1';
    const result = await client.query(
      `SELECT id, email, mfa_enabled, mfa_secret_encrypted,
              mfa_failed_attempts, mfa_blocked_until, mfa_last_used_step
       FROM users WHERE ${lookup} FOR UPDATE`,
      [account]
    );

    const user = result.rows[0];

    async function finish(outcome) {
      await client.query('COMMIT');
      return outcome;
    }

    if (!user) {
      return await finish({
        ok: false, status: 401, error: 'Start login again.'
      });
    }

    if (!user.mfa_secret_encrypted ||
        (confirming ? user.mfa_enabled : !user.mfa_enabled)) {
      return await finish({
        ok: false, status: 409, error: 'MFA setup state has changed.'
      });
    }

    const blockedUntil = user.mfa_blocked_until;
    if (blockedUntil && blockedUntil.getTime() > Date.now()) {
      return await finish({
        ok: false, status: 429,
        error: 'Too many failed MFA attempts. Try again later.'
      });
    }

    const verification = await verifyCodeDetails(
      user.mfa_secret_encrypted,
      token,
      user.mfa_last_used_step
    );

    if (!verification.valid) {
      const previousAttempts = blockedUntil ? 0 : user.mfa_failed_attempts;
      const attempts = previousAttempts + 1;

      await client.query(
        `UPDATE users
         SET mfa_failed_attempts = $1,
             mfa_blocked_until = CASE
               WHEN $1 >= 5 THEN clock_timestamp() + INTERVAL '5 minutes'
               ELSE NULL
             END
         WHERE id = $2`,
        [attempts, user.id]
      );

      return await finish({
        ok: false,
        status: attempts >= 5 ? 429 : 401,
        error: attempts >= 5
          ? 'Too many failed MFA attempts. Try again in five minutes.'
          : 'Invalid, expired, or already-used authentication code.'
      });
    }

    await client.query(
      `UPDATE users
       SET mfa_enabled = TRUE,
           mfa_last_used_step = $1,
           mfa_failed_attempts = 0,
           mfa_blocked_until = NULL
       WHERE id = $2`,
      [verification.timeStep, user.id]
    );

    return await finish({ ok: true, email: user.email });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { verifyAccountCode };
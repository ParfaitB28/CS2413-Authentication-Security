const express = require('express');
const { Pool } = require('pg');
const { createEnrollment } = require('./src/security/mfa/totp');
const { verifyAccountCode } = require('./src/security/mfa/verify-account');
const { checkPasswordSecurity } = require('./src/security/passwords/passwordSecurity');
const app = express();
const port = Number(process.env.PORT || 3000);

const session = require('express-session');
const { loginRateLimiter } = require('./src/security/loginRateLimiter');
const {
  checkAccountLockout,
  recordFailedLogin,
  resetFailedLogins
} = require('./src/security/accountLockout');

app.use(session({
  name: 'cs2413.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000,
  },
}));

const db = new Pool({
  host: process.env.PGHOST || '/tmp',
  database: process.env.PGDATABASE || 'cs2413_auth',
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/health/db', async (req, res) => {
  try {
    await db.query('SELECT id FROM users LIMIT 1');
    res.json({ database: 'ok' });
  } catch (error) {
    console.error('Database check failed:', error.message);
    res.status(503).json({ database: 'unavailable' });
  }
});

const { randomBytes, scrypt } = require('node:crypto');
const { promisify } = require('node:util');
const { error } = require('node:console');
const hashPassword = promisify(scrypt);

app.post('/register', express.json({ limit: '4kb' }), async (req, res) => {
  const { email, password } = req.body ?? {};
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) ||
      normalizedEmail.length > 254 ||
      typeof password !== 'string' || password.length < 15 || password.length > 128) {
    return res.status(400).json({
      error: 'Enter a valid email and a password between 15 and 128 characters.',
    });
  }

  const passwordCheck = checkPasswordSecurity(password);

  if (!passwordCheck.valid) {
    return res.status(400).json({
      error: 'Password does not meet security requirements.',
      details: passwordCheck.errors,
    });
  }

  try {
    const salt = randomBytes(16);
    const hash = await hashPassword(password, salt, 64);
    const storedHash = `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;

    const result = await db.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       ON CONFLICT (email) DO NOTHING
       RETURNING id`,
      [normalizedEmail, storedHash]
    );

    if (result.rowCount === 0) {
      return res.status(409).json({ error: 'This email is already registered.' });
    }

    return res.status(201).json({ message: 'Account created.' });
  } catch (error) {
    console.error('Registration failed:', error.code ?? error.name);
    return res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/login', loginRateLimiter, express.json({ limit: '4kb' }), async (req, res) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== 'string' || email.length > 254 ||
      typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Enter an email and password.' });
  }
  const normalizedEmail = email.trim().toLowerCase();

  const lockoutStatus = checkAccountLockout(normalizedEmail);


if (lockoutStatus.locked || lockoutStatus.backoff) {
  res.set('Retry-After', String(lockoutStatus.retryAfter));

  return res.status(429).json({
    error: 'Too many failed login attempts. Please try again later.'
  });
}


  try {
    const result = await db.query(
      'SELECT id, password_hash, mfa_enabled FROM users WHERE email = $1',
      [email.trim().toLowerCase()]
    );

    const { timingSafeEqual } = require('node:crypto');
    const stored = result.rows[0]?.password_hash;
    const [, saltHex, hashHex] = stored?.split(':') ?? [];
    const salt = saltHex ? Buffer.from(saltHex, 'hex') : Buffer.alloc(16);
    const expected = hashHex ? Buffer.from(hashHex, 'hex') : Buffer.alloc(64);
    const actual = await hashPassword(password, salt, 64);

    if (!stored || expected.length !== actual.length ||
    !timingSafeEqual(expected, actual)) {

      const failureStatus = recordFailedLogin(normalizedEmail);

      if (failureStatus.locked) {
        res.set('Retry-After', String(failureStatus.retryAfter));

        return res.status(429).json({
          error: 'Too many failed login attempts. Please try again later.'
        });
      }

      return res.status(401).json({
        error: 'Invalid email or password.'
      });
    }

    return req.session.regenerate((error) => {
  if (error) {
    return res.status(500).json({ error: 'Could not start session.' });
  }

  resetFailedLogins(normalizedEmail);
  const user = result.rows[0];

  if (user.mfa_enabled) {
    req.session.pendingUserId = user.id;
    req.session.pendingExpiresAt = Date.now() + 5 * 60 * 1000;

    return res.json({
      mfaRequired: true,
      message: 'Enter your authentication code.'
    });
  }

  req.session.email = normalizedEmail;
  return res.json({ message: 'Signed in.' });
});

  } catch (error) {
    console.error('Login failed:', error.code ?? error.name);
    return res.status(500).json({ error: 'Could not check login.' });
  }
});

app.get('/me', (req, res) => {
  if (!req.session.email) {
    return res.status(401).json({ error: 'Sign in first.' });
  }

  return res.json({ email: req.session.email });
});

app.post('/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ error: 'Could not sign out.' });
    }

    res.clearCookie('cs2413.sid');
    return res.json({ message: 'Signed out.' });
  });
});

app.post('/mfa/enroll', async(req,res) => {
  if (!req.session.email){
    return res.status(401).json({error: 'Sign in first.' });
  }

  try{
    const result = await db.query(
      'SELECT mfa_enabled FROM users WHERE email = $1',
      [req.session.email]
    );
  
  if (result.rows.length ===0 ){
    return res.status(401).json({ error: 'Sign in again, '});
  }  

  if (result.rows[0].mfa_enabled){
    return res.status(409).json({ error: 'MFA is already enabled'});
  }
  const enrollment = createEnrollment(req.session.email);

  const updateResult = await db.query(
    `UPDATE users
    SET mfa_secret_encrypted = $1
    WHERE email = $2 AND mfa_enabled = FALSE
    RETURNING id`,
    [enrollment.encryptedSecret, req.session.email]
  );

  if(updateResult.rowCount === 0){
    return res.status(409).json({
      error: 'Could not start enrollment. Sign in again or check MFA status'
    });
  }

  res.set('Cache-control', 'no-store');
    return res.status(200).json({
    uri: enrollment.uri
  });

  } catch (error){
    console.error('MFA enrollment failed: ', error.code ?? error.name);
    return res.status(500).json({
      error: 'Could not start MFA enrollment.'
    });
  }


});

app.post('/mfa/confirm', express.json({ limit: '4kb' }), async (req, res) => {
  if (!req.session.email) {
    return res.status(401).json({ error: 'Sign in first.' });
  }

  const { token } = req.body ?? {};

  try {
    const outcome = await verifyAccountCode(
      db, req.session.email, token, true
    );

    if (!outcome.ok) {
      return res.status(outcome.status).json({ error: outcome.error });
    }

    return res.json({ message: 'MFA enabled.' });
  } catch (error) {
    console.error('MFA confirmation failed:', error.code ?? error.name);
    return res.status(500).json({
      error: 'Could not confirm MFA enrollment.'
    });
  }
});

app.post('/mfa/verify', express.json({ limit: '4kb' }), async (req, res) => {
  const { pendingUserId, pendingExpiresAt } = req.session;

  if (!pendingUserId || !pendingExpiresAt || Date.now() >= pendingExpiresAt) {
    return res.status(401).json({ error: 'Start login again.' });
  }

  const { token } = req.body ?? {};

  try {
    const outcome = await verifyAccountCode(db, pendingUserId, token);

    if (!outcome.ok) {
      return res.status(outcome.status).json({ error: outcome.error });
    }

    return req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({
          error: 'Could not start session.'
        });
      }

      req.session.email = outcome.email;
      return res.json({ message: 'Signed in.' });
    });
  } catch (error) {
    console.error('MFA verification failed:', error.code ?? error.name);
    return res.status(500).json({
      error: 'Could not verify authentication code.'
    });
  }
});

app.listen(port, '127.0.0.1', () => {
  console.log(`Server running at http://127.0.0.1:${port}`);
});
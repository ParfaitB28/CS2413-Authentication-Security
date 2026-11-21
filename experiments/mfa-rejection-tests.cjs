// Run from the repository root with the backend running on 127.0.0.1:3001.
// Uses a disposable account in the default local lab database; never logs secrets.
const { createRequire } = require('node:module');
const requireBackend = createRequire(require('node:path').resolve(__dirname, '../backend/package.json'));
const { Pool } = requireBackend('pg');
const { generate } = requireBackend('otplib');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const db = new Pool({ host: '/tmp', database: 'cs2413_auth' });
const email = `mfa-rejection-${randomBytes(6).toString('hex')}@example.test`;
const password = `LabOnly!${randomBytes(20).toString('hex')}`;
const rows = [];
const cookies = new Set();
async function request(route, body, cookie) {
  const response = await fetch(`http://127.0.0.1:3001${route}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10000)
  });
  const nextCookie = response.headers.get('set-cookie')?.split(';')[0] || cookie;
  if (nextCookie) cookies.add(nextCookie);
  return { status: response.status, body: await response.json(), cookie: nextCookie };
}
async function login() {
  const result = await request('/login', { email, password });
  assert.equal(result.status, 200, 'Password login failed; if rate limited, wait one minute before rerunning.');
  return result.cookie;
}
async function check(name, route, body, cookie, expected) {
  const result = await request(route, body, cookie);
  rows.push({ test: name, expected_status: expected, actual_status: result.status, passed: result.status === expected });
  assert.equal(result.status, expected, name);
  console.log(`PASS: ${name} (HTTP ${result.status})`);
  return result;
}
async function freshInterval() {
  await new Promise(resolve => setTimeout(resolve, 30000 - Date.now() % 30000 + 1500));
}
(async () => {
  try {
    await check('signed_out_verification', '/mfa/verify', { token: '000000' }, undefined, 401);
    assert.equal((await request('/register', { email, password })).status, 201);
    let cookie = await login();
    const enrollment = await request('/mfa/enroll', {}, cookie);
    assert.equal(enrollment.status, 200);
    const secret = new URL(enrollment.body.uri).searchParams.get('secret');
    const enrollmentToken = await generate({ secret });
    assert.equal((await request('/mfa/confirm', { token: enrollmentToken }, cookie)).status, 200);
    await request('/logout', {}, cookie);
    cookie = await login();
    await check('password_alone_denied', '/me', undefined, cookie, 401);
    await check('enrollment_code_cannot_be_reused', '/mfa/verify', { token: enrollmentToken }, cookie, 401);
    const current = await generate({ secret });
    const wrong = String((Number(current) + 1) % 1000000).padStart(6, '0');
    await check('wrong_six_digit_code', '/mfa/verify', { token: wrong }, cookie, 401);
    await check('malformed_code', '/mfa/verify', { token: 'abc' }, cookie, 401);
    await check('rejected_codes_do_not_grant_access', '/me', undefined, cookie, 401);
    console.log('Waiting for a fresh interval to test successful login and replay.');
    await freshInterval();
    const validToken = await generate({ secret });
    const verified = await check('fresh_valid_code', '/mfa/verify', { token: validToken }, cookie, 200);
    await check('access_after_valid_code', '/me', undefined, verified.cookie, 200);
    await request('/logout', {}, verified.cookie);
    cookie = await login();
    await check('accepted_code_replay_new_session', '/mfa/verify', { token: validToken }, cookie, 401);
    for (let attempt = 2; attempt <= 5; attempt++) {
      await check(`failure_${attempt}_after_reset`, '/mfa/verify', { token: 'invalid' }, cookie, attempt === 5 ? 429 : 401);
    }
    const state = await db.query('SELECT mfa_failed_attempts, mfa_blocked_until > clock_timestamp() AS blocked FROM users WHERE email=$1', [email]);
    assert.equal(state.rows[0].mfa_failed_attempts, 5);
    assert.equal(state.rows[0].blocked, true);
    await request('/logout', {}, cookie);
    cookie = await login();
    await check('new_password_login_does_not_reset_cooldown', '/mfa/verify', { token: await generate({ secret }) }, cookie, 429);
    await check('blocked_account_has_no_access', '/me', undefined, cookie, 401);
  } finally {
    for (const cookie of cookies) {
      try { await request('/logout', {}, cookie); } catch {}
    }
    await db.query('DELETE FROM users WHERE email=$1', [email]);
    await db.end();
    const output = path.join(__dirname, 'results/mfa_rejection_tests.csv');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, 'test,expected_status,actual_status,passed\n' + rows.map(r => `${r.test},${r.expected_status},${r.actual_status},${r.passed}`).join('\n') + '\n');
    console.log(`Saved ${rows.length} HTTP checks to ${output}`);
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });

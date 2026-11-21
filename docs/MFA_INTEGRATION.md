# MFA integration

All requests use the same session cookie.

## Enrollment
1. Log in normally.
2. POST /mfa/enroll returns { uri } for authenticator setup.
3. POST /mfa/confirm with { "token": "123456" } confirms setup.
4. MFA is enabled only after successful confirmation.

## Login
1. POST /login with email and password.
2. If the response contains mfaRequired: true, show a code-entry form.
3. POST /mfa/verify with { "token": "123456" } completes login.
4. /me remains inaccessible until verification succeeds.

## Error handling
- 401: missing authentication, invalid code, or expired challenge.
- 409: incompatible MFA setup state.
- 429: MFA verification temporarily blocked after repeated failures.

## Security behavior
- Pending login expires after five minutes.
- Five failed MFA attempts trigger a five-minute account-level cooldown.
- An accepted TOTP time interval cannot be reused.
- After enrollment confirmation, wait for a fresh code before testing login.
- Never log or publicly share the enrollment URI.

## Local setup and testing

These instructions assume macOS, Homebrew PostgreSQL 17, Node.js with
`--env-file` support, and the local database `cs2413_auth`.

### 1. Install dependencies

From the repository root:

```bash
npm ci --prefix backend
```

### 2. Prepare the database

For a new installation, start PostgreSQL, create the database, and apply
`backend/db/schema.sql`.

For an existing database, run these commands from the repository root:

```bash
"$(brew --prefix postgresql@17)/bin/psql" -h /tmp -d cs2413_auth -v ON_ERROR_STOP=1 -f backend/db/migrations/001_add_mfa.sql
"$(brew --prefix postgresql@17)/bin/psql" -h /tmp -d cs2413_auth -v ON_ERROR_STOP=1 -f backend/db/migrations/002_mfa_verification_protection.sql
```

### 3. Configure the encryption key

If you do not already have an MFA encryption key, generate one:

```bash
openssl rand -hex 32
```

Create `backend/.env` and add:

```text
MFA_ENCRYPTION_KEY=replace_with_your_generated_64_character_hex_key
```

Keep an existing key unchanged: replacing it prevents the app from
decrypting previously enrolled MFA secrets.

Never commit `.env`, share the key, or include it in screenshots.

### 4. Start the backend

From the repository root:

```bash
cd backend
PORT=3001 SESSION_SECRET="$(openssl rand -hex 32)" npm start
```

Leave this terminal running. Restarting with a new session secret signs
out existing sessions.

### 5. Run the experiments

In another terminal, from the repository root:

```bash
node experiments/mfa-comparison.cjs
```

Wait at least 60 seconds before running the next script so the shared
IP rate-limit window can reset:

```bash
node experiments/mfa-rejection-tests.cjs
```

Both scripts expect the backend at `127.0.0.1:3001` and PostgreSQL at
`/tmp`, using `cs2413_auth`. They create temporary synthetic accounts,
remove those accounts afterward, and write CSV results to
`experiments/results`.

Avoid other login tests during these runs. A rate-limit rejection during
setup means the experiment should be rerun after the limit resets.

The comparison uses one account and three fresh login sessions per
password-only condition. It demonstrates MFA's effect in this local
configuration; it is not a large-scale credential-stuffing study.
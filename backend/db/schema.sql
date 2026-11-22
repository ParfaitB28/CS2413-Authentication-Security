CREATE TABLE IF NOT EXISTS users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret_encrypted TEXT,
  mfa_failed_attempts INTEGER NOT NULL DEFAULT 0,
  mfa_blocked_until TIMESTAMPTZ,
  mfa_last_used_step BIGINT
);

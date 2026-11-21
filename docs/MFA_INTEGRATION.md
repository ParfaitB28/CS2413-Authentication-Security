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
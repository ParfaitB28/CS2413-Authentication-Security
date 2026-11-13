
# Team Responsibilities

## Project
CS2413 - Password Security and Authentication

## Team Members

### Maheva - Project Lead & Core Authentication
Branch: feature/core-auth
- Core login and registration system
- Database integration
- Session management
- Frontend integration
- Overall project coordination

### Mady - Password Hashing
Branch: feature/password-hashing
- Secure password hashing (bcrypt/Argon2id)
- Password salting
- Optional pepper implementation
- Offline password-cracking evaluation

### Sotonte - Rate Limiting
Branch: feature/rate-limiting
- Login rate limiting
- Account lockout
- Exponential backoff
- Online attack-rate evaluation

### Parfait - Multi-Factor Authentication
Branch: feature/mfa
- TOTP enrollment
- TOTP code verification
- MFA integration with login
- Credential-stuffing experiments with and without MFA

### Aditya - Security Testing & Password Policy
Branch: feature/attack-testing
- Password-strength validation
- Leaked-password blocklist
- Attack testing scripts
- Experiment metrics and result charts

## Collaboration Rules

1. Each member works on their assigned feature branch.
2. Do not push feature changes directly to main.
3. Commit and push changes regularly.
4. Create a pull request when a feature is ready.
5. Review and test changes before merging into main.
6. Never commit passwords, secrets, or .env files.
7. Use synthetic test accounts and a controlled local environment.

## Deadline

Final submission: November 23, 2026.
Internal coding target: November 20, 2026.

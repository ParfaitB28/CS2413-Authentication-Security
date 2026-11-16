## Run the backend locally

Use the `feature/core-auth` branch. Install Node.js and start PostgreSQL 17
before running these commands from the project's `backend` folder:

```bash
npm ci
"$(brew --prefix postgresql@17)/bin/createdb" cs2413_auth
"$(brew --prefix postgresql@17)/bin/psql" -d cs2413_auth -f db/schema.sql
SESSION_SECRET="$(openssl rand -hex 32)" npm start
```

If `cs2413_auth` already exists, skip the `createdb` command.

Open http://127.0.0.1:3000/health/db. The expected response is
`{"database":"ok"}`.

Use a dummy email and password to test registration and login. `/me` returns
401 when signed out and the signed-in email after login. `/logout` ends the
session, so `/me` returns 401 again.
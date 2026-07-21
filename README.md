# SecureTask

SecureTask is a task management system developed with FastAPI.

## Technologies

- Python
- FastAPI
- PostgreSQL
- Docker
- OAuth2 / OpenID Connect

## Features

- REST API
- OpenID Connect authentication (single sign-on)
- Per-user task ownership
- Role Based Access Control (planned)
- Audit Logging (planned)

## Run

```bash
uvicorn app.main:app --reload
```

## Authentication

Interactive login uses OpenID Connect against the configured provider
(`OIDC_ISSUER`). Users authenticate on the provider's own login page; SecureTask
never sees the password.

The provider (openidx.tdv.org) does not implement the OAuth `state` parameter
and delegates the login UI to the client via a `login_session` handoff, so the
flow is not the textbook redirect. PKCE (S256) is the interception defence:

1. `GET /auth/login` — generates a PKCE verifier (stored in the signed session
   cookie) and redirects to the provider's `/oauth/authorize`.
2. The provider redirects back to `/callback?login_session=…` (no session yet).
3. `/callback` redirects the browser to the provider's hosted login page
   (`/login?login_session=…`) — the password is entered there.
4. After sign-in the provider returns to `/callback?code=…`.
5. `/callback` exchanges the code + verifier at `/oauth/token`, verifies the
   `id_token` signature against the JWKS, and upserts the user keyed on
   `(issuer, sub)`.

API requests authenticate with `Authorization: Bearer <access_token>`. JWT
access tokens are verified locally against the JWKS (RS256 pinned); opaque
tokens fall back to the provider's `/oauth/userinfo`.

### Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string |
| `OIDC_ISSUER` | Provider base URL |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | Registered client credentials |
| `OIDC_REDIRECT_URI` | Must match the redirect URI registered with the provider |
| `SESSION_SECRET` | Signs the short-lived PKCE session cookie |
| `SESSION_HTTPS_ONLY` | `false` only for local http; keep `true` in production |

### Endpoints

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/auth/login` | — (starts login) |
| `GET` | `/callback` | — (provider redirect target) |
| `GET` | `/auth/me` | Bearer |
| `GET` | `/auth/logout` | — |
| `GET/POST/PUT/DELETE` | `/tasks` … | Bearer (owner-scoped) |
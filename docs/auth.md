# Auth

This document describes authentication and authorization for the X07 registry API.

## Web sign-in (GitHub OAuth)

The x07.io web UI uses GitHub OAuth to create a session on the `.x07.io` site:

- `GET /v1/auth/github/start` redirects to GitHub.
- `GET /v1/auth/github/callback` sets an `x07_session` cookie and redirects back to x07.io.
- The web UI calls registry endpoints with `credentials: include`.
- For state-changing web requests, the UI must send `X-X07-CSRF` (obtained from `GET /v1/auth/session`).

## Tokens

The registry uses bearer tokens stored in Postgres.

- Clients authenticate with `Authorization: Bearer <token>`.
- Tokens are stored as SHA-256 hashes (the plaintext token is only returned at creation time).
- Tokens can be revoked.
- For the official deployment, tokens are created and revoked in the web UI at https://x07.io/settings/tokens.

## Permissions

Scopes are stored on each token.

Supported scopes:

- `publish`: publish new package versions (and create new packages)
- `token.manage`: create/list/revoke tokens for the current user
- `owner.manage`: manage package owners and yank/unyank versions for owned packages
- `admin`: bypass owner checks and grant any scope

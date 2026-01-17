# Auth

This document describes authentication and authorization for the X07 registry API.

## Tokens

The registry uses bearer tokens stored in Postgres.

- Clients authenticate with `Authorization: Bearer <token>`.
- Tokens are stored as SHA-256 hashes (the plaintext token is only returned at creation time).
- Tokens can be revoked.

## Permissions

Scopes are stored on each token.

Supported scopes:

- `publish`: publish new package versions (and create new packages)
- `token.manage`: create/list/revoke tokens for the current user
- `owner.manage`: manage package owners and yank/unyank versions for owned packages
- `admin`: bypass owner checks and grant any scope

### Bootstrapping

If `X07_REGISTRY_BOOTSTRAP_TOKEN` is set, the registry enables `POST /v1/admin/bootstrap`.
This endpoint creates (or reuses) a user and issues a token.

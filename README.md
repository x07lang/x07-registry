# X07 Registry

This repo contains the X07 package registry server (API) and its contract.

## Contents

- API contract: `openapi/openapi.json`
- Auth notes: `docs/auth.md`

## End-user docs

- Toolchain + agent workflow: https://x07lang.org/docs/getting-started/agent-quickstart/
- Installer / x07up: https://x07lang.org/docs/getting-started/installer/
- Packages: https://x07lang.org/docs/packages/
- Registry UI: https://x07.io/
- Registry UI repo: https://github.com/x07lang/x07-registry-web

## Run locally

Prereqs:

- Rust toolchain
- Postgres (or run `dev-stack/` from the workspace root)

Run:

- `cargo run`

The server listens on `127.0.0.1:8080` and exposes `GET /healthz`.

## Index endpoints

- `GET /index` → redirects to `/index/`
- `GET /index/` → redirects to `/index/catalog.json`
- `GET /index/config.json` → sparse index config (includes API + download bases)
- `GET /index/catalog.json` → package catalog JSON
- `GET /index/<prefix>/<name>` → package index entry (NDJSON)

Index endpoints include `ETag` + `Cache-Control` and support `If-None-Match` revalidation (`304 Not Modified`).

All responses include an `x-request-id` header; JSON error responses include `request_id` alongside `code` and `message`.

## Configuration

- `X07_REGISTRY_BIND`: bind address (default: `127.0.0.1:8080`)
- `X07_REGISTRY_PUBLIC_BASE`: public base URL used in generated links (default: `http://127.0.0.1:8080`)
- `X07_REGISTRY_WEB_BASE`: web base URL used for OAuth redirects (default: `https://x07.io`)
- `X07_REGISTRY_DATABASE_URL` (or `DATABASE_URL`): Postgres connection string (default: `postgres://x07:x07@127.0.0.1:5432/x07_registry`)
- `X07_REGISTRY_DATABASE_SCHEMA`: Postgres schema used by the registry (default: `public`)
- `X07_REGISTRY_CORS_ORIGINS`: comma-separated allowed origins for browser reads (optional)
- `X07_REGISTRY_GITHUB_CLIENT_ID`: GitHub OAuth app client id (enables GitHub login)
- `X07_REGISTRY_GITHUB_CLIENT_SECRET`: GitHub OAuth app client secret
- `X07_REGISTRY_GITHUB_AUTHORIZE_BASE`: override GitHub OAuth base URL (optional; default: `https://github.com`)
- `X07_REGISTRY_GITHUB_API_BASE`: override GitHub API base URL (optional; default: `https://api.github.com`)
- `X07_REGISTRY_ADMIN_GITHUB_USER_IDS`: comma-separated numeric GitHub user IDs treated as admins (optional)
- `X07_REGISTRY_SESSION_COOKIE_DOMAIN`: cookie domain for `x07_session` (recommended: `.x07.io`)
- `X07_REGISTRY_SESSION_COOKIE_SECURE`: `true`/`false` for the `Secure` cookie attribute (default: `true`)
- `X07_REGISTRY_SESSION_TTL_SECONDS`: session lifetime in seconds (default: 2592000)
- `X07_REGISTRY_OAUTH_STATE_TTL_SECONDS`: OAuth state lifetime in seconds (default: 600)
- `X07_REGISTRY_REQUIRE_VERIFIED_EMAIL_FOR_PUBLISH`: require a verified GitHub email to publish (default: `true`)
- `X07_REGISTRY_STORAGE`: `fs` (filesystem) or `s3` (S3-compatible object storage). Default: `fs`
- `X07_REGISTRY_VERIFIED_NAMESPACES`: comma-separated list of “official” namespace prefixes (optional)

Filesystem mode:

- `X07_REGISTRY_DATA_DIR`: base data directory (default: `data`)

S3 mode (`X07_REGISTRY_STORAGE=s3`):

- `X07_REGISTRY_S3_BUCKET`
- `X07_REGISTRY_S3_REGION`
- `X07_REGISTRY_S3_ENDPOINT`
- `X07_REGISTRY_S3_PREFIX` (optional)
- `X07_REGISTRY_S3_FORCE_PATH_STYLE` (set `true` for MinIO)
- `X07_REGISTRY_S3_ACCESS_KEY_ID` (or `AWS_ACCESS_KEY_ID`)
- `X07_REGISTRY_S3_SECRET_ACCESS_KEY` (or `AWS_SECRET_ACCESS_KEY`)

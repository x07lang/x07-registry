# X07 Registry

This repo contains the X07 package registry server (API) and its contract.

## Contents

- API contract: `openapi/openapi.json`
- Auth notes: `docs/auth.md`

## Run locally

Prereqs:

- Rust toolchain
- Postgres (or run `dev-stack/` from the workspace root)

Run:

- `cargo run`

The server listens on `127.0.0.1:8080` and exposes `GET /healthz`.

## Configuration

- `X07_REGISTRY_BIND`: bind address (default: `127.0.0.1:8080`)
- `X07_REGISTRY_PUBLIC_BASE`: public base URL used in generated links (default: `http://127.0.0.1:8080`)
- `X07_REGISTRY_DATABASE_URL` (or `DATABASE_URL`): Postgres connection string (default: `postgres://x07:x07@127.0.0.1:5432/x07_registry`)
- `X07_REGISTRY_DATABASE_SCHEMA`: Postgres schema used by the registry (default: `public`)
- `X07_REGISTRY_BOOTSTRAP_TOKEN`: enables `POST /v1/admin/bootstrap` for creating the first user/token (optional)
- `X07_REGISTRY_CORS_ORIGINS`: comma-separated allowed origins for browser reads (optional)
- `X07_REGISTRY_STORAGE`: `fs` (filesystem) or `s3` (S3-compatible object storage). Default: `fs`

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

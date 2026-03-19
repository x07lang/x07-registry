# X07 Registry

`x07-registry` is the package registry API for the X07 ecosystem.

This repo is where published X07 packages are stored, indexed, downloaded, and authenticated. In practical terms, it is the server behind the package workflows described in the core `x07` docs and surfaced to users through [`x07.io`](https://x07.io).

Support: see `SUPPORT.md`.

Community:

- Discord: https://discord.gg/59xuEuPN47
- Email: support@x07lang.org

## What Is In This Repo

- **Registry API server** implemented in Rust
- **OpenAPI contract** in `openapi/openapi.json`
- **Package index endpoints** used by tooling and UI clients
- **Auth and session handling** for sign-in and publish flows
- **Operational docs** such as `docs/auth.md`

## Vision

The registry exists to give X07 one consistent package story for both humans and coding agents.

An end user should be able to install the toolchain, add a package, publish a package, and inspect what is available without learning a private workflow. A coding agent should be able to do the same with stable machine-readable endpoints and predictable error handling.

## How It Fits The X07 Ecosystem

- [`x07`](https://github.com/x07lang/x07) is the core toolchain that installs packages, locks dependencies, and publishes packages
- `x07-registry` is the API that stores and serves those packages
- [`x07-registry-web`](https://github.com/x07lang/x07-registry-web) is the browser UI for the same registry data
- [`x07lang.org`](https://x07lang.org/docs/packages/) explains the package workflow from an end-user point of view

That makes this repo part of the language’s everyday developer path, not an optional side service.

## Practical Usage

Use the registry when you need to:

- publish a package for other X07 projects to consume
- browse package versions and metadata
- filter or classify package lines by additive archetype, runtime, binding, trust, and capability facets
- serve the sparse index used by tooling
- support the `x07 pkg` workflow with a real API backend

## Install And Run Locally

Prereqs:

- Rust toolchain
- Postgres, or the shared workspace `dev-stack/`

Run the API from the repo root:

```sh
cargo run
```

The server listens on `127.0.0.1:8080` and exposes `GET /healthz`.

## Use It As Part Of The Full X07 Workflow

Install the X07 toolchain first:

- Installer: https://x07lang.org/docs/getting-started/installer/
- Agent quickstart: https://x07lang.org/docs/getting-started/agent-quickstart/

Then pair this repo with:

- [`x07`](https://github.com/x07lang/x07) for `x07 pkg add`, `x07 pkg lock`, and `x07 pkg publish`
- [`x07-registry-web`](https://github.com/x07lang/x07-registry-web) for the browser experience at `x07.io`

Useful end-user docs:

- Packages overview: https://x07lang.org/docs/packages/
- Publishing by example: https://x07lang.org/docs/packages/publishing-by-example/
- Agent contracts: https://x07lang.org/docs/agent/contract/
- Capability map: https://x07lang.org/agent/latest/catalog/capabilities.json

## Contents

- API contract: `openapi/openapi.json`
- Auth notes: `docs/auth.md`

## Index Endpoints

- `GET /index` → redirects to `/index/`
- `GET /index/` → redirects to `/index/catalog.json`
- `GET /index/config.json` → sparse index config with API and download bases
- `GET /index/catalog.json` → package catalog JSON
- `GET /index/<prefix>/<name>` → package index entry in NDJSON form
- `GET /v1/search` and package metadata/detail responses expose additive `facets` derived from package manifest metadata

Index endpoints include `ETag` and `Cache-Control` and support `If-None-Match` revalidation with `304 Not Modified`.

All responses include an `x-request-id` header. JSON error responses include `request_id` alongside `code` and `message`.

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
- `X07_REGISTRY_SESSION_COOKIE_SECURE`: `true` or `false` for the `Secure` cookie attribute (default: `true`)
- `X07_REGISTRY_SESSION_TTL_SECONDS`: session lifetime in seconds (default: 2592000)
- `X07_REGISTRY_OAUTH_STATE_TTL_SECONDS`: OAuth state lifetime in seconds (default: 600)
- `X07_REGISTRY_REQUIRE_VERIFIED_EMAIL_FOR_PUBLISH`: require a verified GitHub email to publish (default: `true`)
- `X07_REGISTRY_STORAGE`: `fs` or `s3` (S3-compatible object storage). Default: `fs`
- `X07_REGISTRY_VERIFIED_NAMESPACES`: comma-separated list of official namespace prefixes (optional)

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

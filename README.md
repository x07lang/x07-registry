# x07-registry

Package registry API for the X07 ecosystem.

This repo is the backend behind X07 package publish, download, search, and sparse-index flows. It is the server-side half of the package experience exposed through `x07 pkg ...` and browsed on [x07.io](https://x07.io).

**Start here:** [`openapi/openapi.json`](openapi/openapi.json) · [`docs/auth.md`](docs/auth.md) · [`x07lang/x07`](https://github.com/x07lang/x07) · [`x07lang/x07-registry-web`](https://github.com/x07lang/x07-registry-web)

## What This Repo Does

- stores and serves published X07 packages
- exposes the sparse index used by the toolchain
- handles sign-in and publish-related API flows
- serves package metadata and search endpoints for the web UI and other clients

## When To Use It

Use `x07-registry` when you want to:

- run the registry API locally
- work on package publish or download behavior
- inspect or change registry API contracts
- support `x07 pkg add`, `x07 pkg lock`, and `x07 pkg publish`

If you want the browser experience, use `x07-registry-web`. If you want the CLI and package workflow, start in `x07`.

## Quick Start

Prerequisites:

- Rust toolchain
- Postgres and object storage, or the shared local [`dev-stack`](../dev-stack)

Run the repo-local gate:

```sh
bash scripts/ci/check_local.sh
```

Run the server:

```sh
cargo run
```

The default bind is `127.0.0.1:8080`, and `GET /healthz` is the simplest liveness check.

## Key Surfaces

- sparse index:
  - `GET /index/config.json`
  - `GET /index/catalog.json`
  - `GET /index/<prefix>/<name>`
- package and search APIs:
  - `GET /v1/packages/...`
  - `GET /v1/search`
  - `GET /v1/archetypes`

The canonical API contract lives in [`openapi/openapi.json`](openapi/openapi.json).

## How It Fits The X07 Ecosystem

- [`x07`](https://github.com/x07lang/x07) owns the CLI, lockfile, and publish commands
- `x07-registry` serves the package and index backend
- [`x07-registry-web`](https://github.com/x07lang/x07-registry-web) is the human-facing browser UI for the same data

## Configuration

Common environment variables:

- `X07_REGISTRY_BIND`
- `X07_REGISTRY_PUBLIC_BASE`
- `X07_REGISTRY_WEB_BASE`
- `X07_REGISTRY_DATABASE_URL`
- `X07_REGISTRY_STORAGE`

See the source configuration handling and [`docs/auth.md`](docs/auth.md) for the full operational picture.

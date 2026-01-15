# X07 Registry

This repo contains the X07 package registry server (API) and its contract.

## Contents

- API contract: `openapi/openapi.json`
- Auth notes: `docs/auth.md`

## Run locally

Prereqs:

- Rust toolchain

Run:

- `cargo run`

The server listens on `127.0.0.1:8080` and exposes `GET /healthz`.


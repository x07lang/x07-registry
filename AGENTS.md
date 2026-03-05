# Repository Guide

## Build and test

- `cargo test`
- `cargo run`

## Toolchain dependency workflow

- This repo tracks the released `x07` toolchain tag in `Cargo.toml`.
- If `x07` is bumped to a new release tag, make sure that tag exists on GitHub before treating `cargo test` failures here as a registry bug.
- Prefer verifying package publication through the live API:
  - `GET /v1/packages/<name>`
  - sparse index under `/index/`
- Installer/package-release work here should stay focused on API and index correctness, not duplicate the publishing logic that already lives in `x07`.

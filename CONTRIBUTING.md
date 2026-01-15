# Contributing

## Code of Conduct

Participation in this project is governed by `CODE_OF_CONDUCT.md`.

## Development workflow

- Prefer small PRs with a clear intent.
- Keep changes deterministic and reproducible.
- Add tests for behavior changes.

### Required checks

Run before opening a PR:

- `cargo fmt --check`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`

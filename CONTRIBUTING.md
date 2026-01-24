# Contributing

## Code of Conduct

Participation in this project is governed by `CODE_OF_CONDUCT.md`.

## Support / questions

If you have usage questions about publishing packages or the end-user workflows, please
use `SUPPORT.md` and GitHub Discussions. Issues in this repo are for actionable registry API bugs.

## Development workflow

- Prefer small PRs with a clear intent.
- Keep changes deterministic and reproducible.
- Add tests for behavior changes.

### Required checks

Run before opening a PR:

- `cargo fmt --check`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`

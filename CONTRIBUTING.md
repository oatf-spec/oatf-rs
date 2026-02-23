# Contributing to oatf-rs

## Getting Started

```bash
git clone --recursive https://github.com/oatf-spec/oatf-rs.git
cd oatf-rs
cargo test
```

The `--recursive` flag ensures the spec submodule is initialized. If you
already cloned without it:

```bash
git submodule update --init --recursive
```

## Development Workflow

1. Create a branch from `main`.
2. Make your changes and ensure all checks pass:
   ```bash
   cargo test --all-features
   cargo clippy -- -D warnings
   cargo fmt --check
   cargo deny check
   ```
3. Open a pull request against `main`.

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new validation rule V-046
fix: correct duration parsing for fractional seconds
test: add property tests for wildcard paths
refactor: simplify actor collection logic
build: update serde to 1.0.230
```

## Updating the Spec Submodule

```bash
cd spec
git fetch origin
git checkout <desired-tag-or-commit>
cd ..
git add spec
git commit -m "build: update spec submodule to <version>"
```

## CI Checklist

All PRs must pass:

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test` on stable, nightly, and MSRV (1.85.0)
- `cargo test --no-default-features` and `--all-features`
- `cargo deny check`
- `cargo doc --no-deps` (warnings as errors)

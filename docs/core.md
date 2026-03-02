# Scanr Core

`scanr-core` is the shared library crate for Scanr.

## Purpose

- Hold reusable security analysis logic
- Define shared data structures used by the CLI and future services
- Keep business logic separate from CLI argument parsing

## Why Separate `scanr-core` From `scanr-cli`

- Cleaner architecture and easier testing
- Better reuse across binaries and integrations
- Lower coupling between command UX and analysis engine internals

## Current State (Milestone 2)

`scanr-core` now provides dependency parsing primitives used by `scanr-cli`:

- Node.js: `package.json`, `package-lock.json`
- Python: `requirements.txt`, `pyproject.toml`, `poetry.lock`
- Rust: `Cargo.toml`, `Cargo.lock`

The crate returns normalized dependency records with ecosystem and direct/transitive flags.

Core dependency model:

```rust
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub direct: bool,
}
```

## Planned Direction

Future milestones should move into this crate:

- Scan orchestration
- SBOM generation and diff models
- Vulnerability and policy evaluation primitives
- Output serialization contracts

## Crate Location

- `crates/scanr-core`

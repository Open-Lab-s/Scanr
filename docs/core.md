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

## Current State (Milestone 1)

`scanr-core` is intentionally minimal and provides placeholder functionality while the CLI skeleton is being validated.

## Planned Direction

Future milestones should move into this crate:

- Scan orchestration
- SBOM generation and diff models
- Vulnerability and policy evaluation primitives
- Output serialization contracts

## Crate Location

- `crates/scanr-core`

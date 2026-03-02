# Development

## Prerequisites

- Rust toolchain (`stable`)
- Git

## Build

```bash
cargo build --workspace --release
```

## Run CLI During Development

```bash
cargo run -p scanr-cli -- scan .
cargo run -p scanr-cli -- sbom generate
cargo run -p scanr-cli -- sbom diff old.json new.json
```

## Workspace Structure

```text
crates/scanr-core  # reusable analysis library
crates/scanr-cli   # scanr executable
```

## CI

GitHub Actions workflow:

- File: `.github/workflows/ci.yml`
- Build step: `cargo build --workspace --release`
- Triggers: push, pull request, manual dispatch

## Documentation

To preview docs locally:

```bash
mkdocs serve
```

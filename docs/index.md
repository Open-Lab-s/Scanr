# Scanr

Scanr is an open-source DevSecOps security engine built in Rust.

The repository is organized as a Rust workspace with two primary crates:

- `scanr-cli`: user-facing command-line interface (`scanr`)
- `scanr-core`: shared domain logic used by the CLI and future integrations

## Current Milestone

Milestone 1 provides a working CLI skeleton with placeholder behavior:

- `scanr scan .`
- `scanr sbom generate`
- `scanr sbom diff old.json new.json`

## Workspace Layout

```text
F:\Scanr
├── crates/
│   ├── scanr-core/
│   └── scanr-cli/
├── installers/
├── docs/
└── Cargo.toml
```

## Build

```bash
cargo build --workspace --release
```

Use the pages in this documentation for details:

- **Scanr CLI**: commands, flags, and output behavior
- **Scanr Core**: crate role and API direction
- **Installation**: supported distribution channels
- **Development**: local build and contribution workflow

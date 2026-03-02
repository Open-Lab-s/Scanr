# Scanr

Scanr is an open-source DevSecOps security engine built in Rust.

The repository is organized as a Rust workspace with two primary crates:

- `scanr-cli`: user-facing command-line interface (`scanr`)
- `scanr-core`: shared domain logic used by the CLI and future integrations

## Current Milestone

Milestone 2 adds dependency parsing for Node.js, Python, and Rust projects:

- `scanr scan .`
- `scanr sbom generate`
- `scanr sbom diff old.json new.json`

Current `scanr scan <path>` support:

- Node.js: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`
- Python: `requirements.txt`, `pyproject.toml`, `poetry.lock`
- Rust: `Cargo.toml`, `Cargo.lock`

Use `scanr scan <path> --recursive` to scan nested projects in monorepos.

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

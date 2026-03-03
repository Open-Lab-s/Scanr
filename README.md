# Scanr

Scanr is a Rust security scanner focused on dependency intelligence for engineering teams.

It is split into:

- `scanr-cli`: end-user CLI and TUI (`scanr`)
- `scanr-core`: reusable scan engine and data models

## What Scanr Currently Does

- Parses dependencies from Node, Python, and Rust manifests
- Queries OSV for known vulnerabilities
- Produces remediation suggestions and upgrade recommendations
- Uses project-local OSV cache for fast and reproducible scans
- Supports offline scans from cache and explicit refresh mode
- Classifies risk (LOW / MODERATE / HIGH) with severity counters
- Enforces CI policy from `scanr.toml`
- Supports vulnerability baseline and security debt delta tracking
- Exports CycloneDX SBOM and computes SBOM diffs
- Emits machine-readable JSON and SARIF
- Provides a full-screen interactive terminal UI

## Install

```bash
# npm
npm install -g @openlabs/scanr_cli

# bun (uses npm package)
bun install -g @openlabs/scanr_cli

# Homebrew
brew install Open-Lab-s/tap/scanr

# cargo (source install)
cargo install --path crates/scanr-cli

# curl installer
curl -fsSL https://scanr.dev/install.sh | bash
```

## Quick Start

```bash
scanr scan .
scanr scan . --ci
scanr scan . --json
scanr scan . --sarif
scanr scan . --offline
scanr scan . --refresh
scanr scan . --baseline
scanr baseline save
scanr baseline status
scanr sbom generate
scanr sbom diff old.cdx.json new.cdx.json
```

Launch TUI:

```bash
scanr
```

## Documentation

- MkDocs source: [`docs/`](docs)
- Main pages:
  - [`docs/index.md`](docs/index.md)
  - [`docs/cli.md`](docs/cli.md)
  - [`docs/core.md`](docs/core.md)
  - [`docs/installation.md`](docs/installation.md)
  - [`docs/output-formats.md`](docs/output-formats.md)
  - [`docs/ci-policy.md`](docs/ci-policy.md)
  - [`docs/baseline.md`](docs/baseline.md)
  - [`docs/cache.md`](docs/cache.md)
  - [`docs/sbom.md`](docs/sbom.md)
  - [`docs/tui.md`](docs/tui.md)

Run docs locally:

```bash
mkdocs serve
```

## Workspace

```text
F:\Scanr
├── crates/
│   ├── scanr-core/
│   └── scanr-cli/
├── installers/
├── docs/
├── Cargo.toml
└── mkdocs.yml
```

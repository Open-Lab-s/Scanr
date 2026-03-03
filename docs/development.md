# Development

## Prerequisites

- Rust stable toolchain
- Git
- Node.js (only if testing npm wrapper flows)
- MkDocs (for docs preview)

## Build And Test

```bash
cargo build --workspace --release
cargo test --workspace
```

## Run Locally

```bash
# interactive TUI
cargo run -p scanr-cli --

# regular scan
cargo run -p scanr-cli -- scan .

# structured outputs
cargo run -p scanr-cli -- scan . --json
cargo run -p scanr-cli -- scan . --sarif

# SBOM operations
cargo run -p scanr-cli -- sbom generate
cargo run -p scanr-cli -- sbom diff old.cdx.json new.cdx.json
```

## Workspace Layout

```text
crates/scanr-engine   shared engine contracts and finding schema
crates/scanr-sca      SCA engine implementation and models
crates/scanr-cli      command and TUI frontend
installers/           packaging assets (npm, bun, brew, aur, curl)
docs/                 mkdocs source pages
```

## CI And Release Workflows

- `.github/workflows/ci.yml`
  - Builds workspace on push and pull request
- `.github/workflows/release.yml`
  - Builds release binaries for Linux/macOS/Windows
  - Publishes release assets for tag builds

## Package Distribution Files

- npm wrapper: `installers/npm`
- Homebrew formula: `installers/homebrew/scanr.rb`
- AUR package files: `installers/aur/PKGBUILD`, `installers/aur/.SRCINFO`
- curl bootstrap installer: `installers/install.sh`

## Docs Preview

```bash
mkdocs serve
```

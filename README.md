# Scanr
A fully open-source Rust-based DevSecOps security engine that scans dependencies, containers, Infrastructure as Code, and runtime behavior to detect vulnerabilities, license risks, and security misconfigurations directly within developer workflows.

## Workspace

This repository is a Rust workspace rooted at `F:\Scanr` with:

- `crates/scanr-core`: shared core library
- `crates/scanr-cli`: CLI binary (`scanr`)

Build:

```bash
cargo build --release
```

Run TUI:

```bash
scanr
```

## Supported Install Channels

- `cargo`
- `npm`
- `bun` (via npm package)
- `curl`
- `brew`
- `paru`

Installer scaffolding lives under [`installers/`](installers).

### Install Commands

```bash
# cargo (source install)
cargo install --path crates/scanr-cli

# npm
npm install -g @openlabs/scanr_cli

# bun (same npm wrapper)
bun install -g @openlabs/scanr_cli

# curl installer
curl -fsSL https://scanr.dev/install.sh | bash

# brew
brew install Open-Lab-s/tap/scanr

# paru via AUR
paru -S scanr
```

Run commands:

```bash
cargo run -p scanr-cli -- scan .
cargo run -p scanr-cli -- sbom generate
cargo run -p scanr-cli -- sbom diff old.json new.json
```

`scanr scan <path>` supports custom paths and can recursively scan manifest files with `--recursive`.

## Release Notes for Packagers

- NPM wrapper downloads prebuilt release binaries in `postinstall`.
- Curl installer downloads the target binary by OS/arch and installs to `~/.local/bin` by default.
- Homebrew and AUR files are in `installers/homebrew` and `installers/aur`.
- All scan output modes (`formatted`, `--json`, `--sarif`) are generated from the same core `ScanResult` model.

## Cargo Publish Checklist

```bash
cargo package --workspace
cargo publish -p scanr-core
cargo publish -p scanr-cli
```

Release flow:

1. Bump crate versions.
2. Tag release (`vX.Y.Z`).
3. Publish prebuilt binaries named:
   - `scanr-x86_64-unknown-linux-gnu`
   - `scanr-aarch64-unknown-linux-gnu`
   - `scanr-x86_64-apple-darwin`
   - `scanr-aarch64-apple-darwin`
   - `scanr-x86_64-pc-windows-msvc.exe`
4. Update Homebrew SHA256 values.
5. Commit and push tag; `.github/workflows/release.yml` publishes release assets and `sha256sums.txt`.

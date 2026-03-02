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

## Supported Install Channels

- `cargo`
- `npm`
- `curl`
- `brew`
- `paru`

Installer scaffolding lives under [`installers/`](installers).

### Install Commands

```bash
# cargo (works now from source)
cargo install --path crates/scanr-cli

# curl bootstrap script (scaffold)
sh installers/install.sh

# npm (scaffold, publish pending)
npm install -g @scanr/cli

# brew (scaffold, tap pending)
brew install scanr

# paru via AUR (scaffold, package pending)
paru -S scanr
```

Run commands:

```bash
cargo run -p scanr-cli -- scan .
cargo run -p scanr-cli -- sbom generate
cargo run -p scanr-cli -- sbom diff old.json new.json
```

`scanr scan <path>` supports custom paths and can recursively scan manifest files with `--recursive`.

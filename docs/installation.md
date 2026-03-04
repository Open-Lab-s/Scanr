# Installation

Scanr can be installed through multiple distribution channels.

## npm (Recommended for end users)

```bash
npm install -g @openlabs/scanr_cli
```

Package page:

- `https://www.npmjs.com/package/@openlabs/scanr_cli`

## Bun

Bun uses the same npm package:

```bash
bun install -g @openlabs/scanr_cli
```

## Homebrew

```bash
brew install Open-Lab-s/tap/scanr
```

Tap repository:

- `https://github.com/Open-Lab-s/homebrew-tap`

## Cargo (crates.io)

```bash
cargo install scanr-cli --locked
```

Crates page:

- `https://crates.io/crates/scanr-cli`

## Published Rust Crates

| Crate | Purpose | Typical user |
| --- | --- | --- |
| `scanr-cli` | Installs the `scanr` command-line interface | CLI users, CI pipelines |
| `scanr-sca` | SCA engine library (dependency parsing + vuln resolution) | Rust app integrators |
| `scanr-engine` | Engine abstraction contracts (`ScanEngine`, `Finding`, `ScanResult`) | Engine/plugin developers |

Add library crates to your Rust project:

```bash
cargo add scanr-sca
cargo add scanr-engine
```

For local workspace development/testing:

```bash
cargo build --workspace --release
cargo install --path crates/scanr-cli --force
```

## curl Installer

```bash
curl -fsSL https://scanr.dev/install.sh | bash
```

Supported installer environment variables:

- `SCANR_VERSION` (default: `latest`)
- `SCANR_INSTALL_DIR` (default: `$HOME/.local/bin`)
- `SCANR_REPO` (default: `Open-Lab-s/Scanr`)

## Paru / AUR

```bash
paru -S scanr
```

Note: AUR package publication depends on AUR registry sync and maintainer push status.

## Verify Installation

```bash
scanr --version
scanr --help
```

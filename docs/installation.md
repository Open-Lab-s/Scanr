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

## Cargo (source install)

```bash
cargo install --path crates/scanr-cli
```

For local workspace development:

```bash
cargo build --workspace --release
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

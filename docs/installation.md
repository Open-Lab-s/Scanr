# Installation

Scanr supports these installation channels:

- `cargo`
- `npm`
- `bun` (via npm package)
- `curl`
- `brew`
- `paru`

## Cargo

Use Cargo for local and source-based installs:

```bash
cargo install --path crates/scanr-cli
```

## NPM

NPM distributes the **Scanr CLI** package with platform detection and binary download:

```bash
npm install -g @openlabs/scanr_cli
```

## Bun

Bun uses the same npm wrapper package:

```bash
bun install -g @openlabs/scanr_cli
```

## Curl

Install from the hosted installer:

```bash
curl -fsSL https://scanr.dev/install.sh | bash
```

Optional installer environment variables:

- `SCANR_VERSION` (default: `latest`)
- `SCANR_INSTALL_DIR` (default: `$HOME/.local/bin`)
- `SCANR_REPO` (default: `Open-Lab-s/Scanr`)

## Homebrew

```bash
brew install Open-Lab-s/tap/scanr
```

## Paru (AUR)

```bash
paru -S scanr
```

## Status Notes

- Cargo install from source works now.
- NPM wrapper is ready and expects prebuilt release binaries.
- Curl installer is ready and expects published release binaries.
- Homebrew and Paru packaging files are maintained in `installers/`.
- Homebrew formula and AUR PKGBUILD must be updated for each release checksum.
- GitHub release workflow (`.github/workflows/release.yml`) publishes binaries and `sha256sums.txt` for packaging updates.

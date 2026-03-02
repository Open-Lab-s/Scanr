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
npm install -g scanr
```

## Bun

Bun uses the same npm wrapper package:

```bash
bun install -g scanr
```

## Curl

Install from the hosted installer:

```bash
curl -fsSL https://scanr.dev/install.sh | bash
```

Optional installer environment variables:

- `SCANR_VERSION` (default: `latest`)
- `SCANR_INSTALL_DIR` (default: `$HOME/.local/bin`)
- `SCANR_REPO` (default: `scanr-dev/scanr`)

## Homebrew

```bash
brew install scanr
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
- For Homebrew formula publishing, replace `REPLACE_WITH_SHA256`.
- For AUR production publishing, replace `sha256sums=("SKIP")` with real hashes.
- GitHub release workflow (`.github/workflows/release.yml`) publishes binaries and `sha256sums.txt` for packaging updates.

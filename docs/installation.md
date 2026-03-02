# Installation

Scanr supports these installation channels:

- `cargo`
- `npm`
- `curl`
- `brew`
- `paru`

## Cargo

Use Cargo for local and source-based installs:

```bash
cargo install --path crates/scanr-cli
```

## NPM

NPM distributes the **Scanr CLI** package:

```bash
npm install -g @scanr/cli
```

## Curl

Bootstrap shell installer:

```bash
sh installers/install.sh
```

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
- NPM, Homebrew, and Paru packaging files are scaffolded and become fully usable once release artifacts are published.

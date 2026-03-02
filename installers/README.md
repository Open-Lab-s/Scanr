# Installer Channels

Scanr supports these distribution channels:

- `cargo`: source install from this workspace
- `npm`: Node package distribution
- `curl`: bootstrap shell installer (`installers/install.sh`)
- `brew`: Homebrew formula
- `paru`: AUR package consumed via `paru`

## Channel Mapping

- `cargo`: handled by workspace crates (`crates/scanr-cli`)
- `npm`: `installers/npm/package.json`
- `curl`: `installers/install.sh`
- `brew`: `installers/homebrew/scanr.rb`
- `paru`: `installers/aur/PKGBUILD`

## Notes

- `brew` and `paru` package files are scaffolds until release artifacts and checksums are published.
- `npm` package is scaffolded and not yet published to npm.

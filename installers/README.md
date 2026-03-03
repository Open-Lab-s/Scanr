# Installer Channels

Scanr supports these distribution channels:

- `cargo`: source install from this workspace
- `npm`: Node package distribution
- `bun`: uses the same npm package
- `curl`: bootstrap shell installer (`installers/install.sh`)
- `brew`: Homebrew formula
- `paru`: AUR package consumed via `paru`

## Channel Mapping

- `cargo`: handled by workspace crates (`crates/scanr-cli`)
- `npm`/`bun`: `installers/npm/package.json`, `installers/npm/bin/scanr.js`, `installers/npm/scripts/install.js`
- `curl`: `installers/install.sh`
- `brew`: `installers/homebrew/scanr.rb`
- `paru`: `installers/aur/PKGBUILD`

## Notes

- npm/bun wrapper expects published prebuilt release binaries.
- npm package name: `@openlabs/scanr_cli`.
- curl installer expects published prebuilt release binaries.
- brew and paru files require checksum updates for each release.

Expected release asset names:

- `scanr-x86_64-unknown-linux-gnu`
- `scanr-aarch64-unknown-linux-gnu`
- `scanr-x86_64-apple-darwin`
- `scanr-aarch64-apple-darwin`
- `scanr-x86_64-pc-windows-msvc.exe`

Default release repository used by installers:

- `https://github.com/Open-Lab-s/Scanr`

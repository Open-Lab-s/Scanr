#!/usr/bin/env sh
set -eu

VERSION="${SCANR_VERSION:-latest}"
INSTALL_DIR="${SCANR_INSTALL_DIR:-/usr/local/bin}"

echo "Scanr curl installer (bootstrap)"
echo "Requested version: ${VERSION}"
echo "Install directory: ${INSTALL_DIR}"
echo
echo "Release binaries are not published yet."
echo "Current supported install channels:"
echo "  - cargo: cargo install --path crates/scanr-cli"
echo "  - npm: npm install -g @scanr/cli (once published)"
echo "  - brew: brew install scanr (once tap is published)"
echo "  - paru: paru -S scanr (once AUR package is published)"

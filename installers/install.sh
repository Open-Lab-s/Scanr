#!/usr/bin/env sh
set -eu

REPO="${SCANR_REPO:-Open-Lab-s/Scanr}"
VERSION="${SCANR_VERSION:-latest}"
INSTALL_DIR="${SCANR_INSTALL_DIR:-$HOME/.local/bin}"

detect_os() {
  case "$(uname -s)" in
    Linux) echo "unknown-linux-gnu" ;;
    Darwin) echo "apple-darwin" ;;
    *)
      echo "Unsupported OS: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

download_url() {
  asset="$1"
  if [ "$VERSION" = "latest" ]; then
    echo "https://github.com/${REPO}/releases/latest/download/${asset}"
  else
    echo "https://github.com/${REPO}/releases/download/v${VERSION}/${asset}"
  fi
}

ARCH="$(detect_arch)"
OS="$(detect_os)"
ASSET="scanr-${ARCH}-${OS}"
URL="$(download_url "$ASSET")"

echo "Installing Scanr"
echo "  repo:    ${REPO}"
echo "  version: ${VERSION}"
echo "  target:  ${ARCH}-${OS}"
echo "  url:     ${URL}"
echo "  dir:     ${INSTALL_DIR}"

mkdir -p "$INSTALL_DIR"
TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/scanr.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT INT TERM

if ! curl -fsSL "$URL" -o "$TMP_FILE"; then
  echo "Download failed for ${URL}" >&2
  echo "If release artifacts are not published yet, install from source:" >&2
  echo "  cargo install --path crates/scanr-cli" >&2
  exit 1
fi

chmod +x "$TMP_FILE"
mv "$TMP_FILE" "${INSTALL_DIR}/scanr"
trap - EXIT INT TERM

echo
echo "Scanr installed: ${INSTALL_DIR}/scanr"
if ! command -v scanr >/dev/null 2>&1; then
  echo "Add to PATH if needed: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

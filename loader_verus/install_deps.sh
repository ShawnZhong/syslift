#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TOOLCHAIN_DIR="$SCRIPT_DIR/.toolchain"
INSTALL_DIR="$TOOLCHAIN_DIR/verus"

VERUS_VERSION=$(curl -fsSL https://api.github.com/repos/verus-lang/verus/releases/latest \
  | sed -n 's/.*"tag_name":[[:space:]]*"release\/\([^"]*\)".*/\1/p' \
  | head -n1)
ARCHIVE="verus-${VERUS_VERSION}-x86-linux.zip"
URL="https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/${ARCHIVE}"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TOOLCHAIN_DIR"
curl -fsSL -o "$TMP_DIR/$ARCHIVE" "$URL"
unzip -q "$TMP_DIR/$ARCHIVE" -d "$TMP_DIR"
rm -rf "$INSTALL_DIR"
mv "$TMP_DIR/verus-x86-linux" "$INSTALL_DIR"

if [[ -f "$HOME/.cargo/env" ]]; then
  source "$HOME/.cargo/env"
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
fi

source "$HOME/.cargo/env"
REQUIRED_TOOLCHAIN=$(sed -n 's/.*"toolchain":[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALL_DIR/version.json" | head -n1)
rustup toolchain install "$REQUIRED_TOOLCHAIN"

echo "installed verus=$VERUS_VERSION toolchain=$REQUIRED_TOOLCHAIN"

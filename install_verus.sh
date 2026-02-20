#!/usr/bin/env bash
set -euo pipefail

VERUS_DIR=".verus"

VERUS_VERSION="0.2026.02.15.61aa1bf"
RUST_TOOLCHAIN="1.93.0-x86_64-unknown-linux-gnu"
ARCHIVE="verus-${VERUS_VERSION}-x86-linux.zip"
URL="https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/${ARCHIVE}"

mkdir -p "$VERUS_DIR"

ARCHIVE_PATH="$VERUS_DIR/$ARCHIVE"
curl -fsSL -o "$ARCHIVE_PATH" "$URL"
unzip -qo "$ARCHIVE_PATH" -d "$VERUS_DIR"

if [[ -f "$HOME/.cargo/env" ]]; then
  source "$HOME/.cargo/env"
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
fi

source "$HOME/.cargo/env"
rustup toolchain install "$RUST_TOOLCHAIN"

echo "installed verus=$VERUS_VERSION toolchain=$RUST_TOOLCHAIN"

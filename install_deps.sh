#!/usr/bin/env bash
set -euo pipefail

PACKAGES=(
  bear
  build-essential
  ca-certificates
  clang-18
  lld-18
  llvm-18
  llvm-18-dev
  make
  pkg-config
)

sudo apt-get update
sudo apt-get install -y "${PACKAGES[@]}"

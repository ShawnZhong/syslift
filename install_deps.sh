#!/usr/bin/env bash
set -euo pipefail

PACKAGES=(
  bear
  build-essential
  ca-certificates
  clang
  lld
  llvm
  llvm-dev
  make
  pkg-config
)

sudo apt-get update
sudo apt-get install -y "${PACKAGES[@]}"

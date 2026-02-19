#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <input.c> <output-prefix> [pass-plugin.so]" >&2
  exit 1
fi

input_src="$1"
out_prefix="$2"
plugin_path="${3:-build/libSysliftCollectSyscallsPass.so}"

mkdir -p "$(dirname "$out_prefix")"

clang -O2 -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -Ithird_party/nolibc -fpass-plugin="$plugin_path" \
  -nostdlib -static "$input_src" -o "${out_prefix}"

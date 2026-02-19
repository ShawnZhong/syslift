#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <input.c> <output-prefix> [pass-plugin.so]" >&2
  exit 1
fi

input_src="$1"
out_prefix="$2"
plugin_path="${3:-build/libSysliftCollectSyscallsPass.so}"
start_src="samples/start.S"

mkdir -p "$(dirname "$out_prefix")"

clang -O2 -S -emit-llvm "$input_src" -o "${out_prefix}.ll"
llc -stop-after=prologepilog "${out_prefix}.ll" -o "${out_prefix}.pre.mir"
llc --load="$plugin_path" -run-pass=syslift-collect-syscalls "${out_prefix}.pre.mir" -o "${out_prefix}.mir"
llc -start-after=prologepilog -filetype=obj "${out_prefix}.mir" -o "${out_prefix}.o"
clang -c "$start_src" -o "${out_prefix}.start.o"
clang -nostdlib -static -fuse-ld=lld -Wl,-e,_start \
  "${out_prefix}.start.o" "${out_prefix}.o" -o "${out_prefix}.elf"

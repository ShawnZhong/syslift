#!/usr/bin/env bash
set -u

make

run() {
  echo
  echo "Running: $*"
  "$@"
  echo "exit=$?"
}

run build/getpid.elf
run build/loader build/getpid.elf
run build/loader --allow 172 build/getpid.elf
run build/loader --deny 172 build/getpid.elf

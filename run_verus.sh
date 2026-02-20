#!/usr/bin/env bash
set -u

make
make verus

NR_EXIT=60
NR_WRITE=1

run() {
  echo
  printf "\033[34mRunning: \`$*\`\033[0m\n"
  "$@"
  rc=$?
  if [[ $rc -eq 0 ]]; then
    printf "\033[32mexit=%d\033[0m\n" "$rc"
  else
    printf "\033[31mexit=%d\033[0m\n" "$rc"
  fi
}

run loader_verus/main build/write "$NR_EXIT,$NR_WRITE"

run loader_verus/main build/write "$NR_EXIT"

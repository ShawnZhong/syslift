#!/usr/bin/env bash
set -u

make

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

run build/getpid
run build/loader --debug --allow 172 build/getpid
run build/loader --deny 172 build/getpid

run build/write
run build/loader build/write
run build/loader --deny 64 build/write

run build/print_pid
run build/loader build/print_pid
run build/loader --deny 172 build/print_pid

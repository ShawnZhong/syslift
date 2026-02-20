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

run build/loader --debug --allow exit,getpid build/getpid
run build/loader --hook getpid,exit build/getpid
run build/loader --deny getpid build/getpid

run build/loader build/write
run build/loader --deny write build/write

run build/loader build/print_pid
run build/loader --deny getpid build/print_pid

run build/loader build/print_args -- one two three

run build/loader --debug build/reject

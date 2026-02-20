#!/usr/bin/env bash
set -u

make

ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64)
    NR_EXIT=93
    NR_GETPID=172
    NR_WRITE=64
    ;;
  x86_64|amd64)
    NR_EXIT=60
    NR_GETPID=39
    NR_WRITE=1
    ;;
  *)
    echo "unsupported host arch: $ARCH"
    exit 1
    ;;
esac

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

run build/loader --debug --allow "$NR_EXIT,$NR_GETPID" build/getpid
run build/loader --hook "$NR_GETPID,$NR_EXIT" build/getpid
run build/loader --deny "$NR_GETPID" build/getpid

run build/loader build/write
run build/loader --deny "$NR_WRITE" build/write

run build/loader build/print_pid
run build/loader --deny "$NR_GETPID" build/print_pid

run build/loader build/print_args -- one two three

run build/loader --debug build/reject

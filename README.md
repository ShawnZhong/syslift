# syslift

[![CI](https://github.com/ShawnZhong/syslift/actions/workflows/ci.yml/badge.svg)](https://github.com/ShawnZhong/syslift/actions/workflows/ci.yml)

`syslift` turns load time into a trust gate. Most policy systems decide too late (after the process is already running) or require full sandbox machinery.

`syslift` shifts policy to the loader boundary:
1. Build time: mark sensitive sites and replace behavior with safe defaults.
2. Load time: verify policy and selectively re-enable only approved behavior.
3. Runtime: execute with exactly the approved surface.

For syscalls, the default is fail-closed (`-ENOSYS`) until explicitly allowed.

## Vision: Load-Time Program Contracts

The long-term goal is not only syscall filtering. It is to make load time the point where program intent is verified, policy is realized, and execution becomes auditable.

Contract surface can include:

- Syscalls / kernel API surface: which syscalls are allowed, plus `ioctl`, `prctl`, `bpf()`, and related interfaces.
- Filesystem behavior: path-level and mode-level intent (read/write/create/delete/rename, metadata operations).
- Network behavior: domains, protocols, ports, DNS resolution behavior.
- Process behavior: `execve`, `fork/clone`, signals, `ptrace`, `setns`, `setuid`, `capset`, and related process-control APIs.
- Control-flow integrity behavior: constrain indirect control-flow targets to approved sets.
- Information-flow behavior (taint contracts): constrain how sensitive data can flow from sources (secrets, PII, credentials, key material) to sinks (logs, network, files, IPC, diagnostics).

## Quick Demo

```bash
./run.sh
```

Example output below is from AArch64.

```diff
Running: `build/loader --debug --allow 93,172 build/getpid`
.syslift entries=7
table[0] site_vaddr=0x400280 vals=[172,   ?,   ?,   ?,   ?,   ?,   ?]
table[1] site_vaddr=0x4002b8 vals=[ 93,   ?,   ?,   ?,   ?,   ?,   ?]
table[2] site_vaddr=0x4002e4 vals=[172,   ?,   ?,   ?,   ?,   ?,   ?]
table[3] site_vaddr=0x4002f4 vals=[129,   ?,   ?,   ?,   ?,   ?,   ?]
table[4] site_vaddr=0x4004e4 vals=[172,   ?,   ?,   ?,   ?,   ?,   ?]
table[5] site_vaddr=0x4004f4 vals=[129,   ?,   6,   ?,   ?,   ?,   ?]
table[6] site_vaddr=0x4002cc vals=[172,   ?,   ?,   ?,   ?,   ?,   ?]
site_vaddr=0x400280 sys_nr=172 action=PATCHED
site_vaddr=0x4002b8 sys_nr=93 action=PATCHED
site_vaddr=0x4002e4 sys_nr=172 action=PATCHED
site_vaddr=0x4002f4 sys_nr=129 action=ENOSYS
site_vaddr=0x4004e4 sys_nr=172 action=PATCHED
site_vaddr=0x4004f4 sys_nr=129 action=ENOSYS
site_vaddr=0x4002cc sys_nr=172 action=PATCHED
start executing: entry_pc=0x4002c0
+ exit=0

Running: `build/loader --hook 172,93 build/getpid`
hook site=0x400280 nr=172 args=[281473172045776, 281473172045776, 3, 131106, 18446744073709551615, 0]
hook site=0x4002b8 nr=93 args=[0, 281473172045776, 3, 131106, 18446744073709551615, 0]
+ exit=0

Running: `build/loader --deny 172 build/getpid`
- exit=1

Running: `build/loader build/write`
hello, world!
+ exit=0

Running: `build/loader --deny 64 build/write`
- exit=1

Running: `build/loader build/print_pid`
pid: <pid>
+ exit=0

Running: `build/loader --deny 172 build/print_pid`
pid: -38
- exit=1

Running: `build/loader build/print_args -- one two three`
argc: 4
argv[0]: build/print_args
argv[1]: one
argv[2]: two
argv[3]: three
+ exit=0

Running: `build/loader --debug build/reject`
.syslift entries=7
table[0] site_vaddr=0x400290 vals=[  ?,   1,   2,   3,   4,   5,   6]
untrusted input: unknown syscall nr in .syslift (site_vaddr=0x400290)
- exit=1
```

## Current Implementation

The LLVM pass (`pass/SysliftCollectSyscalls.cpp`) finds syscall inline-asm sites (`svc #0` on AArch64, `syscall` on x86_64), records them in `.syslift` (nr + arg1..arg6 value/knownness metadata), and rewrites syscall sites to return `-ENOSYS` by default.

The loader (`build/loader`) reads `.syslift` at load time and patches selected sites back to the architecture syscall instruction according to policy flags.

This gives load-time verification and activation of kernel API surface without requiring sandboxing.

## Repository Layout

- `pass/`: LLVM pass plugin (`build/libSysliftCollectSyscallsPass.so`)
- `loader/`: load-time verifier/patcher (`build/loader`)
- `samples/`: sample programs built with policy instrumentation


## Loader Usage

```bash
build/loader [--debug] [--hook <nr>...] [--allow <nr>...] [--deny <nr>...] <elf-file> [-- <args...>]
```

Policy:
- `--hook`: patch listed syscall numbers to a loader stub that dispatches to the framework hook handler
- default (no flags): allow all recorded syscalls (patch all listed sites)
- `--allow`: only patch listed syscall numbers
- `--deny`: patch everything except listed syscall numbers
- passing both `--allow` and `--deny` is an error
- `--hook` takes precedence over `--allow`/`--deny` for matching syscall numbers
- in `--allow` mode, include your arch's `exit` syscall number if you want normal program termination (`93` on AArch64, `60` on x86_64)
- arguments after `--` are passed to the loaded program as `argv[1..]` (`argv[0]` is `<elf-file>`)

`--debug` prints parsed `.syslift` entries (`vals=[nr,arg1..arg6]` with `?` for unknown), per-site patch decisions, and entry address.

## ELF Metadata

Section name: `.syslift`

```c
struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t known_mask;       // bit0=nr, bit1..6=arg1..arg6
  uint64_t values[7];        // [0]=nr, [1..6]=arg1..arg6
} __attribute__((packed));
```

Inspect:

```bash
llvm-readelf -x .syslift build/getpid
```

## Build Other Programs With syslift Pass

Equivalent command used by `samples/build.mk`:

```bash
clang -O2 -Ithird_party/nolibc \
  -fpass-plugin=build/libSysliftCollectSyscallsPass.so \
  -nostdlib -static input.c -o output
```

## Current Scope

- Supports `ET_EXEC` ELF64 little-endian binaries for AArch64 and x86_64.
- Syscall sites are always recorded in `.syslift`; sites are rewritten to `-ENOSYS` by default, and non-constant nr register sites are rejected by the loader because `nr` is unknown.
- Loader rejects binaries if it finds any raw syscall instruction in executable `PT_LOAD` segments before patching.
- Hook mode (`--hook`) is implemented for AArch64 and x86_64.
- Loader enforces W^X at mapping time: writable load segments are mapped non-executable.

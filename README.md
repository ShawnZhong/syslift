# syslift

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
- Resource behavior: CPU time, memory footprint, file descriptors, threads, and rlimits.

## Quick Demo

```bash
./run.sh
```

## Current Implementation (AArch64)

The LLVM pass (`pass/SysliftCollectSyscalls.cpp`) finds `svc #0` inline-asm sites, records them in `.syslift`, and rewrites them to return `-ENOSYS` by default (except `exit`, syscall `93`).

The loader (`build/loader`) reads `.syslift` at load time and patches selected sites back to `svc #0` according to policy flags.

This gives load-time verification and activation of kernel API surface without requiring sandboxing.

## Repository Layout

- `pass/`: LLVM pass plugin (`build/libSysliftCollectSyscallsPass.so`)
- `loader/`: load-time verifier/patcher (`build/loader`)
- `samples/`: sample programs built with policy instrumentation


## Loader Usage

```bash
build/loader [--debug] [--allow <nr>...] [--deny <nr>...] <elf-file>
```

Policy:
- default (no flags): allow all recorded syscalls (patch all listed sites)
- `--allow`: only patch listed syscall numbers
- `--deny`: patch everything except listed syscall numbers
- passing both `--allow` and `--deny` is an error

`--debug` prints per-site decisions and entry address.

## ELF Metadata

Section name: `.syslift`

```c
struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t sys_nr;
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

- AArch64 only.
- Loader currently accepts `ET_EXEC` AArch64 ELF64 little-endian binaries.
- Detection currently targets inline asm containing `svc #0` with constant `{x8}` syscall number.

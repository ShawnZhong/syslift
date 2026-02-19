# TODO: x86_64 Support in syslift

## Goal
Complete and validate first-class x86_64 support while keeping architecture-generic structure for AArch64 + x86_64.

## 1. Pass correctness (LLVM)
- [ ] Verify x86_64 syscall detection coverage:
  - [ ] `asm("syscall")`
  - [ ] variants with whitespace/newlines
  - [ ] avoid accidental matches in unrelated asm strings
- [ ] Validate x86 register-to-argument mapping end-to-end:
  - [ ] `rax -> nr`
  - [ ] `rdi,rsi,rdx,r10,r8,r9 -> arg1..arg6`
- [ ] Confirm unknown syscall number behavior:
  - [ ] non-constant `rax` should emit `.syslift` record with unknown nr
  - [ ] warning is emitted once per site
- [ ] Confirm x86 patch slot is always fixed-size and stable:
  - [ ] replacement asm remains exactly 8 bytes (`mov rax, imm32` + `nop`)
  - [ ] loader patch size matches this exactly
- [ ] Add pass-level test inputs for x86_64 and verify generated asm/ELF section layout.

## 2. Loader arch abstraction
- [ ] Keep all arch-specific instruction encodings in one place (`program.cpp` helpers).
- [ ] Verify scanner logic for executable segments:
  - [ ] AArch64 rejects any `svc #0` before patching
  - [ ] x86_64 rejects any `syscall` (`0F 05`) before patching
- [ ] Validate syscall restoration per arch:
  - [ ] AArch64 writes `svc #0`
  - [ ] x86_64 writes `syscall` + padding nops in the reserved slot
- [ ] Keep fail-fast behavior for unsupported hook on x86_64:
  - [ ] `--hook` on x86_64 should throw immediately with clear error
- [ ] Add explicit debug print of detected ELF arch in `--debug` mode.

## 3. End-to-end x86_64 execution validation
- [ ] Build x86_64 sample binaries with pass enabled in a proper x86_64 toolchain environment.
- [ ] Run loader tests on x86_64:
  - [ ] default allow-all path
  - [ ] `--allow` subset
  - [ ] `--deny` subset
  - [ ] reject unknown syscall nr
  - [ ] reject raw syscall instruction when not patched through table
- [ ] Add one x86-specific reject sample (dynamic syscall nr) to ensure loader rejection path is tested.

## 4. Build system and tooling
- [ ] Add optional x86_64 sample build target (`make samples-x86_64`) when cross toolchain is available.
- [ ] Keep current host build path unchanged.
- [ ] Add a short check target to run x86 smoke tests (compile-time checks) even on non-x86 hosts.
- [ ] Add CI matrix job(s):
  - [ ] AArch64 (existing behavior)
  - [ ] x86_64 (new behavior)

## 5. Docs and examples
- [ ] Update README examples to avoid hardcoded syscall numbers where possible.
- [ ] Document syscall number differences by arch (exit/getpid/write quick reference).
- [ ] Document current limitation clearly:
  - [ ] hook supported on AArch64 only
- [ ] Add short x86_64 demo command block.

## 6. Optional cleanup (after x86 lands)
- [ ] Revisit naming: `patch_syscall_to_svc` could become arch-neutral (`patch_syscall_to_insn`).
- [ ] Add tiny unit tests for parser/scanner helpers in loader.
- [ ] Minimize duplicated arch branches if they grow.

## Resume command checklist
- [ ] `make -j4`
- [ ] `./run.sh` (AArch64 regression)
- [ ] x86 pass smoke compile (`clang -target x86_64-linux-gnu ... -S`)
- [ ] x86 end-to-end loader run on x86_64-capable environment

Below is an **implementation plan for AArch64** that matches your constraints:

* **Statically compiled PIE** with minimal libc (e.g., `nolibc`-style).
* **Program remains a normal valid Linux executable** when run with the stock kernel loader (no custom loader required).
* With **your loader**, you (optionally) patch syscall sites to branch into a **loader stub region** (for checks, logging, etc.).
* A **syscall site table in an ELF section** is produced at compile time and used to **verify** the executable: every syscall instruction in `.text` must correspond **exactly** to the table, and vice versa.
* **No seccomp**.

This is written so you can hand it to a coding agent to implement.

---

## A. Overall architecture

### Key idea

1. **Keep real syscalls in `.text`** so the program runs normally without your loader.
2. During compilation, collect **all syscall instruction sites** into a table in a dedicated ELF section (e.g., `.note.syslift`).
3. A post-link verifier checks that:

   * every syscall instruction in executable code matches a table entry exactly, and
   * there are no “hidden” syscall instructions.
4. Your custom loader optionally:

   * maps the program (single contiguous mapping is fine),
   * generates a **stub region** (in that same mapping),
   * patches each syscall instruction (`svc #0`) into a **branch-with-link** (`bl stub_i`) to run checks and then perform the syscall.

This gives you:

* **Normal execution**: `svc #0` executes directly.
* **Loader execution**: `svc #0` replaced with `bl stub_i` → checks → `svc #0` in stub → return.

---

## B. Concrete binary contract

### 1) Syscall instruction form in `.text`

Require syscall sites to use exactly:

* **AArch64 `svc #0`** (imm == 0)

(If you want to allow other imm values later, encode imm16 in the table too, but start with `#0` only.)

### 2) Syscall number convention

Linux AArch64 syscall ABI uses:

* syscall number in `x8`
* args in `x0..x5`
* return in `x0`

You want to reject “dynamic syscall number”, so require:

* at each syscall site, `x8` must be a **compile-time constant** on all paths reaching `svc #0`.

Enforcement strategy:

* LLVM pass proves `x8` constant and emits it in the table.
* Post-link verifier double-checks (at least for common patterns).

### 3) Patchability requirement

You will patch **one 4-byte instruction** in place:

* replace `svc #0` with `bl <stub_i>`

So each syscall site must be in a code region where overwriting that 4-byte word is safe.

### 4) Stub reachability requirement

AArch64 `bl` has a **±128MB** range.
You said “stub region should be mapped in a single mmap with the rest of the code”. Enforce:

* the stub region is placed within ±128MB of all syscall sites (if not, use veneers; but your plan suggests you can arrange layout to avoid veneers).

---

## C. Syscall site table format (ELF section)

Create a packed array in a named section, e.g. `.note.syslift` (or `.syslift`).

Recommended struct (PIE-relative offsets):

```c
// All little-endian.
struct syslift_syscall_site {
  uint32_t site_rva;     // offset from image base (or from .text start)
  uint32_t sys_nr;       // constant syscall number
  uint16_t flags;        // bit0: patchable, bit1: has_checks, etc.
  uint16_t reserved;
};
```

Also include a header in the section:

```c
struct syslift_syscall_table_hdr {
  uint32_t magic;        // 'syslift0'
  uint16_t version;      // 1
  uint16_t entry_size;   // sizeof(syslift_syscall_site)
  uint32_t count;
};
```

**Important:** Use RVAs rather than absolute VAs so the table is stable under PIE relocation.

---

## D. LLVM implementation plan (no source changes)

You need LLVM to:

1. **identify syscall instructions** in generated code (`svc`)
2. **prove syscall number is constant** (`x8` constant at that site)
3. **emit the table into an ELF section**

### D1) Where to implement: Machine-level pass (recommended)

Inline asm is hard to reason about at IR level, but after instruction selection, `svc` becomes a real MachineInstr. So do it in the AArch64 backend as a `MachineFunctionPass` (or MIR pass).

**Pass: `AArch64CollectSyscallSites`**

* Run late enough that:

  * you see final `SVC` instructions
  * register allocation is done (or at least you can reason about virtual regs reliably)

**Detection:**

* Scan MachineBasicBlocks for `SVC` MachineInstr.
* Require it is `svc #0`. (In LLVM AArch64 backend, this is typically an opcode with an immediate operand.)

**Const-syscall check (reject dynamic):**

* For each `SVC`, compute the reaching definition for `X8` at that point.
* Accept only when you can prove `X8 = constant` along all predecessors.

  * Conservative implementation: require in the same basic block, immediately dominating the `SVC`, a move-immediate into X8 (or a small whitelist of equivalent constant forms).
  * If there are multiple paths, require they agree on the same constant; otherwise reject.
* Record `sys_nr`.

**Record the site:**

* Attach an internal symbol/label at the exact instruction address (MC-level label) or record the MachineInstr index for later lowering.

### D2) Emitting the ELF section from LLVM

There are two practical approaches:

**Approach A (cleaner end-to-end, more LLVM-internals work):**

* Use `MCStreamer` / `AsmPrinter` hooks to emit `.syslift` entries with relocations against labels at syscall sites.
* Each entry uses a relocation to compute `site_rva`.
* This is how sanitizers and profiling metadata often work.

**Approach B (simpler engineering, two-step with a post-link tool):**

* LLVM pass emits a temporary “sidecar” map file (or embedded `.llvm_addrsig`-like metadata).
* A post-link tool reads DWARF / `.symtab` labels for syscall sites and writes the final `.syslift` section into the ELF (using `objcopy`-style rewriting or `llvm-objcopy` APIs).

If you want “LLVM passes build the source file” in one go, pick **Approach A**.

### D3) Build-time enforcement: reject hidden syscalls

In addition to the pass, add a **final build verifier step**:

* scan `.text` for AArch64 `svc` encodings
* ensure every `svc` found corresponds to a table entry
* ensure the table has no extra entries not found in code

This catches:

* weird inline asm that produced `svc` you didn’t record
* toolchain bugs
* any attempt to bypass recording

---

## E. Post-link verifier (table ↔ code equivalence)

Implement a verifier tool `syslift-elf-verify`:

### Inputs:

* ELF binary (static PIE)

### Steps:

1. Parse ELF, locate:

   * executable segments / `.text` boundaries
   * `.note.syslift` (or chosen section)
2. Decode the table header, validate `magic/version/count`.
3. Scan executable code for syscall instructions:

   * In AArch64, `svc` has a recognizable encoding; implement a 4-byte aligned scan:

     * for each 4-byte word in RX text: check if it matches `svc` pattern (and imm==0).
4. Build a set of syscall instruction RVAs found in code.
5. Compare to table entries:

   * Every table `site_rva` must be present in code set.
   * Every code `svc` site must be present in table.
6. (Optional but recommended) Also verify `x8` constant at each site in code:

   * Lightweight check: look backward within the same basic block for a `movz/movk` sequence setting `x8` to the recorded `sys_nr`.
   * Keep it conservative; if uncertain, fail (or rely on LLVM pass correctness).

Result: if verification passes, you know `.text` has **exactly** the syscall sites you expect.

---

## F. Loader implementation (single mmap, optional patching)

You want a custom loader that runs the program and optionally replaces syscall instructions.

### Loader flow

1. Open ELF, parse program headers.
2. Reserve **one contiguous mapping** large enough for all PT_LOAD segments **plus a stub region** (and optional thunk/veneer region).
3. Map the image RW initially.
4. Copy PT_LOAD contents into place; zero bss.
5. Apply relocations (static PIE needs relocations).
6. Locate `.note.syslift` table in the mapped image.
7. (Optional) Run the same verification as `syslift-elf-verify` on the mapped memory (belt-and-suspenders).
8. Allocate stub region inside the contiguous mapping and generate stub code:

   * One stub per syscall site (simplest) or per syscall number/policy class.
   * Stub does:

     * optional checks (your policy)
     * load `x8 = sys_nr`
     * `svc #0`
     * `ret`
9. Patch each syscall site:

   * overwrite the 4-byte `svc #0` instruction at `site_rva` with `bl stub_i`
   * ensure stub is within ±128MB; otherwise pre-plan stub placement (or add veneers—ideally avoid by layout).
10. Set page protections:

* `.text` RX
* stub region RX
* data RW

11. Jump to ELF entry point.

### “Regular valid program without our loader”

Because the binary still contains real `svc #0` at syscall sites:

* executed normally by the kernel loader, it runs fine.
* the syscall table section is ignored by the kernel loader, harmless.

---

## G. Minimal policy/checking support (inside stubs)

Since you don’t want seccomp, any “checking” must happen in the stub before `svc`.

Keep checks intentionally simple and based on scalar args:

* deny syscall numbers not allowed (already enforced by table / which stubs exist)
* optional argument masks (e.g., flags)
* optional fd allowlists (compare against loader-provided constants)
* optional size caps

(Without CET/IBT or seccomp, do not over-claim robustness against memory-corruption-driven control-flow hijack; but you said you’re fine not implementing CET/IBT.)

---

## H. Deliverables for the coding agent

1. **LLVM AArch64 Machine pass**

   * detects `svc #0`
   * proves/records constant `x8` syscall number
   * emits `.note.syslift` with relocations to site labels (preferred)

2. **`syslift-elf-verify` tool**

   * parses ELF
   * reads `.note.syslift`
   * scans `.text` for `svc`
   * checks bijection table ↔ code
   * (optional) checks `x8` const pattern

3. **Custom loader `syslift-loader`**

   * maps ELF into one contiguous region
   * applies relocations
   * reads syscall table
   * generates stub region
   * patches each `svc` to `bl stub`
   * sets final RX/RW protections
   * jumps to entry

4. **Build glue**

   * clang invocation enabling your pass
   * static PIE link flags
   * minimal libc (nolibc-style)
   * run `syslift-elf-verify` as part of build/CI

---

If you want, I can also provide:

* a recommended exact section naming/layout strategy to guarantee the stub region is always within ±128MB of syscall sites (so `bl` always works), and
* a minimal set of AArch64 instruction patterns to accept for “x8 is constant” that won’t reject typical nolibc syscall wrappers.

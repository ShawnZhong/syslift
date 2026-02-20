# loader_verus

`loader_verus` is a parser-first, x86_64-only verified loader prototype in Verus.

Scope:
- x86_64 only
- `--allow` policy model only
- no hook mode
- no bridge to the C++ loader
- trusted runtime boundary (`read`, map/exec handoff)

## Setup

```bash
./install_verus.sh
```

This installs:
- pinned Verus `0.2026.02.15.61aa1bf` (`x86-linux`) into `.verus/verus-x86-linux`
- pinned Rust toolchain `1.93.0-x86_64-unknown-linux-gnu`

## Verify

```bash
make verus
```

Expected output includes:

```text
verification results:: <N> verified, 0 errors
```

## Run

`main` now executes the full parse + allow-plan + patch pipeline and then calls a trusted runtime stub.

Quick sample (`write`):

```bash
./run_verus.sh
```

Direct binary:

```bash
loader_verus/main <elf-file> <allow-csv>
```

Example:

```bash
loader_verus/main build/getpid 60,39
```

## Spec (Verus)

The spec layer (`spec.rs`) describes security properties over parsed/patched programs:

- `raw_syscall_at`: x86_64 raw syscall opcode (`0x0f 0x05`) at a byte position.
- `program_has_exec_raw_syscall`: executable segments contain at least one raw syscall.
- `plan_matches_program`: plan entries align 1:1 with `.syslift` entries.
- `plan_respects_allow`: patched sites come only from `allow`.
- `site_is_patched_by_plan`: a virtual address is explicitly patched by plan.
- `output_syscalls_come_from_plan`: any executable raw syscall in output image comes from a planned patch site.
- `output_contains_only_allowed_syscalls`: top-level output goal; to-be-mapped image only exposes allowed syscalls.
- `reject_raw_syscall_spec`: if raw-syscall rejection returns `Ok`, input has no executable raw syscall.
- `allow_plan_spec`: plan alignment + allow-respect.
- `phase_parsed_ok`: parsed-program structural predicate (currently executable segment non-overlap).
- `build_to_be_mapped_contract`: top-level loader security contract used by the final processing API.

## How Verify Connects To Code

`make verus` runs Verus on `loader_verus/main.rs`, verifies modules, and compiles the `loader_verus/main` binary.

Main verified edges:
- `parse::parse_program` ensures `phase_parsed_ok`.
- `relocate::build_allow_patch_plan` ensures `plan_matches_program` and `plan_respects_allow`.
- `relocate::build_to_be_mapped_program` ensures `build_to_be_mapped_contract`.

Trusted runtime boundary:
- `main.rs` runtime mapping/jump path is ordinary Rust + `unsafe` and is intentionally trusted.
- Verification focuses on parser/reject/policy/patch planning/patch application properties.

## Proof and Exec split

- `spec.rs`: properties, predicates, and small proof lemmas.
- `parse.rs`, `reject.rs`, `relocate.rs`: executable Rust/Verus code with contracts.
- `parse::parse_program` ensures `phase_parsed_ok` on success.
- Program-based phase specs and APIs in `relocate.rs`:
  - phase predicates: `phase_parsed_ok`, `phase_rejected_ok`, `phase_planned_ok`, `phase_patched_ok`
  - `phase_reject_raw_syscalls(program) -> program`
  - `phase_build_allow_plan(program, allow) -> (program, plan)`
  - `phase_apply_patches(program, plan, allow) -> (program, plan)`
  - `build_to_be_mapped_program_phased(program, allow)`

Top-level processing entrypoint:

- `relocate::build_to_be_mapped_program(program, allow)` ensures on success:
  - `build_to_be_mapped_contract(&program, allow, &out_program, plan@)`

The pipeline also rejects executable segment data overlap and applies syscall patching in one pass over segment bytes, using per-segment patch marks instead of per-byte linear membership scans.

## Code Layout

- `model.rs`: constants and data model
- `parse.rs`: verified ELF + `.syslift` parsing
- `reject.rs`: verified rejection checks
- `relocate.rs`: verified allow-plan + patch pipeline for to-be-mapped bytes
- `spec.rs`: Verus spec predicates
- `main.rs`: minimal entry point + trusted runtime boundary
- `install_verus.sh` (repo root): Verus/toolchain bootstrap

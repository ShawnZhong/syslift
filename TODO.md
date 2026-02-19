# Syslift Verus Plan

## Phase 1: Verified Parsing (first target)
- [ ] Create `loader_verus/` as the isolated verification workspace.
- [ ] Define Verus data model for `.syslift`:
  - [ ] `SysliftSyscallSite` with `site_vaddr`, `known_mask`, `values[7]`.
  - [ ] constants for entry size and field offsets.
- [ ] Implement verified little-endian readers (`u32`, `u64`) with explicit bounds requirements.
- [ ] Implement verified single-entry parser (`parse_syslift_site`).
- [ ] Implement table parser (`parse_syslift_section`) that:
  - [ ] rejects invalid section length (`len % entry_size != 0`),
  - [ ] returns all entries in order.
- [ ] Add minimal proof obligations:
  - [ ] successful parse count equals `len / entry_size`,
  - [ ] parsing never reads outside the input bounds.
- [ ] Add a small Verus example proof/input to sanity-check parser behavior.

## Phase 2: Toolchain + Workflow
- [ ] Add `loader-verus/setup.sh` to bootstrap Verus.
- [ ] Add `loader-verus/verify.sh` to run parser verification in one command.
- [ ] Add `make verus-setup` and `make verus-verify` convenience targets.
- [ ] Document host limitations (e.g., missing prebuilt binaries on some architectures) and source-build fallback.

## Phase 3: Bridge to Existing Loader
- [ ] Define a stable serialized format contract shared by C++ and Verus parser.
- [ ] Add a C++ adapter that calls a Verus-verified parser output path (or validates against Verus parser output during tests).
- [ ] Keep runtime mmap/patch/jump logic as trusted code for now.

## Phase 4: Next Verified Checks (after parsing)
- [ ] Verify syscall-site structural validation rules:
  - [ ] unknown syscall number rejection,
  - [ ] unknown argument markers rejection policy.
- [ ] Verify policy decision logic (`allow`/`deny`/`hook`) as pure deterministic functions.
- [ ] Verify patch-plan generation (data-only), then execute plan in existing runtime code.

## Done Criteria (v1)
- [ ] `make verus-verify` passes on a supported host.
- [ ] Parser proofs cover `.syslift` size, field decode, and bounds safety.
- [ ] C++ loader uses the verified parse result for policy and patch decisions.

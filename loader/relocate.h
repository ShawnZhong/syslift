#pragma once

#include "parse.h"

#include <cstddef>
#include <cstdint>
#include <utility>

namespace syslift {

void patch_syscall_to_insn(Program &parsed, const SysliftSyscallSite &site);

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr);

uintptr_t install_hook_stub(const Program &parsed, uintptr_t hook_entry);

// Internal helpers shared by split relocation translation units.
inline constexpr size_t kPatchedSyscallInsnSize = 8;

std::pair<Segment *, size_t> find_executable_site(Program &parsed,
                                                  uint64_t site_vaddr,
                                                  size_t patch_size);

void patch_syscall_to_insn_aarch64(Program &parsed,
                                   const SysliftSyscallSite &site);
void patch_syscall_to_insn_x86_64(Program &parsed,
                                  const SysliftSyscallSite &site);

void patch_syscall_to_hook_aarch64(Program &parsed,
                                   const SysliftSyscallSite &site,
                                   uintptr_t hook_stub_addr);
void patch_syscall_to_hook_x86_64(Program &parsed,
                                  const SysliftSyscallSite &site,
                                  uintptr_t hook_stub_addr);

size_t write_hook_stub_aarch64(uint8_t *stub_bytes, size_t page_size,
                               uintptr_t hook_entry);
size_t write_hook_stub_x86_64(uint8_t *stub_bytes, size_t page_size,
                              uintptr_t hook_entry);

} // namespace syslift

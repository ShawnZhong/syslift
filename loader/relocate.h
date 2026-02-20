#pragma once

#include "parse.h"

#include <cstdint>

namespace syslift {

void patch_syscall_to_insn(Program &parsed, const SysliftSyscallSite &site);

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr);

uintptr_t install_hook_stub(const Program &parsed, uintptr_t hook_entry);

} // namespace syslift

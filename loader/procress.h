#pragma once

#include "parse.h"

#include <cstdint>

namespace syslift {

void reject_if_executable_contains_syscall(const Segment &segment,
                                           ProgramArch arch);

void reject_if_unknown_syscall_nr(const SysliftSyscallSite &site);

void patch_syscall_to_svc(Program &parsed, const SysliftSyscallSite &site);

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr);

uintptr_t install_hook_stub(const Program &parsed, uintptr_t hook_entry);

void dump_program(const Program &parsed);

} // namespace syslift

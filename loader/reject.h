#pragma once

#include "parse.h"

namespace syslift {

void reject_if_executable_contains_syscall(const Segment &segment,
                                           ProgramArch arch);

void reject_if_unknown_syscall_nr(const SysliftSyscallSite &site);

} // namespace syslift

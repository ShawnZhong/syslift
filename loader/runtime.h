#pragma once

#include "program.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace syslift {

uintptr_t map_image(const Program &program);

uintptr_t setup_runtime_stack(const std::string &arg0,
                              const std::vector<std::string> &args);

long syslift_framework_hook(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                            uint64_t arg3, uint64_t arg4, uint64_t arg5,
                            uint64_t sys_nr, uint64_t site_vaddr);

[[noreturn]] void jump_to_entry(uintptr_t entry_pc, uintptr_t entry_sp);

} // namespace syslift

#pragma once

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>

namespace syslift {

struct RuntimeStack {
  void *base = nullptr;
  size_t size = 0;
  uintptr_t entry_sp = 0;

  RuntimeStack(const RuntimeStack &) = delete;
  RuntimeStack &operator=(const RuntimeStack &) = delete;

  ~RuntimeStack() {
    if (base != nullptr && size != 0) {
      munmap(base, size);
    }
  }
};

RuntimeStack setup_runtime_stack(const char *argv0);

long syslift_framework_hook(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                            uint64_t arg3, uint64_t arg4, uint64_t arg5,
                            uint64_t sys_nr, uint64_t site_vaddr);

[[noreturn]] void jump_to_entry(uintptr_t entry, uintptr_t entry_sp);

} // namespace syslift

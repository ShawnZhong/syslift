#pragma once

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>

namespace syslift {

struct RuntimeStack {
  void *base = nullptr;
  size_t size = 0;
  uintptr_t entry_sp = 0;

  ~RuntimeStack() {
    if (base != nullptr && size != 0) {
      munmap(base, size);
    }
  }
};

RuntimeStack setup_runtime_stack(const char *argv0);

[[noreturn]] void jump_to_entry(uintptr_t entry, uintptr_t entry_sp);

} // namespace syslift

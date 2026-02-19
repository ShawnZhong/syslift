#pragma once

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>

namespace syslift {

struct RuntimeStack {
  void *base = nullptr;
  size_t size = 0;

  ~RuntimeStack() {
    if (base != nullptr && size != 0) {
      munmap(base, size);
    }
  }

  void release() {
    base = nullptr;
    size = 0;
  }
};

bool setup_runtime_stack(const char *path, const char *argv0,
                         RuntimeStack *stack, uintptr_t *entry_sp);

[[noreturn]] void jump_to_entry(uintptr_t entry, uintptr_t entry_sp);

} // namespace syslift

#include "runtime.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace syslift {

RuntimeStack setup_runtime_stack(const char *argv0) {
  constexpr size_t kStackSize = 1UL << 20;

  void *mem = mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (mem == MAP_FAILED) {
    throw std::runtime_error(std::string("runtime stack mmap failed: ") +
                             std::strerror(errno));
  }

  uintptr_t sp = reinterpret_cast<uintptr_t>(mem) + kStackSize;
  sp &= ~static_cast<uintptr_t>(0xFUL);

  auto push_u64 = [&](uint64_t v) {
    sp -= sizeof(uint64_t);
    *reinterpret_cast<uint64_t *>(sp) = v;
  };

  push_u64(0);
  push_u64(0);
  push_u64(0);
  push_u64(0);
  push_u64(reinterpret_cast<uintptr_t>(argv0));
  push_u64(1);

  return RuntimeStack{mem, kStackSize, sp};
}

[[noreturn]] void jump_to_entry(uintptr_t entry, uintptr_t entry_sp) {
  __asm__ volatile(
      "mov sp, %0\n"
      "br %1\n"
      :
      : "r"(entry_sp), "r"(entry)
      : "memory");
  __builtin_unreachable();
}

} // namespace syslift

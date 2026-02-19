#include "runtime.h"

#include <sys/mman.h>
#include <unistd.h>

#include <inttypes.h>

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

long syslift_framework_hook(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                            uint64_t arg3, uint64_t arg4, uint64_t arg5,
                            uint64_t sys_nr, uint64_t site_vaddr) {
  std::fprintf(stderr,
               "hook site=0x%" PRIx64 " nr=%" PRIu64
               " args=[%" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64
               ", %" PRIu64 ", %" PRIu64 "]\n",
               site_vaddr, sys_nr, arg0, arg1, arg2, arg3, arg4, arg5);
#if defined(__aarch64__)
  register uint64_t x0 asm("x0") = arg0;
  register uint64_t x1 asm("x1") = arg1;
  register uint64_t x2 asm("x2") = arg2;
  register uint64_t x3 asm("x3") = arg3;
  register uint64_t x4 asm("x4") = arg4;
  register uint64_t x5 asm("x5") = arg5;
  register uint64_t x8 asm("x8") = sys_nr;
  asm volatile("svc #0"
               : "+r"(x0)
               : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
               : "memory", "cc");
  return static_cast<long>(x0);
#else
  (void)site_vaddr;
  return -1;
#endif
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

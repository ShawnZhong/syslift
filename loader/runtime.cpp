#include "runtime.h"

#include <sys/mman.h>
#include <unistd.h>

#include <inttypes.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

namespace syslift {
namespace {

uintptr_t align_down(uintptr_t value, size_t align) {
  return value & ~(static_cast<uintptr_t>(align) - 1U);
}

bool align_up(uintptr_t value, size_t align, uintptr_t *out) {
  const uintptr_t add = static_cast<uintptr_t>(align) - 1U;
  if (value > std::numeric_limits<uintptr_t>::max() - add) {
    return false;
  }
  *out = align_down(value + add, align);
  return true;
}

} // namespace

uintptr_t map_image(const Program &program) {
  const long page_size_long = sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    throw std::runtime_error("failed to query page size");
  }
  const size_t page_size = static_cast<size_t>(page_size_long);

  uint64_t min_vaddr = std::numeric_limits<uint64_t>::max();
  uint64_t max_vaddr = 0;
  if (program.segments.empty()) {
    throw std::runtime_error("no PT_LOAD segments");
  }
  for (const Segment &seg : program.segments) {
    min_vaddr = std::min(min_vaddr, static_cast<uint64_t>(seg.start));
    max_vaddr = std::max(max_vaddr, static_cast<uint64_t>(seg.start + seg.size));
  }

  const uintptr_t min_page = align_down(static_cast<uintptr_t>(min_vaddr), page_size);
  uintptr_t max_page = 0;
  if (!align_up(static_cast<uintptr_t>(max_vaddr), page_size, &max_page) ||
      max_page <= min_page) {
    throw std::runtime_error("invalid load range");
  }

  const size_t span = max_page - min_page;
  void *base = mmap(reinterpret_cast<void *>(min_page), span,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (base == MAP_FAILED) {
    throw std::runtime_error(std::string("mmap failed: ") + std::strerror(errno));
  }

  const uintptr_t mapping_start = reinterpret_cast<uintptr_t>(base);
  const uintptr_t load_bias = mapping_start - min_page;
  const uintptr_t map_end = mapping_start + span;

  for (const Segment &seg : program.segments) {
    if (seg.size < seg.data.size()) {
      throw std::runtime_error("PT_LOAD memsz smaller than filesz");
    }

    const uintptr_t seg_start = load_bias + seg.start;
    const uintptr_t seg_end = seg_start + seg.size;
    if (seg_start < mapping_start || seg_end > map_end || seg_start >= seg_end) {
      throw std::runtime_error("PT_LOAD maps outside reserved range");
    }

    auto *dst = reinterpret_cast<uint8_t *>(seg_start);
    if (!seg.data.empty()) {
      std::memcpy(dst, seg.data.data(), seg.data.size());
    }
    if (seg.size > seg.data.size()) {
      std::memset(dst + seg.data.size(), 0,
                  static_cast<size_t>(seg.size - seg.data.size()));
    }
  }

  if (mprotect(reinterpret_cast<void *>(mapping_start), span, PROT_NONE) != 0) {
    throw std::runtime_error(std::string("mprotect(PROT_NONE) failed: ") +
                             std::strerror(errno));
  }

  for (const Segment &seg : program.segments) {
    const uintptr_t seg_start = load_bias + seg.start;
    const uintptr_t prot_start = align_down(seg_start, page_size);
    uintptr_t prot_end = 0;
    if (!align_up(seg_start + seg.size, page_size, &prot_end) ||
        prot_end <= prot_start) {
      throw std::runtime_error("invalid segment protection range");
    }
    if (mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start,
                 seg.prot) != 0) {
      throw std::runtime_error(std::string("mprotect failed: ") +
                               std::strerror(errno));
    }
  }

  return load_bias;
}

uintptr_t setup_runtime_stack(const std::string &arg0,
                              const std::vector<std::string> &args) {
  constexpr size_t kStackSize = 1UL << 20;

  void *mem = mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (mem == MAP_FAILED) {
    throw std::runtime_error(std::string("runtime stack mmap failed: ") +
                             std::strerror(errno));
  }

  uintptr_t sp = reinterpret_cast<uintptr_t>(mem) + kStackSize;
  sp &= ~static_cast<uintptr_t>(0xFUL);
  const size_t argc = 1 + args.size();
  if ((argc % 2U) == 0U) {
    sp -= sizeof(uint64_t);
  }

  auto push_u64 = [&](uint64_t v) {
    sp -= sizeof(uint64_t);
    *reinterpret_cast<uint64_t *>(sp) = v;
  };

  push_u64(0); // auxv value
  push_u64(0); // auxv type (AT_NULL)
  push_u64(0); // envp terminator
  push_u64(0); // argv terminator
  for (auto it = args.rbegin(); it != args.rend(); ++it) {
    push_u64(reinterpret_cast<uintptr_t>(it->c_str()));
  }
  push_u64(reinterpret_cast<uintptr_t>(arg0.c_str()));
  push_u64(static_cast<uint64_t>(argc));

  return sp;
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
  (void)arg0;
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
  (void)sys_nr;
  (void)site_vaddr;
  return -1;
#endif
}

[[noreturn]] void jump_to_entry(uintptr_t entry_pc, uintptr_t entry_sp) {
#if defined(__aarch64__)
  __asm__ volatile(
      "mov sp, %0\n"
      "br %1\n"
      :
      : "r"(entry_sp), "r"(entry_pc)
      : "memory");
#elif defined(__x86_64__)
  __asm__ volatile(
      "mov %0, %%rsp\n"
      "xor %%rbp, %%rbp\n"
      "jmp *%1\n"
      :
      : "r"(entry_sp), "r"(entry_pc)
      : "memory");
#else
#error "unsupported host arch for jump_to_entry"
#endif
  __builtin_unreachable();
}

} // namespace syslift

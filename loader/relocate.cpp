#include "relocate.h"

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

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

uintptr_t try_map_fixed_page(uintptr_t addr, size_t page_size) {
  void *p = mmap(reinterpret_cast<void *>(addr), page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == MAP_FAILED) {
    return 0;
  }
  return reinterpret_cast<uintptr_t>(p);
}

} // namespace

std::pair<Segment *, size_t> find_executable_site(Program &parsed,
                                                  uint64_t site_vaddr,
                                                  size_t patch_size) {
  for (Segment &seg : parsed.segments) {
    if ((seg.prot & PROT_EXEC) == 0 || site_vaddr < seg.start) {
      continue;
    }
    const uint64_t off = site_vaddr - seg.start;
    if (off + patch_size > seg.data.size()) {
      continue;
    }
    return {&seg, static_cast<size_t>(off)};
  }
  throw std::runtime_error("syscall site outside executable segment data");
}

void patch_syscall_to_insn(Program &parsed, const SysliftSyscallSite &site) {
  if (parsed.arch == ProgramArch::AArch64) {
    patch_syscall_to_insn_aarch64(parsed, site);
    return;
  }
  if (parsed.arch == ProgramArch::X86_64) {
    patch_syscall_to_insn_x86_64(parsed, site);
    return;
  }
  throw std::runtime_error("unsupported arch");
}

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr) {
  if (parsed.arch == ProgramArch::AArch64) {
    patch_syscall_to_hook_aarch64(parsed, site, hook_stub_addr);
    return;
  }
  if (parsed.arch == ProgramArch::X86_64) {
    patch_syscall_to_hook_x86_64(parsed, site, hook_stub_addr);
    return;
  }
  throw std::runtime_error("unsupported arch");
}

uintptr_t install_hook_stub(const Program &parsed, uintptr_t hook_entry) {
  const long page_size_long = sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    throw std::runtime_error("failed to query page size");
  }
  const size_t page_size = static_cast<size_t>(page_size_long);

  uintptr_t min_vaddr = std::numeric_limits<uintptr_t>::max();
  uintptr_t max_vaddr = 0;
  if (parsed.segments.empty()) {
    throw std::runtime_error("no PT_LOAD segments");
  }
  for (const Segment &seg : parsed.segments) {
    min_vaddr = std::min(min_vaddr, seg.start);
    max_vaddr = std::max(max_vaddr, seg.start + seg.size);
  }

  const uintptr_t min_page = align_down(min_vaddr, page_size);
  uintptr_t max_page = 0;
  if (!align_up(max_vaddr, page_size, &max_page) || max_page <= min_page) {
    throw std::runtime_error("invalid load range");
  }

  uintptr_t stub_page = try_map_fixed_page(max_page, page_size);
  if (stub_page == 0 && min_page >= page_size) {
    stub_page = try_map_fixed_page(min_page - page_size, page_size);
  }
  if (stub_page == 0) {
    throw std::runtime_error("failed to map hook stub near image");
  }

  auto *stub_bytes = reinterpret_cast<uint8_t *>(stub_page);
  size_t stub_size = 0;
  if (parsed.arch == ProgramArch::AArch64) {
    stub_size = write_hook_stub_aarch64(stub_bytes, page_size, hook_entry);
  } else if (parsed.arch == ProgramArch::X86_64) {
    stub_size = write_hook_stub_x86_64(stub_bytes, page_size, hook_entry);
  } else {
    throw std::runtime_error("unsupported arch");
  }

  __builtin___clear_cache(reinterpret_cast<char *>(stub_bytes),
                          reinterpret_cast<char *>(stub_bytes) + stub_size);

  if (mprotect(reinterpret_cast<void *>(stub_page), page_size,
               PROT_READ | PROT_EXEC) != 0) {
    throw std::runtime_error(std::string("hook stub mprotect failed: ") +
                             std::strerror(errno));
  }

  return stub_page;
}

} // namespace syslift

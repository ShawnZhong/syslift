#include "image.h"

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
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

int phdr_flags_to_prot(uint32_t flags) {
  int prot = 0;
  if ((flags & PF_R) != 0U) {
    prot |= PROT_READ;
  }
  if ((flags & PF_W) != 0U) {
    prot |= PROT_WRITE;
  }
  if ((flags & PF_X) != 0U && (flags & PF_W) == 0U) {
    prot |= PROT_EXEC;
  }
  return prot;
}

bool is_in_exec_segment(const Image &image, uintptr_t addr) {
  for (const Segment &seg : image.segments) {
    if (!seg.executable) {
      continue;
    }
    if (addr >= seg.start && addr + sizeof(uint32_t) <= seg.start + seg.size) {
      return true;
    }
  }
  return false;
}

uintptr_t try_map_fixed_page(uintptr_t addr, size_t page_size) {
  void *p = mmap(reinterpret_cast<void *>(addr), page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == MAP_FAILED) {
    return 0;
  }
  return reinterpret_cast<uintptr_t>(p);
}

void patch_aarch64_insn(uintptr_t site_addr, uint32_t insn_word) {
  auto *insn = reinterpret_cast<uint32_t *>(site_addr);
  *insn = insn_word;
  __builtin___clear_cache(reinterpret_cast<char *>(insn),
                          reinterpret_cast<char *>(insn) + sizeof(uint32_t));
}

uint32_t encode_bl_insn(uintptr_t from, uintptr_t to) {
  const int64_t delta = static_cast<int64_t>(to) - static_cast<int64_t>(from);
  if ((delta & 0x3LL) != 0) {
    throw std::runtime_error("hook target not 4-byte aligned");
  }
  const int64_t imm26 = delta >> 2;
  if (imm26 < -(1LL << 25) || imm26 > ((1LL << 25) - 1)) {
    throw std::runtime_error("hook target out of BL range");
  }
  return kBlInsnBase | (static_cast<uint32_t>(imm26) & 0x03FFFFFFu);
}

} // namespace

Image map_image(const std::vector<uint8_t> &file, const ParsedElf &parsed) {
  const long page_size_long = sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    throw std::runtime_error("failed to query page size");
  }
  const size_t page_size = static_cast<size_t>(page_size_long);

  uint64_t min_vaddr = std::numeric_limits<uint64_t>::max();
  uint64_t max_vaddr = 0;
  bool saw_load = false;

  for (const Elf64_Phdr &ph : parsed.phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
      continue;
    }
    saw_load = true;
    min_vaddr = std::min(min_vaddr, ph.p_vaddr);
    max_vaddr = std::max(max_vaddr, ph.p_vaddr + ph.p_memsz);
  }

  if (!saw_load) {
    throw std::runtime_error("no PT_LOAD segments");
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
  std::vector<Segment> segments;

  const uintptr_t map_end = mapping_start + span;

  for (const Elf64_Phdr &ph : parsed.phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
      continue;
    }
    if (ph.p_offset + ph.p_filesz > file.size()) {
      throw std::runtime_error("PT_LOAD file range out of bounds");
    }

    const uintptr_t seg_start = load_bias + static_cast<uintptr_t>(ph.p_vaddr);
    const uintptr_t seg_end = seg_start + static_cast<uintptr_t>(ph.p_memsz);
    if (seg_start < mapping_start || seg_end > map_end || seg_start >= seg_end) {
      throw std::runtime_error("PT_LOAD maps outside reserved range");
    }

    auto *dst = reinterpret_cast<uint8_t *>(seg_start);
    if (ph.p_filesz != 0) {
      std::memcpy(dst, file.data() + ph.p_offset, static_cast<size_t>(ph.p_filesz));
    }
    if (ph.p_memsz > ph.p_filesz) {
      std::memset(dst + ph.p_filesz, 0, static_cast<size_t>(ph.p_memsz - ph.p_filesz));
    }

    const int seg_prot = phdr_flags_to_prot(ph.p_flags);
    segments.push_back(
        Segment{seg_start, static_cast<size_t>(ph.p_memsz), seg_prot,
                (seg_prot & PROT_EXEC) != 0});
  }

  return Image{mapping_start, span, page_size, load_bias,
               load_bias + parsed.ehdr.e_entry, std::move(segments)};
}

void patch_syscall_to_svc(const SysliftSyscallSite &site, const Image &image) {
  uintptr_t site_addr = image.load_bias + static_cast<uintptr_t>(site.site_vaddr);

  if ((site_addr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  if (!is_in_exec_segment(image, site_addr)) {
    throw std::runtime_error("syscall site outside executable segment");
  }

  patch_aarch64_insn(site_addr, kSvc0Insn);
}

uintptr_t install_hook_stub(const Image &image, uintptr_t hook_entry) {
  uintptr_t stub_page = 0;
  const uintptr_t after = image.mapping_start + image.mapping_size;
  if (after <= std::numeric_limits<uintptr_t>::max() - image.page_size) {
    stub_page = try_map_fixed_page(after, image.page_size);
  }
  if (stub_page == 0 && image.mapping_start >= image.page_size) {
    stub_page = try_map_fixed_page(image.mapping_start - image.page_size,
                                   image.page_size);
  }
  if (stub_page == 0) {
    void *p = mmap(nullptr, image.page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
      throw std::runtime_error(std::string("hook stub mmap failed: ") +
                               std::strerror(errno));
    }
    stub_page = reinterpret_cast<uintptr_t>(p);
  }

  static constexpr std::array<uint32_t, 9> kHookStubInsns = {
      0xD10043FFu, // sub sp, sp, #16
      0xF90003FEu, // str x30, [sp]
      0xAA0803E6u, // mov x6, x8
      0xD10013C7u, // sub x7, x30, #4
      0x580000B0u, // ldr x16, #0x14
      0xD63F0200u, // blr x16
      0xF94003FEu, // ldr x30, [sp]
      0x910043FFu, // add sp, sp, #16
      0xD65F03C0u, // ret
  };
  constexpr size_t kCodeSize = kHookStubInsns.size() * sizeof(uint32_t);
  constexpr size_t kTotalSize = kCodeSize + sizeof(uint64_t);
  if (kTotalSize > image.page_size) {
    throw std::runtime_error("hook stub too large");
  }

  auto *stub = reinterpret_cast<uint8_t *>(stub_page);
  std::memcpy(stub, kHookStubInsns.data(), kCodeSize);
  *reinterpret_cast<uint64_t *>(stub + kCodeSize) = hook_entry;
  __builtin___clear_cache(reinterpret_cast<char *>(stub),
                          reinterpret_cast<char *>(stub) + kTotalSize);

  if (mprotect(reinterpret_cast<void *>(stub_page), image.page_size,
               PROT_READ | PROT_EXEC) != 0) {
    throw std::runtime_error(std::string("hook stub mprotect failed: ") +
                             std::strerror(errno));
  }

  return stub_page;
}

void patch_syscall_to_hook(const SysliftSyscallSite &site, const Image &image,
                           uintptr_t hook_stub_addr) {
  uintptr_t site_addr = image.load_bias + static_cast<uintptr_t>(site.site_vaddr);

  if ((site_addr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  if (!is_in_exec_segment(image, site_addr)) {
    throw std::runtime_error("syscall site outside executable segment");
  }

  patch_aarch64_insn(site_addr, encode_bl_insn(site_addr, hook_stub_addr));
}

void apply_segment_protections(const Image &image) {
  if (mprotect(reinterpret_cast<void *>(image.mapping_start), image.mapping_size,
               PROT_NONE) != 0) {
    throw std::runtime_error(std::string("mprotect(PROT_NONE) failed: ") +
                             std::strerror(errno));
  }

  for (const Segment &seg : image.segments) {
    const uintptr_t prot_start = align_down(seg.start, image.page_size);
    uintptr_t prot_end = 0;
    if (!align_up(seg.start + seg.size, image.page_size, &prot_end) ||
        prot_end <= prot_start) {
      throw std::runtime_error("invalid segment protection range");
    }
    if (mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start,
                 seg.prot) != 0) {
      throw std::runtime_error(std::string("mprotect failed: ") +
                               std::strerror(errno));
    }
  }
}

} // namespace syslift

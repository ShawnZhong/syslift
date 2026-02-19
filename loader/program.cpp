#include "program.h"

#include <elfio/elfio.hpp>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

namespace syslift {
namespace {

constexpr uint32_t kSvc0Insn = 0xD4000001u;
constexpr uint32_t kBlInsnBase = 0x94000000u;

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

int phdr_flags_to_prot(uint32_t flags) {
  int prot = 0;
  if ((flags & ELFIO::PF_R) != 0U) {
    prot |= PROT_READ;
  }
  if ((flags & ELFIO::PF_W) != 0U) {
    prot |= PROT_WRITE;
  }
  if ((flags & ELFIO::PF_X) != 0U && (flags & ELFIO::PF_W) == 0U) {
    prot |= PROT_EXEC;
  }
  return prot;
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

std::string hex_u64(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

std::pair<Segment *, size_t> find_executable_site(Program &parsed,
                                                   uint64_t site_vaddr) {
  for (Segment &seg : parsed.segments) {
    if ((seg.prot & PROT_EXEC) == 0 || site_vaddr < seg.start) {
      continue;
    }
    const uint64_t off = site_vaddr - seg.start;
    if (off + sizeof(uint32_t) > seg.data.size()) {
      continue;
    }
    return {&seg, static_cast<size_t>(off)};
  }
  throw std::runtime_error("syscall site outside executable segment data");
}

std::vector<SysliftSyscallSite> parse_syscall_table(const ELFIO::elfio &reader) {
  const ELFIO::section *table_sec = reader.sections[kSyscallTableSection];
  if (table_sec == nullptr) {
    throw std::runtime_error(std::string("missing ") + kSyscallTableSection +
                             " section");
  }

  if (table_sec->get_size() % sizeof(SysliftSyscallSite) != 0) {
    throw std::runtime_error(std::string("invalid ") + kSyscallTableSection +
                             " section size");
  }

  const char *table_data = table_sec->get_data();
  if (table_sec->get_size() != 0 && table_data == nullptr) {
    throw std::runtime_error(std::string("failed to read ") + kSyscallTableSection +
                             " section data");
  }

  const auto *table = reinterpret_cast<const uint8_t *>(table_data);
  const size_t count = table_sec->get_size() / sizeof(SysliftSyscallSite);

  std::vector<SysliftSyscallSite> sites;
  sites.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    SysliftSyscallSite site{};
    std::memcpy(&site, table + i * sizeof(SysliftSyscallSite), sizeof(site));
    sites.push_back(site);
  }

  return sites;
}

} // namespace

Program parse_elf(const std::string &path) {
  ELFIO::elfio reader;
  if (!reader.load(path)) {
    throw std::runtime_error("failed to parse ELF");
  }

  if (reader.get_class() != ELFIO::ELFCLASS64 ||
      reader.get_encoding() != ELFIO::ELFDATA2LSB ||
      reader.get_machine() != ELFIO::EM_AARCH64) {
    throw std::runtime_error("unsupported ELF format (need AArch64 ELF64 LE)");
  }
  if (reader.get_type() != ELFIO::ET_EXEC) {
    throw std::runtime_error("unsupported ELF type (need EXEC)");
  }
  if (reader.segments.size() == 0) {
    throw std::runtime_error("invalid program header table");
  }

  Program parsed{};
  parsed.entry = reader.get_entry();

  parsed.segments.reserve(reader.segments.size());
  for (const auto &seg_ptr : reader.segments) {
    const ELFIO::segment *elf_seg = seg_ptr.get();
    if (elf_seg->get_type() != ELFIO::PT_LOAD || elf_seg->get_memory_size() == 0) {
      continue;
    }

    Segment seg{};
    seg.start = static_cast<uintptr_t>(elf_seg->get_virtual_address());
    seg.size = static_cast<size_t>(elf_seg->get_memory_size());
    seg.prot = phdr_flags_to_prot(static_cast<uint32_t>(elf_seg->get_flags()));

    const size_t filesz = static_cast<size_t>(elf_seg->get_file_size());
    const char *seg_data = elf_seg->get_data();
    if (filesz != 0 && seg_data == nullptr) {
      throw std::runtime_error("failed to read segment data");
    }
    seg.data.resize(filesz);
    if (filesz != 0) {
      std::memcpy(seg.data.data(), seg_data, filesz);
    }

    parsed.segments.push_back(std::move(seg));
  }
  if (parsed.segments.empty()) {
    throw std::runtime_error("no PT_LOAD segments");
  }

  parsed.syscall_sites = parse_syscall_table(reader);
  return parsed;
}

void reject_if_executable_contains_svc(const Segment &segment) {
  if ((segment.prot & PROT_EXEC) == 0 ||
      segment.data.size() < sizeof(uint32_t)) {
    return;
  }

  const uint8_t *text = segment.data.data();
  const size_t start_off =
      static_cast<size_t>((4 - (segment.start & 0x3U)) & 0x3U);
  for (size_t off = start_off; off + sizeof(uint32_t) <= segment.data.size();
       off += 4) {
    uint32_t insn = 0;
    std::memcpy(&insn, text + off, sizeof(insn));
    if (insn != kSvc0Insn) {
      continue;
    }

    const uint64_t site_vaddr = segment.start + static_cast<uint64_t>(off);
    throw std::runtime_error(
        "untrusted input: svc #0 found in executable segment (vaddr=" +
        hex_u64(site_vaddr) + ")");
  }
}

void reject_if_unknown_syscall_nr(const SysliftSyscallSite &site) {
  if ((site.known_mask & kSyscallNrBit) != 0u) {
    return;
  }

  throw std::runtime_error("untrusted input: unknown syscall nr in .syslift "
                           "(site_vaddr=" +
                           hex_u64(site.site_vaddr) + ")");
}

void patch_syscall_to_svc(Program &parsed, const SysliftSyscallSite &site) {
  if ((site.site_vaddr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  auto [seg, off] = find_executable_site(parsed, site.site_vaddr);
  std::memcpy(seg->data.data() + off, &kSvc0Insn, sizeof(kSvc0Insn));
}

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr) {
  if ((site.site_vaddr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  auto [seg, off] = find_executable_site(parsed, site.site_vaddr);
  const uint32_t bl = encode_bl_insn(static_cast<uintptr_t>(site.site_vaddr),
                                     hook_stub_addr);
  std::memcpy(seg->data.data() + off, &bl, sizeof(bl));
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
  if (kTotalSize > page_size) {
    throw std::runtime_error("hook stub too large");
  }

  auto *stub = reinterpret_cast<uint8_t *>(stub_page);
  std::memcpy(stub, kHookStubInsns.data(), kCodeSize);
  *reinterpret_cast<uint64_t *>(stub + kCodeSize) = hook_entry;
  __builtin___clear_cache(reinterpret_cast<char *>(stub),
                          reinterpret_cast<char *>(stub) + kTotalSize);

  if (mprotect(reinterpret_cast<void *>(stub_page), page_size,
               PROT_READ | PROT_EXEC) != 0) {
    throw std::runtime_error(std::string("hook stub mprotect failed: ") +
                             std::strerror(errno));
  }

  return stub_page;
}

void dump_syslift_table(const Program &parsed) {
  const std::vector<SysliftSyscallSite> &sites = parsed.syscall_sites;
  std::fprintf(stderr, ".syslift entries=%zu\n", sites.size());
  for (size_t i = 0; i < sites.size(); ++i) {
    const SysliftSyscallSite &site = sites[i];
    std::fprintf(stderr, "table[%zu] site_vaddr=0x%" PRIx64 " vals=[", i,
                 site.site_vaddr);
    for (uint32_t value_index = 0; value_index < kSyscallValueCount;
         ++value_index) {
      if (value_index != 0) {
        std::fprintf(stderr, ", ");
      }
      const uint32_t bit = 1u << value_index;
      if ((site.known_mask & bit) == 0u) {
        std::fprintf(stderr, "%3s", "?");
      } else {
        std::fprintf(stderr, "%3" PRIu64, site.values[value_index]);
      }
    }
    std::fprintf(stderr, "]\n");
  }
}

} // namespace syslift

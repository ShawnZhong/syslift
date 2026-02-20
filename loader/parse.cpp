#include "parse.h"

#include <elfio/elfio.hpp>
#include <sys/mman.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace syslift {
namespace {

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
    throw std::runtime_error(std::string("failed to read ") +
                             kSyscallTableSection + " section data");
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

Program parse_program(const std::string &path) {
  ELFIO::elfio reader;
  if (!reader.load(path)) {
    throw std::runtime_error("failed to parse ELF");
  }

  if (reader.get_class() != ELFIO::ELFCLASS64 ||
      reader.get_encoding() != ELFIO::ELFDATA2LSB) {
    throw std::runtime_error("unsupported ELF format (need ELF64 LE)");
  }

  ProgramArch arch;
  if (reader.get_machine() == ELFIO::EM_AARCH64) {
    arch = ProgramArch::AArch64;
  } else if (reader.get_machine() == ELFIO::EM_X86_64) {
    arch = ProgramArch::X86_64;
  } else {
    throw std::runtime_error(
        "unsupported ELF machine (need AArch64 or x86_64)");
  }
  if (reader.get_type() != ELFIO::ET_EXEC) {
    throw std::runtime_error("unsupported ELF type (need EXEC)");
  }
  if (reader.segments.size() == 0) {
    throw std::runtime_error("invalid program header table");
  }

  Program parsed{};
  parsed.arch = arch;
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

} // namespace syslift

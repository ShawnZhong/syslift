#pragma once

#include <elf.h>

#include <cstdint>
#include <vector>

namespace syslift {

inline constexpr const char *kSyscallTableSection = ".syslift";
inline constexpr uint32_t kSyscallArgCount = 6;

struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t sys_nr;
  uint32_t arg_known_mask;
  uint64_t arg_values[kSyscallArgCount];
} __attribute__((packed));

struct ParsedElf {
  Elf64_Ehdr ehdr{};
  std::vector<Elf64_Phdr> phdrs;
  std::vector<SysliftSyscallSite> syscall_sites;
};

std::vector<uint8_t> read_whole_file(const char *path);

ParsedElf parse_elf(const std::vector<uint8_t> &file);

void reject_if_text_contains_svc(const std::vector<uint8_t> &file,
                                 const ParsedElf &parsed);

void dump_syslift_table(const ParsedElf &parsed);

} // namespace syslift

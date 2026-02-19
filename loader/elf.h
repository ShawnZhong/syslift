#pragma once

#include <elf.h>

#include <cstdint>
#include <vector>

namespace syslift {

inline constexpr const char *kSyscallTableSection = ".syslift";

struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t sys_nr;
  uint32_t arg_known_mask;
  uint64_t arg_values[6];
} __attribute__((packed));

struct ParsedElf {
  Elf64_Ehdr ehdr{};
  std::vector<Elf64_Phdr> phdrs;
  std::vector<SysliftSyscallSite> syscall_sites;
};

void read_whole_file(const char *path, std::vector<uint8_t> *out);

void parse_elf(const std::vector<uint8_t> &file, ParsedElf *parsed);

void reject_if_text_contains_svc(const std::vector<uint8_t> &file,
                                 const ParsedElf &parsed);

void dump_syslift_table(const ParsedElf &parsed);

} // namespace syslift

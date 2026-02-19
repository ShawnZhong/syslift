#pragma once

#include <elf.h>

#include <cstdint>
#include <vector>

namespace syslift {

inline constexpr const char *kSyscallTableSection = ".syslift";
inline constexpr uint32_t kSyscallValueCount = 7;
inline constexpr uint32_t kSyscallNrBit = 1u << 0;

struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t known_mask;
  uint64_t values[kSyscallValueCount]; // [0]=nr, [1..6]=arg1..arg6
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

void reject_if_unknown_syscall_nr(const ParsedElf &parsed);

void dump_syslift_table(const ParsedElf &parsed);

} // namespace syslift

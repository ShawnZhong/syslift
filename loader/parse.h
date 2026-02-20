#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace syslift {

inline constexpr const char *kSyscallTableSection = ".syslift";
inline constexpr uint32_t kSyscallValueCount = 7;
inline constexpr uint32_t kSyscallNrBit = 1u << 0;

enum class ProgramArch {
  AArch64,
  X86_64,
};

struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t known_mask;
  uint64_t values[kSyscallValueCount]; // [0]=nr, [1..6]=arg1..arg6
} __attribute__((packed));

struct Segment {
  uintptr_t start = 0; // ELF virtual address (pre-load-bias)
  size_t size = 0;     // ELF p_memsz (bytes)
  std::vector<uint8_t> data;
  int prot = 0;
};

struct Program {
  ProgramArch arch = ProgramArch::AArch64;
  uint64_t entry = 0;
  std::vector<Segment> segments;
  std::vector<SysliftSyscallSite> syscall_sites;
};

Program parse_program(const std::string &path);

void dump_program(const Program &parsed);

} // namespace syslift

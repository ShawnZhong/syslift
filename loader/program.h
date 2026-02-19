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

Program parse_elf(const std::string &path);

void reject_if_executable_contains_syscall(const Program &program,
                                           const Segment &segment);

void reject_if_unknown_syscall_nr(const SysliftSyscallSite &site);

void patch_syscall_to_svc(Program &parsed, const SysliftSyscallSite &site);

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr);

uintptr_t install_hook_stub(const Program &parsed, uintptr_t hook_entry);

void dump_program(const Program &parsed);

} // namespace syslift

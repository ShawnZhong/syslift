#include "reject.h"

#include <sys/mman.h>

#include <array>
#include <cstring>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace syslift {
namespace {

constexpr std::array<uint8_t, 4> kAArch64SvcInsn = {0x01, 0x00, 0x00, 0xD4};
constexpr std::array<uint8_t, 2> kX86SyscallInsn = {0x0F, 0x05};

std::string hex_u64(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

template <size_t N>
std::optional<size_t> find_raw_syscall_offset(
    const Segment &segment, const std::array<uint8_t, N> &insn, size_t start_off,
    size_t step) {
  if (N == 0 || step == 0 || start_off >= segment.data.size()) {
    return std::nullopt;
  }
  if (segment.data.size() < N) {
    return std::nullopt;
  }

  const uint8_t *text = segment.data.data();
  for (size_t off = start_off; off + N <= segment.data.size(); off += step) {
    if (std::memcmp(text + off, insn.data(), N) == 0) {
      return off;
    }
  }
  return std::nullopt;
}

} // namespace

void reject_if_executable_contains_syscall(const Segment &segment,
                                           ProgramArch arch) {
  if ((segment.prot & PROT_EXEC) == 0 || segment.data.empty()) {
    return;
  }

  std::optional<size_t> off;
  if (arch == ProgramArch::AArch64) {
    const size_t start_off =
        static_cast<size_t>((4 - (segment.start & 0x3U)) & 0x3U);
    off = find_raw_syscall_offset(segment, kAArch64SvcInsn, start_off, 4);
  } else if (arch == ProgramArch::X86_64) {
    off = find_raw_syscall_offset(segment, kX86SyscallInsn, 0, 1);
  } else {
    throw std::runtime_error("unsupported arch");
  }

  if (!off.has_value()) {
    return;
  }
  const uint64_t site_vaddr = segment.start + static_cast<uint64_t>(off.value());
  throw std::runtime_error(
      "untrusted input: syscall instruction found in executable segment "
      "(vaddr=" +
      hex_u64(site_vaddr) + ")");
}

void reject_if_unknown_syscall_nr(const SysliftSyscallSite &site) {
  if ((site.known_mask & kSyscallNrBit) != 0u) {
    return;
  }

  throw std::runtime_error("untrusted input: unknown syscall nr in .syslift "
                           "(site_vaddr=" +
                           hex_u64(site.site_vaddr) + ")");
}

} // namespace syslift

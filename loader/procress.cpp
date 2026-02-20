#include "procress.h"

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

namespace syslift {
namespace {

constexpr std::array<uint8_t, 4> kAArch64SvcInsn = {0x01, 0x00, 0x00, 0xD4};
constexpr std::array<uint8_t, 2> kX86SyscallInsn = {0x0F, 0x05};
constexpr size_t kSyscallPatchSlotSize = 8;
constexpr std::array<uint8_t, kSyscallPatchSlotSize> kAArch64PatchedSyscallInsn = {
    0x01, 0x00, 0x00, 0xD4, 0x1F, 0x20, 0x03, 0xD5};
constexpr std::array<uint8_t, kSyscallPatchSlotSize> kX86PatchedSyscallInsn = {
    0x0F, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
static_assert(kAArch64PatchedSyscallInsn.size() == kSyscallPatchSlotSize,
              "AArch64 syscall patch slot must stay 8 bytes");
static_assert(kX86PatchedSyscallInsn.size() == kSyscallPatchSlotSize,
              "x86 syscall patch slot must stay 8 bytes");
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

int32_t encode_x86_call_rel32(uint64_t from_site_vaddr, uintptr_t to) {
  const int64_t from_next =
      static_cast<int64_t>(from_site_vaddr) + static_cast<int64_t>(5);
  const int64_t delta = static_cast<int64_t>(to) - from_next;
  if (delta < std::numeric_limits<int32_t>::min() ||
      delta > std::numeric_limits<int32_t>::max()) {
    throw std::runtime_error("hook target out of x86 call range");
  }
  return static_cast<int32_t>(delta);
}

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

const std::array<uint8_t, kSyscallPatchSlotSize> &
patched_syscall_slot(ProgramArch arch) {
  switch (arch) {
  case ProgramArch::AArch64:
    return kAArch64PatchedSyscallInsn;
  case ProgramArch::X86_64:
    return kX86PatchedSyscallInsn;
  }
  throw std::runtime_error("unsupported arch");
}

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

} // namespace

void reject_if_executable_contains_syscall(const Segment &segment,
                                           ProgramArch arch) {
  if ((segment.prot & PROT_EXEC) == 0 || segment.data.empty()) {
    return;
  }

  std::optional<size_t> off;
  if (arch == ProgramArch::AArch64) {
    const size_t start_off = static_cast<size_t>((4 - (segment.start & 0x3U)) & 0x3U);
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
      "(vaddr=" + hex_u64(site_vaddr) + ")");
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
  if (parsed.arch == ProgramArch::AArch64 && (site.site_vaddr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  auto [seg, off] =
      find_executable_site(parsed, site.site_vaddr, kSyscallPatchSlotSize);
  const auto &slot = patched_syscall_slot(parsed.arch);
  std::memcpy(seg->data.data() + off, slot.data(), slot.size());
}

void patch_syscall_to_hook(Program &parsed, const SysliftSyscallSite &site,
                           uintptr_t hook_stub_addr) {
  if (parsed.arch == ProgramArch::AArch64) {
    if ((site.site_vaddr & 0x3U) != 0U) {
      throw std::runtime_error("invalid syscall site alignment");
    }
    auto [seg, off] =
        find_executable_site(parsed, site.site_vaddr, kSyscallPatchSlotSize);
    const uint32_t bl = encode_bl_insn(static_cast<uintptr_t>(site.site_vaddr),
                                       hook_stub_addr);
    const std::array<uint32_t, 2> hook_insns = {bl, 0xD503201Fu};
    std::memcpy(seg->data.data() + off, hook_insns.data(), sizeof(hook_insns));
    return;
  }

  if (parsed.arch == ProgramArch::X86_64) {
    auto [seg, off] =
        find_executable_site(parsed, site.site_vaddr, kSyscallPatchSlotSize);
    std::array<uint8_t, kSyscallPatchSlotSize> hook_insns = {0xE8, 0, 0, 0, 0,
                                                              0x90, 0x90, 0x90};
    const int32_t rel32 = encode_x86_call_rel32(site.site_vaddr, hook_stub_addr);
    std::memcpy(hook_insns.data() + 1, &rel32, sizeof(rel32));
    std::memcpy(seg->data.data() + off, hook_insns.data(), hook_insns.size());
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

  auto *stub = reinterpret_cast<uint8_t *>(stub_page);
  size_t stub_size = 0;

  if (parsed.arch == ProgramArch::AArch64) {
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
    std::memcpy(stub, kHookStubInsns.data(), kCodeSize);
    *reinterpret_cast<uint64_t *>(stub + kCodeSize) = hook_entry;
    stub_size = kTotalSize;
  } else if (parsed.arch == ProgramArch::X86_64) {
    // push rdi; push rsi; push rdx; push r10; push r8; push r9
    // load site_vaddr from return address, align stack, and call hook_entry(arg0..arg5, nr, site)
    // restore preserved registers and return to patched site.
    std::vector<uint8_t> code = {
        0x57, 0x56, 0x52, 0x41, 0x52, 0x41, 0x50, 0x41, 0x51,
        0x4C, 0x8B, 0x5C, 0x24, 0x30,       // mov r11, [rsp+0x30]
        0x49, 0x83, 0xEB, 0x05,             // sub r11, 5
        0x49, 0x89, 0xE2,                   // mov r10, rsp
        0x48, 0x83, 0xE4, 0xF0,             // and rsp, -16
        0x48, 0x83, 0xEC, 0x20,             // sub rsp, 32
        0x48, 0x89, 0x04, 0x24,             // mov [rsp], rax
        0x4C, 0x89, 0x5C, 0x24, 0x08,       // mov [rsp+8], r11
        0x4C, 0x89, 0x54, 0x24, 0x10,       // mov [rsp+16], r10
        0x49, 0x8B, 0x4A, 0x10,             // mov rcx, [r10+16]
        0x49, 0xBB                          // movabs r11, imm64
    };
    const uint64_t hook_entry_u64 = static_cast<uint64_t>(hook_entry);
    for (unsigned i = 0; i < 8; ++i) {
      code.push_back(static_cast<uint8_t>((hook_entry_u64 >> (8u * i)) & 0xFFu));
    }
    const std::array<uint8_t, 19> kTail = {
        0x41, 0xFF, 0xD3,                   // call r11
        0x48, 0x8B, 0x64, 0x24, 0x10,       // mov rsp, [rsp+16]
        0x41, 0x59, 0x41, 0x58, 0x41, 0x5A, // pop r9; pop r8; pop r10
        0x5A, 0x5E, 0x5F, 0xC3              // pop rdx; pop rsi; pop rdi; ret
    };
    code.insert(code.end(), kTail.begin(), kTail.end());
    if (code.size() > page_size) {
      throw std::runtime_error("x86 hook stub too large");
    }
    std::memcpy(stub, code.data(), code.size());
    stub_size = code.size();
  } else {
    throw std::runtime_error("unsupported arch");
  }

  __builtin___clear_cache(reinterpret_cast<char *>(stub),
                          reinterpret_cast<char *>(stub) + stub_size);

  if (mprotect(reinterpret_cast<void *>(stub_page), page_size,
               PROT_READ | PROT_EXEC) != 0) {
    throw std::runtime_error(std::string("hook stub mprotect failed: ") +
                             std::strerror(errno));
  }

  return stub_page;
}

} // namespace syslift

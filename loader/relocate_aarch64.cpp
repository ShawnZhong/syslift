#include "relocate.h"

#include <array>
#include <cstring>
#include <stdexcept>

namespace syslift {
namespace {

constexpr std::array<uint8_t, kPatchedSyscallInsnSize> kPatchedSyscallInsn = {
    0x01, 0x00, 0x00, 0xD4, 0x1F, 0x20, 0x03, 0xD5};
static_assert(kPatchedSyscallInsn.size() == kPatchedSyscallInsnSize,
              "AArch64 patched syscall insn must stay 8 bytes");

constexpr uint32_t kBlInsnBase = 0x94000000u;

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

void patch_syscall_to_insn_aarch64(Program &parsed,
                                   const SysliftSyscallSite &site) {
  if ((site.site_vaddr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  auto [seg, off] =
      find_executable_site(parsed, site.site_vaddr, kPatchedSyscallInsnSize);
  std::memcpy(seg->data.data() + off, kPatchedSyscallInsn.data(),
              kPatchedSyscallInsn.size());
}

void patch_syscall_to_hook_aarch64(Program &parsed,
                                   const SysliftSyscallSite &site,
                                   uintptr_t hook_stub_addr) {
  if ((site.site_vaddr & 0x3U) != 0U) {
    throw std::runtime_error("invalid syscall site alignment");
  }
  auto [seg, off] =
      find_executable_site(parsed, site.site_vaddr, kPatchedSyscallInsnSize);
  const uint32_t bl =
      encode_bl_insn(static_cast<uintptr_t>(site.site_vaddr), hook_stub_addr);
  const std::array<uint32_t, 2> hook_insns = {bl, 0xD503201Fu};
  std::memcpy(seg->data.data() + off, hook_insns.data(), sizeof(hook_insns));
}

size_t write_hook_stub_aarch64(uint8_t *stub_bytes, size_t page_size,
                               uintptr_t hook_entry) {
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

  std::memcpy(stub_bytes, kHookStubInsns.data(), kCodeSize);
  *reinterpret_cast<uint64_t *>(stub_bytes + kCodeSize) = hook_entry;
  return kTotalSize;
}

} // namespace syslift

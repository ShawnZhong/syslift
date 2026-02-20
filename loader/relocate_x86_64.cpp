#include "relocate.h"

#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

namespace syslift {
namespace {

constexpr std::array<uint8_t, kPatchedSyscallInsnSize> kPatchedSyscallInsn = {
    0x0F, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
static_assert(kPatchedSyscallInsn.size() == kPatchedSyscallInsnSize,
              "x86 patched syscall insn must stay 8 bytes");

int32_t encode_call_rel32(uint64_t from_site_vaddr, uintptr_t to) {
  const int64_t from_next =
      static_cast<int64_t>(from_site_vaddr) + static_cast<int64_t>(5);
  const int64_t delta = static_cast<int64_t>(to) - from_next;
  if (delta < std::numeric_limits<int32_t>::min() ||
      delta > std::numeric_limits<int32_t>::max()) {
    throw std::runtime_error("hook target out of x86 call range");
  }
  return static_cast<int32_t>(delta);
}

void append_u64_le(std::vector<uint8_t> &out, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8u * i)) & 0xFFu));
  }
}

} // namespace

void patch_syscall_to_insn_x86_64(Program &parsed,
                                  const SysliftSyscallSite &site) {
  auto [seg, off] =
      find_executable_site(parsed, site.site_vaddr, kPatchedSyscallInsnSize);
  std::memcpy(seg->data.data() + off, kPatchedSyscallInsn.data(),
              kPatchedSyscallInsn.size());
}

void patch_syscall_to_hook_x86_64(Program &parsed,
                                  const SysliftSyscallSite &site,
                                  uintptr_t hook_stub_addr) {
  auto [seg, off] =
      find_executable_site(parsed, site.site_vaddr, kPatchedSyscallInsnSize);
  std::array<uint8_t, kPatchedSyscallInsnSize> hook_insns = {
      0xE8, 0, 0, 0, 0, 0x90, 0x90, 0x90};
  const int32_t rel32 = encode_call_rel32(site.site_vaddr, hook_stub_addr);
  std::memcpy(hook_insns.data() + 1, &rel32, sizeof(rel32));
  std::memcpy(seg->data.data() + off, hook_insns.data(), hook_insns.size());
}

size_t write_hook_stub_x86_64(uint8_t *stub_bytes, size_t page_size,
                              uintptr_t hook_entry) {
  // Preserve syscall-arg registers, recover site_vaddr from return address,
  // call hook_entry(arg0..arg5, nr, site), then restore and return.
  const std::vector<uint8_t> kCodePrefix = {
      0x57, 0x56, 0x52, 0x41, 0x52, 0x41, 0x50, // push rdi,rsi,rdx,r10,r8
      0x41, 0x51,                               // push r9
      0x4C, 0x8B, 0x5C, 0x24, 0x30,             // mov r11, [rsp+0x30]
      0x49, 0x83, 0xEB, 0x05,                   // sub r11, 5
      0x49, 0x89, 0xE2,                         // mov r10, rsp
      0x48, 0x83, 0xE4, 0xF0,                   // and rsp, -16
      0x48, 0x83, 0xEC, 0x20,                   // sub rsp, 32
      0x48, 0x89, 0x04, 0x24,                   // mov [rsp], rax
      0x4C, 0x89, 0x5C, 0x24, 0x08,             // mov [rsp+8], r11
      0x4C, 0x89, 0x54, 0x24, 0x10,             // mov [rsp+16], r10
      0x49, 0x8B, 0x4A, 0x10,                   // mov rcx, [r10+16]
      0x49, 0xBB                                // movabs r11, imm64
  };
  const std::vector<uint8_t> kCodeTail = {
      0x41, 0xFF, 0xD3,                   // call r11
      0x48, 0x8B, 0x64, 0x24, 0x10,       // mov rsp, [rsp+16]
      0x41, 0x59, 0x41, 0x58, 0x41, 0x5A, // pop r9; pop r8; pop r10
      0x5A, 0x5E, 0x5F, 0xC3              // pop rdx; pop rsi; pop rdi; ret
  };

  std::vector<uint8_t> code;
  code.reserve(kCodePrefix.size() + sizeof(uint64_t) + kCodeTail.size());
  code.insert(code.end(), kCodePrefix.begin(), kCodePrefix.end());
  append_u64_le(code, static_cast<uint64_t>(hook_entry));
  code.insert(code.end(), kCodeTail.begin(), kCodeTail.end());

  if (code.size() > page_size) {
    throw std::runtime_error("x86 hook stub too large");
  }

  std::memcpy(stub_bytes, code.data(), code.size());
  return code.size();
}

} // namespace syslift

#pragma once

#include "elf.h"
#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace syslift {

inline constexpr uint32_t kSvc0Insn = 0xD4000001u;

struct Segment {
  uintptr_t start = 0;
  size_t size = 0;
  int prot = 0;
  bool executable = false;
};

struct Image {
  uintptr_t mapping_start = 0;
  size_t mapping_size = 0;
  size_t page_size = 0;
  uintptr_t load_bias = 0;
  uintptr_t entry = 0;
  std::vector<Segment> segments;

  Image(const Image &) = delete;
  Image &operator=(const Image &) = delete;

  ~Image() {
    if (mapping_start != 0 && mapping_size != 0) {
      munmap(reinterpret_cast<void *>(mapping_start), mapping_size);
    }
  }
};

Image map_image(const std::vector<uint8_t> &file, const ParsedElf &parsed);

void patch_syscall(const SysliftSyscallSite &site, const Image &image);

void apply_segment_protections(const Image &image);

} // namespace syslift

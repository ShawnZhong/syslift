#include "cli.h"
#include "elf.h"
#include "image.h"
#include "runtime.h"

#include <inttypes.h>

#include <cstdio>
#include <cstdint>
#include <vector>

int main(int argc, char **argv) {
  syslift::Options opts;
  if (!syslift::parse_options(argc, argv, &opts)) {
    return 1;
  }

  const char *elf_path = opts.elf_path.c_str();

  std::vector<uint8_t> file;
  if (!syslift::read_whole_file(elf_path, &file)) {
    return 1;
  }

  syslift::ParsedElf parsed;
  if (!syslift::parse_elf(elf_path, file, &parsed)) {
    return 1;
  }

  std::vector<uint32_t> denied;
  if (!syslift::evaluate_policy(parsed.syscall_sites, opts, &denied)) {
    std::fprintf(stderr, "%s: policy denied %zu syscall number(s):", elf_path,
                 denied.size());
    for (uint32_t nr : denied) {
      std::fprintf(stderr, " %" PRIu32, nr);
    }
    std::fprintf(stderr, "\n");
    return 1;
  }

  std::printf("%s: policy OK (%zu syscall site(s))\n", elf_path,
              parsed.syscall_sites.size());

  syslift::Image image;
  if (!syslift::map_image(elf_path, file, parsed, &image)) {
    return 1;
  }
  if (!syslift::patch_syscalls(elf_path, parsed, image)) {
    return 1;
  }
  if (!syslift::apply_segment_protections(elf_path, image)) {
    return 1;
  }

  syslift::RuntimeStack runtime_stack;
  uintptr_t entry_sp = 0;
  if (!syslift::setup_runtime_stack(elf_path, elf_path, &runtime_stack,
                                    &entry_sp)) {
    return 1;
  }

  const uintptr_t entry = image.entry;
  image.release();
  runtime_stack.release();
  syslift::jump_to_entry(entry, entry_sp);
}

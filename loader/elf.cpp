#include "elf.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <inttypes.h>

namespace syslift {
namespace {

bool in_range(size_t off, size_t len, size_t total) {
  return off <= total && len <= total - off;
}

uint32_t read_u32_le(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t read_u64_le(const uint8_t *p) {
  return static_cast<uint64_t>(p[0]) |
         (static_cast<uint64_t>(p[1]) << 8) |
         (static_cast<uint64_t>(p[2]) << 16) |
         (static_cast<uint64_t>(p[3]) << 24) |
         (static_cast<uint64_t>(p[4]) << 32) |
         (static_cast<uint64_t>(p[5]) << 40) |
         (static_cast<uint64_t>(p[6]) << 48) |
         (static_cast<uint64_t>(p[7]) << 56);
}

bool parse_syscall_table(const char *path,
                         const std::vector<uint8_t> &file,
                         const Elf64_Ehdr &ehdr,
                         std::vector<SysliftSyscallSite> *sites) {
  if (ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shnum == 0) {
    std::fprintf(stderr, "%s: invalid section header table\n", path);
    return false;
  }

  const size_t shdr_size = static_cast<size_t>(ehdr.e_shnum) * sizeof(Elf64_Shdr);
  if (!in_range(ehdr.e_shoff, shdr_size, file.size())) {
    std::fprintf(stderr, "%s: section header table out of bounds\n", path);
    return false;
  }

  const auto *shdrs = reinterpret_cast<const Elf64_Shdr *>(file.data() + ehdr.e_shoff);
  if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= ehdr.e_shnum) {
    std::fprintf(stderr, "%s: invalid section name string table index\n", path);
    return false;
  }

  const Elf64_Shdr &shstr = shdrs[ehdr.e_shstrndx];
  if (!in_range(shstr.sh_offset, shstr.sh_size, file.size())) {
    std::fprintf(stderr, "%s: section name string table out of bounds\n", path);
    return false;
  }

  const char *shstrtab = reinterpret_cast<const char *>(file.data() + shstr.sh_offset);

  int table_idx = -1;
  for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
    const Elf64_Shdr &sec = shdrs[i];
    if (sec.sh_name >= shstr.sh_size) {
      continue;
    }
    const char *name = shstrtab + sec.sh_name;
    if (std::strcmp(name, kSyscallTableSection) == 0) {
      table_idx = static_cast<int>(i);
      break;
    }
  }

  if (table_idx < 0) {
    std::fprintf(stderr, "%s: missing %s section\n", path, kSyscallTableSection);
    return false;
  }

  const Elf64_Shdr &table_sec = shdrs[table_idx];
  if (!in_range(table_sec.sh_offset, table_sec.sh_size, file.size())) {
    std::fprintf(stderr, "%s: %s section out of bounds\n", path,
                 kSyscallTableSection);
    return false;
  }
  if (table_sec.sh_size % sizeof(SysliftSyscallSite) != 0) {
    std::fprintf(stderr, "%s: invalid %s section size\n", path,
                 kSyscallTableSection);
    return false;
  }

  const uint8_t *table = file.data() + table_sec.sh_offset;
  const size_t count = table_sec.sh_size / sizeof(SysliftSyscallSite);
  std::fprintf(stderr, "found %s section offset=0x%llx size=%llu entries=%zu\n",
               kSyscallTableSection,
               static_cast<unsigned long long>(table_sec.sh_offset),
               static_cast<unsigned long long>(table_sec.sh_size), count);

  sites->clear();
  sites->reserve(count);
  for (size_t i = 0; i < count; ++i) {
    size_t rec = i * sizeof(SysliftSyscallSite);
    SysliftSyscallSite site{};
    site.site_vaddr = read_u64_le(table + rec);
    site.sys_nr = read_u32_le(table + rec + 8);
    sites->push_back(site);
    std::fprintf(stderr, "table[%zu] site_vaddr=0x%016" PRIx64 " sys_nr=%" PRIu32
                         "\n",
                 i, site.site_vaddr, site.sys_nr);
  }

  return true;
}

} // namespace

bool read_whole_file(const char *path, std::vector<uint8_t> *out) {
  FILE *fp = std::fopen(path, "rb");
  if (fp == nullptr) {
    std::fprintf(stderr, "%s: failed to open: %s\n", path, std::strerror(errno));
    return false;
  }

  if (std::fseek(fp, 0, SEEK_END) != 0) {
    std::fprintf(stderr, "%s: fseek failed: %s\n", path, std::strerror(errno));
    std::fclose(fp);
    return false;
  }

  long file_size_long = std::ftell(fp);
  if (file_size_long < 0) {
    std::fprintf(stderr, "%s: ftell failed: %s\n", path, std::strerror(errno));
    std::fclose(fp);
    return false;
  }
  if (std::fseek(fp, 0, SEEK_SET) != 0) {
    std::fprintf(stderr, "%s: fseek failed: %s\n", path, std::strerror(errno));
    std::fclose(fp);
    return false;
  }

  out->assign(static_cast<size_t>(file_size_long), 0);
  if (!out->empty() && std::fread(out->data(), 1, out->size(), fp) != out->size()) {
    std::fprintf(stderr, "%s: fread failed\n", path);
    std::fclose(fp);
    return false;
  }

  std::fclose(fp);
  return true;
}

bool parse_elf(const char *path, const std::vector<uint8_t> &file,
               ParsedElf *parsed) {
  if (!in_range(0, sizeof(Elf64_Ehdr), file.size())) {
    std::fprintf(stderr, "%s: file too small for ELF header\n", path);
    return false;
  }

  const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(file.data());
  if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    std::fprintf(stderr, "%s: not an ELF file\n", path);
    return false;
  }
  if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_machine != EM_AARCH64) {
    std::fprintf(stderr, "%s: unsupported ELF format (need AArch64 ELF64 LE)\n", path);
    return false;
  }
  if (ehdr->e_type != ET_EXEC) {
    std::fprintf(stderr, "%s: unsupported ELF type (need EXEC)\n", path);
    return false;
  }
  if (ehdr->e_phentsize != sizeof(Elf64_Phdr) || ehdr->e_phnum == 0) {
    std::fprintf(stderr, "%s: invalid program header table\n", path);
    return false;
  }

  const size_t phdr_size = static_cast<size_t>(ehdr->e_phnum) * sizeof(Elf64_Phdr);
  if (!in_range(ehdr->e_phoff, phdr_size, file.size())) {
    std::fprintf(stderr, "%s: program header table out of bounds\n", path);
    return false;
  }

  parsed->ehdr = *ehdr;
  const auto *phdrs = reinterpret_cast<const Elf64_Phdr *>(file.data() + ehdr->e_phoff);
  parsed->phdrs.assign(phdrs, phdrs + ehdr->e_phnum);

  return parse_syscall_table(path, file, parsed->ehdr, &parsed->syscall_sites);
}

} // namespace syslift

#include "elf.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

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

void parse_syscall_table(const std::vector<uint8_t> &file,
                         const Elf64_Ehdr &ehdr,
                         std::vector<SysliftSyscallSite> *sites) {
  if (ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shnum == 0) {
    throw std::runtime_error("invalid section header table");
  }

  const size_t shdr_size = static_cast<size_t>(ehdr.e_shnum) * sizeof(Elf64_Shdr);
  if (!in_range(ehdr.e_shoff, shdr_size, file.size())) {
    throw std::runtime_error("section header table out of bounds");
  }

  const auto *shdrs = reinterpret_cast<const Elf64_Shdr *>(file.data() + ehdr.e_shoff);
  if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= ehdr.e_shnum) {
    throw std::runtime_error("invalid section name string table index");
  }

  const Elf64_Shdr &shstr = shdrs[ehdr.e_shstrndx];
  if (!in_range(shstr.sh_offset, shstr.sh_size, file.size())) {
    throw std::runtime_error("section name string table out of bounds");
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
    throw std::runtime_error(std::string("missing ") + kSyscallTableSection +
                             " section");
  }

  const Elf64_Shdr &table_sec = shdrs[table_idx];
  if (!in_range(table_sec.sh_offset, table_sec.sh_size, file.size())) {
    throw std::runtime_error(std::string(kSyscallTableSection) +
                             " section out of bounds");
  }
  if (table_sec.sh_size % sizeof(SysliftSyscallSite) != 0) {
    throw std::runtime_error(std::string("invalid ") + kSyscallTableSection +
                             " section size");
  }

  const uint8_t *table = file.data() + table_sec.sh_offset;
  const size_t count = table_sec.sh_size / sizeof(SysliftSyscallSite);

  sites->clear();
  sites->reserve(count);
  for (size_t i = 0; i < count; ++i) {
    size_t rec = i * sizeof(SysliftSyscallSite);
    SysliftSyscallSite site{};
    site.site_vaddr = read_u64_le(table + rec);
    site.sys_nr = read_u32_le(table + rec + 8);
    sites->push_back(site);
  }
}

} // namespace

void read_whole_file(const char *path, std::vector<uint8_t> *out) {
  FILE *fp = std::fopen(path, "rb");
  if (fp == nullptr) {
    throw std::runtime_error(std::string("failed to open: ") +
                             std::strerror(errno));
  }

  if (std::fseek(fp, 0, SEEK_END) != 0) {
    int saved_errno = errno;
    std::fclose(fp);
    throw std::runtime_error(std::string("fseek failed: ") +
                             std::strerror(saved_errno));
  }

  long file_size_long = std::ftell(fp);
  if (file_size_long < 0) {
    int saved_errno = errno;
    std::fclose(fp);
    throw std::runtime_error(std::string("ftell failed: ") +
                             std::strerror(saved_errno));
  }
  if (std::fseek(fp, 0, SEEK_SET) != 0) {
    int saved_errno = errno;
    std::fclose(fp);
    throw std::runtime_error(std::string("fseek failed: ") +
                             std::strerror(saved_errno));
  }

  out->assign(static_cast<size_t>(file_size_long), 0);
  if (!out->empty() && std::fread(out->data(), 1, out->size(), fp) != out->size()) {
    std::fclose(fp);
    throw std::runtime_error("fread failed");
  }

  std::fclose(fp);
}

void parse_elf(const std::vector<uint8_t> &file, ParsedElf *parsed) {
  if (!in_range(0, sizeof(Elf64_Ehdr), file.size())) {
    throw std::runtime_error("file too small for ELF header");
  }

  const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(file.data());
  if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    throw std::runtime_error("not an ELF file");
  }
  if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_machine != EM_AARCH64) {
    throw std::runtime_error("unsupported ELF format (need AArch64 ELF64 LE)");
  }
  if (ehdr->e_type != ET_EXEC) {
    throw std::runtime_error("unsupported ELF type (need EXEC)");
  }
  if (ehdr->e_phentsize != sizeof(Elf64_Phdr) || ehdr->e_phnum == 0) {
    throw std::runtime_error("invalid program header table");
  }

  const size_t phdr_size = static_cast<size_t>(ehdr->e_phnum) * sizeof(Elf64_Phdr);
  if (!in_range(ehdr->e_phoff, phdr_size, file.size())) {
    throw std::runtime_error("program header table out of bounds");
  }

  parsed->ehdr = *ehdr;
  const auto *phdrs = reinterpret_cast<const Elf64_Phdr *>(file.data() + ehdr->e_phoff);
  parsed->phdrs.assign(phdrs, phdrs + ehdr->e_phnum);

  parse_syscall_table(file, parsed->ehdr, &parsed->syscall_sites);
}

} // namespace syslift

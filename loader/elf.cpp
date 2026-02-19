#include "elf.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <inttypes.h>
#include <stdexcept>
#include <string>

namespace syslift {
namespace {

static constexpr uint32_t kSvc0Insn = 0xD4000001u;

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

const Elf64_Shdr *find_section_by_name(const std::vector<uint8_t> &file,
                                       const Elf64_Ehdr &ehdr,
                                       const char *name) {
  if (ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shnum == 0) {
    throw std::runtime_error("invalid section header table");
  }

  const size_t shdr_size = static_cast<size_t>(ehdr.e_shnum) * sizeof(Elf64_Shdr);
  if (!in_range(ehdr.e_shoff, shdr_size, file.size())) {
    throw std::runtime_error("section header table out of bounds");
  }

  const auto *shdrs =
      reinterpret_cast<const Elf64_Shdr *>(file.data() + ehdr.e_shoff);
  if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= ehdr.e_shnum) {
    throw std::runtime_error("invalid section name string table index");
  }

  const Elf64_Shdr &shstr = shdrs[ehdr.e_shstrndx];
  if (!in_range(shstr.sh_offset, shstr.sh_size, file.size())) {
    throw std::runtime_error("section name string table out of bounds");
  }

  const char *shstrtab = reinterpret_cast<const char *>(file.data() + shstr.sh_offset);

  for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
    const Elf64_Shdr &sec = shdrs[i];
    if (sec.sh_name >= shstr.sh_size) {
      continue;
    }
    if (std::strcmp(shstrtab + sec.sh_name, name) == 0) {
      return &sec;
    }
  }

  return nullptr;
}

std::vector<SysliftSyscallSite> parse_syscall_table(const std::vector<uint8_t> &file,
                                                    const Elf64_Ehdr &ehdr) {
  const Elf64_Shdr *table_sec =
      find_section_by_name(file, ehdr, kSyscallTableSection);
  if (table_sec == nullptr) {
    throw std::runtime_error(std::string("missing ") + kSyscallTableSection +
                             " section");
  }

  if (!in_range(table_sec->sh_offset, table_sec->sh_size, file.size())) {
    throw std::runtime_error(std::string(kSyscallTableSection) +
                             " section out of bounds");
  }
  if (table_sec->sh_size % sizeof(SysliftSyscallSite) != 0) {
    throw std::runtime_error(std::string("invalid ") + kSyscallTableSection +
                             " section size");
  }

  const uint8_t *table = file.data() + table_sec->sh_offset;
  const size_t count = table_sec->sh_size / sizeof(SysliftSyscallSite);

  std::vector<SysliftSyscallSite> sites;
  sites.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    size_t rec = i * sizeof(SysliftSyscallSite);
    SysliftSyscallSite site{};
    site.site_vaddr = read_u64_le(table + rec);
    site.sys_nr = read_u32_le(table + rec + 8);
    site.arg_known_mask = read_u32_le(table + rec + 12);
    for (size_t arg = 0; arg < kSyscallArgCount; ++arg) {
      site.arg_values[arg] = read_u64_le(table + rec + 16 + arg * 8);
    }
    sites.push_back(site);
  }
  return sites;
}

} // namespace

std::vector<uint8_t> read_whole_file(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open file");
  }

  input.seekg(0, std::ios::end);
  const std::streamoff size = input.tellg();
  if (size < 0) {
    throw std::runtime_error("failed to get file size");
  }
  input.seekg(0, std::ios::beg);

  std::vector<uint8_t> out(static_cast<size_t>(size), 0);
  if (size > 0 && !input.read(reinterpret_cast<char *>(out.data()), size)) {
    throw std::runtime_error("failed to read file");
  }
  return out;
}

ParsedElf parse_elf(const std::vector<uint8_t> &file) {
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

  ParsedElf parsed;
  parsed.ehdr = *ehdr;
  const auto *phdrs = reinterpret_cast<const Elf64_Phdr *>(file.data() + ehdr->e_phoff);
  parsed.phdrs.assign(phdrs, phdrs + ehdr->e_phnum);

  parsed.syscall_sites = parse_syscall_table(file, parsed.ehdr);
  return parsed;
}

void reject_if_text_contains_svc(const std::vector<uint8_t> &file,
                                 const ParsedElf &parsed) {
  std::vector<uint64_t> trusted_sites;
  trusted_sites.reserve(parsed.syscall_sites.size());
  for (const SysliftSyscallSite &site : parsed.syscall_sites) {
    trusted_sites.push_back(site.site_vaddr);
  }
  std::sort(trusted_sites.begin(), trusted_sites.end());

  if (parsed.ehdr.e_shentsize != sizeof(Elf64_Shdr) ||
      parsed.ehdr.e_shnum == 0) {
    throw std::runtime_error("invalid section header table");
  }
  const size_t shdr_size =
      static_cast<size_t>(parsed.ehdr.e_shnum) * sizeof(Elf64_Shdr);
  if (!in_range(parsed.ehdr.e_shoff, shdr_size, file.size())) {
    throw std::runtime_error("section header table out of bounds");
  }

  const auto *shdrs =
      reinterpret_cast<const Elf64_Shdr *>(file.data() + parsed.ehdr.e_shoff);
  if (parsed.ehdr.e_shstrndx == SHN_UNDEF ||
      parsed.ehdr.e_shstrndx >= parsed.ehdr.e_shnum) {
    throw std::runtime_error("invalid section name string table index");
  }

  const Elf64_Shdr &shstr = shdrs[parsed.ehdr.e_shstrndx];
  if (!in_range(shstr.sh_offset, shstr.sh_size, file.size())) {
    throw std::runtime_error("section name string table out of bounds");
  }
  const char *shstrtab =
      reinterpret_cast<const char *>(file.data() + shstr.sh_offset);

  for (uint16_t i = 0; i < parsed.ehdr.e_shnum; ++i) {
    const Elf64_Shdr &sec = shdrs[i];
    if (sec.sh_name >= shstr.sh_size || sec.sh_size < sizeof(uint32_t)) {
      continue;
    }

    const char *name = shstrtab + sec.sh_name;
    if (std::strncmp(name, ".text", 5) != 0) {
      continue;
    }
    if (!in_range(sec.sh_offset, sec.sh_size, file.size())) {
      throw std::runtime_error("text section out of bounds");
    }

    const uint8_t *text = file.data() + sec.sh_offset;
    const size_t start_off =
        static_cast<size_t>((4 - (sec.sh_addr & 0x3U)) & 0x3U);
    for (size_t off = start_off; off + sizeof(uint32_t) <= sec.sh_size;
         off += 4) {
      if (read_u32_le(text + off) != kSvc0Insn) {
        continue;
      }
      const uint64_t site_vaddr = sec.sh_addr + static_cast<uint64_t>(off);
      if (std::binary_search(trusted_sites.begin(), trusted_sites.end(),
                             site_vaddr)) {
        continue;
      }

      char msg[192];
      std::snprintf(msg, sizeof(msg),
                    "untrusted input: svc #0 not listed in .syslift (%s "
                    "vaddr=0x%" PRIx64 ")",
                    name, site_vaddr);
      throw std::runtime_error(msg);
    }
  }
}

void dump_syslift_table(const ParsedElf &parsed) {
  const std::vector<SysliftSyscallSite> &sites = parsed.syscall_sites;
  std::fprintf(stderr, ".syslift entries=%zu\n", sites.size());
  for (size_t i = 0; i < sites.size(); ++i) {
    const SysliftSyscallSite &site = sites[i];
    std::fprintf(stderr, "table[%zu] site_vaddr=0x%" PRIx64 " sys_nr=%" PRIu32
                         " known={",
                 i, site.site_vaddr, site.sys_nr);

    bool first = true;
    for (uint32_t arg = 0; arg < kSyscallArgCount; ++arg) {
      if ((site.arg_known_mask & (1u << arg)) == 0u) {
        continue;
      }
      std::fprintf(stderr, "%sarg%" PRIu32 "=%" PRIu64, first ? "" : ", ",
                   arg, site.arg_values[arg]);
      first = false;
    }
    std::fprintf(stderr, "}\n");
  }
}

} // namespace syslift

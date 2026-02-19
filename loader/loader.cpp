#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_set>
#include <vector>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

namespace {

constexpr const char *kSyscallTableSection = ".syslift";
constexpr uint32_t kSvc0Insn = 0xD4000001u;

struct SysliftSyscallSite {
  uint64_t site_vaddr;
  uint32_t sys_nr;
} __attribute__((packed));

struct Options {
  bool allow_all = false;
  std::vector<uint32_t> allow;
  int elf_arg_index = -1;
};

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

  ~Image() {
    if (mapping_start != 0 && mapping_size != 0) {
      munmap(reinterpret_cast<void *>(mapping_start), mapping_size);
    }
  }

  void release() {
    mapping_start = 0;
    mapping_size = 0;
    page_size = 0;
    load_bias = 0;
    entry = 0;
    segments.clear();
  }
};

struct ParsedElf {
  Elf64_Ehdr ehdr{};
  std::vector<Elf64_Phdr> phdrs;
  std::vector<SysliftSyscallSite> syscall_sites;
};

static bool in_range(size_t off, size_t len, size_t total) {
  return off <= total && len <= total - off;
}

static uint32_t read_u32_le(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t read_u64_le(const uint8_t *p) {
  return static_cast<uint64_t>(p[0]) |
         (static_cast<uint64_t>(p[1]) << 8) |
         (static_cast<uint64_t>(p[2]) << 16) |
         (static_cast<uint64_t>(p[3]) << 24) |
         (static_cast<uint64_t>(p[4]) << 32) |
         (static_cast<uint64_t>(p[5]) << 40) |
         (static_cast<uint64_t>(p[6]) << 48) |
         (static_cast<uint64_t>(p[7]) << 56);
}

static uintptr_t align_down(uintptr_t value, size_t align) {
  return value & ~(static_cast<uintptr_t>(align) - 1U);
}

static bool align_up(uintptr_t value, size_t align, uintptr_t *out) {
  const uintptr_t add = static_cast<uintptr_t>(align) - 1U;
  if (value > std::numeric_limits<uintptr_t>::max() - add) {
    return false;
  }
  *out = align_down(value + add, align);
  return true;
}

static bool parse_u32(const char *text, uint32_t *out) {
  char *end = nullptr;
  errno = 0;
  unsigned long value = std::strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' ||
      value > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  *out = static_cast<uint32_t>(value);
  return true;
}

static bool parse_allow_csv(const char *csv, std::vector<uint32_t> *allow) {
  std::string copy(csv);
  size_t pos = 0;

  while (pos < copy.size()) {
    size_t comma = copy.find(',', pos);
    if (comma == std::string::npos) {
      comma = copy.size();
    }

    size_t begin = pos;
    while (begin < comma &&
           std::isspace(static_cast<unsigned char>(copy[begin])) != 0) {
      ++begin;
    }

    size_t end = comma;
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(copy[end - 1])) != 0) {
      --end;
    }

    if (begin != end) {
      std::string token = copy.substr(begin, end - begin);
      uint32_t nr = 0;
      if (!parse_u32(token.c_str(), &nr)) {
        std::fprintf(stderr, "invalid --allow value: '%s'\n", token.c_str());
        return false;
      }
      allow->push_back(nr);
    }

    pos = comma + 1;
  }

  return true;
}

static void print_usage(const char *prog) {
  std::fprintf(stderr,
               "usage: %s [--allow-all] [--allow <nr|csv>] "
               "<elf-file>\n",
               prog);
}

static bool consume_value_option(int argc, char **argv, int *idx,
                                 const char *arg, const char *name,
                                 const char **value_out, bool *matched_out) {
  *matched_out = false;

  const size_t name_len = std::strlen(name);
  if (std::strcmp(arg, name) == 0) {
    *matched_out = true;
    if (*idx + 1 >= argc) {
      std::fprintf(stderr, "%s requires a value\n", name);
      return false;
    }
    *value_out = argv[++(*idx)];
    return true;
  }

  if (std::strncmp(arg, name, name_len) == 0 && arg[name_len] == '=') {
    *matched_out = true;
    *value_out = arg + name_len + 1;
    return true;
  }

  return true;
}

static bool parse_options(int argc, char **argv, Options *opts) {
  for (int i = 1; i < argc; ++i) {
    const char *arg = argv[i];

    if (std::strcmp(arg, "--help") == 0) {
      print_usage(argv[0]);
      std::exit(0);
    }
    if (std::strcmp(arg, "--allow-all") == 0) {
      opts->allow_all = true;
      continue;
    }

    const char *value = nullptr;
    bool matched = false;

    if (!consume_value_option(argc, argv, &i, arg, "--allow", &value, &matched)) {
      return false;
    }
    if (matched) {
      if (!parse_allow_csv(value, &opts->allow)) {
        return false;
      }
      continue;
    }

    if (arg[0] == '-' && arg[1] != '\0') {
      std::fprintf(stderr, "unknown option: %s\n", arg);
      print_usage(argv[0]);
      return false;
    }

    opts->elf_arg_index = i;
    break;
  }

  if (opts->elf_arg_index < 0 || opts->elf_arg_index >= argc) {
    print_usage(argv[0]);
    return false;
  }
  if (opts->elf_arg_index + 1 < argc) {
    std::fprintf(stderr,
                 "extra argv forwarding is not supported by in-process loader\n");
    return false;
  }

  return true;
}

static bool read_whole_file(const char *path, std::vector<uint8_t> *out) {
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

static bool parse_syscall_table(const char *path,
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

static bool parse_elf(const char *path, const std::vector<uint8_t> &file,
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

static bool evaluate_policy(const std::vector<SysliftSyscallSite> &sites,
                            const Options &opts,
                            std::vector<uint32_t> *denied) {
  denied->clear();

  if (opts.allow_all || opts.allow.empty()) {
    return true;
  }

  std::unordered_set<uint32_t> allow_set(opts.allow.begin(), opts.allow.end());
  std::unordered_set<uint32_t> denied_set;

  for (const SysliftSyscallSite &site : sites) {
    if (allow_set.find(site.sys_nr) == allow_set.end() &&
        denied_set.insert(site.sys_nr).second) {
      denied->push_back(site.sys_nr);
    }
  }

  return denied->empty();
}

static int phdr_flags_to_prot(uint32_t flags) {
  int prot = 0;
  if ((flags & PF_R) != 0U) {
    prot |= PROT_READ;
  }
  if ((flags & PF_W) != 0U) {
    prot |= PROT_WRITE;
  }
  if ((flags & PF_X) != 0U) {
    prot |= PROT_EXEC;
  }
  return prot;
}

static bool map_image(const char *path, const std::vector<uint8_t> &file,
                      const ParsedElf &parsed, Image *image) {
  const long page_size_long = sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    std::fprintf(stderr, "%s: failed to query page size\n", path);
    return false;
  }
  const size_t page_size = static_cast<size_t>(page_size_long);

  uint64_t min_vaddr = std::numeric_limits<uint64_t>::max();
  uint64_t max_vaddr = 0;
  bool saw_load = false;

  for (const Elf64_Phdr &ph : parsed.phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
      continue;
    }
    saw_load = true;
    min_vaddr = std::min(min_vaddr, ph.p_vaddr);
    max_vaddr = std::max(max_vaddr, ph.p_vaddr + ph.p_memsz);
  }

  if (!saw_load) {
    std::fprintf(stderr, "%s: no PT_LOAD segments\n", path);
    return false;
  }

  const uintptr_t min_page = align_down(static_cast<uintptr_t>(min_vaddr), page_size);
  uintptr_t max_page = 0;
  if (!align_up(static_cast<uintptr_t>(max_vaddr), page_size, &max_page) ||
      max_page <= min_page) {
    std::fprintf(stderr, "%s: invalid load range\n", path);
    return false;
  }

  const size_t span = max_page - min_page;
  void *base = mmap(reinterpret_cast<void *>(min_page), span,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (base == MAP_FAILED) {
    std::fprintf(stderr, "%s: mmap failed: %s\n", path, std::strerror(errno));
    return false;
  }

  image->mapping_start = reinterpret_cast<uintptr_t>(base);
  image->mapping_size = span;
  image->page_size = page_size;
  image->load_bias = image->mapping_start - min_page;
  image->entry = image->load_bias + parsed.ehdr.e_entry;
  image->segments.clear();

  const uintptr_t map_end = image->mapping_start + image->mapping_size;

  for (const Elf64_Phdr &ph : parsed.phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
      continue;
    }
    if (ph.p_offset + ph.p_filesz > file.size()) {
      std::fprintf(stderr, "%s: PT_LOAD file range out of bounds\n", path);
      return false;
    }

    const uintptr_t seg_start = image->load_bias + static_cast<uintptr_t>(ph.p_vaddr);
    const uintptr_t seg_end = seg_start + static_cast<uintptr_t>(ph.p_memsz);
    if (seg_start < image->mapping_start || seg_end > map_end || seg_start >= seg_end) {
      std::fprintf(stderr, "%s: PT_LOAD maps outside reserved range\n", path);
      return false;
    }

    auto *dst = reinterpret_cast<uint8_t *>(seg_start);
    if (ph.p_filesz != 0) {
      std::memcpy(dst, file.data() + ph.p_offset, static_cast<size_t>(ph.p_filesz));
    }
    if (ph.p_memsz > ph.p_filesz) {
      std::memset(dst + ph.p_filesz, 0, static_cast<size_t>(ph.p_memsz - ph.p_filesz));
    }

    image->segments.push_back(
        Segment{seg_start, static_cast<size_t>(ph.p_memsz),
                phdr_flags_to_prot(ph.p_flags), (ph.p_flags & PF_X) != 0U});
  }

  return true;
}

static bool is_in_exec_segment(const Image &image, uintptr_t addr) {
  for (const Segment &seg : image.segments) {
    if (!seg.executable) {
      continue;
    }
    if (addr >= seg.start && addr + sizeof(uint32_t) <= seg.start + seg.size) {
      return true;
    }
  }
  return false;
}

static bool patch_syscalls(const char *path, const ParsedElf &parsed,
                           const Image &image) {
  std::fprintf(stderr, "patching %zu syscall site(s) load_bias=0x%" PRIxPTR "\n",
               parsed.syscall_sites.size(), image.load_bias);
  for (const SysliftSyscallSite &site : parsed.syscall_sites) {
    uintptr_t site_addr = image.load_bias + static_cast<uintptr_t>(site.site_vaddr);

    if ((site_addr & 0x3U) != 0U) {
      std::fprintf(stderr, "%s: syscall site 0x%" PRIxPTR " is not 4-byte aligned\n",
                   path, site_addr);
      return false;
    }
    if (!is_in_exec_segment(image, site_addr)) {
      std::fprintf(stderr,
                   "%s: syscall site 0x%" PRIxPTR " is outside executable segments\n",
                   path, site_addr);
      return false;
    }

    auto *insn = reinterpret_cast<uint32_t *>(site_addr);
    *insn = kSvc0Insn;
    __builtin___clear_cache(reinterpret_cast<char *>(insn),
                            reinterpret_cast<char *>(insn) + sizeof(uint32_t));
    std::fprintf(stderr,
                 "patched site_vaddr=0x%016" PRIx64
                 " mapped=0x%" PRIxPTR " sys_nr=%" PRIu32 " -> svc #0\n",
                 site.site_vaddr, site_addr, site.sys_nr);
  }

  std::fprintf(stderr, "patching complete\n");
  return true;
}

static bool apply_segment_protections(const char *path, const Image &image) {
  if (mprotect(reinterpret_cast<void *>(image.mapping_start), image.mapping_size,
               PROT_NONE) != 0) {
    std::fprintf(stderr, "%s: mprotect(PROT_NONE) failed: %s\n", path,
                 std::strerror(errno));
    return false;
  }

  for (const Segment &seg : image.segments) {
    const uintptr_t prot_start = align_down(seg.start, image.page_size);
    uintptr_t prot_end = 0;
    if (!align_up(seg.start + seg.size, image.page_size, &prot_end) ||
        prot_end <= prot_start) {
      std::fprintf(stderr, "%s: invalid segment protection range\n", path);
      return false;
    }
    if (mprotect(reinterpret_cast<void *>(prot_start), prot_end - prot_start,
                 seg.prot) != 0) {
      std::fprintf(stderr, "%s: mprotect failed: %s\n", path,
                   std::strerror(errno));
      return false;
    }
  }

  return true;
}

[[noreturn]] static void jump_to_entry(uintptr_t entry) {
  using EntryFn = void (*)();
  EntryFn fn = reinterpret_cast<EntryFn>(entry);
  fn();
  _exit(127);
}

}  // namespace

int main(int argc, char **argv) {
  Options opts;
  if (!parse_options(argc, argv, &opts)) {
    return 1;
  }

  const char *elf_path = argv[opts.elf_arg_index];

  std::vector<uint8_t> file;
  if (!read_whole_file(elf_path, &file)) {
    return 1;
  }

  ParsedElf parsed;
  if (!parse_elf(elf_path, file, &parsed)) {
    return 1;
  }

  std::vector<uint32_t> denied;
  if (!evaluate_policy(parsed.syscall_sites, opts, &denied)) {
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

  Image image;
  if (!map_image(elf_path, file, parsed, &image)) {
    return 1;
  }
  if (!patch_syscalls(elf_path, parsed, image)) {
    return 1;
  }
  if (!apply_segment_protections(elf_path, image)) {
    return 1;
  }

  const uintptr_t entry = image.entry;
  image.release();
  jump_to_entry(entry);
}

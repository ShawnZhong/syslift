#include "elf.h"
#include "image.h"
#include "runtime.h"

#include <cxxopts.hpp>
#include <inttypes.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

namespace {

struct Options {
  std::vector<uint32_t> hook;
  std::vector<uint32_t> allow;
  std::vector<uint32_t> deny;
  bool debug = false;
  std::string elf_path;
};

Options parse_options(int argc, char **argv) {
  cxxopts::Options parser(argv[0], "syslift loader");
  parser.positional_help("<elf-file>");
  parser.add_options()(
      "hook", "Hook syscall numbers (comma-separated or repeated)",
      cxxopts::value<std::vector<uint32_t>>())(
      "allow", "Allow-list syscall numbers (comma-separated or repeated)",
      cxxopts::value<std::vector<uint32_t>>())(
      "deny", "Deny-list syscall numbers (comma-separated or repeated)",
      cxxopts::value<std::vector<uint32_t>>())("debug", "Enable debug logging")(
      "h,help", "Show help")(
      "elf", "ELF file", cxxopts::value<std::string>());
  parser.parse_positional({"elf"});

  try {
    auto result = parser.parse(argc, argv);
    if (result.count("help") != 0) {
      std::printf("%s\n", parser.help().c_str());
      std::exit(0);
    }

    const bool allow_mode = result.count("allow") != 0;
    const bool deny_mode = result.count("deny") != 0;
    if (allow_mode && deny_mode) {
      std::fprintf(stderr, "use either --allow or --deny, not both\n");
      std::exit(1);
    }

    if (result.count("elf") == 0) {
      std::fprintf(stderr, "missing <elf-file>\n%s\n", parser.help().c_str());
      std::exit(1);
    }

    Options opts{};
    if (result.count("hook") != 0) {
      opts.hook = result["hook"].as<std::vector<uint32_t>>();
    }
    if (allow_mode) {
      opts.allow = result["allow"].as<std::vector<uint32_t>>();
    }
    if (deny_mode) {
      opts.deny = result["deny"].as<std::vector<uint32_t>>();
    }
    opts.debug = result.count("debug") != 0;
    opts.elf_path = result["elf"].as<std::string>();
    return opts;
  } catch (const cxxopts::exceptions::exception &e) {
    std::fprintf(stderr, "%s\n%s\n", e.what(), parser.help().c_str());
    std::exit(1);
  }
}

} // namespace

int main(int argc, char **argv) {
  try {
    Options opts = parse_options(argc, argv);
    const char *elf_path = opts.elf_path.c_str();

    std::vector<uint8_t> file = syslift::read_whole_file(elf_path);

    syslift::ParsedElf parsed = syslift::parse_elf(file);
    syslift::reject_if_text_contains_svc(file, parsed);
    if (opts.debug) {
      syslift::dump_syslift_table(parsed);
    }
    syslift::reject_if_unknown_syscall_nr(parsed);

    syslift::Image image = syslift::map_image(file, parsed);
    uintptr_t hook_stub_addr = 0;

    auto contains = [](const std::vector<uint32_t> &list, uint32_t value) {
      return std::find(list.begin(), list.end(), value) != list.end();
    };

    for (const syslift::SysliftSyscallSite &site : parsed.syscall_sites) {
      const uint32_t sys_nr = static_cast<uint32_t>(site.values[0]);
      if (contains(opts.hook, sys_nr)) {
        if (hook_stub_addr == 0) {
          hook_stub_addr = syslift::install_hook_stub(
              image, reinterpret_cast<uintptr_t>(&syslift::syslift_framework_hook));
        }
        syslift::patch_syscall_to_hook(site, image, hook_stub_addr);
        if (opts.debug) {
          std::fprintf(stderr,
                       "site_vaddr=0x%" PRIx64 " sys_nr=%" PRIu32
                       " action=HOOKED\n",
                       site.site_vaddr, sys_nr);
        }
        continue;
      }

      bool should_patch = true;
      if (!opts.allow.empty()) {
        should_patch = contains(opts.allow, sys_nr);
      } else if (!opts.deny.empty()) {
        should_patch = !contains(opts.deny, sys_nr);
      }

      if (!should_patch) {
        if (opts.debug) {
          std::fprintf(stderr, "site_vaddr=0x%" PRIx64 " sys_nr=%" PRIu32
                               " action=ENOSYS\n",
                       site.site_vaddr, sys_nr);
        }
        continue;
      }

      syslift::patch_syscall_to_svc(site, image);
      if (opts.debug) {
        std::fprintf(stderr,
                     "site_vaddr=0x%" PRIx64 " sys_nr=%" PRIu32
                     " action=PATCHED\n",
                     site.site_vaddr, sys_nr);
      }
    }

    syslift::apply_segment_protections(image);

    syslift::RuntimeStack runtime_stack = syslift::setup_runtime_stack(elf_path);

    const uintptr_t entry = image.entry;
    const uintptr_t entry_sp = runtime_stack.entry_sp;
    if (opts.debug) {
      std::fprintf(stderr, "start executing: entry=0x%" PRIxPTR "\n", entry);
    }
    syslift::jump_to_entry(entry, entry_sp);
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}

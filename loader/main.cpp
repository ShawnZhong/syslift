#include "parse.h"
#include "reject.h"
#include "relocate.h"
#include "runtime.h"
#include "syscall.h"

#include <cxxopts.hpp>
#include <inttypes.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct Options {
  std::vector<uint32_t> hook;
  std::vector<uint32_t> allow;
  std::vector<uint32_t> deny;
  std::vector<std::string> exec_args;
  bool debug = false;
  std::string elf_path;
};

std::vector<uint32_t> parse_syscall_names(
    const std::vector<std::string> &names) {
  std::vector<uint32_t> numbers;
  numbers.reserve(names.size());
  for (const std::string &name : names) {
    const auto it = syslift::kSyscallNameToNumber.find(name);
    if (it == syslift::kSyscallNameToNumber.end()) {
      throw std::runtime_error("unknown syscall name: " + name);
    }
    numbers.push_back(it->second);
  }
  return numbers;
}

Options parse_options(int argc, char **argv) {
  cxxopts::Options parser(argv[0], "syslift loader");
  parser.positional_help("<elf-file> [-- <args...>]");
  parser.add_options()(
      "hook", "Hook syscall names (comma-separated or repeated)",
      cxxopts::value<std::vector<std::string>>())(
      "allow", "Allow-list syscall names (comma-separated or repeated)",
      cxxopts::value<std::vector<std::string>>())(
      "deny", "Deny-list syscall names (comma-separated or repeated)",
      cxxopts::value<std::vector<std::string>>())(
      "debug", "Enable debug logging")(
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
      opts.hook = parse_syscall_names(result["hook"].as<std::vector<std::string>>());
    }
    if (allow_mode) {
      opts.allow =
          parse_syscall_names(result["allow"].as<std::vector<std::string>>());
    }
    if (deny_mode) {
      opts.deny = parse_syscall_names(result["deny"].as<std::vector<std::string>>());
    }
    opts.exec_args = result.unmatched();
    opts.debug = result.count("debug") != 0;
    opts.elf_path = result["elf"].as<std::string>();
    return opts;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n%s\n", e.what(), parser.help().c_str());
    std::exit(1);
  }
}

bool contains(const std::vector<uint32_t> &list, uint32_t value) {
  return std::find(list.begin(), list.end(), value) != list.end();
}

bool should_patch_syscall(const Options &opts, uint32_t sys_nr) {
  if (!opts.allow.empty()) {
    return contains(opts.allow, sys_nr);
  }
  if (!opts.deny.empty()) {
    return !contains(opts.deny, sys_nr);
  }
  return true;
}

void patch_program_syscall(syslift::Program &program,
                           const syslift::SysliftSyscallSite &site,
                           const Options &opts, uintptr_t hook_stub_addr) {
  const uint32_t sys_nr = static_cast<uint32_t>(site.values[0]);
  const char *action;
  if (contains(opts.hook, sys_nr)) {
    syslift::patch_syscall_to_hook(program, site, hook_stub_addr);
    action = "HOOKED";
  } else if (should_patch_syscall(opts, sys_nr)) {
    syslift::patch_syscall_to_insn(program, site);
    action = "PATCHED";
  } else {
    action = "ENOSYS";
  }

  if (opts.debug) {
    std::fprintf(stderr, "site_vaddr=0x%" PRIx64 " sys_nr=%" PRIu32
                         " action=%s\n",
                 site.site_vaddr, sys_nr, action);
  }
}

void execute_program(const Options &opts) {
  syslift::Program program = syslift::parse_program(opts.elf_path);
  if (opts.debug) {
    syslift::dump_program(program);
  }
  for (const syslift::Segment &segment : program.segments) {
    syslift::reject_if_executable_contains_syscall(segment, program.arch);
  }
  for (const syslift::SysliftSyscallSite &site : program.syscall_sites) {
    syslift::reject_if_unknown_syscall_nr(site);
  }

  uintptr_t hook_stub_addr = 0;
  if (!opts.hook.empty()) {
    hook_stub_addr = syslift::install_hook_stub(
        program, reinterpret_cast<uintptr_t>(&syslift::syslift_framework_hook));
  }
  for (const syslift::SysliftSyscallSite &site : program.syscall_sites) {
    patch_program_syscall(program, site, opts, hook_stub_addr);
  }

  const uintptr_t load_bias = syslift::map_image(program);

  const uintptr_t entry_sp =
      syslift::setup_runtime_stack(opts.elf_path, opts.exec_args);

  const uintptr_t entry_pc = load_bias + program.entry;
  if (opts.debug) {
    std::fprintf(stderr, "start executing: entry_pc=0x%" PRIxPTR "\n", entry_pc);
  }
  syslift::jump_to_entry(entry_pc, entry_sp);
}

} // namespace

int main(int argc, char **argv) {
  try {
    execute_program(parse_options(argc, argv));
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}

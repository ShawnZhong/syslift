#pragma once

#include "elf.h"

#include <cstdint>
#include <string>
#include <vector>

namespace syslift {

struct Options {
  bool allow_all = false;
  std::vector<uint32_t> allow;
  std::string elf_path;
};

bool parse_options(int argc, char **argv, Options *opts);

bool evaluate_policy(const std::vector<SysliftSyscallSite> &sites,
                     const Options &opts,
                     std::vector<uint32_t> *denied);

} // namespace syslift

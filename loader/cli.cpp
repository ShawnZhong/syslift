#include "cli.h"

#include <cxxopts.hpp>

#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_set>

namespace syslift {
namespace {

bool parse_u32(const char *text, uint32_t *out) {
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

bool parse_allow_csv(const char *csv, std::vector<uint32_t> *allow) {
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

} // namespace

bool parse_options(int argc, char **argv, Options *opts) {
  cxxopts::Options parser(argv[0], "syslift loader");
  parser.positional_help("<elf-file>");
  parser.add_options()
      ("allow-all", "Allow all syscall numbers")
      ("allow", "Allowed syscall number(s): nr or comma-separated list",
       cxxopts::value<std::vector<std::string>>())
      ("h,help", "Show help")
      ("elf", "ELF file", cxxopts::value<std::string>());
  parser.parse_positional({"elf"});

  try {
    auto result = parser.parse(argc, argv);
    if (result.count("help") != 0) {
      std::printf("%s\n", parser.help().c_str());
      std::exit(0);
    }

    opts->allow_all = result.count("allow-all") != 0;
    opts->allow.clear();
    opts->elf_path.clear();

    if (result.count("allow") != 0) {
      for (const std::string &value :
           result["allow"].as<std::vector<std::string>>()) {
        if (!parse_allow_csv(value.c_str(), &opts->allow)) {
          return false;
        }
      }
    }

    if (!result.unmatched().empty()) {
      std::fprintf(stderr,
                   "extra argv forwarding is not supported by in-process loader\n");
      return false;
    }

    if (result.count("elf") == 0) {
      std::fprintf(stderr, "%s\n", parser.help().c_str());
      return false;
    }

    opts->elf_path = result["elf"].as<std::string>();
    return true;
  } catch (const cxxopts::exceptions::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    std::fprintf(stderr, "%s\n", parser.help().c_str());
    return false;
  }
}

bool evaluate_policy(const std::vector<SysliftSyscallSite> &sites,
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

} // namespace syslift

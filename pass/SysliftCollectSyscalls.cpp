#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <limits>
#include <optional>
#include <string>

using namespace llvm;

namespace {

static constexpr char SysliftSyscallTableSection[] = ".syslift";
static constexpr unsigned SysliftValueCount = 7;
static constexpr uint32_t SysliftNrBit = 1u << 0;

enum class TargetArch {
  AArch64,
  X86_64,
};

static cl::opt<std::string> SysliftSectionName(
    "syslift-section",
    cl::desc("ELF section used for syscall-site records"),
    cl::init(SysliftSyscallTableSection));

static std::atomic<uint64_t> GlobalSiteId{0};

static bool isAsmIdentChar(char C) {
  const unsigned char UC = static_cast<unsigned char>(C);
  return std::isalnum(UC) != 0 || C == '_' || C == '.';
}

static StringRef dropLeadingAsmLabels(StringRef Statement);

static StringRef extractAsmMnemonic(StringRef Statement, StringRef *Operand) {
  Statement = dropLeadingAsmLabels(Statement).ltrim();
  if (Statement.empty()) {
    *Operand = StringRef();
    return StringRef();
  }

  const size_t MnemonicEnd = Statement.find_first_of(" \t");
  if (MnemonicEnd == StringRef::npos) {
    *Operand = StringRef();
    return Statement;
  }

  *Operand = Statement.drop_front(MnemonicEnd).ltrim();
  return Statement.take_front(MnemonicEnd);
}

static StringRef dropLeadingAsmLabels(StringRef Statement) {
  while (true) {
    Statement = Statement.ltrim();
    if (Statement.empty()) {
      return Statement;
    }

    const size_t Colon = Statement.find(':');
    if (Colon == StringRef::npos) {
      return Statement;
    }

    const size_t Space = Statement.find_first_of(" \t");
    if (Space != StringRef::npos && Space < Colon) {
      return Statement;
    }
    Statement = Statement.drop_front(Colon + 1);
  }
}

static bool matchesAArch64SvcInstruction(StringRef Statement) {
  StringRef Operand;
  const StringRef Mnemonic = extractAsmMnemonic(Statement, &Operand);
  if (Mnemonic.empty()) {
    return false;
  }
  if (!Mnemonic.equals_insensitive("svc")) {
    return false;
  }
  if (Operand.consume_front("#")) {
    Operand = Operand.ltrim();
  }

  if (!Operand.consume_front("0")) {
    return false;
  }
  return Operand.empty() || !isAsmIdentChar(Operand.front());
}

static bool matchesX86SyscallInstruction(StringRef Statement) {
  StringRef Operand;
  const StringRef Mnemonic = extractAsmMnemonic(Statement, &Operand);
  return Mnemonic.equals_insensitive("syscall");
}

static bool containsSyscallInsn(StringRef AsmText, TargetArch Arch) {
  while (!AsmText.empty()) {
    const size_t Delim = AsmText.find_first_of("\n;");
    const StringRef Statement =
        Delim == StringRef::npos ? AsmText : AsmText.take_front(Delim);

    if (Arch == TargetArch::AArch64) {
      if (matchesAArch64SvcInstruction(Statement)) {
        return true;
      }
    } else if (Arch == TargetArch::X86_64) {
      if (matchesX86SyscallInstruction(Statement)) {
        return true;
      }
    } else {
      llvm_unreachable("unsupported arch");
    }

    if (Delim == StringRef::npos) {
      break;
    }
    AsmText = AsmText.drop_front(Delim + 1);
  }
  return false;
}

static std::optional<unsigned> parseAArch64RegFromConstraintCode(StringRef Code) {
  if (Code.size() < 4 || Code.front() != '{' || Code.back() != '}') {
    return std::nullopt;
  }

  StringRef Reg = Code.drop_front().drop_back();
  if (Reg.size() < 2) {
    return std::nullopt;
  }
  if (!Reg.starts_with_insensitive("x") && !Reg.starts_with_insensitive("w")) {
    return std::nullopt;
  }

  unsigned RegNum = 0;
  if (Reg.drop_front().getAsInteger(10, RegNum)) {
    return std::nullopt;
  }
  return RegNum;
}

static std::optional<unsigned>
parseX86ValueIndexFromConstraintCode(StringRef Code) {
  if (Code.size() < 4 || Code.front() != '{' || Code.back() != '}') {
    return std::nullopt;
  }

  StringRef Reg = Code.drop_front().drop_back();
  static constexpr struct {
    const char *Reg;
    unsigned ValueIndex;
  } kX86RegisterMap[] = {
      {"rax", 0}, {"eax", 0}, {"ax", 0},  {"al", 0},   {"rdi", 1},
      {"edi", 1}, {"di", 1},  {"dil", 1}, {"rsi", 2},  {"esi", 2},
      {"si", 2},  {"sil", 2}, {"rdx", 3}, {"edx", 3},  {"dx", 3},
      {"dl", 3},  {"r10", 4}, {"r10d", 4}, {"r10w", 4}, {"r10b", 4},
      {"r8", 5},  {"r8d", 5}, {"r8w", 5}, {"r8b", 5},  {"r9", 6},
      {"r9d", 6}, {"r9w", 6}, {"r9b", 6},
  };
  for (const auto &Entry : kX86RegisterMap) {
    if (Reg.equals_insensitive(Entry.Reg)) {
      return Entry.ValueIndex;
    }
  }
  return std::nullopt;
}

static std::optional<unsigned> parseValueIndexFromConstraintCode(TargetArch Arch,
                                                                 StringRef Code) {
  if (Arch == TargetArch::AArch64) {
    std::optional<unsigned> Reg = parseAArch64RegFromConstraintCode(Code);
    if (!Reg.has_value()) {
      return std::nullopt;
    }
    if (Reg.value() == 8) {
      return 0;
    }
    if (Reg.value() + 1 < SysliftValueCount) {
      return Reg.value() + 1;
    }
    return std::nullopt;
  }
  if (Arch == TargetArch::X86_64) {
    return parseX86ValueIndexFromConstraintCode(Code);
  }
  llvm_unreachable("unsupported arch");
}

struct SyscallArgMetadata {
  uint32_t KnownMask = 0;
  std::array<uint64_t, SysliftValueCount> Values{};
};

static std::optional<uint64_t> extractKnownArgValue(const Value *Arg) {
  if (const auto *Imm = dyn_cast<ConstantInt>(Arg)) {
    APInt Val = Imm->getValue();
    if (Val.getBitWidth() > 64) {
      Val = Val.trunc(64);
    }
    return Val.getZExtValue();
  }
  if (isa<ConstantPointerNull>(Arg)) {
    return 0;
  }
  return std::nullopt;
}

static SyscallArgMetadata collectSyscallArgMetadata(const CallBase &CB,
                                                    const InlineAsm &IA,
                                                    TargetArch Arch) {
  InlineAsm::ConstraintInfoVector Constraints = IA.ParseConstraints();
  unsigned ArgIndex = 0;
  SyscallArgMetadata Meta;

  for (const InlineAsm::ConstraintInfo &Constraint : Constraints) {
    if (!Constraint.hasArg()) {
      continue;
    }
    const unsigned ThisArgIndex = ArgIndex++;
    if (Constraint.Type != InlineAsm::isInput ||
        ThisArgIndex >= CB.arg_size()) {
      continue;
    }

    const Value *Arg = CB.getArgOperand(ThisArgIndex);
    for (const std::string &Code : Constraint.Codes) {
      const std::optional<unsigned> ValueIndex =
          parseValueIndexFromConstraintCode(Arch, Code);
      if (!ValueIndex.has_value()) {
        continue;
      }

      if (ValueIndex.value() == 0u) {
        if (const auto *Imm = dyn_cast<ConstantInt>(Arg);
            Imm != nullptr && !Imm->isNegative() &&
            !Imm->getValue().ugt(std::numeric_limits<uint32_t>::max())) {
          Meta.KnownMask |= SysliftNrBit;
          Meta.Values[0] = Imm->getZExtValue();
        }
        continue;
      }

      std::optional<uint64_t> KnownValue = extractKnownArgValue(Arg);
      if (!KnownValue.has_value()) {
        continue;
      }
      Meta.KnownMask |= (1u << ValueIndex.value());
      Meta.Values[ValueIndex.value()] = KnownValue.value();
    }
  }

  return Meta;
}

static std::string buildSectionEntryAsm(StringRef SectionName,
                                        StringRef SiteLabel,
                                        const SyscallArgMetadata &ArgMeta,
                                        TargetArch Arch) {
  std::string Asm;
  raw_string_ostream OS(Asm);
  const char *U64Directive = Arch == TargetArch::AArch64 ? ".xword" : ".quad";
  OS << "\t.pushsection " << SectionName << ",\"a\",@progbits\n";
  OS << "\t" << U64Directive << " " << SiteLabel << "\n";
  OS << "\t.long " << ArgMeta.KnownMask << "\n";
  for (unsigned I = 0; I < SysliftValueCount; ++I) {
    OS << "\t" << U64Directive << " " << ArgMeta.Values[I] << "\n";
  }
  OS << "\t.popsection\n";
  return Asm;
}

static std::string buildPatchedSiteAsm(StringRef SiteLabel, TargetArch Arch) {
  std::string Asm;
  raw_string_ostream OS(Asm);
  OS << SiteLabel << ":\n";
  if (Arch == TargetArch::AArch64) {
    // Reserve a fixed 8-byte patch slot:
    //   mov x0, #-ENOSYS (4 bytes) + nop (4 bytes)
    OS << "\tmov x0, #" << -ENOSYS << "\n";
    OS << "\tnop\n";
  } else {
    // Reserve a fixed 8-byte patch slot:
    //   mov rax, imm32 (7 bytes) + nop (1 byte)
    OS << "\t.byte 0x48, 0xC7, 0xC0\n";
    OS << "\t.long " << -ENOSYS << "\n";
    OS << "\tnop\n";
  }
  return Asm;
}

static InlineAsm *getInlineAsmCallee(CallBase &CB) {
  Value *Callee = CB.getCalledOperand();
  while (auto *CE = dyn_cast<ConstantExpr>(Callee)) {
    if (!CE->isCast()) {
      break;
    }
    Callee = CE->getOperand(0);
  }
  return dyn_cast<InlineAsm>(Callee);
}

static std::optional<TargetArch> getTargetArch(const Triple &TT) {
  if (TT.isAArch64()) {
    return TargetArch::AArch64;
  }
  if (TT.getArch() == Triple::x86_64) {
    return TargetArch::X86_64;
  }
  return std::nullopt;
}

class SysliftCollectSyscallsPass
    : public PassInfoMixin<SysliftCollectSyscallsPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const Triple TT(M.getTargetTriple());
    const std::optional<TargetArch> ArchOpt = getTargetArch(TT);
    if (!ArchOpt.has_value()) {
      return PreservedAnalyses::all();
    }
    if (SysliftSectionName.empty()) {
      return PreservedAnalyses::all();
    }
    const TargetArch Arch = ArchOpt.value();

    bool Changed = false;

    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          auto *CB = dyn_cast<CallBase>(&I);
          if (CB == nullptr) {
            continue;
          }

          InlineAsm *IA = getInlineAsmCallee(*CB);
          if (IA == nullptr) {
            continue;
          }
          if (!containsSyscallInsn(IA->getAsmString(), Arch)) {
            continue;
          }

          const SyscallArgMetadata ArgMeta =
              collectSyscallArgMetadata(*CB, *IA, Arch);

          const uint64_t SiteId =
              GlobalSiteId.fetch_add(1, std::memory_order_relaxed);
          const std::string SiteLabel =
              (Twine("__syslift_syscall_site_") + Twine(SiteId)).str();

          M.appendModuleInlineAsm(buildSectionEntryAsm(
              SysliftSectionName, SiteLabel, ArgMeta, Arch));

          Changed = true;
          if ((ArgMeta.KnownMask & SysliftNrBit) == 0u) {
            WithColor::warning(errs(), "SysliftCollectSyscallsPass")
                << "unable to prove constant syscall number"
                << "; recorded site with nr unknown for loader rejection\n";
          }

          InlineAsm *Replacement = InlineAsm::get(
              IA->getFunctionType(),
              buildPatchedSiteAsm(SiteLabel, Arch),
              IA->getConstraintString(), IA->hasSideEffects(), IA->isAlignStack(),
              IA->getDialect(), IA->canThrow());
          CB->setCalledOperand(Replacement);
        }
      }
    }

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "SysliftCollectSyscallsPass",
      LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              if (Name != "syslift-collect-syscalls") {
                return false;
              }
              MPM.addPass(SysliftCollectSyscallsPass());
              return true;
            });

        PB.registerOptimizerLastEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
              MPM.addPass(SysliftCollectSyscallsPass());
            });
      },
  };
}

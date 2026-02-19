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

static bool containsSyscallInsn(StringRef AsmText, TargetArch Arch) {
  if (Arch == TargetArch::AArch64) {
    return AsmText.contains_insensitive("svc #0") ||
           AsmText.contains_insensitive("svc\t#0") ||
           AsmText.contains_insensitive("svc 0") ||
           AsmText.contains_insensitive("svc\t0");
  }
  return AsmText.contains_insensitive("syscall");
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
  if (Reg.equals_insensitive("rax") || Reg.equals_insensitive("eax") ||
      Reg.equals_insensitive("ax") || Reg.equals_insensitive("al")) {
    return 0; // nr
  }
  if (Reg.equals_insensitive("rdi") || Reg.equals_insensitive("edi") ||
      Reg.equals_insensitive("di") || Reg.equals_insensitive("dil")) {
    return 1; // arg1
  }
  if (Reg.equals_insensitive("rsi") || Reg.equals_insensitive("esi") ||
      Reg.equals_insensitive("si") || Reg.equals_insensitive("sil")) {
    return 2; // arg2
  }
  if (Reg.equals_insensitive("rdx") || Reg.equals_insensitive("edx") ||
      Reg.equals_insensitive("dx") || Reg.equals_insensitive("dl")) {
    return 3; // arg3
  }
  if (Reg.equals_insensitive("r10") || Reg.equals_insensitive("r10d") ||
      Reg.equals_insensitive("r10w") || Reg.equals_insensitive("r10b")) {
    return 4; // arg4
  }
  if (Reg.equals_insensitive("r8") || Reg.equals_insensitive("r8d") ||
      Reg.equals_insensitive("r8w") || Reg.equals_insensitive("r8b")) {
    return 5; // arg5
  }
  if (Reg.equals_insensitive("r9") || Reg.equals_insensitive("r9d") ||
      Reg.equals_insensitive("r9w") || Reg.equals_insensitive("r9b")) {
    return 6; // arg6
  }
  return std::nullopt;
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
      std::optional<unsigned> ValueIndex;
      if (Arch == TargetArch::AArch64) {
        std::optional<unsigned> Reg = parseAArch64RegFromConstraintCode(Code);
        if (!Reg.has_value()) {
          continue;
        }
        if (Reg.value() == 8) {
          ValueIndex = 0;
        } else if (Reg.value() + 1 < SysliftValueCount) {
          ValueIndex = Reg.value() + 1;
        } else {
          continue;
        }
      } else {
        ValueIndex = parseX86ValueIndexFromConstraintCode(Code);
        if (!ValueIndex.has_value()) {
          continue;
        }
      }

      if (ValueIndex.value() == 0) {
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
    OS << "\tmov x0, #" << -ENOSYS << "\n";
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

class SysliftCollectSyscallsPass
    : public PassInfoMixin<SysliftCollectSyscallsPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const Triple TT(M.getTargetTriple());
    std::optional<TargetArch> Arch;
    if (TT.isAArch64()) {
      Arch = TargetArch::AArch64;
    } else if (TT.getArch() == Triple::x86_64) {
      Arch = TargetArch::X86_64;
    }
    if (!Arch.has_value()) {
      return PreservedAnalyses::all();
    }
    if (SysliftSectionName.empty()) {
      return PreservedAnalyses::all();
    }

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
          if (!containsSyscallInsn(IA->getAsmString(), Arch.value())) {
            continue;
          }

          const SyscallArgMetadata ArgMeta =
              collectSyscallArgMetadata(*CB, *IA, Arch.value());

          const uint64_t SiteId =
              GlobalSiteId.fetch_add(1, std::memory_order_relaxed);
          const std::string SiteLabel =
              (Twine("__syslift_syscall_site_") + Twine(SiteId)).str();

          M.appendModuleInlineAsm(buildSectionEntryAsm(
              SysliftSectionName, SiteLabel, ArgMeta, Arch.value()));

          Changed = true;
          if ((ArgMeta.KnownMask & SysliftNrBit) == 0u) {
            WithColor::warning(errs(), "SysliftCollectSyscallsPass")
                << "unable to prove constant "
                << (Arch.value() == TargetArch::AArch64 ? "x8" : "rax")
                << " for syscall site in function "
                << F.getName()
                << "; recorded site with nr unknown for loader rejection\n";
          }

          InlineAsm *Replacement = InlineAsm::get(
              IA->getFunctionType(),
              buildPatchedSiteAsm(SiteLabel, Arch.value()),
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
            [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
              MPM.addPass(SysliftCollectSyscallsPass());
            });
      },
  };
}

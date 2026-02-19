#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <atomic>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

using namespace llvm;

namespace {

static constexpr char SysliftSyscallTableSection[] = ".syslift";
static constexpr uint32_t AArch64SysExit = 93;
static constexpr int64_t AArch64NegEnosys = -38;

static cl::opt<std::string> SysliftSectionName(
    "syslift-section",
    cl::desc("ELF section used for syscall-site records"),
    cl::init(SysliftSyscallTableSection));

static std::atomic<uint64_t> GlobalSiteId{0};

static bool containsSvcImmZero(StringRef AsmText) {
  return AsmText.contains_insensitive("svc #0") ||
         AsmText.contains_insensitive("svc\t#0") ||
         AsmText.contains_insensitive("svc 0") ||
         AsmText.contains_insensitive("svc\t0");
}

static bool isX8ConstraintCode(StringRef Code) {
  return Code.equals_insensitive("{x8}") || Code.equals_insensitive("{w8}");
}

static std::optional<unsigned>
findX8InputArgIndex(const InlineAsm &IA) {
  InlineAsm::ConstraintInfoVector Constraints = IA.ParseConstraints();
  unsigned ArgIndex = 0;

  for (const InlineAsm::ConstraintInfo &Constraint : Constraints) {
    if (!Constraint.hasArg()) {
      continue;
    }

    const bool IsInput = Constraint.Type == InlineAsm::isInput;
    if (IsInput) {
      for (const std::string &Code : Constraint.Codes) {
        if (isX8ConstraintCode(Code)) {
          return ArgIndex;
        }
      }
    }

    ++ArgIndex;
  }

  return std::nullopt;
}

static std::optional<uint32_t> extractSyscallNumber(const CallBase &CB,
                                                    const InlineAsm &IA) {
  std::optional<unsigned> X8ArgIdx = findX8InputArgIndex(IA);
  if (!X8ArgIdx.has_value() || X8ArgIdx.value() >= CB.arg_size()) {
    return std::nullopt;
  }

  const Value *Arg = CB.getArgOperand(X8ArgIdx.value());
  const auto *Imm = dyn_cast<ConstantInt>(Arg);
  if (Imm == nullptr) {
    return std::nullopt;
  }
  if (Imm->isNegative()) {
    return std::nullopt;
  }
  if (Imm->getValue().ugt(std::numeric_limits<uint32_t>::max())) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(Imm->getZExtValue());
}

static bool isAlwaysAllowedSyscall(uint32_t SysNr) {
  return SysNr == AArch64SysExit;
}

static std::string buildSectionEntryAsm(StringRef SectionName,
                                        StringRef SiteLabel,
                                        uint32_t SysNr) {
  std::string Asm;
  raw_string_ostream OS(Asm);
  OS << "\t.pushsection " << SectionName << ",\"a\",@progbits\n";
  OS << "\t.xword " << SiteLabel << "\n";
  OS << "\t.word " << SysNr << "\n";
  OS << "\t.popsection\n";
  return Asm;
}

static std::string buildPatchedSiteAsm(StringRef SiteLabel) {
  std::string Asm;
  raw_string_ostream OS(Asm);
  OS << SiteLabel << ":\n";
  OS << "\tmov x0, #" << AArch64NegEnosys << "\n";
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
    if (!TT.isAArch64()) {
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
          if (!containsSvcImmZero(IA->getAsmString())) {
            continue;
          }

          std::optional<uint32_t> SysNr = extractSyscallNumber(*CB, *IA);
          if (!SysNr.has_value()) {
            report_fatal_error(
                Twine("SysliftCollectSyscallsPass: unable to prove constant x8 for "
                      "syscall site in function ") +
                F.getName());
          }
          if (isAlwaysAllowedSyscall(SysNr.value())) {
            continue;
          }

          const uint64_t SiteId = GlobalSiteId.fetch_add(1, std::memory_order_relaxed);
          const std::string SiteLabel =
              (Twine("__syslift_syscall_site_") + Twine(SiteId)).str();

          M.appendModuleInlineAsm(buildSectionEntryAsm(
              SysliftSectionName, SiteLabel, SysNr.value()));

          InlineAsm *Replacement = InlineAsm::get(
              IA->getFunctionType(), buildPatchedSiteAsm(SiteLabel),
              IA->getConstraintString(), IA->hasSideEffects(), IA->isAlignStack(),
              IA->getDialect(), IA->canThrow());
          CB->setCalledOperand(Replacement);
          Changed = true;
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

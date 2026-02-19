#include "llvm/ADT/Twine.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachinePassManager.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"

#include <atomic>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

using namespace llvm;

namespace {

static constexpr char SysliftSyscallTableSection[] = ".syslift";

static cl::opt<std::string> SysliftSectionName(
    "syslift-section",
    cl::desc("ELF section used for syscall-site records"),
    cl::init(SysliftSyscallTableSection));

static std::atomic<uint64_t> GlobalSiteId{0};

static bool isSvcOpcode(const MachineInstr &MI, const TargetInstrInfo *TII) {
  return TII->getName(MI.getOpcode()) == "SVC";
}

static bool isSvcInlineAsm(const MachineInstr &MI) {
  if (!MI.isInlineAsm() || MI.getNumOperands() == 0) {
    return false;
  }

  const MachineOperand &AsmOp = MI.getOperand(0);
  if (!AsmOp.isSymbol()) {
    return false;
  }

  StringRef AsmText = AsmOp.getSymbolName();
  if (AsmText.contains_insensitive("svc #0")) {
    return true;
  }
  if (AsmText.contains_insensitive("svc\t#0")) {
    return true;
  }
  if (AsmText.contains_insensitive("svc 0")) {
    return true;
  }
  if (AsmText.contains_insensitive("svc\t0")) {
    return true;
  }
  return false;
}

static bool isSvcImmZero(const MachineInstr &MI, const TargetInstrInfo *TII) {
  if (isSvcOpcode(MI, TII)) {
    for (const MachineOperand &Op : MI.operands()) {
      if (!Op.isImm()) {
        continue;
      }
      return Op.getImm() == 0;
    }
    return false;
  }
  return isSvcInlineAsm(MI);
}

static int findOpcodeByName(const TargetInstrInfo *TII, StringRef Name) {
  for (unsigned Opcode = 0; Opcode < TII->getNumOpcodes(); ++Opcode) {
    if (TII->getName(Opcode) == Name) {
      return static_cast<int>(Opcode);
    }
  }
  return -1;
}

static Register findPhysRegByName(const TargetRegisterInfo *TRI,
                                  StringRef Name) {
  for (unsigned Reg = 1; Reg < TRI->getNumRegs(); ++Reg) {
    StringRef RegName = TRI->getName(Reg);
    if (RegName.equals_insensitive(Name)) {
      return Register(Reg);
    }
  }
  return Register();
}

static bool isRegNamed(Register Reg, const TargetRegisterInfo *TRI,
                       StringRef Name) {
  if (!Reg.isValid() || !Reg.isPhysical()) {
    return false;
  }
  return StringRef(TRI->getName(Reg.id())).equals_insensitive(Name);
}

static bool isX8Reg(Register Reg, const TargetRegisterInfo *TRI) {
  return isRegNamed(Reg, TRI, "x8") || isRegNamed(Reg, TRI, "w8");
}

static bool definesX8(const MachineInstr &MI, const TargetRegisterInfo *TRI) {
  for (const MachineOperand &Op : MI.operands()) {
    if (!Op.isReg() || !Op.isDef()) {
      continue;
    }
    if (isX8Reg(Op.getReg(), TRI)) {
      return true;
    }
  }
  return false;
}

static std::optional<uint32_t>
extractSysNrFromX8Def(const MachineInstr &MI, const TargetInstrInfo *TII) {
  StringRef OpcodeName = TII->getName(MI.getOpcode());
  if (OpcodeName != "MOVi32imm" && OpcodeName != "MOVi64imm") {
    return std::nullopt;
  }

  for (const MachineOperand &Op : MI.operands()) {
    if (!Op.isImm()) {
      continue;
    }
    int64_t Imm = Op.getImm();
    if (Imm < 0 || Imm > std::numeric_limits<uint32_t>::max()) {
      return std::nullopt;
    }
    return static_cast<uint32_t>(Imm);
  }
  return std::nullopt;
}

static std::optional<uint32_t>
findSyscallNumber(const MachineBasicBlock &MBB,
                  MachineBasicBlock::const_iterator SiteIt,
                  const TargetInstrInfo *TII,
                  const TargetRegisterInfo *TRI) {
  for (auto It = SiteIt; It != MBB.begin();) {
    --It;
    const MachineInstr &MI = *It;
    if (MI.isDebugInstr() || MI.isCFIInstruction()) {
      continue;
    }
    if (!definesX8(MI, TRI)) {
      continue;
    }
    return extractSysNrFromX8Def(MI, TII);
  }
  return std::nullopt;
}

static std::string buildSectionEntryAsm(StringRef SectionName,
                                        StringRef SiteLabel,
                                        uint32_t SysNr) {
  std::string Asm;
  raw_string_ostream OS(Asm);
  OS << "\t.pushsection " << SectionName << ",\"a\",@progbits\n";
  OS << "\t.p2align 3\n";
  OS << "\t.xword " << SiteLabel << "\n";
  OS << "\t.word " << SysNr << "\n";
  OS << "\t.word 0\n";
  OS << "\t.popsection\n";
  return Asm;
}

class SysliftCollectSyscallsPass
    : public PassInfoMixin<SysliftCollectSyscallsPass> {
public:
  static bool runImpl(MachineFunction &MF) {
    const Triple &TT = MF.getTarget().getTargetTriple();
    if (!TT.isAArch64()) {
      return false;
    }
    if (SysliftSectionName.empty()) {
      return false;
    }

    Module &M = *MF.getFunction().getParent();
    const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
    const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
    int MovI64ImmOpcode = findOpcodeByName(TII, "MOVi64imm");
    if (MovI64ImmOpcode < 0) {
      report_fatal_error("SysliftCollectSyscallsPass: AArch64 MOVi64imm not found");
    }
    Register X0Reg = findPhysRegByName(TRI, "x0");
    if (!X0Reg.isValid()) {
      report_fatal_error("SysliftCollectSyscallsPass: AArch64 x0 register not found");
    }
    bool Changed = false;

    for (MachineBasicBlock &MBB : MF) {
      for (MachineBasicBlock::iterator It = MBB.begin(); It != MBB.end();) {
        MachineInstr &MI = *It;
        MachineBasicBlock::iterator SiteIt = It;
        ++It;
        if (!isSvcImmZero(MI, TII)) {
          continue;
        }

        std::optional<uint32_t> SysNr =
            findSyscallNumber(MBB, SiteIt, TII, TRI);
        if (!SysNr.has_value()) {
          report_fatal_error(
              Twine("SysliftCollectSyscallsPass: unable to prove constant x8 for "
                    "syscall site in function ") +
              MF.getName());
        }

        uint64_t SiteId = GlobalSiteId.fetch_add(1, std::memory_order_relaxed);
        std::string SiteLabel =
            (Twine("__syslift_syscall_site_") + Twine(SiteId)).str();
        MCSymbol *Sym = MF.getContext().getOrCreateSymbol(SiteLabel);

        BuildMI(MBB, SiteIt, MI.getDebugLoc(),
                TII->get(TargetOpcode::ANNOTATION_LABEL))
            .addSym(Sym);

        M.appendModuleInlineAsm(buildSectionEntryAsm(
            SysliftSectionName, SiteLabel, SysNr.value()));

        if (isSvcInlineAsm(MI)) {
          MI.getOperand(0).ChangeToES("mov x0, #38");
        } else {
          BuildMI(MBB, SiteIt, MI.getDebugLoc(), TII->get(MovI64ImmOpcode),
                  X0Reg)
              .addImm(38);
          MI.eraseFromParent();
        }

        Changed = true;
      }
    }

    return Changed;
  }

  PreservedAnalyses run(MachineFunction &MF,
                        MachineFunctionAnalysisManager &) {
    bool Changed = runImpl(MF);
    if (!Changed) {
      return PreservedAnalyses::all();
    }
    return PreservedAnalyses::none();
  }
};

class LegacySysliftCollectSyscallsPass : public MachineFunctionPass {
public:
  static char ID;

  LegacySysliftCollectSyscallsPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "SysliftCollectSyscallsPass"; }

  bool runOnMachineFunction(MachineFunction &MF) override {
    return SysliftCollectSyscallsPass::runImpl(MF);
  }
};

char LegacySysliftCollectSyscallsPass::ID = 0;
static RegisterPass<LegacySysliftCollectSyscallsPass> LegacyX(
    "syslift-collect-syscalls",
    "Collect all AArch64 svc #0 instruction sites into an ELF section", false,
    false);

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "SysliftCollectSyscallsPass",
      LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, MachineFunctionPassManager &MFPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              if (Name != "syslift-collect-syscalls") {
                return false;
              }
              MFPM.addPass(SysliftCollectSyscallsPass());
              return true;
            });
      },
  };
}

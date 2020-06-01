/******************************************************************************
 * Copyright (c) 2018 Philipp Schubert.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Philipp Schubert and others
 *****************************************************************************/

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/PassAnalysisSupport.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "phasar/DB/ProjectIRDB.h"
#include "phasar/PhasarLLVM/ControlFlow/ICFG.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDEInstInteractionAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDELinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDESolverTest.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDETaintAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDETypeStateAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSConstAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSLinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSSolverTest.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSTaintAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSTypeAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSUninitializedVariables.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/TypeStateDescriptions/CSTDFILEIOTypeStateDescription.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Solver/IDESolver.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Solver/IFDSSolver.h"
#include "phasar/PhasarLLVM/DataFlowSolver/Mono/Problems/InterMonoSolverTest.h"
#include "phasar/PhasarLLVM/DataFlowSolver/Mono/Problems/InterMonoTaintAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/Mono/Problems/IntraMonoFullConstantPropagation.h"
#include "phasar/PhasarLLVM/DataFlowSolver/Mono/Problems/IntraMonoSolverTest.h"
#include "phasar/PhasarLLVM/DataFlowSolver/Mono/Solver/InterMonoSolver.h"
#include "phasar/PhasarLLVM/DataFlowSolver/Mono/Solver/IntraMonoSolver.h"
#include "phasar/PhasarLLVM/DataFlowSolver/WPDS/Problems/WPDSLinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/WPDS/Problems/WPDSSolverTest.h"
#include "phasar/PhasarLLVM/Pointer/LLVMPointsToInfo.h"
#include "phasar/PhasarLLVM/TypeHierarchy/LLVMTypeHierarchy.h"
#include "phasar/PhasarLLVM/Utils/DataFlowAnalysisType.h"
#include "phasar/UntrustedPass/FixApiLinkagePass.h"
#include "phasar/UntrustedPass/Options.h"
#include "phasar/UntrustedPass/UntrustedPass.h"
#include "phasar/Utils/EnumFlags.h"

namespace psr {

char UntrustedPass::ID = 12;
using namespace llvm;

const static std::set<std::string> RemoveNoInline = {"__rust_alloc",
                                                     "__rust_alloc_zeroed"};
const static std::set<std::string> TrustedAllocs = {
    "__rust_alloc", "__rust_alloc_zeroed", "je_malloc",  "je_mallocx",
    "je_realloc",   "je_calloc",           "je_rallocx", "je_xallocx",
    "je_nallocx",   "je_nallocx"};

const static std::set<std::string> UntrustedAllocs = {
    "_Znwm",
    "_Znam",
    "malloc",
    "calloc",
    "realloc",
    "__rust_untrusted_alloc"
    "__rust_untrusted_alloc_zeroed"
    "__rust_untrusted_alloc"};

const static std::map<std::string, std::string> AllocReplacementMap = {
    {"__rust_alloc", "__rust_untrusted_alloc"},
    {"__rust_alloc_zeroed", "__rust_untrusted_alloc_zeroed"},
    {"je_malloc", "malloc"},
    //{"je_mallocx", "malloc"},
    {"je_realloc", "realloc"},
    //{"je_calloc", "calloc"}
    //{    "je_rallocx", }
    //{    "je_xallocx", }
    //{    "je_nallocx", }
    //{    "je_nallocx" }
};

const static std::set<std::string> Blacklist = {"__rust_alloc",
                                                "_ZN5alloc5alloc5alloc"};

void FilterPatchableInstructions(
    std::set<const Instruction *> &patchable_instructions);
bool patchInstruction(Instruction *I);
bool patchAllocCall(CallSite alloc);
bool patchRustAlloc(Instruction *I);

llvm::Function *FindRustMain(llvm::Function *Main) {
  // rust's main function takes a pointer to the real program entry point
  // and makes an indirect call to it inside internal_lang_start
  // so we find that function and just start analysis there instead of analyzing
  // a bogus main, that is not germane to the analysis. If this has been inlined
  // somehow, then we can just start w/ main, per normal.
  for (auto &BB : *Main) {
    for (auto &I : BB) {
      if (auto store = llvm::dyn_cast<llvm::StoreInst>(&I)) {
        auto Val = store->getValueOperand();
        if (Val->getType()->isPointerTy()) {
          auto itermediate_ty = Val->getType()->getPointerElementType();
          if (auto FuncTy =
                  llvm::dyn_cast<llvm::FunctionType>(itermediate_ty)) {
            return llvm::dyn_cast<llvm::Function>(Val);
          }
        }
      } else {
        llvm::CallSite CS(&I);
        if (!CS || CS.isIndirectCall())
          continue;
        if (CS.getCalledFunction()->getName().contains("lang_start")) {
          llvm::errs() << "searching for rust main -- found:\n";
          auto MainVal = CS.getArgOperand(0);
          if (auto RustMain = llvm::dyn_cast<llvm::Function>(MainVal)) {
            llvm::errs() << RustMain->getName() << "\n";
            return RustMain;
          }
        }
      }
    } // end for i in bb
  }   // end for BB in main

  return Main;
}

struct ContextExplorer {
  std::vector<const llvm::Instruction *> CallStack;
  std::unordered_set<const llvm::Function *> VisitedFunctions;
  std::set<const llvm::Value *> ReachingValues;
  const LLVMBasedICFG &Icfg;
  const LLVMPointsToGraph &PTG;
  llvm::Function *StartFunc;

  ContextExplorer(LLVMBasedICFG &ICFG, llvm::Function *Start)
      : Icfg(ICFG), PTG(Icfg.getWholeModulePTG()), StartFunc(Start) {}

  std::set<const llvm::Value *> ContextSensitiveSearchStart() {
    ContextSensitiveSearch(StartFunc);
    return ReachingValues;
  }

  void preCall(const llvm::Instruction *call) { CallStack.push_back(call); }
  void postCall(const llvm::Instruction *call) { CallStack.pop_back(); }

  void ContextSensitiveSearch(const llvm::Function *CalledFunc) {

    if (CalledFunc->isDeclaration() ||
        !VisitedFunctions.insert(CalledFunc).second) {
      return;
    }
    // llvm::errs() << "Context log: " << CalledFunc->getName() << "\n";

    for (auto &BB : *CalledFunc) {
      for (auto &I : BB) {
        llvm::ImmutableCallSite CS(&I);
        if (!CS)
          continue;

        auto CalleeList = Icfg.getCalleesOfCallAt(&I);
        for (auto Callee : CalleeList) {
          if (Callee->hasFnAttribute(llvm::Attribute::Untrusted)) {
            for (auto &A : CS.args()) {
              const llvm::Value *target = A;

              if (!A->getType()->isPointerTy())
                continue;
              llvm::errs() << "CallStack:\n";
              for (auto call : CallStack) {
                llvm::errs() << *call << "\n";
              }
              llvm::errs() << "Call: " << I << "\n";
              llvm::errs() << "Argument = " << *A << "\n";
              // have to throw away the const to use this API  -- great design
              // :/
              LLVMPointsToGraph *p = const_cast<LLVMPointsToGraph *>(&PTG);
              auto ReachableAllocs =
                  p->getReachableAllocationSites(target, CallStack);
              llvm::errs() <<"Reaching Allocs:\n";
              for(auto Alloc : ReachableAllocs)
              {
                llvm::errs() << *Alloc <<"\n";

              }
              ReachingValues.insert(ReachableAllocs.begin(),
                                    ReachableAllocs.end());
            }
          }
          preCall(&I);
          ContextSensitiveSearch(Callee);
          postCall(&I);
        }
      }
    }
  }
};

UntrustedPass::UntrustedPass() : llvm::ModulePass(ID) {}

llvm::StringRef UntrustedPass::getPassName() const { return "UntrustedPass"; }

bool UntrustedPass::runOnFunction(Function &F) {
  bool modified = false;
  // skip declarations
  if (F.isDeclaration())
    return modified;
  bool fixpoint = true;

  // loop over the function until all calls are inlined
  do {
    fixpoint = true;
    SmallVector<Instruction *, 10> CIS;
    for (auto &BB : F)
      for (auto &I : BB) {
        CallSite CS(&I);
        if (!CS)
          continue;
        if (CS.isIndirectCall())
          continue;
        auto Callee = CS.getCalledFunction();
        if (!Callee)
          continue;
        if (Callee->hasFnAttribute(Attribute::RustAllocator)) {
          CIS.push_back(&I);
        }
      } // for I in BB

    for (auto I : CIS) {
      llvm::errs() << *I << "\n";
      CallSite CS(I);
      if (!CS)
        continue;
      auto CalleeName = CS.getCalledFunction()->getName().str();
      InlineFunctionInfo IFI(nullptr);
      if (InlineFunction(CS, IFI)) {
        llvm::errs() << "Inlined call to " << CalleeName << " in "
                     << F.getName() << "\n";
        modified |= true;
        fixpoint = false;
      }
    }
  } while (!fixpoint);

  return modified;
}

bool UntrustedPass::runOnModule(llvm::Module &M) {

  std::set<const llvm::Function *> UntrustedAPIs;
  std::set<const llvm::Instruction *> UntrustedCalls;
  std::set<const llvm::Instruction *> AllocatorCalls;
  std::set<const llvm::Instruction *> patchable_instructions;
  std::set<std::string> EntryPointsSet;
  bool hasUntrusted = false;
  llvm::Function *RustLangStart = nullptr;
  for (auto &F : M) {
    if (F.getName().contains("lang_start"))
      RustLangStart = &F;
    if (F.hasFnAttribute(llvm::Attribute::Untrusted)) {
      hasUntrusted = true;
    }
    if (F.hasFnAttribute(llvm::Attribute::RustAllocator)) {
      // F.setLinkage(llvm::GlobalValue::LinkageTypes::ExternalLinkage);
    }
    if (!F.isDeclaration() && F.hasExternalLinkage()) {
      // EntryPointsSet.insert(F.getName().str());
    }
  }

  if (!hasUntrusted)
    return false;

  bool modified = false;

  // for (auto &F : M) {
  // modified |= runOnFunction(F);
  // llvm::errs() << "RunOnFunction finished\n";
  //}

  llvm::Function *Main = M.getFunction("main");

  llvm::Function *RustMain = RustLangStart ? FindRustMain(Main) : Main;
  EntryPointsSet.insert(RustMain->getName());

  // set up the IRDB
  ProjectIRDB DB({&M}, IRDBOptions::WPA);
  // check if the requested entry points exist

  // set up the call-graph algorithm to be used
  CallGraphAnalysisType CGTy = CallGraphAnalysisType::OTF;
  LLVMTypeHierarchy H(DB);
  LLVMPointsToInfo PT(DB);
  LLVMBasedCFG CFG;

  for (auto entry : EntryPointsSet) {
    llvm::outs() << "Exploring Entry Point " << entry << "\n";
    LLVMBasedICFG Icfg(DB, CGTy, {entry}, &H, &PT);

    for (auto &F : M) {
      if (F.hasFnAttribute(llvm::Attribute::Untrusted)) {
        UntrustedAPIs.insert(&F);
        auto CallerList = Icfg.getCallersOf(&F);
        UntrustedCalls.insert(CallerList.begin(), CallerList.end());
      } else if (F.hasFnAttribute(llvm::Attribute::RustAllocator) ||
                 AllocReplacementMap.count(F.getName().str())) {
        auto CallerList = Icfg.getCallersOf(&F);
        AllocatorCalls.insert(CallerList.begin(), CallerList.end());
      }
    }

    llvm::errs() << "Found " << UntrustedAPIs.size()
                 << " Untrusted APIs in Module\n";
    llvm::errs() << "Found " << UntrustedCalls.size()
                 << " Calls to Untrusted APIs\n";
    llvm::errs() << "Found " << AllocatorCalls.size()
                 << " Calls to RustAllocators\n";

    std::set<const llvm::Value *> UntrustedArgs;
#if 1
    ContextExplorer explorer(Icfg, RustMain);
    auto AllocSites = explorer.ContextSensitiveSearchStart();

    llvm::errs() << "\n\nFound " << AllocSites.size()
                 << " Reaching Allocation Sites\n";

    for (auto alloc : AllocSites) {
      if (auto Inst = llvm::dyn_cast<llvm::Instruction>(alloc)) {
        llvm::errs() << "\t" << *Inst << "\n";
        llvm::ImmutableCallSite CS(Inst);
        if (CS) {
          // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
          if (CS.isIndirectCall()) {
            auto call_targets = Icfg.getCalleesOfCallAt(Inst);
            for (auto target : call_targets) {
              if (target &&
                  (target->hasFnAttribute(llvm::Attribute::RustAllocator) ||
                   // LLVMPointsToGraph::HeapAllocationFunctions.count(
                   // AllocReplacementMap.count(target->getName().str()))) {
                   TrustedAllocs.count(target->getName().str()))) {
                // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
                patchable_instructions.insert(Inst);
              }
            }

          } else {
            auto target = CS.getCalledFunction();
            if (target &&
                (target->hasFnAttribute(llvm::Attribute::RustAllocator) ||
                 // LLVMPointsToGraph::HeapAllocationFunctions.count(
                 // AllocReplacementMap.count(
                 TrustedAllocs.count(target->getName().str()))) {
              // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
              patchable_instructions.insert(Inst);
            }
          }
        } // if it was a call
      }   // if it was an instruction
    }     // for each alloc site we found
          //}

    // llvm::errs() << "\n\nFound " << patchable_instructions.size()
    //<< " Patchable Instructions\n";
    // for (auto I : patchable_instructions) {
    // llvm::errs() << *I << "\n";
    //}
#else
    for (auto *I : UntrustedCalls) {
      llvm::ImmutableCallSite CS(I);
      if (!CS)
        continue;
      // check its arguments for aliases w/ the Allocators
      auto numArgs = CS.getNumArgOperands();
      for (unsigned i = 0; i < numArgs; i++) {
        auto Arg = CS.getArgOperand(i);
        if (!Arg)
          continue;
        if (!(Arg->getType()->isPointerTy() ||
              Arg->getType()->isAggregateType()))
          continue;
        const LLVMPointsToGraph &ptg = Icfg.getWholeModulePTG();
        auto pts = ptg.getPointsToSet(Arg);

        llvm::errs() << "Points to set for:\n";
        llvm::errs() << *Arg << "\n";
        UntrustedArgs.insert(Arg);
        for (auto v : pts) {
          // llvm::errs() << "\t" << *v << "\n";
          if (auto ValInst = llvm::dyn_cast<llvm::Instruction>(v)) {
            llvm::ImmutableCallSite CS(v);
            if (CS) {
              if (CS.isIndirectCall()) {
                auto call_targets = Icfg.getCalleesOfCallAt(ValInst);
                for (auto target : call_targets) {
                  if (target &&
                      (target->hasFnAttribute(llvm::Attribute::RustAllocator) ||
                       AllocReplacementMap.count(target->getName().str()))) {
                    // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
                    patchable_instructions.insert(ValInst);
                  }
                }

              } else {
                auto target = CS.getCalledFunction();
                if (target &&
                    (target->hasFnAttribute(llvm::Attribute::RustAllocator) ||
                     AllocReplacementMap.count(target->getName().str()))) {
                  // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
                  patchable_instructions.insert(ValInst);
                }
              }
              // llvm::errs() << "\t" << *v << "\n";
            } // if it was a call

          } // if v was instruction

        } // for v in pts
      }
    }

    // for (auto I : AllocatorCalls) {
    // for (auto Arg : UntrustedArgs) {
    // if (PT.alias(Arg, I) != AliasResult::NoAlias) {
    // patchable_instructions.insert(I);
    //}
    //}
    //}
#endif

  } // end entrypoints set

  int patchable_count = patchable_instructions.size();

  llvm::errs() << "\n\nFound " << patchable_count
               << " Patchable Instructions\n";

  int patch_count = 0;
  // count = patchable_nodes.size();
  if (patchable_count == 0)
    // LOG("dsa-untrusted",
    errs() << "Warning: No Patchable Instructions were found!\n";
  else {
    FilterPatchableInstructions(patchable_instructions);
    errs() << "Filtered Patchable Instruction count:"
           << patchable_instructions.size() << "\n";
    for (auto I : patchable_instructions) {
      errs() << *I << "\n";
      auto mod = patchInstruction(const_cast<Instruction *>(I));
      if (mod)
        patch_count++;
      modified |= mod;
    }
  }

  llvm::errs() << "Patched " << patch_count << " Instructions, out of "
               << patchable_count << " candidates\n";
  for (auto api : RemoveNoInline) {
    auto F = M.getFunction(api);
    if (!F) {
      llvm::errs() << "Could not find allocator to remove attribute from: "
                   << api << "\n";
      continue;
    }
    F->removeFnAttr(llvm::Attribute::NoInline);
    modified |= true;
  }

  return modified;
}

bool UntrustedPass::doInitialization(llvm::Module &M) {
  llvm::outs() << "UntrustedPass::doInitialization()\n";
  initializeLogger(InitLogger);
  return false;
}

bool UntrustedPass::doFinalization(llvm::Module &M) {
  llvm::outs() << "UntrustedPass::doFinalization()\n";
  return false;
}

void UntrustedPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
  AU.addRequired<FixApiLinkagePass>();
}

void UntrustedPass::releaseMemory() {}

void UntrustedPass::print(llvm::raw_ostream &O, const llvm::Module *M) const {
  O << "I am a UntrustedPass Analysis Result ;-)\n";
}

void FilterPatchableInstructions(
    std::set<const Instruction *> &patchable_instructions) {
  SmallPtrSet<Function *, 4> called;
  for (auto I : patchable_instructions) {
    CallSite CS(const_cast<Instruction *>(I));
    if (CS.isIndirectCall())
      continue;
    called.insert(CS.getCalledFunction());
  }
  SmallPtrSet<Instruction *, 4> ToRemove;

  // std::remove_if(patchable_instructions.begin(),
  // patchable_instructions.end(),
  //[&called](Instruction *I) {
  // auto parent = I->getFunction();
  // return called.find(parent) != called.end();
  //});

  for (auto I : patchable_instructions) {
    auto parent = I->getFunction();
    if (parent && called.find(parent) != called.end()) {
      ToRemove.insert(const_cast<Instruction *>(I));
    } else {
      for (auto Name : Blacklist) {
        if (parent->getName().contains(Name)) {
          ToRemove.insert(const_cast<Instruction *>(I));
          break;
        }
      }
    }
  }

  for (auto I : ToRemove) {
    patchable_instructions.erase(I);
  }
}

bool patchRustAlloc(Instruction *I) {
  CallSite Alloc(I);
  if (!Alloc) {
    errs() << "ERROR: expected trusted allocator call\n"
           << "Patch Failed at " << *I << "\n";
    return false;
  }

  auto F = Alloc.getCalledFunction();
  if (!F) {
    errs() << "ERROR while creating patch: Could not find called function\n";
    return false;
  }

  std::string ReplacementName =
      AllocReplacementMap.find(F->getName().str())->second;

  llvm::errs() << "Patching " << Alloc.getCalledFunction()->getName()
               << " Call Site in " << I->getFunction()->getName() << "\n";
  Function *UntrustedAlloc =
      I->getFunction()->getParent()->getFunction(ReplacementName);

  if (!UntrustedAlloc) {
    errs() << "ERROR while creating patch: Could not find replacement: "
           << ReplacementName << "\n";
    return false;
  }

  if (CallInst *call = dyn_cast<CallInst>(I)) {
    call->setCalledFunction(UntrustedAlloc);
  }
  return true;
}

bool patchAllocCall(CallSite alloc) {
  llvm::errs() << "Patching Allocation Call Site\n";
  auto LastArg = alloc.getNumArgOperands();
  if (LastArg == 0) {
    errs() << "Error Bad Argument index when patching Allocation call\n";
    return false;
  }
  LastArg--;
  Value *arg = alloc.getArgument(LastArg);
  auto isBool = arg->getType()->isIntegerTy(1);

  if (!isBool) {
    errs() << "Patch Failed in:" << alloc.getCaller()->getName() << " at\n"
           << *alloc.getInstruction() << "\n";
    errs() << "\tInstruction not a patchable Allocation call\n";
    return false;
  }

  llvm::errs() << "Boolean Parameter Found ... \n";
  // ConstantInt::get(arg->getType(), 0, SignExtend != 0);
  auto FalseVal = ConstantInt::getFalse(arg->getType());
  alloc.setArgument(LastArg, FalseVal);
  errs() << "Patched call of " << alloc.getCalledFunction()->getName() << " in "
         << alloc.getCaller()->getName() << "\n";
  return true;
}

bool patchInstruction(Instruction *I) {
  CallSite Alloc(I);
  if (!Alloc) {
    errs() << "ERROR: Patch expected a call site\n"
           << "Patch Failed at " << *I << "\n";
    return false;
  }

  // Function *RustAlloc =
  // I->getFunction()->getParent()->getFunction("__rust_alloc");

  // Function *UntrustedAlloc =
  // I->getFunction()->getParent()->getFunction("__rust_untrusted_alloc");

  if (Alloc.isIndirectCall()) {
    errs() << "Error: Indirect call to an allocator was found! Unable to "
              "patch!\n";
    return false;
  }

  if (AllocReplacementMap.count(Alloc.getCalledFunction()->getName().str())) {
    return patchRustAlloc(I);
  } else {
    return patchAllocCall(Alloc);
  }
}

llvm::Pass *createUntrustedPassPass() { return new psr::UntrustedPass(); }

static llvm::RegisterPass<UntrustedPass>
    UntrustedPass("untrusted-mpk", "Untrusted Instrumentation Pass",
                  false /* Only looks at CFG */, false /* Analysis Pass */);

} // namespace psr

/******************************************************************************
 * Copyright (c) 2017 Philipp Schubert.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Philipp Schubert and others
 *****************************************************************************/

#include <fstream>
#include <iostream>

#include "boost/filesystem/operations.hpp"

#include "phasar/DB/ProjectIRDB.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDELinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSLinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Solver/IDESolver.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Solver/IFDSSolver.h"
#include "phasar/PhasarLLVM/Pointer/LLVMPointsToInfo.h"
#include "phasar/PhasarLLVM/TypeHierarchy/LLVMTypeHierarchy.h"
#include "phasar/Utils/Logger.h"

namespace llvm {
class Value;
} // namespace llvm

using namespace psr;

llvm::Function *FindRustMain(llvm::Function *Main) {
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
      } // if store inst
    }   // end for i in bb
  }     // end for BB in main

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
    llvm::errs() << "Context log: " << CalledFunc->getName() << "\n";

    for (auto &BB : *CalledFunc) {
      for (auto &I : BB) {
        llvm::ImmutableCallSite CS(&I);
        if (!CS)
          continue;

        auto CalleeList = Icfg.getCalleesOfCallAt(&I);
        bool markArgs = false;
        for (auto Callee : CalleeList) {
          if (Callee->hasFnAttribute(llvm::Attribute::Untrusted)) {
            markArgs = true;
          }
          preCall(&I);
          ContextSensitiveSearch(Callee);
          postCall(&I);
        }

        if (markArgs) {
          for (auto &A : CS.args()) {
            const llvm::Value *target = A;
            // have to throw away the const to use this API  -- great design :/
            LLVMPointsToGraph *p = const_cast<LLVMPointsToGraph *>(&PTG);
            auto ReachableAllocs =
                p->getReachableAllocationSites(target, CallStack);
            ReachingValues.insert(ReachableAllocs.begin(),
                                  ReachableAllocs.end());
          }
        }
      }
    }
  }
};

int main(int Argc, const char **Argv) {
  initializeLogger(false);
  if (Argc < 2 || !boost::filesystem::exists(Argv[1]) ||
      boost::filesystem::is_directory(Argv[1])) {
    std::cerr << "myphasartool\n"
                 "A small PhASAR-based example program\n\n"
                 "Usage: myphasartool <LLVM IR file>\n";
    return 1;
  }
  ProjectIRDB DB({Argv[1]});
  llvm::Module &M = *DB.getWPAModule();
  llvm::Function *Main = M.getFunction("main");
  if (!Main) {
    std::cerr << "error: file does not contain a 'main' function!\n";
    return -1;
  }

  llvm::Function *RustMain = FindRustMain(Main);

  bool quit = false;
  std::set<const llvm::Function *> CalleeTargets;
  llvm::errs() << "Possible RustMain: " << RustMain->getName() << "\n";

  LLVMTypeHierarchy H(DB);
  LLVMPointsToInfo P(DB);
  LLVMBasedICFG Icfg(DB, CallGraphAnalysisType::OTF, {RustMain->getName()}, &H,
                     &P);

  // DB.getFunctionDefinition("_ZN8mpk_test4main17h22ea653e306581a2E"))
  // {
  // DB.getFunctionDefinition("main")) {
  // print type hierarchy
  // H.print();

  // print points-to information
  // P.print();
  // LLVMBasedICFG I(DB, CallGraphAnalysisType::OTF,
  //{"_ZN8mpk_test4main17h22ea653e306581a2E"}, &H, &P);
  // print inter-procedural control-flow graph
  // I.print();

  std::set<const llvm::Function *> UntrustedAPIs;
  std::set<const llvm::Instruction *> UntrustedCalls;
  std::set<const llvm::Instruction *> AllocatorCalls;
  for (auto &F : M) {
    if (F.hasFnAttribute(llvm::Attribute::Untrusted)) {
      UntrustedAPIs.insert(&F);
      auto CallerList = Icfg.getCallersOf(&F);
      UntrustedCalls.insert(CallerList.begin(), CallerList.end());
    } else if (F.hasFnAttribute(llvm::Attribute::RustAllocator)) {
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
  std::set<const llvm::Instruction *> patchable_instructions;
#if 0
  for (auto *I : UntrustedCalls) {
    llvm::ImmutableCallSite CS(I);
    if (!CS)
      continue;
    // check its arguments for aliases w/ the Allocators
    auto numArgs = CS.getNumArgOperands();
    for (unsigned i = 0; i < numArgs; i++) {
      auto Arg = CS.getArgOperand(i);
      const LLVMPointsToGraph &ptg = Icfg.getWholeModulePTG();
      auto pts = ptg.getPointsToSet(Arg);
      llvm::errs() << "Points to set for:\n";
      llvm::errs() << *Arg << "\n";
      for (auto v : pts) {
        if (auto ValInst = llvm::dyn_cast<llvm::Instruction>(v)) {
          llvm::ImmutableCallSite CS(v);
          if (CS) {
            if (CS.isIndirectCall()) {
              auto call_targets = Icfg.getCalleesOfCallAt(ValInst);
              for (auto target : call_targets) {
                if (target &&
                    target->hasFnAttribute(llvm::Attribute::RustAllocator)) {
                  // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
                  patchable_instructions.insert(ValInst);
                }
              }

            } else {
              auto target = CS.getCalledFunction();
              if (target &&
                  target->hasFnAttribute(llvm::Attribute::RustAllocator)) {
                // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
                patchable_instructions.insert(ValInst);
              }
            }
            // llvm::errs() << "\t" << *v << "\n";
          } // if it was a call

        } // if v was instruction

      } // for v in pts

#if 0
        for (auto I : AllocatorCalls) {
          if (P.alias(Arg, I) != AliasResult::NoAlias) {
            patchable_instructions.insert(I);
          }
        }
#endif

    } // for all callers of the API

  } // for each UntrustedAPIs

  llvm::errs() << "\n\nFound " << patchable_instructions.size()
               << " Patchable Instructions\n";
  for (auto I : patchable_instructions) {
    llvm::errs() << *I << "\n";
  }
#endif
  ContextExplorer explorer(Icfg, RustMain);
  auto AllocSites = explorer.ContextSensitiveSearchStart();

  llvm::errs() << "\n\nFound " << AllocSites.size()
               << " Reaching Allocation Sites\n";

  for (auto alloc : AllocSites) {
    if (auto Inst = llvm::dyn_cast<llvm::Instruction>(alloc)) {
      llvm::ImmutableCallSite CS(Inst);
      if (CS) {
        llvm::errs() << "\t" << *CS.getInstruction() << "\n";
        if (CS.isIndirectCall()) {
          auto call_targets = Icfg.getCalleesOfCallAt(Inst);
          for (auto target : call_targets) {
            if (target &&
                (target->hasFnAttribute(llvm::Attribute::RustAllocator) ||
                 LLVMPointsToGraph::HeapAllocationFunctions.count(
                     target->getName().str()))) {
              // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
              patchable_instructions.insert(Inst);
            }
          }

        } else {
          auto target = CS.getCalledFunction();
          if (target &&
              (target->hasFnAttribute(llvm::Attribute::RustAllocator) ||
               LLVMPointsToGraph::HeapAllocationFunctions.count(
                   target->getName().str()))) {
            // llvm::errs() << "\t" << *CS.getInstruction() << "\n";
            patchable_instructions.insert(Inst);
          }
        }
      } // if it was a call
    }   // if it was an instruction
  }     // for each alloc site we found

  llvm::errs() << "\n\nFound " << patchable_instructions.size()
               << " Patchable Instructions\n";
  for (auto I : patchable_instructions) {
    llvm::errs() << *I << "\n";
  }

  // consider marking functions we don't want to be removed as external linkage
  // llvm::errs() << "Functions w/ external linkage:\n";
  // for(auto &F : M)
  //{
  // if(F.isExternalLinkage(F.getLinkage()))
  //{
  // llvm::errs() << F.getName() << "\n";
  //}
  //}

  return 0;
}

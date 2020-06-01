/******************************************************************************
 * Copyright (c) 2018 Philipp Schubert.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Philipp Schubert and others
 *****************************************************************************/

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/GlobalValue.h"
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
#include "phasar/Utils/EnumFlags.h"

namespace psr {

char FixApiLinkagePass::ID = 12;
using namespace llvm;
const static std::set<std::string> BadLinkageApis = {
    "__rust_untrusted_alloc", "__rust_untrusted_alloc_zeroed"};

const static std::set<std::string> TrustedAllocs = {"__rust_alloc",
                                                    "__rust_alloc_zeroed"};

FixApiLinkagePass::FixApiLinkagePass() : llvm::ModulePass(ID) {}

llvm::StringRef FixApiLinkagePass::getPassName() const {
  return "FixApiLinkagePass";
}

bool FixApiLinkagePass::runOnModule(llvm::Module &M) {

  bool modified = false;
  for (auto api : BadLinkageApis) {
    auto F = M.getFunction(api);
    if (!F) {

      llvm::errs() << "Could not find api to modify: " << api << "\n";
      continue;
    }
    F->setLinkage(llvm::GlobalValue::LinkageTypes::ExternalLinkage);
    modified = true;
  }
  for (auto api : TrustedAllocs) {
    auto F = M.getFunction(api);
    if (!F) {
      llvm::errs() << "Could not find api to modify: " << api << "\n";
      continue;
    }
    F->addFnAttr(llvm::Attribute::NoInline);
    modified = true;
  }
  if (!modified)
    llvm::errs() << "No linkages were patched\n";

  return modified;
}

void FixApiLinkagePass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {}

void FixApiLinkagePass::releaseMemory() {}

void FixApiLinkagePass::print(llvm::raw_ostream &O,
                              const llvm::Module *M) const {
  O << "I am a FixApiLinkagePass Analysis Result ;-)\n";
}

llvm::Pass *createFixApiLinkagePassPass() {
  return new psr::FixApiLinkagePass();
}

static llvm::RegisterPass<FixApiLinkagePass>
    FixApiLinkagePass("untrusted-linkage", "FixApiLinkage Instrumentation Pass",
                      false /* Only looks at CFG */, false /* Analysis Pass */);

} // namespace psr

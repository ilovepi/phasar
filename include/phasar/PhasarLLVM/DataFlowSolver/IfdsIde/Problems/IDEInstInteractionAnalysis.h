/******************************************************************************
 * Copyright (c) 2019 Philipp Schubert, Richard Leer, and Florian Sattler.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Philipp Schubert and others
 *****************************************************************************/

#ifndef PHASAR_PHASARLLVM_IFDSIDE_PROBLEMS_IDEINSTINTERACTIONALYSIS_H_
#define PHASAR_PHASARLLVM_IFDSIDE_PROBLEMS_IDEINSTINTERACTIONALYSIS_H_

#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/EdgeFunctions/AllTop.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/EdgeFunctions/EdgeIdentity.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/FlowFunctions/Gen.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/FlowFunctions/Identity.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/IDETabulationProblem.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/LLVMFlowFunctions/MapFactsToCallee.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/LLVMFlowFunctions/MapFactsToCaller.h"
#include "phasar/PhasarLLVM/DataFlowSolver/IfdsIde/LLVMZeroValue.h"
#include "phasar/PhasarLLVM/Pointer/LLVMPointsToInfo.h"
#include "phasar/PhasarLLVM/TypeHierarchy/LLVMTypeHierarchy.h"
#include "phasar/Utils/BitVectorSet.h"
#include "phasar/Utils/LLVMShorthands.h"

#include "llvm/IR/Instruction.h"

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace psr {

template <typename EdgeFactType = std::string>
class IDEInstInteractionAnalysisT
    : public IDETabulationProblem<const llvm::Instruction *,
                                  const llvm::Value *, const llvm::Function *,
                                  const llvm::StructType *, const llvm::Value *,
                                  BitVectorSet<std::string>, LLVMBasedICFG> {
public:
  using d_t = const llvm::Value *;
  using n_t = const llvm::Instruction *;
  using m_t = const llvm::Function *;
  using t_t = const llvm::StructType *;
  using v_t = const llvm::Value *;

  // type of the element contained in the sets of edge functions
  using e_t = EdgeFactType;
  using l_t = BitVectorSet<e_t>;
  using i_t = LLVMBasedICFG;

private:
  std::function<std::set<e_t>(n_t, d_t, d_t)> EdgeFactGen;

public:
  IDEInstInteractionAnalysisT(const ProjectIRDB *IRDB,
                              const LLVMTypeHierarchy *TH,
                              const LLVMBasedICFG *ICF,
                              const LLVMPointsToInfo *PT,
                              std::set<std::string> EntryPoints = {"main"})
      : IDETabulationProblem(IRDB, TH, ICF, PT, EntryPoints) {
    IDETabulationProblem::ZeroValue = createZeroValue();
  }

  ~IDEInstInteractionAnalysisT() override = default;

  // Offer a special hook to the user that allows to generate additional
  // edge facts on-the-fly. Above the generator function, the ordinary
  // edge facts are generated according to the usual edge functions.

  inline void registerEdgeFactGenerator(
      std::function<std::set<e_t>(n_t curr, d_t srcNode, d_t destNode)>
          EdgeFactGenerator) {
    EdgeFactGen = EdgeFactGenerator;
  }

  // start formulating our analysis by specifying the parts required for IFDS

  std::shared_ptr<FlowFunction<d_t>> getNormalFlowFunction(n_t curr,
                                                           n_t succ) override {
    if (const auto *Alloca = llvm::dyn_cast<llvm::AllocaInst>(curr)) {
      return std::make_shared<Gen<d_t>>(Alloca, getZeroValue());
    }

    struct IIAFlowFunction : FlowFunction<d_t> {

      IDEInstInteractionAnalysisT &Problem;
      n_t Inst;

      IIAFlowFunction(IDEInstInteractionAnalysisT &Problem, n_t Inst)
          : Problem(Problem), Inst(Inst) {}

      std::set<d_t> computeTargets(d_t src) override {
        std::set<d_t> Facts;
        if (Problem.isZeroValue(src)) {
          // keep the zero flow fact
          Facts.insert(src);
          return Facts;
        }
        // populate and propagate other existing facts
        for (auto &Op : Inst->operands()) {
          // if one of the operands holds, also generate the instruction using
          // it
          if (Op == src) {
            Facts.insert(Inst);
          }
        }
        // pass everything that alreay holds as identity
        Facts.insert(src);
        return Facts;
      }
    };
    return std::make_shared<IIAFlowFunction>(*this, curr);
  }

  inline std::shared_ptr<FlowFunction<d_t>>
  getCallFlowFunction(n_t callStmt, m_t destMthd) override {
    return std::make_shared<MapFactsToCallee>(llvm::ImmutableCallSite(callStmt),
                                              destMthd);
  }

  inline std::shared_ptr<FlowFunction<d_t>>
  getRetFlowFunction(n_t callSite, m_t calleeMthd, n_t exitStmt,
                     n_t retSite) override {
    return std::make_shared<MapFactsToCaller>(llvm::ImmutableCallSite(callSite),
                                              calleeMthd, exitStmt);
  }

  inline std::shared_ptr<FlowFunction<d_t>>
  getCallToRetFlowFunction(n_t callSite, n_t retSite,
                           std::set<m_t> callees) override {
    return Identity<d_t>::getInstance();
  }

  inline std::shared_ptr<FlowFunction<d_t>>
  getSummaryFlowFunction(n_t callStmt, m_t destMthd) override {
    // do not use summaries
    return nullptr;
  }

  inline std::map<n_t, std::set<d_t>> initialSeeds() override {
    llvm::outs() << "IDEInstInteractionAnalysis::initialSeeds()\n";
    std::map<n_t, std::set<d_t>> SeedMap;
    for (auto &EntryPoint : EntryPoints) {
      SeedMap.insert(
          std::make_pair(&ICF->getFunction(EntryPoint)->front().front(),
                         std::set<d_t>({getZeroValue()})));
    }
    return SeedMap;
  }

  inline d_t createZeroValue() const override {
    llvm::outs() << "IDEInstInteractionAnalysis::createZeroValue()\n";
    // create a special value to represent the zero value!
    return LLVMZeroValue::getInstance();
  }

  inline bool isZeroValue(d_t d) const override {
    return LLVMZeroValue::getInstance()->isLLVMZeroValue(d);
  }

  // in addition provide specifications for the IDE parts

  inline std::shared_ptr<EdgeFunction<l_t>>
  getNormalEdgeFunction(n_t curr, d_t currNode, n_t succ,
                        d_t succNode) override {
    // check if the user has registered a fact generator function
    std::set<e_t> UserEdgeFacts;
    if (EdgeFactGen) {
      UserEdgeFacts = EdgeFactGen(curr, currNode, succNode);
    }
    // In addition to the edge facts generated by the ordinary edge functions,
    // generate the UserEdgeFacts, too.
    return EdgeIdentity<l_t>::getInstance();
  }

  inline std::shared_ptr<EdgeFunction<l_t>>
  getCallEdgeFunction(n_t callStmt, d_t srcNode, m_t destinationMethod,
                      d_t destNode) override {
    // can be passed as identity
    return EdgeIdentity<l_t>::getInstance();
  }

  inline std::shared_ptr<EdgeFunction<l_t>>
  getReturnEdgeFunction(n_t callSite, m_t calleeMethod, n_t exitStmt,
                        d_t exitNode, n_t reSite, d_t retNode) override {
    // can be passed as identity
    return EdgeIdentity<l_t>::getInstance();
  }

  inline std::shared_ptr<EdgeFunction<l_t>>
  getCallToRetEdgeFunction(n_t callSite, d_t callNode, n_t retSite,
                           d_t retSiteNode, std::set<m_t> callees) override {
    return EdgeIdentity<l_t>::getInstance();
  }

  inline std::shared_ptr<EdgeFunction<l_t>>
  getSummaryEdgeFunction(n_t callSite, d_t callNode, n_t retSite,
                         d_t retSiteNode) override {
    // do not use summaries
    return nullptr;
  }

  inline l_t topElement() override {
    llvm::outs() << "IDEInstInteractionAnalysis::topElement()\n";
    // have empty set to represent no information
    return {"__TOP__"};
  }

  inline l_t bottomElement() override {
    llvm::outs() << "IDEInstInteractionAnalysis::bottomElement()\n";
    return {"__BOTTOM__"};
  }

  inline l_t join(l_t lhs, l_t rhs) override {
    llvm::outs() << "IDEInstInteractionAnalysis::join()\n";
    return lhs.setUnion(rhs);
  }

  inline std::shared_ptr<EdgeFunction<l_t>> allTopFunction() override {
    llvm::outs() << "IDEInstInteractionAnalysis::allTopFunction()\n";
    return std::make_shared<AllTop<l_t>>(topElement());
  }

  void printNode(std::ostream &os, n_t n) const override {
    os << llvmIRToString(n);
  }

  void printDataFlowFact(std::ostream &os, d_t d) const override {
    os << llvmIRToString(d);
  }

  void printFunction(std::ostream &os, m_t m) const override {
    os << m->getName().str();
  }

  void printEdgeFact(std::ostream &os, l_t l) const override {
    auto lset = l.getAsSet();
    size_t idx = 0;
    for (const auto &s : lset) {
      os << s;
      if (idx != lset.size() - 1) {
        os << ", ";
      }
      ++idx;
    }
  }
};

using IDEInstInteractionAnalysis = IDEInstInteractionAnalysisT<>;

} // namespace psr

#endif

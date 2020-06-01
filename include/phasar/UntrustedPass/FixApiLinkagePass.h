/******************************************************************************
 * Copyright (c) 2020 Paul Kirth.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Paul Kirth
 *****************************************************************************/

#ifndef FIXAPILINKAGE_FIXAPILINKAGE_H_
#define FIXAPILINKAGE_FIXAPILINKAGE_H_

#include "llvm/Pass.h"

namespace llvm {
class Module;
class AnalysisUsage;
class raw_ostream;
} // namespace llvm

namespace psr {

class FixApiLinkagePass : public llvm::ModulePass {
public:
  static char ID;

  explicit FixApiLinkagePass();
  FixApiLinkagePass(const FixApiLinkagePass &) = delete;
  FixApiLinkagePass &operator=(const FixApiLinkagePass &) = delete;
  ~FixApiLinkagePass() override = default;

  llvm::StringRef getPassName() const override;

  bool runOnModule(llvm::Module &M) override;

  bool runOnFunction(llvm::Function &F);

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

  void releaseMemory() override;

  void print(llvm::raw_ostream &O, const llvm::Module *M) const override;
};

llvm::Pass *createFixApiLinkagePassPass();

} // namespace psr

#endif

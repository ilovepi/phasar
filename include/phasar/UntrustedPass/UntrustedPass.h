/******************************************************************************
 * Copyright (c) 2020 Paul Kirth.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Paul Kirth
 *****************************************************************************/

#ifndef UNTRUSTEDPASS_UNTRUSTEDPASS_H_
#define UNTRUSTEDPASS_UNTRUSTEDPASS_H_

#include "llvm/Pass.h"

namespace llvm {
class Module;
class AnalysisUsage;
class raw_ostream;
} // namespace llvm

namespace psr {

class UntrustedPass : public llvm::ModulePass {
public:
  static char ID;

  explicit UntrustedPass();
  UntrustedPass(const UntrustedPass &) = delete;
  UntrustedPass &operator=(const UntrustedPass &) = delete;
  ~UntrustedPass() override = default;

  llvm::StringRef getPassName() const override;

  bool runOnModule(llvm::Module &M) override;

  bool runOnFunction(llvm::Function &F);

  bool doInitialization(llvm::Module &M) override;

  bool doFinalization(llvm::Module &M) override;

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

  void releaseMemory() override;

  void print(llvm::raw_ostream &O, const llvm::Module *M) const override;
};

llvm::Pass *createUntrustedPassPass();

} // namespace psr

#endif

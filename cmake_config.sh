#!/bin/bash -e

BUILD_TYPE=Release
CC=/usr/bin/clang
CXX=/usr/bin/clang++

cmake -G Ninja \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DLLVM_DIR=$HOME/clang/lib/cmake/llvm \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  ..


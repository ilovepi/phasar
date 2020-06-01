file(GLOB_RECURSE UNTRUSTEDPASS_SRC *.h *.cpp)

set(PHASAR_LINK_LIBS
  phasar_config
  phasar_controlflow
  phasar_db
  #phasar_ifdside
  #phasar_mono
  #phasar_passes
  phasar_phasarllvm_utils
  phasar_pointer
  phasar_typehierarchy
  phasar_utils
)

set(LLVM_LINK_COMPONENTS
  Core
  Support
  TransformUtils
)

message("\nBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}\n")
if(BUILD_SHARED_LIBS)
  add_phasar_library(untrusted_pass
    SHARED
    ${UNTRUSTEDPASS_SRC}
  )
else()
  add_phasar_library(untrusted_pass
    STATIC
    ${UNTRUSTEDPASS_SRC}
  )
endif()

# We specifically link internal phasar libs into phasar_pass so on that the
# llvm user side only has to specify one library.

find_package(Boost COMPONENTS log filesystem graph program_options REQUIRED)
target_link_libraries(untrusted_pass
  LINK_PUBLIC
  ${PHASAR_LINK_LIBS}
  ${Boost_LIBRARIES}
)

set_target_properties(untrusted_pass
  PROPERTIES
  LINKER_LANGUAGE CXX
  PREFIX "lib"
)

#if (LLVM_LINK_LLVM_DYLIB)
  #llvm_config (untrusted_pass USE_SHARED ${LLVM_LINK_COMPONENTS})
#else()
  #llvm_config (SeaDsaAnalysis ${LLVM_LINK_COMPONENTS})
#endif ()


cmake_minimum_required(VERSION 3.15)

project(simdutf
  DESCRIPTION "Fast Unicode validation, transcoding and processing"
  LANGUAGES CXX
  VERSION 5.6.3
)

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
  message(STATUS "Big-endian system detected.")
endif()

include(GNUInstallDirs)
# The following requires CMake 3.21.
# if(PROJECT_IS_TOP_LEVEL)
#  message(STATUS "Building simdutf as a top-level project.")
#  include(CTest)
#else()
#  message(STATUS "Building simdutf as a subproject.")
#endif(PROJECT_IS_TOP_LEVEL)
include(CTest)
include(cmake/simdutf-flags.cmake)

set(SIMDUTF_LIB_VERSION "11.0.0" CACHE STRING "simdutf library version")
set(SIMDUTF_LIB_SOVERSION "11" CACHE STRING "simdutf library soversion")
option(SIMDUTF_TESTS "Whether the tests are included as part of the CMake Build." OFF)
option(SIMDUTF_BENCHMARKS "Whether the benchmarks are included as part of the CMake Build." OFF)
option(SIMDUTF_TOOLS "Whether the tools are included as part of the CMake build. Requires C++17 or better." OFF)
option(SIMDUTF_FUZZERS "Whether to build the fuzzers." OFF)


set(SIMDUTF_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(src)

message(STATUS "Compiling using the C++ standard:" ${CMAKE_CXX_STANDARD})
# ---- Install rules ----
add_library(rspamd-simdutf ALIAS simdutf)

set_target_properties(
    simdutf PROPERTIES
    VERSION "${SIMDUTF_LIB_VERSION}"
    SOVERSION "${SIMDUTF_LIB_SOVERSION}"
    WINDOWS_EXPORT_ALL_SYMBOLS YES
)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

configure_file(cmake/simdutf-config.cmake.in simdutf-config.cmake @ONLY)

write_basic_package_version_file(
    simdutf-config-version.cmake
    COMPATIBILITY SameMinorVersion
)

set(
    SIMDUTF_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/simdutf"
    CACHE STRING "CMake package config location relative to the install prefix"
)
mark_as_advanced(SIMDUTF_INSTALL_CMAKEDIR)


# pkg-config
include(cmake/JoinPaths.cmake)
join_paths(PKGCONFIG_INCLUDEDIR "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
join_paths(PKGCONFIG_LIBDIR "\${prefix}" "${CMAKE_INSTALL_LIBDIR}")

if(NOT SIMDUTF_SANITIZE)
  find_program(GREP grep)
  find_program(NM nm)
  if((NOT GREP) OR (NOT NM))
    message("grep and nm are unavailable on this system.")
  else()
    add_test(
      NAME "avoid_abort"
      # Under FreeBSD, the __cxa_guard_abort symbol may appear but it is fine.
      # So we want to look for <space><possibly _>abort as a test.
      COMMAND sh -c "${NM}  $<TARGET_FILE_NAME:simdutf> |  ${GREP} ' _*abort' || exit 0  && exit 1"
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
    add_test(
      NAME "avoid_cout"
      COMMAND sh -c "${NM}  $<TARGET_FILE_NAME:simdutf> |  ${GREP} ' _*cout' || exit 0  && exit 1"
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
    add_test(
      NAME "avoid_cerr"
      COMMAND sh -c "${NM}  $<TARGET_FILE_NAME:simdutf> |  ${GREP} ' _*cerr' || exit 0  && exit 1"
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
    add_test(
      NAME "avoid_printf"
      COMMAND sh -c "${NM}  $<TARGET_FILE_NAME:simdutf> |  ${GREP} ' _*printf' || exit 0  && exit 1"
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
    add_test(
      NAME "avoid_stdout"
      COMMAND sh -c "${NM}  $<TARGET_FILE_NAME:simdutf> |  ${GREP} stdout || exit 0 && exit 1"
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
    add_test(
      NAME "avoid_stderr"
      COMMAND sh -c "${NM}  $<TARGET_FILE_NAME:simdutf> |  ${GREP} stderr || exit 0 && exit 1"
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
  endif()
endif()

if(SIMDUTF_FUZZERS)
    add_subdirectory(fuzz)
endif()

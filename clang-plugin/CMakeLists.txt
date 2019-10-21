IF (ENABLE_CLANG_PLUGIN MATCHES "ON")
    # Clang plugin for static analysis
    PROJECT(RspamdClangPlugin)
    if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "Cannot build clang plugin when compiler is not clang")
    endif ()
    FIND_PACKAGE(LLVM REQUIRED CONFIG)

    MESSAGE(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
    MESSAGE(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
    INCLUDE_DIRECTORIES(${LLVM_INCLUDE_DIRS})
    ADD_DEFINITIONS(${LLVM_DEFINITIONS})

    find_path(LIBCLANG_INCLUDE_DIR clang-c/Index.h
            PATHS ${LLVM_INCLUDE_DIRS}
            DOC "The path to the directory that contains clang-c/Index.h")

    find_library(LIBCLANG_LIBRARY
            NAMES
            libclang
            clang
            PATHS ${LLVM_LIBRARY_DIRS}
            DOC "The file that corresponds to the libclang library.")

    get_filename_component(LIBCLANG_LIBRARY_DIR ${LIBCLANG_LIBRARY} PATH)

    set(LIBCLANG_LIBRARIES ${LIBCLANG_LIBRARY})
    set(LIBCLANG_INCLUDE_DIRS ${LIBCLANG_INCLUDE_DIR})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LibClang DEFAULT_MSG
            LIBCLANG_LIBRARY LIBCLANG_INCLUDE_DIR)

    mark_as_advanced(LIBCLANG_INCLUDE_DIR LIBCLANG_LIBRARY)

    if (NOT LIBCLANG_FOUND)
        MESSAGE(FATAL_ERROR "Libclang is required to build clang plugin")
    endif()

    SET(CLANGPLUGINSRC plugin.cc printf_check.cc)

    ADD_LIBRARY(rspamd-clang SHARED ${CLANGPLUGINSRC})
    SET_TARGET_PROPERTIES(rspamd-clang PROPERTIES
            COMPILE_FLAGS "${LLVM_CPP_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Werror"
            INCLUDE_DIRECTORIES ${LIBCLANG_INCLUDE_DIR}
            LINKER_LANGUAGE CXX)
    TARGET_LINK_LIBRARIES(rspamd-clang ${LIBCLANG_LIBRARIES})
    LINK_DIRECTORIES(${LLVM_LIBRARY_DIRS})
ENDIF()

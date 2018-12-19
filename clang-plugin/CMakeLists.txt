IF (ENABLE_CLANG_PLUGIN MATCHES "ON")
    # Clang plugin for static analysis
    if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "Cannot build clang plugin when compiler is not clang")
    endif ()

    LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
    ENABLE_LANGUAGE(CXX)
    FIND_PACKAGE(LLVM REQUIRED)
    MESSAGE(STATUS "Trying to find libclang for llvm version ${LLVM_PACKAGE_VERSION}")
    SET(libclang_llvm_header_search_paths
            # LLVM Debian/Ubuntu nightly packages: http://llvm.org/apt/
            "/usr/lib/llvm-${LLVM_PACKAGE_VERSION}/include/"
            # LLVM MacPorts
            "/opt/local/libexec/llvm-${LLVM_PACKAGE_VERSION}/include"
            # LLVM Homebrew
            "/usr/local/Cellar/llvm/${LLVM_PACKAGE_VERSION}/include"
            # LLVM Homebrew/versions
            "/usr/local/lib/llvm-${LLVM_PACKAGE_VERSION}/include"
            # FreeBSD ports versions
            "/usr/local/llvm${LLVM_PACKAGE_VERSION}/include"
            "${LLVM_INCLUDE_DIRS}"
            )

    SET(libclang_llvm_lib_search_paths
            # LLVM Debian/Ubuntu nightly packages: http://llvm.org/apt/
            "/usr/lib/llvm-${LLVM_PACKAGE_VERSION}/lib/"
            # LLVM MacPorts
            "/opt/local/libexec/llvm-${LLVM_PACKAGE_VERSION}/lib"
            # LLVM Homebrew
            "/usr/local/Cellar/llvm/${LLVM_PACKAGE_VERSION}/lib"
            # LLVM Homebrew/versions
            "/usr/local/lib/llvm-${LLVM_PACKAGE_VERSION}/lib"
            # FreeBSD ports versions
            "/usr/local/llvm${LLVM_PACKAGE_VERSION}/lib"
            "${LLVM_LIBRARY_DIRS}"
            )

    find_path(LIBCLANG_INCLUDE_DIR clang-c/Index.h
            PATHS ${libclang_llvm_header_search_paths}
            PATH_SUFFIXES LLVM/include #Windows package from http://llvm.org/releases/
            DOC "The path to the directory that contains clang-c/Index.h")
    find_library(LIBCLANG_LIBRARY NAMES libclang.imp libclang clang
            PATHS ${libclang_llvm_lib_search_paths}
            PATH_SUFFIXES LLVM/lib #Windows package from http://llvm.org/releases/
            DOC "The file that corresponds to the libclang library.")

    get_filename_component(LIBCLANG_LIBRARY_DIR ${LIBCLANG_LIBRARY} PATH)

    set(LIBCLANG_LIBRARIES ${LIBCLANG_LIBRARY})
    set(LIBCLANG_INCLUDE_DIRS ${LIBCLANG_INCLUDE_DIR})

    SET(CLANGPLUGINSRC plugin.cc printf_check.cc)

    ADD_LIBRARY(rspamd-clang SHARED ${CLANGPLUGINSRC})
    SET_TARGET_PROPERTIES(rspamd-clang PROPERTIES
            COMPILE_FLAGS "${LLVM_CPP_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Werror"
            INCLUDE_DIRECTORIES ${LIBCLANG_INCLUDE_DIR}
            LINKER_LANGUAGE CXX)
    TARGET_LINK_LIBRARIES(rspamd-clang ${LIBCLANG_LIBRARIES})
    LINK_DIRECTORIES(${LLVM_LIBRARY_DIRS})
ENDIF()


IF (ENABLE_CLANG_PLUGIN MATCHES "ON")
    # Clang plugin for static analysis
    PROJECT(RspamdClangPlugin CXX)
    if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "Cannot build clang plugin when compiler is not clang")
    endif ()
    FIND_PACKAGE(LLVM REQUIRED CONFIG)

    MESSAGE(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
    MESSAGE(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
    INCLUDE_DIRECTORIES(${LLVM_INCLUDE_DIRS})
    ADD_DEFINITIONS(${LLVM_DEFINITIONS})

    find_package(Clang REQUIRED)

    message(STATUS "Found LibClang in: ${CLANG_INSTALL_PREFIX}")
    include_directories(${CLANG_INCLUDE_DIRS})

    SET(CLANGPLUGINSRC plugin.cc printf_check.cc)

    ADD_LIBRARY(rspamd-clang SHARED ${CLANGPLUGINSRC})

    # Clang plugins must not be built with sanitizers - they conflict when loaded
    IF (SANITIZE)
        # Remove sanitizer flags from compile options
        set_target_properties(rspamd-clang PROPERTIES
            COMPILE_OPTIONS ""
            LINK_OPTIONS ""
        )
        target_compile_options(rspamd-clang PRIVATE
            -fno-sanitize=all
            -g -O0
        )
        target_link_options(rspamd-clang PRIVATE
            -fno-sanitize=all
        )
    ENDIF()

    # Link against LLVM shared library
    find_library(found_LLVM LLVM HINTS ${LLVM_LIBRARY_DIRS})
    if(found_LLVM)
        target_link_libraries(rspamd-clang PRIVATE ${found_LLVM})
    else()
        llvm_map_components_to_libnames(llvm_libs support core)
        target_link_libraries(rspamd-clang PRIVATE ${llvm_libs})
    endif()

    # Link against clang-cpp shared library (contains all clang components)
    find_library(found_clang_cpp clang-cpp HINTS ${LLVM_LIBRARY_DIRS})
    if(found_clang_cpp)
        target_link_libraries(rspamd-clang PRIVATE ${found_clang_cpp})
    else()
        # Fallback to libclang
        find_library(found_clang clang HINTS ${LLVM_LIBRARY_DIRS})
        if(found_clang)
            target_link_libraries(rspamd-clang PRIVATE ${found_clang})
        endif()
    endif()
ENDIF()

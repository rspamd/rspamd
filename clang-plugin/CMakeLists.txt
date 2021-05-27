
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

    set(clang_libs clang)

    message(STATUS "Found LibClang in: ${CLANG_INSTALL_PREFIX}")
    include_directories(${CLANG_INCLUDE_DIRS})

    SET(CLANGPLUGINSRC plugin.cc printf_check.cc)

    ADD_LIBRARY(rspamd-clang SHARED ${CLANGPLUGINSRC})
    IF (SANITIZE)
        set (CMAKE_C_FLAGS "")
        set (CMAKE_CXX_FLAGS "")
        set (CMAKE_EXE_LINKER_FLAGS "")
    ENDIF()


    find_library(found_LLVM LLVM HINTS ${LLVM_LIBRARY_DIRS})
    if(found_LLVM)
        target_link_libraries(rspamd-clang PRIVATE ${LLVM})
    else()
        # XXX not tested yet
        llvm_map_components_to_libnames(llvm_libs support core)
        target_link_libraries(rspamd-clang PRIVATE ${llvm_libs})
    endif()

    target_link_libraries(rspamd-clang PRIVATE ${clang_libs})
ENDIF()

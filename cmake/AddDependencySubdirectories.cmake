function(AddDependencySubdirectories)
    # Core dependencies
    add_subdirectory(contrib/hiredis)
    include_directories(BEFORE "${CMAKE_SOURCE_DIR}/contrib/hiredis")

    # Configure xxhash
    if (SYSTEM_XXHASH MATCHES "OFF")
        add_subdirectory(contrib/xxhash)
        include_directories("${CMAKE_SOURCE_DIR}/contrib/xxhash")
    else ()
        ProcessPackage(XXHASH LIBRARY xxhash INCLUDE xxhash.h
                ROOT ${LIBXXHASH_ROOT_DIR} MODULES xxhash libxxhash)
    endif ()

    # Add essential dependencies
    add_subdirectory(contrib/cdb)
    add_subdirectory(contrib/http-parser)
    add_subdirectory(contrib/fpconv)
    add_subdirectory(contrib/lc-btrie)
    add_subdirectory(contrib/libottery)
    add_subdirectory(contrib/simdutf)
    include_directories("${CMAKE_SOURCE_DIR}/contrib/simdutf/include")

    # Configure zstd
    if (SYSTEM_ZSTD MATCHES "OFF")
        add_subdirectory(contrib/zstd)
    else ()
        ProcessPackage(LIBZSTD LIBRARY zstd INCLUDE zstd.h
                ROOT ${LIBZSTD_ROOT_DIR} MODULES zstd libzstd)
        add_definitions(-DSYS_ZSTD)
    endif ()

    # Optional dependencies based on configuration
    if (ENABLE_SNOWBALL)
        add_subdirectory(contrib/snowball)
        set(WITH_SNOWBALL 1 PARENT_SCOPE)
    endif ()

    # Core libraries
    add_subdirectory(contrib/libucl)
    add_subdirectory(contrib/librdns)
    add_subdirectory(contrib/aho-corasick)
    add_subdirectory(contrib/lua-lpeg)
    add_subdirectory(contrib/t1ha)
    add_subdirectory(contrib/libev)
    add_subdirectory(contrib/kann)
    add_subdirectory(contrib/google-ced)

    # Backward-cpp for stacktraces
    if (ENABLE_BACKWARD)
        add_subdirectory(contrib/backward-cpp)
        message(STATUS "Backward-cpp config: ${BACKWARD_DEFINITIONS}")
    else ()
        set(BACKWARD_ENABLE)
        macro(add_backward target)
            # do nothing
        endmacro()
    endif ()

    if (BACKWARD_LIBRARIES)
        message(STATUS "Backward-cpp libraries: ${BACKWARD_LIBRARIES}")
    endif ()

    # Doctest for testing
    if (SYSTEM_DOCTEST MATCHES "OFF")
        add_subdirectory(contrib/doctest)
        include_directories("${CMAKE_SOURCE_DIR}/contrib/doctest")
    else ()
        find_package(doctest)
    endif ()

    # Lua-specific dependencies
    if (NOT WITH_LUAJIT)
        add_subdirectory(contrib/lua-bit)
    endif ()

    # Lua REPL support
    add_subdirectory(contrib/replxx)
    set(WITH_LUA_REPL 1 PARENT_SCOPE)
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-replxx)

    # Update the required libraries list based on dependencies
    if (ENABLE_SNOWBALL)
        list(APPEND RSPAMD_REQUIRED_LIBRARIES stemmer)
    endif ()

    # Add core required libraries
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-hiredis)
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-actrie)
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-t1ha)
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-ev)
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-kann)
    list(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-ced)

    # Clang plugin (optional)
    if (ENABLE_CLANG_PLUGIN)
        add_subdirectory(clang-plugin)
    endif ()

    # Main source code
    add_subdirectory(src)

    # Utilities
    add_subdirectory(utils)

    # Propagate variables to parent scope
    set(RSPAMD_REQUIRED_LIBRARIES ${RSPAMD_REQUIRED_LIBRARIES} PARENT_SCOPE)
    set(WITH_SNOWBALL ${WITH_SNOWBALL} PARENT_SCOPE)
    set(WITH_LUA_REPL ${WITH_LUA_REPL} PARENT_SCOPE)
endfunction()

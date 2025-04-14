# Function to generate module registrations
function(generate_modules_list MODULE_LIST)
    # Generate unique string for this build
    set(MODULES_C "${CMAKE_CURRENT_BINARY_DIR}/modules.c")
    file(WRITE "${MODULES_C}"
            "#include \"rspamd.h\"\n")

    # Process each module
    foreach (MOD IN LISTS ${MODULE_LIST})
        file(APPEND "${MODULES_C}" "extern module_t ${MOD}_module;\n")
    endforeach ()

    file(APPEND "${MODULES_C}" "\n\nmodule_t *modules[] = {\n")

    foreach (MOD IN LISTS ${MODULE_LIST})
        file(APPEND "${MODULES_C}" "&${MOD}_module,\n")
    endforeach ()

    file(APPEND "${MODULES_C}" "NULL\n};\n")

    # Return the generated file path
    set(MODULES_C_PATH "${MODULES_C}" PARENT_SCOPE)
endfunction()

# Function to generate worker registrations
function(generate_workers_list WORKER_LIST)
    set(WORKERS_C "${CMAKE_CURRENT_BINARY_DIR}/workers.c")
    file(WRITE "${WORKERS_C}"
            "#include \"rspamd.h\"\n")

    # Process each worker
    foreach (WRK IN LISTS ${WORKER_LIST})
        file(APPEND "${WORKERS_C}" "extern worker_t ${WRK}_worker;\n")
    endforeach ()

    file(APPEND "${WORKERS_C}" "\n\nworker_t *workers[] = {\n")

    foreach (WRK IN LISTS ${WORKER_LIST})
        file(APPEND "${WORKERS_C}" "&${WRK}_worker,\n")
    endforeach ()

    file(APPEND "${WORKERS_C}" "NULL\n};\n")

    # Return the generated file path
    set(WORKERS_C_PATH "${WORKERS_C}" PARENT_SCOPE)
endfunction()

# Function to generate both modules and workers
function(generate_registration_code MODULE_LIST WORKER_LIST)
    generate_modules_list(${MODULE_LIST})
    generate_workers_list(${WORKER_LIST})

    # Set parent scope variables
    set(MODULES_C_PATH ${MODULES_C_PATH} PARENT_SCOPE)
    set(WORKERS_C_PATH ${WORKERS_C_PATH} PARENT_SCOPE)
endfunction()

# Configure Clang Plugin if enabled
if (ENABLE_CLANG_PLUGIN)
    set(CLANG_PLUGIN_FLAGS "-Xclang -load -Xclang ${CMAKE_CURRENT_BINARY_DIR}/../clang-plugin/librspamd-clang${CMAKE_SHARED_LIBRARY_SUFFIX} -Xclang -add-plugin -Xclang rspamd-ast")

    # Apply to both C and C++ compiler flags
    add_compile_options(${CLANG_PLUGIN_FLAGS})

    # Add any extra clang plugins
    if (CLANG_EXTRA_PLUGINS_LIBS)
        foreach (lib ${CLANG_EXTRA_PLUGINS_LIBS})
            add_compile_options("-Xclang" "-load" "-Xclang" "${lib}")
        endforeach ()
    endif ()

    if (CLANG_EXTRA_PLUGINS)
        foreach (plug ${CLANG_EXTRA_PLUGINS})
            add_compile_options("-Xclang" "-add-plugin" "-Xclang" "${plug}")
        endforeach ()
    endif ()
endif ()

# Add subdirectories for components
add_subdirectory(lua)
add_subdirectory(libcryptobox)
add_subdirectory(libutil)
add_subdirectory(libserver)
add_subdirectory(libmime)
add_subdirectory(libstat)
add_subdirectory(client)
add_subdirectory(rspamadm)

# Define source files
set(RSPAMD_SOURCES
        controller.c
        fuzzy_storage.c
        rspamd.c
        worker.c
        rspamd_proxy.c)

set(PLUGIN_SOURCES
        plugins/regexp.c
        plugins/chartable.cxx
        plugins/fuzzy_check.c
        plugins/dkim_check.c
        libserver/rspamd_control.c)

# Define module and worker lists
set(MODULES_LIST regexp chartable fuzzy_check dkim)
set(WORKERS_LIST normal controller fuzzy rspamd_proxy)

# Add hyperscan worker if enabled
if (ENABLE_HYPERSCAN)
    list(APPEND WORKERS_LIST hs_helper)
    list(APPEND RSPAMD_SOURCES hs_helper.c)
endif ()

# Generate modules and workers registration code
generate_registration_code(MODULES_LIST WORKERS_LIST)

# Count the number of modules
list(LENGTH PLUGIN_SOURCES RSPAMD_MODULES_NUM)

# Configure Ragel for parsers
set(RAGEL_DEPENDS
        "${CMAKE_SOURCE_DIR}/src/ragel/smtp_address.rl"
        "${CMAKE_SOURCE_DIR}/src/ragel/smtp_date.rl"
        "${CMAKE_SOURCE_DIR}/src/ragel/smtp_ip.rl"
        "${CMAKE_SOURCE_DIR}/src/ragel/smtp_base.rl"
        "${CMAKE_SOURCE_DIR}/src/ragel/content_disposition.rl")

# Generate parsers with Ragel
ragel_target(ragel_smtp_addr
        INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/smtp_addr_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -T1
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/smtp_addr_parser.rl.c)

ragel_target(ragel_content_disposition
        INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/content_disposition_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -G2
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/content_disposition.rl.c)

ragel_target(ragel_rfc2047
        INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/rfc2047_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -G2
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/rfc2047.rl.c)

ragel_target(ragel_smtp_date
        INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/smtp_date_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -G2
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/date_parser.rl.c)

ragel_target(ragel_smtp_ip
        INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/smtp_ip_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -G2
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ip_parser.rl.c)

# Mark generated files correctly
foreach (_gen ${LIBSERVER_GENERATED})
    set_source_files_properties(${_gen} PROPERTIES GENERATED TRUE)
endforeach ()

# Collection of all generated Ragel outputs
set(RAGEL_OUTPUTS
        ${RAGEL_ragel_smtp_addr_OUTPUTS}
        ${RAGEL_ragel_newlines_strip_OUTPUTS}
        ${RAGEL_ragel_content_type_OUTPUTS}
        ${RAGEL_ragel_content_disposition_OUTPUTS}
        ${RAGEL_ragel_rfc2047_OUTPUTS}
        ${RAGEL_ragel_smtp_date_OUTPUTS}
        ${RAGEL_ragel_smtp_ip_OUTPUTS})

# Common sources for rspamd-server
set(SERVER_COMMON_SOURCES
        ${RSPAMD_CRYPTOBOX}
        ${RSPAMD_UTIL}
        ${RSPAMD_LUA}
        ${RSPAMD_SERVER}
        ${RSPAMD_STAT}
        ${RSPAMD_MIME}
        ${MODULES_C_PATH}
        ${PLUGIN_SOURCES}
        ${RAGEL_OUTPUTS}
        ${BACKWARD_ENABLE})

# Build rspamd-server as static or shared library based on configuration
if (ENABLE_STATIC)
    add_library(rspamd-server STATIC ${SERVER_COMMON_SOURCES})
else ()
    add_library(rspamd-server SHARED ${SERVER_COMMON_SOURCES})
endif ()

# Set dependencies for rspamd-server
foreach (_dep ${LIBSERVER_DEPENDS})
    add_dependencies(rspamd-server "${_dep}")
endforeach ()

# Link dependencies
target_link_libraries(rspamd-server
        PRIVATE
        rspamd-http-parser
        rspamd-fpconv
        rspamd-cdb
        rspamd-lpeg
        ottery
        lcbtrie
        rspamd-simdutf
        rdns
        ucl)

# Handle xxhash dependency
if (SYSTEM_XXHASH)
    target_link_libraries(rspamd-server PUBLIC xxhash)
else ()
    target_link_libraries(rspamd-server PUBLIC rspamd-xxhash)
endif ()

# Handle zstd dependency
if (SYSTEM_ZSTD)
    target_link_libraries(rspamd-server PUBLIC zstd)
else ()
    target_link_libraries(rspamd-server PRIVATE rspamd-zstd)
endif ()

# Handle clang plugin dependency
if (ENABLE_CLANG_PLUGIN)
    add_dependencies(rspamd-server rspamd-clang)
endif ()

# Handle Lua JIT/Lua dependency
if (NOT WITH_LUAJIT)
    target_link_libraries(rspamd-server PRIVATE rspamd-bit)
endif ()

# Link additional optional dependencies
if (ENABLE_SNOWBALL)
    target_link_libraries(rspamd-server PRIVATE stemmer)
endif ()

target_link_libraries(rspamd-server PRIVATE rspamd-hiredis)

if (ENABLE_FANN)
    target_link_libraries(rspamd-server PRIVATE fann)
endif ()

if (ENABLE_HYPERSCAN)
    target_link_libraries(rspamd-server PUBLIC hs)
endif ()

if (WITH_BLAS)
    target_link_libraries(rspamd-server PRIVATE ${BLAS_REQUIRED_LIBRARIES})
endif ()

# Link all required system libraries
target_link_libraries(rspamd-server PUBLIC ${RSPAMD_REQUIRED_LIBRARIES})

# Add Backward support for stacktrace
add_backward(rspamd-server)

# Build main rspamd executable
add_executable(rspamd
        ${RSPAMD_SOURCES}
        ${WORKERS_C_PATH}
        ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# Configure rspamd executable
add_backward(rspamd)
set_target_properties(rspamd PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(rspamd-server PROPERTIES LINKER_LANGUAGE CXX)

if (NOT NO_TARGET_VERSIONS)
    set_target_properties(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})
endif ()

# Link rspamd executable with the server library
target_link_libraries(rspamd PRIVATE rspamd-server)

# Install targets
install(TARGETS rspamd
        RUNTIME
        DESTINATION bin)

install(TARGETS rspamd-server
        LIBRARY
        DESTINATION ${RSPAMD_LIBDIR})

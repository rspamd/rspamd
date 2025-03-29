
# Define C test sources
set(RSPAMD_TEST_SOURCES
        rspamd_mem_pool_test.c
        rspamd_statfile_test.c
        rspamd_url_test.c
        rspamd_dns_test.c
        rspamd_dkim_test.c
        rspamd_rrd_test.c
        rspamd_radix_test.c
        rspamd_shingles_test.c
        rspamd_upstream_test.c
        rspamd_lua_pcall_vs_resume_test.c
        rspamd_lua_test.c
        rspamd_cryptobox_test.c
        rspamd_heap_test.c
        rspamd_test_suite.c
)

# Main C test executable
add_executable(rspamd-test ${RSPAMD_TEST_SOURCES})
target_compile_definitions(rspamd-test PRIVATE RSPAMD_TEST)
target_link_libraries(rspamd-test PRIVATE rspamd-server)
set_target_properties(rspamd-test PROPERTIES
        LINKER_LANGUAGE CXX
)

# Add the test
add_test(
        NAME rspamd-test
        COMMAND rspamd-test -p /rspamd/lua
)

# C++ unit tests
set(CXX_TEST_SOURCES rspamd_cxx_unit.cxx)

# C++ test executable
add_executable(rspamd-test-cxx ${CXX_TEST_SOURCES})
target_link_libraries(rspamd-test-cxx PRIVATE rspamd-server)
set_target_properties(rspamd-test-cxx PROPERTIES
        LINKER_LANGUAGE CXX
)

# Add the C++ test
add_test(
        NAME rspamd-test-cxx
        COMMAND rspamd-test-cxx
)

# Copy test Lua scripts for out-of-source builds
if (NOT "${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_BINARY_DIR}")
    # Find Lua test files
    file(GLOB_RECURSE LUA_TESTS CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/lua/*.*")

    # Create target to ensure unit directory exists
    add_custom_target(units-dir
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/lua/unit"
    )

    # Make the main test depend on the directory creation
    add_dependencies(rspamd-test units-dir)

    # Create file-specific targets for each Lua test file
    foreach (lua_file IN LISTS LUA_TESTS)
        # Extract just the filename
        get_filename_component(file_name "${lua_file}" NAME)

        # Determine destination path
        if ("${lua_file}" MATCHES "^.*/unit/.*$")
            set(dest_file "${CMAKE_CURRENT_BINARY_DIR}/lua/unit/${file_name}")
        else ()
            set(dest_file "${CMAKE_CURRENT_BINARY_DIR}/lua/${file_name}")
        endif ()

        # Create custom target to copy the file
        add_custom_target("${file_name}"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${lua_file}" "${dest_file}"
                SOURCES "${lua_file}"
                COMMENT "Copying ${file_name} to test directory"
        )

        # Make the main test depend on this file copy
        add_dependencies(rspamd-test "${file_name}")
    endforeach ()
endif ()

# Add test properties
set_tests_properties(rspamd-test PROPERTIES
        ENVIRONMENT "RSPAMD_INSTALLROOT=${CMAKE_INSTALL_PREFIX}"
)

# Custom target for running all tests directly (convenience target)
add_custom_target(run-tests
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        DEPENDS rspamd-test rspamd-test-cxx
        COMMENT "Running all Rspamd tests"
)

# Custom target for running C tests only
add_custom_target(run-c-tests
        COMMAND ${CMAKE_COMMAND} -E echo "Running C unit tests..."
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/rspamd-test -p /rspamd/lua
        DEPENDS rspamd-test
        COMMENT "Running Rspamd C tests"
)

# Custom target for running C++ tests only
add_custom_target(run-cxx-tests
        COMMAND ${CMAKE_COMMAND} -E echo "Running C++ unit tests..."
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/rspamd-test-cxx
        DEPENDS rspamd-test-cxx
        COMMENT "Running Rspamd C++ tests"
)
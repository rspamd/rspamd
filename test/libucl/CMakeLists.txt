# Upstream libucl regressions run against Rspamd's embedded library.
foreach (ucl_test empty_chunks limits schema_refs strnstr object_free dup_error_key lua cbor_vectors msgpack_malformed roundtrip size_overflow)
    add_executable(rspamd-ucl-${ucl_test} test_${ucl_test}.c ${CMAKE_SOURCE_DIR}/src/sanitizer_conf.c)
    target_include_directories(rspamd-ucl-${ucl_test} PRIVATE ${CMAKE_SOURCE_DIR}/contrib/libucl)
    target_link_libraries(rspamd-ucl-${ucl_test} PRIVATE rspamd-server)
    set_target_properties(rspamd-ucl-${ucl_test} PROPERTIES LINKER_LANGUAGE CXX)
    RspamdLinkJemalloc(rspamd-ucl-${ucl_test})
    add_test(NAME rspamd-ucl-${ucl_test} COMMAND rspamd-ucl-${ucl_test})
    set_tests_properties(rspamd-ucl-${ucl_test} PROPERTIES
        ENVIRONMENT "TEST_OUT_DIR=${CMAKE_CURRENT_BINARY_DIR}" LABELS "libucl")
endforeach ()

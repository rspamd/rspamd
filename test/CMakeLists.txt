SET(TESTSRC		rspamd_expression_test.c
				rspamd_memcached_test.c
				rspamd_mem_pool_test.c
				rspamd_statfile_test.c
				rspamd_fuzzy_test.c
				rspamd_test_suite.c
				rspamd_url_test.c
				rspamd_dns_test.c)

SET(TESTDEPENDS	../src/mem_pool.c
				../src/hash.c
				../src/url.c
				../src/trie.c
				../src/util.c
				../src/radix.c
				../src/fuzzy.c
				../src/map.c
				../src/logger.c
				../src/memcached.c
				../src/message.c
				../src/html.c
				../src/expressions.c
				../src/statfile.c
				../src/events.c
				../src/upstream.c
				../src/dns.c)

ADD_EXECUTABLE(rspamd-test EXCLUDE_FROM_ALL ${TESTDEPENDS} ${CONTRIBSRC} ${TESTSRC})
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES COMPILE_FLAGS "-DRSPAMD_TEST")
TARGET_LINK_LIBRARIES(rspamd-test event)
TARGET_LINK_LIBRARIES(rspamd-test ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd-test ${CMAKE_REQUIRED_LIBRARIES})
IF(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(rspamd-test ${GMIME2_LIBRARIES})
ELSE(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(rspamd-test ${GMIME24_LIBRARIES})
ENDIF(GMIME2_FOUND)
IF(ENABLE_STATIC MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-test ${PCRE_LIBRARIES})
ENDIF(ENABLE_STATIC MATCHES "ON")
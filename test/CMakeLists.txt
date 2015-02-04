SET(TESTSRC		rspamd_expression_test.c
				rspamd_mem_pool_test.c
				rspamd_statfile_test.c
				rspamd_fuzzy_test.c
				rspamd_url_test.c
				rspamd_dns_test.c
				rspamd_async_test.c
				rspamd_dkim_test.c
				rspamd_rrd_test.c
				rspamd_radix_test.c
				rspamd_shingles_test.c
				rspamd_upstream_test.c
				rspamd_http_test.c
				rspamd_test_suite.c)

ADD_EXECUTABLE(rspamd-test EXCLUDE_FROM_ALL ${TESTSRC})
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES COMPILE_FLAGS "-DRSPAMD_TEST")

TARGET_LINK_LIBRARIES(rspamd-test rspamd-mime)
TARGET_LINK_LIBRARIES(rspamd-test rspamd-server)
TARGET_LINK_LIBRARIES(rspamd-test rspamd-util)
TARGET_LINK_LIBRARIES(rspamd-test rspamd-lua)

TARGET_LINK_LIBRARIES(rspamd-test event)
IF(HAVE_LIBEVENT2)
	TARGET_LINK_LIBRARIES(rspamd-test event_pthreads)
ENDIF(HAVE_LIBEVENT2)
IF(WITH_DB)
	TARGET_LINK_LIBRARIES(rspamd-test db)
ENDIF(WITH_DB)

IF(OPENSSL_FOUND)
	TARGET_LINK_LIBRARIES(rspamd-test ${OPENSSL_LIBRARIES})
ENDIF(OPENSSL_FOUND)
IF(HAVE_FETCH_H)
	TARGET_LINK_LIBRARIES(rspamd-test fetch)
ENDIF(HAVE_FETCH_H)
TARGET_LINK_LIBRARIES(rspamd-test ${RSPAMD_REQUIRED_LIBRARIES})

IF(ENABLE_LUAJIT MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-test "${LUAJIT_LIBRARY}")
ELSE(ENABLE_LUAJIT MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-test "${LUA_LIBRARY}")
ENDIF(ENABLE_LUAJIT MATCHES "ON")

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-test profiler)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")
TARGET_LINK_LIBRARIES(rspamd-test hiredis)
IF(GLIB_COMPAT)
	TARGET_LINK_LIBRARIES(rspamd-test glibadditions)
ENDIF(GLIB_COMPAT)
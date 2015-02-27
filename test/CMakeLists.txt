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
				rspamd_lua_test.c
				rspamd_test_suite.c)

ADD_EXECUTABLE(rspamd-test EXCLUDE_FROM_ALL ${TESTSRC})
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES COMPILE_FLAGS "-DRSPAMD_TEST")

TARGET_LINK_LIBRARIES(rspamd-test rspamd-server)
TARGET_LINK_LIBRARIES(rspamd-test ${RSPAMD_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd-test stemmer)

IF(NOT "${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_BINARY_DIR}")
	FILE(COPY "${CMAKE_CURRENT_SOURCE_DIR}/lua"
			  DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

	# Also add dependencies for convenience
	FILE(GLOB LUA_TESTS "${CMAKE_CURRENT_SOURCE_DIR}/lua/*")
	FOREACH(_LF IN LISTS LUA_TESTS)
		GET_FILENAME_COMPONENT(_NM "${_LF}" NAME)
		SET(_DS "${CMAKE_CURRENT_BINARY_DIR}/lua/${_NM}")
		MESSAGE(STATUS "${_LF} -> ${_DS}")
		ADD_CUSTOM_TARGET("${_NM}" COMMAND
			${CMAKE_COMMAND} -E copy_if_different ${_LF} ${_DS}
			SOURCES "${_LF}"
		)
		ADD_DEPENDENCIES(rspamd-test "${_NM}")
	ENDFOREACH()
	
ENDIF()
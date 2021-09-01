SET(TESTSRC		rspamd_mem_pool_test.c
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
				rspamd_test_suite.c)

ADD_EXECUTABLE(rspamd-test EXCLUDE_FROM_ALL ${TESTSRC})
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES COMPILE_FLAGS "-DRSPAMD_TEST")
ADD_DEPENDENCIES(rspamd-test rspamd-server)
SET_TARGET_PROPERTIES(rspamd-test PROPERTIES LINKER_LANGUAGE CXX)
TARGET_LINK_LIBRARIES(rspamd-test rspamd-server)

SET(CXXTESTSSRC		rspamd_cxx_unit.cxx)

ADD_EXECUTABLE(rspamd-test-cxx EXCLUDE_FROM_ALL ${CXXTESTSSRC})
SET_TARGET_PROPERTIES(rspamd-test-cxx PROPERTIES LINKER_LANGUAGE CXX)
ADD_DEPENDENCIES(rspamd-test-cxx rspamd-server)
TARGET_LINK_LIBRARIES(rspamd-test-cxx PRIVATE rspamd-server)
SET_TARGET_PROPERTIES(rspamd-test-cxx PROPERTIES LINKER_LANGUAGE CXX)

IF(NOT "${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_BINARY_DIR}")
	# Also add dependencies for convenience
	FILE(GLOB_RECURSE LUA_TESTS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/lua/*.*")
	ADD_CUSTOM_TARGET(units-dir COMMAND
		${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/lua/unit"
	)
	ADD_DEPENDENCIES(rspamd-test units-dir)
	FOREACH(_LF IN LISTS LUA_TESTS)
		GET_FILENAME_COMPONENT(_NM "${_LF}" NAME)
		IF("${_LF}" MATCHES "^.*/unit/.*$")
			SET(_DS "${CMAKE_CURRENT_BINARY_DIR}/lua/unit/${_NM}")
		ELSE()
			SET(_DS "${CMAKE_CURRENT_BINARY_DIR}/lua/${_NM}")
		ENDIF()
		ADD_CUSTOM_TARGET("${_NM}" COMMAND
			${CMAKE_COMMAND} -E copy_if_different ${_LF} ${_DS}
			SOURCES "${_LF}"
		)
		ADD_DEPENDENCIES(rspamd-test "${_NM}")
	ENDFOREACH()
ENDIF()
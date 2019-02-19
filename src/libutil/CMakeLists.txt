# Librspamd-util
SET(LIBRSPAMDUTILSRC
				${CMAKE_CURRENT_SOURCE_DIR}/addr.c
				${CMAKE_CURRENT_SOURCE_DIR}/aio_event.c
				${CMAKE_CURRENT_SOURCE_DIR}/bloom.c
				${CMAKE_CURRENT_SOURCE_DIR}/expression.c
				${CMAKE_CURRENT_SOURCE_DIR}/fstring.c
				${CMAKE_CURRENT_SOURCE_DIR}/hash.c
				${CMAKE_CURRENT_SOURCE_DIR}/http_util.c
				${CMAKE_CURRENT_SOURCE_DIR}/http_message.c
				${CMAKE_CURRENT_SOURCE_DIR}/http_connection.c
				${CMAKE_CURRENT_SOURCE_DIR}/http_router.c
				${CMAKE_CURRENT_SOURCE_DIR}/http_context.c
				${CMAKE_CURRENT_SOURCE_DIR}/logger.c
				${CMAKE_CURRENT_SOURCE_DIR}/map.c
				${CMAKE_CURRENT_SOURCE_DIR}/map_helpers.c
				${CMAKE_CURRENT_SOURCE_DIR}/mem_pool.c
				${CMAKE_CURRENT_SOURCE_DIR}/printf.c
				${CMAKE_CURRENT_SOURCE_DIR}/radix.c
				${CMAKE_CURRENT_SOURCE_DIR}/regexp.c
				${CMAKE_CURRENT_SOURCE_DIR}/rrd.c
				${CMAKE_CURRENT_SOURCE_DIR}/shingles.c
				${CMAKE_CURRENT_SOURCE_DIR}/sqlite_utils.c
				${CMAKE_CURRENT_SOURCE_DIR}/str_util.c
				${CMAKE_CURRENT_SOURCE_DIR}/upstream.c
				${CMAKE_CURRENT_SOURCE_DIR}/util.c
				${CMAKE_CURRENT_SOURCE_DIR}/heap.c
				${CMAKE_CURRENT_SOURCE_DIR}/multipattern.c
				${CMAKE_CURRENT_SOURCE_DIR}/ssl_util.c)
# Rspamdutil
SET(RSPAMD_UTIL ${LIBRSPAMDUTILSRC} PARENT_SCOPE)
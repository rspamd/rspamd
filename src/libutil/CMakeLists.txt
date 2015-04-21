# Librspamd-util
SET(LIBRSPAMDUTILSRC			
								${CMAKE_CURRENT_SOURCE_DIR}/addr.c
								${CMAKE_CURRENT_SOURCE_DIR}/aio_event.c
								${CMAKE_CURRENT_SOURCE_DIR}/bloom.c
								${CMAKE_CURRENT_SOURCE_DIR}/diff.c
								${CMAKE_CURRENT_SOURCE_DIR}/expression.c
								${CMAKE_CURRENT_SOURCE_DIR}/fstring.c
								${CMAKE_CURRENT_SOURCE_DIR}/fuzzy.c
								${CMAKE_CURRENT_SOURCE_DIR}/hash.c
								${CMAKE_CURRENT_SOURCE_DIR}/http.c
								${CMAKE_CURRENT_SOURCE_DIR}/keypairs_cache.c
								${CMAKE_CURRENT_SOURCE_DIR}/logger.c
								${CMAKE_CURRENT_SOURCE_DIR}/map.c
								${CMAKE_CURRENT_SOURCE_DIR}/mem_pool.c
								${CMAKE_CURRENT_SOURCE_DIR}/printf.c
								${CMAKE_CURRENT_SOURCE_DIR}/radix.c
								${CMAKE_CURRENT_SOURCE_DIR}/regexp.c
								${CMAKE_CURRENT_SOURCE_DIR}/rrd.c
								${CMAKE_CURRENT_SOURCE_DIR}/shingles.c
								${CMAKE_CURRENT_SOURCE_DIR}/upstream.c
								${CMAKE_CURRENT_SOURCE_DIR}/util.c)
# Rspamdutil
SET(RSPAMD_UTIL ${LIBRSPAMDUTILSRC} PARENT_SCOPE)
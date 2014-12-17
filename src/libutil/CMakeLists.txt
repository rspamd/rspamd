# Librspamd-util
SET(LIBRSPAMDUTILSRC			
								addr.c
								aio_event.c
								bloom.c
								diff.c
								fstring.c
								fuzzy.c
								hash.c
								http.c
								logger.c
								map.c
								mem_pool.c
								printf.c
								radix.c
								rrd.c
								shingles.c
								trie.c
								upstream.c
								util.c)
# Rspamdutil
ADD_LIBRARY(rspamd-util ${LINK_TYPE} ${LIBRSPAMDUTILSRC})
IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamd-util PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(rspamd-util ${RSPAMD_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd-util pcre)
TARGET_LINK_LIBRARIES(rspamd-util ucl)
TARGET_LINK_LIBRARIES(rspamd-util ottery)
TARGET_LINK_LIBRARIES(rspamd-util rspamd-http-parser)
TARGET_LINK_LIBRARIES(rspamd-util event)
TARGET_LINK_LIBRARIES(rspamd-util xxhash)
TARGET_LINK_LIBRARIES(rspamd-util siphash)
TARGET_LINK_LIBRARIES(rspamd-util rdns)
IF(OPENSSL_FOUND)
	TARGET_LINK_LIBRARIES(rspamd-util ${OPENSSL_LIBRARIES})
ENDIF(OPENSSL_FOUND)

IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-util PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
	TARGET_LINK_LIBRARIES(rspamd-util glibadditions)
ENDIF(GLIB_COMPAT)

IF(NO_SHARED MATCHES "OFF")
	INSTALL(TARGETS rspamd-util 
    	LIBRARY DESTINATION ${LIBDIR} 
    	PUBLIC_HEADER DESTINATION include)
ENDIF(NO_SHARED MATCHES "OFF")
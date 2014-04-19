# Librspamd-util
SET(LIBRSPAMDUTILSRC			aio_event.c
								bloom.c
								diff.c
								fstring.c
								fuzzy.c
								hash.c
								http.c
								logger.c
								map.c
								memcached.c
								mem_pool.c
								printf.c
								radix.c
								rrd.c
								trie.c
								upstream.c
								util.c)

# Librspamdserver
SET(LIBRSPAMDSERVERSRC
				binlog.c
				buffer.c
				cfg_utils.c
				cfg_rcl.c
				dkim.c
				dns.c
				dynamic_cfg.c
				events.c
				html.c
				proxy.c
				roll_history.c
				settings.c
				spf.c
				statfile.c
				statfile_sync.c
				symbols_cache.c
				url.c
				view.c)
				
# Librspamd mime
SET(LIBRSPAMDMIMESRC
				expressions.c
				filter.c
				images.c
				message.c
				protocol.c
				smtp_utils.c
				smtp_proto.c
				worker_util.c)
				
SET(TOKENIZERSSRC  tokenizers/tokenizers.c
				tokenizers/osb.c)

SET(CLASSIFIERSSRC classifiers/classifiers.c
                classifiers/bayes.c
				classifiers/winnow.c)
# Add targets

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
    
# Librspamd-server

#IF(WITH_DB)
#	LIST(APPEND LIBRSPAMDSERVERSRC kvstorage_bdb.c)
#ENDIF(WITH_DB)
#IF(WITH_SQLITE)
#	LIST(APPEND LIBRSPAMDSERVERSRC kvstorage_sqlite.c)
#ENDIF(WITH_SQLITE)
				
ADD_LIBRARY(rspamd-server ${LINK_TYPE} ${LIBRSPAMDSERVERSRC} ${TOKENIZERSSRC} ${CLASSIFIERSSRC})
IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES LINKER_LANGUAGE C COMPILE_FLAGS "-DRSPAMD_LIB")
TARGET_LINK_LIBRARIES(rspamd-server rspamd-lua)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-json)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-cdb)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-util)
TARGET_LINK_LIBRARIES(rspamd-server rdns)   
IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB -fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

IF(WITH_DB)
	TARGET_LINK_LIBRARIES(rspamd-server db)
ENDIF(WITH_DB)

IF(OPENSSL_FOUND)
	TARGET_LINK_LIBRARIES(rspamd-server ${OPENSSL_LIBRARIES})
ENDIF(OPENSSL_FOUND)

IF(NO_SHARED MATCHES "OFF")
	INSTALL(TARGETS rspamd-server 
    	LIBRARY DESTINATION ${LIBDIR} 
    	PUBLIC_HEADER DESTINATION ${INCLUDEDIR})
ENDIF(NO_SHARED MATCHES "OFF")
    
# Librspamdmime
ADD_LIBRARY(rspamd-mime ${LINK_TYPE} ${LIBRSPAMDMIMESRC})
IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-mime PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-mime PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd-mime PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
TARGET_LINK_LIBRARIES(rspamd-mime rspamd-server)
TARGET_LINK_LIBRARIES(rspamd-mime rspamd-util)      
IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamd-mime PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB -fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

IF(NO_SHARED MATCHES "OFF")
	INSTALL(TARGETS rspamd-mime 
   	 	LIBRARY DESTINATION ${LIBDIR}  
    	PUBLIC_HEADER DESTINATION ${INCLUDEDIR})
ENDIF(NO_SHARED MATCHES "OFF")

INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/src")
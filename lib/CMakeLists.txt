# Librspamdclient
SET(LIBRSPAMDCLIENTSRC			  client/librspamdclient.c )

# Librspamd-util
SET(LIBRSPAMDUTILSRC		  	../src/aio_event.c
								../src/bloom.c
								../src/diff.c
								../src/fstring.c
								../src/fuzzy.c
								../src/hash.c
								../src/logger.c
								../src/map.c
								../src/memcached.c
								../src/mem_pool.c
								../src/printf.c
								../src/radix.c
								../src/trie.c
								../src/upstream.c
								../src/util.c)

# kvstorageclient

SET(LIBRKVSTORAGESRC			  kvstorage/libkvstorageclient.c)

# Librspamdserver
SET(LIBRSPAMDSERVERSRC
				../src/binlog.c
				../src/buffer.c
				../src/cfg_utils.c
				../src/cfg_xml.c
				../src/dkim.c
				../src/dns.c
				../src/events.c
				../src/html.c
				../src/kvstorage.c
				../src/kvstorage_config.c
				../src/kvstorage_file.c
				../src/lmtp_proto.c
				../src/proxy.c
				../src/settings.c
				../src/spf.c
				../src/statfile.c
				../src/statfile_sync.c
				../src/symbols_cache.c
				../src/url.c
				../src/view.c)
				
# Librspamd mime
SET(LIBRSPAMDMIMESRC
				../src/expressions.c
				../src/filter.c
				../src/images.c
				../src/message.c
				../src/protocol.c
				../src/smtp_utils.c
				../src/smtp_proto.c
				../src/worker_util.c)
# Add targets

# Rspamdutil
ADD_LIBRARY(rspamd-util ${LINK_TYPE} ${LIBRSPAMDUTILSRC})
IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamd-util PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(rspamd-util ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd-util pcre)
TARGET_LINK_LIBRARIES(rspamd-util ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd-util event)

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

# Rspamd client
ADD_LIBRARY(rspamdclient SHARED ${LIBRSPAMDCLIENTSRC})
ADD_LIBRARY(rspamdclient_static STATIC ${LIBRSPAMDCLIENTSRC})
IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES PUBLIC_HEADER "client/librspamdclient.h")
ENDIF(NOT DEBIAN_BUILD)

IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(rspamdclient rspamd-util)

TARGET_LINK_LIBRARIES(rspamdclient_static ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamdclient_static ${GLIB2_LIBRARIES})


IF(NOT DEBIAN_BUILD)
	SET_TARGET_PROPERTIES(rspamdclient PROPERTIES VERSION ${RSPAMD_VERSION})
	SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES VERSION ${RSPAMD_VERSION})
ELSE(NOT DEBIAN_BUILD)
	SET_TARGET_PROPERTIES(rspamdclient PROPERTIES SOVERSION ${RSPAMD_VERSION})
	SET_TARGET_PROPERTIES(rspamdclient PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
	TARGET_LINK_LIBRARIES(rspamdclient glibadditions)
ENDIF(GLIB_COMPAT)

IF(NOT DEBIAN_BUILD)
	INSTALL(TARGETS rspamdclient rspamdclient_static LIBRARY PUBLIC_HEADER 
   	 	LIBRARY DESTINATION ${LIBDIR} 
    	PUBLIC_HEADER DESTINATION ${INCLUDEDIR}
   		ARCHIVE DESTINATION ${LIBDIR})
ELSE(NOT DEBIAN_BUILD)
	INSTALL(TARGETS rspamdclient 
    	LIBRARY DESTINATION ${LIBDIR}
    	NAMELINK_SKIP)
ENDIF(NOT DEBIAN_BUILD)    

    
# Librspamd-server

IF(WITH_DB)
	LIST(APPEND LIBRSPAMDSERVERSRC ../src/kvstorage_bdb.c)
ENDIF(WITH_DB)
IF(WITH_SQLITE)
	LIST(APPEND LIBRSPAMDSERVERSRC ../src/kvstorage_sqlite.c)
ENDIF(WITH_SQLITE)
				
ADD_LIBRARY(rspamd-server ${LINK_TYPE} ${LIBRSPAMDSERVERSRC})
IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES LINKER_LANGUAGE C COMPILE_FLAGS "-DRSPAMD_LIB")
TARGET_LINK_LIBRARIES(rspamd-server rspamd-lua)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-json)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-cdb)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-util)      
IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB -fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

IF(WITH_DB)
	TARGET_LINK_LIBRARIES(rspamd-server db)
ENDIF(WITH_DB)
IF(SQLITE_LIBRARIES)
	TARGET_LINK_LIBRARIES(rspamd-server ${SQLITE_LIBRARIES})
ENDIF(SQLITE_LIBRARIES)

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

IF(GMIME24)
	TARGET_LINK_LIBRARIES(rspamd-mime ${GMIME24_LIBRARIES})
ELSE(GMIME24)
	TARGET_LINK_LIBRARIES(rspamd-mime ${GMIME2_LIBRARIES})
ENDIF(GMIME24)

IF(NO_SHARED MATCHES "OFF")
	INSTALL(TARGETS rspamd-mime 
   	 	LIBRARY DESTINATION ${LIBDIR}  
    	PUBLIC_HEADER DESTINATION ${INCLUDEDIR})
ENDIF(NO_SHARED MATCHES "OFF")

# Libkvstorageclient

ADD_LIBRARY(kvstorageclient SHARED ${LIBRKVSTORAGESRC})
ADD_LIBRARY(kvstorageclient_static STATIC ${LIBRKVSTORAGESRC})
IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(kvstorageclient PROPERTIES PUBLIC_HEADER "kvstorage/libkvstorageclient.h")
ENDIF(NOT DEBIAN_BUILD)

IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(kvstorageclient PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
SET_TARGET_PROPERTIES(kvstorageclient_static PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(kvstorageclient rspamd-util)

TARGET_LINK_LIBRARIES(kvstorageclient_static ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(kvstorageclient_static ${GLIB2_LIBRARIES})

IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(kvstorageclient PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(kvstorageclient_static PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
	TARGET_LINK_LIBRARIES(kvstorageclient glibadditions)
ENDIF(GLIB_COMPAT)
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/src")
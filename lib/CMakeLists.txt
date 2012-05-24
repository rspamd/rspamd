# Librspamdclient
SET(LIBRSPAMDSRC			  client/librspamdclient.c 
							  ../src/mem_pool.c 
							  ../src/upstream.c 
							  ../src/printf.c)

ADD_LIBRARY(rspamdclient SHARED ${LIBRSPAMDSRC})
ADD_LIBRARY(rspamdclient_static STATIC ${LIBRSPAMDSRC})
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES PUBLIC_HEADER "client/librspamdclient.h")

IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(rspamdclient ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamdclient pcre)
TARGET_LINK_LIBRARIES(rspamdclient ${GLIB2_LIBRARIES})

TARGET_LINK_LIBRARIES(rspamdclient_static ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamdclient_static ${GLIB2_LIBRARIES})

SET_TARGET_PROPERTIES(rspamdclient PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES VERSION ${RSPAMD_VERSION})

IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
	TARGET_LINK_LIBRARIES(rspamdclient glibadditions)
ENDIF(GLIB_COMPAT)

INSTALL(TARGETS rspamdclient rspamdclient_static LIBRARY PUBLIC_HEADER 
    LIBRARY DESTINATION lib 
    PUBLIC_HEADER DESTINATION include
    ARCHIVE DESTINATION lib)

    
# Librspamdserver
SET(RSPAMDLIBSRC
				../src/aio_event.c 
				../src/binlog.c
                ../src/bloom.c
				../src/buffer.c
				../src/cfg_utils.c
				../src/cfg_xml.c
				../src/diff.c
				../src/dkim.c
				../src/dns.c
				../src/events.c
				../src/expressions.c
				../src/filter.c
				../src/fstring.c
				../src/fuzzy.c
				../src/hash.c
				../src/html.c
				../src/images.c
				../src/kvstorage.c
				../src/kvstorage_config.c
				../src/kvstorage_file.c
				../src/lmtp_proto.c
				../src/logger.c
				../src/map.c
				../src/memcached.c
				../src/mem_pool.c
				../src/message.c
				../src/printf.c
				../src/protocol.c
				../src/proxy.c
				../src/radix.c
				../src/settings.c
				../src/spf.c
				../src/smtp_proto.c
				../src/smtp_utils.c
				../src/statfile.c
				../src/statfile_sync.c
				../src/symbols_cache.c
				../src/trie.c
				../src/upstream.c
				../src/url.c
				../src/util.c
				../src/view.c)

IF(WITH_DB)
	LIST(APPEND RSPAMDLIBSRC ../src/kvstorage_bdb.c)
ENDIF(WITH_DB)
IF(WITH_SQLITE)
	LIST(APPEND RSPAMDLIBSRC ../src/kvstorage_sqlite.c)
ENDIF(WITH_SQLITE)
				
ADD_LIBRARY(rspamdserver STATIC ${RSPAMDLIBSRC})
SET_TARGET_PROPERTIES(rspamdserver PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamdserver PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
TARGET_LINK_LIBRARIES(rspamdserver rspamd_lua)
TARGET_LINK_LIBRARIES(rspamdserver rspamd_json)
TARGET_LINK_LIBRARIES(rspamdserver rspamd_cdb)   


# Libkvstorageclient
SET(LIBRKVSTORAGESRC			  kvstorage/libkvstorageclient.c 
								  ../src/mem_pool.c 
								  ../src/upstream.c 
								  ../src/printf.c 
								  ../src/util.c)

ADD_LIBRARY(kvstorageclient SHARED ${LIBRKVSTORAGESRC})
ADD_LIBRARY(kvstorageclient_static STATIC ${LIBRKVSTORAGESRC})
SET_TARGET_PROPERTIES(kvstorageclient PROPERTIES PUBLIC_HEADER "kvstorage/libkvstorageclient.h")

IF(CMAKE_COMPILER_IS_GNUCC)
SET_TARGET_PROPERTIES(kvstorageclient PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
SET_TARGET_PROPERTIES(kvstorageclient_static PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

TARGET_LINK_LIBRARIES(kvstorageclient ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(kvstorageclient pcre)
TARGET_LINK_LIBRARIES(kvstorageclient ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(kvstorageclient event)

TARGET_LINK_LIBRARIES(kvstorageclient_static ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(kvstorageclient_static ${GLIB2_LIBRARIES})

SET_TARGET_PROPERTIES(kvstorageclient PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(kvstorageclient_static PROPERTIES VERSION ${RSPAMD_VERSION})

IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
	TARGET_LINK_LIBRARIES(kvstorageclient glibadditions)
ENDIF(GLIB_COMPAT)
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/src")

INSTALL(TARGETS rspamdclient rspamdclient_static LIBRARY PUBLIC_HEADER 
    LIBRARY DESTINATION lib 
    PUBLIC_HEADER DESTINATION include
    ARCHIVE DESTINATION lib)

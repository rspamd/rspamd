# Librspamdclient
SET(LIBRSPAMDSRC			  librspamdclient.c ../src/mem_pool.c ../src/upstream.c ../src/printf.c)

ADD_LIBRARY(rspamdclient SHARED ${LIBRSPAMDSRC})
ADD_LIBRARY(rspamdclient_static STATIC ${LIBRSPAMDSRC})
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing -I../src/")
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES PUBLIC_HEADER "librspamdclient.h")
SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing -I../src/")

TARGET_LINK_LIBRARIES(rspamdclient ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamdclient ${GLIB2_LIBRARIES})

TARGET_LINK_LIBRARIES(rspamdclient_static ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamdclient_static ${GLIB2_LIBRARIES})

SET_TARGET_PROPERTIES(rspamdclient PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES VERSION ${RSPAMD_VERSION})

INSTALL(TARGETS rspamdclient rspamdclient_static LIBRARY PUBLIC_HEADER 
    LIBRARY DESTINATION lib 
    PUBLIC_HEADER DESTINATION include
    ARCHIVE DESTINATION lib)

    
# Librspamdserver
SET(RSPAMDLIBSRC ../src/binlog.c
                ../src/bloom.c
				../src/buffer.c
				../src/cfg_utils.c
				../src/cfg_xml.c
				../src/dns.c
				../src/events.c
				../src/expressions.c
				../src/filter.c
				../src/fstring.c
				../src/fuzzy.c
				../src/hash.c
				../src/html.c
				../src/images.c
				../src/lmtp_proto.c
				../src/logger.c
				../src/map.c
				../src/memcached.c
				../src/mem_pool.c
				../src/message.c
				../src/printf.c
				../src/protocol.c
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
				
ADD_LIBRARY(rspamdserver STATIC ${RSPAMDLIBSRC})
SET_TARGET_PROPERTIES(rspamdserver PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamdserver PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
TARGET_LINK_LIBRARIES(rspamdserver rspamd_lua)
TARGET_LINK_LIBRARIES(rspamdserver rspamd_json)
TARGET_LINK_LIBRARIES(rspamdserver rspamd_cdb)   
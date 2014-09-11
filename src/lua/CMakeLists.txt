# Lua support makefile
SET(LUASRC			  lua_common.c
					  lua_task.c
					  lua_config.c
					  lua_classifier.c
					  lua_cfg_file.c
					  lua_regexp.c
					  lua_cdb.c
					  lua_xmlrpc.c
					  lua_http.c
					  lua_redis.c
					  lua_upstream.c
					  lua_mempool.c
					  lua_session.c
					  lua_buffer.c
					  lua_dns.c
					  lua_rsa.c
					  lua_ip.c)

ADD_LIBRARY(rspamd-lua ${LINK_TYPE} ${LUASRC})
SET_TARGET_PROPERTIES(rspamd-lua PROPERTIES VERSION ${RSPAMD_VERSION})
TARGET_LINK_LIBRARIES(rspamd-lua rspamd-util)
TARGET_LINK_LIBRARIES(rspamd-lua hiredis)
IF(ENABLE_LUAJIT MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-lua "${LUAJIT_LIBRARY}")
ELSE(ENABLE_LUAJIT MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-lua "${LUA_LIBRARY}")
ENDIF(ENABLE_LUAJIT MATCHES "ON")
TARGET_LINK_LIBRARIES(rspamd-lua ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd-lua lua-ucl)
IF(GMIME24)
	TARGET_LINK_LIBRARIES(rspamd-lua ${GMIME24_LIBRARIES})
ELSE(GMIME24)
	TARGET_LINK_LIBRARIES(rspamd-lua ${GMIME2_LIBRARIES})
ENDIF(GMIME24)
TARGET_LINK_LIBRARIES(rspamd-lua rspamd-cdb)
SET_TARGET_PROPERTIES(rspamd-lua PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
IF(NO_SHARED MATCHES "OFF")
	INSTALL(TARGETS rspamd-lua 
    	LIBRARY DESTINATION ${LIBDIR} 
    	PUBLIC_HEADER DESTINATION ${INCLUDEDIR})
ENDIF(NO_SHARED MATCHES "OFF")
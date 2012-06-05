# Lua support makefile
SET(LUASRC			  lua_common.c
					  lua_task.c
					  lua_message.c
					  lua_config.c
					  lua_classifier.c
					  lua_cfg_file.c
					  lua_regexp.c
					  lua_cdb.c
					  lua_xmlrpc.c
					  lua_http.c
					  lua_redis.c
					  lua_upstream.c)

ADD_LIBRARY(rspamd-lua SHARED ${LUASRC})
TARGET_LINK_LIBRARIES(rspamd-lua ${LUALIB})
SET_TARGET_PROPERTIES(rspamd-lua PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
INSTALL(TARGETS rspamd-lua 
    LIBRARY DESTINATION ${LIBDIR} 
    PUBLIC_HEADER DESTINATION ${INCLUDEDIR}
    ARCHIVE DESTINATION ${LIBDIR})

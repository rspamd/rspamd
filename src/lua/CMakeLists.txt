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

ADD_LIBRARY(rspamd_lua STATIC ${LUASRC})
TARGET_LINK_LIBRARIES(rspamd_lua ${LUALIB})
TARGET_LINK_LIBRARIES(rspamd_lua hiredis)
SET_TARGET_PROPERTIES(rspamd_lua PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")

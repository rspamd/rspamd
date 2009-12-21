# Lua support makefile
SET(LUASRC			  lua_common.c
					  lua_task.c
					  lua_message.c
					  lua_config.c
					  lua_classifier.c)

ADD_LIBRARY(rspamd_lua STATIC ${LUASRC})
TARGET_LINK_LIBRARIES(rspamd_lua ${LUALIB})
SET_TARGET_PROPERTIES(rspamd_lua PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")

# Lua support makefile
SET(LUASRC			  lua_common.c
					  lua_task.c
					  lua_message.c
					  lua_config.c)

ADD_LIBRARY(rspamd_lua STATIC ${LUASRC})
TARGET_LINK_LIBRARIES(rspamd_lua ${LUALIB})

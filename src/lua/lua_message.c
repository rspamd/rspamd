/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "lua_common.h"
#include "message.h"

#define LUA_GMIME_BRIDGE_GET(class, name, mime_class)									\
static gint																				\
lua_##class##_##name(lua_State *L)														\
{																						\
	GMime##mime_class *obj = lua_check_##class(L);										\
	if (obj != NULL) {																	\
		lua_pushstring (L, g_mime_##class##_##name(obj));								\
	}																					\
	else {																				\
		lua_pushnil (L);																\
	}																					\
	return 1;																			\
}

#define LUA_GMIME_BRIDGE_SET(class, name, mime_class)									\
static gint																				\
lua_##class##_##name(lua_State *L)														\
{																						\
	const gchar *str;																	\
	GMime##mime_class *obj = lua_check_##class(L);										\
	if (obj != NULL) {																	\
		str = luaL_checkstring (L, 2);													\
		g_mime_##class##_##name(obj, str);												\
	}																					\
	else {																				\
		lua_pushnil (L);																\
	}																					\
	return 1;																			\
}

/*  Message methods */
LUA_FUNCTION_DEF (message, get_subject);
LUA_FUNCTION_DEF (message, set_subject);
LUA_FUNCTION_DEF (message, get_message_id);
LUA_FUNCTION_DEF (message, set_message_id);
LUA_FUNCTION_DEF (message, get_sender);
LUA_FUNCTION_DEF (message, set_sender);
LUA_FUNCTION_DEF (message, get_reply_to);
LUA_FUNCTION_DEF (message, set_reply_to);
LUA_FUNCTION_DEF (message, get_header);
LUA_FUNCTION_DEF (message, get_header_strong);
LUA_FUNCTION_DEF (message, set_header);
LUA_FUNCTION_DEF (message, get_date);

static const struct luaL_reg    msglib_m[] = {
	LUA_INTERFACE_DEF (message, get_subject),
	LUA_INTERFACE_DEF (message, set_subject),
	LUA_INTERFACE_DEF (message, get_message_id),
	LUA_INTERFACE_DEF (message, set_message_id),
	LUA_INTERFACE_DEF (message, get_sender),
	LUA_INTERFACE_DEF (message, set_sender),
	LUA_INTERFACE_DEF (message, get_reply_to),
	LUA_INTERFACE_DEF (message, set_reply_to),
	LUA_INTERFACE_DEF (message, get_header),
	LUA_INTERFACE_DEF (message, get_header_strong),
	LUA_INTERFACE_DEF (message, set_header),
	LUA_INTERFACE_DEF (message, get_date),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};



static GMimeMessage            *
lua_check_message (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{message}");
	luaL_argcheck (L, ud != NULL, 1, "'message' expected");
	return ud ? *((GMimeMessage **) ud) : NULL;
}


/*** Message interface	***/

LUA_GMIME_BRIDGE_GET (message, get_subject, Message)
LUA_GMIME_BRIDGE_SET (message, set_subject, Message)
LUA_GMIME_BRIDGE_GET (message, get_message_id, Message)
LUA_GMIME_BRIDGE_SET (message, set_message_id, Message)
LUA_GMIME_BRIDGE_GET (message, get_sender, Message)
LUA_GMIME_BRIDGE_SET (message, set_sender, Message)
LUA_GMIME_BRIDGE_GET (message, get_reply_to, Message)
LUA_GMIME_BRIDGE_SET (message, set_reply_to, Message)

static gint
lua_message_get_header_common (lua_State * L, gboolean strong)
{
	const gchar                     *headern;
	GMimeMessage                   *obj = lua_check_message (L);
	GList                          *res = NULL, *cur;
	gint                            i = 1;

	if (obj != NULL) {
		headern = luaL_checkstring (L, 2);
		if (headern) {
			res = message_get_header (NULL, obj, headern, strong);
			if (res) {
				cur = res;
				lua_newtable (L);
				while (cur) {
					lua_pushstring (L, (const gchar *)cur->data);
					lua_rawseti (L, -2, i++);
					g_free (cur->data);
					cur = g_list_next (cur);
				}
				g_list_free (res);
			}
			else {
				lua_pushnil (L);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_message_get_header (lua_State * L)
{
	return lua_message_get_header_common (L, FALSE);
}

static gint
lua_message_get_header_strong (lua_State * L)
{
	return lua_message_get_header_common (L, TRUE);
}

static gint
lua_message_set_header (lua_State * L)
{
	const gchar                     *headern, *headerv;
	GMimeMessage                   *obj = lua_check_message (L);

	if (obj != NULL) {
		headern = luaL_checkstring (L, 2);
		headerv = luaL_checkstring (L, 3);
		if (headern && headerv) {
			message_set_header (obj, headern, headerv);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_message_get_date (lua_State * L)
{
	GMimeMessage                   *obj = lua_check_message (L);
	time_t                          msg_time;
	int                             offset;

	if (obj != NULL) {
		g_mime_message_get_date (obj, &msg_time, &offset);
		lua_pushnumber (L, msg_time);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

gint
luaopen_message (lua_State * L)
{
	lua_newclass (L, "rspamd{message}", msglib_m);
	luaL_openlib (L, "rspamd_message", null_reg, 0);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}

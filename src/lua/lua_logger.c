/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"


/* Logger methods */
LUA_FUNCTION_DEF (logger, err);
LUA_FUNCTION_DEF (logger, warn);
LUA_FUNCTION_DEF (logger, info);
LUA_FUNCTION_DEF (logger, debug);

static const struct luaL_reg loggerlib_f[] = {
	LUA_INTERFACE_DEF (logger, err),
	LUA_INTERFACE_DEF (logger, warn),
	LUA_INTERFACE_DEF (logger, info),
	LUA_INTERFACE_DEF (logger, debug),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static void
lua_common_log (GLogLevelFlags level, lua_State *L, const gchar *msg)
{
	lua_Debug d;
	gchar func_buf[128], *p;

	if (lua_getstack (L, 1, &d) == 1) {
		(void)lua_getinfo (L, "Sl", &d);
		if ((p = strrchr (d.short_src, '/')) == NULL) {
			p = d.short_src;
		}
		else {
			p++;
		}
		rspamd_snprintf (func_buf, sizeof (func_buf), "%s:%d", p,
			d.currentline);
		if (level == G_LOG_LEVEL_DEBUG) {
			rspamd_conditional_debug (rspamd_main->logger,
				NULL,
				func_buf,
				"%s",
				msg);
		}
		else {
			rspamd_common_log_function (rspamd_main->logger,
				level,
				func_buf,
				"%s",
				msg);
		}
	}
	else {
		if (level == G_LOG_LEVEL_DEBUG) {
			rspamd_conditional_debug (rspamd_main->logger,
				NULL,
				__FUNCTION__,
				"%s",
				msg);
		}
		else {
			rspamd_common_log_function (rspamd_main->logger,
				level,
				__FUNCTION__,
				"%s",
				msg);
		}
	}
}

/*** Logger interface ***/
static gint
lua_logger_err (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log (G_LOG_LEVEL_CRITICAL, L, msg);
	return 1;
}

static gint
lua_logger_warn (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log (G_LOG_LEVEL_WARNING, L, msg);
	return 1;
}

static gint
lua_logger_info (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log (G_LOG_LEVEL_INFO, L, msg);
	return 1;
}

static gint
lua_logger_debug (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log (G_LOG_LEVEL_DEBUG, L, msg);
	return 1;
}


/*** Init functions ***/

static gint
lua_load_logger (lua_State *L)
{
	lua_newtable (L);
	luaL_register (L, NULL, loggerlib_f);

	return 1;
}

void
luaopen_logger (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_logger", lua_load_logger);
}

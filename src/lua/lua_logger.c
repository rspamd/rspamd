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

/***
 * @module rspamd_logger
 * Rspamd logger module is used to log messages from LUA API to the main rspamd logger.
 * It supports legacy and modern interfaces allowing highly customized an convenient log functions.
 * Here is an example of logger usage:
 * @example
local rspamd_logger = require "rspamd_logger"

local a = 'string'
local b = 1.5
local c = 1
local d = {
	'aa',
	1,
	'bb'
}
local e = {
	key = 'value',
	key2 = 1.0
}

-- New extended interface

rspamd_logger.infox('a=%1, b=%2, c=%3, d=%4, e=%5', a, b, c, d, e)
-- Output: a=string, b=1.50000, c=1, d={[1] = aa, [2] = 1, [3] = bb} e={[key]=value, [key2]=1.0}

-- Legacy interface (can handle merely strings)
rspamd_logger.info('Old stupid API')

-- Create string using logger API
local str = rspamd_logger.slog('a=%1, b=%2, c=%3, d=%4, e=%5', a, b, c, d, e)

print(str)
-- Output: a=string, b=1.50000, c=1, d={[1] = aa, [2] = 1, [3] = bb} e={[key]=value, [key2]=1.0}
 */

static gsize lua_logger_out_type (lua_State *L, gint pos, gchar *outbuf, gsize len);

/* Logger methods */
/***
 * @function logger.err(msg)
 * Log message as an error
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF (logger, err);
/***
 * @function logger.warn(msg)
 * Log message as a warning
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF (logger, warn);
/***
 * @function logger.info(msg)
 * Log message as an informational message
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF (logger, info);
/***
 * @function logger.debug(msg)
 * Log message as a debug message
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF (logger, debug);
/***
 * @function logger.errx(fmt[, args)
 * Extended interface to make an error log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, errx);
/***
 * @function logger.warn(fmt[, args)
 * Extended interface to make a warning log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, warnx);
/***
 * @function logger.infox(fmt[, args)
 * Extended interface to make an informational log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, infox);
/***
 * @function logger.debugx(fmt[, args)
 * Extended interface to make a debug log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, debugx);
/***
 * @function logger.slog(fmt[, args)
 * Create string replacing percent params with corresponding arguments
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 * @return {string} string with percent parameters substituted
 */
LUA_FUNCTION_DEF (logger, slog);

static const struct luaL_reg loggerlib_f[] = {
	LUA_INTERFACE_DEF (logger, err),
	LUA_INTERFACE_DEF (logger, warn),
	LUA_INTERFACE_DEF (logger, info),
	LUA_INTERFACE_DEF (logger, debug),
	LUA_INTERFACE_DEF (logger, errx),
	LUA_INTERFACE_DEF (logger, warnx),
	LUA_INTERFACE_DEF (logger, infox),
	LUA_INTERFACE_DEF (logger, debugx),
	LUA_INTERFACE_DEF (logger, slog),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static void
lua_common_log_line (GLogLevelFlags level, lua_State *L, const gchar *msg)
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
	lua_common_log_line (G_LOG_LEVEL_CRITICAL, L, msg);
	return 0;
}

static gint
lua_logger_warn (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_WARNING, L, msg);
	return 0;
}

static gint
lua_logger_info (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_INFO, L, msg);
	return 0;
}

static gint
lua_logger_debug (lua_State * L)
{
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_DEBUG, L, msg);
	return 0;
}

static gsize
lua_logger_out_str (lua_State *L, gint pos, gchar *outbuf, gsize len)
{
	const gchar *str = lua_tostring (L, pos);
	gsize r = 0;

	if (str) {
		r = rspamd_strlcpy (outbuf, str, len);
	}

	return r;
}

static gsize
lua_logger_out_num (lua_State *L, gint pos, gchar *outbuf, gsize len)
{
	gdouble num = lua_tonumber (L, pos);
	glong inum;
	gsize r = 0;

	if ((gdouble)(glong)num == num) {
		inum = num;
		r = rspamd_snprintf (outbuf, len, "%l", inum);
	}
	else {
		r = rspamd_snprintf (outbuf, len, "%f", num);
	}

	return r;
}

static gsize
lua_logger_out_boolean (lua_State *L, gint pos, gchar *outbuf, gsize len)
{
	gboolean val = lua_toboolean (L, pos);
	gsize r = 0;

	r = rspamd_strlcpy (outbuf, val ? "true" : "false", len);

	return r;
}

static gsize
lua_logger_out_userdata (lua_State *L, gint pos, gchar *outbuf, gsize len)
{
	gint r;

	if (!lua_getmetatable (L, pos)) {
		return 0;
	}

	lua_pushstring (L, "__index");
	lua_gettable (L, -2);

	if (!lua_istable (L, -1)) {
		lua_pop (L, 2);
		return 0;
	}

	lua_pushstring (L, "class");
	lua_gettable (L, -2);

	if (!lua_isstring (L, -1)) {
		lua_pop (L, 3);
		return 0;
	}

	r = rspamd_snprintf (outbuf, len, "%s(%p)", lua_tostring (L, -1),
			lua_touserdata (L, pos));
	lua_pop (L, 3);

	return r;
}

#define MOVE_BUF(d, remain, r) if ((remain) - (r) == 0) break; (d) += (r); (remain) -= (r)

static gsize
lua_logger_out_table (lua_State *L, gint pos, gchar *outbuf, gsize len)
{
	gchar *d = outbuf;
	gsize remain = len, r;
	gboolean first = TRUE;
	gint i;

	if (!lua_istable (L, pos)) {
		return 0;
	}

	lua_pushvalue (L, pos);
	r = rspamd_snprintf (d, remain, "{");
	remain -= r;
	d += r;

	/* Get numeric keys (ipairs) */
	for (i = 1; ; i ++) {
		lua_rawgeti (L, -1, i);

		if (lua_isnil (L, -1)) {
			lua_pop (L, 1);
			break;
		}

		if (!first) {
			r = rspamd_snprintf (d, remain, ", ");
			MOVE_BUF(d, remain, r);
		}

		r = rspamd_snprintf (d, remain, "[%d] = ", i);
		MOVE_BUF(d, remain, r);
		r = lua_logger_out_type (L, -1, d, remain);
		MOVE_BUF(d, remain, r);

		first = FALSE;
		lua_pop (L, 1);
	}

	/* Get string keys (pairs) */
	for (lua_pushnil (L); lua_next (L, -2) && remain > 0; lua_pop (L, 1)) {
		/* 'key' is at index -2 and 'value' is at index -1 */

		if (lua_type (L, -2) == LUA_TNUMBER) {
			continue;
		}

		if (!first) {
			r = rspamd_snprintf (d, remain, ", ");
			MOVE_BUF(d, remain, r);
		}

		r = rspamd_snprintf (d, remain, "[%s] = ",
				lua_tostring (L, -2));
		MOVE_BUF(d, remain, r);
		r = lua_logger_out_type (L, lua_gettop (L), d, remain);
		MOVE_BUF(d, remain, r);

		first = FALSE;
	}

	lua_pop (L, 1);

	r = rspamd_snprintf (d, remain, "}");
	d += r;

	return (d - outbuf);
}
#undef MOVE_BUF

static gsize
lua_logger_out_type (lua_State *L, gint pos, gchar *outbuf, gsize len)
{
	gint type;
	gsize r = 0;

	type = lua_type (L, pos);

	switch (type) {
	case LUA_TNUMBER:
		r = lua_logger_out_num (L, pos, outbuf, len);
		break;
	case LUA_TBOOLEAN:
		r = lua_logger_out_boolean (L, pos, outbuf, len);
		break;
	case LUA_TTABLE:
		r = lua_logger_out_table (L, pos, outbuf, len);
		break;
	case LUA_TUSERDATA:
		r = lua_logger_out_userdata (L, pos, outbuf, len);
		break;
	default:
		/* Try to push everything as string using tostring magic */
		r = lua_logger_out_str (L, pos, outbuf, len);
		break;
	}

	return r;
}

static gint
lua_logger_logx (lua_State *L, GLogLevelFlags level, gboolean is_string)
{
	gchar logbuf[BUFSIZ];
	gchar *d;
	const gchar *s, *c;
	gsize remain, r;
	guint arg_num = 0;
	enum {
		copy_char = 0,
		got_percent,
		parse_arg_num
	} state = copy_char;

	d = logbuf;
	remain = sizeof (logbuf);
	s = lua_tostring (L, 1);
	c = s;

	if (s == NULL) {
		return 0;
	}

	while (remain > 0 && *s != '\0') {
		switch (state) {
		case copy_char:
			if (*s == '%') {
				state = got_percent;
				s ++;
			}
			else {
				*d++ = *s++;
				remain --;
			}
			break;
		case got_percent:
			if (g_ascii_isdigit (*s)) {
				state = parse_arg_num;
				c = s;
			}
			else {
				*d++ = *s++;
				state = copy_char;
			}
			break;
		case parse_arg_num:
			if (g_ascii_isdigit (*s)) {
				s ++;
			}
			else {
				arg_num = strtoul (c, NULL, 10);

				if (arg_num < 1 || arg_num > (guint)lua_gettop (L) + 1) {
					msg_err ("wrong argument number: %ud", arg_num);

					if (is_string) {
						lua_pushnil (L);
						return 1;
					}
					else {
						return 0;
					}
				}

				r = lua_logger_out_type (L, arg_num + 1, d, remain);
				g_assert (r <= remain);
				remain -= r;
				d += r;
				state = copy_char;
			}
			break;
		}
	}

	if (state == parse_arg_num) {
		arg_num = strtoul (c, NULL, 10);

		if (arg_num < 1 || arg_num > (guint)lua_gettop (L) + 1) {
			msg_err ("wrong argument number: %ud", arg_num);

			if (is_string) {
				lua_pushnil (L);
				return 1;
			}
			else {
				return 0;
			}
		}

		r = lua_logger_out_type (L, arg_num + 1, d, remain);
		g_assert (r <= remain);
		remain -= r;
		d += r;
	}

	if (is_string) {
		lua_pushlstring (L, logbuf, sizeof (logbuf) - remain);
		return 1;
	}
	else {
		*d = '\0';
		lua_common_log_line (level, L, logbuf);
	}

	return 0;
}

static gint
lua_logger_errx (lua_State * L)
{
	return lua_logger_logx (L, G_LOG_LEVEL_CRITICAL, FALSE);
}

static gint
lua_logger_warnx (lua_State * L)
{
	return lua_logger_logx (L, G_LOG_LEVEL_WARNING, FALSE);
}

static gint
lua_logger_infox (lua_State * L)
{
	return lua_logger_logx (L, G_LOG_LEVEL_INFO, FALSE);
}

static gint
lua_logger_debugx (lua_State * L)
{
	return lua_logger_logx (L, G_LOG_LEVEL_DEBUG, FALSE);
}

static gint
lua_logger_slog (lua_State * L)
{
	return lua_logger_logx (L, 0, TRUE);
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

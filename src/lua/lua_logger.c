/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "lua_common.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_private.h"

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
-- %<number> means numeric arguments and %s means the next argument
-- for example %1, %2, %s: %s would mean the third argument

rspamd_logger.infox('a=%1, b=%2, c=%3, d=%4, e=%s', a, b, c, d, e)
-- Output: a=string, b=1.50000, c=1, d={[1] = aa, [2] = 1, [3] = bb} e={[key]=value, [key2]=1.0}

-- Legacy interface (can handle merely strings)
rspamd_logger.info('Old stupid API')

-- Create string using logger API
local str = rspamd_logger.slog('a=%1, b=%2, c=%3, d=%4, e=%5', a, b, c, d, e)

print(str)
-- Output: a=string, b=1.50000, c=1, d={[1] = aa, [2] = 1, [3] = bb} e={[key]=value, [key2]=1.0}
 */

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
 * @function logger.message(msg)
 * Log message as an notice message
 * @param {string} msg string to be logged
 */
LUA_FUNCTION_DEF (logger, message);
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
 * @function logger.infox(fmt[, args)
 * Extended interface to make an informational log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, messagex);
/***
 * @function logger.debugx(fmt[, args)
 * Extended interface to make a debug log message
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, debugx);

/***
 * @function logger.debugm(module, id, fmt[, args)
 * Extended interface to make a debug log message
 * @param {string} module debug module
 * @param {task|cfg|pool|string} id id to log
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, debugm);
/***
 * @function logger.slog(fmt[, args)
 * Create string replacing percent params with corresponding arguments
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 * @return {string} string with percent parameters substituted
 */
LUA_FUNCTION_DEF (logger, slog);

/***
 * @function logger.logx(level, module, id, fmt[, args)
 * Extended interface to make a generic log message on any level
 * @param {number} log level as a number (see GLogLevelFlags enum for values)
 * @param {task|cfg|pool|string} id id to log
 * @param {string} fmt format string, arguments are encoded as %<number>
 * @param {any} args list of arguments to be replaced in %<number> positions
 */
LUA_FUNCTION_DEF (logger, logx);

/***
 * @function logger.log_level()
 * Returns log level for a logger
 * @return {string} current log level
 */
LUA_FUNCTION_DEF (logger, log_level);

static const struct luaL_reg loggerlib_f[] = {
		LUA_INTERFACE_DEF (logger, err),
		LUA_INTERFACE_DEF (logger, warn),
		LUA_INTERFACE_DEF (logger, message),
		{"msg", lua_logger_message},
		LUA_INTERFACE_DEF (logger, info),
		LUA_INTERFACE_DEF (logger, debug),
		LUA_INTERFACE_DEF (logger, errx),
		LUA_INTERFACE_DEF (logger, warnx),
		LUA_INTERFACE_DEF (logger, infox),
		LUA_INTERFACE_DEF (logger, messagex),
		{"msgx", lua_logger_messagex},
		LUA_INTERFACE_DEF (logger, debugx),
		LUA_INTERFACE_DEF (logger, debugm),
		LUA_INTERFACE_DEF (logger, slog),
		LUA_INTERFACE_DEF (logger, logx),
		LUA_INTERFACE_DEF (logger, log_level),
		{"__tostring", rspamd_lua_class_tostring},
		{NULL, NULL}
};

static void
lua_common_log_line (GLogLevelFlags level,
					 lua_State *L,
					 const gchar *msg,
					 const gchar *uid,
					 const gchar *module,
					 gint stack_level)
{
	lua_Debug d;
	gchar func_buf[128], *p;

	if (lua_getstack (L, stack_level, &d) == 1) {
		(void) lua_getinfo (L, "Sl", &d);
		if ((p = strrchr (d.short_src, '/')) == NULL) {
			p = d.short_src;
		}
		else {
			p++;
		}

		if (strlen (p) > 30) {
			rspamd_snprintf (func_buf, sizeof (func_buf), "%27s...:%d", p,
					d.currentline);
		}
		else {
			rspamd_snprintf (func_buf, sizeof (func_buf), "%s:%d", p,
					d.currentline);
		}

		rspamd_common_log_function (NULL,
				level,
				module,
				uid,
				func_buf,
				"%s",
				msg);
	}
	else {
		rspamd_common_log_function (NULL,
				level,
				module,
				uid,
				G_STRFUNC,
				"%s",
				msg);
	}
}

/*** Logger interface ***/
static gint
lua_logger_err (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_CRITICAL, L, msg, NULL, NULL, 1);
	return 0;
}

static gint
lua_logger_warn (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_WARNING, L, msg, NULL, NULL, 1);
	return 0;
}

static gint
lua_logger_info (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_INFO, L, msg, NULL, NULL, 1);
	return 0;
}

static gint
lua_logger_message (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_MESSAGE, L, msg, NULL, NULL, 1);
	return 0;
}

static gint
lua_logger_debug (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *msg;
	msg = luaL_checkstring (L, 1);
	lua_common_log_line (G_LOG_LEVEL_DEBUG, L, msg, NULL, NULL, 1);
	return 0;
}

static inline bool
lua_logger_char_safe (int t, unsigned int esc_type)
{
	if (t & 0x80) {
		if (esc_type & LUA_ESCAPE_8BIT) {
			return false;
		}

		return true;
	}

	if (esc_type & LUA_ESCAPE_UNPRINTABLE) {
		if (!g_ascii_isprint (t) && !g_ascii_isspace (t)) {
			return false;
		}
	}

	if (esc_type & LUA_ESCAPE_NEWLINES) {
		if (t == '\r' || t == '\n') {
			return false;
		}
	}

	return true;
}

static gsize
lua_logger_out_str (lua_State *L, gint pos,
					gchar *outbuf, gsize len,
					struct lua_logger_trace *trace,
					enum lua_logger_escape_type esc_type)
{
	gsize slen, flen;
	const gchar *str = lua_tolstring (L, pos, &slen);
	static const gchar hexdigests[16] = "0123456789abcdef";
	gsize r = 0, s;

	if (str) {
		gboolean normal = TRUE;
		flen = MIN (slen, len - 1);

		for (r = 0; r < flen; r ++) {
			if (!lua_logger_char_safe (str[r], esc_type)) {
				normal = FALSE;
				break;
			}
		}

		if (normal) {
			r = rspamd_strlcpy (outbuf, str, flen + 1);
		}
		else {
			/* Need to escape non printed characters */
			r = 0;
			s = 0;

			while (slen > 0 && len > 1) {
				if (!lua_logger_char_safe (str[s], esc_type)) {
					if (len >= 3) {
						outbuf[r++] = '\\';
						outbuf[r++] = hexdigests[((str[s] >> 4) & 0xF)];
						outbuf[r++] = hexdigests[((str[s]) & 0xF)];

						len -= 2;
					}
					else {
						outbuf[r++] = '?';
					}
				}
				else {
					outbuf[r++] = str[s];
				}

				s++;
				slen --;
				len --;
			}

			outbuf[r] = '\0';
		}
	}

	return r;
}

static gsize
lua_logger_out_num (lua_State *L, gint pos, gchar *outbuf, gsize len,
					struct lua_logger_trace *trace)
{
	gdouble num = lua_tonumber (L, pos);
	glong inum;
	gsize r = 0;

	if ((gdouble) (glong) num == num) {
		inum = num;
		r = rspamd_snprintf (outbuf, len + 1, "%l", inum);
	}
	else {
		r = rspamd_snprintf (outbuf, len + 1, "%f", num);
	}

	return r;
}

static gsize
lua_logger_out_boolean (lua_State *L, gint pos, gchar *outbuf, gsize len,
						struct lua_logger_trace *trace)
{
	gboolean val = lua_toboolean (L, pos);
	gsize r = 0;

	r = rspamd_strlcpy (outbuf, val ? "true" : "false", len + 1);

	return r;
}

static gsize
lua_logger_out_userdata (lua_State *L, gint pos, gchar *outbuf, gsize len,
						 struct lua_logger_trace *trace)
{
	gint r = 0, top;
	const gchar *str = NULL;
	gboolean converted_to_str = FALSE;

	top = lua_gettop (L);

	if (!lua_getmetatable (L, pos)) {
		return 0;
	}

	lua_pushstring (L, "__index");
	lua_gettable (L, -2);

	if (!lua_istable (L, -1)) {

		if (lua_isfunction (L, -1)) {
			/* Functional metatable, try to get __tostring directly */
			lua_pushstring (L, "__tostring");
			lua_gettable (L, -3);

			if (lua_isfunction (L, -1)) {
				lua_pushvalue (L, pos);

				if (lua_pcall (L, 1, 1, 0) != 0) {
					lua_settop (L, top);

					return 0;
				}

				str = lua_tostring (L, -1);

				if (str) {
					r = rspamd_snprintf (outbuf, len, "%s", str);
				}

				lua_settop (L, top);

				return r;
			}
		}
		lua_settop (L, top);

		return 0;
	}

	lua_pushstring (L, "__tostring");
	lua_gettable (L, -2);

	if (lua_isfunction (L, -1)) {
		lua_pushvalue (L, pos);

		if (lua_pcall (L, 1, 1, 0) != 0) {
			lua_settop (L, top);

			return 0;
		}

		str = lua_tostring (L, -1);

		if (str) {
			converted_to_str = TRUE;
		}
	}
	else {
		lua_pop (L, 1);
		lua_pushstring (L, "class");
		lua_gettable (L, -2);

		if (lua_isstring (L, -1)) {
			str = lua_tostring (L, -1);
			converted_to_str = TRUE;
		}
	}

	if (converted_to_str) {
		r = rspamd_snprintf (outbuf, len, "%s", str);
	}
	else {
		/* Print raw pointer */
		r = rspamd_snprintf (outbuf, len, "%s(%p)", str, lua_touserdata (L, pos));
	}

	lua_settop (L, top);

	return r;
}

#define MOVE_BUF(d, remain, r)    \
    (d) += (r); (remain) -= (r);    \
    if ((remain) == 0) { lua_pop (L, 1); break; }

static gsize
lua_logger_out_table (lua_State *L, gint pos, gchar *outbuf, gsize len,
					  struct lua_logger_trace *trace,
					  enum lua_logger_escape_type esc_type)
{
	gchar *d = outbuf;
	gsize remain = len, r;
	gboolean first = TRUE;
	gconstpointer self = NULL;
	gint i, tpos, last_seq = -1;

	if (!lua_istable (L, pos) || remain == 0) {
		return 0;
	}

	self = lua_topointer (L, pos);

	/* Check if we have seen this pointer */
	for (i = 0; i < TRACE_POINTS; i ++) {
		if (trace->traces[i] == self) {
			r = rspamd_snprintf (d, remain + 1, "ref(%p)", self);

			d += r;

			return (d - outbuf);
		}
	}

	trace->traces[trace->cur_level % TRACE_POINTS] = self;

	lua_pushvalue (L, pos);
	r = rspamd_snprintf (d, remain + 1, "{");
	remain -= r;
	d += r;

	/* Get numeric keys (ipairs) */
	for (i = 1; ; i++) {
		lua_rawgeti (L, -1, i);

		if (lua_isnil (L, -1)) {
			lua_pop (L, 1);
			break;
		}

		last_seq = i;

		if (!first) {
			r = rspamd_snprintf (d, remain + 1, ", ");
			MOVE_BUF(d, remain, r);
		}

		r = rspamd_snprintf (d, remain + 1, "[%d] = ", i);
		MOVE_BUF(d, remain, r);
		tpos = lua_gettop (L);

		if (lua_topointer (L, tpos) == self) {
			r = rspamd_snprintf (d, remain + 1, "__self");
		}
		else {
			r = lua_logger_out_type (L, tpos, d, remain, trace, esc_type);
		}
		MOVE_BUF(d, remain, r);

		first = FALSE;
		lua_pop (L, 1);
	}

	/* Get string keys (pairs) */
	for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
		/* 'key' is at index -2 and 'value' is at index -1 */

		if (lua_type (L, -2) == LUA_TNUMBER) {
			if (last_seq > 0) {
				lua_pushvalue (L, -2);

				if (lua_tonumber (L, -1) <= last_seq + 1) {
					lua_pop (L, 1);
					/* Already seen */
					continue;
				}

				lua_pop (L, 1);
			}
		}

		if (!first) {
			r = rspamd_snprintf (d, remain + 1, ", ");
			MOVE_BUF(d, remain, r);
		}

		/* Preserve key */
		lua_pushvalue (L, -2);
		r = rspamd_snprintf (d, remain + 1, "[%s] = ",
				lua_tostring (L, -1));
		lua_pop (L, 1); /* Remove key */
		MOVE_BUF(d, remain, r);
		tpos = lua_gettop (L);

		if (lua_topointer (L, tpos) == self) {
			r = rspamd_snprintf (d, remain + 1, "__self");
		}
		else {
			r = lua_logger_out_type (L, tpos, d, remain, trace, esc_type);
		}
		MOVE_BUF(d, remain, r);

		first = FALSE;
	}

	lua_pop (L, 1);

	r = rspamd_snprintf (d, remain + 1, "}");
	d += r;

	return (d - outbuf);
}

#undef MOVE_BUF

gsize
lua_logger_out_type (lua_State *L, gint pos,
					 gchar *outbuf, gsize len,
					 struct lua_logger_trace *trace,
					 enum lua_logger_escape_type esc_type)
{
	gint type;
	gsize r = 0;

	if (len == 0) {
		return 0;
	}

	type = lua_type (L, pos);
	trace->cur_level ++;

	switch (type) {
	case LUA_TNUMBER:
		r = lua_logger_out_num (L, pos, outbuf, len, trace);
		break;
	case LUA_TBOOLEAN:
		r = lua_logger_out_boolean (L, pos, outbuf, len, trace);
		break;
	case LUA_TTABLE:
		r = lua_logger_out_table (L, pos, outbuf, len, trace, esc_type);
		break;
	case LUA_TUSERDATA:
		r = lua_logger_out_userdata (L, pos, outbuf, len, trace);
		break;
	case LUA_TFUNCTION:
		r = rspamd_snprintf (outbuf, len + 1, "function");
		break;
	case LUA_TLIGHTUSERDATA:
		r = rspamd_snprintf (outbuf, len + 1, "0x%p", lua_topointer (L, pos));
		break;
	case LUA_TNIL:
		r = rspamd_snprintf (outbuf, len + 1, "nil");
		break;
	case LUA_TNONE:
		r = rspamd_snprintf (outbuf, len + 1, "no value");
		break;
	default:
		/* Try to push everything as string using tostring magic */
		r = lua_logger_out_str (L, pos, outbuf, len, trace, esc_type);
		break;
	}

	trace->cur_level --;

	return r;
}

static const gchar *
lua_logger_get_id (lua_State *L, gint pos, GError **err)
{
	const gchar *uid = NULL, *clsname;

	if (lua_getmetatable (L, pos) != 0) {
		uid = "";
		lua_pushstring (L, "__index");
		lua_gettable (L, -2);

		lua_pushstring (L, "class");
		lua_gettable (L, -2);

		clsname = lua_tostring (L, -1);

		if (strcmp (clsname, "rspamd{task}") == 0) {
			struct rspamd_task *task = lua_check_task (L, pos);

			if (task) {
				uid = task->task_pool->tag.uid;
			}
			else {
				g_set_error (err, g_quark_from_static_string ("lua_logger"),
						EINVAL, "invalid rspamd{task}");
			}
		}
		else if (strcmp (clsname, "rspamd{mempool}") == 0) {
			rspamd_mempool_t  *pool;

			pool = rspamd_lua_check_mempool (L, pos);

			if (pool) {
				uid = pool->tag.uid;
			}
			else {
				g_set_error (err, g_quark_from_static_string ("lua_logger"),
						EINVAL, "invalid rspamd{mempool}");
			}
		}
		else if (strcmp (clsname, "rspamd{config}") == 0) {
			struct rspamd_config *cfg;

			cfg = lua_check_config (L, pos);

			if (cfg) {
				if (cfg->checksum) {
					uid = cfg->checksum;
				}
			}
			else {
				g_set_error (err, g_quark_from_static_string ("lua_logger"),
						EINVAL, "invalid rspamd{config}");
			}
		}
		else if (strcmp (clsname, "rspamd{map}") == 0) {
			struct rspamd_lua_map *map;

			map = lua_check_map (L, pos);

			if (map) {
				if (map->map) {
					uid = map->map->tag;
				}
				else {
					uid = "embedded";
				}
			}
			else {
				g_set_error (err, g_quark_from_static_string ("lua_logger"),
						EINVAL, "invalid rspamd{map}");
			}
		}
		else {
			g_set_error (err, g_quark_from_static_string ("lua_logger"),
					EINVAL, "unknown class: %s", clsname);
		}


		/* Metatable, __index, classname */
		lua_pop (L, 3);
	}
	else {
		g_set_error (err, g_quark_from_static_string ("lua_logger"),
				EINVAL, "no metatable found for userdata");
	}

	return uid;
}

static gboolean
lua_logger_log_format (lua_State *L, gint fmt_pos, gboolean is_string,
		gchar *logbuf, gsize remain)
{
	gchar *d;
	const gchar *s, *c;
	gsize r, cpylen = 0;
	guint arg_num = 0, cur_arg;
	bool num_arg = false;
	struct lua_logger_trace tr;
	enum {
		copy_char = 0,
		got_percent,
		parse_arg_num
	} state = copy_char;

	d = logbuf;
	s = lua_tostring (L, fmt_pos);
	c = s;
	cur_arg = fmt_pos;

	if (s == NULL) {
		return FALSE;
	}

	while (remain > 0 && *s != '\0') {
		switch (state) {
		case copy_char:
			if (*s == '%') {
				state = got_percent;
				s++;
				if (cpylen > 0) {
					memcpy (d, c, cpylen);
					d += cpylen;
				}
				cpylen = 0;
			}
			else {
				s++;
				cpylen ++;
				remain--;
			}
			break;
		case got_percent:
			if (g_ascii_isdigit (*s) || *s == 's') {
				state = parse_arg_num;
				c = s;
			}
			else {
				*d++ = *s++;
				c = s;
				state = copy_char;
			}
			break;
		case parse_arg_num:
			if (g_ascii_isdigit (*s)) {
				s++;
				num_arg = true;
			}
			else {
				if (num_arg) {
					arg_num = strtoul (c, NULL, 10);
					arg_num += fmt_pos - 1;
					/* Update the current argument */
					cur_arg = arg_num;
				}
				else {
					/* We have non numeric argument, e.g. %s */
					arg_num = cur_arg ++;
					s ++;
				}

				if (arg_num < 1 || arg_num > (guint) lua_gettop (L) + 1) {
					msg_err ("wrong argument number: %ud", arg_num);

					return FALSE;
				}

				memset (&tr, 0, sizeof (tr));
				r = lua_logger_out_type (L, arg_num + 1, d, remain, &tr,
						is_string ? LUA_ESCAPE_UNPRINTABLE : LUA_ESCAPE_LOG);
				g_assert (r <= remain);
				remain -= r;
				d += r;
				state = copy_char;
				c = s;
			}
			break;
		}
	}

	if (state == parse_arg_num) {
		if (num_arg) {
			arg_num = strtoul (c, NULL, 10);
			arg_num += fmt_pos - 1;
		}
		else {
			/* We have non numeric argument, e.g. %s */
			arg_num = cur_arg;
		}

		if (arg_num < 1 || arg_num > (guint) lua_gettop (L) + 1) {
			msg_err ("wrong argument number: %ud", arg_num);

			return FALSE;
		}

		memset (&tr, 0, sizeof (tr));
		r = lua_logger_out_type (L, arg_num + 1, d, remain, &tr,
				is_string ? LUA_ESCAPE_UNPRINTABLE : LUA_ESCAPE_LOG);
		g_assert (r <= remain);
		remain -= r;
		d += r;
	}
	else if (state == copy_char) {
		if (cpylen > 0 && remain > 0) {
			memcpy (d, c, cpylen);
			d += cpylen;
		}
	}

	*d = '\0';


	return TRUE;
}

static gint
lua_logger_do_log (lua_State *L,
				   GLogLevelFlags level,
				   gboolean is_string,
				   gint start_pos)
{
	gchar logbuf[RSPAMD_LOGBUF_SIZE - 128];
	const gchar *uid = NULL;
	gint fmt_pos = start_pos;
	gint ret;
	GError *err = NULL;

	if (lua_type (L, start_pos) == LUA_TSTRING) {
		fmt_pos = start_pos;
	}
	else if (lua_type (L, start_pos) == LUA_TUSERDATA) {
		fmt_pos = start_pos + 1;

		uid = lua_logger_get_id (L, start_pos, &err);

		if (uid == NULL) {
			ret = luaL_error (L, "bad userdata for logging: %s",
					err ? err->message : "unknown error");

			if (err) {
				g_error_free (err);
			}

			return ret;
		}
	}
	else {
		/* Bad argument type */
		return luaL_error (L, "bad format string type: %s",
				lua_typename (L, lua_type (L, start_pos)));
	}

	ret = lua_logger_log_format (L, fmt_pos, is_string,
			logbuf, sizeof (logbuf) - 1);

	if (ret) {
		if (is_string) {
			lua_pushstring (L, logbuf);
			return 1;
		}
		else {
			lua_common_log_line (level, L, logbuf, uid, "lua", 1);
		}
	}
	else {
		if (is_string) {
			lua_pushnil (L);

			return 1;
		}
	}

	return 0;
}

static gint
lua_logger_errx (lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log (L, G_LOG_LEVEL_CRITICAL, FALSE, 1);
}

static gint
lua_logger_warnx (lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log (L, G_LOG_LEVEL_WARNING, FALSE, 1);
}

static gint
lua_logger_infox (lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log (L, G_LOG_LEVEL_INFO, FALSE, 1);
}

static gint
lua_logger_messagex (lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log (L, G_LOG_LEVEL_MESSAGE, FALSE, 1);
}

static gint
lua_logger_debugx (lua_State *L)
{
	LUA_TRACE_POINT;
	return lua_logger_do_log (L, G_LOG_LEVEL_DEBUG, FALSE, 1);
}

static gint
lua_logger_logx (lua_State *L)
{
	LUA_TRACE_POINT;
	GLogLevelFlags flags = lua_tonumber (L, 1);
	const gchar *modname = lua_tostring (L, 2), *uid = NULL;
	gchar logbuf[RSPAMD_LOGBUF_SIZE - 128];
	gboolean ret;
	gint stack_pos = 1;

	if (lua_type (L, 3) == LUA_TSTRING) {
		uid = luaL_checkstring (L, 3);
	}
	else if (lua_type (L, 3) == LUA_TUSERDATA) {
		uid = lua_logger_get_id (L, 3, NULL);
	}
	else {
		uid = "???";
	}

	if (uid && modname) {
		if (lua_type (L, 4) == LUA_TSTRING) {
			ret = lua_logger_log_format (L, 4, FALSE, logbuf, sizeof (logbuf) - 1);
		}
		else if (lua_type (L, 4) == LUA_TNUMBER) {
			stack_pos = lua_tonumber (L, 4);
			ret = lua_logger_log_format (L, 5, FALSE, logbuf, sizeof (logbuf) - 1);
		}
		else {
			return luaL_error (L, "invalid argument on pos 4");
		}

		if (ret) {
			lua_common_log_line (flags, L, logbuf, uid, modname, stack_pos);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}


static gint
lua_logger_debugm (lua_State *L)
{
	LUA_TRACE_POINT;
	gchar logbuf[RSPAMD_LOGBUF_SIZE - 128];
	const gchar *uid = NULL, *module = NULL;
	gint stack_pos = 1;
	gboolean ret;

	module = luaL_checkstring (L, 1);

	if (lua_type (L, 2) == LUA_TSTRING) {
		uid = luaL_checkstring (L, 2);
	}
	else {
		uid = lua_logger_get_id (L, 2, NULL);
	}

	if (uid && module) {
		if (lua_type (L, 3) == LUA_TSTRING) {
			ret = lua_logger_log_format (L, 3, FALSE, logbuf, sizeof (logbuf) - 1);
		}
		else if (lua_type (L, 3) == LUA_TNUMBER) {
			stack_pos = lua_tonumber (L, 3);
			ret = lua_logger_log_format (L, 4, FALSE, logbuf, sizeof (logbuf) - 1);
		}
		else {
			return luaL_error (L, "invalid argument on pos 3");
		}

		if (ret) {
			lua_common_log_line (G_LOG_LEVEL_DEBUG, L, logbuf, uid, module, stack_pos);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}



static gint
lua_logger_slog (lua_State *L)
{
	return lua_logger_do_log (L, 0, TRUE, 1);
}

static gint
lua_logger_log_level (lua_State *L)
{
	gint log_level = rspamd_log_get_log_level (NULL);

	lua_pushstring (L, rspamd_get_log_severity_string(log_level));

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
luaopen_logger (lua_State *L)
{
	rspamd_lua_add_preload (L, "rspamd_logger", lua_load_logger);
}

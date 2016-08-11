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
#include "task.h"
#include "rspamd.h"
#include "html.h"
#include "cfg_rcl.h"
#include "tokenizers/tokenizers.h"
#include "libserver/url.h"
#include "unix-std.h"
#include <math.h>
#include <glob.h>

/***
 * @module rspamd_util
 * This module contains some generic purpose utilities that could be useful for
 * testing and production rules.
 */

/***
 * @function util.create_event_base()
 * Creates new event base for processing asynchronous events
 * @return {ev_base} new event processing base
 */
LUA_FUNCTION_DEF (util, create_event_base);
/***
 * @function util.load_rspamd_config(filename)
 * Load rspamd config from the specified file
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF (util, load_rspamd_config);
/***
 * @function util.config_from_ucl(any)
 * Load rspamd config from ucl reperesented by any lua table
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF (util, config_from_ucl);
/***
 * @function util.encode_base64(input[, str_len])
 * Encodes data in base64 breaking lines if needed
 * @param {text or string} input input data
 * @param {number} str_len optional size of lines or 0 if split is not needed
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF (util, encode_base64);
/***
 * @function util.decode_base64(input)
 * Decodes data from base64 ignoring whitespace characters
 * @param {text or string} input data to decode; if `rspamd{text}` is used then the string is modified **in-place**
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_base64);

/***
 * @function util.encode_base32(input)
 * Encodes data in base32 breaking lines if needed
 * @param {text or string} input input data
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF (util, encode_base32);
/***
 * @function util.decode_base32(input)
 * Decodes data from base32 ignoring whitespace characters
 * @param {text or string} input data to decode
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_base32);

/***
 * @function util.decode_url(input)
 * Decodes data from url encoding
 * @param {text or string} input data to decode
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_url);

/***
 * @function util.tokenize_text(input[, exceptions])
 * Create tokens from a text using optional exceptions list
 * @param {text/string} input input data
 * @param {table} exceptions, a table of pairs containing <start_pos,lenght> of exceptions in the input
 * @return {table/strings} list of strings representing words in the text
 */
LUA_FUNCTION_DEF (util, tokenize_text);
LUA_FUNCTION_DEF (util, process_message);
/***
 * @function util.tanh(num)
 * Calculates hyperbolic tanhent of the specified floating point value
 * @param {number} num input number
 * @return {number} hyperbolic tanhent of the variable
 */
LUA_FUNCTION_DEF (util, tanh);

/***
 * @function util.parse_html(input)
 * Parses HTML and returns the according text
 * @param {string|text} in input HTML
 * @return {rspamd_text} processed text with no HTML tags
 */
LUA_FUNCTION_DEF (util, parse_html);

/***
 * @function util.levenshtein_distance(s1, s2)
 * Returns levenstein distance between two strings
 * @param {string} s1 the first string
 * @param {string} s2 the second string
 * @return {number} number of differences in two strings
 */
LUA_FUNCTION_DEF (util, levenshtein_distance);

/***
 * @function util.parse_addr(str)
 * Parse rfc822 address to components. Returns a table of components:
 *
 * - `name`: name of address (e.g. Some User)
 * - `addr`: address part (e.g. user@example.com)
 *
 * @param {string} str input string
 * @return {table} resulting table of components
 */
LUA_FUNCTION_DEF (util, parse_addr);

/***
 * @function util.fold_header(name, value)
 * Fold rfc822 header according to the folding rules
 *
 * @param {string} name name of the header
 * @param {string} value value of the header
 * @return {string} Folded value of the header
 */
LUA_FUNCTION_DEF (util, fold_header);

/***
 * @function util.is_uppercase(str)
 * Returns true if a string is all uppercase
 *
 * @param {string} str input string
 * @return {bool} true if a string is all uppercase
 */
LUA_FUNCTION_DEF (util, is_uppercase);

/***
 * @function util.humanize_number(num)
 * Returns humanized representation of given number (like 1k instead of 1000)
 *
 * @param {number} num number to humanize
 * @return {string} humanized representation of a number
 */
LUA_FUNCTION_DEF (util, humanize_number);

/***
 * @function util.get_tld(host)
 * Returns tld for the specified host
 *
 * @param {string} host hostname
 * @return {string} tld part of hostname or the full hostname
 */
LUA_FUNCTION_DEF (util, get_tld);

/***
 * @function util.glob(pattern)
 * Returns results for the glob match for the specified pattern
 *
 * @param {string} pattern glob pattern to match ('?' and '*' are supported)
 * @return {table/string} list of matched files
 */
LUA_FUNCTION_DEF (util, glob);

/***
 * @function util.parse_mail_address(str)
 * Parses email address and returns a table of tables in the following format:
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 *
 * @param {string} str input string
 * @return {table/tables} parsed list of mail addresses
 */
LUA_FUNCTION_DEF (util, parse_mail_address);

/***
 * @function util.strlen_utf8(str)
 * Returns length of string encoded in utf-8 in characters.
 * If invalid characters are found, then this function returns number of bytes.
 * @param {string} str utf8 encoded string
 * @return {number} number of characters in string
 */
LUA_FUNCTION_DEF (util, strlen_utf8);

/***
 * @function util.strcasecmp(str1, str2)
 * Compares two utf8 strings regardless of their case. Return value >0, 0 and <0
 * if `str1` is more, equal or less than `str2`
 * @param {string} str1 utf8 encoded string
 * @param {string} str2 utf8 encoded string
 * @return {number} result of comparison
 */
LUA_FUNCTION_DEF (util, strcasecmp_utf8);

/***
 * @function util.strcasecmp(str1, str2)
 * Compares two ascii strings regardless of their case. Return value >0, 0 and <0
 * if `str1` is more, equal or less than `str2`
 * @param {string} str1 plain string
 * @param {string} str2 plain string
 * @return {number} result of comparison
 */
LUA_FUNCTION_DEF (util, strcasecmp_ascii);

/***
 * @function util.strequal_caseless(str1, str2)
 * Compares two utf8 strings regardless of their case. Return `true` if `str1` is
 * equal to `str2`
 * @param {string} str1 utf8 encoded string
 * @param {string} str2 utf8 encoded string
 * @return {bool} result of comparison
 */
LUA_FUNCTION_DEF (util, strequal_caseless);

/***
 * @function util.get_ticks()
 * Returns current number of ticks as floating point number
 * @return {number} number of current clock ticks (monotonically increasing)
 */
LUA_FUNCTION_DEF (util, get_ticks);

/***
 * @function util.get_time()
 * Returns current time as unix time in floating point representation
 * @return {number} number of seconds since 01.01.1970
 */
LUA_FUNCTION_DEF (util, get_time);

/***
 * @function util.time_to_string(seconds)
 * Converts time from Unix time to HTTP date format
 * @param {number} seconds unix timestamp
 * @return {string} date as HTTP date
 */
LUA_FUNCTION_DEF (util, time_to_string);

/***
 * @function util.stat(fname)
 * Performs stat(2) on a specified filepath and returns table of values
 *
 * - `size`: size of file in bytes
 * - `type`: type of filepath: `regular`, `directory`, `special`
 * - `mtime`: modification time as unix time
 *
 * @return {string,table} string is returned when error is occurred
 * @example
 *
 * local err,st = util.stat('/etc/password')
 *
 * if err then
 *   -- handle error
 * else
 *   print(st['size'])
 * end
 */
LUA_FUNCTION_DEF (util, stat);

/***
 * @function util.unlink(fname)
 * Removes the specified file from the filesystem
 *
 * @param {string} fname filename to remove
 * @return {boolean,[string]} true if file has been deleted or false,'error string'
 */
LUA_FUNCTION_DEF (util, unlink);

/***
 * @function util.lock_file(fname, [fd])
 * Lock the specified file. This function returns {number} which must be passed to `util.unlock_file` after usage
 * or you'll have a resource leak
 *
 * @param {string} fname filename to lock
 * @param {number} fd use the specified fd instead of opening one
 * @return {number|nil,string} number if locking was successful or nil + error otherwise
 */
LUA_FUNCTION_DEF (util, lock_file);

/***
 * @function util.unlock_file(fd, [close_fd])
 * Unlock the specified file closing the file descriptor associated.
 *
 * @param {number} fd descriptor to unlock
 * @param {boolean} close_fd close descriptor on unlocking (default: TRUE)
 * @return {boolean[,string]} true if a file was unlocked
 */
LUA_FUNCTION_DEF (util, unlock_file);

/***
 * @function util.create_file(fname, [mode])
 * Creates the specified file with the default mode 0644
 *
 * @param {string} fname filename to create
 * @param {number} mode open mode (you should use octal number here)
 * @return {number|nil,string} file descriptor or pair nil + error string
 */
LUA_FUNCTION_DEF (util, create_file);

/***
 * @function util.close_file(fd)
 * Closes descriptor fd
 *
 * @param {number} fd descriptor to close
 * @return {boolean[,string]} true if a file was closed
 */
LUA_FUNCTION_DEF (util, close_file);

/**
 * @function util.random_hex(size)
 * Returns random hex string of the specified size
 *
 * @param {number} len length of desired string in bytes
 * @return {string} string with random hex digests
 */
LUA_FUNCTION_DEF (util, random_hex);

static const struct luaL_reg utillib_f[] = {
	LUA_INTERFACE_DEF (util, create_event_base),
	LUA_INTERFACE_DEF (util, load_rspamd_config),
	LUA_INTERFACE_DEF (util, config_from_ucl),
	LUA_INTERFACE_DEF (util, process_message),
	LUA_INTERFACE_DEF (util, encode_base64),
	LUA_INTERFACE_DEF (util, decode_base64),
	LUA_INTERFACE_DEF (util, encode_base32),
	LUA_INTERFACE_DEF (util, decode_base32),
	LUA_INTERFACE_DEF (util, decode_url),
	LUA_INTERFACE_DEF (util, tokenize_text),
	LUA_INTERFACE_DEF (util, tanh),
	LUA_INTERFACE_DEF (util, parse_html),
	LUA_INTERFACE_DEF (util, levenshtein_distance),
	LUA_INTERFACE_DEF (util, parse_addr),
	LUA_INTERFACE_DEF (util, fold_header),
	LUA_INTERFACE_DEF (util, is_uppercase),
	LUA_INTERFACE_DEF (util, humanize_number),
	LUA_INTERFACE_DEF (util, get_tld),
	LUA_INTERFACE_DEF (util, glob),
	LUA_INTERFACE_DEF (util, parse_mail_address),
	LUA_INTERFACE_DEF (util, strlen_utf8),
	LUA_INTERFACE_DEF (util, strcasecmp_utf8),
	LUA_INTERFACE_DEF (util, strcasecmp_ascii),
	LUA_INTERFACE_DEF (util, strequal_caseless),
	LUA_INTERFACE_DEF (util, get_ticks),
	LUA_INTERFACE_DEF (util, get_time),
	LUA_INTERFACE_DEF (util, time_to_string),
	LUA_INTERFACE_DEF (util, stat),
	LUA_INTERFACE_DEF (util, unlink),
	LUA_INTERFACE_DEF (util, lock_file),
	LUA_INTERFACE_DEF (util, unlock_file),
	LUA_INTERFACE_DEF (util, create_file),
	LUA_INTERFACE_DEF (util, close_file),
	LUA_INTERFACE_DEF (util, random_hex),
	{NULL, NULL}
};

static gint
lua_util_create_event_base (lua_State *L)
{
	struct event_base **pev_base;

	pev_base = lua_newuserdata (L, sizeof (struct event_base *));
	rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
	*pev_base = event_init ();

	return 1;
}

static gint
lua_util_load_rspamd_config (lua_State *L)
{
	struct rspamd_config *cfg, **pcfg;
	const gchar *cfg_name;

	cfg_name = luaL_checkstring (L, 1);

	if (cfg_name) {
		cfg = rspamd_config_new ();

		if (rspamd_config_read (cfg, cfg_name, NULL, NULL, NULL, NULL)) {
			msg_err_config ("cannot load config from %s", cfg_name);
			lua_pushnil (L);
		}
		else {
			rspamd_config_post_load (cfg, 0);
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static gint
lua_util_config_from_ucl (lua_State *L)
{
	struct rspamd_config *cfg, **pcfg;
	struct rspamd_rcl_section *top;
	GError *err = NULL;
	ucl_object_t *obj;

	obj = ucl_object_lua_import (L, 1);

	if (obj) {
		cfg = g_malloc0 (sizeof (struct rspamd_config));
		cfg = rspamd_config_new ();

		cfg->rcl_obj = obj;
		cfg->cache = rspamd_symbols_cache_new (cfg);
		top = rspamd_rcl_config_init (cfg);

		if (!rspamd_rcl_parse (top, cfg, cfg, cfg->cfg_pool, cfg->rcl_obj, &err)) {
			msg_err_config ("rcl parse error: %s", err->message);
			ucl_object_unref (obj);
			lua_pushnil (L);
		}
		else {
			rspamd_config_post_load (cfg, 0);
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static gboolean
lua_util_task_fin (struct rspamd_task *task, void *ud)
{
	ucl_object_t **target = ud;

	*target = rspamd_protocol_write_ucl (task);
	rdns_resolver_release (task->resolver->r);

	return TRUE;
}

static gint
lua_util_process_message (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *message;
	gsize mlen;
	struct rspamd_task *task;
	struct event_base *base;
	ucl_object_t *res = NULL;

	message = luaL_checklstring (L, 2, &mlen);

	if (cfg != NULL && message != NULL) {
		base = event_init ();
		rspamd_init_filters (cfg, FALSE);
		task = rspamd_task_new (NULL, cfg);
		task->ev_base = base;
		task->msg.begin = rspamd_mempool_alloc (task->task_pool, mlen);
		rspamd_strlcpy ((gpointer)task->msg.begin, message, mlen);
		task->msg.len = mlen;
		task->fin_callback = lua_util_task_fin;
		task->fin_arg = &res;
		task->resolver = dns_resolver_init (NULL, base, cfg);
		task->s = rspamd_session_create (task->task_pool, rspamd_task_fin,
					rspamd_task_restore, (event_finalizer_t)rspamd_task_free, task);

		if (!rspamd_task_load_message (task, NULL, message, mlen)) {
			lua_pushnil (L);
		}
		else {
			if (rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
				event_base_loop (base, 0);

				if (res != NULL) {
					ucl_object_push_lua (L, res, true);

					ucl_object_unref (res);
				}
				else {
					ucl_object_push_lua (L, rspamd_protocol_write_ucl (task),
							true);
					rdns_resolver_release (task->resolver->r);
					rspamd_session_destroy (task->s);
				}
			}
			else {
				lua_pushnil (L);
			}
		}

		event_base_free (base);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_encode_base64 (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gchar *out;
	gsize inlen, outlen;
	guint str_lim = 0;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (lua_gettop (L) > 1) {
		str_lim = luaL_checknumber (L, 2);
	}

	if (s == NULL) {
		lua_pushnil (L);
	}
	else {
		out = rspamd_encode_base64 (s, inlen, str_lim, &outlen);

		if (out != NULL) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->own = TRUE;
		}
		else {
			lua_pushnil (L);
		}
	}

	return 1;
}

static gint
lua_util_decode_base64 (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen, outlen;
	gboolean zero_copy = FALSE, grab_own = FALSE;
	gint state = 0;
	guint save = 0;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
			zero_copy = TRUE;
			if (t->own) {
				t->own = FALSE;
				grab_own = TRUE;
			}
		}
	}

	if (s != NULL) {
		if (zero_copy) {
			/* Decode in place */
			outlen = g_base64_decode_step (s, inlen, (guchar *)s, &state, &save);
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = s;
			t->len = outlen;
			t->own = grab_own;
		}
		else {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->len = (inlen / 4) * 3 + 3;
			t->start = g_malloc (t->len);
			outlen = g_base64_decode_step (s, inlen, (guchar *)t->start,
					&state, &save);
			t->len = outlen;
			t->own = TRUE;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_encode_base32 (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gchar *out;
	gsize inlen, outlen;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s == NULL) {
		lua_pushnil (L);
	}
	else {
		out = rspamd_encode_base32 (s, inlen);

		if (out != NULL) {
			t = lua_newuserdata (L, sizeof (*t));
			outlen = strlen (out);
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->own = TRUE;
		}
		else {
			lua_pushnil (L);
		}
	}

	return 1;
}

static gint
lua_util_decode_base32 (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen, outlen;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s != NULL) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = rspamd_decode_base32 (s, inlen, &outlen);
		t->len = outlen;
		t->own = TRUE;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_decode_url (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s != NULL) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = g_malloc (inlen);
		memcpy ((char *)t->start, s, inlen);
		t->len = rspamd_decode_url ((char *)t->start, s, inlen);
		t->own = TRUE;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_util_tokenize_text (lua_State *L)
{
	const gchar *in = NULL;
	gsize len, pos, ex_len, i;
	GList *exceptions = NULL, *cur;
	struct rspamd_lua_text *t;
	struct rspamd_process_exception *ex;
	GArray *res;
	rspamd_ftok_t *w;
	gboolean compat = FALSE;

	if (lua_type (L, 1) == LUA_TSTRING) {
		in = luaL_checklstring (L, 1, &len);
	}
	else if (lua_type (L, 1) == LUA_TTABLE) {
		t = lua_check_text (L, 1);

		if (t) {
			in = t->start;
			len = t->len;
		}
	}

	if (in == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (lua_gettop (L) > 1 && lua_type (L, 2) == LUA_TTABLE) {
		lua_pushvalue (L, 2);
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			if (lua_type (L, -1) == LUA_TTABLE) {
				lua_rawgeti (L, -1, 1);
				pos = luaL_checknumber (L, -1);
				lua_pop (L, 1);
				lua_rawgeti (L, -1, 2);
				ex_len = luaL_checknumber (L, -1);
				lua_pop (L, 1);

				if (ex_len > 0) {
					ex = g_slice_alloc (sizeof (*ex));
					ex->pos = pos;
					ex->len = ex_len;
					exceptions = g_list_prepend (exceptions, ex);
				}
			}
			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}

	if (lua_gettop (L) > 2 && lua_type (L, 3) == LUA_TBOOLEAN) {
		compat = lua_toboolean (L, 3);
	}

	if (exceptions) {
		exceptions = g_list_reverse (exceptions);
	}

	res = rspamd_tokenize_text ((gchar *)in, len, TRUE, NULL, exceptions, compat,
			NULL);

	if (res == NULL) {
		lua_pushnil (L);
	}
	else {
		lua_newtable (L);

		for (i = 0; i < res->len; i ++) {
			w = &g_array_index (res, rspamd_ftok_t, i);
			lua_pushlstring (L, w->begin, w->len);
			lua_rawseti (L, -2, i + 1);
		}
	}

	cur = exceptions;
	while (cur) {
		ex = cur->data;
		g_slice_free1 (sizeof (*ex), ex);
		cur = g_list_next (cur);
	}

	g_list_free (exceptions);

	return 1;
}

static gint
lua_util_tanh (lua_State *L)
{
	gdouble in = luaL_checknumber (L, 1);

	lua_pushnumber (L, tanh (in));

	return 1;
}

static gint
lua_util_parse_html (lua_State *L)
{
	struct rspamd_lua_text *t;
	const gchar *start = NULL;
	gsize len;
	GByteArray *res, *in;
	rspamd_mempool_t *pool;
	struct html_content *hc;

	if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			start = t->start;
			len = t->len;
		}
	}
	else if (lua_type (L, 1) == LUA_TSTRING) {
		start = luaL_checklstring (L, 1, &len);
	}

	if (start != NULL) {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
		hc = rspamd_mempool_alloc0 (pool, sizeof (*hc));
		in = g_byte_array_sized_new (len);
		g_byte_array_append (in, start, len);

		res = rspamd_html_process_part (pool, hc, in);

		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = res->data;
		t->len = res->len;
		t->own = TRUE;

		g_byte_array_free (res, FALSE);
		g_byte_array_free (in, TRUE);
		rspamd_mempool_delete (pool);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_levenshtein_distance (lua_State *L)
{
	const gchar *s1, *s2;
	gsize s1len, s2len;
	gint dist = 0;
	guint replace_cost = 1;

	s1 = luaL_checklstring (L, 1, &s1len);
	s2 = luaL_checklstring (L, 2, &s2len);

	if (lua_isnumber (L, 3)) {
		replace_cost = lua_tonumber (L, 3);
	}

	if (s1 && s2) {
		dist = rspamd_strings_levenshtein_distance (s1, s1len, s2, s2len,
				replace_cost);
	}

	lua_pushnumber (L, dist);

	return 1;
}

static gint
lua_util_parse_addr (lua_State *L)
{
	InternetAddressList *ia;
	InternetAddress *addr;
	const gchar *str = luaL_checkstring (L, 1);
	int i, cnt;

	if (str) {
		ia = internet_address_list_parse_string (str);

		if (ia == NULL) {
			lua_pushnil (L);
		}
		else {
			cnt = internet_address_list_length (ia);
			lua_newtable (L);

			for (i = 0; i < cnt; i ++) {
				addr = internet_address_list_get_address (ia, i);

				lua_newtable (L);
				lua_pushstring (L, "name");
				lua_pushstring (L, internet_address_get_name (addr));
				lua_settable (L, -3);

				if (INTERNET_ADDRESS_IS_MAILBOX (addr)) {
					lua_pushstring (L, "addr");
					lua_pushstring (L, internet_address_mailbox_get_addr (
							INTERNET_ADDRESS_MAILBOX (addr)));
					lua_settable (L, -3);
				}

				lua_rawseti (L, -2, (i + 1));
			}

			g_object_unref (ia);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_fold_header (lua_State *L)
{
	const gchar *name, *value;
	GString *folded;

	name = luaL_checkstring (L, 1);
	value = luaL_checkstring (L, 2);

	if (name && value) {
		folded = rspamd_header_value_fold (name, value, 0);

		if (folded) {
			lua_pushlstring (L, folded->str, folded->len);
			g_string_free (folded, TRUE);

			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_util_is_uppercase (lua_State *L)
{
	const gchar *str, *p;
	gsize sz, remain;
	gunichar uc;
	guint nlc = 0, nuc = 0;

	str = luaL_checklstring (L, 1, &sz);
	remain = sz;

	if (str && remain > 0) {
		while (remain > 0) {
			uc = g_utf8_get_char_validated (str, remain);
			p = g_utf8_next_char (str);

			if (p - str > (gint) remain) {
				break;
			}

			remain -= p - str;

			if (g_unichar_isupper (uc)) {
				nuc++;
			}
			else if (g_unichar_islower (uc)) {
				nlc++;
			}

			str = p;
		}
	}

	if (nuc > 0 && nlc == 0) {
		lua_pushboolean (L, TRUE);
	}
	else {
		lua_pushboolean (L, FALSE);
	}

	return 1;
}

static gint
lua_util_humanize_number (lua_State *L)
{
	gdouble number = luaL_checknumber (L, 1);
	gchar numbuf[32];


	rspamd_snprintf (numbuf, sizeof (numbuf), "%hL", (gint64)number);
	lua_pushstring (L, numbuf);

	return 1;
}

static gint
lua_util_get_tld (lua_State *L)
{
	const gchar *host;
	gsize hostlen;
	rspamd_ftok_t tld;

	host = luaL_checklstring (L, 1, &hostlen);

	if (host) {
		if (!rspamd_url_find_tld (host, hostlen, &tld)) {
			lua_pushlstring (L, host, hostlen);
		}
		else {
			lua_pushlstring (L, tld.begin, tld.len);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_util_glob (lua_State *L)
{
	const gchar *pattern;
	glob_t gl;
	gint top, i, flags;

	top = lua_gettop (L);
	memset (&gl, 0, sizeof (gl));
	flags = GLOB_NOSORT;

	for (i = 1; i <= top; i ++, flags |= GLOB_APPEND) {
		pattern = luaL_checkstring (L, i);

		if (pattern) {
			glob (pattern, flags, NULL, &gl);
		}
	}

	lua_newtable (L);
	/* Push results */
	for (i = 0; i < (gint)gl.gl_pathc; i ++) {
		lua_pushstring (L, gl.gl_pathv[i]);
		lua_rawseti (L, -2, i + 1);
	}

	globfree (&gl);

	return 1;
}

static gint
lua_util_parse_mail_address (lua_State *L)
{
	InternetAddressList *ia;
	const gchar *str = luaL_checkstring (L, 1);
	gboolean ret = FALSE;

	if (str) {
		ia = internet_address_list_parse_string (str);

		if (ia != NULL) {
			ret = TRUE;

			lua_push_internet_address_list (L, ia);
#ifdef GMIME24
		g_object_unref (ia);
#else
		internet_address_list_destroy (ia);
#endif
		}
	}

	if (!ret) {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_strlen_utf8 (lua_State *L)
{
	const gchar *str, *end;
	gsize len;

	str = lua_tolstring (L, 1, &len);

	if (str) {
		if (g_utf8_validate (str, len, &end)) {
			len = g_utf8_strlen (str, len);
		}
		else if (end != NULL && end > str) {
			len = (g_utf8_strlen (str, end - str)) /* UTF part */
					+ (len - (end - str)) /* raw part */;
		}

		lua_pushnumber (L, len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_strcasecmp_utf8 (lua_State *L)
{
	const gchar *str1, *str2;
	gsize len1, len2;
	gint ret = -1;

	str1 = lua_tolstring (L, 1, &len1);
	str2 = lua_tolstring (L, 1, &len2);

	if (str1 && str2) {

		if (len1 == len2) {
			ret = rspamd_lc_cmp (str1, str2, len1);
		}
		else {
			ret = len1 - len2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushnumber (L, ret);
	return 1;
}

static gint
lua_util_strcasecmp_ascii (lua_State *L)
{
	const gchar *str1, *str2;
	gsize len1, len2;
	gint ret = -1;

	str1 = lua_tolstring (L, 1, &len1);
	str2 = lua_tolstring (L, 1, &len2);

	if (str1 && str2) {

		if (len1 == len2) {
			ret = g_ascii_strncasecmp (str1, str2, len1);
		}
		else {
			ret = len1 - len2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushnumber (L, ret);
	return 1;
}

static gint
lua_util_strequal_caseless (lua_State *L)
{
	const gchar *str1, *str2;
	gsize len1, len2;
	gint ret = -1;

	str1 = lua_tolstring (L, 1, &len1);
	str2 = lua_tolstring (L, 2, &len2);

	if (str1 && str2) {

		if (len1 == len2) {
			ret = rspamd_lc_cmp (str1, str2, len1);
		}
		else {
			ret = len1 - len2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, (ret == 0) ? true : false);
	return 1;
}

static gint
lua_util_get_ticks (lua_State *L)
{
	gdouble ticks;

	ticks = rspamd_get_ticks ();
	lua_pushnumber (L, ticks);

	return 1;
}

static gint
lua_util_get_time (lua_State *L)
{
	gdouble seconds;
	struct timeval tv;

	if (gettimeofday (&tv, NULL) == 0) {
		seconds = tv_to_double (&tv);
	}
	else {
		seconds = time (NULL);
	}

	lua_pushnumber (L, seconds);

	return 1;
}

static gint
lua_util_time_to_string (lua_State *L)
{
	gdouble seconds;
	struct timeval tv;
	char timebuf[128];

	if (lua_isnumber (L, 1)) {
		seconds = lua_tonumber (L, 1);
	}
	else {
		if (gettimeofday (&tv, NULL) == 0) {
			seconds = tv_to_double (&tv);
		}
		else {
			seconds = time (NULL);
		}
	}

	rspamd_http_date_format (timebuf, sizeof (timebuf), seconds);
	lua_pushstring (L, timebuf);

	return 1;
}

static gint
lua_util_stat (lua_State *L)
{
	const gchar *fpath;
	struct stat st;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		if (stat (fpath, &st) == -1) {
			lua_pushstring (L, strerror (errno));
			lua_pushnil (L);
		}
		else {
			lua_pushnil (L);
			lua_createtable (L, 0, 3);

			lua_pushstring (L, "size");
			lua_pushnumber (L, st.st_size);
			lua_settable (L, -3);

			lua_pushstring (L, "mtime");
			lua_pushnumber (L, st.st_mtime);
			lua_settable (L, -3);

			lua_pushstring (L, "type");
			if (S_ISREG (st.st_mode)) {
				lua_pushstring (L, "regular");
			}
			else if (S_ISDIR (st.st_mode)) {
				lua_pushstring (L, "directory");
			}
			else {
				lua_pushstring (L, "special");
			}
			lua_settable (L, -3);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 2;
}

static gint
lua_util_unlink (lua_State *L)
{
	const gchar *fpath;
	gint ret;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		ret = unlink (fpath);

		if (ret == -1) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_lock_file (lua_State *L)
{
	const gchar *fpath;
	gint fd = -1;
	gboolean own = FALSE;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		if (lua_isnumber (L, 2)) {
			fd = lua_tonumber (L, 2);
		}
		else {
			fd = open (fpath, O_RDONLY);
			own = TRUE;
		}

		if (fd == -1) {
			lua_pushnil (L);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		if (flock (fd, LOCK_EX) == -1) {
			lua_pushnil (L);
			lua_pushstring (L, strerror (errno));

			if (own) {
				close (fd);
			}

			return 2;
		}

		lua_pushnumber (L, fd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_unlock_file (lua_State *L)
{
	gint fd = -1, ret, serrno;
	gboolean do_close = TRUE;

	if (lua_isnumber (L, 1)) {
		fd = lua_tonumber (L, 1);

		if (lua_isboolean (L, 2)) {
			do_close = lua_toboolean (L, 2);
		}

		ret = flock (fd, LOCK_UN);

		if (do_close) {
			serrno = errno;
			close (fd);
			errno = serrno;
		}

		if (ret == -1) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_create_file (lua_State *L)
{
	gint fd, mode = 00644;
	const gchar *fpath;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		if (lua_isnumber (L, 2)) {
			mode = lua_tonumber (L, 2);
		}

		fd = rspamd_file_xopen (fpath, O_RDWR|O_CREAT|O_EXCL, mode);

		if (fd == -1) {
			lua_pushnil (L);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushnumber (L, fd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_close_file (lua_State *L)
{
	gint fd = -1;

	if (lua_isnumber (L, 1)) {
		fd = lua_tonumber (L, 1);

		if (close (fd) == -1) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_random_hex (lua_State *L)
{
	gchar *buf;
	gint buflen;

	buflen = lua_tonumber (L, 1);

	if (buflen <= 0) {
		return luaL_error (L, "invalid arguments");
	}

	buf = g_malloc (buflen);
	rspamd_random_hex (buf, buflen);
	lua_pushlstring (L, buf, buflen);
	g_free (buf);

	return 1;
}

static gint
lua_load_util (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, utillib_f);

	return 1;
}

void
luaopen_util (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_util", lua_load_util);
}
